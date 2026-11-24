//go:build windows

package main

import (
	"context"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"
	"unicode/utf16"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"
	"privetantigravity/internal/patch"
	"privetantigravity/internal/route"
)

const serviceName = "PrivetAntigravity"
const nrptTag = "PrivetAntigravity-v1"

func platformDataDir() string {
	p := os.Getenv("ProgramData")
	if p == "" {
		p = `C:\ProgramData`
	}
	return filepath.Join(p, "PrivetAntigravity")
}
func clientNames() []string {
	return []string{"Antigravity.exe", "Antigravity IDE.exe", "antigravity.exe", "agy.exe"}
}
func platformRoots() []string {
	var roots []string
	for _, base := range []string{filepath.Join(os.Getenv("LOCALAPPDATA"), "Programs"), os.Getenv("ProgramFiles"), os.Getenv("ProgramFiles(x86)")} {
		if base == "" {
			continue
		}
		for _, name := range []string{"Antigravity", "Antigravity IDE"} {
			roots = append(roots, filepath.Join(base, name))
		}
	}
	h, _ := os.UserHomeDir()
	roots = append(roots, filepath.Join(h, ".gemini/bin"), filepath.Join(os.Getenv("LOCALAPPDATA"), "agy"))
	for _, p := range []string{".vscode/extensions/google*antigravity*", ".vscode-insiders/extensions/google*antigravity*"} {
		matches, _ := filepath.Glob(filepath.Join(h, p))
		roots = append(roots, matches...)
	}
	for _, hive := range []registry.Key{registry.CURRENT_USER, registry.LOCAL_MACHINE} {
		for _, base := range []string{`SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall`, `SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall`} {
			k, e := registry.OpenKey(hive, base, registry.READ)
			if e != nil {
				continue
			}
			names, _ := k.ReadSubKeyNames(-1)
			for _, name := range names {
				sub, e := registry.OpenKey(k, name, registry.QUERY_VALUE)
				if e != nil {
					continue
				}
				display, _, _ := sub.GetStringValue("DisplayName")
				if strings.Contains(strings.ToLower(display), "antigravity") {
					p, _, _ := sub.GetStringValue("InstallLocation")
					if p != "" {
						roots = append(roots, p)
					}
				}
				sub.Close()
			}
			k.Close()
		}
	}
	if p, e := exec.LookPath("agy.exe"); e == nil {
		roots = append(roots, filepath.Dir(p))
	}
	return roots
}
func powershell(script string) error {
	b := utf16.Encode([]rune("$ErrorActionPreference='Stop'; " + script))
	raw := make([]byte, len(b)*2)
	for i, v := range b {
		binary.LittleEndian.PutUint16(raw[i*2:], v)
	}
	cmd := exec.Command("powershell.exe", "-NoProfile", "-NonInteractive", "-EncodedCommand", base64.StdEncoding.EncodeToString(raw))
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	out, e := cmd.CombinedOutput()
	if e != nil {
		return fmt.Errorf("настройка Windows: %s (%w)", strings.TrimSpace(string(out)), e)
	}
	return nil
}
func nrpt(enable bool) error {
	s := `Get-DnsClientNrptRule | Where-Object { $_.Comment -eq '` + nrptTag + `' } | Remove-DnsClientNrptRule -Force; `
	if enable {
		for _, host := range route.Domains {
			s += `Add-DnsClientNrptRule -Namespace '` + host + `' -NameServers '` + route.DNSIP + `' -Comment '` + nrptTag + `' | Out-Null; `
		}
	}
	s += `Clear-DnsClientCache`
	return powershell(s)
}
func setProxyEnv(enable bool) error {
	k, _, e := registry.CreateKey(registry.CURRENT_USER, `Environment`, registry.SET_VALUE)
	if e != nil {
		return e
	}
	defer k.Close()
	if enable {
		e = k.SetStringValue("PA_LS_PROXY", "http://"+route.Proxy)
	} else {
		e = k.DeleteValue("PA_LS_PROXY")
		if e == syscall.ERROR_FILE_NOT_FOUND {
			e = nil
		}
	}
	if e != nil {
		return e
	}
	p, _ := windows.UTF16PtrFromString("Environment")
	var result uintptr
	user32.NewProc("SendMessageTimeoutW").Call(0xffff, 0x1a, 0, uintptr(unsafe.Pointer(p)), 2, 2000, uintptr(unsafe.Pointer(&result)))
	return nil
}
func platformListeners(ctx context.Context, r *route.Router) error {
	udp, e := net.ListenPacket("udp4", route.DNSIP+":53")
	if e != nil {
		return fmt.Errorf("локальный DNS недоступен: %w", e)
	}
	tcp, e := net.Listen("tcp4", route.DNSIP+":53")
	if e != nil {
		udp.Close()
		return e
	}
	tls, e := net.Listen("tcp4", route.DNSIP+":443")
	if e != nil {
		udp.Close()
		tcp.Close()
		return fmt.Errorf("локальный TLS порт занят: %w", e)
	}
	route.ServeDNS(ctx, udp, tcp)
	go r.ServeTLS(ctx, tls)
	return nil
}

type service struct{}

func (service) Execute(_ []string, req <-chan svc.ChangeRequest, status chan<- svc.Status) (bool, uint32) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	status <- svc.Status{State: svc.StartPending}
	done := make(chan error, 1)
	go func() {
		done <- daemon(ctx, func() error {
			status <- svc.Status{State: svc.Running, Accepts: svc.AcceptStop | svc.AcceptShutdown}
			return nil
		})
	}()
	for {
		select {
		case r := <-req:
			switch r.Cmd {
			case svc.Interrogate:
				status <- r.CurrentStatus
			case svc.Stop, svc.Shutdown:
				status <- svc.Status{State: svc.StopPending}
				cancel()
				<-done
				return false, 0
			}
		case e := <-done:
			if e != nil {
				return true, 1
			}
			return false, 0
		}
	}
}
func runDaemon() error {
	is, e := svc.IsWindowsService()
	if e != nil {
		return e
	}
	if is {
		return svc.Run(serviceName, service{})
	}
	return daemon(context.Background(), nil)
}
func stopService() error {
	m, e := mgr.Connect()
	if e != nil {
		return e
	}
	defer m.Disconnect()
	s, e := m.OpenService(serviceName)
	if e != nil {
		if e == windows.ERROR_SERVICE_DOES_NOT_EXIST {
			return nil
		}
		return e
	}
	defer s.Close()
	st, e := s.Query()
	if e != nil {
		return e
	}
	if st.State == svc.Stopped {
		return nil
	}
	if _, e = s.Control(svc.Stop); e != nil {
		return e
	}
	for i := 0; i < 80; i++ {
		st, e = s.Query()
		if e != nil {
			return e
		}
		if st.State == svc.Stopped {
			return nil
		}
		time.Sleep(100 * time.Millisecond)
	}
	return fmt.Errorf("служба ещё останавливается, повторите действие")
}
func protectData() error {
	sd, e := windows.SecurityDescriptorFromString("D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;GRGX;;;BU)")
	if e != nil {
		return e
	}
	dacl, _, e := sd.DACL()
	if e != nil {
		return e
	}
	return windows.SetNamedSecurityInfo(dataDir(), windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, dacl, nil)
}
func installService() error {
	if e := os.MkdirAll(filepath.Join(dataDir(), "bin"), 0700); e != nil {
		return e
	}
	if e := protectData(); e != nil {
		return e
	}
	if e := stopService(); e != nil {
		return e
	}
	dst := filepath.Join(dataDir(), "bin/PrivetAntigravity.exe")
	src, e := os.Executable()
	if e != nil {
		return e
	}
	if !strings.EqualFold(src, dst) {
		b, e := os.ReadFile(src)
		if e != nil {
			return e
		}
		if e = patch.Atomic(dst, b, 0700); e != nil {
			return e
		}
	}
	m, e := mgr.Connect()
	if e != nil {
		return e
	}
	defer m.Disconnect()
	s, e := m.OpenService(serviceName)
	if e == windows.ERROR_SERVICE_DOES_NOT_EXIST {
		s, e = m.CreateService(serviceName, dst, mgr.Config{DisplayName: "PrivetAntigravity", StartType: mgr.StartAutomatic, Description: "Подключение Antigravity и повторный патч после обновлений"}, "--daemon")
	}
	if e != nil {
		return e
	}
	defer s.Close()
	_ = s.SetRecoveryActions([]mgr.RecoveryAction{{Type: mgr.ServiceRestart, Delay: 3 * time.Second}}, 60)
	if e = s.Start(); e != nil {
		return e
	}
	for i := 0; i < 100; i++ {
		st, e := s.Query()
		if e != nil {
			return e
		}
		if st.State == svc.Running {
			if e = nrpt(true); e != nil {
				return e
			}
			return setProxyEnv(true)
		}
		if st.State == svc.Stopped {
			return fmt.Errorf("служба не запустилась. Подробности: %s", filepath.Join(dataDir(), "service.log"))
		}
		time.Sleep(100 * time.Millisecond)
	}
	return fmt.Errorf("превышено время запуска службы")
}
func disableService() error {
	if e := nrpt(false); e != nil {
		return e
	}
	if e := setProxyEnv(false); e != nil {
		return e
	}
	if e := stopService(); e != nil {
		return e
	}
	m, e := mgr.Connect()
	if e != nil {
		return e
	}
	defer m.Disconnect()
	s, e := m.OpenService(serviceName)
	if e == windows.ERROR_SERVICE_DOES_NOT_EXIST {
		return nil
	}
	if e != nil {
		return e
	}
	defer s.Close()
	return s.Delete()
}
func launchClient() error {
	p := findClient()
	if p == "" {
		return fmt.Errorf("выберите папку Antigravity")
	}
	if c, e := net.DialTimeout("tcp", route.Proxy, time.Second); e != nil {
		return fmt.Errorf("сначала нажмите «Включить»")
	} else {
		c.Close()
	}
	params := ""
	if !strings.EqualFold(filepath.Base(p), "agy.exe") {
		params = "--proxy-server=http://" + route.Proxy
	}
	os.Setenv("PA_LS_PROXY", "http://"+route.Proxy)
	// Ask the desktop shell to launch the editor as the signed-in user, not as administrator.
	script := `$shell=New-Object -ComObject Shell.Application; $shell.ShellExecute('` + strings.ReplaceAll(p, "'", "''") + `','` + params + `','','open',1)`
	return powershell(script)
}

func elevated([]string) error {
	return fmt.Errorf("запустите приложение от имени администратора")
}
