//go:build linux

package main

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"privetantigravity/internal/patch"
	"privetantigravity/internal/route"
	"strings"
	"syscall"
)

func platformDataDir() string {
	if s := os.Getenv("PRIVET_ANTIGRAVITY_DATA"); s != "" {
		return s
	}
	base := os.Getenv("XDG_DATA_HOME")
	if base == "" {
		h, _ := os.UserHomeDir()
		base = filepath.Join(h, ".local/share")
	}
	return filepath.Join(base, "PrivetAntigravity")
}
func platformRoots() []string {
	h, _ := os.UserHomeDir()
	r := []string{"/opt/Antigravity", "/opt/antigravity", "/opt/antigravity-ide", "/usr/share/antigravity", "/usr/lib/antigravity", filepath.Join(h, ".local/share/antigravity"), filepath.Join(h, ".antigravity"), filepath.Join(h, ".gemini/bin"), filepath.Join(h, ".local/bin")}
	for _, g := range []string{".vscode/extensions/google.antigravity*", ".vscode/extensions/google.google-antigravity*", ".vscode-insiders/extensions/google*antigravity*"} {
		p, _ := filepath.Glob(filepath.Join(h, g))
		r = append(r, p...)
	}
	if p, e := exec.LookPath("antigravity"); e == nil {
		if q, e := filepath.EvalSymlinks(p); e == nil {
			r = append(r, filepath.Dir(q))
		}
	}
	return r
}
func clientNames() []string {
	return []string{"antigravity", "Antigravity", "antigravity-ide", "bin/antigravity", "agy"}
}
func platformListeners(context.Context, *route.Router) error { return nil }
func runDaemon() error {
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGTERM, os.Interrupt)
	defer cancel()
	return daemon(ctx, nil)
}
func launchClient() error {
	p := findClient()
	if p == "" {
		return fmt.Errorf("Antigravity не найден. Выберите его папку в меню патчера")
	}
	if c, e := net.Dial("tcp", route.Proxy); e != nil {
		return fmt.Errorf("служба выключена. Сначала выберите «Включить»")
	} else {
		c.Close()
	}
	cmd := exec.Command(p)
	if filepath.Base(p) != "agy" {
		cmd.Args = append(cmd.Args, "--proxy-server=http://"+route.Proxy)
	}
	env := os.Environ()
	for _, v := range []string{"PA_LS_PROXY", "HTTPS_PROXY", "https_proxy"} {
		prefix := v + "="
		var next []string
		for _, e := range env {
			if !strings.HasPrefix(e, prefix) {
				next = append(next, e)
			}
		}
		env = append(next, prefix+"http://"+route.Proxy)
	}
	cmd.Env = env
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Start()
}
func unitPath() string {
	h, _ := os.UserHomeDir()
	return filepath.Join(h, ".config/systemd/user/privetantigravity.service")
}
func systemctl(args ...string) error {
	c := exec.Command("systemctl", append([]string{"--user"}, args...)...)
	b, e := c.CombinedOutput()
	if e != nil {
		return fmt.Errorf("systemd: %s: %w", strings.TrimSpace(string(b)), e)
	}
	return nil
}
func installService() error {
	if os.Geteuid() == 0 {
		return fmt.Errorf("запустите меню от обычного пользователя: служба работает в его сеансе")
	}
	dst := filepath.Join(dataDir(), "bin/PrivetAntigravity")
	if e := os.MkdirAll(filepath.Dir(dst), 0700); e != nil {
		return e
	}
	src, e := os.Executable()
	if e != nil {
		return e
	}
	if src != dst {
		b, e := os.ReadFile(src)
		if e != nil {
			return e
		}
		if e = patch.Atomic(dst, b, 0700); e != nil {
			return e
		}
	}
	if strings.ContainsAny(dst, "\n\r\"%") {
		return fmt.Errorf("путь содержит неподдерживаемые символы")
	}
	unit := "[Unit]\nDescription=PrivetAntigravity\nAfter=network-online.target\n\n[Service]\nExecStart=\"" + dst + "\" --daemon\nRestart=on-failure\nRestartSec=3\n\n[Install]\nWantedBy=default.target\n"
	if e = os.MkdirAll(filepath.Dir(unitPath()), 0700); e != nil {
		return e
	}
	if e = patch.Atomic(unitPath(), []byte(unit), 0600); e != nil {
		return e
	}
	if e = systemctl("daemon-reload"); e != nil {
		return e
	}
	return systemctl("enable", "--now", "privetantigravity.service")
}
func runUI() {
	in := bufio.NewScanner(os.Stdin)
	print := func(s string) { fmt.Println(s) }
	for {
		fmt.Printf("\nPrivetAntigravity %s · Arch Linux\n\n1  Включить патч и службу\n2  Запустить Antigravity\n3  Проверить сеть\n4  Выбрать папку Antigravity\n5  Откатить и выключить\n6  Открыть инструкцию\n0  Выйти\n\n> ", version)
		if !in.Scan() {
			return
		}
		switch strings.TrimSpace(in.Text()) {
		case "0":
			return
		case "1":
			c := readConfig()
			if e := saveConfig(c); e != nil {
				print(e.Error())
				continue
			}
			_ = systemctl("stop", "privetantigravity.service")
			n, b := patchAll(c, print)
			if b > 0 {
				print("Для записи в системную папку нужны права администратора.")
				c.Roots = roots(c)
				if e := saveConfig(c); e != nil {
					print(e.Error())
					continue
				}
				if e := requestElevated("apply"); e != nil {
					print(e.Error())
					continue
				}
				n, b = patchAll(c, print)
				if b > 0 {
					print("Есть ошибки патча. Подробности выше.")
				}
			}

			if n > 0 && b == 0 {
				if e := installService(); e != nil {
					print(e.Error())
				} else {
					print("Включено. Запускайте Antigravity пунктом 2 или ярлыком PrivetAntigravity — запуск.")
				}
			}
		case "2":
			if e := launchClient(); e != nil {
				print(e.Error())
			}
		case "3":
			diagnostic(print)
		case "4":
			print("Введите путь к папке или исполняемому файлу:")
			if in.Scan() {
				p := cleanRoot(in.Text())
				if st, e := os.Stat(p); e != nil || !st.IsDir() {
					print("Папка не найдена")
				} else {
					c := readConfig()
					c.Roots = append(c.Roots, p)
					if e := saveConfig(c); e != nil {
						print(e.Error())
					} else {
						print("Сохранено: " + p)
					}
				}
			}
		case "5":
			if e := systemctl("disable", "--now", "privetantigravity.service"); e != nil {
				print(e.Error())
			}
			errs := manager().RestoreAll()
			for _, e := range errs {
				print(e.Error())
			}
			if len(errs) == 0 {
				os.Remove(unitPath())
				_ = systemctl("daemon-reload")
				print("Изменения отменены. Резервные копии сохранены.")
			} else {
				if e := requestElevated("restore"); e != nil {
					print(e.Error())
				} else {
					print("Оригиналы восстановлены.")
				}
			}
		case "6":
			print(guide)
		}
	}
}

func requestElevated(action string) error {
	exe, e := os.Executable()
	if e != nil {
		return e
	}
	var cmd *exec.Cmd
	if _, e = exec.LookPath("pkexec"); e == nil {
		cmd = exec.Command("pkexec", exe, "--elevated", action, dataDir())
	} else {
		cmd = exec.Command("sudo", exe, "--elevated", action, dataDir())
	}
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}
func elevated(args []string) error {
	if os.Geteuid() != 0 || len(args) != 2 {
		return fmt.Errorf("неверный вызов помощника")
	}
	dir := args[1]
	info, e := os.Stat(dir)
	if e != nil {
		return e
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return fmt.Errorf("не удалось определить владельца")
	}
	os.Setenv("PRIVET_ANTIGRAVITY_DATA", dir)
	defer filepath.WalkDir(filepath.Join(dir, "backups"), func(p string, d os.DirEntry, e error) error {
		if e == nil {
			os.Chown(p, int(st.Uid), int(st.Gid))
		}
		return nil
	})
	switch args[0] {
	case "apply":
		n, b := patchAll(readConfig(), func(s string) { fmt.Println(s) })
		if n == 0 || b > 0 {
			return fmt.Errorf("не все файлы удалось обработать")
		}
		return nil
	case "restore":
		errs := manager().RestoreAll()
		for _, e := range errs {
			fmt.Println(e)
		}
		if len(errs) > 0 {
			return fmt.Errorf("не все файлы восстановлены")
		}
		return nil
	}
	return fmt.Errorf("неизвестная операция")
}
