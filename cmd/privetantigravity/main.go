package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"

	"privetantigravity/internal/patch"
	"privetantigravity/internal/route"
)

const version = "0.1.0-beta"

type Config struct {
	Roots     []string `json:"roots"`
	Resolvers []string `json:"resolvers"`
	Watch     bool     `json:"watch"`
}

func dataDir() string        { return platformDataDir() }
func manager() patch.Manager { return patch.Manager{Dir: filepath.Join(dataDir(), "backups")} }
func readConfig() Config {
	c := Config{Resolvers: route.DefaultResolvers, Watch: true}
	b, e := os.ReadFile(filepath.Join(dataDir(), "config.json"))
	if e == nil {
		json.Unmarshal(b, &c)
	}
	if len(c.Resolvers) == 0 {
		c.Resolvers = route.DefaultResolvers
	}
	return c
}
func saveConfig(c Config) error {
	if e := os.MkdirAll(dataDir(), 0700); e != nil {
		return e
	}
	b, e := json.MarshalIndent(c, "", "  ")
	if e != nil {
		return e
	}
	return patch.Atomic(filepath.Join(dataDir(), "config.json"), b, 0600)
}
func roots(c Config) []string { return append(platformRoots(), c.Roots...) }
func patchAll(c Config, report func(string)) (int, int) {
	return patchPaths(roots(c), report)
}
func patchPaths(dirs []string, report func(string)) (int, int) {
	files := patch.Discover(dirs)
	ok, bad := 0, 0
	for _, p := range files {
		r, e := manager().Apply(p)
		if e != nil {
			bad++
			report(filepath.Base(p) + ": " + e.Error())
		} else if r.State == "применён" {
			ok++
			report(p + " — патч применён")
		} else {
			report(p + " — подходящая сигнатура не найдена")
		}
	}
	report(fmt.Sprintf("Найдено файлов: %d. Патч применён: %d. Ошибок: %d.", len(files), ok, bad))
	return ok, bad
}
func daemon(ctx context.Context, ready func() error) error {
	if e := os.MkdirAll(dataDir(), 0700); e != nil {
		return e
	}
	f, e := os.OpenFile(filepath.Join(dataDir(), "service.log"), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
	if e != nil {
		return e
	}
	defer f.Close()
	logger := log.New(f, "", log.Ldate|log.Ltime)
	report := func(s string) { logger.Println(s) }
	proxy, e := net.Listen("tcp4", route.Proxy)
	if e != nil {
		return fmt.Errorf("порт прокси занят: %w", e)
	}
	defer proxy.Close()
	c := readConfig()
	router := route.New(c.Resolvers, report)
	if e = platformListeners(ctx, router); e != nil {
		return e
	}
	if ready != nil {
		if e = ready(); e != nil {
			return e
		}
	}
	go router.ServeProxy(ctx, proxy)
	report("Служба запущена. Версия " + version)
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	last := map[string]string{}
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			c = readConfig()
			if !c.Watch {
				continue
			}
			for _, p := range patch.Discover(roots(c)) {
				st, e := os.Stat(p)
				if e != nil {
					continue
				}
				key := fmt.Sprintf("%d:%d", st.Size(), st.ModTime().UnixNano())
				if last[p] == key {
					continue
				}
				r, e := manager().Apply(p)
				if e != nil {
					report(e.Error())
					continue
				}
				last[p] = key
				if r.Changes > 0 {
					report("Повторно применён патч: " + p)
				}
			}
		}
	}
}
func diagnostic(report func(string)) {
	router := route.New(readConfig().Resolvers, report)
	for _, host := range route.Domains {
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		start := time.Now()
		conn, e := router.Dial(ctx, host)
		cancel()
		if e != nil {
			report(host + ": " + e.Error())
		} else {
			conn.Close()
			report(fmt.Sprintf("%s: TCP и сертификат TLS доступны (%d мс)", host, time.Since(start).Milliseconds()))
		}
	}
	report("Проверка сети завершена. Для проверки аккаунта отправьте сообщение модели в Antigravity.")
}
func main() {
	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "--elevated":
			if e := elevated(os.Args[2:]); e != nil {
				fmt.Fprintln(os.Stderr, e)
				os.Exit(1)
			}
			return
		case "--version":
			fmt.Println("PrivetAntigravity " + version)
			return
		case "--daemon":
			if e := runDaemon(); e != nil {
				log.Fatal(e)
			}
			return
		case "--check":
			diagnostic(func(s string) { fmt.Println(s) })
			return
		case "--patch-only":
			dirs := roots(readConfig())
			if len(os.Args) > 2 {
				dirs = []string{cleanRoot(os.Args[2])}
			}
			n, b := patchPaths(dirs, func(s string) { fmt.Println(s) })
			if n == 0 || b > 0 {
				os.Exit(1)
			}
			return
		case "--restore-only":
			errs := manager().RestoreAll()
			for _, e := range errs {
				fmt.Println(e)
			}
			if len(errs) > 0 {
				os.Exit(1)
			}
			return
		case "--launch":
			if e := launchClient(); e != nil {
				fmt.Fprintln(os.Stderr, e)
				os.Exit(1)
			}
			return
		case "--self-test":
			fmt.Println("PrivetAntigravity " + version + "; platform OK; data=" + dataDir())
			return
		case "--help":
			fmt.Println("PrivetAntigravity: --check, --patch-only [папка], --restore-only, --launch, --version")
			return
		}
	}
	runUI()
}
func findClient() string {
	for _, root := range roots(readConfig()) {
		for _, name := range clientNames() {
			p := filepath.Join(root, name)
			if st, e := os.Stat(p); e == nil && !st.IsDir() {
				return p
			}
		}
	}
	return ""
}
func cleanRoot(s string) string {
	s = strings.Trim(strings.TrimSpace(s), "\"")
	if st, e := os.Stat(s); e == nil && !st.IsDir() {
		s = filepath.Dir(s)
	}
	return s
}
