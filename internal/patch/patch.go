// Package patch applies size-preserving edits with verified, versioned backups.
package patch

import (
	"bytes"
	"crypto/sha256"
	"debug/elf"
	"debug/pe"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

type Record struct {
	Path, Original, Patched, Backup string
	Time                            time.Time
}
type Manager struct{ Dir string }
type Result struct {
	Path, State string
	Changes     int
}

var ide = regexp.MustCompile(`resetIsTierGCPTos\(\),this\.[A-Za-z_$0-9]+\.isGoogleInternal`)

func Hash(b []byte) string { h := sha256.Sum256(b); return hex.EncodeToString(h[:]) }
func transform(path string, data []byte) ([]byte, int, error) {
	out := bytes.Clone(data)
	count := 0
	switch strings.ToLower(filepath.Base(path)) {
	case "main.js", "extension.js":
		hits := ide.FindAllIndex(data, -1)
		if len(hits) > 1 {
			return nil, 0, errors.New("неоднозначная сигнатура JavaScript")
		}
		for _, h := range hits {
			prefix := "resetIsTierGCPTos(),true"
			copy(out[h[0]:h[1]], []byte(prefix+strings.Repeat(" ", h[1]-h[0]-len(prefix))))
			count++
		}
	case "agy.exe", "language_server_windows_x64.exe", "language_server_windows_arm.exe", "language_server_windows_arm64.exe", "language_server.exe", "agy", "language_server", "language_server_linux_x64", "language_server_linux_arm64":
		if strings.HasSuffix(strings.ToLower(path), ".exe") {
			f, err := pe.NewFile(bytes.NewReader(data))
			if err != nil {
				return nil, 0, errors.New("файл не является Windows PE")
			}
			defer f.Close()
			if f.Machine != pe.IMAGE_FILE_MACHINE_AMD64 && f.Machine != pe.IMAGE_FILE_MACHINE_ARM64 {
				return nil, 0, errors.New("поддерживаются x64 и ARM64")
			}
		} else {
			f, err := elf.NewFile(bytes.NewReader(data))
			if err != nil {
				return nil, 0, errors.New("файл не является Linux ELF")
			}
			defer f.Close()
			if f.Machine != elf.EM_X86_64 && f.Machine != elf.EM_AARCH64 {
				return nil, 0, errors.New("поддерживаются x64 и ARM64")
			}
		}
		if !bytes.Contains(data, []byte("cloudcode")) && !bytes.Contains(data, []byte("antigravity")) {
			return nil, 0, errors.New("нет признаков клиента Antigravity")
		}
		for _, p := range [][2]string{{"ineligible", "inexigible"}, {"https_proxy", "PA_LS_PROXY"}} {
			n := bytes.Count(out, []byte(p[0]))
			if n > 64 {
				return nil, 0, errors.New("слишком много совпадений: версия не поддерживается")
			}
			for offset := 0; ; {
				i := bytes.Index(out[offset:], []byte(p[0]))
				if i < 0 {
					break
				}
				i += offset
				copy(out[i:i+len(p[0])], p[1])
				offset = i + len(p[0])
			}
			count += n
		}
	default:
		return nil, 0, errors.New("тип файла не поддерживается")
	}
	return out, count, nil
}
func (m Manager) records() ([]Record, error) {
	b, e := os.ReadFile(filepath.Join(m.Dir, "records.json"))
	if os.IsNotExist(e) {
		return nil, nil
	}
	if e != nil {
		return nil, e
	}
	var r []Record
	e = json.Unmarshal(b, &r)
	return r, e
}
func Atomic(path string, b []byte, mode os.FileMode) error {
	f, e := os.CreateTemp(filepath.Dir(path), ".privet-*")
	if e != nil {
		return e
	}
	name := f.Name()
	defer os.Remove(name)
	if e = f.Chmod(mode); e == nil {
		_, e = f.Write(b)
	}
	if e == nil {
		e = f.Sync()
	}
	ce := f.Close()
	if e == nil {
		e = ce
	}
	if e != nil {
		return e
	}
	return os.Rename(name, path)
}
func (m Manager) Apply(path string) (Result, error) {
	res := Result{Path: path, State: "не поддерживается"}
	info, e := os.Lstat(path)
	if e != nil {
		return res, e
	}
	if !info.Mode().IsRegular() {
		return res, errors.New("ожидался обычный файл")
	}
	b, e := os.ReadFile(path)
	if e != nil {
		return res, e
	}
	records, e := m.records()
	if e != nil {
		return res, e
	}
	hash := Hash(b)
	for _, r := range records {
		if strings.EqualFold(r.Path, path) && r.Patched == hash {
			res.State = "применён"
			return res, nil
		}
	}
	out, n, e := transform(path, b)
	if e != nil {
		return res, e
	}
	if n == 0 {
		return res, nil
	}
	if e = os.MkdirAll(m.Dir, 0700); e != nil {
		return res, e
	}
	backup := hash + ".bak"
	bp := filepath.Join(m.Dir, backup)
	if old, e := os.ReadFile(bp); e == nil {
		if Hash(old) != hash {
			return res, errors.New("резервная копия повреждена")
		}
	} else if os.IsNotExist(e) {
		if e = Atomic(bp, b, 0600); e != nil {
			return res, e
		}
	} else {
		return res, e
	}
	// Persist recovery information before touching the installed file.
	record := Record{Path: path, Original: hash, Patched: Hash(out), Backup: backup, Time: time.Now()}
	records = append(records, record)
	raw, _ := json.MarshalIndent(records, "", "  ")
	if e = Atomic(filepath.Join(m.Dir, "records.json"), raw, 0600); e != nil {
		return res, e
	}
	current, e := FileHash(path)
	if e != nil {
		return res, e
	}
	if current != hash {
		return res, errors.New("файл обновился во время операции: повторите поиск")
	}
	if e = Atomic(path, out, info.Mode()); e != nil {
		return res, fmt.Errorf("закройте Antigravity; если установлен в Program Files, нужны права администратора: %w", e)
	}
	check, e := FileHash(path)
	if e != nil {
		return res, e
	}
	if check != record.Patched {
		return res, errors.New("проверка записи не прошла")
	}
	res.State = "применён"
	res.Changes = n
	return res, nil
}
func (m Manager) RestoreAll() []error {
	records, e := m.records()
	if e != nil {
		return []error{e}
	}
	var errs []error
	seen := map[string]bool{}
	for i := len(records) - 1; i >= 0; i-- {
		r := records[i]
		key := strings.ToLower(r.Path)
		if seen[key] {
			continue
		}
		seen[key] = true
		b, e := os.ReadFile(r.Path)
		if os.IsNotExist(e) {
			continue
		}
		if e != nil {
			errs = append(errs, e)
			continue
		}
		h := Hash(b)
		if h == r.Original {
			continue
		}
		if h != r.Patched {
			errs = append(errs, fmt.Errorf("%s: файл обновился или изменён; старая копия не записана поверх него", r.Path))
			continue
		}
		if filepath.Base(r.Backup) != r.Backup || r.Backup != r.Original+".bak" {
			errs = append(errs, errors.New("неверное имя резервной копии"))
			continue
		}
		orig, e := os.ReadFile(filepath.Join(m.Dir, r.Backup))
		if e == nil && Hash(orig) != r.Original {
			e = errors.New("резервная копия повреждена")
		}
		if e == nil {
			info, ie := os.Stat(r.Path)
			if ie != nil {
				e = ie
			} else {
				e = Atomic(r.Path, orig, info.Mode())
			}
		}
		if e != nil {
			errs = append(errs, fmt.Errorf("%s: %w", r.Path, e))
		}
	}
	return errs
}
func Discover(roots []string) []string {
	found := map[string]bool{}
	var paths []string
	for _, root := range roots {
		root = filepath.Clean(root)
		baseDepth := strings.Count(root, string(filepath.Separator))
		filepath.WalkDir(root, func(p string, d os.DirEntry, e error) error {
			if e != nil {
				return nil
			}
			if d.Type()&os.ModeSymlink != 0 {
				if d.IsDir() {
					return filepath.SkipDir
				}
				return nil
			}
			if d.IsDir() {
				name := strings.ToLower(d.Name())
				if strings.Count(p, string(filepath.Separator))-baseDepth > 10 || name == "node_modules" || name == ".git" || name == "backups" {
					return filepath.SkipDir
				}
				return nil
			}
			name := strings.ToLower(d.Name())
			wanted := name == "agy" || name == "language_server" || name == "language_server_linux_x64" || name == "language_server_linux_arm64" || name == "agy.exe" || name == "language_server.exe" || name == "language_server_windows_x64.exe" || name == "language_server_windows_arm64.exe" || name == "language_server_windows_arm.exe" || name == "main.js" || name == "extension.js"
			if wanted {
				key := strings.ToLower(p)
				if !found[key] {
					found[key] = true
					paths = append(paths, p)
				}
			}
			return nil
		})
	}
	return paths
}

func FileHash(path string) (string, error) {
	f, e := os.Open(path)
	if e != nil {
		return "", e
	}
	defer f.Close()
	h := sha256.New()
	if _, e = io.Copy(h, f); e != nil {
		return "", e
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}
