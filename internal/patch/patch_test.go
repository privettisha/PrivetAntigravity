package patch

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

func TestRoundTripAndUpdateProtection(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "main.js")
	original := []byte("prefix;resetIsTierGCPTos(),this._productService.isGoogleInternal;suffix")
	os.WriteFile(p, original, 0755)
	m := Manager{filepath.Join(dir, "backups")}
	r, e := m.Apply(p)
	if e != nil || r.Changes != 1 {
		t.Fatalf("apply: %+v %v", r, e)
	}
	patched, _ := os.ReadFile(p)
	if len(patched) != len(original) || bytes.Equal(patched, original) {
		t.Fatal("expected size-preserving patch")
	}
	r, e = m.Apply(p)
	if e != nil || r.Changes != 0 || r.State != "применён" {
		t.Fatal("not idempotent", r, e)
	}
	if e := m.RestoreAll(); len(e) != 0 {
		t.Fatal(e)
	}
	restored, _ := os.ReadFile(p)
	if !bytes.Equal(restored, original) {
		t.Fatal("restore mismatch")
	}
	m.Apply(p)
	newVersion := []byte("new client version")
	os.WriteFile(p, newVersion, 0755)
	if len(m.RestoreAll()) == 0 {
		t.Fatal("must refuse outdated backup")
	}
	restored, _ = os.ReadFile(p)
	if !bytes.Equal(restored, newVersion) {
		t.Fatal("update overwritten")
	}
}
func TestCorruptBackupRefused(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "main.js")
	original := []byte("resetIsTierGCPTos(),this.p.isGoogleInternal")
	os.WriteFile(p, original, 0644)
	m := Manager{filepath.Join(dir, "backups")}
	m.Apply(p)
	os.WriteFile(filepath.Join(m.Dir, Hash(original)+".bak"), []byte("bad"), 0600)
	if len(m.RestoreAll()) == 0 {
		t.Fatal("corrupt backup accepted")
	}
}
func TestRejectAmbiguousAndWrongExecutable(t *testing.T) {
	for _, s := range []struct {
		Path string
		Data []byte
	}{{"main.js", []byte("resetIsTierGCPTos(),this.a.isGoogleInternal;resetIsTierGCPTos(),this.b.isGoogleInternal")}, {"agy.exe", []byte("MZ ineligible https_proxy antigravity")}, {"agy", []byte("not ELF ineligible antigravity")}} {
		if _, _, e := transform(s.Path, s.Data); e == nil {
			t.Fatal("accepted", s.Path)
		}
	}
}
func TestBackupHistory(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "main.js")
	m := Manager{filepath.Join(dir, "backups")}
	for _, prefix := range []string{"version1;", "version2;"} {
		b := []byte(prefix + "resetIsTierGCPTos(),this.p.isGoogleInternal")
		os.WriteFile(p, b, 0644)
		if _, e := m.Apply(p); e != nil {
			t.Fatal(e)
		}
		if errs := m.RestoreAll(); len(errs) > 0 {
			t.Fatal(errs)
		}
		restored, _ := os.ReadFile(p)
		if !bytes.Equal(restored, b) {
			t.Fatal("wrong generation restored")
		}
	}
}
