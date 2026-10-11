package install_test

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/Astatine-213-Tian/agent-secrets/internal/install"
)

func put(t *testing.T, p string, b []byte) {
	t.Helper()
	if e := os.MkdirAll(filepath.Dir(p), 0700); e != nil {
		t.Fatal(e)
	}
	if e := os.WriteFile(p, b, 0600); e != nil {
		t.Fatal(e)
	}
}
func read(t *testing.T, p string) []byte {
	t.Helper()
	b, e := os.ReadFile(p)
	if e != nil {
		t.Fatal(e)
	}
	return b
}

func TestInstallAndInspect(t *testing.T) {
	home := t.TempDir()
	hooks := filepath.Join(home, ".codex/hooks.json")
	claude := filepath.Join(home, ".claude/settings.json")
	put(t, hooks, []byte(`{"keep":true}`))
	put(t, claude, []byte(`{"model":"keep"}`))
	config := filepath.Join(home, ".codex/config.toml")
	put(t, config, []byte("deliberately not TOML; installer must not read or write this"))
	source := []byte("synthetic executable")
	if e := install.User(home, source); e != nil {
		t.Fatal(e)
	}
	first := read(t, hooks)
	if e := install.User(home, source); e != nil {
		t.Fatal(e)
	}
	if !bytes.Equal(first, read(t, hooks)) {
		t.Fatal("not idempotent")
	}
	if string(read(t, config)) != "deliberately not TOML; installer must not read or write this" {
		t.Fatal("touched permission configuration")
	}
	s := install.Inspect(home, source)
	if !s.Readable || !s.BinaryMatches || !s.CodexHook || !s.ClaudeHook {
		t.Fatalf("failed readback %+v", s)
	}
	if install.Inspect(home, []byte("different executable")).BinaryMatches {
		t.Fatal("stale binary reported current")
	}
	st, e := os.Stat(filepath.Join(home, ".local/share/agent-secrets/agent-secrets"))
	if e != nil || st.Mode().Perm() != 0755 {
		t.Fatal("bad executable mode")
	}
	backups, e := filepath.Glob(filepath.Join(home, ".local/share/agent-secrets/backups/*/*"))
	if e != nil || len(backups) != 4 {
		t.Fatal("missing backups")
	}
	for _, p := range backups {
		st, e := os.Stat(p)
		if e != nil || st.Mode().Perm() != 0600 {
			t.Fatal("backup is not private")
		}
	}
}

func TestInvalidInputIsNotPartiallyInstalled(t *testing.T) {
	home := t.TempDir()
	p := filepath.Join(home, ".claude/settings.json")
	put(t, p, []byte("invalid"))
	if e := install.User(home, []byte("binary")); e == nil {
		t.Fatal("accepted invalid settings")
	}
	if string(read(t, p)) != "invalid" {
		t.Fatal("changed source")
	}
	if _, e := os.Stat(filepath.Join(home, ".codex/hooks.json")); !os.IsNotExist(e) {
		t.Fatal("partial install")
	}
}

func TestSymlinkSettingsRefused(t *testing.T) {
	home := t.TempDir()
	target := filepath.Join(home, "other.json")
	put(t, target, []byte(`{}`))
	if e := os.MkdirAll(filepath.Join(home, ".claude"), 0700); e != nil {
		t.Fatal(e)
	}
	if e := os.Symlink(target, filepath.Join(home, ".claude/settings.json")); e != nil {
		t.Fatal(e)
	}
	if e := install.User(home, []byte("binary")); e == nil {
		t.Fatal("followed settings symlink")
	}
	if string(read(t, target)) != "{}" {
		t.Fatal("changed link target")
	}
}

func TestFreshInstallAndMissingStatus(t *testing.T) {
	home := t.TempDir()
	s := install.Inspect(home, []byte("binary"))
	if s.BinaryMatches || s.CodexHook || s.ClaudeHook {
		t.Fatal("missing install passed")
	}
	if e := install.User(home, []byte("binary")); e != nil {
		t.Fatal(e)
	}
	if _, e := os.Stat(filepath.Join(home, ".codex/config.toml")); !os.IsNotExist(e) {
		t.Fatal("created permissions")
	}
	if e := install.User("relative", []byte("binary")); e == nil {
		t.Fatal("accepted relative home")
	}
	if e := install.User(home, nil); e == nil {
		t.Fatal("accepted empty binary")
	}
}

func TestConcurrentInstallLock(t *testing.T) {
	home := t.TempDir()
	p := filepath.Join(home, ".local/share/agent-secrets/.install-lock")
	put(t, p, []byte(""))
	if e := install.User(home, []byte("binary")); e == nil {
		t.Fatal("ignored active lock")
	}
	if _, e := os.Stat(filepath.Join(home, ".codex/hooks.json")); !os.IsNotExist(e) {
		t.Fatal("changed settings while locked")
	}
}
