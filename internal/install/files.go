package install

import (
	"bytes"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"time"
)

var ErrFiles = errors.New("installation failed: settings could not be safely read, backed up, or written; no file contents are printed")
var ErrConflict = errors.New("installation refused: settings changed during preparation; retry with fresh input")

// User installs the executable and two user-level hooks, with private backups
// and live readback. It never reads or changes permission or managed policies.
func User(home string, source []byte) error {
	if !filepath.IsAbs(home) || home == "/" || len(source) == 0 {
		return ErrFiles
	}
	target := filepath.Join(home, ".local/share/agent-secrets")
	if os.MkdirAll(target, 0700) != nil {
		return ErrFiles
	}
	lockPath := filepath.Join(target, ".install-lock")
	lock, e := os.OpenFile(lockPath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if e != nil {
		return errors.New("installation is locked or inaccessible; remove .install-lock only if no installer is running")
	}
	_ = lock.Close()
	defer os.Remove(lockPath)
	paths := []string{filepath.Join(home, ".codex/hooks.json"), filepath.Join(home, ".claude/settings.json")}
	raw := make([][]byte, 2)
	for i, p := range paths {
		raw[i], e = readOptional(p)
		if e != nil {
			return e
		}
	}
	binary := filepath.Join(target, "agent-secrets")
	out, e := Prepare(binary, Documents{raw[0], raw[1]})
	if e != nil {
		return e
	}
	backup := filepath.Join(target, "backups", fmt.Sprintf("%d", time.Now().UnixNano()))
	for i, b := range raw {
		if b != nil {
			if e = atomicWrite(filepath.Join(backup, fmt.Sprintf("%d-%s", i, filepath.Base(paths[i]))), b, 0600); e != nil {
				return e
			}
		}
	}
	for i, p := range paths {
		now, e := readOptional(p)
		if e != nil || !bytes.Equal(now, raw[i]) {
			return ErrConflict
		}
	}
	if e = atomicWrite(binary, source, 0755); e != nil {
		return e
	}
	for i, b := range [][]byte{out.Codex, out.Claude} {
		if e = atomicWrite(paths[i], b, 0600); e != nil {
			for j := i - 1; j >= 0; j-- {
				if raw[j] == nil {
					_ = os.Remove(paths[j])
				} else {
					_ = atomicWrite(paths[j], raw[j], 0600)
				}
			}
			return e
		}
	}
	return nil
}

type Status struct {
	BinaryMatches bool `json:"binary_matches"`
	CodexHook     bool `json:"codex_hook_configured"`
	ClaudeHook    bool `json:"claude_hook_configured"`
	Readable      bool `json:"settings_readable"`
}

// Inspect reports installed bytes and registrations, not live client trust.
func Inspect(home string, source []byte) Status {
	binary := filepath.Join(home, ".local/share/agent-secrets/agent-secrets")
	b, e := readOptional(binary)
	s := Status{Readable: e == nil, BinaryMatches: e == nil && len(source) > 0 && bytes.Equal(b, source)}
	b, e = readOptional(filepath.Join(home, ".codex/hooks.json"))
	s.Readable = s.Readable && e == nil
	s.CodexHook = e == nil && hasHook(b, command(binary))
	b, e = readOptional(filepath.Join(home, ".claude/settings.json"))
	s.Readable = s.Readable && e == nil
	s.ClaudeHook = e == nil && hasHook(b, claudeCommand(binary))
	return s
}
func readOptional(p string) ([]byte, error) {
	st, e := os.Lstat(p)
	if os.IsNotExist(e) {
		return nil, nil
	}
	if e != nil || !st.Mode().IsRegular() {
		return nil, ErrFiles
	}
	b, e := os.ReadFile(p)
	if e != nil {
		return nil, ErrFiles
	}
	return b, nil
}
func atomicWrite(p string, b []byte, mode fs.FileMode) error {
	if os.MkdirAll(filepath.Dir(p), 0700) != nil {
		return ErrFiles
	}
	if st, e := os.Lstat(p); e == nil && !st.Mode().IsRegular() {
		return ErrFiles
	} else if e != nil && !os.IsNotExist(e) {
		return ErrFiles
	}
	f, e := os.CreateTemp(filepath.Dir(p), ".agent-secrets-*")
	if e != nil {
		return ErrFiles
	}
	name := f.Name()
	defer os.Remove(name)
	if f.Chmod(mode) != nil {
		_ = f.Close()
		return ErrFiles
	}
	if _, e = f.Write(b); e == nil {
		e = f.Sync()
	}
	closeErr := f.Close()
	if e != nil || closeErr != nil {
		return ErrFiles
	}
	if os.Rename(name, p) != nil {
		return ErrFiles
	}
	got, e := os.ReadFile(p)
	if e != nil || !bytes.Equal(got, b) {
		return ErrFiles
	}
	return nil
}
