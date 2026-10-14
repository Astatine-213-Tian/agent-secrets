package install

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"syscall"
	"testing"

	"github.com/Astatine-213-Tian/agent-secrets/internal/policy"
)

func TestCodexConfigViewFiles(t *testing.T) {
	for _, kind := range []string{"regular", "missing", "malformed", "oversized", "directory", "symlink", "directory symlink", "fifo"} {
		t.Run(kind, func(t *testing.T) {
			home := t.TempDir()
			dir := filepath.Join(home, ".codex")
			if err := os.Mkdir(dir, 0700); err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(dir, "config.toml")
			input := []byte("prevent_idle_sleep = true\nsecret = 'DO_NOT_ECHO'\n")
			var err error
			switch kind {
			case "regular":
				err = os.WriteFile(path, input, 0600)
			case "malformed":
				err = os.WriteFile(path, []byte("'DO_NOT_ECHO"), 0600)
			case "oversized":
				err = os.WriteFile(path, bytes.Repeat([]byte("#"), policy.MaxDocument+1), 0600)
			case "directory":
				err = os.Mkdir(path, 0700)
			case "symlink":
				target := filepath.Join(dir, "auth.json")
				if err = os.WriteFile(target, input, 0600); err == nil {
					err = os.Symlink("auth.json", path)
				}
			case "directory symlink":
				target := filepath.Join(home, "other")
				if err = os.Rename(dir, target); err == nil {
					err = os.Symlink("other", dir)
				}
			case "fifo":
				err = syscall.Mkfifo(path, 0600)
			}
			if err != nil {
				t.Fatal(err)
			}
			out, _, err := RunPlan(context.Background(), home, (policy.Plan{Kind: "read", Cwd: home, Path: path, Reader: "cat"}).Encode())
			if kind != "regular" {
				if err != ErrPlan || len(out) != 0 {
					t.Fatal("unsafe file accepted")
				}
				return
			}
			if err != nil || !bytes.Contains(out, []byte("prevent_idle_sleep = true")) || bytes.Contains(out, []byte("DO_NOT_ECHO")) {
				t.Fatal("regular config not safely displayed")
			}
			after, err := os.ReadFile(path)
			if err != nil || !bytes.Equal(after, input) {
				t.Fatal("source configuration changed")
			}
		})
	}
}

func TestReaderRejectsFileAndExecutionOptions(t *testing.T) {
	home := t.TempDir()
	for _, args := range [][]string{
		{"cat", "/tmp/extra-file"},
		{"sed", "-n", "r /tmp/extra-file"},
		{"sed", "-n", "w /tmp/output"},
		{"sed", "-n", "1e echo executed"},
		{"tail", "-f"},
		{"sh", "-c", "echo executed"},
	} {
		out, _, err := RunPlan(context.Background(), home, (policy.Plan{Kind: "read", Cwd: home, Path: filepath.Join(home, ".codex/config.toml"), Reader: args[0], Args: args[1:]}).Encode())
		if err != ErrPlan || len(out) != 0 {
			t.Fatal("private reader accepted unsafe arguments")
		}
	}
}
