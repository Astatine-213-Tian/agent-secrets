package install

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Astatine-213-Tian/agent-secrets/internal/policy"
)

func TestRunnerConfigAndForgedPlans(t *testing.T) {
	home := t.TempDir()
	dir := filepath.Join(home, ".codex")
	if e := os.Mkdir(dir, 0700); e != nil {
		t.Fatal(e)
	}
	config := filepath.Join(dir, "config.toml")
	if e := os.WriteFile(config, []byte("future = 'visible'\napi_key = 'DO_NOT_ECHO'\n"), 0600); e != nil {
		t.Fatal(e)
	}
	good := policy.Plan{Kind: "read", Cwd: home, Path: config, Reader: "cat"}
	out, code, e := RunPlan(context.Background(), home, good.Encode())
	if e != nil || code != 0 || strings.Contains(string(out), "DO_NOT_ECHO") || !strings.Contains(string(out), "visible") {
		t.Fatal("safe plan failed")
	}
	for _, mutate := range []func(*policy.Plan){
		func(p *policy.Plan) { p.Kind = "exec" }, func(p *policy.Plan) { p.Path = filepath.Join(home, ".env") },
		func(p *policy.Plan) { p.Reader = "sh"; p.Args = []string{"-c", "echo unsafe"} },
		func(p *policy.Plan) { p.Reader = "cat"; p.Args = []string{filepath.Join(home, ".env")} },
		func(p *policy.Plan) { p.Reader = "sed"; p.Args = []string{"-n", "r /tmp/unsafe"} },
		func(p *policy.Plan) { p.Cwd = "relative" },
	} {
		p := good
		mutate(&p)
		out, _, e := RunPlan(context.Background(), home, p.Encode())
		if e != ErrPlan || len(out) > 0 {
			t.Fatal("forged plan accepted")
		}
	}
	if e := os.Remove(config); e != nil {
		t.Fatal(e)
	}
	if e := os.Symlink("auth.json", config); e != nil {
		t.Fatal(e)
	}
	if e := os.WriteFile(filepath.Join(dir, "auth.json"), []byte("future='DO_NOT_ECHO'"), 0600); e != nil {
		t.Fatal(e)
	}
	if out, _, e := RunPlan(context.Background(), home, good.Encode()); e != ErrPlan || len(out) > 0 {
		t.Fatal("config symlink accepted")
	}
}

func TestSearchFiltersActualReads(t *testing.T) {
	if ripgrep() == "" {
		t.Skip("ripgrep unavailable")
	}
	home := t.TempDir()
	for path, data := range map[string]string{
		"README.md": "needle public\n", "nested/other.txt": "needle another\n",
		".env": "needle DO_NOT_ECHO\n", "nested/.npmrc": "needle DO_NOT_ECHO\n",
		".codex/config.toml": "needle DO_NOT_ECHO\n", ".ssh/id_custom": "needle DO_NOT_ECHO\n",
		".ssh/id_custom.pub": "needle public-key\n", ".env.example": "needle example\n",
	} {
		p := filepath.Join(home, path)
		if e := os.MkdirAll(filepath.Dir(p), 0700); e != nil {
			t.Fatal(e)
		}
		if e := os.WriteFile(p, []byte(data), 0600); e != nil {
			t.Fatal(e)
		}
	}
	if e := os.Symlink(".env", filepath.Join(home, "alias")); e != nil {
		t.Fatal(e)
	}
	for _, args := range [][]string{{"--hidden", "--no-ignore", "-n", "needle", "."}, {"--hidden", "needle", "README.md", "."}} {
		p := policy.Plan{Kind: "search", Cwd: home, Args: args}
		out, code, e := RunPlan(context.Background(), home, p.Encode())
		if e != nil || code != 0 || strings.Contains(string(out), "DO_NOT_ECHO") {
			t.Fatal("search unsafe or failed")
		}
		for _, want := range []string{"README.md:", "nested/other.txt:", "public-key", "example"} {
			if !strings.Contains(string(out), want) {
				t.Errorf("ordinary result missing: %s", want)
			}
		}
	}
	for _, args := range [][]string{{"--hidden", "needle", ".", ".env"}, {"--pre", "cat .env", "needle", "."}, {"-f", ".env", "."}, {"needle", "alias"}, {"--follow", "needle", "."}} {
		out, _, e := RunPlan(context.Background(), home, policy.Plan{Kind: "search", Cwd: home, Args: args}.Encode())
		if e != ErrPlan || len(out) > 0 {
			t.Fatal("unsafe search plan accepted")
		}
	}
	out, code, e := RunPlan(context.Background(), home, policy.Plan{Kind: "search", Cwd: home, Args: []string{"no-match", "."}}.Encode())
	if e != nil || code != 1 || len(out) > 0 {
		t.Fatal("no-match status lost")
	}
}
