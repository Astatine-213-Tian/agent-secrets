package install

import (
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
	good := policy.Plan{Kind: "read", Cwd: home, Path: config}
	out, e := RunPlan(home, good.Encode())
	if e != nil || strings.Contains(string(out), "DO_NOT_ECHO") || !strings.Contains(string(out), "visible") {
		t.Fatal("safe plan failed")
	}
	for _, mutate := range []func(*policy.Plan){
		func(p *policy.Plan) { p.Kind = "exec" }, func(p *policy.Plan) { p.Kind = "search" }, func(p *policy.Plan) { p.Path = filepath.Join(home, ".env") },
		func(p *policy.Plan) { p.Cwd = "relative" },
	} {
		p := good
		mutate(&p)
		out, e := RunPlan(home, p.Encode())
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
	if out, e := RunPlan(home, good.Encode()); e != ErrPlan || len(out) > 0 {
		t.Fatal("config symlink accepted")
	}
}
