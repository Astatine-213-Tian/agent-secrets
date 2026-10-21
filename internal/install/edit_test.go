package install

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Astatine-213-Tian/agent-secrets/internal/policy"
)

const settings = `{"env": {"GITHUB_PERSONAL_ACCESS_TOKEN": "DO_NOT_ECHO", "SHELL": "/bin/zsh"}}`

func settingsHome(t *testing.T) (home, path string) {
	t.Helper()
	home = t.TempDir()
	path = filepath.Join(home, ".claude/settings.json")
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(settings), 0644); err != nil {
		t.Fatal(err)
	}
	return home, path
}

func TestConfigCommandEditsSettings(t *testing.T) {
	home, path := settingsHome(t)
	if err := ConfigCommand(home, home, []string{"set", "~/.claude/settings.json", "env.MCP_TOOL_TIMEOUT", `"1800000"`}); err != nil {
		t.Fatal(err)
	}
	if err := ConfigCommand(home, filepath.Dir(path), []string{"unset", "settings.json", `["env","SHELL"]`}); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(path)
	want := "{\n  \"env\": {\n    \"GITHUB_PERSONAL_ACCESS_TOKEN\": \"DO_NOT_ECHO\",\n    \"MCP_TOOL_TIMEOUT\": \"1800000\"\n  }\n}\n"
	if err != nil || string(b) != want {
		t.Fatal("settings not edited as requested")
	}
	if st, err := os.Lstat(path); err != nil || st.Mode().Perm() != 0644 {
		t.Fatal("settings mode changed")
	}
	backups, err := filepath.Glob(filepath.Join(home, ".local/share/agent-secrets/backups/*/settings.json"))
	if err != nil || len(backups) != 2 {
		t.Fatal("edits were not backed up")
	}
	found := false
	for _, backup := range backups {
		b, err := os.ReadFile(backup)
		st, serr := os.Stat(backup)
		if err != nil || serr != nil || st.Mode().Perm() != 0600 {
			t.Fatal("backup is not private")
		}
		found = found || string(b) == settings
	}
	if !found {
		t.Fatal("original settings not backed up")
	}
}

func TestConfigCommandRefusesUnsafeEdits(t *testing.T) {
	for _, tt := range []struct {
		name string
		args []string
		want error
	}{
		{"credential", []string{"set", "~/.claude/settings.json", "env.GITHUB_PERSONAL_ACCESS_TOKEN", `"x"`}, ErrEditCredential},
		{"credential subtree", []string{"unset", "~/.claude/settings.json", "env"}, ErrEditCredential},
		{"missing key", []string{"unset", "~/.claude/settings.json", "model"}, ErrEdit},
		{"codex toml", []string{"set", "~/.codex/config.toml", "model", `"o3"`}, ErrEditUnsupported},
		{"npmrc", []string{"set", "~/.npmrc", "registry", `"x"`}, ErrEditUnsupported},
		{"env file", []string{"set", ".env", "A", `"x"`}, ErrEditUnsupported},
		{"ordinary file", []string{"set", "/tmp/settings.json", "A", `"x"`}, ErrEditUnsupported},
		{"auth store", []string{"set", "~/.claude/.credentials.json", "A", `"x"`}, ErrEditUnsupported},
		{"bare string value", []string{"set", "~/.claude/settings.json", "env.A", "1800000x"}, ErrEditUsage},
		{"trailing value", []string{"set", "~/.claude/settings.json", "env.A", `"a" "b"`}, ErrEditUsage},
		{"empty segment", []string{"set", "~/.claude/settings.json", "env..A", `"x"`}, ErrEditUsage},
		{"bad key array", []string{"set", "~/.claude/settings.json", `["env",1]`, `"x"`}, ErrEditUsage},
		{"arity", []string{"set", "~/.claude/settings.json", "env.A"}, ErrEditUsage},
		{"verb", []string{"get", "~/.claude/settings.json", "env.A"}, ErrEditUsage},
		{"none", nil, ErrEditUsage},
	} {
		t.Run(tt.name, func(t *testing.T) {
			home, path := settingsHome(t)
			if err := ConfigCommand(home, home, tt.args); err != tt.want {
				t.Fatalf("got %v", err)
			}
			if b, err := os.ReadFile(path); err != nil || string(b) != settings {
				t.Fatal("refused edit changed settings")
			}
			if strings.Contains(tt.want.Error(), "DO_NOT_ECHO") {
				t.Fatal("message echoed a value")
			}
		})
	}
}

func TestConfigEditKeepsOwnHook(t *testing.T) {
	home, path := settingsHome(t)
	installed, err := Prepare(filepath.Join(home, ".local/share/agent-secrets/agent-secrets"), Documents{Claude: []byte(settings)})
	if err != nil || os.WriteFile(path, installed.Claude, 0600) != nil {
		t.Fatal("cannot register hook")
	}
	for _, args := range [][]string{
		{"unset", path, "hooks"},
		{"unset", path, "hooks.PreToolUse"},
		{"set", path, "hooks.PreToolUse", "[]"},
		{"set", path, "disableAllHooks", "true"},
	} {
		if err := ConfigCommand(home, home, args); err != ErrEditHook {
			t.Fatalf("%v: hook removal accepted", args)
		}
		if b, err := os.ReadFile(path); err != nil || string(b) != string(installed.Claude) {
			t.Fatalf("%v: refused edit changed settings", args)
		}
	}
	// Other hooks remain editable.
	if err := ConfigCommand(home, home, []string{"set", path, "hooks.Stop", `[{"hooks":[{"type":"command","command":"say done"}]}]`}); err != nil {
		t.Fatal(err)
	}
	if b, err := os.ReadFile(path); err != nil || !hasHook(b, claudeCommand(filepath.Join(home, ".local/share/agent-secrets/agent-secrets"))) {
		t.Fatal("own hook lost")
	}
}

func TestConfigEditRefusesLinkedSettings(t *testing.T) {
	home, path := settingsHome(t)
	target := filepath.Join(home, "dotfiles-settings.json")
	if err := os.Rename(path, target); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, path); err != nil {
		t.Fatal(err)
	}
	if err := ConfigCommand(home, home, []string{"set", path, "model", `"x"`}); err != ErrEdit {
		t.Fatal("linked settings edited")
	}
	if b, err := os.ReadFile(target); err != nil || string(b) != settings {
		t.Fatal("link target changed")
	}
}

func TestRunnerStoresPrivateView(t *testing.T) {
	home, path := settingsHome(t)
	out, err := RunPlan(home, (policy.Plan{Kind: "view", Cwd: home, Path: path}).Encode())
	if err != nil || len(out) != 0 {
		t.Fatal("view plan failed or printed output")
	}
	view := policy.ViewPath(home, path)
	b, err := os.ReadFile(view)
	if err != nil || strings.Contains(string(b), "DO_NOT_ECHO") || !strings.Contains(string(b), "/bin/zsh") {
		t.Fatal("view not sanitized")
	}
	if err := os.WriteFile(filepath.Join(home, ".env"), []byte("TOKEN=DO_NOT_ECHO\n"), 0600); err != nil {
		t.Fatal(err)
	}
	forged := filepath.Join(home, ".env")
	if out, err := RunPlan(home, (policy.Plan{Kind: "view", Cwd: home, Path: forged}).Encode()); err != ErrPlan || len(out) != 0 {
		t.Fatal("forged view plan accepted")
	}
	if _, err := os.Lstat(policy.ViewPath(home, forged)); !os.IsNotExist(err) {
		t.Fatal("forged view written")
	}
}
