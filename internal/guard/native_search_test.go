package guard_test

import (
	"bytes"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Astatine-213-Tian/agent-secrets/internal/guard"
)

func TestNativeSearch(t *testing.T) {
	if _, err := exec.LookPath("rg"); err != nil {
		t.Fatal("ripgrep is required for search verification")
	}
	home := t.TempDir()
	for name, content := range map[string]string{
		"normal.txt": "needle public\nneedle second\n",
		".env":       "needle DO_NOT_ECHO\n", "nested/.env.local": "needle DO_NOT_ECHO\n",
		".env.example": "needle example\n", ".env.schema.json": "needle schema\n",
		".env.exampl": "needle DO_NOT_ECHO\n", ".env.schema.json.local": "needle DO_NOT_ECHO\n",
		".ssh/id_custom": "needle DO_NOT_ECHO\n", ".ssh/id_custom.pub": "needle public-key\n",
		".codex/config.toml": "needle DO_NOT_ECHO\n", ".aws/credentials": "needle DO_NOT_ECHO\n",
		"nested/.npmrc": "needle DO_NOT_ECHO\n", ".local/share/agent-secrets/backups/example/settings.json": "needle DO_NOT_ECHO\n",
	} {
		path := filepath.Join(home, name)
		if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(content), 0600); err != nil {
			t.Fatal(err)
		}
	}
	for _, command := range []string{
		"rg --hidden --no-ignore --max-count 1 --sort path -n needle .",
		"printf 'ready\\n'; rg --hidden -m1 --json needle . | cat",
		"rg --hidden --context 1 --color never needle . > result.txt; cat result.txt",
		"rg --hidden -g '*' --max-count=1 needle .",
		"rg --hidden --max-count 1 -- needle .",
		"rg --hidden -S --no-filename --max-count 1 needle .",
		"(cd .codex); rg --hidden needle .",
	} {
		t.Run(command, func(t *testing.T) {
			updated := rewrittenSearch(t, command, home, home)
			if strings.Contains(updated, "__run") {
				t.Fatal("search still uses private runner")
			}
			cmd := exec.Command("/bin/sh", "-c", updated)
			cmd.Dir = home
			cmd.Env = []string{"PATH=" + os.Getenv("PATH"), "HOME=" + home}
			out, err := cmd.CombinedOutput()
			if err != nil {
				t.Fatalf("native search failed: %v: %s", err, out)
			}
			if strings.Contains(string(out), "DO_NOT_ECHO") {
				t.Fatal("credential fixture leaked")
			}
			for _, want := range []string{"public", "example", "schema", "public-key"} {
				if !strings.Contains(string(out), want) {
					t.Errorf("missing ordinary result %s", want)
				}
			}
			_ = os.Remove(filepath.Join(home, "result.txt"))
		})
	}
	for _, cwd := range []string{home, filepath.Dir(home), filepath.Join(home, ".codex")} {
		command := "rg --hidden -l needle '" + home + "'"
		if cwd == filepath.Join(home, ".codex") {
			command = "rg --hidden needle ."
		}
		updated := rewrittenSearch(t, command, home, cwd)
		cmd := exec.Command("/bin/sh", "-c", updated)
		cmd.Dir = cwd
		cmd.Env = []string{"PATH=" + os.Getenv("PATH"), "HOME=" + home}
		out, _ := cmd.CombinedOutput()
		if strings.Contains(string(out), "DO_NOT_ECHO") || strings.Contains(string(out), "config.toml") || strings.Contains(string(out), "credentials") {
			t.Fatalf("protected result from cwd %s", cwd)
		}
	}
	updated := rewrittenSearch(t, "cd .codex && rg needle .", home, home)
	cmd := exec.Command("/bin/sh", "-c", updated)
	cmd.Dir = home
	cmd.Env = []string{"PATH=" + os.Getenv("PATH"), "HOME=" + home}
	if out, _ := cmd.CombinedOutput(); len(out) != 0 {
		t.Fatal("search after directory change disclosed config")
	}
}

func TestNativeRecursiveGrep(t *testing.T) {
	home := t.TempDir()
	project := filepath.Join(home, "project")
	for name, content := range map[string]string{
		"README.md": "needle public\n", ".env.example": "needle example\n", ".env.schema.json": "needle schema\n",
		".env": "needle DO_NOT_ECHO\n", "nested/.env.local": "needle DO_NOT_ECHO\n", ".env.exampl": "needle DO_NOT_ECHO\n",
		".envrc": "needle DO_NOT_ECHO\n", "certs/client.p12": "needle DO_NOT_ECHO\n", "nested/.npmrc": "needle DO_NOT_ECHO\n",
		"browser-profiles/site/state.json": "needle DO_NOT_ECHO\n",
	} {
		path := filepath.Join(project, name)
		if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(content), 0600); err != nil {
			t.Fatal(err)
		}
	}
	for _, command := range []string{"grep -rn needle .", "grep -R needle .", "grep -rl needle . | sort", "egrep -r -e needle .", "grep --recursive needle", "cd nested && grep -r needle .."} {
		t.Run(command, func(t *testing.T) {
			updated := rewrittenSearch(t, command, home, project)
			cmd := exec.Command("/bin/sh", "-c", updated)
			cmd.Dir = project
			cmd.Env = []string{"PATH=" + os.Getenv("PATH"), "HOME=" + home}
			out, err := cmd.CombinedOutput()
			if err != nil {
				t.Fatalf("native grep failed: %v: %s", err, out)
			}
			if strings.Contains(string(out), "DO_NOT_ECHO") || strings.Contains(string(out), ".env.local") {
				t.Fatalf("credential fixture leaked: %s", out)
			}
			if !strings.Contains(string(out), "README.md") || !strings.Contains(string(out), ".env.example") {
				t.Fatalf("missing ordinary results: %s", out)
			}
		})
	}
	// Base-name exclusions cannot express home credential stores.
	for _, tt := range []struct {
		command, cwd string
		want         int
	}{
		{"grep -r needle ~", project, 2}, {"grep -rn needle " + filepath.Join(home, ".aws"), project, 2},
		{"cd ~ && grep -r needle", project, 2}, {"cd && grep -r needle .", project, 2}, {"grep -r needle", home, 2}, {"rgrep needle ~", project, 2},
		{"grep -rn needle nested", project, 0}, {"grep -r needle", project, 0}, {"grep -n needle README.md", project, 0},
	} {
		check(t, "exec_command", map[string]any{"cmd": tt.command}, home, tt.cwd, tt.want)
	}
	input, _ := json.Marshal(map[string]any{"tool_name": "exec_command", "cwd": project, "tool_input": map[string]any{"cmd": "grep -n needle README.md"}})
	var out, stderr bytes.Buffer
	if guard.Hook(bytes.NewReader(input), &out, &stderr, home, project, "/tmp/binary") != 0 || out.Len() != 0 {
		t.Fatal("non-recursive grep rewritten")
	}
}

func TestBookflowDiagnosticAndNativeOptions(t *testing.T) {
	home := t.TempDir()
	for _, command := range []string{
		"ps -axo pid,command | rg 'Google Chrome.*remote-debugging|browser-harness.*daemon|daemon_server' | cut -c 1-400; rg -n 'CDP|websocket|9222|DevToolsActivePort' '" + home + "/.browser-harness' '" + home + "/.config/browser-harness' -g '*.json' -g '*.log' --max-count 2",
		"rg --future-output-option -e '.env' .",
		"rg --json -g '.env*' -e '.env' .",
		"rg -f patterns.txt .",
		"rg --pre cat needle .",
	} {
		_ = rewrittenSearch(t, command, home, home)
	}
	check(t, "exec_command", map[string]any{"cmd": "agent-browser doctor --offline --quick"}, home, home, 0)
}

func rewrittenSearch(t *testing.T, command, home, cwd string) string {
	t.Helper()
	input, _ := json.Marshal(map[string]any{"tool_name": "exec_command", "cwd": cwd, "tool_input": map[string]any{"cmd": command, "max_output_tokens": 2200}})
	var out, stderr bytes.Buffer
	if code := guard.Hook(bytes.NewReader(input), &out, &stderr, home, cwd, "/tmp/binary"); code != 0 {
		t.Fatalf("ordinary native command denied: %s", command)
	}
	var response struct {
		Output struct {
			Input map[string]any `json:"updatedInput"`
		} `json:"hookSpecificOutput"`
	}
	if err := json.Unmarshal(out.Bytes(), &response); err != nil {
		t.Fatalf("missing rewrite: %v", err)
	}
	if response.Output.Input["max_output_tokens"] != float64(2200) {
		t.Fatal("metadata lost")
	}
	return response.Output.Input["cmd"].(string)
}

func TestNativeSearchKeepsExplicitLeakChecks(t *testing.T) {
	home := t.TempDir()
	for _, command := range []string{
		"rg --max-count 1 needle .env", "rg --hidden needle .; cat .env",
		"rg -f .env .", "rg --file=.env .", "rg needle . < .env",
		"rg -f~/.codex/auth.json .", "rg --ignore-file ~/.aws/credentials needle .",
		"rg --pre 'cat .env' needle .",
		"rg needle .; printenv API_KEY",
		"rg --files --sort path -f .env",
		"rg -e --files .env",
	} {
		input, _ := json.Marshal(map[string]any{"tool_name": "exec_command", "tool_input": map[string]any{"cmd": command}})
		var out, stderr bytes.Buffer
		if code := guard.Hook(bytes.NewReader(input), &out, &stderr, home, home, "/tmp/binary"); code != 2 || out.Len() != 0 {
			t.Errorf("explicit leak accepted: %s", command)
		}
	}
}
