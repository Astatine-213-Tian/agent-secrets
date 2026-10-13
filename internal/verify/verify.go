// Package verify tests the actual executable's hook protocol using only
// synthetic arguments and fixtures. It never reads real secrets or uses a model.
package verify

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/Astatine-213-Tian/agent-secrets/internal/guard"
	"github.com/Astatine-213-Tian/agent-secrets/internal/install"
)

type Check struct {
	Name   string `json:"name"`
	Passed bool   `json:"passed"`
}
type Report struct {
	Passed bool    `json:"passed"`
	Checks []Check `json:"checks"`
	Scope  string  `json:"scope"`
}

// Process crosses the same stdin/exit-status seam used by Codex and Claude.
// Child output is compared, never forwarded, even on failure.
func Process(ctx context.Context, binary, home string) Report {
	cases := []struct {
		name, tool string
		args       any
		want       int
	}{
		{"ordinary_read", "Read", map[string]any{"path": "README.md"}, 0},
		{"public_example", "Read", map[string]any{"path": ".env.example"}, 0},
		{"secret_read", "Read", map[string]any{"path": ".env"}, 2},
		{"nested_mcp", "mcp__filesystem__read", map[string]any{"nested": []any{map[string]any{"path": "file:///tmp/%2Eenv.local"}}}, 2},
		{"shell_secret", "Bash", map[string]any{"command": "cat app/.env.production"}, 2},
		{"environment_dump", "Bash", map[string]any{"command": "printenv"}, 2},
		{"credential_reference", "Bash", map[string]any{"command": "echo $EXAMPLE_API_KEY"}, 2},
		{"credential_store", "Read", map[string]any{"path": filepath.Join(home, ".aws/credentials")}, 2},
		{"raw_codex_config", "Read", map[string]any{"path": filepath.Join(home, ".codex/config.toml")}, 2},
		{"codex_auth_store", "Read", map[string]any{"path": filepath.Join(home, ".codex/auth.json")}, 2},
		{"multiple_protected_reads", "Bash", map[string]any{"command": "cat ~/.codex/config.toml; cat ~/.codex/auth.json"}, 2},
		{"normal_development", "Bash", map[string]any{"command": "go test ./..."}, 0},
		{"worker_message", "collaborationspawn_agent", map[string]any{"task_name": "reader", "message": strings.Repeat("Read the supplied book page and preserve its paragraphs. ", 20)}, 0},
		{"worker_nested_secret", "collaborationspawn_agent", map[string]any{"message": "Read the supplied page.", "nested": map[string]any{"path": ".env"}}, 2},
		{"long_code_literal", "exec_command", map[string]any{"cmd": "python3 -c \"text = '" + strings.Repeat("书中文字。", 200) + "'\""}, 0},
		{"long_code_literal_secret", "exec_command", map[string]any{"cmd": "echo '" + strings.Repeat("text", 1024) + "'\ncat .env"}, 2},
		{"python_wildcard_import", "exec_command", map[string]any{"cmd": "python3 - <<'PY'\nfrom page_helpers import *\nPY"}, 0},
		{"python_import_shell_wildcard", "exec_command", map[string]any{"cmd": "python3 - <<'PY'\nfrom page_helpers import *\nPY\ncat *"}, 2},
	}
	r := Report{Passed: true, Scope: "executable hook and sanitized-reader protocols only; not proof of live client hook activation"}
	for _, c := range cases {
		b, _ := json.Marshal(map[string]any{"tool_name": c.tool, "tool_input": c.args})
		r.Checks = append(r.Checks, Check{c.name, probe(ctx, binary, b, c.want)})
	}
	for _, b := range []string{"DO_NOT_ECHO", `[]`, `{}`, `{"tool_name":"Read","tool_input":null}`} {
		r.Checks = append(r.Checks, Check{"malformed_request", probe(ctx, binary, []byte(b), 2)})
	}
	r.Checks = append(r.Checks, configViewProbes(ctx, binary)...)
	for _, c := range r.Checks {
		r.Passed = r.Passed && c.Passed
	}
	return r
}

func configViewProbes(ctx context.Context, binary string) []Check {
	checks := []Check{{Name: "sanitized_config_output"}, {Name: "malformed_config_output"}, {Name: "automatic_cat"}, {Name: "automatic_head"}, {Name: "automatic_tail"}, {Name: "automatic_sed"}, {Name: "config_fixture_cleanup"}}
	home, err := os.MkdirTemp("", "agent-secrets-verify-")
	if err != nil {
		return checks
	}
	defer func() { checks[len(checks)-1].Passed = os.RemoveAll(home) == nil }()
	dir := filepath.Join(home, ".codex")
	if os.Mkdir(dir, 0700) != nil {
		return checks
	}
	fixtures := []struct{ input, stdout, stderr string }{
		{"prevent_idle_sleep = true\napi_key = 'DO_NOT_ECHO'\n", "api_key = \"[REDACTED]\"\nprevent_idle_sleep = true\n", ""},
		{"prevent_idle_sleep = true\nbroken = 'DO_NOT_ECHO", "", install.ErrConfigView.Error() + "\n"},
	}
	for i, fixture := range fixtures {
		if os.WriteFile(filepath.Join(dir, "config.toml"), []byte(fixture.input), 0600) != nil {
			continue
		}
		c := exec.CommandContext(ctx, binary, "__read-codex-config", home, "cat")
		var stdout, stderr bytes.Buffer
		c.Stdout, c.Stderr = &stdout, &stderr
		err := c.Run()
		statusOK := err == nil
		if i == 1 {
			var exitErr *exec.ExitError
			statusOK = errors.As(err, &exitErr) && exitErr.ExitCode() == 1
		}
		checks[i].Passed = statusOK && stdout.String() == fixture.stdout && stderr.String() == fixture.stderr
	}
	if os.WriteFile(filepath.Join(dir, "config.toml"), []byte(fixtures[0].input), 0600) == nil {
		for i, c := range []struct{ command, want string }{
			{"cat ~/.codex/config.toml", fixtures[0].stdout},
			{"head -n 1 ~/.codex/config.toml", "api_key = \"[REDACTED]\"\n"},
			{"tail -n 1 ~/.codex/config.toml", "prevent_idle_sleep = true\n"},
			{"sed -n '2p' ~/.codex/config.toml", "prevent_idle_sleep = true\n"},
		} {
			checks[i+2].Passed = automaticRead(ctx, binary, home, c.command, c.want)
		}
	}
	return checks
}

// Simulate the documented client boundary: feed an ordinary read into the
// hook, apply updatedInput, then execute the rewritten tool in an isolated home.
// This tests the executable end to end; it does not assert live client trust.
func automaticRead(ctx context.Context, binary, home, command, want string) bool {
	request, _ := json.Marshal(map[string]any{"tool_name": "Bash", "tool_input": map[string]any{"command": command}, "cwd": home})
	hook := exec.CommandContext(ctx, binary, "hook")
	hook.Env = append(os.Environ(), "HOME="+home)
	hook.Stdin = bytes.NewReader(request)
	var stdout, stderr bytes.Buffer
	hook.Stdout, hook.Stderr = &stdout, &stderr
	if hook.Run() != nil || stderr.Len() != 0 {
		return false
	}
	var result struct {
		Output struct {
			Event    string `json:"hookEventName"`
			Decision string `json:"permissionDecision"`
			Input    struct {
				Command string `json:"command"`
			} `json:"updatedInput"`
		} `json:"hookSpecificOutput"`
	}
	if json.Unmarshal(stdout.Bytes(), &result) != nil || result.Output.Event != "PreToolUse" || result.Output.Decision != "allow" {
		return false
	}
	if !strings.Contains(result.Output.Input.Command, "'__read-codex-config'") {
		return false
	}
	read := exec.CommandContext(ctx, "/bin/sh", "-c", result.Output.Input.Command)
	read.Env = hook.Env
	read.Dir = home
	stdout.Reset()
	stderr.Reset()
	read.Stdout, read.Stderr = &stdout, &stderr
	return read.Run() == nil && stdout.String() == want && stderr.Len() == 0
}

func probe(ctx context.Context, binary string, input []byte, want int) bool {
	c := exec.CommandContext(ctx, binary, "hook")
	c.Stdin = bytes.NewReader(input)
	var stdout, stderr bytes.Buffer
	c.Stdout = &stdout
	c.Stderr = &stderr
	err := c.Run()
	status := 0
	if err != nil {
		e, ok := err.(*exec.ExitError)
		if !ok {
			return false
		}
		status = e.ExitCode()
	}
	message := ""
	if want == 2 {
		message = guard.Reason + "\n"
	}
	return status == want && stdout.Len() == 0 && stderr.String() == message
}
