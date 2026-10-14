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
	"github.com/Astatine-213-Tian/agent-secrets/internal/policy"
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
		{"metadata_listing", "Bash", map[string]any{"command": "ls -l .env"}, 0},
		{"metadata_nested_read", "Bash", map[string]any{"command": "ls $(cat .env)"}, 2},
		{"public_ssh_key", "Read", map[string]any{"path": "~/.ssh/id_ed25519.pub"}, 0},
		{"ordinary_environment", "Bash", map[string]any{"command": "printenv MAX_TOKENS TOKENIZERS_PARALLELISM"}, 0},
		{"docker_status", "Bash", map[string]any{"command": "docker inspect -f '{{.State.Status}}' app"}, 0},
		{"configured_store", "Bash", map[string]any{"command": "CODEX_HOME=/tmp/synthetic-codex cat /tmp/synthetic-codex/auth.json"}, 2},
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
		{"quoted_search_pattern", "exec_command", map[string]any{"cmd": `rg '⿰(豕|豸).*(兔|免)|⿰.*兔' /tmp/public-ids.txt`}, 0},
		{"credential_name_search", "exec_command", map[string]any{"cmd": `rg -e '.env' README.md`}, 0},
		{"search_protected_operand", "exec_command", map[string]any{"cmd": `rg '.*' '.env'`}, 2},
		{"search_protected_substitution", "exec_command", map[string]any{"cmd": `rg "$(cat .env)" README.md`}, 2},
		{"search_protected_sibling", "exec_command", map[string]any{"cmd": `rg '.*' README.md; cat .env`}, 2},
		{"quoted_wildcard_literal", "exec_command", map[string]any{"cmd": `echo '*'`}, 0},
		{"public_certificate", "exec_command", map[string]any{"cmd": `cat certificate.pem`}, 0},
		{"private_key", "exec_command", map[string]any{"cmd": `cat private-key.pem`}, 2},
		{"process_columns", "exec_command", map[string]any{"cmd": `ps -axo pid,etime,command | rg 'output-last-message'`}, 0},
		{"process_environment_bsd", "exec_command", map[string]any{"cmd": `ps auxe`}, 2},
		{"process_environment_macos", "exec_command", map[string]any{"cmd": `ps -E`}, 2},
		{"grep_flag_protected_operand", "exec_command", map[string]any{"cmd": `grep -T public .env`}, 2},
		{"grep_optional_color_operand", "exec_command", map[string]any{"cmd": `grep --color public .env`}, 2},
		{"process_dynamic_environment", "exec_command", map[string]any{"cmd": `ps "$@" e`}, 2},
		{"embedded_shell_glob", "exec_command", map[string]any{"cmd": `python3 -c 'import os; os.system("cat .*")'`}, 2},
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
	r.Checks = append(r.Checks, searchProbes(ctx, binary)...)
	for _, c := range r.Checks {
		r.Passed = r.Passed && c.Passed
	}
	return r
}

func searchProbes(ctx context.Context, binary string) []Check {
	checks := []Check{{Name: "filtered_recursive_search"}, {Name: "mixed_search_operands"}, {Name: "search_fixture_cleanup"}}
	home, e := os.MkdirTemp("", "agent-secrets-search-verify-")
	if e != nil {
		return checks
	}
	defer func() { checks[len(checks)-1].Passed = os.RemoveAll(home) == nil }()
	for name, value := range map[string]string{"README.md": "needle public\n", ".env": "needle DO_NOT_ECHO\n"} {
		if os.WriteFile(filepath.Join(home, name), []byte(value), 0600) != nil {
			return checks
		}
	}
	checks[0].Passed = automaticRead(ctx, binary, home, "rg --hidden --max-count 1 needle .", "./README.md:needle public\n")
	checks[1].Passed = automaticRead(ctx, binary, home, "true; rg --hidden --no-filename needle README.md .", "needle public\nneedle public\n")
	return checks
}

func configViewProbes(ctx context.Context, binary string) []Check {
	checks := []Check{{Name: "sanitized_config_output"}, {Name: "malformed_config_output"}, {Name: "automatic_cat"}, {Name: "native_head_pipeline"}, {Name: "native_tail_pipeline"}, {Name: "native_sed_pipeline"}, {Name: "config_fixture_cleanup"}}
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
		{"prevent_idle_sleep = true\nbroken = 'DO_NOT_ECHO", "", install.ErrPlan.Error() + "\n"},
	}
	for i, fixture := range fixtures {
		if os.WriteFile(filepath.Join(dir, "config.toml"), []byte(fixture.input), 0600) != nil {
			continue
		}
		c := exec.CommandContext(ctx, binary, "__run", (policy.Plan{Kind: "read", Cwd: home, Path: filepath.Join(dir, "config.toml")}).Encode())
		c.Env = append(os.Environ(), "HOME="+home)
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
			{"cat ~/.codex/config.toml | head -n 1", "api_key = \"[REDACTED]\"\n"},
			{"cat ~/.codex/config.toml | tail -n 1", "prevent_idle_sleep = true\n"},
			{"cat ~/.codex/config.toml | sed -n '2p'", "prevent_idle_sleep = true\n"},
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
	hook.Env = []string{"PATH=" + os.Getenv("PATH"), "HOME=" + home}
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
	if result.Output.Input.Command == "" || result.Output.Input.Command == command {
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
	if status != want || stderr.String() != message {
		return false
	}
	if stdout.Len() == 0 {
		return true
	}
	if want != 0 {
		return false
	}
	var response struct {
		Output struct {
			Event    string         `json:"hookEventName"`
			Decision string         `json:"permissionDecision"`
			Input    map[string]any `json:"updatedInput"`
		} `json:"hookSpecificOutput"`
	}
	return json.Unmarshal(stdout.Bytes(), &response) == nil && response.Output.Event == "PreToolUse" && response.Output.Decision == "allow" && len(response.Output.Input) > 0
}
