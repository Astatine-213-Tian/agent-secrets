// Package verify tests the actual executable's hook protocol using only
// synthetic arguments. It doesn't read secrets or require agent/model access.
package verify

import (
	"bytes"
	"context"
	"encoding/json"
	"os/exec"
	"path/filepath"

	"github.com/Astatine-213-Tian/agent-secrets/internal/guard"
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
		{"normal_development", "Bash", map[string]any{"command": "go test ./..."}, 0},
	}
	r := Report{Passed: true, Scope: "executable protocol only; not proof of live client hook activation"}
	for _, c := range cases {
		b, _ := json.Marshal(map[string]any{"tool_name": c.tool, "tool_input": c.args})
		r.Checks = append(r.Checks, Check{c.name, probe(ctx, binary, b, c.want)})
	}
	for _, b := range []string{"DO_NOT_ECHO", `[]`, `{}`, `{"tool_name":"Read","tool_input":null}`} {
		r.Checks = append(r.Checks, Check{"malformed_request", probe(ctx, binary, []byte(b), 2)})
	}
	for _, c := range r.Checks {
		r.Passed = r.Passed && c.Passed
	}
	return r
}

func probe(ctx context.Context, binary string, input []byte, want int) bool {
	c := exec.CommandContext(ctx, binary, "guard")
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
