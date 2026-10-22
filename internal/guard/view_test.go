package guard_test

import (
	"bytes"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Astatine-213-Tian/agent-secrets/internal/guard"
	"github.com/Astatine-213-Tian/agent-secrets/internal/policy"
)

const settings = `{"env": {"GITHUB_PERSONAL_ACCESS_TOKEN": "DO_NOT_ECHO", "SHELL": "/bin/zsh"}}`

func readRequest(t *testing.T, home string, args map[string]any) []byte {
	t.Helper()
	request, err := json.Marshal(map[string]any{"tool_name": "Read", "tool_input": args, "cwd": home})
	if err != nil {
		t.Fatal(err)
	}
	return request
}

func TestHookPointsReadAtSanitizedView(t *testing.T) {
	runner, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	home := t.TempDir()
	source := filepath.Join(home, ".claude/settings.json")
	if err := os.MkdirAll(filepath.Dir(source), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(source, []byte(settings), 0600); err != nil {
		t.Fatal(err)
	}
	view := policy.ViewPath(home, source)
	for _, path := range []string{"~/.claude/settings.json", source, ".claude/settings.json", filepath.Join(home, ".claude/../.claude/settings.json")} {
		for _, tt := range []struct {
			hook     func(io.Reader, io.Writer, io.Writer, string, string, string) int
			decision bool
		}{{guard.ClaudeHook, false}, {guard.Hook, true}} {
			args := map[string]any{"file_path": path, "offset": json.Number("9007199254740993"), "limit": 40}
			var out, stderr bytes.Buffer
			if tt.hook(bytes.NewReader(readRequest(t, home, args)), &out, &stderr, home, "/workspace", runner) != 0 || stderr.Len() != 0 {
				t.Fatalf("%s: config read not rewritten", path)
			}
			if strings.Contains(out.String(), "DO_NOT_ECHO") {
				t.Fatal("hook output leaked a credential")
			}
			var result struct {
				Output map[string]any `json:"hookSpecificOutput"`
			}
			decoder := json.NewDecoder(&out)
			decoder.UseNumber()
			if decoder.Decode(&result) != nil || result.Output["hookEventName"] != "PreToolUse" {
				t.Fatalf("%s: invalid rewrite protocol", path)
			}
			if _, decided := result.Output["permissionDecision"]; decided != tt.decision {
				t.Fatalf("%s: permission decision present = %v", path, decided)
			}
			if result.Output["additionalContext"] != guard.ViewContext(runner, true) {
				t.Fatalf("%s: view does not name config set", path)
			}
			updated, _ := result.Output["updatedInput"].(map[string]any)
			if updated["file_path"] != view || updated["offset"] != json.Number("9007199254740993") || updated["limit"] != json.Number("40") || len(updated) != len(args) {
				t.Fatalf("%s: rewrite changed the wrong arguments", path)
			}
		}
	}
	b, err := os.ReadFile(view)
	if err != nil || !bytes.Contains(b, []byte("/bin/zsh")) || !bytes.Contains(b, []byte(policy.Redacted)) || bytes.Contains(b, []byte("DO_NOT_ECHO")) {
		t.Fatal("view is not the sanitized configuration")
	}
	if st, err := os.Stat(view); err != nil || st.Mode().Perm() != 0600 {
		t.Fatal("view is not owner-only")
	}
	if st, err := os.Stat(filepath.Dir(view)); err != nil || st.Mode().Perm() != 0700 {
		t.Fatal("view directory is not owner-only")
	}
	if after, err := os.ReadFile(source); err != nil || string(after) != settings {
		t.Fatal("source configuration changed")
	}
	if guard.Check(bytes.NewReader(readRequest(t, home, map[string]any{"file_path": source})), io.Discard, home, home) != 2 {
		t.Fatal("guard without the bridge allowed a config read")
	}

	// Each read refreshes the one view for its source.
	if err := os.WriteFile(source, []byte(`{"model": "updated"}`), 0600); err != nil {
		t.Fatal(err)
	}
	if guard.ClaudeHook(bytes.NewReader(readRequest(t, home, map[string]any{"file_path": source})), io.Discard, io.Discard, home, home, runner) != 0 {
		t.Fatal("second read not rewritten")
	}
	if b, err := os.ReadFile(view); err != nil || !bytes.Contains(b, []byte("updated")) {
		t.Fatal("view was not refreshed")
	}
	if entries, err := os.ReadDir(filepath.Dir(view)); err != nil || len(entries) != 1 {
		t.Fatal("views accumulated")
	}
}

func TestHookViewOfUneditableConfigNamesNoCommand(t *testing.T) {
	runner, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	for _, tt := range []struct{ name, contents, visible string }{
		{".codex/config.toml", "model = \"gpt\"\n", "gpt"},
		{".claude.json", `{"mcpServers": {"api": {"command": "openrouter", "env": {"OPENROUTER_API_KEY": "DO_NOT_ECHO"}}}}`, "openrouter"},
	} {
		home := t.TempDir()
		source := filepath.Join(home, tt.name)
		if err := os.MkdirAll(filepath.Dir(source), 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(source, []byte(tt.contents), 0600); err != nil {
			t.Fatal(err)
		}
		var out bytes.Buffer
		if guard.ClaudeHook(bytes.NewReader(readRequest(t, home, map[string]any{"file_path": source})), &out, io.Discard, home, home, runner) != 0 {
			t.Fatalf("%s: config read not rewritten", tt.name)
		}
		var result struct {
			Output map[string]any `json:"hookSpecificOutput"`
		}
		if json.Unmarshal(out.Bytes(), &result) != nil || result.Output["additionalContext"] != guard.ViewContext(runner, false) {
			t.Fatalf("%s: view offered config set", tt.name)
		}
		b, err := os.ReadFile(policy.ViewPath(home, source))
		if err != nil || !bytes.Contains(b, []byte(tt.visible)) || bytes.Contains(b, []byte("DO_NOT_ECHO")) {
			t.Fatalf("%s: view is not the sanitized configuration", tt.name)
		}
	}
}

func TestHookDeniesReadWhenViewFails(t *testing.T) {
	runner, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	for _, kind := range []string{"missing", "malformed", "symlink", "no runner", "unsafe sibling"} {
		t.Run(kind, func(t *testing.T) {
			home := t.TempDir()
			source := filepath.Join(home, ".claude/settings.json")
			if err := os.MkdirAll(filepath.Dir(source), 0700); err != nil {
				t.Fatal(err)
			}
			binary := runner
			args := map[string]any{"file_path": source}
			switch kind {
			case "malformed":
				err = os.WriteFile(source, []byte(`{"token": "DO_NOT_ECHO"`), 0600)
			case "symlink":
				target := filepath.Join(home, ".claude/.credentials.json")
				if err = os.WriteFile(target, []byte(settings), 0600); err == nil {
					err = os.Symlink(target, source)
				}
			case "no runner":
				binary = filepath.Join(home, "missing-agent-secrets")
				err = os.WriteFile(source, []byte(settings), 0600)
			case "unsafe sibling":
				args["nested"] = map[string]any{"path": ".env"}
				err = os.WriteFile(source, []byte(settings), 0600)
			}
			if err != nil {
				t.Fatal(err)
			}
			var out, stderr bytes.Buffer
			if guard.ClaudeHook(bytes.NewReader(readRequest(t, home, args)), &out, &stderr, home, home, binary) != 2 || out.Len() != 0 {
				t.Fatal("failed view was not denied")
			}
			if stderr.String() != guard.Reason+"\n" && stderr.String() != guard.ConfigReason+"\n" {
				t.Fatal("denial was not fixed")
			}
			if b, err := os.ReadFile(policy.ViewPath(home, source)); err == nil && bytes.Contains(b, []byte("DO_NOT_ECHO")) {
				t.Fatal("view leaked a credential")
			}
		})
	}
}
