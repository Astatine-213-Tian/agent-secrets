package install

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"syscall"
	"testing"

	"github.com/BurntSushi/toml"
)

func TestRedactCodexConfig(t *testing.T) {
	input := `# DO_NOT_ECHO comment
prevent_idle_sleep = true
model = "gpt-6.1-sol"
model_reasoning_effort = "high"
approval_policy = "on-request"
sandbox_mode = "workspace-write"
model_context_window = 9007199254740993
developer_instructions = """DO_NOT_ECHO
multiline instructions"""
unknown = "DO_NOT_ECHO"
unknown_number = 424242
unknown_date = 2026-10-13
notify = ["DO_NOT_ECHO", "DO_NOT_ECHO"]

[features]
hooks = true
arbitrary_text = "DO_NOT_ECHO"

[profiles.work]
prevent_idle_sleep = false
model_reasoning_effort = "low"
api_key = "DO_NOT_ECHO"

[mcp_servers."中文.service"]
enabled = true
startup_timeout_sec = 2.5
bearer_token_env_var = "MY_TOKEN"
env_vars = ["MY_TOKEN", "PATH"]
url = "https://user:DO_NOT_ECHO@example.com/DO_NOT_ECHO?key=DO_NOT_ECHO#DO_NOT_ECHO"
command = "DO_NOT_ECHO"
args = ["--credential", "DO_NOT_ECHO"]
env = { API_KEY = "DO_NOT_ECHO", INNOCENT_NAME = "DO_NOT_ECHO", NUMBER = 424242 }
http_headers = { Authorization = "Bearer DO_NOT_ECHO", "X-Custom" = "DO_NOT_ECHO" }
env_http_headers = { Authorization = "HEADER_TOKEN" }

[model_providers.custom]
env_key = "PROVIDER_KEY"
env_http_headers = { Authorization = "PROVIDER_HEADER" }
http_headers = { Authorization = "DO_NOT_ECHO" }
base_url = "https://example.com/DO_NOT_ECHO"
query_params = { key = "DO_NOT_ECHO" }
experimental_bearer_token = "DO_NOT_ECHO"
wire_api = "responses"

[[hooks.PreToolUse]]
matcher = "DO_NOT_ECHO"
[[hooks.PreToolUse.hooks]]
type = "DO_NOT_ECHO"
command = "DO_NOT_ECHO"

[unknown_table]
prevent_idle_sleep = "DO_NOT_ECHO"
bearer_token_env_var = "DO_NOT_ECHO"
`
	output, err := RedactCodexConfig(strings.NewReader(input))
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(output, []byte("DO_NOT_ECHO")) || bytes.Contains(output, []byte("424242")) || bytes.Contains(output, []byte("2026-10-13")) {
		t.Fatal("sensitive value survived")
	}
	var got map[string]any
	if err := toml.Unmarshal(output, &got); err != nil {
		t.Fatal("output is not TOML")
	}
	assertConfigValue(t, got, true, "prevent_idle_sleep")
	assertConfigValue(t, got, "gpt-6.1-sol", "model")
	assertConfigValue(t, got, int64(9007199254740993), "model_context_window")
	assertConfigValue(t, got, "on-request", "approval_policy")
	assertConfigValue(t, got, "workspace-write", "sandbox_mode")
	assertConfigValue(t, got, true, "features", "hooks")
	assertConfigValue(t, got, false, "profiles", "work", "prevent_idle_sleep")
	assertConfigValue(t, got, "low", "profiles", "work", "model_reasoning_effort")
	assertConfigValue(t, got, "[REDACTED]", "profiles", "work", "api_key")
	assertConfigValue(t, got, "MY_TOKEN", "mcp_servers", "中文.service", "bearer_token_env_var")
	assertConfigValue(t, got, []any{"MY_TOKEN", "PATH"}, "mcp_servers", "中文.service", "env_vars")
	assertConfigValue(t, got, float64(2.5), "mcp_servers", "中文.service", "startup_timeout_sec")
	assertConfigValue(t, got, "HEADER_TOKEN", "mcp_servers", "中文.service", "env_http_headers", "Authorization")
	assertConfigValue(t, got, "[REDACTED]", "mcp_servers", "中文.service", "http_headers", "X-Custom")
	assertConfigValue(t, got, "[REDACTED]", "mcp_servers", "中文.service", "env", "INNOCENT_NAME")
	assertConfigValue(t, got, []any{"[REDACTED]", "[REDACTED]"}, "mcp_servers", "中文.service", "args")
	assertConfigValue(t, got, "PROVIDER_KEY", "model_providers", "custom", "env_key")
	assertConfigValue(t, got, "PROVIDER_HEADER", "model_providers", "custom", "env_http_headers", "Authorization")
	assertConfigValue(t, got, "responses", "model_providers", "custom", "wire_api")
	assertConfigValue(t, got, "[REDACTED]", "unknown_table", "bearer_token_env_var")
	// Re-encoding a sanitized document should not restore or alter any values.
	again, err := RedactCodexConfig(bytes.NewReader(output))
	if err != nil || !bytes.Equal(output, again) {
		t.Fatal("sanitization is not idempotent")
	}
}

func assertConfigValue(t *testing.T, config map[string]any, want any, path ...string) {
	t.Helper()
	var got any = config
	for _, key := range path {
		m, ok := got.(map[string]any)
		if !ok {
			t.Fatalf("missing table for %v", path)
		}
		got = m[key]
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("unexpected sanitized value at %v", path)
	}
}

func TestConfigSyntaxCannotBypassRedaction(t *testing.T) {
	for _, input := range []string{
		`mcp_servers.demo.env."API\u005fKEY" = "DO_NOT_ECHO"`,
		`mcp_servers = { demo = { env = { model = "DO_NOT_ECHO" } } }`,
		"[mcp_servers.demo]\nargs = ['''DO_NOT_ECHO\nmultiline''']",
		`model = "https://example.com/DO_NOT_ECHO"`,
		`prevent_idle_sleep = "DO_NOT_ECHO"`,
		`model_reasoning_effort = "DO_NOT_ECHO"`,
		`model_reasoning_effort = ["DO_NOT_ECHO"]`,
		"[mcp_servers.demo]\nbearer_token_env_var = 'Bearer DO_NOT_ECHO'",
		"[mcp_servers.demo.env_http_headers]\nAuthorization = '$DO_NOT_ECHO'",
		`unknown = [{ model = "DO_NOT_ECHO" }, { nested = ["DO_NOT_ECHO"] }]`,
		`unknown = [["DO_NOT_ECHO"], ["DO_NOT_ECHO"]]`,
	} {
		out, err := RedactCodexConfig(strings.NewReader(input))
		if err != nil || bytes.Contains(out, []byte("DO_NOT_ECHO")) {
			t.Fatal("syntax-dependent redaction failure")
		}
	}
}

func TestConfigViewFailsWithoutPartialOutput(t *testing.T) {
	for _, input := range []string{
		`prevent_idle_sleep = true` + "\nbroken = \"DO_NOT_ECHO",
		"key = 'DO_NOT_ECHO'\nkey = 'duplicate'",
		strings.Repeat("#", maxConfigInput+1),
		strings.Repeat("nested.", 66) + "value = 'DO_NOT_ECHO'",
		"key = '\xff'",
	} {
		out, err := RedactCodexConfig(strings.NewReader(input))
		if len(out) != 0 || err != ErrConfigView {
			t.Fatal("invalid input did not fail closed")
		}
	}
	out, err := RedactCodexConfig(errorReader{})
	if len(out) != 0 || err != ErrConfigView {
		t.Fatal("reader error did not fail closed")
	}
}

type errorReader struct{}

func (errorReader) Read([]byte) (int, error) { return 0, errors.New("DO_NOT_ECHO") }

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
				err = os.WriteFile(path, bytes.Repeat([]byte("#"), maxConfigInput+1), 0600)
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
			out, err := CodexConfigView(home)
			if kind != "regular" {
				if err != ErrConfigView || len(out) != 0 {
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
		out, err := ReadCodexConfig(context.Background(), home, args[0], args[1:])
		if err != ErrConfigView || len(out) != 0 {
			t.Fatal("private reader accepted unsafe arguments")
		}
	}
}

func FuzzRedactCodexConfig(f *testing.F) {
	for _, input := range []string{"", "prevent_idle_sleep = true", "[mcp_servers.test]\nargs = ['fake-secret']", "[[hooks.PreToolUse]]\ncommand = 'fake-secret'"} {
		f.Add(input)
	}
	f.Fuzz(func(t *testing.T, input string) {
		out, err := RedactCodexConfig(strings.NewReader(input))
		if err != nil {
			if len(out) != 0 || err != ErrConfigView {
				t.Fatal("failed parser emitted data")
			}
			return
		}
		var config map[string]any
		if toml.Unmarshal(out, &config) != nil {
			t.Fatal("invalid sanitized TOML")
		}
		// Every arbitrary string value in an environment must disappear,
		// irrespective of token prefixes, encoding, or TOML escaping.
		var fixture bytes.Buffer
		if toml.NewEncoder(&fixture).Encode(map[string]any{"mcp_servers": map[string]any{"test": map[string]any{"env": map[string]any{"VALUE": input}}}}) != nil {
			return
		}
		clean, e := RedactCodexConfig(&fixture)
		if e != nil {
			return // Size limits and invalid UTF-8 can reject the fixture.
		}
		if toml.Unmarshal(clean, &config) != nil {
			t.Fatal("invalid sanitized fixture")
		}
		assertConfigValue(t, config, "[REDACTED]", "mcp_servers", "test", "env", "VALUE")
	})
}
