package policy_test

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/Astatine-213-Tian/agent-secrets/internal/policy"
)

const document = `{
  "env": {"GITHUB_PERSONAL_ACCESS_TOKEN": "DO_NOT_ECHO", "SHELL": "/bin/zsh"},
  "hooks": {"Stop": [{"command": "make && say done"}]},
  "counter": 9007199254740993,
  "mcpServers": {"demo": {"args": ["--token", "DO_NOT_ECHO"], "headers": {"Accept": "json"}}},
  "registry": "https://user:DO_NOT_ECHO@example.test/"
}`

func TestEditChangesOrdinarySettings(t *testing.T) {
	for _, tt := range []struct {
		key    []string
		value  any
		remove bool
		check  func(map[string]any) bool
	}{
		{[]string{"env", "MCP_TOOL_TIMEOUT"}, "1800000", false, func(m map[string]any) bool {
			return m["env"].(map[string]any)["MCP_TOOL_TIMEOUT"] == "1800000"
		}},
		{[]string{"env", "SHELL"}, "/bin/bash", false, func(m map[string]any) bool { return m["env"].(map[string]any)["SHELL"] == "/bin/bash" }},
		{[]string{"env", "SHELL"}, nil, true, func(m map[string]any) bool { _, ok := m["env"].(map[string]any)["SHELL"]; return !ok }},
		{[]string{"a.b", "c", "d"}, json.Number("1"), false, func(m map[string]any) bool {
			return m["a.b"].(map[string]any)["c"].(map[string]any)["d"] == json.Number("1")
		}},
		{[]string{"mcpServers", "demo", "headers", "Accept"}, "text", false, func(m map[string]any) bool {
			return m["mcpServers"].(map[string]any)["demo"].(map[string]any)["headers"].(map[string]any)["Accept"] == "text"
		}},
	} {
		out, err := policy.Edit(policy.ClaudeSettings, []byte(document), tt.key, tt.value, tt.remove)
		if err != nil {
			t.Fatalf("%v: %v", tt.key, err)
		}
		var m map[string]any
		d := json.NewDecoder(strings.NewReader(string(out)))
		d.UseNumber()
		if d.Decode(&m) != nil || !tt.check(m) {
			t.Fatalf("%v: edit not applied", tt.key)
		}
		// Unrelated values, credentials, and number precision survive.
		if m["env"].(map[string]any)["GITHUB_PERSONAL_ACCESS_TOKEN"] != "DO_NOT_ECHO" || m["counter"] != json.Number("9007199254740993") || m["registry"] != "https://user:DO_NOT_ECHO@example.test/" {
			t.Fatalf("%v: unrelated settings changed", tt.key)
		}
		if !strings.Contains(string(out), `"make && say done"`) || !strings.HasSuffix(string(out), "}\n") {
			t.Fatalf("%v: encoding escaped or truncated values", tt.key)
		}
	}
}

func TestEditRefusesCredentialSettings(t *testing.T) {
	for _, tt := range []struct {
		key    []string
		remove bool
	}{
		{[]string{"env", "GITHUB_PERSONAL_ACCESS_TOKEN"}, false},
		{[]string{"env", "GITHUB_PERSONAL_ACCESS_TOKEN"}, true},
		{[]string{"env", "NEW_API_KEY"}, false},
		{[]string{"env"}, false},
		{[]string{"env"}, true},
		{[]string{"mcpServers", "demo"}, true},
		{[]string{"mcpServers", "demo", "args"}, false},
		{[]string{"mcpServers", "demo", "headers", "Authorization"}, false},
		{[]string{"credentials", "note"}, false},
		{[]string{"registry"}, false},
	} {
		if out, err := policy.Edit(policy.ClaudeSettings, []byte(document), tt.key, "replacement", tt.remove); err != policy.ErrCredentialSetting || out != nil {
			t.Fatalf("%v: credential setting changed", tt.key)
		}
	}
}

func TestEditRejectsInvalidTargets(t *testing.T) {
	for _, tt := range []struct {
		data   string
		key    []string
		remove bool
	}{
		{document, []string{"env", "SHELL", "nested"}, false},
		{document, []string{"mcpServers", "demo", "args", "0"}, false},
		{document, []string{"missing"}, true},
		{document, []string{"missing", "child"}, true},
		{document, []string{"env", ""}, false},
		{document, []string{"env", "\x81"}, false},
		{document, nil, false},
		{`{"token": "DO_NOT_ECHO"`, []string{"model"}, false},
		{`[]`, []string{"model"}, false},
		{`{} {}`, []string{"model"}, false},
	} {
		if out, err := policy.Edit(policy.ClaudeSettings, []byte(tt.data), tt.key, "x", tt.remove); err != policy.ErrDocument || out != nil {
			t.Fatalf("%v: invalid edit accepted", tt.key)
		}
	}
}

func TestEditScopesSandboxDeclarationsToClaudeSettings(t *testing.T) {
	data := []byte(`{"sandbox": {"credentials": {"note": "visible"}}}`)
	key := []string{"sandbox", "credentials", "note"}
	if _, err := policy.Edit(policy.ClaudeSettings, data, key, "changed", false); err != nil {
		t.Fatalf("Claude settings: %v", err)
	}
	for _, config := range []policy.Config{policy.DockerConfig, policy.ClaudeState} {
		if out, err := policy.Edit(config, data, key, "changed", false); err != policy.ErrCredentialSetting || out != nil {
			t.Fatalf("%s: got %v", config, err)
		}
	}
	for _, config := range []policy.Config{policy.NPMConfig, ""} {
		if out, err := policy.Edit(config, []byte(`{"a": 1}`), []string{"a"}, 2, false); err != policy.ErrDocument || out != nil {
			t.Fatalf("%q: edited an unsupported config", config)
		}
	}
}

const codexDocument = `# comment
model = "gpt"
cutoff = 07:32:00
day = 2024-05-01

[[profiles]]
name = "fast"

[mcp_servers.demo]
command = "npx"
args = ["-y", "--token", "DO_NOT_ECHO"]
env = { API_KEY = "DO_NOT_ECHO", MODE = "dev" }
`

func TestEditChangesCodexConfig(t *testing.T) {
	for _, tt := range []struct {
		key    []string
		value  any
		remove bool
		want   string
	}{
		{[]string{"model"}, "o3", false, `model = "o3"`},
		{[]string{"mcp_servers", "demo", "startup_timeout_sec"}, json.Number("30"), false, "startup_timeout_sec = 30"},
		{[]string{"temperature"}, json.Number("0.5"), false, "temperature = 0.5"},
		{[]string{"features"}, map[string]any{"web_search": true, "depth": json.Number("2")}, false, "depth = 2"},
		{[]string{"mcp_servers", "demo", "env", "MODE"}, nil, true, ""},
		{[]string{"cutoff"}, nil, true, ""},
	} {
		out, err := policy.Edit(policy.CodexConfig, []byte(codexDocument), tt.key, tt.value, tt.remove)
		if err != nil {
			t.Fatalf("%v: %v", tt.key, err)
		}
		text := string(out)
		if !strings.Contains(text, tt.want) || tt.remove && strings.Contains(text, tt.key[len(tt.key)-1]+" =") {
			t.Fatalf("%v: edit not applied", tt.key)
		}
		// Unrelated values, credentials, local times, and arrays of tables survive.
		for _, kept := range []string{`API_KEY = "DO_NOT_ECHO"`, `"--token", "DO_NOT_ECHO"`, "day = 2024-05-01", "[[profiles]]"} {
			if !strings.Contains(text, kept) {
				t.Fatalf("%v: lost %q", tt.key, kept)
			}
		}
		if tt.key[0] != "cutoff" && !strings.Contains(text, "cutoff = 07:32:00") {
			t.Fatalf("%v: local time changed", tt.key)
		}
	}
}

func TestEditRefusesCodexCredentialsAndNull(t *testing.T) {
	for _, tt := range []struct {
		key    []string
		value  any
		remove bool
		want   error
	}{
		{[]string{"mcp_servers", "demo", "env", "API_KEY"}, "x", false, policy.ErrCredentialSetting},
		{[]string{"mcp_servers", "demo", "args"}, []any{}, false, policy.ErrCredentialSetting},
		{[]string{"mcp_servers", "demo"}, nil, true, policy.ErrCredentialSetting},
		{[]string{"model"}, nil, false, policy.ErrDocument},
		{[]string{"features"}, map[string]any{"a": nil}, false, policy.ErrDocument},
		{[]string{"model", "nested"}, "x", false, policy.ErrDocument},
	} {
		if out, err := policy.Edit(policy.CodexConfig, []byte(codexDocument), tt.key, tt.value, tt.remove); err != tt.want || out != nil {
			t.Fatalf("%v: got %v", tt.key, err)
		}
	}
	if out, err := policy.Edit(policy.CodexConfig, []byte("model = "), []string{"model"}, "x", false); err != policy.ErrDocument || out != nil {
		t.Fatal("malformed TOML edited")
	}
}

// An accepted TOML edit never changes what the sanitized view hides, and
// repeating it changes nothing.
func FuzzEditTOML(f *testing.F) {
	f.Add(codexDocument, "model", false)
	f.Add(codexDocument, "mcp_servers.demo.command", false)
	f.Add(codexDocument, "mcp_servers.demo.env.MODE", true)
	f.Add("a = 1979-05-27T07:32:00\n[t]\nb = [1, 2]\n", "t.c", false)
	f.Fuzz(func(t *testing.T, data, key string, remove bool) {
		path := strings.Split(key, ".")
		out, err := policy.Edit(policy.CodexConfig, []byte(data), path, "visible", remove)
		if err != nil {
			return
		}
		before, e1 := policy.Sanitize(policy.CodexConfig, []byte(data))
		after, e2 := policy.Sanitize(policy.CodexConfig, out)
		if e1 != nil || e2 != nil || strings.Count(string(before), policy.Redacted) != strings.Count(string(after), policy.Redacted) {
			t.Fatal("edit changed hidden values")
		}
		if !remove {
			again, err := policy.Edit(policy.CodexConfig, out, path, "visible", false)
			if err != nil || string(again) != string(out) {
				t.Fatal("edit is not repeatable")
			}
		}
	})
}

// An accepted edit of a visible setting never changes what the sanitized view
// hides, and repeating it changes nothing.
func FuzzEdit(f *testing.F) {
	f.Add(document, "env.MCP_TOOL_TIMEOUT", false)
	f.Add(document, "mcpServers.demo.headers.Accept", false)
	f.Add(document, "env.SHELL", true)
	f.Add(`{"args": ["--token", "s"], "a": {"b": 1}}`, "a.b", false)
	f.Fuzz(func(t *testing.T, data, key string, remove bool) {
		path := strings.Split(key, ".")
		out, err := policy.Edit(policy.ClaudeSettings, []byte(data), path, "visible", remove)
		if err != nil {
			return
		}
		before, e1 := policy.Sanitize(policy.ClaudeSettings, []byte(data))
		after, e2 := policy.Sanitize(policy.ClaudeSettings, out)
		if e1 != nil || e2 != nil || strings.Count(string(before), policy.Redacted) != strings.Count(string(after), policy.Redacted) {
			t.Fatal("edit changed hidden values")
		}
		if !remove {
			again, err := policy.Edit(policy.ClaudeSettings, out, path, "visible", false)
			if err != nil || string(again) != string(out) {
				t.Fatal("edit is not repeatable")
			}
		}
	})
}
