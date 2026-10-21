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
		out, err := policy.Edit([]byte(document), tt.key, tt.value, tt.remove)
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
		if out, err := policy.Edit([]byte(document), tt.key, "replacement", tt.remove); err != policy.ErrCredentialSetting || out != nil {
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
		if out, err := policy.Edit([]byte(tt.data), tt.key, "x", tt.remove); err != policy.ErrDocument || out != nil {
			t.Fatalf("%v: invalid edit accepted", tt.key)
		}
	}
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
		out, err := policy.Edit([]byte(data), path, "visible", remove)
		if err != nil {
			return
		}
		before, e1 := policy.Sanitize("json", []byte(data))
		after, e2 := policy.Sanitize("json", out)
		if e1 != nil || e2 != nil || strings.Count(string(before), policy.Redacted) != strings.Count(string(after), policy.Redacted) {
			t.Fatal("edit changed hidden values")
		}
		if !remove {
			again, err := policy.Edit(out, path, "visible", false)
			if err != nil || string(again) != string(out) {
				t.Fatal("edit is not repeatable")
			}
		}
	})
}
