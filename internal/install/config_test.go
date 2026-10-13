package install_test

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/Astatine-213-Tian/agent-secrets/internal/install"
)

func TestPreparePreservesSettingsAndRepeats(t *testing.T) {
	in := install.Documents{
		Codex:  []byte(`{"counter":9007199254740993,"hooks":{"PreToolUse":[{"matcher":"Bash","hooks":[{"command":"other"}]}],"Stop":[{"hooks":[{"command":"keep-stop"}]}]}}`),
		Claude: []byte(`{"model":"keep","env":{"EXAMPLE_API_KEY":"synthetic"},"permissions":{"allow":["Read(src/**)"]},"sandbox":{"enabled":false}}`),
	}
	out, e := install.Prepare("/home/tester/.local/share/agent-secrets/agent-secrets", in)
	if e != nil {
		t.Fatal(e)
	}
	for _, s := range []string{"9007199254740993", "other", "keep-stop"} {
		if !bytes.Contains(out.Codex, []byte(s)) {
			t.Fatalf("lost %s", s)
		}
	}
	var c map[string]any
	if json.Unmarshal(out.Claude, &c) != nil {
		t.Fatal("invalid output")
	}
	if c["model"] != "keep" || c["sandbox"].(map[string]any)["enabled"] != false || c["env"].(map[string]any)["EXAMPLE_API_KEY"] != "synthetic" {
		t.Fatal("unrelated settings changed")
	}
	if bytes.Contains(out.Codex, []byte("permissions")) || bytes.Contains(out.Claude, []byte("denyRead")) {
		t.Fatal("installed native policy")
	}
	again, e := install.Prepare("/home/tester/.local/share/agent-secrets/agent-secrets", out)
	if e != nil {
		t.Fatal(e)
	}
	if !bytes.Equal(out.Codex, again.Codex) || !bytes.Equal(out.Claude, again.Claude) {
		t.Fatal("not idempotent")
	}
}

func TestPrepareRejectsMalformedSettings(t *testing.T) {
	for _, s := range []string{"invalid DO_NOT_ECHO", "null", "[]", "{} {}", `{"hooks":[]}`, `{"hooks":{"PreToolUse":{}}}`, `{"hooks":{"PreToolUse":[null]}}`, `{"hooks":{"PreToolUse":[{"hooks":42}]}}`} {
		for _, d := range []install.Documents{{Codex: []byte(s)}, {Claude: []byte(s)}} {
			if _, e := install.Prepare("/bin/agent-secrets", d); e == nil {
				t.Fatal("accepted invalid settings")
			} else if strings.Contains(e.Error(), "DO_NOT_ECHO") {
				t.Fatal("diagnostic reflected input")
			}
		}
	}
}

func TestReplacesOwnHandlerInSharedGroup(t *testing.T) {
	in := install.Documents{Codex: []byte(`{"hooks":{"PreToolUse":[{"matcher":"Bash","hooks":[{"command":"'/bin/agent-secrets' guard"},{"command":"other"}]}]}}`)}
	out, e := install.Prepare("/bin/agent-secrets", in)
	if e != nil {
		t.Fatal(e)
	}
	if strings.Count(string(out.Codex), "'/bin/agent-secrets' hook") != 1 || bytes.Contains(out.Codex, []byte("'/bin/agent-secrets' guard")) || !bytes.Contains(out.Codex, []byte("other")) {
		t.Fatal("lost other handler or duplicated own handler")
	}
}

func TestQuotedInstallationPath(t *testing.T) {
	out, e := install.Prepare("/home/a user's directory/agent-secrets", install.Documents{})
	if e != nil {
		t.Fatal(e)
	}
	var m map[string]any
	_ = json.Unmarshal(out.Codex, &m)
	groups := m["hooks"].(map[string]any)["PreToolUse"].([]any)
	h := groups[0].(map[string]any)["hooks"].([]any)[0].(map[string]any)
	if h["command"] != `'/home/a user'"'"'s directory/agent-secrets' hook` {
		t.Fatal("unsafe shell quoting")
	}
}

func FuzzPrepare(f *testing.F) {
	for _, s := range []string{`{}`, `{"hooks":{"PreToolUse":[]}}`, `null`, `{"env":{"KEEP":"yes"}}`} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		out, e := install.Prepare("/bin/agent-secrets", install.Documents{Codex: []byte(s), Claude: []byte(s)})
		if e == nil && (!json.Valid(out.Codex) || !json.Valid(out.Claude)) {
			t.Fatal("invalid output")
		}
	})
}
