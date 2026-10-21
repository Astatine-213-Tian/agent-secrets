package policy_test

import (
	"encoding/base64"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Astatine-213-Tian/agent-secrets/internal/policy"
)

func FuzzPlan(f *testing.F) {
	f.Add((policy.Plan{Kind: "read", Path: "/synthetic/.npmrc", Cwd: "/synthetic"}).Encode())
	f.Add((policy.Plan{Kind: "view", Path: "/synthetic/.claude/settings.json", Cwd: "/synthetic"}).Encode())
	f.Add((policy.Plan{Kind: "search", Cwd: "/synthetic"}).Encode())
	f.Add("")
	f.Fuzz(func(t *testing.T, s string) {
		p, ok := policy.DecodePlan(s)
		if !ok {
			return
		}
		again, ok := policy.DecodePlan(p.Encode())
		if !ok || p.Encode() != again.Encode() {
			t.Fatal("accepted plan does not round trip")
		}
	})
}

func TestPlansCannotExecuteCommands(t *testing.T) {
	for _, raw := range []string{
		`{"kind":"read","path":"/synthetic/.npmrc","cwd":"/synthetic","reader":"cat"}`,
		`{"kind":"read","path":"/synthetic/.npmrc","cwd":"/synthetic","args":["-n"]}`,
		`{"kind":"read","path":"relative","cwd":"/synthetic"}`,
		`{"kind":"search","path":"/synthetic/.npmrc","cwd":"/synthetic"}`,
	} {
		if _, ok := policy.DecodePlan(base64.RawURLEncoding.EncodeToString([]byte(raw))); ok {
			t.Fatal("accepted executable or invalid plan")
		}
	}
}

func TestViewPathsAreStableAndUnprotected(t *testing.T) {
	l := policy.Locations{Home: "/home/tester"}
	seen := map[string]bool{}
	for _, source := range []string{"/home/tester/.claude/settings.json", "/home/tester/.codex/config.toml", "/home/tester/.npmrc", "/work/.npmrc", "/home/tester/.docker/config.json"} {
		view := policy.ViewPath(l.Home, source)
		if view != policy.ViewPath(l.Home, source+"/") || seen[view] || l.Protected(view) || !strings.HasPrefix(view, "/home/tester/.cache/agent-secrets/views/") {
			t.Fatalf("%s: unsafe or unstable view path", source)
		}
		if strings.HasPrefix(filepath.Base(view), ".") {
			t.Fatalf("%s: hidden view name", source)
		}
		seen[view] = true
	}
}
