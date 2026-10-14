package policy_test

import (
	"encoding/base64"
	"github.com/Astatine-213-Tian/agent-secrets/internal/policy"
	"testing"
)

func FuzzPlan(f *testing.F) {
	f.Add((policy.Plan{Kind: "read", Path: "/synthetic/.npmrc", Cwd: "/synthetic"}).Encode())
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
