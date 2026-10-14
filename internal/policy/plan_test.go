package policy_test

import (
	"github.com/Astatine-213-Tian/agent-secrets/internal/policy"
	"testing"
)

func TestClosedPlanOptions(t *testing.T) {
	for _, args := range [][]string{{"--pre", "program", "pattern", "."}, {"-f", "file", "."}, {"--ignore-file=file", "pattern", "."}, {"--follow", "pattern", "."}, {"--count=oops", "pattern", "."}, {"-lc", "pattern", "."}} {
		if _, ok := policy.ParseSearch(args); ok {
			t.Fatalf("unsafe/invalid option accepted: %v", args)
		}
	}
	for _, args := range [][]string{{"--hidden", "-ni", "pattern", "."}, {"-e", "one", "-e", "two", "-g", "*.go", "."}, {"--", "-pattern", "."}} {
		if _, ok := policy.ParseSearch(args); !ok {
			t.Fatalf("supported search rejected: %v", args)
		}
	}
}

func FuzzPlan(f *testing.F) {
	f.Add((policy.Plan{Kind: "read", Path: "/synthetic/.npmrc", Cwd: "/synthetic", Reader: "cat"}).Encode())
	f.Add((policy.Plan{Kind: "search", Cwd: "/synthetic", Args: []string{"--hidden", "pattern", "."}}).Encode())
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
