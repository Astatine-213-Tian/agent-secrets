package guard_test

import (
	"os"
	"testing"

	"github.com/Astatine-213-Tian/agent-secrets/internal/install"
)

// The hook starts the private runner as `BINARY __run PLAN`. Tests pass this
// test binary as BINARY, so it serves as that runner.
func TestMain(m *testing.M) {
	if len(os.Args) == 3 && os.Args[1] == "__run" {
		home, _ := os.UserHomeDir()
		b, err := install.RunPlan(home, os.Args[2])
		if err != nil {
			os.Exit(1)
		}
		_, _ = os.Stdout.Write(b)
		os.Exit(0)
	}
	os.Exit(m.Run())
}
