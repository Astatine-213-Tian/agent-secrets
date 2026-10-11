package verify_test

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/Astatine-213-Tian/agent-secrets/internal/guard"
	"github.com/Astatine-213-Tian/agent-secrets/internal/verify"
)

func TestMain(m *testing.M) {
	if len(os.Args) == 2 && os.Args[1] == "guard" {
		home, _ := os.UserHomeDir()
		cwd, _ := os.Getwd()
		os.Exit(guard.Check(os.Stdin, os.Stderr, home, cwd))
	}
	os.Exit(m.Run())
}

func TestProcess(t *testing.T) {
	exe, e := os.Executable()
	if e != nil {
		t.Fatal(e)
	}
	home, e := os.UserHomeDir()
	if e != nil {
		t.Fatal(e)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	r := verify.Process(ctx, exe, home)
	if !r.Passed || len(r.Checks) != 13 {
		t.Fatalf("process contract failed: %+v", r)
	}
}

func TestMissingExecutableFails(t *testing.T) {
	r := verify.Process(context.Background(), "/nonexistent/agent-secrets", "/home/tester")
	if r.Passed {
		t.Fatal("missing binary reported success")
	}
}
