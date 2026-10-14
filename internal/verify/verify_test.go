package verify_test

import (
	"context"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/Astatine-213-Tian/agent-secrets/internal/guard"
	"github.com/Astatine-213-Tian/agent-secrets/internal/install"
	"github.com/Astatine-213-Tian/agent-secrets/internal/verify"
)

func TestMain(m *testing.M) {
	if len(os.Args) == 2 && (os.Args[1] == "guard" || os.Args[1] == "hook") {
		home, _ := os.UserHomeDir()
		cwd, _ := os.Getwd()
		if os.Args[1] == "hook" {
			exe, _ := os.Executable()
			os.Exit(guard.Hook(os.Stdin, os.Stdout, os.Stderr, home, cwd, exe))
		}
		os.Exit(guard.Check(os.Stdin, os.Stderr, home, cwd))
	}
	if len(os.Args) == 3 && os.Args[1] == "__run" {
		home, _ := os.UserHomeDir()
		b, status, err := install.RunPlan(context.Background(), home, os.Args[2])
		if err != nil {
			fmt.Fprintln(os.Stderr, install.ErrPlan)
			os.Exit(1)
		}
		_, _ = os.Stdout.Write(b)
		os.Exit(status)
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
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	r := verify.Process(ctx, exe, home)
	if !r.Passed || len(r.Checks) == 0 {
		t.Fatalf("process contract failed: %+v", r)
	}
}

func TestMissingExecutableFails(t *testing.T) {
	r := verify.Process(context.Background(), "/nonexistent/agent-secrets", "/home/tester")
	if r.Passed {
		t.Fatal("missing binary reported success")
	}
}
