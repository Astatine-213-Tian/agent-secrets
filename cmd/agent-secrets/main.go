// agent-secrets is a user-level credential-disclosure hook for local agents.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"time"

	"github.com/Astatine-213-Tian/agent-secrets/internal/guard"
	"github.com/Astatine-213-Tian/agent-secrets/internal/install"
	"github.com/Astatine-213-Tian/agent-secrets/internal/verify"
)

const version = "1.1.0"

func main() { os.Exit(run(os.Args[1:], os.Stdin, os.Stdout, os.Stderr)) }
func run(args []string, in io.Reader, out, errOut io.Writer) int {
	if len(args) == 0 {
		usage(out)
		return 0
	}
	home, e := os.UserHomeDir()
	if e != nil {
		fmt.Fprintln(errOut, "Cannot determine home directory.")
		return 1
	}
	switch args[0] {
	case "guard", "hook":
		if len(args) != 1 {
			fmt.Fprintln(errOut, guard.Reason)
			return 2
		}
		cwd, e := os.Getwd()
		if e != nil {
			fmt.Fprintln(errOut, guard.Reason)
			return 2
		}
		if args[0] == "hook" {
			exe, err := os.Executable()
			if err != nil {
				fmt.Fprintln(errOut, guard.Reason)
				return 2
			}
			return guard.Hook(in, out, errOut, home, cwd, exe)
		}
		return guard.Check(in, errOut, home, cwd)
	case "version", "--version":
		fmt.Fprintf(out, "agent-secrets %s (%s)\n", version, runtime.Version())
		return 0
	case "help", "--help", "-h":
		usage(out)
		return 0
	case "__read-codex-config":
		// Private hook target, never a command agents need to discover or use.
		if len(args) < 3 {
			fmt.Fprintln(errOut, install.ErrConfigView)
			return 1
		}
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		b, e := install.ReadCodexConfig(ctx, args[1], args[2], args[3:])
		if e != nil {
			fmt.Fprintln(errOut, install.ErrConfigView)
			return 1
		}
		if _, e := out.Write(b); e != nil {
			fmt.Fprintln(errOut, install.ErrConfigView)
			return 1
		}
		return 0
	case "install":
		f := flag.NewFlagSet(args[0], flag.ContinueOnError)
		f.SetOutput(io.Discard)
		target := f.String("home", home, "target user home")
		if f.Parse(args[1:]) != nil || f.NArg() != 0 {
			fmt.Fprintln(errOut, "Invalid options; see agent-secrets help.")
			return 1
		}
		abs, e := filepath.Abs(*target)
		if e != nil {
			fmt.Fprintln(errOut, "Invalid home directory.")
			return 1
		}
		{
			if os.Geteuid() == 0 {
				fmt.Fprintln(errOut, "Run install as your normal user, without sudo.")
				return 1
			}
			var source []byte
			var exe string
			exe, e = os.Executable()
			if e == nil {
				source, e = os.ReadFile(exe)
			}
			if e == nil {
				e = install.User(abs, source)
			}
		}
		if e != nil {
			fmt.Fprintln(errOut, "Installation failed. Settings may be inaccessible, malformed, or changed; no values were printed.")
			return 1
		}
		fmt.Fprintln(out, "Go executable and user hooks installed and read back. Restart agents and trust the Codex hook in /hooks.")
		return 0
	case "verify":
		if len(args) != 1 {
			fmt.Fprintln(errOut, "Invalid options; see agent-secrets help.")
			return 1
		}
		exe, e := os.Executable()
		if e != nil {
			fmt.Fprintln(errOut, "Cannot locate executable.")
			return 1
		}
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		report := verify.Process(ctx, exe, home)
		_ = json.NewEncoder(out).Encode(report)
		if !report.Passed {
			return 1
		}
		return 0
	case "status":
		if len(args) != 1 {
			fmt.Fprintln(errOut, "Invalid options; see agent-secrets help.")
			return 1
		}
		exe, e := os.Executable()
		if e != nil {
			fmt.Fprintln(errOut, "Cannot locate executable.")
			return 1
		}
		b, e := os.ReadFile(exe)
		if e != nil {
			fmt.Fprintln(errOut, "Cannot read executable.")
			return 1
		}
		s := install.Inspect(home, b)
		_ = json.NewEncoder(out).Encode(s)
		if !s.Readable || !s.BinaryMatches || !s.CodexHook || !s.ClaudeHook {
			return 1
		}
		return 0
	default:
		fmt.Fprintln(errOut, "Unknown command; see agent-secrets help.")
		return 1
	}
}

func usage(w io.Writer) {
	fmt.Fprintln(w, `agent-secrets — hook-only credential-disclosure protection

  install [--home PATH]             Install Go hooks for both clients
  guard                            Check one JSON hook request on stdin (exit 0 or 2)
  hook                             Screen requests and sanitize common config reads
  verify                           Test this executable with synthetic hook requests
  status                           Read back hooks and installed binary
  version                          Print package and Go versions

New installs never create a permission mode or managed sandbox policy.
Run install as your normal user. Restart clients and trust the hook in Codex /hooks.
Installation needs access to client settings; run it outside an agent sandbox.`)
}
