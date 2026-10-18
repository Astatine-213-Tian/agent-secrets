package guard_test

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Astatine-213-Tian/agent-secrets/internal/guard"
)

func check(t *testing.T, tool string, args any, home, cwd string, want int) {
	t.Helper()
	b, e := json.Marshal(map[string]any{"tool_name": tool, "tool_input": args, "cwd": cwd})
	if e != nil {
		t.Fatal(e)
	}
	var stderr bytes.Buffer
	got := guard.Check(bytes.NewReader(b), &stderr, home, cwd)
	if got != want {
		t.Fatalf("%s: got exit %d, want %d (args %#v)", tool, got, want, args)
	}
	expected := ""
	if want == 2 {
		expected = guard.Reason + "\n"
	}
	if stderr.String() != expected {
		t.Fatal("unexpected hook output")
	}
}

func TestRequests(t *testing.T) {
	home, cwd := "/home/tester", "/workspace"
	for _, tt := range []struct {
		name, tool string
		args       any
		want       int
	}{
		{"shell", "Bash", map[string]any{"command": "cat service/.env"}, 2},
		{"inline python", "Bash", map[string]any{"command": `python -c 'open("/home/tester/.aws/credentials").read()'`}, 2},
		{"image", "view_image", map[string]any{"path": ".env"}, 2},
		{"encoded", "read_resource", map[string]any{"uri": "file:///tmp/%2Eenv"}, 2},
		{"paths", "mcp__fs__read", map[string]any{"paths": []any{"README.md", ".env"}}, 2},
		{"nested", "functions", map[string]any{"nested": []any{map[string]any{"cmd": "cat .env.local"}}}, 2},
		{"stdin", "write_stdin", map[string]any{"chars": "cat .env\n"}, 2},
		{"wildcard", "Bash", map[string]any{"command": "cat .[e]nv"}, 2},
		{"patch destination", "apply_patch", map[string]any{"input": "*** Update File: .env\n+FAKE=value"}, 2},
		{"patch rename", "apply_patch", map[string]any{"input": "*** Update File: old.txt\n*** Move to: .env\n"}, 2},
		{"patch content", "apply_patch", map[string]any{"command": "*** Update File: src/app.go\n+_ = os.Getenv(\"TOKEN\")"}, 0},
		{"edit content", "Edit", map[string]any{"file_path": "app.go", "new_string": "read(\".env\")"}, 0},
		{"ordinary path", "Read", map[string]any{"path": "src/main.go"}, 0},
		{"example", "Read", map[string]any{"path": ".env.example"}, 0},
		{"schema", "Read", map[string]any{"path": ".env.schema.json"}, 0},
		{"example suffix", "Read", map[string]any{"path": ".env.example.local"}, 2},
		{"certificate", "Read", map[string]any{"path": "/etc/ssl/cert.pem"}, 0},
		{"private key", "Read", map[string]any{"path": "/repo/private-key.pem"}, 2},
		{"browser state", "Read", map[string]any{"path": "/repo/browser-profiles/site/state.json"}, 2},
		{"browser direct", "Read", map[string]any{"path": "/repo/browser-profiles/state.json"}, 2},
		{"settings", "Read", map[string]any{"path": "/home/tester/.codex/config.toml"}, 2},
		{"auth store", "Read", map[string]any{"path": "~/.codex/auth.json"}, 2},
		{"home expansion", "Bash", map[string]any{"command": "cat $HOME/.aws/credentials"}, 2},
		{"braced home", "Bash", map[string]any{"command": "cat ${HOME}/.config/gh/hosts.yml"}, 2},
		{"ssh glob", "Read", map[string]any{"path": "~/.ssh/id_custom"}, 2},
		{"git", "Bash", map[string]any{"command": "git status --short"}, 0},
		{"inventory", "Bash", map[string]any{"command": `rg --files --hidden -g "*.go"`}, 0},
		{"broad scan", "Bash", map[string]any{"command": "rg --hidden TOKEN ."}, 0},
		{"raw input", "Bash", "cat .env", 2},
		{"metadata", "Bash", map[string]any{"command": "go test ./...", "description": "does not read .env"}, 0},
	} {
		t.Run(tt.name, func(t *testing.T) { check(t, tt.tool, tt.args, home, cwd, tt.want) })
	}
}

func TestEnvironmentCommands(t *testing.T) {
	for _, command := range []string{"env", "printenv", "/usr/bin/printenv", "export -p", "set -x; ./app", `echo "$NEW_API_KEY"`, `echo "${OTHER_TOKEN}"`, `python -c "print(os.environ)"`, `node -e "console.log(process.env)"`, "gh auth token", "docker inspect app", "docker compose config", "security find-generic-password -w -s service", "sudo printenv"} {
		t.Run(command, func(t *testing.T) {
			check(t, "Bash", map[string]any{"command": command}, "/home/tester", "/workspace", 2)
		})
	}
}

func TestWorkerMessages(t *testing.T) {
	home, cwd := t.TempDir(), t.TempDir()
	for _, tool := range []string{"collaboration.spawn_agent", "collaborationspawn_agent", "collaboration.send_message", "collaboration.followup_task"} {
		t.Run(tool, func(t *testing.T) {
			for _, message := range []string{
				strings.Repeat("Read the supplied book page and preserve its paragraph structure. ", 20),
				strings.Repeat("请直接阅读图片，保留原文和段落，并记录无法辨认的文字。", 20),
				"Read /tmp/book/page-0004.png.\nSave the independent reading to /tmp/book/reading-a.txt.\n" + strings.Repeat("Keep all footnotes. ", 30),
				"Explain why reading .env is unsafe; do not open it.",
			} {
				check(t, tool, map[string]any{"task_name": "reader", "message": message}, home, cwd, 0)
			}
			// Prose handling must not exempt sibling or nested execution arguments.
			check(t, tool, map[string]any{"message": "Read the supplied page.", "path": ".env"}, home, cwd, 2)
			check(t, tool, map[string]any{"message": "Read the supplied page.", "nested": map[string]any{"cmd": "printenv"}}, home, cwd, 2)
		})
	}
}

func TestLongCodeLiterals(t *testing.T) {
	home, cwd := t.TempDir(), t.TempDir()
	for _, prose := range []string{strings.Repeat("text", 1024), strings.Repeat("书中文字与标点。", 150)} {
		command := "python3 - <<'PY'\ntext = '" + prose + "'\nprint(len(text))\nPY"
		check(t, "exec_command", map[string]any{"cmd": command}, home, cwd, 0)
		// A non-path literal does not exempt other code or protected paths.
		check(t, "exec_command", map[string]any{"cmd": command + "\ncat .env"}, home, cwd, 2)
		check(t, "exec_command", map[string]any{"cmd": command + "\nprintenv"}, home, cwd, 2)
		check(t, "exec_command", map[string]any{"cmd": "cat " + filepath.Join(home, ".aws/credentials", prose)}, home, cwd, 2)
		check(t, "Read", map[string]any{"path": prose}, home, cwd, 2)
	}
}

func TestPythonWildcardImports(t *testing.T) {
	home, cwd := t.TempDir(), t.TempDir()
	for _, statement := range []string{"from page_helpers import *", "from package.helpers import *", "from .helpers import *", "from .. import *", "  from helpers import * # shared functions"} {
		command := "python3 - <<'PY'\n" + statement + "\nPY"
		check(t, "exec_command", map[string]any{"cmd": command}, home, cwd, 0)
		check(t, "exec_command", map[string]any{"cmd": command + "\ncat *"}, home, cwd, 2)
		check(t, "exec_command", map[string]any{"cmd": command + "\ncat .env"}, home, cwd, 2)
		check(t, "exec_command", map[string]any{"cmd": command + "\nprintenv"}, home, cwd, 2)
	}
	// Parsed as a shell invocation of an unknown "from" command, this has
	// no recognized content-read operation. A filename alone is not denied.
	check(t, "exec_command", map[string]any{"cmd": "from helpers import * .env"}, home, cwd, 0)
	for _, command := range []string{"cat *", "from helpers import *; cat *", "from helpers import *\nopen('.env').read()"} {
		check(t, "exec_command", map[string]any{"cmd": command}, home, cwd, 2)
	}
}

func TestSymlinks(t *testing.T) {
	dir := t.TempDir()
	for _, pair := range [][2]string{{"secret", ".env"}, {"alias", "real"}, {"cycle", "cycle"}, {"public", "public.txt"}} {
		if e := os.Symlink(pair[1], filepath.Join(dir, pair[0])); e != nil {
			t.Fatal(e)
		}
	}
	for _, p := range []string{"secret", "alias/.env.local", "cycle"} {
		check(t, "Read", map[string]any{"path": p}, "/home/tester", dir, 2)
	}
	check(t, "Read", map[string]any{"path": "public"}, "/home/tester", dir, 0)
}

func TestMalformedAndOversizedFailClosed(t *testing.T) {
	for _, input := range []string{"DO_NOT_ECHO", "[]", "null", "{}", `{"tool_name":"Read","tool_input":null}`, `{"tool_name":"Read","tool_input":42}`, `{"tool_name":"Read","tool_input":{}} {}`, strings.Repeat(" ", 4<<20+1)} {
		var stderr bytes.Buffer
		if guard.Check(strings.NewReader(input), &stderr, "/home/tester", "/workspace") != 2 {
			t.Fatal("accepted malformed input")
		}
		if stderr.String() != guard.Reason+"\n" {
			t.Fatal("input leaked in diagnostic")
		}
	}
}

func FuzzCheck(f *testing.F) {
	for _, seed := range []string{`{"tool_name":"Bash","tool_input":{"command":"git status"}}`, `{"tool_name":"Read","tool_input":{"path":".env"}}`, `[]`, ``} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, s string) {
		var out bytes.Buffer
		code := guard.Check(strings.NewReader(s), &out, "/home/tester", "/workspace")
		if code != 0 && code != 2 {
			t.Fatal("invalid exit")
		}
		if code == 0 && out.Len() != 0 || code == 2 && out.String() != guard.Reason+"\n" {
			t.Fatal("unexpected output")
		}
	})
}
