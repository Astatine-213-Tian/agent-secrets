package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Astatine-213-Tian/agent-secrets/internal/guard"
	"github.com/Astatine-213-Tian/agent-secrets/internal/install"
)

func TestCLI(t *testing.T) {
	for _, tt := range []struct {
		args  []string
		input string
		want  int
	}{
		{nil, "", 0},
		{[]string{"--help"}, "", 0},
		{[]string{"version"}, "", 0},
		{[]string{"unknown"}, "", 1},
		{[]string{"install", "--bad=DO_NOT_ECHO"}, "", 1},
		{[]string{"guard"}, `{"tool_name":"Read","tool_input":{"path":"README.md"}}`, 0},
		{[]string{"guard"}, `{"tool_name":"Read","tool_input":{"path":".env"}}`, 2},
		{[]string{"guard"}, "DO_NOT_ECHO", 2},
		{[]string{"guard", "unexpected"}, "", 2},
		{[]string{"hook", "unexpected"}, "", 2},
		{[]string{"hook"}, "DO_NOT_ECHO", 2},
		{[]string{"__read-codex-config"}, "", 1},
		{[]string{"config-view"}, "", 1},
	} {
		var out, stderr bytes.Buffer
		if got := run(tt.args, strings.NewReader(tt.input), &out, &stderr); got != tt.want {
			t.Fatalf("%v: got %d want %d", tt.args, got, tt.want)
		}
		if strings.Contains(out.String()+stderr.String(), "DO_NOT_ECHO") {
			t.Fatal("input echoed")
		}
		if tt.want == 2 && (out.Len() != 0 || stderr.String() != guard.Reason+"\n") {
			t.Fatal("invalid hook protocol")
		}
	}
}

func TestPrivateReaderCLI(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	dir := filepath.Join(home, ".codex")
	if err := os.Mkdir(dir, 0700); err != nil {
		t.Fatal(err)
	}
	for _, input := range []string{
		"prevent_idle_sleep = true\n[mcp_servers.demo]\nbearer_token_env_var = 'MY_TOKEN'\nenv = { API_KEY = 'DO_NOT_ECHO' }\n",
		"prevent_idle_sleep = true\nbroken = 'DO_NOT_ECHO",
	} {
		if err := os.WriteFile(filepath.Join(dir, "config.toml"), []byte(input), 0600); err != nil {
			t.Fatal(err)
		}
		for _, args := range [][]string{{"__read-codex-config", home, "cat"}, {"__read-codex-config", home, "head", "-n", "100"}} {
			var out, stderr bytes.Buffer
			code := run(args, strings.NewReader(""), &out, &stderr)
			if strings.Contains(out.String()+stderr.String(), "DO_NOT_ECHO") {
				t.Fatal("configuration leaked")
			}
			if strings.Contains(input, "broken") {
				if code != 1 || out.Len() != 0 || stderr.String() != install.ErrConfigView.Error()+"\n" {
					t.Fatal("invalid config protocol")
				}
			} else if code != 0 || stderr.Len() != 0 || !strings.Contains(out.String(), "prevent_idle_sleep = true") || !strings.Contains(out.String(), "MY_TOKEN") || !strings.Contains(out.String(), "[REDACTED]") {
				t.Fatal("sanitized config protocol failed")
			}
		}
	}
}
