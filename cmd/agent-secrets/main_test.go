package main

import (
	"bytes"
	"strings"
	"testing"

	"github.com/Astatine-213-Tian/agent-secrets/internal/guard"
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
