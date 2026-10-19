package guard_test

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Astatine-213-Tian/agent-secrets/internal/guard"
)

func TestCommandArgumentRoles(t *testing.T) {
	home, cwd := t.TempDir(), t.TempDir()
	if err := os.WriteFile(filepath.Join(cwd, "README.md"), []byte("public fixture"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(".env", filepath.Join(cwd, "alias")); err != nil {
		t.Fatal(err)
	}
	for _, tt := range []struct {
		command string
		want    int
	}{
		{`rg '.*' README.md`, 0},
		{`rg '⿰(豕|豸).*(兔|免)|⿰.*兔' /tmp/BabelStone-IDS.txt | head -35; rg '𩳏|豸鬼|豸免|豸兔' /tmp/IDS_PUA.TXT`, 0},
		{`rg '⿰(田|曲|由|酉).*(鹿|广|比)' /tmp/cjkvi-ids.txt | head -40`, 0},
		{`grep -nE '.*' README.md`, 0},
		{`rg -n '.env' README.md`, 0},
		{`rg -e '.env' -e '.*' README.md`, 0},
		{`rg --regexp='.env' README.md`, 0},
		{`grep -e.env README.md`, 0},
		{`rg -- '.env' README.md`, 0},
		{`rg -- '.env' "$PWD/README.md"`, 0},
		{`grep -- '.env' "$PWD/README.md"`, 0},
		{`rg -- '.env' "$EXAMPLE_API_KEY"`, 0},
		{`rg -- '.env' "$PWD/.env"`, 2},
		{`rg -A 2 '.env' README.md`, 0},
		{`rg '.*' '.env'`, 2},
		{`rg -e '.*' -f .env README.md`, 2},
		{`rg .env -e public`, 2},
		{`grep .env --regexp=public`, 2},
		{`grep -T public .env`, 2},
		{`grep --color public .env`, 2},
		{`grep --colour public .env`, 2},
		{`grep -T '.env' README.md`, 0},
		{`grep --color '.env' README.md`, 0},
		{`rg -T json '.env' README.md`, 0},
		{`rg --color always '.env' README.md`, 0},
		{`rg alias -e public`, 2},
		{`rg '.*' alias`, 2},
		{`rg '.*' README.md; cat .env`, 2},
		{`rg '.*' README.md < .env`, 2},
		{`rg "$(cat .env)" README.md`, 2},
		{`rg "$(cat .*)" README.md`, 2},
		{`rg "$EXAMPLE_API_KEY" README.md`, 0},
		{`echo "rg '$EXAMPLE_API_KEY' README.md"`, 2},
		{`echo "rg '$(printenv)' README.md"`, 2},
		{`echo "rg '$(env)' README.md"`, 2},
		{`echo "rg '$(cat .env)' README.md"`, 2},
		{`rg --hidden '.env' .`, 0},
		{`rg --hidden '.*' README.md`, 0},
		{`rg .* README.md`, 2},
		{`cat '.env'`, 2},
		{`cat .[e]nv`, 2},
		{`cat .*`, 2},
		{`cat .*(.)`, 2},
		{`cat *(D)`, 2},
		{`cat @(.*|*.md)`, 2},
		{`cat @(README.md|LICENSE)`, 0},
		{`zsh -c 'cat .*(.)'`, 2},
		{`zsh -c 'cat *(D)'`, 2},
		{`cat *`, 2},
		{`cat '.env.example'`, 0},
		{`cat certificate.pem`, 0},
		{`cat public.key`, 0},
		{`cat private-key.pem`, 2},
		{`cat ~/.aws/credentials`, 2},
		{`echo '*'`, 0},
		{`python3 -c "pattern = '.*'; print(pattern)"`, 0},
		{`python3 -c 'import os; os.system("ps e")'`, 2},
		{`python3 -c 'import os; os.system("cat .*")'`, 2},
		{`python3 -c 'import os; os.system("ps -axo pid,etime,command")'`, 0},
		{`await tools.exec_command({cmd: "ps e"})`, 2},
		{`await tools.exec_command({cmd: "cat .*"})`, 2},
		{`await tools.exec_command({cmd: "rg '.*' README.md"})`, 0},
		{"await tools.exec_command({cmd: `ps e`})", 2},
		{"await tools.exec_command({cmd: `cat .*`})", 2},
		{"await tools.exec_command({cmd: `rg '.*' README.md`})", 0},
		{"await tools.exec_command({cmd: `ps -axo pid,etime,command`})", 0},
		{"await tools.exec_command({cmd: `rg '${process.env.EXAMPLE_API_KEY}' README.md`})", 0},
		{"python3 - <<'PY'\nfrom helpers import *\npattern = '.*'\nPY", 0},
		{`sh -c 'cat .*'`, 2},
		{`bash -lc 'rg ".*" README.md'`, 0},
		{"sh <<'SH'\ncat .*\nSH", 2},
		{"sh <<SH\nrg '$EXAMPLE_API_KEY' README.md\nSH", 0},
		{"sh <<SH\nrg '$(printenv)' README.md\nSH", 2},
		{"sh <<SH\nrg '$(env)' README.md\nSH", 2},
		{"sh <<'SH'\nrg '$EXAMPLE_API_KEY' README.md\nSH", 0},
		{"sh <<'SH'\nrg '$(printenv)' README.md\nSH", 0},
		{"echo $(sh <<'SH'; echo done\nprintenv\nSH\n)", 2},
		{"echo $(sh <<'SH'\nrg '.env' README.md\nSH\n)", 0},
		{`ps -axo pid,etime,command`, 0},
		{`ps -axo pid,etime,command | rg 'codex exec.*(output-last-message|read-only)' | cut -c1-270`, 0},
		{`ps -axo pid,command | rg message`, 0},
		{`ps -eo pid,etime,command`, 0},
		{`ps -e`, 0},
		{`ps -A -o command=message`, 0},
		{`ps e`, 2},
		{`ps "$@" e`, 2},
		{`ps $process_options e`, 2},
		{`ps auxe`, 2},
		{`ps axe`, 2},
		{`ps se`, 2},
		{`ps -E`, 2},
		{`ps -axE`, 2},
		{`ps -o pid,command e`, 2},
		{`command ps e`, 2},
		{`command -p ps e`, 2},
		{`sudo ps e`, 2},
		{`sudo -u tester ps e`, 2},
		{`exec -a listing ps e`, 2},
		{`env ps e`, 2},
		{`env -S 'ps e'`, 2},
		{`env -u DISPLAY ps e`, 2},
		{`sh -c 'ps e'`, 2},
		{"echo `echo \\`ps e\\``", 2},
		{"echo `echo \\`cat .*\\``", 2},
		{"echo `echo \\`printenv\\``", 2},
		{"echo `echo \\`ps -axo pid,etime,command\\``", 0},
		{"echo `rg '.*' README.md`", 0},
	} {
		t.Run(tt.command, func(t *testing.T) {
			args := map[string]any{"cmd": tt.command}
			check(t, "exec_command", args, home, cwd, tt.want)
			request, _ := json.Marshal(map[string]any{"tool_name": "exec_command", "tool_input": args, "cwd": cwd})
			var stdout, stderr bytes.Buffer
			if tt.command == `rg --hidden '.env' .` {
				if guard.Hook(bytes.NewReader(request), &stdout, &stderr, home, cwd, "/tmp/agent-secrets") != 0 || stdout.Len() == 0 {
					t.Fatal("recursive search not rewritten")
				}
				return
			}
			if got := guard.Hook(bytes.NewReader(request), &stdout, &stderr, home, cwd, "/tmp/agent-secrets"); got != tt.want || got == 2 && stdout.Len() != 0 {
				t.Fatalf("Hook got %d, want %d", got, tt.want)
			}
			if stdout.Len() > 0 {
				var result struct {
					Output struct {
						Decision string         `json:"permissionDecision"`
						Input    map[string]any `json:"updatedInput"`
					} `json:"hookSpecificOutput"`
				}
				if json.Unmarshal(stdout.Bytes(), &result) != nil || result.Output.Decision != "allow" || result.Output.Input["cmd"] == tt.command {
					t.Fatal("invalid native search rewrite")
				}
			}
		})
	}
}

func TestNestedCommandSubstitutions(t *testing.T) {
	home, cwd := t.TempDir(), t.TempDir()
	command := strings.Repeat("echo $(", 16) + "echo public" + strings.Repeat(")", 16)
	request, _ := json.Marshal(map[string]any{"tool_name": "exec_command", "tool_input": map[string]any{"cmd": command}, "cwd": cwd})
	result := make(chan int, 1)
	go func() {
		var stderr bytes.Buffer
		result <- guard.Check(bytes.NewReader(request), &stderr, home, cwd)
	}()
	select {
	case code := <-result:
		if code != 0 {
			t.Fatalf("safe substitutions denied: %d", code)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("nested substitutions exceeded the installed hook timeout")
	}
}
