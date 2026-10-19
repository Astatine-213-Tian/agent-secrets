package guard

import (
	"encoding/json"
	"io"
)

// Hook adds transparent shell-read rewriting to Check. Neither path reads any
// configuration contents. Only the rewritten tool's private runner does that.
// A rewrite carries permissionDecision "allow", which Codex requires with
// updatedInput; Codex still applies its own approval policy afterwards.
func Hook(input io.Reader, stdout, stderr io.Writer, home, cwd, binary string) int {
	return hook(input, stdout, stderr, home, cwd, binary, true)
}

// ClaudeHook is Hook for Claude Code, where "allow" would skip the permission
// prompt for the whole command. A rewrite there omits the decision, so the
// rewritten input goes through Claude Code's normal permission evaluation.
func ClaudeHook(input io.Reader, stdout, stderr io.Writer, home, cwd, binary string) int {
	return hook(input, stdout, stderr, home, cwd, binary, false)
}

func hook(input io.Reader, stdout, stderr io.Writer, home, cwd, binary string, allow bool) (code int) {
	defer func() {
		if recover() != nil {
			_, _ = io.WriteString(stderr, Reason+"\n")
			code = 2
		}
	}()
	data, err := io.ReadAll(io.LimitReader(input, maxInput+1))
	if err != nil || len(data) > maxInput {
		_, _ = io.WriteString(stderr, Reason+"\n")
		return 2
	}
	decision := Evaluate(data, home, cwd, binary)
	if decision.Kind == Rewrite {
		updated := decision.Input
		output := map[string]any{"hookEventName": "PreToolUse", "updatedInput": updated}
		if allow {
			output["permissionDecision"] = "allow"
		}
		b, err := json.Marshal(map[string]any{"hookSpecificOutput": output})
		if err == nil {
			_, err = stdout.Write(append(b, '\n'))
		}
		if err != nil {
			_, _ = io.WriteString(stderr, Reason+"\n")
			return 2
		}
		return 0
	}
	if decision.Kind == Allow {
		return 0
	}
	reason := Reason
	if decision.ConfigView {
		reason = ConfigReason
	}
	_, _ = io.WriteString(stderr, reason+"\n")
	return 2
}
