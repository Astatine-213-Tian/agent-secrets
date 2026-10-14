package guard

import (
	"encoding/json"
	"io"
)

// Hook adds transparent shell-read rewriting to Check. Neither path reads any
// configuration contents. Only the rewritten tool's private runner does that.
func Hook(input io.Reader, stdout, stderr io.Writer, home, cwd, binary string) (code int) {
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
		b, err := json.Marshal(map[string]any{"hookSpecificOutput": map[string]any{
			"hookEventName":      "PreToolUse",
			"permissionDecision": "allow",
			"updatedInput":       updated,
		}})
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
	_, _ = io.WriteString(stderr, Reason+"\n")
	return 2
}
