package guard

import (
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
)

var quotedCode = regexp.MustCompile(`(?s)"(?:\\.|[^"\\])*"|'(?:\\.|[^'\\])*'` + "|`(?:\\\\.|[^`\\\\])*`")

// Preserve the literal-command coverage of embedded Python/JavaScript and
// code-mode requests. This is a bounded heuristic, not a language interpreter:
// only recognizable commands or nested quoted source are screened as code.
// A bare regex such as '.*' never becomes a shell glob here.
func (g checker) screenEmbeddedCommands(code string, depth int) (string, bool) {
	view := []byte(code)
	for _, span := range quotedCode.FindAllStringIndex(code, -1) {
		literal := code[span[0]:span[1]]
		value := literal[1 : len(literal)-1]
		if literal[0] == '"' {
			if decoded, err := strconv.Unquote(literal); err == nil {
				value = decoded
			}
		} else {
			value = strings.ReplaceAll(value, `\'`, `'`)
			value = strings.ReplaceAll(value, `\\`, `\`)
		}
		if !commandLiteral(value) && !strings.ContainsAny(value, "\"'") {
			continue
		}
		if g.inspectCode(value, depth+1) {
			return code, true
		}
		if literal[0] == '`' && strings.Contains(value, "${") {
			// JavaScript interpolation is source code, not shell quoting.
			// Keep it visible to the remaining lexical credential checks.
			continue
		}
		// Only remove a literal after all of its code/path checks succeeded;
		// reinterpreting it again would lose the regex roles just established.
		for i := span[0]; i < span[1]; i++ {
			if view[i] != '\n' {
				view[i] = ' '
			}
		}
	}
	return string(view), false
}

func commandLiteral(value string) bool {
	words := strings.Fields(value)
	if len(words) < 2 {
		return false
	}
	switch filepath.Base(words[0]) {
	case "cat", "head", "tail", "less", "more", "sed", "awk", "rg", "grep", "egrep", "fgrep", "ps", "env", "printenv", "command", "exec", "sudo", "sh", "bash", "zsh", "dash", "ksh", "python", "python3", "node":
		return true
	}
	return false
}
