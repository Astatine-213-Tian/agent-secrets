package guard

import (
	"regexp"
	"strconv"
	"strings"

	"github.com/Astatine-213-Tian/agent-secrets/internal/policy"
)

var quotedCode = regexp.MustCompile(`(?s)"(?:\\.|[^"\\])*"|'(?:\\.|[^'\\])*'` + "|`(?:\\\\.|[^`\\\\])*`")

// A print call whose argument is a credential lookup or the whole environment.
var printedEnvironment = regexp.MustCompile(`\b(?:print|console\.(?:log|info|warn|error))\s*\(\s*(?:(?:os\.getenv|os\.environ\.get)\s*\(\s*["']([A-Za-z_]\w*)["']|os\.environ\s*\[\s*["']([A-Za-z_]\w*)["']\s*\]|process\.env\.([A-Za-z_]\w*)|process\.env\s*\[\s*["']([A-Za-z_]\w*)["']\s*\]|(?:dict\s*\(\s*|JSON\.stringify\s*\(\s*)?(?:os\.environ|process\.env)\s*\))`)

var executableLiteral = regexp.MustCompile(`(?s)(?:\b(?:cmd|command|script|code)\s*:\s*|(?:os\.system|execSync|exec|eval|subprocess\.(?:run|call|check_output|Popen))\s*\(\s*\[?\s*)$`)
var fileLiteral = regexp.MustCompile(`(?s)(?:\b(?:open|Path|readFile|readFileSync|ReadFile|writeFile|writeFileSync)\s*\(\s*|\b(?:path|file_path|filename)\s*:\s*)$`)

// Source heuristics inspect executed scripts, not file contents or edit text.
// Only recognizable file and execution APIs are interpreted. Environment
// lookups are ordinary runtime configuration; only printing a credential
// value or the whole environment directly is denied.
func (g checker) scriptBlocked(code string, depth int) bool {
	if depth > 32 {
		return true
	}
	for _, m := range printedEnvironment.FindAllStringSubmatch(code, -1) {
		name := m[1] + m[2] + m[3] + m[4]
		if name == "" || policy.SecretName(name) {
			return true
		}
	}
	return g.embeddedBlocked(code, depth)
}

// Preserve the literal-command coverage of embedded Python/JavaScript and
// code-mode requests. This is a bounded heuristic, not a language interpreter:
// only recognizable commands or nested quoted source are screened as code.
// A bare regex such as '.*' never becomes a shell glob here.
func (g checker) embeddedBlocked(code string, depth int) bool {
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
		prefix := code[:span[0]]
		if fileLiteral.MatchString(prefix) && g.protected(value) {
			return true
		}
		if !executableLiteral.MatchString(prefix) {
			continue
		}
		if g.inspectCode(value, depth+1) {
			return true
		}
	}
	return false
}
