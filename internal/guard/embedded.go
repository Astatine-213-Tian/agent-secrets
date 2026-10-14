package guard

import (
	"regexp"
	"strconv"
	"strings"

	"github.com/Astatine-213-Tian/agent-secrets/internal/policy"
)

var quotedCode = regexp.MustCompile(`(?s)"(?:\\.|[^"\\])*"|'(?:\\.|[^'\\])*'` + "|`(?:\\\\.|[^`\\\\])*`")

var envLookup = regexp.MustCompile(`(?:os\.(?:getenv|Getenv|LookupEnv)|getenv)\s*\(\s*["']([A-Za-z_][A-Za-z_0-9]*)["']|(?:os\.environ|process\.env)\s*\[\s*["']([A-Za-z_][A-Za-z_0-9]*)["']\s*\]|process\.env\.([A-Za-z_][A-Za-z_0-9]*)|os\.environ\.get\s*\(\s*["']([A-Za-z_][A-Za-z_0-9]*)["']`)
var environmentCollection = regexp.MustCompile(`\bos\.environ\b|\bprocess\.env\b|\bos\.Environ\s*\(`)
var executableLiteral = regexp.MustCompile(`(?s)(?:\b(?:cmd|command|script|code)\s*:\s*|(?:os\.system|execSync|exec|eval|subprocess\.(?:run|call|check_output|Popen))\s*\(\s*\[?\s*)$`)
var fileLiteral = regexp.MustCompile(`(?s)(?:\b(?:open|Path|readFile|readFileSync|ReadFile|writeFile|writeFileSync)\s*\(\s*|\b(?:path|file_path|filename)\s*:\s*)$`)

// Source heuristics inspect executed scripts, not file contents or edit text.
// Only explicit environment access and recognizable file/execution APIs are
// interpreted. Arbitrary program data does not become a path or command.
func (g checker) scriptBlocked(code string, depth int) bool {
	if depth > 32 {
		return true
	}
	view := []byte(code)
	quotes := quotedCode.FindAllStringIndex(code, -1)
	mask := func(a, b int) {
		for i := a; i < b; i++ {
			view[i] = ' '
		}
	}
	for _, span := range envLookup.FindAllStringIndex(code, -1) {
		inside := false
		for _, q := range quotes {
			if span[0] >= q[0] && span[0] < q[1] && code[q[0]] != '`' {
				inside = true
				break
			}
		}
		if inside {
			continue
		}
		s := code[span[0]:span[1]]
		m := envLookup.FindStringSubmatch(s)
		name := ""
		for _, v := range m[1:] {
			if v != "" {
				name = v
			}
		}
		if policy.SecretName(name) {
			return true
		}
		mask(span[0], span[1])
	}
	for _, q := range quotes {
		if code[q[0]] != '`' || !strings.Contains(code[q[0]:q[1]], "${") {
			mask(q[0], q[1])
		}
	}
	for _, span := range environmentCollection.FindAllIndex(view, -1) {
		tail := strings.TrimSpace(string(view[span[1]:]))
		if strings.HasPrefix(tail, "[") {
			continue
		} // computed scalar lookup
		if strings.HasPrefix(tail, ".") && !strings.HasPrefix(tail, ".items(") && !strings.HasPrefix(tail, ".values(") && !strings.HasPrefix(tail, ".copy(") {
			continue
		}
		return true
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
