package policy

import (
	"path/filepath"
	"regexp"
	"strings"
)

// Protected classifies one absolute lexical or resolved resource name. Public
// exceptions apply only to their own rule, never an unrelated protected parent.
func (l Locations) Protected(p string) bool {
	for _, rule := range l.Paths() {
		if MatchPath(rule, p) || strings.HasPrefix(p, rule+"/") {
			name := filepath.Base(p)
			if (rule == "/**/.env" || rule == "/**/.env.*") && (name == ".env.example" || name == ".env.schema.json") {
				continue
			}
			if rule == filepath.Join(l.Home, ".ssh/id_*") && strings.HasSuffix(name, ".pub") {
				continue
			}
			return true
		}
	}
	return false
}

// MatchPath supports ** across zero or more directories, and * within one.
func MatchPath(pattern, value string) bool {
	var b strings.Builder
	b.WriteByte('^')
	for i := 0; i < len(pattern); i++ {
		switch pattern[i] {
		case '*':
			if i+1 < len(pattern) && pattern[i+1] == '*' {
				i++
				if i+1 < len(pattern) && pattern[i+1] == '/' {
					i++
					b.WriteString(`(?:.*/)?`)
				} else {
					b.WriteString(`.*`)
				}
			} else {
				b.WriteString(`[^/]*`)
			}
		case '?':
			b.WriteString(`[^/]`)
		default:
			b.WriteString(regexp.QuoteMeta(string(pattern[i])))
		}
	}
	b.WriteByte('$')
	return regexp.MustCompile(b.String()).MatchString(value)
}
