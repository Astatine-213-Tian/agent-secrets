package policy

import (
	"path/filepath"
	"sort"
	"strings"
)

// SearchExclusions are native ripgrep globs, not a second search engine.
// Include both cwd-relative and absolute-root spellings. Explicit operands
// are screened separately because ripgrep deliberately ignores globs for them.
func (l Locations) SearchExclusions(cwd string) []string {
	seen := map[string]bool{}
	for _, path := range l.Paths() {
		var patterns []string
		switch path {
		case "/**/.env.*":
			for _, suffix := range exceptNames([]string{"example", "schema.json"}) {
				patterns = append(patterns, "/**/.env."+suffix)
			}
		case filepath.Join(l.Home, ".ssh/id_*"):
			// All suffixes except .pub, including names shorter than .pub.
			prefix := strings.TrimSuffix(path, "*")
			for i := 0; i < len(".pub"); i++ {
				patterns = append(patterns, prefix+strings.Repeat("?", i))
				patterns = append(patterns, prefix+"*[!"+string(".pub"[i])+"]"+".pub"[i+1:])
			}
		default:
			patterns = []string{path}
		}
		for _, pattern := range patterns {
			if strings.HasPrefix(pattern, "/**/") {
				seen["!"+strings.TrimPrefix(pattern, "/")] = true
				continue
			}
			seen["!**/"+strings.TrimPrefix(pattern, "/")] = true
			if relative, err := filepath.Rel(cwd, pattern); err == nil {
				seen["!"+relative] = true
			}
		}
	}
	out := make([]string, 0, len(seen))
	for glob := range seen {
		out = append(out, glob)
	}
	sort.Strings(out)
	return out
}

// Express * minus exact public filenames using negative-only globs. Positive
// globs would change rg's native include/ignore behavior for unrelated files.
func exceptNames(names []string) []string {
	if len(names) == 0 {
		return []string{"*"}
	}
	var out []string
	allowEmpty := true
	groups := map[byte][]string{}
	for _, name := range names {
		if name == "" {
			allowEmpty = false
			continue
		}
		groups[name[0]] = append(groups[name[0]], name[1:])
	}
	if allowEmpty {
		out = append(out, "")
	}
	var chars []byte
	for ch := range groups {
		chars = append(chars, ch)
	}
	sort.Slice(chars, func(i, j int) bool { return chars[i] < chars[j] })
	if len(chars) == 0 {
		return append(out, "?*")
	}
	out = append(out, "[!"+string(chars)+"]*")
	for _, ch := range chars {
		for _, rest := range exceptNames(groups[ch]) {
			out = append(out, string(ch)+rest)
		}
	}
	return out
}
