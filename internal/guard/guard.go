// Package guard screens tool arguments without reading credential contents.
// Its argument heuristics do not provide file isolation.
package guard

import (
	"encoding/json"
	"errors"
	"io"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"

	"github.com/Astatine-213-Tian/agent-secrets/internal/policy"
)

const Reason = "Blocked by global credential protection: secret files and environment values must not enter agent transcripts."
const maxInput = 4 << 20

var envRef = regexp.MustCompile(`(?:^|[^\w.\-])(\.env(?:\.[\w*?\[\]-]+)*)(?:$|[^\w.\-])`)
var envAccess = regexp.MustCompile(`os\.(?:environ|getenv|Environ|Getenv|LookupEnv)|process\.env|\b(?:getenv|environ)\s*\(`)
var shellVar = regexp.MustCompile(`\$\{?([A-Za-z_][A-Za-z_0-9]*)`)
var envDump = regexp.MustCompile(`(?:^|[;|&\n(])\s*(?:(?:command|exec|sudo)\s+)?(?:/\S*/)?(?:printenv\b|env\s*(?:$|[;|&\n])|set\s*(?:$|-[a-zA-Z]*x)|(?:export|declare|typeset)\s+-p)`)
var credentialCommand = regexp.MustCompile(`\b(?:ps\s+[^\n]*[eE]|security\s+find-(?:generic|internet)-password|gh\s+auth\s+token|docker\s+(?:container\s+)?inspect|(?:docker\s+)?compose\s+config)\b`)
var patchPath = regexp.MustCompile(`(?m)^\*\*\* (?:Add File|Update File|Delete File|Move to): (.+)\r?$`)
var pythonWildcardImport = regexp.MustCompile(`(?m)^([ \t]*from[ \t]+(?:\.*[A-Za-z_]\w*(?:\.[A-Za-z_]\w*)*|\.+)[ \t]+import[ \t]+)\*([ \t]*(?:#[^\r\n]*)?\r?$)`)

// Check consumes one hook request. Malformed, oversized, or uninspectable input
// is denied. Output is a fixed message; request content is never reflected.
func Check(input io.Reader, stderr io.Writer, home, cwd string) (exitCode int) {
	deny := true
	defer func() {
		if recover() != nil {
			_, _ = io.WriteString(stderr, Reason+"\n")
			exitCode = 2
		}
	}()
	data, err := io.ReadAll(io.LimitReader(input, maxInput+1))
	if err == nil && len(data) <= maxInput {
		var payload map[string]any
		if json.Unmarshal(data, &payload) == nil && payload != nil {
			tool, valid := payload["tool_name"].(string)
			args, found := payload["tool_input"]
			if !found {
				args, found = payload["arguments"]
			}
			if s, ok := payload["cwd"].(string); ok && filepath.IsAbs(s) {
				cwd = s
			}
			if valid && tool != "" && found && args != nil {
				switch args.(type) {
				case string, map[string]any:
					g := checker{home: home, cwd: cwd, tool: strings.ToLower(tool)}
					deny = g.inspect(args, "")
				}
			}
		}
	}
	if deny {
		_, _ = io.WriteString(stderr, Reason+"\n")
		return 2
	}
	return 0
}

type checker struct{ home, cwd, tool string }

func (g checker) inspect(v any, key string) bool {
	switch value := v.(type) {
	case map[string]any:
		for k, item := range value {
			if g.inspect(item, strings.ToLower(k)) {
				return true
			}
		}
	case []any:
		for _, item := range value {
			if g.inspect(item, key) {
				return true
			}
		}
	case string:
		switch key {
		case "description", "title", "justification":
			return false
		}
		if strings.Contains(g.tool, "apply_patch") {
			for _, match := range patchPath.FindAllStringSubmatch(value, -1) {
				if g.protected(match[1]) {
					return true
				}
			}
			return false
		}
		switch key {
		case "path", "paths", "file_path", "filepath", "filename", "file", "uri", "url", "resource_uri":
			return g.protected(value)
		case "command", "cmd", "code", "expression", "script", "chars", "input", "":
			return g.codeBlocked(value)
		case "content", "old_string", "new_string", "pattern", "prompt", "message":
			// Prose is not a filesystem path. In particular, long worker
			// messages can exceed a path-component limit during Lstat.
			// Sibling and nested path/command arguments are still inspected.
			return false
		default:
			return g.protected(value)
		}
	}
	return false
}

func publicEnv(name string) bool { return name == ".env.example" || name == ".env.schema.json" }

func (g checker) protected(value string) bool {
	return g.inspectPath(value, false)
}

func (g checker) inspectPath(value string, codeWord bool) bool {
	if decoded, err := url.PathUnescape(value); err == nil {
		value = decoded
	}
	value = strings.ReplaceAll(value, `\`, "/")
	if strings.ContainsRune(value, 0) {
		return true
	}
	for _, m := range envRef.FindAllStringSubmatch(value, -1) {
		if !publicEnv(m[1]) {
			return true
		}
	}
	value = strings.TrimPrefix(value, "file://")
	for _, prefix := range []string{"$HOME/", "${HOME}/"} {
		if strings.HasPrefix(value, prefix) {
			value = filepath.Join(g.home, strings.TrimPrefix(value, prefix))
		}
	}
	if value == "~" {
		value = g.home
	} else if strings.HasPrefix(value, "~/") {
		value = filepath.Join(g.home, value[2:])
	}
	if !filepath.IsAbs(value) {
		value = filepath.Join(g.cwd, value)
	}
	value = filepath.Clean(value)
	resolved, err := resolveMissing(value, 0)
	if err != nil {
		// Code words also include prose literals, not just filenames. A word
		// the filesystem cannot represent is not a readable path. Keep the
		// lexical policy checks below, and fail closed for explicit paths or
		// any other metadata error (including symlink cycles and permissions).
		if !codeWord || !errors.Is(err, syscall.ENAMETOOLONG) {
			return true
		}
		resolved = value
	}
	for _, candidate := range []string{value, resolved} {
		name := filepath.Base(candidate)
		if publicEnv(name) {
			continue
		}
		if name == ".env" || strings.HasPrefix(name, ".env.") {
			return true
		}
		for _, pattern := range policy.DeniedPaths(g.home) {
			if glob(pattern, candidate) || strings.HasPrefix(candidate, pattern+"/") {
				return true
			}
		}
		if strings.ContainsAny(name, "*?[") {
			for _, secret := range []string{".env", ".env.local", ".env.production"} {
				if yes, _ := path.Match(name, secret); yes {
					return true
				}
			}
		}
	}
	return false
}

// Resolve existing parents and dangling symlinks using metadata only. Unlike
// EvalSymlinks this also handles a link whose protected target doesn't exist.
func resolveMissing(p string, depth int) (string, error) {
	if depth > 64 {
		return "", os.ErrInvalid
	}
	if p == filepath.Dir(p) {
		return p, nil
	}
	parent, err := resolveMissing(filepath.Dir(p), depth+1)
	if err != nil {
		return "", err
	}
	p = filepath.Join(parent, filepath.Base(p))
	info, err := os.Lstat(p)
	if os.IsNotExist(err) {
		return p, nil
	}
	if err != nil {
		return "", err
	}
	if info.Mode()&os.ModeSymlink == 0 {
		return p, nil
	}
	target, err := os.Readlink(p)
	if err != nil {
		return "", err
	}
	if !filepath.IsAbs(target) {
		target = filepath.Join(parent, target)
	}
	return resolveMissing(filepath.Clean(target), depth+1)
}

// Path patterns use **. Translate it here with matching across directories,
// including zero directories, rather than filepath.Match's single segments.
func glob(pattern, value string) bool {
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

func (g checker) codeBlocked(code string) bool {
	if envAccess.MatchString(code) || envDump.MatchString(code) || credentialCommand.MatchString(code) {
		return true
	}
	for _, m := range envRef.FindAllStringSubmatch(code, -1) {
		if !publicEnv(m[1]) {
			return true
		}
	}
	for _, m := range shellVar.FindAllStringSubmatch(code, -1) {
		if policy.SecretName(m[1]) {
			return true
		}
	}
	// Inspect literal words even within embedded code. This is intentionally
	// heuristic: arbitrary computed paths are outside the hook's coverage.
	// Python import-all syntax is not a filesystem glob. Exempt only the
	// star in a complete import statement; all other arguments and the
	// original code's credential/environment checks remain active.
	pathCode := pythonWildcardImport.ReplaceAllString(code, "${1} ${2}")
	words := strings.FieldsFunc(pathCode, func(r rune) bool { return strings.ContainsRune(" \t\r\n\"'`;|&()<>=,", r) })
	scan, broad, listing, explicit := false, false, false, false
	for _, word := range words {
		if g.inspectPath(word, true) {
			return true
		}
		switch filepath.Base(word) {
		case "rg", "grep":
			scan = true
		}
		switch word {
		case "--hidden", "--no-ignore", "-uu", "-uuu", "-R", "-r":
			broad = true
		case "--files", "-l", "--files-with-matches":
			listing = true
		}
		if !strings.HasPrefix(word, "-") {
			p := word
			if !filepath.IsAbs(p) {
				p = filepath.Join(g.cwd, p)
			}
			if st, err := os.Stat(p); err == nil && st.Mode().IsRegular() {
				explicit = true
			}
		}
	}
	return scan && broad && !listing && !explicit
}
