// Package guard screens tool arguments without reading credential contents.
// Its argument heuristics do not provide file isolation.
package guard

import (
	"errors"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"

	"github.com/Astatine-213-Tian/agent-secrets/internal/install"
	"github.com/Astatine-213-Tian/agent-secrets/internal/policy"
	"mvdan.cc/sh/v3/pattern"
)

const Reason = "Blocked by global credential protection: secret files and environment values must not enter agent transcripts."
const maxInput = 4 << 20

var envRef = regexp.MustCompile(`(?:^|[^\w.\-])(\.env(?:\.[\w*?\[\]-]+)*)(?:$|[^\w.\-])`)
var patchPath = regexp.MustCompile(`(?m)^\*\*\* (?:Add File|Update File|Delete File|Move to): (.+)\r?$`)

// Check consumes one hook request. Malformed, oversized, or uninspectable input
// is denied. Output is a fixed message; request content is never reflected.
func Check(input io.Reader, stderr io.Writer, home, cwd string) (exitCode int) {
	data, err := io.ReadAll(io.LimitReader(input, maxInput+1))
	if err == nil && Evaluate(data, home, cwd, "").Kind == Allow {
		return 0
	}
	_, _ = io.WriteString(stderr, Reason+"\n")
	return 2
}

type checker struct {
	home, cwd, tool string
	stores          *policy.Locations
}

func (g checker) locations() policy.Locations {
	if g.stores != nil {
		return *g.stores
	}
	return install.Locations(g.home, g.cwd)
}

func (g checker) inspect(v any, key string) bool {
	switch value := v.(type) {
	case map[string]any:
		if p, ok := value["workdir"].(string); ok {
			g = g.atWorkdir(p)
		}
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
		case "description", "title", "justification", "workdir":
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
			// Creating a file discloses nothing. An existing file, including a
			// symlink, keeps the normal rules since its contents can be shown.
			if g.tool == "write" && key == "file_path" && g.missing(value) {
				return false
			}
			return g.protected(value)
		case "command", "cmd", "code", "expression", "script", "chars", "input", "":
			return g.codeBlocked(value)
		case "content", "old_string", "new_string", "pattern", "prompt", "message":
			// Prose is not a filesystem path. In particular, long worker
			// messages can exceed a path-component limit during Lstat.
			// Sibling and nested path/command arguments are still inspected.
			return false
		default:
			// Other strings are often prose: search queries, titles, page
			// text. Only a single path-like word is screened as a file name.
			if strings.ContainsAny(value, " \t\r\n") {
				return false
			}
			return g.inspectPath(value, metadataValue)
		}
	}
	return false
}

func publicEnv(name string) bool { return name == ".env.example" || name == ".env.schema.json" }

// pathRole sets how strictly a string is screened as a filesystem path.
type pathRole int

const (
	// explicitPath is a file-tool path, patch target, or file literal.
	explicitPath pathRole = iota
	// metadataValue is any other string argument, such as a question, label,
	// or preview. It may be a path, but is often prose.
	metadataValue
	// codeWord is a shell word or code literal. Wildcards are screened by
	// the caller.
	codeWord
)

func (g checker) missing(value string) bool {
	if strings.HasPrefix(value, "~/") {
		value = filepath.Join(g.home, value[2:])
	}
	if !filepath.IsAbs(value) {
		value = filepath.Join(g.cwd, value)
	}
	_, err := os.Lstat(value)
	return errors.Is(err, os.ErrNotExist)
}

func (g checker) protected(value string) bool {
	return g.inspectPath(value, explicitPath)
}

func (g checker) inspectPath(value string, role pathRole) bool {
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
	l := g.locations()
	for name, path := range map[string]string{"CODEX_HOME": l.Codex, "DOCKER_CONFIG": l.Docker, "NPM_CONFIG_USERCONFIG": l.NPM, "AWS_SHARED_CREDENTIALS_FILE": l.AWS, "PWD": g.cwd} {
		if path == "" {
			continue
		}
		for _, prefix := range []string{"$" + name, "${" + name + "}"} {
			if value == prefix {
				value = path
			} else if strings.HasPrefix(value, prefix+"/") {
				value = filepath.Join(path, strings.TrimPrefix(value, prefix+"/"))
			}
		}
	}
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
	resolved, err := install.ResolvePath(value)
	if err != nil {
		// Code words and metadata values also carry prose, not just filenames.
		// A value the filesystem cannot represent is not a readable path. Keep
		// the lexical policy checks below, and fail closed for explicit paths
		// or any other metadata error (including symlink cycles and permissions).
		if role == explicitPath || !errors.Is(err, syscall.ENAMETOOLONG) {
			return true
		}
		resolved = value
	}
	physical, err := install.ResolveLocations(l)
	if err != nil {
		return true
	}
	if physical.Protected(resolved) {
		return true
	}
	if g.stores != nil {
		base := install.Locations(g.home, g.cwd)
		physical, e := install.ResolveLocations(base)
		if e != nil || base.Protected(value) || physical.Protected(resolved) {
			return true
		}
	}
	for _, candidate := range []string{value, resolved} {
		if g.locations().Protected(candidate) {
			return true
		}
		name := filepath.Base(candidate)
		if role != codeWord && strings.ContainsAny(name, "*?[") {
			if expression, err := pattern.Regexp(name, pattern.ExtendedOperators); err == nil {
				matcher := regexp.MustCompile("^(?:" + expression + ")$")
				for _, rule := range g.locations().Paths() {
					sample := filepath.Base(rule)
					if strings.ContainsAny(sample, "*?") {
						continue
					}
					if matcher.MatchString(sample) {
						return true
					}
				}
			}
		}
	}

	return false
}

func (g checker) codeBlocked(code string) bool {
	return g.inspectCode(code, 0)
}

func (g checker) inspectCode(code string, depth int) bool {
	if depth > 32 {
		return true
	}
	trim := strings.TrimSpace(code)
	for _, prefix := range []string{"await ", "const ", "let ", "import "} {
		if strings.HasPrefix(trim, prefix) {
			return g.scriptBlocked(code, depth)
		}
	}
	code, blocked := g.screenShell(code, depth)
	if blocked {
		return true
	}
	if code == "" {
		return false
	}
	return g.scriptBlocked(code, depth)
}
