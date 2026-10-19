package guard

import (
	"path/filepath"
	"regexp"
	"strings"

	"github.com/Astatine-213-Tian/agent-secrets/internal/policy"
	"mvdan.cc/sh/v3/syntax"
)

func literalArgs(args []*syntax.Word) ([]string, bool) {
	out := make([]string, len(args))
	static := true
	for i, w := range args {
		v, glob, ok := literalWord(w.Parts, false)
		if !ok || glob {
			static = false
			continue
		}
		out[i] = v
	}
	return out, static
}

// Only common file-handling commands have their operands screened as paths.
// An arbitrary application receiving a credential path is not itself evidence
// of disclosure. Expansions, nested code, redirects, and dumps are separate
// checks, including when the outer command is not recognized here.
func fileCommand(name string) bool {
	switch name {
	case "cat", "head", "tail", "less", "more", "sed", "awk", "cut", "paste", "sort", "uniq", "diff",
		"rg", "grep", "egrep", "fgrep", "jq", "yq", "strings", "od", "xxd", "hexdump", "base64",
		"cp", "mv", "rsync", "scp", "sftp", "tar", "zip", "dd", "tee", "curl", "wget", "find":
		return true
	}
	return false
}

// These commands do not open operands for contents. Shell expansions and
// redirects remain separate operations and are always checked by the walker.
func metadataCommand(name string, args []*syntax.Word) bool {
	switch name {
	case "ls", "stat", "test", "[", "pwd", "cd":
		return true
	case "find":
		for _, w := range args {
			v, _, ok := literalWord(w.Parts, false)
			if !ok {
				return false
			}
			switch v {
			case "-fprint", "-fprint0", "-fprintf", "-delete":
				return false
			}
		}
		return true
	case "rg":
		patterns := searchPatterns(name, args)
		for _, word := range args {
			v, _, ok := literalWord(word.Parts, false)
			if !ok || patterns[word] {
				continue
			}
			if v == "--" {
				break
			}
			if v == "--files" {
				return true
			}
		}

	}
	return false
}

func transferSource(name string, index, total int) bool {
	switch name {
	case "cp", "mv", "rsync", "scp":
		return index < total-1
	case "tar", "zip", "sftp":
		return true
	}
	return false
}

func (g checker) protectedDirectory(value string) bool {
	if strings.HasPrefix(value, "~/") {
		value = filepath.Join(g.home, value[2:])
	}
	if value == "~" {
		value = g.home
	}
	if !filepath.IsAbs(value) {
		value = filepath.Join(g.cwd, value)
	}
	for _, p := range g.locations().Paths() {
		if strings.HasPrefix(p, filepath.Clean(value)+"/") && !strings.HasPrefix(p, "/**/") {
			return true
		}
	}
	return false
}

func environmentCommand(name string, args []*syntax.Word) bool {
	words, static := literalArgs(args)
	switch name {
	case "printenv":
		// Names are checked by the credential grammar, never by a public-name
		// list. Options remain native; options alone still request a dump.
		names := 0
		for _, w := range words {
			if w == "--help" || w == "--version" {
				return false
			}
			if strings.HasPrefix(w, "-") {
				continue
			}
			names++
			if policy.SecretName(w) {
				return true
			}
		}
		return static && names == 0
	case "env":
		return true // unwrapped commands are checked under their own name
	case "set":
		// Bare set lists every variable. Tracing (-x) is ordinary script
		// debugging, as with bash -x, and is not a dump.
		return len(words) == 0
	case "export", "declare", "typeset":
		if len(words) == 0 {
			return true
		}
		for _, w := range words {
			if strings.HasPrefix(w, "-") && strings.Contains(w, "p") {
				return true
			}
		}
	}
	return false
}

// Inspection rules recognize credential-bearing output, not permitted templates.
var inspectionField = regexp.MustCompile(`\.[A-Za-z_][A-Za-z_0-9.]*`)
var inspectionRoot = regexp.MustCompile(`(?:\{\{\s*|\s)[.$]\s*(?:\}\}|[|)])`)

func credentialInspection(name string, args []*syntax.Word) bool {
	// Preserve literal words even when another argument is computed. Unknown
	// arguments alone are not evidence of a credential dump.
	words := make([]string, len(args))
	for i, w := range args {
		words[i], _, _ = literalWord(w.Parts, false)
	}
	joined := " " + strings.Join(words, " ") + " "
	if name == "security" {
		password := strings.Contains(joined, " find-generic-password ") || strings.Contains(joined, " find-internet-password ")
		return password && (strings.Contains(joined, " -w ") || strings.Contains(joined, " -g "))
	}
	if name == "gh" {
		return len(words) >= 2 && words[0] == "auth" && words[1] == "token"
	}
	compose := name == "compose" || name == "docker" && strings.Contains(joined, " compose ")
	if compose && strings.Contains(joined, " config ") {
		for _, w := range words {
			switch w {
			case "--services", "--images", "--volumes", "--profiles", "--networks", "--quiet", "-q":
				return false
			}
		}
		return true
	}
	if name != "docker" || !strings.Contains(joined, " inspect ") {
		return false
	}
	formatted := false
	for i, w := range words {
		format := ""
		if w == "--format" || w == "-f" {
			formatted = true
			if i+1 < len(words) {
				format = words[i+1]
			}
		} else if strings.HasPrefix(w, "--format=") {
			formatted = true
			format = strings.TrimPrefix(w, "--format=")
		}
		if strings.TrimSpace(format) == "json" || inspectionRoot.MatchString(format) {
			return true
		}
		for _, field := range inspectionField.FindAllString(format, -1) {
			parts := strings.Split(strings.Trim(field, "."), ".")
			for _, part := range parts {
				if policy.SecretName(part) {
					return true
				}
				switch part {
				case "Env", "Args", "Cmd", "Entrypoint", "Labels":
					return true
				}
			}
			switch parts[len(parts)-1] {
			case "Config", "ContainerConfig":
				return true
			}
		}
	}
	return !formatted // Default inspection includes the whole environment.
}

func scriptCommand(name string) bool {
	return strings.HasPrefix(name, "python") || name == "node" || name == "nodejs" || name == "ruby" || name == "perl"
}
