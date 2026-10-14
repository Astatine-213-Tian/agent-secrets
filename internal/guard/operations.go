package guard

import (
	"path/filepath"
	"strings"

	"github.com/Astatine-213-Tian/agent-secrets/internal/policy"
	"mvdan.cc/sh/v3/syntax"
)

func literalArgs(args []*syntax.Word) ([]string, bool) {
	out := make([]string, len(args))
	for i, w := range args {
		v, glob, ok := literalWord(w.Parts, false)
		if !ok || glob {
			return nil, false
		}
		out[i] = v
	}
	return out, true
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
			case "-exec", "-execdir", "-ok", "-okdir", "-fprint", "-fprint0", "-fprintf", "-delete":
				return false
			}
		}
		return true
	case "rg":
		files := false
		for i := 0; i < len(args); i++ {
			v, _, ok := literalWord(args[i].Parts, false)
			if !ok {
				return false
			}
			if v == "--files" {
				files = true
				continue
			}
			if v == "-g" || v == "--glob" || v == "--iglob" || v == "-t" || v == "-T" {
				i++
				if i >= len(args) {
					return false
				}
				continue
			}
			if strings.HasPrefix(v, "-") {
				switch v {
				case "--hidden", "--no-ignore", "-u", "-uu", "-uuu", "--null", "-0", "--no-config":
				default:
					return false
				}
			}
		}
		return files
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

func literalOutput(name string) bool { return name == "echo" || name == "printf" }

func environmentCommand(name string, args []*syntax.Word) bool {
	words, static := literalArgs(args)
	switch name {
	case "printenv":
		if !static || len(words) == 0 {
			return true
		}
		for _, w := range words {
			if !policy.PublicEnvironment(w) {
				return true
			}
		}
		return false
	case "env":
		return true // unwrapped commands are checked under their own name
	case "set":
		if len(words) == 0 || !static {
			return true
		}
		for i, w := range words {
			if w == "--" {
				break
			}
			if strings.HasPrefix(w, "-") && strings.Contains(w, "x") {
				return true
			}
			if w == "-o" && i+1 < len(words) && words[i+1] == "xtrace" {
				return true
			}
		}
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

func credentialInspection(name string, args []*syntax.Word) bool {
	words, ok := literalArgs(args)
	if name == "security" {
		for _, w := range words {
			if w == "find-generic-password" || w == "find-internet-password" {
				return true
			}
		}
	}
	if name == "gh" {
		return len(words) >= 2 && words[0] == "auth" && words[1] == "token"
	}
	if name == "compose" {
		return len(words) > 0 && words[0] == "config"
	}
	if name != "docker" {
		return false
	}
	if !ok {
		return true
	}
	joined := " " + strings.Join(words, " ") + " "
	if strings.Contains(joined, " compose ") && strings.Contains(joined, " config ") {
		return true
	}
	inspect := -1
	for i, w := range words {
		if w == "inspect" {
			inspect = i
			break
		}
	}
	if inspect < 0 {
		return false
	}
	// Accept only one object and one exact status field; arbitrary templates
	// and full inspection may expose Config.Env, labels, arguments and mounts.
	rest := words[inspect+1:]
	format := ""
	objects := 0
	for i := 0; i < len(rest); i++ {
		w := rest[i]
		if w == "-f" || w == "--format" {
			i++
			if i >= len(rest) || format != "" {
				return true
			}
			format = rest[i]
		} else if strings.HasPrefix(w, "--format=") {
			if format != "" {
				return true
			}
			format = strings.TrimPrefix(w, "--format=")
		} else if strings.HasPrefix(w, "-") {
			return true
		} else {
			objects++
		}
	}
	switch format {
	case "{{.State.Status}}", "{{.State.Running}}", "{{.State.Health.Status}}":
		return objects != 1
	}
	return true
}

func scriptCommand(name string) bool {
	return strings.HasPrefix(name, "python") || name == "node" || name == "nodejs" || name == "ruby" || name == "perl"
}

func (g checker) searchNeedsControl(name string, args []*syntax.Word, stdin bool) bool {
	if name != "rg" && name != "grep" && name != "egrep" && name != "fgrep" {
		return false
	}
	patterns := searchPatterns(name, args)
	operands := 0
	for i := 0; i < len(args); i++ {
		w := args[i]
		if patterns[w] {
			continue
		}
		v, _, ok := literalWord(w.Parts, false)
		if !ok {
			v, ok = g.pathWord(w.Parts)
			if !ok {
				return true
			}
		}
		if strings.HasPrefix(v, "-") {
			// Value options never establish a safe file operand.
			if v == "-g" || v == "-t" || v == "-T" || v == "-A" || v == "-B" || v == "-C" || v == "-m" || v == "--glob" || v == "--iglob" || v == "--type" || v == "--type-not" || v == "--color" || v == "--encoding" || v == "-f" || v == "--file" {
				i++
			}
			continue
		}
		operands++
		p := v
		if !filepath.IsAbs(p) {
			p = filepath.Join(g.cwd, p)
		}
		if isDirectory(p) {
			return true
		}
		if v == "." || v == ".." || strings.HasSuffix(v, "/") {
			return true
		}
	}
	return operands == 0 && name == "rg" && !stdin
}
