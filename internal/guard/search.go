package guard

import (
	"path/filepath"
	"strings"

	"github.com/Astatine-213-Tian/agent-secrets/internal/install"
	"mvdan.cc/sh/v3/syntax"
)

// rewriteSearch preserves the native shell source and rg arguments. Only
// negative globs are inserted; rg owns its options, traversal, output and errors.
// Unrecognized syntax is left to the normal argument checks, not blanket-denied.
func (s *shellCommand) rewriteSearch() string {
	if s.tree == nil {
		return s.source
	}
	var edits []shellEdit
	g := s.scope
	var scopes []*checker
	syntax.Walk(s.tree, func(node syntax.Node) bool {
		if node == nil {
			last := len(scopes) - 1
			if scopes[last] != nil {
				g = *scopes[last]
			}
			scopes = scopes[:last]
			return true
		}
		var restore *checker
		switch node.(type) {
		case *syntax.Subshell, *syntax.CmdSubst, *syntax.ProcSubst, *syntax.FuncDecl:
			saved := g
			restore = &saved
		}
		scopes = append(scopes, restore)
		if declaration, ok := node.(*syntax.DeclClause); ok {
			if next, valid := g.scopeCall(&syntax.CallExpr{Assigns: declaration.Args}); valid {
				g = next
			}
		}
		call, ok := node.(*syntax.CallExpr)
		if !ok {
			return true
		}
		scope, ok := g.scopeCall(call)
		if !ok {
			return true
		}
		words := commandArgs(call.Args)
		if len(words) == 0 {
			g = scope
			return true
		}
		name, _, _ := literalWord(words[0].Parts, false)
		if name == "cd" && len(words) <= 2 {
			path, ok := g.home, true
			if len(words) == 2 {
				path, ok = readWord(words[1].Parts, s.source, g.home, false)
			}
			if ok {
				if !filepath.IsAbs(path) {
					path = filepath.Join(g.cwd, path)
				}
				g.cwd = filepath.Clean(path)
			}
		}
		if grepCommand(filepath.Base(name)) {
			if recursiveGrep(filepath.Base(name), words[1:]) {
				// Options go right after the name: BSD grep stops parsing
				// options at the first operand.
				files, dirs := scope.locations().GrepExclusions()
				var options strings.Builder
				for _, glob := range files {
					options.WriteString(" --exclude=" + shellQuote(glob))
				}
				for _, glob := range dirs {
					options.WriteString(" --exclude-dir=" + shellQuote(glob))
				}
				at := words[0].End().Offset()
				edits = append(edits, shellEdit{at, at, options.String()})
			}
			return true
		}
		if filepath.Base(name) != "rg" || metadataCommand("rg", words[1:]) {
			return true
		}
		globs := scope.locations().SearchExclusions(scope.cwd)
		if physical, err := install.ResolveLocations(scope.locations()); err == nil {
			globs = append(globs, physical.SearchExclusions(scope.cwd)...)
		}
		seen := map[string]bool{}
		var options strings.Builder
		for _, glob := range globs {
			if seen[glob] {
				continue
			}
			seen[glob] = true
			options.WriteString(" --glob " + shellQuote(glob))
		}
		at := words[len(words)-1].End().Offset()
		// A literal -- ends option parsing; insert before it. Recognized
		// expression/option values are not option terminators.
		patterns := searchPatterns("rg", words[1:])
		for i := 1; i < len(words); i++ {
			value, _, _ := literalWord(words[i].Parts, false)
			if value == "--" && !patterns[words[i]] {
				at = words[i].Pos().Offset()
				options.WriteByte(' ')
				break
			}
		}
		edits = append(edits, shellEdit{at, at, options.String()})
		return true
	})
	return applyShellEdits(s.source, edits)
}

// Recognize search-expression operands, never pattern files (-f) or file
// operands. This recognizes argument roles, not permitted options: unknown
// flags are left for the native tool to validate.
func searchPatterns(name string, args []*syntax.Word) map[*syntax.Word]bool {
	patterns := make(map[*syntax.Word]bool)
	if name != "rg" && !grepCommand(name) {
		return patterns
	}
	explicit, options := false, true
	var positional *syntax.Word
	for i := 0; i < len(args); i++ {
		v, _, ok := literalWord(args[i].Parts, false)
		if !ok {
			if !options {
				break
			}
			return patterns
		}
		if options && v == "--" {
			options = false
			continue
		}
		if options && strings.HasPrefix(v, "--") {
			flag, _, attached := strings.Cut(v, "=")
			// grep's optional color value must use '='; rg requires a value.
			if name != "rg" && (flag == "--color" || flag == "--colour") {
				continue
			}
			switch flag {
			case "--regexp", "--file", "--ignore-file", "--pre", "--pre-glob", "--after-context", "--before-context", "--context", "--max-count", "--glob", "--iglob", "--type", "--type-not", "--type-add", "--type-clear", "--encoding", "--color", "--colors", "--sort", "--sortr", "--threads", "--max-depth", "--max-filesize", "--max-columns", "--replace", "--field-match-separator", "--field-context-separator", "--context-separator", "--path-separator", "--engine":
				if flag == "--regexp" || flag == "--file" {
					explicit = true
				}
				if !attached {
					i++
					if i == len(args) {
						return patterns
					}
				}
				if flag != "--file" && flag != "--ignore-file" && flag != "--pre" {
					patterns[args[i]] = true
				}
			}
			continue
		}
		if options && strings.HasPrefix(v, "-") && v != "-" {
			for j := 1; j < len(v); j++ {
				flag := v[j]
				valueOptions := "efABCm"
				if name == "rg" {
					valueOptions += "gtTEjrM"
				}
				if strings.ContainsRune(valueOptions, rune(flag)) {
					if flag == 'e' || flag == 'f' {
						explicit = true
					}
					if j == len(v)-1 {
						i++
						if i == len(args) {
							return patterns
						}
					}
					if flag != 'f' {
						patterns[args[i]] = true
					}
					break
				}
			}
			continue
		}
		if positional == nil {
			positional = args[i]
		}
	}
	if !explicit && positional != nil {
		patterns[positional] = true
	}
	return patterns
}

func grepCommand(name string) bool {
	return name == "grep" || name == "egrep" || name == "fgrep" || name == "rgrep"
}

// recursiveGrep recognizes -r/-R (alone or clustered), their long forms, and
// --directories=recurse. Values of options such as -e and -A are skipped.
func recursiveGrep(name string, args []*syntax.Word) bool {
	if name == "rgrep" {
		return true
	}
	for i := 0; i < len(args); i++ {
		v, _, ok := literalWord(args[i].Parts, false)
		if !ok {
			continue
		}
		switch {
		case v == "--":
			return false
		case v == "--recursive" || v == "--dereference-recursive" || v == "--directories=recurse":
			return true
		case v == "--directories" || v == "-d":
			if next, _, _ := literalWordAt(args, i+1); next == "recurse" {
				return true
			}
			i++
		case strings.HasPrefix(v, "--"):
		case strings.HasPrefix(v, "-"):
			for j := 1; j < len(v); j++ {
				if v[j] == 'r' || v[j] == 'R' {
					return true
				}
				if strings.ContainsRune("efABCmdD", rune(v[j])) {
					if v[j] == 'd' && v[j+1:] == "recurse" {
						return true
					}
					if j == len(v)-1 {
						i++
					}
					break
				}
			}
		}
	}
	return false
}

func literalWordAt(args []*syntax.Word, i int) (string, bool, bool) {
	if i >= len(args) {
		return "", false, false
	}
	return literalWord(args[i].Parts, false)
}

// grepsProtectedDirectory reports a recursive grep over a directory holding
// home credential stores, which grep's base-name exclusions cannot express.
// Without operands, GNU grep searches the working directory.
func (g checker) grepsProtectedDirectory(args []*syntax.Word, patterns map[*syntax.Word]bool) bool {
	operands, options := 0, true
	for i := 0; i < len(args); i++ {
		v, _, ok := literalWord(args[i].Parts, false)
		if !ok || patterns[args[i]] {
			continue
		}
		if options && v == "--" {
			options = false
			continue
		}
		if options && strings.HasPrefix(v, "-") && v != "-" {
			if v == "-d" || v == "--directories" || v == "-f" || v == "--file" || v == "--exclude" || v == "--include" || v == "--exclude-dir" {
				i++
			}
			continue
		}
		operands++
		if g.protectedDirectory(v) {
			return true
		}
	}
	return operands == 0 && g.protectedDirectory(g.cwd)
}

// File-bearing search options remain reads even with filename-only output.
func searchFileInput(name string, args []*syntax.Word, i int) bool {
	if name != "rg" && !grepCommand(name) {
		return false
	}
	value, _, _ := literalWord(args[i].Parts, false)
	if strings.HasPrefix(value, "--file=") || strings.HasPrefix(value, "--ignore-file=") || strings.HasPrefix(value, "--pre=") || strings.HasPrefix(value, "-f") {
		return true
	}
	if i == 0 {
		return false
	}
	previous, _, _ := literalWord(args[i-1].Parts, false)
	return previous == "-f" || previous == "--file" || previous == "--ignore-file" || previous == "--pre"
}
