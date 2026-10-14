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
		if name == "cd" && len(words) == 2 {
			if path, ok := readWord(words[1].Parts, s.source, g.home, false); ok {
				if !filepath.IsAbs(path) {
					path = filepath.Join(g.cwd, path)
				}
				g.cwd = filepath.Clean(path)
			}
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
	if name != "rg" && name != "grep" && name != "egrep" && name != "fgrep" {
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

// File-bearing search options remain reads even with filename-only output.
func searchFileInput(name string, args []*syntax.Word, i int) bool {
	if name != "rg" && name != "grep" && name != "egrep" && name != "fgrep" {
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
