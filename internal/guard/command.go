package guard

import (
	"os"
	"path/filepath"
	"strings"

	"github.com/Astatine-213-Tian/agent-secrets/internal/policy"
	"mvdan.cc/sh/v3/syntax"
)

// screenShell checks shell operations and their argument roles without executing
// expansions. Unparsed source is returned for the bounded script recognizer.
func (g checker) screenShell(code string, depth int) (string, bool) {
	f, err := syntax.NewParser(syntax.Variant(syntax.LangBash)).Parse(strings.NewReader(code), "")
	if err != nil {
		f, err = syntax.NewParser(syntax.Variant(syntax.LangZsh)).Parse(strings.NewReader(code), "")
	}
	if err != nil {
		return code, false
	}
	// A successful literal cd followed by && has one unambiguous base. Other
	// compound directory changes are rejected below rather than guessed.
	if len(f.Stmts) == 1 {
		if b, ok := f.Stmts[0].Cmd.(*syntax.BinaryCmd); ok && b.Op == syntax.AndStmt {
			if c, ok := b.X.Cmd.(*syntax.CallExpr); ok && len(c.Args) == 2 && len(c.Assigns) == 0 && len(b.X.Redirs) == 0 {
				name, _, _ := literalWord(c.Args[0].Parts, false)
				if name == "cd" {
					p, ok := readWord(c.Args[1].Parts, code, g.home, false)
					if !ok {
						return "", true
					}
					if !filepath.IsAbs(p) {
						p = filepath.Join(g.cwd, p)
					}
					g.cwd = filepath.Clean(p)
					return "", g.inspectCode(code[b.Y.Pos().Offset():b.Y.End().Offset()], depth+1)
				}
			}
		}
	}
	stdin := map[*syntax.CallExpr]bool{}
	syntax.Walk(f, func(node syntax.Node) bool {
		if s, ok := node.(*syntax.Stmt); ok {
			if c, ok := s.Cmd.(*syntax.CallExpr); ok {
				for _, r := range s.Redirs {
					if r.Op == syntax.RdrIn || r.Hdoc != nil {
						stdin[c] = true
					}
				}
			}
		}
		if b, ok := node.(*syntax.BinaryCmd); ok && (b.Op == syntax.Pipe || b.Op == syntax.PipeAll) {
			syntax.Walk(b.Y, func(n syntax.Node) bool {
				if c, ok := n.(*syntax.CallExpr); ok {
					stdin[c] = true
				}
				return true
			})
		}
		return true
	})
	blocked := false
	inspectWord := func(g checker, word *syntax.Word) {
		value, wildcard, ok := literalWord(word.Parts, false)
		if !ok {
			syntax.Walk(word, func(n syntax.Node) bool {
				switch n.(type) {
				case *syntax.CmdSubst, *syntax.ProcSubst:
					blocked = true
				}
				return !blocked
			})
			value = code[word.Pos().Offset():word.End().Offset()]
			value = strings.ReplaceAll(strings.ReplaceAll(value, "${PWD}", g.cwd), "$PWD", g.cwd)
			value = strings.Trim(value, "\"'")
			ok = true
		}
		if ok && (g.inspectPath(value, true) || wildcard && g.protected(value)) {
			blocked = true
		}
		// File-bearing flags and upload operands are still paths after their
		// syntactic prefix. Never grant the prefix a blanket exemption.
		path := strings.TrimPrefix(value, "@")
		if _, v, found := strings.Cut(path, "="); found {
			path = strings.TrimPrefix(v, "@")
		}
		if path != value && g.inspectPath(path, true) {
			blocked = true
		}
		// zsh appends qualifiers to the glob, e.g. .*(.) or *(D). Bash
		// parses these as extended globs; screen the zsh interpretation too.
		if ok && wildcard && strings.HasSuffix(value, ")") {
			if i := strings.LastIndexByte(value, '('); i > 0 && g.protected(value[:i]) {
				blocked = true
			}
		}
	}
	syntax.Walk(f, func(node syntax.Node) bool {
		if blocked {
			return false
		}
		switch n := node.(type) {
		case *syntax.DeclClause:
			if next, ok := g.scopeCall(&syntax.CallExpr{Assigns: n.Args}); ok {
				g = next
			} else {
				blocked = true
			}
			if len(n.Args) == 0 {
				blocked = true
			}
			for _, a := range n.Args {
				if a.Value != nil {
					v, _, _ := literalWord(a.Value.Parts, false)
					if strings.HasPrefix(v, "-") && strings.Contains(v, "p") {
						blocked = true
					}
				}
			}
		case *syntax.ParamExp:
			// These expansions belong to the outer shell, including unquoted
			// heredocs. Inner quote characters cannot make them literal.
			if n.Param != nil && policy.SecretName(n.Param.Value) {
				blocked = true
			}
		case *syntax.CmdSubst:
			start := n.Left.Offset() + 2 // $( or ${
			if n.Backquotes {
				start--
			} else if n.ReplyVar {
				start++
			}
			// Statement.End can precede its heredoc after a semicolon. Use
			// the complete substitution body, including heredoc delimiters.
			body := code[start:n.Right.Offset()]
			if n.Backquotes {
				body = backquoteBody(body)
			}
			if g.inspectCode(body, depth+1) {
				blocked = true
			}
			// Recursion has checked this complete subtree, including its
			// expansions. Do not walk or reinterpret it a second time.
			return false
		case *syntax.CallExpr:
			// command -v/-V resolves executable metadata, not an invocation.
			if len(n.Args) >= 2 {
				name, _, _ := literalWord(n.Args[0].Parts, false)
				flag, _, _ := literalWord(n.Args[1].Parts, false)
				if name == "command" && (flag == "-v" || flag == "-V") {
					return true
				}
			}
			op, valid := g.scopeCall(n)
			if !valid {
				blocked = true
				return false
			}
			if len(n.Args) == 0 {
				g = op
			}
			for i, w := range n.Args {
				v, _, _ := literalWord(w.Parts, false)
				if v == "-S" || v == "--split-string" {
					if i+1 < len(n.Args) {
						body, _, ok := literalWord(n.Args[i+1].Parts, false)
						if !ok || op.inspectCode(body, depth+1) {
							blocked = true
						}
					} else {
						blocked = true
					}
				}
			}
			args := commandArgs(n.Args)
			if len(args) == 0 {
				// Bare env (including wrappers/options) dumps the environment.
				for _, w := range n.Args {
					v, _, _ := literalWord(w.Parts, false)
					if filepath.Base(v) == "env" {
						blocked = true
					}
				}
				return !blocked
			}
			name, _, _ := literalWord(args[0].Parts, false)
			name = filepath.Base(name)
			if environmentCommand(name, args[1:]) || credentialInspection(name, args[1:]) {
				blocked = true
				return false
			}
			if name == "cd" && len(f.Stmts) > 1 {
				blocked = true
				return false
			}
			if name == "cd" && f.Stmts[0].Cmd != n {
				blocked = true
				return false
			}
			if name == "ps" && processEnvironment(args[1:]) {
				blocked = true
				return false
			}
			patterns := searchPatterns(name, args[1:])
			metadata := metadataCommand(name, args[1:])
			if name == "find" && !metadata {
				blocked = true
				return false
			}
			if !metadata && op.searchNeedsControl(name, args[1:], stdin[n]) {
				blocked = true
				return false
			}
			for i, word := range n.Args {
				value, wildcard, literal := literalWord(word.Parts, false)
				if patterns[word] && literal && !wildcard {
					continue
				}
				// Shell -c operands are code, including their own regex roles.
				if isShell(name) && i > 0 && literal {
					previous, _, _ := literalWord(n.Args[i-1].Parts, false)
					if strings.HasPrefix(previous, "-") && strings.Contains(previous, "c") {
						if op.inspectCode(value, depth+1) {
							blocked = true
						}
						continue
					}
				}
				if scriptCommand(name) && i > 0 && literal {
					previous, _, _ := literalWord(n.Args[i-1].Parts, false)
					if previous == "-c" || previous == "-e" || previous == "--eval" {
						if op.scriptBlocked(value, depth+1) {
							blocked = true
						}
						continue
					}
				}
				if metadata || literalOutput(name) {
					continue
				}
				if transferSource(name, i, len(n.Args)) && literal && op.protectedDirectory(value) {
					blocked = true
				}
				inspectWord(op, word)
			}
		case *syntax.Stmt:
			call, ok := n.Cmd.(*syntax.CallExpr)
			if !ok {
				return true
			}
			args := commandArgs(call.Args)
			if len(args) == 0 {
				return true
			}
			name, _, _ := literalWord(args[0].Parts, false)
			if isShell(filepath.Base(name)) || scriptCommand(filepath.Base(name)) {
				for _, redirect := range n.Redirs {
					if redirect.Hdoc != nil {
						body := code[redirect.Hdoc.Pos().Offset():redirect.Hdoc.End().Offset()]
						unsafe := false
						if isShell(filepath.Base(name)) {
							unsafe = g.inspectCode(body, depth+1)
						} else {
							unsafe = g.scriptBlocked(body, depth+1)
						}
						if unsafe {
							blocked = true
						}
					}
				}
			}
		case *syntax.Redirect:
			if n.Hdoc == nil {
				inspectWord(g, n.Word)
			}
		}
		return !blocked
	})
	return "", blocked
}

func isDirectory(p string) bool { st, err := os.Stat(p); return err == nil && st.IsDir() }

// Legacy backquotes remove one escaping layer before the body is parsed.
// Backslashes otherwise remain literal; this never performs expansions.
func backquoteBody(body string) string {
	var out strings.Builder
	for i := 0; i < len(body); i++ {
		if body[i] == '\\' && i+1 < len(body) && strings.ContainsRune("$`\\\n", rune(body[i+1])) {
			i++
			if body[i] == '\n' {
				continue
			}
		}
		out.WriteByte(body[i])
	}
	return out.String()
}

// literalWord removes ordinary quotes and escapes, but never evaluates a
// parameter, command substitution, or ANSI-C quote. wildcard means shell
// expansion is possible, not that quoted punctuation resembles a filename.
func literalWord(parts []syntax.WordPart, quoted bool) (value string, wildcard, ok bool) {
	var out strings.Builder
	for _, part := range parts {
		switch p := part.(type) {
		case *syntax.Lit:
			for i := 0; i < len(p.Value); i++ {
				c := p.Value[i]
				if c == '\\' && i+1 < len(p.Value) && (!quoted || strings.ContainsRune("\"\\$`\n", rune(p.Value[i+1]))) {
					i++
					if p.Value[i] != '\n' {
						out.WriteByte(p.Value[i])
					}
					continue
				}
				wildcard = wildcard || !quoted && strings.ContainsRune("*?[", rune(c))
				out.WriteByte(c)
			}
		case *syntax.SglQuoted:
			if p.Dollar {
				return "", false, false
			}
			out.WriteString(p.Value)
		case *syntax.DblQuoted:
			if p.Dollar {
				return "", false, false
			}
			v, _, valid := literalWord(p.Parts, true)
			if !valid {
				return "", false, false
			}
			out.WriteString(v)
		case *syntax.ExtGlob:
			out.WriteString(p.Op.String())
			out.WriteString(p.Pattern.Value)
			out.WriteByte(')')
			wildcard = true
		default:
			return "", false, false
		}
	}
	return out.String(), wildcard, true
}

// Unwrap common command launchers only; wrapper options and assignments are
// still inspected by screenShell along with the underlying command.
func commandArgs(args []*syntax.Word) []*syntax.Word {
	for len(args) > 0 {
		name, _, _ := literalWord(args[0].Parts, false)
		name = filepath.Base(name)
		switch name {
		case "command", "exec", "sudo", "env":
			args = args[1:]
			for len(args) > 0 {
				v, _, ok := literalWord(args[0].Parts, false)
				if !ok || !strings.HasPrefix(v, "-") && !strings.Contains(v, "=") {
					break
				}
				args = args[1:]
				if v == "--" {
					break
				}
				if wrapperValueOption(name, v) {
					if len(args) > 0 {
						args = args[1:]
					}
				}
			}
		default:
			return args
		}
	}
	return args
}

func wrapperValueOption(name, flag string) bool {
	options := ""
	switch name {
	case "exec":
		options = " -a "
	case "sudo":
		options = " -u -g -h -p -C -T --user --group --host --prompt --close-from --command-timeout "
	case "env":
		options = " -u -C --unset --chdir "
	}
	return options != "" && strings.Contains(options, " "+flag+" ")
}

func isShell(name string) bool {
	return name == "sh" || name == "bash" || name == "zsh" || name == "dash" || name == "ksh"
}

// -e selects processes in POSIX ps. BSD's bare e and macOS's -E display
// environments. Output-column names and option values are not options.
func processEnvironment(args []*syntax.Word) bool {
	for i := 0; i < len(args); i++ {
		v, _, ok := literalWord(args[i].Parts, false)
		if !ok {
			continue
		}
		if v == "--" {
			return false
		}
		if strings.HasPrefix(v, "--") {
			if !strings.Contains(v, "=") && (v == "--format" || v == "--sort" || v == "--pid" || v == "--user") {
				i++
			}
			continue
		}
		dashed := strings.HasPrefix(v, "-")
		for _, option := range strings.TrimPrefix(v, "-") {
			if option == 'E' || option == 'e' && !dashed {
				return true
			}
			valueOptions := "oOpPtUG"
			if dashed {
				valueOptions += "ugsC"
			}
			if strings.ContainsRune(valueOptions, option) {
				if strings.HasSuffix(v, string(option)) {
					i++
				}
				break
			}
		}
	}
	return false
}

// Recognize search-expression operands, never pattern files (-f) or file
// operands. Unknown options stop classification instead of exempting a path.
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
			case "--regexp", "--file", "--after-context", "--before-context", "--context", "--max-count", "--glob", "--iglob", "--type", "--type-not", "--encoding", "--color":
				if flag == "--regexp" || flag == "--file" {
					explicit = true
				}
				if !attached {
					i++
					if i == len(args) {
						return patterns
					}
				}
				if flag == "--regexp" {
					patterns[args[i]] = true
				}
			case "--hidden", "--no-ignore", "--line-number", "--ignore-case", "--fixed-strings", "--extended-regexp", "--perl-regexp", "--files-with-matches", "--files-without-match", "--count", "--no-heading", "--heading", "--word-regexp", "--invert-match":
			default:
				return patterns
			}
			continue
		}
		if options && strings.HasPrefix(v, "-") && v != "-" {
			for j := 1; j < len(v); j++ {
				flag := v[j]
				valueOptions := "efABCm"
				if name == "rg" {
					valueOptions += "gtT"
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
					if flag == 'e' {
						patterns[args[i]] = true
					}
					break
				}
				if !strings.ContainsRune("nNivwxlLqscHEFPrRhoIUaubzZT0123456789", rune(flag)) {
					return patterns
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
