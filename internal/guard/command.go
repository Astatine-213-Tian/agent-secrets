package guard

import (
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
	blocked := false
	inspectWord := func(g checker, word *syntax.Word) {
		value, wildcard, ok := literalWord(word.Parts, false)
		if !ok {
			// A substitution used as an operand can produce a protected path.
			// Check explicit path words without rejecting every substitution.
			syntax.Walk(word, func(n syntax.Node) bool {
				if sub, ok := n.(*syntax.CmdSubst); ok {
					syntax.Walk(sub, func(child syntax.Node) bool {
						if w, ok := child.(*syntax.Word); ok {
							if path, glob, literal := literalWord(w.Parts, false); literal && (g.inspectPath(path, codeWord) || glob && g.protected(path)) {
								blocked = true
							}
						}
						return !blocked
					})
					return false
				}
				return !blocked
			})
			value = code[word.Pos().Offset():word.End().Offset()]
			value = strings.ReplaceAll(strings.ReplaceAll(value, "${PWD}", g.cwd), "$PWD", g.cwd)
			value = strings.Trim(value, "\"'")
			ok = true
		}
		if ok && (g.inspectPath(value, codeWord) || wildcard && g.protected(value)) {
			blocked = true
		}
		// File-bearing flags and upload operands are still paths after their
		// syntactic prefix. Never grant the prefix a blanket exemption.
		path := strings.TrimPrefix(value, "@")
		if _, v, found := strings.Cut(path, "="); found {
			path = strings.TrimPrefix(v, "@")
		}
		if path != value && g.inspectPath(path, codeWord) {
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
		case *syntax.Subshell:
			blocked = g.inspectCode(code[n.Lparen.Offset()+1:n.Rparen.Offset()], depth+1)
			return false
		case *syntax.ProcSubst:
			blocked = g.inspectCode(code[n.OpPos.Offset()+2:n.Rparen.Offset()], depth+1)
			return false
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
			for i, w := range n.Args[:len(n.Args)-len(commandArgs(n.Args))] {
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
			if environmentCommand(name, args[1:]) || credentialInspection(name, args[1:]) || printsSecret(name, args[1:]) {
				blocked = true
				return false
			}
			if name == "cd" && len(args) <= 2 {
				// A bare cd, like cd ~, changes to the home directory.
				path, ok := "~", true
				if len(args) == 2 {
					path, ok = g.pathWord(args[1].Parts)
				}
				if ok {
					if path == "~" {
						path = g.home
					} else if strings.HasPrefix(path, "~/") {
						path = filepath.Join(g.home, path[2:])
					}
					if !filepath.IsAbs(path) {
						path = filepath.Join(g.cwd, path)
					}
					g.cwd = filepath.Clean(path)
				}
			}
			if name == "git" && op.gitObjectRead(args[1:]) {
				blocked = true
				return false
			}
			if name == "ps" && processEnvironment(args[1:]) {
				blocked = true
				return false
			}
			patterns := searchPatterns(name, args[1:])
			metadata := metadataCommand(name, args[1:])
			if grepCommand(name) && recursiveGrep(name, args[1:]) && op.grepsProtectedDirectory(args[1:], patterns) {
				if op.grepTree != nil {
					*op.grepTree = true
				}
				blocked = true
				return false
			}
			if name == "find" && op.findActionBlocked(args[1:], code, depth) {
				blocked = true
				return false
			}
			for i, word := range n.Args {
				value, wildcard, literal := literalWord(word.Parts, false)
				if patterns[word] && literal && !wildcard {
					continue
				}
				if (name == "rg" || grepCommand(name)) && strings.HasPrefix(value, "-f") && len(value) > 2 && op.protected(value[2:]) {
					blocked = true
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
				if !fileCommand(name) || metadata && !searchFileInput(name, n.Args, i) {
					continue
				}
				if transferSource(name, i, len(n.Args)) && literal && op.protectedDirectory(value) {
					blocked = true
				}
				if writeOnlyOperand(name, i, len(n.Args), value) {
					continue
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
			// Writing or appending to a file discloses nothing; input
			// redirects and here-strings are still screened.
			if n.Hdoc == nil && !outputRedirect(n.Op) {
				inspectWord(g, n.Word)
			}
		}
		return !blocked
	})
	return "", blocked
}

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

func outputRedirect(op syntax.RedirOperator) bool {
	switch op {
	case syntax.RdrOut, syntax.AppOut, syntax.RdrClob, syntax.AppClob, syntax.RdrAll, syntax.RdrAllClob, syntax.AppAll, syntax.AppAllClob:
		return true
	}
	return false
}

// writeOnlyOperand is a copy/move destination or a tee output. Writing a
// protected file discloses nothing; sources remain screened.
func writeOnlyOperand(name string, index, total int, value string) bool {
	if strings.HasPrefix(value, "-") {
		return false
	}
	switch name {
	case "cp", "mv":
		return index == total-1
	case "tee":
		return true
	}
	return false
}

// printsSecret recognizes echo/printf writing a credential variable's value.
// Passing a credential to another program is ordinary runtime use, and
// set/length tests such as ${TOKEN:+set} and ${#TOKEN} print no value.
// Command substitutions are separate code and are checked on their own.
func printsSecret(name string, args []*syntax.Word) bool {
	if name != "echo" && name != "printf" {
		return false
	}
	found := false
	for _, w := range args {
		syntax.Walk(w, func(node syntax.Node) bool {
			switch n := node.(type) {
			case *syntax.CmdSubst, *syntax.ProcSubst:
				return false
			case *syntax.ParamExp:
				alternate := n.Exp != nil && (n.Exp.Op == syntax.AlternateUnset || n.Exp.Op == syntax.AlternateUnsetOrNull)
				if n.Param != nil && !n.Length && !alternate && policy.SecretName(n.Param.Value) {
					found = true
				}
			}
			return !found
		})
	}
	return found
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
