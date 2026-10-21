package guard

import (
	"path/filepath"
	"strings"

	"github.com/Astatine-213-Tian/agent-secrets/internal/policy"
	"mvdan.cc/sh/v3/syntax"
)

func (shell *shellCommand) rewriteRead(binary string) string {
	if shell.tree == nil {
		return shell.source
	}
	var edits []shellEdit
	g := shell.scope
	contextChange := false
	syntax.Walk(shell.tree, func(node syntax.Node) bool {
		if call, ok := node.(*syntax.CallExpr); ok {
			words := commandArgs(call.Args)
			if len(call.Assigns) != 0 {
				contextChange = true
			}
			if len(words) > 0 {
				name, _, _ := literalWord(words[0].Parts, false)
				if name == "cd" || name == "env" || len(words) != len(call.Args) && name != "cat" {
					contextChange = true
				}
			}
		}
		if _, ok := node.(*syntax.DeclClause); ok {
			contextChange = true
		}
		s, ok := node.(*syntax.Stmt)
		if !ok {
			return true
		}
		if s.Cmd == nil {
			return true
		}
		start, end := s.Cmd.Pos().Offset(), s.Cmd.End().Offset()
		for _, r := range s.Redirs {
			if r.End().Offset() > end {
				end = r.End().Offset()
			}
		}
		plan, ok := g.readPlan(s, shell.source)
		if !ok {
			return true
		}
		replacement := shellQuote(binary) + " '__run' " + shellQuote(plan.Encode())
		edits = append(edits, shellEdit{start, end, replacement})
		return false
	})
	if contextChange {
		return shell.source
	}
	return applyShellEdits(shell.source, edits)
}

// readView points Claude Code's Read tool at a private sanitized copy of a
// supported configuration. Evaluate reads nothing: the hook has the private
// runner store the copy from the returned plan before emitting the rewrite.
func (g checker) readView(tool string, args any) (map[string]any, policy.Plan, bool) {
	input, ok := args.(map[string]any)
	if tool != "Read" || !ok {
		return nil, policy.Plan{}, false
	}
	p, ok := input["file_path"].(string)
	if !ok {
		return nil, policy.Plan{}, false
	}
	p = g.absolute(p)
	if g.locations().ConfigFormat(p) == "" {
		return nil, policy.Plan{}, false
	}
	updated := make(map[string]any, len(input))
	for key, value := range input {
		updated[key] = value
	}
	updated["file_path"] = policy.ViewPath(g.home, p)
	return updated, policy.Plan{Kind: "view", Path: p, Cwd: g.cwd}, true
}

// Recognize a basic cat read directly from the already-parsed statement.
func (g checker) readPlan(s *syntax.Stmt, source string) (policy.Plan, bool) {
	no := policy.Plan{}
	call, ok := s.Cmd.(*syntax.CallExpr)
	if !ok || len(call.Assigns) != 0 || len(call.Args) == 0 {
		return no, false
	}
	value := func(w *syntax.Word) (string, bool) {
		if v, ok := readWord(w.Parts, source, g.home, false); ok {
			return v, true
		}
		return g.pathWord(w.Parts)
	}
	args := call.Args
	if name, _ := value(args[0]); name == "command" {
		args = args[1:]
	}
	if len(args) == 0 {
		return no, false
	}
	name, _ := value(args[0])
	if name != "cat" && name != "/bin/cat" && name != "/usr/bin/cat" {
		return no, false
	}
	args = args[1:]
	var operand *syntax.Word
	switch len(s.Redirs) {
	case 0:
		if len(args) == 2 {
			if flag, _ := value(args[0]); flag == "--" {
				args = args[1:]
			}
		}
		if len(args) != 1 {
			return no, false
		}
		operand = args[0]
	case 1:
		r := s.Redirs[0]
		if len(args) != 0 || r.Op != syntax.RdrIn || (r.N != nil && r.N.Value != "0") || r.Pos().Offset() < call.Pos().Offset() {
			return no, false
		}
		operand = r.Word
	default:
		return no, false
	}
	path, ok := value(operand)
	if !ok {
		return no, false
	}
	if !filepath.IsAbs(path) {
		path = filepath.Join(g.cwd, path)
	}
	if g.locations().ConfigFormat(path) == "" {
		return no, false
	}
	return policy.Plan{Kind: "read", Path: filepath.Clean(path), Cwd: g.cwd}, true
}

func readWord(parts []syntax.WordPart, source, home string, quoted bool) (string, bool) {
	var out strings.Builder
	for i, part := range parts {
		switch p := part.(type) {
		case *syntax.Lit:
			// Backslash escapes and globbing are unnecessary for common reads;
			// declining them is safer than approximating shell evaluation.
			if strings.ContainsAny(p.Value, "\\\x00\n\r") || (!quoted && strings.ContainsAny(p.Value, "*?[]{}")) {
				return "", false
			}
			v := p.Value
			if !quoted && i == 0 && (v == "~" || strings.HasPrefix(v, "~/")) {
				v = home + v[1:]
			}
			out.WriteString(v)
		case *syntax.SglQuoted:
			if p.Dollar {
				return "", false
			}
			out.WriteString(p.Value)
		case *syntax.DblQuoted:
			if p.Dollar {
				return "", false
			}
			v, ok := readWord(p.Parts, source, home, true)
			if !ok {
				return "", false
			}
			out.WriteString(v)
		case *syntax.ParamExp:
			text := source[p.Pos().Offset():p.End().Offset()]
			if text != "$HOME" && text != "${HOME}" {
				return "", false
			}
			out.WriteString(home)
		default:
			return "", false
		}
	}
	return out.String(), true
}
