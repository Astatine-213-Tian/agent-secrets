package guard

import (
	"path/filepath"
	"sort"
	"strings"

	"github.com/Astatine-213-Tian/agent-secrets/internal/install"
	"github.com/Astatine-213-Tian/agent-secrets/internal/policy"
	"mvdan.cc/sh/v3/syntax"
)

func rewriteRead(payload map[string]any, home, cwd, binary string) map[string]any {
	tool, _ := payload["tool_name"].(string)
	key := "command"
	switch tool {
	case "Bash", "shell_command":
	case "exec_command":
		key = "cmd"
	default:
		return nil
	}
	args, ok := payload["tool_input"].(map[string]any)
	if !ok {
		return nil
	}
	command, ok := args[key].(string)
	if !ok {
		return nil
	}
	if p, ok := payload["cwd"].(string); ok && filepath.IsAbs(p) {
		cwd = p
	}
	if p, ok := args["workdir"].(string); ok {
		if filepath.IsAbs(p) {
			cwd = p
		} else {
			cwd = filepath.Join(cwd, p)
		}
	}
	f, err := syntax.NewParser(syntax.Variant(syntax.LangBash)).Parse(strings.NewReader(command), "")
	if err != nil {
		return nil
	}
	// The bridge only recognizes basic reads in an unchanged shell context.
	// It never interprets reader options or executes downstream commands.
	type edit struct {
		start, end uint
		text       string
	}
	var edits []edit
	contextChange := false
	syntax.Walk(f, func(node syntax.Node) bool {
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
		plan, ok := readPlan(command[start:end], home, cwd)
		if !ok {
			return true
		}
		replacement := shellQuote(binary) + " '__run' " + shellQuote(plan.Encode())
		edits = append(edits, edit{start, end, replacement})
		return false
	})
	if contextChange || len(edits) == 0 {
		return nil
	}
	sort.Slice(edits, func(i, j int) bool { return edits[i].start > edits[j].start })
	for _, e := range edits {
		command = command[:e.start] + e.text + command[e.end:]
	}
	updated := make(map[string]any, len(args))
	for k, v := range args {
		updated[k] = v
	}
	updated[key] = command
	// Check the complete resulting command and all sibling inputs. Only the
	// validated config read has been replaced; pipes and other calls stay native.
	g := checker{home: home, cwd: cwd, tool: strings.ToLower(tool)}
	for k, v := range updated {
		if k != "workdir" && g.inspect(v, strings.ToLower(k)) {
			return nil
		}
	}
	return updated
}

// Recognize one simple read. Never run expansion or reuse unparsed shell text.
func readPlan(command, home, cwd string) (policy.Plan, bool) {
	no := policy.Plan{}
	f, err := syntax.NewParser(syntax.Variant(syntax.LangBash)).Parse(strings.NewReader(command), "")
	if err != nil || len(f.Stmts) != 1 {
		return no, false
	}
	s := f.Stmts[0]
	call, ok := s.Cmd.(*syntax.CallExpr)
	if !ok || s.Negated || s.Background || s.Coprocess || s.Disown || len(call.Assigns) != 0 {
		return no, false
	}
	words := make([]string, len(call.Args))
	for i, word := range call.Args {
		var valid bool
		words[i], valid = readWord(word.Parts, command, home, false)
		if !valid {
			words[i], valid = (checker{home: home, cwd: cwd}).pathWord(word.Parts)
		}
		if !valid {
			return no, false
		}
	}
	if len(words) > 0 && words[0] == "command" {
		words = words[1:]
	}
	if len(words) == 0 {
		return no, false
	}
	reader := filepath.Base(words[0])
	if words[0] != reader && words[0] != "/bin/"+reader && words[0] != "/usr/bin/"+reader {
		return no, false
	}
	options := words[1:]
	var path string
	switch len(s.Redirs) {
	case 0:
		if len(options) == 0 {
			return no, false
		}
		path, options = options[len(options)-1], options[:len(options)-1]
		if len(options) > 0 && options[len(options)-1] == "--" {
			options = options[:len(options)-1]
		}
	case 1:
		r := s.Redirs[0]
		if r.Op != syntax.RdrIn || (r.N != nil && r.N.Value != "0") {
			return no, false
		}
		path, ok = readWord(r.Word.Parts, command, home, false)
		if !ok {
			path, ok = (checker{home: home, cwd: cwd}).pathWord(r.Word.Parts)
		}
		if !ok {
			return no, false
		}
	default:
		return no, false
	}
	if !filepath.IsAbs(path) {
		path = filepath.Join(cwd, path)
	}
	if install.Locations(home, cwd).ConfigFormat(path) == "" {
		return no, false
	}
	return policy.Plan{Kind: "read", Path: filepath.Clean(path), Cwd: cwd}, reader == "cat" && len(options) == 0
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
			if !quoted && i == 0 && strings.HasPrefix(v, "~/") {
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
