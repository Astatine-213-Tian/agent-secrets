package guard

import (
	"bytes"
	"encoding/json"
	"io"
	"path/filepath"
	"strings"

	"github.com/Astatine-213-Tian/agent-secrets/internal/policy"
	"mvdan.cc/sh/v3/syntax"
)

// Hook adds transparent shell-read rewriting to Check. Neither path reads any
// configuration contents. Only the rewritten tool's private runner does that.
func Hook(input io.Reader, stdout, stderr io.Writer, home, cwd, binary string) (code int) {
	defer func() {
		if recover() != nil {
			_, _ = io.WriteString(stderr, Reason+"\n")
			code = 2
		}
	}()
	data, err := io.ReadAll(io.LimitReader(input, maxInput+1))
	if err != nil || len(data) > maxInput {
		_, _ = io.WriteString(stderr, Reason+"\n")
		return 2
	}
	if updated := rewriteRead(data, home, cwd, binary); updated != nil {
		b, err := json.Marshal(map[string]any{"hookSpecificOutput": map[string]any{
			"hookEventName":      "PreToolUse",
			"permissionDecision": "allow",
			"updatedInput":       updated,
		}})
		if err == nil {
			_, err = stdout.Write(append(b, '\n'))
		}
		if err != nil {
			_, _ = io.WriteString(stderr, Reason+"\n")
			return 2
		}
		return 0
	}
	return Check(bytes.NewReader(data), stderr, home, cwd)
}

func rewriteRead(data []byte, home, cwd, binary string) map[string]any {
	if !filepath.IsAbs(home) || !filepath.IsAbs(binary) {
		return nil
	}
	var payload map[string]any
	d := json.NewDecoder(bytes.NewReader(data))
	d.UseNumber()
	if d.Decode(&payload) != nil || payload == nil {
		return nil
	}
	var trailing any
	if d.Decode(&trailing) != io.EOF {
		return nil
	}
	if event, exists := payload["hook_event_name"]; exists && event != "PreToolUse" {
		return nil
	}
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
	reader, options, ok := configRead(command, home, cwd)
	if !ok {
		return nil
	}
	// Preserve metadata and its number precision, but screen every sibling.
	// Do not let an accepted command exempt another path, script or input.
	updated := make(map[string]any, len(args))
	for k, v := range args {
		if k != key {
			updated[k] = v
		}
	}
	g := checker{home: home, cwd: cwd, tool: strings.ToLower(tool)}
	if g.inspect(updated, "") {
		return nil
	}
	words := []string{binary, "__read-codex-config", home, reader}
	words = append(words, options...)
	for i, word := range words {
		words[i] = "'" + strings.ReplaceAll(word, "'", "'\"'\"'") + "'"
	}
	updated[key] = strings.Join(words, " ")
	return updated
}

// Recognize one simple read. Never run expansion or reuse unparsed shell text.
func configRead(command, home, cwd string) (string, []string, bool) {
	f, err := syntax.NewParser(syntax.Variant(syntax.LangBash)).Parse(strings.NewReader(command), "")
	if err != nil || len(f.Stmts) != 1 {
		return "", nil, false
	}
	s := f.Stmts[0]
	call, ok := s.Cmd.(*syntax.CallExpr)
	if !ok || s.Negated || s.Background || s.Coprocess || s.Disown || len(call.Assigns) != 0 {
		return "", nil, false
	}
	words := make([]string, len(call.Args))
	for i, word := range call.Args {
		var valid bool
		words[i], valid = readWord(word.Parts, command, home, false)
		if !valid {
			return "", nil, false
		}
	}
	if len(words) > 0 && words[0] == "command" {
		words = words[1:]
	}
	if len(words) == 0 {
		return "", nil, false
	}
	reader := filepath.Base(words[0])
	if words[0] != reader && words[0] != "/bin/"+reader && words[0] != "/usr/bin/"+reader {
		return "", nil, false
	}
	options := words[1:]
	var path string
	switch len(s.Redirs) {
	case 0:
		if len(options) == 0 {
			return "", nil, false
		}
		path, options = options[len(options)-1], options[:len(options)-1]
		if len(options) > 0 && options[len(options)-1] == "--" {
			options = options[:len(options)-1]
		}
	case 1:
		r := s.Redirs[0]
		if r.Op != syntax.RdrIn || (r.N != nil && r.N.Value != "0") {
			return "", nil, false
		}
		path, ok = readWord(r.Word.Parts, command, home, false)
		if !ok {
			return "", nil, false
		}
	default:
		return "", nil, false
	}
	if !filepath.IsAbs(path) {
		path = filepath.Join(cwd, path)
	}
	if filepath.Clean(path) != filepath.Join(home, ".codex/config.toml") {
		return "", nil, false
	}
	_, ok = policy.ConfigReadFilter(reader, options)
	return reader, options, ok
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
