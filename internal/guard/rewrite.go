package guard

import (
	"sort"
	"strings"

	"mvdan.cc/sh/v3/syntax"
)

// shellCommand owns the shared input and source handling for the two rewrites.
// Rule-specific code edits shell source; tool metadata is copied here.
type shellCommand struct {
	input       map[string]any
	key, source string
	tree        *syntax.File
	scope       checker
}

func (g checker) shellCommand(tool string, input any) *shellCommand {
	key := "command"
	switch tool {
	case "Bash", "shell_command":
	case "exec_command":
		key = "cmd"
	default:
		return nil
	}
	args, ok := input.(map[string]any)
	if !ok {
		return nil
	}
	source, ok := args[key].(string)
	if !ok {
		return nil
	}
	if dir, ok := args["workdir"].(string); ok {
		g = g.atWorkdir(dir)
	}
	return &shellCommand{args, key, source, parseRewrite(source), g}
}

func parseRewrite(source string) *syntax.File {
	f, err := syntax.NewParser(syntax.Variant(syntax.LangBash)).Parse(strings.NewReader(source), "")
	if err != nil {
		return nil
	}
	return f
}

func (s *shellCommand) updatedInput(source string) map[string]any {
	updated := make(map[string]any, len(s.input))
	for key, value := range s.input {
		updated[key] = value
	}
	updated[s.key] = source
	return updated
}

type shellEdit struct {
	start, end uint
	text       string
}

func applyShellEdits(source string, edits []shellEdit) string {
	sort.SliceStable(edits, func(i, j int) bool { return edits[i].start > edits[j].start })
	for _, edit := range edits {
		source = source[:edit.start] + edit.text + source[edit.end:]
	}
	return source
}

func shellQuote(s string) string { return "'" + strings.ReplaceAll(s, "'", "'\"'\"'") + "'" }
