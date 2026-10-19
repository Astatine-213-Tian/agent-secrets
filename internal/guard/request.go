package guard

import (
	"bytes"
	"encoding/json"
	"io"
	"path/filepath"
	"strings"

	"mvdan.cc/sh/v3/syntax"
)

type Outcome uint8

const (
	Deny Outcome = iota
	Allow
	Rewrite
)

type Decision struct {
	Kind  Outcome
	Input map[string]any
	// ConfigView marks a denial that names a supported configuration file
	// while the config-read bridge is available.
	ConfigView bool
}

// Evaluate is the screening boundary. It parses once, retains JSON precision,
// and returns a decision without reading file contents or emitting diagnostics.
// An empty binary disables rewriting for the guard-only protocol.
func Evaluate(data []byte, home, cwd, binary string) (decision Decision) {
	defer func() {
		if recover() != nil {
			decision = Decision{Kind: Deny}
		}
	}()
	if len(data) > maxInput || !filepath.IsAbs(home) || !filepath.IsAbs(cwd) {
		return
	}
	var payload map[string]any
	d := json.NewDecoder(bytes.NewReader(data))
	d.UseNumber()
	if d.Decode(&payload) != nil || payload == nil {
		return
	}
	var trailing any
	if d.Decode(&trailing) != io.EOF {
		return
	}
	if event, exists := payload["hook_event_name"]; exists && event != "PreToolUse" {
		return
	}
	tool, ok := payload["tool_name"].(string)
	if !ok || tool == "" {
		return
	}
	args, found := payload["tool_input"]
	if !found {
		args, found = payload["arguments"]
	}
	if !found || args == nil {
		return
	}
	if dir, exists := payload["cwd"]; exists {
		p, ok := dir.(string)
		if !ok || !filepath.IsAbs(p) {
			return
		}
		cwd = p
	}
	switch a := args.(type) {
	case string:
	case map[string]any:
		if dir, exists := a["workdir"]; exists {
			if p, ok := dir.(string); !ok || p == "" {
				return
			}
		}
	default:
		return
	}
	g := checker{home: home, cwd: cwd, tool: strings.ToLower(tool)}
	var shell *shellCommand
	if filepath.IsAbs(binary) {
		shell = g.shellCommand(tool, payload["tool_input"])
		if shell != nil {
			if source := shell.rewriteRead(binary); source != shell.source {
				args = shell.updatedInput(source)
				shell.source, shell.tree = source, parseRewrite(source)
			}
		}
	}
	// Screen once, after replacing only validated config reads. All remaining
	// operands and sibling inputs stay subject to the same disclosure rules.
	if g.inspect(args, "") {
		return Decision{Kind: Deny, ConfigView: filepath.IsAbs(binary) && g.namesConfig(args)}
	}
	if shell != nil {
		if source := shell.rewriteSearch(); source != shell.input[shell.key] {
			return Decision{Kind: Rewrite, Input: shell.updatedInput(source)}
		}
	}
	return Decision{Kind: Allow}
}

// namesConfig reports a file-tool path or shell word naming a supported
// configuration file. It only selects the denial message.
func (g checker) namesConfig(args any) bool {
	m, ok := args.(map[string]any)
	if !ok {
		return false
	}
	for _, key := range []string{"file_path", "path"} {
		if v, ok := m[key].(string); ok && g.configPath(v) {
			return true
		}
	}
	for _, key := range []string{"command", "cmd"} {
		source, ok := m[key].(string)
		if !ok {
			continue
		}
		f := parseRewrite(source)
		if f == nil {
			continue
		}
		found := false
		syntax.Walk(f, func(n syntax.Node) bool {
			if w, ok := n.(*syntax.Word); ok {
				if v, ok := readWord(w.Parts, source, g.home, false); ok && g.configPath(v) {
					found = true
				}
			}
			return !found
		})
		if found {
			return true
		}
	}
	return false
}

func (g checker) configPath(p string) bool {
	if p == "~" || strings.HasPrefix(p, "~/") {
		p = g.home + p[1:]
	}
	if !filepath.IsAbs(p) {
		p = filepath.Join(g.cwd, p)
	}
	return g.locations().ConfigFormat(filepath.Clean(p)) != ""
}
