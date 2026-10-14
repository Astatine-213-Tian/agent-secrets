package guard

import (
	"bytes"
	"encoding/json"
	"io"
	"path/filepath"
	"strings"
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
	if filepath.IsAbs(binary) {
		if updated := rewriteRead(payload, home, cwd, binary); updated != nil {
			rewritten := make(map[string]any, len(payload))
			for k, v := range payload {
				rewritten[k] = v
			}
			rewritten["tool_input"] = updated
			if search := rewriteSearch(rewritten, home, cwd); search != nil {
				updated = search
			}
			return Decision{Kind: Rewrite, Input: updated}
		}
	}
	g := checker{home: home, cwd: cwd, tool: strings.ToLower(tool)}
	if !g.inspect(args, "") {
		if filepath.IsAbs(binary) {
			if updated := rewriteSearch(payload, home, cwd); updated != nil {
				return Decision{Kind: Rewrite, Input: updated}
			}
		}
		return Decision{Kind: Allow}
	}
	return
}
