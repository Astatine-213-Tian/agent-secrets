// Package install owns user hook configuration and its filesystem lifecycle.
package install

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"strings"
)

var ErrConfig = errors.New("hook settings could not be safely parsed; no configuration values are printed")

type object = map[string]any
type Documents struct{ Codex, Claude []byte }

// Prepare merges one hook in each client without I/O. Unknown settings and
// other handlers survive unchanged; repeated calls produce identical output.
func Prepare(binary string, original Documents) (out Documents, err error) {
	defer func() {
		if recover() != nil {
			out = Documents{}
			err = ErrConfig
		}
	}()
	codex, claude := object{}, object{}
	if !decode(original.Codex, &codex) || !decode(original.Claude, &claude) {
		return out, ErrConfig
	}
	for _, m := range []object{codex, claude} {
		replaceHook(m, binary)
	}
	out.Codex, err = encode(codex)
	if err != nil {
		return Documents{}, err
	}
	out.Claude, err = encode(claude)
	if err != nil {
		return Documents{}, err
	}
	return out, nil
}
func table(m object, key string) object {
	if v, ok := m[key]; ok {
		return v.(map[string]any)
	}
	v := object{}
	m[key] = v
	return v
}
func array(m object, key string) []any {
	if v, ok := m[key]; ok {
		return v.([]any)
	}
	return []any{}
}
func decode(b []byte, m *object) bool {
	if len(b) == 0 {
		return true
	}
	d := json.NewDecoder(bytes.NewReader(b))
	d.UseNumber()
	if d.Decode(m) != nil || *m == nil {
		return false
	}
	var trailing any
	return d.Decode(&trailing) == io.EOF
}
func encode(m object) ([]byte, error) {
	b, e := json.MarshalIndent(m, "", "  ")
	if e != nil {
		return nil, ErrConfig
	}
	return append(b, '\n'), nil
}
func command(binary string) string {
	return "'" + strings.ReplaceAll(binary, "'", "'\"'\"'") + "' guard"
}
func replaceHook(m object, binary string) {
	h := table(m, "hooks")
	groups := []any{}
	for _, raw := range array(h, "PreToolUse") {
		g := raw.(map[string]any)
		kept := []any{}
		for _, entry := range array(g, "hooks") {
			x := entry.(map[string]any)
			if x["command"] != command(binary) {
				kept = append(kept, x)
			}
		}
		if len(kept) > 0 {
			g["hooks"] = kept
			groups = append(groups, g)
		}
	}
	h["PreToolUse"] = append(groups, object{"matcher": "*", "hooks": []any{object{"type": "command", "command": command(binary), "timeout": 5}}})
}
func hasHook(b []byte, binary string) (found bool) {
	defer func() {
		if recover() != nil {
			found = false
		}
	}()
	m := object{}
	if !decode(b, &m) {
		return false
	}
	for _, raw := range array(table(m, "hooks"), "PreToolUse") {
		g := raw.(map[string]any)
		if g["matcher"] != "*" {
			continue
		}
		for _, raw := range array(g, "hooks") {
			h := raw.(map[string]any)
			if h["command"] == command(binary) && h["type"] == "command" {
				return true
			}
		}
	}
	return false
}
