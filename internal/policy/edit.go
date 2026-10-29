package policy

import (
	"bytes"
	"encoding/json"
	"errors"
	"reflect"
	"time"
	"unicode/utf8"

	"github.com/BurntSushi/toml"
)

// ErrCredentialSetting refuses an edit that would write, replace, or remove a
// value the sanitized view hides.
var ErrCredentialSetting = errors.New("setting is or contains a credential")

// Edit sets, or with remove deletes, one object member of a JSON or TOML
// document. It is pure, like Sanitize. The key names object members (TOML
// tables and keys) only: an array element cannot be addressed, so an edit never
// changes how another value is classified (argument vectors pair --token with
// the following element). Missing parent objects are created. Output is
// re-encoded with sorted keys and exact values; formatting and TOML comments
// are not preserved.
func Edit(config Config, data []byte, key []string, value any, remove bool) (out []byte, err error) {
	defer func() {
		if recover() != nil {
			out = nil
			err = ErrDocument
		}
	}()
	format := config.Format()
	if format != "json" && format != "toml" || len(data) > MaxDocument || !utf8.Valid(data) || len(key) == 0 || len(key) > 64 {
		return nil, ErrDocument
	}
	var document map[string]any
	if format == "json" {
		document = decodeJSON(data)
	} else if toml.Unmarshal(data, &document) == nil {
		document, _ = tomlDocument(document).(map[string]any)
		if !remove {
			if value = tomlValue(value); value == nil {
				return nil, ErrDocument
			}
		}
	}
	if document == nil {
		return nil, ErrDocument
	}
	parent := document
	for i, name := range key {
		// Encoding would replace invalid UTF-8, renaming the member.
		if name == "" || !utf8.ValidString(name) {
			return nil, ErrDocument
		}
		// Ancestors hide their whole subtree, so check each prefix.
		if sensitiveField(config, key[:i+1]) {
			return nil, ErrCredentialSetting
		}
		if i == len(key)-1 {
			break
		}
		next, exists := parent[name]
		if !exists {
			if remove {
				return nil, ErrDocument
			}
			child := map[string]any{}
			parent[name] = child
			parent = child
			continue
		}
		child, ok := next.(map[string]any)
		if !ok {
			return nil, ErrDocument
		}
		parent = child
	}
	name := key[len(key)-1]
	old, exists := parent[name]
	if exists {
		// The old value must be fully visible in the sanitized view.
		clean, e := sanitizeValue(config, old, key, false)
		if e != nil || !reflect.DeepEqual(clean, old) {
			return nil, ErrCredentialSetting
		}
	}
	if remove {
		if !exists {
			return nil, ErrDocument
		}
		delete(parent, name)
	} else {
		parent[name] = value
	}
	if format == "json" {
		return encodeJSON(document)
	}
	return encodeTOML(document)
}

// tomlDocument gives decoded TOML the shapes Sanitize produces, so a visible
// value compares equal to its view: local times keep their wall clock, and
// arrays of tables become plain arrays.
func tomlDocument(value any) any {
	switch v := value.(type) {
	case map[string]any:
		for k, item := range v {
			v[k] = tomlDocument(item)
		}
	case []map[string]any:
		out := make([]any, len(v))
		for i, item := range v {
			out[i] = tomlDocument(item)
		}
		return out
	case []any:
		for i, item := range v {
			v[i] = tomlDocument(item)
		}
	case time.Time:
		if local, ok := localTime(v); ok {
			return local
		}
	}
	return value
}

// tomlValue converts a JSON value to TOML, or returns nil: TOML has no null.
// JSON numbers become integers when exact, and floats otherwise.
func tomlValue(value any) any {
	switch v := value.(type) {
	case json.Number:
		if n, e := v.Int64(); e == nil {
			return n
		}
		if f, e := v.Float64(); e == nil {
			return f
		}
		return nil
	case map[string]any:
		for k, item := range v {
			if v[k] = tomlValue(item); v[k] == nil {
				return nil
			}
		}
	case []any:
		for i, item := range v {
			if v[i] = tomlValue(item); v[i] == nil {
				return nil
			}
		}
	}
	return value
}

// encodeTOML writes flat tables and refuses output that does not parse back.
func encodeTOML(document map[string]any) ([]byte, error) {
	var buf bytes.Buffer
	encoder := toml.NewEncoder(&buf)
	encoder.Indent = ""
	var check map[string]any
	if encoder.Encode(document) != nil || toml.Unmarshal(buf.Bytes(), &check) != nil {
		return nil, ErrDocument
	}
	return buf.Bytes(), nil
}
