package policy

import (
	"errors"
	"reflect"
	"unicode/utf8"
)

// ErrCredentialSetting refuses an edit that would write, replace, or remove a
// value the sanitized view hides.
var ErrCredentialSetting = errors.New("setting is or contains a credential")

// Edit sets, or with remove deletes, one object member of a JSON document. It
// is pure, like Sanitize. The key names object members only: an array element
// cannot be addressed, so an edit never changes how another value is
// classified (argument vectors pair --token with the following element).
// Missing parent objects are created. Output is re-encoded with two-space
// indentation, sorted keys, and exact numbers; formatting is not preserved.
func Edit(config Config, data []byte, key []string, value any, remove bool) (out []byte, err error) {
	defer func() {
		if recover() != nil {
			out = nil
			err = ErrDocument
		}
	}()
	if config.Format() != "json" || len(data) > MaxDocument || !utf8.Valid(data) || len(key) == 0 || len(key) > 64 {
		return nil, ErrDocument
	}
	document := decodeJSON(data)
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
	return encodeJSON(document)
}
