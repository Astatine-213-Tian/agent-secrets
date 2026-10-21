package policy

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/BurntSushi/toml"
)

const MaxDocument = 4 << 20

var ErrDocument = errors.New("cannot safely sanitize document")

// Sanitize is pure: no environment lookup, file reads or process execution.
// Parse errors never return partial output or parser diagnostics.
func Sanitize(format string, data []byte) (out []byte, err error) {
	defer func() {
		if recover() != nil {
			out = nil
			err = ErrDocument
		}
	}()
	if len(data) > MaxDocument || !utf8.Valid(data) {
		return nil, ErrDocument
	}
	if format == "npm" {
		return sanitizeNPM(string(data))
	}
	var document map[string]any
	switch format {
	case "toml":
		if toml.Unmarshal(data, &document) != nil {
			return nil, ErrDocument
		}
	case "json":
		if document = decodeJSON(data); document == nil {
			return nil, ErrDocument
		}
	default:
		return nil, ErrDocument
	}
	clean, err := sanitizeValue(document, nil, false)
	if err != nil {
		return nil, ErrDocument
	}
	if format == "json" {
		b, e := json.MarshalIndent(clean, "", "  ")
		if e != nil {
			return nil, ErrDocument
		}
		return append(b, '\n'), nil
	}
	var buf bytes.Buffer
	if toml.NewEncoder(&buf).Encode(clean) != nil {
		return nil, ErrDocument
	}
	return buf.Bytes(), nil
}

// decodeJSON returns one JSON object with numbers kept exact, or nil.
func decodeJSON(data []byte) map[string]any {
	var document map[string]any
	d := json.NewDecoder(bytes.NewReader(data))
	d.UseNumber()
	if d.Decode(&document) != nil {
		return nil
	}
	var extra any
	if d.Decode(&extra) != io.EOF {
		return nil
	}
	return document
}

func sanitizeValue(value any, path []string, hidden bool) (any, error) {
	if len(path) > 64 {
		return nil, ErrDocument
	}
	if !hidden && referenceField(path, value) {
		return value, nil
	}
	hidden = hidden || sensitiveField(path)
	switch v := value.(type) {
	case map[string]any:
		out := make(map[string]any, len(v))
		for k, item := range v {
			clean, e := sanitizeValue(item, append(path, k), hidden)
			if e != nil {
				return nil, e
			}
			out[k] = clean
		}
		return out, nil
	case []map[string]any:
		out := make([]any, len(v))
		for i, item := range v {
			clean, e := sanitizeValue(item, append(path, ""), hidden)
			if e != nil {
				return nil, e
			}
			out[i] = clean
		}
		return out, nil
	case []any:
		if len(path) > 0 && path[len(path)-1] == "args" && !hidden {
			return sanitizeArgs(v, path)
		}
		out := make([]any, len(v))
		for i, item := range v {
			clean, e := sanitizeValue(item, append(path, ""), hidden)
			if e != nil {
				return nil, e
			}
			out[i] = clean
		}
		return out, nil
	default:
		if hidden {
			return Redacted, nil
		}
		if stamp, ok := v.(time.Time); ok {
			// BurntSushi represents TOML local times with named locations but
			// its encoder converts them to UTC. Preserve their wall-clock
			// fields without changing process-global timezone state.
			formats := map[string]string{"datetime-local": "2006-01-02T15:04:05.999999999", "date-local": "2006-01-02", "time-local": "15:04:05.999999999"}
			if format, ok := formats[stamp.Location().String()]; ok {
				return localTimestamp(stamp.Format(format)), nil
			}
		}
		if s, ok := v.(string); ok {
			return SanitizeText(s), nil
		}
		return value, nil
	}
}

type localTimestamp string

func (t localTimestamp) MarshalTOML() ([]byte, error) { return []byte(t), nil }

// Argument vectors carry a relationship across elements: --token and its
// following value must be handled together, while ordinary arguments survive.
func sanitizeArgs(args []any, path []string) ([]any, error) {
	out := make([]any, len(args))
	secretNext := false
	for i, arg := range args {
		if secretNext {
			out[i] = Redacted
			secretNext = false
			continue
		}
		clean, e := sanitizeValue(arg, append(path, ""), false)
		if e != nil {
			return nil, e
		}
		out[i] = clean
		if s, ok := arg.(string); ok {
			secretNext = strings.HasPrefix(s, "--") && !strings.Contains(s, "=") && SecretName(strings.TrimPrefix(s, "--"))
			// A username alone is ordinary; the user:password auth form is not.
			if (s == "-u" || s == "--user") && i+1 < len(args) {
				if next, ok := args[i+1].(string); ok && strings.Contains(next, ":") {
					secretNext = true
				}
			}
		}
	}
	return out, nil
}

func sanitizeNPM(text string) ([]byte, error) {
	var out strings.Builder
	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}
		key, value, ok := strings.Cut(line, "=")
		if !ok || strings.TrimSpace(key) == "" {
			return nil, ErrDocument
		}
		key = strings.TrimSpace(key)
		value = strings.TrimSpace(value)
		name := key
		if i := strings.LastIndex(name, ":"); i >= 0 {
			name = name[i+1:]
		}
		if SecretName(name) || name == "_auth" {
			value = Redacted
		} else {
			value = SanitizeText(value)
		}
		out.WriteString(key + "=" + value + "\n")
	}
	return []byte(out.String()), nil
}
