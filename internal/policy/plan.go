package policy

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"
	"path/filepath"
	"strings"
)

// Plan is a closed operation, not a program or shell fragment. Treat even an
// encoded hook-generated plan as untrusted at the execution boundary. A "read"
// prints the sanitized view; a "view" stores it at ViewPath for a file tool.
type Plan struct {
	Kind string `json:"kind"`
	Path string `json:"path"`
	Cwd  string `json:"cwd"`
}

func (p Plan) Encode() string {
	b, _ := json.Marshal(p)
	return base64.RawURLEncoding.EncodeToString(b)
}
func DecodePlan(s string) (Plan, bool) {
	var p Plan
	if len(s) > MaxDocument {
		return p, false
	}
	b, e := base64.RawURLEncoding.DecodeString(s)
	if e != nil {
		return p, false
	}
	d := json.NewDecoder(bytes.NewReader(b))
	d.DisallowUnknownFields()
	if d.Decode(&p) != nil {
		return p, false
	}
	var extra any
	if d.Decode(&extra) != io.EOF || !filepath.IsAbs(p.Cwd) {
		return p, false
	}
	return p, (p.Kind == "read" || p.Kind == "view") && filepath.IsAbs(p.Path)
}

// ViewPath names the sanitized copy that a file-tool read of source is pointed
// at. It derives from the trusted home and the source alone, never a plan
// field, and each source has one view, so views are replaced, not accumulated.
// The name drops a leading dot so a view never matches a protected filename.
func ViewPath(home, source string) string {
	sum := sha256.Sum256([]byte(filepath.Clean(source)))
	name := strings.TrimLeft(filepath.Base(source), ".")
	return filepath.Join(home, ".cache/agent-secrets/views", hex.EncodeToString(sum[:8])+"-"+name)
}
