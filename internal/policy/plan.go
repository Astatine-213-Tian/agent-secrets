package policy

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"io"
	"path/filepath"
)

// Plan is a closed operation, not a program or shell fragment. Treat even an
// encoded hook-generated plan as untrusted at the execution boundary.
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
	return p, p.Kind == "read" && filepath.IsAbs(p.Path)
}
