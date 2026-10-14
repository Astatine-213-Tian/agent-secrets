package install

import (
	"errors"
	"path/filepath"
	"strings"

	"github.com/Astatine-213-Tian/agent-secrets/internal/policy"
)

var ErrPlan = errors.New("Cannot safely run protected operation; no file contents or error details were printed.")

// RunPlan revalidates the operation against this process's trusted locations.
// The plan cannot supply a replacement home, classification or executable.
func RunPlan(home, encoded string) ([]byte, error) {
	p, ok := policy.DecodePlan(encoded)
	if !ok {
		return nil, ErrPlan
	}
	l := Locations(home, p.Cwd)
	if !l.Valid() {
		return nil, ErrPlan
	}
	switch p.Kind {
	case "read":
		format := l.ConfigFormat(p.Path)
		if format == "" {
			return nil, ErrPlan
		}
		resolved, e := ResolvePath(p.Path)
		if e != nil {
			return nil, ErrPlan
		}
		if relative, e := filepath.Rel(home, p.Path); e == nil && relative != ".." && !strings.HasPrefix(relative, "../") {
			root, e := ResolvePath(home)
			if e != nil || resolved != filepath.Join(root, relative) {
				return nil, ErrPlan
			}
		}
		// Config aliases are not a way to read a different resource. System /tmp
		// aliases are resolved by resolving the containing trusted location too.
		parent, e := ResolvePath(filepath.Dir(p.Path))
		if e != nil || resolved != filepath.Join(parent, filepath.Base(p.Path)) {
			return nil, ErrPlan
		}
		b, e := readRegular(resolved, policy.MaxDocument)
		if e != nil {
			return nil, ErrPlan
		}
		b, e = policy.Sanitize(format, b)
		if e != nil {
			return nil, ErrPlan
		}
		return b, nil
	}
	return nil, ErrPlan
}
