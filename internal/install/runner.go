package install

import (
	"errors"
	"os"
	"path/filepath"
	"strings"

	"github.com/Astatine-213-Tian/agent-secrets/internal/policy"
)

var ErrPlan = errors.New("Cannot safely run protected operation; no file contents or error details were printed.")

// RunPlan revalidates the operation against this process's trusted locations.
// The plan cannot supply a replacement home, classification, executable, or
// output destination. A read returns the sanitized view; a view stores it
// privately at policy.ViewPath and returns nothing.
func RunPlan(home, encoded string) ([]byte, error) {
	p, ok := policy.DecodePlan(encoded)
	if !ok {
		return nil, ErrPlan
	}
	resolved, format, e := configFile(home, p.Cwd, p.Path)
	if e != nil {
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
	if p.Kind == "view" {
		if writeView(policy.ViewPath(home, p.Path), b) != nil {
			return nil, ErrPlan
		}
		return nil, nil
	}
	return b, nil
}

// configFile classifies a supported configuration and resolves it to the file
// that may be opened. Config aliases are not a way to reach another resource.
func configFile(home, cwd, path string) (resolved, format string, err error) {
	l := Locations(home, cwd)
	if !l.Valid() || !filepath.IsAbs(path) {
		return "", "", ErrPlan
	}
	path = filepath.Clean(path)
	format = l.ConfigFormat(path)
	if format == "" {
		return "", "", ErrPlan
	}
	resolved, e := ResolvePath(path)
	if e != nil {
		return "", "", ErrPlan
	}
	if relative, e := filepath.Rel(home, path); e == nil && relative != ".." && !strings.HasPrefix(relative, "../") {
		root, e := ResolvePath(home)
		if e != nil || resolved != filepath.Join(root, relative) {
			return "", "", ErrPlan
		}
	}
	// System /tmp aliases are resolved by resolving the containing location too.
	parent, e := ResolvePath(filepath.Dir(path))
	if e != nil || resolved != filepath.Join(parent, filepath.Base(path)) {
		return "", "", ErrPlan
	}
	return resolved, format, nil
}

// writeView replaces one private view file. Its directory is kept owner-only.
func writeView(path string, b []byte) error {
	dir := filepath.Dir(path)
	if os.MkdirAll(dir, 0700) != nil {
		return ErrPlan
	}
	if st, e := os.Lstat(dir); e != nil || !st.IsDir() || os.Chmod(dir, 0700) != nil {
		return ErrPlan
	}
	return atomicWrite(path, b, 0600)
}
