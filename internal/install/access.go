package install

import (
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/Astatine-213-Tian/agent-secrets/internal/policy"
)

// Locations reads only supported location overrides, never credential values.
func Locations(home, cwd string) policy.Locations {
	abs := func(name string) string {
		p := os.Getenv(name)
		if p != "" && !filepath.IsAbs(p) {
			p = filepath.Join(cwd, p)
		}
		return p
	}
	return policy.Locations{Home: home, Codex: abs("CODEX_HOME"), Docker: abs("DOCKER_CONFIG"), NPM: abs("NPM_CONFIG_USERCONFIG"), AWS: abs("AWS_SHARED_CREDENTIALS_FILE")}
}

// ResolveLocations gives both callers the same physical credential anchors,
// including a home or configured store reached through a directory alias.
func ResolveLocations(l policy.Locations) (policy.Locations, error) {
	out := l
	for _, p := range []*string{&out.Home, &out.Codex, &out.Docker, &out.NPM, &out.AWS} {
		if *p == "" {
			continue
		}
		r, e := ResolvePath(*p)
		if e != nil {
			return out, e
		}
		*p = r
	}
	return out, nil
}

// ResolvePath follows existing parents and dangling symlinks using metadata
// only. A link to a missing credential file still has a protected target.
func ResolvePath(p string) (string, error) { return resolvePath(p, 0) }

func resolvePath(p string, depth int) (string, error) {
	if depth > 64 {
		return "", os.ErrInvalid
	}
	if p == filepath.Dir(p) {
		return p, nil
	}
	parent, err := resolvePath(filepath.Dir(p), depth+1)
	if err != nil {
		return "", err
	}
	p = filepath.Join(parent, filepath.Base(p))
	st, err := os.Lstat(p)
	if os.IsNotExist(err) {
		return p, nil
	}
	if err != nil {
		return "", err
	}
	if st.Mode()&os.ModeSymlink == 0 {
		return p, nil
	}
	target, err := os.Readlink(p)
	if err != nil {
		return "", err
	}
	if !filepath.IsAbs(target) {
		target = filepath.Join(parent, target)
	}
	return resolvePath(filepath.Clean(target), depth+1)
}

// readRegular pins every directory and checks identity before opening a file.
// No symlink is followed after classification, including a swapped parent.
func readRegular(path string, limit int64) ([]byte, error) {
	if !filepath.IsAbs(path) {
		return nil, os.ErrInvalid
	}
	root, err := os.OpenRoot("/")
	if err != nil {
		return nil, err
	}
	defer func() { root.Close() }()
	parts := strings.Split(strings.TrimPrefix(filepath.Clean(path), "/"), "/")
	for _, part := range parts[:len(parts)-1] {
		st, e := root.Lstat(part)
		if e != nil || !st.IsDir() {
			return nil, os.ErrInvalid
		}
		next, e := root.OpenRoot(part)
		if e != nil {
			return nil, e
		}
		opened, e := next.Stat(".")
		if e != nil || !os.SameFile(st, opened) {
			next.Close()
			return nil, os.ErrInvalid
		}
		root.Close()
		root = next
	}
	name := parts[len(parts)-1]
	before, err := root.Lstat(name)
	if err != nil || !before.Mode().IsRegular() || before.Size() > limit {
		return nil, os.ErrInvalid
	}
	f, err := root.OpenFile(name, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	opened, err := f.Stat()
	if err != nil || !opened.Mode().IsRegular() || !os.SameFile(before, opened) || opened.Size() > limit {
		return nil, os.ErrInvalid
	}
	b, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil || int64(len(b)) > limit {
		return nil, os.ErrInvalid
	}
	return b, nil
}
