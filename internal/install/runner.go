package install

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/Astatine-213-Tian/agent-secrets/internal/policy"
)

var ErrPlan = errors.New("Cannot safely run protected operation; no file contents or error details were printed.")

const maxSearchBytes = 32 << 20

// RunPlan revalidates the operation against this process's trusted locations.
// The plan cannot supply a replacement home, classification or executable.
func RunPlan(ctx context.Context, home, encoded string) ([]byte, int, error) {
	p, ok := policy.DecodePlan(encoded)
	if !ok {
		return nil, 1, ErrPlan
	}
	l := Locations(home, p.Cwd)
	if !l.Valid() {
		return nil, 1, ErrPlan
	}
	switch p.Kind {
	case "read":
		format := l.ConfigFormat(p.Path)
		if format == "" {
			return nil, 1, ErrPlan
		}
		resolved, e := ResolvePath(p.Path)
		if e != nil {
			return nil, 1, ErrPlan
		}
		if relative, e := filepath.Rel(home, p.Path); e == nil && relative != ".." && !strings.HasPrefix(relative, "../") {
			root, e := ResolvePath(home)
			if e != nil || resolved != filepath.Join(root, relative) {
				return nil, 1, ErrPlan
			}
		}
		// Config aliases are not a way to read a different resource. System /tmp
		// aliases are resolved by resolving the containing trusted location too.
		parent, e := ResolvePath(filepath.Dir(p.Path))
		if e != nil || resolved != filepath.Join(parent, filepath.Base(p.Path)) {
			return nil, 1, ErrPlan
		}
		b, e := readRegular(resolved, policy.MaxDocument)
		if e != nil {
			return nil, 1, ErrPlan
		}
		b, e = policy.Sanitize(format, b)
		if e != nil {
			return nil, 1, ErrPlan
		}
		program, _ := policy.ConfigReadFilter(p.Reader, p.Args)
		out, code, e := runBuffered(ctx, program, p.Args, b, p.Cwd, policy.MaxDocument*8)
		if e != nil || code != 0 {
			return nil, 1, ErrPlan
		}
		return out, 0, nil
	case "search":
		return runSearch(ctx, l, p)
	}
	return nil, 1, ErrPlan
}

type limitedBuffer struct {
	bytes.Buffer
	limit int
}

func (b *limitedBuffer) Write(p []byte) (int, error) {
	if b.Len()+len(p) > b.limit {
		return 0, ErrPlan
	}
	return b.Buffer.Write(p)
}

func runBuffered(ctx context.Context, program string, args []string, input []byte, cwd string, limit int) ([]byte, int, error) {
	c := exec.CommandContext(ctx, program, args...)
	c.Dir = cwd
	c.Stdin = bytes.NewReader(input)
	c.Stderr = io.Discard
	// rg must not load arbitrary option files from RIPGREP_CONFIG_PATH.
	c.Env = []string{"PATH=/usr/bin:/bin", "LC_ALL=C", "HOME=" + cwd}
	out := limitedBuffer{limit: limit}
	c.Stdout = &out
	e := c.Run()
	if e == nil {
		return out.Bytes(), 0, nil
	}
	var exit *exec.ExitError
	if errors.As(e, &exit) && exit.ExitCode() == 1 && ctx.Err() == nil {
		return out.Bytes(), 1, nil
	}
	return nil, 1, ErrPlan
}

func ripgrep() string {
	for _, p := range []string{"/opt/homebrew/bin/rg", "/usr/local/bin/rg", "/usr/bin/rg"} {
		if st, e := os.Stat(p); e == nil && st.Mode().IsRegular() {
			return p
		}
	}
	return ""
}

func runSearch(ctx context.Context, l policy.Locations, p policy.Plan) ([]byte, int, error) {
	s, ok := policy.ParseSearch(p.Args)
	program := ripgrep()
	if !ok || program == "" {
		return nil, 1, ErrPlan
	}
	// Resolve protected anchors as well as candidates. This covers symlinked
	// home/location directories without reading a protected file.
	physical, e := ResolveLocations(l)
	if e != nil {
		return nil, 1, ErrPlan
	}
	protected := func(lexical, resolved string) bool {
		return l.Protected(lexical) || physical.Protected(resolved)
	}
	var candidates []string
	for _, root := range s.Roots {
		if !filepath.IsAbs(root) {
			root = filepath.Join(p.Cwd, root)
		}
		resolved, e := ResolvePath(root)
		if e != nil {
			return nil, 1, ErrPlan
		}
		st, e := os.Stat(resolved)
		if e != nil {
			return nil, 1, ErrPlan
		}
		if protected(root, resolved) {
			return nil, 1, ErrPlan
		}
		if st.Mode().IsRegular() {
			candidates = append(candidates, root)
			continue
		}
		if !st.IsDir() {
			return nil, 1, ErrPlan
		}
		// Inventory is metadata-only. It never receives content-producing options.
		args := append([]string{"--no-config", "--files", "--null"}, s.Inventory...)
		args = append(args, "--", root)
		out, _, e := runBuffered(ctx, program, args, nil, p.Cwd, maxSearchBytes)
		if e != nil {
			return nil, 1, ErrPlan
		}
		for _, file := range bytes.Split(out, []byte{0}) {
			if len(file) > 0 {
				candidates = append(candidates, string(file))
			}
		}
	}
	var result bytes.Buffer
	seen := map[string]bool{}
	matched := false
	for _, path := range candidates {
		if seen[path] {
			continue
		}
		seen[path] = true
		resolved, e := ResolvePath(path)
		if e != nil {
			return nil, 1, ErrPlan
		}
		if protected(path, resolved) {
			continue
		}
		// Skip aliases in recursive inventories. Independently pin and open each
		// approved regular file; never ask rg to open a directory or pathname.
		st, e := os.Lstat(path)
		if e != nil {
			return nil, 1, ErrPlan
		}
		if !st.Mode().IsRegular() {
			continue
		}
		b, e := readRegular(resolved, maxSearchBytes)
		if e != nil {
			return nil, 1, ErrPlan
		}
		label, e := filepath.Rel(p.Cwd, path)
		if e != nil {
			return nil, 1, ErrPlan
		}
		args := []string{"--no-config", "--color=never", "--no-heading"}
		args = append(args, s.Match...)
		if s.List {
			args = append(args, "--quiet")
		}
		if s.Count {
			args = append(args, "-c")
		}
		args = append(args, "--no-filename", "--", "-")
		out, code, e := runBuffered(ctx, program, args, b, p.Cwd, maxSearchBytes-result.Len())
		if e != nil {
			return nil, 1, ErrPlan
		}
		if code == 0 {
			matched = true
		}
		if s.List && code == 0 {
			result.WriteString(label + "\n")
		} else {
			for _, line := range bytes.SplitAfter(out, []byte{'\n'}) {
				if len(line) > 0 {
					result.WriteString(label + ":")
					result.Write(line)
				}
			}
		}
		if result.Len() > maxSearchBytes {
			return nil, 1, ErrPlan
		}
	}
	if !matched {
		return result.Bytes(), 1, nil
	}
	return result.Bytes(), 0, nil
}
