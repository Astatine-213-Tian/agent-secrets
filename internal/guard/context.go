package guard

import (
	"path/filepath"
	"strings"

	"mvdan.cc/sh/v3/syntax"
)

func (g checker) atWorkdir(dir string) checker {
	if filepath.IsAbs(dir) {
		g.cwd = dir
	} else {
		g.cwd = filepath.Join(g.cwd, dir)
	}
	return g
}

// scopeCall handles literal env working directories and credential-location
// assignments. Unknown computed location changes cannot safely be interpreted.
func (g checker) scopeCall(call *syntax.CallExpr) (checker, bool) {
	prefix := len(call.Args) - len(commandArgs(call.Args))
	inEnv := false
	for i, w := range call.Args[:prefix] {
		v, _, _ := literalWord(w.Parts, false)
		if filepath.Base(v) == "env" {
			inEnv = true
			continue
		}
		if !inEnv {
			continue
		}
		if v == "-C" || v == "--chdir" {
			if i+1 >= len(call.Args) {
				return g, false
			}
			p, glob, ok := literalWord(call.Args[i+1].Parts, false)
			if !ok || glob {
				return g, false
			}
			if !filepath.IsAbs(p) {
				p = filepath.Join(g.cwd, p)
			}
			g.cwd = filepath.Clean(p)
		} else if strings.HasPrefix(v, "--chdir=") {
			p := strings.TrimPrefix(v, "--chdir=")
			if !filepath.IsAbs(p) {
				p = filepath.Join(g.cwd, p)
			}
			g.cwd = filepath.Clean(p)
		}
	}
	l := g.locations()
	changed := false
	assign := func(name, value string, valid bool) bool {
		var target *string
		switch name {
		case "CODEX_HOME":
			target = &l.Codex
		case "DOCKER_CONFIG":
			target = &l.Docker
		case "NPM_CONFIG_USERCONFIG":
			target = &l.NPM
		case "AWS_SHARED_CREDENTIALS_FILE":
			target = &l.AWS
		default:
			return true
		}
		if !valid || value == "" {
			return false
		}
		if !filepath.IsAbs(value) {
			value = filepath.Join(g.cwd, value)
		}
		*target = value
		changed = true
		return true
	}
	for _, a := range call.Assigns {
		if a.Name != nil && a.Value != nil {
			v, glob, ok := literalWord(a.Value.Parts, false)
			if !assign(a.Name.Value, v, ok && !glob) {
				return g, false
			}
		}
	}
	for _, w := range call.Args {
		v, glob, ok := literalWord(w.Parts, false)
		name, value, found := strings.Cut(v, "=")
		if found && !assign(name, value, ok && !glob) {
			return g, false
		}
	}
	if changed {
		g.stores = &l
	}
	return g, true
}

func (g checker) pathWord(parts []syntax.WordPart) (string, bool) {
	var out strings.Builder
	for _, part := range parts {
		switch p := part.(type) {
		case *syntax.ParamExp:
			if p.Param == nil || p.Excl || p.Length || p.Width || p.Index != nil || p.Slice != nil || p.Repl != nil || p.Exp != nil {
				return "", false
			}
			l := g.locations()
			value := map[string]string{"HOME": g.home, "PWD": g.cwd, "CODEX_HOME": l.Codex, "DOCKER_CONFIG": l.Docker, "NPM_CONFIG_USERCONFIG": l.NPM, "AWS_SHARED_CREDENTIALS_FILE": l.AWS}[p.Param.Value]
			if value == "" {
				return "", false
			}
			out.WriteString(value)
		case *syntax.DblQuoted:
			v, ok := g.pathWord(p.Parts)
			if !ok {
				return "", false
			}
			out.WriteString(v)
		default:
			v, glob, ok := literalWord([]syntax.WordPart{part}, false)
			if !ok || glob {
				return "", false
			}
			out.WriteString(v)
		}
	}
	return out.String(), true
}
