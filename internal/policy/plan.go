package policy

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"io"
	"path/filepath"
	"strings"
)

// Plan is a closed operation, not a program or shell fragment. Treat even an
// encoded hook-generated plan as untrusted at the execution boundary.
type Plan struct {
	Kind   string   `json:"kind"`
	Path   string   `json:"path,omitempty"`
	Cwd    string   `json:"cwd"`
	Reader string   `json:"reader,omitempty"`
	Args   []string `json:"args,omitempty"`
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
	switch p.Kind {
	case "read":
		_, ok := ConfigReadFilter(p.Reader, p.Args)
		return p, ok && filepath.IsAbs(p.Path)
	case "search":
		_, ok := ParseSearch(p.Args)
		return p, ok && p.Path == "" && p.Reader == ""
	}
	return p, false
}

type Search struct {
	Match     []string
	Inventory []string
	Roots     []string
	List      bool
	Count     bool
}

// ParseSearch accepts only ripgrep options whose reads we can control. Pattern
// files, config/preprocessor helpers, symlink following and arbitrary options
// are deliberately outside the closed runner interface.
func ParseSearch(args []string) (Search, bool) {
	var s Search
	explicit := false
	options := true
	var positional []string
	for i := 0; i < len(args); i++ {
		a := args[i]
		if strings.ContainsRune(a, 0) {
			return s, false
		}
		if options && a == "--" {
			options = false
			continue
		}
		if options && strings.HasPrefix(a, "--") {
			flag, value, attached := strings.Cut(a, "=")
			switch flag {
			case "--regexp", "--glob", "--iglob", "--type", "--type-not":
				if !attached {
					i++
					if i >= len(args) {
						return s, false
					}
					value = args[i]
				}
				if flag == "--regexp" {
					s.Match = append(s.Match, "-e", value)
					explicit = true
				} else {
					s.Inventory = append(s.Inventory, flag, value)
				}
			case "--hidden", "--no-ignore":
				if attached {
					return s, false
				}
				s.Inventory = append(s.Inventory, a)
			case "--line-number", "--ignore-case", "--fixed-strings", "--word-regexp", "--line-regexp", "--invert-match", "--no-heading", "--with-filename":
				if attached {
					return s, false
				}
				s.Match = append(s.Match, a)
			case "--files-with-matches":
				if attached {
					return s, false
				}
				s.List = true
			case "--count":
				if attached {
					return s, false
				}
				s.Count = true
			default:
				return s, false
			}
			continue
		}
		if options && strings.HasPrefix(a, "-") && a != "-" {
			for j := 1; j < len(a); j++ {
				c := a[j]
				if strings.ContainsRune("egtT", rune(c)) {
					v := a[j+1:]
					if v == "" {
						i++
						if i >= len(args) {
							return s, false
						}
						v = args[i]
					}
					if c == 'e' {
						s.Match = append(s.Match, "-e", v)
						explicit = true
					} else {
						s.Inventory = append(s.Inventory, "-"+string(c), v)
					}
					break
				}
				switch c {
				case 'n', 'i', 'F', 'w', 'x', 'v', 'H':
					s.Match = append(s.Match, "-"+string(c))
				case 'l':
					s.List = true
				case 'c':
					s.Count = true
				case 'u':
					s.Inventory = append(s.Inventory, "-u")
				default:
					return s, false
				}
			}
			continue
		}
		positional = append(positional, a)
	}
	if !explicit {
		if len(positional) == 0 {
			return s, false
		}
		s.Match = append(s.Match, "-e", positional[0])
		positional = positional[1:]
	}
	s.Roots = positional
	if len(s.Roots) == 0 {
		s.Roots = []string{"."}
	}
	for _, p := range s.Roots {
		if p == "-" || strings.ContainsRune(p, 0) {
			return s, false
		}
	}
	return s, !(s.List && s.Count)
}
