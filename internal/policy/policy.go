// Package policy owns the hook's credential-name and path recognition rules.
package policy

import (
	"path/filepath"
	"strings"
)

func DeniedPaths(home string) []string {
	paths := []string{"/**/.env", "/**/.env.*", "/**/private-key.pem", "/**/private.key", "/**/id_rsa", "/**/id_dsa", "/**/id_ed25519", "/**/id_ecdsa", "/**/*.p12", "/**/*.pfx", "/**/.envrc", "/**/.dev.vars", "/**/browser-profiles/**/state.json", "/**/browser-profiles/**/.state.*.tmp"}
	paths = append(paths, "/**/.npmrc")
	for _, p := range []string{".aws/credentials", ".ssh/id_*", ".config/gh/hosts.yml", ".git-credentials", ".kube/config", ".config/gcloud/application_default_credentials.json", ".config/gcloud/credentials.db", ".config/gcloud/access_tokens.db", ".config/gcloud/legacy_credentials", ".netrc", ".npmrc", ".pypirc", ".docker/config.json", ".codex/auth.json", ".codex/config.toml", ".claude/settings.json", ".claude.json", ".claude/.credentials.json", ".local/share/agent-secrets/backups"} {
		paths = append(paths, filepath.Join(home, p))
	}
	return paths
}

// Locations contains only directory/file locations, never credential values.
// The caller supplies supported location overrides from its execution context.
type Locations struct {
	Home   string `json:"home"`
	Codex  string `json:"codex,omitempty"`
	Docker string `json:"docker,omitempty"`
	NPM    string `json:"npm,omitempty"`
	AWS    string `json:"aws,omitempty"`
}

func (l Locations) Valid() bool {
	if !filepath.IsAbs(l.Home) || l.Home == "/" {
		return false
	}
	for _, p := range []string{l.Codex, l.Docker, l.NPM, l.AWS} {
		if p != "" && (!filepath.IsAbs(p) || p == "/") {
			return false
		}
	}
	return true
}

func (l Locations) Paths() []string {
	out := DeniedPaths(l.Home)
	if l.Codex != "" {
		out = append(out, filepath.Join(l.Codex, "config.toml"), filepath.Join(l.Codex, "auth.json"))
	}
	if l.Docker != "" {
		out = append(out, filepath.Join(l.Docker, "config.json"))
	}
	if l.NPM != "" {
		out = append(out, l.NPM)
	}
	if l.AWS != "" {
		out = append(out, l.AWS)
	}
	return out
}

// ConfigFormat identifies only supported sanitizable configurations. Auth
// stores remain protected even if their serialization happens to be JSON.
func (l Locations) ConfigFormat(p string) string {
	p = filepath.Clean(p)
	backup := filepath.Join(l.Home, ".local/share/agent-secrets/backups")
	if p == backup || strings.HasPrefix(p, backup+"/") {
		return ""
	}
	if p == filepath.Join(l.Home, ".codex/config.toml") || l.Codex != "" && p == filepath.Join(l.Codex, "config.toml") {
		return "toml"
	}
	if p == filepath.Join(l.Home, ".docker/config.json") || l.Docker != "" && p == filepath.Join(l.Docker, "config.json") || p == filepath.Join(l.Home, ".claude/settings.json") {
		return "json"
	}
	if filepath.Base(p) == ".npmrc" || l.NPM != "" && p == l.NPM {
		return "npm"
	}
	return ""
}
