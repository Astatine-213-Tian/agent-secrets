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

// Config names a supported sanitizable configuration. Rules that hide values
// apply to every config, so a misplaced match only hides more. Rules that keep
// an otherwise hidden value visible apply only to the config they describe.
type Config string

const (
	CodexConfig    Config = "codex"
	ClaudeSettings Config = "claude-settings"
	ClaudeState    Config = "claude-state"
	DockerConfig   Config = "docker"
	NPMConfig      Config = "npm"
)

// Format is the serialization the config is parsed and encoded with.
func (c Config) Format() string {
	switch c {
	case CodexConfig:
		return "toml"
	case ClaudeSettings, ClaudeState, DockerConfig:
		return "json"
	case NPMConfig:
		return "npm"
	}
	return ""
}

// Config identifies only supported sanitizable configurations. Auth stores
// remain protected even if their serialization happens to be JSON.
func (l Locations) Config(p string) Config {
	p = filepath.Clean(p)
	backup := filepath.Join(l.Home, ".local/share/agent-secrets/backups")
	switch {
	case p == backup || strings.HasPrefix(p, backup+"/"):
		return ""
	case p == filepath.Join(l.Home, ".codex/config.toml") || l.Codex != "" && p == filepath.Join(l.Codex, "config.toml"):
		return CodexConfig
	case p == filepath.Join(l.Home, ".claude/settings.json"):
		return ClaudeSettings
	case p == filepath.Join(l.Home, ".claude.json"):
		return ClaudeState
	case p == filepath.Join(l.Home, ".docker/config.json") || l.Docker != "" && p == filepath.Join(l.Docker, "config.json"):
		return DockerConfig
	case filepath.Base(p) == ".npmrc" || l.NPM != "" && p == l.NPM:
		return NPMConfig
	}
	return ""
}

// Editable reports a configuration that config set may change: JSON keeps no
// comments to lose. Claude Code rewrites ~/.claude.json from memory and has
// its own commands for it, so an outside edit could be silently undone.
func (l Locations) Editable(p string) bool {
	c := l.Config(p)
	return c == ClaudeSettings || c == DockerConfig
}
