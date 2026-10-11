// Package policy owns the hook's credential-name and path recognition rules.
package policy

import (
	"path/filepath"
	"regexp"
)

var secretName = regexp.MustCompile(`(?i)TOKEN|SECRET|PASSWORD|PASSWD|CREDENTIAL|API_?KEY|PRIVATE_?KEY|DATABASE_URL|DSN`)

func SecretName(name string) bool { return secretName.MatchString(name) }

func DeniedPaths(home string) []string {
	paths := []string{"/**/.env", "/**/.env.*", "/**/private-key.pem", "/**/private.key", "/**/id_rsa", "/**/id_ed25519", "/**/id_ecdsa", "/**/browser-profiles/**/state.json", "/**/browser-profiles/**/.state.*.tmp"}
	for _, p := range []string{".aws/credentials", ".ssh/id_*", ".config/gh/hosts.yml", ".netrc", ".npmrc", ".pypirc", ".codex/auth.json", ".codex/config.toml", ".claude/settings.json", ".claude.json", ".claude/.credentials.json", ".local/share/agent-secrets/backups"} {
		paths = append(paths, filepath.Join(home, p))
	}
	return paths
}
