package policy

import (
	"regexp"
	"strings"
)

const Redacted = "[REDACTED]"

var acronymBoundary = regexp.MustCompile(`([A-Z]+)([A-Z][a-z])`)
var wordBoundary = regexp.MustCompile(`([a-z0-9])([A-Z])`)
var nameSeparators = regexp.MustCompile(`[^a-z0-9]+`)
var environmentName = regexp.MustCompile(`^[A-Za-z_][A-Za-z_0-9]*$`)

func NormalizeName(s string) string {
	s = acronymBoundary.ReplaceAllString(s, "${1}_${2}")
	s = wordBoundary.ReplaceAllString(s, "${1}_${2}")
	return strings.Trim(nameSeparators.ReplaceAllString(strings.ToLower(s), "_"), "_")
}

// SecretName matches complete field names and credential suffixes. Token
// budgets, tokenizers, password policies and key identifiers do not match.
func SecretName(name string) bool {
	n := NormalizeName(name)
	for _, suffix := range []string{"password", "passwd", "passphrase", "token", "api_key", "apikey", "access_key", "secret", "secret_key", "private_key", "signing_key", "encryption_key", "hmac_key", "password_hash", "hashed_password", "credential", "credentials"} {
		if n == suffix || strings.HasSuffix(n, "_"+suffix) {
			return true
		}
	}
	return false
}

func SensitiveHeader(name string) bool {
	switch NormalizeName(name) {
	case "authorization", "proxy_authorization", "cookie", "set_cookie", "x_registry_auth", "x_auth":
		return true
	}
	return SecretName(name)
}

func SensitiveQuery(name string) bool {
	switch NormalizeName(name) {
	case "key", "sig", "signature", "x_amz_signature", "x_amz_credential", "x_goog_signature", "x_goog_credential":
		return true
	}
	return SecretName(name)
}

// referenceField keeps Codex environment-variable references visible, even
// below a credential-like name such as env_http_headers."X-API-Key".
func referenceField(config Config, path []string, value any) bool {
	if config != CodexConfig {
		return false
	}
	if len(path) >= 3 && path[0] == "profiles" {
		path = path[2:]
	}
	if len(path) < 3 {
		return false
	}
	if path[0] != "mcp_servers" && path[0] != "model_providers" {
		return false
	}
	key := path[2]
	valid := len(path) == 3 && (path[0] == "mcp_servers" && key == "bearer_token_env_var" || path[0] == "model_providers" && key == "env_key")
	valid = valid || len(path) == 4 && (key == "env_http_headers" || path[0] == "mcp_servers" && key == "env_vars" && path[3] == "")
	s, ok := value.(string)
	return valid && ok && environmentName.MatchString(s)
}

func sensitiveField(config Config, path []string) bool {
	if len(path) == 0 {
		return false
	}
	n := path[len(path)-1]
	// Claude Code's sandbox.credentials declares which variables and files to
	// protect: names, paths, modes, and hosts, never their values. Its members
	// are checked by the ordinary rules instead of being hidden wholesale.
	if config == ClaudeSettings && len(path) == 2 && path[0] == "sandbox" && path[1] == "credentials" {
		return false
	}
	// ~/.claude.json keeps the endings of API keys the user approved or
	// rejected and, in older versions, per-project prompt history that may
	// hold pasted secrets.
	if len(path) == 1 && path[0] == "customApiKeyResponses" || len(path) == 3 && path[0] == "projects" && path[2] == "history" {
		return true
	}
	if len(path) >= 2 && (NormalizeName(path[len(path)-2]) == "http_headers" || NormalizeName(path[len(path)-2]) == "headers") {
		return SensitiveHeader(n)
	}
	if len(path) >= 2 && NormalizeName(path[len(path)-2]) == "query_params" {
		return SensitiveQuery(n)
	}
	if len(path) >= 3 && path[len(path)-3] == "auths" {
		switch NormalizeName(n) {
		case "auth", "identitytoken", "registrytoken":
			return true
		}
	}
	return SecretName(n)
}
