package policy

import (
	"regexp"
	"slices"
)

const Redacted = "[REDACTED]"

var configIdentifier = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$`)
var environmentName = regexp.MustCompile(`^[A-Za-z_][A-Za-z_0-9]{0,127}$`)

// VisibleCodexValue is an allowlist of settings whose values can be shown.
// Unknown fields and wrong types are redacted by the caller. In particular,
// nothing inside env, headers, URLs, instructions or launch commands is allowed.
// An empty final path segment represents an array element, not a field name.
func VisibleCodexValue(path []string, value any) bool {
	if len(path) >= 3 && path[0] == "profiles" {
		path = path[2:]
	}
	if len(path) == 1 {
		key := path[0]
		switch key {
		case "prevent_idle_sleep", "disable_response_storage", "hide_agent_reasoning", "show_raw_agent_reasoning", "check_for_update_on_startup":
			_, ok := value.(bool)
			return ok
		case "model_context_window", "model_auto_compact_token_limit", "tool_output_token_limit":
			n, ok := value.(int64)
			return ok && n >= 0
		case "model", "review_model", "model_provider", "profile":
			s, ok := value.(string)
			return ok && configIdentifier.MatchString(s)
		case "model_reasoning_effort":
			return enum(value, "none", "minimal", "low", "medium", "high", "xhigh", "max", "ultra")
		case "model_reasoning_summary":
			return enum(value, "auto", "concise", "detailed", "none")
		case "model_verbosity":
			return enum(value, "low", "medium", "high")
		case "approval_policy":
			return enum(value, "untrusted", "on-failure", "on-request", "never")
		case "sandbox_mode":
			return enum(value, "read-only", "workspace-write", "danger-full-access")
		case "web_search":
			return enum(value, "disabled", "cached", "live")
		case "personality":
			return enum(value, "none", "friendly", "pragmatic")
		case "service_tier":
			return enum(value, "fast", "flex", "priority", "default")
		}
	}
	if len(path) == 2 {
		switch path[0] {
		case "features":
			_, ok := value.(bool)
			return ok && !SecretName(path[1])
		case "analytics", "feedback":
			_, ok := value.(bool)
			return ok && path[1] == "enabled"
		case "history":
			if path[1] == "persistence" {
				return enum(value, "save-all", "none")
			}
		case "sandbox_workspace_write":
			_, ok := value.(bool)
			return ok && slices.Contains([]string{"network_access", "exclude_tmpdir_env_var", "exclude_slash_tmp"}, path[1])
		}
	}
	if len(path) == 3 {
		key := path[2]
		switch path[0] {
		case "projects":
			return key == "trust_level" && enum(value, "trusted", "untrusted")
		case "plugins":
			_, ok := value.(bool)
			return key == "enabled" && ok
		case "mcp_servers":
			switch key {
			case "bearer_token_env_var":
				return envName(value)
			case "enabled", "required":
				_, ok := value.(bool)
				return ok
			case "startup_timeout_sec", "startup_timeout_ms", "tool_timeout_sec":
				return nonnegativeNumber(value)
			}
		case "model_providers":
			switch key {
			case "env_key":
				return envName(value)
			case "requires_openai_auth", "supports_websockets":
				_, ok := value.(bool)
				return ok
			case "wire_api":
				return enum(value, "responses", "chat")
			case "request_max_retries", "stream_max_retries", "stream_idle_timeout_ms":
				return nonnegativeNumber(value)
			}
		}
	}
	if len(path) == 4 && (path[0] == "mcp_servers" || path[0] == "model_providers") {
		if path[2] == "env_http_headers" || (path[0] == "mcp_servers" && path[2] == "env_vars" && path[3] == "") {
			return envName(value)
		}
	}
	return false
}

func envName(value any) bool {
	s, ok := value.(string)
	return ok && environmentName.MatchString(s)
}

func enum(value any, choices ...string) bool {
	s, ok := value.(string)
	return ok && slices.Contains(choices, s)
}

func nonnegativeNumber(value any) bool {
	switch n := value.(type) {
	case int64:
		return n >= 0
	case float64:
		return n >= 0 && n < 1e12
	}
	return false
}
