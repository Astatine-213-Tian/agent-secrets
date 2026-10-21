package policy_test

import (
	"bytes"
	"encoding/json"
	"github.com/Astatine-213-Tian/agent-secrets/internal/policy"
	"github.com/BurntSushi/toml"
	"reflect"
	"strings"
	"testing"
)

func TestCredentialNames(t *testing.T) {
	for _, name := range []string{"PASSWORD", "dbPassword", "client-secret", "OPENAI_API_KEY", "AWS_SECRET_ACCESS_KEY", "accessToken", "refresh_token", "ID_TOKEN", "auth_token", "bearer_token", "session_token", "personal_access_token", "vendor_token", "apikey", "privateKey", "signing_key", "encryption_key", "hmac_key", "password_hash", "hashed_password", "_authToken", "_password"} {
		if !policy.SecretName(name) {
			t.Errorf("missed credential name %q", name)
		}
	}
	for _, name := range []string{"MAX_TOKENS", "TOKENIZERS_PARALLELISM", "token_limit", "password_min_length", "client_id", "username", "key", "auth", "secret_name", "monkey", "tokenizer"} {
		if policy.SecretName(name) {
			t.Errorf("ordinary name matched %q", name)
		}
	}
}

func TestDefaultVisibleDocument(t *testing.T) {
	input := `# comment removed
model = "future-model"
future_number = 9007199254740993
future_date = 2026-10-13
future_bool = true
developer_instructions = "Use the staging endpoint; password=DO_NOT_ECHO; keep logging enabled."
custom = [{model = "unlisted", token = "DO_NOT_ECHO"}, {values = ["ordinary", "also ordinary"]}]
[profiles.work]
apiKey = "DO_NOT_ECHO"
arbitrary = "visible"
[mcp_servers.demo]
command = "server"
args = ["--port", "3000", "--token", "DO_NOT_ECHO", "--debug", "--api-key=DO_NOT_ECHO"]
bearer_token_env_var = "MY_TOKEN"
env_vars = ["MY_TOKEN", "PATH"]
env = { API_KEY = "DO_NOT_ECHO", NODE_ENV = "development", MAX_TOKENS = 4000, TOKENIZERS_PARALLELISM = false }
http_headers = { Authorization = "DO_NOT_ECHO", Cookie = "DO_NOT_ECHO", "X-API-Key" = "DO_NOT_ECHO", Accept = "application/json", "X-Request-ID" = "trace-123" }
env_http_headers = { Authorization = "HEADER_TOKEN" }
url = "https://user:DO_NOT_ECHO@example.com/v1?access_token=DO_NOT_ECHO&region=us"
[model_providers.custom]
env_key = "PROVIDER_KEY"
base_url = "https://example.com/v1"
env_http_headers = { Authorization = "PROVIDER_HEADER" }
query_params = { api_key = "DO_NOT_ECHO", version = "2" }
`
	out, e := policy.Sanitize("toml", []byte(input))
	if e != nil {
		t.Fatal(e)
	}
	if bytes.Contains(out, []byte("DO_NOT_ECHO")) {
		t.Fatal("credential survived")
	}
	var got map[string]any
	if toml.Unmarshal(out, &got) != nil {
		t.Fatal("invalid TOML")
	}
	value := func(path ...string) any {
		var v any = got
		for _, p := range path {
			v = v.(map[string]any)[p]
		}
		return v
	}
	for _, tt := range []struct {
		path []string
		want any
	}{
		{[]string{"model"}, "future-model"}, {[]string{"future_number"}, int64(9007199254740993)},
		{[]string{"future_bool"}, true}, {[]string{"profiles", "work", "arbitrary"}, "visible"},
		{[]string{"mcp_servers", "demo", "env", "NODE_ENV"}, "development"},
		{[]string{"mcp_servers", "demo", "env", "MAX_TOKENS"}, int64(4000)},
		{[]string{"mcp_servers", "demo", "env", "TOKENIZERS_PARALLELISM"}, false},
		{[]string{"mcp_servers", "demo", "http_headers", "Accept"}, "application/json"},
		{[]string{"mcp_servers", "demo", "http_headers", "X-Request-ID"}, "trace-123"},
		{[]string{"mcp_servers", "demo", "bearer_token_env_var"}, "MY_TOKEN"},
		{[]string{"mcp_servers", "demo", "env_http_headers", "Authorization"}, "HEADER_TOKEN"},
		{[]string{"mcp_servers", "demo", "command"}, "server"},
		{[]string{"mcp_servers", "demo", "args"}, []any{"--port", "3000", "--token", policy.Redacted, "--debug", "--api-key=" + policy.Redacted}},
		{[]string{"model_providers", "custom", "env_key"}, "PROVIDER_KEY"},
	} {
		if !reflect.DeepEqual(value(tt.path...), tt.want) {
			t.Errorf("preservation/redaction at %v: got %#v", tt.path, value(tt.path...))
		}
	}
	again, e := policy.Sanitize("toml", out)
	if e != nil || !bytes.Equal(out, again) {
		t.Fatal("not idempotent")
	}
}

func TestRedactionSyntaxAndFormats(t *testing.T) {
	for _, input := range []string{
		`mcp_servers.demo.env."API\u005fKEY" = "DO_NOT_ECHO"`,
		`mcp_servers = { demo = { env = { apiKey = "DO_NOT_ECHO" } } }`,
		`custom = [{clientSecret = "DO_NOT_ECHO"}, {nested = [{password = "DO_NOT_ECHO"}]}]`,
		`credentials = {one = "DO_NOT_ECHO", array = ["DO_NOT_ECHO"]}`,
		"[profiles.work.mcp_servers.demo]\nargs = ['--password', '''DO_NOT_ECHO\nmultiline''']",
	} {
		out, e := policy.Sanitize("toml", []byte(input))
		if e != nil || bytes.Contains(out, []byte("DO_NOT_ECHO")) {
			t.Fatal("syntax bypass")
		}
	}
	out, e := policy.Sanitize("json", []byte(`{"auths":{"registry.example":{"auth":"DO_NOT_ECHO","identitytoken":"DO_NOT_ECHO"}},"credsStore":"osxkeychain","future":9007199254740993}`))
	if e != nil || bytes.Contains(out, []byte("DO_NOT_ECHO")) || !bytes.Contains(out, []byte("osxkeychain")) || !bytes.Contains(out, []byte("9007199254740993")) {
		t.Fatal("Docker redaction or precision")
	}
	out, e = policy.Sanitize("npm", []byte("//registry.example/:_authToken=DO_NOT_ECHO\n_auth=DO_NOT_ECHO\n_password=DO_NOT_ECHO\nregistry=https://registry.example\nstrict-ssl=true\n"))
	if e != nil || bytes.Contains(out, []byte("DO_NOT_ECHO")) || !bytes.Contains(out, []byte("strict-ssl=true")) {
		t.Fatal("npm redaction")
	}
}

func TestTextCredentials(t *testing.T) {
	for _, tt := range []struct{ input, visible string }{
		{`run --password "escaped\" DO_NOT_ECHO" --port 9000`, "--port 9000"},
		{`run --password "unterminated DO_NOT_ECHO`, "run --password"},
		{"curl --user user:DO_NOT_ECHO https://host.test/v1", "https://host.test/v1"},
		{"https://u:DO_NOT_ECHO@host.test/path?token=DO_NOT_ECHO&region=us", "region=us"},
		{"https://host.test/path#access_token=DO_NOT_ECHO&state=public", "state=public"},
		{"https://host.test/path?X-Amz-Signature=DO_NOT_ECHO&part=2", "part=2"},
		{"postgres://u:DO_NOT_ECHO@db.test:5432/database", "database"},
		{"password='DO_NOT_ECHO' host=db.test", "host=db.test"},
		{"curl -H 'Authorization: Bearer DO_NOT_ECHO' https://host.test/v1", "https://host.test/v1"},
		{"run --api-key DO_NOT_ECHO --port 9000", "--port 9000"},
		{"Use password: DO_NOT_ECHO; keep retries enabled", "keep retries enabled"},
		{"https://hooks.slack.com/services/DO_NOT_ECHO/DO_NOT_ECHO", "hooks.slack.com"},
		{"https://discord.com/api/webhooks/123/DO_NOT_ECHO", "discord.com"},
		{"-----BEGIN PRIVATE KEY-----\nDO_NOT_ECHO\n-----END PRIVATE KEY-----\nordinary", "ordinary"},
	} {
		got := policy.SanitizeText(tt.input)
		if strings.Contains(got, "DO_NOT_ECHO") || !strings.Contains(got, tt.visible) {
			t.Errorf("text redaction failed: %s", got)
		}
	}
	for _, s := range []string{"https://example.com/path?version=2", "--max-tokens 4096 --debug", "a long ordinary instruction about token budgets", "0123456789abcdef0123456789abcdef", "Basic configuration uses Bearer authentication"} {
		if policy.SanitizeText(s) != s {
			t.Errorf("ordinary text changed: %s", s)
		}
	}
}

func FuzzSanitize(f *testing.F) {
	f.Add(`token = 'synthetic'`)
	f.Add(`future = ['visible']`)
	f.Fuzz(func(t *testing.T, s string) {
		for _, format := range []string{"toml", "json", "npm"} {
			out, e := policy.Sanitize(format, []byte(s))
			if e != nil {
				if len(out) > 0 || e != policy.ErrDocument {
					t.Fatal("partial output")
				}
				continue
			}
			if format == "json" && !json.Valid(out) {
				t.Fatal("invalid json")
			}
			again, e := policy.Sanitize(format, out)
			if e != nil || !bytes.Equal(out, again) {
				t.Fatalf("not idempotent: format=%s output=%q again=%q error=%v", format, out, again, e)
			}
		}
	})
}

func TestInvalidDocumentsHaveNoOutput(t *testing.T) {
	for _, s := range []string{"broken = 'DO_NOT_ECHO", "key = 1\nkey = 2", strings.Repeat("#", policy.MaxDocument+1), strings.Repeat("nested.", 66) + "value='DO_NOT_ECHO'", "key='\xff'"} {
		out, e := policy.Sanitize("toml", []byte(s))
		if e != policy.ErrDocument || len(out) > 0 {
			t.Fatal("invalid TOML exposed output")
		}
	}
	for _, s := range []string{`{"token":"DO_NOT_ECHO"} {}`, `null`, `[1]`, `{"token":"DO_NOT_ECHO"`} {
		out, e := policy.Sanitize("json", []byte(s))
		if e != policy.ErrDocument || len(out) > 0 {
			t.Fatal("invalid JSON exposed output")
		}
	}
}

func TestLocalDatesAndTimesKeepWallClockValues(t *testing.T) {
	input := "date = 2026-10-13\nclock = 23:45:12.123\nlocal = 2026-10-13T23:45:12\nzoned = 2026-10-13T23:45:12-04:00\n"
	out, e := policy.Sanitize("toml", []byte(input))
	if e != nil {
		t.Fatal(e)
	}
	for _, want := range []string{"date = 2026-10-13", "clock = 23:45:12.123", "local = 2026-10-13T23:45:12", "zoned = 2026-10-13T23:45:12-04:00"} {
		if !strings.Contains(string(out), want) {
			t.Fatalf("changed temporal value: %s", want)
		}
	}
}

func TestClaudeSandboxCredentialDeclarationsStayVisible(t *testing.T) {
	input := `{
  "sandbox": {"credentials": {
    "envVars": [{"name": "GITHUB_TOKEN", "mode": "mask", "injectHosts": ["api.github.com"]}],
    "files": [{"path": "~/.aws/credentials", "mode": "deny"}],
    "awsPairs": [{"accessKeyIdVar": "MY_KEY_ID", "secretAccessKeyVar": "MY_SECRET_KEY", "sessionTokenVar": "MY_SESSION_TOKEN"}],
    "sigv4": {"streaming": "passthrough"},
    "note": "ghp_DONOTECHO0123456789abcdef",
    "token": "DO_NOT_ECHO"
  }},
  "credentials": {"name": "DO_NOT_ECHO"},
  "other": {"sandbox": {"credentials": {"name": "DO_NOT_ECHO"}}},
  "hooks": {"Stop": [{"command": "make && say <done>"}]}
}`
	out, err := policy.Sanitize("json", []byte(input))
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(out, []byte("DO_NOT_ECHO")) || bytes.Contains(out, []byte("DONOTECHO")) {
		t.Fatal("credential survived")
	}
	for _, visible := range []string{`"name": "GITHUB_TOKEN"`, `"mode": "mask"`, `"api.github.com"`, `"path": "~/.aws/credentials"`, `"secretAccessKeyVar": "MY_SECRET_KEY"`, `"sessionTokenVar": "MY_SESSION_TOKEN"`, `"streaming": "passthrough"`, `"make && say <done>"`} {
		if !bytes.Contains(out, []byte(visible)) {
			t.Fatalf("hid or escaped %s", visible)
		}
	}
}
