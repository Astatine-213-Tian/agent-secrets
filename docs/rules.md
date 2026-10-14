# Protection rules

Agent Secrets uses **filename and operation checks for ordinary files** and
**selective value redaction for supported configuration reads**. It does not
scan every source file for secret-looking variable names. Unmatched config
values remain visible; there is no setting, type, or safe-value allowlist.

The hook inspects arguments and filesystem metadata only. A separate private
runner reads and sanitizes supported configs. Ordinary commands execute natively,
with their own options, environment, output, and exit behavior. The only input
rewrites are the basic config-read bridge and native ripgrep path exclusions.
There is no general command runner or catalogue of permitted native options.

## Protected resources

Paths are case-sensitive. `*` matches within a component; `**` spans directories.
`~` below means the hook user's home.

| Location | Protected resources |
| --- | --- |
| Anywhere | `.env`, `.env.*`, `.npmrc`, `private-key.pem`, `private.key`, `id_rsa`, `id_ed25519`, `id_ecdsa` |
| Browser sessions | `**/browser-profiles/**/state.json`, `**/browser-profiles/**/.state.*.tmp` |
| SSH | `~/.ssh/id_*` |
| Provider/package credentials | `~/.aws/credentials`, `~/.config/gh/hosts.yml`, `~/.netrc`, `~/.npmrc`, `~/.pypirc`, `~/.docker/config.json` |
| Agent settings/credentials | `~/.codex/config.toml`, `~/.codex/auth.json`, `~/.claude/settings.json`, `~/.claude.json`, `~/.claude/.credentials.json` |
| Backups | `~/.local/share/agent-secrets/backups` and everything beneath it |

Exceptions are exactly `.env.example`, `.env.schema.json`, and SSH `id_*.pub`
public keys. An exception to one rule does not exempt another protected
location. A public-looking symlink to a protected target is protected. There
is no blanket `.pem`, `.key`, JSON, or TOML ban.

These location overrides add protection; defaults remain protected:

| Variable | Additional resources |
| --- | --- |
| `CODEX_HOME` | `config.toml` and `auth.json` in that directory |
| `DOCKER_CONFIG` | `config.json` in that directory |
| `NPM_CONFIG_USERCONFIG` | The specified file |
| `AWS_SHARED_CREDENTIALS_FILE` | The specified file |

Only location strings are inspected. Inherited values and literal shell
assignments are recognized. Relative locations use the effective working
directory. Recognized computed location changes are rejected.

## Operation checks

| Operation | Rule |
| --- | --- |
| `ls`, `stat`, existence tests, ordinary `find` listing | Allow: names and metadata do not disclose file values. |
| Literal output, messages, edit replacement text, search patterns | Literal mentions of `.env` are not reads. |
| Read, content-search, upload, copy, rename, or patch a protected file | Deny raw access. Supported config reads can be rewritten. |
| Copy/rename/export a conventional credential directory as source | Deny, including its containing home directory. Copying an ordinary file into the home directory is allowed. |
| Write/edit a protected file | Deny; tools can expose previous contents or diffs. No blanket write-only exemption. |
| `find` actions | Inspect explicit nested commands and protected operands. Common bulk readers such as `-exec cat {} +` are denied; `-exec basename {} \;` is allowed. |
| Environment, process-environment, or credential-store dumps | Deny. |
| Application internally using credentials | Authentication alone is not a reason to block. |

**`ls -l .env` is allowed**: it does not reveal environment values. `cat .env`,
`cp .env public.txt`, and `curl --data-binary @.env …` are denied.
`echo '.env'` is allowed; `echo "$(cat .env)"` is denied.

Expansions, redirections, nested execution, and sibling commands are checked
independently. Metadata permission does not exempt `ls $(cat .env)` or
`ls .env; cat .env`. A safe operand never exempts an unsafe operand.

The hook uses request `cwd` and tool `workdir`, checks lexical and resolved
paths, and follows symlink metadata even for missing targets. Supported shell
context changes include literal `cd DIR; COMMAND`, `cd DIR && COMMAND`, and
`env -C DIR COMMAND`. A compound command, substitution, or unfamiliar option
alone is not a denial. Nested operations remain checked. Computed directories
and arbitrary shell control flow are outside reliable context tracking.

### Environment and inspection commands

Environment checks apply to executed shell/script arguments, not repository
file contents or edit text. Credential shell expansions use the name grammar
below. `$API_KEY` and `${MY_ACCESS_TOKEN}` are denied; `$MAX_TOKENS` and
`$TOKENIZERS_PARALLELISM` do not match.

`printenv` and recognized Python/JavaScript/Go scalar environment lookups use
that same credential-name grammar. `printenv APP_MODE` is allowed;
`printenv API_KEY` is denied. There is no permitted-variable list. Computed
scalar lookups are not rejected solely because the name is unknown; their
runtime values cannot be classified by this argument-only hook.

Dumping forms include bare `env`/`printenv`, exported-variable listing, shell
tracing, `ps e`/`ps auxe`, and macOS `ps -E`. Ordinary `ps -e` and explicit
process columns such as `ps -axo pid,etime,command` are allowed.

`gh auth token`, Keychain password output (`-w` or `-g` on
`find-generic-password`/`find-internet-password`), full `docker inspect`, and
full `docker compose config` are denied. Keychain metadata lookup is allowed.
Compose selectors `--services`, `--images`, `--volumes`, `--profiles`,
`--networks`, and `--quiet`/`-q` are allowed.

Docker inspection has no permitted-template or object-count list. Ordinary
selections such as `{{.Name}}` and `{{.Config.Image}}` are allowed. Recognizable
whole-object output (`{{json .}}`, `{{.}}`, or format `json`), whole `Config` or
`ContainerConfig`, and field selections containing `Env`, `Args`, `Cmd`,
`Entrypoint`, `Labels`, or credential-name matches are denied. These are bounded
recognizers, not a Go-template interpreter; dynamically constructed selections
and indirect template lookups can exceed coverage.

### Content searches

Normal searches and their native options are allowed. There is no search-option
allowlist, and a directory operand or compound command alone is not a denial.
Explicit access to protected files, including pattern-file inputs and
redirections, remains blocked, as do secret expansions and sibling credential
reads. Ordinary pattern files remain usable.

For directly parsed shell `rg` calls, the hook appends negative `--glob`
exclusions for protected paths. This also works inside pipelines and compound
commands. Original arguments, executable selection, configuration, stdin,
redirections, output format, ordering, duplicate matches, and exit behavior
remain under the native shell and ripgrep. Options such as `--max-count`,
`--json`, `--sort`, context flags, and future flags are not rejected merely
because they are absent from a package-maintained list. Invalid options receive
the native tool's own error. Filename-only `rg --files` remains metadata-only;
pattern-file inputs are still screened.

The search exception retains recognition of common argument roles (patterns,
file inputs, option values, and `--`) so a literal `.env` search pattern is not
mistaken for a file read. This is intentionally bounded, not a complete option
specification. Unrecognized argument layouts can still be ambiguous; explicit
`-e PATTERN` avoids positional-pattern ambiguity.

The hook checks the original request before adding exclusions, so an explicit
`rg pattern .env` is denied even though a recursive `rg --hidden pattern .`
runs with that file excluded. Public `.env` examples and SSH public keys remain
searchable. The exclusions follow the protected locations above, including
supported location overrides; they do not depend on scanning file contents.

This is native filename filtering, not controlled execution of every file read.
Symlink following, custom preprocessors, dynamically changed directories or
arguments, and searches hidden inside scripts can exceed these heuristics.
Other search tools receive explicit argument checks without automatic recursive
exclusions. `guard` alone checks arguments but cannot add exclusions; use the
installed `hook` for native ripgrep rewriting. There is no private search runner,
search byte limit, search deadline, or fixed ripgrep installation path.

## Redaction rules

### Supported config reads

The runner sanitizes Codex `config.toml`, Claude `settings.json`, Docker
`config.json`, and `.npmrc` files, including supported location overrides.
Auth stores such as Codex `auth.json` remain unreadable through this interface.

Rewriting supports object-valued `tool_input` on `Bash` and `shell_command`
(`command`) and `exec_command` (`cmd`). The bridge recognizes only a basic
`cat FILE`, `cat -- FILE`, or `cat < FILE`, optionally prefixed with `command`.
`cat`, `/bin/cat`, and `/usr/bin/cat` match. Literal paths, `~/…`, and supported
location-variable references work. Other arguments and JSON number precision
are preserved; siblings remain screened.

Basic reads can appear in pipelines and compound commands with an unchanged
working directory and environment. The bridge substitutes only that read with
the private sanitizer. For native options or selections, use ordinary pipelines:

```sh
cat ~/.codex/config.toml | cat -n
cat ~/.codex/config.toml | head -n 40
cat ~/.codex/config.toml | sed -n '1,80p'
```

Downstream tools own their complete native behavior, including errors and
pipeline exit status; a later successful command can mask an earlier failure
under normal shell pipeline rules. Their additional file inputs and nested
operations remain screened. The sanitizer never launches another command.
Direct `head`, `tail`, `sed`, or `cat` with options on a protected config remain
raw protected reads and are denied. There is no supported-reader option table.
Generic Read/MCP file tools are also denied on protected configs.

Files must be regular and at most 4 MiB. Config-file symlinks and symlinks below
user-home config locations are refused. The entire document is parsed before
output, with a nesting limit of 64. TOML/JSON formatting and comments are not
preserved; JSON numeric precision is retained. Npm supports line-based
`key=value` entries and drops comment lines. Failures return a fixed error and
no configuration output. Line numbers refer to the sanitized view. The source
file is never modified.

### Credential keys and paths

Normalize names across case, camelCase, underscores, hyphens, and punctuation.
A key matches if its normalized name equals one of these names or ends with
`_` followed by one of them:

`password`, `passwd`, `passphrase`, `token`, `api_key`, `apikey`, `access_key`,
`secret`, `secret_key`, `private_key`, `signing_key`, `encryption_key`, `hmac_key`,
`password_hash`, `hashed_password`, `credential`, `credentials`.

Examples: `access_token`, `refresh_token`, `id_token`, `auth_token`,
`bearer_token`, `session_token`, `personal_access_token`, `client_secret`,
`webhook_secret`, `shared_secret`, `AWS_SECRET_ACCESS_KEY`, `OPENAI_API_KEY`.
Nonmatches: `MAX_TOKENS`, `TOKENIZERS_PARALLELISM`, `token_limit`,
`password_min_length`, `username`, `client_id`, generic `key`, generic `auth`.

Matching scalars become `[REDACTED]`. Matching containers retain their shape
with descendant scalar values redacted. These rules recurse through tables,
arrays, and every `profiles.<name>` subtree. Context adds these matches:

- Docker `auths.<registry>.auth`, `.identitytoken`, and `.registrytoken`.
- Npm `_auth`, `_authToken`, `_password`, including registry-prefixed entries.
- `headers`/`http_headers` entries use the header rules below.
- `query_params` entries use the query rules below.

Only sensitive inline environment entries are hidden. `NODE_ENV`, `LOG_LEVEL`,
`PATH`, and unmatched values remain visible, subject to recognizable credential
material in their text. Ordinary source files are not scanned by these rules.

### References and headers

These fields retain syntactically valid environment-variable names without
looking up their values. They also apply below profiles:

- `mcp_servers.<name>.bearer_token_env_var`
- `mcp_servers.<name>.env_vars[]`
- `mcp_servers.<name>.env_http_headers.<header>`
- `model_providers.<name>.env_key`
- `model_providers.<name>.env_http_headers.<header>`

Sensitive header names are case-insensitive: `Authorization`,
`Proxy-Authorization`, `Cookie`, `Set-Cookie`, `X-Registry-Auth`, `X-Auth`, plus
credential-name matches. This includes `X-API-Key`, `Api-Key`, `X-Auth-Token`,
`X-Access-Token`, and `X-Amz-Security-Token`. Hide their complete values.
Other headers, such as `Accept` and `X-Request-ID`, survive.

### URLs, commands, arguments, and instructions

All string values are checked for these specific constructs:

| Construct | Redaction |
| --- | --- |
| URL user information, including database URLs | Hide user information; keep ordinary host, path, query values. |
| Query parameters and parameter-style URL fragments | Hide credential-name matches, `key`, `sig`, `signature`, `X-Amz-Signature`, `X-Amz-Credential`, `X-Goog-Signature`, `X-Goog-Credential`. |
| Slack `hooks.slack.com/services/…`, Discord `/api/webhooks/…` URLs | Hide the credential-bearing path. |
| Explicit `name=value` / `name: value` | Hide values for credential-name matches. |
| `--credential-flag VALUE` / `--credential-flag=VALUE` | Hide the value; keep other arguments. `args` arrays also handle separate flag/value elements. |
| `-u` / `--user` with `user:password` | Hide the pair. A username alone remains visible. |
| Sensitive header lines; `Bearer` / `Basic` authentication text | Hide authentication values. |
| PEM private-key blocks | Hide the block; an unterminated block is hidden through the end of the string. |
| Recognizable provider tokens | GitHub `gh[pousr]_`/`github_pat_`, `sk-`/`sk-proj-`, Slack `xox[baprs]-`, Docker `dckr_pat_`, GitLab `glpat-`, npm `npm_`; minimum payload length 20, or 10 for Slack. |

The runner never executes configured commands, instructions, credential helpers,
or environment expansions. Recognized malformed URL constructs are hidden in
full. There is no entropy detector and no blanket hiding of prose, commands,
arguments, or URLs.

Outside a header, `Basic` requires a valid base64 `user:password` pair. `Bearer`
requires at least eight characters, excluding the explanatory words `token`,
`tokens`, `authentication`, `authorization`, and `credentials`.

## Coverage limits

This is an accidental-disclosure guard, not filesystem isolation or a general
interpreter. Unknown secret filenames, arbitrary unlabeled values, custom token
formats, hard links, opaque encodings, dynamically assembled paths/programs,
and unrecognized tool schemas can escape the heuristics. A random secret under
an innocent key is not guaranteed to be redacted. Application output and
network responses are not generally filtered. General directory transfers are
not a sandbox-enforced file policy.

The private runner controls its reads and revalidates untrusted plans. Ordinary
allowed tools still execute in the client and can race with changes after
metadata screening. Client permissions, sandbox restrictions, and hook trust
remain separate controls. See [usage](usage.md) and [development](development.md)
for activation and verification boundaries.
