# Protection rules

Agent Secrets uses **filename and operation checks for ordinary files** and
**selective value redaction for supported configuration reads**. It does not
scan every source file for secret-looking variable names. Unmatched config
values remain visible; there is no setting, type, or safe-value allowlist.

The hook inspects arguments and filesystem metadata only. A separate private
runner reads approved files after the hook rewrites the request.

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
| `find` execution/file-writing actions | Deny; supported forms are metadata-only. |
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
context changes include literal `cd DIR && COMMAND` and `env -C DIR COMMAND`.
Other recognized compound directory changes are rejected rather than simulated.

### Environment and inspection commands

Environment checks apply to executed shell/script arguments, not repository
file contents or edit text. Credential shell expansions use the name grammar
below. `$API_KEY` and `${MY_ACCESS_TOKEN}` are denied; `$MAX_TOKENS` and
`$TOKENIZERS_PARALLELISM` do not match.

`printenv` and recognized Python/JavaScript/Go environment lookups permit these
ordinary names: `PATH`, `HOME`, `SHELL`, `PWD`, `OLDPWD`, `LANG`, `LANGUAGE`,
`TERM`, `TMPDIR`, `TMP`, `TEMP`, `USER`, `LOGNAME`, `NODE_ENV`, `LOG_LEVEL`,
`PORT`, `CI`, `MAX_TOKENS`, `TOKENIZERS_PARALLELISM`, and valid `LC_*` names.
Other names, computed lookups, and whole-environment output are denied.

Dumping forms include bare `env`/`printenv`, exported-variable listing, shell
tracing, `ps e`/`ps auxe`, and macOS `ps -E`. Ordinary `ps -e` and explicit
process columns such as `ps -axo pid,etime,command` are allowed.

`gh auth token`, Keychain password retrieval, full `docker inspect`, and
`docker compose config` are denied. Docker inspection permits exactly one
object and one exact format, via `-f`, `--format`, or `--format=`:
`{{.State.Status}}`, `{{.State.Running}}`, `{{.State.Health.Status}}`.
Arbitrary templates and environment/config selections remain denied.

### Content searches

Explicit ordinary-file searches remain allowed after operand checks. Supported
directory `rg` searches are rewritten to a private runner. `guard` alone cannot
rewrite these and denies them. Supported arguments are a pattern (or repeated
`-e`/`--regexp`) and zero or more roots, plus:

- Matching/output: `-n`, `-i`, `-F`, `-w`, `-x`, `-v`, `-H`, `-l`, `-c`,
  and their long equivalents; `--no-heading`. Do not combine `-l` and `-c`.
- Inventory: `--hidden`, `--no-ignore`, `-u`/`-uu`/`-uuu`, `-g`/`--glob`,
  `--iglob`, `-t`/`--type`, `-T`/`--type-not`.
- `--` to end options.

Only one simple command can be rewritten. Unsupported recursive `grep`,
compound directory searches, pattern files, preprocessors, symlink following,
and additional options are denied when recognized as broad searches.
`rg --files` with supported inventory options remains metadata-only.

The runner inventories names, excludes protected resources, then securely opens
approved regular files and passes their bytes on stdin to `rg`. It never lets
`rg` open a content pathname or directory and disables ripgrep configuration.
Explicit protected operands deny the plan; protected files discovered inside a
directory are skipped. A safe file alongside a directory does not exempt the
directory. Results include relative filenames; no-match exit status is `1`.

Ripgrep must exist at `/opt/homebrew/bin/rg`, `/usr/local/bin/rg`, or `/usr/bin/rg`.
Each file and total output are limited to 32 MiB, with a 30-second deadline.
Inventory symlinks are skipped. Read/utility failures produce a fixed error and
no partial output. This controls actual reads, rather than approving an
unrestricted directory search after a preflight check.

## Redaction rules

### Supported config reads

The runner sanitizes Codex `config.toml`, Claude `settings.json`, Docker
`config.json`, and `.npmrc` files, including supported location overrides.
Auth stores such as Codex `auth.json` remain unreadable through this interface.

Rewriting supports object-valued `tool_input` on `Bash` and `shell_command`
(`command`) and `exec_command` (`cmd`). It accepts one simple read, optionally
prefixed with `command`, with one final file operand or one stdin redirection.
Literal paths, `~/…`, and supported location-variable references work. Other
arguments and JSON number precision are preserved; siblings remain screened.

| Reader | Accepted options |
| --- | --- |
| `cat` | None, or short flags made only from `n b s v e t` |
| `head`, `tail` | None; `-n COUNT`, `-c COUNT`, `-COUNT`, `-nCOUNT`, `-cCOUNT`; at most nine digits, optionally prefixed `+` |
| `sed` | `-n ADDRESSp` or `-n -e ADDRESSp`; ADDRESS is a positive line number or `$`, optionally a comma-separated pair |

Only normal executable names and their `/bin` or `/usr/bin` forms match. No
extra files, follow mode, output redirection, or sed execution/file operations
are accepted. Generic Read/MCP file tools are denied on protected configs.

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
