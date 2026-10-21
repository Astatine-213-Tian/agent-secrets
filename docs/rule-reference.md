# Rule reference

Read [Protection rules](rules.md) for a short guide and common examples.
This page lists the exact paths, commands, and value checks.

Agent Secrets uses **filename checks for recognized file operations** and
**selective value redaction for supported configuration reads**. It does not
scan every source file for secret-looking variable names. Unmatched config
values remain visible; there is no setting, type, or safe-value allowlist.

The hook inspects arguments and filesystem metadata only. A separate private
runner reads and sanitizes supported configs. Ordinary commands execute natively,
with their own options, environment, output, and exit behavior. The only input
rewrites are the config-read bridge (basic shell `cat` reads and Claude Code
`Read` calls) and native ripgrep path exclusions. `config set` and `config unset`
change one non-credential setting without printing the file.
There is no general command runner or catalogue of permitted native options.

## Protected resources

Paths are case-sensitive. `*` matches within a component; `**` spans directories.
`~` below means the hook user's home.

| Location | Protected resources |
| --- | --- |
| Anywhere | `.env`, `.env.*`, `.envrc`, `.dev.vars`, `.npmrc`, `private-key.pem`, `private.key`, `*.p12`, `*.pfx`, `id_rsa`, `id_dsa`, `id_ed25519`, `id_ecdsa` |
| Browser sessions | `**/browser-profiles/**/state.json`, `**/browser-profiles/**/.state.*.tmp` |
| SSH | `~/.ssh/id_*` |
| Provider/package credentials | `~/.aws/credentials`, `~/.config/gh/hosts.yml`, `~/.git-credentials`, `~/.kube/config`, `~/.netrc`, `~/.npmrc`, `~/.pypirc`, `~/.docker/config.json` |
| Google Cloud | `~/.config/gcloud/application_default_credentials.json`, `credentials.db`, `access_tokens.db`, and `legacy_credentials/` in that directory |
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
| Literal output, messages, edit replacement text, search patterns, prose tool arguments | Literal mentions of `.env` are not reads. |
| Recognized read, content-search, upload, copy, rename, or patch of a protected file | Deny raw access. Supported config reads can be rewritten. `git show`/`git cat-file` of `REV:PATH` is a read. |
| Recognized copy/rename/export of a conventional credential directory as source | Deny, including its containing home directory. Copying an ordinary file into the home directory is allowed. |
| Shell writes to a protected file: output redirects (`>`, `>>`), the `cp`/`mv` destination, `tee` outputs | Allow: writing discloses nothing. Sources and input redirects remain screened. |
| Write tool creating a new file | Allow. An existing file or link keeps the normal rules. |
| Edit/patch of a protected file | Deny; these tools can expose previous contents or diffs. For Claude `settings.json` and Docker `config.json`, the denial points to [`config set`](#config-edits). |
| `find` actions | Inspect explicit nested commands and protected operands. Common bulk readers such as `-exec cat {} +` are denied; `-exec basename {} \;` is allowed. |
| Environment, process-environment, or credential-store dumps | Deny. |
| Other application commands with credential-file arguments | Allow unless a separate recognized operation is denied. A protected filename alone is not a reason to block. |

Tool path arguments (`path`, `paths`, `file_path`, `filepath`, `filename`,
`file`, `uri`, `url`, `resource_uri`) are always screened. Any other tool
argument is screened as a file name only when it is a single word without
whitespace; queries, titles, and page text are prose. In such a word, a
backslash before `*`, `?`, or `[` is an escape, as in Markdown `\*\*bold\*\*`,
so that character is matched literally; other backslashes are path separators.

Shell operand checks apply to this finite set of common file-handling commands:
`cat`, `bat`, `nl`, `tac`, `xargs`, `head`, `tail`, `less`, `more`, `sed`, `awk`,
`cut`, `paste`, `sort`, `uniq`, `diff`, `rg`, `grep`, `egrep`, `fgrep`, `jq`, `yq`, `strings`, `od`,
`xxd`, `hexdump`, `base64`, `cp`, `mv`, `rsync`, `scp`, `sftp`, `tar`, `zip`,
`dd`, `tee`, `curl`, `wget`, and `find`. Metadata and search-pattern roles
still apply. Recognized wrappers (`command`, `exec`, `sudo`, `env`) use the
underlying command's checks. Native options are not validated; protected path
arguments to these commands remain conservatively screened.

Other command names do not trigger filename checks on their ordinary arguments.
For example, `uv run --env-file .env app.py`, `node --env-file=.env app.js`,
and `my-app --config .env` are allowed by the same general rule.
Direct file-tool paths, patch targets,
recognized inline file APIs, and shell redirections remain screened.

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

Using a credential at runtime is allowed: `curl -H "Authorization: Bearer
$GITHUB_TOKEN" …`, `OPENAI_API_KEY=$OPENAI_API_KEY app`, `test -n "$NPM_TOKEN"`,
and script lookups such as `os.getenv("OPENAI_API_KEY")` are not checked.
Environment checks deny only direct printing and dumps, in executed
shell/script arguments, never in repository file contents or edit text.

Direct printing uses the credential-name grammar below. `echo`/`printf` of
`$API_KEY` or `${MY_ACCESS_TOKEN}`, `printenv API_KEY`, and a Python/JavaScript
`print`/`console.log` whose argument is a credential lookup are denied.
`$MAX_TOKENS` and `printenv APP_MODE` do not match. Set and length tests such
as `${TOKEN:+set}` and `${#TOKEN}` print no value and are allowed. There is no
permitted-variable list.

Dumping forms include bare `env`/`printenv`/`set`, exported-variable listing,
printing the whole Python/JavaScript environment, `ps e`/`ps auxe`, and macOS
`ps -E`. Shell tracing (`set -x`, `bash -x`) is allowed. Ordinary `ps -e` and
explicit process columns such as `ps -axo pid,etime,command` are allowed.

`gh auth token`, `aws configure export-credentials`, `aws configure get` of a
credential name, `gcloud auth print-access-token`/`print-identity-token`,
`op read`, `op item get --reveal`, Keychain password output (`-w` or `-g` on
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
For recognized search commands, explicit access to protected files, including
pattern-file inputs, remains blocked. Redirections, secret expansions, and
recognized sibling credential reads are checked independently. Ordinary
pattern files remain usable.

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
`grep`, `egrep`, and `fgrep` receive explicit argument checks. A recursive grep
(`-r`, `-R`, `--recursive`, `-d recurse`, `rgrep`) gets `--exclude` and
`--exclude-dir` options for protected names that apply anywhere, inserted right
after the command name. Grep matches base names only, so a recursive grep over
a directory that holds home credential stores, such as `~` or `~/.aws`, is
denied; use `rg` there. `guard` alone checks arguments but cannot add
exclusions; use the installed `hook` for native search rewriting. There is no private search
runner, search byte limit, search deadline, or fixed ripgrep installation path.

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
under normal shell pipeline rules. Recognized downstream file operations and
nested execution remain screened. The sanitizer never launches another command.
Direct `head`, `tail`, `sed`, or `cat` with options on a protected config remain
raw protected reads and are denied. There is no supported-reader option table.

A `Read` call whose `file_path` names a supported config (absolute, `~/…`, or
relative to the request `cwd`) is pointed at a sanitized copy. The hook starts
the private runner as a separate process with a closed view plan; the runner
writes the view to `~/.cache/agent-secrets/views/<hash>-<name>` (directory
`0700`, file `0600`) and prints nothing. The view location derives from the
trusted home and source path, not from the plan, and each source has one view
that every read replaces. Other `Read` arguments such as `offset` and `limit`
are preserved and apply to the view. If the view cannot be written, the read is
denied. `guard`, other generic file tools, and MCP file tools remain denied on
protected configs.

Files must be regular and at most 4 MiB. Config-file symlinks and symlinks below
user-home config locations are refused. The entire document is parsed before
output, with a nesting limit of 64. TOML/JSON formatting and comments are not
preserved; JSON numeric precision is retained, and `&`, `<`, and `>` stay literal. Npm supports line-based
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

Claude Code's top-level `sandbox.credentials` block is an exception to the
container rule: it declares the variables and files to protect by name, path,
mode, and host, so its members use the ordinary rules instead of being hidden
as a whole. A `credentials` key anywhere else still hides its subtree.

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

## Config edits

```sh
agent-secrets config set FILE KEY JSON_VALUE
agent-secrets config unset FILE KEY
```

`FILE` must be Claude `~/.claude/settings.json` or a Docker `config.json`
location. TOML and npm files are refused so their comments are not lost.
`KEY` is dot-separated (`env.MCP_TOOL_TIMEOUT`) or a JSON array of member
names for names containing dots. `JSON_VALUE` is one JSON value, so a string is
quoted twice in the shell: `'"1800000"'`. Missing parent objects are created.

An edit is refused when the key or any parent key is a credential name, or when
the replaced or removed value is not fully visible in the sanitized view. Keys
address object members only, never array elements, so an edit cannot change how
another value is classified. Symlinked and malformed files are refused. In
Claude `settings.json`, an edit that removes the agent-secrets hook
registration, sets `disableAllHooks`, or changes `sandbox` as a whole or
`sandbox.credentials` is refused; other hooks and sandbox settings stay editable.
Client permissions still govern the command like any other shell command.

The edit follows the installation rules: parse before writing, back up the
original privately under `~/.local/share/agent-secrets/backups/`, refuse a
concurrent change, replace atomically with the original mode, and verify by
readback. The document is re-encoded with two-space indentation and sorted keys;
JSON number precision is kept. Output is a fixed message; the file and the
request are never printed. `agent-secrets` is outside the file-command set, so
its `FILE` argument is not screened as a read.

## Coverage limits

This is an accidental-disclosure guard, not filesystem isolation or a general
interpreter. Unknown secret filenames, arbitrary unlabeled values, custom token
formats, hard links, opaque encodings, dynamically assembled paths/programs,
and unrecognized tool schemas can escape the heuristics. Commands outside the
finite file-command set, including custom readers and readers hidden behind
unsupported application launchers, are not classified by their file arguments.
A random secret under an innocent key is not guaranteed to be redacted.
Application output and network responses are not generally filtered. General
directory transfers are not a sandbox-enforced file policy.

The private runner controls its reads and revalidates untrusted plans. Ordinary
allowed tools still execute in the client and can race with changes after
metadata screening. Client permissions, sandbox restrictions, and hook trust
remain separate controls. See [usage](usage.md) and [development](development.md)
for activation and verification boundaries.
