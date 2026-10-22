# Rule reference

For a short guide and common examples, read [Protection rules](rules.md).
This page gives the exact paths, commands, and value checks.

Agent Secrets uses two methods:

- **Filename checks for known file operations**
- **Selective value redaction for supported configuration reads**

Agent Secrets does not scan all source files for variable names that look
secret. Config values that do not match a rule stay visible. There is no
allowlist of settings, types, or safe values.

The hook examines only arguments and file-system metadata. A separate private
runner reads and sanitizes supported configs. Usual commands run natively, with
their own options, environment, output, and exit behavior.

The hook changes the input in two cases only:

- The config-read bridge: basic shell `cat` reads and Claude Code `Read` calls
- Native ripgrep path exclusions

`config set` and `config unset` change one setting that is not a credential.
They do not print the file.
There is no general command runner. There is no list of permitted native
options.

## Protected resources

Paths are case-sensitive. `*` matches in one path component. `**` matches
across directories. In this section, `~` is the home directory of the hook user.

| Location | Protected resources |
| --- | --- |
| Anywhere | `.env`, `.env.*`, `.envrc`, `.dev.vars`, `.npmrc`, `private-key.pem`, `private.key`, `*.p12`, `*.pfx`, `id_rsa`, `id_dsa`, `id_ed25519`, `id_ecdsa` |
| Browser sessions | `**/browser-profiles/**/state.json`, `**/browser-profiles/**/.state.*.tmp` |
| SSH | `~/.ssh/id_*` |
| Provider and package credentials | `~/.aws/credentials`, `~/.config/gh/hosts.yml`, `~/.git-credentials`, `~/.kube/config`, `~/.netrc`, `~/.npmrc`, `~/.pypirc`, `~/.docker/config.json` |
| Google Cloud | `~/.config/gcloud/application_default_credentials.json`, and `credentials.db`, `access_tokens.db`, and `legacy_credentials/` in that directory |
| Agent settings and credentials | `~/.codex/config.toml`, `~/.codex/auth.json`, `~/.claude/settings.json`, `~/.claude.json`, `~/.claude/.credentials.json` |
| Backups | `~/.local/share/agent-secrets/backups` and all items in it |

The only exceptions are `.env.example`, `.env.schema.json`, and SSH `id_*.pub`
public keys. An exception to one rule does not make a different protected
location exempt. A symlink with a public name to a protected target is
protected. The hook does not block all `.pem`, `.key`, JSON, or TOML files.

These location variables add protection. The default locations stay protected.

| Variable | Added resources |
| --- | --- |
| `CODEX_HOME` | `config.toml` and `auth.json` in that directory |
| `DOCKER_CONFIG` | `config.json` in that directory |
| `NPM_CONFIG_USERCONFIG` | The specified file |
| `AWS_SHARED_CREDENTIALS_FILE` | The specified file |

The hook examines only the location strings. It identifies inherited values and
literal shell assignments. A relative location starts from the effective
working directory. The hook rejects known computed changes to a location.

## Operation checks

| Operation | Rule |
| --- | --- |
| `ls`, `stat`, existence tests, usual `find` listing | Allow. Names and metadata do not show file values. |
| Literal output, messages, edit replacement text, search patterns, prose tool arguments | A literal mention of `.env` is not a read. |
| Known read, content search, upload, copy, rename, or patch of a protected file | Deny raw access. The hook can rewrite supported config reads. `git show` or `git cat-file` of `REV:PATH` is a read. |
| Known copy, rename, or export of a usual credential directory as source | Deny. This also applies to the home directory that contains it. A copy of a usual file into the home directory is allowed. |
| Shell writes to a protected file: output redirects (`>`, `>>`), the `cp` or `mv` destination, `tee` outputs | Allow. A write shows nothing. The hook continues to screen sources and input redirects. |
| Write tool that makes a new file | Allow. For an existing file or link, the usual rules apply. |
| Edit or patch of a protected file | Deny. These tools can show previous contents or diffs. For Claude `settings.json` and Docker `config.json`, the denial gives [`config set`](#config-edits). |
| `find` actions | Examine explicit nested commands and protected operands. Deny common bulk readers, for example `-exec cat {} +`. Allow `-exec basename {} \;`. |
| Dumps of the environment, the process environment, or a credential store | Deny. |
| Other application commands with credential-file arguments | Allow, if the hook does not deny a separate known operation. A protected filename alone is not a cause for a block. |

The hook always screens these tool path arguments: `path`, `paths`,
`file_path`, `filepath`, `filename`, `file`, `uri`, `url`, and `resource_uri`.
The hook screens a different tool argument as a filename only if the argument is
one word with no whitespace. Queries, titles, and page text are prose.
In such a word, a backslash before `*`, `?`, or `[` is an escape, as in Markdown
`\*\*bold\*\*`. Thus, the hook matches that character literally. Other
backslashes are path separators.

Shell operand checks apply only to this fixed set of common file commands:
`cat`, `bat`, `nl`, `tac`, `xargs`, `head`, `tail`, `less`, `more`, `sed`, `awk`,
`cut`, `paste`, `sort`, `uniq`, `diff`, `rg`, `grep`, `egrep`, `fgrep`, `jq`, `yq`, `strings`, `od`,
`xxd`, `hexdump`, `base64`, `cp`, `mv`, `rsync`, `scp`, `sftp`, `tar`, `zip`,
`dd`, `tee`, `curl`, `wget`, and `find`.
The metadata and search-pattern roles continue to apply. Known wrappers
(`command`, `exec`, `sudo`, `env`) use the checks of the command that they run.
The hook does not validate native options. It continues to screen protected path
arguments to these commands carefully.

Other command names do not cause filename checks on their usual arguments.
For example, the same general rule allows `uv run --env-file .env app.py`,
`node --env-file=.env app.js`, and `my-app --config .env`.
The hook continues to screen file-tool paths, patch targets, known inline file
APIs, and shell redirections.

**The hook allows `ls -l .env`**, because it does not show environment values.
The hook denies `cat .env`, `cp .env public.txt`, and
`curl --data-binary @.env …`.
The hook allows `echo '.env'`. It denies `echo "$(cat .env)"`.

The hook examines expansions, redirections, nested execution, and sibling
commands separately. A metadata permission does not make `ls $(cat .env)` or
`ls .env; cat .env` exempt. A safe operand never makes an unsafe operand exempt.

The hook uses the request `cwd` and the tool `workdir`. It examines lexical and
resolved paths. It follows symlink metadata, also for missing targets.
The hook supports these shell context changes: literal `cd DIR; COMMAND`,
`cd DIR && COMMAND`, and `env -C DIR COMMAND`.
A compound command, a substitution, or an unknown option alone does not cause a
denial. The hook continues to examine nested operations. The hook cannot
reliably follow computed directories and all shell control flow.

### Environment and inspection commands

A command can use a credential at runtime. The hook does not examine these
examples: `curl -H "Authorization: Bearer $GITHUB_TOKEN" …`,
`OPENAI_API_KEY=$OPENAI_API_KEY app`, `test -n "$NPM_TOKEN"`, and script lookups,
for example `os.getenv("OPENAI_API_KEY")`.
Environment checks deny only direct output and dumps. They apply to the
arguments of executed shell commands and scripts. They do not apply to
repository file contents or edit text.

For direct output, the hook uses the credential-name grammar that follows.
The hook denies these examples:

- `echo` or `printf` of `$API_KEY` or `${MY_ACCESS_TOKEN}`
- `printenv API_KEY`
- A Python `print` or JavaScript `console.log` with a credential lookup as its
  argument

`$MAX_TOKENS` and `printenv APP_MODE` do not match. Set tests and length tests,
for example `${TOKEN:+set}` and `${#TOKEN}`, print no value. The hook allows
them. There is no list of permitted variables.

These forms are dumps:

- `env`, `printenv`, or `set` with no arguments
- A list of exported variables
- Output of the full Python or JavaScript environment
- `ps e`, `ps auxe`, and macOS `ps -E`

The hook allows shell traces (`set -x`, `bash -x`). It allows usual `ps -e` and
explicit process columns, for example `ps -axo pid,etime,command`.

The hook denies these commands:

- `gh auth token`
- `aws configure export-credentials`, and `aws configure get` of a credential
  name
- `gcloud auth print-access-token` and `print-identity-token`
- `op read` and `op item get --reveal`
- Keychain password output (`-w` or `-g` on `find-generic-password` or
  `find-internet-password`)
- Full `docker inspect` and full `docker compose config`

The hook allows Keychain metadata lookups. It allows these Compose selectors:
`--services`, `--images`, `--volumes`, `--profiles`, `--networks`, and
`--quiet` or `-q`.

Docker inspection has no list of permitted templates or object counts. The hook
allows usual selections, for example `{{.Name}}` and `{{.Config.Image}}`.
The hook denies these items:

- Known output of the full object (`{{json .}}`, `{{.}}`, or format `json`)
- The full `Config` or `ContainerConfig`
- Field selections that contain `Env`, `Args`, `Cmd`, `Entrypoint`, `Labels`,
  or a credential-name match

These checks are limited recognizers. They are not a Go-template interpreter.
Selections that a program makes at runtime and indirect template lookups can
go around them.

### Content searches

The hook allows usual searches and their native options. There is no allowlist
of search options. A directory operand or a compound command alone does not
cause a denial. For known search commands, the hook continues to block explicit
access to protected files, including pattern-file inputs. It examines
redirections, secret expansions, and known sibling credential reads
separately. Usual pattern files stay usable.

For shell `rg` calls that the hook parses directly, it adds negative `--glob`
exclusions for protected paths. This also operates in pipelines and compound
commands. The native shell and ripgrep continue to control these items:

- The original arguments and the executable selection
- The configuration, stdin, and redirections
- The output format, the order, and duplicate matches
- The exit behavior

The hook does not reject an option only because the option is not on a list.
Examples are `--max-count`, `--json`, `--sort`, context flags, and future flags.
For an incorrect option, the native tool gives its own error. `rg --files`
shows filenames only, so it stays a metadata operation. The hook continues to
screen pattern-file inputs.

The search exception identifies common argument roles: patterns, file inputs,
option values, and `--`. Thus, the hook does not think that a literal `.env`
search pattern is a file read. This recognition is intentionally limited. It is
not a full option specification. Unknown argument layouts can stay ambiguous.
To prevent ambiguity with a positional pattern, use `-e PATTERN`.

The hook examines the original request before it adds exclusions. Thus, the
hook denies an explicit `rg pattern .env`. But a recursive
`rg --hidden pattern .` runs, and ripgrep skips that file. Public `.env`
examples and SSH public keys stay searchable. The exclusions follow the
protected locations in this document, including the supported location
variables. They do not depend on file contents.

This is native filename filtering. It does not control each file read.
These items can go around the heuristics: symlink following, custom
preprocessors, directories or arguments that change at runtime, and searches
in scripts.

The hook examines the arguments of `grep`, `egrep`, and `fgrep`. For a
recursive grep (`-r`, `-R`, `--recursive`, `-d recurse`, `rgrep`), the hook adds
`--exclude` and `--exclude-dir` options for protected names that apply
anywhere. It puts them immediately after the command name. Grep matches only
base names. Thus, the hook denies a recursive grep of a directory that contains
home credential stores, for example `~` or `~/.aws`. Use `rg` for these
directories.

`guard` examines arguments, but it cannot add exclusions. For native search
rewrites, use the installed `hook`. There is no private search runner, search
byte limit, search deadline, or fixed ripgrep installation path.

## Redaction rules

### Supported config reads

The runner sanitizes these files, including the supported location variables:

- Codex `config.toml`
- Claude `settings.json` and `~/.claude.json`
- Docker `config.json`
- `.npmrc` files

This interface does not read auth stores, for example Codex `auth.json`.

A rewrite needs a `tool_input` that is an object. It operates on `Bash` and
`shell_command` (`command`), and on `exec_command` (`cmd`).
The bridge identifies only a basic `cat FILE`, `cat -- FILE`, or `cat < FILE`.
A `command` prefix is optional. `cat`, `/bin/cat`, and `/usr/bin/cat` match.
Literal paths, `~/…`, and supported location-variable references operate.
The rewrite keeps the other arguments and the precision of JSON numbers. The
hook continues to screen siblings.

Basic reads can be in pipelines and compound commands, if the working directory
and the environment do not change. The bridge replaces only that read with the
private sanitizer. For native options or selections, use usual pipelines:

```sh
cat ~/.codex/config.toml | cat -n
cat ~/.codex/config.toml | head -n 40
cat ~/.codex/config.toml | sed -n '1,80p'
```

Downstream tools control all their native behavior, including errors and the
exit status of the pipeline. Under usual shell pipeline rules, a later command
that succeeds can hide an earlier failure. The hook continues to screen known
downstream file operations and nested execution. The sanitizer never starts a
different command. Direct `head`, `tail`, `sed`, or `cat` with options on a
protected config are raw protected reads. The hook denies them. There is no
table of supported reader options.

The hook points a `Read` call at a sanitized copy if its `file_path` names a
supported config. The path can be absolute, `~/…`, or relative to the request
`cwd`. These steps occur:

1. The hook starts the private runner as a separate process with a closed view
   plan.
2. The runner writes the view to `~/.cache/agent-secrets/views/<hash>-<name>`.
   The directory mode is `0700` and the file mode is `0600`. The runner prints
   nothing.
3. The hook gives Claude Code the view path and a fixed `additionalContext`
   note.

The view location comes from the trusted home directory and the source path.
It does not come from the plan. Each source has one view, and each read
replaces it. The rewrite keeps the other `Read` arguments, for example `offset`
and `limit`, and they apply to the view. If the runner cannot write the view,
the hook denies the read.

The note is necessary because Claude Code now thinks that the copy is the read
file. Thus, the read-before-edit check of Claude Code rejects `Edit` and `Write`
on the original before the hook runs. For JSON files that `config set` can
edit, the note gives `config set`. For other files, it gives the client
commands, for example `claude mcp`, or tells the agent to ask the user.
The hook continues to deny `guard`, other generic file tools, and MCP file tools
on protected configs.

Files must be regular files. The maximum size is 4 MiB. The runner refuses
config-file symlinks and symlinks below config locations in the user home
directory. The runner parses the full document before output. The maximum
nesting depth is 64. The output does not keep TOML or JSON formatting and
comments. It keeps the precision of JSON numbers, and `&`, `<`, and `>` stay
literal. For npm, the runner supports `key=value` lines and removes comment
lines. A failure gives a fixed error and no configuration output. Line numbers
refer to the sanitized view. The runner never changes the source file.

### Credential keys and paths

Normalize names for case, camelCase, underscores, hyphens, and punctuation.
A key matches if its normalized name is one of these names, or if it ends with
`_` and one of these names:

`password`, `passwd`, `passphrase`, `token`, `api_key`, `apikey`, `access_key`,
`secret`, `secret_key`, `private_key`, `signing_key`, `encryption_key`, `hmac_key`,
`password_hash`, `hashed_password`, `credential`, `credentials`.

Examples of matches: `access_token`, `refresh_token`, `id_token`, `auth_token`,
`bearer_token`, `session_token`, `personal_access_token`, `client_secret`,
`webhook_secret`, `shared_secret`, `AWS_SECRET_ACCESS_KEY`, `OPENAI_API_KEY`.

Examples that do not match: `MAX_TOKENS`, `TOKENIZERS_PARALLELISM`,
`token_limit`, `password_min_length`, `username`, `client_id`, generic `key`,
generic `auth`.

A matching scalar becomes `[REDACTED]`. A matching container keeps its shape,
and the runner hides all scalar values in it. These rules apply to all tables,
arrays, and `profiles.<name>` subtrees. Context adds these matches:

- Docker `auths.<registry>.auth`, `.identitytoken`, and `.registrytoken`.
- Npm `_auth`, `_authToken`, and `_password`, including entries with a
  registry prefix.
- Entries in `headers` and `http_headers` use the header rules that follow.
- Entries in `query_params` use the query rules that follow.
- Claude `~/.claude.json` top-level `customApiKeyResponses`. This item keeps
  the endings of approved and rejected API keys.
- Claude `~/.claude.json` `projects.<path>.history`. This item is an older
  prompt history, and it can contain pasted secrets.

The rules that hide values apply to all supported configs. If a rule matches
in an unrelated file, the runner only hides more. The two rules that keep a
value visible apply only to one config each. In other configs, the same layout
stays hidden.

The top-level `sandbox.credentials` block in Claude `settings.json` is an
exception to the container rule. This block gives the variables and files to
protect by name, path, mode, and host. Thus, its members use the usual rules,
and the runner does not hide the full block. A `credentials` key in a different
location or in a different file continues to hide its subtree.

The runner hides only sensitive inline environment entries. `NODE_ENV`,
`LOG_LEVEL`, `PATH`, and values that do not match stay visible. But the runner
hides known credential material in their text. These rules do not scan usual
source files.

### References and headers

In Codex `config.toml` only, these fields keep environment-variable names that
have a correct syntax. The runner does not look up their values. The fields
also apply below profiles:

- `mcp_servers.<name>.bearer_token_env_var`
- `mcp_servers.<name>.env_vars[]`
- `mcp_servers.<name>.env_http_headers.<header>`
- `model_providers.<name>.env_key`
- `model_providers.<name>.env_http_headers.<header>`

Sensitive header names are not case-sensitive. They are `Authorization`,
`Proxy-Authorization`, `Cookie`, `Set-Cookie`, `X-Registry-Auth`, `X-Auth`, and
credential-name matches. The matches include `X-API-Key`, `Api-Key`,
`X-Auth-Token`, `X-Access-Token`, and `X-Amz-Security-Token`. Hide their full
values. Other headers, for example `Accept` and `X-Request-ID`, stay visible.

### URLs, commands, arguments, and instructions

The runner examines all string values for these specific constructs:

| Construct | Redaction |
| --- | --- |
| URL user information, including database URLs | Hide the user information. Keep the usual host, path, and query values. |
| Query parameters and URL fragments in parameter style | Hide credential-name matches, `key`, `sig`, `signature`, `X-Amz-Signature`, `X-Amz-Credential`, `X-Goog-Signature`, `X-Goog-Credential`. |
| Slack `hooks.slack.com/services/…` and Discord `/api/webhooks/…` URLs | Hide the path that contains the credential. |
| Explicit `name=value` or `name: value` | Hide the values of credential-name matches. |
| `--credential-flag VALUE` or `--credential-flag=VALUE` | Hide the value. Keep the other arguments. In `args` arrays, this also applies when the flag and the value are separate elements. |
| `-u` or `--user` with `user:password` | Hide the pair. A username alone stays visible. |
| Sensitive header lines, and `Bearer` or `Basic` authentication text | Hide the authentication values. |
| PEM private-key blocks | Hide the block. If the block has no end, hide it to the end of the string. |
| Known provider tokens | GitHub `gh[pousr]_` and `github_pat_`, `sk-` and `sk-proj-`, Slack `xox[baprs]-`, Docker `dckr_pat_`, GitLab `glpat-`, npm `npm_`. The minimum payload length is 20, or 10 for Slack. |

The runner never runs configured commands, instructions, credential helpers, or
environment expansions. It hides known malformed URL constructs fully.
There is no entropy detector. The runner does not hide all prose, commands,
arguments, or URLs.

Outside a header, `Basic` needs a correct base64 `user:password` pair.
`Bearer` needs a minimum of eight characters. These words do not count:
`token`, `tokens`, `authentication`, `authorization`, and `credentials`.

## Config edits

```sh
agent-secrets config set FILE KEY JSON_VALUE
agent-secrets config unset FILE KEY
```

`FILE` must be Claude `~/.claude/settings.json` or a Docker `config.json`
location. The command refuses TOML and npm files, because an edit removes their
comments. The command refuses `~/.claude.json`, because Claude Code writes it
again from memory and can undo a change from a different process. Use the
Claude Code commands for this file, for example `claude mcp remove`.

`KEY` uses dots as separators (`env.MCP_TOOL_TIMEOUT`). If a member name
contains a dot, give `KEY` as a JSON array of member names. `JSON_VALUE` is one
JSON value. Thus, a string has two levels of quotes in the shell: `'"1800000"'`.
The command makes missing parent objects.

The command refuses an edit in these conditions:

- The key or a parent key is a credential name.
- The sanitized view of that file does not fully show the value that the edit
  replaces or removes.
- The file is a symlink or is malformed.
- In Claude `settings.json`, the edit removes the agent-secrets hook
  registration, sets `disableAllHooks`, or changes all of `sandbox` or
  `sandbox.credentials`.

Other hooks and sandbox settings stay editable. Keys address only object
members, never array elements. Thus, an edit cannot change how the runner
classifies a different value. Client permissions control the command as they
control all shell commands.

The edit follows the installation rules:

1. Parse the file before the write.
2. Make a private backup of the original in
   `~/.local/share/agent-secrets/backups/`.
3. Refuse the edit if a different process changed the file.
4. Replace the file atomically and keep the original mode.
5. Read the file again to verify the write.

The command encodes the document again with two-space indentation and sorted
keys. It keeps the precision of JSON numbers. The output is a fixed message.
The command never prints the file or the request. `agent-secrets` is not in the
set of file commands. Thus, the hook does not screen its `FILE` argument as a
read.

## Coverage limits

This tool prevents accidental disclosure. It does not isolate the file system,
and it is not a general interpreter. These items can go around the heuristics:

- Unknown secret filenames
- Values with no label
- Custom token formats
- Hard links and opaque encodings
- Paths and programs that a process makes at runtime
- Tool schemas that the hook does not know

The hook does not classify the file arguments of commands outside the fixed
set of file commands. This includes custom readers and readers in unsupported
application launchers. The runner cannot always hide a random secret under a
harmless key. The hook does not filter all application output and network
responses. General directory transfers are not a file policy that a sandbox
enforces.

The private runner controls its reads and validates untrusted plans again.
Usual allowed tools run in the client. A file can change after the metadata
screening and before the tool runs. Client permissions, sandbox restrictions,
and hook trust are separate controls. For activation and verification
boundaries, refer to [usage](usage.md) and [development](development.md).
