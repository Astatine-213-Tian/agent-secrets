# Agent Secrets

A Go `PreToolUse` hook for local Codex and Claude Code. Ordinary shell reads of
the user's Codex config return locally redacted content automatically. Other
recognizable credential-file reads and environment dumps remain blocked.

**Hook only.** Installation adds ordinary user hooks. It does not create a
permission mode, change sandbox settings, disable Full Access, or install
administrator-managed restrictions.

## Install

macOS and Linux are supported. Build with [mise](https://mise.jdx.dev/):

```sh
mise install
mise run check
mise run build
./bin/agent-secrets install
```

Go **1.27.2** is pinned in `mise.toml` and `go.mod`, verified against the
[official stable release feed](https://go.dev/dl/?mode=json) on 2026-10-11.
The reader uses `github.com/BurntSushi/toml` to parse TOML; command recognition
uses `mvdan.cc/sh/v3` to parse shell syntax without executing expansions. The
installed executable needs neither Go nor Python at runtime. It uses the
standard system `cat`, `head`, `tail`, and `sed` utilities for output selection.

The installer copies the executable to
`~/.local/share/agent-secrets/agent-secrets` and merges registrations into:

- `~/.codex/hooks.json`
- `~/.claude/settings.json`

Unrelated settings and hooks are preserved. Existing settings are backed up
privately under `~/.local/share/agent-secrets/backups/`, and writes are read back.
Repeated installation is idempotent. Existing `guard` registrations are replaced
with `hook` registrations so automatic redaction runs. Use `install --home PATH`
for an alternate user home. Run as a normal user, outside a sandbox that denies
these settings.

Restart both clients. In Codex, open **`/hooks`**, review the command and trust
it. Writing configuration does not automatically grant hook trust. Changes to
the hook definition may require renewed trust, and hooks must be enabled in
the client. No trust bypass is installed.

```sh
~/.local/share/agent-secrets/agent-secrets status
~/.local/share/agent-secrets/agent-secrets verify
```

`status` compares the installed binary and reads both hook registrations.
`verify` invokes the actual executable with synthetic requests, checking exit
codes and exact output, including sanitized-reader fixtures in a temporary home.
Neither command claims that a running client has loaded or trusted its hook.
Verification needs no agent login or model usage.

## Ordinary config reads are redacted automatically

After installation and hook trust, agents use their usual shell reads:

```sh
cat ~/.codex/config.toml
head -n 40 ~/.codex/config.toml
tail -n 20 ~/.codex/config.toml
sed -n '1,120p' ~/.codex/config.toml
```

There is no special command to learn and no initial denial for supported reads.
Before the tool runs, the hook rewrites the request to a private local runner.
That runner parses `~/.codex/config.toml`, redacts values, then feeds only the
sanitized TOML to the requested reader. The raw file is never tool output.
The hook itself inspects arguments and metadata only; it never reads the config.

Supported requests are one simple `cat`, `head`, `tail`, or line-printing
`sed -n` command targeting this file. Quoted absolute paths, `~`, `$HOME`, and
relative paths from the tool's working directory are recognized, as is input
redirection (`cat < ~/.codex/config.toml`). Standard `cat` display flags,
`head`/`tail` counts, and numeric or `$` line ranges for `sed` are supported.
Line selection applies to the **sanitized** document; original line numbers and
formatting are not preserved.

Pipelines, compound commands, multiple files, shell substitutions, arbitrary
scripts, direct file/MCP reads, and write/follow options remain subject to the
raw-read guard. They are not automatically rewritten. Only the exact user
config is supported; project layers and `CODEX_HOME` overrides are not merged.
The reader leaves the source unchanged, does not resolve environment values or
launch configured commands, and creates no raw or sanitized files on disk.

- Known ordinary settings remain visible, including `prevent_idle_sleep`,
  model identifiers, reasoning effort, approval/sandbox settings, feature
  booleans, and MCP enablement/timeouts. Profile settings use the same rules.
- Environment-variable names in `bearer_token_env_var`, `env_vars`,
  `env_http_headers`, and provider `env_key` remain visible when syntactically
  valid. Their values are never looked up.
- Inline environment values, HTTP headers, URLs (including credentials in
  paths or queries), commands, arguments, instructions, and unknown values
  become `[REDACTED]`. Conservative redaction may hide harmless values too.
- Setting names, table names, and array structure are retained. Comments and
  original formatting are discarded. Do not store credentials in setting/table
  names, model identifiers, or environment-variable names: these are visible
  metadata. The output is an inspection view, **not a replacement config**.

Malformed, oversized (over 4 MiB), excessively nested, missing, or inaccessible
configuration fails with a fixed error and no config output. Symlinked config
files and `.codex` directories are refused, as are non-regular files. Filesystem
denials remain in force; the reader does not bypass sandbox permissions.

Private keys and authentication stores remain blocked. No broad shell-command
exemption is installed. The hook returns `updatedInput` with an `allow` decision
only for an allowlisted read, preserving and screening the other tool arguments.
Codex requires `allow` for input rewriting; this can approve the rewritten read
at the hook layer, while native filesystem denials still apply.

This uses `PreToolUse` input rewriting instead of `PostToolUse` filtering. Codex
does not support general output-replacement fields on every tool path. The
private runner sanitizes before producing stdout, including when the read is
made through a nested code-mode tool call covered by the client hook.

## What it checks

- Nested file, image, MCP, shell, stdin, and patch-destination arguments.
- `.env`, `.env.*`, known private-key filenames, credential/settings stores,
  and browser authentication state.
- File URIs, percent-encoded paths, `~` and common home-variable paths, and
  symlink targets, including dangling links.
- Recognizable environment dumps, credential-variable expansions, common
  credential commands, and broad hidden-file content scans.

`.env.example` and `.env.schema.json` are allowed unless their symlink target
is protected. Editing normal source files is allowed even when the source
contains credential-loading code. Ordinary authenticated commands such as
`gh api user` remain allowed; the hook doesn't prevent the application itself
from using its credentials internally.

Prompt and message prose is not treated as a filesystem path, so long worker
instructions remain allowed. Sibling and nested path or command arguments are
still screened, as are the worker's subsequent tool calls.
Long prose literals inside commands also remain allowed when filesystem metadata
reports that they cannot be filenames. Protected-path and environment checks
still apply; explicit path arguments and other metadata errors fail closed.
Python's `from module import *` syntax is recognized as an import, while shell
wildcard reads such as `cat *` remain screened.

This is an accidental-disclosure guard, **not an isolation mechanism**. Computed
paths, arbitrary code, remote tools, encoded values, and content already in a
conversation can evade argument inspection. False positives are possible.
Clients may fail open on hook crashes or timeouts. Users can disable ordinary
hooks, and Codex cloud orchestration does not load local command hooks.

## Development

```sh
mise run check
mise exec -- go test -cover ./...
mise exec -- go test ./internal/guard -run '^$' -fuzz FuzzCheck -fuzztime 10s
mise exec -- go test ./internal/guard -run '^$' -fuzz FuzzHook -fuzztime 10s
mise exec -- go test ./internal/install -run '^$' -fuzz FuzzPrepare -fuzztime 10s
mise exec -- go test ./internal/install -run '^$' -fuzz FuzzRedactCodexConfig -fuzztime 10s
```

Tests use synthetic inputs and isolated homes. CI runs on macOS and Linux.

Protocol: the installed `agent-secrets hook` reads one JSON hook request on
stdin. Ordinary allowed requests exit `0` silently; recognized config reads
exit `0` with the client's `PreToolUse.updatedInput` JSON contract. Denied,
malformed, or oversized requests exit `2` with a fixed message on stderr.
Input is limited to 4 MiB. Config contents and internal errors are never echoed
by the hook. `agent-secrets guard` retains the original silent allow/deny-only
protocol for direct testing. The private reader is not a user-facing CLI.

## References

- [Codex hooks, trust, and coverage](https://learn.chatgpt.com/docs/hooks)
- [Claude Code hooks](https://code.claude.com/docs/en/hooks)
