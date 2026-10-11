# Agent Secrets

A Go `PreToolUse` hook that blocks recognizable credential-file reads and
environment dumps in local Codex and Claude Code sessions. It inspects tool
arguments and filesystem metadata, never secret contents.

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
The package uses only Go's standard library. The installed executable needs
neither Go nor Python at runtime.

The installer copies the executable to
`~/.local/share/agent-secrets/agent-secrets` and merges registrations into:

- `~/.codex/hooks.json`
- `~/.claude/settings.json`

Unrelated settings and hooks are preserved. Existing settings are backed up
privately under `~/.local/share/agent-secrets/backups/`, and writes are read back.
Repeated installation is idempotent. Use `install --home PATH` for an alternate
user home. Run as a normal user, outside a sandbox that denies these settings.

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
codes and exact output. Neither command claims that a running client has loaded
or trusted its hook. Verification needs no agent login or model usage.

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
mise exec -- go test ./internal/install -run '^$' -fuzz FuzzPrepare -fuzztime 10s
```

Tests use synthetic inputs and isolated homes. CI runs on macOS and Linux.

Protocol: `agent-secrets guard` reads one JSON hook request on stdin. Allowed
requests exit `0` silently. Denied, malformed, or oversized requests exit `2`
with a fixed message on stderr. Input is limited to 4 MiB. Request data and
internal error details are never echoed.

## References

- [Codex hooks, trust, and coverage](https://learn.chatgpt.com/docs/hooks)
- [Claude Code hooks](https://code.claude.com/docs/en/hooks)
