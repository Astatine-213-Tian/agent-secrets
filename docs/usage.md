# Installation and usage

Read the [protection rules](rules.md) for common examples.
Use the [rule reference](rule-reference.md) for exact checks and limits.

## Install

macOS and Linux are supported. Build with [mise](https://mise.jdx.dev/):

```sh
mise install
mise run check
mise run build
./bin/agent-secrets install
```

The installed executable needs neither Go nor Python at runtime. Its private
reader parses and sanitizes configurations directly, without starting a utility.
Searches use the existing native ripgrep executable, options, and configuration;
see the [search rules](rules.md#content-searches).
See [development](development.md) for the toolchain and dependencies.

The installer copies the executable to
`~/.local/share/agent-secrets/agent-secrets` and merges a `PreToolUse` command
hook with matcher `*` and a five-second timeout into:

- `~/.codex/hooks.json`, as `agent-secrets hook`
- `~/.claude/settings.json`, as `agent-secrets hook --client claude`

Unrelated settings, hook handlers, and JSON number precision are preserved.
Both settings documents are parsed before replacement. Existing settings are
backed up privately under `~/.local/share/agent-secrets/backups/`; replacements
are atomic per file and verified by readback. A concurrent settings change
detected before replacement causes installation to fail. Installation is not
a transaction across the binary and both settings files; after a failure,
check status before relying on the result.

Repeated installation keeps the registrations idempotent, while making fresh
backups. Registrations using the same binary's old `guard` command, or the other
client's `hook` form, are replaced so each client gets its own form. `install --home PATH` targets another
home directory; run the clients with the corresponding home. Run installation
as your normal user, without `sudo`. If an agent sandbox denies access to the
settings, perform the installation in your own terminal. The installer does
not change permission modes, native sandbox policy, or administrator restrictions.

## Activate and verify

Restart both clients. In Codex, open **`/hooks`**, review the command and trust
it. Changed hook definitions require renewed trust, and hooks must be enabled
in the client. The installer does not grant trust or install a trust bypass.

From the checkout, compare the build with the installation:

```sh
./bin/agent-secrets status
```

Then verify the installed executable:

```sh
~/.local/share/agent-secrets/agent-secrets verify
```

`status` compares the invoking binary with the installed binary and reads both
registrations. Running the installed binary's own `status` checks it against
itself, so use the checkout build to check whether a new build was installed.
`verify` runs synthetic hook requests and sanitized-reader fixtures, checks
exact output and exit codes, and requires fixture cleanup to succeed. It needs
no agent login or model usage. Neither command proves that a running client
has loaded or trusted the hook.

## Use

Agents can use these ordinary shell reads after activation:

```sh
cat ~/.codex/config.toml
cat ~/.codex/config.toml | head -n 40
cat ~/.codex/config.toml | tail -n 20
cat ~/.codex/config.toml | sed -n '1,120p'
```

The hook rewrites supported reads automatically. The tool receives a redacted
inspection view; line numbers refer to that view, not the original file.
The [redaction reference](rule-reference.md#redaction-rules) lists the value
checks and supported read forms. Tools after the pipe keep their normal options.
The hook still blocks known raw reads of protected configuration files.
Unmatched settings remain visible. Supported reads of Docker, Claude, and npm
configuration also hide detected secrets. Known reads of credential stores
remain blocked.

Metadata checks such as `ls -l .env` are allowed. Native directory searches such
as `rg --hidden --max-count 2 pattern .` receive protected-path exclusions.
Application commands such as `uv run --env-file .env app.py` are allowed;
shell filename checks apply only to the [listed file commands](rule-reference.md#operation-checks).
Pipelines and compound searches keep their original shell behavior. Coverage
and limits are listed in the rules.

Use `agent-secrets help` for the CLI and `agent-secrets version` for the package
and Go versions. The private reader is an internal hook target, not a public
configuration-export command.

Client references: [Codex hooks and trust](https://learn.chatgpt.com/docs/hooks),
[Claude Code hooks](https://code.claude.com/docs/en/hooks).
