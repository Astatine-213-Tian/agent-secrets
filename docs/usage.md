# Installation and usage

For common examples, read the [protection rules](rules.md).
For exact checks and limits, use the [rule reference](rule-reference.md).

## Install

Agent Secrets operates on macOS and Linux. Use [mise](https://mise.jdx.dev/)
to build it:

```sh
mise install
mise run check
mise run build
./bin/agent-secrets install
```

The installed executable does not need Go or Python at runtime. Its private
reader parses configurations and hides their secrets directly. It does not
start a different utility.
Searches use the installed ripgrep executable with its usual options and
configuration. Refer to the [search rules](rules.md#content-searches).
For the toolchain and dependencies, refer to [development](development.md).

The installer copies the executable to
`~/.local/share/agent-secrets/agent-secrets`. Then it adds a `PreToolUse`
command hook to these files. The hook has the matcher `*` and a timeout of
five seconds.

- `~/.codex/hooks.json`, as `agent-secrets hook`
- `~/.claude/settings.json`, as `agent-secrets hook --client claude`

The installer keeps these items without change:

- Unrelated settings
- Other hook handlers
- The precision of JSON numbers

The installer does these steps:

1. It parses the two settings files before it replaces them.
2. It makes a private backup of each file in
   `~/.local/share/agent-secrets/backups/`.
3. It replaces each file in one atomic operation.
4. It reads each file again to make sure that the write is correct.

If a different process changes a settings file before the replacement, the
installation stops with an error.
The installation is not one transaction across the binary and the two settings
files. After a failure, examine the status before you use the result.

You can install again. The registrations do not change, but the installer makes
new backups. The installer replaces an older registration that uses the `guard`
command, or that uses the hook form of the other client. Thus, each client gets
its own form.

To install into a different home directory, use `install --home PATH`.
Then run the clients with that home directory.

Install as your usual user. Do not use `sudo`.
If an agent sandbox prevents access to the settings, install in your own
terminal.
The installer does not change permission modes, the native sandbox policy, or
administrator restrictions.

## Activate and verify

Restart the two clients.
In Codex, open **`/hooks`**. Examine the command, then trust it.
When a hook definition changes, you must trust it again. The hooks must also be
enabled in the client.
The installer does not give trust. It does not install a trust bypass.

In the checkout, compare the build with the installation:

```sh
./bin/agent-secrets status
```

Then verify the installed executable:

```sh
~/.local/share/agent-secrets/agent-secrets verify
```

`status` compares the binary that you run with the installed binary.
It also reads the two registrations.
If you run `status` from the installed binary, it compares that binary with
itself. Thus, to find if the installer copied a new build, run `status` from the
checkout build.

`verify` sends synthetic hook requests and runs test files through the private
reader. It examines the exact output and exit codes. It also makes sure that
the test files are removed.
It does not need an agent login or a model.
These two commands do not show that a running client loaded or trusted the hook.

## Use

After activation, agents can use these usual shell reads:

```sh
cat ~/.codex/config.toml
cat ~/.codex/config.toml | head -n 40
cat ~/.codex/config.toml | tail -n 20
cat ~/.codex/config.toml | sed -n '1,120p'
```

The hook changes supported reads automatically. The tool gets a redacted view.
Line numbers refer to that view, not to the original file.
In Claude Code, the `Read` tool also operates on these files. It reads a private
redacted copy in `~/.cache/agent-secrets/views/`.
The [redaction reference](rule-reference.md#redaction-rules) gives the value
checks and the supported read forms.
The tools after the pipe keep their usual options.

The hook continues to block known raw reads of protected configuration files.
Settings that do not match a rule stay visible.
Supported reads of Docker, Claude, and npm configuration also hide the secrets
that the reader finds. The hook continues to block known reads of credential
stores.

The hook allows metadata checks, for example `ls -l .env`.
For directory searches, for example `rg --hidden --max-count 2 pattern .`, the
hook adds options that skip protected paths.
The hook allows application commands, for example
`uv run --env-file .env app.py`.
Shell filename checks apply only to the
[listed file commands](rule-reference.md#operation-checks).
Pipelines and compound searches keep their usual shell behavior.
The rules give the coverage and the limits.

To change a setting in Claude `settings.json`, Codex `config.toml`, or Docker
`config.json` and not read the file, run the installed executable. An agent or
you can run it:

```sh
~/.local/share/agent-secrets/agent-secrets config set ~/.claude/settings.json env.MCP_TOOL_TIMEOUT '"1800000"'
~/.local/share/agent-secrets/agent-secrets config unset ~/.claude/settings.json env.MCP_TOOL_TIMEOUT
~/.local/share/agent-secrets/agent-secrets config set ~/.codex/config.toml model '"o3"'
```

The value is JSON. Thus, a string must have inner quotes.
The command does not change credential settings.
It makes a backup of the original file in
`~/.local/share/agent-secrets/backups/`. It prints only a fixed message.
The hook denies `Edit`, `Write`, and `apply_patch` on these files, because
the clients record previous file contents in their transcripts. The denial
message gives this command.
An edit of `config.toml` removes its comments. The backup keeps them.
When Claude Code does a `Read` of these files, the hook note also gives it.
The note is necessary because Claude Code rejects an `Edit` of a file that it
read only as a redacted copy.
If the client does not load the file again, restart the client.
Refer to the [edit rules](rule-reference.md#config-edits).

You can read `~/.claude.json` with the same redacted view. The command does not
edit this file, because Claude Code writes it again from memory. Use the
Claude Code commands, for example `claude mcp remove NAME`.

For the CLI, use `agent-secrets help`. For the package and Go versions, use
`agent-secrets version`.
The private reader is an internal hook target. It is not a public command to
export configuration.

Client references: [Codex hooks and trust](https://learn.chatgpt.com/docs/hooks),
[Claude Code hooks](https://code.claude.com/docs/en/hooks).
