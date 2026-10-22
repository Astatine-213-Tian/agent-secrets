# Protection rules

Agent Secrets helps keep secret values out of agent conversations.
It examines common file commands for protected paths.
It also hides the secret values that it finds when it shows a supported
configuration file.

**An application can use a secret file. The filename alone does not cause a block.**

## Command checks

| Example | Result | Reason |
| --- | --- | --- |
| `uv run --env-file .env app.py` | Allow | The hook does not examine filenames in application arguments. |
| `my-app --config .env` | Allow | The same rule applies to all applications. |
| `ls -l .env` | Allow | The command shows file data, not file contents. |
| `echo '.env'` | Allow | The command prints the filename as text. |
| `cat .env` | Block | The command prints protected file contents. |
| `grep TOKEN .env` | Block | The command searches protected file contents. |
| `cp .env public.txt` | Block | The command copies protected file contents. |
| `printenv` | Block | The command can print secret environment values. |
| `echo "FOO=1" >> .env` | Allow | A write to a file does not show its contents. |

Filename checks apply only to a [fixed list of common file commands](rule-reference.md#operation-checks).
Other commands can cause different checks for secret access.

The hook examines commands in `$()` and `sh -c`.
It also examines shell redirections, printed secret variables, and later commands.
For example, the hook blocks `uv run --env-file .env app.py; cat .env`.
A command can use a secret variable. For example, the hook allows
`curl -H "Authorization: Bearer $GITHUB_TOKEN"`.

File tools, such as `Read`, cannot read protected files.
In Claude Code, a `Read` of a supported configuration file gets the redacted view.
The hook also examines patch targets and known file access calls in scripts.

## Protected files

Protected paths include these items:

- `.env` and `.env.*` files
- Private keys and credential stores
- Some configuration files
- Browser session files
- Agent Secrets backups

Refer to the [full path list](rule-reference.md#protected-resources).

These public files are not protected: `.env.example`, `.env.schema.json`, and
SSH `id_*.pub` keys. If a different path rule matches one of these files, the
file is protected. A symbolic link to a protected file is also protected.

## Content searches

The hook examines the file arguments of `rg`, `grep`, `egrep`, and `fgrep`.
For shell `rg` searches and recursive `grep` searches, the hook adds options
that skip protected paths.

| Example | Result |
| --- | --- |
| `rg --hidden TOKEN .` | The hook allows the search and skips protected paths. |
| `rg TOKEN .env` | The hook blocks the direct file search. |
| `rg -e '.env' README.md` | The hook allows the filename as a search pattern. |
| `rg --files` | The hook allows the file list. |

Recursive `grep` cannot skip home credential stores by path.
Thus, the hook blocks `grep -r TOKEN ~` and `grep -r TOKEN ~/.claude`.
The denial message tells you to use `rg` instead.
The search tool controls its options, output, and exit code.

## Redaction rules

The hook can replace a basic `cat FILE` command with a private reader.
The reader replaces each secret value that it finds with `[REDACTED]`.
All other values stay visible.

The reader supports these configuration files: Codex, Claude (`~/.claude.json`
also), Docker, and npm.
The reader does not show `.env` files or login token stores.
If the hook denies a different command on a supported configuration file, the
denial message tells you to use the `cat` view.
To select part of the result, use a pipe:

```sh
cat ~/.codex/config.toml | head -n 40
```

In Claude Code, a `Read` of the same files reads a private redacted copy in
`~/.cache/agent-secrets/views/`. Thus, `offset` and `limit` operate as usual.
The reader does not change the source file.

## Changing settings

The hook blocks `Edit` and `Write` on these files, because these tools show
previous contents. To change one setting and not read the file, run:

```sh
agent-secrets config set ~/.claude/settings.json env.MCP_TOOL_TIMEOUT '"1800000"'
agent-secrets config unset ~/.claude/settings.json env.MCP_TOOL_TIMEOUT
```

These commands change Claude `settings.json` and Docker `config.json` only.
To change `~/.claude.json`, use the Claude Code commands, for example
`claude mcp remove`.

The command does not write, replace, or remove a credential. It prints no values.
It makes a backup of the original file.
The denial message for a blocked edit gives this command.
The note that the hook adds to a Claude Code `Read` of the file also gives it.

Refer to these sections:

- [Edit rules](rule-reference.md#config-edits)
- [Supported read forms](rule-reference.md#supported-config-reads)
- [Exact value checks](rule-reference.md#credential-keys-and-paths)

## Limits

The hook examines tool arguments and file data. It does not read file contents.
Only the private reader reads supported configuration files and hides their
secret values.

These checks cannot find every secret read.
Custom commands and hidden script behavior can go around the checks.
The hook does not filter all application output or network responses.
Client permissions and sandbox restrictions are separate controls.

Refer to the [full limits](rule-reference.md#coverage-limits)
and the [installation instructions](usage.md).
