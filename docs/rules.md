# Protection rules

Agent Secrets helps keep secret values out of agent conversations.
It checks common file commands for protected paths.
It also hides detected secret values when it shows supported configuration files.

**An application can use a secret file. Its filename alone does not cause a block.**

## Command checks

| Example | Result | Reason |
| --- | --- | --- |
| `uv run --env-file .env app.py` | Allow | Application arguments do not trigger filename checks. |
| `my-app --config .env` | Allow | The same rule applies to other applications. |
| `ls -l .env` | Allow | It shows file details, not file contents. |
| `echo '.env'` | Allow | It prints the filename as text. |
| `cat .env` | Block | It prints protected file contents. |
| `grep TOKEN .env` | Block | It searches protected file contents. |
| `cp .env public.txt` | Block | It copies protected file contents. |
| `printenv` | Block | It can print secret environment values. |
| `echo "FOO=1" >> .env` | Allow | Writing a file does not reveal its contents. |

Filename checks apply to a [fixed list of common file commands](rule-reference.md#operation-checks).
Other commands can still trigger separate checks for secret access.

The hook checks commands inside `$()` and `sh -c`.
It also checks shell redirections, printed secret variables, and later commands.
Using a secret variable, as in `curl -H "Authorization: Bearer $GITHUB_TOKEN"`, is allowed.
For example, `uv run --env-file .env app.py; cat .env` is blocked.

Direct file tools, such as `Read`, cannot read protected files. Claude Code's
`Read` of a supported configuration file receives the redacted view instead.
The hook also checks patch targets and known file access calls in scripts.

## Protected files

Protected paths include `.env`, `.env.*`, private keys, credential stores,
selected configuration files, browser session files, and Agent Secrets backups.
See the [full path list](rule-reference.md#protected-resources).

The public file exceptions are `.env.example`, `.env.schema.json`, and SSH `id_*.pub` keys.
An exception still receives protection if another path rule matches.
A symbolic link to a protected file also receives protection.

## Content searches

The hook checks the file arguments of `rg`, `grep`, `egrep`, and `fgrep`.
For shell `rg` and recursive `grep` searches, it also adds rules to skip protected paths.

| Example | Result |
| --- | --- |
| `rg --hidden TOKEN .` | Search the directory and skip protected paths. |
| `rg TOKEN .env` | Block the direct file search. |
| `rg -e '.env' README.md` | Allow the filename as a search pattern. |
| `rg --files` | Allow the file list. |

Recursive `grep` cannot skip home credential stores by path, so `grep -r TOKEN ~` is blocked; use `rg`.
The search tool still controls its options, output, and exit code.

## Redaction rules

The hook can replace a basic `cat FILE` command with a private reader.
The reader replaces detected secret values with `[REDACTED]`.
Other values remain visible.

This works for supported Codex, Claude, Docker, and npm configuration files.
It does not provide a readable view of `.env` or login token stores.
When another command is denied on a supported configuration,
the denial message points to this `cat` view.
Use a pipe to select part of the result:

```sh
cat ~/.codex/config.toml | head -n 40
```

In Claude Code, `Read` of the same files is pointed at a private redacted copy
under `~/.cache/agent-secrets/views/`, so `offset` and `limit` work as usual.
The reader does not change the source file.

## Changing settings

`Edit` and `Write` stay blocked on these files, because they show previous
contents. To change one setting without reading the file, run:

```sh
agent-secrets config set ~/.claude/settings.json env.MCP_TOOL_TIMEOUT '"1800000"'
agent-secrets config unset ~/.claude/settings.json env.MCP_TOOL_TIMEOUT
```

This works for Claude `settings.json` and Docker `config.json`.
It refuses to write, replace, or remove a credential, prints no values, and
backs up the original. The denial for a blocked edit names this command, as
does the note attached to a Claude Code `Read` of the file.
See the [edit rules](rule-reference.md#config-edits).
See the [supported read forms](rule-reference.md#supported-config-reads)
and [exact value checks](rule-reference.md#credential-keys-and-paths).

## Limits

The hook checks tool arguments and file details. It does not read file contents.
Only the private reader reads and hides values in supported configuration files.

These checks cannot identify every secret read.
Custom commands and hidden script behavior can escape the checks.
The hook does not filter all application output or network responses.
Client permissions and sandbox restrictions remain separate controls.

See the [full limits](rule-reference.md#coverage-limits)
and [installation instructions](usage.md).
