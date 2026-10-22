# Agent Secrets

Agent Secrets helps keep credentials out of local Codex and Claude Code
conversations. It installs a user-level `PreToolUse` hook. The hook does these
tasks:

- It blocks known credential paths and environment dumps.
- It shows supported configuration files with the secret values hidden.
- It removes protected files from supported recursive searches.

The hook prevents accidental disclosure only. It does not isolate the file
system. It does not change client permissions, sandbox settings, or
administrator policies.

- [Rules: redaction, blocked operations, and coverage limits](docs/rules.md)
- [Installation and usage](docs/usage.md)
- [Development and verification](docs/development.md)
