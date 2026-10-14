# Agent Secrets

Agent Secrets helps keep credentials out of local Codex and Claude Code
conversations. Its user-level `PreToolUse` hook blocks recognizable credential
paths and environment dumps, sanitizes supported configuration reads, and
filters protected files out of supported recursive searches.

It is an accidental-disclosure guard. It does not provide filesystem isolation
or change client permissions, sandbox settings, or administrator policies.

- [Rules: redaction, blocked operations, and coverage limits](docs/rules.md)
- [Installation and usage](docs/usage.md)
- [Development and verification](docs/development.md)
