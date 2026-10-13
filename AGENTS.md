# Agent Secrets

## Scope

Build a user-level `PreToolUse` hook for local Codex and Claude Code. Installation
owns the executable and its registrations in the two user hook/settings files.
Keep permission profiles, native sandbox policy, and administrator-managed
restrictions outside the package. Keep one-time cleanup scripts and review
reports out of version control.

Read `README.md` when changing installation, CLI behavior, or supported coverage;
keep its user-facing instructions consistent with the resulting behavior.

## Implementation

- Use the Go version pinned by mise. Keep `mise.toml` and `go.mod` aligned when
  updating it; verify stable releases against the official Go release feed.
- Use the standard library unless a dependency demonstrably simplifies the
  implementation. Format Go changes with `gofmt`.
- Keep screening in `internal/guard`, credential recognition in
  `internal/policy`, configuration and file effects in `internal/install`, and
  subprocess verification in `internal/verify`. The CLI handles dispatch.
- Design small interfaces with substantial behavior behind them. Test through
  those interfaces; introduce adapters only for dependencies that actually vary.
- Preserve unrelated settings and hook handlers, JSON number precision, and
  repeatable installation. Parse before writing, back up settings privately,
  replace files atomically, and verify writes by readback.

## Credential handling

- The guard inspects arguments and metadata only. It must never read credential
  contents or echo requests, configuration values, or internal errors.
- Preserve `guard`'s silent exit `0` for allowed requests and fixed exit `2`
  denial for denied, malformed, or oversized requests. The installed `hook`
  also emits `updatedInput` for allowlisted config reads, without reading
  contents itself. Sanitize locally before the rewritten tool produces output;
  validate reader arguments independently in the hook and private runner.
- Use synthetic data and isolated homes in tests. Real settings and credentials
  are not test fixtures. Respect any active filesystem denials; use a terminal
  handoff for operations that the agent's permissions cannot perform.

## Validation and delivery

- Run `mise run check`, `mise run build`, and `./bin/agent-secrets verify` after
  code changes. For decoding or matching changes, also run the relevant fuzz
  command documented in `README.md`.
- Add regression coverage for changed behavior, including allowed requests
  alongside denials and preservation cases alongside installation changes.
- Report sandbox-caused failures separately from product failures. A test suite
  with cleanup errors has not passed; do not weaken tests to hide them.
- After an authorized reinstall, verify the installed binary and registrations.
  Distinguish configuration readback from live client activation: Codex requires
  user hook trust, and running clients may need restarting.
- Review and stage only in-scope files, run `git diff --cached --check`, and use
  Conventional Commits. Keep build output, scratch work, and credentials out of
  commits; verify remote visibility and commit identity after publication.
