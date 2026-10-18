# Development and verification

Read [the rules](rules.md) and [rule reference](rule-reference.md) before changing
recognition, redaction, or supported tool coverage.
Keep [usage](usage.md) current when changing installation or CLI behavior.
The [design](design.md) explains module boundaries and the decision model.

## Toolchain and ownership

`mise.toml` and `go.mod` pin Go 1.27.2. Keep them aligned, and verify upgrades
against the [official Go release feed](https://go.dev/dl/?mode=json).
`github.com/BurntSushi/toml` parses and re-encodes config; `mvdan.cc/sh/v3`
parses shell syntax and glob patterns without executing expansions.

| Package | Responsibility |
| --- | --- |
| `cmd/agent-secrets` | CLI dispatch and process exit/output. |
| `internal/guard` | One `Evaluate` entrypoint; request/context normalization, operation checks, and constrained rewrites; metadata only. |
| `internal/policy` | Pure credential/path recognition, selective document/text redaction, native search exclusions, and closed config-read plans. |
| `internal/install` | Installation/readback; shared metadata resolution and the private runner's controlled file reads. |
| `internal/verify` | Subprocess verification of the executable protocol. |

## Checks

After code changes:

```sh
mise run check
mise run build
./bin/agent-secrets verify
```

`check` runs `go vet` and the race-enabled test suite. Tests use synthetic data
and isolated homes; real settings and credentials are not fixtures. Treat
cleanup failures as failures, and report sandbox restrictions separately from
product errors. CI runs the checks, build, executable verification, and the
following fuzz targets on macOS and Linux.

Run the relevant targets after decoding or matching changes:

```sh
mise exec -- go test ./internal/guard -run '^$' -fuzz FuzzCheck -fuzztime 10s
mise exec -- go test ./internal/guard -run '^$' -fuzz FuzzHook -fuzztime 10s
mise exec -- go test ./internal/install -run '^$' -fuzz FuzzPrepare -fuzztime 10s
mise exec -- go test ./internal/policy -run '^$' -fuzz FuzzSanitize -fuzztime 10s
mise exec -- go test ./internal/policy -run '^$' -fuzz FuzzPlan -fuzztime 10s
```

For coverage: `mise exec -- go test -cover ./...`.

## Hook protocol

`agent-secrets hook` consumes one JSON object on stdin, limited to 4 MiB. It
requires a nonempty string `tool_name` and a non-null string/object `tool_input`
(or `arguments` for ordinary guard screening). An absolute request `cwd`
overrides the process working directory; tool `workdir` is resolved from it.

| Outcome | Exit code | Output |
| --- | --- | --- |
| Ordinary allow | `0` | Silent. |
| Supported config read or native ripgrep call | `0` | JSON `hookSpecificOutput` with `hookEventName: "PreToolUse"`, `permissionDecision: "allow"`, and `updatedInput`. |
| Denied, malformed, oversized, or uninspectable request | `2` | No stdout; fixed denial on stderr. |

The denial is exactly:

```text
Blocked by global credential protection: secret files and environment values must not enter agent transcripts.
```

Rewriting requires object-valued `tool_input` and a supported tool/command
field. If `hook_event_name` is supplied, it must be `PreToolUse` for rewriting.
Other arguments and JSON number precision are preserved; sibling arguments
remain screened. The rewritten tool sanitizes or filters before producing stdout.
Native search rewrites preserve command source and options while adding path
exclusions. Nested code requests are screened but are not themselves rewritten. This is input rewriting,
not general `PostToolUse` output filtering.

`agent-secrets guard` retains the silent allow/deny-only protocol and never
rewrites reads. The private runner exits `1` on failure with no file-content stdout
and this fixed stderr message:

```text
Cannot safely run protected operation; no file contents or error details were printed.
```

The private reader reads bounded regular files and launches no subprocess.
Native commands retain their own errors and exit behavior. Hook responses and reader
errors do not echo input, config values, parser diagnostics, or internal errors.

## Verification boundary

Executable verification simulates a client applying `updatedInput` and runs
the result against a temporary synthetic config. It does not establish live
client hook activation, trust, or every tool's integration. After an authorized
reinstall, separately verify the installed binary and registrations, then the
client's activation state as described in [usage](usage.md#activate-and-verify).
