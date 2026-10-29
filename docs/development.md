# Development and verification

Before you change recognition, redaction, or supported tool coverage, read
[the rules](rules.md) and the [rule reference](rule-reference.md).
When you change installation or CLI behavior, update [usage](usage.md).
The [design](design.md) gives the module boundaries and the decision model.

## Toolchain and ownership

`mise.toml` and `go.mod` set Go 1.27.2. Keep the two files aligned. Before an
upgrade, examine the [official Go release feed](https://go.dev/dl/?mode=json).
`github.com/BurntSushi/toml` parses and encodes config again.
`mvdan.cc/sh/v3` parses shell syntax and glob patterns. It does not run
expansions.

| Package | Responsibility |
| --- | --- |
| `cmd/agent-secrets` | CLI dispatch, process exit, and output. |
| `internal/guard` | One `Evaluate` entry point. Request and context normalization, operation checks, and limited rewrites. Metadata only. |
| `internal/policy` | Pure credential and path recognition. Selective redaction of documents and text. JSON edits that keep credentials safe. Native search exclusions. Closed config-read plans. |
| `internal/install` | Installation and readback. Shared metadata resolution. Controlled file reads and views for the private runner. File effects of `config set`. |
| `internal/verify` | Subprocess verification of the executable protocol. |

## Checks

After you change code, run these commands:

```sh
mise run check
mise run build
./bin/agent-secrets verify
```

`check` runs `go vet` and the test suite with the race detector. The tests use
synthetic data and isolated home directories. Do not use real settings or
credentials as fixtures. A cleanup failure is a test failure. Report sandbox
restrictions separately from product errors.
CI runs on macOS and Linux. It runs the checks, the build, the executable
verification, and the fuzz targets that follow.

After you change decoding or matching, run the related targets:

```sh
mise exec -- go test ./internal/guard -run '^$' -fuzz FuzzCheck -fuzztime 10s
mise exec -- go test ./internal/guard -run '^$' -fuzz FuzzHook -fuzztime 10s
mise exec -- go test ./internal/install -run '^$' -fuzz FuzzPrepare -fuzztime 10s
mise exec -- go test ./internal/policy -run '^$' -fuzz FuzzSanitize -fuzztime 10s
mise exec -- go test ./internal/policy -run '^$' -fuzz FuzzPlan -fuzztime 10s
mise exec -- go test ./internal/policy -run '^$' -fuzz '^FuzzEdit$' -fuzztime 10s
mise exec -- go test ./internal/policy -run '^$' -fuzz '^FuzzEditTOML$' -fuzztime 10s
```

To measure coverage, run `mise exec -- go test -cover ./...`.

## Hook protocol

`agent-secrets hook` reads one JSON object on stdin. The maximum size is
4 MiB. The object must have a `tool_name` that is a string and not empty. It
must also have a `tool_input` that is a string or an object and not null. For
usual guard screening, `arguments` can replace `tool_input`. An absolute
request `cwd` replaces the working directory of the process. The hook resolves
the tool `workdir` from it.

| Outcome | Exit code | Output |
| --- | --- | --- |
| Usual allow | `0` | No output. |
| Supported config read (shell `cat` or `Read` `file_path`), or native ripgrep call | `0` | JSON `hookSpecificOutput` with `hookEventName: "PreToolUse"` and `updatedInput`. `hook` adds `permissionDecision: "allow"`, because Codex needs it with `updatedInput`. `hook --client claude` does not add it, because in Claude Code `allow` skips the permission prompt for the full command. For `Read`, the hook first runs the private runner, which stores the view that `updatedInput.file_path` names. The hook also adds a fixed `additionalContext` note. |
| Denied, malformed, oversized, or uninspectable request | `2` | No stdout. A fixed denial on stderr. |

The denial is exactly:

```text
Blocked by global credential protection: secret files and environment values must not enter agent transcripts.
```

If a denied request names a supported configuration file, `hook` adds one fixed
sentence. `guard` does not add it, because `guard` has no config-read bridge.

```text
For a redacted view of this configuration file, use the Read tool on it, or run cat on it in the shell, alone or piped (cat FILE | head -n 40).
```

If the hook denies `Edit`, `MultiEdit`, or `Write` on a configuration that
`config set` can edit, the sentence is different. It names the executable of
the hook:

```text
To change one setting without reading the file, run in the shell: 'BINARY' config set FILE KEY JSON_VALUE (for example env.EXAMPLE '"value"'), or config unset FILE KEY. Credential settings are refused.
```

If the hook denies a recursive grep of a directory that contains home
credential stores, it adds a different sentence. `guard` does not add it,
because `guard` cannot add `rg` exclusions. A configuration sentence has
priority.

```text
Recursive grep cannot skip the protected files in this directory; use rg instead, which skips them.
```

The `additionalContext` note on a `Read` view tells the agent three things:

- The original file is not read for Claude Code, so `Edit` and `Write` on it
  fail.
- Changes to the copy are lost.
- How to change a setting. For a file that `config set` can edit, the note
  gives the same `config set` sentence. For a different file, it gives the
  client commands, for example `claude mcp`.

A rewrite needs a `tool_input` that is an object and a supported tool or
command field. If the request has `hook_event_name`, it must be `PreToolUse`
for a rewrite. The rewrite keeps the other arguments and the precision of JSON
numbers. The hook continues to screen sibling arguments. The rewritten tool
sanitizes or filters before it writes to stdout.
A native search rewrite keeps the command source and options. It adds only path
exclusions. The hook screens nested code requests but does not rewrite them.
This is input rewriting. It is not general output filtering with `PostToolUse`.

`agent-secrets guard` keeps the silent allow-or-deny protocol. It does not
rewrite reads. If the private runner fails, it exits with `1`. It writes no file
contents to stdout. It writes this fixed message to stderr:

```text
Cannot safely run protected operation; no file contents or error details were printed.
```

For a view plan, the runner writes the sanitized view to its fixed private
path. It prints nothing. The hook ignores the output of the runner. If the
runner fails or runs for more than three seconds, the hook denies the read.

`config set` and `config unset` print a fixed success line on stdout. If they
fail, they print one fixed line on stderr and exit with `1`. The line is for
usage, an unsupported file, a credential refusal, or a failure. The commands do
not print file contents, the key, or the value.

The private reader reads regular files with a size limit. It does not start a
subprocess. Native commands keep their own errors and exit behavior. Hook
responses and reader errors do not show input, config values, parser
diagnostics, or internal errors.

## Verification boundary

The executable verification simulates a client that applies `updatedInput`.
It runs the result against a temporary synthetic config. It does not show that
a live client activated or trusted the hook. It does not test the integration
of each tool. After an authorized reinstall, verify the installed binary and
the registrations. Then verify the activation state of the client, as
[usage](usage.md#activate-and-verify) describes.
