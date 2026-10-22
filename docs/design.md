# Design

The policy protects credential values from disclosure while permitting ordinary
metadata inspection and development. Configuration redaction preserves values
by default and removes only explicitly recognized credentials.

## Modules and interfaces

| Module | Interface | Responsibility |
| --- | --- | --- |
| Request screening (`guard`) | Evaluate a hook request into allow, deny, or rewrite. | Normalize execution context, recognize disclosure operations, and apply access rules using arguments and metadata only. |
| Credential policy (`policy`) | Classify names/paths and sanitize a parsed document or string. | Own credential conventions and default-visible redaction. No filesystem reads or command execution. |
| Private runner (within `install`) | Return or store a validated, sanitized config view. | Revalidate plans, resolve and open supported files, and sanitize configurations before output. |
| Installation (`install`) | Prepare, install, inspect, edit one config setting. | Preserve unrelated settings, back up privately, replace atomically, and read back. |
| Verification (`verify`) | Exercise the executable. | Synthetic requests and isolated homes through the actual process interface. |

The CLI dispatches and encodes fixed user-facing responses. A separate module
does not require a separate package: the private runner shares file-effect
ownership with installation but has its own entrypoint and files.

## Native command ownership

The hook does not validate general native options or maintain lists of safe
variable names and templates. Unknown options and harmless shell composition
are not reasons for denial. Small recognizers identify specific disclosure
operations and distinguish literal patterns from paths.

Shell filename checks apply only to the finite common file-command set in
`guard/operations.go`. Other applications may receive protected filenames as
arguments without an exemption per application. Nested execution, expansions,
redirections, explicit file APIs, and recognized dumps have independent checks.

The two deliberate rewriting exceptions are a basic config-read bridge and
native search exclusions for ripgrep and recursive grep. The bridge covers shell
`cat` reads and Claude Code `Read` calls; `guard/read.go` owns both forms. Reader-option
emulation and private search execution are absent. `guard/read.go` owns the config bridge; `guard/search.go` owns the
search exception; `guard/operations.go` and `guard/find.go` own disclosure checks.
Both rewrites share tool-input extraction, working-directory resolution, parsed
shell source, and source editing through `guard/rewrite.go`. The config bridge
uses the existing statement nodes; it does not parse each statement again.

## Request decisions

Normalize request `cwd`, supported tool `workdir`, and configured credential
locations once. Supported literal shell directory changes update the context
of subsequent operations. Resolve lexical paths and symlink targets from that
same context. Metadata failures do not imply that a content read is safe.

Parse shell syntax before applying rules. Retain each word's role: literal,
option value, path, pattern, redirect, or nested execution. Each operation is
checked independently; a safe sibling or operand cannot exempt another.
The decision path first substitutes validated config reads, then screens the
resulting input and every sibling, and finally adds native search exclusions.
This ordering is shared by both rewrite paths.

Named checks cover:

- Metadata and literal output: allow known forms while checking expansions.
- Content access and transfer: deny recognized protected reads, exports, copies, and moves.
- Environment exposure: distinguish ordinary variables from credentials and dumps.
- Inspection commands: deny recognized credential-bearing dumps and selections.
- Content searches: screen explicit operands and add native ripgrep path exclusions.
- Config reads: replace a basic cat read with a constrained sanitized-read plan.

Denial wins over allowance or rewriting. Unsupported computed execution remains
a documented limitation; the guard does not attempt to interpret arbitrary
programs. No general-purpose rule plugin system or interface per predicate is
needed. Each rule family has named implementation functions and behavior tests.

## Redaction

Parse before sanitizing. Walk the complete document, including profiles, nested
tables, and arrays. Preserve unmatched values and structure. Recognition belongs
to one of these rule families:

- Credential names and meaningful suffixes, with normalized spelling.
- Documented reference fields, which retain environment-variable names.
- Authentication/session HTTP headers.
- URL user information, sensitive query parameters, and known credential paths.
- Credential flags/assignments and recognizable secret material in text.

Generic names such as `auth` and `key` require context. Name recognition is
shared by inline environment entries, headers, and command arguments; ordinary
source files are not scanned for variable names. Sanitization never resolves
environment values or invokes configured commands/helpers.

## Private execution

Config rewrites contain closed read plans. An encoded plan is untrusted input;
the runner validates its kind, paths, and resource classification again.
It accepts no executable, command options, or output destination. It returns
sanitized bytes directly and never starts a subprocess. Native downstream tools
process that view through ordinary shell pipelines.

A file tool has no pipeline to substitute, so a `Read` of a supported config is
rewritten to a stored view. `Evaluate` stays pure and returns the view plan; the
hook starts the private runner as a separate process, so the hook itself still
reads no contents. The runner derives the view's location from its own home and
the source path. Failure to store the view denies the read. Claude Code then
treats the original as unread and rejects an `Edit` before any hook runs, so the
rewrite itself tells the agent about `config set`.

Config edits are the write-side counterpart. `policy.Edit` is pure: it changes
one object member and refuses credential keys and any replaced value that the
sanitized view would hide. Array elements cannot be addressed, because argument
classification spans neighbouring elements. `install` owns the file effects,
following the installation rules for backup, conflicts, atomic replacement, and
readback. The edit prints only fixed messages.

Only regular config files may be read. Check paths and opened-file identity at
execution time. Buffer results so fixed errors cannot expose raw configuration
or parser diagnostics.

Searches keep their native implementation. The hook inserts protected-path
exclusions into parsed ripgrep calls and preserves the original shell source.
Ripgrep validates its own options and owns traversal, output and exit behavior.
There is no private search engine or option allowlist. This deliberately trades
coverage of unusual aliases/helpers/computed execution for native compatibility;
explicit credential operands are still denied before rewriting.

## Validation

Exercise the same interfaces as callers. Pair every allowed case with a nearby
denied case. Cover metadata versus content, literal versus executed text, public
versus private keys, ordinary versus credential variables, mixed search operands,
working directories, symlinks, alternate stores, and forged runner plans.

Use real temporary filesystem fixtures and synthetic values. Check exact output,
preservation of ordinary settings, absence of credential markers, and cleanup.
Fuzz hook decoding/analysis and document sanitation. Installation retains its
preservation, idempotence, conflict, and readback checks.
