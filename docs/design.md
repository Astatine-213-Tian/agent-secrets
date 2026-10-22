# Design

The policy prevents the disclosure of credential values. It allows usual
metadata inspection and development. Configuration redaction keeps values by
default. It removes only the credentials that a rule identifies.

## Modules and interfaces

| Module | Interface | Responsibility |
| --- | --- | --- |
| Request screening (`guard`) | Change a hook request into an allow, deny, or rewrite decision. | Normalize the execution context. Identify disclosure operations. Apply access rules with arguments and metadata only. |
| Credential policy (`policy`) | Classify names and paths. Sanitize a parsed document or string. | Own the credential conventions and the default-visible redaction. Do not read files or run commands. |
| Private runner (in `install`) | Return or store a validated, sanitized config view. | Validate plans again. Resolve and open supported files. Sanitize configurations before output. |
| Installation (`install`) | Prepare, install, and inspect. Edit one config setting. | Keep unrelated settings. Make private backups. Replace files atomically and read them back. |
| Verification (`verify`) | Operate the executable. | Send synthetic requests in isolated home directories through the real process interface. |

The CLI dispatches commands and encodes fixed responses for the user.
A separate module does not need a separate package. The private runner and the
installation own the file effects together. But the runner has its own entry
point and its own files.

## Native command ownership

The hook does not validate general native options. It does not keep lists of
safe variable names and templates. Unknown options and harmless shell
composition are not causes for denial. Small recognizers identify specific
disclosure operations. They also tell literal patterns from paths.

Shell filename checks apply only to the fixed set of common file commands in
`guard/operations.go`. Other applications can get protected filenames as
arguments. They do not need an exemption for each application. Nested
execution, expansions, redirections, explicit file APIs, and known dumps have
separate checks.

The design has two intentional rewrite exceptions:

- A basic config-read bridge. It covers shell `cat` reads and Claude Code
  `Read` calls. `guard/read.go` owns the two forms.
- Native search exclusions for ripgrep and recursive grep.
  `guard/search.go` owns this exception.

The bridge does not emulate reader options. The hook does not run searches
privately. `guard/operations.go` and `guard/find.go` own the disclosure checks.
The two rewrites share code in `guard/rewrite.go` for these tasks: tool-input
extraction, working-directory resolution, parsed shell source, and source
edits. The config bridge uses the statement nodes that are already parsed. It
does not parse each statement again.

## Request decisions

Normalize the request `cwd`, the supported tool `workdir`, and the configured
credential locations one time. A supported literal shell directory change
updates the context of the subsequent operations. Resolve lexical paths and
symlink targets from that context. A metadata failure does not show that a
content read is safe.

Parse the shell syntax before you apply the rules. Keep the role of each word:
literal, option value, path, pattern, redirect, or nested execution. Examine
each operation separately. A safe sibling or operand cannot make a different
one exempt.

The decision path has three steps, and the two rewrite paths share this order:

1. Replace the validated config reads.
2. Screen the resulting input and every sibling.
3. Add the native search exclusions.

The named checks are as follows:

- Metadata and literal output: Allow known forms. Examine their expansions.
- Content access and transfer: Deny known protected reads, exports, copies,
  and moves.
- Environment exposure: Tell usual variables from credentials and dumps.
- Inspection commands: Deny known dumps and selections that contain
  credentials.
- Content searches: Screen explicit operands. Add native ripgrep path
  exclusions.
- Config reads: Replace a basic `cat` read with a limited sanitized-read plan.

A denial has priority over an allow or a rewrite. The guard does not support
computed execution, and the docs record this limit. The guard does not try to
interpret all programs. The design does not need a general rule plugin system
or an interface for each predicate. Each rule family has named functions and
behavior tests.

## Redaction

Parse the document before you sanitize it. Go through the full document,
including profiles, nested tables, and arrays. Keep the values and structure
that do not match a rule. Each identification comes from one of these rule
families:

- Credential names and their meaningful suffixes, with normalized spelling
- Documented reference fields, which keep environment-variable names
- Authentication and session HTTP headers
- URL user information, sensitive query parameters, and known credential paths
- Credential flags, credential assignments, and known secret material in text

The rules that hide values apply to all configs. Thus, a match in an
unrelated file only hides more. A rule that keeps an otherwise hidden value
visible applies only to the config that it describes. `policy.Config` names
the config. The runner and `policy.Edit` get it from the trusted path, not from
the plan.

Generic names, such as `auth` and `key`, need context. Inline environment
entries, headers, and command arguments share the name recognition. The
sanitizer does not scan usual source files for variable names. It does not
resolve environment values. It does not run configured commands or helpers.

## Private execution

Config rewrites contain closed read plans. An encoded plan is untrusted input.
The runner validates its kind, paths, and resource classification again.
The plan cannot give an executable, command options, or an output destination.
The runner returns the sanitized bytes directly. It does not start a
subprocess. Native downstream tools process that view through usual shell
pipelines.

A file tool has no pipeline for a replacement. Thus, the hook changes a `Read`
of a supported config to a stored view. `Evaluate` stays pure and returns the
view plan. The hook starts the private runner as a separate process. Thus, the
hook itself does not read contents. The runner gets the location of the view
from its own home directory and the source path. If the runner cannot store the
view, the hook denies the read.

After a `Read` of a view, Claude Code thinks that the original file is not
read. Thus, Claude Code rejects an `Edit` before a hook can run. For this
reason, the rewrite itself tells the agent about `config set`.

Config edits are the write side of config views. `policy.Edit` is pure. It
changes one object member. It refuses credential keys. It also refuses to
replace a value that the sanitized view hides. An edit cannot address an array
element, because argument classification uses adjacent elements. `install`
owns the file effects. It follows the installation rules for backups,
conflicts, atomic replacement, and readback. The edit prints only fixed
messages.

The runner reads only regular config files. Examine the paths and the identity
of the opened file at execution time. Keep the results in a buffer. Thus, fixed
errors cannot show raw configuration or parser diagnostics.

Searches keep their native implementation. The hook adds protected-path
exclusions to parsed ripgrep calls. It keeps the original shell source.
Ripgrep validates its own options. It owns traversal, output, and exit
behavior. The hook has no private search engine and no option allowlist.
This decision gives native compatibility. The cost is less coverage of unusual
aliases, helpers, and computed execution. The hook continues to deny explicit
credential operands before a rewrite.

## Validation

Operate the same interfaces as the callers. For each allowed case, add a
related denied case. Cover these pairs and items:

- Metadata and content
- Literal text and executed text
- Public keys and private keys
- Usual variables and credential variables
- Mixed search operands
- Working directories, symlinks, and alternative stores
- Forged runner plans

Use real temporary file-system fixtures and synthetic values. Examine the exact
output. Make sure that usual settings stay, that no credential markers appear,
and that cleanup is complete. Fuzz the hook decoding and analysis, and the
document sanitation. The installation tests continue to examine preservation,
idempotence, conflicts, and readback.
