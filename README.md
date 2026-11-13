# fenceline

Zero-day security scanner for Python codebases. Generic, pip-install-anywhere
tool — `pip install fenceline && fenceline` scans whatever's under the
current directory, no project-specific setup required.

## Installation

```bash
uv add fenceline
```

Maps every finding to a CWE from the 2025 CWE Top 25, OWASP Top 10:2025, and known
Python zero-day exploit patterns (pickle bypass CVE-2026-56315, PyYAML shadow
vulnerability CVE-2026-24009, LangChain SSTI CVE-2025-68664, dependency confusion
CVE-2025-61774, and more — see the CWE reference printed at the end of every
text-mode report). 57 checks total: 40 walk the parsed AST; the rest are line-regex
checks for surface-syntax patterns that don't need full parsing. Neither kind
false-positives on a dangerous call quoted in a docstring or comment: the regex
checks scan a copy of each file with comments and string-only statements blanked
out (columns preserved), so only real code is matched.

## Usage

```bash
uv run fenceline
uv run fenceline --json > report.json
uv run fenceline -q
uv run fenceline --fail-on critical
uv run fenceline --exclude tests/ examples/
uv run fenceline --config fenceline.toml
uv run fenceline --package my-lib=my-lib/src/my_lib
uv run fenceline --packages my-lib other-lib
```

Exit codes: `0` (no findings at or above `--fail-on`), `1` (one or more).

### Options

| Flag | Default | Description |
| --- | --- | --- |
| `--json` | off | Machine-readable output |
| `--sarif` | off | SARIF 2.1.0 output for GitHub code scanning and other SARIF consumers (see "CI integration" below) |
| `--quiet` / `-q` | off | Suppress the banner |
| `--config` | none | TOML file with a `packages` table of `name = "path"` entries (see below); replaces cwd auto-discovery |
| `--package` | none | Add or override one package as `NAME=PATH` (repeatable); applied on top of `--config` |
| `--packages` | all resolved packages | Names to scan from the resolved registry |
| `--exclude` | none | Path substrings to exclude from scanning |
| `--fail-on` | `high` | Severity threshold (`critical`\|`high`\|`medium`\|`low`\|`info`) for the exit code |
| `--confidence-min` | `low` | Drop findings below this confidence (`high`\|`medium`\|`low`) |
| `--baseline PATH` | — | Only report/fail on findings not already present in this baseline |
| `--write-baseline PATH` | — | Snapshot current findings to PATH and exit 0 |
| `--include-tests` | off | Include CWE-798/617/918/770/295 findings inside test code (see "Test code" below) |
| `--test-paths DIRNAME [DIRNAME ...]` | — | Extra directory names to treat as non-production, alongside the built-in `tests`/`test`/`conftest.py` conventions (see "Test code" below) |
| `--version` | — | Print the installed fenceline version and exit |

### Test code

By default, findings for CWE-798 (hardcoded credentials), CWE-617 (reachable
assert), CWE-918 (SSRF), CWE-770 (unbounded resource allocation), and CWE-295
(disabled TLS verification) are suppressed when they occur in a
`tests/`/`test/` directory, a `test_*.py`/`*_test.py` file, or `conftest.py`
— an ephemeral `testcontainers` password, a `pytest` assertion, a hardcoded
localhost test URL, a small committed fixture read, or `CERT_NONE` against a
self-signed local test server isn't the same risk as the identical pattern in
a production request handler, and scoring them identically drowns out real
findings in the same category. Pass `--include-tests` to see them
anyway. Production code paths are unaffected either way. This is a
naming-convention heuristic only — a codebase-specific directory like an
`evaluation/` benchmark harness isn't recognized by name alone, since that
name means different things in different codebases. Declare your own such
directories explicitly with `--test-paths`, e.g. `--test-paths evaluation
benchmarks` — they're unioned with the built-in conventions above.

### What gets scanned by default

A bare `fenceline` invocation (no `--config`/`--package`) auto-discovers packages from
the current directory: every immediate subdirectory containing at least one
`.py` file anywhere in its subtree becomes its own named package, skipping
noise directories (`.venv`, `.git`, `__pycache__`, `node_modules`, `build`,
`dist`, `*.egg-info`, and similar caches — also excluded *within* a scanned
subtree, not just at the top level). Loose `.py` files sitting directly in
the current directory (outside any subdirectory) are scanned too, grouped
into a package named after the directory itself.

To point it at other packages — in this workspace, another workspace, or
any directory on disk — use `--config` and/or `--package`:

1. No `--config`/`--package` → cwd auto-discovery, as above.
2. `--config` given → its `packages` table is used as the full set,
   explicitly rather than auto-discovered.
3. `--package NAME=PATH` entries are then overlaid on top of whichever set
   (1) or (2) produced — adding new names or overriding ones already
   defined, so a config file plus a quick ad-hoc addition both work
   together.

Use `--packages NAME [NAME ...]` afterwards to narrow down to a subset of
whichever registry was resolved. Use `--exclude SUBSTR [SUBSTR ...]` to skip
additional path substrings on top of the built-in noise-directory list.

#### `--config`: TOML file

```toml
# fenceline.toml
[packages]
my-lib = "my-lib/src/my_lib"
other = "../other/src/other"
```

```bash
uv run fenceline --config fenceline.toml
```

TOML rather than YAML deliberately: fenceline's own dependency list is
intentionally empty, and the PyYAML shadow vulnerability (CVE-2026-24009,
mentioned above) is itself one of the patterns fenceline scans for — adding
a YAML dependency to a tool that flags YAML-library CVEs would be ironic.
Python's stdlib `tomllib` covers this without adding one. Paths resolve
relative to the config file, and every resolved path passes the same
path-security sandbox check `--package` entries get.

### CI integration

`--sarif` writes the scan as a [SARIF 2.1.0](https://sarifweb.azurewebsites.net/)
log: one rule per CWE (with a `helpUri` into the MITRE CWE database and a
`security-severity` so GitHub labels alerts critical/high/medium/low), one
result per finding, and any file that could not be parsed as a tool
notification. Upload it with GitHub's `upload-sarif` action and findings
appear as code scanning alerts, with GitHub tracking which are new on a pull
request:

```yaml
- run: pipx run fenceline --sarif -q > fenceline.sarif || true
- uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: fenceline.sarif
```

The `|| true` keeps the upload step reachable; `--fail-on` still decides the
exit code if you want the scan step itself to gate.

As a [pre-commit](https://pre-commit.com) hook, fenceline scans the working
tree whenever a Python file is staged:

```yaml
repos:
  - repo: https://github.com/lvalverdeb/fenceline
    rev: v1.6.0
    hooks:
      - id: fenceline
        # args: [--fail-on, critical, --baseline, fenceline-baseline.json]
```

### How it compares

`benchmark/` holds a labelled, reproducible comparison against Bandit and
Semgrep on three intentionally vulnerable apps (pygoat, vulpy, dvpwa), with
every finding of all three tools adjudicated by hand. As of 1.6.0 fenceline
sits between the two: higher recall than the Semgrep community ruleset,
lower recall and precision than Bandit, with the gap concentrated in three
checks (hardcoded secrets in non-constant shapes, hardcoded `/tmp` paths,
weak randomness) and one noisy one (unbounded `read()`). The numbers, the
labelling rules and `run.sh` are in [`benchmark/README.md`](benchmark/README.md).

### Severity vs. confidence

Every finding carries two independent ratings, the same distinction Bandit
makes: **severity** is how bad it would be if the finding is real; **confidence**
is how sure the check is that it *is* real. A line-regex check that can't fully
rule out a docstring or string-literal mention is `MEDIUM`; a handful of
inherently heuristic checks (timing-attack keyword proximity, ReDoS
backtracking-risk judgment, `debug=True` pattern matching) are `LOW`. For most
AST checks, matching a real `Call` node is all there is to know, and the
finding is `HIGH`.

For the injection-shaped checks (command, code, SQL, template and CRLF
injection, SSRF, open redirect, path traversal, arbitrary file write, pandas
`eval`/`query`), knowing the shape of the call is not enough: `subprocess.run(cmd)` is a
finding or not depending on where `cmd` came from. These checks trace the
sink's arguments back through the enclosing function and set confidence from
what they find:

| The sink is fed by | Confidence |
| --- | --- |
| A recognised entry point: a `request` object, `os.environ`, `sys.argv`, `input()`, a socket read, or a parameter of a route-decorated function or handler method | `HIGH` |
| Plain function parameters, `self` attributes, or values the function cannot resolve | `MEDIUM`, with a note on the finding |
| Only literals, module constants, library references, or values that cannot carry a payload (a length, an `int()`, a `shlex.quote()`) | not reported |

The analysis stays inside one function and follows assignments without
regard to order, so it is deliberately pessimistic: a name assigned a
constant and later a request value counts as a request value. It does not
see through `self` fields set elsewhere or through calls into other
functions; those land in the `MEDIUM` row. Use `--confidence-min medium` to
cut noise from the fuzzier regex checks, and `--confidence-min high` to see
only findings where attacker-controlled input provably reaches the sink.

### Severity policy

Severity is fenceline's judgement of how bad a finding is if real; a team may
know better for its own codebase. A `[tool.fenceline.severity]` table in the
nearest `pyproject.toml` (searched upward from the directory fenceline runs
in) caps a check's severity, by check function name:

```toml
[tool.fenceline.severity]
check_crlf = "medium"      # we build HTTP framing by hand; CRLF here is by design
check_ssrf = "low"         # outbound URLs come from our own config, never a request
```

A cap never raises: an INFO finding from a capped check stays INFO. This keeps
`--fail-on high` meaningful without `# nosec`-ing every occurrence or dropping
the check altogether, and the policy is a reviewable file in the repository. A
misspelled check name or level is an error (exit 2), not a silently inert line.

### Files that could not be parsed

A Python file that fails to parse still gets the line-regex checks, but none
of the AST checks. The report says so rather than passing the file off as
clean: the text report prints a `could not be parsed` line, and the JSON
payload carries a `skipped_files` list.

### Dependency CVEs and lockfiles

`check_dependency_cve` compares the version a project will actually install
against a small table of known-vulnerable releases (`vuln_deps.json`, a
curated zero-day watchlist, not an advisory-database mirror; run `pip-audit`
for full CVE coverage). When a lockfile (`uv.lock`, `poetry.lock`,
`Pipfile.lock`) sits next to the manifest, the lockfile's exact versions are
checked and the manifest's ranges are ignored, with the finding reported on
the lockfile line. Without a lockfile, an `==` pin below the fixed version is
HIGH confidence and a lower bound (`>=`, `~=`) below it is MEDIUM. Version
comparison follows PEP 440 (`1.0rc1 < 1.0 < 1.0.post1`, `2024.1.0`).

### Baselining an existing codebase

Adopting fenceline on a codebase with existing findings doesn't mean fixing
all of them before CI can pass:

```bash
uv run fenceline --write-baseline fenceline-baseline.json   # snapshot today's findings
uv run fenceline --baseline fenceline-baseline.json          # only new findings fail CI
```

A finding is matched against the baseline by `(cwe_id, file, code_snippet)`,
not line number, so it keeps matching across unrelated edits that shift line
numbers elsewhere in the file. Re-run `--write-baseline` periodically (or
whenever a baselined finding is deliberately fixed) to keep it current.

### Suppressing a specific finding

`# nosec` (bare) suppresses every finding on that line; `# nosec CWE-502`
suppresses only that CWE, leaving any other finding on the same line intact
— the same convention Bandit uses, with CWE IDs instead of Bandit's own
B-numbers:

```python
pickle.loads(data)  # nosec CWE-502 -- trusted internal cache, not user input
```

### Extending fenceline with your own checks

Built-in checks aren't dynamically discovered — they're a fixed list. Your
own checks are, via a `fenceline.checks` entry point in *your own*
`pyproject.toml`:

```toml
[project.entry-points."fenceline.checks"]
"My Custom Check (CWE-000)" = "my_package.checks:my_check_function"
```

The entry point's own name becomes the check's display name; the object it
points at must be a function with the same `(path, lines, tree) ->
list[Finding]` signature every built-in check has. A plugin that fails to
import is skipped with a warning rather than crashing the whole scan.

## Design

- `fenceline.models` — the `Finding` dataclass, severity ordering, and confidence ordering.
- `fenceline.config` — workspace-root discovery and the default package registry.
- `fenceline.ast_helpers` — shared AST/text-matching helpers used across checks.
- `fenceline.scanner` — file discovery and reading.
- `fenceline.checks` — the built-in check registry, plus `fenceline.checks`
  entry-point discovery for third-party checks.
- `fenceline.checks.ast_checks` — checks that walk the parsed AST (won't match
  a dangerous call mentioned in a docstring or string literal).
- `fenceline.checks.text_checks` — checks that regex-scan source lines (with
  comments and docstrings blanked out by `scanner.mask_non_code`; Trojan Source
  alone scans the raw lines, since bidi overrides hide in exactly those) for
  surface-syntax patterns.
- `fenceline.checks.manifest_checks` — checks over dependency manifests
  (`pyproject.toml`, `requirements.txt`, etc.), not Python source.
- `fenceline.suppression` — `# nosec` inline-suppression parsing.
- `fenceline.baseline` — baseline snapshot/diff for adopting fenceline on an existing codebase.
- `fenceline.reporting` — text/JSON report rendering.
- `fenceline.cli` — argument parsing and the scan loop.
