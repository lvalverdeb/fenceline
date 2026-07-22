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
text-mode report). 57 checks total: most are AST-based (won't false-positive on a
dangerous call mentioned in a docstring or comment); the rest are line-regex checks
for surface-syntax patterns that don't need full parsing.

## Usage

```bash
uv run fenceline
uv run fenceline --json > report.json
uv run fenceline -q
uv run fenceline --fail-on critical
uv run fenceline --package my-lib=my-lib/src/my_lib
uv run fenceline --packages my-lib other-lib
```

Exit codes: `0` (no findings at or above `--fail-on`), `1` (one or more).

### Options

| Flag | Default | Description |
| --- | --- | --- |
| `--json` | off | Machine-readable output |
| `--quiet` / `-q` | off | Suppress the banner |
| `--fail-on` | `high` | Severity threshold (`critical`\|`high`\|`medium`\|`low`\|`info`) for the exit code |
| `--confidence-min` | `low` | Drop findings below this confidence (`high`\|`medium`\|`low`) |
| `--package NAME=PATH` | — | Add a scan target package (repeatable); replaces cwd auto-discovery entirely when given |
| `--packages NAME [NAME ...]` | all | Scan only these names from the resolved registry |
| `--baseline PATH` | — | Only report/fail on findings not already present in this baseline |
| `--write-baseline PATH` | — | Snapshot current findings to PATH and exit 0 |
| `--include-tests` | off | Include CWE-798/617/918/770 findings inside test code (see "Test code" below) |

### Test code

By default, findings for CWE-798 (hardcoded credentials), CWE-617 (reachable
assert), CWE-918 (SSRF), and CWE-770 (unbounded resource allocation) are
suppressed when they occur in a `tests/`/`test/` directory, a
`test_*.py`/`*_test.py` file, or `conftest.py` — an ephemeral
`testcontainers` password, a `pytest` assertion, a hardcoded localhost test
URL, or a small committed fixture read isn't the same risk as the identical
pattern in a production request handler, and scoring them identically drowns
out real findings in the same category. Pass `--include-tests` to see them
anyway. Production code paths are unaffected either way. This is a
naming-convention heuristic only — a codebase-specific directory like an
`evaluation/` benchmark harness isn't recognized, since that name means
different things in different codebases.

### What gets scanned by default

A bare `fenceline` invocation (no `--package`) auto-discovers packages from
the current directory: every immediate subdirectory containing at least one
`.py` file anywhere in its subtree becomes its own named package, skipping
noise directories (`.venv`, `.git`, `__pycache__`, `node_modules`, `build`,
`dist`, `*.egg-info`, and similar caches — also excluded *within* a scanned
subtree, not just at the top level). Loose `.py` files sitting directly in
the current directory (outside any subdirectory) are scanned too, grouped
into a package named after the directory itself.

Pass `--package NAME=PATH` (repeatable) to scan an explicit set of
directories instead — this replaces auto-discovery entirely rather than
adding to it. Use `--packages NAME [NAME ...]` afterwards to narrow down to
a subset of whichever registry was resolved.

### Severity vs. confidence

Every finding carries two independent ratings, the same distinction Bandit
makes: **severity** is how bad it would be if the finding is real; **confidence**
is how sure the check is that it *is* real. An AST-based check that matched a
real `Call` node is `HIGH` confidence; a line-regex check that can't fully
rule out a docstring or string-literal mention is `MEDIUM`; a handful of
inherently heuristic checks (timing-attack keyword proximity, ReDoS
backtracking-risk judgment, `debug=True` pattern matching) are `LOW`. Use
`--confidence-min medium` to cut noise from the fuzzier checks without
raising your severity bar.

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
- `fenceline.checks.text_checks` — checks that scan raw source lines for
  surface-syntax patterns.
- `fenceline.checks.manifest_checks` — checks over dependency manifests
  (`pyproject.toml`, `requirements.txt`, etc.), not Python source.
- `fenceline.suppression` — `# nosec` inline-suppression parsing.
- `fenceline.baseline` — baseline snapshot/diff for adopting fenceline on an existing codebase.
- `fenceline.reporting` — text/JSON report rendering.
- `fenceline.cli` — argument parsing and the scan loop.
