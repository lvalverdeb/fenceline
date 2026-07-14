# tripwire

Zero-day security scanner for the Boti workspace.

Maps every finding to a CWE from the 2025 CWE Top 25, OWASP Top 10:2025, and known
Python zero-day exploit patterns (pickle bypass CVE-2026-56315, PyYAML shadow
vulnerability CVE-2026-24009, LangChain SSTI CVE-2025-68664, dependency confusion
CVE-2025-61774, and more — see the CWE reference printed at the end of every
text-mode report). 52 checks total: most are AST-based (won't false-positive on a
dangerous call mentioned in a docstring or comment); the rest are line-regex checks
for surface-syntax patterns that don't need full parsing.

## Usage

```bash
uv run tripwire
uv run tripwire --json > report.json
uv run tripwire -q
uv run tripwire --fail-on critical
uv run tripwire --package my-lib=my-lib/src/my_lib
```

Exit codes: `0` (no findings at or above `--fail-on`), `1` (one or more).

### Options

| Flag | Default | Description |
| --- | --- | --- |
| `--json` | off | Machine-readable output |
| `--quiet` / `-q` | off | Suppress the banner |
| `--fail-on` | `high` | Severity threshold (`critical`\|`high`\|`medium`\|`low`\|`info`) for the exit code |
| `--package NAME=PATH` | — | Add or override a scan target package (repeatable) |

By default, tripwire scans `boti`, `boti-data`, `boti-dask`, and itself.

## Design

- `tripwire.models` — the `Finding` dataclass and severity ordering.
- `tripwire.config` — workspace-root discovery and the default package registry.
- `tripwire.ast_helpers` — shared AST/text-matching helpers used across checks.
- `tripwire.scanner` — file discovery and reading.
- `tripwire.checks.ast_checks` — checks that walk the parsed AST (won't match
  a dangerous call mentioned in a docstring or string literal).
- `tripwire.checks.text_checks` — checks that scan raw source lines for
  surface-syntax patterns.
- `tripwire.checks.manifest_checks` — checks over dependency manifests
  (`pyproject.toml`, `requirements.txt`, etc.), not Python source.
- `tripwire.reporting` — text/JSON report rendering.
- `tripwire.cli` — argument parsing and the scan loop.
