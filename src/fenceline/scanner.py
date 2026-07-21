"""File discovery and reading helpers used by the CLI before dispatching to checks."""

from __future__ import annotations

import ast
from pathlib import Path

from fenceline.config import WORKSPACE_ROOT

__all__ = ["_iter_py", "_read", "_ast_parse", "_rel", "_is_self_scan_exclusion"]

# fenceline's own check-definition, shared-detection-helper, and
# reporting files necessarily contain, as string literals, the exact regex
# patterns / function names / CVE tables their own checks search for
# elsewhere (e.g. `checks/text_checks.py` defines `r"pickle\.loads?\s*\("`
# to *detect* pickle.loads() calls — that pattern's own source line contains
# the substring "pickle.loads(" and will match itself). Scanning these files
# produces guaranteed self-referential false positives — the tool flagging
# its own detection rules as if they were the vulnerabilities they detect —
# not real findings in application code. `cli.py`/`scanner.py`/`config.py`/
# `models.py` are deliberately left scannable: they're plumbing (arg
# parsing, file I/O, data models), not pattern tables, so real bugs there
# are still worth catching by self-scan.
#
# Matched by path suffix (not "is this literally the fenceline package"), so
# this only ever excludes fenceline's own files, wherever a package root
# happens to point — the default registry or an explicit --package
# override both resolve to the same real files on disk.
_SELF_SCAN_EXCLUDE = (
    Path("fenceline/checks/__init__.py"),
    Path("fenceline/checks/text_checks.py"),
    Path("fenceline/checks/ast_checks.py"),
    Path("fenceline/checks/manifest_checks.py"),
    Path("fenceline/ast_helpers.py"),
    Path("fenceline/reporting.py"),
)


def _is_self_scan_exclusion(path: Path) -> bool:
    return any(path.parts[-len(pattern.parts) :] == pattern.parts for pattern in _SELF_SCAN_EXCLUDE)


def _iter_py(root: Path) -> list[Path]:
    return sorted(p for p in root.rglob("*.py") if not _is_self_scan_exclusion(p))


def _read(path: Path) -> list[str]:
    try:
        return path.read_text(encoding="utf-8").splitlines()
    except Exception:
        return []


def _ast_parse(path: Path) -> ast.Module | None:
    try:
        return ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    except SyntaxError:
        return None


def _rel(path: Path) -> str:
    if WORKSPACE_ROOT is None:
        return str(path)
    try:
        return str(path.relative_to(WORKSPACE_ROOT))
    except ValueError:
        return str(path)
