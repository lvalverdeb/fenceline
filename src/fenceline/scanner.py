"""File discovery and reading helpers used by the CLI before dispatching to checks."""

from __future__ import annotations

import ast
import io
import tokenize
from collections.abc import Sequence
from pathlib import Path

from fenceline.config import WORKSPACE_ROOT

__all__ = [
    "_iter_py",
    "_read",
    "_ast_parse",
    "mask_non_code",
    "_rel",
    "_is_self_scan_exclusion",
    "_is_test_path",
]

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


def _iter_py(root: Path, *, recursive: bool = True, exclude: Sequence[str] = ()) -> list[Path]:
    """Every ``.py`` file under *root*, sorted for deterministic output.

    ``recursive=False`` globs only *root* itself (non-recursive) — used for
    the cwd auto-discovery "loose root" package, whose files sit directly in
    the invoking directory and whose subdirectories are already registered
    as their own separate packages (scanning both would double-count them).

    ``exclude`` is a list of path-substring patterns (e.g. ``"/.venv/"``) to
    skip, same convention as ``spaghetti``'s own ``ScanConfig.exclude`` —
    lets cwd auto-discovery step around virtualenvs, caches, and vendored
    dependency trees that happen to sit under a scanned directory instead of
    being filtered out at the top level.
    """
    glob_fn = root.rglob if recursive else root.glob
    found = []
    for path in glob_fn("*.py"):
        path_str = str(path)
        if "__pycache__" in path_str:
            continue
        if any(pattern in path_str for pattern in exclude):
            continue
        if _is_self_scan_exclusion(path):
            continue
        found.append(path)
    return sorted(found)


def _read(path: Path) -> list[str]:
    try:
        return path.read_text(encoding="utf-8").splitlines()
    except Exception:
        return []


def _ast_parse(path: Path) -> ast.Module | None:
    try:
        return ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    except (SyntaxError, OSError, UnicodeDecodeError, RecursionError):
        # RecursionError: CPython's AST builder recurses per operand, so a
        # pathologically wide expression (`1+1+...` tens of thousands of
        # terms) overflows before SyntaxError would. Treat it like any other
        # unparseable file -- text checks still run on it.
        return None


def _byte_col_to_char_col(line: str, byte_col: int) -> int:
    """``ast`` reports ``col_offset``/``end_col_offset`` in UTF-8 *bytes*;
    the line-based checks index by character."""
    return len(line.encode("utf-8")[:byte_col].decode("utf-8", errors="ignore"))


def mask_non_code(path: Path, lines: list[str], tree: ast.Module | None) -> list[str]:
    """A copy of *lines* with every comment and every string-only statement
    (docstrings, and bare ``"..."`` statements used as block comments)
    blanked out to spaces, so line numbers and columns are preserved
    exactly. This is what the line-regex checks scan: a regex can't tell
    ``os.system(`` in code from ``os.system(`` quoted in a docstring or
    noted in a trailing comment, and on real code the latter dominated the
    HIGH/CRITICAL false positives.

    Non-``.py`` files (dependency manifests) are returned unchanged -- the
    Python tokenizer has nothing to say about TOML. Comments come from
    :mod:`tokenize` and are taken as far as the tokenizer gets on a file it
    can't fully tokenize; string statements come from *tree* and so are only
    masked when the file parsed. Trojan Source is the one check that
    deliberately keeps scanning the raw lines (see ``checks.lines_for``).
    """
    if path.suffix != ".py":
        return lines
    spans: dict[int, list[tuple[int, int]]] = {}  # 1-based line -> [(start_col, end_col)]

    if tree is not None:
        for node in ast.walk(tree):
            if not (
                isinstance(node, ast.Expr)
                and isinstance(node.value, ast.Constant)
                and isinstance(node.value.value, str)
            ):
                continue
            v = node.value
            end_lineno = v.end_lineno if v.end_lineno is not None else v.lineno
            for ln in range(v.lineno, end_lineno + 1):
                line = lines[ln - 1] if ln - 1 < len(lines) else ""
                start = _byte_col_to_char_col(line, v.col_offset) if ln == v.lineno else 0
                end = (
                    _byte_col_to_char_col(line, v.end_col_offset or 0)
                    if ln == end_lineno
                    else len(line)
                )
                spans.setdefault(ln, []).append((start, end))

    try:
        readline = io.StringIO("\n".join(lines) + "\n").readline
        for tok in tokenize.generate_tokens(readline):
            if tok.type == tokenize.COMMENT:
                spans.setdefault(tok.start[0], []).append((tok.start[1], tok.end[1]))
    except (tokenize.TokenError, SyntaxError, ValueError):
        pass  # keep whatever was collected before the tokenizer gave up

    if not spans:
        return lines
    masked = list(lines)
    for ln, ranges in spans.items():
        if ln - 1 >= len(masked):
            continue
        chars = list(masked[ln - 1])
        for start, end in ranges:
            for i in range(start, min(end, len(chars))):
                chars[i] = " "
        masked[ln - 1] = "".join(chars)
    return masked


def _rel(path: Path) -> str:
    if WORKSPACE_ROOT is None:
        return str(path)
    try:
        return str(path.relative_to(WORKSPACE_ROOT))
    except ValueError:
        return str(path)


_TEST_DIR_NAMES = frozenset({"tests", "test"})


def _is_test_path(file_path: str, extra_dir_names: frozenset[str] = frozenset()) -> bool:
    """True if *file_path* looks like test code by common pytest
    convention: a ``tests``/``test`` directory component, a
    ``test_*.py``/``*_test.py`` filename, or ``conftest.py``.

    Deliberately narrow to these well-established naming conventions by
    default — doesn't attempt to recognize codebase-specific "not quite
    production" directories (e.g. an app's own ``evaluation/`` benchmark
    harness), since a name like that means different things in different
    codebases and guessing wrong risks silently suppressing real production
    findings under a misleadingly broad match. A project that has its own
    such directories can name them explicitly via *extra_dir_names* (see
    ``cli.py``'s ``--test-paths`` flag) rather than fenceline guessing.
    """
    parts = file_path.replace("\\", "/").split("/")
    name = parts[-1]
    if name == "conftest.py":
        return True
    if name.endswith(".py") and (name.startswith("test_") or name.endswith("_test.py")):
        return True
    return any(part in _TEST_DIR_NAMES or part in extra_dir_names for part in parts[:-1])
