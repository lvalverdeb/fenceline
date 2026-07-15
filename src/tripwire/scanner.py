"""File discovery and reading helpers used by the CLI before dispatching to checks."""

from __future__ import annotations

import ast
from pathlib import Path

from tripwire.config import WORKSPACE_ROOT

__all__ = ["_iter_py", "_read", "_ast_parse", "_rel"]


def _iter_py(root: Path) -> list[Path]:
    return sorted(root.rglob("*.py"))


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
