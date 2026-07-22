"""Package-wide configuration: workspace root discovery, the path-security
sandbox check, and dependency-manifest filenames.
"""

from __future__ import annotations

import tomllib
from pathlib import Path

__all__ = [
    "WORKSPACE_ROOT",
    "DEP_MANIFEST_FILES",
    "is_secure_path",
]


def is_secure_path(target: Path, allowed_dirs: list[Path]) -> bool:
    """Verifies *target* resolves inside one of *allowed_dirs* — a defensive
    sandbox check for a *security* tool's own file access, since fenceline
    reads and reports the contents of whatever it's pointed at.

    Inlined rather than imported from ``boti.core`` so fenceline has no
    runtime dependency on an unrelated internal package — a generic,
    pip-install-anywhere security scanner shouldn't drag in this workspace's
    own tooling as a hard dependency.
    """
    try:
        resolved = target.resolve()
        return any(resolved.is_relative_to(allowed.resolve()) for allowed in allowed_dirs)
    except (ValueError, RuntimeError, OSError):
        return False


def _find_workspace_root(start: Path) -> Path | None:
    """Walk upward from *start* for the ``pyproject.toml`` declaring the uv workspace.

    Deliberately not ``boti.core.ProjectService.detect_project_root``: that
    helper stops at the *nearest* marker file (any ``pyproject.toml``,
    ``.git``, or ``.env``), which would incorrectly resolve to fenceline's own
    package root — fenceline ships its own ``pyproject.toml`` one level below
    the true workspace root. This search specifically requires the
    ``[tool.uv.workspace]`` table, so it walks past package-local markers to
    find the actual workspace root.

    Returns ``None`` rather than raising when no such ancestor exists —
    fenceline is pip-installable and importable standalone (e.g. in this
    package's own standalone CI checkout, which has no sibling ``boti``/etc.
    directories and no ambient workspace at all), and a bare import must not
    crash. Callers fall back to scanning only explicitly-provided
    ``--package`` targets in that case.
    """
    for candidate in (start, *start.parents):
        pyproject = candidate / "pyproject.toml"
        if not pyproject.is_file():
            continue
        try:
            data = tomllib.loads(pyproject.read_text())
        except (tomllib.TOMLDecodeError, OSError):
            continue
        if "workspace" in data.get("tool", {}).get("uv", {}):
            return candidate
    return None


WORKSPACE_ROOT: Path | None = _find_workspace_root(Path(__file__).resolve().parent)

# Dependency-manifest filenames probed alongside each package's source tree
# for check_dependency_cve / check_unbounded_pins.
DEP_MANIFEST_FILES = ("pyproject.toml", "requirements.txt", "setup.py", "Pipfile")
