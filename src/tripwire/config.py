"""Package-wide configuration: workspace root discovery, the scan-target
package registry, and dependency-manifest filenames.
"""

from __future__ import annotations

import tomllib
from pathlib import Path

from boti.core import is_secure_path

__all__ = ["WORKSPACE_ROOT", "DEFAULT_PACKAGES", "PACKAGES", "DEP_MANIFEST_FILES"]


def _find_workspace_root(start: Path) -> Path | None:
    """Walk upward from *start* for the ``pyproject.toml`` declaring the uv workspace.

    Deliberately not ``boti.core.ProjectService.detect_project_root``: that
    helper stops at the *nearest* marker file (any ``pyproject.toml``,
    ``.git``, or ``.env``), which would incorrectly resolve to tripwire's own
    package root — tripwire ships its own ``pyproject.toml`` one level below
    the true workspace root. This search specifically requires the
    ``[tool.uv.workspace]`` table, so it walks past package-local markers to
    find the actual workspace root.

    Returns ``None`` rather than raising when no such ancestor exists —
    tripwire is pip-installable and importable standalone (e.g. in this
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

# Every default scan target must resolve inside the workspace root — a
# defensive sandbox check for a *security* tool's own file access, using the
# same primitive boti-data and boti's own ResourceConfig gating rely on.
# Empty when no ambient workspace was found (see _find_workspace_root):
# there's nothing to default to, the caller must pass --package explicitly.
DEFAULT_PACKAGES: dict[str, Path] = (
    {
        name: path
        for name, path in {
            "boti": WORKSPACE_ROOT / "boti" / "src" / "boti",
            "boti-data": WORKSPACE_ROOT / "boti-data" / "src" / "boti_data",
            "boti-dask": WORKSPACE_ROOT / "boti-dask" / "src" / "boti_dask",
            "tripwire": WORKSPACE_ROOT / "tripwire" / "src" / "tripwire",
        }.items()
        if is_secure_path(path, [WORKSPACE_ROOT])
    }
    if WORKSPACE_ROOT is not None
    else {}
)

PACKAGES: dict[str, Path] = dict(DEFAULT_PACKAGES)

# Dependency-manifest filenames probed alongside each package's source tree
# for check_dependency_cve / check_unbounded_pins.
DEP_MANIFEST_FILES = ("pyproject.toml", "requirements.txt", "setup.py", "Pipfile")
