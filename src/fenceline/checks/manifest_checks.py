"""Checks that operate on dependency manifests (pyproject.toml,
requirements.txt, setup.py, Pipfile) rather than Python source files."""

from __future__ import annotations

import ast
import json
import re
from functools import lru_cache
from importlib import resources
from pathlib import Path

from fenceline.ast_helpers import _skip
from fenceline.models import Finding
from fenceline.scanner import _rel

__all__ = ["check_dependency_cve", "check_unbounded_pins"]


@lru_cache(maxsize=1)
def _load_vuln_deps() -> list[tuple[str, str]]:
    """Loads the known-vulnerable dependency table from vuln_deps.json --
    shared data (not Python-specific logic) so a future Rust port reads the
    identical file instead of maintaining a second hardcoded copy that can
    silently drift out of sync on the next CVE addition."""
    raw = resources.files("fenceline").joinpath("vuln_deps.json").read_text()
    return [(entry["dep"], entry["cve"]) for entry in json.loads(raw)]


def check_dependency_cve(path: Path, lines: list[str], tree: ast.Module | None) -> list[Finding]:
    """Scan pyproject.toml / requirements.txt / setup.py for known CVEs.  CWE-1104."""
    if path.name not in ("pyproject.toml", "requirements.txt", "setup.py", "Pipfile"):
        return []
    pk = _rel(path)
    results: list[Finding] = []
    content = "\n".join(lines).lower()

    for dep_name, cve_info in _load_vuln_deps():
        dep_base = dep_name.split("<")[0].strip()
        max_ver = dep_name.split("<")[1].strip()
        # Build a pattern that matches the dependency name as a word boundary,
        # not as a substring (e.g., "dask" should not match "boti-dask")
        dep_pattern = re.compile(rf'(?:^|["\'=,\s]){re.escape(dep_base)}(?=["\':,<>=!\s]|$)')
        if not dep_pattern.search(content):
            continue
        for lineno, line in enumerate(lines, 1):
            if dep_pattern.search(line.lower()):
                # Extract version constraint from the line
                version_match = re.search(r"(?:>=|==|~=|!=|<|>)\s*(\d+\.\d+\.\d+)", line)
                if version_match:
                    found_ver = version_match.group(1)
                    # Simple comparison: version < max_ver is vulnerable
                    if tuple(int(x) for x in found_ver.split(".")) < tuple(
                        int(x) for x in max_ver.split(".")
                    ):
                        results.append(
                            Finding(
                                cwe_id="CWE-1104",
                                cwe_name="Supply Chain — Dependency with Known Vulnerability",
                                severity="HIGH",
                                confidence="HIGH",
                                package="",
                                file=pk,
                                line=lineno,
                                code_snippet=line.strip(),
                                description=f"{dep_name}: {cve_info}",
                                zero_day_relevance="Dependency CVEs are the most common zero-day entry vector — 74% of breaches involve third-party code.",
                            )
                        )
                        break
    return results


def check_unbounded_pins(path: Path, lines: list[str], tree: ast.Module | None) -> list[Finding]:
    """CVE-2026-42208 pattern: >=<version> without upper bound allows
    pip to resolve to a compromised wheel."""
    if path.name not in ("pyproject.toml", "requirements.txt", "Pipfile"):
        return []
    pk = _rel(path)
    results: list[Finding] = []

    lower_bound_pat = re.compile(r'["\']([\w.-]+)\s*>=\s*(\d+\.\d+(?:\.\d+)?)["\']')
    for lineno, line in enumerate(lines, 1):
        if _skip(line):
            continue
        stripped = line.strip()
        m = lower_bound_pat.search(stripped)
        if m:
            dep_name = m.group(1)
            version = m.group(2)
            # Skip Python version constraint
            if dep_name in ("python", "requires-python"):
                continue
            # Check for upper bound elsewhere in same line
            if re.search(r"\s*<\s*", stripped):
                continue
            # Check if the line has an upper bound in multi-constraint format like ">=X,<Y"
            if re.search(r",\s*<\s*", stripped):
                continue
            results.append(
                Finding(
                    cwe_id="CWE-1104",
                    cwe_name="Supply Chain — Unbounded Dependency Pin",
                    severity="LOW",
                    package="",
                    file=pk,
                    line=lineno,
                    code_snippet=stripped,
                    description=f"'{dep_name}>={version}' has no upper bound — pip resolves to latest "
                    f"matching version. A compromised wheel at a higher version propagates silently. "
                    f"Use '{dep_name}>={version},<next_major' to bound.",
                    zero_day_relevance="CVE-2026-42208: litellm>=1.61.3 with no upper bound led to "
                    "..pth backdoor via transitive dep (semantic-router).",
                )
            )
    return results
