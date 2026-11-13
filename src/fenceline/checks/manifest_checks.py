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


_PRE_TAGS = {"a": 0, "alpha": 0, "b": 1, "beta": 1, "c": 2, "rc": 2, "pre": 2, "preview": 2}
_VERSION_RE = re.compile(
    r"^(?:(\d+)!)?(\d+(?:\.\d+)*)"
    r"(?:[-._]?(a|b|c|rc|alpha|beta|pre|preview)[-._]?(\d*))?"
    r"(?:[-._]?(?:post|rev|r)[-._]?(\d*)|-(\d+))?"
    r"(?:[-._]?dev[-._]?(\d*))?"
    r"(?:\+[0-9a-z.]+)?$"
)

Version = tuple[int, tuple[int, ...], tuple[int, int, int]]


def _parse_version(text: str) -> Version | None:
    """PEP 440 version as an orderable key, or ``None`` if *text* isn't one.
    ``(epoch, release, stage)``: trailing ``.0`` release segments are dropped
    (``1.0 == 1.0.0``) and *stage* orders ``.devN < aN/bN/rcN < final <
    .postN`` within one release. Local version labels are ignored."""
    m = _VERSION_RE.match(text.strip().lower())
    if not m:
        return None
    epoch = int(m.group(1) or 0)
    release = [int(x) for x in m.group(2).split(".")]
    while len(release) > 1 and release[-1] == 0:
        release.pop()
    pre_tag, pre_n, post_n, post_implicit, dev_n = m.group(3, 4, 5, 6, 7)
    if pre_tag is not None:
        stage = (1, _PRE_TAGS[pre_tag], int(pre_n or 0))
    elif post_n is not None or post_implicit is not None:
        stage = (3, int(post_n or post_implicit or 0), 0)
    elif dev_n is not None:
        stage = (0, int(dev_n or 0), 0)
    else:
        stage = (2, 0, 0)
    return epoch, tuple(release), stage


_SPECIFIER_RE = re.compile(r"(===|==|~=|>=|<=|!=|<|>)\s*([0-9][0-9A-Za-z.!+\-]*)")


def _constraint_floor(line: str) -> tuple[str, Version] | None:
    """What a manifest line says about the version that will be installed:
    ``("exact", v)`` for ``==``/``===``; ``("floor", v)`` for the highest
    lower bound among ``>=``/``>``/``~=``; ``None`` when the line pins
    nothing (no specifier, or only an upper bound / exclusion)."""
    exact = floor = None
    for op, raw in _SPECIFIER_RE.findall(line):
        v = _parse_version(raw)
        if v is None:
            continue
        if op in ("==", "==="):
            exact = v
        elif op in (">=", ">", "~="):
            floor = v if floor is None else max(floor, v)
    if exact is not None:
        return "exact", exact
    if floor is not None:
        return "floor", floor
    return None


def _normalize_dist(name: str) -> str:
    """PEP 503 normalised distribution name."""
    return re.sub(r"[-_.]+", "-", name.strip().lower())


# Lockfile -> the manifest that owns it. Only the owner reports lockfile
# findings, so a requirements.txt sitting next to pyproject.toml + uv.lock
# doesn't produce the same finding twice.
_LOCK_OWNERS = (
    ("uv.lock", "pyproject.toml"),
    ("poetry.lock", "pyproject.toml"),
    ("Pipfile.lock", "Pipfile"),
)


def _locked_versions(lock_path: Path, lock_lines: list[str]) -> dict[str, tuple[str, int]]:
    """``{normalised name: (version, line)}`` for every package a lockfile
    resolves. ``uv.lock``/``poetry.lock`` are ``[[package]]`` TOML blocks
    with ``name``/``version`` lines; ``Pipfile.lock`` is JSON. Line-scanned
    rather than parsed, because the finding needs the line number and
    neither ``tomllib`` nor ``json`` reports one."""
    out: dict[str, tuple[str, int]] = {}
    if lock_path.name == "Pipfile.lock":
        try:
            data = json.loads("\n".join(lock_lines))
        except json.JSONDecodeError:
            return out
        for section in ("default", "develop"):
            for name, info in (data.get(section) or {}).items():
                version = str((info or {}).get("version", "")).lstrip("=")
                key = re.compile(rf'^\s*"{re.escape(name)}"\s*:\s*\{{')
                lineno = next((i for i, line in enumerate(lock_lines, 1) if key.match(line)), 0)
                if version and lineno:
                    out[_normalize_dist(name)] = (version, lineno)
        return out
    name: str | None = None
    name_line = 0
    for i, line in enumerate(lock_lines, 1):
        stripped = line.strip()
        if stripped.startswith("["):
            name = None
        elif m := re.match(r'^name\s*=\s*"([^"]+)"', stripped):
            name, name_line = m.group(1), i
        elif name is not None and (m := re.match(r'^version\s*=\s*"([^"]+)"', stripped)):
            out[_normalize_dist(name)] = (m.group(1), name_line)
            name = None
    return out


_CVE_ZERO_DAY = (
    "Dependency CVEs are the most common zero-day entry vector — 74% of breaches "
    "involve third-party code."
)


def _cve_finding(pk: str, line: int, snippet: str, confidence: str, description: str) -> Finding:
    return Finding(
        cwe_id="CWE-1104",
        cwe_name="Supply Chain — Dependency with Known Vulnerability",
        severity="HIGH",
        confidence=confidence,
        package="",
        file=pk,
        line=line,
        code_snippet=snippet,
        description=description,
        zero_day_relevance=_CVE_ZERO_DAY,
    )


def _lockfile_cve_findings(lock_path: Path) -> list[Finding] | None:
    """Findings against the versions a lockfile actually resolves, or ``None``
    if the lockfile yielded nothing usable (the caller then falls back to
    the manifest's own constraints)."""
    try:
        lock_lines = lock_path.read_text(errors="replace").splitlines()
    except OSError:
        return None
    locked = _locked_versions(lock_path, lock_lines)
    if not locked:
        return None
    pk = _rel(lock_path)
    results: list[Finding] = []
    for dep_name, cve_info in _load_vuln_deps():
        dep_base, _, max_ver_text = dep_name.partition("<")
        max_ver = _parse_version(max_ver_text)
        entry = locked.get(_normalize_dist(dep_base))
        if max_ver is None or entry is None:
            continue
        version, lineno = entry
        found = _parse_version(version)
        if found is not None and found < max_ver:
            results.append(
                _cve_finding(
                    pk,
                    lineno,
                    lock_lines[lineno - 1].strip(),
                    "HIGH",
                    f"{dep_name}: {cve_info} (locked at {version} in {lock_path.name})",
                )
            )
    return results


def check_dependency_cve(path: Path, lines: list[str], tree: ast.Module | None) -> list[Finding]:
    """CWE-1104: a dependency pinned or locked to a release with a known CVE
    (table: ``vuln_deps.json``).

    When a lockfile sits next to the manifest, the lockfile is what gets
    installed, so its exact versions are checked and the manifest's own
    ranges are ignored: ``requests>=2.0`` locked at 2.32.3 is fine, and
    locked at 2.31.0 is reported on the lockfile line. Without a lockfile
    the manifest is read on its own terms: an ``==`` pin below the fixed
    version is a HIGH-confidence finding; a lower bound (``>=``, ``~=``)
    below it is MEDIUM confidence -- a fresh resolve may well pick a fixed
    release, but nothing in the repository guarantees it."""
    if path.name not in ("pyproject.toml", "requirements.txt", "setup.py", "Pipfile"):
        return []
    parent = path.parent
    for lock_name, owner in _LOCK_OWNERS:
        lock_path = parent / lock_name
        if not lock_path.is_file():
            continue
        if not (parent / owner).is_file():
            owner = min(
                n
                for n in ("pyproject.toml", "requirements.txt", "setup.py", "Pipfile")
                if (parent / n).is_file()
            )
        if path.name != owner:
            return []
        locked = _lockfile_cve_findings(lock_path)
        if locked is not None:
            return locked
        break

    pk = _rel(path)
    results: list[Finding] = []
    content = "\n".join(lines).lower()
    for dep_name, cve_info in _load_vuln_deps():
        dep_base, _, max_ver_text = dep_name.partition("<")
        dep_base = dep_base.strip()
        max_ver = _parse_version(max_ver_text)
        if max_ver is None:
            continue
        # Word-boundary match on the dependency name, so "dask" doesn't match "boti-dask".
        dep_pattern = re.compile(rf'(?:^|["\'=,\s]){re.escape(dep_base)}(?=["\':,<>=!\s]|$)')
        if not dep_pattern.search(content):
            continue
        for lineno, line in enumerate(lines, 1):
            if _skip(line) or not dep_pattern.search(line.lower()):
                continue
            constraint = _constraint_floor(line)
            if constraint is None:
                continue
            kind, found = constraint
            if found >= max_ver:
                continue
            if kind == "exact":
                description = f"{dep_name}: {cve_info}"
                confidence = "HIGH"
            else:
                description = (
                    f"{dep_name}: {cve_info} — lower bound allows a vulnerable release to "
                    f"resolve; pin or lock above the fixed version"
                )
                confidence = "MEDIUM"
            results.append(_cve_finding(pk, lineno, line.strip(), confidence, description))
            break
    return results


_LOCKFILE_NAMES = ("uv.lock", "poetry.lock", "Pipfile.lock")


def _sibling_lockfile_exists(manifest_path: Path) -> bool:
    """True if a recognized lockfile sits alongside *manifest_path*.

    When a project is locked (``uv``/``poetry``/``Pipfile``/``pip-compile``),
    the manifest's own loose version ranges only matter at upgrade time -- a
    deliberate, reviewable ``uv lock --upgrade`` (or equivalent) that commits
    a new lockfile -- not at every install/sync, which resolves from the
    lockfile rather than re-resolving the manifest's ranges. "Any version
    satisfying >=X might install silently" is true for an unlocked project
    and false for a locked one.
    """
    parent = manifest_path.parent
    if any((parent / name).exists() for name in _LOCKFILE_NAMES):
        return True
    # pip-compile: requirements.txt is itself the generated lockfile, so its
    # presence only counts when *this* manifest isn't that same file (e.g.
    # scanning pyproject.toml or a requirements.in source alongside it).
    return manifest_path.name != "requirements.txt" and (parent / "requirements.txt").exists()


def check_unbounded_pins(path: Path, lines: list[str], tree: ast.Module | None) -> list[Finding]:
    """CVE-2026-42208 pattern: >=<version> without upper bound allows
    pip to resolve to a compromised wheel."""
    if path.name not in ("pyproject.toml", "requirements.txt", "Pipfile"):
        return []
    pk = _rel(path)
    results: list[Finding] = []
    locked = _sibling_lockfile_exists(path)

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
            if locked:
                description = (
                    f"'{dep_name}>={version}' has no upper bound, but a lockfile alongside this "
                    f"manifest means installs resolve from the lockfile, not this range directly — "
                    f"the residual risk is at upgrade-time review (`lock --upgrade` or equivalent), "
                    f"not silent install-time drift. Still worth bounding for when that upgrade happens."
                )
            else:
                description = (
                    f"'{dep_name}>={version}' has no upper bound — pip resolves to latest "
                    f"matching version. A compromised wheel at a higher version propagates silently. "
                    f"Use '{dep_name}>={version},<next_major' to bound."
                )
            results.append(
                Finding(
                    cwe_id="CWE-1104",
                    cwe_name="Supply Chain — Unbounded Dependency Pin",
                    severity="INFO" if locked else "LOW",
                    package="",
                    file=pk,
                    line=lineno,
                    code_snippet=stripped,
                    description=description,
                    zero_day_relevance="CVE-2026-42208: litellm>=1.61.3 with no upper bound led to "
                    "..pth backdoor via transitive dep (semantic-router).",
                )
            )
    return results
