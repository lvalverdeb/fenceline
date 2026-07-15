"""CLI entry point for the tripwire scanner."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from boti.core import is_secure_path

from tripwire.checks import CHECKS
from tripwire.config import DEP_MANIFEST_FILES, PACKAGES, WORKSPACE_ROOT
from tripwire.models import SEVERITY_ORDER, Finding
from tripwire.reporting import print_report
from tripwire.scanner import _ast_parse, _iter_py, _read, _rel

__all__ = ["main"]


def _find_manifest_files(root: Path, *, ceiling: Path) -> list[Path]:
    """Find dependency manifest files for a package by walking upward from
    *root* (the package's importable source dir) to *ceiling* (the workspace
    root), stopping at the first ancestor where any manifest file exists.

    Not a fixed-depth ``root.parent`` lookup: DEFAULT_PACKAGES points at the
    innermost ``src/<pkg>`` dir (two levels below the package's
    pyproject.toml), but a ``--package`` entry may point at a flat-layout
    root where the manifest sits one level up, or even at the manifest's own
    directory. Searching upward handles both without assuming a fixed depth.
    """
    for candidate in (root, *root.parents):
        found = [candidate / df for df in DEP_MANIFEST_FILES if (candidate / df).exists()]
        if found:
            return found
        if candidate == ceiling:
            break
    return []


def _parse_package_args(entries: list[str], *, cwd: Path) -> dict[str, Path]:
    """Parse repeated ``--package NAME=PATH`` CLI entries into a registry.

    Every resolved path is validated with ``is_secure_path`` against the
    workspace root: tripwire reads and reports the contents of whatever it's
    pointed at, so a mistyped or malicious ``--package foo=../../../etc``
    should be rejected rather than silently scanned.
    """
    resolved: dict[str, Path] = {}
    for entry in entries:
        name, sep, raw_path = entry.partition("=")
        name, raw_path = name.strip(), raw_path.strip()
        if not sep or not name or not raw_path:
            raise SystemExit(f"error: --package expects NAME=PATH, got {entry!r}")
        candidate = (cwd / raw_path).resolve()
        if not is_secure_path(candidate, [WORKSPACE_ROOT]):
            raise SystemExit(
                f"error: --package {entry!r} resolves to {candidate}, which is "
                f"outside the workspace root {WORKSPACE_ROOT}."
            )
        resolved[name] = candidate
    return resolved


def main() -> int:
    parser = argparse.ArgumentParser(description="Zero-day vulnerability scanner for the workspace")
    parser.add_argument("--json", action="store_true", help="JSON output")
    parser.add_argument("--quiet", "-q", action="store_true", help="Suppress banner")
    parser.add_argument(
        "--package",
        action="append",
        default=[],
        metavar="NAME=PATH",
        help="Add or override a scan target package (repeatable)",
    )
    parser.add_argument(
        "--fail-on",
        choices=["critical", "high", "medium", "low", "info"],
        default="high",
        help="Exit 1 only when findings at or above this severity exist (default: high)",
    )
    args = parser.parse_args()

    packages = dict(PACKAGES)
    packages.update(_parse_package_args(args.package, cwd=Path.cwd()))

    total_files = sum(1 for root in packages.values() for _ in _iter_py(root))

    # JSON mode keeps stdout machine-parseable: banner is suppressed and
    # diagnostics go to stderr.
    if not args.quiet and not args.json:
        print(f"\n  {'=' * 72}")
        print("  Zero-Day Security Audit — tripwire")
        print("  CWEs: CWE Top 25 (2025) + OWASP Top 10:2025 + Python Zero-Day Patterns")
        print(f"  Scanning {len(packages)} packages, {total_files} files...")
        print(f"  {'=' * 72}")
        print()

    all_findings: list[Finding] = []

    # Collect all files: .py from each package + dep manifests for CVE scan,
    # recording which package each path belongs to at collection time (not
    # re-derived from the path afterward — a manifest file can sit multiple
    # directory levels above its package's source root, so prefix matching
    # on the resolved path can't reliably recover the owning package).
    path_package: dict[Path, str] = {}
    for name, root in packages.items():
        for path in _iter_py(root):
            path_package.setdefault(path, name)
        for path in _find_manifest_files(root, ceiling=WORKSPACE_ROOT):
            path_package.setdefault(path, name)

    for path in sorted(path_package):
        lines = _read(path)
        tree = _ast_parse(path) if path.suffix == ".py" else None
        pkg_name = path_package[path]

        for check_name, check_fn in CHECKS:
            try:
                findings = check_fn(path, lines, tree)
                for f in findings:
                    f.package = pkg_name
                all_findings.extend(findings)
            except Exception as exc:
                if not args.quiet:
                    print(f"  ⚠ {check_name} error on {_rel(path)}: {exc}", file=sys.stderr)

    print_report(all_findings, json_output=args.json)
    threshold = SEVERITY_ORDER[args.fail_on.upper()]
    gating = [f for f in all_findings if SEVERITY_ORDER.get(f.severity, 99) <= threshold]
    return 1 if gating else 0


if __name__ == "__main__":
    sys.exit(main())
