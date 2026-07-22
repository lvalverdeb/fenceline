"""CLI entry point for the fenceline scanner."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from fenceline.baseline import load_baseline, split_by_baseline, write_baseline
from fenceline.checks import CHECKS
from fenceline.config import DEP_MANIFEST_FILES, WORKSPACE_ROOT, is_secure_path
from fenceline.models import CONFIDENCE_ORDER, SEVERITY_ORDER, Finding
from fenceline.reporting import print_report
from fenceline.scanner import _ast_parse, _iter_py, _read, _rel
from fenceline.suppression import apply_suppressions

__all__ = ["main", "discover_cwd_packages"]


def _find_manifest_files(root: Path, *, ceiling: Path | None) -> list[Path]:
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
    workspace root (when one was found) and the invoking directory: fenceline
    reads and reports the contents of whatever it's pointed at, so a
    mistyped or malicious ``--package foo=../../../etc`` should be rejected
    rather than silently scanned. ``cwd`` is always an allowed root — the
    caller explicitly invoked fenceline from there — which also covers running
    fenceline standalone (pip-installed, no ambient workspace) pointed at an
    arbitrary target directory.
    """
    allowed_roots = [root for root in (WORKSPACE_ROOT, cwd) if root is not None]
    resolved: dict[str, Path] = {}
    for entry in entries:
        name, sep, raw_path = entry.partition("=")
        name, raw_path = name.strip(), raw_path.strip()
        if not sep or not name or not raw_path:
            raise SystemExit(f"error: --package expects NAME=PATH, got {entry!r}")
        candidate = (cwd / raw_path).resolve()
        if not is_secure_path(candidate, allowed_roots):
            raise SystemExit(
                f"error: --package {entry!r} resolves to {candidate}, which is "
                f"outside the allowed roots {allowed_roots}."
            )
        resolved[name] = candidate
    return resolved


_NOISE_DIR_NAMES = frozenset({"__pycache__", "node_modules", "build", "dist", "site-packages"})

# Path-substring patterns skipped while walking a cwd-auto-discovered
# package's subtree -- same convention as spaghetti's own
# DEFAULT_CWD_EXCLUDES, so a virtualenv/cache/vendored-dependency tree
# nested *under* a scanned directory (not just at the top level, which
# _is_noise_dir already handles) doesn't get scanned as if it were the
# user's own code.
DEFAULT_CWD_EXCLUDES: list[str] = [
    "/.venv/",
    "/venv/",
    "/.git/",
    "/__pycache__/",
    "/node_modules/",
    "/build/",
    "/dist/",
    ".egg-info",
    "/.mypy_cache/",
    "/.pytest_cache/",
    "/.ruff_cache/",
    "/.tox/",
    "/site-packages/",
]


def _is_noise_dir(name: str) -> bool:
    return name.startswith(".") or name in _NOISE_DIR_NAMES or name.endswith(".egg-info")


def discover_cwd_packages(cwd: Path) -> tuple[dict[str, Path], str | None]:
    """Auto-discover a ``{name: path}`` registry from *cwd* for a bare
    ``fenceline`` invocation (no ``--package`` given) — this is what makes
    fenceline a generic, pip-install-anywhere tool instead of one that only
    knows how to scan this workspace's own boti/boti-data/boti-dask/fenceline
    layout: a bare invocation scans whatever's actually under the current
    directory, matching ``spaghetti``'s own ``discover_cwd_packages``.

    Each immediate, non-noise subdirectory of *cwd* containing at least one
    ``.py`` file anywhere in its subtree becomes its own named package.
    ``.py`` files sitting directly in *cwd* (outside any subdirectory) are
    grouped into one additional package named after *cwd* itself — the
    second return value is that package's name (``None`` if there were no
    such loose files), so the caller can scan it non-recursively and avoid
    double-scanning the subdirectories already registered on their own.
    """
    packages: dict[str, Path] = {}
    for entry in sorted(cwd.iterdir()):
        if not entry.is_dir() or _is_noise_dir(entry.name):
            continue
        if next(entry.rglob("*.py"), None) is not None:
            packages[entry.name] = entry

    loose_root_name: str | None = None
    if next(cwd.glob("*.py"), None) is not None:
        loose_root_name = cwd.resolve().name or str(cwd.resolve())
        if loose_root_name in packages:
            loose_root_name = f"{loose_root_name} (root)"
        packages[loose_root_name] = cwd

    return packages, loose_root_name


def main() -> int:
    parser = argparse.ArgumentParser(description="Zero-day vulnerability scanner for Python code")
    parser.add_argument("--json", action="store_true", help="JSON output")
    parser.add_argument("--quiet", "-q", action="store_true", help="Suppress banner")
    parser.add_argument(
        "--package",
        action="append",
        default=[],
        metavar="NAME=PATH",
        help=(
            "Add a scan target package as NAME=PATH (repeatable). Replaces the "
            "cwd auto-discovered registry entirely when given, rather than "
            "adding to it — pass one --package per target to scan more than one."
        ),
    )
    parser.add_argument(
        "--packages",
        nargs="*",
        default=None,
        metavar="NAME",
        help=(
            "Names to scan from the resolved registry (default: all — see "
            "--package for how the registry is built)"
        ),
    )
    parser.add_argument(
        "--fail-on",
        choices=["critical", "high", "medium", "low", "info"],
        default="high",
        help="Exit 1 only when findings at or above this severity exist (default: high)",
    )
    parser.add_argument(
        "--confidence-min",
        choices=["high", "medium", "low"],
        default="low",
        help="Drop findings below this confidence level (default: low, i.e. no filtering)",
    )
    parser.add_argument(
        "--baseline",
        type=Path,
        default=None,
        metavar="PATH",
        help="Only report/fail on findings not already present in this baseline file",
    )
    parser.add_argument(
        "--write-baseline",
        type=Path,
        default=None,
        metavar="PATH",
        help="Write current findings to PATH as a baseline (for --baseline on later runs) and exit 0",
    )
    args = parser.parse_args()

    cwd = Path.cwd()

    # A bare invocation (no --package) must never silently fall back to this
    # workspace's own boti/boti-data/boti-dask/fenceline registry — instead
    # it auto-discovers whatever's actually under the current directory,
    # same fix spaghetti's own CLI already applies for the same reason.
    # --package opts back into an explicit, non-cwd-derived registry.
    non_recursive: frozenset[str] = frozenset()
    exclude: list[str] = []
    if not args.package:
        packages, loose_root_name = discover_cwd_packages(cwd)
        exclude = DEFAULT_CWD_EXCLUDES
        if loose_root_name is not None:
            non_recursive = frozenset({loose_root_name})
    else:
        packages = _parse_package_args(args.package, cwd=cwd)

    if not packages:
        parser.error("no packages to scan — the resolved package registry is empty")

    selected = args.packages if args.packages is not None else list(packages.keys())
    unknown = [name for name in selected if name not in packages]
    if unknown:
        parser.error(
            f"unknown package(s): {', '.join(unknown)}. Available: {', '.join(sorted(packages))}"
        )
    packages = {name: packages[name] for name in selected}

    total_files = sum(
        1
        for name, root in packages.items()
        for _ in _iter_py(root, recursive=name not in non_recursive, exclude=exclude)
    )

    # JSON mode keeps stdout machine-parseable: banner is suppressed and
    # diagnostics go to stderr.
    if not args.quiet and not args.json:
        print(f"\n  {'=' * 72}")
        print("  Zero-Day Security Audit — fenceline")
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
        for path in _iter_py(root, recursive=name not in non_recursive, exclude=exclude):
            path_package.setdefault(path, name)
        for path in _find_manifest_files(root, ceiling=WORKSPACE_ROOT):
            path_package.setdefault(path, name)

    nosec_suppressed = 0
    for path in sorted(path_package):
        lines = _read(path)
        tree = _ast_parse(path) if path.suffix == ".py" else None
        pkg_name = path_package[path]

        file_findings: list[Finding] = []
        for check_name, check_fn in CHECKS:
            try:
                findings = check_fn(path, lines, tree)
                for f in findings:
                    f.package = pkg_name
                file_findings.extend(findings)
            except Exception as exc:
                if not args.quiet:
                    print(f"  ⚠ {check_name} error on {_rel(path)}: {exc}", file=sys.stderr)

        kept, suppressed_here = apply_suppressions(file_findings, lines)
        nosec_suppressed += suppressed_here
        all_findings.extend(kept)

    conf_threshold = CONFIDENCE_ORDER[args.confidence_min.upper()]
    all_findings = [
        f for f in all_findings if CONFIDENCE_ORDER.get(f.confidence, 0) <= conf_threshold
    ]

    if args.write_baseline is not None:
        write_baseline(all_findings, args.write_baseline)
        print_report(all_findings, json_output=args.json, nosec_suppressed=nosec_suppressed)
        if not args.quiet and not args.json:
            print(f"  Wrote baseline with {len(all_findings)} finding(s) to {args.write_baseline}")
        return 0

    baseline_suppressed = 0
    if args.baseline is not None:
        baseline_fingerprints = load_baseline(args.baseline)
        all_findings, baseline_suppressed = split_by_baseline(all_findings, baseline_fingerprints)

    print_report(
        all_findings,
        json_output=args.json,
        baseline_suppressed=baseline_suppressed,
        nosec_suppressed=nosec_suppressed,
    )
    threshold = SEVERITY_ORDER[args.fail_on.upper()]
    gating = [f for f in all_findings if SEVERITY_ORDER.get(f.severity, 99) <= threshold]
    return 1 if gating else 0


if __name__ == "__main__":
    sys.exit(main())
