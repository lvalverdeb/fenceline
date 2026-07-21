"""Baseline support: snapshot current findings so a later scan only reports
and fails on *new* findings, letting an existing codebase adopt fenceline
without having to fix every pre-existing finding on day one.
"""

from __future__ import annotations

import json
from pathlib import Path

from fenceline.models import Finding

__all__ = ["write_baseline", "load_baseline", "split_by_baseline"]

Fingerprint = tuple[str, str, str]


def _fingerprint(f: Finding) -> Fingerprint:
    # (cwe_id, file, code_snippet) -- deliberately not line number, so the
    # baseline still matches after unrelated edits elsewhere in the file
    # shift line numbers.
    return (f.cwe_id, f.file, f.code_snippet)


def write_baseline(findings: list[Finding], path: Path) -> None:
    fingerprints = sorted({_fingerprint(f) for f in findings})
    data = {"fingerprints": [list(fp) for fp in fingerprints]}
    path.write_text(json.dumps(data, indent=2) + "\n")


def load_baseline(path: Path) -> set[Fingerprint]:
    data = json.loads(path.read_text())
    return {tuple(fp) for fp in data.get("fingerprints", [])}


def split_by_baseline(
    findings: list[Finding], baseline: set[Fingerprint]
) -> tuple[list[Finding], int]:
    """Returns ``(new_findings, suppressed_count)`` -- a finding whose
    fingerprint is already in *baseline* is pre-existing debt, not new."""
    new: list[Finding] = []
    suppressed = 0
    for f in findings:
        if _fingerprint(f) in baseline:
            suppressed += 1
        else:
            new.append(f)
    return new, suppressed
