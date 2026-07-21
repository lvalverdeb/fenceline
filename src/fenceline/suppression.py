"""Bandit-compatible inline suppression comments.

``# nosec`` (bare) suppresses every finding on that line; ``# nosec
CWE-502,CWE-94`` suppresses only findings with one of the listed CWE IDs,
leaving any other finding on the same line intact.
"""

from __future__ import annotations

import re

from fenceline.models import Finding

__all__ = ["apply_suppressions"]

_NOSEC_RE = re.compile(r"#\s*nosec\b(?:\s+([\w,-]+))?", re.IGNORECASE)


def _nosec_scope(line: str) -> set[str] | None:
    """None: no ``# nosec`` comment on this line. Empty set: bare ``# nosec``,
    suppress everything. Non-empty set: suppress only these CWE IDs."""
    match = _NOSEC_RE.search(line)
    if not match:
        return None
    scope = match.group(1)
    if not scope:
        return set()
    return {token.strip().upper() for token in scope.split(",") if token.strip()}


def apply_suppressions(findings: list[Finding], lines: list[str]) -> tuple[list[Finding], int]:
    """Filters *findings* (all from the same file) against ``# nosec``
    comments in *lines*. Returns ``(kept, suppressed_count)``."""
    kept: list[Finding] = []
    suppressed = 0
    for f in findings:
        line_text = lines[f.line - 1] if 1 <= f.line <= len(lines) else ""
        scope = _nosec_scope(line_text)
        if scope is None or (scope and f.cwe_id.upper() not in scope):
            kept.append(f)
        else:
            suppressed += 1
    return kept, suppressed
