"""Inline suppression comments.

``# nosec`` (bare) suppresses every finding on that line; ``# nosec
CWE-502,CWE-94`` suppresses only findings with one of the listed CWE IDs,
leaving any other finding on the same line intact. A Bandit rule code in
either comment (``# nosec B608``) or in a Ruff one (``# noqa: S608``)
suppresses the fenceline checks that cover the same shape: the authors have
already adjudicated that line for another tool, and a second report of the
same thing is noise.
"""

from __future__ import annotations

import re

from fenceline.models import Finding

__all__ = ["apply_suppressions"]

_NOSEC_RE = re.compile(r"#\s*nosec\b(?:\s+([\w,-]+))?", re.IGNORECASE)
_NOQA_RE = re.compile(r"#\s*noqa\s*:\s*([A-Z]+\d+(?:\s*,\s*[A-Z]+\d+)*)", re.IGNORECASE)
_RULE_CODE_RE = re.compile(r"[SB](\d{3})", re.IGNORECASE)

#: Bandit rule numbers (Ruff's ``S`` codes use the same numbers) and the
#: fenceline CWE IDs that report the same shape.
_BANDIT_CWES: dict[str, tuple[str, ...]] = {
    "102": ("CWE-94",),
    "104": ("CWE-1327",),
    "105": ("CWE-798",),
    "106": ("CWE-798",),
    "107": ("CWE-798",),
    "108": ("CWE-377",),
    "110": ("CWE-391", "CWE-778"),
    "112": ("CWE-391", "CWE-778"),
    "113": ("CWE-1088",),
    "201": ("CWE-489",),
    "301": ("CWE-502",),
    "302": ("CWE-502",),
    "303": ("CWE-328", "CWE-327"),
    "304": ("CWE-327",),
    "305": ("CWE-327",),
    "306": ("CWE-377",),
    "307": ("CWE-94",),
    "308": ("CWE-79",),
    "310": ("CWE-918",),
    "311": ("CWE-338",),
    "313": ("CWE-611",),
    "314": ("CWE-611",),
    "315": ("CWE-611",),
    "316": ("CWE-611",),
    "317": ("CWE-611",),
    "318": ("CWE-611",),
    "319": ("CWE-611",),
    "320": ("CWE-611",),
    "323": ("CWE-295",),
    "324": ("CWE-328", "CWE-327"),
    "405": ("CWE-611",),
    "406": ("CWE-611",),
    "407": ("CWE-611",),
    "408": ("CWE-611",),
    "409": ("CWE-611",),
    "410": ("CWE-611",),
    "501": ("CWE-295",),
    "502": ("CWE-295",),
    "503": ("CWE-295",),
    "504": ("CWE-295",),
    "506": ("CWE-502",),
    "602": ("CWE-78",),
    "603": ("CWE-78",),
    "604": ("CWE-78",),
    "605": ("CWE-78",),
    "606": ("CWE-78",),
    "607": ("CWE-78",),
    "608": ("CWE-89",),
    "609": ("CWE-78",),
    "701": ("CWE-79",),
    "702": ("CWE-79",),
    "704": ("CWE-79",),
}


def _nosec_scope(line: str) -> set[str] | None:
    """None: no ``# nosec`` comment on this line. Empty set: bare ``# nosec``,
    suppress everything. Non-empty set: suppress only these tokens."""
    match = _NOSEC_RE.search(line)
    if not match:
        return None
    scope = match.group(1)
    if not scope:
        return set()
    return {token.strip().upper() for token in scope.split(",") if token.strip()}


def _expand_rule_codes(tokens: set[str]) -> set[str]:
    out: set[str] = set()
    for token in tokens:
        match = _RULE_CODE_RE.fullmatch(token)
        if match:
            out.update(_BANDIT_CWES.get(match.group(1), ()))
        else:
            out.add(token)
    return out


def _suppressed_cwes(line: str) -> set[str] | None:
    """None: no suppression comment. Empty set: suppress everything.
    Non-empty set: the CWE IDs suppressed on this line."""
    scope = _nosec_scope(line)
    if scope is not None and not scope:
        return set()
    noqa = _NOQA_RE.search(line)
    codes = {t.strip().upper() for t in noqa.group(1).split(",")} if noqa else set()
    if scope is None and not codes:
        return None
    return _expand_rule_codes((scope or set()) | codes)


def apply_suppressions(findings: list[Finding], lines: list[str]) -> tuple[list[Finding], int]:
    """Filters *findings* (all from the same file) against ``# nosec`` and
    ``# noqa`` comments in *lines*. Returns ``(kept, suppressed_count)``."""
    kept: list[Finding] = []
    suppressed = 0
    for f in findings:
        line_text = lines[f.line - 1] if 1 <= f.line <= len(lines) else ""
        scope = _suppressed_cwes(line_text)
        if scope is None or (scope and f.cwe_id.upper() not in scope):
            kept.append(f)
        else:
            suppressed += 1
    return kept, suppressed
