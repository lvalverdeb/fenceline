"""Core data model for fenceline findings."""

from __future__ import annotations

from dataclasses import dataclass

__all__ = ["Finding", "SEVERITY_ORDER", "CONFIDENCE_ORDER"]


@dataclass
class Finding:
    cwe_id: str
    cwe_name: str
    severity: str
    package: str
    file: str
    line: int
    code_snippet: str
    description: str
    zero_day_relevance: str = ""
    # How sure the check is that this is a real positive, independent of how
    # bad it would be if true (that's severity). AST-based checks default to
    # HIGH (matched a real Call/ExceptHandler/etc. node, not just a substring);
    # line-regex checks default to MEDIUM (can't fully rule out a docstring or
    # string-literal mention beyond whole-line comments); a handful of
    # inherently heuristic checks (timing-attack keyword proximity, ReDoS
    # backtracking-risk judgment) are explicitly LOW.
    confidence: str = "MEDIUM"


SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
CONFIDENCE_ORDER = {"HIGH": 0, "MEDIUM": 1, "LOW": 2}
