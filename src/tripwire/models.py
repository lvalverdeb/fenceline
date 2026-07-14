"""Core data model for tripwire findings."""
from __future__ import annotations

from dataclasses import dataclass

__all__ = ["Finding", "SEVERITY_ORDER"]


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


SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
