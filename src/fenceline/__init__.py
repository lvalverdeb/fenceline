"""Zero-day security scanner for the Boti workspace.

Maps findings to the CWE Top 25 (2025), OWASP Top 10:2025, and known Python
zero-day exploit patterns. See :mod:`fenceline.cli` for the CLI entry point
and :mod:`fenceline.checks` for the check registry.
"""

from __future__ import annotations

from fenceline.cli import main

__all__ = ["main"]
