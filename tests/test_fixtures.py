"""Conformance runner for the fixture corpus (Phase 1 of RUST_PORT_PROPOSAL.md).

Every ``fixtures/<check_fn_name>/case_*.py`` + ``case_*.expected.json`` pair
is run through the real, unmodified check function and diffed on the fields
a port to another language must reproduce exactly -- ``cwe_id``,
``severity``, ``confidence``, and ``line``. Message/description text is
deliberately not compared: it's allowed to differ across implementations
(see RUST_PORT_PROPOSAL.md Sec. 5), so comparing it here would make normal
wording improvements fail this suite for no real reason.

A separate guard test asserts every check without its own dedicated unit
test in test_fenceline.py has at least one fixture case here, so fixture
coverage can't silently regress as new checks are added.
"""

from __future__ import annotations

import ast
import json
import re
from pathlib import Path

import pytest

from fenceline.checks import CHECKS

FIXTURES_DIR = Path(__file__).parent.parent / "fixtures"
TEST_FENCELINE_PATH = Path(__file__).parent / "test_fenceline.py"

_CHECK_BY_NAME = {fn.__name__: fn for _, fn in CHECKS}


def _discover_cases() -> list[tuple[str, Path, Path]]:
    cases = []
    if not FIXTURES_DIR.is_dir():
        return cases
    for check_dir in sorted(FIXTURES_DIR.iterdir()):
        if not check_dir.is_dir():
            continue
        for py_file in sorted(check_dir.glob("case_*.py")):
            expected_file = py_file.parent / f"{py_file.stem}.expected.json"
            if expected_file.exists():
                cases.append((check_dir.name, py_file, expected_file))
    return cases


CASES = _discover_cases()


def _fingerprint(cwe_id: str, severity: str, confidence: str, line: int) -> tuple:
    return (cwe_id, severity, confidence, line)


@pytest.mark.parametrize(
    "check_name,py_file,expected_file",
    CASES,
    ids=[f"{c[0]}/{c[1].stem}" for c in CASES],
)
def test_fixture_case(check_name, py_file, expected_file, tmp_path, monkeypatch):
    # Fixture cases use a fake, often-relative path label (path_name) that's
    # never actually written to disk -- a check that does its own real
    # filesystem lookups relative to that path (e.g. checking for a sibling
    # lockfile) would otherwise silently resolve against wherever pytest's
    # cwd happens to be (this repo's own root), not an empty directory as
    # intended. Running from an empty tmp_path makes every fixture case's
    # filesystem view consistently empty regardless of invocation directory.
    monkeypatch.chdir(tmp_path)
    check_fn = _CHECK_BY_NAME[check_name]
    source = py_file.read_text()
    expected_data = json.loads(expected_file.read_text())
    fake_path = Path(expected_data.get("path_name", py_file.name))

    lines = source.splitlines()
    tree = ast.parse(source) if fake_path.suffix == ".py" else None

    findings = check_fn(fake_path, lines, tree)
    actual = sorted(_fingerprint(f.cwe_id, f.severity, f.confidence, f.line) for f in findings)
    expected = sorted(
        _fingerprint(f["cwe_id"], f["severity"], f["confidence"], f["line"])
        for f in expected_data["findings"]
    )
    assert actual == expected


def test_every_check_without_a_dedicated_unit_test_has_a_fixture():
    """Guards fixture coverage against silent regression: a check newly
    added without either a direct test in test_fenceline.py or a fixture
    case here fails this test, rather than quietly having zero conformance
    coverage."""
    directly_tested = set(re.findall(r"\bcheck_\w+\b", TEST_FENCELINE_PATH.read_text()))
    fixture_covered = (
        {p.name for p in FIXTURES_DIR.iterdir() if p.is_dir()} if FIXTURES_DIR.is_dir() else set()
    )
    all_check_names = {fn.__name__ for _, fn in CHECKS}

    uncovered = all_check_names - directly_tested - fixture_covered
    assert not uncovered, f"checks with neither a unit test nor a fixture: {sorted(uncovered)}"
