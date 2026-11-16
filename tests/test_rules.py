"""The rule loader: a rule file is a security policy, so every malformed
entry is an error that names the file and the rule, never a silently inert
line. Matching semantics are covered by ``fixtures/rules/`` (shared with the
Rust port); the CLI wiring by ``test_cli_rules_*`` here."""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

from fenceline.rules import RuleError, load_rule_set

GOOD = """
[[rule]]
id = "t/mktemp"
cwe = "CWE-377"
name = "Insecure Temporary File"
severity = "high"
description = "mktemp() names a file without creating it."
kind = "call"
callee = ["tempfile.mktemp"]
"""


def _load(tmp_path: Path, text: str):
    rules_file = tmp_path / "rules.toml"
    rules_file.write_text(text)
    return load_rule_set(None, [rules_file])


def test_good_rule_loads_with_defaults(tmp_path):
    (rule,) = _load(tmp_path, GOOD)
    assert (rule.id, rule.severity, rule.confidence, rule.callee) == (
        "t/mktemp",
        "HIGH",
        "HIGH",
        ("tempfile.mktemp",),
    )


def test_pattern_rule_defaults_to_medium_confidence(tmp_path):
    (rule,) = _load(
        tmp_path,
        GOOD.replace(
            'kind = "call"\ncallee = ["tempfile.mktemp"]', 'kind = "pattern"\nregex = "mktemp"'
        ),
    )
    assert rule.confidence == "MEDIUM" and rule.regex is not None


@pytest.mark.parametrize(
    "old,new,message",
    [
        ('kind = "call"', 'kind = "cal"', "kind 'cal' is not one of"),
        ('kind = "call"', 'kind = "call"\nregex = "x"', "unknown key.s. for a call rule: regex"),
        ('severity = "high"', 'severity = "urgent"', "severity must be one of"),
        ('cwe = "CWE-377"', 'cwe = "377"', "must look like CWE-123"),
        ('callee = ["tempfile.mktemp"]', "callee = []", "'callee' must be a non-empty array"),
        (
            'kind = "call"',
            'kind = "sink"\nconfidence = "low"',
            "unknown key.s. for a sink rule: confidence",
        ),
        ('kind = "call"', 'kind = "sink"\ndata = "second"', "'data' must be"),
        (
            'kind = "call"',
            'kind = "keyword"\nkeyword = "verify"',
            "exactly one of 'value', 'unless' or 'required = true'",
        ),
        (
            'kind = "call"',
            'kind = "keyword"\nkeyword = "verify"\nvalue = 1.5',
            "'value' must be a boolean, an integer or a string",
        ),
        (
            'kind = "call"',
            'kind = "keyword"\nkeyword = "verify"\nrequired = false',
            "'required' can only be true",
        ),
        (
            'kind = "call"\ncallee = ["tempfile.mktemp"]',
            'kind = "pattern"\nregex = "(?=x)mktemp"',
            "lookaround or a backreference",
        ),
        (
            'kind = "call"\ncallee = ["tempfile.mktemp"]',
            'kind = "pattern"\nregex = "mktemp("',
            "regex does not compile",
        ),
    ],
)
def test_malformed_rule_is_an_error_naming_the_rule(tmp_path, old, new, message):
    text = GOOD.replace(old, new)
    with pytest.raises(RuleError, match=message) as info:
        _load(tmp_path, text)
    assert "rule 't/mktemp'" in str(info.value) or "rule 1" in str(info.value)


def test_duplicate_ids_across_files_are_an_error(tmp_path):
    a, b = tmp_path / "a.toml", tmp_path / "b.toml"
    a.write_text(GOOD)
    b.write_text(GOOD)
    with pytest.raises(RuleError, match="defined twice"):
        load_rule_set(None, [a, b])


def test_rules_file_without_rules_is_an_error(tmp_path):
    with pytest.raises(RuleError, match="no \\[\\[rule\\]\\] tables"):
        _load(tmp_path, 'title = "nothing"\n')


def test_config_file_rules_load_and_may_be_absent(tmp_path):
    config = tmp_path / "fenceline.toml"
    config.write_text('[packages]\napp = "app"\n' + GOOD)
    assert [r.id for r in load_rule_set(config, [])] == ["t/mktemp"]
    config.write_text('[packages]\napp = "app"\n')
    assert load_rule_set(config, []) == []


def _run_cli(cwd: Path, *flags: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        [
            sys.executable,
            "-m",
            "fenceline.cli",
            "--json",
            "--quiet",
            "--package",
            "app=app",
            *flags,
        ],
        cwd=cwd,
        capture_output=True,
        text=True,
    )


@pytest.fixture
def app(tmp_path: Path) -> Path:
    pkg = tmp_path / "app"
    pkg.mkdir()
    (pkg / "mod.py").write_text("import tempfile\n\nname = tempfile.mktemp()\n")
    (tmp_path / "rules.toml").write_text(GOOD)
    return tmp_path


def test_cli_rules_add_findings_and_disable_removes_the_builtin(app):
    plain = json.loads(_run_cli(app).stdout)["findings"]
    with_rule = json.loads(_run_cli(app, "--rules", "rules.toml").stdout)["findings"]
    swapped = json.loads(
        _run_cli(app, "--rules", "rules.toml", "--disable", "check_tempfile").stdout
    )["findings"]
    assert [(f["cwe_id"], f["line"]) for f in plain] == [("CWE-377", 3)]
    assert [(f["cwe_id"], f["line"]) for f in with_rule] == [("CWE-377", 3), ("CWE-377", 3)]
    assert [(f["cwe_id"], f["line"], f["cwe_name"]) for f in swapped] == [
        ("CWE-377", 3, "Insecure Temporary File")
    ]


def test_cli_rejects_bad_rules_and_unknown_disable(app):
    (app / "bad.toml").write_text(GOOD.replace('kind = "call"', 'kind = "nope"'))
    bad = _run_cli(app, "--rules", "bad.toml")
    assert bad.returncode == 2 and "kind 'nope' is not one of" in bad.stderr
    unknown = _run_cli(app, "--disable", "check_nothing")
    assert unknown.returncode == 2 and "unknown check(s) check_nothing" in unknown.stderr
