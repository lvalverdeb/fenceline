from __future__ import annotations

import ast
import subprocess
import sys
from pathlib import Path

from tripwire.checks import CHECKS
from tripwire.checks.ast_checks import check_numpy_load, check_pandas_eval
from tripwire.checks.text_checks import check_pickle
from tripwire.config import DEFAULT_PACKAGES, WORKSPACE_ROOT
from tripwire.models import Finding


def _findings(check_fn, src: str) -> list[Finding]:
    tree = ast.parse(src)
    return check_fn(Path("x.py"), src.splitlines(), tree)


def test_checks_registry_has_every_check_once():
    names = [fn.__name__ for _, fn in CHECKS]
    assert len(names) == len(set(names))
    assert len(CHECKS) == 52


def test_every_check_is_callable_and_returns_a_list():
    src = "import os\nos.system('ls')\n"
    tree = ast.parse(src)
    lines = src.splitlines()
    for _, check_fn in CHECKS:
        result = check_fn(Path("x.py"), lines, tree)
        assert isinstance(result, list)


def test_check_pickle_flags_pickle_loads():
    findings = _findings(check_pickle, "pickle.loads(data)\n")
    assert len(findings) == 1
    assert findings[0].severity == "CRITICAL"


def test_check_pandas_eval_ignores_docstrings_and_comments():
    # Regression test: the original line-regex implementation flagged any
    # non-comment line mentioning ".eval("/".query(", including docstrings.
    src = '"""Use df.eval() carefully."""\n# df.query("a > 1") in a comment\n'
    assert _findings(check_pandas_eval, src) == []


def test_check_pandas_eval_flags_real_calls():
    findings = _findings(check_pandas_eval, 'result = df.query("a > 1")\n')
    assert len(findings) == 1
    assert findings[0].severity == "HIGH"


def test_check_numpy_load_flags_explicit_allow_pickle_true_only():
    # Regression test: the original implementation had the condition
    # inverted — it flagged the absence of allow_pickle (numpy's own safe
    # default) and stayed silent on the actually dangerous allow_pickle=True.
    assert _findings(check_numpy_load, "np.load(f)\n") == []
    assert _findings(check_numpy_load, "np.load(f, allow_pickle=False)\n") == []
    findings = _findings(check_numpy_load, "np.load(f, allow_pickle=True)\n")
    assert len(findings) == 1
    assert findings[0].severity == "HIGH"


def test_default_packages_resolve_inside_workspace_root():
    for path in DEFAULT_PACKAGES.values():
        assert path.is_relative_to(WORKSPACE_ROOT)


def test_cli_json_output_is_well_formed():
    result = subprocess.run(
        [sys.executable, "-m", "tripwire.cli", "--package", f"boti={WORKSPACE_ROOT / 'boti' / 'src' / 'boti'}", "--json", "--quiet"],
        capture_output=True,
        text=True,
        timeout=60,
    )
    assert result.returncode in (0, 1)
    import json

    payload = json.loads(result.stdout)
    assert "findings" in payload and "count" in payload
