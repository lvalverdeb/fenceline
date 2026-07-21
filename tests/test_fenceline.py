from __future__ import annotations

import ast
import json
import subprocess
import sys
from pathlib import Path

from fenceline.baseline import load_baseline, split_by_baseline, write_baseline
from fenceline.checks import CHECKS, _discover_plugin_checks
from fenceline.checks.ast_checks import (
    check_huggingface_unsafe_download,
    check_numpy_load,
    check_pandas_eval,
)
from fenceline.checks.text_checks import (
    check_bind_all_interfaces,
    check_debug_mode,
    check_legacy_pycrypto,
    check_pickle,
    check_weak_hash,
    check_weak_tls_version,
)
from fenceline.config import DEFAULT_PACKAGES, WORKSPACE_ROOT, _find_workspace_root
from fenceline.models import Finding
from fenceline.scanner import _is_self_scan_exclusion, _iter_py
from fenceline.suppression import apply_suppressions


def _findings(check_fn, src: str) -> list[Finding]:
    tree = ast.parse(src)
    return check_fn(Path("x.py"), src.splitlines(), tree)


def test_checks_registry_has_every_check_once():
    names = [fn.__name__ for _, fn in CHECKS]
    assert len(names) == len(set(names))
    assert len(CHECKS) == 56


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


def test_check_bind_all_interfaces_flags_host_bound_to_all_interfaces():
    findings = _findings(check_bind_all_interfaces, 'uvicorn.run(app, host="0.0.0.0", port=7700)\n')
    assert len(findings) == 1
    assert findings[0].severity == "MEDIUM"
    assert findings[0].cwe_id == "CWE-1327"


def test_check_weak_hash_flags_direct_call_and_new_indirection():
    direct = _findings(check_weak_hash, "hashlib.md5(data).hexdigest()\n")
    assert len(direct) == 1
    assert direct[0].cwe_id == "CWE-328"

    # Regression target: hashlib.new("md5", data) reaches the same weak
    # algorithm through the generic constructor rather than the dedicated
    # hashlib.md5() function — a direct-call-only pattern misses it.
    indirect = _findings(check_weak_hash, 'hashlib.new("md5", data).hexdigest()\n')
    assert len(indirect) == 1
    assert indirect[0].cwe_id == "CWE-328"


def test_check_weak_hash_ignores_strong_new_algorithm():
    assert _findings(check_weak_hash, 'hashlib.new("sha256", data).hexdigest()\n') == []


def test_check_weak_tls_version_flags_deprecated_protocols():
    findings = _findings(check_weak_tls_version, "ctx = ssl.SSLContext(ssl.PROTOCOL_TLSv1)\n")
    assert len(findings) == 1
    assert findings[0].severity == "HIGH"
    assert findings[0].cwe_id == "CWE-326"

    findings = _findings(check_weak_tls_version, "ssl.wrap_socket(sock, ssl_version=ssl.PROTOCOL_SSLv3)\n")
    assert len(findings) == 1


def test_check_weak_tls_version_ignores_modern_protocols():
    # TLSv1_2/TLSv1_3 must not match: the word-boundary check after
    # "PROTOCOL_TLSv1" fails to find a boundary before the following "_"
    # (both are \w characters), so the pattern can't partially match here.
    assert _findings(check_weak_tls_version, "ssl.SSLContext(ssl.PROTOCOL_TLSv1_2)\n") == []
    assert _findings(check_weak_tls_version, "ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)\n") == []


def test_check_legacy_pycrypto_flags_old_package_import():
    findings = _findings(check_legacy_pycrypto, "from Crypto.Cipher import AES\n")
    assert len(findings) == 1
    assert findings[0].cwe_id == "CWE-1104"
    assert _findings(check_legacy_pycrypto, "import Crypto\n") != []


def test_check_legacy_pycrypto_ignores_maintained_fork():
    # "Cryptodome" must not match: there's no word boundary between the "o"
    # ending "Crypto" and the "d" starting "dome" (both are \w characters).
    assert _findings(check_legacy_pycrypto, "from Cryptodome.Cipher import AES\n") == []
    assert _findings(check_legacy_pycrypto, "import Cryptodome\n") == []


def test_check_huggingface_unsafe_download_flags_trust_remote_code():
    findings = _findings(
        check_huggingface_unsafe_download,
        'AutoModel.from_pretrained("org/model", trust_remote_code=True)\n',
    )
    assert len(findings) == 1
    assert findings[0].severity == "CRITICAL"
    assert findings[0].cwe_id == "CWE-94"


def test_check_huggingface_unsafe_download_flags_unpinned_revision():
    findings = _findings(
        check_huggingface_unsafe_download, 'AutoTokenizer.from_pretrained("org/model")\n'
    )
    assert len(findings) == 1
    assert findings[0].severity == "MEDIUM"
    assert findings[0].cwe_id == "CWE-1104"


def test_check_huggingface_unsafe_download_ignores_pinned_revision():
    findings = _findings(
        check_huggingface_unsafe_download,
        'AutoModel.from_pretrained("org/model", revision="a1b2c3d")\n',
    )
    assert findings == []


def test_check_bind_all_interfaces_ignores_cidr_ranges():
    # A CIDR range like "0.0.0.0/0" (or "10.0.0.0/8") is a network/ACL
    # notation, not a literal bind-to-all-interfaces host string — the
    # trailing "/N" means the closing quote never immediately follows
    # "0.0.0.0", so the pattern must not fire on it.
    assert _findings(check_bind_all_interfaces, 'ipaddress.ip_network("0.0.0.0/0")\n') == []


def test_iter_py_excludes_fencelines_own_check_definition_files(tmp_path):
    # Regression test: these files are guaranteed to trip fenceline's own
    # checks when scanned, since they define the exact regex patterns/CVE
    # tables/function names those checks search for (e.g. text_checks.py's
    # own r"pickle\.loads?\s*\(" pattern contains the literal substring
    # "pickle.loads(" and matches itself). See _SELF_SCAN_EXCLUDE.
    pkg = tmp_path / "fenceline"
    (pkg / "checks").mkdir(parents=True)
    (pkg / "checks" / "__init__.py").write_text("CHECKS = []\n")
    (pkg / "checks" / "text_checks.py").write_text("PATTERN = r'pickle.loads('\n")
    (pkg / "checks" / "ast_checks.py").write_text("# ast checks\n")
    (pkg / "checks" / "manifest_checks.py").write_text("# manifest checks\n")
    (pkg / "ast_helpers.py").write_text("# helpers\n")
    (pkg / "reporting.py").write_text("# report\n")
    # Real plumbing — must still be scanned.
    (pkg / "cli.py").write_text("import sys\n")
    (pkg / "scanner.py").write_text("import ast\n")

    found = {p.name for p in _iter_py(pkg)}
    assert found == {"cli.py", "scanner.py"}


def test_is_self_scan_exclusion_matches_by_suffix_not_absolute_path():
    # Matching is by trailing path parts, not "is this exactly fenceline's
    # installed package" — so it works the same whether the package root
    # came from the default registry or an explicit --package override
    # pointing at a differently-located checkout.
    assert _is_self_scan_exclusion(Path("/anywhere/src/fenceline/reporting.py"))
    assert _is_self_scan_exclusion(Path("/other/checkout/fenceline/checks/text_checks.py"))
    assert not _is_self_scan_exclusion(Path("/anywhere/src/fenceline/cli.py"))
    assert not _is_self_scan_exclusion(Path("/anywhere/src/boti_data/reporting.py"))


def test_default_packages_resolve_inside_workspace_root():
    # Vacuously true when no ambient workspace was found (e.g. fenceline's own
    # standalone CI checkout) — DEFAULT_PACKAGES is empty in that case.
    for path in DEFAULT_PACKAGES.values():
        assert WORKSPACE_ROOT is not None
        assert path.is_relative_to(WORKSPACE_ROOT)


def test_find_workspace_root_returns_none_when_absent(tmp_path):
    # Regression test: this used to be a hard RuntimeError raised at import
    # time, which broke importing fenceline.config (and therefore this whole
    # test module) in any standalone checkout with no ancestor
    # [tool.uv.workspace] — exactly what fenceline's own GitHub Actions
    # checkout looks like.
    assert _find_workspace_root(tmp_path) is None


def test_find_workspace_root_finds_ancestor_workspace_marker(tmp_path):
    (tmp_path / "pyproject.toml").write_text("[tool.uv.workspace]\nmembers = []\n")
    nested = tmp_path / "a" / "b"
    nested.mkdir(parents=True)
    assert _find_workspace_root(nested) == tmp_path


def test_cli_json_output_is_well_formed(tmp_path):
    # Self-contained fixture rather than depending on the ambient boti
    # package: the latter doesn't exist in fenceline's own standalone
    # checkout. --package is resolved relative to cwd, and cwd is always an
    # allowed root, so pointing the subprocess's cwd at tmp_path works
    # identically whether or not an ambient workspace is present.
    pkg_dir = tmp_path / "pkg"
    pkg_dir.mkdir()
    (pkg_dir / "mod.py").write_text("pickle.loads(data)\n")
    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "fenceline.cli",
            "--package",
            "pkg=pkg",
            "--json",
            "--quiet",
        ],
        cwd=tmp_path,
        capture_output=True,
        text=True,
        timeout=60,
    )
    assert result.returncode in (0, 1)
    payload = json.loads(result.stdout)
    assert "findings" in payload and "count" in payload


def test_finding_confidence_defaults_to_medium():
    findings = _findings(check_pickle, "pickle.loads(data)\n")
    assert len(findings) == 1
    assert findings[0].confidence == "MEDIUM"


def test_ast_checks_report_high_confidence():
    # AST-based checks match a real Call/ExceptHandler node, not just a
    # substring, so they're tagged HIGH rather than the text-check default.
    findings = _findings(check_pandas_eval, 'result = df.query("a > 1")\n')
    assert len(findings) == 1
    assert findings[0].confidence == "HIGH"


def test_heuristic_text_checks_report_low_confidence():
    findings = _findings(check_debug_mode, "app.run(debug=True)\n")
    assert len(findings) == 1
    assert findings[0].confidence == "LOW"


def test_apply_suppressions_bare_nosec_suppresses_everything_on_the_line():
    src = "pickle.loads(data)  # nosec\n"
    findings = _findings(check_pickle, src)
    assert len(findings) == 1
    kept, suppressed = apply_suppressions(findings, src.splitlines())
    assert kept == []
    assert suppressed == 1


def test_apply_suppressions_scoped_nosec_only_suppresses_listed_cwes():
    src = "pickle.loads(data)  # nosec CWE-999\n"
    findings = _findings(check_pickle, src)
    assert len(findings) == 1
    kept, suppressed = apply_suppressions(findings, src.splitlines())
    # CWE-502 (pickle's real ID) isn't in the nosec scope (CWE-999), so the
    # finding must survive rather than being silently dropped.
    assert len(kept) == 1
    assert suppressed == 0


def test_apply_suppressions_matching_scoped_cwe_is_suppressed():
    src = "pickle.loads(data)  # nosec CWE-502\n"
    findings = _findings(check_pickle, src)
    assert len(findings) == 1
    kept, suppressed = apply_suppressions(findings, src.splitlines())
    assert kept == []
    assert suppressed == 1


def test_baseline_round_trip_suppresses_only_matching_findings(tmp_path):
    old = Finding(
        cwe_id="CWE-502",
        cwe_name="Deserialization of Untrusted Data",
        severity="CRITICAL",
        package="",
        file="mod.py",
        line=1,
        code_snippet="pickle.loads(data)",
        description="...",
    )
    new = Finding(
        cwe_id="CWE-94",
        cwe_name="Code Injection",
        severity="CRITICAL",
        package="",
        file="mod.py",
        line=5,
        code_snippet="eval(user_input)",
        description="...",
    )
    baseline_path = tmp_path / "baseline.json"
    write_baseline([old], baseline_path)

    loaded = load_baseline(baseline_path)
    kept, suppressed = split_by_baseline([old, new], loaded)
    assert kept == [new]
    assert suppressed == 1


def test_baseline_matches_by_fingerprint_not_line_number(tmp_path):
    # The baseline must survive unrelated edits shifting line numbers --
    # fingerprint is (cwe_id, file, code_snippet), not line.
    original = Finding(
        cwe_id="CWE-502",
        cwe_name="Deserialization of Untrusted Data",
        severity="CRITICAL",
        package="",
        file="mod.py",
        line=10,
        code_snippet="pickle.loads(data)",
        description="...",
    )
    shifted = Finding(
        cwe_id="CWE-502",
        cwe_name="Deserialization of Untrusted Data",
        severity="CRITICAL",
        package="",
        file="mod.py",
        line=25,  # shifted down by unrelated edits above it
        code_snippet="pickle.loads(data)",
        description="...",
    )
    baseline_path = tmp_path / "baseline.json"
    write_baseline([original], baseline_path)
    kept, suppressed = split_by_baseline([shifted], load_baseline(baseline_path))
    assert kept == []
    assert suppressed == 1


def test_discover_plugin_checks_loads_registered_entry_point(monkeypatch):
    def fake_check(path, lines, tree):
        return []

    class FakeEntryPoint:
        name = "My Plugin Check (CWE-000)"

        def load(self):
            return fake_check

    monkeypatch.setattr(
        "fenceline.checks.entry_points", lambda group: [FakeEntryPoint()]
    )
    discovered = _discover_plugin_checks()
    assert discovered == [("My Plugin Check (CWE-000)", fake_check)]


def test_discover_plugin_checks_skips_a_broken_plugin_without_crashing(monkeypatch):
    class BrokenEntryPoint:
        name = "Broken Plugin"

        def load(self):
            raise ImportError("third-party package not installed")

    monkeypatch.setattr(
        "fenceline.checks.entry_points", lambda group: [BrokenEntryPoint()]
    )
    # Must not raise -- one broken third-party plugin shouldn't take down
    # discovery for every other check.
    assert _discover_plugin_checks() == []


def test_cli_confidence_min_filters_out_low_confidence_findings(tmp_path):
    pkg_dir = tmp_path / "pkg"
    pkg_dir.mkdir()
    # check_debug_mode is LOW confidence; check_pickle is MEDIUM.
    (pkg_dir / "mod.py").write_text("app.run(debug=True)\npickle.loads(data)\n")

    result_all = subprocess.run(
        [sys.executable, "-m", "fenceline.cli", "--package", "pkg=pkg", "--json", "--quiet"],
        cwd=tmp_path,
        capture_output=True,
        text=True,
        timeout=60,
    )
    payload_all = json.loads(result_all.stdout)
    cwes_all = {f["cwe_id"] for f in payload_all["findings"] if f["file"].endswith("mod.py")}
    assert "CWE-489" in cwes_all  # the LOW-confidence debug-mode finding

    result_filtered = subprocess.run(
        [
            sys.executable,
            "-m",
            "fenceline.cli",
            "--package",
            "pkg=pkg",
            "--confidence-min",
            "medium",
            "--json",
            "--quiet",
        ],
        cwd=tmp_path,
        capture_output=True,
        text=True,
        timeout=60,
    )
    payload_filtered = json.loads(result_filtered.stdout)
    cwes_filtered = {
        f["cwe_id"] for f in payload_filtered["findings"] if f["file"].endswith("mod.py")
    }
    assert "CWE-489" not in cwes_filtered  # dropped by --confidence-min medium
    assert "CWE-502" in cwes_filtered  # pickle stays -- MEDIUM meets the threshold


def test_cli_write_baseline_then_baseline_suppresses_pre_existing_findings(tmp_path):
    pkg_dir = tmp_path / "pkg"
    pkg_dir.mkdir()
    (pkg_dir / "mod.py").write_text("pickle.loads(data)\n")
    baseline_path = tmp_path / "baseline.json"

    write_result = subprocess.run(
        [
            sys.executable,
            "-m",
            "fenceline.cli",
            "--package",
            "pkg=pkg",
            "--write-baseline",
            str(baseline_path),
            "--json",
            "--quiet",
        ],
        cwd=tmp_path,
        capture_output=True,
        text=True,
        timeout=60,
    )
    assert write_result.returncode == 0
    assert baseline_path.exists()

    # Same code, same findings -- but now baselined, so nothing new to report.
    rerun_result = subprocess.run(
        [
            sys.executable,
            "-m",
            "fenceline.cli",
            "--package",
            "pkg=pkg",
            "--baseline",
            str(baseline_path),
            "--json",
            "--quiet",
        ],
        cwd=tmp_path,
        capture_output=True,
        text=True,
        timeout=60,
    )
    payload = json.loads(rerun_result.stdout)
    pkg_findings = [f for f in payload["findings"] if f["file"].endswith("mod.py")]
    assert pkg_findings == []
    assert payload.get("baseline_suppressed", 0) >= 1
