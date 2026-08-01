from __future__ import annotations

import ast
import json
import subprocess
import sys
from pathlib import Path

import pytest

from fenceline.baseline import load_baseline, split_by_baseline, write_baseline
from fenceline.checks import CHECKS, _discover_plugin_checks
from fenceline.checks.ast_checks import (
    check_huggingface_unsafe_download,
    check_numpy_load,
    check_pandas_eval,
    check_unbounded_pydantic_field,
)
from fenceline.checks.manifest_checks import check_unbounded_pins
from fenceline.checks.text_checks import (
    check_bind_all_interfaces,
    check_debug_mode,
    check_legacy_pycrypto,
    check_pickle,
    check_weak_hash,
    check_weak_tls_version,
)
from fenceline.cli import (
    _load_packages_from_config,
    _manifest_package_label,
    discover_cwd_packages,
    resolve_packages,
)
from fenceline.config import _find_workspace_root, is_secure_path
from fenceline.models import Finding
from fenceline.reporting import print_report
from fenceline.scanner import _ast_parse, _is_self_scan_exclusion, _is_test_path, _iter_py
from fenceline.suppression import apply_suppressions


def _findings(check_fn, src: str) -> list[Finding]:
    tree = ast.parse(src)
    return check_fn(Path("x.py"), src.splitlines(), tree)


def test_checks_registry_has_every_check_once():
    names = [fn.__name__ for _, fn in CHECKS]
    assert len(names) == len(set(names))
    assert len(CHECKS) == 57


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

    findings = _findings(
        check_weak_tls_version, "ssl.wrap_socket(sock, ssl_version=ssl.PROTOCOL_SSLv3)\n"
    )
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


def test_check_huggingface_unsafe_download_flags_trust_remote_code_on_load_dataset():
    # Regression target: trust_remote_code=True carries the same RCE risk on
    # datasets.load_dataset() as it does on from_pretrained(), but the
    # original implementation only matched the from_pretrained call name.
    findings = _findings(
        check_huggingface_unsafe_download,
        'load_dataset("org/dataset", trust_remote_code=True)\n',
    )
    assert len(findings) == 1
    assert findings[0].severity == "CRITICAL"
    assert findings[0].cwe_id == "CWE-94"


def test_check_huggingface_unsafe_download_flags_trust_remote_code_on_pipeline():
    findings = _findings(
        check_huggingface_unsafe_download,
        'pipeline("text-generation", model=name, trust_remote_code=True)\n',
    )
    assert len(findings) == 1
    assert findings[0].severity == "CRITICAL"
    assert findings[0].cwe_id == "CWE-94"


def test_check_huggingface_unsafe_download_no_unpinned_revision_noise_on_load_dataset():
    # The unpinned-revision heuristic (CWE-1104) is scoped to from_pretrained
    # only -- load_dataset()/pipeline() without trust_remote_code shouldn't
    # be flagged for a risk this check was never written to assess for them.
    assert _findings(check_huggingface_unsafe_download, 'load_dataset("org/dataset")\n') == []


def test_check_unbounded_pydantic_field_flags_bare_str_field():
    # This is the real-world gap reported from a scanned FastAPI app:
    # EnrollRequest.image: str had no size limit, letting a client force
    # expensive base64 decode/CPU work with an arbitrarily large payload.
    findings = _findings(
        check_unbounded_pydantic_field,
        "class EnrollRequest(BaseModel):\n    image: str\n",
    )
    assert len(findings) == 1
    assert findings[0].cwe_id == "CWE-770"
    assert findings[0].severity == "MEDIUM"


def test_check_unbounded_pydantic_field_ignores_field_max_length():
    src = "class EnrollRequest(BaseModel):\n    image: str = Field(max_length=15_000_000)\n"
    assert _findings(check_unbounded_pydantic_field, src) == []


def test_check_unbounded_pydantic_field_ignores_annotated_field_max_length():
    src = (
        "class EnrollRequest(BaseModel):\n    image: Annotated[str, Field(max_length=15_000_000)]\n"
    )
    assert _findings(check_unbounded_pydantic_field, src) == []


def test_check_unbounded_pydantic_field_flags_optional_str_without_constraint():
    src = "class EnrollRequest(BaseModel):\n    note: Optional[str] = None\n"
    findings = _findings(check_unbounded_pydantic_field, src)
    assert len(findings) == 1


def test_check_unbounded_pydantic_field_ignores_non_str_fields():
    src = "class EnrollRequest(BaseModel):\n    count: int\n    ratio: float\n"
    assert _findings(check_unbounded_pydantic_field, src) == []


def test_check_unbounded_pydantic_field_ignores_non_basemodel_classes():
    # A plain class (not a BaseModel subclass) with an unconstrained str
    # attribute isn't network-facing request input by construction.
    src = "class NotARequestModel:\n    image: str\n"
    assert _findings(check_unbounded_pydantic_field, src) == []


def test_check_unbounded_pydantic_field_ignores_constr_annotation():
    # A field whose annotation is itself a call (constr(...)) is assumed
    # already constrained by whoever wrote it -- not this check's concern.
    src = "class EnrollRequest(BaseModel):\n    image: constr(max_length=100)\n"
    assert _findings(check_unbounded_pydantic_field, src) == []


def test_check_unbounded_pydantic_field_ignores_config_class_by_name():
    # A BaseModel subclass that isn't named like a request/input DTO (e.g.
    # an internal config/settings model) is out of scope -- without this
    # narrowing, every settings class in a codebase fires, drowning out
    # the real signal on genuine network-facing request bodies.
    src = "class FilesystemConfig(BaseModel):\n    fs_path: str\n"
    assert _findings(check_unbounded_pydantic_field, src) == []


def test_check_unbounded_pins_severity_downgraded_when_locked(tmp_path):
    # Real-world feedback: an unbounded ">=" pin is a much smaller risk when
    # a lockfile means installs resolve from it, not the manifest's own
    # range -- residual risk is at upgrade-review time, not silent install
    # drift.
    manifest = tmp_path / "pyproject.toml"
    manifest.write_text('"alembic>=1.14",\n')
    lines = manifest.read_text().splitlines()

    unlocked = check_unbounded_pins(manifest, lines, None)
    assert len(unlocked) == 1
    assert unlocked[0].severity == "LOW"

    (tmp_path / "uv.lock").write_text("")
    locked = check_unbounded_pins(manifest, lines, None)
    assert len(locked) == 1
    assert locked[0].severity == "INFO"


def test_check_unbounded_pins_recognizes_pip_compile_lockfile(tmp_path):
    # A project might declare loose ranges in pyproject.toml but lock via a
    # separately pip-compile-generated requirements.txt sitting alongside it.
    manifest = tmp_path / "pyproject.toml"
    manifest.write_text('"alembic>=1.14",\n')
    lines = manifest.read_text().splitlines()

    assert check_unbounded_pins(manifest, lines, None)[0].severity == "LOW"

    (tmp_path / "requirements.txt").write_text("alembic==1.14.0\n")
    assert check_unbounded_pins(manifest, lines, None)[0].severity == "INFO"


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


def test_ast_parse_returns_none_on_malformed_utf8_instead_of_raising(tmp_path):
    # Regression test: _ast_parse's own read_text() call had no guard against
    # a decode error, unlike _read()'s -- and this call happens outside
    # cli.py's per-check try/except, so a single malformed-UTF8 .py file
    # would have crashed the entire scan rather than just being skipped.
    bad_file = tmp_path / "bad.py"
    bad_file.write_bytes(b"import os\nx = '\xff\xfe invalid utf8'\n")
    assert _ast_parse(bad_file) is None


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


# ── Generic package registry: --config / --package / resolve_packages ──────


def test_load_packages_from_config_resolves_relative_to_config_dir(tmp_path):
    config_dir = tmp_path / "conf"
    config_dir.mkdir()
    (config_dir / "fenceline.toml").write_text('[packages]\nmy-lib = "src/my_lib"\n')

    packages = _load_packages_from_config(config_dir / "fenceline.toml", cwd=tmp_path)

    assert packages == {"my-lib": (config_dir / "src" / "my_lib").resolve()}


def test_load_packages_from_config_rejects_path_outside_allowed_roots(tmp_path):
    config_dir = tmp_path / "conf"
    config_dir.mkdir()
    (config_dir / "fenceline.toml").write_text('[packages]\nevil = "../../../etc"\n')

    with pytest.raises(SystemExit, match="outside the allowed roots"):
        _load_packages_from_config(config_dir / "fenceline.toml", cwd=tmp_path)


def test_load_packages_from_config_missing_packages_key_errors(tmp_path):
    config_path = tmp_path / "fenceline.toml"
    config_path.write_text("not_packages = {}\n")

    with pytest.raises(SystemExit, match="must define a top-level 'packages' table"):
        _load_packages_from_config(config_path, cwd=tmp_path)


def test_load_packages_from_config_bad_toml_errors(tmp_path):
    config_path = tmp_path / "fenceline.toml"
    config_path.write_text("this is not valid toml [[[\n")

    with pytest.raises(SystemExit, match="could not parse --config"):
        _load_packages_from_config(config_path, cwd=tmp_path)


def test_load_packages_from_config_missing_file_errors(tmp_path):
    with pytest.raises(SystemExit, match="could not read --config"):
        _load_packages_from_config(tmp_path / "does-not-exist.toml", cwd=tmp_path)


def test_resolve_packages_package_args_overlay_config(tmp_path):
    config_path = tmp_path / "fenceline.toml"
    config_path.write_text('[packages]\nconfigured = "src/configured"\n')

    result = resolve_packages(
        config_path=config_path,
        package_args=["extra=src/extra", "configured=src/override"],
        cwd=tmp_path,
    )

    assert result == {
        "configured": (tmp_path / "src" / "override").resolve(),
        "extra": (tmp_path / "src" / "extra").resolve(),
    }


def test_resolve_packages_package_args_alone_no_config(tmp_path):
    result = resolve_packages(config_path=None, package_args=["only=src/only"], cwd=tmp_path)
    assert result == {"only": (tmp_path / "src" / "only").resolve()}


def test_cli_config_flag_scans_configured_package(tmp_path):
    pkg_dir = tmp_path / "pkg"
    pkg_dir.mkdir()
    (pkg_dir / "mod.py").write_text("pickle.loads(data)\n")
    (tmp_path / "fenceline.toml").write_text('[packages]\npkg = "pkg"\n')

    result = subprocess.run(
        [sys.executable, "-m", "fenceline.cli", "--config", "fenceline.toml", "--json", "--quiet"],
        cwd=tmp_path,
        capture_output=True,
        text=True,
        timeout=60,
    )
    payload = json.loads(result.stdout)
    assert payload["count"] == 1


def test_cli_exclude_flag_skips_matching_paths(tmp_path):
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
            "--exclude",
            "mod.py",
            "--json",
            "--quiet",
        ],
        cwd=tmp_path,
        capture_output=True,
        text=True,
        timeout=60,
    )
    payload = json.loads(result.stdout)
    assert payload["count"] == 0


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


def _sample_finding() -> Finding:
    return Finding(
        cwe_id="CWE-502",
        cwe_name="Deserialization of Untrusted Data",
        severity="CRITICAL",
        package="pkg",
        file="mod.py",
        line=1,
        code_snippet="pickle.loads(data)",
        description="...",
    )


def test_report_hints_at_suppression_mechanisms_when_none_used_yet(capsys):
    # Real-world feedback: a first-time reader of the report has no way to
    # discover that # nosec/--baseline exist at all unless they already
    # know to look in the README.
    print_report([_sample_finding()], json_output=False)
    out = capsys.readouterr().out
    assert "# nosec" in out
    assert "--baseline" in out


def test_report_omits_suppression_hint_once_suppression_is_already_in_use(capsys):
    print_report([_sample_finding()], json_output=False, nosec_suppressed=2)
    out = capsys.readouterr().out
    assert "# nosec [CWE-ID]" not in out


def test_json_report_also_hints_at_suppression_mechanisms_when_none_used_yet(capsys):
    # Real-world feedback: a reader who only ever looks at --json output
    # never sees the text-mode footer hint at all -- the JSON payload
    # itself needs its own equivalent.
    print_report([_sample_finding()], json_output=True)
    payload = json.loads(capsys.readouterr().out)
    assert "# nosec" in payload["suppression_hint"]
    assert "--baseline" in payload["suppression_hint"]


def test_json_report_omits_suppression_hint_once_suppression_is_already_in_use(capsys):
    print_report([_sample_finding()], json_output=True, nosec_suppressed=2)
    payload = json.loads(capsys.readouterr().out)
    assert "suppression_hint" not in payload


def test_discover_plugin_checks_loads_registered_entry_point(monkeypatch):
    def fake_check(path, lines, tree):
        return []

    class FakeEntryPoint:
        name = "My Plugin Check (CWE-000)"

        def load(self):
            return fake_check

    monkeypatch.setattr("fenceline.checks.entry_points", lambda group: [FakeEntryPoint()])
    discovered = _discover_plugin_checks()
    assert discovered == [("My Plugin Check (CWE-000)", fake_check)]


def test_discover_plugin_checks_skips_a_broken_plugin_without_crashing(monkeypatch):
    class BrokenEntryPoint:
        name = "Broken Plugin"

        def load(self):
            raise ImportError("third-party package not installed")

    monkeypatch.setattr("fenceline.checks.entry_points", lambda group: [BrokenEntryPoint()])
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


def test_is_secure_path_inlined_matches_boti_core_semantics(tmp_path):
    # fenceline no longer depends on boti at runtime (§ generic pip-install
    # story) -- is_secure_path is reimplemented locally in config.py and
    # must behave the same: accept nested paths, reject paths outside every
    # allowed root.
    nested = tmp_path / "a"
    nested.mkdir()
    other = tmp_path.parent / "definitely-not-a-real-sibling-dir-xyz"
    assert is_secure_path(nested, [tmp_path])
    assert not is_secure_path(other, [tmp_path])


def test_discover_cwd_packages_registers_each_subdir_containing_python(tmp_path):
    (tmp_path / "pkg_a").mkdir()
    (tmp_path / "pkg_a" / "mod.py").write_text("x = 1\n")
    (tmp_path / "pkg_b" / "nested").mkdir(parents=True)
    (tmp_path / "pkg_b" / "nested" / "mod.py").write_text("y = 2\n")
    (tmp_path / "no_python").mkdir()
    (tmp_path / "no_python" / "readme.txt").write_text("nothing here\n")

    packages, loose_root_name = discover_cwd_packages(tmp_path)

    assert set(packages) == {"pkg_a", "pkg_b"}
    assert loose_root_name is None


def test_discover_cwd_packages_groups_loose_root_files_separately(tmp_path):
    (tmp_path / "loose.py").write_text("z = 3\n")
    (tmp_path / "pkg_a").mkdir()
    (tmp_path / "pkg_a" / "mod.py").write_text("x = 1\n")

    packages, loose_root_name = discover_cwd_packages(tmp_path)

    assert loose_root_name == tmp_path.resolve().name
    assert set(packages) == {"pkg_a", loose_root_name}
    assert packages[loose_root_name] == tmp_path


def test_discover_cwd_packages_skips_noise_directories(tmp_path):
    for noise in (".venv", "__pycache__", "node_modules", ".git"):
        (tmp_path / noise).mkdir()
        (tmp_path / noise / "junk.py").write_text("# not real code\n")
    (tmp_path / "real_pkg").mkdir()
    (tmp_path / "real_pkg" / "mod.py").write_text("x = 1\n")

    packages, _ = discover_cwd_packages(tmp_path)

    assert set(packages) == {"real_pkg"}


def test_manifest_package_label_uses_owning_package_when_manifest_is_local(tmp_path):
    packages = {"evaluation": tmp_path / "evaluation", "migrations": tmp_path / "migrations"}
    manifest = tmp_path / "evaluation" / "pyproject.toml"
    assert _manifest_package_label(manifest, packages) == "evaluation"


def test_manifest_package_label_falls_back_to_parent_dir_name_for_shared_manifest():
    # Real-world bug report: a manifest shared above every package's own
    # root (the scanned project's top-level pyproject.toml, found by every
    # package's upward search once it climbs past its own directory) must
    # not be attributed to whichever package's dict.setdefault reached it
    # first -- it should be traceable to where it actually lives instead.
    packages = {
        "evaluation": Path("/proj/evaluation"),
        "migrations": Path("/proj/migrations"),
    }
    manifest = Path("/proj/pyproject.toml")
    assert _manifest_package_label(manifest, packages) == "proj"


def test_cli_bare_invocation_auto_discovers_cwd_instead_of_erroring(tmp_path):
    # The core "generic pip-install-anywhere" behaviour: no --package given,
    # no ambient uv workspace at tmp_path -- must scan tmp_path itself
    # instead of failing with "no packages to scan".
    pkg_dir = tmp_path / "myproject"
    pkg_dir.mkdir()
    (pkg_dir / "mod.py").write_text("pickle.loads(data)\n")

    result = subprocess.run(
        [sys.executable, "-m", "fenceline.cli", "--json", "--quiet"],
        cwd=tmp_path,
        capture_output=True,
        text=True,
        timeout=60,
    )
    assert result.returncode in (0, 1)
    payload = json.loads(result.stdout)
    cwe_ids = {f["cwe_id"] for f in payload["findings"] if f["file"].endswith("mod.py")}
    assert "CWE-502" in cwe_ids


def test_cli_packages_selector_filters_resolved_registry(tmp_path):
    (tmp_path / "pkg_a").mkdir()
    (tmp_path / "pkg_a" / "mod.py").write_text("pickle.loads(data)\n")
    (tmp_path / "pkg_b").mkdir()
    (tmp_path / "pkg_b" / "mod.py").write_text("eval(user_input)\n")

    result = subprocess.run(
        [sys.executable, "-m", "fenceline.cli", "--packages", "pkg_a", "--json", "--quiet"],
        cwd=tmp_path,
        capture_output=True,
        text=True,
        timeout=60,
    )
    assert result.returncode in (0, 1)
    payload = json.loads(result.stdout)
    files = {f["file"] for f in payload["findings"]}
    assert any("pkg_a" in f for f in files)
    assert not any("pkg_b" in f for f in files)


def test_cli_packages_selector_rejects_unknown_name(tmp_path):
    (tmp_path / "pkg_a").mkdir()
    (tmp_path / "pkg_a" / "mod.py").write_text("x = 1\n")

    result = subprocess.run(
        [sys.executable, "-m", "fenceline.cli", "--packages", "not-a-real-package"],
        cwd=tmp_path,
        capture_output=True,
        text=True,
        timeout=60,
    )
    assert result.returncode != 0
    assert "unknown package" in result.stderr


def test_cli_shared_root_manifest_not_misattributed_to_first_scanned_package(tmp_path):
    # End-to-end reproduction of a real bug report: a root-level
    # pyproject.toml shared above two auto-discovered packages must not be
    # attributed to whichever one happens first in scan order.
    (tmp_path / "pyproject.toml").write_text('"alembic>=1.14",\n')
    (tmp_path / "evaluation").mkdir()
    (tmp_path / "evaluation" / "mod.py").write_text("x = 1\n")
    (tmp_path / "migrations").mkdir()
    (tmp_path / "migrations" / "mod.py").write_text("y = 2\n")

    result = subprocess.run(
        [sys.executable, "-m", "fenceline.cli", "--json", "--quiet"],
        cwd=tmp_path,
        capture_output=True,
        text=True,
        timeout=60,
    )
    payload = json.loads(result.stdout)
    manifest_findings = [f for f in payload["findings"] if f["file"].endswith("pyproject.toml")]
    assert manifest_findings
    for f in manifest_findings:
        assert f["package"] not in ("evaluation", "migrations")
        assert f["package"] == tmp_path.name


def test_is_test_path_recognizes_pytest_conventions():
    assert _is_test_path("tests/test_foo.py")
    assert _is_test_path("pkg/tests/helpers.py")
    assert _is_test_path("pkg/test_foo.py")
    assert _is_test_path("pkg/foo_test.py")
    assert _is_test_path("pkg/conftest.py")
    assert _is_test_path("test/foo.py")


def test_is_test_path_ignores_production_code():
    assert not _is_test_path("pkg/mod.py")
    assert not _is_test_path("pkg/attestation.py")  # contains "test" as a substring, not a token
    assert not _is_test_path("pkg/testing_utils.py")  # not test_*/​*_test naming convention
    # "evaluation/" is deliberately NOT recognized by default -- see
    # _is_test_path's own docstring for why a codebase-specific directory
    # name isn't safe to hardcode as a universal "not production" signal.
    assert not _is_test_path("evaluation/load_test_identify.py")


def test_is_test_path_recognizes_extra_dir_names_when_given():
    # Real-world feedback follow-up: a project's own non-production
    # directory (e.g. an "evaluation/" load-test harness) can be declared
    # explicitly via --test-paths rather than fenceline guessing.
    assert _is_test_path("evaluation/load_test_identify.py", frozenset({"evaluation"}))
    assert not _is_test_path("evaluation/load_test_identify.py", frozenset({"benchmarks"}))


def test_cli_test_paths_suppresses_findings_in_custom_directory(tmp_path):
    # Filename deliberately doesn't match test_*.py/*_test.py/conftest.py --
    # only the --test-paths directory declaration should suppress this one.
    (tmp_path / "evaluation").mkdir()
    (tmp_path / "evaluation" / "load_scenario.py").write_text("urllib.request.urlopen(some_url)\n")
    (tmp_path / "pkg").mkdir()
    (tmp_path / "pkg" / "mod.py").write_text("urllib.request.urlopen(some_url)\n")

    default_run = subprocess.run(
        [sys.executable, "-m", "fenceline.cli", "--json", "--quiet"],
        cwd=tmp_path,
        capture_output=True,
        text=True,
        timeout=60,
    )
    default_payload = json.loads(default_run.stdout)
    default_files = {f["file"] for f in default_payload["findings"]}
    assert any("evaluation/" in f for f in default_files)

    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "fenceline.cli",
            "--test-paths",
            "evaluation",
            "--json",
            "--quiet",
        ],
        cwd=tmp_path,
        capture_output=True,
        text=True,
        timeout=60,
    )
    payload = json.loads(result.stdout)
    files = {f["file"] for f in payload["findings"]}
    assert not any("evaluation/" in f for f in files)
    assert any("pkg/" in f for f in files)
    assert payload.get("test_suppressed", 0) >= 1


def test_cli_version_flag_reports_installed_version():
    result = subprocess.run(
        [sys.executable, "-m", "fenceline.cli", "--version"],
        capture_output=True,
        text=True,
        timeout=60,
    )
    assert result.returncode == 0
    assert "fenceline" in result.stdout


def test_cli_deprioritized_cwes_suppressed_by_default_in_test_paths(tmp_path):
    # Real-world feedback: CWE-798/617/918/770 findings inside test code
    # (testcontainers fixtures, pytest assertions, hardcoded localhost test
    # URLs, small fixture reads) fired at the same severity as a genuine
    # production hit, drowning out real findings in the same category.
    (tmp_path / "tests").mkdir()
    (tmp_path / "tests" / "conftest.py").write_text(
        'password = "hunter2"\nurllib.request.urlopen("http://127.0.0.1:8000")\n'
    )
    (tmp_path / "pkg").mkdir()
    (tmp_path / "pkg" / "mod.py").write_text('password = "hunter2"\n')

    default_run = subprocess.run(
        [sys.executable, "-m", "fenceline.cli", "--json", "--quiet"],
        cwd=tmp_path,
        capture_output=True,
        text=True,
        timeout=60,
    )
    default_payload = json.loads(default_run.stdout)
    default_files = {f["file"] for f in default_payload["findings"]}
    assert not any("tests/" in f for f in default_files)
    assert any("pkg/" in f for f in default_files)
    assert default_payload.get("test_suppressed", 0) >= 1

    included_run = subprocess.run(
        [sys.executable, "-m", "fenceline.cli", "--include-tests", "--json", "--quiet"],
        cwd=tmp_path,
        capture_output=True,
        text=True,
        timeout=60,
    )
    included_payload = json.loads(included_run.stdout)
    included_files = {f["file"] for f in included_payload["findings"]}
    assert any("tests/" in f for f in included_files)
    assert "test_suppressed" not in included_payload
