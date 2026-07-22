"""Aggregates every check function into a single ordered CHECKS registry.

Each entry is ``(display_name, check_fn)``; ``check_fn`` receives
``(path, lines, tree)`` and returns ``list[Finding]``. See
:mod:`fenceline.checks.ast_checks`, :mod:`fenceline.checks.text_checks`,
and :mod:`fenceline.checks.manifest_checks` for the implementations.

Third-party packages can register additional checks without touching this
file, by declaring an entry point in the ``fenceline.checks`` group in their
own ``pyproject.toml``::

    [project.entry-points."fenceline.checks"]
    "My Custom Check (CWE-000)" = "my_package.checks:my_check_function"

The entry point's own name is used as the check's display name; the object
it loads must be a check function with the same ``(path, lines, tree) ->
list[Finding]`` signature every built-in check has. Built-in checks are
*not* themselves routed through entry points -- there's no benefit to
indirecting checks fenceline ships with itself through a discovery
mechanism meant for external extension, the same way pytest's own built-in
behavior isn't implemented as a "plugin" of itself even though third-party
pytest plugins use exactly that mechanism.
"""

from __future__ import annotations

import sys
from collections.abc import Callable
from importlib.metadata import entry_points

from fenceline.checks.ast_checks import (
    check_decode_exec_chains,
    check_eval_exec,
    check_except_pass,
    check_format_string,
    check_huggingface_unsafe_download,
    check_insecure_default,
    check_insecure_random,
    check_insufficient_logging,
    check_numpy_load,
    check_pandas_eval,
    check_parquet_arrow_deserialize,
    check_request_timeout,
    check_torch_load,
    check_unbounded_pydantic_field,
)
from fenceline.checks.manifest_checks import (
    check_dependency_cve,
    check_unbounded_pins,
)
from fenceline.checks.text_checks import (
    check_arbitrary_write,
    check_assert_security,
    check_bind_all_interfaces,
    check_command_injection,
    check_crlf,
    check_debug_mode,
    check_exec_driver_sql,
    check_hardcoded_secrets,
    check_hardcoded_tokens,
    check_ldap,
    check_legacy_pycrypto,
    check_log_injection,
    check_log_secrets,
    check_model_file_load,
    check_null_byte,
    check_numpy_load_lib,
    check_open_redirect,
    check_pandas_pickle,
    check_pandas_xml_xxe,
    check_path_traversal,
    check_pickle,
    check_pth_startup_hooks,
    check_redos,
    check_resource_limits,
    check_sensitive_exposure,
    check_sql_injection,
    check_ssh_host_key,
    check_ssrf,
    check_ssti,
    check_supply_chain,
    check_symlink,
    check_tempfile,
    check_timing_attack,
    check_tls_verify,
    check_trojan_source,
    check_weak_crypto,
    check_weak_hash,
    check_weak_tls_version,
    check_xxe,
    check_yaml_deserialize,
    check_zipslip,
)
from fenceline.models import Finding

__all__ = ["CHECKS"]

CheckFn = Callable[..., list[Finding]]

_BUILTIN_CHECKS: list[tuple[str, CheckFn]] = [
    ("Pickle Deserialization (CWE-502)", check_pickle),
    ("eval/exec/compile Injection (CWE-94)", check_eval_exec),
    ("Command Injection (CWE-78)", check_command_injection),
    ("SQL Injection (CWE-89)", check_sql_injection),
    ("Path Traversal (CWE-22)", check_path_traversal),
    ("Hardcoded Secrets (CWE-798)", check_hardcoded_secrets),
    ("YAML Unsafe Deserialization (CWE-502)", check_yaml_deserialize),
    ("XXE (CWE-611)", check_xxe),
    ("SSRF (CWE-918)", check_ssrf),
    ("Insecure Temp File (CWE-377)", check_tempfile),
    ("Symlink Following (CWE-61)", check_symlink),
    ("ReDoS (CWE-1333)", check_redos),
    ("Assert Security (CWE-617/670)", check_assert_security),
    ("exec_driver_sql Safety (CWE-89)", check_exec_driver_sql),
    ("Supply Chain Dep Confusion (CWE-1104)", check_supply_chain),
    ("Active Debug Code (CWE-489)", check_debug_mode),
    ("Insufficient Logging (CWE-778)", check_insufficient_logging),
    ("Timing Attack (CWE-208)", check_timing_attack),
    ("Sensitive Exposure (CWE-200)", check_sensitive_exposure),
    ("NUL Byte Injection (CWE-158)", check_null_byte),
    ("Resource Limits (CWE-770)", check_resource_limits),
    ("Insecure Random (CWE-338)", check_insecure_random),
    ("SSTI (CWE-1336)", check_ssti),
    ("CRLF Injection (CWE-93)", check_crlf),
    ("LDAP Injection (CWE-90)", check_ldap),
    ("Weak Hash (CWE-328)", check_weak_hash),
    ("Open Redirect (CWE-601)", check_open_redirect),
    ("Log Injection (CWE-117)", check_log_injection),
    ("Format String (CWE-134)", check_format_string),
    ("Arbitrary File Write (CWE-73)", check_arbitrary_write),
    ("Insecure Default (CWE-453)", check_insecure_default),
    ("Log Secrets (CWE-532)", check_log_secrets),
    ("Disabled TLS Verify (CWE-295)", check_tls_verify),
    ("ZipSlip / TarSlip (CWE-22)", check_zipslip),
    ("Hardcoded API Keys (CWE-798)", check_hardcoded_tokens),
    ("Weak Crypto (CWE-327)", check_weak_crypto),
    ("Dependency CVE Scan (CWE-1104)", check_dependency_cve),
    ("Trojan Source (CWE-1007)", check_trojan_source),
    ("HTTP Request Timeout (CWE-1088)", check_request_timeout),
    ("torch.load weights_only (CWE-502)", check_torch_load),
    ("SSH Host Key Verification (CWE-322)", check_ssh_host_key),
    ("except:pass/continue (CWE-391)", check_except_pass),
    ("pandas eval/query Code Injection (CWE-94)", check_pandas_eval),
    ("numpy.load allow_pickle (CWE-502)", check_numpy_load),
    ("pandas.read_pickle (CWE-502)", check_pandas_pickle),
    ("numpy.load library injection (CWE-114)", check_numpy_load_lib),
    ("pandas.read_xml XXE (CWE-611)", check_pandas_xml_xxe),
    (".pth Startup Hooks (CWE-829 / T1546.018)", check_pth_startup_hooks),
    ("Parquet Arrow Deserialization (CWE-502 / CVE-2026-41486)", check_parquet_arrow_deserialize),
    ("Unbounded Dependency Pins (CWE-1104)", check_unbounded_pins),
    ("ML Model File Loading (OWASP ML06 / CWE-502)", check_model_file_load),
    ("Decode-then-Execute Chains (CWE-94)", check_decode_exec_chains),
    ("Binding to All Interfaces (CWE-1327)", check_bind_all_interfaces),
    ("Weak TLS Protocol Version (CWE-326)", check_weak_tls_version),
    ("Legacy PyCrypto Import (CWE-1104)", check_legacy_pycrypto),
    ("HuggingFace Unsafe Download (OWASP ML06 / B615)", check_huggingface_unsafe_download),
    ("Unbounded Request Field Size (OWASP API4:2023 / CWE-770)", check_unbounded_pydantic_field),
]

_PLUGIN_GROUP = "fenceline.checks"


def _discover_plugin_checks() -> list[tuple[str, CheckFn]]:
    """Loads third-party checks registered under the ``fenceline.checks``
    entry-point group. A plugin that fails to import is skipped with a
    warning rather than crashing the whole tool -- one broken third-party
    package shouldn't take down scanning for everyone else."""
    discovered: list[tuple[str, CheckFn]] = []
    for ep in entry_points(group=_PLUGIN_GROUP):
        try:
            check_fn = ep.load()
        except Exception as exc:
            print(f"  ⚠ fenceline: failed to load plugin check {ep.name!r}: {exc}", file=sys.stderr)
            continue
        discovered.append((ep.name, check_fn))
    return discovered


CHECKS: list[tuple[str, CheckFn]] = _BUILTIN_CHECKS + _discover_plugin_checks()
