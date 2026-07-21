"""Line-regex-based check functions.

These checks scan raw source text rather than the AST. They're faster to
write for surface-syntax patterns (a specific function name, a literal flag)
but can't distinguish real code from a mention inside a comment or string —
only full-line comments are filtered via ``_skip()``. Checks where that
distinction matters (dangerous calls that are also common in docstrings)
belong in :mod:`tripwire.checks.ast_checks` instead.
"""

from __future__ import annotations

import ast
import re
from pathlib import Path

from tripwire.ast_helpers import _LOG_METHOD_CALL_ANY_RE, _LOG_METHOD_CALL_RE, _skip
from tripwire.models import Finding
from tripwire.scanner import _rel

__all__ = [
    "check_pickle",
    "check_command_injection",
    "check_sql_injection",
    "check_path_traversal",
    "check_hardcoded_secrets",
    "_is_secret_false_positive",
    "check_yaml_deserialize",
    "check_xxe",
    "check_ssrf",
    "check_tempfile",
    "check_symlink",
    "check_redos",
    "check_assert_security",
    "check_exec_driver_sql",
    "check_supply_chain",
    "check_debug_mode",
    "check_timing_attack",
    "check_sensitive_exposure",
    "check_null_byte",
    "check_resource_limits",
    "check_ssti",
    "check_crlf",
    "check_ldap",
    "check_weak_hash",
    "check_open_redirect",
    "check_log_injection",
    "check_arbitrary_write",
    "check_log_secrets",
    "check_tls_verify",
    "check_zipslip",
    "check_hardcoded_tokens",
    "check_weak_crypto",
    "check_trojan_source",
    "check_ssh_host_key",
    "check_pandas_pickle",
    "check_numpy_load_lib",
    "check_pandas_xml_xxe",
    "check_pth_startup_hooks",
    "check_model_file_load",
    "check_bind_all_interfaces",
    "check_weak_tls_version",
    "check_legacy_pycrypto",
]


def check_pickle(path: Path, lines: list[str], tree: ast.Module | None) -> list[Finding]:
    """CWE-502 rank #15. Zero-days: CVE-2026-56315 (picklescan bypass),
    CVE-2026-0763 (GPT Academic, CVSS 9.8)."""
    pk = _rel(path)
    results: list[Finding] = []
    patterns = {
        r"pickle\.loads?\s*\(": ("pickle.loads() / pickle.load()", "CRITICAL"),
        r"pickle\.Unpickler\s*\(": ("pickle.Unpickler()", "CRITICAL"),
        r"cloudpickle\.loads?\s*\(": ("cloudpickle.loads() / cloudpickle.load()", "CRITICAL"),
        r"dill\.loads?\s*\(": ("dill.loads() / dill.load()", "CRITICAL"),
        r"joblib\.load\s*\(": ("joblib.load()", "HIGH"),
        r"shelve\.open\s*\(": ("shelve.open()", "HIGH"),
        r"marshal\.loads?\s*\(": ("marshal.loads() / marshal.load()", "HIGH"),
    }
    for lineno, line in enumerate(lines, 1):
        if _skip(line):
            continue
        for pat, (label, sev) in patterns.items():
            if re.search(pat, line):
                results.append(
                    Finding(
                        cwe_id="CWE-502",
                        cwe_name="Deserialization of Untrusted Data",
                        severity=sev,
                        package="",
                        file=pk,
                        line=lineno,
                        code_snippet=line.strip(),
                        description=f"Unsafe deserialisation via {label}. Allows arbitrary code execution.",
                        zero_day_relevance="CVE-2026-56315 picklescan <1.0.4 bypass (uuid, imaplib etc. unblocked); "
                        "CVE-2026-0763 GPT Academic CVSS 9.8; LangChain CVE-2025-68664 SSTI+pickle chain",
                    )
                )
                break
    return results


def check_command_injection(path: Path, lines: list[str], tree: ast.Module | None) -> list[Finding]:
    """CWE-78 rank #9, CWE-77 rank #23."""
    pk = _rel(path)
    results: list[Finding] = []
    calls = {
        "os.system": "CRITICAL",
        "os.popen": "CRITICAL",
        "subprocess.call": "HIGH",
        "subprocess.Popen": "HIGH",
        "subprocess.run": "HIGH",
        "subprocess.check_output": "HIGH",
        "subprocess.getoutput": "HIGH",
        "subprocess.getstatusoutput": "HIGH",
        "os.execv": "HIGH",
        "os.execl": "HIGH",
        "os.execve": "HIGH",
        "os.execvp": "HIGH",
        "pty.spawn": "HIGH",
        "asyncio.create_subprocess_shell": "HIGH",
    }
    for lineno, line in enumerate(lines, 1):
        if _skip(line):
            continue
        for call, sev in calls.items():
            if re.search(rf"\b{re.escape(call)}\s*\(", line):
                results.append(
                    Finding(
                        cwe_id="CWE-78",
                        cwe_name="OS Command Injection",
                        severity=sev,
                        package="",
                        file=pk,
                        line=lineno,
                        code_snippet=line.strip(),
                        description=f"{call}() spawns subprocesses; may allow command injection if arguments are unvalidated.",
                        zero_day_relevance="CWE-78: 20 CVEs in KEV. Still a top Python zero-day vector.",
                    )
                )
                break
        if re.search(r"shell\s*=\s*True", line):
            results.append(
                Finding(
                    cwe_id="CWE-78",
                    cwe_name="OS Command Injection",
                    severity="HIGH",
                    package="",
                    file=pk,
                    line=lineno,
                    code_snippet=line.strip(),
                    description="shell=True enables shell injection in subprocess calls.",
                )
            )
    return results


def check_sql_injection(path: Path, lines: list[str], tree: ast.Module | None) -> list[Finding]:
    """CWE-89 rank #2."""
    pk = _rel(path)
    results: list[Finding] = []
    patterns = [
        (r'execute\s*\(\s*f["\']', "f-string in execute() — probable SQL injection"),
        (
            r'exec_driver_sql\s*\(\s*f["\']',
            "f-string in exec_driver_sql() — probable SQL injection",
        ),
        (r"\.execute\s*\([^)]*\+", "String concatenation in execute() — probable SQL injection"),
    ]
    for lineno, line in enumerate(lines, 1):
        if _skip(line):
            continue
        for pat, desc in patterns:
            if re.search(pat, line):
                results.append(
                    Finding(
                        cwe_id="CWE-89",
                        cwe_name="SQL Injection",
                        severity="CRITICAL",
                        package="",
                        file=pk,
                        line=lineno,
                        code_snippet=line.strip(),
                        description=desc,
                        zero_day_relevance="CWE-89 rose to #2 in 2025 Top 25. Most exploited injection class after XSS.",
                    )
                )
                break
    return results


def check_path_traversal(path: Path, lines: list[str], tree: ast.Module | None) -> list[Finding]:
    """CWE-22 rank #6."""
    pk = _rel(path)
    results: list[Finding] = []
    for lineno, line in enumerate(lines, 1):
        if _skip(line):
            continue
        if re.search(r"lstrip\(['\"]\/['\"]\)", line):
            results.append(
                Finding(
                    cwe_id="CWE-22",
                    cwe_name="Path Traversal",
                    severity="HIGH",
                    package="",
                    file=pk,
                    line=lineno,
                    code_snippet=line.strip(),
                    description="lstrip('/') does NOT prevent ../ traversal — use Path.resolve() + is_relative_to().",
                    zero_day_relevance="CWE-22 is #6 in Top 25 with 10 CVEs in KEV.",
                )
            )
        if re.search(r"relative_path", line) and re.search(r"open\s*\(", line):
            results.append(
                Finding(
                    cwe_id="CWE-22",
                    cwe_name="Path Traversal",
                    severity="MEDIUM",
                    package="",
                    file=pk,
                    line=lineno,
                    code_snippet=line.strip(),
                    description="Variable named 'relative_path' used in open() — verify ../ is rejected with Path.resolve().",
                )
            )
    return results


def check_hardcoded_secrets(path: Path, lines: list[str], tree: ast.Module | None) -> list[Finding]:
    """CWE-798 (was #35 in 2025)."""
    pk = _rel(path)
    results: list[Finding] = []
    patterns: list[tuple[str, str, str]] = [
        (
            r'(?:private_key|ssh_key|pem)\s*[:=]\s*["\'][^"\']+["\']',
            "CRITICAL",
            "Hardcoded private key",
        ),
        (
            r'connection_url\s*=\s*["\'][^"\']*://[^"\']+:[^"\']+@',
            "CRITICAL",
            "Connection URL with embedded credentials",
        ),
        (r'(?:password|passwd|pwd)\s*[:=]\s*["\'][^"\']{4,}["\']', "HIGH", "Hardcoded password"),
    ]
    for lineno, line in enumerate(lines, 1):
        if _skip(line):
            continue
        for pat, sev, desc in patterns:
            if re.search(pat, line) and not _is_secret_false_positive(line):
                results.append(
                    Finding(
                        cwe_id="CWE-798",
                        cwe_name="Use of Hard-coded Credentials",
                        severity=sev,
                        package="",
                        file=pk,
                        line=lineno,
                        code_snippet=line.strip(),
                        description=desc,
                        zero_day_relevance="Leaked creds in source code are the #1 initial access vector in supply-chain attacks.",
                    )
                )
                break
    return results


def _is_secret_false_positive(line: str) -> bool:
    low = line.lower()
    # env var reference
    if "environ" in low or "getenv" in low or "config" in low:
        return True
    # example / placeholder
    if any(x in low for x in ("your-", "placeholder", "...", "example", "xxxx", "****")):
        return True
    # sqlalchemy documented URL pattern
    if "connection_url" in low and ("{" in line or "}" in line or "dialect" in low):
        return True
    return False


def check_yaml_deserialize(path: Path, lines: list[str], tree: ast.Module | None) -> list[Finding]:
    """CWE-502 via PyYAML.  Zero-day: CVE-2026-24009 Docling RCE."""
    pk = _rel(path)
    results: list[Finding] = []
    for lineno, line in enumerate(lines, 1):
        if _skip(line):
            continue
        if re.search(r"yaml\.load\s*\(", line) and "SafeLoader" not in line:
            results.append(
                Finding(
                    cwe_id="CWE-502",
                    cwe_name="Deserialization of Untrusted Data",
                    severity="CRITICAL",
                    package="",
                    file=pk,
                    line=lineno,
                    code_snippet=line.strip(),
                    description="yaml.load() without SafeLoader — enables arbitrary code execution.",
                    zero_day_relevance="CVE-2026-24009: Docling RCE via PyYAML shadow vulnerability. "
                    "Transitive YAML deps can introduce RCE without a direct yaml import.",
                )
            )
    return results


def check_xxe(path: Path, lines: list[str], tree: ast.Module | None) -> list[Finding]:
    pk = _rel(path)
    results: list[Finding] = []
    for lineno, line in enumerate(lines, 1):
        if _skip(line):
            continue
        if re.search(r"(?:xml\.etree|xml\.dom|xml\.sax)\.", line):
            results.append(
                Finding(
                    cwe_id="CWE-611",
                    cwe_name="XXE (XML External Entity)",
                    severity="HIGH",
                    package="",
                    file=pk,
                    line=lineno,
                    code_snippet=line.strip(),
                    description="XML parser without external entity protection. Use defusedxml.",
                    zero_day_relevance="XXE remains a zero-day vector for data-processing pipelines.",
                )
            )
    return results


def check_ssrf(path: Path, lines: list[str], tree: ast.Module | None) -> list[Finding]:
    """CWE-918 rank #22."""
    pk = _rel(path)
    results: list[Finding] = []
    http_pattern = re.compile(
        r"(?:requests|httpx)\.(?:get|post|put|patch|delete|head|options|request)\s*\("
        r"|urllib\.request\.urlopen\s*\("
        r"|aiohttp\.ClientSession"
    )
    for lineno, line in enumerate(lines, 1):
        if _skip(line):
            continue
        if http_pattern.search(line):
            results.append(
                Finding(
                    cwe_id="CWE-918",
                    cwe_name="Server-Side Request Forgery",
                    severity="HIGH",
                    package="",
                    file=pk,
                    line=lineno,
                    code_snippet=line.strip(),
                    description="HTTP request — verify URL is validated against allowlist; SSRF if user-controlled.",
                    zero_day_relevance="CWE-918 fell to #22 but SSRF zero-days (cloud metadata exfiltration) remain critical.",
                )
            )
    return results


def check_tempfile(path: Path, lines: list[str], tree: ast.Module | None) -> list[Finding]:
    pk = _rel(path)
    results: list[Finding] = []
    for lineno, line in enumerate(lines, 1):
        if _skip(line):
            continue
        if "tempfile.mktemp" in line:
            results.append(
                Finding(
                    cwe_id="CWE-377",
                    cwe_name="Insecure Temporary File",
                    severity="HIGH",
                    package="",
                    file=pk,
                    line=lineno,
                    code_snippet=line.strip(),
                    description="tempfile.mktemp() is insecure (TOCTOU race). Use TemporaryFile or NamedTemporaryFile.",
                )
            )
    return results


def check_symlink(path: Path, lines: list[str], tree: ast.Module | None) -> list[Finding]:
    pk = _rel(path)
    results: list[Finding] = []
    for lineno, line in enumerate(lines, 1):
        if _skip(line):
            continue
        if ".symlink_to" in line or "os.symlink" in line:
            results.append(
                Finding(
                    cwe_id="CWE-61",
                    cwe_name="UNIX Symbolic Link Following",
                    severity="MEDIUM",
                    package="",
                    file=pk,
                    line=lineno,
                    code_snippet=line.strip(),
                    description="Creating symlink — verify target is validated to prevent path escape.",
                )
            )
    return results


def check_redos(path: Path, lines: list[str], tree: ast.Module | None) -> list[Finding]:
    pk = _rel(path)
    results: list[Finding] = []
    for lineno, line in enumerate(lines, 1):
        if _skip(line):
            continue
        if re.search(r"re\.(?:compile|match|search)", line):
            if re.search(r"\([^)]+[+*?]\)[+*?{]", line):
                results.append(
                    Finding(
                        cwe_id="CWE-1333",
                        cwe_name="ReDoS (Catastrophic Backtracking)",
                        severity="MEDIUM",
                        package="",
                        file=pk,
                        line=lineno,
                        code_snippet=line.strip(),
                        description="Nested quantifier pattern — potential ReDoS (catastrophic backtracking).",
                        zero_day_relevance="ReDoS zero-days have been used to DoS auth gateways. CWE-1333 new to OWASP 2025.",
                    )
                )
    return results


def check_assert_security(path: Path, lines: list[str], tree: ast.Module | None) -> list[Finding]:
    pk = _rel(path)
    results: list[Finding] = []
    for lineno, line in enumerate(lines, 1):
        stripped = line.strip()
        if stripped.startswith("assert ") and not stripped.startswith("assert_"):
            # Only flag bare `assert <condition>` that looks like a security check
            # (e.g. `assert role == "admin"`), not isinstance narrowing for type checkers.
            if "isinstance" not in stripped and re.search(r"\b(is|==|!=|in)\b", stripped):
                if re.search(
                    r"(?:admin|owner|role|permission|authorized|authenticated)", stripped, re.I
                ):
                    results.append(
                        Finding(
                            cwe_id="CWE-617",
                            cwe_name="Reachable Assertion",
                            severity="MEDIUM",
                            package="",
                            file=pk,
                            line=lineno,
                            code_snippet=stripped,
                            description="Assert used for access control check — stripped with python -O. Use proper if/raise.",
                            zero_day_relevance="Assert-based security checks are a known zero-day bypass pattern.",
                        )
                    )
    return results


def check_exec_driver_sql(path: Path, lines: list[str], tree: ast.Module | None) -> list[Finding]:
    """Verify exec_driver_sql calls use pre-compiled SQL with proper param binding."""
    pk = _rel(path)
    results: list[Finding] = []
    for lineno, line in enumerate(lines, 1):
        if _skip(line):
            continue
        if re.search(r'exec_driver_sql\s*\(\s*f["\']', line):
            results.append(
                Finding(
                    cwe_id="CWE-89",
                    cwe_name="SQL Injection",
                    severity="CRITICAL",
                    package="",
                    file=pk,
                    line=lineno,
                    code_snippet=line.strip(),
                    description="exec_driver_sql() with f-string — direct SQL injection.",
                )
            )
    return results


def check_supply_chain(path: Path, lines: list[str], tree: ast.Module | None) -> list[Finding]:
    pk = _rel(path)
    results: list[Finding] = []
    for lineno, line in enumerate(lines, 1):
        if _skip(line):
            continue
        if "--extra-index-url" in line:
            results.append(
                Finding(
                    cwe_id="CWE-1104",
                    cwe_name="Supply Chain — Dependency Confusion",
                    severity="HIGH",
                    package="",
                    file=pk,
                    line=lineno,
                    code_snippet=line.strip(),
                    description="--extra-index-url enables dependency confusion. Use --index-url instead.",
                    zero_day_relevance="CVE-2025-61774: PyVista dependency confusion RCE. Supply-chain attacks on PyPI surged in 2025-2026.",
                )
            )
    return results


def check_debug_mode(path: Path, lines: list[str], tree: ast.Module | None) -> list[Finding]:
    pk = _rel(path)
    results: list[Finding] = []
    for lineno, line in enumerate(lines, 1):
        if _skip(line):
            continue
        if re.search(r"debug\s*=\s*True", line) and "docstring" not in line.lower():
            results.append(
                Finding(
                    cwe_id="CWE-489",
                    cwe_name="Active Debug Code",
                    severity="MEDIUM",
                    package="",
                    file=pk,
                    line=lineno,
                    code_snippet=line.strip(),
                    description="Hardcoded debug=True — may expose sensitive info in production.",
                )
            )
    return results


def check_timing_attack(path: Path, lines: list[str], tree: ast.Module | None) -> list[Finding]:
    pk = _rel(path)
    results: list[Finding] = []
    for lineno, line in enumerate(lines, 1):
        if _skip(line):
            continue
        if re.search(r"==\s*['\"]", line) and re.search(
            r"(?:token|secret|password|auth)", line, re.I
        ):
            results.append(
                Finding(
                    cwe_id="CWE-208",
                    cwe_name="Timing Attack",
                    severity="LOW",
                    package="",
                    file=pk,
                    line=lineno,
                    code_snippet=line.strip(),
                    description="String comparison with == may leak timing information for secret comparison. Use secrets.compare_digest().",
                )
            )
    return results


def check_sensitive_exposure(
    path: Path, lines: list[str], tree: ast.Module | None
) -> list[Finding]:
    pk = _rel(path)
    results: list[Finding] = []
    for lineno, line in enumerate(lines, 1):
        if _skip(line):
            continue
        if "traceback.print_exc" in line or "traceback.print_exception" in line:
            results.append(
                Finding(
                    cwe_id="CWE-200",
                    cwe_name="Information Exposure",
                    severity="MEDIUM",
                    package="",
                    file=pk,
                    line=lineno,
                    code_snippet=line.strip(),
                    description="traceback.print_exc() may leak internal paths / stack traces to users.",
                )
            )
    return results


def check_null_byte(path: Path, lines: list[str], tree: ast.Module | None) -> list[Finding]:
    pk = _rel(path)
    results: list[Finding] = []
    for lineno, line in enumerate(lines, 1):
        if _skip(line):
            continue
        if re.search(r"\\x00|\\0", line):
            # Guard against NUL byte env var value rejection — this is defense, not vulnerability
            results.append(
                Finding(
                    cwe_id="CWE-158",
                    cwe_name="NUL Byte Injection",
                    severity="INFO",
                    package="",
                    file=pk,
                    line=lineno,
                    code_snippet=line.strip(),
                    description="NUL byte detected — ensure it is rejected/validated before passing to C-based runtimes.",
                )
            )
    return results


def check_resource_limits(path: Path, lines: list[str], tree: ast.Module | None) -> list[Finding]:
    """CWE-770 rank #25 — new to Top 25 in 2025."""
    pk = _rel(path)
    results: list[Finding] = []
    for lineno, line in enumerate(lines, 1):
        if _skip(line):
            continue
        if re.search(r"\.read\(\)", line) and not re.search(r"read\(\d", line):
            if not re.search(r"(?:chunk|iter_content|stream)", line, re.I):
                results.append(
                    Finding(
                        cwe_id="CWE-770",
                        cwe_name="Unbounded Resource Allocation",
                        severity="INFO",
                        package="",
                        file=pk,
                        line=lineno,
                        code_snippet=line.strip(),
                        description="Unbounded .read() — may exhaust memory on large inputs. Use .read(n) or streaming.",
                        zero_day_relevance="CWE-770 entered Top 25 at #25 in 2025.",
                    )
                )
    return results


def check_ssti(path: Path, lines: list[str], tree: ast.Module | None) -> list[Finding]:
    """CWE-1336. Zero-day: LangChain CVE-2025-68664."""
    pk = _rel(path)
    results: list[Finding] = []
    for lineno, line in enumerate(lines, 1):
        if _skip(line):
            continue
        if re.search(r"(?:Jinja2?\.Template|Template)\s*\(", line):
            results.append(
                Finding(
                    cwe_id="CWE-1336",
                    cwe_name="Server-Side Template Injection",
                    severity="HIGH",
                    package="",
                    file=pk,
                    line=lineno,
                    code_snippet=line.strip(),
                    description="Template instantiation — SSTI if template string is user-controlled.",
                    zero_day_relevance="CVE-2025-68664: LangChain Core SSTI zero-day chaining deserialisation + Jinja2 for RCE.",
                )
            )
    return results


def check_crlf(path: Path, lines: list[str], tree: ast.Module | None) -> list[Finding]:
    pk = _rel(path)
    results: list[Finding] = []
    for lineno, line in enumerate(lines, 1):
        if _skip(line):
            continue
        if re.search(r"\\r\\n|%0d%0a|%0D%0A", line):
            results.append(
                Finding(
                    cwe_id="CWE-93",
                    cwe_name="CRLF Injection",
                    severity="HIGH",
                    package="",
                    file=pk,
                    line=lineno,
                    code_snippet=line.strip(),
                    description="CRLF sequence — may enable HTTP response splitting / log injection.",
                )
            )
    return results


def check_ldap(path: Path, lines: list[str], tree: ast.Module | None) -> list[Finding]:
    pk = _rel(path)
    results: list[Finding] = []
    for lineno, line in enumerate(lines, 1):
        if _skip(line):
            continue
        if "ldap.initialize" in line or "ldap3" in line:
            results.append(
                Finding(
                    cwe_id="CWE-90",
                    cwe_name="LDAP Injection",
                    severity="HIGH",
                    package="",
                    file=pk,
                    line=lineno,
                    code_snippet=line.strip(),
                    description="LDAP connection — verify queries are parameterised.",
                )
            )
    return results


def check_weak_hash(path: Path, lines: list[str], tree: ast.Module | None) -> list[Finding]:
    """CWE-328. Direct hashlib.md5()/sha1() calls, plus the hashlib.new("md5"/...)
    indirection (B324) — same weak algorithms, reached through the generic
    constructor instead of the dedicated function, so a direct-call-only
    pattern misses it entirely."""
    pk = _rel(path)
    results: list[Finding] = []
    for lineno, line in enumerate(lines, 1):
        if _skip(line):
            continue
        if re.search(r"hashlib\.(?:md5|sha1)\s*\(", line):
            results.append(
                Finding(
                    cwe_id="CWE-328",
                    cwe_name="Weak Cryptographic Hash",
                    severity="MEDIUM",
                    package="",
                    file=pk,
                    line=lineno,
                    code_snippet=line.strip(),
                    description="Use of MD5/SHA-1 — collision-prone, use SHA-256 or better.",
                )
            )
        if re.search(r'hashlib\.new\s*\(\s*["\'](?:md5|md4|md2|sha1)["\']', line, re.I):
            results.append(
                Finding(
                    cwe_id="CWE-328",
                    cwe_name="Weak Cryptographic Hash",
                    severity="MEDIUM",
                    package="",
                    file=pk,
                    line=lineno,
                    code_snippet=line.strip(),
                    description="hashlib.new() with a weak algorithm name (MD5/MD4/MD2/SHA-1) — "
                    "same collision risk as calling hashlib.md5()/sha1() directly, "
                    "just reached through the generic constructor. Use SHA-256 or better.",
                )
            )
    return results


def check_open_redirect(path: Path, lines: list[str], tree: ast.Module | None) -> list[Finding]:
    pk = _rel(path)
    results: list[Finding] = []
    for lineno, line in enumerate(lines, 1):
        if _skip(line):
            continue
        if re.search(r"(?:redirect|Redirect)\s*\(", line):
            results.append(
                Finding(
                    cwe_id="CWE-601",
                    cwe_name="Open Redirect",
                    severity="MEDIUM",
                    package="",
                    file=pk,
                    line=lineno,
                    code_snippet=line.strip(),
                    description="URL redirect — ensure destination is validated against an allowlist.",
                )
            )
    return results


def check_log_injection(path: Path, lines: list[str], tree: ast.Module | None) -> list[Finding]:
    pk = _rel(path)
    results: list[Finding] = []
    for lineno, line in enumerate(lines, 1):
        if _skip(line):
            continue
        if _LOG_METHOD_CALL_RE.search(line):
            if not re.search(r"%[srd]|{!r}|{!s}", line):
                results.append(
                    Finding(
                        cwe_id="CWE-117",
                        cwe_name="Log Injection / Forging",
                        severity="LOW",
                        package="",
                        file=pk,
                        line=lineno,
                        code_snippet=line.strip(),
                        description="f-string in logger call — may embed newlines/CRLF from user input, forging log entries.",
                    )
                )
    return results


def check_arbitrary_write(path: Path, lines: list[str], tree: ast.Module | None) -> list[Finding]:
    pk = _rel(path)
    results: list[Finding] = []
    for lineno, line in enumerate(lines, 1):
        if _skip(line):
            continue
        if re.search(r"(?:shutil\.copy|shutil\.move|os\.rename)\s*\(", line):
            results.append(
                Finding(
                    cwe_id="CWE-73",
                    cwe_name="External Control of File Name",
                    severity="MEDIUM",
                    package="",
                    file=pk,
                    line=lineno,
                    code_snippet=line.strip(),
                    description="File operation — verify destination path is validated to prevent arbitrary write.",
                )
            )
    return results


def check_log_secrets(path: Path, lines: list[str], tree: ast.Module | None) -> list[Finding]:
    """CWE-532.  Logging passwords, tokens, secrets or full objects that contain them."""
    pk = _rel(path)
    results: list[Finding] = []
    secret_keywords = (
        r"(password|passwd|secret|token|api_key|apikey|auth_token|access_key|private_key)"
    )
    for lineno, line in enumerate(lines, 1):
        if _skip(line):
            continue
        stripped = line.strip()
        # logger.info/debug/warning/error(..., password_var) style
        if _LOG_METHOD_CALL_ANY_RE.search(stripped):
            if re.search(secret_keywords, stripped, re.I):
                results.append(
                    Finding(
                        cwe_id="CWE-532",
                        cwe_name="Insertion of Sensitive Information into Logs",
                        severity="HIGH",
                        package="",
                        file=pk,
                        line=lineno,
                        code_snippet=stripped,
                        description="Logger call includes a variable whose name suggests it holds a secret — potential credential leakage in logs.",
                        zero_day_relevance="CWE-532: leaked creds in logs are a common zero-day discovery vector (GitHub secret scanning, SIEM alerts).",
                    )
                )
    return results


def check_tls_verify(path: Path, lines: list[str], tree: ast.Module | None) -> list[Finding]:
    """CWE-295 rank #8.  verify=False, CERT_NONE, check_hostname=False, etc."""
    pk = _rel(path)
    results: list[Finding] = []
    patterns = [
        (
            r"verify\s*=\s*False",
            "HTTP/S3 client with verify=False — TLS certificate validation disabled.",
        ),
        (r"check_hostname\s*=\s*False", "Hostname verification disabled — no TLS identity check."),
        (
            r"CERT_NONE",
            "ssl.CERT_NONE — peer certificate not verified, man-in-the-middle possible.",
        ),
        (
            r"_create_unverified_context",
            "ssl._create_unverified_context() — creates unverified TLS context.",
        ),
    ]
    for lineno, line in enumerate(lines, 1):
        if _skip(line):
            continue
        stripped = line.strip()
        for pat, desc in patterns:
            if re.search(pat, stripped):
                results.append(
                    Finding(
                        cwe_id="CWE-295",
                        cwe_name="Improper Certificate Validation",
                        severity="CRITICAL",
                        package="",
                        file=pk,
                        line=lineno,
                        code_snippet=stripped,
                        description=desc,
                        zero_day_relevance="CWE-295 is #8 in CWE Top 25. TLS bypass zero-days (e.g. CVE-2026-27834 Python CERT_NONE in urllib) enable MITM on every connection.",
                    )
                )
                break
    return results


def check_zipslip(path: Path, lines: list[str], tree: ast.Module | None) -> list[Finding]:
    """CWE-22 via ZipFile.extractall / tarfile.extractall without path validation."""
    pk = _rel(path)
    results: list[Finding] = []
    for lineno, line in enumerate(lines, 1):
        if _skip(line):
            continue
        stripped = line.strip()
        if re.search(r"\.extractall\s*\(", stripped) and not re.search(
            r"(resolve|is_relative_to|member.*safe)", stripped
        ):
            results.append(
                Finding(
                    cwe_id="CWE-22",
                    cwe_name="Path Traversal — ZipSlip / TarSlip",
                    severity="HIGH",
                    package="",
                    file=pk,
                    line=lineno,
                    code_snippet=stripped,
                    description="extractall() without path traversal guard — an archive with ../ entries can overwrite arbitrary files.",
                    zero_day_relevance="ZipSlip zero-day pattern: path traversal in archive extraction enables RCE via overwritten binaries (CVE-2026-20624 Python tarfile).",
                )
            )
    return results


def check_hardcoded_tokens(path: Path, lines: list[str], tree: ast.Module | None) -> list[Finding]:
    """CWE-798 — extended: api_key, token, jwt, bearer, secret literal strings."""
    pk = _rel(path)
    results: list[Finding] = []
    # Look for: api_key = "actual-key", token = "eyJ...", bearer = "Bearer xyz", secret = "literal"
    patterns = [
        (r'(?:api_key|apikey)\s*[:=]\s*["\'][A-Za-z0-9_\-=]{16,}["\']', "Hardcoded API key"),
        (
            r'(?:token|jwt)\s*[:=]\s*["\'][A-Za-z0-9_\-]{20,}\.[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+["\']',
            "Hardcoded JWT token",
        ),
        (
            r'(?:bearer|auth_token)\s*[:=]\s*["\'][A-Za-z0-9_\-]{20,}["\']',
            "Hardcoded bearer / auth token",
        ),
        (r'(?:secret|client_secret)\s*[:=]\s*["\'][A-Za-z0-9_\-+/=]{16,}["\']', "Hardcoded secret"),
    ]
    for lineno, line in enumerate(lines, 1):
        if _skip(line):
            continue
        stripped = line.strip()
        for pat, desc in patterns:
            if re.search(pat, stripped) and not _is_secret_false_positive(stripped):
                results.append(
                    Finding(
                        cwe_id="CWE-798",
                        cwe_name="Use of Hard-coded Credentials",
                        severity="CRITICAL",
                        package="",
                        file=pk,
                        line=lineno,
                        code_snippet=stripped,
                        description=f"{desc} — plaintext credential in source code.",
                        zero_day_relevance="Hardcoded cloud API keys are the #1 initial-access vector in supply-chain attacks. Attackers scan public repos for these patterns.",
                    )
                )
                break
    return results


def check_weak_crypto(path: Path, lines: list[str], tree: ast.Module | None) -> list[Finding]:
    """CWE-327.  DES, RC4, ECB mode, PKCS1_v1_5, MD5-for-security, etc."""
    pk = _rel(path)
    results: list[Finding] = []
    patterns = [
        (
            r"Crypto\.Cipher\.DES\b|pycryptodome.*DES\b",
            "DES — 56-bit key, bruteforceable. Use AES-256.",
        ),
        (r"ARC4\b|RC4\b", "RC4 — biased output, completely broken. Use ChaCha20 or AES-GCM."),
        (r"MODE_ECB\b", "AES ECB mode — deterministic, leaks plaintext structure. Use GCM or CBC."),
        (
            r"PKCS1_v1_5\b",
            "PKCS1_v1_5 padding — vulnerable to Bleichenbacher oracle attack. Use OAEP.",
        ),
        (
            r"hashlib\.md5\b.*(?=.*\b(?:sign|hmac|sig|token|password|hash\b))",
            "MD5 used in a security context (signing/hashing secrets) — collision-broken.",
        ),
    ]
    for lineno, line in enumerate(lines, 1):
        if _skip(line):
            continue
        stripped = line.strip()
        for pat, desc in patterns:
            if re.search(pat, stripped, re.I):
                results.append(
                    Finding(
                        cwe_id="CWE-327",
                        cwe_name="Use of a Broken or Risky Cryptographic Algorithm",
                        severity="HIGH",
                        package="",
                        file=pk,
                        line=lineno,
                        code_snippet=stripped,
                        description=desc,
                        zero_day_relevance="CWE-327: Weak crypto zero-days (Bleichenbacher, Padding Oracle) remain exploitable decades after disclosure.",
                    )
                )
                break
    return results


def check_trojan_source(path: Path, lines: list[str], tree: ast.Module | None) -> list[Finding]:
    """CWE-1007. Unicode bidi override characters that reorder source code display."""
    pk = _rel(path)
    results: list[Finding] = []
    bidi = re.compile("[\u202a\u202b\u202c\u202d\u202e\u2066\u2067\u2068\u2069]")
    for lineno, line in enumerate(lines, 1):
        if bidi.search(line):
            results.append(
                Finding(
                    cwe_id="CWE-1007",
                    cwe_name="Trojan Source (Bidirectional Override)",
                    severity="CRITICAL",
                    package="",
                    file=pk,
                    line=lineno,
                    code_snippet=repr(line.strip()),
                    description="Unicode bidi override character — enables Trojan Source attacks: code appears different than it executes.",
                    zero_day_relevance="CVE-2021-42574: bidi overrides hide malicious code in plain sight. Bypasses code review.",
                )
            )
    return results


def check_ssh_host_key(path: Path, lines: list[str], tree: ast.Module | None) -> list[Finding]:
    """B507 / CWE-322. SSH connections without host key verification — MITM."""
    pk = _rel(path)
    results: list[Finding] = []
    patterns: list[tuple[str, str]] = [
        (r"AutoAddPolicy", "paramiko AutoAddPolicy — auto-accepts any unknown host key (MITM)."),
        (
            r"WarningPolicy",
            "paramiko WarningPolicy — warns but allows connection with unknown host key (MITM).",
        ),
        (r"sshtunnel\.open_tunnel", "sshtunnel.open_tunnel — verify host_key is explicitly set."),
    ]
    for lineno, line in enumerate(lines, 1):
        if _skip(line):
            continue
        stripped = line.strip()
        for pat, desc in patterns:
            if re.search(pat, stripped):
                results.append(
                    Finding(
                        cwe_id="CWE-322",
                        cwe_name="Key Exchange without Entity Authentication",
                        severity="HIGH",
                        package="",
                        file=pk,
                        line=lineno,
                        code_snippet=stripped,
                        description=desc,
                        zero_day_relevance="SSH MITM allows credential interception and lateral movement. Common zero-day chain component.",
                    )
                )
                break
    return results


def check_pandas_pickle(path: Path, lines: list[str], tree: ast.Module | None) -> list[Finding]:
    """Trail of Bits: pd.read_pickle() — explicit pickle-based deserialization."""
    pk = _rel(path)
    results: list[Finding] = []
    for lineno, line in enumerate(lines, 1):
        if _skip(line):
            continue
        if re.search(r"(?:pd|pandas)\.read_pickle\s*\(", line):
            results.append(
                Finding(
                    cwe_id="CWE-502",
                    cwe_name="Deserialization of Untrusted Data (read_pickle)",
                    severity="CRITICAL",
                    package="",
                    file=pk,
                    line=lineno,
                    code_snippet=line.strip(),
                    description="pd.read_pickle() deserializes Python objects via pickle — arbitrary code execution if file is untrusted.",
                    zero_day_relevance="Trail of Bits: pandas.read_pickle() uses pickle.load() under the hood — standard pickle RCE.",
                )
            )
    return results


def check_numpy_load_lib(path: Path, lines: list[str], tree: ast.Module | None) -> list[Finding]:
    """Trail of Bits: numpy.load() on .so/.dll files — arbitrary code execution from library loading."""
    pk = _rel(path)
    results: list[Finding] = []
    for lineno, line in enumerate(lines, 1):
        if _skip(line):
            continue
        stripped = line.strip()
        if re.search(r"numpy\.(?:load|ctypeslib)\.", stripped) and re.search(
            r"\.(so|dll|dylib)", stripped
        ):
            results.append(
                Finding(
                    cwe_id="CWE-114",
                    cwe_name="Process Control (numpy library loading)",
                    severity="HIGH",
                    package="",
                    file=pk,
                    line=lineno,
                    code_snippet=stripped,
                    description="numpy.load() loading a shared library (.so/.dll) — arbitrary code execution if path is user-controlled.",
                    zero_day_relevance="Trail of Bits: numpy.load() on .so files enables arbitrary code execution during array deserialization.",
                )
            )
    return results


def check_pandas_xml_xxe(path: Path, lines: list[str], tree: ast.Module | None) -> list[Finding]:
    """Trail of Bits: pd.read_xml(parser='lxml') — potential XXE."""
    pk = _rel(path)
    results: list[Finding] = []
    for lineno, line in enumerate(lines, 1):
        if _skip(line):
            continue
        stripped = line.strip()
        if re.search(r"(?:pd|pandas)\.read_xml\s*\(", stripped) and "parser" not in stripped:
            results.append(
                Finding(
                    cwe_id="CWE-611",
                    cwe_name="XXE via pandas.read_xml",
                    severity="HIGH",
                    package="",
                    file=pk,
                    line=lineno,
                    code_snippet=stripped,
                    description="pd.read_xml() defaults to lxml parser — may be vulnerable to XXE. Use parser='etree' or defusedxml.",
                    zero_day_relevance="Trail of Bits: pandas.read_xml with lxml parser enables XXE attacks on XML data pipelines.",
                )
            )
    return results


def check_pth_startup_hooks(path: Path, lines: list[str], tree: ast.Module | None) -> list[Finding]:
    """MITRE ATT&CK T1546.018: .pth files execute arbitrary code at interpreter
    startup before any import. Used by LiteLLM CVE-2026-42208, Hades campaign,
    ChocoPoC supply-chain attacks."""
    pk = _rel(path)
    results: list[Finding] = []

    # Scan for .pth files themselves
    if path.suffix == ".pth":
        for lineno, line in enumerate(lines, 1):
            stripped = line.strip()
            if stripped and not stripped.startswith("#"):
                results.append(
                    Finding(
                        cwe_id="CWE-829",
                        cwe_name="Inclusion of Functionality from Untrusted Control Sphere",
                        severity="CRITICAL",
                        package="",
                        file=pk,
                        line=lineno,
                        code_snippet=stripped,
                        description=".pth file executes arbitrary Python at interpreter startup — "
                        "MITRE ATT&CK T1546.018. LiteLLM CVE-2026-42208 vector.",
                        zero_day_relevance="CVE-2026-42208: .pth in litellm >=1.61.3. Hades campaign: 26+ "
                        "PyPI packages hijacked via .pth. CPython issue #113659 acknowledges gap.",
                    )
                )
                break
        return results

    # Scan .py files for .pth installation patterns
    for lineno, line in enumerate(lines, 1):
        if _skip(line):
            continue
        stripped = line.strip()
        if re.search(r"site\.addsitedir\s*\(", stripped):
            results.append(
                Finding(
                    cwe_id="CWE-829",
                    cwe_name=".pth Directory Added to sys.path",
                    severity="HIGH",
                    package="",
                    file=pk,
                    line=lineno,
                    code_snippet=stripped,
                    description="site.addsitedir() processes .pth files from the given directory — "
                    "enables startup code execution if any .pth file is present.",
                    zero_day_relevance="MITRE ATT&CK T1546.018: .pth files execute at Python startup "
                    "before any application code runs.",
                )
            )
        if re.search(r"exec\s*\(\s*(?:compile|open|base64)", stripped) and re.search(
            r"\.pth", line
        ):
            results.append(
                Finding(
                    cwe_id="CWE-829",
                    cwe_name="Dynamic .pth Execution",
                    severity="CRITICAL",
                    package="",
                    file=pk,
                    line=lineno,
                    code_snippet=stripped,
                    description="Dynamic .pth installation with exec() — classic supply-chain pivot.",
                    zero_day_relevance="ChocoPoC: .pth files used to maintain persistence after initial compromise.",
                )
            )
    return results


def check_model_file_load(path: Path, lines: list[str], tree: ast.Module | None) -> list[Finding]:
    """OWASP ML06 (supply-chain): loading ML model files (.pt, .pkl, .h5, .joblib)
    without SafeTensors alternatives allows arbitrary code execution."""
    pk = _rel(path)
    results: list[Finding] = []
    model_exts = (r'\.pt["\']', r'\.pkl["\']', r'\.h5["\']', r'\.joblib["\']', r'\.ckpt["\']')

    for lineno, line in enumerate(lines, 1):
        if _skip(line):
            continue
        stripped = line.strip()

        # torch.load with model extension
        if re.search(r"torch\.load\s*\(", stripped) and re.search(
            r'\.(?:pt|pth|ckpt)["\']', stripped
        ):
            has_weights_only = "weights_only" in stripped
            results.append(
                Finding(
                    cwe_id="CWE-502",
                    cwe_name="Deserialization of Untrusted Data (ML Model)",
                    severity="CRITICAL" if not has_weights_only else "LOW",
                    package="",
                    file=pk,
                    line=lineno,
                    code_snippet=stripped,
                    description=f"torch.load() on model file{' without weights_only=True' if not has_weights_only else ''}. "
                    f"Prefer SafeTensors format for untrusted model files.",
                    zero_day_relevance="OWASP ML06: pickle-based model formats enable RCE via malicious model files. "
                    "SafeTensors mitigates this by design.",
                )
            )

        # joblib.load / pickle.load on model files
        for ext in model_exts:
            if re.search(r"(?:joblib|pickle|cloudpickle|dill)\.load\s*\(", stripped) and re.search(
                ext, stripped
            ):
                results.append(
                    Finding(
                        cwe_id="CWE-502",
                        cwe_name="Deserialization of Untrusted Data (ML Model)",
                        severity="HIGH",
                        package="",
                        file=pk,
                        line=lineno,
                        code_snippet=stripped,
                        description=f"pickle-based load on {ext} file — arbitrary code execution via malicious model. "
                        f"Prefer SafeTensors for untrusted model files.",
                        zero_day_relevance="OWASP ML06: 80% of ML supply-chain attacks exploit pickle-based model formats.",
                    )
                )
                break

        # keras/tensorflow model loading
        if re.search(r"(?:tf|keras)\.(?:models\.)?load_model\s*\(", stripped):
            results.append(
                Finding(
                    cwe_id="CWE-502",
                    cwe_name="Deserialization of Untrusted Data (Keras Model)",
                    severity="HIGH",
                    package="",
                    file=pk,
                    line=lineno,
                    code_snippet=stripped,
                    description="tf.keras.models.load_model() can deserialize arbitrary Python objects "
                    "via custom layers/optimizers. Prefer SafeTensors for untrusted models.",
                    zero_day_relevance="OWASP ML06: Keras H5 format carries pickle-like deserialization risk.",
                )
            )
    return results


def check_legacy_pycrypto(path: Path, lines: list[str], tree: ast.Module | None) -> list[Finding]:
    """CWE-1104. `import Crypto` / `from Crypto import ...` pulls in the old,
    unmaintained PyCrypto package (last released 2013, several unpatched
    CVEs) — distinct from check_weak_crypto, which flags weak *algorithms*
    regardless of package. This flags the package itself, correctly used or
    not. `Cryptodome`/`pycryptodome` is the maintained drop-in replacement;
    the word-boundary check naturally excludes it (no boundary between the
    "o" ending "Crypto" and the "d" starting "dome")."""
    pk = _rel(path)
    results: list[Finding] = []
    legacy_import_pat = re.compile(r"^(?:from|import)\s+Crypto\b")

    for lineno, line in enumerate(lines, 1):
        if _skip(line):
            continue
        stripped = line.strip()
        if legacy_import_pat.search(stripped):
            results.append(
                Finding(
                    cwe_id="CWE-1104",
                    cwe_name="Supply Chain — Unmaintained Dependency",
                    severity="MEDIUM",
                    package="",
                    file=pk,
                    line=lineno,
                    code_snippet=stripped,
                    description="Imports the old PyCrypto package (unmaintained since 2013, several "
                    "unpatched CVEs) — migrate to pycryptodome (`import Cryptodome` / "
                    "`from Cryptodome import ...`), a maintained drop-in replacement.",
                    zero_day_relevance="PyCrypto has no security fixes for over a decade; several "
                    "known vulnerabilities (e.g. weak RNG seeding in old releases) remain unpatched.",
                )
            )
    return results


def check_weak_tls_version(path: Path, lines: list[str], tree: ast.Module | None) -> list[Finding]:
    """B502/B503/B504 / CWE-326. Explicit use of a broken or obsolete SSL/TLS
    protocol version — distinct from check_tls_verify (CWE-295), which is
    about *disabled* certificate/hostname verification, not protocol
    downgrade. SSLv2/SSLv3/TLSv1.0/TLSv1.1 are all deprecated (RFC 8996 for
    the TLS 1.0/1.1 case) and vulnerable to known plaintext-recovery/
    downgrade attacks (POODLE, BEAST)."""
    pk = _rel(path)
    results: list[Finding] = []
    weak_tls_pat = re.compile(r"PROTOCOL_(?:SSLv2|SSLv3|TLSv1)\b")

    for lineno, line in enumerate(lines, 1):
        if _skip(line):
            continue
        stripped = line.strip()
        match = weak_tls_pat.search(stripped)
        if match:
            results.append(
                Finding(
                    cwe_id="CWE-326",
                    cwe_name="Inadequate Encryption Strength",
                    severity="HIGH",
                    package="",
                    file=pk,
                    line=lineno,
                    code_snippet=stripped,
                    description=f"{match.group()} — explicitly requests a deprecated, broken SSL/TLS "
                    "protocol version. Use ssl.PROTOCOL_TLS_CLIENT/SERVER (or omit ssl_version "
                    "entirely) to let Python negotiate the strongest mutually-supported version.",
                    zero_day_relevance="B502/B503/B504: SSLv3 enables POODLE, TLSv1.0/1.1 are formally "
                    "deprecated by RFC 8996 — still found in legacy integration code talking to old servers.",
                )
            )
    return results


def check_bind_all_interfaces(path: Path, lines: list[str], tree: ast.Module | None) -> list[Finding]:
    """B104 / CWE-1327. A server bound to 0.0.0.0 listens on every network
    interface, not just localhost — reachable from outside the host unless
    something else (firewall, container network policy) restricts it."""
    pk = _rel(path)
    results: list[Finding] = []
    bind_all_pat = re.compile(r'["\']0\.0\.0\.0["\']')

    for lineno, line in enumerate(lines, 1):
        if _skip(line):
            continue
        stripped = line.strip()
        if bind_all_pat.search(stripped):
            results.append(
                Finding(
                    cwe_id="CWE-1327",
                    cwe_name="Binding to an Unrestricted IP Address",
                    severity="MEDIUM",
                    package="",
                    file=pk,
                    line=lineno,
                    code_snippet=stripped,
                    description="Host bound to 0.0.0.0 — listens on every network interface, not just "
                    "localhost. Bind to 127.0.0.1 unless external access is actually required.",
                    zero_day_relevance="B104: services accidentally exposed on all interfaces are a common "
                    "initial-access vector once a container/VM's network boundary is misconfigured.",
                )
            )
    return results
