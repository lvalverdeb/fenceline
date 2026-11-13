"""Line-regex-based check functions.

These checks scan raw source text rather than the AST. They're faster to
write for surface-syntax patterns (a specific function name, a literal flag)
but can't distinguish real code from a mention inside a comment or string —
only full-line comments are filtered via ``_skip()``. Checks where that
distinction matters (dangerous calls that are also common in docstrings)
belong in :mod:`fenceline.checks.ast_checks` instead.
"""

from __future__ import annotations

import ast
import re
from pathlib import Path

from fenceline.ast_helpers import (
    _skip,
)
from fenceline.models import Finding
from fenceline.scanner import _rel

__all__ = [
    "check_hardcoded_secrets",
    "_is_secret_false_positive",
    "check_xxe",
    "check_tempfile",
    "check_symlink",
    "check_assert_security",
    "check_supply_chain",
    "check_timing_attack",
    "check_sensitive_exposure",
    "check_null_byte",
    "check_ldap",
    "check_hardcoded_tokens",
    "check_weak_crypto",
    "check_trojan_source",
    "check_ssh_host_key",
    "check_pth_startup_hooks",
]


def check_hardcoded_secrets(path: Path, lines: list[str], tree: ast.Module | None) -> list[Finding]:
    """CWE-798 (was #35 in 2025). Matched case-insensitively — UPPER_SNAKE_CASE
    module constants (``PASSWORD = "..."``) are the standard Python
    convention for exactly this kind of value and were otherwise invisible."""
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
            if re.search(pat, line, re.IGNORECASE) and not _is_secret_false_positive(line):
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


def _lxml_etree_alias(tree: ast.Module | None) -> str | None:
    """Local name bound to ``lxml.etree`` — ``from lxml import etree``
    (optionally aliased) or ``import lxml.etree`` (optionally aliased) — or
    ``None`` if not imported.

    ``lxml.etree`` is the standard XML library alternative to the stdlib
    ``xml.etree``/``xml.dom``/``xml.sax`` modules this check already
    covers, and in production code is more common than any of them — but
    it's almost always imported under a bare ``etree`` name, so the
    ``xml.etree.``-style prefix match below never fires on lxml usage
    (including the textbook OWASP XXE-enabling pattern,
    ``etree.XMLParser(resolve_entities=True)``).
    """
    if tree is None:
        return None
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom) and node.module == "lxml":
            for alias in node.names:
                if alias.name == "etree":
                    return alias.asname or "etree"
        elif isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name == "lxml.etree":
                    return alias.asname or "lxml.etree"
    return None


def check_xxe(path: Path, lines: list[str], tree: ast.Module | None) -> list[Finding]:
    pk = _rel(path)
    results: list[Finding] = []
    lxml_alias = _lxml_etree_alias(tree)
    lxml_pattern = re.compile(rf"\b{re.escape(lxml_alias)}\.") if lxml_alias else None
    for lineno, line in enumerate(lines, 1):
        if _skip(line):
            continue
        if re.search(r"(?:xml\.etree|xml\.dom|xml\.sax)\.", line) or (
            lxml_pattern and lxml_pattern.search(line)
        ):
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
                    confidence="LOW",
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


def check_hardcoded_tokens(path: Path, lines: list[str], tree: ast.Module | None) -> list[Finding]:
    """CWE-798 — extended: api_key, token, jwt, bearer, secret literal strings.
    Matched case-insensitively — UPPER_SNAKE_CASE module constants
    (``API_KEY = "..."``) are the standard Python convention for exactly
    this kind of value and were otherwise invisible."""
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
            if re.search(pat, stripped, re.IGNORECASE) and not _is_secret_false_positive(stripped):
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
