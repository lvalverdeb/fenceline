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
    "check_xxe",
    "check_symlink",
    "check_assert_security",
    "check_supply_chain",
    "check_sensitive_exposure",
    "check_null_byte",
    "check_ldap",
    "check_weak_crypto",
    "check_trojan_source",
    "check_ssh_host_key",
    "check_pth_startup_hooks",
]


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


#: ``from xml.etree.ElementTree import Element, SubElement``: the names a
#: module imports from the stdlib XML packages.
_XML_IMPORT_RE = re.compile(r"^\s*from\s+xml\.[\w.]+\s+import\s+([\w\s,]+?)\s*$")
#: Builders and serialisers, not parsers: importing only these cannot parse
#: untrusted XML.
_XML_NON_PARSERS = frozenset(
    {
        "Element",
        "SubElement",
        "tostring",
        "tostringlist",
        "indent",
        "register_namespace",
        "QName",
        "Comment",
        "ProcessingInstruction",
        "dump",
        "Document",
        "escape",
        "quoteattr",
        "unescape",
    }
)


def _imports_only_non_parsers(line: str) -> bool:
    m = _XML_IMPORT_RE.match(line)
    if not m:
        return False
    names = {part.strip().split(" ")[0] for part in m.group(1).split(",") if part.strip()}
    return bool(names) and names <= _XML_NON_PARSERS


def _defused_parser_names(tree: ast.Module | None) -> list[str]:
    """Names bound to an lxml ``XMLParser(...)`` constructed with
    ``resolve_entities=False``: a parse call that passes one as ``parser=``
    is protected."""
    if tree is None:
        return []
    names: list[str] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Assign) or not isinstance(node.value, ast.Call):
            continue
        func = node.value.func
        if not (isinstance(func, ast.Attribute) and func.attr == "XMLParser"):
            continue
        if not any(
            kw.arg == "resolve_entities"
            and isinstance(kw.value, ast.Constant)
            and kw.value.value is False
            for kw in node.value.keywords
        ):
            continue
        names.extend(t.id for t in node.targets if isinstance(t, ast.Name))
    return names


def check_xxe(path: Path, lines: list[str], tree: ast.Module | None) -> list[Finding]:
    """CWE-611. A stdlib or lxml XML parser call. Not reported: an lxml
    parser constructed with ``resolve_entities=False``, a parse call that
    passes such a parser as ``parser=``, an import of builders and
    serialisers only (``Element``, ``tostring``), and ``xml.sax.saxutils``."""
    pk = _rel(path)
    results: list[Finding] = []
    lxml_alias = _lxml_etree_alias(tree)
    lxml_pattern = re.compile(rf"\b{re.escape(lxml_alias)}\.") if lxml_alias else None
    defused = _defused_parser_names(tree)
    defused_pattern = (
        re.compile(rf"\bparser\s*=\s*(?:{'|'.join(map(re.escape, defused))})\b")
        if defused
        else None
    )
    for lineno, line in enumerate(lines, 1):
        if _skip(line) or "xml.sax.saxutils" in line:
            continue  # saxutils is the escaping helper, not a parser
        if (
            "resolve_entities=False" in line
            or _imports_only_non_parsers(line)
            or (defused_pattern and defused_pattern.search(line))
        ):
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


#: Traceback text produced on a line that hands something back to the
#: client: ``return Response(traceback.format_exc(), 500)``.
_TRACEBACK_TEXT_RE = re.compile(r"traceback\.format_exc(?:eption)?\(")
_RESPONSE_LINE_RE = re.compile(
    r"\breturn\b|Response\(|render|jsonify\(|make_response\(|\.write\(|abort\(|HTTPException\("
)


def check_sensitive_exposure(
    path: Path, lines: list[str], tree: ast.Module | None
) -> list[Finding]:
    """CWE-200. ``traceback.format_exc()`` on a line that returns or builds
    a response: the stack trace, with its file paths and frames, reaches the
    client. ``traceback.print_exc()`` is not reported: it writes to the
    process's stderr, which is a log, and the logging check counts it as a
    diagnostic."""
    pk = _rel(path)
    results: list[Finding] = []
    for lineno, line in enumerate(lines, 1):
        if _skip(line):
            continue
        if _TRACEBACK_TEXT_RE.search(line) and _RESPONSE_LINE_RE.search(line):
            results.append(
                Finding(
                    cwe_id="CWE-200",
                    cwe_name="Information Exposure",
                    severity="MEDIUM",
                    package="",
                    file=pk,
                    line=lineno,
                    code_snippet=line.strip(),
                    description="Traceback text returned to the client — leaks internal paths and stack frames; log it and return a generic error.",
                )
            )
    return results


#: A NUL escape: ``\x00``, or octal ``\0`` / ``\00`` / ``\000`` not followed
#: by another octal digit (``\033`` is ESC, not NUL).
_NUL_ESCAPE_RE = re.compile(r"\\x00|\\00?0?(?:[^0-7]|$)")
#: A NUL escape as the operand of a membership test (``"\x00" in path``) or
#: the start of a regex character class (``[\x00-\x1f]``): validation or
#: sanitising, not a NUL reaching a C runtime.
_NUL_VALIDATION_RE = re.compile(r"""["']\\x00["']\s+(?:not\s+)?in\b|\[\\x00-""")


def check_null_byte(path: Path, lines: list[str], tree: ast.Module | None) -> list[Finding]:
    pk = _rel(path)
    results: list[Finding] = []
    for lineno, line in enumerate(lines, 1):
        if _skip(line):
            continue
        if _NUL_ESCAPE_RE.search(line) and not _NUL_VALIDATION_RE.search(line):
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
