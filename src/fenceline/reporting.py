"""Human-readable and JSON report rendering for a completed scan."""

from __future__ import annotations

import json as _json

from fenceline.models import SEVERITY_ORDER, Finding

__all__ = ["print_report", "CWE_REFERENCE"]


SEV_COLORS = {
    "CRITICAL": "\033[1;31m",
    "HIGH": "\033[31m",
    "MEDIUM": "\033[33m",
    "LOW": "\033[34m",
    "INFO": "\033[37m",
}
RESET = "\033[0m"


def _color(sev: str) -> str:
    return SEV_COLORS.get(sev, RESET)


def print_report(all_findings: list[Finding], json_output: bool) -> None:
    if json_output:
        data = []
        for f in all_findings:
            data.append(
                {
                    "cwe_id": f.cwe_id,
                    "cwe_name": f.cwe_name,
                    "severity": f.severity,
                    "package": f.package,
                    "file": f.file,
                    "line": f.line,
                    "code": f.code_snippet,
                    "description": f.description,
                    "zero_day_relevance": f.zero_day_relevance,
                }
            )
        print(_json.dumps({"findings": data, "count": len(data)}, indent=2))
        return

    if not all_findings:
        print(f"\n  {'=' * 72}")
        print("  SECURITY AUDIT RESULT: ALL CHECKS PASSED (0 findings)")
        print(f"  {'=' * 72}")
        print()
        return

    # Sort by severity
    all_findings.sort(key=lambda f: (SEVERITY_ORDER.get(f.severity, 99), f.file, f.line))

    print(f"\n  {'=' * 72}")
    print(f"  SECURITY AUDIT RESULT: {len(all_findings)} FINDING(S)")
    print(f"  {'=' * 72}\n")

    for f in all_findings:
        c = _color(f.severity)
        print(f"  {c}[{f.severity}]{RESET} {f.cwe_id} — {f.cwe_name}")
        print(f"  File:    {f.file}:{f.line}")
        if f.package:
            print(f"  Package: {f.package}")
        print(f"  Code:    {f.code_snippet}")
        print(f"  Detail:  {f.description}")
        if f.zero_day_relevance:
            print(f"  ZeroDay: {f.zero_day_relevance}")
        print()

    # Summary
    counts: dict[str, int] = {}
    for f in all_findings:
        counts[f.severity] = counts.get(f.severity, 0) + 1
    print(f"  {'─' * 72}")
    for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"):
        c = counts.get(sev, 0)
        if c:
            print(f"  {_color(sev)}{c:>4} × {sev}{RESET}")
    print(f"  {'─' * 72}\n")
    print(CWE_REFERENCE)


CWE_REFERENCE = """\
2025 CWE Top 25 Coverage
=========================
Rank  CWE-ID   Name                                                  Status
----  -------  ----------------------------------------------------  ------
  1   CWE-79   XSS                                                   N/A (no web)
  2   CWE-89   SQL Injection                                         ✓
  3   CWE-352  CSRF                                                  N/A (no web)
   4   CWE-862  Missing Authorization                                 Partial (indirect via secret scan)
  5   CWE-787  Out-of-bounds Write                                   N/A (mem-safe)
  6   CWE-22   Path Traversal                                        ✓
  7   CWE-416  Use After Free                                        N/A (mem-safe)
  8   CWE-125  Out-of-bounds Read                                    N/A (mem-safe)
  9   CWE-78   OS Command Injection                                  ✓
 10   CWE-94   Code Injection                                        ✓
 11   CWE-120  Classic Buffer Overflow                               N/A (mem-safe)
 12   CWE-434  File Upload Dangerous                                 N/A (no upload)
 13   CWE-476  NULL Pointer Dereference                               N/A (mem-safe)
 14   CWE-121  Stack Buffer Overflow                                 N/A (mem-safe)
 15   CWE-502  Deserialization (Untrusted Data)                      ✓
 16   CWE-122  Heap Buffer Overflow                                  N/A (mem-safe)
  17   CWE-863  Incorrect Authorization                               Partial (indirect via secret scan)
  18   CWE-20   Improper Input Validation                             Partial (via path traversal + resource limits)
  19   CWE-284  Improper Access Control                               Partial (via assert + hardcoded secrets)
 20   CWE-200  Information Exposure                                  ✓
 21   CWE-306  Missing Authentication                                N/A (no auth)
 22   CWE-918  SSRF                                                  ✓
 23   CWE-77   Command Injection (general)                           ✓
  24   CWE-639  Authorization Bypass                                  Partial (indirect via secret scan)
 25   CWE-770  Resource Allocation (unbounded)                       ✓

Additional Zero-Day Coverage
=============================
CWE-1333 ReDoS                     ✓   CWE-1336 SSTI                ✓
CWE-1104 Dep Confusion + CVE Scan  ✓   CWE-117  Log Injection       ✓
CWE-93   CRLF Injection            ✓   CWE-90   LDAP Injection      ✓
CWE-61   Symlink Following          ✓   CWE-377  Temp File           ✓
CWE-158  NUL Byte Injection        ✓   CWE-338  Insecure Random     ✓
CWE-208  Timing Attack             ✓   CWE-617  Reachable Assert    ✓
CWE-489  Active Debug Code          ✓   CWE-73   File Write          ✓
CWE-778  Insufficient Logging       ✓   CWE-134  Format String       ✓
CWE-453  Insecure Default           ✓   CWE-328  Weak Hash           ✓
CWE-601  Open Redirect             ✓   CWE-532  Log Secrets          ✓
CWE-295  Disabled TLS Verify        ✓   CWE-327  Weak Crypto          ✓
CWE-22   ZipSlip / TarSlip          ✓   CWE-798  Hardcoded Tokens     ✓
CWE-1007 Trojan Source (B613)      ✓   CWE-1088 Request Timeout     ✓
CWE-322  SSH Host Key Verify        ✓   CWE-391  except:pass/continue ✓
CWE-502  torch.load (ML pickle)     ✓   CWE-94   pandas eval/query    ✓
CWE-502  numpy.load + read_pickle   ✓   CWE-114  numpy lib injection  ✓
CWE-611  pandas read_xml XXE        ✓
CWE-829  .pth Startup Hooks         ✓   CWE-502  Parquet Arrow Ext     ✓
CWE-1104 Unbounded Dep Pins        ✓   CWE-502  ML Model File Load    ✓
CWE-94   Decode-then-Execute Chains ✓   CWE-1327 Bind All Interfaces (B104) ✓
CWE-326  Weak TLS Version (B502-504) ✓   CWE-1104 Legacy PyCrypto Import   ✓
CWE-94   HF trust_remote_code (B615)  ✓   CWE-1104 HF Unpinned Revision     ✓

Referenced CVE Database
=======================
CVE-2026-56315  picklescan <1.0.4 bypass                   (Python stdlib)
CVE-2026-24009  Docling RCE via PyYAML shadow vulnerability  (YAML)
CVE-2025-68664  LangChain Core SSTI/RCE deserialisation     (SSTI)
CVE-2026-0763   GPT Academic pickle RCE (CVSS 9.8)          (pickle)
CVE-2025-61774  PyVista dependency confusion RCE            (supply-chain)
CVE-2026-27834  Python urllib CERT_NONE MITM                (TLS)
CVE-2026-20624  Python tarfile path traversal RCE           (ZipSlip)
CVE-2024-37891  urllib3 HTTP redirect race condition        (dep)
CVE-2024-45187  Dask YAML RCE (CVSS 9.8)                   (dep)
CVE-2025-27516  Jinja2 SSTI via template filename           (dep)
CVE-2026-41486  Ray Parquet cloudpickle.loads RCE (CVSS 10) (parquet)
CVE-2025-30065  Apache Parquet Avro schema RCE (CVSS 10)   (parquet)
CVE-2026-41205  Mako template double-slash path traversal   (mako)
CVE-2026-44307  Mako template backslash path traversal      (mako)
CVE-2024-9880   pandas.eval/df.query sandbox bypass RCE     (pandas)
CVE-2019-6446   numpy.load pickle RCE                       (numpy)
dill-4vulns     dill: 4 extra RCE vectors beyond pickle     (dill)
CVE-2026-42208  LiteLLM .pth backdoor via transitive dep    (.pth / supply-chain)
CVE-2026-41486  Ray Parquet cloudpickle.loads RCE (CVSS 10) (parquet-ext)
OWASP ML06     ML model pickle-based formats RCE            (ML supply-chain)
pydepgate       decode-then-execute chains on PyPI           (supply-chain)
"""
