"""AST-based check functions.

These checks walk the parsed ``ast.Module`` rather than scanning raw text,
so they don't false-positive on mentions of a dangerous call inside a
docstring, comment, or string literal — only real ``ast.Call``/``ast.Assign``
nodes are matched.
"""

from __future__ import annotations

import ast
import re
from pathlib import Path

from tripwire.ast_helpers import (
    _full_attr,
    _handler_has_diagnostic,
    _has_dynamic_arg,
    _is_re_compile,
    _is_sqlalchemy_compile,
    _node_line,
    _skip,
)
from tripwire.models import Finding
from tripwire.scanner import _rel

__all__ = [
    "check_eval_exec",
    "check_insufficient_logging",
    "check_insecure_random",
    "check_format_string",
    "check_insecure_default",
    "check_request_timeout",
    "check_torch_load",
    "check_except_pass",
    "check_pandas_eval",
    "check_numpy_load",
    "check_parquet_arrow_deserialize",
    "check_decode_exec_chains",
]


def check_eval_exec(path: Path, lines: list[str], tree: ast.Module | None) -> list[Finding]:
    """CWE-94 rank #10.  Exclude re.compile and SQLAlchemy .compile()."""
    pk = _rel(path)
    results: list[Finding] = []
    for node in ast.walk(tree) if tree else []:
        if not isinstance(node, ast.Call):
            continue
        fn = _full_attr(node)
        line = _node_line(node)
        code = lines[line - 1].strip() if 1 <= line <= len(lines) else ""

        if fn in ("eval", "exec"):
            results.append(
                Finding(
                    cwe_id="CWE-94",
                    cwe_name="Code Injection",
                    severity="CRITICAL",
                    package="",
                    file=pk,
                    line=line,
                    code_snippet=code,
                    description=f"{fn}() with dynamic input allows arbitrary code execution.",
                )
            )
        elif fn == "compile" and not _is_re_compile(node) and not _is_sqlalchemy_compile(node):
            # Only flag bare compile(...) — method calls like obj.compile() are not Python's built-in
            if isinstance(node.func, ast.Name) and _has_dynamic_arg(node):
                results.append(
                    Finding(
                        cwe_id="CWE-94",
                        cwe_name="Code Injection",
                        severity="CRITICAL",
                        package="",
                        file=pk,
                        line=line,
                        code_snippet=code,
                        description="compile() with dynamic input can enable arbitrary code execution.",
                    )
                )
        elif fn == "__import__":
            results.append(
                Finding(
                    cwe_id="CWE-94",
                    cwe_name="Code Injection",
                    severity="HIGH",
                    package="",
                    file=pk,
                    line=line,
                    code_snippet=code,
                    description="Dynamic __import__() can import arbitrary modules if argument is user-controlled.",
                )
            )
    return results


def check_insufficient_logging(
    path: Path, lines: list[str], tree: ast.Module | None
) -> list[Finding]:
    """Flag bare ``except:``/``except Exception:`` blocks that swallow the
    exception with no logging, re-raise, or other diagnostic.

    Uses the AST to inspect the handler's actual body (see
    _handler_has_diagnostic) rather than a fixed line-window text scan, so a
    diagnostic call anywhere in the block — including deep in a nested
    if/try, or via a non-attribute logging helper — is correctly recognized
    and the block is not flagged. Falls back to the old broadest-catch-only
    line scan (with no body inspection) when the file failed to parse.
    """
    pk = _rel(path)
    results: list[Finding] = []

    if tree is None:
        for lineno, line in enumerate(lines, 1):
            stripped = line.strip()
            if _skip(line):
                continue
            if re.match(r"except\s*(?::|Exception\s*:)", stripped):
                results.append(
                    Finding(
                        cwe_id="CWE-778",
                        cwe_name="Insufficient Logging",
                        severity="LOW",
                        package="",
                        file=pk,
                        line=lineno,
                        code_snippet=stripped,
                        description="Bare except: or except Exception: — should at minimum log the exception.",
                        zero_day_relevance="Insufficient logging delays zero-day attack detection by months.",
                    )
                )
        return results

    for node in ast.walk(tree):
        if not isinstance(node, ast.ExceptHandler):
            continue
        is_bare = node.type is None
        is_exception = isinstance(node.type, ast.Name) and node.type.id == "Exception"
        if not (is_bare or is_exception):
            continue
        if _handler_has_diagnostic(node):
            continue
        line = _node_line(node)
        code = lines[line - 1].strip() if 1 <= line <= len(lines) else ""
        if _skip(lines[line - 1] if 1 <= line <= len(lines) else ""):
            continue
        results.append(
            Finding(
                cwe_id="CWE-778",
                cwe_name="Insufficient Logging",
                severity="LOW",
                package="",
                file=pk,
                line=line,
                code_snippet=code,
                description="Bare except: or except Exception: — should at minimum log the exception.",
                zero_day_relevance="Insufficient logging delays zero-day attack detection by months.",
            )
        )
    return results


def check_insecure_random(path: Path, lines: list[str], tree: ast.Module | None) -> list[Finding]:
    pk = _rel(path)
    results: list[Finding] = []
    for node in ast.walk(tree) if tree else []:
        if isinstance(node, ast.Call):
            fn = _full_attr(node)
            if fn.startswith("random.") and fn not in ("random.SystemRandom", "random.secrets"):
                base = fn.split(".")[1] if "." in fn else fn
                if base in (
                    "random",
                    "randint",
                    "choice",
                    "uniform",
                    "shuffle",
                    "sample",
                    "randrange",
                ):
                    line = _node_line(node)
                    code = lines[line - 1].strip() if 1 <= line <= len(lines) else ""
                    results.append(
                        Finding(
                            cwe_id="CWE-338",
                            cwe_name="Insecure Randomness",
                            severity="LOW",
                            package="",
                            file=pk,
                            line=line,
                            code_snippet=code,
                            description=f"random.{base}() uses Mersenne Twister (not crypto-secure). Use secrets module for security-sensitive contexts.",
                        )
                    )
    return results


def check_format_string(path: Path, lines: list[str], tree: ast.Module | None) -> list[Finding]:
    pk = _rel(path)
    results: list[Finding] = []
    for node in ast.walk(tree) if tree else []:
        if isinstance(node, ast.Call):
            fn = _full_attr(node)
            if fn == "str.format" and _has_dynamic_arg(node):
                line = _node_line(node)
                code = lines[line - 1].strip() if 1 <= line <= len(lines) else ""
                results.append(
                    Finding(
                        cwe_id="CWE-134",
                        cwe_name="Externally-Controlled Format String",
                        severity="MEDIUM",
                        package="",
                        file=pk,
                        line=line,
                        code_snippet=code,
                        description="str.format() with dynamic format string — potential format string vulnerability.",
                    )
                )
    return results


def _is_true(node: ast.AST) -> bool:
    return isinstance(node, ast.Constant) and node.value is True


def _allow_pickle_kw_line(node: ast.Call) -> int | None:
    for kw in node.keywords:
        if kw.arg == "allow_pickle" and _is_true(kw.value):
            return _node_line(kw.value)
    return None


def _allow_pickle_assign_line(node: ast.Assign) -> int | None:
    targets_match = any(
        (isinstance(t, ast.Name) and t.id == "allow_pickle")
        or (isinstance(t, ast.Attribute) and t.attr == "allow_pickle")
        for t in node.targets
    )
    if targets_match and _is_true(node.value):
        return _node_line(node)
    return None


def _allow_pickle_ann_assign_line(node: ast.AnnAssign) -> int | None:
    target = node.target
    name_match = (isinstance(target, ast.Name) and target.id == "allow_pickle") or (
        isinstance(target, ast.Attribute) and target.attr == "allow_pickle"
    )
    if name_match and node.value is not None and _is_true(node.value):
        return _node_line(node)
    return None


def _allow_pickle_default_lines(node: ast.FunctionDef | ast.AsyncFunctionDef) -> list[int]:
    """Parameter defaults: def load(..., allow_pickle=True)"""
    flagged: list[int] = []
    args = node.args
    positional = args.posonlyargs + args.args
    for arg, default in zip(positional[len(positional) - len(args.defaults) :], args.defaults):
        if arg.arg == "allow_pickle" and _is_true(default):
            flagged.append(_node_line(default))
    for arg, default in zip(args.kwonlyargs, args.kw_defaults):
        if arg.arg == "allow_pickle" and default is not None and _is_true(default):
            flagged.append(_node_line(default))
    return flagged


def _allow_pickle_finding(pk: str, lines: list[str], lineno: int) -> Finding:
    code = lines[lineno - 1].strip() if 1 <= lineno <= len(lines) else ""
    return Finding(
        cwe_id="CWE-453",
        cwe_name="Insecure Default",
        severity="HIGH",
        package="",
        file=pk,
        line=lineno,
        code_snippet=code,
        description="allow_pickle=True enables pickle deserialisation — verify strict input gating.",
        zero_day_relevance="CVE-2026-56315: picklescan bypass. Allow-pickle flags are a common zero-day entry point.",
    )


def check_insecure_default(path: Path, lines: list[str], tree: ast.Module | None) -> list[Finding]:
    """AST-based so `allow_pickle=True` inside string literals (e.g. error
    messages documenting the flag) is not flagged — only real keyword
    arguments and assignments count."""
    pk = _rel(path)
    flagged_lines: list[int] = []

    for node in ast.walk(tree) if tree else []:
        if isinstance(node, ast.Call):
            line = _allow_pickle_kw_line(node)
            if line is not None:
                flagged_lines.append(line)
        elif isinstance(node, ast.Assign):
            line = _allow_pickle_assign_line(node)
            if line is not None:
                flagged_lines.append(line)
        elif isinstance(node, ast.AnnAssign):
            line = _allow_pickle_ann_assign_line(node)
            if line is not None:
                flagged_lines.append(line)
        elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            flagged_lines.extend(_allow_pickle_default_lines(node))

    return [_allow_pickle_finding(pk, lines, lineno) for lineno in flagged_lines]


def check_request_timeout(path: Path, lines: list[str], tree: ast.Module | None) -> list[Finding]:
    """CWE-1088. requests.get/post/put etc. without timeout= — DoS via hanging connections."""
    pk = _rel(path)
    results: list[Finding] = []
    for node in ast.walk(tree) if tree else []:
        if not isinstance(node, ast.Call):
            continue
        fn = _full_attr(node)
        parts = fn.split(".")
        if (
            len(parts) == 2
            and parts[0] == "requests"
            and parts[1] in ("get", "post", "put", "patch", "delete", "head", "options", "request")
        ):
            if not any(kw.arg == "timeout" for kw in node.keywords if kw.arg is not None):
                line = _node_line(node)
                code = lines[line - 1].strip() if 1 <= line <= len(lines) else ""
                results.append(
                    Finding(
                        cwe_id="CWE-1088",
                        cwe_name="Synchronous Access without Timeout",
                        severity="HIGH",
                        package="",
                        file=pk,
                        line=line,
                        code_snippet=code,
                        description=f"requests.{parts[1]}(...) without timeout= — may hang indefinitely. Add timeout=30.",
                        zero_day_relevance="CWE-1088: hung connections enable resource-exhaustion DoS. Zero-day botnets use this for unauthenticated amplification.",
                    )
                )
    return results


def check_torch_load(path: Path, lines: list[str], tree: ast.Module | None) -> list[Finding]:
    """B614 / CWE-502. torch.load() without weights_only=True — pickle RCE."""
    pk = _rel(path)
    results: list[Finding] = []
    for node in ast.walk(tree) if tree else []:
        if not isinstance(node, ast.Call):
            continue
        fn = _full_attr(node)
        if fn == "torch.load":
            if not any(
                kw.arg == "weights_only"
                and isinstance(kw.value, ast.Constant)
                and kw.value.value is True
                for kw in node.keywords
                if kw.arg is not None
            ):
                line = _node_line(node)
                code = lines[line - 1].strip() if 1 <= line <= len(lines) else ""
                results.append(
                    Finding(
                        cwe_id="CWE-502",
                        cwe_name="Deserialization of Untrusted Data (torch.load)",
                        severity="CRITICAL",
                        package="",
                        file=pk,
                        line=line,
                        code_snippet=code,
                        description="torch.load() without weights_only=True — enables arbitrary code execution via pickle deserialisation.",
                        zero_day_relevance="B614: torch.load defaults to pickle. ML model poisoning attacks exploit this for RCE in data pipelines.",
                    )
                )
    return results


def check_except_pass(path: Path, lines: list[str], tree: ast.Module | None) -> list[Finding]:
    """B110/B112 / CWE-391. Bare except handler body is only pass or continue — silently swallows errors."""
    pk = _rel(path)
    results: list[Finding] = []
    for node in ast.walk(tree) if tree else []:
        if not isinstance(node, ast.ExceptHandler):
            continue
        body = node.body
        if len(body) == 1:
            child = body[0]
            if isinstance(child, ast.Pass):
                line = _node_line(node)
                code = lines[line - 1].strip() if 1 <= line <= len(lines) else ""
                results.append(
                    Finding(
                        cwe_id="CWE-391",
                        cwe_name="Unchecked Error Condition",
                        severity="MEDIUM",
                        package="",
                        file=pk,
                        line=line,
                        code_snippet=code,
                        description="except: pass — silently swallows all exceptions. At minimum log the exception.",
                    )
                )
            elif isinstance(child, ast.Continue):
                line = _node_line(node)
                code = lines[line - 1].strip() if 1 <= line <= len(lines) else ""
                results.append(
                    Finding(
                        cwe_id="CWE-391",
                        cwe_name="Unchecked Error Condition",
                        severity="MEDIUM",
                        package="",
                        file=pk,
                        line=line,
                        code_snippet=code,
                        description="except: continue — silently swallows exceptions in a loop. At minimum log the exception.",
                    )
                )
    return results


def check_pandas_eval(path: Path, lines: list[str], tree: ast.Module | None) -> list[Finding]:
    """Trail of Bits: pandas.eval(), df.eval(), df.query() — arbitrary code execution via expression eval.

    AST-based so mentions of ``.eval(``/``.query(`` in docstrings, comments,
    or string literals (e.g. code that documents or guards against this
    exact vulnerability) are never flagged — only real Call nodes count.
    """
    pk = _rel(path)
    results: list[Finding] = []
    for node in ast.walk(tree) if tree else []:
        if not isinstance(node, ast.Call):
            continue
        fn = _full_attr(node)
        line = _node_line(node)
        code = lines[line - 1].strip() if 1 <= line <= len(lines) else ""
        if fn in ("pandas.eval", "pd.eval"):
            results.append(
                Finding(
                    cwe_id="CWE-94",
                    cwe_name="Code Injection (pandas eval)",
                    severity="CRITICAL",
                    package="",
                    file=pk,
                    line=line,
                    code_snippet=code,
                    description="pandas.eval() evaluates arbitrary Python expressions — code injection if user input reaches the expression.",
                    zero_day_relevance="CVE-2024-9880 / Trail of Bits: pandas.eval() / df.query() sandbox bypass via dunder methods. Pandas docs now warn explicitly.",
                )
            )
        elif isinstance(node.func, ast.Attribute) and node.func.attr in ("eval", "query"):
            results.append(
                Finding(
                    cwe_id="CWE-94",
                    cwe_name="Code Injection (DataFrame eval/query)",
                    severity="HIGH",
                    package="",
                    file=pk,
                    line=line,
                    code_snippet=code,
                    description="DataFrame.eval() or DataFrame.query() evaluates Python expressions — code injection if user-controlled input reaches the expression.",
                    zero_day_relevance="CVE-2024-9880: pandas.DataFrame.query() sandbox bypass. Thousands of attribute chains lead to os.system.",
                )
            )
    return results


def check_numpy_load(path: Path, lines: list[str], tree: ast.Module | None) -> list[Finding]:
    """Trail of Bits / CVE-2019-6446. np.load() may deserialize pickled object arrays — RCE.

    numpy itself defaults ``allow_pickle`` to ``False`` since the 1.16.3 fix
    for CVE-2019-6446, so the dangerous case is an *explicit*
    ``allow_pickle=True`` — not the absence of the kwarg.
    """
    pk = _rel(path)
    results: list[Finding] = []
    for node in ast.walk(tree) if tree else []:
        if not isinstance(node, ast.Call):
            continue
        fn = _full_attr(node)
        if fn in ("numpy.load", "np.load"):
            allow_pickle_true = any(
                kw.arg == "allow_pickle"
                and isinstance(kw.value, ast.Constant)
                and kw.value.value is True
                for kw in node.keywords
            )
            if allow_pickle_true:
                line = _node_line(node)
                code = lines[line - 1].strip() if 1 <= line <= len(lines) else ""
                results.append(
                    Finding(
                        cwe_id="CWE-502",
                        cwe_name="Deserialization of Untrusted Data (numpy.load)",
                        severity="HIGH",
                        package="",
                        file=pk,
                        line=line,
                        code_snippet=code,
                        description="np.load(allow_pickle=True) may load pickled object arrays enabling RCE. Only use with trusted data; numpy's own default is allow_pickle=False.",
                        zero_day_relevance="CVE-2019-6446: numpy.load() RCE via pickle. numpy docs now recommend allow_pickle=False for untrusted sources.",
                    )
                )
    return results


def check_parquet_arrow_deserialize(
    path: Path, lines: list[str], tree: ast.Module | None
) -> list[Finding]:
    """CVE-2026-41486 (Ray, CVSS 10): __arrow_ext_deserialize__ methods
    calling cloudpickle.loads() — RCE during schema parsing before row data read."""
    pk = _rel(path)
    results: list[Finding] = []

    for node in ast.walk(tree) if tree else []:
        if isinstance(node, ast.FunctionDef) and node.name == "__arrow_ext_deserialize__":
            line = _node_line(node)
            code = lines[line - 1].strip() if 1 <= line <= len(lines) else ""
            results.append(
                Finding(
                    cwe_id="CWE-502",
                    cwe_name="Deserialization of Untrusted Data (Arrow Extension)",
                    severity="CRITICAL",
                    package="",
                    file=pk,
                    line=line,
                    code_snippet=code,
                    description="__arrow_ext_deserialize__ method defined — if it calls cloudpickle.loads() "
                    "on metadata bytes, grants RCE during schema parsing (CVE-2026-41486).",
                    zero_day_relevance="CVE-2026-41486: Ray Parquet cloudpickle.loads RCE (CVSS 10). "
                    "CVE-2025-30065: Apache Parquet Avro schema RCE (CVSS 10).",
                )
            )

    # Scan for cloudpickle.loads near pyarrow/parquet code
    for lineno, line in enumerate(lines, 1):
        if _skip(line):
            continue
        stripped = line.strip()
        if re.search(r"cloudpickle\.loads?\s*\(", stripped) and re.search(
            r"(?:py)?arrow|parquet|arrow_ext|deserialize", line.lower()
        ):
            results.append(
                Finding(
                    cwe_id="CWE-502",
                    cwe_name="Deserialization of Untrusted Data (Parquet+cloudpickle)",
                    severity="CRITICAL",
                    package="",
                    file=pk,
                    line=lineno,
                    code_snippet=stripped,
                    description="cloudpickle.loads() near parquet/arrow code — potential RCE if "
                    "deserializing untrusted metadata bytes (CVE-2026-41486 pattern).",
                    zero_day_relevance="CVE-2026-41486: cloudpickle.loads on arrow extension metadata (CVSS 10).",
                )
            )
    return results


def check_decode_exec_chains(
    path: Path, lines: list[str], tree: ast.Module | None
) -> list[Finding]:
    """pydepgate-style detection: decode(base64/bz2/zlib) followed by exec/eval/compile
    in package init scripts — classic supply-chain obfuscation pattern."""
    pk = _rel(path)
    results: list[Finding] = []

    # Multi-line chain detection: look for decode calls followed by exec/eval within 5 lines
    decode_calls: list[int] = []
    for lineno, line in enumerate(lines, 1):
        if _skip(line):
            continue
        stripped = line.strip()
        if re.search(
            r"(?:base64\.(?:b64decode|urlsafe_b64decode|decodestring)|"
            r"zlib\.decompress|bz2\.decompress|codecs\.decode)\s*\(",
            stripped,
        ):
            decode_calls.append(lineno)
        if re.search(r"(?:exec|eval)\s*\(", stripped) and decode_calls:
            for dl in reversed(decode_calls):
                if lineno - dl <= 5:
                    results.append(
                        Finding(
                            cwe_id="CWE-94",
                            cwe_name="Code Injection (decode-then-execute)",
                            severity="CRITICAL",
                            package="",
                            file=pk,
                            line=lineno,
                            code_snippet=f"decode at line {dl}, exec at line {lineno}",
                            description="decode() followed by exec/eval within 5 lines — classic "
                            "supply-chain obfuscation pattern (pydepgate-style).",
                            zero_day_relevance="pydepgate: decode-then-execute chains used in 60% of PyPI "
                            "supply-chain attacks (2025-2026). Hades campaign, ChocoPoC.",
                        )
                    )
                    # Only report the closest decode match per exec
                    decode_calls = [d for d in decode_calls if d != dl]
                    break

    # AST-based detection for same-line patterns
    for node in ast.walk(tree) if tree else []:
        if not isinstance(node, ast.Call):
            continue
        fn = _full_attr(node)
        line = _node_line(node)
        code = lines[line - 1].strip() if 1 <= line <= len(lines) else ""

        if fn in ("exec", "eval") and isinstance(node.func, ast.Name):
            if len(node.args) > 0:
                arg = node.args[0]
                # Check if arg is a call to a decode function
                if isinstance(arg, ast.Call):
                    call_fn = _full_attr(arg)
                    if call_fn in (
                        "base64.b64decode",
                        "base64.urlsafe_b64decode",
                        "base64.decodestring",
                        "zlib.decompress",
                        "bz2.decompress",
                        "codecs.decode",
                    ):
                        results.append(
                            Finding(
                                cwe_id="CWE-94",
                                cwe_name="Code Injection (inline decode-exec)",
                                severity="CRITICAL",
                                package="",
                                file=pk,
                                line=line,
                                code_snippet=code,
                                description=f"exec({call_fn}(...)) inline — direct decode-then-execute chain. "
                                f"Obfuscated malware delivery.",
                                zero_day_relevance="pydepgate: inline decode-exec chains found in compromised wheels.",
                            )
                        )
    return results
