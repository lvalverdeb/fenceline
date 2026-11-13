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

from fenceline.ast_helpers import (
    _call_name,
    _call_nodes,
    _callee,
    _dotted_matches,
    _dotted_name,
    _full_attr,
    _handler_has_diagnostic,
    _has_dynamic_arg,
    _import_aliases,
    _is_locally_safe_expr,
    _is_re_compile,
    _is_sqlalchemy_compile,
    _iter_calls_in_scope,
    _node_line,
    _skip,
)
from fenceline.models import Finding
from fenceline.scanner import _rel

__all__ = [
    "check_pickle",
    "check_command_injection",
    "check_yaml_deserialize",
    "check_ssti",
    "check_crlf",
    "check_weak_hash",
    "check_open_redirect",
    "check_tls_verify",
    "check_legacy_pycrypto",
    "check_weak_tls_version",
    "check_bind_all_interfaces",
    "check_debug_mode",
    "check_path_traversal",
    "check_model_file_load",
    "check_pandas_xml_xxe",
    "check_pandas_pickle",
    "check_zipslip",
    "check_arbitrary_write",
    "check_resource_limits",
    "check_redos",
    "check_ssrf",
    "check_exec_driver_sql",
    "check_sql_injection",
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
    "check_huggingface_unsafe_download",
    "check_unbounded_pydantic_field",
]


def check_eval_exec(path: Path, lines: list[str], tree: ast.Module | None) -> list[Finding]:
    """CWE-94 rank #10.  Exclude re.compile and SQLAlchemy .compile()."""
    pk = _rel(path)
    results: list[Finding] = []
    aliases = _import_aliases(tree)
    for node in ast.walk(tree) if tree else []:
        if not isinstance(node, ast.Call):
            continue
        fn = _callee(node, aliases)
        line = _node_line(node)
        code = lines[line - 1].strip() if 1 <= line <= len(lines) else ""

        if fn in ("eval", "exec"):
            results.append(
                Finding(
                    cwe_id="CWE-94",
                    cwe_name="Code Injection",
                    severity="CRITICAL",
                    confidence="HIGH",
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
                        confidence="HIGH",
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
                    confidence="HIGH",
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
                        confidence="HIGH",
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
                confidence="HIGH",
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
    aliases = _import_aliases(tree)
    for node in ast.walk(tree) if tree else []:
        if isinstance(node, ast.Call):
            fn = _callee(node, aliases)
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
                            confidence="HIGH",
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
    aliases = _import_aliases(tree)
    for node in ast.walk(tree) if tree else []:
        if isinstance(node, ast.Call):
            fn = _callee(node, aliases)
            if fn == "str.format" and _has_dynamic_arg(node):
                line = _node_line(node)
                code = lines[line - 1].strip() if 1 <= line <= len(lines) else ""
                results.append(
                    Finding(
                        cwe_id="CWE-134",
                        cwe_name="Externally-Controlled Format String",
                        severity="MEDIUM",
                        confidence="HIGH",
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
        confidence="HIGH",
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
    aliases = _import_aliases(tree)
    for node in ast.walk(tree) if tree else []:
        if not isinstance(node, ast.Call):
            continue
        fn = _callee(node, aliases)
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
                        confidence="HIGH",
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
    aliases = _import_aliases(tree)
    for node in ast.walk(tree) if tree else []:
        if not isinstance(node, ast.Call):
            continue
        fn = _callee(node, aliases)
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
                        confidence="HIGH",
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
                        confidence="HIGH",
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
                        confidence="HIGH",
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
    aliases = _import_aliases(tree)
    for node in ast.walk(tree) if tree else []:
        if not isinstance(node, ast.Call):
            continue
        fn = _callee(node, aliases)
        line = _node_line(node)
        code = lines[line - 1].strip() if 1 <= line <= len(lines) else ""
        if fn in ("pandas.eval", "pd.eval"):
            results.append(
                Finding(
                    cwe_id="CWE-94",
                    cwe_name="Code Injection (pandas eval)",
                    severity="CRITICAL",
                    confidence="HIGH",
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
                    confidence="HIGH",
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
    aliases = _import_aliases(tree)
    for node in ast.walk(tree) if tree else []:
        if not isinstance(node, ast.Call):
            continue
        fn = _callee(node, aliases)
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
                        confidence="HIGH",
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
                    confidence="HIGH",
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
                    confidence="HIGH",
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
    aliases = _import_aliases(tree)

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
                            confidence="HIGH",
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
        fn = _callee(node, aliases)
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
                                confidence="HIGH",
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


_HF_TRUST_REMOTE_CODE_CALL_NAMES = frozenset({"from_pretrained", "load_dataset", "pipeline"})


def check_huggingface_unsafe_download(
    path: Path, lines: list[str], tree: ast.Module | None
) -> list[Finding]:
    """B615 / OWASP ML06. HuggingFace-style `from_pretrained(...)` calls.

    Two distinct risks, both about trusting an upstream model repo:
    - `trust_remote_code=True` executes arbitrary Python shipped in the
      model repo at load time — CWE-94, the more severe of the two. The
      same kwarg, with the same RCE semantics, is also accepted by
      `datasets.load_dataset()` and `transformers.pipeline()` — not just
      `from_pretrained` — so all three call names are checked for it.
    - No `revision=` pin means `from_pretrained` follows the repo's moving
      `main` ref, so the repo owner (or anyone who compromises their
      account) can swap weights/code under an already-reviewed call site
      with no local diff to catch it — CWE-1104, supply-chain. Scoped to
      `from_pretrained` only, the call name this heuristic was written
      against.
    """
    pk = _rel(path)
    results: list[Finding] = []
    for node in ast.walk(tree) if tree else []:
        if not isinstance(node, ast.Call):
            continue
        call_name = _call_name(node)
        if call_name not in _HF_TRUST_REMOTE_CODE_CALL_NAMES:
            continue
        line = _node_line(node)
        code = lines[line - 1].strip() if 1 <= line <= len(lines) else ""
        kw_names = {kw.arg for kw in node.keywords if kw.arg is not None}
        trust_remote_code = any(
            kw.arg == "trust_remote_code" and _is_true(kw.value) for kw in node.keywords
        )

        if trust_remote_code:
            results.append(
                Finding(
                    cwe_id="CWE-94",
                    cwe_name="Code Injection (HuggingFace trust_remote_code)",
                    severity="CRITICAL",
                    confidence="HIGH",
                    package="",
                    file=pk,
                    line=line,
                    code_snippet=code,
                    description="from_pretrained(trust_remote_code=True) executes arbitrary Python "
                    "shipped in the model repo at load time — equivalent to running code from "
                    "an untrusted third party.",
                    zero_day_relevance="Malicious HuggingFace repos with trust_remote_code payloads "
                    "have been used for real supply-chain RCE against ML pipelines.",
                )
            )
        elif call_name == "from_pretrained" and "revision" not in kw_names:
            results.append(
                Finding(
                    cwe_id="CWE-1104",
                    cwe_name="Supply Chain — Unpinned Model Revision",
                    severity="MEDIUM",
                    confidence="HIGH",
                    package="",
                    file=pk,
                    line=line,
                    code_snippet=code,
                    description="from_pretrained(...) with no revision= pin follows the model repo's "
                    "moving main ref — weights or code can change under this call site with no "
                    "local diff to review. Pin revision= to a specific commit SHA or tag.",
                    zero_day_relevance="OWASP ML06: unpinned model sources are a supply-chain vector — "
                    "a compromised or malicious upstream repo push propagates silently on next load.",
                )
            )
    return results


def _expr_dotted_name(node: ast.expr) -> str:
    """Dotted name for a bare ``Name``/``Attribute`` chain, e.g.
    ``pydantic.BaseModel`` -> ``"pydantic.BaseModel"``. Mirrors
    ``_full_attr``, but for a general expression (a class base) rather
    than specifically a ``Call``'s ``.func``. Empty string for anything
    else (a subscript, a call, ...)."""
    parts: list[str] = []
    cur = node
    while isinstance(cur, ast.Attribute):
        parts.append(cur.attr)
        cur = cur.value
    if isinstance(cur, ast.Name):
        parts.append(cur.id)
        parts.reverse()
        return ".".join(parts)
    return ""


def _is_pydantic_base(node: ast.expr) -> bool:
    name = _expr_dotted_name(node)
    return name == "BaseModel" or name.endswith(".BaseModel")


# Pydantic's BaseModel is used for internal config/settings objects just as
# often as for network-facing request bodies -- an unbounded str field on a
# config class isn't a real attack surface. Narrowing to conventional
# request/input-DTO name suffixes (matching FastAPI community convention,
# and the exact EnrollRequest/VerifyRequest/IdentifyRequest names this check
# was written to catch) keeps the signal-to-noise ratio usable rather than
# flagging every settings class in a codebase.
_REQUEST_MODEL_SUFFIXES = ("Request", "Input", "Payload", "Body", "Params")


def _looks_like_request_model(class_name: str) -> bool:
    return class_name.endswith(_REQUEST_MODEL_SUFFIXES)


def _str_or_bytes_base_type(annotation: ast.expr) -> str | None:
    """``"str"``/``"bytes"`` if *annotation* is a bare, ``Optional``-wrapped,
    ``| None``-wrapped, or ``Annotated``-wrapped ``str``/``bytes`` type;
    ``None`` otherwise.

    Deliberately narrow: an annotation that's itself a ``Call``
    (``constr(...)``, a custom validator type) is left alone on the
    assumption that whoever wrote it already thought about constraints, and
    anything that isn't ``str``/``bytes`` at all (``int``, a collection, a
    custom model) isn't this check's concern.
    """
    if isinstance(annotation, ast.Name) and annotation.id in ("str", "bytes"):
        return annotation.id
    if isinstance(annotation, ast.Subscript) and isinstance(annotation.value, ast.Name):
        if (
            annotation.value.id == "Optional"
            and isinstance(annotation.slice, ast.Name)
            and annotation.slice.id in ("str", "bytes")
        ):
            return annotation.slice.id
        if (
            annotation.value.id == "Annotated"
            and isinstance(annotation.slice, ast.Tuple)
            and annotation.slice.elts
            and isinstance(annotation.slice.elts[0], ast.Name)
            and annotation.slice.elts[0].id in ("str", "bytes")
        ):
            return annotation.slice.elts[0].id
    if isinstance(annotation, ast.BinOp) and isinstance(annotation.op, ast.BitOr):
        for side in (annotation.left, annotation.right):
            if isinstance(side, ast.Name) and side.id in ("str", "bytes"):
                return side.id
    return None


def _field_call_has_max_length(node: ast.expr) -> bool:
    return (
        isinstance(node, ast.Call)
        and _call_name(node) in ("Field", "StringConstraints")
        and any(kw.arg == "max_length" for kw in node.keywords)
    )


def _has_length_constraint(annotation: ast.expr, default: ast.expr | None) -> bool:
    if default is not None and _field_call_has_max_length(default):
        return True
    if (
        isinstance(annotation, ast.Subscript)
        and isinstance(annotation.value, ast.Name)
        and annotation.value.id == "Annotated"
        and isinstance(annotation.slice, ast.Tuple)
    ):
        return any(_field_call_has_max_length(item) for item in annotation.slice.elts[1:])
    return False


def check_unbounded_pydantic_field(
    path: Path, lines: list[str], tree: ast.Module | None
) -> list[Finding]:
    """OWASP API4:2023 / CWE-770. A Pydantic ``BaseModel`` field typed
    ``str``/``bytes`` with no length constraint (``Field(max_length=...)``,
    ``Annotated[str, Field(max_length=...)]``) accepts an arbitrarily large
    request body — a client can force expensive decode/validation work
    (e.g. a base64-encoded image field) before any handler logic runs, with
    no size check anywhere in the request pipeline.

    Only checks direct ``BaseModel`` subclasses — a field on a class that
    inherits from an intermediate local base class (not textually
    ``BaseModel`` itself) is a known false negative, same class of
    limitation as this codebase's other single-hop heuristic checks. Also
    restricted to classes named like a request/input DTO (``*Request``,
    ``*Input``, ``*Payload``, ``*Body``, ``*Params``) — see
    ``_looks_like_request_model`` for why: without this, every internal
    config/settings ``BaseModel`` in a codebase fires too, drowning out the
    real signal.
    """
    pk = _rel(path)
    results: list[Finding] = []
    for node in ast.walk(tree) if tree else []:
        if not isinstance(node, ast.ClassDef):
            continue
        if not _looks_like_request_model(node.name):
            continue
        if not any(_is_pydantic_base(base) for base in node.bases):
            continue
        for stmt in node.body:
            if not isinstance(stmt, ast.AnnAssign) or not isinstance(stmt.target, ast.Name):
                continue
            base_type = _str_or_bytes_base_type(stmt.annotation)
            if base_type is None:
                continue
            if _has_length_constraint(stmt.annotation, stmt.value):
                continue
            line = _node_line(stmt)
            code = lines[line - 1].strip() if 1 <= line <= len(lines) else ""
            results.append(
                Finding(
                    cwe_id="CWE-770",
                    cwe_name="Unbounded Request Field Size",
                    severity="MEDIUM",
                    confidence="MEDIUM",
                    package="",
                    file=pk,
                    line=line,
                    code_snippet=code,
                    description=(
                        f"'{stmt.target.id}: {base_type}' has no length constraint — a client "
                        "can send an arbitrarily large value, forcing expensive decode/validation "
                        "work before any handler logic runs. Add Field(max_length=...) or an "
                        "Annotated[str, StringConstraints(max_length=...)]."
                    ),
                    zero_day_relevance="OWASP API4:2023: Unrestricted Resource Consumption — "
                    "unbounded request fields are a common DoS vector in FastAPI/Pydantic APIs.",
                )
            )
    return results


# ── Converted from line-regex checks (Phase 2) ────────────────────────────
#
# Each of the checks below used to regex-match a line of source. Matching the
# parsed AST instead means: a quoted mention in a string literal can't match,
# `pkg.pickle.loads(...)` is recognised while `cloudpickle.loads(...)` is kept
# distinct, keyword arguments are inspected rather than pattern-matched, and
# a call with only literal arguments can be told apart from one fed data.


def _code_at(lines: list[str], line: int) -> str:
    return lines[line - 1].strip() if 1 <= line <= len(lines) else ""


def _calls(tree: ast.Module | None) -> tuple[ast.Call, ...]:
    return _call_nodes(tree)


def _keyword_is(node: ast.Call, name: str, value: bool) -> bool:
    return any(
        kw.arg == name and isinstance(kw.value, ast.Constant) and kw.value.value is value
        for kw in node.keywords
    )


_PICKLE_CALLS: tuple[tuple[str, str, str], ...] = (
    ("pickle.loads", "pickle.loads() / pickle.load()", "CRITICAL"),
    ("pickle.load", "pickle.loads() / pickle.load()", "CRITICAL"),
    ("pickle.Unpickler", "pickle.Unpickler()", "CRITICAL"),
    ("cloudpickle.loads", "cloudpickle.loads() / cloudpickle.load()", "CRITICAL"),
    ("cloudpickle.load", "cloudpickle.loads() / cloudpickle.load()", "CRITICAL"),
    ("dill.loads", "dill.loads() / dill.load()", "CRITICAL"),
    ("dill.load", "dill.loads() / dill.load()", "CRITICAL"),
    ("joblib.load", "joblib.load()", "HIGH"),
    ("shelve.open", "shelve.open()", "HIGH"),
    ("marshal.loads", "marshal.loads() / marshal.load()", "HIGH"),
    ("marshal.load", "marshal.loads() / marshal.load()", "HIGH"),
)


def check_pickle(path: Path, lines: list[str], tree: ast.Module | None) -> list[Finding]:
    """CWE-502 rank #15. Zero-days: CVE-2026-56315 (picklescan bypass),
    CVE-2026-0763 (GPT Academic, CVSS 9.8)."""
    pk = _rel(path)
    results: list[Finding] = []
    aliases = _import_aliases(tree)
    for node in _calls(tree):
        fn = _callee(node, aliases)
        for name, label, sev in _PICKLE_CALLS:
            if _dotted_matches(fn, name):
                line = _node_line(node)
                results.append(
                    Finding(
                        cwe_id="CWE-502",
                        cwe_name="Deserialization of Untrusted Data",
                        severity=sev,
                        confidence="HIGH",
                        package="",
                        file=pk,
                        line=line,
                        code_snippet=_code_at(lines, line),
                        description=f"Unsafe deserialisation via {label}. Allows arbitrary code execution.",
                        zero_day_relevance="CVE-2026-56315 picklescan <1.0.4 bypass (uuid, imaplib etc. unblocked); "
                        "CVE-2026-0763 GPT Academic CVSS 9.8; LangChain CVE-2025-68664 SSTI+pickle chain",
                    )
                )
                break
    return results


_COMMAND_CALLS: tuple[tuple[str, str], ...] = (
    ("os.system", "CRITICAL"),
    ("os.popen", "CRITICAL"),
    ("subprocess.call", "HIGH"),
    ("subprocess.Popen", "HIGH"),
    ("subprocess.run", "HIGH"),
    ("subprocess.check_output", "HIGH"),
    ("subprocess.getoutput", "HIGH"),
    ("subprocess.getstatusoutput", "HIGH"),
    ("os.execv", "HIGH"),
    ("os.execl", "HIGH"),
    ("os.execve", "HIGH"),
    ("os.execvp", "HIGH"),
    ("pty.spawn", "HIGH"),
    ("asyncio.create_subprocess_shell", "HIGH"),
)


def check_command_injection(path: Path, lines: list[str], tree: ast.Module | None) -> list[Finding]:
    """CWE-78 rank #9, CWE-77 rank #23."""
    pk = _rel(path)
    results: list[Finding] = []
    aliases = _import_aliases(tree)
    for node in _calls(tree):
        fn = _callee(node, aliases)
        line = _node_line(node)
        for call, sev in _COMMAND_CALLS:
            if _dotted_matches(fn, call):
                results.append(
                    Finding(
                        cwe_id="CWE-78",
                        cwe_name="OS Command Injection",
                        severity=sev,
                        confidence="HIGH",
                        package="",
                        file=pk,
                        line=line,
                        code_snippet=_code_at(lines, line),
                        description=f"{call}() spawns subprocesses; may allow command injection if arguments are unvalidated.",
                        zero_day_relevance="CWE-78: 20 CVEs in KEV. Still a top Python zero-day vector.",
                    )
                )
                break
        if _keyword_is(node, "shell", True):
            results.append(
                Finding(
                    cwe_id="CWE-78",
                    cwe_name="OS Command Injection",
                    severity="HIGH",
                    confidence="HIGH",
                    package="",
                    file=pk,
                    line=line,
                    code_snippet=_code_at(lines, line),
                    description="shell=True enables shell injection in subprocess calls.",
                )
            )
    return results


def check_yaml_deserialize(path: Path, lines: list[str], tree: ast.Module | None) -> list[Finding]:
    """CWE-502 via PyYAML.  Zero-day: CVE-2026-24009 Docling RCE.
    ``yaml.unsafe_load()`` is PyYAML's own alias for
    ``yaml.load(x, Loader=yaml.UnsafeLoader)`` -- same RCE, different call
    name. ``yaml.load`` is safe only when a SafeLoader (``yaml.SafeLoader``,
    ``yaml.CSafeLoader``) is passed, positionally or as ``Loader=``."""
    pk = _rel(path)
    results: list[Finding] = []
    aliases = _import_aliases(tree)
    for node in _calls(tree):
        fn = _callee(node, aliases)
        if _dotted_matches(fn, "yaml.load"):
            loader_exprs = [*node.args, *(kw.value for kw in node.keywords)]
            if any("SafeLoader" in _dotted_name(e) for e in loader_exprs):
                continue
        elif not _dotted_matches(fn, "yaml.unsafe_load"):
            continue
        line = _node_line(node)
        results.append(
            Finding(
                cwe_id="CWE-502",
                cwe_name="Deserialization of Untrusted Data",
                severity="CRITICAL",
                confidence="HIGH",
                package="",
                file=pk,
                line=line,
                code_snippet=_code_at(lines, line),
                description="yaml.load()/yaml.unsafe_load() without SafeLoader — enables arbitrary code execution.",
                zero_day_relevance="CVE-2026-24009: Docling RCE via PyYAML shadow vulnerability. "
                "Transitive YAML deps can introduce RCE without a direct yaml import.",
            )
        )
    return results


def check_ssti(path: Path, lines: list[str], tree: ast.Module | None) -> list[Finding]:
    """CWE-1336. Zero-day: LangChain CVE-2025-68664. A ``Template(...)``
    instantiation (jinja2, string, or any other) fed a non-literal: a
    template built from a string literal can't be user-controlled."""
    pk = _rel(path)
    results: list[Finding] = []
    for node in _calls(tree):
        if _call_name(node) != "Template" or not _has_dynamic_arg(node):
            continue
        line = _node_line(node)
        results.append(
            Finding(
                cwe_id="CWE-1336",
                cwe_name="Server-Side Template Injection",
                severity="HIGH",
                confidence="HIGH",
                package="",
                file=pk,
                line=line,
                code_snippet=_code_at(lines, line),
                description="Template instantiation — SSTI if template string is user-controlled.",
                zero_day_relevance="CVE-2025-68664: LangChain Core SSTI zero-day chaining deserialisation + Jinja2 for RCE.",
            )
        )
    return results


def _has_crlf(expr: ast.expr) -> bool:
    if not isinstance(expr, ast.Constant):
        return False
    v = expr.value
    if isinstance(v, bytes):
        return b"\r\n" in v or b"%0d%0a" in v.lower()
    return isinstance(v, str) and ("\r\n" in v or "%0d%0a" in v.lower())


def check_crlf(path: Path, lines: list[str], tree: ast.Module | None) -> list[Finding]:
    """CWE-93. A CRLF-bearing literal *combined with non-literal data* --
    ``data + "\\r\\n"``, ``"%s\\r\\n" % x``, ``f"{x}\\r\\n"``, ``"...\\r\\n".format(x)``
    -- is the response-splitting shape. A bare ``b"\\r\\n"`` constant (an HTTP
    parser's delimiter, a comparison, a ``write()`` of a fixed line) is not,
    and on real HTTP code those outnumbered the combined ones ten to one."""
    pk = _rel(path)
    results: list[Finding] = []
    seen: set[int] = set()
    for node in ast.walk(tree) if tree else []:
        if isinstance(node, ast.BinOp) and isinstance(node.op, (ast.Add, ast.Mod)):
            sides = (node.left, node.right)
            hit = any(_has_crlf(s) for s in sides) and any(
                not isinstance(s, ast.Constant) for s in sides
            )
        elif isinstance(node, ast.JoinedStr):
            hit = any(_has_crlf(v) for v in node.values) and any(
                isinstance(v, ast.FormattedValue) for v in node.values
            )
        elif isinstance(node, ast.Call):
            hit = (
                isinstance(node.func, ast.Attribute)
                and node.func.attr == "format"
                and _has_crlf(node.func.value)
                and bool(node.args or node.keywords)
            )
        else:
            continue
        line = _node_line(node)
        if not hit or line in seen:
            continue
        seen.add(line)
        results.append(
            Finding(
                cwe_id="CWE-93",
                cwe_name="CRLF Injection",
                severity="HIGH",
                confidence="MEDIUM",
                package="",
                file=pk,
                line=line,
                code_snippet=_code_at(lines, line),
                description="CRLF sequence combined with non-literal data — may enable HTTP response splitting / log injection.",
            )
        )
    return results


_WEAK_HASH_NAMES = frozenset({"md5", "md4", "md2", "sha1"})


def check_weak_hash(path: Path, lines: list[str], tree: ast.Module | None) -> list[Finding]:
    """CWE-328. ``hashlib.md5()``/``sha1()``, plus the ``hashlib.new("md5")``
    indirection (B324). ``usedforsecurity=False`` -- the stdlib's own way of
    saying "this is a checksum, not a credential" -- is exempt."""
    pk = _rel(path)
    results: list[Finding] = []
    aliases = _import_aliases(tree)
    for node in _calls(tree):
        if _keyword_is(node, "usedforsecurity", False):
            continue
        fn = _callee(node, aliases)
        line = _node_line(node)
        if _dotted_matches(fn, "hashlib.md5") or _dotted_matches(fn, "hashlib.sha1"):
            results.append(
                Finding(
                    cwe_id="CWE-328",
                    cwe_name="Weak Cryptographic Hash",
                    severity="MEDIUM",
                    confidence="HIGH",
                    package="",
                    file=pk,
                    line=line,
                    code_snippet=_code_at(lines, line),
                    description="Use of MD5/SHA-1 — collision-prone, use SHA-256 or better.",
                )
            )
        elif (
            _dotted_matches(fn, "hashlib.new")
            and node.args
            and isinstance(node.args[0], ast.Constant)
            and isinstance(node.args[0].value, str)
            and node.args[0].value.lower() in _WEAK_HASH_NAMES
        ):
            results.append(
                Finding(
                    cwe_id="CWE-328",
                    cwe_name="Weak Cryptographic Hash",
                    severity="MEDIUM",
                    confidence="HIGH",
                    package="",
                    file=pk,
                    line=line,
                    code_snippet=_code_at(lines, line),
                    description="hashlib.new() with a weak algorithm name (MD5/MD4/MD2/SHA-1) — "
                    "same collision risk as calling hashlib.md5()/sha1() directly, "
                    "just reached through the generic constructor. Use SHA-256 or better.",
                )
            )
    return results


def check_open_redirect(path: Path, lines: list[str], tree: ast.Module | None) -> list[Finding]:
    """CWE-601. A ``redirect(...)``/``Redirect(...)`` call fed a non-literal
    destination. ``HTTPTemporaryRedirect(...)``, ``authorize_redirect(...)``
    and a redirect to a fixed path are not open redirects."""
    pk = _rel(path)
    results: list[Finding] = []
    for node in _calls(tree):
        if _call_name(node) not in ("redirect", "Redirect") or not _has_dynamic_arg(node):
            continue
        line = _node_line(node)
        results.append(
            Finding(
                cwe_id="CWE-601",
                cwe_name="Open Redirect",
                severity="MEDIUM",
                confidence="HIGH",
                package="",
                file=pk,
                line=line,
                code_snippet=_code_at(lines, line),
                description="URL redirect — ensure destination is validated against an allowlist.",
            )
        )
    return results


def _is_cert_none(expr: ast.expr) -> bool:
    return (isinstance(expr, ast.Attribute) and expr.attr == "CERT_NONE") or (
        isinstance(expr, ast.Name) and expr.id == "CERT_NONE"
    )


def _is_false(expr: ast.expr | None) -> bool:
    return isinstance(expr, ast.Constant) and expr.value is False


def _targets_check_hostname(targets: list[ast.expr]) -> bool:
    return any(
        (isinstance(t, ast.Attribute) and t.attr == "check_hostname")
        or (isinstance(t, ast.Name) and t.id == "check_hostname")
        for t in targets
    )


_TLS_ZERO_DAY = (
    "CWE-295 is #8 in CWE Top 25. TLS bypass zero-days (e.g. CVE-2026-27834 Python "
    "CERT_NONE in urllib) enable MITM on every connection."
)


def check_tls_verify(path: Path, lines: list[str], tree: ast.Module | None) -> list[Finding]:
    """CWE-295 rank #8. ``verify=False``, ``check_hostname = False``,
    ``CERT_NONE`` used as a *value* (keyword, assignment, dict entry -- not
    ``== ssl.CERT_NONE``, which is a check, not a configuration), and
    ``ssl._create_unverified_context()``. One finding per line."""
    pk = _rel(path)
    results: list[Finding] = []
    seen: set[int] = set()
    nodes = list(ast.walk(tree)) if tree else []
    compared = {
        id(operand)
        for n in nodes
        if isinstance(n, ast.Compare)
        for operand in (n.left, *n.comparators)
    }

    def add(node: ast.AST, desc: str) -> None:
        line = _node_line(node)
        if line in seen:
            return
        seen.add(line)
        results.append(
            Finding(
                cwe_id="CWE-295",
                cwe_name="Improper Certificate Validation",
                severity="CRITICAL",
                confidence="HIGH",
                package="",
                file=pk,
                line=line,
                code_snippet=_code_at(lines, line),
                description=desc,
                zero_day_relevance=_TLS_ZERO_DAY,
            )
        )

    for node in nodes:
        if isinstance(node, ast.Call):
            if _keyword_is(node, "verify", False):
                add(node, "HTTP/S3 client with verify=False — TLS certificate validation disabled.")
            if _keyword_is(node, "check_hostname", False):
                add(node, "Hostname verification disabled — no TLS identity check.")
            if _call_name(node) == "_create_unverified_context":
                add(node, "ssl._create_unverified_context() — creates unverified TLS context.")
        elif (
            isinstance(node, ast.Assign)
            and _targets_check_hostname(node.targets)
            and _is_false(node.value)
        ):
            add(node, "Hostname verification disabled — no TLS identity check.")
        elif (
            isinstance(node, ast.AnnAssign)
            and _targets_check_hostname([node.target])
            and _is_false(node.value)
        ):
            add(node, "Hostname verification disabled — no TLS identity check.")
        elif _is_cert_none(node) and id(node) not in compared:
            add(node, "ssl.CERT_NONE — peer certificate not verified, man-in-the-middle possible.")
    return results


def _all_constant(expr: ast.expr) -> bool:
    if isinstance(expr, ast.Constant):
        return True
    if isinstance(expr, ast.BinOp):
        return _all_constant(expr.left) and _all_constant(expr.right)
    return False


def _sql_shape(arg: ast.expr) -> str | None:
    """``"f-string"`` for an f-string with at least one interpolation,
    ``"concatenation"`` for ``+``/``%`` on a non-literal or ``"...".format(x)``,
    else ``None`` -- the three ways a query gets data spliced into it."""
    if isinstance(arg, ast.JoinedStr):
        if any(isinstance(v, ast.FormattedValue) for v in arg.values):
            return "f-string"
        return None
    if isinstance(arg, ast.BinOp) and isinstance(arg.op, (ast.Add, ast.Mod)):
        return None if _all_constant(arg) else "concatenation"
    if (
        isinstance(arg, ast.Call)
        and isinstance(arg.func, ast.Attribute)
        and arg.func.attr == "format"
        and isinstance(arg.func.value, ast.Constant)
        and (arg.args or arg.keywords)
    ):
        return "concatenation"
    return None


_SQL_EXEC_METHOD_NAMES = frozenset({"execute", "exec_driver_sql"})


def check_sql_injection(path: Path, lines: list[str], tree: ast.Module | None) -> list[Finding]:
    """CWE-89 rank #2. ``execute(...)``/``exec_driver_sql(...)`` whose statement
    argument has data spliced in (f-string, ``+``, ``%``, ``.format``), unless
    every spliced value resolves to a locally-safe origin (see
    ``ast_helpers._is_locally_safe_expr``): a module-level constant or a
    value derived from imported names is not attacker-reachable. Real-world
    report: 7 CRITICAL findings on an Alembic migration, all of them
    interpolating a module constant and the database's own introspection."""
    pk = _rel(path)
    results: list[Finding] = []
    if tree is None:
        return results
    for call, params, literals, imports in _iter_calls_in_scope(tree):
        name = _call_name(call)
        if name not in _SQL_EXEC_METHOD_NAMES or not call.args:
            continue
        shape = _sql_shape(call.args[0])
        if shape is None or _is_locally_safe_expr(call.args[0], params, literals, imports):
            continue
        line = _node_line(call)
        results.append(
            Finding(
                cwe_id="CWE-89",
                cwe_name="SQL Injection",
                severity="CRITICAL",
                confidence="HIGH",
                package="",
                file=pk,
                line=line,
                code_snippet=_code_at(lines, line),
                description=(
                    f"f-string in {name}() — probable SQL injection"
                    if shape == "f-string"
                    else f"String concatenation or %-formatting in {name}() — probable SQL injection"
                ),
                zero_day_relevance="CWE-89 rose to #2 in 2025 Top 25. Most exploited injection class after XSS.",
            )
        )
    return results


def check_exec_driver_sql(path: Path, lines: list[str], tree: ast.Module | None) -> list[Finding]:
    """SQLAlchemy ``exec_driver_sql(f"...")`` -- bypasses the ORM's parameter
    binding entirely, so an f-string here is direct SQL injection. Same
    locally-safe suppression as ``check_sql_injection``."""
    pk = _rel(path)
    results: list[Finding] = []
    if tree is None:
        return results
    for call, params, literals, imports in _iter_calls_in_scope(tree):
        if _call_name(call) != "exec_driver_sql" or not call.args:
            continue
        if _sql_shape(call.args[0]) != "f-string":
            continue
        if _is_locally_safe_expr(call.args[0], params, literals, imports):
            continue
        line = _node_line(call)
        results.append(
            Finding(
                cwe_id="CWE-89",
                cwe_name="SQL Injection",
                severity="CRITICAL",
                confidence="HIGH",
                package="",
                file=pk,
                line=line,
                code_snippet=_code_at(lines, line),
                description="exec_driver_sql() with f-string — direct SQL injection.",
            )
        )
    return results


_SSRF_METHOD_NAMES = frozenset(
    {"get", "post", "put", "patch", "delete", "head", "options", "request"}
)
_SSRF_SESSION_CONSTRUCTORS = frozenset(
    {"requests.Session", "httpx.Client", "httpx.AsyncClient", "aiohttp.ClientSession"}
)


def _ssrf_url_arg(call: ast.Call) -> ast.expr | None:
    if call.args:
        return call.args[0]
    return next((kw.value for kw in call.keywords if kw.arg == "url"), None)


def check_ssrf(path: Path, lines: list[str], tree: ast.Module | None) -> list[Finding]:
    """CWE-918 rank #22. An outbound HTTP request -- ``requests.get(...)``,
    ``httpx.post(...)``, ``urllib.request.urlopen(...)``, or ``<var>.get(...)``
    where ``<var>`` is bound in the same scope to a ``requests.Session()``/
    ``httpx.Client()``/``httpx.AsyncClient()``/``aiohttp.ClientSession()`` --
    whose URL is not locally safe. SSRF is about *attacker-influenced*
    destination selection, so a literal URL or one built entirely from
    module constants is not reported; nor is a bare mention of a client
    class (a type annotation, say), which used to match as text.

    The session binding is resolved per scope on purpose: ``session``/
    ``client`` are among the most reused names in Python, and a SQLAlchemy
    ``session.get(Model, pk)`` in another function is a realistic collision
    a file-wide name match would wrongly report."""
    pk = _rel(path)
    results: list[Finding] = []
    if tree is None:
        return results
    aliases = _import_aliases(tree)
    for call, params, literals, imports in _iter_calls_in_scope(tree):
        fn = _callee(call, aliases)
        method = _call_name(call)
        is_module_call = fn == "urllib.request.urlopen" or (
            method in _SSRF_METHOD_NAMES
            and any(_dotted_matches(fn, f"{m}.{method}") for m in ("requests", "httpx"))
        )
        is_session_call = False
        if (
            not is_module_call
            and method in _SSRF_METHOD_NAMES
            and isinstance(call.func, ast.Attribute)
            and isinstance(call.func.value, ast.Name)
        ):
            bound = literals.get(call.func.value.id)
            is_session_call = (
                isinstance(bound, ast.Call)
                and _callee(bound, aliases) in _SSRF_SESSION_CONSTRUCTORS
            )
        if not (is_module_call or is_session_call):
            continue
        url = _ssrf_url_arg(call)
        if url is None or _is_locally_safe_expr(url, params, literals, imports):
            continue
        line = _node_line(call)
        results.append(
            Finding(
                cwe_id="CWE-918",
                cwe_name="Server-Side Request Forgery",
                severity="HIGH",
                confidence="HIGH",
                package="",
                file=pk,
                line=line,
                code_snippet=_code_at(lines, line),
                description="HTTP request — verify URL is validated against allowlist; SSRF if user-controlled.",
                zero_day_relevance="CWE-918 fell to #22 but SSRF zero-days (cloud metadata exfiltration) remain critical.",
            )
        )
    return results


_NESTED_QUANTIFIER_RE = re.compile(r"\([^)]+[+*?]\)[+*?{]")
_REGEX_COMPILE_CALLS = ("re.compile", "re.match", "re.search")


def _first_str_arg(node: ast.Call) -> str | None:
    if node.args and isinstance(node.args[0], ast.Constant) and isinstance(node.args[0].value, str):
        return node.args[0].value
    return None


def check_redos(path: Path, lines: list[str], tree: ast.Module | None) -> list[Finding]:
    """CWE-1333. A regex literal with a quantified group that is itself
    quantified -- ``(a+)+`` -- handed to ``re.compile``/``match``/``search``.
    The nested-quantifier test is a heuristic, hence LOW confidence; but it
    is now applied to the pattern literal itself, not the whole line."""
    pk = _rel(path)
    results: list[Finding] = []
    aliases = _import_aliases(tree)
    for node in _calls(tree):
        fn = _callee(node, aliases)
        if not any(_dotted_matches(fn, n) for n in _REGEX_COMPILE_CALLS):
            continue
        pattern = _first_str_arg(node)
        if pattern is None or not _NESTED_QUANTIFIER_RE.search(pattern):
            continue
        line = _node_line(node)
        results.append(
            Finding(
                cwe_id="CWE-1333",
                cwe_name="ReDoS (Catastrophic Backtracking)",
                severity="MEDIUM",
                confidence="LOW",
                package="",
                file=pk,
                line=line,
                code_snippet=_code_at(lines, line),
                description="Nested quantifier pattern — potential ReDoS (catastrophic backtracking).",
                zero_day_relevance="ReDoS zero-days have been used to DoS auth gateways. CWE-1333 new to OWASP 2025.",
            )
        )
    return results


_STREAMING_CONTEXT_RE = re.compile(r"chunk|iter_content|stream", re.I)


def check_resource_limits(path: Path, lines: list[str], tree: ast.Module | None) -> list[Finding]:
    """CWE-770 rank #25. ``x.read()`` with no size argument. A line that
    mentions chunking/streaming is taken as bounded by context."""
    pk = _rel(path)
    results: list[Finding] = []
    for node in _calls(tree):
        if not (
            isinstance(node.func, ast.Attribute)
            and node.func.attr == "read"
            and not node.args
            and not node.keywords
        ):
            continue
        line = _node_line(node)
        code = _code_at(lines, line)
        if _STREAMING_CONTEXT_RE.search(code):
            continue
        results.append(
            Finding(
                cwe_id="CWE-770",
                cwe_name="Unbounded Resource Allocation",
                severity="INFO",
                confidence="HIGH",
                package="",
                file=pk,
                line=line,
                code_snippet=code,
                description="Unbounded .read() — may exhaust memory on large inputs. Use .read(n) or streaming.",
                zero_day_relevance="CWE-770 entered Top 25 at #25 in 2025.",
            )
        )
    return results


def _is_file_move_or_copy(fn: str) -> bool:
    head, _, tail = fn.rpartition(".")
    return (
        _dotted_matches(fn, "shutil.move")
        or _dotted_matches(fn, "os.rename")
        or (tail.startswith("copy") and (head == "shutil" or head.endswith(".shutil")))
    )


def check_arbitrary_write(path: Path, lines: list[str], tree: ast.Module | None) -> list[Finding]:
    """CWE-73. ``shutil.copy*``/``shutil.move``/``os.rename`` fed a non-literal
    path. Two literal paths can't be an arbitrary write."""
    pk = _rel(path)
    results: list[Finding] = []
    aliases = _import_aliases(tree)
    for node in _calls(tree):
        if not _is_file_move_or_copy(_callee(node, aliases)) or not _has_dynamic_arg(node):
            continue
        line = _node_line(node)
        results.append(
            Finding(
                cwe_id="CWE-73",
                cwe_name="External Control of File Name",
                severity="MEDIUM",
                confidence="HIGH",
                package="",
                file=pk,
                line=line,
                code_snippet=_code_at(lines, line),
                description="File operation — verify destination path is validated to prevent arbitrary write.",
            )
        )
    return results


def check_zipslip(path: Path, lines: list[str], tree: ast.Module | None) -> list[Finding]:
    """CWE-22 via ``extractall()``. Guarded when the caller chooses the
    members (second positional or ``members=``) or passes a tarfile
    ``filter=`` -- the two mechanisms that actually reject ``../`` entries."""
    pk = _rel(path)
    results: list[Finding] = []
    for node in _calls(tree):
        if not (isinstance(node.func, ast.Attribute) and node.func.attr == "extractall"):
            continue
        if len(node.args) >= 2 or any(kw.arg in ("members", "filter") for kw in node.keywords):
            continue
        line = _node_line(node)
        results.append(
            Finding(
                cwe_id="CWE-22",
                cwe_name="Path Traversal — ZipSlip / TarSlip",
                severity="HIGH",
                confidence="HIGH",
                package="",
                file=pk,
                line=line,
                code_snippet=_code_at(lines, line),
                description="extractall() without path traversal guard — an archive with ../ entries can overwrite arbitrary files.",
                zero_day_relevance="ZipSlip zero-day pattern: path traversal in archive extraction enables RCE via overwritten binaries (CVE-2026-20624 Python tarfile).",
            )
        )
    return results


def _is_pandas_fn(fn: str, name: str) -> bool:
    return _dotted_matches(fn, f"pandas.{name}") or _dotted_matches(fn, f"pd.{name}")


def check_pandas_pickle(path: Path, lines: list[str], tree: ast.Module | None) -> list[Finding]:
    """Trail of Bits: ``pd.read_pickle()`` is pickle.load() under the hood."""
    pk = _rel(path)
    results: list[Finding] = []
    aliases = _import_aliases(tree)
    for node in _calls(tree):
        if not _is_pandas_fn(_callee(node, aliases), "read_pickle"):
            continue
        line = _node_line(node)
        results.append(
            Finding(
                cwe_id="CWE-502",
                cwe_name="Deserialization of Untrusted Data (read_pickle)",
                severity="CRITICAL",
                confidence="HIGH",
                package="",
                file=pk,
                line=line,
                code_snippet=_code_at(lines, line),
                description="pd.read_pickle() deserializes Python objects via pickle — arbitrary code execution if file is untrusted.",
                zero_day_relevance="Trail of Bits: pandas.read_pickle() uses pickle.load() under the hood — standard pickle RCE.",
            )
        )
    return results


def check_pandas_xml_xxe(path: Path, lines: list[str], tree: ast.Module | None) -> list[Finding]:
    """Trail of Bits: ``pd.read_xml()`` defaults to the lxml parser (XXE);
    any explicit ``parser=`` is taken as a deliberate choice."""
    pk = _rel(path)
    results: list[Finding] = []
    aliases = _import_aliases(tree)
    for node in _calls(tree):
        if not _is_pandas_fn(_callee(node, aliases), "read_xml"):
            continue
        if any(kw.arg == "parser" for kw in node.keywords):
            continue
        line = _node_line(node)
        results.append(
            Finding(
                cwe_id="CWE-611",
                cwe_name="XXE via pandas.read_xml",
                severity="HIGH",
                confidence="HIGH",
                package="",
                file=pk,
                line=line,
                code_snippet=_code_at(lines, line),
                description="pd.read_xml() defaults to lxml parser — may be vulnerable to XXE. Use parser='etree' or defusedxml.",
                zero_day_relevance="Trail of Bits: pandas.read_xml with lxml parser enables XXE attacks on XML data pipelines.",
            )
        )
    return results


_TORCH_MODEL_EXTS = (".pt", ".pth", ".ckpt")
_PICKLE_MODEL_EXTS = (".pt", ".pkl", ".h5", ".joblib", ".ckpt")
_PICKLE_LOAD_FAMILY = ("joblib.load", "pickle.load", "cloudpickle.load", "dill.load")
_KERAS_LOAD_MODEL = (
    "tf.load_model",
    "tf.models.load_model",
    "keras.load_model",
    "keras.models.load_model",
)


def _str_args(node: ast.Call) -> list[str]:
    """String literals passed directly as positional or keyword arguments."""
    return [
        a.value
        for a in [*node.args, *(kw.value for kw in node.keywords)]
        if isinstance(a, ast.Constant) and isinstance(a.value, str)
    ]


def check_model_file_load(path: Path, lines: list[str], tree: ast.Module | None) -> list[Finding]:
    """OWASP ML06 (supply chain): loading ML model files (.pt, .pkl, .h5,
    .joblib, .ckpt) through pickle-based loaders allows arbitrary code
    execution. ``torch.load`` is downgraded to LOW when ``weights_only`` is
    set (to anything but a literal ``False``)."""
    pk = _rel(path)
    results: list[Finding] = []
    aliases = _import_aliases(tree)
    for node in _calls(tree):
        fn = _callee(node, aliases)
        strs = _str_args(node)
        line = _node_line(node)
        if _dotted_matches(fn, "torch.load") and any(s.endswith(_TORCH_MODEL_EXTS) for s in strs):
            weights_only = next(
                (kw.value for kw in node.keywords if kw.arg == "weights_only"), None
            )
            guarded = weights_only is not None and not _is_false(weights_only)
            results.append(
                Finding(
                    cwe_id="CWE-502",
                    cwe_name="Deserialization of Untrusted Data (ML Model)",
                    severity="LOW" if guarded else "CRITICAL",
                    confidence="HIGH",
                    package="",
                    file=pk,
                    line=line,
                    code_snippet=_code_at(lines, line),
                    description=f"torch.load() on model file{'' if guarded else ' without weights_only=True'}. "
                    "Prefer SafeTensors format for untrusted model files.",
                    zero_day_relevance="OWASP ML06: pickle-based model formats enable RCE via malicious model files. "
                    "SafeTensors mitigates this by design.",
                )
            )
        elif any(_dotted_matches(fn, n) for n in _PICKLE_LOAD_FAMILY) and (
            ext := next((e for s in strs for e in _PICKLE_MODEL_EXTS if s.endswith(e)), None)
        ):
            results.append(
                Finding(
                    cwe_id="CWE-502",
                    cwe_name="Deserialization of Untrusted Data (ML Model)",
                    severity="HIGH",
                    confidence="HIGH",
                    package="",
                    file=pk,
                    line=line,
                    code_snippet=_code_at(lines, line),
                    description=f"pickle-based load on {ext} file — arbitrary code execution via malicious model. "
                    "Prefer SafeTensors for untrusted model files.",
                    zero_day_relevance="OWASP ML06: 80% of ML supply-chain attacks exploit pickle-based model formats.",
                )
            )
        elif any(_dotted_matches(fn, n) for n in _KERAS_LOAD_MODEL):
            results.append(
                Finding(
                    cwe_id="CWE-502",
                    cwe_name="Deserialization of Untrusted Data (Keras Model)",
                    severity="HIGH",
                    confidence="HIGH",
                    package="",
                    file=pk,
                    line=line,
                    code_snippet=_code_at(lines, line),
                    description="tf.keras.models.load_model() can deserialize arbitrary Python objects "
                    "via custom layers/optimizers. Prefer SafeTensors for untrusted models.",
                    zero_day_relevance="OWASP ML06: Keras H5 format carries pickle-like deserialization risk.",
                )
            )
    return results


def _names_in(exprs: list[ast.expr]) -> set[str]:
    """Every identifier (bare name or attribute) anywhere inside ``exprs``."""
    out: set[str] = set()
    for e in exprs:
        for n in ast.walk(e):
            if isinstance(n, ast.Name):
                out.add(n.id)
            elif isinstance(n, ast.Attribute):
                out.add(n.attr)
    return out


def check_path_traversal(path: Path, lines: list[str], tree: ast.Module | None) -> list[Finding]:
    """CWE-22 rank #6. ``x.lstrip("/")`` as a sanitiser (it isn't), and an
    ``open(...)`` whose arguments mention a ``relative_path``."""
    pk = _rel(path)
    results: list[Finding] = []
    for node in _calls(tree):
        name = _call_name(node)
        line = _node_line(node)
        if name == "lstrip" and _first_str_arg(node) == "/":
            results.append(
                Finding(
                    cwe_id="CWE-22",
                    cwe_name="Path Traversal",
                    severity="HIGH",
                    confidence="HIGH",
                    package="",
                    file=pk,
                    line=line,
                    code_snippet=_code_at(lines, line),
                    description="lstrip('/') does NOT prevent ../ traversal — use Path.resolve() + is_relative_to().",
                    zero_day_relevance="CWE-22 is #6 in Top 25 with 10 CVEs in KEV.",
                )
            )
        elif name == "open" and any(
            "relative_path" in n
            for n in _names_in([*node.args, *(kw.value for kw in node.keywords)])
        ):
            results.append(
                Finding(
                    cwe_id="CWE-22",
                    cwe_name="Path Traversal",
                    severity="MEDIUM",
                    confidence="HIGH",
                    package="",
                    file=pk,
                    line=line,
                    code_snippet=_code_at(lines, line),
                    description="Variable named 'relative_path' used in open() — verify ../ is rejected with Path.resolve().",
                )
            )
    return results


def _target_tails(targets: list[ast.expr]) -> set[str]:
    return {t.attr for t in targets if isinstance(t, ast.Attribute)} | {
        t.id for t in targets if isinstance(t, ast.Name)
    }


def check_debug_mode(path: Path, lines: list[str], tree: ast.Module | None) -> list[Finding]:
    """CWE-489. ``debug=True`` passed to a call (``app.run(debug=True)``) or
    assigned (``app.debug = True``). LOW confidence: whether this reaches
    production is not knowable from the source."""
    pk = _rel(path)
    results: list[Finding] = []
    for node in ast.walk(tree) if tree else []:
        if isinstance(node, ast.Call):
            hit = _keyword_is(node, "debug", True)
        elif isinstance(node, ast.Assign):
            hit = "debug" in _target_tails(node.targets) and _is_true(node.value)
        elif isinstance(node, ast.AnnAssign):
            hit = "debug" in _target_tails([node.target]) and _is_true(node.value)
        else:
            continue
        if not hit:
            continue
        line = _node_line(node)
        results.append(
            Finding(
                cwe_id="CWE-489",
                cwe_name="Active Debug Code",
                severity="MEDIUM",
                confidence="LOW",
                package="",
                file=pk,
                line=line,
                code_snippet=_code_at(lines, line),
                description="Hardcoded debug=True — may expose sensitive info in production.",
            )
        )
    return results


def _is_true(expr: ast.expr | None) -> bool:
    return isinstance(expr, ast.Constant) and expr.value is True


def check_bind_all_interfaces(
    path: Path, lines: list[str], tree: ast.Module | None
) -> list[Finding]:
    """B104 / CWE-1327. The string literal ``"0.0.0.0"`` anywhere in code: a
    server bound to it listens on every interface, not just localhost."""
    pk = _rel(path)
    results: list[Finding] = []
    seen: set[int] = set()
    for node in ast.walk(tree) if tree else []:
        if not (isinstance(node, ast.Constant) and node.value == "0.0.0.0"):
            continue
        line = _node_line(node)
        if line in seen:
            continue
        seen.add(line)
        results.append(
            Finding(
                cwe_id="CWE-1327",
                cwe_name="Binding to an Unrestricted IP Address",
                severity="MEDIUM",
                confidence="HIGH",
                package="",
                file=pk,
                line=line,
                code_snippet=_code_at(lines, line),
                description="Host bound to 0.0.0.0 — listens on every network interface, not just "
                "localhost. Bind to 127.0.0.1 unless external access is actually required.",
                zero_day_relevance="B104: services accidentally exposed on all interfaces are a common "
                "initial-access vector once a container/VM's network boundary is misconfigured.",
            )
        )
    return results


_WEAK_TLS_PROTOCOLS = frozenset(
    {"PROTOCOL_SSLv2", "PROTOCOL_SSLv3", "PROTOCOL_TLSv1", "PROTOCOL_TLSv1_1"}
)


def check_weak_tls_version(path: Path, lines: list[str], tree: ast.Module | None) -> list[Finding]:
    """B502/B503/B504 / CWE-326. A reference to a broken or obsolete
    SSL/TLS protocol constant -- SSLv2/SSLv3/TLSv1.0/TLSv1.1 (RFC 8996).
    Distinct from ``check_tls_verify`` (CWE-295), which is about *disabled*
    certificate verification rather than protocol downgrade."""
    pk = _rel(path)
    results: list[Finding] = []
    seen: set[int] = set()
    for node in ast.walk(tree) if tree else []:
        if isinstance(node, ast.Attribute):
            name = node.attr
        elif isinstance(node, ast.Name):
            name = node.id
        else:
            continue
        if name not in _WEAK_TLS_PROTOCOLS:
            continue
        line = _node_line(node)
        if line in seen:
            continue
        seen.add(line)
        results.append(
            Finding(
                cwe_id="CWE-326",
                cwe_name="Inadequate Encryption Strength",
                severity="HIGH",
                confidence="HIGH",
                package="",
                file=pk,
                line=line,
                code_snippet=_code_at(lines, line),
                description=f"{name} — explicitly requests a deprecated, broken SSL/TLS "
                "protocol version. Use ssl.PROTOCOL_TLS_CLIENT/SERVER (or omit ssl_version "
                "entirely) to let Python negotiate the strongest mutually-supported version.",
                zero_day_relevance="B502/B503/B504: SSLv3 enables POODLE, TLSv1.0/1.1 are formally "
                "deprecated by RFC 8996 — still found in legacy integration code talking to old servers.",
            )
        )
    return results


def check_legacy_pycrypto(path: Path, lines: list[str], tree: ast.Module | None) -> list[Finding]:
    """CWE-1104. ``import Crypto...``/``from Crypto... import`` pulls in the
    old, unmaintained PyCrypto package (last release 2013). ``Cryptodome``
    is the maintained drop-in replacement and is a different top-level
    package, so it does not match."""
    pk = _rel(path)
    results: list[Finding] = []
    for node in ast.walk(tree) if tree else []:
        if isinstance(node, ast.Import):
            hit = any(alias.name.split(".")[0] == "Crypto" for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            hit = not node.level and bool(node.module) and node.module.split(".")[0] == "Crypto"
        else:
            continue
        if not hit:
            continue
        line = _node_line(node)
        results.append(
            Finding(
                cwe_id="CWE-1104",
                cwe_name="Supply Chain — Unmaintained Dependency",
                severity="MEDIUM",
                confidence="HIGH",
                package="",
                file=pk,
                line=line,
                code_snippet=_code_at(lines, line),
                description="Imports the old PyCrypto package (unmaintained since 2013, several "
                "unpatched CVEs) — migrate to pycryptodome (`import Cryptodome` / "
                "`from Cryptodome import ...`), a maintained drop-in replacement.",
                zero_day_relevance="PyCrypto has no security fixes for over a decade; several "
                "known vulnerabilities (e.g. weak RNG seeding in old releases) remain unpatched.",
            )
        )
    return results
