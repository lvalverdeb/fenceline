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
    _LOGGING_METHOD_NAMES,
    _call_name,
    _call_nodes,
    _callee,
    _dotted_matches,
    _dotted_name,
    _full_attr,
    _handler_has_diagnostic,
    _handler_returns_error_response,
    _has_dynamic_arg,
    _import_aliases,
    _is_fallback_handler,
    _is_re_compile,
    _is_sqlalchemy_compile,
    _iter_calls_in_scope,
    _node_line,
    _skip,
)
from fenceline.models import Finding
from fenceline.scanner import _rel
from fenceline.taint import Taint, bound_values, classify, confidence_for

__all__ = [
    "check_tempfile",
    "check_hardcoded_secrets",
    "check_hardcoded_tokens",
    "check_log_injection",
    "check_log_secrets",
    "check_numpy_load_lib",
    "check_pickle",
    "check_command_injection",
    "check_yaml_deserialize",
    "check_ssti",
    "check_timing_attack",
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
    """CWE-94 rank #10.  Exclude re.compile and SQLAlchemy .compile(). A literal
    program text (``exec("...")``) is not code injection and is not reported;
    see ``fenceline.taint`` for how the argument's origin sets confidence."""
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
            severity, description = (
                "CRITICAL",
                f"{fn}() with dynamic input allows arbitrary code execution.",
            )
        elif fn == "compile" and not _is_re_compile(node) and not _is_sqlalchemy_compile(node):
            # Only flag bare compile(...) — method calls like obj.compile() are not Python's built-in
            if not isinstance(node.func, ast.Name):
                continue
            severity, description = (
                "CRITICAL",
                "compile() with dynamic input can enable arbitrary code execution.",
            )
        elif fn == "__import__":
            severity = "HIGH"
            description = (
                "Dynamic __import__() can import arbitrary modules if argument is user-controlled."
            )
        else:
            continue
        taint = _tainted(tree, node, _call_data(node))
        if taint is None:
            continue
        confidence, note = taint
        results.append(
            Finding(
                cwe_id="CWE-94",
                cwe_name="Code Injection",
                severity=severity,
                confidence=confidence,
                package="",
                file=pk,
                line=line,
                code_snippet=code,
                description=description + note,
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
    and the block is not flagged. A file that failed to parse is not
    scanned: a line scan cannot see the handler body, and every handler it
    reported on real code turned out to log.

    A handler that only substitutes an outcome (``pass``, ``continue``,
    ``return default``, ``name = ""``, or a nested ``try`` of the same
    shape) is not reported here either: ``pass``/``continue`` is
    ``check_except_pass``'s finding, so each handler is reported once, and
    a chosen fallback value is the author's explicit handling of the
    failure, not a swallowed error. Nor is one that answers the request
    with an error response (``return response_404()``, a ``status_code``
    of 400 or more): the failure reaches the client. What remains is a
    catch-all that does other work and records nothing.
    """
    pk = _rel(path)
    results: list[Finding] = []
    if tree is None:
        return results

    for node in ast.walk(tree):
        if not isinstance(node, ast.ExceptHandler):
            continue
        if not _is_catch_all(node.type):
            continue
        if (
            _handler_has_diagnostic(node)
            or _is_fallback_handler(node)
            or _handler_returns_error_response(node)
        ):
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


def _parent_map(tree: ast.Module | None) -> dict[int, ast.AST]:
    """``id(child) -> parent`` for every node."""
    parents: dict[int, ast.AST] = {}
    for node in ast.walk(tree) if tree else []:
        for child in ast.iter_child_nodes(node):
            parents[id(child)] = node
    return parents


def _enclosing_targets(node: ast.AST, parents: dict[int, ast.AST]) -> list[ast.expr]:
    """The targets of the assignment statement *node* is part of
    (``token = f(x)``, ``self.key: str = f(x)``, ``h += f(x)``); empty when
    the enclosing statement is not an assignment."""
    parent = parents.get(id(node))
    while parent is not None and not isinstance(parent, ast.stmt):
        parent = parents.get(id(parent))
    if isinstance(parent, ast.Assign):
        return list(parent.targets)
    if isinstance(parent, (ast.AnnAssign, ast.AugAssign)):
        return [parent.target]
    return []


# A value named like a credential: what a weak hash or a weak random source
# must not produce.
_CREDENTIAL_NAME_RE = re.compile(
    r"(?:^|_)(?:password|passwd|pwd|secret|token|api_key|apikey|key|otp|credential|credentials"
    r"|auth|session|nonce|salt|signature|csrf|pin)(?:_|$)",
    re.I,
)
# Character sets a token is drawn from: random.choices(string.ascii_letters, k=16).
_ALPHABET_NAMES = frozenset(
    {
        "ascii_letters",
        "ascii_lowercase",
        "ascii_uppercase",
        "digits",
        "hexdigits",
        "octdigits",
        "letters",
        "printable",
        "punctuation",
        "chars",
        "charset",
        "alphabet",
        "symbols",
    }
)
_NOT_CREDENTIAL_NOTE = " — neither the inputs nor the assigned name look like a credential; confirm the value is not used as one."
_RANDOM_FNS = frozenset(
    {
        "random",
        "randint",
        "choice",
        "choices",
        "uniform",
        "triangular",
        "shuffle",
        "sample",
        "randrange",
        "getrandbits",
        "randbytes",
    }
)


def _looks_like_alphabet(text: str) -> bool:
    """``"abc...XYZ0123456789"``: a character set, not a message."""
    return len(text) >= 10 and " " not in text and any(ch.isalnum() for ch in text)


def _draws_from_alphabet(tree: ast.Module, node: ast.Call) -> bool:
    """``random.choices(string.ascii_letters, k=16)``,
    ``random.sample(field, n)`` with ``field = "abc...789"`` in scope."""
    if _names_in(node.args) & _ALPHABET_NAMES:
        return True
    if not node.args:
        return False
    first = node.args[0]
    values = bound_values(tree, node, first.id) if isinstance(first, ast.Name) else [first]
    return any(
        isinstance(v, ast.Constant) and isinstance(v.value, str) and _looks_like_alphabet(v.value)
        for v in values
    )


def _credential_context(node: ast.Call, parents: dict[int, ast.AST]) -> bool:
    """The call's arguments or the name its result is bound to are named like
    a credential."""
    exprs = [*node.args, *(kw.value for kw in node.keywords), *_enclosing_targets(node, parents)]
    return any(_CREDENTIAL_NAME_RE.search(n) for n in _names_in(exprs))


def check_insecure_random(path: Path, lines: list[str], tree: ast.Module | None) -> list[Finding]:
    """CWE-338. ``random.*`` is HIGH confidence when it plainly produces a
    secret: the result is bound to a credential-like name, it is drawn from
    a character set (``random.choices(string.ascii_letters, k=16)``), or it
    is ``getrandbits``/``randbytes``. Jitter, sampling and shuffling
    (``randint(0, 120)`` minutes, ``random.choice(servers)``) are MEDIUM:
    they need no cryptographic source, and on ordinary code they are most
    of what ``random`` is used for."""
    pk = _rel(path)
    results: list[Finding] = []
    aliases = _import_aliases(tree)
    parents = _parent_map(tree)
    for node in _calls(tree):
        fn = _callee(node, aliases)
        if not fn.startswith("random.") or fn in ("random.SystemRandom", "random.secrets"):
            continue
        base = fn.split(".")[1]
        if base not in _RANDOM_FNS:
            continue
        from_alphabet = base in ("choice", "choices", "sample") and _draws_from_alphabet(tree, node)
        if (
            base in ("getrandbits", "randbytes")
            or from_alphabet
            or _credential_context(node, parents)
        ):
            confidence, note = "HIGH", ""
        else:
            confidence, note = "MEDIUM", _NOT_CREDENTIAL_NOTE
        line = _node_line(node)
        results.append(
            Finding(
                cwe_id="CWE-338",
                cwe_name="Insecure Randomness",
                severity="LOW",
                confidence=confidence,
                package="",
                file=pk,
                line=line,
                code_snippet=_code_at(lines, line),
                description=f"random.{base}() uses Mersenne Twister (not crypto-secure). Use secrets module for security-sensitive contexts."
                + note,
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


def _is_catch_all(exc_type: ast.expr | None) -> bool:
    """A handler type that catches everything: bare, ``Exception``,
    ``BaseException``, or a tuple containing one of those."""
    if exc_type is None:
        return True
    types = exc_type.elts if isinstance(exc_type, ast.Tuple) else [exc_type]
    return any(isinstance(t, ast.Name) and t.id in ("Exception", "BaseException") for t in types)


def check_except_pass(path: Path, lines: list[str], tree: ast.Module | None) -> list[Finding]:
    """B110/B112 / CWE-391. A catch-all handler (bare, ``Exception`` or
    ``BaseException``) whose body is only ``pass`` or ``continue`` silently
    swallows every error. A handler naming a specific type and passing
    (``except FileNotFoundError: pass``) is a deliberate, idiomatic choice
    and is not reported."""
    pk = _rel(path)
    results: list[Finding] = []
    for node in ast.walk(tree) if tree else []:
        if not isinstance(node, ast.ExceptHandler) or not _is_catch_all(node.type):
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


def _is_sqlalchemy_query(node: ast.Call) -> bool:
    """``session.query(Model)`` / ``db_session.query(cls)``: the receiver is a
    session or the first argument is a class, so this is an ORM query, not
    ``DataFrame.query(expr)``."""
    receiver = _dotted_name(node.func.value) if isinstance(node.func, ast.Attribute) else ""
    if any(seg.endswith("session") for seg in receiver.split(".")):
        return True
    if node.args and isinstance(node.args[0], (ast.Name, ast.Attribute)):
        last = _dotted_name(node.args[0]).rsplit(".", 1)[-1]
        return last[:1].isupper()
    return False


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
            cwe_name, severity = "Code Injection (pandas eval)", "CRITICAL"
            description = "pandas.eval() evaluates arbitrary Python expressions — code injection if user input reaches the expression."
            zero_day = "CVE-2024-9880 / Trail of Bits: pandas.eval() / df.query() sandbox bypass via dunder methods. Pandas docs now warn explicitly."
        elif isinstance(node.func, ast.Attribute) and node.func.attr in ("eval", "query"):
            if _is_sqlalchemy_query(node):
                continue
            cwe_name, severity = "Code Injection (DataFrame eval/query)", "HIGH"
            description = "DataFrame.eval() or DataFrame.query() evaluates Python expressions — code injection if user-controlled input reaches the expression."
            zero_day = "CVE-2024-9880: pandas.DataFrame.query() sandbox bypass. Thousands of attribute chains lead to os.system."
        else:
            continue
        taint = _tainted(tree, node, _call_data(node))
        if taint is None:
            continue
        confidence, note = taint
        results.append(
            Finding(
                cwe_id="CWE-94",
                cwe_name=cwe_name,
                severity=severity,
                confidence=confidence,
                package="",
                file=pk,
                line=line,
                code_snippet=code,
                description=description + note,
                zero_day_relevance=zero_day,
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


#: Field names that carry bulk content -- a document, an image, a body --
#: where an unbounded value costs real decode and validation work. A
#: ``username`` or ``code`` with no bound is a validation choice, not a
#: resource risk.
_BULK_FIELD_RE = re.compile(
    r"(?i)(?:^|_)(?:contents?|body|data|payload|html|text|images?|img|files?|blob|base64"
    r"|markdown|description|notes?|csv|json|xml|document|attachments?|avatar|picture"
    r"|photo|message|comment)(?:_|$)"
)


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
    real signal. And restricted to fields whose name says they carry bulk
    content (``image``, ``content``, ``description``; see
    ``_BULK_FIELD_RE``): a ``username: str`` with no bound is a validation
    choice, not the resource risk this check is about.
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
            if base_type is None or not _BULK_FIELD_RE.search(stmt.target.id):
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


def _call_data(node: ast.Call) -> list[ast.expr]:
    """The expressions a sink call is fed: every positional argument and
    every keyword value."""
    return [*node.args, *(kw.value for kw in node.keywords)]


def _tainted(tree: ast.Module, anchor: ast.AST, exprs: list[ast.expr]) -> tuple[str, str] | None:
    """``(confidence, description_suffix)`` for a sink fed by *exprs*, or
    ``None`` when every input is provably constant and there is nothing to
    report. See ``fenceline.taint`` for the three-way model."""
    return confidence_for(classify(tree, anchor, exprs))


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


def _is_fixed_program_argv(node: ast.Call) -> bool:
    """``["pybabel", "compile", "-d", folder]`` or ``[sys.executable, "-m",
    ...]``: the program is fixed and there is no shell, so the most a
    non-literal element can be is an argument."""
    if not node.args or not isinstance(node.args[0], (ast.List, ast.Tuple)):
        return False
    elts = node.args[0].elts
    if not elts:
        return False
    first = elts[0]
    if isinstance(first, ast.Constant) and isinstance(first.value, str):
        return True
    return _dotted_name(first) == "sys.executable"


def check_command_injection(path: Path, lines: list[str], tree: ast.Module | None) -> list[Finding]:
    """CWE-78 rank #9, CWE-77 rank #23. A fully literal command
    (``subprocess.run(["git", "status"])``) is not reported; the argument's
    origin sets confidence (see ``fenceline.taint``). A list-form command
    with a fixed program and no shell is reported only for request data:
    with the program fixed, internal values can at most be arguments."""
    pk = _rel(path)
    results: list[Finding] = []
    aliases = _import_aliases(tree)
    for node in _calls(tree):
        fn = _callee(node, aliases)
        line = _node_line(node)
        matched = next((call for call, _ in _COMMAND_CALLS if _dotted_matches(fn, call)), None)
        shell = _keyword_is(node, "shell", True)
        if matched is None and not shell:
            continue
        # The command and its arguments; `shell=`/`cwd=`/`env=` and friends
        # don't carry the payload.
        level = classify(
            tree,
            node,
            [*node.args, *(kw.value for kw in node.keywords if kw.arg in ("args", "cmd"))],
        )
        if not shell and _is_fixed_program_argv(node) and level not in (Taint.SOURCE, Taint.CALLER):
            continue
        taint = confidence_for(level)
        if taint is None:
            continue
        confidence, note = taint
        if matched is not None:
            sev = dict(_COMMAND_CALLS)[matched]
            results.append(
                Finding(
                    cwe_id="CWE-78",
                    cwe_name="OS Command Injection",
                    severity=sev,
                    confidence=confidence,
                    package="",
                    file=pk,
                    line=line,
                    code_snippet=_code_at(lines, line),
                    description=f"{matched}() spawns subprocesses; may allow command injection if arguments are unvalidated."
                    + note,
                    zero_day_relevance="CWE-78: 20 CVEs in KEV. Still a top Python zero-day vector.",
                )
            )
        if shell:
            results.append(
                Finding(
                    cwe_id="CWE-78",
                    cwe_name="OS Command Injection",
                    severity="HIGH",
                    confidence=confidence,
                    package="",
                    file=pk,
                    line=line,
                    code_snippet=_code_at(lines, line),
                    description="shell=True enables shell injection in subprocess calls." + note,
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
    """CWE-1336. Zero-day: LangChain CVE-2025-68664. A ``Template(...)`` or
    ``env.from_string(...)`` fed request data (or a parameter some caller
    feeds request data). A template built from anything else is not
    reported: a template string of unknown provenance is, on ordinary code,
    nearly always one the program authored (a loader reading its own files,
    a notification message constant), and the corpora held eighteen of those
    against no true one."""
    pk = _rel(path)
    results: list[Finding] = []
    for node in _calls(tree):
        if _call_name(node) not in ("Template", "from_string"):
            continue
        taint_level = classify(tree, node, _call_data(node))
        if taint_level not in (Taint.SOURCE, Taint.CALLER):
            continue
        confidence, note = confidence_for(taint_level) or ("HIGH", "")
        line = _node_line(node)
        results.append(
            Finding(
                cwe_id="CWE-1336",
                cwe_name="Server-Side Template Injection",
                severity="HIGH",
                confidence=confidence,
                package="",
                file=pk,
                line=line,
                code_snippet=_code_at(lines, line),
                description="Template instantiation — SSTI if template string is user-controlled."
                + note,
                zero_day_relevance="CVE-2025-68664: LangChain Core SSTI zero-day chaining deserialisation + Jinja2 for RCE.",
            )
        )
    return results


def check_unsafe_markup(path: Path, lines: list[str], tree: ast.Module | None) -> list[Finding]:
    """CWE-79. ``mark_safe(...)`` (Django) or ``Markup(...)`` (markupsafe,
    Flask) fed a non-literal: both tell the template engine not to escape
    the value, so request data inside it is reflected XSS."""
    pk = _rel(path)
    results: list[Finding] = []
    for node in _calls(tree):
        if _call_name(node) not in ("mark_safe", "Markup"):
            continue
        taint = _tainted(tree, node, _call_data(node))
        if taint is None:
            continue
        confidence, note = taint
        line = _node_line(node)
        results.append(
            Finding(
                cwe_id="CWE-79",
                cwe_name="Cross-site Scripting",
                severity="HIGH",
                confidence=confidence,
                package="",
                file=pk,
                line=line,
                code_snippet=_code_at(lines, line),
                description="mark_safe()/Markup() disables HTML escaping — XSS if the content is user-controlled."
                + note,
                zero_day_relevance="CWE-79 is #1 in the 2025 Top 25.",
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
    and on real HTTP code those outnumbered the combined ones ten to one.
    The joined data's origin then sets confidence (``fenceline.taint``): a
    hex chunk length or a module constant is not an injection and is
    dropped; a request header value is HIGH."""
    pk = _rel(path)
    results: list[Finding] = []
    # Several hits on one line (an f-string inside a concatenation) report
    # once, at the worst taint among them.
    hits: dict[int, Taint] = {}
    for node in ast.walk(tree) if tree else []:
        # `data`: the non-literal operands joined to the CRLF literal.
        if isinstance(node, ast.BinOp) and isinstance(node.op, (ast.Add, ast.Mod)):
            sides = (node.left, node.right)
            data = [s for s in sides if not isinstance(s, ast.Constant)]
            hit = any(_has_crlf(s) for s in sides) and bool(data)
        elif isinstance(node, ast.JoinedStr):
            data = [v.value for v in node.values if isinstance(v, ast.FormattedValue)]
            hit = any(_has_crlf(v) for v in node.values) and bool(data)
        elif isinstance(node, ast.Call):
            data = _call_data(node)
            hit = (
                isinstance(node.func, ast.Attribute)
                and node.func.attr == "format"
                and _has_crlf(node.func.value)
                and bool(data)
            )
        else:
            continue
        if not hit:
            continue
        line = _node_line(node)
        hits[line] = max(hits.get(line, Taint.CLEAN), classify(tree, node, data))
    for line, taint in hits.items():
        scored = confidence_for(taint)
        if scored is None:
            continue
        confidence, note = scored
        results.append(
            Finding(
                cwe_id="CWE-93",
                cwe_name="CRLF Injection",
                severity="HIGH",
                confidence=confidence,
                package="",
                file=pk,
                line=line,
                code_snippet=_code_at(lines, line),
                description="CRLF sequence combined with non-literal data — may enable HTTP response splitting / log injection."
                + note,
            )
        )
    return results


_WEAK_HASH_NAMES = frozenset({"md5", "md4", "md2", "sha1"})


def check_weak_hash(path: Path, lines: list[str], tree: ast.Module | None) -> list[Finding]:
    """CWE-328. ``hashlib.md5()``/``sha1()``, plus the ``hashlib.new("md5")``
    indirection (B324). ``usedforsecurity=False`` -- the stdlib's own way of
    saying "this is a checksum, not a credential" -- is exempt. HIGH
    confidence when the hashed value or the name the digest is bound to is
    credential-like (``md5(password.encode())``, ``token = sha1(...)``);
    MEDIUM otherwise, since a digest of anything else is as likely an
    identifier or a cache key as a credential."""
    pk = _rel(path)
    results: list[Finding] = []
    aliases = _import_aliases(tree)
    parents = _parent_map(tree)
    for node in _calls(tree):
        if _keyword_is(node, "usedforsecurity", False):
            continue
        fn = _callee(node, aliases)
        line = _node_line(node)
        if _credential_context(node, parents):
            confidence, note = "HIGH", ""
        else:
            confidence, note = "MEDIUM", _NOT_CREDENTIAL_NOTE
        if _dotted_matches(fn, "hashlib.md5") or _dotted_matches(fn, "hashlib.sha1"):
            results.append(
                Finding(
                    cwe_id="CWE-328",
                    cwe_name="Weak Cryptographic Hash",
                    severity="MEDIUM",
                    confidence=confidence,
                    package="",
                    file=pk,
                    line=line,
                    code_snippet=_code_at(lines, line),
                    description="Use of MD5/SHA-1 — collision-prone, use SHA-256 or better." + note,
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
                    confidence=confidence,
                    package="",
                    file=pk,
                    line=line,
                    code_snippet=_code_at(lines, line),
                    description="hashlib.new() with a weak algorithm name (MD5/MD4/MD2/SHA-1) — "
                    "same collision risk as calling hashlib.md5()/sha1() directly, "
                    "just reached through the generic constructor. Use SHA-256 or better." + note,
                )
            )
    return results


# Flask/Django/aiohttp helpers plus the response classes of Django,
# Starlette/FastAPI and aiohttp that take a destination directly.
_REDIRECT_CALLS = frozenset(
    {
        "redirect",
        "Redirect",
        "HttpResponseRedirect",
        "HttpResponsePermanentRedirect",
        "RedirectResponse",
        "HTTPFound",
    }
)


def _leading_str(expr: ast.expr) -> str | None:
    """The string literal a built-up string starts with: ``"/a/" + x``,
    ``f"/a/{x}"``, ``"/a/%s" % x`` and ``"/a/{}".format(x)`` all give
    ``"/a/"``. ``None`` when the expression does not start with a literal."""
    while True:
        if isinstance(expr, ast.Constant):
            return expr.value if isinstance(expr.value, str) else None
        if isinstance(expr, ast.BinOp) and isinstance(expr.op, (ast.Add, ast.Mod)):
            expr = expr.left
        elif isinstance(expr, ast.JoinedStr) and expr.values:
            expr = expr.values[0]
        elif (
            isinstance(expr, ast.Call)
            and isinstance(expr.func, ast.Attribute)
            and expr.func.attr == "format"
        ):
            expr = expr.func.value
        else:
            return None


def _is_same_site_path(target: ast.expr) -> bool:
    """A redirect target that starts with a literal absolute path
    (``"/account/" + user_id``) can only land on the same site. A bare
    ``"/"`` or ``"\\"`` prefix does not count: browsers read ``///host``
    and ``/\\host`` as scheme-relative URLs."""
    lead = _leading_str(target)
    return lead is not None and len(lead) >= 2 and lead[0] == "/" and lead[1] not in "/\\"


# The request's own path: a redirect back to it stays on the site.
_REQUEST_OWN_PATH_ATTRS = frozenset(
    {"path", "path_info", "full_path", "get_full_path", "script_root", "url_rule"}
)


def _leading_operand(expr: ast.expr) -> ast.expr:
    """The leftmost operand of a concatenation -- ``a + "?x"`` and
    ``f"{a}#x"`` both give ``a`` -- or *expr* itself. A redirect to a
    destination that starts same-site stays same-site whatever is appended."""
    while True:
        if isinstance(expr, ast.BinOp) and isinstance(expr.op, ast.Add):
            expr = expr.left
        elif (
            isinstance(expr, ast.JoinedStr)
            and expr.values
            and isinstance(expr.values[0], ast.FormattedValue)
        ):
            expr = expr.values[0].value
        else:
            return expr


def _attr_segments(expr: ast.expr) -> tuple[list[str], bool]:
    """Attribute names of a chain, root first, and whether the root is a
    bare name: ``a.b.c`` → ``(["a", "b", "c"], True)``; ``f().b.c`` →
    ``(["b", "c"], False)``."""
    parts: list[str] = []
    while isinstance(expr, ast.Attribute):
        parts.append(expr.attr)
        expr = expr.value
    if isinstance(expr, ast.Name):
        parts.append(expr.id)
    parts.reverse()
    return parts, isinstance(expr, ast.Name)


def _is_request_own_path(target: ast.expr) -> bool:
    target = _leading_operand(target)
    if isinstance(target, ast.Call) and not target.args:
        target = target.func
    parts = (_dotted_name(target) or "").split(".")
    return len(parts) >= 2 and parts[-2] == "request" and parts[-1] in _REQUEST_OWN_PATH_ATTRS


#: Route builders: a same-site URL from a route name. A concatenation they
#: lead (``reverse("login") + "?next=" + request.path``) stays same-site
#: whatever is appended, like one led by a literal path.
_ROUTE_BUILDERS = frozenset(
    {
        "url_for",
        "flask.url_for",
        "reverse",
        "reverse_lazy",
        "django.urls.reverse",
        "django.urls.reverse_lazy",
        "resolve_url",
        "django.shortcuts.resolve_url",
    }
)


def _is_route_builder_led(target: ast.expr) -> bool:
    lead = _leading_operand(target)
    return isinstance(lead, ast.Call) and _dotted_name(lead.func) in _ROUTE_BUILDERS


def _concat_operands(expr: ast.expr) -> list[ast.expr]:
    """The operands of a ``+`` chain or the interpolations of an f-string."""
    if isinstance(expr, ast.BinOp) and isinstance(expr.op, ast.Add):
        return _concat_operands(expr.left) + _concat_operands(expr.right)
    if isinstance(expr, ast.JoinedStr):
        return [v.value for v in expr.values if isinstance(v, ast.FormattedValue)]
    return [expr]


def _is_safe_tail(op: ast.expr) -> bool:
    return (
        (isinstance(op, ast.Constant) and isinstance(op.value, str))
        or _is_request_own_path(op)
        or (isinstance(op, ast.Call) and _dotted_name(op.func) in _ROUTE_BUILDERS)
    )


def _concat_lead(target: ast.expr) -> ast.expr | None:
    """The leading operand of a concatenation whose other operands cannot
    change the destination's host: literals, the request's own path, route
    builders. ``prefix + "/login/?next=" + request.path`` goes wherever
    ``prefix`` goes, so the leading operand's taint is the redirect's."""
    ops = _concat_operands(target)
    if len(ops) >= 2 and not isinstance(ops[0], ast.Constant) and all(map(_is_safe_tail, ops[1:])):
        return ops[0]
    return None


#: A URL property or URL getter: ``topic.url``, ``self.next_url``,
#: ``self.get_success_url()``.
_URL_PROPERTY_RE = re.compile(r"(?:^|_)urls?$")
#: A URL namespace on an object -- urlman's ``event.urls.base``,
#: ``submission.orga_urls.reviews`` -- whose attributes are named URLs.
_URLS_NAMESPACE_RE = re.compile(r"(?:^|_)urls$")


def _url_property_kind(target: ast.expr) -> str | None:
    """How a redirect destination is read off one of the application's
    objects, with no argument that could carry data; ``None`` when it is
    not. ``"urls"``: a named URL in an urlman-style namespace
    (``event.urls.base``, ``obj.orga_urls.x.full()``), built by the
    application whatever the object's origin. ``"url"``: a URL property or
    getter (``topic.url``, ``self.get_success_url()``), trusted only when
    the object is the application's own (the destination is INTERNAL):
    ``body.url`` on a request payload is still a redirect the client
    chooses."""
    target = _leading_operand(target)
    if isinstance(target, ast.Call):
        if not all(isinstance(a, ast.Constant) for a in target.args) or not all(
            isinstance(kw.value, ast.Constant) for kw in target.keywords
        ):
            return None
        func = target.func
        if isinstance(func, ast.Attribute) and _URL_PROPERTY_RE.search(func.attr):
            return "url"
        if not isinstance(func, ast.Attribute):
            return None
        target = func.value  # a method on a property: event.urls.base.full()
    parts, root_is_name = _attr_segments(target)
    if len(parts) >= 2 and _URLS_NAMESPACE_RE.search(parts[-2]):
        return "urls"
    if parts and (len(parts) >= 2 or not root_is_name) and _URL_PROPERTY_RE.search(parts[-1]):
        return "url"
    return None


def check_open_redirect(path: Path, lines: list[str], tree: ast.Module | None) -> list[Finding]:
    """CWE-601. A ``redirect(...)``/``Redirect(...)`` call fed a non-literal
    destination. ``HTTPTemporaryRedirect(...)``, ``authorize_redirect(...)``
    and a redirect whose first argument is a string literal are not open
    redirects: the literal is a fixed path or, in Django, a URL pattern name
    whose other arguments are URL parameters (``redirect("hc-checks",
    project.code)``). Nor is one whose destination starts with a literal
    path (``"/tasks/" + task_id``), is the request's own path
    (``redirect(request.path)``), or is a URL property or getter of the
    application's own objects (``redirect(self.get_success_url())``,
    ``redirect(event.urls.base)``) that no request data reaches."""
    pk = _rel(path)
    results: list[Finding] = []
    for node in _calls(tree):
        if _call_name(node) not in _REDIRECT_CALLS:
            continue
        if (
            node.args
            and isinstance(node.args[0], ast.Constant)
            and isinstance(node.args[0].value, str)
        ):
            continue
        data = _call_data(node)
        if data and (
            _is_same_site_path(data[0])
            or _is_request_own_path(data[0])
            or _is_route_builder_led(data[0])
        ):
            continue
        lead = _concat_lead(data[0]) if data else None
        taint = classify(tree, node, [lead] if lead is not None else data)
        kind = _url_property_kind(data[0]) if len(data) == 1 else None
        if kind == "urls" or (kind == "url" and taint is Taint.INTERNAL):
            continue
        rated = confidence_for(taint)
        if rated is None:
            continue
        confidence, note = rated
        line = _node_line(node)
        results.append(
            Finding(
                cwe_id="CWE-601",
                cwe_name="Open Redirect",
                severity="MEDIUM",
                confidence=confidence,
                package="",
                file=pk,
                line=line,
                code_snippet=_code_at(lines, line),
                description="URL redirect — ensure destination is validated against an allowlist."
                + note,
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


# ``raw``/``RawSQL``: Django's escape hatches take the statement verbatim.
_SQL_EXEC_METHOD_NAMES = frozenset({"execute", "exec_driver_sql", "raw", "RawSQL"})


def _sql_shape_at(tree: ast.Module | None, call: ast.Call, arg: ast.expr) -> str | None:
    """``_sql_shape`` of *arg*, looking through a local name to the values
    assigned to it in the enclosing function (``q = "..." % x; execute(q)``)."""
    shape = _sql_shape(arg)
    if shape is not None or tree is None or not isinstance(arg, ast.Name):
        return shape
    for value in bound_values(tree, call, arg.id):
        shape = _sql_shape(value)
        if shape is not None:
            return shape
    return None


def check_sql_injection(path: Path, lines: list[str], tree: ast.Module | None) -> list[Finding]:
    """CWE-89 rank #2. ``execute(...)``/``exec_driver_sql(...)`` whose statement
    argument has data spliced in (f-string, ``+``, ``%``, ``.format``). The
    spliced values' origin sets confidence (``fenceline.taint``): a
    module-level constant or the database's own introspection is not
    attacker-reachable and is not reported. Real-world report: 7 CRITICAL
    findings on an Alembic migration, all of them interpolating a module
    constant and the database's own introspection."""
    pk = _rel(path)
    results: list[Finding] = []
    for call in _calls(tree):
        name = _call_name(call)
        if name not in _SQL_EXEC_METHOD_NAMES or not call.args:
            continue
        shape = _sql_shape_at(tree, call, call.args[0])
        if shape is None:
            continue
        taint = _tainted(tree, call, [call.args[0]])
        if taint is None:
            continue
        confidence, note = taint
        line = _node_line(call)
        results.append(
            Finding(
                cwe_id="CWE-89",
                cwe_name="SQL Injection",
                severity="CRITICAL",
                confidence=confidence,
                package="",
                file=pk,
                line=line,
                code_snippet=_code_at(lines, line),
                description=(
                    f"f-string in {name}() — probable SQL injection"
                    if shape == "f-string"
                    else f"String concatenation or %-formatting in {name}() — probable SQL injection"
                )
                + note,
                zero_day_relevance="CWE-89 rose to #2 in 2025 Top 25. Most exploited injection class after XSS.",
            )
        )
    return results


def check_exec_driver_sql(path: Path, lines: list[str], tree: ast.Module | None) -> list[Finding]:
    """SQLAlchemy ``exec_driver_sql(f"...")`` -- bypasses the ORM's parameter
    binding entirely, so an f-string here is direct SQL injection. Same
    taint-based confidence as ``check_sql_injection``."""
    pk = _rel(path)
    results: list[Finding] = []
    for call in _calls(tree):
        if _call_name(call) != "exec_driver_sql" or not call.args:
            continue
        if _sql_shape_at(tree, call, call.args[0]) != "f-string":
            continue
        taint = _tainted(tree, call, [call.args[0]])
        if taint is None:
            continue
        confidence, note = taint
        line = _node_line(call)
        results.append(
            Finding(
                cwe_id="CWE-89",
                cwe_name="SQL Injection",
                severity="CRITICAL",
                confidence=confidence,
                package="",
                file=pk,
                line=line,
                code_snippet=_code_at(lines, line),
                description="exec_driver_sql() with f-string — direct SQL injection." + note,
            )
        )
    return results


_SSRF_METHOD_NAMES = frozenset(
    {"get", "post", "put", "patch", "delete", "head", "options", "request", "build_request"}
)
#: ``x.request(method, url)`` / ``client.build_request(method, url)``: the URL
#: is the second positional argument, and the two-argument shape is itself
#: the mark of an HTTP client (``requests.Session``, ``httpx.Client``,
#: ``aiohttp.ClientSession``, ``urllib3.PoolManager``), whatever ``x`` is
#: bound to.
_SSRF_METHOD_THEN_URL = frozenset({"request", "build_request"})
_SSRF_SESSION_CONSTRUCTORS = frozenset(
    {"requests.Session", "httpx.Client", "httpx.AsyncClient", "aiohttp.ClientSession"}
)


def _ssrf_url_arg(call: ast.Call, method: str) -> ast.expr | None:
    if method in _SSRF_METHOD_THEN_URL:
        if len(call.args) >= 2:
            return call.args[1]
    elif call.args:
        return call.args[0]
    return next((kw.value for kw in call.keywords if kw.arg == "url"), None)


def check_ssrf(path: Path, lines: list[str], tree: ast.Module | None) -> list[Finding]:
    """CWE-918 rank #22. An outbound HTTP request -- ``requests.get(...)``,
    ``httpx.post(...)``, ``urllib.request.urlopen(...)``, or ``<var>.get(...)``
    where ``<var>`` is bound in the same scope to a ``requests.Session()``/
    ``httpx.Client()``/``httpx.AsyncClient()``/``aiohttp.ClientSession()``;
    and ``<anything>.request(method, url)`` or ``.build_request(method,
    url)``, whose two-argument shape marks an HTTP client by itself
    (``_SSRF_METHOD_THEN_URL``), with the URL as the second argument.
    SSRF is about *attacker-influenced* destination selection, so the URL's
    origin sets confidence (``fenceline.taint``): a literal URL or one built
    entirely from module constants is not reported; nor is a bare mention of
    a client class (a type annotation, say), which used to match as text.

    The session binding is resolved per scope on purpose: ``session``/
    ``client`` are among the most reused names in Python, and a SQLAlchemy
    ``session.get(Model, pk)`` in another function is a realistic collision
    a file-wide name match would wrongly report."""
    pk = _rel(path)
    results: list[Finding] = []
    if tree is None:
        return results
    aliases = _import_aliases(tree)
    for call, _params, literals, _imports in _iter_calls_in_scope(tree):
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
        ):
            if method in _SSRF_METHOD_THEN_URL:
                is_session_call = _ssrf_url_arg(call, method) is not None
            elif isinstance(call.func.value, ast.Name):
                bound = literals.get(call.func.value.id)
                is_session_call = (
                    isinstance(bound, ast.Call)
                    and _callee(bound, aliases) in _SSRF_SESSION_CONSTRUCTORS
                )
        if not (is_module_call or is_session_call):
            continue
        url = _ssrf_url_arg(call, method)
        if url is None:
            continue
        taint = _tainted(tree, call, [url])
        if taint is None:
            continue
        confidence, note = taint
        line = _node_line(call)
        results.append(
            Finding(
                cwe_id="CWE-918",
                cwe_name="Server-Side Request Forgery",
                severity="HIGH",
                confidence=confidence,
                package="",
                file=pk,
                line=line,
                code_snippet=_code_at(lines, line),
                description="HTTP request — verify URL is validated against allowlist; SSRF if user-controlled."
                + note,
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
    """CWE-770 rank #25. ``x.read()`` with no size argument, where whoever
    controls ``x`` controls the size: a socket, a response body, ``sys.stdin``,
    or a file whose path came from outside. A file opened at a path the
    program chose (``open("config.toml")``, a configured path, a bundled
    resource) is the program's own and is not reported. A line that
    mentions chunking/streaming is taken as bounded."""
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
        taint = classify(tree, node, [node.func.value])
        if taint not in (Taint.SOURCE, Taint.CALLER):
            continue
        confidence, note = confidence_for(taint) or ("HIGH", "")
        results.append(
            Finding(
                cwe_id="CWE-770",
                cwe_name="Unbounded Resource Allocation",
                severity="INFO",
                confidence=confidence,
                package="",
                file=pk,
                line=line,
                code_snippet=code,
                description="Unbounded .read() — may exhaust memory on large inputs. Use .read(n) or streaming."
                + note,
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


def _write_destination(node: ast.Call) -> list[ast.expr]:
    """The destination of a copy/move: the second positional argument or
    ``dst=``. The source's taint says nothing about where the write lands --
    ``copyfileobj(upload.file, buffer)`` into a path the application chose
    is not an arbitrary write."""
    if len(node.args) >= 2:
        return [node.args[1]]
    dst = [kw.value for kw in node.keywords if kw.arg in ("dst", "fdst", "dest")]
    return dst or _call_data(node)


def check_arbitrary_write(path: Path, lines: list[str], tree: ast.Module | None) -> list[Finding]:
    """CWE-73. ``shutil.copy*``/``shutil.move``/``os.rename`` whose
    destination is a non-literal path. A literal destination can't be an
    arbitrary write, whatever is copied there."""
    pk = _rel(path)
    results: list[Finding] = []
    aliases = _import_aliases(tree)
    for node in _calls(tree):
        if not _is_file_move_or_copy(_callee(node, aliases)):
            continue
        taint = _tainted(tree, node, _write_destination(node))
        if taint is None:
            continue
        confidence, note = taint
        line = _node_line(node)
        results.append(
            Finding(
                cwe_id="CWE-73",
                cwe_name="External Control of File Name",
                severity="MEDIUM",
                confidence=confidence,
                package="",
                file=pk,
                line=line,
                code_snippet=_code_at(lines, line),
                description="File operation — verify destination path is validated to prevent arbitrary write."
                + note,
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
        if (
            name == "lstrip"
            and _first_str_arg(node) == "/"
            and isinstance(node.func, ast.Attribute)
        ):
            # The value being "sanitised" is the receiver, not the argument.
            data = [node.func.value]
            severity = "HIGH"
            description = "lstrip('/') does NOT prevent ../ traversal — use Path.resolve() + is_relative_to()."
            zero_day = "CWE-22 is #6 in Top 25 with 10 CVEs in KEV."
        elif name == "open" and any("relative_path" in n for n in _names_in(_call_data(node))):
            data = _call_data(node)
            severity = "MEDIUM"
            description = "Variable named 'relative_path' used in open() — verify ../ is rejected with Path.resolve()."
            zero_day = ""
        elif name in ("send_file", "FileResponse") and _call_data(node):
            # Flask's send_file / Starlette's and Django's FileResponse take a
            # path verbatim (unlike send_from_directory, which safe-joins).
            data = _call_data(node)
            severity = "HIGH"
            description = "File served from a non-literal path — path traversal if the path is request-derived; resolve it and check is_relative_to() first."
            zero_day = "CWE-22 is #6 in Top 25 with 10 CVEs in KEV."
        else:
            continue
        raw = classify(tree, node, data)
        if (
            name == "lstrip"
            and raw is Taint.INTERNAL
            and isinstance(data[0], (ast.Attribute, ast.Subscript))
        ):
            # A field read off the application's own object, normalised; a
            # bare name of unknown provenance stays reported at MEDIUM.
            continue
        taint = confidence_for(raw)
        if taint is None:
            continue
        confidence, note = taint
        results.append(
            Finding(
                cwe_id="CWE-22",
                cwe_name="Path Traversal",
                severity=severity,
                confidence=confidence,
                package="",
                file=pk,
                line=line,
                code_snippet=_code_at(lines, line),
                description=description + note,
                zero_day_relevance=zero_day,
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


_BIND_NAME_RE = re.compile(r"bind|listen", re.I)


def check_bind_all_interfaces(
    path: Path, lines: list[str], tree: ast.Module | None
) -> list[Finding]:
    """B104 / CWE-1327. The string literal ``"0.0.0.0"`` as a value: a
    server bound to it listens on every interface, not just localhost. Not
    one in a comparison or in a list/set/tuple of nothing but strings
    (``ALLOWED_HOSTS = ["0.0.0.0"]``, ``WILDCARDS = {"0.0.0.0", "::"}``):
    those recognise the address rather than bind to it. A list bound to a
    name that says bind (``DEFAULT_BIND = ["0.0.0.0", "::"]``) still is one."""
    pk = _rel(path)
    results: list[Finding] = []
    seen: set[int] = set()
    parents = _parent_map(tree)
    for node in ast.walk(tree) if tree else []:
        if not (isinstance(node, ast.Constant) and node.value == "0.0.0.0"):
            continue
        parent = parents.get(id(node))
        bound_to_bind = any(
            _BIND_NAME_RE.search(n) for n in _names_in(_enclosing_targets(node, parents))
        )
        if isinstance(parent, ast.Compare) or (
            isinstance(parent, (ast.List, ast.Set, ast.Tuple))
            and not bound_to_bind
            and all(isinstance(e, ast.Constant) and isinstance(e.value, str) for e in parent.elts)
        ):
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


# ── Logging and library-loading calls (converted from line regexes so a
# call whose arguments continue on later lines is still matched) ──────────

# In message text: whole words, so "tokeniser" and "tokens" do not count.
_SECRET_KEYWORD_RE = re.compile(
    r"\b(?:password|passwd|secret|token|api_key|apikey|auth_token|access_key"
    r"|private_key|credential|credentials)\b",
    re.I,
)
# In identifiers: whole ``_``-separated segments (``self.password``,
# ``user.api_key``), not ``model_token_limit`` or ``tokeniser``.
_SECRET_IDENT_RE = re.compile(
    r"(?:^|_)(?:password|passwd|secret|secrets|token|tokens|api_key|apikey|auth_token|access_key"
    r"|private_key|credential|credentials)(?:_|$)",
    re.I,
)
_SHARED_LIB_RE = re.compile(r"\.(?:so|dll|dylib)\b")


def _is_logging_call(node: ast.Call, aliases: dict[str, str]) -> bool:
    """``x.info(...)``/``x.debug(...)``/... on anything but the ``warnings``
    module, whose ``warn`` goes to stderr, not a log (``_warnings=warnings``
    default-argument idiom included), and Django's ``django.contrib.messages``,
    whose ``warning``/``error`` queue a flash message for the next response."""
    if not (isinstance(node.func, ast.Attribute) and node.func.attr in _LOGGING_METHOD_NAMES):
        return False
    callee = _callee(node, aliases)
    if callee.startswith("django.contrib.messages."):
        return False
    return callee.split(".", 1)[0].lstrip("_") != "warnings"


def _string_fragments(exprs: list[ast.expr]) -> list[str]:
    """String literals passed directly as arguments, plus the literal parts
    of f-string arguments."""
    out: list[str] = []
    for e in exprs:
        if isinstance(e, ast.Constant) and isinstance(e.value, str):
            out.append(e.value)
        elif isinstance(e, ast.JoinedStr):
            out.extend(
                v.value
                for v in e.values
                if isinstance(v, ast.Constant) and isinstance(v.value, str)
            )
    return out


def check_log_secrets(path: Path, lines: list[str], tree: ast.Module | None) -> list[Finding]:
    """CWE-532. A logging call whose arguments *name* a secret
    (``logger.info("token=%s", token)``, ``self.password``) is HIGH
    confidence. One whose message mentions a secret and logs some
    non-literal value alongside (``logger.info("Found credentials in %s",
    path)``) is MEDIUM: the value may or may not be the secret. A message
    with nothing but literals (``logger.debug("Credentials refreshed.")``)
    cannot leak anything and is not reported."""
    pk = _rel(path)
    results: list[Finding] = []
    aliases = _import_aliases(tree)
    for node in _calls(tree):
        if not _is_logging_call(node, aliases):
            continue
        data = _call_data(node)
        if any(
            _SECRET_IDENT_RE.search(n) and not _DESCRIPTOR_NAME_RE.search(n)
            for n in _names_in(data)
        ):
            confidence = "HIGH"
            description = "Logger call includes a variable whose name suggests it holds a secret — potential credential leakage in logs."
        elif _has_dynamic_arg(node) and any(
            _SECRET_KEYWORD_RE.search(s) for s in _string_fragments(data)
        ):
            confidence = "MEDIUM"
            description = "Logger message mentions a secret-like term — confirm the value itself is not written to the log."
        else:
            continue
        line = _node_line(node)
        results.append(
            Finding(
                cwe_id="CWE-532",
                cwe_name="Insertion of Sensitive Information into Logs",
                severity="HIGH",
                confidence=confidence,
                package="",
                file=pk,
                line=line,
                code_snippet=_code_at(lines, line),
                description=description,
                zero_day_relevance="CWE-532: leaked creds in logs are a common zero-day discovery vector (GitHub secret scanning, SIEM alerts).",
            )
        )
    return results


def _fstring_values(args: list[ast.expr]) -> list[ast.expr]:
    """The interpolated expressions of every f-string in *args*."""
    return [
        v.value
        for a in args
        if isinstance(a, ast.JoinedStr)
        for v in a.values
        if isinstance(v, ast.FormattedValue)
    ]


def check_log_injection(path: Path, lines: list[str], tree: ast.Module | None) -> list[Finding]:
    """CWE-117. An f-string passed positionally to a logging call
    interpolates request data (or a parameter some caller feeds request
    data): the logger's own ``%s`` formatting is bypassed, so a value
    carrying a newline forges a log entry. An f-string over identifiers,
    counts, exceptions or configuration is not reported: on ordinary code
    those are nearly every logging line, and none of them is attacker
    content. Data that arrives through a caller is MEDIUM here rather than
    HIGH: what is logged is usually a field of the parameter, and whether
    that field is free text or a typed identifier is not visible."""
    pk = _rel(path)
    results: list[Finding] = []
    aliases = _import_aliases(tree)
    for node in _calls(tree):
        if not _is_logging_call(node, aliases):
            continue
        values = _fstring_values(node.args)
        if not values:
            continue
        taint = classify(tree, node, values)
        if taint not in (Taint.SOURCE, Taint.CALLER):
            continue
        confidence, note = confidence_for(taint) or ("HIGH", "")
        if taint is Taint.CALLER:
            confidence = "MEDIUM"
        line = _node_line(node)
        results.append(
            Finding(
                cwe_id="CWE-117",
                cwe_name="Log Injection / Forging",
                severity="LOW",
                confidence=confidence,
                package="",
                file=pk,
                line=line,
                code_snippet=_code_at(lines, line),
                description="f-string in logger call interpolates request data — a value carrying a newline or CRLF forges a log entry."
                + note,
            )
        )
    return results


def check_numpy_load_lib(path: Path, lines: list[str], tree: ast.Module | None) -> list[Finding]:
    """Trail of Bits: ``numpy.load()``/``numpy.ctypeslib.*`` handed a shared
    library (.so/.dll/.dylib) — arbitrary code execution from library loading."""
    pk = _rel(path)
    results: list[Finding] = []
    aliases = _import_aliases(tree)
    for node in _calls(tree):
        fn = _callee(node, aliases)
        if not (fn == "numpy.load" or fn.startswith("numpy.ctypeslib.")):
            continue
        if not any(_SHARED_LIB_RE.search(s) for s in _string_fragments(_call_data(node))):
            continue
        line = _node_line(node)
        results.append(
            Finding(
                cwe_id="CWE-114",
                cwe_name="Process Control (numpy library loading)",
                severity="HIGH",
                confidence="HIGH",
                package="",
                file=pk,
                line=line,
                code_snippet=_code_at(lines, line),
                description="numpy.load() loading a shared library (.so/.dll) — arbitrary code execution if path is user-controlled.",
                zero_day_relevance="Trail of Bits: numpy.load() on .so files enables arbitrary code execution during array deserialization.",
            )
        )
    return results


# ── Hardcoded credentials (CWE-798) ──────────────────────────────────────────
#
# Two complementary views. check_hardcoded_secrets is name-based: a string
# literal bound to something called password/secret/token/... in any binding
# shape Python offers (plain or attribute assignment, a subscript key such as
# app.config["SECRET_KEY"] or os.environ["JWT_SECRET"], a dict entry, a
# keyword argument, a comparison). check_hardcoded_tokens is value-based: a
# literal that *is* a credential by its shape (JWT, AWS/Stripe/GitHub/Slack/
# Google keys, PEM private key, bearer token) whatever it is bound to.

_SECRET_NAME_RE = re.compile(
    r"password|passwd|pwd|secret|token|api_key|apikey|access_key|private_key|auth_key"
    r"|client_secret|authorization",
    re.I,
)
_PRIVATE_KEY_NAME_RE = re.compile(r"private_key|ssh_key|\bpem\b", re.I)
_PASSWORD_NAME_RE = re.compile(r"password|passwd|pwd", re.I)
# A name that holds a *description* of a credential, not the credential:
# password_field = "password", token_type = "Bearer", auth_header = "X-Auth".
_NOT_A_SECRET_NAME_RE = re.compile(
    r"(?:^|_)(?:field|name|param|prefix|suffix|type|kind|url|uri|hint|label|help|placeholder"
    r"|regex|pattern|length|len|path|file|algorithm|salt|provider|status|id)(?:_|$)"
    r"|header$"
    # A configuration-key constant: CONF_PASSWORD = "password", DATA_SIGN_SECRET = "...".
    r"|^(?:conf|key|data|storage|attr|setting|option)_"
    # An action on the password, not the password: reset_password = "1/m/ip"
    # (a rate limit), account_reset_password = "/account/password-reset".
    r"|(?:^|_)(?:reset|change|forgot|confirm|validate|verify)_password(?:_|$)"
    # ...in either word order: DEFAULT_PASSWORD_RESET_SUBJECT = "Password Reset Request".
    r"|(?:^|_)password_(?:reset|change|changed|forgot|confirm|validate|verify|alert|expired|expiry|policy)(?:_|$)",
    re.I,
)

_PLACEHOLDER_RE = re.compile(
    r"your[-_ ]|placeholder|example|change[-_ ]?me|xxxx|\*\*\*\*|<[^>]+>|^\.\.\.$|dummy|sample"
    r"|insert[-_ ]|fill[-_ ]?in|redacted|^\$\{|^%\(|%s|\{",
    re.I,
)
_CREDS_IN_URL_RE = re.compile(r"://[^/\s@:]+:[^@/\s]+@")
# Values that are a *name*, not a credential: a short all-caps word
# (SECRET_COOKIE_KEY = "PYGOAT"), an environment-variable or constant name
# (ACCESS_KEY = "AWS_ACCESS_KEY_ID"), a number (_TOKEN_TTL = "21600"), a
# literal None/true/false.
_CONSTANT_NAME_RE = re.compile(r"^[A-Z_]{1,12}$|^[A-Z][A-Z0-9]*(?:_[A-Z0-9]+)+$|^\d+(?:\.\d+)?$")
_LITERAL_WORDS = frozenset({"None", "none", "null", "True", "true", "False", "false"})
# Identifier-shaped and digit-free: as likely a config-key name
# (SECRET_KEY = "aws_secret_access_key") as a weak credential
# (secret = "MYSUPERSECRETKEY"); reported, at MEDIUM confidence.
_IDENTIFIER_LIKE_RE = re.compile(r"^[A-Za-z][A-Za-z_-]*$")
_IDENTIFIER_NOTE = " — value is identifier-like and may be a key name rather than a credential."
_PLACEHOLDER_NOTE = " — value looks like a placeholder; confirm it is not used as-is."


def _normalised(text: str) -> str:
    return "".join(ch for ch in text.lower() if ch.isalnum())


_TOKEN_SHAPES: tuple[tuple[re.Pattern[str], str], ...] = (
    (
        re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----"),
        "Hardcoded private key (PEM)",
    ),
    (re.compile(r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]+"), "Hardcoded JWT"),
    (re.compile(r"\bAKIA[0-9A-Z]{16}\b"), "Hardcoded AWS access key ID"),
    (re.compile(r"\bsk_(?:live|test)_[0-9a-zA-Z]{16,}\b"), "Hardcoded Stripe secret key"),
    (re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36}\b"), "Hardcoded GitHub token"),
    (re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b"), "Hardcoded Slack token"),
    (re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b"), "Hardcoded Google API key"),
    (re.compile(r"\bBearer [A-Za-z0-9_\-.=]{20,}"), "Hardcoded bearer token"),
)


def _binding_name(target: ast.expr) -> str | None:
    """The name a value is being bound to: ``x``, ``obj.x`` -> ``x``,
    ``obj["x"]`` -> ``x``; ``None`` for anything else."""
    if isinstance(target, ast.Name):
        return target.id
    if isinstance(target, ast.Attribute):
        return target.attr
    if (
        isinstance(target, ast.Subscript)
        and isinstance(target.slice, ast.Constant)
        and isinstance(target.slice.value, str)
    ):
        return target.slice.value
    return None


def _str_value(node: ast.expr | None) -> str | None:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    return None


def _secret_bindings(tree: ast.Module | None) -> list[tuple[int, str, str]]:
    """``(line, name, value)`` for every string literal bound to a name, in
    any binding shape: assignment, dict entry, keyword argument, comparison."""
    out: list[tuple[int, str, str]] = []
    if tree is None:
        return out

    def add(line: int, target: ast.expr | None, value: ast.expr | None) -> None:
        name = _binding_name(target) if target is not None else None
        text = _str_value(value)
        if name is not None and text is not None:
            out.append((line, name, text))

    for node in ast.walk(tree):
        if isinstance(node, ast.Assign):
            for t in node.targets:
                add(node.lineno, t, node.value)
        elif isinstance(node, ast.AnnAssign):
            add(node.lineno, node.target, node.value)
        elif isinstance(node, ast.Dict):
            for k, v in zip(node.keys, node.values):
                if (
                    isinstance(k, ast.Constant)
                    and isinstance(k.value, str)
                    and _str_value(v) is not None
                ):
                    out.append(
                        (node.lineno if k is None else k.lineno, k.value, _str_value(v) or "")
                    )
        elif isinstance(node, ast.Call):
            for kw in node.keywords:
                if kw.arg is not None and _str_value(kw.value) is not None:
                    out.append((kw.value.lineno, kw.arg, _str_value(kw.value) or ""))
        elif (
            isinstance(node, ast.Compare)
            and node.comparators
            and isinstance(node.ops[0], (ast.Eq, ast.NotEq))
        ):
            add(node.lineno, node.left, node.comparators[0])
            add(node.lineno, node.comparators[0], node.left)
    return out


def _classify_secret(name: str, value: str) -> tuple[str, str, str] | None:
    """``(severity, confidence, description)`` if binding ``value`` to
    ``name`` is a hardcoded credential, else ``None``."""
    if _CREDS_IN_URL_RE.search(value):
        return "CRITICAL", "HIGH", "Connection URL with embedded credentials"
    if not _SECRET_NAME_RE.search(name) or _NOT_A_SECRET_NAME_RE.search(name):
        return None
    if (
        len(value) < 4
        or value in _LITERAL_WORDS
        or _CONSTANT_NAME_RE.match(value)
        # aliases = {"secretsmanager": "secrets-manager"}: a name, not a credential.
        or (_normalised(value) == _normalised(name) and " " not in value)
        # A URL or filesystem path: password_url = "/account/password-reset",
        # password_file = "/run/secrets/db" -- where the secret is, not the secret.
        or (value.startswith("/") and " " not in value)
    ):
        return None
    if _PRIVATE_KEY_NAME_RE.search(name):
        severity, description = "CRITICAL", "Hardcoded private key"
    elif _PASSWORD_NAME_RE.search(name):
        severity, description = "HIGH", "Hardcoded password"
    else:
        severity, description = "HIGH", "Hardcoded secret"
    # SECRET_KEY = "secret key": a phrase that names itself is still the
    # default a forgotten deployment runs with.
    if _PLACEHOLDER_RE.search(value) or _normalised(value) == _normalised(name):
        return severity, "MEDIUM", description + _PLACEHOLDER_NOTE
    if _IDENTIFIER_LIKE_RE.match(value):
        return severity, "MEDIUM", description + _IDENTIFIER_NOTE
    return severity, "HIGH", description


def check_hardcoded_secrets(path: Path, lines: list[str], tree: ast.Module | None) -> list[Finding]:
    """CWE-798, name-based. A value that looks like a placeholder
    (``"your-password-here"``, ``"changeme"``, ``"%s"``) is still a hardcoded
    credential if it is what the program actually uses, so it is reported at
    MEDIUM confidence rather than dropped; so is an identifier-shaped value
    that may be a key name."""
    pk = _rel(path)
    results: list[Finding] = []
    seen: set[tuple[int, str]] = set()
    for line, name, value in _secret_bindings(tree):
        verdict = _classify_secret(name, value)
        if verdict is None or (line, name) in seen:
            continue
        seen.add((line, name))
        severity, confidence, description = verdict
        results.append(
            Finding(
                cwe_id="CWE-798",
                cwe_name="Use of Hard-coded Credentials",
                severity=severity,
                confidence=confidence,
                package="",
                file=pk,
                line=line,
                code_snippet=_code_at(lines, line),
                description=description,
                zero_day_relevance="Leaked creds in source code are the #1 initial access vector in supply-chain attacks.",
            )
        )
    return results


def check_hardcoded_tokens(path: Path, lines: list[str], tree: ast.Module | None) -> list[Finding]:
    """CWE-798, value-based: a string literal whose shape identifies it as a
    credential, wherever it appears."""
    pk = _rel(path)
    results: list[Finding] = []
    seen: set[int] = set()
    if tree is None:
        return results
    for node in ast.walk(tree):
        text = _str_value(node) if isinstance(node, ast.Constant) else None
        if text is None or len(text) < 16 or node.lineno in seen:
            continue
        for pattern, description in _TOKEN_SHAPES:
            if pattern.search(text):
                seen.add(node.lineno)
                results.append(
                    Finding(
                        cwe_id="CWE-798",
                        cwe_name="Use of Hard-coded Credentials",
                        severity="CRITICAL",
                        confidence="HIGH",
                        package="",
                        file=pk,
                        line=node.lineno,
                        code_snippet=_code_at(lines, node.lineno),
                        description=f"{description} — plaintext credential in source code.",
                        zero_day_relevance="Hardcoded cloud API keys are the #1 initial-access vector in supply-chain attacks. Attackers scan public repos for these patterns.",
                    )
                )
                break
    return results


# ── Insecure temporary files (CWE-377) ───────────────────────────────────────

_SHARED_TMP_PREFIXES = ("/tmp/", "/var/tmp/", "/dev/shm/")
_SHARED_TMP_DIRS = frozenset({"/tmp", "/var/tmp", "/dev/shm"})


def check_tempfile(path: Path, lines: list[str], tree: ast.Module | None) -> list[Finding]:
    """CWE-377. ``tempfile.mktemp()`` (a name, not an open file: TOCTOU race)
    and any literal path under a shared temporary directory, whose fixed
    name any local user can predict and pre-create or symlink."""
    pk = _rel(path)
    results: list[Finding] = []
    if tree is None:
        return results
    aliases = _import_aliases(tree)
    seen: set[int] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and _callee(node, aliases) == "tempfile.mktemp":
            line = _node_line(node)
            results.append(
                Finding(
                    cwe_id="CWE-377",
                    cwe_name="Insecure Temporary File",
                    severity="HIGH",
                    confidence="HIGH",
                    package="",
                    file=pk,
                    line=line,
                    code_snippet=_code_at(lines, line),
                    description="tempfile.mktemp() is insecure (TOCTOU race). Use TemporaryFile or NamedTemporaryFile.",
                )
            )
        elif isinstance(node, ast.Constant) and isinstance(node.value, str):
            text = node.value
            if (
                text.startswith(_SHARED_TMP_PREFIXES) or text in _SHARED_TMP_DIRS
            ) and node.lineno not in seen:
                seen.add(node.lineno)
                results.append(
                    Finding(
                        cwe_id="CWE-377",
                        cwe_name="Insecure Temporary File",
                        severity="MEDIUM",
                        confidence="HIGH",
                        package="",
                        file=pk,
                        line=node.lineno,
                        code_snippet=_code_at(lines, node.lineno),
                        description="Hardcoded path under a shared temporary directory — predictable name any local user can pre-create or symlink. Use the tempfile module.",
                    )
                )
    return results


# ── Timing attack (converted from a line regex so the *compared name* is
# what decides, not any word on the line) ─────────────────────────────────

_TIMING_SECRET_RE = re.compile(
    r"(?:^|_)(?:password|passwd|pwd|secret|token|auth|api_key|apikey|signature|otp)(?:_|$)", re.I
)
# A name that describes a secret rather than holding one: auth_type,
# token_kind, model_token_limit.
_DESCRIPTOR_NAME_RE = re.compile(
    r"(?:^|_)(?:type|kind|provider|scheme|version|status|mode|method|name|field|url|uri|id|len"
    r"|length|count|limit|max|min|size|ttl|timeout|expiry|expires|enabled|disabled|required)"
    r"(?:_|$)",
    re.I,
)
_TIMING_PASSTHROUGH_METHODS = frozenset(
    {"strip", "lstrip", "rstrip", "lower", "upper", "casefold", "decode", "encode", "hexdigest"}
)


def _compared_name(expr: ast.expr) -> str:
    """The name of the value an operand denotes: ``token`` for ``token``,
    ``self.token``, ``d["token"]``, ``headers.get("token")`` and
    ``token.strip()``; ``""`` when there is none."""
    if isinstance(expr, ast.Name):
        return expr.id
    if isinstance(expr, ast.Attribute):
        return expr.attr
    if isinstance(expr, ast.Subscript):
        return _str_value(expr.slice) or ""
    if isinstance(expr, ast.Call) and isinstance(expr.func, ast.Attribute):
        if expr.func.attr == "get" and expr.args:
            return _str_value(expr.args[0]) or ""
        if expr.func.attr in _TIMING_PASSTHROUGH_METHODS:
            return _compared_name(expr.func.value)
    return ""


def _is_secret_name(name: str) -> bool:
    return (
        bool(name) and bool(_TIMING_SECRET_RE.search(name)) and not _DESCRIPTOR_NAME_RE.search(name)
    )


def check_timing_attack(path: Path, lines: list[str], tree: ast.Module | None) -> list[Finding]:
    """CWE-208. ``==``/``!=`` between a value named like a secret
    (``password``, ``auth_header``, ``request.args.get("token")``) and a
    non-empty string literal. ``auth_type == "bearer"`` compares a
    descriptor, ``token == ""`` tests emptiness; neither is reported."""
    pk = _rel(path)
    results: list[Finding] = []
    seen: set[int] = set()
    for node in ast.walk(tree) if tree else []:
        if not isinstance(node, ast.Compare):
            continue
        operands = [node.left, *node.comparators]
        for op, left, right in zip(node.ops, operands, operands[1:]):
            if not isinstance(op, (ast.Eq, ast.NotEq)):
                continue
            for literal, other in ((left, right), (right, left)):
                text = _str_value(literal)
                # token != "None": a sentinel test, not a secret comparison.
                if text is None or text in _LITERAL_WORDS or not any(ch.isalnum() for ch in text):
                    continue
                if not _is_secret_name(_compared_name(other)):
                    continue
                line = _node_line(node)
                if line in seen:
                    break
                seen.add(line)
                results.append(
                    Finding(
                        cwe_id="CWE-208",
                        cwe_name="Timing Attack",
                        severity="LOW",
                        confidence="LOW",
                        package="",
                        file=pk,
                        line=line,
                        code_snippet=_code_at(lines, line),
                        description="String comparison with == may leak timing information for secret comparison. Use secrets.compare_digest().",
                    )
                )
                break
    return results
