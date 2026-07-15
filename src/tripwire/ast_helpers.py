"""AST and text-matching helpers shared by the check functions in
:mod:`tripwire.checks`.
"""

from __future__ import annotations

import ast
import re

__all__ = [
    "_LOGGING_METHOD_NAMES",
    "_LOG_METHOD_CALL_RE",
    "_LOG_METHOD_CALL_ANY_RE",
    "_LOG_NAME_TOKENS",
    "_NESTED_SCOPE_TYPES",
    "_call_name",
    "_full_attr",
    "_is_re_compile",
    "_is_sqlalchemy_compile",
    "_has_dynamic_arg",
    "_node_line",
    "_has_log_like_token",
    "_walk_skip_nested_scopes",
    "_handler_has_diagnostic",
    "_skip",
]

# Logging method names shared by every check that needs to recognize a
# logging call (CWE-778 diagnostic detection, CWE-117 log injection,
# CWE-532 log secrets). Defined once so these checks can never independently
# drift out of sync with each other on which method names count as logging.
_LOGGING_METHOD_NAMES = frozenset(
    {"debug", "info", "warning", "warn", "error", "critical", "exception", "log"}
)

# Derived from _LOGGING_METHOD_NAMES (not a second hand-typed list) — matches
# a logging call whose argument is an f-string, e.g. `logger.error(f"...")`.
_LOG_METHOD_CALL_RE = re.compile(
    r"\.(?:" + "|".join(re.escape(name) for name in _LOGGING_METHOD_NAMES) + r')\s*\(\s*f["\']'
)

# Same method-name set, without the f-string requirement — for checks (e.g.
# check_log_secrets) that need to detect any logging call regardless of the
# argument's literal form.
_LOG_METHOD_CALL_ANY_RE = re.compile(
    r"\.(?:" + "|".join(re.escape(name) for name in _LOGGING_METHOD_NAMES) + r")\s*\("
)

# Word-level tokens (not raw substrings) that mark a bare function call as
# logging-related, e.g. `_log(logger, "debug", ...)` or `log_error(...)`.
# Matching on whole '.'/'_'-delimited tokens rather than a raw substring test
# avoids false positives on unrelated names that merely end in "...log" with
# no delimiter — `catalog.get()`, `dialog.close()`, `backlog.append()`, and
# `analog_signal.process()` all contain the substring "log" but are not
# logging calls; none of them tokenize to a standalone "log"-family word.
_LOG_NAME_TOKENS = frozenset({"log", "logs", "logger", "logging"})

# AST node types that introduce a new, separately-executed scope. A statement
# merely *defined* inside one of these (a nested function/lambda/class body)
# does not run when the enclosing except block runs, so diagnostics found
# there don't count as the handler having one.
_NESTED_SCOPE_TYPES = (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda, ast.ClassDef)


def _call_name(node: ast.Call) -> str:
    if isinstance(node.func, ast.Name):
        return node.func.id
    if isinstance(node.func, ast.Attribute):
        return node.func.attr
    return ""


def _full_attr(node: ast.Call) -> str:
    parts: list[str] = []
    cur = node.func
    while isinstance(cur, ast.Attribute):
        parts.append(cur.attr)
        cur = cur.value
    if isinstance(cur, ast.Name):
        parts.append(cur.id)
    parts.reverse()
    return ".".join(parts)


def _is_re_compile(node: ast.Call) -> bool:
    name = _full_attr(node)
    return (
        name
        in (
            "re.compile",
            "re.compile",
        )
        or _call_name(node) == "compile"
        and isinstance(node.func, ast.Attribute)
        and isinstance(node.func.value, ast.Name)
        and node.func.value.id == "re"
    )


def _is_sqlalchemy_compile(node: ast.Call) -> bool:
    name = _full_attr(node)
    return "compile" in name and any(x in name for x in ("statement", "query", "select", "sql"))


def _has_dynamic_arg(node: ast.Call) -> bool:
    """Check if any positional or keyword argument to a call is dynamic (not a constant)."""
    for arg in node.args:
        if not isinstance(arg, (ast.Constant, ast.Str, ast.Num, ast.NameConstant)):
            return True
    for kw in node.keywords:
        if not isinstance(kw.value, (ast.Constant, ast.Str, ast.Num, ast.NameConstant)):
            return True
    return False


def _node_line(node: ast.AST) -> int:
    return getattr(node, "lineno", 0)


def _has_log_like_token(full_name: str) -> bool:
    """True if any ``.``/``_``-delimited token in *full_name* is a
    logging-related word, e.g. ``"log"`` or ``"logger"`` — not merely present
    as a substring somewhere inside a longer, unrelated word.
    """
    tokens = re.split(r"[._]+", full_name.lower())
    return any(tok in _LOG_NAME_TOKENS for tok in tokens if tok)


def _walk_skip_nested_scopes(node: ast.AST):
    """Like ``ast.walk()``, but does not descend into nested function/lambda/
    class bodies — see ``_NESTED_SCOPE_TYPES`` for why.

    Checks *node itself* (not just its children) against ``_NESTED_SCOPE_TYPES``
    before recursing, so this is correct both when a scope-creating node is
    reached via recursion from a wrapping statement (e.g. a ``Lambda`` inside
    an ``Assign``) and when it *is* the starting node passed in directly (e.g.
    a top-level ``def`` statement in the handler body being walked itself).
    """
    yield node
    if isinstance(node, _NESTED_SCOPE_TYPES):
        return
    for child in ast.iter_child_nodes(node):
        yield from _walk_skip_nested_scopes(child)


def _handler_has_diagnostic(handler: ast.ExceptHandler) -> bool:
    """True if an ``except`` block logs, re-raises, or otherwise surfaces the
    exception rather than silently swallowing it.

    Looks for: a call whose attribute name is a logging method (``logger.debug(...)``,
    ``self.logger.error(...)``); a bare function call whose name tokenizes to a
    logging-related word (catches helper wrappers like ``_log(logger, "debug", ...)``
    without false-positiving on unrelated names like ``catalog``/``dialog``); ``warnings.warn(...)``;
    or a ``raise`` statement anywhere in the block (including nested ``if``/``try``,
    but not inside a nested function/lambda/class body — code merely defined there
    doesn't run as part of this handler). Walks the whole subtree, not just
    top-level statements, so a diagnostic inside a nested block still counts.
    """
    for stmt in handler.body:
        for node in _walk_skip_nested_scopes(stmt):
            if isinstance(node, ast.Raise):
                return True
            if not isinstance(node, ast.Call):
                continue
            if isinstance(node.func, ast.Attribute) and node.func.attr in _LOGGING_METHOD_NAMES:
                return True
            full = _full_attr(node)
            if full == "warnings.warn" or _has_log_like_token(full):
                return True
    return False


def _skip(line: str) -> bool:
    return line.strip().startswith("#")
