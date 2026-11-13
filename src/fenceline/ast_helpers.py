"""AST and text-matching helpers shared by the check functions in
:mod:`fenceline.checks`.
"""

from __future__ import annotations

import ast
import functools
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
    "_iter_function_scopes",
    "_collect_scope_names",
    "_iter_calls_in_scope",
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


def _dotted_name(expr: ast.expr) -> str:
    """``a.b.c`` for an attribute chain rooted at a name; ``""`` for anything else."""
    parts: list[str] = []
    cur = expr
    while isinstance(cur, ast.Attribute):
        parts.append(cur.attr)
        cur = cur.value
    if isinstance(cur, ast.Name):
        parts.append(cur.id)
    parts.reverse()
    return ".".join(parts)


def _full_attr(node: ast.Call) -> str:
    return _dotted_name(node.func)


@functools.lru_cache(maxsize=4)
def _call_nodes(tree: ast.Module | None) -> tuple[ast.Call, ...]:
    """Every ``ast.Call`` in *tree*, in ``ast.walk`` order. Cached per tree
    object: a file's tree is handed to every check in turn, and a dozen of
    them want exactly this list -- one walk instead of one per check. The
    cache holds a reference to the tree, so an id can't be reused while
    its entry is live; the handful of entries is bounded by ``maxsize``."""
    return tuple(n for n in (ast.walk(tree) if tree else ()) if isinstance(n, ast.Call))


@functools.lru_cache(maxsize=4)
def _import_aliases(tree: ast.Module | None) -> dict[str, str]:
    """Local name -> fully-qualified dotted name, for every absolute import in
    the file that binds something other than its own top-level name (cached
    per tree, like ``_call_nodes``):
    ``import a.b as c`` gives ``{"c": "a.b"}``, ``from a.b import c as d``
    gives ``{"d": "a.b.c"}`` (``from a.b import c`` gives ``{"c": "a.b.c"}``).
    ``import a.b`` binds ``a`` to itself and is omitted; relative and
    star imports can't be resolved and are omitted too."""
    aliases: dict[str, str] = {}
    for node in ast.walk(tree) if tree else []:
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.asname and alias.asname != alias.name:
                    aliases[alias.asname] = alias.name
        elif isinstance(node, ast.ImportFrom) and node.module and not node.level:
            for alias in node.names:
                if alias.name != "*":
                    aliases[alias.asname or alias.name] = f"{node.module}.{alias.name}"
    return aliases


def _resolve_dotted(dotted: str, aliases: dict[str, str]) -> str:
    """``dotted`` with its first segment replaced by what the file's imports
    bind it to -- ``p.loads`` is ``pickle.loads`` after ``import pickle as p``,
    ``loads`` is ``pickle.loads`` after ``from pickle import loads``."""
    head, sep, rest = dotted.partition(".")
    target = aliases.get(head)
    return f"{target}{sep}{rest}" if target else dotted


def _callee(node: ast.Call, aliases: dict[str, str]) -> str:
    """Import-alias-resolved dotted name of a call's callee (see
    ``_resolve_dotted``); ``""`` when the callee isn't a name/attribute chain."""
    return _resolve_dotted(_full_attr(node), aliases)


def _dotted_matches(dotted: str, name: str) -> bool:
    """``name`` as the whole dotted path or its tail (``pkg.pickle.loads``
    counts as ``pickle.loads``; ``cloudpickle.loads`` does not)."""
    return dotted == name or dotted.endswith("." + name)


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
    a ``raise`` statement anywhere in the block (including nested ``if``/``try``,
    but not inside a nested function/lambda/class body — code merely defined there
    doesn't run as part of this handler); or any reference to the handler's own
    bound exception name (``except Exception as exc:`` -- a later ``exc``
    anywhere in the body, e.g. ``print(f"...{exc}")`` or ``metrics.record(exc)``,
    means the exception is being surfaced through some mechanism other than
    the stdlib ``logging`` module, which still counts as reported rather than
    silently swallowed). Walks the whole subtree, not just top-level
    statements, so a diagnostic inside a nested block still counts.
    """
    for stmt in handler.body:
        for node in _walk_skip_nested_scopes(stmt):
            if isinstance(node, ast.Raise):
                return True
            if handler.name is not None and isinstance(node, ast.Name) and node.id == handler.name:
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


# ── Local (same-function-scope) constant resolution ──────────────────────
#
# Deliberately NOT full taint tracking: this only ever looks at the same
# function's own body plus the enclosing module's top-level constants and
# imports -- never across a function/call boundary. ``fenceline.taint`` builds
# on the same scope model to classify a sink's inputs.


def _collect_scope_names(stmts: list[ast.stmt]) -> tuple[dict[str, ast.expr], frozenset[str]]:
    """``(name -> assigned value, names bound by import statements or
    sibling function definitions)`` for every simple ``Name = value``/
    ``Name: T = value`` assignment, ``import``/``from ... import``
    statement, and ``def``/``async def`` directly in *stmts* — not nested
    inside a further function/class body (mirrors
    ``_walk_skip_nested_scopes``'s own scope boundary).

    A locally-defined helper function's *name* is folded into the same
    "known safe reference" set as imports: calling ``build_request(BASE,
    path)`` only depends on whether ``BASE``/``path`` are themselves safe
    (checked recursively via each argument), exactly like calling
    ``requests.get(...)`` doesn't require inspecting ``requests``' own
    internals. Without this, routing a call through any local helper
    function — rather than inlining it — made `_is_locally_safe_expr`
    treat the whole expression as unsafe regardless of its arguments,
    since a bare reference to the helper's name resolved to neither an
    import nor an assigned literal.
    """
    literals: dict[str, ast.expr] = {}
    imports: set[str] = set()
    for stmt in stmts:
        for node in _walk_skip_nested_scopes(stmt):
            if isinstance(node, ast.Assign):
                for target in node.targets:
                    if isinstance(target, ast.Name):
                        literals[target.id] = node.value
            elif (
                isinstance(node, ast.AnnAssign)
                and isinstance(node.target, ast.Name)
                and node.value is not None
            ):
                literals[node.target.id] = node.value
            elif isinstance(node, (ast.Import, ast.ImportFrom)):
                for alias in node.names:
                    imports.add(alias.asname or alias.name.split(".")[0])
            elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                imports.add(node.name)
            elif isinstance(node, (ast.With, ast.AsyncWith)):
                # `with X() as y:` binds `y` to X()'s result for the
                # remainder of the block, same as `y = X()` would -- treated
                # identically here so a name bound via a context manager
                # (e.g. `with httpx.AsyncClient() as client:`) resolves the
                # same way a plain assignment does for callers that walk
                # this scope's `literals`.
                for item in node.items:
                    if isinstance(item.optional_vars, ast.Name):
                        literals[item.optional_vars.id] = item.context_expr
    return literals, frozenset(imports)


def _iter_function_scopes(tree: ast.Module):
    """Yields ``(stmts, param_names)`` for the module's own top-level body
    (no parameters) and for every ``FunctionDef``/``AsyncFunctionDef`` in
    the tree, regardless of nesting depth — each function's own body is
    yielded once, independently. Uses a single ``ast.walk(tree)`` pass to
    find every function (visits each node exactly once, so no manual
    recursion is needed and a call inside a nested inner function can't
    get double-processed under both the inner and outer function's scope).
    """
    yield tree.body, frozenset()
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            params = frozenset(
                a.arg for a in (*node.args.posonlyargs, *node.args.args, *node.args.kwonlyargs)
            )
            yield node.body, params


def _iter_calls_in_scope(tree: ast.Module):
    """Yields ``(call_node, param_names, literals, imports)`` for every
    ``ast.Call`` in *tree*, each correctly scoped to its own immediately
    enclosing function (or the module, if not inside any function).

    Uses ``_walk_skip_nested_scopes`` (not a raw ``ast.walk``) when hunting
    for calls within one scope's statements — critical for correctness,
    not just tidiness: a raw ``ast.walk`` would also descend into a nested
    inner function's body and yield its calls scoped to the *outer*
    function (wrong parameter names, wrong locals), and that same inner
    call would then be yielded a second time, correctly, when its own
    function's turn comes up via ``_iter_function_scopes``. Skipping
    nested scopes here means each call is yielded exactly once, with the
    scope that's actually its own.
    """
    module_literals, module_imports = _collect_scope_names(tree.body)
    for stmts, params in _iter_function_scopes(tree):
        literals, imports = _collect_scope_names(stmts)
        merged_literals = {**module_literals, **literals}
        merged_imports = module_imports | imports
        for stmt in stmts:
            for node in _walk_skip_nested_scopes(stmt):
                if isinstance(node, ast.Call):
                    yield node, params, merged_literals, merged_imports
