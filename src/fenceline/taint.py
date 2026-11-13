"""Intra-procedural taint classification for injection-shaped sinks.

A check like ``check_command_injection`` knows the *shape* of a dangerous
call but not where its data came from, and "may allow injection if
arguments are unvalidated" is a hedge, not a finding. This module answers
the one question that hedge leaves open, within the enclosing function:

- ``SOURCE`` -- data from a recognised entry point (a request object,
  ``os.environ``, ``sys.argv``, ``input()``, a socket read, or a parameter
  of a request handler) reaches the sink. The finding is real as reported.
- ``INTERNAL`` -- the sink is fed by plain function parameters, ``self``
  attributes, or values this scope cannot resolve. Dangerous if the caller
  is untrusted; library plumbing (an HTTP writer building its own framing)
  looks exactly like this too.
- ``CLEAN`` -- every input resolves to a literal, a module-level constant,
  a library reference, or a value that cannot carry an injection (a
  length, an int, a quoted argument). Nothing to report.

The analysis is deliberately flow-insensitive and never crosses a
function boundary: a name's taint is the worst of every value assigned
to it anywhere in the same scope, and a call to an unknown function
propagates its arguments' taint. ``confidence_for`` maps the result onto
the finding's existing confidence axis -- no new field, so
``--confidence-min high`` means "a source reaches the sink" for these
checks while the default keeps every unresolved case visible.
"""

from __future__ import annotations

import ast
import builtins
from dataclasses import dataclass, field
from enum import IntEnum

from fenceline.ast_helpers import _dotted_name, _walk_skip_nested_scopes

__all__ = [
    "Taint",
    "bound_values",
    "classify",
    "confidence_for",
    "enclosing_class",
    "mark_caller_param",
    "CALLER_NOTE",
    "INTERNAL_NOTE",
]


class Taint(IntEnum):
    CLEAN = 0
    INTERNAL = 1
    #: A parameter that a caller elsewhere in the package feeds request data
    #: (``fenceline.callers``); as reportable as SOURCE, with its own note.
    CALLER = 2
    SOURCE = 3


#: Appended to a finding's description when no source reaches the sink.
INTERNAL_NOTE = " No request or environment input reaches this call within the enclosing function."

#: Appended when the source is a caller's argument, not this function's code.
CALLER_NOTE = " Request data reaches a parameter of this function from a caller in the package."

# Names that carry request data in the frameworks fenceline recognises when
# used as the root of an attribute, subscript or call chain.
_REQUEST_ROOTS = frozenset({"request", "environ"})

# Dotted prefixes that are sources wherever they appear.
_SOURCE_PREFIXES = ("os.environ", "sys.argv", "sys.stdin", "self.request")

# Bare calls that read external input.
_SOURCE_CALLS = frozenset({"input", "os.getenv", "os.environb.get"})

# Method names whose result is request or network input regardless of receiver.
_SOURCE_METHODS = frozenset(
    {
        "recv",
        "recv_into",
        "recvfrom",
        "recvmsg",
        "get_argument",
        "get_arguments",
        "get_query_argument",
        "get_query_arguments",
        "get_body_argument",
        "get_body_arguments",
        "get_cookie",
        "get_secure_cookie",
        "get_json",
        "get_data",
    }
)

# Calls whose result cannot carry an injection payload: numeric conversions,
# sizes, and the standard quoting/escaping functions.
_CLEAN_CALLS = frozenset(
    {
        "int",
        "float",
        "bool",
        "len",
        "abs",
        "round",
        "hash",
        "id",
        "isinstance",
        "ord",
        "min",
        "max",
        "sum",
        "shlex.quote",
        "shlex.join",
        "urllib.parse.quote",
        "urllib.parse.quote_plus",
        "html.escape",
        "re.escape",
    }
)

# Methods returning a bool/int rather than the receiver's content.
_CLEAN_METHODS = frozenset(
    {
        "isdigit",
        "isalnum",
        "isalpha",
        "isidentifier",
        "startswith",
        "endswith",
        "count",
        "index",
        "find",
        "rfind",
        "isdisjoint",
    }
)

# Decorator tails that mark a function as an HTTP route or handler.
_ROUTE_DECORATORS = frozenset(
    {
        "route",
        "get",
        "post",
        "put",
        "patch",
        "delete",
        "head",
        "options",
        "api_route",
        "websocket",
        "websocket_route",
        "view",
        "middleware",
    }
)

# Base-class name tails that mark a class as a request handler; HTTP-method
# names on such a class take request data as parameters.
_HANDLER_BASES = ("Handler", "View", "ViewSet", "Resource", "Endpoint", "Consumer")
_HANDLER_METHODS = frozenset(
    {
        "get",
        "post",
        "put",
        "patch",
        "delete",
        "head",
        "options",
        "prepare",
        "dispatch",
        "open",
        "on_message",
        "data_received",
        "receive",
    }
)

_BUILTIN_NAMES = frozenset(dir(builtins))
_MAX_DEPTH = 10


@dataclass
class _Scope:
    params: frozenset[str]
    handler: bool
    assigns: dict[str, list[ast.expr]] = field(default_factory=dict)
    imports: set[str] = field(default_factory=set)
    #: ``Class.method`` / ``func`` / ``outer.inner``; "" for the module.
    qualname: str = ""
    #: Name of the class whose body directly holds this function, if any.
    cls: str | None = None
    #: Parameters some caller in the package feeds request data (set by
    #: ``fenceline.callers`` after every file of the package is parsed).
    caller_params: set[str] = field(default_factory=set)


@dataclass
class _Scopes:
    at: dict[int, _Scope]
    functions: dict[str, _Scope]


def _bind(scope: _Scope, target: ast.expr, value: ast.expr) -> None:
    for node in ast.walk(target):
        if isinstance(node, ast.Name):
            scope.assigns.setdefault(node.id, []).append(value)


def _collect(scope: _Scope, stmts: list[ast.stmt]) -> None:
    for stmt in stmts:
        for node in _walk_skip_nested_scopes(stmt):
            if isinstance(node, ast.Assign):
                for target in node.targets:
                    _bind(scope, target, node.value)
            elif isinstance(node, (ast.AnnAssign, ast.AugAssign)) and node.value is not None:
                _bind(scope, node.target, node.value)
            elif isinstance(node, ast.NamedExpr):
                _bind(scope, node.target, node.value)
            elif isinstance(node, (ast.For, ast.AsyncFor, ast.comprehension)):
                _bind(scope, node.target, node.iter)
            elif isinstance(node, (ast.With, ast.AsyncWith)):
                for item in node.items:
                    if item.optional_vars is not None:
                        _bind(scope, item.optional_vars, item.context_expr)
            elif isinstance(node, (ast.Import, ast.ImportFrom)):
                for alias in node.names:
                    scope.imports.add(alias.asname or alias.name.split(".")[0])
            elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                scope.imports.add(node.name)


def _is_handler(fn: ast.FunctionDef | ast.AsyncFunctionDef, cls: ast.ClassDef | None) -> bool:
    for deco in fn.decorator_list:
        target = deco.func if isinstance(deco, ast.Call) else deco
        dotted = _dotted_name(target) or ""
        if dotted.rsplit(".", 1)[-1] in _ROUTE_DECORATORS and "." in dotted:
            return True
    if cls is not None and fn.name in _HANDLER_METHODS:
        for base in cls.bases:
            if (_dotted_name(base) or "").endswith(_HANDLER_BASES):
                return True
    return False


def _scope_map(tree: ast.Module) -> _Scopes:
    """``id(node) -> scope`` for every node in *tree* plus ``qualname ->
    scope`` for every function; module-level names are folded into every
    function scope so a module constant resolves the same way a local one
    does. Cached on the tree itself: the scopes are mutable (caller
    parameters) and must stay the same objects for the tree's lifetime."""
    cached = getattr(tree, "_fenceline_scopes", None)
    if cached is not None:
        return cached
    module = _Scope(params=frozenset(), handler=False)
    _collect(module, tree.body)
    scopes: dict[int, _Scope] = {}
    functions: dict[str, _Scope] = {}
    for stmt in tree.body:
        for node in _walk_skip_nested_scopes(stmt):
            scopes[id(node)] = module

    def visit_functions(body: list[ast.stmt], cls: ast.ClassDef | None, prefix: str) -> None:
        for stmt in body:
            for node in _walk_skip_nested_scopes(stmt):
                if isinstance(node, ast.ClassDef):
                    visit_functions(node.body, node, f"{prefix}{node.name}.")
                elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    args = node.args
                    params = frozenset(
                        a.arg
                        for a in (*args.posonlyargs, *args.args, *args.kwonlyargs)
                        if a.arg not in ("self", "cls")
                    ) | frozenset(a.arg for a in (args.vararg, args.kwarg) if a is not None)
                    qualname = f"{prefix}{node.name}"
                    scope = _Scope(
                        params=params,
                        handler=_is_handler(node, cls),
                        qualname=qualname,
                        cls=cls.name if cls is not None else None,
                    )
                    scope.assigns = {k: list(v) for k, v in module.assigns.items()}
                    scope.imports = set(module.imports)
                    _collect(scope, node.body)
                    functions[qualname] = scope
                    for inner in node.body:
                        for n in _walk_skip_nested_scopes(inner):
                            scopes[id(n)] = scope
                    visit_functions(node.body, None, f"{qualname}.")

    visit_functions(tree.body, None, "")
    result = _Scopes(at=scopes, functions=functions)
    tree._fenceline_scopes = result  # type: ignore[attr-defined]
    return result


def _source_chain(dotted: str) -> bool:
    root = dotted.split(".", 1)[0]
    return root in _REQUEST_ROOTS or dotted.startswith(_SOURCE_PREFIXES)


class _Classifier:
    def __init__(self, scope: _Scope) -> None:
        self.scope = scope
        self.active: set[str] = set()

    def name(self, name: str, depth: int) -> Taint:
        scope = self.scope
        if name in _REQUEST_ROOTS:
            return Taint.SOURCE
        if name in scope.params:
            if scope.handler:
                return Taint.SOURCE
            return Taint.CALLER if name in scope.caller_params else Taint.INTERNAL
        if name in scope.assigns:
            if name in self.active:
                return Taint.CLEAN  # cycle: the other branch decides
            self.active.add(name)
            try:
                return max(
                    (self.expr(v, depth + 1) for v in scope.assigns[name]), default=Taint.CLEAN
                )
            finally:
                self.active.discard(name)
        if name in scope.imports or name in _BUILTIN_NAMES:
            return Taint.CLEAN
        return Taint.INTERNAL

    def many(self, exprs, depth: int) -> Taint:
        worst = Taint.CLEAN
        for e in exprs:
            worst = max(worst, self.expr(e, depth))
            if worst is Taint.SOURCE:
                break
        return worst

    def expr(self, node: ast.expr, depth: int = 0) -> Taint:  # noqa: PLR0911
        if depth > _MAX_DEPTH:
            return Taint.INTERNAL
        if isinstance(node, ast.Constant):
            return Taint.CLEAN
        if isinstance(node, ast.Name):
            return self.name(node.id, depth)
        if isinstance(node, (ast.Attribute, ast.Subscript)):
            dotted = _dotted_name(node.value if isinstance(node, ast.Subscript) else node) or ""
            if dotted and _source_chain(dotted):
                return Taint.SOURCE
            if isinstance(node, ast.Attribute):
                if isinstance(node.value, ast.Name) and node.value.id == "self":
                    return Taint.INTERNAL
                return self.expr(node.value, depth + 1)
            return max(self.expr(node.value, depth + 1), self.expr(node.slice, depth + 1))
        if isinstance(node, ast.Call):
            dotted = _dotted_name(node.func) or ""
            method = node.func.attr if isinstance(node.func, ast.Attribute) else ""
            if dotted in _SOURCE_CALLS or _source_chain(dotted) or method in _SOURCE_METHODS:
                return Taint.SOURCE
            if dotted in _CLEAN_CALLS or method in _CLEAN_METHODS:
                return Taint.CLEAN
            return max(
                self.expr(node.func, depth + 1),
                self.many(node.args, depth + 1),
                self.many((kw.value for kw in node.keywords), depth + 1),
            )
        if isinstance(node, ast.JoinedStr):
            return self.many(
                (v.value for v in node.values if isinstance(v, ast.FormattedValue)), depth + 1
            )
        if isinstance(node, ast.FormattedValue):
            return self.expr(node.value, depth + 1)
        if isinstance(node, ast.BinOp):
            return max(self.expr(node.left, depth + 1), self.expr(node.right, depth + 1))
        if isinstance(node, (ast.BoolOp, ast.Tuple, ast.List, ast.Set)):
            return self.many(node.values if isinstance(node, ast.BoolOp) else node.elts, depth + 1)
        if isinstance(node, ast.Dict):
            return self.many((*(k for k in node.keys if k is not None), *node.values), depth + 1)
        if isinstance(node, ast.IfExp):
            return max(self.expr(node.body, depth + 1), self.expr(node.orelse, depth + 1))
        if isinstance(node, (ast.Starred, ast.Await, ast.NamedExpr, ast.UnaryOp)):
            inner = node.operand if isinstance(node, ast.UnaryOp) else node.value
            return self.expr(inner, depth + 1)
        if isinstance(node, (ast.ListComp, ast.SetComp, ast.GeneratorExp)):
            return max(
                self.expr(node.elt, depth + 1),
                self.many((g.iter for g in node.generators), depth + 1),
            )
        if isinstance(node, ast.DictComp):
            return max(
                self.expr(node.key, depth + 1),
                self.expr(node.value, depth + 1),
                self.many((g.iter for g in node.generators), depth + 1),
            )
        if isinstance(node, (ast.Compare, ast.Lambda)):
            return Taint.CLEAN
        return Taint.INTERNAL


def classify(tree: ast.Module, anchor: ast.AST, exprs: list[ast.expr]) -> Taint:
    """Worst taint over *exprs*, resolved in the scope that contains
    *anchor* (the sink node itself). An empty *exprs* is ``CLEAN``: a sink
    fed nothing has nothing to inject."""
    scope = _scope_map(tree).at.get(id(anchor))
    if scope is None:
        return Taint.INTERNAL
    return _Classifier(scope).many(exprs, 0)


def bound_values(tree: ast.Module, anchor: ast.AST, name: str) -> list[ast.expr]:
    """Every expression assigned to *name* in the scope that contains
    *anchor*, in source order; empty when the scope is unknown or the name
    is never assigned there. Lets a check see through ``q = ...; execute(q)``."""
    scope = _scope_map(tree).at.get(id(anchor))
    if scope is None:
        return []
    return list(scope.assigns.get(name, ()))


def enclosing_class(tree: ast.Module, node: ast.AST) -> str | None:
    """Name of the class whose method directly contains *node*, if any."""
    scope = _scope_map(tree).at.get(id(node))
    return scope.cls if scope is not None else None


def mark_caller_param(tree: ast.Module, qualname: str, param: str) -> bool:
    """Record that some caller feeds request data to *param* of the function
    *qualname* in *tree*; ``True`` when this is new information."""
    scope = _scope_map(tree).functions.get(qualname)
    if scope is None or param not in scope.params or param in scope.caller_params:
        return False
    scope.caller_params.add(param)
    return True


def confidence_for(taint: Taint) -> tuple[str, str] | None:
    """``(confidence, description_suffix)`` for a sink's taint, or ``None``
    to drop the finding: nothing attacker-reachable feeds it."""
    if taint is Taint.SOURCE:
        return "HIGH", ""
    if taint is Taint.CALLER:
        return "HIGH", CALLER_NOTE
    if taint is Taint.INTERNAL:
        return "MEDIUM", INTERNAL_NOTE
    return None
