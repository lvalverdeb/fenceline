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
    #: The enclosing class is a view/handler class, so ``self.kwargs`` and
    #: ``self.args`` hold URL captures.
    view_class: bool = False
    #: ``self.<field>`` -> every value assigned to it anywhere in the class,
    #: with the scope of the method that assigns it. Shared by the class's
    #: methods.
    fields: dict[str, list[tuple[ast.expr, _Scope]]] = field(default_factory=dict)


#: A guard on a name: ``(name, container)`` for ``name in container``, or
#: ``(name, None)`` for a check that needs no container (an anchored regex
#: match, an ``isdigit()``-style predicate, equality with a literal).
_Guard = tuple[str, "ast.expr | None"]


@dataclass
class _Scopes:
    at: dict[int, _Scope]
    functions: dict[str, _Scope]
    #: ``id(node) -> guards`` that hold where the node executes.
    guards: dict[int, tuple[_Guard, ...]]


_TERMINATING_CALLS = frozenset({"abort", "exit", "quit", "sys.exit", "os._exit"})
_PREDICATE_METHODS = frozenset(
    {"isdigit", "isalnum", "isalpha", "isidentifier", "isdecimal", "isnumeric"}
)


def _anchored_match_target(call: ast.Call) -> str | None:
    """The name a call validates: ``re.fullmatch(p, x)``, ``re.match("...$", x)``,
    ``PATTERN.fullmatch(x)``, or ``x.isdigit()``."""
    func = call.func
    if isinstance(func, ast.Attribute) and func.attr in _PREDICATE_METHODS:
        return func.value.id if isinstance(func.value, ast.Name) and not call.args else None
    dotted = _dotted_name(func) or ""
    args = call.args
    if dotted == "re.fullmatch" and len(args) >= 2 and isinstance(args[1], ast.Name):
        return args[1].id
    if (
        dotted == "re.match"
        and len(args) >= 2
        and isinstance(args[1], ast.Name)
        and isinstance(args[0], ast.Constant)
        and isinstance(args[0].value, str)
        and args[0].value.endswith(("$", "\\Z"))
    ):
        return args[1].id
    if (
        isinstance(func, ast.Attribute)
        and func.attr == "fullmatch"
        and len(args) == 1
        and isinstance(args[0], ast.Name)
    ):
        return args[0].id
    return None


def _guard_names(test: ast.expr) -> tuple[list[_Guard], list[_Guard]]:
    """``(when true, when false)``: the names *test* vouches for in each
    branch. ``not`` swaps them; ``and`` keeps only the true side, ``or`` only
    the false side, since one failing operand says nothing about the others."""
    if isinstance(test, ast.UnaryOp) and isinstance(test.op, ast.Not):
        pos, neg = _guard_names(test.operand)
        return neg, pos
    if isinstance(test, ast.BoolOp):
        parts = [_guard_names(v) for v in test.values]
        if isinstance(test.op, ast.And):
            return [g for pos, _ in parts for g in pos], []
        return [], [g for _, neg in parts for g in neg]
    if isinstance(test, ast.Compare) and len(test.ops) == 1 and isinstance(test.left, ast.Name):
        op, right = test.ops[0], test.comparators[0]
        if isinstance(op, ast.In):
            return [(test.left.id, right)], []
        if isinstance(op, ast.NotIn):
            return [], [(test.left.id, right)]
        if isinstance(right, ast.Constant):
            if isinstance(op, ast.Eq):
                return [(test.left.id, None)], []
            if isinstance(op, ast.NotEq):
                return [], [(test.left.id, None)]
        return [], []
    if isinstance(test, ast.Call):
        target = _anchored_match_target(test)
        return ([(target, None)], []) if target else ([], [])
    return [], []


def _terminates(stmts: list[ast.stmt]) -> bool:
    """The block never falls through: it raises, returns, breaks, continues
    or calls an exit/abort helper last."""
    if not stmts:
        return False
    last = stmts[-1]
    if isinstance(last, (ast.Raise, ast.Return, ast.Continue, ast.Break)):
        return True
    return (
        isinstance(last, ast.Expr)
        and isinstance(last.value, ast.Call)
        and (_dotted_name(last.value.func) or "") in _TERMINATING_CALLS
    )


def _bound_names(stmt: ast.stmt) -> set[str]:
    """Every name any assignment anywhere inside *stmt* (nested scopes
    excluded) binds: a guard on such a name no longer holds afterwards."""
    names: set[str] = set()
    for node in _walk_skip_nested_scopes(stmt):
        targets: list[ast.expr] = []
        if isinstance(node, ast.Assign):
            targets = node.targets
        elif isinstance(node, (ast.AnnAssign, ast.AugAssign, ast.NamedExpr, ast.For, ast.AsyncFor)):
            targets = [node.target]
        elif isinstance(node, (ast.With, ast.AsyncWith)):
            targets = [i.optional_vars for i in node.items if i.optional_vars is not None]
        for target in targets:
            names.update(n.id for n in ast.walk(target) if isinstance(n, ast.Name))
    return names


def _walk_guards(
    stmts: list[ast.stmt], guarded: list[_Guard], out: dict[int, tuple[_Guard, ...]]
) -> None:
    """Record, for every node in *stmts* (nested scopes excluded), the guards
    that hold where it executes. A block starts with its parent's guards and
    its own do not outlive it, except that an ``if`` whose body cannot fall
    through leaves its negated test in force for the statements after it."""
    guarded = list(guarded)

    def record(nodes: list[ast.AST]) -> None:
        if not guarded:
            return
        for root in nodes:
            for node in _walk_skip_nested_scopes(root):
                out[id(node)] = tuple(guarded)

    for stmt in stmts:
        if isinstance(stmt, (ast.If, ast.While)):
            record([stmt.test])
            pos, neg = _guard_names(stmt.test)
            _walk_guards(stmt.body, guarded + pos, out)
            _walk_guards(stmt.orelse, guarded + neg, out)
            if isinstance(stmt, ast.If):
                if _terminates(stmt.body):
                    guarded += neg
                if _terminates(stmt.orelse):
                    guarded += pos
        elif isinstance(stmt, ast.Assert):
            record([stmt.test])
            guarded += _guard_names(stmt.test)[0]
        elif isinstance(stmt, (ast.For, ast.AsyncFor)):
            record([stmt.target, stmt.iter])
            _walk_guards(stmt.body, guarded, out)
            _walk_guards(stmt.orelse, guarded, out)
        elif isinstance(stmt, (ast.With, ast.AsyncWith)):
            record(list(stmt.items))
            _walk_guards(stmt.body, guarded, out)
        elif isinstance(stmt, ast.Try):
            _walk_guards(stmt.body, guarded, out)
            for handler in stmt.handlers:
                _walk_guards(handler.body, guarded, out)
            _walk_guards(stmt.orelse, guarded, out)
            _walk_guards(stmt.finalbody, guarded, out)
        elif isinstance(stmt, ast.Match):
            record([stmt.subject])
            for case in stmt.cases:
                _walk_guards(case.body, guarded, out)
        elif isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            pass  # its own scope starts without guards
        else:
            record([stmt])
        if guarded:
            killed = _bound_names(stmt)
            guarded = [g for g in guarded if g[0] not in killed]


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


def _self_fields(
    methods: list[tuple[ast.FunctionDef | ast.AsyncFunctionDef, _Scope]],
) -> dict[str, list[tuple[ast.expr, _Scope]]]:
    """Every ``self.<field> = value`` in the class's methods, keyed by field."""
    fields: dict[str, list[tuple[ast.expr, _Scope]]] = {}
    for fn, scope in methods:
        for stmt in fn.body:
            for node in _walk_skip_nested_scopes(stmt):
                if isinstance(node, ast.Assign):
                    targets, value = node.targets, node.value
                elif isinstance(node, (ast.AnnAssign, ast.AugAssign)) and node.value is not None:
                    targets, value = [node.target], node.value
                else:
                    continue
                for target in targets:
                    if (
                        isinstance(target, ast.Attribute)
                        and isinstance(target.value, ast.Name)
                        and target.value.id == "self"
                    ):
                        fields.setdefault(target.attr, []).append((value, scope))
    return fields


def _is_view_class(cls: ast.ClassDef | None) -> bool:
    return cls is not None and any(
        (_dotted_name(base) or "").endswith(_HANDLER_BASES) for base in cls.bases
    )


def _is_handler(fn: ast.FunctionDef | ast.AsyncFunctionDef, cls: ast.ClassDef | None) -> bool:
    for deco in fn.decorator_list:
        target = deco.func if isinstance(deco, ast.Call) else deco
        dotted = _dotted_name(target) or ""
        if dotted.rsplit(".", 1)[-1] in _ROUTE_DECORATORS and "." in dotted:
            return True
    if fn.name in _HANDLER_METHODS and _is_view_class(cls):
        return True
    # An AWS Lambda entry point: the event is the request.
    return [a.arg for a in (*fn.args.posonlyargs, *fn.args.args)] == ["event", "context"]


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
    guards: dict[int, tuple[_Guard, ...]] = {}
    for stmt in tree.body:
        for node in _walk_skip_nested_scopes(stmt):
            scopes[id(node)] = module
    _walk_guards(tree.body, [], guards)

    def visit_functions(
        body: list[ast.stmt], cls: ast.ClassDef | None, prefix: str
    ) -> list[tuple[ast.FunctionDef | ast.AsyncFunctionDef, _Scope]]:
        """Build the scopes of the functions directly in *body*, recursing
        into nested classes and functions; returns the ones at this level."""
        made: list[tuple[ast.FunctionDef | ast.AsyncFunctionDef, _Scope]] = []
        for stmt in body:
            for node in _walk_skip_nested_scopes(stmt):
                if isinstance(node, ast.ClassDef):
                    methods = visit_functions(node.body, node, f"{prefix}{node.name}.")
                    fields = _self_fields(methods)
                    for _, method_scope in methods:
                        method_scope.fields = fields
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
                        view_class=_is_view_class(cls),
                    )
                    scope.assigns = {k: list(v) for k, v in module.assigns.items()}
                    scope.imports = set(module.imports)
                    _collect(scope, node.body)
                    functions[qualname] = scope
                    made.append((node, scope))
                    for inner in node.body:
                        for n in _walk_skip_nested_scopes(inner):
                            scopes[id(n)] = scope
                    _walk_guards(node.body, [], guards)
                    visit_functions(node.body, None, f"{qualname}.")
        return made

    visit_functions(tree.body, None, "")
    result = _Scopes(at=scopes, functions=functions, guards=guards)
    tree._fenceline_scopes = result  # type: ignore[attr-defined]
    return result


def _is_view_capture(dotted: str) -> bool:
    """``self.kwargs`` / ``self.args`` (or a chain on them): the URL captures
    of a class-based view."""
    return dotted in ("self.kwargs", "self.args") or dotted.startswith(
        ("self.kwargs.", "self.args.")
    )


def _source_chain(dotted: str) -> bool:
    root = dotted.split(".", 1)[0]
    return root in _REQUEST_ROOTS or dotted.startswith(_SOURCE_PREFIXES)


class _Classifier:
    def __init__(
        self,
        scope: _Scope,
        active_fields: frozenset[str] = frozenset(),
        clean_names: frozenset[str] = frozenset(),
    ) -> None:
        self.scope = scope
        self.active: set[str] = set()
        #: ``self.<field>`` names being resolved up the chain (cycle guard).
        self.active_fields = active_fields
        #: Names a guard vouches for where the sink executes.
        self.clean_names = clean_names

    def field(self, name: str, depth: int) -> Taint:
        """Taint of ``self.<name>``: the worst value assigned to it anywhere
        in the class, each resolved in its own method's scope. A field is
        never below INTERNAL -- it may be set from outside the class."""
        values = self.scope.fields.get(name)
        if not values or name in self.active_fields:
            return Taint.INTERNAL
        active = self.active_fields | {name}
        worst = Taint.INTERNAL
        for value, scope in values:
            worst = max(worst, _Classifier(scope, active).expr(value, depth + 1))
            if worst is Taint.SOURCE:
                break
        return worst

    def name(self, name: str, depth: int) -> Taint:
        scope = self.scope
        if name in _REQUEST_ROOTS:
            return Taint.SOURCE
        if name in self.clean_names:
            return Taint.CLEAN
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
            if self.scope.view_class and _is_view_capture(dotted):
                return Taint.SOURCE
            if isinstance(node, ast.Attribute):
                if isinstance(node.value, ast.Name) and node.value.id == "self":
                    return self.field(node.attr, depth)
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
    scopes = _scope_map(tree)
    scope = scopes.at.get(id(anchor))
    if scope is None:
        return Taint.INTERNAL
    clean = frozenset(
        name
        for name, container in scopes.guards.get(id(anchor), ())
        if container is None or _Classifier(scope).expr(container) is Taint.CLEAN
    )
    return _Classifier(scope, clean_names=clean).many(exprs, 0)


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
