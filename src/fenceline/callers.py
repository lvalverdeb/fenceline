"""Cross-file parameter taint.

``fenceline.taint`` classifies a sink by the names that feed it inside one
function; a parameter of a non-handler function is INTERNAL because the
function alone does not say where its argument came from. This module
looks at the callers: after every file of a package is parsed, it binds
each call's arguments to the callee's parameters and marks a parameter
CALLER (``taint.mark_caller_param``) when some caller in the package
passes request data to it. Repeated to a fixpoint, so a value that crosses
two or three helpers still arrives.

Callees are resolved by name: a function or class defined in the same
file, ``from mod import f`` / ``import mod`` (absolute, relative, or a
sibling file of the importer), ``Class.method`` for a class in scope, and
``self.method`` inside a class. Anything else is left alone; the pass only
ever promotes a parameter, never creates or removes a finding.
"""

from __future__ import annotations

import ast
from dataclasses import dataclass, field
from pathlib import Path

from fenceline.ast_helpers import _dotted_name
from fenceline.taint import Taint, classify, enclosing_class, mark_caller_param

__all__ = ["propagate"]

_MAX_ROUNDS = 8


@dataclass
class _Def:
    positional: list[str]  # posonly + regular, in order, including self/cls
    kwonly: frozenset[str]
    vararg: str | None
    skip_first: bool  # a method: self/cls is bound implicitly


@dataclass
class _Module:
    path: Path
    tree: ast.Module
    defs: dict[str, _Def] = field(default_factory=dict)
    classes: set[str] = field(default_factory=set)
    #: local name (or dotted prefix, for ``import a.b``) -> module spec
    aliases: dict[str, str] = field(default_factory=dict)
    #: local name -> (module spec, attribute) for ``from mod import attr``
    from_names: dict[str, tuple[str, str]] = field(default_factory=dict)
    calls: list[ast.Call] = field(default_factory=list)


def _def_of(fn: ast.FunctionDef | ast.AsyncFunctionDef, *, method: bool) -> _Def:
    a = fn.args
    static = any(_dotted_name(d) == "staticmethod" for d in fn.decorator_list)
    return _Def(
        positional=[p.arg for p in (*a.posonlyargs, *a.args)],
        kwonly=frozenset(p.arg for p in a.kwonlyargs),
        vararg=a.vararg.arg if a.vararg is not None else None,
        skip_first=method and not static,
    )


def _index(path: Path, tree: ast.Module) -> _Module:
    mod = _Module(path=path, tree=tree)
    for stmt in tree.body:
        if isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef)):
            mod.defs[stmt.name] = _def_of(stmt, method=False)
        elif isinstance(stmt, ast.ClassDef):
            mod.classes.add(stmt.name)
            for inner in stmt.body:
                if isinstance(inner, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    mod.defs[f"{stmt.name}.{inner.name}"] = _def_of(inner, method=True)
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                mod.aliases[alias.asname or alias.name] = alias.name
        elif isinstance(node, ast.ImportFrom):
            spec = "." * node.level + (node.module or "")
            for alias in node.names:
                if alias.name != "*":
                    mod.from_names[alias.asname or alias.name] = (spec, alias.name)
        elif isinstance(node, ast.Call):
            mod.calls.append(node)
    return mod


class _Package:
    def __init__(self, trees: dict[Path, ast.Module], root: Path) -> None:
        self.root = root
        self.modules = [_index(p, t) for p, t in sorted(trees.items())]
        self.by_path = {m.path: m for m in self.modules}
        self.by_stem: dict[str, list[_Module]] = {}
        for m in self.modules:
            self.by_stem.setdefault(m.path.stem, []).append(m)

    def _at(self, base: Path, dotted: str) -> _Module | None:
        p = base.joinpath(*dotted.split(".")) if dotted else base
        return self.by_path.get(p.with_suffix(".py")) or self.by_path.get(p / "__init__.py")

    def module(self, spec: str, importer: _Module) -> _Module | None:
        """The package file an import spec names, or ``None`` for anything
        outside the package. A sibling of the importer wins over a path from
        the package root, which wins over a unique file of that stem."""
        if spec.startswith("."):
            level = len(spec) - len(spec.lstrip("."))
            base = importer.path.parent
            for _ in range(level - 1):
                base = base.parent
            return self._at(base, spec.lstrip("."))
        found = self._at(importer.path.parent, spec) or self._at(self.root, spec)
        if found is None:
            candidates = self.by_stem.get(spec.rsplit(".", 1)[-1], [])
            found = candidates[0] if len(candidates) == 1 else None
        return found

    @staticmethod
    def _callable(target: _Module | None, name: str) -> tuple[_Module, str] | None:
        """``name`` as a def of *target*: a function, a ``Class.method``, or
        a class (its ``__init__``)."""
        if target is None:
            return None
        if name in target.defs:
            return target, name
        if f"{name}.__init__" in target.defs:
            return target, f"{name}.__init__"
        return None

    def callee(self, mod: _Module, call: ast.Call) -> tuple[_Module, str] | None:
        func = call.func
        if isinstance(func, ast.Name):
            if func.id in mod.from_names:
                spec, attr = mod.from_names[func.id]
                return self._callable(self.module(spec, mod), attr)
            return self._callable(mod, func.id)
        dotted = _dotted_name(func) or ""
        parts = dotted.split(".")
        if len(parts) < 2:
            return None
        head = parts[0]
        if head in ("self", "cls") and len(parts) == 2:
            cls = enclosing_class(mod.tree, call)
            return self._callable(mod, f"{cls}.{parts[1]}") if cls else None
        for i in range(len(parts) - 1, 0, -1):
            prefix = ".".join(parts[:i])
            if prefix in mod.aliases:
                target = self.module(mod.aliases[prefix], mod)
                return self._callable(target, ".".join(parts[i:]))
        if len(parts) == 2 and head in mod.from_names:
            spec, attr = mod.from_names[head]
            # ``from pkg import mod`` binds a submodule, not an attribute.
            submodule = self.module(spec + ("" if spec.endswith(".") else ".") + attr, mod)
            if submodule is not None:
                return self._callable(submodule, parts[1])
            return self._callable(self.module(spec, mod), f"{attr}.{parts[1]}")
        if len(parts) == 2 and head in mod.classes:
            return self._callable(mod, dotted)
        return None

    def bind(self, mod: _Module, call: ast.Call) -> bool:
        """Mark the callee's parameters that this call feeds request data;
        ``True`` when a new parameter was marked."""
        resolved = self.callee(mod, call)
        if resolved is None:
            return False
        target, qualname = resolved
        d = target.defs[qualname]
        positional = d.positional[1:] if d.skip_first else d.positional
        bound: list[tuple[str, ast.expr]] = []
        for i, arg in enumerate(call.args):
            if isinstance(arg, ast.Starred):
                break
            if i < len(positional):
                bound.append((positional[i], arg))
            elif d.vararg is not None:
                bound.append((d.vararg, arg))
            else:
                break
        for kw in call.keywords:
            if kw.arg is not None and (kw.arg in positional or kw.arg in d.kwonly):
                bound.append((kw.arg, kw.value))
        changed = False
        for param, arg in bound:
            if classify(mod.tree, call, [arg]) >= Taint.CALLER:
                changed |= mark_caller_param(target.tree, qualname, param)
        return changed


def propagate(trees: dict[Path, ast.Module], root: Path) -> None:
    """Mark, in every tree of the package rooted at *root*, the parameters
    that receive request data from some call in the package."""
    if len(trees) == 0:
        return
    package = _Package(trees, root)
    for _ in range(_MAX_ROUNDS):
        changed = False
        for mod in package.modules:
            for call in mod.calls:
                changed |= package.bind(mod, call)
        if not changed:
            return
