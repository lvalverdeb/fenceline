"""Declarative rules: ``[[rule]]`` tables in a TOML file, loaded from
``--rules PATH`` (repeatable) and from the ``--config`` file, and run on
every scanned file after the built-in checks. The format is specified once,
in ``docs/rules.md``; the Rust port implements the same contract and both
conformance suites run the same ``fixtures/rules/`` cases.

Four kinds, which between them cover the shapes Semgrep's Python audit
rules take without pattern-inside, metavariable comparison or autofix:

- ``sink``: the callee matches and the selected arguments feed the taint
  engine, which sets confidence exactly as it does for the built-ins (or
  drops the finding when every input is provably constant).
- ``call``: the callee matches; confidence is fixed by the rule.
- ``keyword``: the callee matches and a named keyword has a given literal
  value, lacks one, or is missing.
- ``pattern``: a regex over the comment- and docstring-masked lines, with
  the full-line-comment skip the text checks apply.

A rule file is checked strictly: an unknown key, a misspelled kind or a
severity that is not one of the five levels is an error, not a silently
inert line in a security policy.
"""

from __future__ import annotations

import ast
import re
import tomllib
from dataclasses import dataclass
from pathlib import Path

from fenceline.ast_helpers import _callee, _dotted_matches, _import_aliases, _node_line, _skip
from fenceline.checks.ast_checks import _call_data, _calls, _code_at
from fenceline.models import CONFIDENCE_ORDER, SEVERITY_ORDER, Finding
from fenceline.scanner import _rel
from fenceline.taint import classify, confidence_for


class RuleError(ValueError):
    """A rule file that cannot be loaded; the message names the file and rule."""


KINDS = ("sink", "call", "keyword", "pattern")
_COMMON = frozenset({"id", "cwe", "name", "severity", "description", "kind"})
_FIELDS: dict[str, frozenset[str]] = {
    "sink": _COMMON | {"callee", "data"},
    "call": _COMMON | {"callee", "confidence"},
    "keyword": _COMMON | {"callee", "confidence", "keyword", "value", "unless", "required"},
    "pattern": _COMMON | {"confidence", "regex"},
}
_DEFAULT_CONFIDENCE = {"call": "HIGH", "keyword": "HIGH", "pattern": "MEDIUM"}
_CWE_RE = re.compile(r"^CWE-\d+$")
# The Rust port's regex engine has no lookaround and no backreferences; a
# pattern using them would load here and fail there, so it is refused here
# too. ``(?P<name>...)`` groups are fine; ``(?P=name)`` is a backreference.
_UNPORTABLE_RE = re.compile(r"\(\?<?[=!]|\\[1-9]|\(\?P=")

Literal = bool | int | str


@dataclass(frozen=True)
class Rule:
    id: str
    cwe: str
    name: str
    severity: str
    description: str
    kind: str
    #: Fixed confidence for ``call``/``keyword``/``pattern``; ``sink`` rules
    #: take theirs from the taint engine and ignore this.
    confidence: str = "HIGH"
    callee: tuple[str, ...] = ()
    #: ``sink``: ``"all"`` (every positional and keyword value), ``"first"``
    #: (the first positional) or selectors: positional indexes and keyword
    #: names.
    data: str | tuple[int | str, ...] = "all"
    keyword: str = ""
    #: ``keyword``: ``("value", lit)`` reports the keyword present with that
    #: literal; ``("unless", lit)`` reports it missing or anything but that
    #: literal; ``("required", True)`` reports it missing.
    keyword_test: tuple[str, Literal] = ("required", True)
    regex: re.Pattern[str] | None = None


def load_rule_set(config_path: Path | None, rule_paths: list[Path]) -> list[Rule]:
    """Every rule from the ``--config`` file's ``[[rule]]`` tables (if any)
    and from each ``--rules`` file, in that order; ids must be unique over
    the whole set."""
    rules: list[Rule] = []
    if config_path is not None:
        rules.extend(_rules_from_table(_read_toml(config_path, "--config"), str(config_path)))
    for path in rule_paths:
        loaded = _rules_from_table(_read_toml(path, "--rules"), str(path))
        if not loaded:
            raise RuleError(f"{path}: no [[rule]] tables")
        rules.extend(loaded)
    seen: dict[str, str] = {}
    for rule in rules:
        if rule.id in seen:
            raise RuleError(f"rule {rule.id!r} is defined twice")
        seen[rule.id] = rule.id
    return rules


def _read_toml(path: Path, flag: str) -> dict:
    try:
        return tomllib.loads(path.read_text())
    except OSError as exc:
        raise RuleError(f"could not read {flag} {path}: {exc}") from exc
    except tomllib.TOMLDecodeError as exc:
        raise RuleError(f"could not parse {flag} {path}: {exc}") from exc


def _rules_from_table(raw: dict, source: str) -> list[Rule]:
    entries = raw.get("rule", [])
    if not isinstance(entries, list) or not all(isinstance(e, dict) for e in entries):
        raise RuleError(f"{source}: 'rule' must be an array of tables ([[rule]])")
    return [_parse_rule(entry, index, source) for index, entry in enumerate(entries, 1)]


def _parse_rule(entry: dict, index: int, source: str) -> Rule:
    where = (
        f"{source}: rule {entry['id']!r}"
        if isinstance(entry.get("id"), str)
        else f"{source}: rule {index}"
    )

    def fail(msg: str) -> RuleError:
        return RuleError(f"{where}: {msg}")

    def text(key: str) -> str:
        value = entry.get(key)
        if not isinstance(value, str) or not value:
            raise fail(f"'{key}' must be a non-empty string")
        return value

    kind = text("kind")
    if kind not in KINDS:
        raise fail(f"kind {kind!r} is not one of {', '.join(KINDS)}")
    unknown = sorted(set(entry) - _FIELDS[kind])
    if unknown:
        raise fail(f"unknown key(s) for a {kind} rule: {', '.join(unknown)}")
    rule_id, cwe, name, description = text("id"), text("cwe"), text("name"), text("description")
    if not _CWE_RE.match(cwe):
        raise fail(f"cwe {cwe!r} must look like CWE-123")
    severity = text("severity").upper()
    if severity not in SEVERITY_ORDER:
        raise fail(f"severity must be one of {', '.join(k.lower() for k in SEVERITY_ORDER)}")
    confidence = _DEFAULT_CONFIDENCE.get(kind, "HIGH")
    if "confidence" in entry:
        confidence = text("confidence").upper()
        if confidence not in CONFIDENCE_ORDER:
            raise fail(
                f"confidence must be one of {', '.join(k.lower() for k in CONFIDENCE_ORDER)}"
            )

    callee: tuple[str, ...] = ()
    if kind != "pattern":
        raw_callee = entry.get("callee")
        if (
            not isinstance(raw_callee, list)
            or not raw_callee
            or not all(isinstance(c, str) and c for c in raw_callee)
        ):
            raise fail("'callee' must be a non-empty array of dotted names")
        callee = tuple(raw_callee)

    data: str | tuple[int | str, ...] = "all"
    if kind == "sink":
        raw_data = entry.get("data", "all")
        if raw_data in ("all", "first"):
            data = raw_data
        elif (
            isinstance(raw_data, list)
            and raw_data
            and all(
                (isinstance(s, int) and not isinstance(s, bool) and s >= 0)
                or (isinstance(s, str) and s)
                for s in raw_data
            )
        ):
            data = tuple(raw_data)
        else:
            raise fail(
                '\'data\' must be "all", "first" or an array of argument positions and keyword names'
            )

    keyword = ""
    keyword_test: tuple[str, Literal] = ("required", True)
    if kind == "keyword":
        keyword = text("keyword")
        tests = [k for k in ("value", "unless", "required") if k in entry]
        if len(tests) != 1:
            raise fail("exactly one of 'value', 'unless' or 'required = true' is needed")
        test = tests[0]
        literal = entry[test]
        if test == "required":
            if literal is not True:
                raise fail("'required' can only be true")
        elif not isinstance(literal, (bool, int, str)):
            raise fail(f"'{test}' must be a boolean, an integer or a string")
        keyword_test = (test, literal)

    regex: re.Pattern[str] | None = None
    if kind == "pattern":
        source_re = text("regex")
        if _UNPORTABLE_RE.search(source_re):
            raise fail("regex uses lookaround or a backreference, which the Rust port cannot run")
        try:
            regex = re.compile(source_re)
        except re.error as exc:
            raise fail(f"regex does not compile: {exc}") from exc

    return Rule(
        id=rule_id,
        cwe=cwe,
        name=name,
        severity=severity,
        description=description,
        kind=kind,
        confidence=confidence,
        callee=callee,
        data=data,
        keyword=keyword,
        keyword_test=keyword_test,
        regex=regex,
    )


def run_rules(
    rules: list[Rule],
    path: Path,
    lines: list[str],
    code_lines: list[str],
    tree: ast.Module | None,
) -> list[Finding]:
    """Findings of *rules* on one file. ``lines`` is the raw view (snippets
    for the call kinds), ``code_lines`` the masked view the pattern kind
    scans, as the text checks do."""
    if not rules:
        return []
    pk = _rel(path)
    results: list[Finding] = []
    call_rules = [r for r in rules if r.kind != "pattern"]
    if tree is not None and call_rules:
        aliases = _import_aliases(tree)
        for node in _calls(tree):
            fn = _callee(node, aliases)
            for rule in call_rules:
                if not any(_dotted_matches(fn, c) for c in rule.callee):
                    continue
                hit = _match_call(rule, tree, node)
                if hit is None:
                    continue
                confidence, note = hit
                line = _node_line(node)
                results.append(
                    Finding(
                        cwe_id=rule.cwe,
                        cwe_name=rule.name,
                        severity=rule.severity,
                        confidence=confidence,
                        package="",
                        file=pk,
                        line=line,
                        code_snippet=_code_at(lines, line),
                        description=rule.description + note,
                    )
                )
    for rule in rules:
        if rule.regex is None:
            continue
        for lineno, line in enumerate(code_lines, 1):
            if _skip(line) or not rule.regex.search(line):
                continue
            results.append(
                Finding(
                    cwe_id=rule.cwe,
                    cwe_name=rule.name,
                    severity=rule.severity,
                    confidence=rule.confidence,
                    package="",
                    file=pk,
                    line=lineno,
                    code_snippet=line.strip(),
                    description=rule.description,
                )
            )
    return results


def _match_call(rule: Rule, tree: ast.Module, node: ast.Call) -> tuple[str, str] | None:
    """``(confidence, description_suffix)`` when *rule* reports *node*."""
    if rule.kind == "sink":
        return confidence_for(classify(tree, node, _selected_data(rule.data, node)))
    if rule.kind == "call":
        return rule.confidence, ""
    found = next((kw for kw in node.keywords if kw.arg == rule.keyword), None)
    test, literal = rule.keyword_test
    if test == "required":
        hit = found is None
    elif test == "value":
        hit = found is not None and _literal_equals(found.value, literal)
    else:
        hit = found is None or not _literal_equals(found.value, literal)
    return (rule.confidence, "") if hit else None


def _selected_data(data: str | tuple[int | str, ...], node: ast.Call) -> list[ast.expr]:
    if data == "all":
        return _call_data(node)
    if data == "first":
        return node.args[:1]
    exprs: list[ast.expr] = []
    for selector in data:
        if isinstance(selector, int):
            if selector < len(node.args):
                exprs.append(node.args[selector])
        else:
            exprs.extend(kw.value for kw in node.keywords if kw.arg == selector)
    return exprs


def _literal_equals(expr: ast.expr, literal: Literal) -> bool:
    """``expr`` is the constant *literal*, with ``True``/``1`` and ``1``/``1.0``
    kept apart: a rule saying ``value = true`` means the keyword ``True``."""
    if not isinstance(expr, ast.Constant):
        return False
    value = expr.value
    if isinstance(literal, bool):
        return value is literal
    if isinstance(literal, int):
        return type(value) is int and value == literal
    return isinstance(value, str) and value == literal
