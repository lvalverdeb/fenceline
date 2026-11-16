# Declarative rules

fenceline's built-in checks are a fixed list. Rules let a team add its own
sinks, dangerous calls, bad keyword arguments and line patterns without
writing Python, in a TOML file both ports read identically:

```sh
fenceline --rules security/rules.toml
fenceline --rules security/rules.toml --disable check_pandas_pickle   # a rule standing in for a built-in
```

Rules also load from `[[rule]]` tables in the `--config` file. They run on
every scanned file after the built-in checks and go through the same
pipeline: `# nosec` / `# noqa` suppression, `--confidence-min`, the
test-code handling of `--include-tests`, `--baseline`, JSON and SARIF
output. The `[tool.fenceline.severity]` cap does not apply to them: a rule
states its own severity.

The format is specified here once; `fenceline` (Python) and `fenceline-rs`
implement it and share the conformance cases in `fixtures/rules/`.

## A rule

```toml
[[rule]]
id = "acme/mako-render"
cwe = "CWE-94"
name = "Mako template from data"
severity = "HIGH"
description = "A Mako Template built from a non-literal string renders attacker-controlled code."
kind = "sink"
callee = ["mako.template.Template"]
data = "first"
```

| Key | Required | Meaning |
| --- | --- | --- |
| `id` | yes | Unique over every loaded rule; used in error messages |
| `cwe` | yes | `CWE-` and digits; the finding's `cwe_id` |
| `name` | yes | The finding's `cwe_name` |
| `severity` | yes | `critical`, `high`, `medium`, `low` or `info` |
| `description` | yes | The finding's description; `sink` rules get the taint engine's note appended |
| `kind` | yes | `sink`, `call`, `keyword` or `pattern` |
| `confidence` | no | `high`, `medium` or `low`; default `high` for `call` and `keyword`, `medium` for `pattern`; not allowed on `sink` |
| `callee` | `sink`, `call`, `keyword` | Non-empty array of dotted names (below) |
| `data` | `sink` | `"all"` (default), `"first"`, or an array of argument positions and keyword names |
| `keyword` | `keyword` | The keyword argument's name |
| `value` / `unless` / `required` | `keyword` | Exactly one of them (below) |
| `regex` | `pattern` | The pattern (below) |

Loading is strict. An unknown key, a misspelled kind, a severity outside
the five levels, a `data` selector that is neither a position nor a name,
a regex that does not compile: each is an error that names the file and
the rule, and the scan does not start. A security policy with a silently
inert line is worse than one that refuses to load.

## Callees

`callee` names are matched against the call's dotted name after the file's
imports are resolved, the way the built-ins match:

- `import pickle as p; p.loads(x)` is `pickle.loads`.
- `from pandas import read_pickle as rp; rp(x)` is `pandas.read_pickle`.
- `import pandas as pd; pd.read_pickle(x)` is `pandas.read_pickle`.

A name matches as the whole dotted path or as its tail: `pickle.loads`
matches `pickle.loads` and `pkg.pickle.loads`, not `cloudpickle.loads`. A
single segment matches any call of that name: `mark_safe` matches
`mark_safe(x)` and `django.utils.safestring.mark_safe(x)`. Relative and
star imports are not resolved; a method on an object (`client.get(url)`)
is `client.get` and matches a one-segment `get` or `client.get`, nothing
longer.

The tail match is wider than some built-ins' exact match. In the ten-check
proof below, `builtins/requests-timeout` reaches a project's own
`weblate.utils.requests.request()` wrapper through the tail `requests.request`,
which `check_request_timeout` does not; three findings on one tree, all
call sites of a wrapper that sets no timeout.

## Kinds

### `sink`: the arguments are checked by the taint engine

```toml
kind = "sink"
callee = ["render"]
data = [1, "text"]
```

The callee matches and the selected arguments go through the same
three-way taint model the built-ins use (`taint.py`): request data or a
parameter some caller feeds request data gives HIGH confidence, a value of
unknown provenance gives MEDIUM, and a sink fed nothing but constants is
not reported. The engine's note about the input is appended to the
description. `data` selects what is checked:

- `"all"`: every positional argument and keyword value (the default).
- `"first"`: the first positional argument only.
- `[0, "text"]`: positional indexes (0-based) and keyword names; a
  selector that the call does not have is skipped.

### `call`: the call itself is the finding

```toml
kind = "call"
callee = ["tempfile.mktemp", "ssl.wrap_socket"]
```

Every matching call is reported at the rule's confidence (default HIGH).

### `keyword`: a keyword argument is, or is not, a literal

```toml
kind = "keyword"
callee = ["requests.get", "httpx.get"]
keyword = "verify"
value = false
```

The callee matches and the named keyword is tested, with exactly one of:

- `value = <literal>`: the keyword is present and is this literal.
- `unless = <literal>`: the keyword is missing or is anything but this
  literal (`torch.load(path)`, `torch.load(path, weights_only=False)`).
- `required = true`: the keyword is missing (`requests.get(url)` without
  `timeout=`).

A literal is a boolean, an integer or a string, compared as Python would
compare types: `value = true` means `True`, not `1`; `value = 1` means the
integer, not `True` or `1.0`. Floats are refused. A keyword given a name
(`cert_reqs=ssl.CERT_NONE`) or a container (`options={"verify_signature":
False}`) cannot be tested by this kind; a `pattern` rule can see the text.
A `**kwargs` splat is not looked into, as the built-ins do not.

### `pattern`: a regex over code lines

```toml
kind = "pattern"
regex = "\\.symlink_to\\(|os\\.symlink\\("
```

Runs line by line over the file as the text checks see it: comments and
string-only statements (docstrings) are blanked to spaces, columns kept,
and full-line comments are skipped. One finding per matching line, at the
rule's confidence (default MEDIUM: a line cannot rule out a mention inside
an inline string). The snippet is the masked line.

The regex is the dialect both ports share: no lookaround, no
backreferences (the Rust port's engine has neither, so both ports refuse
them at load). Alternation, classes, `\b`, `(?i)`, named groups and
repetition all work the same in both.

## What a rule cannot say

A rule that needs any of these is a Python plugin (`fenceline.checks`
entry point), not a rule:

- A condition on the statement around the call (`pattern-inside`,
  "only inside a route handler", "not inside `if __name__ == ...`").
- A comparison on a value (`key_size < 2048`), or a keyword whose value is
  a name, a dict or a list rather than a literal.
- A positional argument that must be a given literal (`jwt.encode(x, "")`).
- A sequence of statements (`set_password("") ... save()`).
- Dropping a finding on a second pattern in the same line.
- An autofix.

`docs/semgrep-coverage.md` applies these limits to every rule in Semgrep's
`p/python` ruleset.

## Conformance

`fixtures/rules/<set>/rules.toml` with that directory's `case_*.py` and
`case_*.expected.json` is run by both ports' fixture suites: `kinds`
exercises each kind and each keyword test; `builtins` re-expresses ten
built-in checks (`check_pandas_pickle`, `check_pandas_xml_xxe`,
`check_torch_load`, `check_numpy_load`, `check_request_timeout`,
`check_pickle`, `check_unsafe_markup`, `check_symlink`, `check_ldap`,
`check_ssh_host_key`) as fourteen rules. With those ten disabled and the
rules loaded, both ports produce the same findings as the plain run on the
vulnerable benchmark, the eight-app corpus and the 28 CVE trees, with the
one tail-match difference named above; `benchmark/README.md` records the
measurement.

Built-ins that the format cannot express, and why: `check_legacy_pycrypto`
(an import statement, not a call), `check_yaml_deserialize` (the safe
loader is a dotted name passed positionally or as `Loader=`),
`check_huggingface_unsafe_download` (one finding is suppressed when the
other fires on the same call), `check_tls_verify` and `check_debug_mode`
(keywords on any callee, plus assignments), `check_bind_all_interfaces` (a
string constant judged by its context), `check_null_byte` (a line that
must not also match a second regex), `check_weak_crypto` (one pattern uses
lookahead), `check_ssti` (reports only request-fed templates, dropping
the MEDIUM tier a `sink` rule would report).
