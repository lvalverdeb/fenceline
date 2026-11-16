# Benchmark: fenceline vs Bandit vs Semgrep

A labelled, reproducible comparison on four intentionally vulnerable Python
web applications, plus a second corpus of four ordinary, maintained
applications that measures the other side: how much of what the tools report
on code nobody made vulnerable is worth a reviewer's time (see
[Clean-code corpus](#clean-code-corpus)). The point is not a leaderboard but
a measurement that can be re-run after every change to see which gaps closed
and what it cost in false positives.

## Corpus

| App | Framework | Commit | Python lines |
| --- | --- | --- | --- |
| [pygoat](https://github.com/adeyosemanputra/pygoat) | Django + Flask labs | `2aa4cc1` | 8118 |
| [vulpy](https://github.com/fportantier/vulpy) | Flask | `5249cc8` | 2373 |
| [dvpwa](https://github.com/anxolerd/dvpwa) | aiohttp | `4a8f4a4` | 674 |
| [django.nV](https://github.com/nVisium/django.nV) | Django | `a48901f` | 2461 |

Tools: fenceline 1.9.0 for the current table, 1.8.0 for the
three-app tables and 1.6.0 for the baseline (this repository; the Python and
Rust ports give identical findings), Bandit 1.9.4 with default settings,
Semgrep 1.185.0 with the community `p/python` ruleset. django.nV was added
after 1.8.0, so every table before the four-app one covers three apps. Test files (`tests.py`, `test_*.py`, `tests/`),
migrations and non-Python files are excluded for every tool alike, so
fenceline's manifest checks and Bandit's test-code hits are both out.

## Ground truth

Every finding from the three tools was read in context and labelled true or
false by hand; the union of true findings is the ground truth. A finding is
*true* when the line is a genuine instance of the weakness its rule claims,
in application code, whether or not the app's authors planted it. It is
*false* when a reviewer would dismiss it: an `import` line reported for a
sink elsewhere, SQL built only from literal seed data, a `/tmp` read of a
public wordlist, a specific exception type deliberately passed, a
`"0.0.0.0"` entry in Django's `ALLOWED_HOSTS` reported as a bind address, a
dev utility's command-line URL reported as SSRF. When several tools point at
different lines of the same vulnerability (the taint source, the SQL string
and the `execute` call), `labels.json` merges them into one instance so no
tool is rewarded for reporting the same bug three times. The same merge
applies to one weakness repeated line after line in one function: the ten
raw `request.POST` reads after `form.is_valid()` in a django.nV view are one
instance.

Two consequences to keep in mind. A weakness none of the three tools reports
is invisible (the path traversal at `ssrf_lab/app.py:21` is one such). And
because the apps are built to be vulnerable, most findings are true, so the
benchmark is better at exposing recall gaps than at estimating a tool's
false-positive rate on ordinary code.

## Results

### 1.10.0 (2026-11-14)

The clean-corpus work (below) changed twenty-odd check shapes. On the
vulnerable apps the effect is three false positives fewer and no recall
change, which is what a regression gate is supposed to say:

| Tool | Findings | True | False | Precision | Recall |
|---|---|---|---|---|---|
| fenceline | 210 | 201 | 9 | 96% | 190/204 (93%) |
| fenceline (--confidence-min high) | 152 | 149 | 3 | 98% | 139/204 (68%) |
| Bandit | 179 | 159 | 20 | 89% | 156/204 (76%) |
| Semgrep | 91 | 90 | 1 | 99% | 68/204 (33%) |

Gone: pygoat's `ALLOWED_HOSTS` entry reported as a bind address (the
`0.0.0.0` check now skips lists of nothing but strings), a dvpwa log
message about CSRF tokens reported as a secret leak (secret words now match
whole words), and a `url_for()` redirect in pygoat's template lab (route
builders are clean). The five `CWE-770` reads of program-chosen files that
were already excluded by rule are no longer reported either; the one
labelled true (a user-controlled path read whole) stays at HIGH. Every
weak-hash and weak-random instance keeps HIGH confidence under the new
credential-context rule. The nine remaining false positives are the seven
`CWE-391` specific-exception handlers labelled intentional and two
CLI-utility SSRFs.

### 1.9.0: Django function views (2026-11-14)

In a module that imports a web framework, a function whose first parameter
is `request` is now a handler, so its other parameters are URL captures and
count as web input (`def upload(request, project_id)` in django.nV; the same
shape serves Pyramid and aiohttp function views). Alongside it, a Django ORM
lookup (`Model.objects.get(pk=project_id)` and the rest of a manager chain)
now yields stored data at INTERNAL whatever selected the row, where before
the row inherited the taint of its lookup key. The two rules cancel on
django.nV: the view rule alone would have raised the two remaining false
positives (`redirect(user.userprofile.image)` and the whole-file read of a
stored upload) to HIGH, because both read a row selected by a URL capture,
and the ORM rule keeps them at MEDIUM. No finding changes on the four apps
or on the library corpus; the table above stands. The gain is in the model,
not the numbers: a URL capture that reaches a sink directly is now HIGH.

### In 1.9.0: check-shape fixes (2026-11-14)

The two check shapes django.nV exposed are fixed. `check_open_redirect` no
longer reports a target that starts with a literal absolute path
(`'/taskManager/' + project_id`, `f"/account/{target}"`, `"/p/%s" % x`,
`"/p/{}".format(x)`): such a target can only land on the same site. A bare
`"/"` or `"\"` prefix still counts, because browsers read `///host` and
`/\host` as scheme-relative URLs. `check_log_secrets` no longer treats
`django.contrib.messages` as a logger: its `warning`/`error` queue a flash
message for the next response, not a log line. Fifteen findings disappear,
every one previously labelled false (nine redirects and five flash messages
in django.nV, one flash message in pygoat). Nothing else changes on the four
apps or on the library corpus, and the two ports still agree finding for
finding.

| Tool | Findings | True | False | Precision | Recall |
|---|---|---|---|---|---|
| fenceline | 218 | 201 | 17 | 92% | 190/204 (93%) |
| fenceline (--confidence-min high) | 154 | 149 | 5 | 97% | 139/204 (68%) |
| Bandit | 179 | 159 | 20 | 89% | 156/204 (76%) |
| Semgrep | 91 | 90 | 1 | 99% | 68/204 (33%) |

Two django.nV false positives remain: `redirect(user.userprofile.image)`,
a stored path fenceline cannot know is under `/static/`, and the whole-file
read of a stored upload. Both are MEDIUM.

### In 1.9.0: four apps (2026-11-13)

django.nV joins the corpus. It was chosen because its request data crosses a
file boundary before reaching a sink (`views.upload` passes the POSTed name
and file to `misc.store_uploaded_file`, which runs `os.system`), which the
three earlier apps barely do. Two other candidates were rejected: vulnpy
dispatches every vulnerable function through `importlib` and `getattr`, so
no static analysis can follow it, and VAmPI routes through a connexion
OpenAPI spec and is 520 lines.

| Tool | Findings | True | False | Precision | Recall |
|---|---|---|---|---|---|
| fenceline | 233 | 201 | 32 | 86% | 190/204 (93%) |
| fenceline (--confidence-min high) | 154 | 149 | 5 | 97% | 139/204 (68%) |
| Bandit | 179 | 159 | 20 | 89% | 156/204 (76%) |
| Semgrep | 91 | 90 | 1 | 99% | 68/204 (33%) |

The new app adds six instances: a shell command, a hardcoded `SECRET_KEY`, a
SQL insert, an open redirect from a query parameter, and two views that read
raw `request.POST` after validating a form (Semgrep's
`django-using-request-post-after-is-valid`, a new category only Semgrep
has). fenceline finds the first four, all at HIGH; the shell command is HIGH
because the cross-file pass carries the view's request data into the helper,
which is the one place in the corpus where that pass changes a verdict on
its own.

It also adds sixteen fenceline false positives, which is what drops
precision from 92% to 86%, and they are check-shaped, not taint-shaped:

- Nine `redirect('/taskManager/' + project_id + ...)` calls reported as open
  redirects. A target that starts with a literal path can only ever be a
  same-site redirect. One more is `redirect(user.userprofile.image)`, a
  stored upload path under `/static/`.
- Five `messages.warning(request, 'Invalid password reset token')`-style
  Django flash messages reported as logging secrets. A flash message is not
  a log sink. (The same shape is already labelled false once in pygoat.)
- One whole-file read of a stored upload, which the CWE-770 rule already
  treats as noise.

Bandit adds two false positives of its own (`reset_token = ''` reported as a
hardcoded password). The HIGH-only numbers are unchanged in substance because
all sixteen new false positives are MEDIUM.

What no tool reports, and so stays outside the ground truth: the path
traversal in `store_uploaded_file` (the upload's title becomes part of the
destination path), the IDOR on every `pk=` lookup, the CSRF-exempt profile
update, and the reflected XSS the app documents.

### In 1.9.0: request-name rule (2026-11-13)

The name `request` is now web input only inside a handler or in a module
that imports a web framework somewhere; elsewhere it resolves like any other
name. No change on these three apps: every `request` here sits in a Flask,
Django or aiohttp module. On the library corpus five findings moved from
HIGH to MEDIUM: the two CRLF findings on botocore's chunked-encoding writer
that the rule was meant to fix (the source was an outbound `AWSRequest`
parameter), and three INFO-severity unbounded reads inside aiohttp's own
websocket implementation, where `request` is a `BaseRequest` parameter but
the framework imports itself relatively, so the module is not recognised as
web-facing. The latter is a cost of the rule when scanning a framework's
internals rather than an application built on it.

### 1.8.0 (2026-11-13)

Cross-file parameter taint: a parameter that a caller anywhere in the
package feeds request data is HIGH inside the callee. Finding counts and
the default-settings table are unchanged; the five SQL injections that sat
at MEDIUM because the request value arrived from another file (vulpy's
`libuser.py` from `mod_user.py`/`libapi.py`, dvpwa's `dao/student.py` from
`views.py`) are now HIGH.

| fenceline (--confidence-min high) | 150 | 145 | 5 | 97% | 135/198 (68%) |

Phase B4 (source and sink vocabulary: Django class-based view URL captures
and `raw()`/`RawSQL`, Lambda `event` handlers, framework redirect classes,
`send_file`/`FileResponse`, `from_string`, and a CWE-79 check for
`mark_safe`/`Markup`) changed nothing on these three apps: pygoat serves
files through `send_from_directory`, which safe-joins and is deliberately
not a sink.

Phase B3 (`self` field flow) also changed nothing here; on the reference
library corpus it moved six findings from MEDIUM to HIGH, four defensible
(websocket readers built from the request, a token file whose path comes
from the environment) and two not: CRLF findings on botocore's
chunked-encoding writer, where the source is botocore's outbound
`AWSRequest` matching fenceline's `request` root.

Phase B2 (guards as sanitizers: allow-list membership, `assert`, anchored
regex and `isdigit()`-style checks that exit on failure) changed nothing on
either corpus: no sink in these apps or libraries sits behind such a guard.
It is covered by a six-case fixture instead.

What still separates HIGH-only recall from the default: 23 hardcoded-secret
findings that are MEDIUM by design (placeholder-shaped or identifier-like
values), the MEDIUM `read()` and SSRF findings in command-line utilities,
and the handful of weaknesses no tool finds. Those are not taint depth.

### Phase B0 (2026-11-13, in 1.8.0)

One change over 1.7.0: the SQL injection checks look through a local
variable to the query assigned to it (`q = "..." % x; execute(q)`), which
found dvpwa's `dao/student.py:45` that no tool had reported, so the ground
truth grew by one instance.

| Tool | Findings | True | False | Precision | Recall |
|---|---|---|---|---|---|
| fenceline | 213 | 197 | 16 | 92% | 186/198 (94%) |
| Bandit | 174 | 156 | 18 | 90% | 153/198 (77%) |
| Semgrep | 77 | 76 | 1 | 99% | 64/198 (32%) |

| fenceline (--confidence-min high) | 146 | 141 | 5 | 97% | 131/198 (66%) |

### 1.7.0 (2026-11-13)

Default settings for every tool:

| Tool | Findings | True | False | Precision | Recall |
|---|---|---|---|---|---|
| fenceline | 211 | 195 | 16 | 92% | 184/197 (93%) |
| Bandit | 174 | 156 | 18 | 90% | 153/197 (78%) |
| Semgrep | 77 | 76 | 1 | 99% | 64/197 (32%) |

fenceline with `--confidence-min high`: 145 findings, 140 true, 5 false (97%
precision, 66% recall).

| Category | Instances | fenceline | Bandit | Semgrep |
|---|---|---|---|---|
| secret | 64 | 61 | 52 | 2 |
| debug | 25 | 25 | 23 | 23 |
| bind-all | 23 | 23 | 23 | 23 |
| tmpfile | 21 | 21 | 21 | 0 |
| silent-except | 18 | 18 | 5 | 0 |
| no-timeout | 7 | 7 | 7 | 0 |
| sqli | 6 | 4 | 6 | 1 |
| weak-random | 6 | 6 | 6 | 0 |
| plaintext-http | 4 | 0 | 0 | 4 |
| weak-hash | 4 | 4 | 4 | 4 |
| deserialization | 3 | 3 | 3 | 1 |
| code-injection | 2 | 2 | 1 | 1 |
| log-injection | 2 | 2 | 0 | 0 |
| open-redirect | 2 | 2 | 0 | 0 |
| timing | 2 | 2 | 0 | 0 |
| weak-crypto-mode | 2 | 0 | 0 | 2 |
| cmdi | 1 | 1 | 1 | 1 |
| log-secret | 1 | 1 | 0 | 0 |
| nan-injection | 1 | 0 | 0 | 1 |
| ssrf | 1 | 1 | 0 | 1 |
| unbounded-read | 1 | 1 | 0 | 0 |
| xxe | 1 | 0 | 1 | 0 |

Remaining fenceline false positives: CWE-770 4 (all MEDIUM confidence, INFO
severity: reads of files whose handle came from a parameter or a directory
listing), CWE-918 3 (command-line URLs in dev utilities), and one each of
CWE-532/611/117/601/1327/78/377 plus one CWE-611 pair on import lines.

What changed between the two tables, in order of effect:

1. Hardcoded credentials rebuilt on the AST (2 -> 61 of 64): every binding
   shape, placeholder and identifier-like values at MEDIUM confidence, a
   value-shaped companion check for JWT/AWS/Stripe/GitHub/Slack/Google keys
   and PEM blocks.
2. `check_tempfile` now also reports literal paths under `/tmp`, `/var/tmp`
   and `/dev/shm` (0 -> 21 of 21).
3. `random.choices`, `getrandbits`, `triangular` and `randbytes` joined the
   weak-randomness list (1 -> 6 of 6).
4. Unbounded `read()` consults the receiver's taint: a file the program
   opened at its own constant path is not reported (14 -> 4 false positives).
5. `except ...: pass` is reported only for catch-all handlers; a specific
   type with `pass` is deliberate (7 -> 0 false positives, and 93 -> 8
   findings on the reference library corpus).

### Baseline at 1.6.0 (2026-11-13)

Default settings for every tool:

| Tool | Findings | True | False | Precision | Recall |
|---|---|---|---|---|---|
| fenceline | 139 | 106 | 33 | 76% | 99/187 (53%) |
| Bandit | 174 | 156 | 18 | 90% | 153/187 (82%) |
| Semgrep | 77 | 76 | 1 | 99% | 64/187 (34%) |

fenceline with `--confidence-min high` scores 97 findings, 72 true, 25 false
(74% precision, 35% recall). The drop in recall is mostly the `debug=True`
check, which is rated LOW confidence by design and finds all 25 debug-mode
instances.

Per category, instances in the ground truth and how many each tool found:

| Category | Instances | fenceline | Bandit | Semgrep |
|---|---|---|---|---|
| secret | 54 | 2 | 52 | 2 |
| debug | 25 | 25 | 23 | 23 |
| bind-all | 23 | 23 | 23 | 23 |
| tmpfile | 21 | 0 | 21 | 0 |
| silent-except | 18 | 18 | 5 | 0 |
| no-timeout | 7 | 7 | 7 | 0 |
| sqli | 6 | 4 | 6 | 1 |
| weak-random | 6 | 1 | 6 | 0 |
| plaintext-http | 4 | 0 | 0 | 4 |
| weak-hash | 4 | 4 | 4 | 4 |
| deserialization | 3 | 3 | 3 | 1 |
| timing | 2 | 2 | 0 | 0 |
| open-redirect | 2 | 2 | 0 | 0 |
| weak-crypto-mode | 2 | 0 | 0 | 2 |
| log-injection | 2 | 2 | 0 | 0 |
| code-injection | 2 | 2 | 1 | 1 |
| cmdi | 1 | 1 | 1 | 1 |
| xxe | 1 | 0 | 1 | 0 |
| unbounded-read | 1 | 1 | 0 | 0 |
| ssrf | 1 | 1 | 0 | 1 |
| nan-injection | 1 | 0 | 0 | 1 |
| log-secret | 1 | 1 | 0 | 0 |

False positives by rule: fenceline CWE-770 14, CWE-391 7, CWE-918 3, CWE-532
2, CWE-611 2, one each of CWE-117/798/601/1327/78; Bandit B603 4, B404 3,
B403 2, B105 2, B406 2, B608 2, one each of B409/B104/B108; Semgrep one
(`dangerous-subprocess-use-tainted-env-args` on a CLI tool).

## Clean-code corpus

`clean/` holds the measurement the vulnerable apps cannot give: precision on
ordinary code. Five maintained applications, pinned and scanned at their
application package; every finding of all three tools in scope adjudicated
by hand. The first four were chosen one per framework; the fifth, pretalx,
was the held-out application of the first tuning round and joined the
corpus once the checks had been tuned against it (D7 in `ROADMAP.md`).

| App | Framework | Commit | Scanned | Lines in scope |
|---|---|---|---|---|
| [healthchecks](https://github.com/healthchecks/healthchecks) | Django | `cb5c976` | `hc/` | 16884 |
| [dispatch](https://github.com/Netflix/dispatch) | FastAPI | `dd2837e` | `src/dispatch/` | 62177 |
| [flaskbb](https://github.com/flaskbb/flaskbb) | Flask | `1028f17` | `flaskbb/` | 23731 |
| [home-assistant/core](https://github.com/home-assistant/core) | aiohttp | `e68768b` | `homeassistant/auth/`, `homeassistant/components/http/` (sparse checkout) | 25967 |
| [pretalx](https://github.com/pretalx/pretalx) | Django | `1510dea` | `src/pretalx/` | 64074 |

Tools: fenceline 1.9.0, Bandit 1.9.4, Semgrep 1.185.0 `p/python`, as in the
main benchmark. The universe is the same too: findings on `.py` files outside
tests and migrations (alembic `revisions/` included), so manifest findings
and fenceline's test-code suppression are out of the picture for every tool.
Home Assistant is scanned at the two packages that face requests; the
sparse checkout also brings in the top-level modules they import, which are
scanned and counted.

### Labels

Each finding carries one of three labels and a one-line reason, in
`clean/labels.json`:

- **true**: a genuine instance a maintainer would fix.
- **false**: a reviewer would dismiss it.
- **by design**: a correct detection of deliberate code. A home server
  binding `0.0.0.0` by default, an integration whose feature is running the
  command the project owner configured, a placeholder token in a test
  fixture. Ordinary code has many of these, and lumping them with either of
  the other labels misstates the tool.

Strict precision counts only *true*; lenient precision also counts *by
design*. Recall is not measured: nobody knows how many weaknesses these
applications hold. `clean/score.py` refuses to run if any in-scope finding
has no verdict, so the labels are complete by construction.

### Held-out application: Tandoor Recipes (2026-11-16, at 1.11.0)

The second blind measurement, taken after the pretalx shapes below were
fixed and pretalx had joined the corpus. The application was chosen before
any check was touched: [Tandoor Recipes](https://github.com/TandoorRecipes/recipes)
(Django, `4fdc854`, `cookbook/` + `recipes/`, 20170 lines in scope), a
maintained recipe manager by different authors in a different style. Labels
are in `heldout-labels.json`, the runner is `heldout.sh`.

| Tool | Findings | True | By design | False | Precision (strict) | Precision (lenient) | Per 1000 lines |
|---|---|---|---|---|---|---|---|
| fenceline | 141 | 4 | 87 | 50 | 3% | 65% | 7.0 |
| fenceline (--confidence-min high) | 110 | 4 | 87 | 19 | 4% | 83% | 5.5 |
| Bandit | 41 | 2 | 26 | 13 | 5% | 68% | 2.0 |
| Semgrep | 4 | 0 | 0 | 4 | 0% | 0% | 0.2 |

**What it says.** The precision gates transfer this time and the density
gate does not. Lenient precision is 65% at default and 83% at HIGH, against
the 35% and 70% bars; density is 7.0 findings per 1,000 lines against a
bar of 1.0. Both facts have one cause: Tandoor is written in a
try/`except Exception:`-fallback style, and 94 of the 141 findings are the
two exception-handler checks, `CWE-778` (65) and `CWE-391` (29), firing on
those handlers. 87 of them are deliberate fallbacks (a scraper field that
is missing, a permission check that fails closed, an optional image), so
they count towards lenient precision and against density at the same time.
The four true findings are two sites reported by both checks: importers
that drop an ingredient or a step from the imported recipe with no entry
in the import log. Bandit's two true findings are the same two sites.

**The false positives, 50.** `CWE-200` 22: `traceback.print_exc()` in views
and helpers, where the trace goes to the server's stderr and never to a
user; a text check cannot tell. `CWE-601` 7: the login URL built as
`reverse('account_login') + '?next=' + request.path`, where the leading
operand is a route builder rather than a literal. `CWE-611` 5: lxml parsers
constructed with `resolve_entities=False, no_network=True, load_dtd=False`,
and an `Element` import. `CWE-798` 5: rate-limit specifications and URL
paths under keys like `reset_password`. The rest are the known tails.

**Observations, recorded and not fixed** (the blind rule): `CWE-391` and
`CWE-778` report the same `except: pass` line twice, so a team sees two
findings per handler; a handler that returns or assigns a fallback value
is rated the same as one that passes; `CWE-200` cannot see whether a
traceback reaches a response; `_is_same_site_path` wants a literal where a
`reverse()` call leads the concatenation; defused lxml parser options are
not recognised; `*_password` keys whose values are paths or specifications
are still reported. `ROADMAP.md`, D8.

**Port divergence.** Seven findings: `cookbook/serializer.py` and
`cookbook/integration/mealie1.py` use PEP 701 f-strings (the same quote
nested inside the expression), which rustpython-parser does not accept;
the Rust port reports both files as unparsable and skips their AST checks.
Same class as the PEP 695 file in Home Assistant.

### 1.11.0 (2026-11-16): the pretalx shapes, five apps

The D7 round: the three shapes pretalx exposed, plus two found behind them
while fixing (ORM chains with an intermediate call, and concatenations led
by a URL property or the request's own path), in both ports with parity.
Then pretalx joined the corpus and the next blind application was measured
(above).

The corpus is now five apps and 192,833 lines; the numbers are not
comparable line for line with the four-app tables below, so both views are
given.

Five apps:

| Tool | Findings | True | By design | False | Precision (strict) | Precision (lenient) | Per 1000 lines |
|---|---|---|---|---|---|---|---|
| fenceline | 195 | 23 | 23 | 149 | 12% | 24% | 1.0 |
| fenceline (--confidence-min high) | 81 | 19 | 15 | 47 | 23% | 42% | 0.4 |
| Bandit | 338 | 12 | 11 | 315 | 4% | 7% | 1.8 |
| Semgrep | 35 | 0 | 1 | 34 | 0% | 3% | 0.2 |

fenceline confidence calibration:

| Confidence | Findings | True | By design | False | Share true |
|---|---|---|---|---|---|
| HIGH | 81 | 19 | 15 | 47 | 23% |
| MEDIUM | 112 | 4 | 8 | 100 | 4% |
| LOW | 2 | 0 | 0 | 2 | 0% |

fenceline per app:

| App | Findings | True | By design | False | Per 1000 lines |
|---|---|---|---|---|---|
| healthchecks | 15 | 0 | 3 | 12 | 0.9 |
| dispatch | 58 | 19 | 8 | 31 | 0.9 |
| flaskbb | 22 | 4 | 8 | 10 | 0.9 |
| hacore | 13 | 0 | 2 | 11 | 0.5 |
| pretalx | 87 | 0 | 2 | 85 | 1.4 |

The original four apps, for comparison with the 1.10.0 table: 108 findings,
23 true, 21 by design, 64 false, 21% strict and 41% lenient at 0.8 per
1,000 lines (1.10.0: 116, 20%, 38%, 0.9); at HIGH 45 findings, 19 / 13 /
13, 42% and 71% at 0.3, unchanged. pretalx itself went from 224 findings
to 87 (0 true, 2 by design, 85 false; 3.5 to 1.4 per 1,000 lines; at HIGH
86 to 36).

**What changed.** Attribute chains under `request` whose first attribute
is not a data attribute of a recognised framework (`request.user.email`,
`request.session.get(...)`, `request.event.urls.base`) are server-side
state and classify INTERNAL. Class bodies are scopes, so a literal there
is CLEAN and `placeholder = mark_safe("&mdash;")` no longer reports.
Redirects to a named URL in an urlman-style namespace (`event.urls.base`,
`obj.orga_urls.x.full()`) are dropped whatever the object's origin; a URL
property or getter (`topic.url`, `self.get_success_url()`) is dropped when
the destination is INTERNAL, which also removes the seven flaskbb model-URL
redirects the 1.10.0 notes called type-shaped. Both rules and the
request's-own-path rule see through a concatenation.
`url_has_allowed_host_and_scheme(x, ...)` is a guard on `x`. The NUL-byte
regex matched any octal escape starting with `\0`, so every `\033[33m`
colour code reported; it matches NUL only now, and a NUL in a membership
test or at the start of a regex character class is skipped (27 findings
gone from the library corpus too, all of that shape). ORM lookups through
an intermediate call (`Model.objects.select_related("e").get(code=code)`)
are recognised. The vulnerable benchmark is unchanged: 210 findings, 96%
precision, recall 190/204, 98% at HIGH. Released as 1.11.0 from the tree
these numbers were measured on.

**Where the remaining noise is.** 149 false positives on five apps, by
check: `CWE-601` 37 (26 at HIGH; in pretalx these are now `get_next_url(request)`
results the check cannot see are validated inside the helper, `reverse()`
URLs with a query string appended, and middleware redirects through
`urljoin(settings.SITE_URL, ...)`), `CWE-79` 31 (28 in pretalx, each with
the maintainers' `S308` note: bleach-sanitised markdown, escaped fragments,
rendered templates; the engine would need to know the renderer sanitises),
`CWE-117` 23 (dispatch, unchanged), `CWE-338` 15, `CWE-328` 10, `CWE-918`
8, `CWE-22` 8, `CWE-73` 5, `CWE-798` 3, `CWE-770` 2, and one each of seven
others.

**Port divergence.** The PEP 695 file in Home Assistant, as before: 178
against 177. Vulnerable benchmark and library corpus identical.

### Held-out application: pretalx (2026-11-14, at 1.10.0; in the corpus since 2026-11-16)

The check this corpus exists to pass. After the C2 work was frozen and
released, one more application of a framework already in the corpus was
scanned once and adjudicated blind: [pretalx](https://github.com/pretalx/pretalx)
(Django, `1510dea`, `src/pretalx/`, 64074 lines in scope), a maintained
conference-management system. Labels are in `heldout-labels.json`, the
runner is `heldout.sh`; the three tools ran as for the corpus.

| Tool | Findings | True | By design | False | Precision (strict) | Precision (lenient) | Per 1000 lines |
|---|---|---|---|---|---|---|---|
| fenceline | 224 | 0 | 2 | 222 | 0% | 1% | 3.5 |
| fenceline (--confidence-min high) | 86 | 0 | 2 | 84 | 0% | 2% | 1.3 |
| Bandit | 116 | 0 | 0 | 116 | 0% | 0% | 1.8 |
| Semgrep | 18 | 0 | 0 | 18 | 0% | 0% | 0.3 |

**What it says.** The tuned numbers do not transfer. Nobody finds anything
true in pretalx, which is plausible for a project that carries a
maintainers' note on every suppressed Bandit line; but fenceline reports
four times the density it reaches on the tuning set, and 143 of the 224
findings are one shape the tuning set did not contain. The 1.10.0 corpus
numbers above describe the four apps the checks were tuned on; this table
is what a team should expect today.

**The three shapes, by false positives.**

- `CWE-601`, 143. pretalx builds every URL through
  [urlman](https://github.com/andrewgodwin/urlman): `event.urls.base`,
  `submission.orga_urls.reviews`. Reached through `request.event` the chain
  is SOURCE (70 at HIGH); through `self.object` it is INTERNAL (MEDIUM).
  Another 40-odd are Django's own idiom, `redirect(self.get_success_url())`,
  where the method returns a `reverse()` result or a `?next=` validated by
  `url_has_allowed_host_and_scheme()`. None is a destination the request
  chooses. The two signed safe-redirect sites are the by-design ones.
- `CWE-79`, 35. Twenty-six are MEDIUM `mark_safe()` of static markup
  (`placeholder = mark_safe("&mdash;")`) at class level: the taint engine
  has no scope for a class body, so a literal there classifies as INTERNAL
  where the same literal at module level is CLEAN and dropped. The rest are
  bleach-sanitised markdown, escaped fragments and urlman URLs, each
  carrying the maintainers' `S308` note saying so.
- `CWE-158`, 15. ANSI colour escapes (`\033[33m`) in a terminal-rendered
  schedule, plus the NUL-byte validation and control-character sanitiser
  shapes already seen on the corpus.

The remainder (31) are the known tails: `random` for test fixtures, MD5 for
cache busting, `FileResponse` of a model's file, configuration names.

**Consequence.** C2's gates were met on the tuning set and are not met
here. The three shapes are check- and engine-shaped, not type-shaped, so
they are fixable; but once fixed against, pretalx is part of the tuning
set, and the held-out measurement has to be repeated on a further
application. See `ROADMAP.md`, D7.

### 1.10.0 (2026-11-14)

Two rounds of check-shape fixes against the per-check table below, each
validated on all three corpora with Rust parity (the work list and the
reasoning are in `ROADMAP.md`, the shapes in the commit messages):

| Tool | Findings | True | By design | False | Precision (strict) | Precision (lenient) | Per 1000 lines |
|---|---|---|---|---|---|---|---|
| fenceline | 116 | 23 | 21 | 72 | 20% | 38% | 0.9 |
| fenceline (--confidence-min high) | 45 | 19 | 13 | 13 | 42% | 71% | 0.3 |
| Bandit | 222 | 12 | 11 | 199 | 5% | 10% | 1.7 |
| Semgrep | 17 | 0 | 1 | 16 | 0% | 6% | 0.1 |

fenceline confidence calibration:

| Confidence | Findings | True | By design | False | Share true |
|---|---|---|---|---|---|
| HIGH | 45 | 19 | 13 | 13 | 42% |
| MEDIUM | 69 | 4 | 8 | 57 | 6% |
| LOW | 2 | 0 | 0 | 2 | 0% |

fenceline per app:

| App | Findings | True | By design | False | Per 1000 lines |
|---|---|---|---|---|---|
| healthchecks | 16 | 0 | 3 | 13 | 0.9 |
| dispatch | 58 | 19 | 8 | 31 | 0.9 |
| flaskbb | 29 | 4 | 8 | 17 | 1.2 |
| hacore | 13 | 0 | 2 | 11 | 0.5 |

**What changed.** Findings went from 637 to 116 with one true finding
gained (flaskbb's `SECRET_KEY = "secret key"`, the recall miss C1 named)
and none lost. Confidence now means something here: a HIGH finding is true
42% of the time and true-or-deliberate 71%, a MEDIUM one 6%. A team
turning on `--confidence-min high` sees one alert per 3,000 lines, and
seven in ten of those are real or intentional.

**Where the remaining noise is.** 72 false positives, by check:
`CWE-117` 23, `CWE-601` 15, `CWE-918` 8, `CWE-328` 6, `CWE-73` 4,
`CWE-79` 3, `CWE-22` 3, and eleven more across nine checks. Only 13 are
at HIGH: five `CWE-117` (request fields logged directly in dispatch's
MFA views, where the field is a typed integer), four `CWE-601` (redirects
to a `reverse()` path with the Referer's query string appended, which the
check cannot see is same-site, and one to a validated URL), and one each
of `CWE-502`, `CWE-770`, `CWE-22` and `CWE-79`. The 23 `CWE-117` false
positives are now MEDIUM: all are f-strings over fields of a Pydantic
request model reaching a logger through a service function, where the
engine sees request data two calls away but not that the field is an
integer id. The 15 `CWE-601` are flaskbb redirects to model URL
properties (`topic.url`, built with `url_for`) and redirects through a
validating helper; the eight `CWE-918` are administrator-configured
integration URLs in dispatch plugins. None of these three has a
check-shape fix left; they are what inter-procedural type knowledge would
buy.

**Port divergence.** One finding: the `CWE-338` in `config_entries.py`,
which uses PEP 695 type parameters that rustpython-parser does not accept.
The `CWE-778` text fallback that produced the other six is gone.

### 1.9.0 (2026-11-14)

| Tool | Findings | True | By design | False | Precision (strict) | Precision (lenient) | Per 1000 lines |
|---|---|---|---|---|---|---|---|
| fenceline | 637 | 22 | 21 | 594 | 3% | 7% | 4.9 |
| fenceline (--confidence-min high) | 528 | 19 | 15 | 494 | 4% | 6% | 4.1 |
| Bandit | 222 | 12 | 11 | 199 | 5% | 10% | 1.7 |
| Semgrep | 17 | 0 | 1 | 16 | 0% | 6% | 0.1 |

fenceline confidence calibration:

| Confidence | Findings | True | By design | False | Share true |
|---|---|---|---|---|---|
| HIGH | 528 | 19 | 15 | 494 | 4% |
| MEDIUM | 91 | 3 | 6 | 82 | 3% |
| LOW | 18 | 0 | 0 | 18 | 0% |

fenceline per app:

| App | Findings | True | By design | False | Per 1000 lines |
|---|---|---|---|---|---|
| healthchecks | 93 | 0 | 3 | 90 | 5.5 |
| dispatch | 440 | 19 | 8 | 413 | 7.1 |
| flaskbb | 68 | 3 | 8 | 57 | 2.9 |
| hacore | 36 | 0 | 2 | 34 | 1.4 |

**What the number means.** On the vulnerable apps fenceline is 92% precise;
on ordinary code it is 3%, and `--confidence-min high` does not help because
the noise is reported at HIGH. Confidence is not calibrated on this corpus:
HIGH, MEDIUM and LOW findings are true at nearly the same rate. Bandit is
5%, and Semgrep's community Python rules report almost nothing and nothing
true. A team turning any of the three on without a baseline file sees
roughly one alert per 200 to 600 lines, of which one in twenty or thirty
deserves a look.

**Where fenceline's noise comes from.** Two check shapes account for 477 of
the 594 false positives:

- `CWE-117` log injection, 394. The check reports every f-string with an
  interpolation passed to a logger, with no regard to what is interpolated.
  Running the taint classifier over the interpolated values finds 11 of the
  400 reach request data; the other 389 are identifiers, counts, exceptions
  and configuration. Five of the eleven are labelled true (raw headers and
  a request body logged in dispatch's auth code).
- `CWE-601` open redirect, 83. Sixty-odd are Django's `redirect("hc-channels",
  project.code)`: a URL pattern *name* with URL parameters, resolved
  server-side, not a destination. The rest are `url_for()` results,
  `reverse()` results, model URL properties and targets validated by a
  helper the check cannot see.

The remaining 117 are a long tail of shapes, each small: configuration key
names reported as hardcoded credentials (`CONF_PASSWORD = "password"`, 17),
literal comparisons of provider names and status strings reported as timing
attacks (16), notification templates rendered from the module's own
constants reported as SSTI (14), SQLAlchemy `session.query()` reported as
pandas `DataFrame.query()` (8), administrator-configured integration URLs
reported as SSRF (8), and `except Exception:` handlers that do log reported
as silent (7, see below).

**What fenceline found that the others did not.** Of the 22 true findings:
11 outbound HTTP calls without a timeout (Bandit finds 8), 5 raw request
headers or bodies written to logs, a redirect to the `Referer` header in
flaskbb, an SSRF in dispatch's AWS ALB authentication plugin where the
region and key id from an unverified JWT header are spliced into a URL, a
default CSRF secret in flaskbb's base config, a login handler that swallows
every exception, a Zoom meeting password drawn from `random`, and
user-authored markdown marked safe in dispatch's email filters. Bandit's
one true finding fenceline missed is flaskbb's `SECRET_KEY = "secret key"`
default, which the secrets check discards as placeholder-shaped.

**Port divergence.** The Rust port reports 701 findings here against the
Python port's 708. Four Home Assistant files use Python 3.14's
unparenthesised `except A, B:` syntax and fail to parse under CPython 3.13
and rustpython-parser alike; on those the Python port's `CWE-778` check
falls back to a line scan that cannot see the handler body and reports six
handlers that do log, while the Rust port has no fallback and reports
nothing. Three more files use PEP 695 type parameters, which CPython parses
and rustpython-parser does not; one `CWE-338` finding in `config_entries.py`
is lost there. The first is a divergence to resolve in C2 (the fallback
produced six false positives and no true ones); the second is a parser gap
to record.

```bash
benchmark/clean/run.sh                         # default settings
benchmark/clean/run.sh --confidence-min high --fps
BENCH_DIR=/tmp/fl-clean benchmark/clean/run.sh # keep the clones and raw JSON
```

## What the baseline said

Three gaps accounted for almost all of fenceline's missed recall at 1.6.0,
and none of them was a taint problem (all three are closed above):

1. **Hardcoded secrets** (2 of 54). The check matches `UPPER_SNAKE = "..."`
   assignments; these apps write `app.secret_key = "..."`,
   `app.config["SECRET_KEY"] = "..."`, `"password": "..."` dictionary
   entries and `os.environ["JWT_SECRET"] = "..."`. Bandit's B105 catches
   all of those shapes.
2. **Hardcoded `/tmp` paths** (0 of 21). No check exists; Bandit's B108.
3. **Weak randomness** (1 of 6). The check only fires on names like `otp`;
   `random.choices(...)` used to mint tickets and API keys is missed.

The false-positive side is dominated by one check: CWE-770 (unbounded
`read()`) fires on every `f.read()` of a local key file or template, 14
times, and at HIGH confidence. CWE-391 fires on `except SpecificError: pass`
seven times, where the specific type says the silence is deliberate.

Where fenceline leads: silent exception handling (18 vs 5 vs 0), request
timeouts, open redirects, timing-unsafe comparisons and log injection, none
of which the Semgrep community ruleset covers here.

## Running it

```bash
benchmark/run.sh                       # default settings, fresh temp dir
benchmark/run.sh --confidence-min high --fps
BENCH_DIR=/tmp/fl-bench benchmark/run.sh          # keep the clones and raw JSON
FENCELINE_CMD=path/to/fenceline-rs/target/release/fenceline benchmark/run.sh
```

`run.sh` needs `git`, `uv` and network access for the clones and for
`uvx` to fetch the pinned Bandit and Semgrep. If a new tool version reports a
rule that `labels.json` does not map, `score.py` stops and names it; label
it and add it to the `categories` table rather than letting it through
unscored.
