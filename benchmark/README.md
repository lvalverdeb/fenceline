# Benchmark: fenceline vs Bandit vs Semgrep

A labelled, reproducible comparison on four intentionally vulnerable Python
web applications, plus two more corpora: eight ordinary, maintained
applications that measure the other side, how much of what the tools report
on code nobody made vulnerable is worth a reviewer's time (see
[Clean-code corpus](#clean-code-corpus)), and twenty-eight real CVEs in
real applications, pinned at their last vulnerable commit, that measure
recall on bugs that shipped (see [CVE regression set](#cve-regression-set)). The point is not a leaderboard but
a measurement that can be re-run after every change to see which gaps closed
and what it cost in false positives.

## Corpus

| App | Framework | Commit | Python lines |
| --- | --- | --- | --- |
| [pygoat](https://github.com/adeyosemanputra/pygoat) | Django + Flask labs | `2aa4cc1` | 8118 |
| [vulpy](https://github.com/fportantier/vulpy) | Flask | `5249cc8` | 2373 |
| [dvpwa](https://github.com/anxolerd/dvpwa) | aiohttp | `4a8f4a4` | 674 |
| [django.nV](https://github.com/nVisium/django.nV) | Django | `a48901f` | 2461 |

Tools: fenceline at the commit each section below names (this repository;
the Python and Rust ports give identical findings; a section labelled with
a version was measured on the tree that version was released from), Bandit
1.9.4 with default settings,
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

Each section is labelled by the fenceline tree its numbers were measured
on: a release version where one was cut from that tree, otherwise the
commit hash. Releases are not cut to label measurements (`ROADMAP.md`,
release policy).

### Commit `006ce07` (2026-11-16): timing compares between two values

| Tool | Findings | True | False | Precision | Recall |
|---|---|---|---|---|---|
| fenceline | 205 | 195 | 10 | 95% | 190/204 (93%) |
| fenceline (--confidence-min high) | 142 | 139 | 3 | 98% | 135/204 (66%) |

The timing check (`CWE-208`) now reports a secret compared with another
non-literal value, not only with a string literal. Four true instances
join the ground truth (pygoat's OTP and password-hash compares, dvpwa's
`pwd_hash == md5(...)`), found by no other tool; one false positive
(vulpy compares a new password against a leaked-password list). Precision
96% to 95%.

### Commit `de44224` (2026-11-16): the Mealie round

| Tool | Findings | True | False | Precision | Recall |
|---|---|---|---|---|---|
| fenceline | 200 | 191 | 9 | 96% | 186/200 (93%) |
| fenceline (--confidence-min high) | 142 | 139 | 3 | 98% | 135/200 (68%) |

One `CWE-778` finding is gone, labelled true: pygoat's container-quota
check, `except Exception: return JsonResponse({"status": "error", ...},
status=500)`. The round treats a handler that answers the request with an
error response as having handled the failure, because on the ordinary
applications that shape was never a swallowed error; the instance was
found by no other tool, so the ground truth shrinks with it (201 to 200).
Precision unchanged.

### 1.13.0 (2026-11-16): the CTFd round

No change on the vulnerable apps: 207 raw findings in both ports, the same
201 scored, 96% precision, recall 187/201. The round's seven shapes (under
the clean corpus below) do not occur in intentionally vulnerable code.

### 1.12.0 (2026-11-16): the Tandoor round

The handler round (under the clean corpus below) changed six check shapes.
On the vulnerable apps:

| Tool | Findings | True | False | Precision | Recall |
|---|---|---|---|---|---|
| fenceline | 201 | 192 | 9 | 96% | 187/201 (93%) |
| fenceline (--confidence-min high) | 143 | 140 | 3 | 98% | 136/201 (68%) |
| Bandit | 179 | 159 | 20 | 89% | 156/201 (78%) |
| Semgrep | 91 | 90 | 1 | 99% | 68/201 (34%) |

Nine `CWE-778` findings are gone, all labelled true. Six were handlers of
nothing but `pass` or `continue`, which `CWE-391` still reports on the same
line, so each of those handlers is now reported once instead of twice.
Three are gone from the benchmark altogether: two `except: error =
"Invalid input"` in pygoat's insecure-design lab and `except Exception as
e: return False` in vulpy's user lookup. The round treats a handler that
only substitutes a value as the author's explicit handling of the failure,
because on the ordinary applications that shape was by design nearly every
time; these three are the price on the vulnerable side. They were found by
no other tool, so the ground truth shrinks with them (204 to 201) and the
recall percentage does not move; the honest statement is three true
positives fewer at the same precision.

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
ordinary code. Eight maintained applications, pinned and scanned at their
application package; every finding of all three tools in scope adjudicated
by hand. The first four were chosen one per framework; the other four,
pretalx, Tandoor Recipes, CTFd and Mealie, were the held-out applications
of the four tuning rounds and joined the corpus once the checks had been
tuned against them (D7 to D10 in `ROADMAP.md`). Phase C2 closed with this
corpus as its regression gate: no check change may lower its lenient
precision or raise its density.

| App | Framework | Commit | Scanned | Lines in scope |
|---|---|---|---|---|
| [healthchecks](https://github.com/healthchecks/healthchecks) | Django | `cb5c976` | `hc/` | 16884 |
| [dispatch](https://github.com/Netflix/dispatch) | FastAPI | `dd2837e` | `src/dispatch/` | 62177 |
| [flaskbb](https://github.com/flaskbb/flaskbb) | Flask | `1028f17` | `flaskbb/` | 23731 |
| [home-assistant/core](https://github.com/home-assistant/core) | aiohttp | `e68768b` | `homeassistant/auth/`, `homeassistant/components/http/` (sparse checkout) | 25967 |
| [pretalx](https://github.com/pretalx/pretalx) | Django | `1510dea` | `src/pretalx/` | 64074 |
| [Tandoor Recipes](https://github.com/TandoorRecipes/recipes) | Django | `4fdc854` | `cookbook/`, `recipes/` | 20170 |
| [CTFd](https://github.com/CTFd/CTFd) | Flask | `485d59e` | `CTFd/` | 23824 |
| [Mealie](https://github.com/mealie-recipes/mealie) | FastAPI | `3d639dd` | `mealie/` | 43417 |

Tools: fenceline at the commit each section names, Bandit 1.9.4, Semgrep
1.185.0 `p/python`, as in the main benchmark. The universe is the same too: findings on `.py` files outside
tests and migrations (alembic `revisions/` and `alembic/` included), so manifest findings
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

### Commit `de44224` (2026-11-16): the Mealie round, eight apps; C2 closed

The round D10 limited to two check defects and two shapes, in both ports
with parity. `CWE-73` rates a copy or move by its destination (the second
positional argument or `dst=`), not by the content copied, so
`copyfileobj(upload.file, buffer)` into a path the application chose is
not an arbitrary write. `path.is_relative_to(base)` is a guard for its
receiver, so a resolved path checked that way before `FileResponse()` or
`send_file()` is clean. A catch-all handler that returns an error response
(`return response_404()`, a `status_code` of 400 or more) has answered the
request. The Pydantic field check reports only fields whose name says they
carry bulk content (`image`, `content`, `description`); a `username: str`
with no bound is a validation choice. Then Mealie joined the corpus and no
further application was held out: C2 closes here.

The corpus is now eight apps and 280,244 lines:

| Tool | Findings | True | By design | False | Precision (strict) | Precision (lenient) | Per 1000 lines |
|---|---|---|---|---|---|---|---|
| fenceline | 252 | 28 | 56 | 168 | 11% | 33% | 0.9 |
| fenceline (--confidence-min high) | 128 | 24 | 42 | 62 | 19% | 52% | 0.5 |
| Bandit | 412 | 14 | 43 | 355 | 3% | 14% | 1.5 |
| Semgrep | 61 | 0 | 3 | 58 | 0% | 5% | 0.2 |

| Confidence | Findings | True | By design | False | Share true |
|---|---|---|---|---|---|
| HIGH | 128 | 24 | 42 | 62 | 19% |
| MEDIUM | 116 | 4 | 14 | 98 | 3% |
| LOW | 8 | 0 | 0 | 8 | 0% |

| App | Framework | Lines | Findings | True | By design | False | Per 1000 lines |
|---|---|---|---|---|---|---|---|
| healthchecks | Django | 16884 | 15 | 0 | 3 | 12 | 0.9 |
| dispatch | FastAPI | 62177 | 53 | 19 | 4 | 30 | 0.9 |
| flaskbb | Flask | 23731 | 21 | 4 | 7 | 10 | 0.9 |
| hacore | aiohttp | 25967 | 13 | 0 | 2 | 11 | 0.5 |
| pretalx | Django | 64074 | 43 | 0 | 1 | 42 | 0.7 |
| recipes | Django | 20170 | 41 | 2 | 28 | 11 | 2.0 |
| CTFd | Flask | 23824 | 13 | 0 | 5 | 8 | 0.5 |
| mealie | FastAPI | 43417 | 53 | 3 | 6 | 44 | 1.2 |

False positives by check: `CWE-601` 41 (28 at HIGH), `CWE-117` 25,
`CWE-22` 18, `CWE-73` 17, `CWE-918` 12, `CWE-532` 9, `CWE-338` 8,
`CWE-770` 7, `CWE-328` 7, `CWE-1333` 5, twelve others three times or
fewer.

**Mealie, before and after.** 68 findings at 1.13.0, 53 now: 3 true, 6 by
design, 44 false, 6% strict and 17% lenient at 1.2 per 1,000 (HIGH: 20
findings, 15% and 35% at 0.5; was 27, 11% and 26%). Gone: the two
`is_relative_to()`-guarded file responses, three uploads copied into the
application's temporary directory, the three SPA handlers that return a
404, and seven short string fields of request models. What remains is the
per-application idiom recorded with the blind measurement below: copies
of the application's own files rated MEDIUM, log messages that name the
password-reset feature, file responses of UUID-typed parameters, anchored
regexes, config-mode compares.

**The seven apps, before and after.** 200 findings at 1.13.0, 199 now:
one CTFd `copyfileobj()` to a `safe_join()` destination. The eight-app
lenient precision, 33%, is below the 35% default gate the seven apps met
at 38%; Mealie brought it down and no round was run against it after it
joined. Density, 0.9, stays under the bar.

**Elsewhere.** Library corpus unchanged at 220; vulnerable benchmark: one
true `CWE-778` instance fewer (top of this file).

**Port divergence.** Unchanged: the PEP 695 file in Home Assistant, the two
PEP 701 files in Tandoor, and ten PEP 701 files in Mealie that carry no
finding.

**C2, closed as measured.** Four blind applications read 1%, 65%, 15% and
13% lenient at 3.5, 7.0, 1.4 and 1.6 findings per 1,000 lines; the tuning
set reads 33% lenient (52% at HIGH) at 0.9. The density gate is met on the
tuning set; the lenient gates (35% default, 70% HIGH) are not, and no blind
application met any of the three. The honest number for a team turning
fenceline on is the blind one: between one and two findings per 1,000 lines,
most of them the application's own idiom, with the real ones among them
(Mealie's log injection, Tandoor's silent importers) found by no other
tool.

### Held-out application: Mealie (2026-11-16, at 1.13.0; in the corpus since 2026-11-16)

The fourth blind measurement, the second on a framework other than Django:
[Mealie](https://github.com/mealie-recipes/mealie) (FastAPI, `3d639dd`,
`mealie/`, 43417 lines in scope), a recipe manager with a FastAPI backend,
chosen before any check of the CTFd round was touched. Labels are in
`heldout-labels.json`, the runner is `heldout.sh`. Mealie's alembic
migrations live under `alembic/versions/`, so `alembic/` joined the
exclusion list of the universe; no finding of the seven corpus apps moved.

| Tool | Findings | True | By design | False | Precision (strict) | Precision (lenient) | Per 1000 lines |
|---|---|---|---|---|---|---|---|
| fenceline | 68 | 3 | 6 | 59 | 4% | 13% | 1.6 |
| fenceline (--confidence-min high) | 27 | 3 | 4 | 20 | 11% | 26% | 0.6 |
| Bandit | 21 | 0 | 4 | 17 | 0% | 19% | 0.5 |
| Semgrep | 9 | 0 | 0 | 9 | 0% | 0% | 0.2 |

**What it says.** All three gates fail again: 13% lenient at default
against 35%, 26% at HIGH against 70%, 1.6 findings per 1,000 lines against
1.0. The three true findings are log injection, found by fenceline alone:
the raw `X-Forwarded-For` header interpolated into two error logs in the
token endpoint, and the 422 handler logging the validation error text,
which echoes request body values. Blind density across the four held-out
applications has read 3.5, 7.0, 1.4, 1.6.

**The false positives, 59.** `CWE-73` 14: `shutil.copyfileobj(upload.file,
buffer)` into a temporary path the application chose, rated HIGH because
the check rates the content being copied, not the destination; copies of
the application's own backup, export and image files. `CWE-770` 9:
`username: str`, `password: str` and other string fields of Pydantic
request models reported as unbounded reads. `CWE-532` 8: a `secrets_dir`
path, messages that name the password-reset or token feature, a token id.
`CWE-22` 8: `FileResponse()` of a path checked with `.resolve()` and
`is_relative_to()` (the guard the description asks for), of a UUID path
parameter joined with an enum file name, or of a file the application
wrote to its own temporary directory. `CWE-1333` 4: anchored regexes whose
repeats are separated by a literal. `CWE-778` 3: SPA handlers that
`return response_404()`. `CWE-208` 2: a configured SMTP mode compared with
`==`. `CWE-158` 2: a NUL-stripping regex `[\x00\u0000]` and silence
samples in a WAV file. `CWE-117` 2: the request method and URL as parsed
by the server, and a UUID path parameter. `CWE-338` 2, `CWE-918` 2 (one is
the SSRF-safe transport itself), `CWE-90`, `CWE-798` (a field name),
`CWE-93` (iCalendar requires CRLF).

**Observations, recorded and not fixed** (the blind rule): `CWE-73` rates
the copied content rather than the destination path; `.resolve()` followed
by `is_relative_to()` is not recognised as a path guard; Pydantic `str`
fields are reported as unbounded reads; a handler that returns an error
response is not recognised as handling; a `[\x00...]` character class is
not recognised as validation; `==` on a configured mode name is reported
as a timing leak. `ROADMAP.md`, D10.

**Port divergence.** None in findings: 71 in both ports. The Rust port
skips ten files for PEP 701 f-strings, none of which carries a finding in
the Python port.

### 1.13.0 (2026-11-16): the CTFd round, seven apps

The round the D9 text asked for, in both ports with parity. A guard may
vouch for a stable expression and not only a name, so `if
is_safe_url(request.args.get("next")): return
redirect(request.args.get("next"))` is validated; guard keys are canonical
forms of the expression and die when their root name is rebound.
`safe_join()` (werkzeug, flask, django) is a path sanitiser, and a
comprehension whose element is clean is clean whatever it iterates over, so
`send_file(cand)` fed from `(safe_join(...) for t in themes)` is not
reported. `x.lstrip("/")` on a field read off the application's own object
is normalisation, not a sanitiser of input; a bare name stays at MEDIUM. A
catch-all handler that `print()`s, echoes, writes to stdout or stderr, or
`abort()`s has dealt with the exception. A redirect concatenation whose tail
is literals, the request's own path or route builders takes the taint of its
leading operand (`prefix + "/login/?next=" + request.path` goes where
`prefix` goes). `password_reset` and `password_change` names in the other
word order are not secrets. And `# noqa: S608` or `# nosec B608` suppress
the fenceline checks that cover the same Bandit rule: the authors have
adjudicated that line for another tool already. Then CTFd joined the corpus
and Mealie was measured blind (above).

The corpus is now seven apps and 236,827 lines:

| Tool | Findings | True | By design | False | Precision (strict) | Precision (lenient) | Per 1000 lines |
|---|---|---|---|---|---|---|---|
| fenceline | 200 | 25 | 50 | 125 | 12% | 38% | 0.8 |
| fenceline (--confidence-min high) | 108 | 21 | 38 | 49 | 19% | 55% | 0.5 |
| Bandit | 391 | 14 | 39 | 338 | 4% | 14% | 1.7 |
| Semgrep | 52 | 0 | 3 | 49 | 0% | 6% | 0.2 |

| Confidence | Findings | True | By design | False | Share true |
|---|---|---|---|---|---|
| HIGH | 108 | 21 | 38 | 49 | 19% |
| MEDIUM | 90 | 4 | 12 | 74 | 4% |
| LOW | 2 | 0 | 0 | 2 | 0% |

| App | Framework | Lines | Findings | True | By design | False | Per 1000 lines |
|---|---|---|---|---|---|---|---|
| healthchecks | Django | 16884 | 15 | 0 | 3 | 12 | 0.9 |
| dispatch | FastAPI | 62177 | 53 | 19 | 4 | 30 | 0.9 |
| flaskbb | Flask | 23731 | 21 | 4 | 7 | 10 | 0.9 |
| hacore | aiohttp | 25967 | 13 | 0 | 2 | 11 | 0.5 |
| pretalx | Django | 64074 | 43 | 0 | 1 | 42 | 0.7 |
| recipes | Django | 20170 | 41 | 2 | 28 | 11 | 2.0 |
| CTFd | Flask | 23824 | 14 | 0 | 5 | 9 | 0.6 |

False positives by check: `CWE-601` 41 (28 at HIGH), `CWE-117` 23,
`CWE-22` 12, `CWE-918` 10, `CWE-73` 7, `CWE-328` 7, `CWE-338` 6, `CWE-770`
5, `CWE-79` 3, `CWE-798` 2, nine others once each.

**The six apps, before and after.** 233 findings at 1.12.0, 186 now: 25
true, 45 by design, 116 false, 13% strict and 38% lenient at 0.9 per 1,000
(HIGH: 105 findings, 20% and 55% at 0.5; was 117, 18% and 50%). Forty-three
of the 47 findings removed are pretalx lines carrying `# noqa: S308`,
`S311` or `S324`: `mark_safe()` of static markup, cosmetic `random`, MD5
for cache busting, each with the authors' reason in the comment. pretalx
went from 86 findings to 43 (1.3 to 0.7 per 1,000). Tandoor went from 45
to 41: the login redirect led by a configured prefix, and three handlers
that print or write the failure to the command output. For the first time
the tuning set meets the density gate and the default lenient gate; the
HIGH lenient gate (70%) is not met at 55%.

**CTFd, before and after.** 33 findings at 1.12.0, 14 now: 0 true, 5 by
design, 9 false, 36% lenient at 0.6 per 1,000 (HIGH: 3 findings, 0.1).
Gone: the two validated `next` redirects, the application-root redirect
(now MEDIUM: its lead is configuration), the seven `send_file()` and
`lstrip()` paths, the four password-action e-mail templates, the two
handlers that print and the one that aborts, and the three `# noqa` lines.
What remains: `send_file()` of an in-memory CSV export (two, HIGH: a
type-shaped case the model cannot see), the two API client wrappers, the
presigned S3 URL, `KILL {proc_id}`, `copyfileobj()` to a `safe_join()`
destination (the copied content is rated), and the by-design findings.

**Elsewhere.** Library corpus unchanged at 220; vulnerable benchmark
unchanged (top of this file).

**Port divergence.** Unchanged: the PEP 695 file in Home Assistant and the
two PEP 701 files in Tandoor. Released as 1.13.0 from the tree these
numbers were measured on.

### Held-out application: CTFd (2026-11-16, at 1.12.0; in the corpus since 2026-11-16)

The third blind measurement and the first on an application that is not
Django: [CTFd](https://github.com/CTFd/CTFd) (Flask, `485d59e`, `CTFd/`,
23824 lines in scope), the capture-the-flag platform, chosen before any
check of the Tandoor round was touched. Labels are in `heldout-labels.json`,
the runner is `heldout.sh`.

| Tool | Findings | True | By design | False | Precision (strict) | Precision (lenient) | Per 1000 lines |
|---|---|---|---|---|---|---|---|
| fenceline | 33 | 0 | 5 | 28 | 0% | 15% | 1.4 |
| fenceline (--confidence-min high) | 11 | 0 | 1 | 10 | 0% | 9% | 0.5 |
| Bandit | 12 | 0 | 2 | 10 | 0% | 17% | 0.5 |
| Semgrep | 13 | 0 | 2 | 11 | 0% | 15% | 0.5 |

fenceline also reports one `CWE-1104` on the repository's `uv.lock`
(werkzeug 2.2.3, CVE-2024-49766), which is correct and outside the
application-code universe the three tools share.

**What it says.** All three gates fail: 15% lenient at default against
35%, 9% at HIGH against 70%, 1.4 findings per 1,000 lines against 1.0. Two
things qualify that. No tool found anything true in CTFd, so strict
precision could not have been above zero, and lenient precision on an app
with five by-design findings is a count of false positives, not of
judgement. And density on a blind application has read 3.5 (pretalx at
1.10.0), 7.0 (Tandoor at 1.11.0) and now 1.4: the first blind number near
the bar, on a framework the two previous rounds did not tune on. Bandit
and Semgrep read 0.5 each at 17% and 15% lenient.

**The false positives, 28.** `CWE-22` 10: `send_file()` of an in-memory CSV
export (a `BytesIO`, not a path), of `safe_join()` results that are checked
for `None` first, and of a plugin asset path captured in a closure at
startup; template paths declared by the challenge plugin class with
`.lstrip("/")`. `CWE-601` 4: `redirect(request.args.get("next"))` guarded
by `validators.is_safe_url(request.args.get("next"))` in the enclosing
`if`, where the guard's argument is a call rather than a name so the
URL-validator rule does not bind; `application_root + request.script_root
+ request.full_path`, a configured prefix leading the concatenation; a
boto3 presigned URL re-hosted on a configured domain. `CWE-798` 4:
`DEFAULT_PASSWORD_RESET_SUBJECT` and three siblings, e-mail text under
password-action names in the other word order (`password_reset`,
`password_change`); Bandit's B105 reports the same four. `CWE-778` 3:
handlers that `print()` the failure (a print without the exception bound
is not a diagnostic, by rule) or `abort(401, ...)` to the client. `CWE-328`
2 and `CWE-79` 1: MD5 of a cache key, SHA-1 of an upload's content and a
`Markup()` helper, each with a `# noqa` for the equivalent Bandit code.
`CWE-918` 2: `requests.request(method, url, ...)` in an API client wrapper
whose URL comes from the administrator's integration settings. `CWE-89` 1:
`f"KILL {proc_id}"` with an id read from the database's process list.
`CWE-73` 1: `copyfileobj()` to a `safe_join()` destination.

**Observations, recorded and not fixed** (the blind rule): a URL validator
applied to a call expression rather than a bound name; `send_file()` of a
non-path object; `safe_join()` as a sanitiser for `send_file()`; `abort()`
and `print()` as explicit handling of a caught exception; the
`password_reset` word order of the password-action rule; a configured
prefix leading a redirect concatenation; and `# noqa: Sxxx` on a line,
which says the authors have already adjudicated the equivalent Bandit
finding. `ROADMAP.md`, D9.

**Port divergence.** None: 34 findings in both ports.

### 1.12.0 (2026-11-16): the Tandoor round, six apps

The round the D8 text asked for, in both ports with parity: `CWE-778` no
longer reports a catch-all handler that only substitutes an outcome
(`pass`, `continue`, `break`, a `return` or assignment whose value makes no
call, or a nested `try` of the same shape), so a `pass` handler is
`CWE-391`'s finding alone and a chosen fallback value is the author's
handling; a handler that returns a built response or does other work
without recording the error still reports. `CWE-200` reports
`traceback.format_exc()` on a line that returns or builds a response, not
`traceback.print_exc()`, which goes to stderr. A redirect concatenation
led by a route builder (`reverse('login') + '?next=' + request.path`) is
same-site. An lxml parser built with `resolve_entities=False`, a parse
call passing such a parser, and an import of XML builders and serialisers
only are not XXE. `reset_password`/`change_password` keys are actions on
the password, and a value that is a URL or filesystem path is not a
secret. Then Tandoor joined the corpus and CTFd was measured blind (above).

The corpus is now six apps and 213,003 lines:

| Tool | Findings | True | By design | False | Precision (strict) | Precision (lenient) | Per 1000 lines |
|---|---|---|---|---|---|---|---|
| fenceline | 233 | 25 | 46 | 162 | 11% | 30% | 1.1 |
| fenceline (--confidence-min high) | 117 | 21 | 38 | 58 | 18% | 50% | 0.5 |
| Bandit | 379 | 14 | 37 | 328 | 4% | 13% | 1.8 |
| Semgrep | 39 | 0 | 1 | 38 | 0% | 3% | 0.2 |

| Confidence | Findings | True | By design | False | Share true |
|---|---|---|---|---|---|
| HIGH | 117 | 21 | 38 | 58 | 18% |
| MEDIUM | 114 | 4 | 8 | 102 | 4% |
| LOW | 2 | 0 | 0 | 2 | 0% |

| App | Framework | Lines | Findings | True | By design | False | Per 1000 lines |
|---|---|---|---|---|---|---|---|
| healthchecks | Django | 16884 | 15 | 0 | 3 | 12 | 0.9 |
| dispatch | FastAPI | 62177 | 53 | 19 | 4 | 30 | 0.9 |
| flaskbb | Flask | 23731 | 21 | 4 | 7 | 10 | 0.9 |
| hacore | aiohttp | 25967 | 13 | 0 | 2 | 11 | 0.5 |
| pretalx | Django | 64074 | 86 | 0 | 1 | 85 | 1.3 |
| recipes | Django | 20170 | 45 | 2 | 29 | 14 | 2.2 |

False positives by check: `CWE-601` 40 (29 at HIGH), `CWE-79` 31,
`CWE-117` 23, `CWE-338` 16, `CWE-328` 11, `CWE-22` 9, `CWE-918` 8,
`CWE-73` 6, `CWE-770` 5, `CWE-798` 3, `CWE-778` 3, seven others once each.

**Tandoor, before and after.** 141 findings at 1.11.0, 45 now: 2 true, 29
by design, 14 false, 4% strict and 69% lenient at 2.2 per 1,000 lines
(HIGH: 42 findings, 5% and 74% at 2.1). The two true sites, importers that
drop content with no log entry, are reported once each now, by `CWE-391`.
The 65 `CWE-778` fell to 4, the 22 `CWE-200` to none, the 7 `CWE-601` to 3,
the 5 `CWE-611` and the 5 `CWE-798` to none. What remains: three redirects
where the leading operand is a configured prefix or allauth's
`build_absolute_uri()` of a `reverse()` URL; two handlers that `print()`
or write the failure to a command's output (not a diagnostic, by rule) and
one that returns an error message to the user; three `.read()` of uploads
Django has already received; one each of `CWE-328`, `CWE-338`, `CWE-73`,
`CWE-22`, `CWE-94`. Density 7.0 to 2.2 is the round's result; 2.2 is still
above the bar, and the remaining 29 by-design findings are the `CWE-391`
`pass` handlers, which are reported once each and are what the check is
for.

**The five apps, before and after.** 195 findings at 1.11.0, 188 now: 23
true, 17 by design, 148 false, 12% strict and 21% lenient at 1.0 (HIGH: 75
findings, 25% and 37% at 0.4; was 81, 23% and 42%). Lenient precision fell
three points because the seven findings removed were by-design handlers
(dispatch's version and git lookups, flaskbb's celery probe, pretalx's
session recovery) and one `print_exc()` at import time; strict precision
and density did not move.

**Elsewhere.** Library corpus 235 to 220: fourteen `CWE-778` fallback
handlers in aiohttp, botocore and tornado, and one `CWE-200` `print_exc()`
in a tornado test. pretalx 88 to 87. Vulnerable benchmark: see the top of
this file (three true `CWE-778` instances fewer).

**Port divergence.** Unchanged: the PEP 695 file in Home Assistant and the
two PEP 701 files in Tandoor. Released as 1.12.0 from the tree these
numbers were measured on.

### Held-out application: Tandoor Recipes (2026-11-16, at 1.11.0; in the corpus since 2026-11-16)

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

## CVE regression set

Recall on vulnerabilities that shipped, in applications with real service
layers: for each CVE, `benchmark/cves/manifest.json` pins the last
vulnerable commit (the parent of the fix, or the base of the fix PR), the
package scanned, the sink file and line a reviewer would name, and the
CWE. `benchmark/cves/run.sh` clones each tree sparsely, scans the package
and scores; `score.py` prints the tables below. A CVE is *found* when a
finding with the right CWE sits on the sink line (or another line of the
same instance the manifest lists); the same CWE elsewhere in the file does
not count. *Other findings in file* is what a reviewer wades through in
that file apart from the hit.

Twenty-two CVEs are in classes fenceline claims (path traversal, arbitrary
write, command and code injection, deserialization, SSRF, open redirect,
XSS, hard-coded secrets, timing attacks); six are in classes it does not
(missing authentication, session fixation, unsafe reflection, permissive
CORS, ORM field leaks), kept so the set also says what the tool is not.
Applications: mlflow, Apache Airflow, MindsDB (Flask); Gradio, Langflow
(FastAPI); BentoML (Starlette); label-studio, Weblate (Django); Jupyter
Server (Tornado); vLLM (a network pipe, not HTTP). Selection rule in
`ROADMAP.md`, Phase C3 and D3.

### Commit `de44224` (2026-11-16): first measurement

### Classes fenceline claims: fenceline, 15/22 found, 12 at HIGH

| CVE | App | Framework | CWE | Result | Same CWE elsewhere in file | Other findings in file | Root cause of the miss |
|---|---|---|---|---|---|---|---|
| CVE-2023-1177 | mlflow | Flask | CWE-22 | found (HIGH) | 2 | 2 |  |
| CVE-2023-2780 | mlflow | Flask | CWE-22 | found (HIGH) | 2 | 2 |  |
| CVE-2023-6977 | mlflow | Flask | CWE-22 | found (HIGH) | 2 | 4 |  |
| CVE-2023-6018 | mlflow | Flask | CWE-22 | missed | 1 | 3 | The write is `open(local_path, "wb")` with a parameter path; the traversal is in the file listing a remote server returned, two calls up and in another file. fenceline has no write-`open()` sink; its CWE-73 covers copy and move only. |
| CVE-2023-6909 | mlflow | Flask | CWE-22 | found (HIGH) | 2 | 4 |  |
| CVE-2023-6974 | mlflow | Flask | CWE-918 | missed | 0 | 1 | `Session.request(method, url)` is not an SSRF sink fenceline knows (`requests.request()` is), and the flaw is redirect-following, a request setting fenceline does not model. |
| CVE-2022-40127 | airflow | Flask | CWE-78 | missed | 0 | 0 | The sink is a `BashOperator(bash_command=...)` Jinja template the scheduler renders; the file has no subprocess call. |
| CVE-2022-40754 | airflow | Flask | CWE-601 | found (HIGH) | 28 | 41 |  |
| CVE-2022-24710 | weblate | Django | CWE-79 | missed | 0 | 0 | HTML is built with `str.format()` and returned in an `HttpResponse`; the XSS check reports `Markup()`/`mark_safe()` only. |
| CVE-2023-51449 | gradio | FastAPI | CWE-22 | found (HIGH) | 1 | 5 |  |
| CVE-2023-34239 | gradio | FastAPI | CWE-918 | missed | 0 | 4 | `httpx.Client.build_request()` and `client.send()` are not SSRF sinks fenceline knows. |
| CVE-2024-1728 | gradio | FastAPI | CWE-22 | found (HIGH) | 0 | 4 |  |
| CVE-2024-4941 | gradio | FastAPI | CWE-22 | found (MEDIUM) | 0 | 4 |  |
| CVE-2024-47164 | gradio | FastAPI | CWE-22 | found (HIGH) | 2 | 8 |  |
| CVE-2024-1729 | gradio | FastAPI | CWE-208 | missed | 0 | 5 | The timing check reports a secret compared with a string literal; `app.auth[username] == password` compares two values. |
| CVE-2023-39968 | jupyter_server | Tornado | CWE-601 | found (HIGH) | 0 | 2 |  |
| CVE-2024-45846 | mindsdb | Flask | CWE-95 | found (MEDIUM) | 1 | 1 |  |
| CVE-2023-30620 | mindsdb | Flask | CWE-22 | found (HIGH) | 0 | 5 |  |
| CVE-2024-2912 | bentoml | Starlette | CWE-502 | found (HIGH) | 0 | 1 |  |
| CVE-2025-29783 | vllm | none | CWE-502 | found (HIGH) | 0 | 0 |  |
| CVE-2023-43791 | label-studio | Django | CWE-798 | found (MEDIUM) | 0 | 1 |  |
| CVE-2023-47116 | label-studio | Django | CWE-918 | missed | 0 | 0 | The sink line carries the developer's bare `# nosec`, which fenceline honours; with the comment removed the line is reported as CWE-918, HIGH severity at MEDIUM confidence. |

### Classes fenceline does not claim: fenceline, 0/6 found, 0 at HIGH

| CVE | App | Framework | CWE | Result | Same CWE elsewhere in file | Other findings in file | Root cause of the miss |
|---|---|---|---|---|---|---|---|
| CVE-2021-38540 | airflow | Flask | CWE-306 | missed | 0 | 48 | No check: a view absent from a permission map is an authorization fact fenceline does not model. |
| CVE-2023-40273 | airflow | Flask | CWE-384 | missed | 0 | 0 | No check for session lifecycle. |
| CVE-2024-1561 | gradio | FastAPI | CWE-470 | missed | 0 | 6 | No check for `getattr()` with a request-controlled attribute name (unsafe reflection). |
| CVE-2024-1727 | gradio | FastAPI | CWE-942 | missed | 0 | 5 | No check for `CORSMiddleware(allow_origins=["*"])`; a candidate for the declarative rules of C4. |
| CVE-2023-47117 | label-studio | Django | CWE-200 | missed | 0 | 0 | No check for request-controlled ORM field names. |
| CVE-2025-3248 | langflow | FastAPI | CWE-306 | missed | 0 | 16 | No check for an unauthenticated route. fenceline reports the `exec()`/`compile()` sinks themselves, sixteen CWE-94 findings in the file at MEDIUM, which is the by-design code sink, not the missing authentication. |

Findings over all 28 trees: 3166.

**Covered classes: 15 of 22 found, 12 at HIGH confidence.** Every hit was
checked by hand against the vulnerable tree. The four mlflow path
traversals share one sink, the `send_file()` of the artifact handler, and
fenceline reports it HIGH in each tree; the guard bugs that made each CVE
(an unresolved `..`, a `file://` source, a URL form `is_local_uri()`
missed) are not what it sees, the unguarded sink is. The same holds for the
three Gradio `/file=` traversals and `FileResponse()`. Both deserialization
CVEs, the tar slip, the MindsDB `eval()`s, both open redirects and the
hard-coded Django key are found where the advisory points. Two Gradio
file reads are found as CWE-73 on the `shutil.copy2()` into the cache
rather than as CWE-22; the manifest accepts the neighbouring CWE.

**The seven misses, by cause.** Two are SSRF sinks fenceline does not know:
`Session.request()` (mlflow) and `httpx.Client.build_request()`/`send()`
(Gradio); the shared cause makes them the first follow-on. One is a write
through `open(path, "wb")` with the traversal in a remote listing two calls
up (mlflow): no write-`open()` sink. One is an Airflow `BashOperator`
template with no subprocess call in the file. One is HTML built with
`str.format()` (Weblate): the XSS check covers `Markup()`/`mark_safe()`
only. One is `app.auth[username] == password` (Gradio): the timing check
reports a secret compared with a literal, not with another value. One is a
developer's bare `# nosec` on the sink line (label-studio): fenceline
honours it, and with the comment removed reports the line at HIGH severity,
MEDIUM confidence. The uncovered six are missed by construction; on
Langflow fenceline reports the `exec()` sinks themselves, sixteen CWE-94
findings in the file, which is the by-design code path, not the missing
authentication.

**Noise.** The Airflow `views.py` trees carry 41 to 48 other findings in
the sink's file, most of them `redirect(self.get_redirect())` at MEDIUM
and `Markup(chart.htmlcontent)`; everywhere else the reviewer reads
between zero and eight.

**Port parity.** The set is also the largest varied corpus the two ports
had been run on (3,166 findings over 28 trees), and the first run found
three divergences the earlier corpora never exercised, all on the Rust
side and all fixed in the same change: the pandas `query()` check tested
the dotted name instead of the call shape (a bare imported `query()` was
reported, a `Client().query()` was not); each f-string level consumed an
extra taint-depth step, so a module constant built from two nested
f-strings read INTERNAL; and the identifier collector behind the
log-secrets check did not descend into dict literals. Fixtures cover each.
Both ports now agree on every tree.

### Commit `eaf0b47` (2026-11-16): follow-on 1, SSRF sinks

The shared cause of two misses, fixed in both ports: `x.request(method,
url)` and `client.build_request(method, url)` are HTTP requests whatever
`x` is bound to (every HTTP client has that two-argument method, no ORM
session does), with the URL as the second argument. The same change fixed
a defect in the existing sink: `requests.request(method, url)` rated its
first argument, the method, so a request-derived URL in second position
was never reported and a request-derived method with a literal URL was.

### Classes fenceline claims: fenceline, 17/22 found, 12 at HIGH

| CVE | App | Framework | CWE | Result | Same CWE elsewhere in file | Other findings in file | Root cause of the miss |
|---|---|---|---|---|---|---|---|
| CVE-2023-1177 | mlflow | Flask | CWE-22 | found (HIGH) | 2 | 2 |  |
| CVE-2023-2780 | mlflow | Flask | CWE-22 | found (HIGH) | 2 | 2 |  |
| CVE-2023-6977 | mlflow | Flask | CWE-22 | found (HIGH) | 2 | 4 |  |
| CVE-2023-6018 | mlflow | Flask | CWE-22 | missed | 1 | 3 | The write is `open(local_path, "wb")` with a parameter path; the traversal is in the file listing a remote server returned, two calls up and in another file. fenceline has no write-`open()` sink; its CWE-73 covers copy and move only. |
| CVE-2023-6909 | mlflow | Flask | CWE-22 | found (HIGH) | 2 | 4 |  |
| CVE-2023-6974 | mlflow | Flask | CWE-918 | found (MEDIUM) | 0 | 1 |  |
| CVE-2022-40127 | airflow | Flask | CWE-78 | missed | 0 | 0 | The sink is a `BashOperator(bash_command=...)` Jinja template the scheduler renders; the file has no subprocess call. |
| CVE-2022-40754 | airflow | Flask | CWE-601 | found (HIGH) | 28 | 41 |  |
| CVE-2022-24710 | weblate | Django | CWE-79 | missed | 0 | 0 | HTML is built with `str.format()` and returned in an `HttpResponse`; the XSS check reports `Markup()`/`mark_safe()` only. |
| CVE-2023-51449 | gradio | FastAPI | CWE-22 | found (HIGH) | 1 | 6 |  |
| CVE-2023-34239 | gradio | FastAPI | CWE-918 | found (MEDIUM) | 0 | 4 |  |
| CVE-2024-1728 | gradio | FastAPI | CWE-22 | found (HIGH) | 0 | 4 |  |
| CVE-2024-4941 | gradio | FastAPI | CWE-22 | found (MEDIUM) | 0 | 5 |  |
| CVE-2024-47164 | gradio | FastAPI | CWE-22 | found (HIGH) | 2 | 9 |  |
| CVE-2024-1729 | gradio | FastAPI | CWE-208 | missed | 0 | 6 | The timing check reports a secret compared with a string literal; `app.auth[username] == password` compares two values. |
| CVE-2023-39968 | jupyter_server | Tornado | CWE-601 | found (HIGH) | 0 | 2 |  |
| CVE-2024-45846 | mindsdb | Flask | CWE-95 | found (MEDIUM) | 1 | 1 |  |
| CVE-2023-30620 | mindsdb | Flask | CWE-22 | found (HIGH) | 0 | 5 |  |
| CVE-2024-2912 | bentoml | Starlette | CWE-502 | found (HIGH) | 0 | 1 |  |
| CVE-2025-29783 | vllm | none | CWE-502 | found (HIGH) | 0 | 0 |  |
| CVE-2023-43791 | label-studio | Django | CWE-798 | found (MEDIUM) | 0 | 1 |  |
| CVE-2023-47116 | label-studio | Django | CWE-918 | missed | 0 | 0 | The sink line carries the developer's bare `# nosec`, which fenceline honours; with the comment removed the line is reported as CWE-918, HIGH severity at MEDIUM confidence. |

### Classes fenceline does not claim: fenceline, 0/6 found, 0 at HIGH

| CVE | App | Framework | CWE | Result | Same CWE elsewhere in file | Other findings in file | Root cause of the miss |
|---|---|---|---|---|---|---|---|
| CVE-2021-38540 | airflow | Flask | CWE-306 | missed | 0 | 48 | No check: a view absent from a permission map is an authorization fact fenceline does not model. |
| CVE-2023-40273 | airflow | Flask | CWE-384 | missed | 0 | 0 | No check for session lifecycle. |
| CVE-2024-1561 | gradio | FastAPI | CWE-470 | missed | 0 | 7 | No check for `getattr()` with a request-controlled attribute name (unsafe reflection). |
| CVE-2024-1727 | gradio | FastAPI | CWE-942 | missed | 0 | 6 | No check for `CORSMiddleware(allow_origins=["*"])`; a candidate for the declarative rules of C4. |
| CVE-2023-47117 | label-studio | Django | CWE-200 | missed | 0 | 0 | No check for request-controlled ORM field names. |
| CVE-2025-3248 | langflow | FastAPI | CWE-306 | missed | 0 | 16 | No check for an unauthenticated route. fenceline reports the `exec()`/`compile()` sinks themselves, sixteen CWE-94 findings in the file at MEDIUM, which is the by-design code sink, not the missing authentication. |

Findings over all 28 trees: 3235.

**Covered classes: 17 of 22 found, 12 at HIGH.** mlflow's
`session.request(method, url)` and Gradio's `client.build_request("GET",
url)` are found at MEDIUM: in both the URL is a parameter of a helper, and
the request-derived value enters one call up. The five remaining misses
are single-cause (write-`open()`, operator template, `str.format()` HTML,
timing compare of two values, developer `# nosec`).

**Cost on the eight-app corpus.** Seven findings more (259; 28 true, 60 by
design, 171 false): three in dispatch's Jira and Confluence plugins,
`requests.request("GET", url)` to administrator-configured URLs, false and
previously hidden by the argument defect; four in healthchecks'
notification transport, `curl.request(method, url)` and the Webhook
integration, by design. Lenient precision 33% to 34%, strict 11%,
density 0.90 to 0.92 per 1,000 lines (0.9 at the stated precision), HIGH
unchanged (128; 19% / 52%). Vulnerable benchmark unchanged (200 scored,
96%, 186/200). Both ports agree on every corpus; the CVE trees carry 69
more CWE-918 findings at MEDIUM in total, all `.request(method, url)` on
client wrappers (Weblate's Git API wrappers, label-studio's ML backend
connector, BentoML's client), which is the same shape the clean corpus
labels by design or false.

### Commit `006ce07` (2026-11-16): follow-on 2, timing compares; C3 closed

`app.auth[username] == password` compares a secret with a looked-up value;
the timing check reported only secret-against-literal. It now reports a
secret-named value compared with another non-literal value too, LOW/LOW,
unless both sides are secrets (a password confirmation), either side is an
ALL_CAPS constant or sentinel, or either side is a constant.

### Classes fenceline claims: fenceline, 18/22 found, 12 at HIGH

| CVE | App | Framework | CWE | Result | Same CWE elsewhere in file | Other findings in file | Root cause of the miss |
|---|---|---|---|---|---|---|---|
| CVE-2023-1177 | mlflow | Flask | CWE-22 | found (HIGH) | 2 | 2 |  |
| CVE-2023-2780 | mlflow | Flask | CWE-22 | found (HIGH) | 2 | 2 |  |
| CVE-2023-6977 | mlflow | Flask | CWE-22 | found (HIGH) | 2 | 4 |  |
| CVE-2023-6018 | mlflow | Flask | CWE-22 | missed | 1 | 3 | The write is `open(local_path, "wb")` with a parameter path; the traversal is in the file listing a remote server returned, two calls up and in another file. fenceline has no write-`open()` sink; its CWE-73 covers copy and move only. A write-`open()` sink was prototyped and declined: it finds this line at MEDIUM and adds eleven MEDIUM findings to the eight-app corpus (CLI, backup and settings writers at operator-chosen paths), lenient precision 34% to 33%. |
| CVE-2023-6909 | mlflow | Flask | CWE-22 | found (HIGH) | 2 | 4 |  |
| CVE-2023-6974 | mlflow | Flask | CWE-918 | found (MEDIUM) | 0 | 1 |  |
| CVE-2022-40127 | airflow | Flask | CWE-78 | missed | 0 | 0 | The sink is a `BashOperator(bash_command=...)` Jinja template the scheduler renders; the file has no subprocess call. A declarative `pattern` rule for `bash_command=` templates that reference `run_id`/`dag_run`/`params` is the C4 shape for this; not a built-in. |
| CVE-2022-40754 | airflow | Flask | CWE-601 | found (HIGH) | 28 | 41 |  |
| CVE-2022-24710 | weblate | Django | CWE-79 | missed | 0 | 0 | HTML is built with `str.format()` and returned in an `HttpResponse`; the XSS check reports `Markup()`/`mark_safe()` only. A response sink (`HttpResponse(text)`) would see the content arrive through a list and a `join()`, INTERNAL, and would report every Django view that returns built text; declined without a prototype. |
| CVE-2023-51449 | gradio | FastAPI | CWE-22 | found (HIGH) | 1 | 7 |  |
| CVE-2023-34239 | gradio | FastAPI | CWE-918 | found (MEDIUM) | 0 | 5 |  |
| CVE-2024-1728 | gradio | FastAPI | CWE-22 | found (HIGH) | 0 | 4 |  |
| CVE-2024-4941 | gradio | FastAPI | CWE-22 | found (MEDIUM) | 0 | 5 |  |
| CVE-2024-47164 | gradio | FastAPI | CWE-22 | found (HIGH) | 2 | 9 |  |
| CVE-2024-1729 | gradio | FastAPI | CWE-208 | found (LOW) | 0 | 6 |  |
| CVE-2023-39968 | jupyter_server | Tornado | CWE-601 | found (HIGH) | 0 | 2 |  |
| CVE-2024-45846 | mindsdb | Flask | CWE-95 | found (MEDIUM) | 1 | 1 |  |
| CVE-2023-30620 | mindsdb | Flask | CWE-22 | found (HIGH) | 0 | 5 |  |
| CVE-2024-2912 | bentoml | Starlette | CWE-502 | found (HIGH) | 0 | 1 |  |
| CVE-2025-29783 | vllm | none | CWE-502 | found (HIGH) | 0 | 0 |  |
| CVE-2023-43791 | label-studio | Django | CWE-798 | found (MEDIUM) | 0 | 1 |  |
| CVE-2023-47116 | label-studio | Django | CWE-918 | missed | 0 | 0 | The sink line carries the developer's bare `# nosec`, which fenceline honours; with the comment removed the line is reported as CWE-918, HIGH severity at MEDIUM confidence. |

### Classes fenceline does not claim: fenceline, 0/6 found, 0 at HIGH

| CVE | App | Framework | CWE | Result | Same CWE elsewhere in file | Other findings in file | Root cause of the miss |
|---|---|---|---|---|---|---|---|
| CVE-2021-38540 | airflow | Flask | CWE-306 | missed | 0 | 48 | No check: a view absent from a permission map is an authorization fact fenceline does not model. |
| CVE-2023-40273 | airflow | Flask | CWE-384 | missed | 0 | 0 | No check for session lifecycle. |
| CVE-2024-1561 | gradio | FastAPI | CWE-470 | missed | 0 | 8 | No check for `getattr()` with a request-controlled attribute name (unsafe reflection). |
| CVE-2024-1727 | gradio | FastAPI | CWE-942 | missed | 0 | 6 | No check for `CORSMiddleware(allow_origins=["*"])`; a candidate for the declarative rules of C4. |
| CVE-2023-47117 | label-studio | Django | CWE-200 | missed | 0 | 0 | No check for request-controlled ORM field names. |
| CVE-2025-3248 | langflow | FastAPI | CWE-306 | missed | 0 | 16 | No check for an unauthenticated route. fenceline reports the `exec()`/`compile()` sinks themselves, sixteen CWE-94 findings in the file at MEDIUM, which is the by-design code sink, not the missing authentication. |

Findings over all 28 trees: 3254.

**Covered classes: 18 of 22 found, 12 at HIGH.** Gradio's login compare is
found at LOW. **Cost on the eight-app corpus:** six findings more (265; 30
true, 61 by design, 174 false): two true, healthchecks' e-mail
verification token compared with `==`; one by design, Mealie's test-only
`FakeHasher`; three false, a password confirmation and two lexer tokens
named `token`. Lenient 34%, strict 11%, density 0.92 to 0.95 per 1,000
(0.9 reported), HIGH unchanged. Vulnerable benchmark: top of this file.

**The four remaining misses, and why they stay.** A write-`open()` sink
for mlflow's `open(local_path, "wb")` was prototyped: it finds the line at
MEDIUM and adds eleven MEDIUM findings to the eight-app corpus, CLI and
backup and settings writers at operator-chosen paths, taking lenient
precision from 34% to 33%; declined, numbers in the manifest. A response
sink for Weblate's `str.format()` HTML would see the content arrive
through a list and a `join()` at INTERNAL and report every Django view
that returns built text; declined without a prototype. Airflow's
`BashOperator(bash_command=...)` template is a `pattern` rule for C4, not a
built-in. label-studio's `# nosec` is honoured by design.

**C3 closes here.** The instrument exists (manifest, runner, scorer), the
table is published, every miss has a cause, and the two shared or cheap
causes are fixed with their cost measured and labelled. 18 of 22 claimed
CVEs found, 12 at HIGH; the set is part of the parity check and grows as
CVEs are added.

## Declarative rules: the ten-check proof

### Commit `51125ec` (2026-11-16): C4

`fixtures/rules/builtins/rules.toml` re-expresses ten built-in checks
(`check_pandas_pickle`, `check_pandas_xml_xxe`, `check_torch_load`,
`check_numpy_load`, `check_request_timeout`, `check_pickle`,
`check_unsafe_markup`, `check_symlink`, `check_ldap`, `check_ssh_host_key`)
as fourteen rules. Each corpus was scanned twice per port: plain, and with
`--disable` for the ten checks plus `--rules` for the file. Findings are
compared on (file, line, CWE, severity, confidence); descriptions differ
by the rules' wording.

| Corpus | Plain (Python / Rust) | With rules (Python / Rust) | Difference |
|---|---|---|---|
| Vulnerable benchmark, 4 apps | 209 / 209 | 209 / 209 | none |
| Eight-app clean corpus | 353 / 351 | 353 / 351 | none |
| 28 CVE trees | 3,254 / 3,254 | 3,257 / 3,257 | +3 on one tree |

The Rust and Python counts on the eight-app corpus differ by the two
files rustpython-parser cannot parse (PEP 695 / PEP 701), as everywhere
else in this file. The three extra findings are Weblate's
(`CVE-2022-24710`): `weblate/addons/tasks.py:50`,
`weblate/utils/checks.py:522`, `weblate/wladmin/models.py:145`, each a
call of the project's `weblate.utils.requests.request()` wrapper without
`timeout=`. The wrapper itself sets none, so the findings are defensible;
they appear because a rule's `callee` tail-matches (`requests.request`
matches `weblate.utils.requests.request`) where `check_request_timeout`
matches exactly two segments. The other nine checks reproduce exactly.
Both ports' rule runs agree on every tree.

Scanned with the scratchpad clones named in the sections above; the
command pair is in `fixtures/rules/builtins/rules.toml`'s header.

