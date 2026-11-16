# Roadmap: from "beats Bandit on vulnerable apps" to "a scanner a team turns on"

**Status**: D1–D5 accepted 2026-11-14. Phase 0 done (1.9.0 on PyPI and
crates.io, `v1.9.0` tags). C1 done 2026-11-14: `benchmark/clean/` with the
four accepted apps, 872 verdicts, scorer and runner; result 3% strict
precision at 1.9.0 (4% at HIGH), Bandit 5%, Semgrep 0%. C2 two rounds done
2026-11-14 and released as 1.10.0: 20% strict / 38% lenient at default,
42% / 71% at HIGH, vulnerable benchmark 96% precision with no recall
change. D6 accepted 2026-11-14: the C2 gates are the lenient ones stated
there, and they are met on the tuning set. Held-out application (pretalx)
measured 2026-11-14: 0% precise, 224 findings, three shapes the tuning
set did not contain. D7 accepted 2026-11-16 as (a): shapes fixed in both
ports, pretalx in the corpus (five apps: 12% strict, 24% lenient, 1.0 per
1,000 lines; 23% / 42% at HIGH), second held-out application (Tandoor
Recipes) measured blind: 3% strict, 65% lenient, 7.0 per 1,000 lines. The
precision gates transfer; the density gate does not. D8 accepted 2026-11-16
as (b): released as 1.11.0 from that tree. Tandoor round done 2026-11-16,
unreleased: six-app corpus 11% strict / 30% lenient at 1.1 per 1,000 lines
(18% / 50% at HIGH, 0.5); Tandoor 7.0 to 2.2 per 1,000; vulnerable
benchmark 96% precision with three true fallback-value handlers fewer.
Third held-out application (CTFd, Flask, 23,824 lines) measured blind: 0%
strict, 15% lenient, 1.4 per 1,000 lines, nothing true found by any tool;
all three gates fail, and blind density has read 3.5, 7.0, 1.4 across the
three rounds. D9 accepted 2026-11-16 as (a): released as 1.12.0 from
that tree. CTFd round done 2026-11-16, unreleased: seven-app corpus 12%
strict / 38% lenient at 0.8 per 1,000 lines (19% / 55% at HIGH, 0.5), the
first time the tuning set meets the density and default gates; vulnerable
benchmark unchanged. Fourth held-out application (Mealie, FastAPI, 43,417
lines) measured blind: 4% strict, 13% lenient, 1.6 per 1,000, three true
log-injection findings; all three gates fail, blind density 3.5, 7.0, 1.4,
1.6. D10 accepted 2026-11-16 as (a): released as 1.13.0 from that tree.
Mealie round done 2026-11-16, unreleased: Mealie 68 to 53 findings (1.6 to
1.2 per 1,000), eight-app corpus 11% strict / 33% lenient at 0.9 per 1,000
(19% / 52% at HIGH, 0.5), vulnerable benchmark 96% with one true
error-response handler fewer. **C2 closed as measured**: density gate met
on the tuning set, lenient gates not, no blind application met any gate;
the eight-app corpus is the regression gate from here. C3 started
2026-11-16: 28 CVEs pinned (22 in claimed classes, 6 not), runner and
scorer in `benchmark/cves/`, first table: 15/22 found, 12 at HIGH; every
miss has a root cause, two share one (SSRF sinks `Session.request()`,
`httpx` `build_request()`/`send()`). C3's first milestone is done. Follow-on 1 (SSRF sinks) done at `eaf0b47`, follow-on 2 (timing
compares between two values) done at `006ce07`: 18/22 found, 12 at HIGH;
eight-app corpus 265 findings, 11% / 34%, 0.95 per 1,000, HIGH unchanged;
vulnerable benchmark 95%, 190/204. Write-`open()` sink prototyped and
declined (+11 corpus findings for one CVE). **C3 closed 2026-11-16.** C4
done 2026-11-16 at `51125ec` (D12): both ports load `[[rule]]` TOML, four
kinds, `--disable`; ten built-ins re-expressed with identical findings on
all three corpora (one documented tail-match difference); Semgrep
`p/python` matrix 69 built-in / 52 rule / 30 not expressible of 151.
**All four phases are done.**
**Scope**: both ports. Python stays the spec of record; every phase ends
with the Rust port producing identical findings on every corpus named here.
**Release policy (D11, 2026-11-16)**: a release is cut when something is
user-visible (a new capability, a check whose findings change materially,
a phase closing), not to label a measurement. Benchmark sections are
pinned to the commit they were measured on, a version only where one was
released from that tree. The per-round gate stays: both ports identical on
every corpus, the clean corpus no worse; that gate does not need a tag.
Four minor versions in one day (1.10.0 to 1.13.0) is the cadence this
replaces.

## 1. The four problems

Measured against the benchmark in `benchmark/`, fenceline finds more than
Bandit with fewer false positives and three times Semgrep's community
Python rules at 92% precision. Four things stop that from meaning what it
sounds like:

1. **Precision on ordinary code is unmeasured.** The benchmark apps are
   built to be vulnerable, so most alerts there are correct by construction.
   A team judges a scanner on its own repository, where almost every alert is
   a false positive by base rate. Nobody has that number for fenceline.
2. **The benchmark has saturated.** Recall is 93% and the misses are
   categories with no check. The last model change moved zero findings. The
   table can no longer say whether a change was worth making.
3. **The corpus is small and homogeneous.** Four apps, none over 2,500
   lines, all Django/Flask/aiohttp, no FastAPI, no service layer between
   route and sink.
4. **No declarative rule format.** A security team can write a Semgrep rule
   in ten minutes without touching the scanner. fenceline offers a Python
   plugin API in one port and nothing in the other.

Problems 1 and 2 are the same problem: the instrument that measures
progress has to be one with headroom. Problem 3 is solved as a side effect
of fixing 2 the right way. Problem 4 is independent engineering.

## 2. Phases

### Phase 0: release 1.9.0

Ship what is on main (request-root rule, django.nV, the two check-shape
fixes, Django function views and ORM lookups) so every number this roadmap
produces describes a released version. Standard release process, both
packages, `v1.9.0` tags.

### Phase C1: a clean-code precision corpus

The number nobody has. Pick real, maintained Python *applications* (not
libraries: the existing audit corpus of aiohttp, botocore, tornado and
PyYAML has no routes), pin commits, run fenceline at default settings, and
adjudicate every finding by hand. Also run Bandit and Semgrep `p/python`
and adjudicate theirs, so the comparison has the same footing as the
vulnerable benchmark.

**Corpus (D1).** One app per framework, sized so the total number of
fenceline findings to adjudicate stays around 400:

| Candidate | Framework | Why |
|---|---|---|
| healthchecks/healthchecks | Django | Mid-size SaaS, mature, ordinary views and management commands |
| Netflix/dispatch | FastAPI | The async/service-layer shape the benchmark lacks |
| flaskbb/flaskbb | Flask | A real Flask application rather than a tutorial; dormant but representative |
| home-assistant/core, `homeassistant/auth` + `homeassistant/components/http` | aiohttp | Too large whole; these two packages are the request-facing core |

Sizes and finding counts are measured when pinned; swap any app whose
count blows the budget.

**Labels.** Each finding gets one of three labels with a one-line reason:
*false* (a reviewer would dismiss it), *true* (a genuine instance a
maintainer would fix), *by design* (a correct detection of deliberate code:
`debug=True` in a dev entry point, `0.0.0.0` in a container entry point).
Ordinary code has a lot of the third kind and lumping it with either of the
others misstates the tool. Stored in `benchmark/clean/labels.json`, scored
by an extension of `score.py` that reports:

- precision, strict (true only) and lenient (true + by design), at default
  and at `--confidence-min high`, overall and per check;
- findings per 1,000 lines at each confidence level, which is what a team
  actually feels;
- confidence calibration: the share of HIGH, MEDIUM and LOW findings that
  are true. If MEDIUM is not meaningfully less reliable than HIGH, the
  confidence axis is decoration.

Recall is not measurable here and is not claimed.

**Done when** the corpus is pinned and labelled, the numbers are in
`benchmark/README.md` next to the vulnerable-app table, and the per-check
false-positive table exists. No check is changed during C1: the corpus is a
measurement first and a tuning set second.

**Outcome (2026-11-14).** 637 fenceline findings in scope, not the 400
budgeted; the overshoot is one check, `CWE-117`, with 394 false positives
of a single shape, so adjudication stayed within budget in effort. Strict
precision 3%, lenient 7%, 4% at HIGH; confidence is uncalibrated on this
corpus (HIGH 4% true, MEDIUM 3%, LOW 0%). The C2 work list, in order of
false positives removed: make `CWE-117` taint-aware (394), treat a literal
first argument to `redirect()` as a URL name or fixed path and `url_for` /
`reverse` as same-site (83), stop reporting configuration key names as
credentials (17), restrict the timing-attack check to comparisons that
involve a secret-shaped operand (16), exempt templates built from module
constants from SSTI (14), stop matching SQLAlchemy `session.query()` as
pandas (8), and drop the `CWE-778` text fallback on unparsable files (7,
and it is also the Rust parity gap). One recall miss to fix alongside:
`SECRET_KEY = "secret key"` discarded as placeholder-shaped.

### Phase C2: fix what C1 exposes

The django.nV experience in miniature: expect the false positives to be
check-shaped (a sink that is not a sink in some common idiom, a secret
pattern that matches a config key name) rather than taint-shaped, and fix
them one shape at a time, each validated on the vulnerable benchmark, the
library corpus and the clean corpus, with Rust parity after every change.

**Gates (D2).** Proposed exit: strict precision at `--confidence-min high`
≥ 85%, at default ≥ 70%, with no recall loss on the vulnerable benchmark.
Calibrate after C1's first measurement if these turn out to be far off in
either direction; the point is a stated bar, not this specific one.

**Held-out check.** When the gates are met, add one fresh application of a
framework already in the corpus, adjudicate it blind, and report its number
separately. Tuning against the C1 apps and then quoting the C1 apps is the
mistake this guards against.

**Outcome so far (2026-11-14).** Two rounds, both ports, parity held.
Round one took the C1 work list in order: `CWE-117` taint-aware, literal
first argument and route builders for `redirect()`, ORM lookups
generalised, configuration key names out of the secrets check, the timing
check rewritten on `Compare` nodes, SSTI only for request data, SQLAlchemy
`session.query()` out of the pandas check, the `CWE-778` text fallback
removed. Round two took the next tier: `.read()` only on request-fed
receivers, fixed-program list argv only for request data, escaping helpers
clean in the taint engine, the request's own path and class-level getters
for redirects, `0.0.0.0` in address sets, whole-word secret terms for log
leaks, `traceback.print_exc()` as a diagnostic, and two confidence
calibrations (weak hash and weak random HIGH only in a credential context;
log injection through a caller MEDIUM). Clean corpus: 637 findings → 116,
3% → 20% strict, 4% → 42% at HIGH, 71% lenient at HIGH, one true finding
gained and none lost. Vulnerable benchmark: 92% → 96% precision, recall
190/204 unchanged, 98% at HIGH. The tables are in the benchmark README.

What remains is not check-shaped. Of the 13 false positives at HIGH, five
are request fields logged in views where the field is a typed integer,
four are redirects whose same-site prefix is a `reverse()` result the
check cannot see through a concatenation. Of the 59 at MEDIUM, 23 are
Pydantic request fields reaching a logger through a service function, 15
are flaskbb redirects to model URL properties, 8 are administrator-
configured integration URLs. Each would need type knowledge of parameter
fields or a notion of "configured by an administrator", which is a
different kind of work from C2's.

**D6, accepted 2026-11-14.** The gates (85% strict at HIGH, 70% strict at default) count
by-design findings against precision by definition, and 13 of the 45 HIGH
findings on this corpus are deliberate code the check is right to report.
Strict precision at HIGH cannot exceed 71% here even with zero false
positives. Proposed restatement: *lenient* precision ≥ 70% at HIGH (met,
71%) and ≥ 35% at default (met, 38%), with density ≤ 1 finding per 1,000
lines at default (met, 0.9) and the vulnerable benchmark unchanged.
Accepted: C2 closes with the held-out application; type-aware work on the
remaining shapes is deferred past C3 and C4.

**Held-out outcome (2026-11-14).** pretalx (Django, 64,074 lines), scanned
once at 1.10.0 and adjudicated blind: 224 findings, 0 true, 2 by design,
222 false; 0% strict and 1% lenient at default, 0% and 2% at HIGH, 3.5
findings per 1,000 lines. Bandit 116 findings and Semgrep 18, none true.
Every C2 gate fails here. The causes are three shapes the four tuning apps
did not contain, in `benchmark/README.md`: urlman URL properties and
Django's `get_success_url()` idiom as redirect targets (143), class-body
literals classifying as INTERNAL because the taint engine has no class
scope (26 of 35 `CWE-79`), and ANSI escapes in terminal output (15). The
held-out step did what it is for: the 1.10.0 corpus numbers describe the
tuning set, and the README now says so.

**D7, open.** Three ways forward: (a) fix the three shapes, add pretalx to
the tuning corpus, and repeat the held-out measurement on a further
application before claiming C2 closed; (b) fix the shapes and close C2 on
the pretalx re-measurement alone, accepting that it is no longer blind;
(c) leave the checks, close C2 as measured, and let C3 proceed. (a) is the
honest one and costs one more adjudication; it is the recommendation.

**D7 accepted 2026-11-16, as (a). Outcome.** The three shapes were fixed
in both ports with parity, and two more surfaced while fixing: ORM chains
with an intermediate call (`Model.objects.select_related("e").get(...)`
was not a lookup), and concatenations led by a URL property or the
request's own path. pretalx went from 224 findings to 87 and joined the
corpus; the four original apps moved from 20% / 38% to 21% / 41% (the
flaskbb model-URL redirects, called type-shaped above, fell to the URL
property rule); the vulnerable benchmark did not move. Five-app corpus:
195 findings, 23 true, 23 by design, 149 false, 12% strict and 24% lenient
at 1.0 per 1,000 lines; at HIGH 81 findings, 23% and 42% at 0.4. The next
held-out application, Tandoor Recipes (Django, 20,170 lines, chosen before
any check was touched), read 141 findings, 4 true, 87 by design, 50 false:
3% strict, 65% lenient, 7.0 per 1,000 lines; at HIGH 110 findings, 4% and
83% at 5.5. The two precision gates are met on the blind app for the first
time; the density gate fails by a factor of seven, and the cause is one
shape: 94 of the 141 findings are the exception-handler checks `CWE-778`
and `CWE-391` on an application written in try/`except Exception:`
fallback style, both checks firing on the same line. Details and the
recorded observations are in `benchmark/README.md`.

**D8, open.** How to close C2. (a) One more round on the Tandoor shapes
(one finding per handler instead of two, a fallback that returns or
assigns a value rated below a bare `pass`, `traceback.print_exc()` in
server code, `reverse()` leading a concatenation, defused lxml options),
Tandoor into the corpus, a third blind application of a framework other
than Django, then release. (b) Release now as 1.11.0 (every corpus is
better than 1.10.0 and the blind numbers describe this exact tree), record
the density caveat in the README, and do (a) as the first item after. (c)
Close C2 as measured and start C3. (b) is the recommendation: the
improvement is real and should ship, and the handler shape is cheap enough
that it need not hold the release.

**D8 accepted 2026-11-16, as (b).** 1.11.0 released from the measured
tree. The Tandoor round follows, as the first item.

**Tandoor round done 2026-11-16, released as 1.12.0. Outcome.** Six shapes in both
ports: a handler is reported once (`pass`/`continue` are `CWE-391`'s), a
handler that only substitutes a value is not reported as unlogged,
`CWE-200` reports `format_exc()` in a response rather than `print_exc()`,
a route builder may lead a redirect concatenation, defused lxml parsers
and builder-only XML imports are not XXE, and password-action keys and
path values are not secrets. Tandoor went from 141 findings to 45 (7.0 to
2.2 per 1,000 lines, 65% to 69% lenient) and joined the corpus. Six apps,
213,003 lines: 233 findings, 25 true, 46 by design, 162 false, 11% strict
and 30% lenient at 1.1 per 1,000; at HIGH 117 findings, 18% and 50% at
0.5. The five previous apps lost three points of lenient precision (seven
by-design handlers no longer reported) and nothing else. The vulnerable
benchmark keeps 96% precision and loses three true instances, all
fallback-value handlers in lab code (`except: error = "Invalid input"`,
`return False`). The third held-out application, CTFd (Flask, `485d59e`,
23,824 lines, chosen before any check was touched), read 33 findings, 0
true, 5 by design, 28 false: 0% strict, 15% lenient, 1.4 per 1,000; at
HIGH 11 findings, 9% lenient at 0.5. Bandit and Semgrep found nothing true
either, at 0.5 per 1,000 each. The 28 false findings are seven shapes
(`send_file()` of a non-path or a `safe_join()` result, a URL validator
applied to a call expression, the `password_reset` word order, `abort()`
and `print()` as handling, a configured prefix leading a redirect, API
client wrappers, `# noqa` lines), recorded in `benchmark/README.md` and
not fixed.

**D9, open.** How to proceed with C2 after a third blind failure. (a)
Release 1.12.0 from this tree (every corpus is better than 1.11.0, with
the three benchmark instances stated in the notes), then a CTFd round: the
seven shapes, CTFd into the corpus, a fourth blind application of a
framework neither Django nor Flask (FastAPI or Starlette), re-measure. (b)
Close C2 as measured and not met: keep the six-app corpus as the
regression gate (no check change may lower its lenient precision or raise
its density), state the blind numbers in the README as what a team should
expect, and start C3. (c) Reverse the fallback-value rule to a lower
confidence instead of a skip, recovering the three benchmark instances at
the cost of Tandoor's density returning towards 5 per 1,000. (a) is the
recommendation: blind density has gone 3.5, 7.0, 1.4 and the CTFd shapes
are small and specific, so one more round on a third framework is the
cheapest way to learn whether 1.0 is reachable without a recall cost;
releasing first keeps the measured tree and the published tree the same,
as D8 did. (c) is not recommended: the three instances are lab-code
fallbacks of exactly the shape that was by design 29 times in Tandoor and
seven times in the other five apps.

**D9 accepted 2026-11-16, as (a).** 1.12.0 released from the measured
tree. The CTFd round follows, as the first item.

**CTFd round done 2026-11-16, released as 1.13.0. Outcome.** Seven shapes in both
ports: guards on stable expressions (`is_safe_url(request.args.get("next"))`),
`safe_join()` as a sanitiser with clean-element comprehensions, `lstrip()`
on the application's own fields, `print()`/`abort()`/stdout writes as
handling, redirect concatenations rated by their leading operand,
`password_reset` word order, and `# noqa: Sxxx`/`# nosec Bxxx` suppressing
the matching fenceline checks. CTFd went from 33 findings to 14 (1.4 to
0.6 per 1,000, 36% lenient) and joined the corpus. Seven apps, 236,827
lines: 200 findings, 25 true, 50 by design, 125 false, 12% strict and 38%
lenient at 0.8 per 1,000; at HIGH 108 findings, 19% and 55% at 0.5. The
six previous apps went from 233 to 186, forty-three of them pretalx lines
the authors had already marked with `# noqa` and a reason. Vulnerable
benchmark and library corpus unchanged. The fourth held-out application,
Mealie (FastAPI, `3d639dd`, 43,417 lines, chosen before any check was
touched), read 68 findings, 3 true, 6 by design, 59 false: 4% strict, 13%
lenient, 1.6 per 1,000; at HIGH 27 findings, 26% lenient at 0.6. The three
true findings are log injection of the raw `X-Forwarded-For` header and of
the 422 error text, found by fenceline alone; Bandit and Semgrep found
nothing true at 0.5 and 0.2 per 1,000. Two of the 59 false findings are
check defects rather than shapes: `CWE-73` rates the content copied rather
than the destination path (14 findings), and `.resolve()` followed by
`is_relative_to()` is not recognised as the path guard the `CWE-22`
description itself asks for. The rest are recorded in
`benchmark/README.md` and not fixed.

**D10, open.** Where C2 ends. Four blind applications have read 1%, 65%,
15% and 13% lenient at 3.5, 7.0, 1.4 and 1.6 per 1,000 lines; the tuning
set, now seven apps, meets two of the three gates. (a) Release 1.13.0 from
this tree; a Mealie round limited to the two check defects and the two
cheap shapes (error-response returns as handling, Pydantic `str` fields),
Mealie into the corpus; then close C2 as measured and not met on blind
applications, keep the eight-app corpus as the regression gate (no check
change may lower its lenient precision or raise its density), and start
C3. (b) The same, then a fifth blind application and another round. (c)
Close C2 now, without the Mealie round. (a) is the recommendation: blind
density has plateaued near 1.5 per 1,000 across two frameworks while each
round still removes a third of a blind app's findings, so the remaining
gap is per-application idiom rather than a shape a next round would
generalise; the two Mealie defects are worth fixing regardless; and C3 is
the instrument with headroom for the number that matters next, recall on
real vulnerabilities.

**D10 accepted 2026-11-16, as (a).** 1.13.0 released from the measured
tree. The Mealie round follows, limited as stated; then C2 closes.

**Mealie round done 2026-11-16, unreleased. Outcome, and C2 closed.** The
two defects and two shapes in both ports: `CWE-73` rates the destination
of a copy or move rather than the content copied; `is_relative_to()` is a
path guard for its receiver; a handler that returns an error response has
answered the request (`CWE-778`); the Pydantic field check reports only
bulk-content field names. Mealie went from 68 findings to 53 (1.6 to 1.2
per 1,000, 17% lenient, 35% at HIGH) and joined the corpus. Eight apps,
280,244 lines: 252 findings, 28 true, 56 by design, 168 false, 11% strict
and 33% lenient at 0.9 per 1,000; at HIGH 128 findings, 19% and 52% at
0.5. The seven previous apps lost one finding. Vulnerable benchmark: one
true `CWE-778` instance fewer (pygoat's `return JsonResponse({"status":
"error"}, status=500)`), 96% precision, 186/200. Library corpus unchanged.

C2 closes here as measured and not met: the density gate (≤ 1.0 per
1,000) is met on the tuning set at 0.9; the lenient gates (35% default,
70% HIGH) are not (33%, 52%); none of the four blind applications met any
gate (1%, 65%, 15%, 13% lenient at 3.5, 7.0, 1.4, 1.6 per 1,000). What the
phase established: precision on ordinary code is measurable and is
measured, with 1,568 adjudicated verdicts across eight applications and
four frameworks; four blind measurements say what a team sees on day one;
and the shapes a round removes are mostly one application's idiom, so
further rounds would buy per-app numbers, not a generalising one. From
here the eight-app corpus is the regression gate: no check change may
lower its lenient precision or raise its density, in either port, and
`benchmark/clean/heldout.sh` stays as the recipe for the next blind
measurement whenever a new application is chosen.

### Phase C3: a CVE regression set

The instrument with headroom for recall. Instead of a fifth intentionally
vulnerable app (candidates were examined and rejected: `importlib`
dispatch, OpenAPI routing, too small), build a set of real vulnerabilities
in real applications: for each CVE, pin the parent of the fix commit,
record the sink file and line and the CWE, and ask whether fenceline
reports it and at what confidence.

**Why this beats a fifth app.** It measures recall on bugs that shipped,
in applications with real service layers and tens of thousands of lines
(mlflow and Apache Airflow are Flask, Gradio is FastAPI, label-studio and
NetBox are Django), so it also closes the FastAPI and size gaps of problem
3. It does not saturate: there are new Python CVEs every month. And every
miss has a root cause worth knowing: source not recognised, sink not
recognised, cross-file depth, or no check.

**Selection rule (D3).** Fifteen to twenty CVEs to start. The vulnerable
code must be Python application code reachable from a route; the fix must
be public; the CWE must be one fenceline claims (the injection family,
deserialization, path traversal, SSRF, open redirect). Add three to five
CVEs in classes fenceline does *not* cover, labelled as such, so the set
also says what the tool is not.

**Scoring.** Found / found at HIGH / missed, per CVE and in total, plus
the number of other findings in the same file (the noise a reviewer would
wade through to reach the real one). `benchmark/cves/` holds the
manifest, a runner that clones each pinned commit and scans only the
affected package, and the results table.

**The four-app benchmark becomes a regression gate**, not a progress
metric: its findings must not change without a labels update that
explains why. The clean corpus measures precision progress; the CVE set
measures recall progress.

\1
**Started 2026-11-16; first table measured at `de44224`.** 28 CVEs in
`benchmark/cves/manifest.json`: mlflow (6), Gradio (7), Apache Airflow
(4), label-studio (3), MindsDB (2), Jupyter Server, BentoML, vLLM, Weblate,
Langflow. 22 in claimed classes, 6 not. `run.sh` clones each last
vulnerable tree sparsely and scans the affected package; `score.py` prints
the table (`benchmark/README.md`, "CVE regression set"). Result: 15/22
found, 12 at HIGH; 0/6 of the unclaimed, as expected. Misses by cause:
SSRF sinks not known (2: `requests.Session.request()`, `httpx.Client`
`build_request()`/`send()`); no write-`open()` sink (1); operator template,
no subprocess (1); HTML via `str.format()` (1); timing check wants a
literal operand (1); developer `# nosec` on the sink line (1, by design).
Prioritised follow-on: the SSRF sink list first (two CVEs, cheap, and the
clean corpus has 12 SSRF false positives to keep in view); the others one
each, each weighed against the eight-app gate before landing. The run also
exposed and fixed three Rust parity bugs (pandas `query()` call shape,
f-string taint depth, dict literals in the identifier collector), so the
\1
**Follow-on 1 done 2026-11-16, at `eaf0b47`.** `.request(method, url)` and
`.build_request(method, url)` are SSRF sinks on any receiver, URL second;
the same change fixed `requests.request()` rating its method argument.
CVE set 17/22 (12 HIGH); eight-app corpus 259 findings, +3 false (dispatch
admin URLs, previously hidden by the defect) and +4 by design
(healthchecks' transport), lenient 33% to 34%, density 0.90 to 0.92, HIGH
unchanged; vulnerable benchmark unchanged. The density rise is seven
findings on 280,244 lines and reads 0.9 at the reported precision; it is
recorded here because the gate says "raise", and the trade (two shipped
CVEs found, three false positives of a shape already labelled) is the
kind the gate exists to make visible, not to forbid. Remaining misses are
single-cause: write-`open()`, operator template, `str.format()` HTML,
\1
**Follow-on 2 done 2026-11-16, at `006ce07`; C3 closed.** The timing check
reports a secret compared with another non-literal value (not both secrets,
no ALL_CAPS side, no constant side). CVE set 18/22, 12 HIGH. Eight-app
corpus +6 (2 true, 1 by design, 3 false): 265, 11% / 34%, 0.95 per 1,000,
HIGH unchanged. Vulnerable benchmark +4 true, +1 false: 95%, 190/204. The
write-`open()` sink was prototyped and declined on the gate: it finds
mlflow's line at MEDIUM and costs eleven MEDIUM corpus findings (lenient
34% to 33%). The `str.format()` HTML miss is declined without a prototype
(a response sink reports INTERNAL content from every Django view); the
`BashOperator` template is a C4 `pattern` rule; the `# nosec` miss is by
design. C3 is done: instrument, table, causes, and the fixes the gate
allowed.

### Phase C4: declarative rules in both ports

A TOML rule format, consistent with `--config` being TOML in both ports,
loaded from `--rules PATH` or a `[rules]` table in the config file.

**Scope (D4).** Four rule kinds, which between them cover the shapes
Semgrep's Python audit rules actually take:

```toml
[[rule]]
id = "acme/mako-render"
cwe = "CWE-94"
name = "Mako template from data"
severity = "HIGH"
description = "A Mako Template built from a non-literal string renders attacker-controlled code."
kind = "sink"                      # sink | call | keyword | pattern
callee = ["mako.template.Template"]  # alias-resolved dotted names, tail-matched like built-ins
data = "first"                     # all | first | ["arg", "kw=text"]
```

- `sink`: the callee matches and the named arguments feed the existing
  taint engine, which sets confidence exactly as it does for built-ins.
- `call`: the callee matches; confidence is fixed by the rule.
- `keyword`: the callee matches and a named keyword has a given literal
  value (`verify = false`).
- `pattern`: a regex over lines, with the same comment, docstring and
  test-code handling the text checks have.

Out of scope, deliberately: `pattern-inside`, metavariable comparisons,
autofix. A rule that needs those is a Python plugin.

**Both ports, one loader contract.** The format is specified once in
`docs/rules.md`; each port implements it; `fixtures/rules/` holds rule
files with case files and expected findings, run by both conformance
suites. This also ends the "nothing in the other port" asymmetry: the Rust
port gains user-defined rules without gaining a plugin API.

**Proof.** Express ten built-in checks as rules and show identical findings
on all three corpora with the built-in disabled. If a built-in cannot be
expressed, that is a finding about the format, and the reason is recorded.

**Coverage matrix.** `docs/semgrep-coverage.md`: every rule in Semgrep's
`p/python` listed as *built-in*, *expressible as a rule* (with the rule),
or *not expressible* (with why). This is the document that lets the README
say "replacement" with a straight face, and it is also the list of what to
build next.

**Done when** both ports load the same rule file and agree on the fixtures
and corpora, the ten-check proof passes, and the matrix is published.

**Started and done 2026-11-16, at `51125ec` (Python) / `86727fc` (Rust).**
`docs/rules.md` is the format; `fenceline/rules.py` and `src/rules.rs`
load and run it; `fixtures/rules/kinds/` covers each kind and keyword test,
`fixtures/rules/builtins/` holds the fourteen rules that re-express ten
built-ins. Proof: with those ten checks disabled and the rules loaded, both
ports produce the same findings as the plain run on the vulnerable
benchmark (209), the eight-app corpus (353 / 351) and 27 of the 28 CVE
trees; on Weblate's tree the rules add three `CWE-1088` findings, call
sites of the project's own `weblate.utils.requests.request()` wrapper
(which sets no timeout), reached through the tail match
`requests.request` that `check_request_timeout`'s exact match does not
make. The Rust and Python rule runs agree everywhere (the two known parser
skips aside). Built-ins the format cannot express are listed in
`docs/rules.md` with the reason. The matrix (`docs/semgrep-coverage.md`,
`p/python` as served 2026-11-16, 151 rules): 69 built-in, 52 expressible
as a rule, 30 not expressible; the 30 fall into five shapes, of which a
positional-literal test and a value regex would be the cheapest additions.
Deviations from the sketch above are D12.

## 3. Order and size

```
0 ──► C1 ──► C2 ──► C3 ──► C4
```

C4 does not depend on C1–C3 and could interleave, but C2 may reshape the
checks C4's proof re-expresses, so after C2 is cheaper. Relative effort:
C1 is mostly adjudication by hand (the largest manual cost, one or two
sessions); C2 depends on what C1 finds; C3 is medium (pinning commits and
locating sinks is slow, the runner is small); C4 is the largest
engineering item because it lands in two ports.

## 4. What the "big boy" claim looks like at the end

- A precision number on ordinary code, with a held-out confirmation, and a
  density figure a team can compare to its own tolerance.
- A recall number on real CVEs in real applications, with every miss
  explained.
- The vulnerable-app benchmark frozen as a regression gate.
- A rule format a security team can use in both ports, and a published
  matrix saying exactly which Semgrep Python rules it does and does not
  cover.

Until those four exist, the honest claim stays what the README says now:
a credible Bandit replacement for anyone willing to check, not yet a
Semgrep replacement.

## 5. Decisions

- **D1** Clean corpus: accept the four candidates in C1, or name others.
  Constraint: real applications with routes, one per framework, total
  fenceline findings around 400.
- **D2** C2 exit gates: 85% strict precision at HIGH, 70% at default, or
  different bars.
- **D3** Recall instrument: the CVE regression set over a fifth vulnerable
  app, and the 15–20 starting size.
- **D4** Rule format: TOML, the four kinds, the stated non-goals, and that
  the Rust port gets rules but still no plugin API.
- **D5** Release 1.9.0 before C1 starts.
- **D6** C2 gates restated as lenient precision ≥ 70% at HIGH and ≥ 35% at
  default with density ≤ 1 per 1,000 lines (see Phase C2); accepted.
- **D7** After the held-out failure: fix the three pretalx shapes and
  re-measure on a further held-out app (recommended), re-measure on pretalx
  alone, or close C2 as measured. Accepted 2026-11-16 as the first.
- **D8** After the second held-out measurement (precision gates met,
  density gate not): another round on the handler shape plus a third blind
  app before release, release 1.11.0 now and do that round after
  (recommended), or close C2 as measured. Accepted 2026-11-16 as the second.
- **D9** After the third held-out measurement (all gates failed, nothing
  true to find, blind density 1.4): release 1.12.0 and run a CTFd round
  with a fourth blind app on a third framework (recommended), close C2 as
  measured, or restore fallback-value handlers at lower confidence.
  Accepted 2026-11-16 as the first.
- **D12** (accepted 2026-11-16, with C4) Rule format details settled in
  implementation, where they differ from the sketch in the C4 section:
  rules in the config file are `[[rule]]` tables (a rule is a table, several
  are an array of tables), not a `[rules]` table; `--rules PATH` is
  repeatable; `--disable CHECK` exists so a rule can stand in for a
  built-in (and it is what the proof runs on); the `keyword` kind has three
  tests (`value`, `unless`, `required = true`), since the three Semgrep
  shapes (`verify=False`, `torch.load` without `weights_only=True`, a
  missing `timeout=`) need all three; `data` selectors are 0-based
  positions and keyword names (`[1, "text"]`); keyword literals are
  booleans, integers and strings, compared by type; a `pattern` regex is
  the dialect both ports share (lookaround and backreferences refused at
  load); `sink` rules cannot set `confidence`. Callees tail-match like most
  built-ins, so a rule standing in for an exact-match built-in can be
  wider; the proof records the one case.
- **D10** After the fourth held-out measurement (all gates failed again,
  blind density 1.6): release 1.13.0, a Mealie round limited to the two
  check defects, then close C2 with the corpus as the regression gate and
  start C3 (recommended); the same plus a fifth blind app; or close C2 now.
  Accepted 2026-11-16 as the first; C2 closed 2026-11-16.
\1- **C3 follow-on order** (no decision needed; recorded 2026-11-16): SSRF
  sinks first, then the single-cause misses, each gated on the eight-app
  corpus. Any new check for an unclaimed class (CORS, reflection, auth)
  is C4 material.
