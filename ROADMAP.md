# Roadmap: from "beats Bandit on vulnerable apps" to "a scanner a team turns on"

**Status**: D1–D5 accepted 2026-11-14. Phase 0 done (1.9.0 on PyPI and
crates.io, `v1.9.0` tags). C1 done 2026-11-14: `benchmark/clean/` with the
four accepted apps, 872 verdicts, scorer and runner; result 3% strict
precision at 1.9.0 (4% at HIGH), Bandit 5%, Semgrep 0%. C2 two rounds done
2026-11-14 and released as 1.10.0: 20% strict / 38% lenient at default,
42% / 71% at HIGH, vulnerable benchmark 96% precision with no recall
change. D6 accepted 2026-11-14: the C2 gates are the lenient ones stated
there, and they are met; the held-out application is the remaining C2
step.
**Scope**: both ports. Python stays the spec of record; every phase ends
with the Rust port producing identical findings on every corpus named here.

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

**Done when** the manifest and runner exist, the first table is in the
README, and every miss has a one-line root cause. Fixes for the misses are
their own follow-on work, prioritised by how many CVEs share a cause.

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
