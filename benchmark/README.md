# Benchmark: fenceline vs Bandit vs Semgrep

A labelled, reproducible comparison on three intentionally vulnerable Python
web applications. The point is not a leaderboard but a measurement that can
be re-run after every change to see which gaps closed and what it cost in
false positives.

## Corpus

| App | Framework | Commit | Python lines |
| --- | --- | --- | --- |
| [pygoat](https://github.com/adeyosemanputra/pygoat) | Django + Flask labs | `2aa4cc1` | 8118 |
| [vulpy](https://github.com/fportantier/vulpy) | Flask | `5249cc8` | 2373 |
| [dvpwa](https://github.com/anxolerd/dvpwa) | aiohttp | `4a8f4a4` | 674 |

Tools: fenceline 1.7.0 for the current table and 1.6.0 for the baseline (this
repository; the Python and Rust ports give identical findings), Bandit 1.9.4 with default settings, Semgrep 1.185.0 with the
community `p/python` ruleset. Test files (`tests.py`, `test_*.py`, `tests/`),
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
tool is rewarded for reporting the same bug three times.

Two consequences to keep in mind. A weakness none of the three tools reports
is invisible (the path traversal at `ssrf_lab/app.py:21` is one such). And
because the apps are built to be vulnerable, most findings are true, so the
benchmark is better at exposing recall gaps than at estimating a tool's
false-positive rate on ordinary code.

## Results

### Unreleased main (Phase B0, 2026-11-13)

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
