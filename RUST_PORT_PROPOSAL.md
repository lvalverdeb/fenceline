# Proposal: A Rust Port of Tripwire

**Status**: Draft, unspiked. Nothing built yet — this is a sketch for discussion, modeled on [`spaghetti`'s own port proposal](../spaghetti/RUST_PORT_PROPOSAL.md), which went from proposal to a finished, conformance-verified `spaghetti-rs` (674/674 issues identical to Python). That project is the template for structure and phasing here, not a reason to assume this one is equally low-risk — §7 lays out where tripwire's risk profile actually differs.
**Author**: Luis Valverde, 2026-07-20
**Companion doc**: none yet — tripwire has no SDD.md; §4 below is this proposal's own inventory of current shape.

## 1. Summary

Build a Rust implementation of `tripwire` alongside the existing Python one, not instead of it, exactly on the `spaghetti`/`spaghetti-rs` model: Python stays the spec of record and the easiest place to prototype a new check; Rust ships a single static binary with no interpreter dependency, for dropping into someone else's CI or pre-commit hook.

tripwire is arguably a **better-shaped** port candidate than spaghetti was: it's about half the size (2,791 lines vs. spaghetti's ~3,000 of implementation, but with no cross-file/whole-package analysis at all — every one of its 52 checks operates on a single file in isolation), and its only non-stdlib runtime dependency is one ten-line helper (`boti.core.is_secure_path`, a `Path.resolve()`/`is_relative_to()` sandbox check — trivial to reimplement natively, not something to wrap or FFI into). The real open questions are narrower and more concrete than spaghetti's were: two specific regex patterns use lookahead syntax Rust's `regex` crate doesn't support (§7.1), and the tool's actual differentiator — a hardcoded CVE table — is a data-maintenance problem no port changes (§7.3).

## 2. Why

- **Zero-dependency distribution**, same rationale as spaghetti-rs: running `tripwire` today requires a Python 3.13+ environment (`tomllib` is used directly, so 3.11+ at minimum) plus `boti` as a runtime dependency pulled in for one function. A static binary drops into any CI image or pre-commit hook with nothing else installed.
- **Speed at scale** — less central here than for spaghetti, since tripwire's checks are simpler (mostly single regex passes over lines, not multi-pass AST complexity scoring), but still real: 52 checks × every file, each running `ast.parse` for the 12 AST-based checks even when just doing a line scan would do, adds up on large external codebases the way it does for spaghetti's `--config`/`--package` use case.
- **A clean-shaped tool to port.** No cross-file analysis, no import graphs, no structural-similarity scoring — the single hardest part of the spaghetti port (§7.2/7.3 there: `ast.dump()`-equivalent structural hashing, a from-scratch Ratcliff/Obershelp reimplementation because the `similar` crate's ratio diverged from `difflib`'s) simply doesn't exist here. Every check has the shape `(path, lines, tree) -> list[Finding]` and touches only its own file.
- **Reuses proven infrastructure.** `spaghetti-rs` already answered "does `rustpython-parser` parse this workspace's real Python cleanly" (111/111 files, 0 failures) and already has `regex`, `toml`, `serde_json` as dependencies. This isn't a port starting from zero-crate-experience.

## 3. Non-goals

- **Not deprecating the Python version.** It remains canonical — same framing as spaghetti (§5 there).
- **Not trying to make the Rust build own the CVE table.** The `vuln_deps` list in `manifest_checks.py` (currently ~15 hardcoded CVE entries) is a curated dataset, not logic — see §7.3 for where it should live so both implementations read the same data instead of maintaining two copies.
- **Not chasing all 52 checks in one phase.** Same reasoning as spaghetti §3: ship the easy majority first, grow into the two lookahead-dependent checks (§7.1) once a resolution for those is chosen.

## 4. Current shape (what's being ported)

| Area | File | LOC | Port complexity |
|---|---|---|---|
| AST-based checks (12 rules) | `checks/ast_checks.py` | 635 | Low-medium — walks a handful of `ast.Call`/`ast.ExceptHandler`/`ast.Assign` node types; no exotic AST features beyond what spaghetti-rs already handles |
| Text/regex-based checks (~38 rules) | `checks/text_checks.py` | 1,230 | Low, with two exceptions — pure line-based regex; two patterns use lookahead (§7.1) |
| Manifest checks (2 rules: CVE scan, unbounded pins) | `checks/manifest_checks.py` | 147 | Low — line-based regex over `pyproject.toml`/`requirements.txt`/`Pipfile` text, not real TOML parsing (no `toml` crate dependency needed here, unlike spaghetti's workspace-root walk) |
| Shared AST/text helpers | `ast_helpers.py` | 174 | Low — logging-call detection, nested-scope-aware exception-handler walk, attribute-chain flattening |
| Data model | `models.py` | 23 | Trivial — one dataclass (`Finding`) plus a severity-ordering dict |
| Report rendering (text + JSON) | `reporting.py` | 162 | Low — string formatting, ANSI color codes, a static CWE-reference block |
| File discovery/reading/parsing | `scanner.py` | 67 | Low — `rglob("*.py")`, UTF-8-tolerant read, a self-scan exclusion list (§7.4) |
| Workspace/package registry | `config.py` | 72 | Low — same upward-walk-for-`[tool.uv.workspace]` pattern as spaghetti's `_find_workspace_root`, already solved there (spaghetti §7.4) |
| CLI + orchestration | `cli.py` | 144 | Low-medium — `argparse`, `--package NAME=PATH` parsing with sandboxing, single-threaded scan loop (no `ProcessPoolExecutor`/`Agent` to simplify away — see §4.2) |
| Test suite | `tests/test_tripwire.py` | 151 / 12 tests | Thin relative to the 52 checks — see §5 |

Total: ~2,650 lines of implementation (excluding `__init__.py`/registry wiring), 52 checks, 12 tests.

### 4.1 Checks are uniformly simple — no tier structure needed

Unlike spaghetti's "30 easy + 3 hard" split, tripwire has no rule that needs anything beyond a single-file, single-pass scan. The AST checks (`check_pickle`-adjacent ones needing real parsing, e.g. `check_eval_exec`, `check_torch_load`, `check_pandas_eval`) still just walk one file's tree looking for specific `ast.Call`/`ast.Attribute` shapes — same tree-walk shape spaghetti-rs's per-file checks already use. There's no equivalent of spaghetti's `import-cycle` (needs a package-wide graph) or `sync-async-duplication` (needs cross-function text similarity).

### 4.2 No concurrency simplification to win

spaghetti's port got `rayon::par_iter()` "for free" by dropping Python's `ProcessPoolExecutor`/`Agent` multiprocessing dance (spaghetti §4.3) — but tripwire's `cli.py` was already a plain sequential `for path in sorted(...)` loop with no multiprocessing to begin with. The Rust port can still add `rayon::par_iter()` over files (checks are pure functions with no shared mutable state), but this is a genuine new capability, not a simplification of something already there — worth flagging as real, not automatic, scope.

### 4.3 One piece of non-Python-specific logic to reimplement: `is_secure_path`

`boti.core.is_secure_path(target, allowed_dirs)` is `config.py`'s and `cli.py`'s only import from outside tripwire itself — a directory-traversal sandbox check (`Path(target).resolve().is_relative_to(Path(allowed).resolve())` for each allowed dir). Trivial in Rust (`std::path::Path::canonicalize` + a prefix check), and since it's ~10 lines with no Python-specific behavior, this is copy-the-logic-once territory, not a dependency to design around.

## 5. Keeping two implementations honest: reuse spaghetti's conformance-suite design, don't reinvent it

spaghetti's proposal (§5 there) already worked out the right mechanism for this exact problem — a shared golden-fixture corpus (`{input.py, expected.json}` pairs), Python as spec of record, message text allowed to differ but `cwe_id`/`severity`/`line` must match exactly, new rules land as a fixture with no implementation before either language builds it. That design transfers directly; no need to re-derive it here.

What's different for tripwire, and worth flagging rather than assuming away:

- **The existing Python test suite is much thinner relative to rule count than spaghetti's was.** spaghetti had 152 tests across 36 rules (existing tests were largely already "one small source snippet, assert on the resulting Issues" — cheap to extract into fixtures). tripwire has 12 tests across 52 checks — most checks currently have **no** existing unit test to extract a fixture from at all. This means the tripwire fixture corpus is mostly a **build-from-scratch** effort, not a mine-the-existing-suite effort, and should be budgeted as such — likely the single largest chunk of pre-port work, done in Python first since it strengthens the Python tool regardless of whether the Rust port proceeds.
- **The CVE/version table is data, not logic** (§7.3) — it needs its own place in the fixture-adjacent shared-state story: a `vuln_deps.toml`/`.json` both implementations load, rather than a fixture *per entry* (a fixture only needs to assert the *matching logic* works, not re-litigate each of the ~15 CVE entries independently).

## 6. Proposed Rust architecture

Reuses spaghetti-rs's already-validated choices wherever the same problem recurs; only rows tripwire needs that spaghetti didn't are new.

| Concern | Python | Rust choice | Why |
|---|---|---|---|
| Python parsing → AST | `ast` (stdlib) | `rustpython-parser` + `rustpython-ast` (same version spaghetti-rs pins) | Already proven against this exact workspace's real files (111/111, 0 failures) — no reason to re-spike a parser choice spaghetti-rs already settled. |
| CLI parsing | `argparse` | `clap` (derive) | Direct match to tripwire's small flag set (`--json`, `--quiet`/`-q`, `--package`, `--fail-on`). |
| Line-based regex checks | `re` (stdlib) | `regex` crate, **plus `fancy-regex` for the two lookahead patterns** | See §7.1 — this is the one place tripwire's dependency list needs to diverge from spaghetti-rs's. |
| Manifest text scanning | `re` (stdlib) over `.toml`/`.txt` **as plain text** | `regex` crate, no TOML parser needed | Confirmed by reading `manifest_checks.py`: both `check_dependency_cve` and `check_unbounded_pins` regex over raw lines, never `tomllib.loads()` the manifest — so, unlike spaghetti's workspace-root walk, this needs no `toml` crate dependency at all. |
| JSON output | `json` (stdlib) | `serde_json` | Direct match; also the fixture-diffing wire format per §5. |
| Sandboxing (`is_secure_path`) | `boti.core` | Inline reimplementation (§4.3) | ~10 lines, no crate needed. |
| Concurrency | none (sequential loop) | `rayon::par_iter()` over files — optional, new capability not present in Python (§4.2) | Checks are pure `(path, lines, tree) -> Vec<Finding>` functions with no shared state, so this is low-risk to add, but isn't required for parity. |
| CVE/version data | Hardcoded `vuln_deps: list[tuple[str,str,str]]` in `manifest_checks.py` | Shared `vuln_deps.toml` (or `.json`) loaded by both languages | See §7.3 — moves a currently Python-only literal into data both implementations read, the same "move hardcoded constants into one shared source" move spaghetti's proposal recommended for its own thresholds (spaghetti §5). |

## 7. Parity risk register

Unspiked — these are the concrete things a Phase 0 spike needs to answer before committing to the phasing in §8, ranked by how much they could change the plan.

### 7.1 Two regex patterns use lookahead — Rust's `regex` crate doesn't support it, needs a spike to confirm the fallback

Found by grepping both check files for `(?=`/`(?<=`/`\1`-style backreferences:

- `checks/manifest_checks.py:75` — `check_dependency_cve`'s dependency-name matcher: `rf'(?:^|["\'=,\s]){re.escape(dep_base)}(?=["\':,<>=!\s]|$)'`, using lookahead to assert a word boundary after the dependency name without consuming it.
- `checks/text_checks.py:929` — a weak-hash-adjacent-to-security-context check: `r"hashlib\.md5\b.*(?=.*\b(?:sign|hmac|sig|token|password|hash\b))"`, using lookahead to check "does a security-sounding word appear later on this line" without anchoring the match's end to it.

Rust's mainline `regex` crate deliberately excludes all lookaround (lookahead/lookbehind) to preserve its linear-time matching guarantee — this isn't a missing feature that'll appear in a future version, it's a permanent design constraint. Two options, both viable, needing a spike to pick:

1. **`fancy-regex`** (backtracking, supports lookaround) for just these two patterns, `regex` for the other ~50. Keeps the patterns textually identical to Python's, at the cost of two dependencies doing overlapping jobs.
2. **Rewrite both patterns without lookahead** — both are checking "is there a word boundary/security-term after this point" which is expressible without lookahead by restructuring the capture (e.g. matching the boundary character into a non-capturing group and checking it separately, or scanning for the security term anywhere in the line as a second, independent regex rather than one combined pattern). Zero extra dependencies, but means the Rust source no longer textually mirrors the Python regex — the conformance suite becomes the only proof they're equivalent, not "read the two side by side."

No strong recommendation yet pending a quick spike: try rewriting `hashlib\.md5` first (it's checking two independent conditions ANDed together — that decomposes cleanly into two separate `regex` searches with no lookahead needed at all, likely resolving 1 of 2 without `fancy-regex`), then decide whether the remaining `check_dependency_cve` pattern is worth a second dependency or also decomposes.

### 7.2 Deprecated `ast` node aliases used in one helper — likely a non-issue, worth confirming

`ast_helpers.py:108`'s `_has_dynamic_arg` checks `isinstance(arg, (ast.Constant, ast.Str, ast.Num, ast.NameConstant))` — `ast.Str`/`ast.Num`/`ast.NameConstant` are deprecated-since-3.8 aliases that Python's `ast` module still resolves (via `__instancecheck__` trickery) to plain `ast.Constant` under the hood. `rustpython-ast` is a fresh implementation with no such back-compat aliasing baggage, so the Rust port's equivalent almost certainly just matches the single `Constant` expression variant — this is a simplification, not a gap, but worth a one-line confirmation during the spike rather than assumed.

### 7.3 The CVE table is a data-maintenance problem, not a porting problem — flagging so it isn't accidentally solved twice

`manifest_checks.py`'s `vuln_deps` (~15 entries: package/version constraint/CVE description) and the `CWE_REFERENCE`/CVE list in `reporting.py`'s docstring-style banner are hand-maintained, point-in-time security data — e.g. `CVE-2026-42208`, `CVE-2026-41486`, dated entries that will need updating long after any port ships. Porting this table into Rust as a second hardcoded literal would mean **every future CVE addition needs updating twice, in two languages** — the exact "two implementations drift" failure mode spaghetti's proposal identifies (spaghetti §5), except here it'd affect *data* nobody is proposing to keep in sync via a conformance suite. Recommend extracting `vuln_deps` into a shared `vuln_deps.toml` both implementations load at build or run time, decided as part of Phase 0 rather than deferred — this is cheap to do now and expensive to unwind once two copies exist.

### 7.4 Self-scan exclusion list needs to travel with the port, not be rediscovered

`scanner.py`'s `_SELF_SCAN_EXCLUDE` (checks/__init__.py, checks/text_checks.py, checks/manifest_checks.py, ast_helpers.py, reporting.py) exists because tripwire's own pattern-table source files necessarily contain, as string literals, the exact patterns they detect (a documented, deliberate design choice — see the comment in `scanner.py`). The Rust port needs the equivalent exclusion for its own pattern-table files, matched by path suffix the same way — a detail easy to silently drop if the port is written by comparing check-by-check without re-reading `scanner.py`'s framing comment first.

### 7.5 Encoding tolerance

Same requirement as spaghetti §7.5: `_read()`'s `path.read_text(encoding="utf-8")` (with an exception caught and treated as "unreadable, skip" per `scanner.py`) must have a non-panicking equivalent in Rust — a scan shouldn't die on one malformed file in a large external codebase.

## 8. Distribution & packaging

Same shape as spaghetti-rs (spaghetti §8, §11.3): prebuilt binaries via `cargo-dist` across the same platform set, published to crates.io as `cargo install tripwire`. No `pip`-installable wheel planned initially, for the same reason spaghetti deferred it — build only if real demand for a `pip`-native path shows up.

## 9. Repo placement

New sibling repo, `tripwire-rs`, matching `spaghetti-rs`'s placement decision (spaghetti §9, §11.2) and this workspace's existing one-language-per-repo convention (`boti`/`boti-data`/`boti-dask`/`tripwire`/`spaghetti` are each already standalone). Shared fixtures (§5) and the shared `vuln_deps` data (§7.3) are the connective tissue between the two repos, following the same pattern spaghetti's conformance fixtures already establish — potentially even living in the same shared-fixtures location if one gets built for spaghetti, rather than standing up a second one.

## 10. Phased plan (proposed, not yet started)

| Phase | Deliverable | Gate to move on |
|---|---|---|
| 0 | Spike: confirm `rustpython-parser` handles every AST shape tripwire's 12 AST checks need (expected: yes, since spaghetti-rs already exercises a superset); resolve §7.1's two lookahead patterns (rewrite vs. `fancy-regex`); confirm §7.2 is a non-issue. | Both spikes resolved, no open parser/regex questions |
| 1 | Build fixture corpus for the ~40 checks with no existing Python test (§5) — this is Python-side work, valuable independent of whether the port proceeds. Extract `vuln_deps` into shared data (§7.3). | Every check has at least one fixture with a known-correct expected `Finding` |
| 2 | Port `models.rs`, `config.rs` (workspace-root walk — can likely copy spaghetti-rs's `_find_workspace_root` equivalent near-verbatim), `scanner.rs` (incl. self-scan exclusion, §7.4), `reporting.rs`. | Fixture-driven output for a handful of hand-picked checks matches Python byte-for-byte |
| 3 | Port all 52 checks in batches (grouping by file: `ast_checks` batch, `text_checks` batches, `manifest_checks` batch), checked in after each batch against the fixture corpus. | Fixture corpus green for every ported check |
| 4 | CLI (`clap`), `--package`/`--fail-on`/`--json` flags, optional `rayon` parallelism (§4.2). Repeatability check (same lesson as spaghetti §7.7: diff a few consecutive runs against the same input, not just against Python). | Full conformance suite green; N consecutive runs byte-identical |
| 5 | Packaging: crate metadata, CI, `cargo-dist` config — same checklist as spaghetti §10 Phase 5. | `cargo test`/`clippy -D warnings`/`fmt --check` green; `dist plan` correct |
| 6 | Publish — gated on explicit go-ahead, same three irreversible steps as spaghetti §12 (create repo, set `CARGO_REGISTRY_TOKEN`, `cargo publish`). | User sign-off |

## 11. Open decisions

Unlike spaghetti's proposal (written after Phase 4 was already done), these are genuinely open, not settled-in-hindsight:

1. **Spec of record**: recommend Python, same as spaghetti, for the same reason (cheaper to prototype a new CWE check in Python first). Worth confirming rather than assuming, since tripwire's checks are simpler and the "prototype in the slower language" cost is lower than it was for spaghetti's harder rules.
2. **Where `vuln_deps` data lives** (§7.3): a file in this new `tripwire-rs` repo, a file in the existing `tripwire` repo that `tripwire-rs` fetches/vendors at build time, or a third shared location alongside spaghetti's fixture corpus if one exists by the time this starts.
3. **Whether to build the fixture corpus (Phase 1) before or in parallel with the Rust skeleton (Phase 2).** Spaghetti had the luxury of an existing 152-test suite to lean on early; tripwire doesn't, so Phase 1 is real, sequenceable work rather than a formality — worth deciding whether it blocks Phase 2 or runs alongside it.
4. **Whether `rayon` parallelism (§4.2) is worth adding on day one** given it's new capability rather than parity, or whether it should wait until the sequential port is fixture-clean first, to keep the Phase 3/4 diff-against-Python story simple (a parallel scan reordering output would need the same sort-before-emit discipline spaghetti's port needed for reproducibility, spaghetti §7.7).
