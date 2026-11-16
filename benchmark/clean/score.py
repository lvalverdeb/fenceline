"""Score the three tools on the clean-code corpus: precision only.

usage: score.py LABELS FENCELINE_JSON BANDIT_JSON SEMGREP_JSON [--confidence-min LEVEL] [--fps]

Every in-scope finding must carry a verdict in LABELS (true, false or
by-design); an unlabelled finding is an error, not a silent true. Strict
precision counts only *true*; lenient precision also counts *by-design*
(a correct detection of deliberate code). Recall is not measured: nobody
knows how many weaknesses these applications hold.
"""

from __future__ import annotations

import collections
import json
import re
import sys

CONFIDENCE_RANK = {"HIGH": 0, "MEDIUM": 1, "LOW": 2}
# Test code and migrations are outside the universe for every tool alike.
EXCLUDED = re.compile(
    r"(^|/)(migrations|revisions|alembic|tests?|node_modules|venv|\.venv)(/|$)"
    r"|(^|/)tests?\.py$|(^|/)test_[^/]*\.py$|_test\.py$|(^|/)conftest\.py$"
)
TOOLS = ("fenceline", "bandit", "semgrep")


def _norm(path: str) -> str:
    path = str(path)
    if "apps/" in path:
        path = path.split("apps/", 1)[1]
    return path.lstrip("./")


def _load_findings(fenceline, bandit, semgrep):
    """(tool, rule, file, line, confidence) for every finding on a .py file in scope."""
    out = []
    for x in fenceline["findings"]:
        out.append(("fenceline", x["cwe_id"], _norm(x["file"]), x["line"], x["confidence"]))
    for x in bandit["results"]:
        out.append(("bandit", x["test_id"], _norm(x["filename"]), x["line_number"], None))
    for x in semgrep["results"]:
        rule = x["check_id"].rsplit(".", 1)[-1]
        out.append(("semgrep", rule, _norm(x["path"]), x["start"]["line"], None))
    return [f for f in out if f[2].endswith(".py") and not EXCLUDED.search(f[2])]


def main(argv: list[str]) -> int:
    labels = json.load(open(argv[1]))
    fenceline, bandit, semgrep = (json.load(open(p)) for p in argv[2:5])
    conf_min = (
        argv[argv.index("--confidence-min") + 1].upper() if "--confidence-min" in argv else None
    )
    verdict = {(t, r, loc): label for t, r, loc, label, _ in labels["verdicts"]}
    apps = labels["apps"]
    total_lines = sum(a["lines"] for a in apps.values())

    per = {t: collections.Counter() for t in TOOLS}
    by_conf = collections.defaultdict(collections.Counter)
    by_app = collections.defaultdict(collections.Counter)
    fps = collections.Counter()
    for tool, rule, file, line, conf in _load_findings(fenceline, bandit, semgrep):
        key = (tool, rule, f"{file}:{line}")
        if key not in verdict:
            raise SystemExit(f"unlabelled finding {tool}:{rule} at {file}:{line}; add it to labels.json")
        label = verdict[key]
        if tool == "fenceline":
            by_conf[conf][label] += 1
            if conf_min is not None and CONFIDENCE_RANK[conf] > CONFIDENCE_RANK[conf_min]:
                continue
            by_app[file.split("/", 1)[0]][label] += 1
            if label == "false":
                fps[rule] += 1
        per[tool][label] += 1

    name = {"bandit": "Bandit", "semgrep": "Semgrep"}
    name["fenceline"] = (
        f"fenceline (--confidence-min {conf_min.lower()})" if conf_min else "fenceline"
    )
    print(
        f"Universe: application code of {len(apps)} apps, {total_lines} lines; "
        "tests and migrations excluded for every tool.\n"
    )
    print("| Tool | Findings | True | By design | False | Precision (strict) | Precision (lenient) | Per 1000 lines |")
    print("|---|---|---|---|---|---|---|---|")
    for t in TOOLS:
        c = per[t]
        n = sum(c.values())
        print(
            f"| {name[t]} | {n} | {c['true']} | {c['by-design']} | {c['false']} "
            f"| {c['true'] / max(n, 1):.0%} | {(c['true'] + c['by-design']) / max(n, 1):.0%} "
            f"| {1000 * n / total_lines:.1f} |"
        )

    print("\nfenceline confidence calibration (all findings):\n")
    print("| Confidence | Findings | True | By design | False | Share true |")
    print("|---|---|---|---|---|---|")
    for conf in ("HIGH", "MEDIUM", "LOW"):
        c = by_conf[conf]
        n = sum(c.values())
        print(f"| {conf} | {n} | {c['true']} | {c['by-design']} | {c['false']} | {c['true'] / max(n, 1):.0%} |")

    print(f"\n{name['fenceline']} per app:\n")
    print("| App | Framework | Lines | Findings | True | By design | False | Per 1000 lines |")
    print("|---|---|---|---|---|---|---|---|")
    for app, meta in apps.items():
        c = by_app[app]
        n = sum(c.values())
        print(
            f"| {app} | {meta['framework']} | {meta['lines']} | {n} | {c['true']} | {c['by-design']} "
            f"| {c['false']} | {1000 * n / meta['lines']:.1f} |"
        )
    if "--fps" in argv:
        print(f"\n{name['fenceline']} false positives by check: " + ", ".join(f"{r} {n}" for r, n in fps.most_common()))
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
