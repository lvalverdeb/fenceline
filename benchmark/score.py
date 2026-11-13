"""Score fenceline, Bandit and Semgrep against the adjudicated labels.

usage: score.py LABELS FENCELINE_JSON BANDIT_JSON SEMGREP_JSON [--confidence-min LEVEL] [--fps]

Ground truth is always derived from the full, unfiltered run of all three
tools; ``--confidence-min`` only narrows which fenceline findings are scored,
so recall at HIGH confidence is measured against the same truth set.
"""

from __future__ import annotations

import collections
import json
import re
import sys

CONFIDENCE_RANK = {"HIGH": 0, "MEDIUM": 1, "LOW": 2}
# Test code and migrations are outside the benchmark universe for every tool alike.
EXCLUDED = re.compile(
    r"(^|/)(migrations|tests?|node_modules|venv|\.venv)(/|$)"
    r"|(^|/)tests?\.py$|(^|/)test_[^/]*\.py$|_test\.py$|(^|/)conftest\.py$"
)
TOOLS = ("fenceline", "bandit", "semgrep")


def _norm(path: str) -> str:
    path = str(path)
    if "apps/" in path:
        path = path.split("apps/", 1)[1]
    return path.lstrip("./")


def _load_findings(fenceline, bandit, semgrep, conf_min):
    """(tool, rule, file, line, scored) for every finding on a .py file in scope."""
    out = []
    for x in fenceline["findings"]:
        scored = conf_min is None or CONFIDENCE_RANK[x["confidence"]] <= CONFIDENCE_RANK[conf_min]
        out.append(("fenceline", x["cwe_id"], _norm(x["file"]), x["line"], scored))
    for x in bandit["results"]:
        out.append(("bandit", x["test_id"], _norm(x["filename"]), x["line_number"], True))
    for x in semgrep["results"]:
        rule = x["check_id"].rsplit(".", 1)[-1]
        out.append(("semgrep", rule, _norm(x["path"]), x["start"]["line"], True))
    return [f for f in out if f[2].endswith(".py") and not EXCLUDED.search(f[2])]


def main(argv: list[str]) -> int:
    labels = json.load(open(argv[1]))
    fenceline, bandit, semgrep = (json.load(open(p)) for p in argv[2:5])
    conf_min = (
        argv[argv.index("--confidence-min") + 1].upper() if "--confidence-min" in argv else None
    )

    categories = labels["categories"]
    fp_rules = labels["false_positive_rules"]
    fp_set = {(t, r, loc) for t, r, loc, _ in labels["false_positives"]}
    tp_set = {(t, r, loc) for t, r, loc, _ in labels.get("true_positive_overrides", [])}
    canonical = {}
    for file, cat, lines in labels["same_instance"]:
        for line in lines:
            canonical[(file, cat, line)] = (file, cat, lines[0])

    def is_true(tool, rule, file, line) -> bool:
        if (tool, rule, f"{file}:{line}") in tp_set:
            return True
        return rule not in fp_rules.get(tool, []) and (tool, rule, f"{file}:{line}") not in fp_set

    def instance(tool, rule, file, line):
        cat = categories[tool][rule]
        return canonical.get((file, cat, line), (file, cat, line))

    truth = set()
    per = {t: {"n": 0, "tp": 0, "fp": 0, "hits": set(), "fps": []} for t in TOOLS}
    for tool, rule, file, line, scored in _load_findings(fenceline, bandit, semgrep, conf_min):
        if rule not in categories[tool]:
            raise SystemExit(f"unmapped rule {tool}:{rule} at {file}:{line}; add it to labels.json")
        ok = is_true(tool, rule, file, line)
        if ok:
            truth.add(instance(tool, rule, file, line))
        if not scored:
            continue
        d = per[tool]
        d["n"] += 1
        if ok:
            d["tp"] += 1
            d["hits"].add(instance(tool, rule, file, line))
        else:
            d["fp"] += 1
            d["fps"].append(rule)

    name = {"bandit": "Bandit", "semgrep": "Semgrep"}
    name["fenceline"] = (
        f"fenceline (--confidence-min {conf_min.lower()})" if conf_min else "fenceline"
    )
    print(
        f"Ground truth: {len(truth)} distinct weakness instances across {len({i[1] for i in truth})} categories.\n"
    )
    print("| Tool | Findings | True | False | Precision | Recall |")
    print("|---|---|---|---|---|---|")
    for t in TOOLS:
        d = per[t]
        hits = len(d["hits"])
        print(
            f"| {name[t]} | {d['n']} | {d['tp']} | {d['fp']} | {d['tp'] / max(d['n'], 1):.0%} "
            f"| {hits}/{len(truth)} ({hits / len(truth):.0%}) |"
        )
    print("\n| Category | Instances | fenceline | Bandit | Semgrep |")
    print("|---|---|---|---|---|")
    by_cat = collections.defaultdict(set)
    for inst in truth:
        by_cat[inst[1]].add(inst)
    for cat, insts in sorted(by_cat.items(), key=lambda kv: (-len(kv[1]), kv[0])):
        cells = " | ".join(str(len(insts & per[t]["hits"])) for t in TOOLS)
        print(f"| {cat} | {len(insts)} | {cells} |")
    if "--fps" in argv:
        for t in TOOLS:
            counts = collections.Counter(per[t]["fps"]).most_common()
            print(f"\n{t} false positives by rule: " + ", ".join(f"{r} {n}" for r, n in counts))
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
