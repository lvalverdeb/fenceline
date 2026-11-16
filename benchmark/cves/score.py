"""Score fenceline on the CVE regression set.

    python3 -I score.py manifest.json OUT_DIR [--confidence-min high]

OUT_DIR holds one `<CVE-id>.json` per manifest entry (fenceline --json of
the entry's root). A CVE is *found* when a finding whose CWE is the
manifest's (or one of `accept_cwes`) sits on the `sink` line or one of the
`also` lines; *same CWE elsewhere in the file* is reported separately, it is
not a hit. *Other findings in the file* counts what a reviewer wades through
in the sink's file apart from the hit.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

CONF_RANK = {"HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}


def rel_file(f: dict, cve_id: str) -> str:
    path = f["file"].replace("\\", "/")
    marker = f"/{cve_id}/"
    return path.split(marker, 1)[1] if marker in path else path


def score_one(c: dict, findings: list[dict], min_conf: str | None) -> dict:
    if min_conf:
        findings = [f for f in findings if CONF_RANK[f["confidence"]] >= CONF_RANK[min_conf]]
    sink_file, sink_line = c["sink"].rsplit(":", 1)
    targets = {(sink_file, int(sink_line))}
    for a in c.get("also", []):
        p, l = a.rsplit(":", 1)
        targets.add((p, int(l)))
    cwes = {c["cwe"], *c.get("accept_cwes", [])}
    hits = [f for f in findings if (rel_file(f, c["id"]), f["line"]) in targets and f["cwe_id"] in cwes]
    in_file = [f for f in findings if rel_file(f, c["id"]) == sink_file]
    same_cwe_elsewhere = [f for f in in_file if f["cwe_id"] in cwes and f not in hits]
    best = max((f["confidence"] for f in hits), key=lambda k: CONF_RANK[k], default=None)
    return {
        "result": f"found ({best})" if hits else "missed",
        "found": bool(hits),
        "high": best == "HIGH",
        "same_cwe_elsewhere": len(same_cwe_elsewhere),
        "noise": len([f for f in in_file if f not in hits]),
        "total": len(findings),
    }


def main(argv: list[str]) -> int:
    if len(argv) < 2:
        print(__doc__)
        return 2
    manifest = json.loads(Path(argv[0]).read_text())
    out_dir = Path(argv[1])
    min_conf = None
    if "--confidence-min" in argv:
        min_conf = argv[argv.index("--confidence-min") + 1].upper()
    rows = []
    for c in manifest["cves"]:
        p = out_dir / f"{c['id']}.json"
        findings = json.loads(p.read_text())["findings"] if p.exists() else []
        rows.append((c, score_one(c, findings, min_conf)))
    label = f"fenceline (--confidence-min {min_conf.lower()})" if min_conf else "fenceline"
    for cls in ("covered", "uncovered"):
        sel = [(c, r) for c, r in rows if c["class"] == cls]
        if not sel:
            continue
        title = "Classes fenceline claims" if cls == "covered" else "Classes fenceline does not claim"
        found = sum(r["found"] for _, r in sel)
        high = sum(r["high"] for _, r in sel)
        print(f"### {title}: {label}, {found}/{len(sel)} found, {high} at HIGH\n")
        print("| CVE | App | Framework | CWE | Result | Same CWE elsewhere in file | Other findings in file | Root cause of the miss |")
        print("|---|---|---|---|---|---|---|---|")
        for c, r in sel:
            app = c["repo"].split("/")[1]
            cause = (c.get("root_cause") or "") if not r["found"] else ""
            print(f"| {c['id']} | {app} | {c['framework']} | {c['cwe']} | {r['result']} | {r['same_cwe_elsewhere']} | {r['noise']} | {cause} |")
        print()
    total = sum(r["total"] for _, r in rows)
    print(f"Findings over all {len(rows)} trees: {total}.")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
