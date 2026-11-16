#!/usr/bin/env sh
# Reproduce the CVE regression measurement: clone each CVE's last vulnerable
# commit (sparse, blob-filtered), scan the affected package, score against
# manifest.json. Extra arguments go to score.py.
#
#   BENCH_DIR=/tmp/fl-cves benchmark/cves/run.sh
#   FENCELINE_CMD=/path/to/fenceline-rs/target/release/fenceline benchmark/cves/run.sh
set -eu
here=$(cd "$(dirname "$0")" && pwd)
work=${BENCH_DIR:-$(mktemp -d)}
fenceline=${FENCELINE_CMD:-"uv run --quiet --project $here/../.. fenceline"}
mkdir -p "$work/apps" "$work/out"

python3 -I - "$here/manifest.json" <<'PY' | while read -r id repo sha root; do
import json, sys
for c in json.load(open(sys.argv[1]))["cves"]:
    print(c["id"], c["repo"], c["commit"], c["root"])
PY
  dir="$work/apps/$id"
  if [ ! -d "$dir" ]; then
    git init -q "$dir"
    git -C "$dir" remote add origin "https://github.com/$repo"
    git -C "$dir" sparse-checkout set "$root"
    git -C "$dir" fetch -q --depth 1 --filter=blob:none origin "$sha"
    git -C "$dir" checkout -q FETCH_HEAD
  fi
  name=$(basename "$root" | tr -c 'a-zA-Z0-9_\n' '_')
  (cd "$work/apps" && $fenceline --package "$name=$id/$root" --json >"$work/out/$id.json") || true
done

python3 -I "$here/score.py" "$here/manifest.json" "$work/out" "$@"
