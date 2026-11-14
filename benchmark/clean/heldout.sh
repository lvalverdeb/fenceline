#!/usr/bin/env sh
# The held-out application of ROADMAP phase C2: pretalx, scanned once at the
# pinned commit after the C2 work was frozen, adjudicated blind, scored with
# the clean-corpus scorer against heldout-labels.json. Extra arguments go to
# score.py (--confidence-min high, --fps).
set -eu
here=$(cd "$(dirname "$0")" && pwd)
work=${BENCH_DIR:-$(mktemp -d)}
fenceline=${FENCELINE_CMD:-"uv run --quiet --project $here/../.. fenceline"}
mkdir -p "$work/apps"
cd "$work/apps"
if [ ! -d pretalx ]; then
  git init -q pretalx
  git -C pretalx remote add origin https://github.com/pretalx/pretalx
  git -C pretalx fetch -q --depth 1 --filter=blob:none origin 1510dea9aafd580d1b2d7b8466736a09cd0298ec
  git -C pretalx checkout -q FETCH_HEAD
fi
$fenceline --package pretalx=pretalx/src/pretalx --json >"$work/fenceline.json" || true
uvx --quiet bandit==1.9.4 -q -r pretalx/src/pretalx -f json -o "$work/bandit.json" || true
uvx --quiet semgrep==1.185.0 --config p/python --metrics=off --json -o "$work/semgrep.json" -q pretalx/src/pretalx || true
python3 -I "$here/score.py" "$here/heldout-labels.json" "$work/fenceline.json" "$work/bandit.json" "$work/semgrep.json" "$@"
