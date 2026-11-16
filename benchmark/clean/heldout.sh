#!/usr/bin/env sh
# The held-out application of ROADMAP phase C2: one fresh application,
# scanned once at the pinned commit after the check work was frozen,
# adjudicated blind, scored with the clean-corpus scorer against
# heldout-labels.json. The first three held-out apps, pretalx, Tandoor
# Recipes and CTFd, have since joined the tuning corpus (run.sh); the
# current one is Mealie. Extra
# arguments go to score.py (--confidence-min high, --fps).
set -eu
here=$(cd "$(dirname "$0")" && pwd)
work=${BENCH_DIR:-$(mktemp -d)}
fenceline=${FENCELINE_CMD:-"uv run --quiet --project $here/../.. fenceline"}
mkdir -p "$work/apps"
cd "$work/apps"
if [ ! -d mealie ]; then
  git init -q mealie
  git -C mealie remote add origin https://github.com/mealie-recipes/mealie
  git -C mealie fetch -q --depth 1 --filter=blob:none origin 3d639dd5ea8eca729da641f1ddb2f18500d7323a
  git -C mealie checkout -q FETCH_HEAD
fi
roots="mealie/mealie"
$fenceline --package mealie=mealie/mealie --json >"$work/fenceline.json" || true
uvx --quiet bandit==1.9.4 -q -r $roots -f json -o "$work/bandit.json" || true
uvx --quiet semgrep==1.185.0 --config p/python --metrics=off --json -o "$work/semgrep.json" -q $roots || true
python3 -I "$here/score.py" "$here/heldout-labels.json" "$work/fenceline.json" "$work/bandit.json" "$work/semgrep.json" "$@"
