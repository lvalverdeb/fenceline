#!/usr/bin/env sh
# The held-out application of ROADMAP phase C2: one fresh application,
# scanned once at the pinned commit after the check work was frozen,
# adjudicated blind, scored with the clean-corpus scorer against
# heldout-labels.json. The first held-out app, pretalx, has since joined the
# tuning corpus (run.sh); the current one is Tandoor Recipes. Extra
# arguments go to score.py (--confidence-min high, --fps).
set -eu
here=$(cd "$(dirname "$0")" && pwd)
work=${BENCH_DIR:-$(mktemp -d)}
fenceline=${FENCELINE_CMD:-"uv run --quiet --project $here/../.. fenceline"}
mkdir -p "$work/apps"
cd "$work/apps"
if [ ! -d recipes ]; then
  git init -q recipes
  git -C recipes remote add origin https://github.com/TandoorRecipes/recipes
  git -C recipes fetch -q --depth 1 --filter=blob:none origin 4fdc8549b5f1755ef135ccd05131f111f3b31a9c
  git -C recipes checkout -q FETCH_HEAD
fi
roots="recipes/cookbook recipes/recipes"
$fenceline --package cookbook=recipes/cookbook --package settings=recipes/recipes --json >"$work/fenceline.json" || true
uvx --quiet bandit==1.9.4 -q -r $roots -f json -o "$work/bandit.json" || true
uvx --quiet semgrep==1.185.0 --config p/python --metrics=off --json -o "$work/semgrep.json" -q $roots || true
python3 -I "$here/score.py" "$here/heldout-labels.json" "$work/fenceline.json" "$work/bandit.json" "$work/semgrep.json" "$@"
