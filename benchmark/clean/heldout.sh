#!/usr/bin/env sh
# The held-out application of ROADMAP phase C2: one fresh application,
# scanned once at the pinned commit after the check work was frozen,
# adjudicated blind, scored with the clean-corpus scorer against
# heldout-labels.json. The first two held-out apps, pretalx and Tandoor
# Recipes, have since joined the tuning corpus (run.sh); the current one is
# CTFd. Extra
# arguments go to score.py (--confidence-min high, --fps).
set -eu
here=$(cd "$(dirname "$0")" && pwd)
work=${BENCH_DIR:-$(mktemp -d)}
fenceline=${FENCELINE_CMD:-"uv run --quiet --project $here/../.. fenceline"}
mkdir -p "$work/apps"
cd "$work/apps"
if [ ! -d CTFd ]; then
  git init -q CTFd
  git -C CTFd remote add origin https://github.com/CTFd/CTFd
  git -C CTFd fetch -q --depth 1 --filter=blob:none origin 485d59e7bff790424f093be80ea9f6031b631f2d
  git -C CTFd checkout -q FETCH_HEAD
fi
roots="CTFd/CTFd"
$fenceline --package ctfd=CTFd/CTFd --json >"$work/fenceline.json" || true
uvx --quiet bandit==1.9.4 -q -r $roots -f json -o "$work/bandit.json" || true
uvx --quiet semgrep==1.185.0 --config p/python --metrics=off --json -o "$work/semgrep.json" -q $roots || true
python3 -I "$here/score.py" "$here/heldout-labels.json" "$work/fenceline.json" "$work/bandit.json" "$work/semgrep.json" "$@"
