#!/usr/bin/env sh
# Reproduce the benchmark: clone the apps at their pinned commits, run the three
# tools, score against labels.json. Extra arguments go to score.py
# (e.g. --confidence-min high, --fps).
#
#   BENCH_DIR=/tmp/fl-bench benchmark/run.sh
#   FENCELINE_CMD=/path/to/fenceline-rs/target/release/fenceline benchmark/run.sh
set -eu
here=$(cd "$(dirname "$0")" && pwd)
work=${BENCH_DIR:-$(mktemp -d)}
fenceline=${FENCELINE_CMD:-"uv run --quiet --project $here/.. fenceline"}

clone() {  # clone REPO DIR SHA
  if [ ! -d "$2" ]; then
    git init -q "$2"
    git -C "$2" remote add origin "https://github.com/$1"
    git -C "$2" fetch -q --depth 1 origin "$3"
    git -C "$2" checkout -q FETCH_HEAD
  fi
}
mkdir -p "$work/apps"
cd "$work/apps"
clone adeyosemanputra/pygoat pygoat 2aa4cc14f251e4a780e94e200aed6b36a5b15c21
clone fportantier/vulpy vulpy 5249cc8b05a1c37f6b2f757b1cf16a509c327122
clone anxolerd/dvpwa dvpwa 4a8f4a43fafcc1b304f1b97d0f0a8dea755a7756

$fenceline --package pygoat=pygoat --package vulpy=vulpy --package dvpwa=dvpwa --json >"$work/fenceline.json" || true
uvx --quiet bandit==1.9.4 -q -r pygoat vulpy dvpwa -f json -o "$work/bandit.json" || true
uvx --quiet semgrep==1.185.0 --config p/python --metrics=off --json -o "$work/semgrep.json" -q pygoat vulpy dvpwa || true

python3 -I "$here/score.py" "$here/labels.json" "$work/fenceline.json" "$work/bandit.json" "$work/semgrep.json" "$@"
