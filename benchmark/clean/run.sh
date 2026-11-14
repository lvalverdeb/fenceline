#!/usr/bin/env sh
# Reproduce the clean-code precision measurement: clone the apps at their
# pinned commits, run the three tools on their application packages, score
# against labels.json. Extra arguments go to score.py (--confidence-min high,
# --fps).
#
#   BENCH_DIR=/tmp/fl-clean benchmark/clean/run.sh
#   FENCELINE_CMD=/path/to/fenceline-rs/target/release/fenceline benchmark/clean/run.sh
set -eu
here=$(cd "$(dirname "$0")" && pwd)
work=${BENCH_DIR:-$(mktemp -d)}
fenceline=${FENCELINE_CMD:-"uv run --quiet --project $here/../.. fenceline"}

clone() {  # clone REPO DIR SHA [SPARSE PATHS...]
  repo=$1; dir=$2; sha=$3; shift 3
  if [ ! -d "$dir" ]; then
    git init -q "$dir"
    git -C "$dir" remote add origin "https://github.com/$repo"
    if [ $# -gt 0 ]; then
      git -C "$dir" sparse-checkout set "$@"
    fi
    git -C "$dir" fetch -q --depth 1 --filter=blob:none origin "$sha"
    git -C "$dir" checkout -q FETCH_HEAD
  fi
}
mkdir -p "$work/apps"
cd "$work/apps"
clone healthchecks/healthchecks healthchecks cb5c9764ee483dd30864c0869cc0cbe12d3dfad8
clone Netflix/dispatch dispatch dd2837e82a0bf5565b1b4b4b91ea30b7262d4061
clone flaskbb/flaskbb flaskbb 1028f176840be67a239be3763720c8e249eb70de
clone home-assistant/core hacore e68768b8549fc7d6d06235858e9ebbc8bd1472b7 homeassistant/auth homeassistant/components/http

roots="healthchecks/hc dispatch/src/dispatch flaskbb/flaskbb hacore/homeassistant"
$fenceline --package healthchecks=healthchecks/hc --package dispatch=dispatch/src/dispatch --package flaskbb=flaskbb/flaskbb --package hacore=hacore/homeassistant --json >"$work/fenceline.json" || true
uvx --quiet bandit==1.9.4 -q -r $roots -f json -o "$work/bandit.json" || true
uvx --quiet semgrep==1.185.0 --config p/python --metrics=off --json -o "$work/semgrep.json" -q $roots || true

python3 -I "$here/score.py" "$here/labels.json" "$work/fenceline.json" "$work/bandit.json" "$work/semgrep.json" "$@"
