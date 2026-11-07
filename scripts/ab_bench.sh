#!/usr/bin/env bash
# A/B benchmark: the current working tree against a git ref, median of REPS
# runs per configuration, runs interleaved (A, B, A, B, ...) so slow periods
# on the machine hit both sides equally. Every run is also checked against
# the reference matcher (bench_local.sh fails on a mismatch).
#   scripts/ab_bench.sh REF [REPS]      e.g. scripts/ab_bench.sh c26e4e7 5
set -euo pipefail
cd "$(dirname "$0")/.."
REF=${1:?usage: ab_bench.sh REF [REPS]}; REPS=${2:-5}
OLD=$(mktemp -d)
trap 'git worktree remove --force "$OLD" >/dev/null 2>&1 || true' EXIT
git worktree add --detach "$OLD" "$REF" >/dev/null 2>&1
echo "building $REF and the working tree..."
(cd "$OLD" && cargo build -q --release -p darkmpc-server)
cargo build -q --release -p darkmpc-server

secs() { grep '^server=0' | sed 's/.*auction_secs=\([0-9.]*\).*/\1/'; }
median() { sort -g | awk '{a[NR]=$1} END {print (NR%2 ? a[(NR+1)/2] : (a[NR/2]+a[NR/2+1])/2)}'; }

printf "| Config | %s (median of %s) | working tree (median of %s) | change |\n|---|---|---|---|\n" "$REF" "$REPS" "$REPS"
for cfg in "1000 lan" "10000 lan" "1000 wan"; do
  set -- $cfg
  a=(); b=()
  for _ in $(seq "$REPS"); do
    a+=("$( (cd "$OLD" && scripts/bench_local.sh "$1" 3 "$2" 100 malicious) | secs)")
    b+=("$(scripts/bench_local.sh "$1" 3 "$2" 100 malicious | secs)")
  done
  ma=$(printf '%s\n' "${a[@]}" | median); mb=$(printf '%s\n' "${b[@]}" | median)
  awk -v c="$1 orders, $2" -v x="$ma" -v y="$mb" 'BEGIN { printf "| %s | %.3f s | %.3f s | %+.0f%% |\n", c, x, y, 100*(y-x)/x }'
done
