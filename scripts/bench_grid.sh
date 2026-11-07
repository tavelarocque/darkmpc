#!/usr/bin/env bash
# Median-of-3 auction latency for several batch sizes and network profiles,
# printed as a markdown table. Every run is also checked against the
# reference matcher (bench_local.sh exits non-zero on a mismatch).
#   scripts/bench_grid.sh [PASSES] [SYMBOLS]
set -euo pipefail
cd "$(dirname "$0")/.."
K=${1:-3}; SYMBOLS=${2:-100}
echo "| Profile | Orders | Rounds | MB sent per server | Auction time (median of 3) | Orders/s |"
echo "|---|---|---|---|---|---|"
for prof in lan wan; do
  for n in 100 1000 10000 100000; do
    times=()
    for rep in 1 2 3; do
      out=$(scripts/bench_local.sh "$n" "$K" "$prof" "$SYMBOLS")
      line=$(echo "$out" | grep "^server=0")
      times+=("$(echo "$line" | sed 's/.*auction_secs=\([0-9.]*\).*/\1/')")
      rounds=$(echo "$line" | sed 's/.*rounds=\([0-9]*\).*/\1/')
      bytes=$(echo "$line" | sed 's/.*bytes_sent=\([0-9]*\).*/\1/')
    done
    med=$(printf '%s\n' "${times[@]}" | sort -g | sed -n 2p)
    awk -v p="$prof" -v n="$n" -v r="$rounds" -v b="$bytes" -v t="$med" \
      'BEGIN { printf "| %s | %d | %d | %.1f | %.3f s | %.0f |\n", p, n, r, b/1e6, t, n/t }'
  done
done
