#!/usr/bin/env bash
# Run one auction with the three servers as separate processes on this
# machine, over mutually authenticated TLS, then check the fills against the
# reference matcher.
#   scripts/bench_local.sh ORDERS PASSES PROFILE [SYMBOLS] [malicious|stage2|malicious,stage2]
# PROFILE: none | lan | wan
#   none: real loopback only, no simulation
#   lan:  simulated 0.47 ms RTT, 10 Gbit/s (the prior work's LAN ping)
#   wan:  simulated 40 ms RTT, 1 Gbit/s
set -euo pipefail
cd "$(dirname "$0")/.."
N=${1:-1000}; K=${2:-3}; PROFILE=${3:-none}; SYMBOLS=${4:-8192}
MAL=()
case "${5:-}" in *malicious*) MAL+=(--malicious) ;; esac
case "${5:-}" in *stage2*) MAL+=(--stage2) ;; esac
case "$PROFILE" in
  none) NETARGS=() ;;
  lan)  NETARGS=(--rtt-ms 0.47 --mbps 10000) ;;
  wan)  NETARGS=(--rtt-ms 40 --mbps 1000) ;;
  *) echo "profile must be none, lan or wan"; exit 2 ;;
esac
cargo build -q --release -p darkmpc-server
BIN=target/release/darkmpc-server
DIR=$(mktemp -d)
trap 'rm -rf "$DIR"' EXIT
PORT=$((20000 + RANDOM % 20000))
ADDRS="127.0.0.1:$PORT,127.0.0.1:$((PORT+1)),127.0.0.1:$((PORT+2))"
$BIN setup --dir "$DIR" >/dev/null
$BIN deal --dir "$DIR" --orders "$N" --symbols "$SYMBOLS" ${MAL[@]+"${MAL[@]}"} >/dev/null
for i in 0 1 2; do
  $BIN run --dir "$DIR" --id $i --addrs "$ADDRS" --passes "$K" ${NETARGS[@]+"${NETARGS[@]}"} ${MAL[@]+"${MAL[@]}"} >/dev/null &
done
wait
$BIN check --dir "$DIR" --passes "$K" ${MAL[@]+"${MAL[@]}"}
