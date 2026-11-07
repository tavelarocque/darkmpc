#!/usr/bin/env bash
# Every planted bug must make the test suite fail. If a planted bug survives,
# the tests are not strong enough and this script exits non-zero.
set -uo pipefail
cd "$(dirname "$0")/.."

# crate:feature pairs (plain list, so it runs on macOS's bash 3.2)
PLANTS="
darkmpc-reference:plant-mes-boundary
darkmpc-reference:plant-skip-elimination
darkmpc-reference:plant-prefix-inclusive
darkmpc-reference:plant-stage2-no-surplus
darkmpc-reference:plant-stage2-time-before-price
darkmpc-mpc:plant-mul-wrong-share
darkmpc-mpc:plant-no-rerandomize
darkmpc-mpc:plant-lt-off-by-one
darkmpc-mpc:plant-short-carry
darkmpc-mpc:plant-unstable-sort
darkmpc-mpc:plant-scan-ignores-segments
darkmpc-auction:plant-skip-unsort
darkmpc-mpc:plant-cheat-mul
darkmpc-mpc:plant-cheat-and
darkmpc-mpc:plant-cheat-keep-own
darkmpc-mpc:plant-cheat-triple
darkmpc-mpc:plant-cheat-open-copy
darkmpc-auction:plant-skip-consistency
darkmpc-auction:plant-skip-bit-check
darkmpc-auction:plant-skip-range-check
darkmpc-auction:plant-skip-order-check
darkmpc-mpc:plant-skip-shuffle-check
darkmpc-auction:plant-stage2-mpc-drop-flat-stretch
darkmpc-auction:plant-stage2-mpc-strict-sell
darkmpc-auction:plant-stage2-mpc-buy-time-only
darkmpc-mpc:plant-open-unshuffled
darkmpc-auction:plant-stage2-debug-open
"

status=0
for entry in $PLANTS; do
  crate="${entry%%:*}"; plant="${entry#*:}"
  {
    if cargo test -q --workspace --features "$crate/$plant" >/dev/null 2>&1; then
      echo "SURVIVED  $crate/$plant  (tests did not catch it)"
      status=1
    else
      echo "caught    $crate/$plant"
    fi
  }
done

if cargo test -q --workspace >/dev/null 2>&1; then
  echo "clean build passes"
else
  echo "CLEAN BUILD FAILS"
  status=1
fi
exit $status
