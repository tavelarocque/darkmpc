#!/usr/bin/env bash
# Builds docs/m3_auction_part2.pdf from the Milestone 3 walkthrough, part 2 (needs pandoc + xelatex).
set -euo pipefail
cd "$(dirname "$0")/.."
mkdir -p docs/build
{
  printf -- '---\ntitle: "darkmpc, Milestone 3 walkthrough, part 2"\nsubtitle: "Separate processes, TLS, and the first benchmarks"\nauthor: "Tave La Rocque"\ndate: "4 November 2026"\n---\n\n'
  cat docs/learning/05-processes-and-network.md
} > docs/build/m3b.md
pandoc docs/build/m3b.md -o docs/m3_auction_part2.pdf --pdf-engine=xelatex -H docs/pdf-head.tex \
  -V geometry:margin=1in -V fontsize=11pt -V colorlinks=true
