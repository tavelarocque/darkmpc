#!/usr/bin/env bash
# Builds docs/m3_auction_part1.pdf from the Milestone 3 walkthrough, part 1 (needs pandoc + xelatex).
set -euo pipefail
cd "$(dirname "$0")/.."
mkdir -p docs/build
{
  printf -- '---\ntitle: "darkmpc, Milestone 3 walkthrough, part 1"\nsubtitle: "The Stage 1 auction in MPC"\nauthor: "Tave La Rocque"\ndate: "4 November 2026"\n---\n\n'
  cat docs/learning/04-stage1-mpc.md
} > docs/build/m3.md
pandoc docs/build/m3.md -o docs/m3_auction_part1.pdf --pdf-engine=xelatex -H docs/pdf-head.tex \
  -V geometry:margin=1in -V fontsize=11pt -V colorlinks=true
