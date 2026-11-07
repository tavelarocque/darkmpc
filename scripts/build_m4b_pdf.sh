#!/usr/bin/env bash
# Builds docs/m4b_shuffle.pdf from the Milestone 4b walkthrough (needs pandoc + xelatex).
set -euo pipefail
cd "$(dirname "$0")/.."
mkdir -p docs/build
{
  printf -- '---\ntitle: "darkmpc, Milestone 4b walkthrough"\nsubtitle: "A shuffle that cannot be tampered with"\nauthor: "Tave La Rocque"\ndate: "4 November 2026"\n---\n\n'
  cat docs/learning/07-verified-shuffle.md
} > docs/build/m4b.md
pandoc docs/build/m4b.md -o docs/m4b_shuffle.pdf --pdf-engine=xelatex -H docs/pdf-head.tex \
  -V geometry:margin=1in -V fontsize=11pt -V colorlinks=true
