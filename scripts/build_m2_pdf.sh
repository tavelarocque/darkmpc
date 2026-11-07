#!/usr/bin/env bash
# Builds docs/m2_core.pdf from the Milestone 2 walkthrough (needs pandoc + xelatex).
set -euo pipefail
cd "$(dirname "$0")/.."
mkdir -p docs/build
{
  printf -- '---\ntitle: "darkmpc, Milestone 2 walkthrough"\nsubtitle: "The semi-honest three-party core"\nauthor: "Tave La Rocque"\ndate: "4 November 2026"\n---\n\n'
  cat docs/learning/03-semi-honest-core.md
} > docs/build/m2.md
pandoc docs/build/m2.md -o docs/m2_core.pdf --pdf-engine=xelatex -H docs/pdf-head.tex \
  -V geometry:margin=1in -V fontsize=11pt -V colorlinks=true
