#!/usr/bin/env bash
# Builds docs/ring_proofs.pdf from docs/design/ring-proofs.md (needs pandoc + xelatex).
set -euo pipefail
cd "$(dirname "$0")/.."
mkdir -p docs/build
{
  printf -- '---\ntitle: "darkmpc: the two ring extensions, proved"\nsubtitle: "Product checks in the 64-bit ring, and the MAC-checked shuffle"\nauthor: "Tave La Rocque"\ndate: "6 November 2026"\n---\n\n'
  sed '1d' docs/design/ring-proofs.md
} > docs/build/ring_proofs.md
pandoc docs/build/ring_proofs.md -o docs/ring_proofs.pdf --pdf-engine=xelatex -H docs/pdf-head.tex \
  -V geometry:margin=1in -V fontsize=11pt -V colorlinks=true
