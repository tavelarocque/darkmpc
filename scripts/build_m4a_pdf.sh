#!/usr/bin/env bash
# Builds docs/m4a_malicious.pdf from the Milestone 4a walkthrough (needs pandoc + xelatex).
set -euo pipefail
cd "$(dirname "$0")/.."
mkdir -p docs/build
{
  printf -- '---\ntitle: "darkmpc, Milestone 4a walkthrough"\nsubtitle: "Catching a cheating server or trader"\nauthor: "Tave La Rocque"\ndate: "4 November 2026"\n---\n\n'
  cat docs/learning/06-malicious-4a.md
} > docs/build/m4a.md
pandoc docs/build/m4a.md -o docs/m4a_malicious.pdf --pdf-engine=xelatex -H docs/pdf-head.tex \
  -V geometry:margin=1in -V fontsize=11pt -V colorlinks=true
