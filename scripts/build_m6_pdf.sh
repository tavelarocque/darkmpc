#!/usr/bin/env bash
# Builds docs/m6_design_report.pdf from docs/design-report.md (needs pandoc + xelatex).
set -euo pipefail
cd "$(dirname "$0")/.."
mkdir -p docs/build
{
  printf -- '---\ntitle: "darkmpc: design report"\nsubtitle: "A dark pool its operator cannot see into"\nauthor: "Tave La Rocque"\ndate: "November 2026"\n---\n\n'
  sed '1,3d' docs/design-report.md
} > docs/build/m6.md
pandoc docs/build/m6.md -o docs/m6_design_report.pdf --pdf-engine=xelatex -H docs/pdf-head.tex \
  -V geometry:margin=1in -V fontsize=11pt -V colorlinks=true
