#!/usr/bin/env bash
# Builds docs/m5_stage2_audit_benchmarks.pdf from the Milestone 5 walkthroughs (needs pandoc + xelatex).
set -euo pipefail
cd "$(dirname "$0")/.."
mkdir -p docs/build
{
  printf -- '---\ntitle: "darkmpc, Milestone 5 walkthrough"\nsubtitle: "Limit prices, a leakage audit, and real machines"\nauthor: "Tave La Rocque"\ndate: "6 November 2026"\n---\n\n'
  cat docs/learning/08-stage2.md
  printf '\n\n\\newpage\n\n'
  cat docs/learning/09-leakage-audit.md
  printf '\n\n\\newpage\n\n'
  cat docs/learning/10-benchmarks.md
  printf '\n\n\\newpage\n\n# Appendix A: the leakage proof\n\n'
  sed '1d' docs/design/leakage-audit.md | sed 's/^## /## A. /'
  printf '\n\n\\newpage\n\n# Appendix B: benchmark report\n\n'
  sed '1d' docs/benchmarks.md | sed 's/^## /## B. /'
} > docs/build/m5.md
pandoc docs/build/m5.md -o docs/m5_stage2_audit_benchmarks.pdf --pdf-engine=xelatex -H docs/pdf-head.tex \
  -V geometry:margin=1in -V fontsize=11pt -V colorlinks=true
