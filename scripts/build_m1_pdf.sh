#!/usr/bin/env bash
# Builds docs/m1_design_draft.pdf from the Milestone 1 markdown (needs pandoc + xelatex).
set -euo pipefail
cd "$(dirname "$0")/.."
mkdir -p docs/build
{
  printf -- '---\ntitle: "darkmpc, Milestone 1 walkthrough (draft)"\nsubtitle: "Prior work, secret sharing, protocol choices, threat model, and the reference matcher"\nauthor: "Tave La Rocque"\ndate: "4 November 2026"\n---\n\n'
  for f in docs/prior-work.md docs/learning/01-secret-sharing.md docs/design/decisions.md docs/design/threat-model.md docs/learning/02-reference-matcher.md; do
    sed '1s/^# /\\newpage\n\n# /' "$f"; printf '\n\n'
  done
} > docs/build/m1.md
pandoc docs/build/m1.md -o docs/m1_design_draft.pdf --pdf-engine=xelatex -H docs/pdf-head.tex \
  -V geometry:margin=1in -V fontsize=11pt -V colorlinks=true --toc
