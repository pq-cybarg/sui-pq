#!/usr/bin/env bash
# Run the full FIPS-205 formal-verification pipeline.
#
# What this does:
#   1. lake build — runs all Lean proofs (28 verifier-execution theorems,
#      structural invariants, MoveEquiv lemmas, SHA-256 KATs, etc.)
#   2. lean-exe-vs-nist.ts — confirms the Lean-compiled binary agrees with
#      NIST official ACVP vectors
#   3. lean-diff-noble.ts — 100-case differential vs noble for breadth
#
# Pass any non-zero exit code straight through so this fails CI loudly.
#
# Tools required: lean (via elan), node, pnpm, tsx.

set -euo pipefail

cd "$(dirname "$0")/.."

echo "── 1/3 — Lean proofs (lake build) ──"
( cd proofs && lake build )
echo "✓ all Lean proofs check"

echo
echo "── 2/3 — Lean exe vs NIST ACVP vectors ──"
pnpm exec tsx packages/pqc/scripts/lean-exe-vs-nist.ts

echo
echo "── 3/4 — Differential vs noble (100 random cases) ──"
pnpm exec tsx packages/pqc/scripts/lean-diff-noble.ts 100

echo
echo "── 4/5 — Fixture replay (1000 pre-generated cases) ──"
pnpm exec tsx packages/pqc/scripts/run-diff-fixture.ts

echo
echo "── 5/5 — Three-way differential (noble ↔ Lean ↔ TS reference) ──"
pnpm exec tsx packages/pqc/scripts/lean-diff-tsref.ts 30

echo
echo "✓ FIPS-205 formal verification: all checks passed"
