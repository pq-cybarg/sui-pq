#!/usr/bin/env bash
# Run the full FIPS-205 formal-verification pipeline.
#
# What this does:
#   1. lake build — all Lean proofs (403 theorems/examples: SHA-256 KATs,
#      verifier-execution proofs, MoveEquiv equivalences, structural
#      invariants, the Move VM, verifyViaBC_total, and the Move/*Real
#      opcode-for-opcode bytecode-equivalence proofs).
#   2. lean-exe-vs-nist.ts — Lean-compiled binary agrees with NIST ACVP.
#   3. lean-diff-noble.ts — 100-case differential vs noble for breadth.
#   4. run-diff-fixture.ts — 1000-case fixture replay through the spec exe.
#   5. lean-diff-tsref.ts — three-way differential (noble ↔ Lean ↔ TS ref).
#   6. lean-diff-bc.ts — spec verifier vs the 100%-bytecode verifier
#      (verifyViaBC_total) over the 1000-case fixture.
#
# Pass any non-zero exit code straight through so this fails CI loudly.
#
# Tools required: lean (via elan), node, pnpm, tsx.

set -euo pipefail

cd "$(dirname "$0")/.."

echo "── 1/6 — Lean proofs (lake build) ──"
( cd proofs && lake build )
echo "✓ all Lean proofs check"

echo
echo "── 2/6 — Lean exe vs NIST ACVP vectors ──"
pnpm exec tsx packages/pqc/scripts/lean-exe-vs-nist.ts

echo
echo "── 3/6 — Differential vs noble (100 random cases) ──"
pnpm exec tsx packages/pqc/scripts/lean-diff-noble.ts 100

echo
echo "── 4/6 — Fixture replay (1000 pre-generated cases) ──"
pnpm exec tsx packages/pqc/scripts/run-diff-fixture.ts

echo
echo "── 5/6 — Three-way differential (noble ↔ Lean ↔ TS reference) ──"
pnpm exec tsx packages/pqc/scripts/lean-diff-tsref.ts 30

echo
echo "── 6/6 — Spec verifier vs 100%-bytecode verifier (1000-case fixture) ──"
pnpm exec tsx packages/pqc/scripts/lean-diff-bc.ts

echo
echo "✓ FIPS-205 formal verification: all checks passed"
