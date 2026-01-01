import Lake
open Lake DSL

/-!
Formal verification of FIPS-205 SLH-DSA-SHA2-128s.

Goals (incremental):
  1. Executable Lean spec of FIPS-205 §10.3 (verify).
  2. Run the spec on noble-generated KAT vectors; ground-truth equivalence.
  3. Prove the TS reference / Move impl byte-format compatibility against the spec.
  4. Stretch: verified Rust extraction for a native Sui module.
-/

package fips205 where
  -- We deliberately avoid heavy external deps (no Mathlib) so the project
  -- bootstraps in seconds from a fresh checkout. Anything we need (SHA-256,
  -- byte/bit ops) we either bring in via Lean stdlib or write ourselves —
  -- this is a verification project, so the dependency surface IS the TCB.

@[default_target]
lean_lib Fips205 where
  -- single library, multi-file. Files added under proofs/Fips205/.

@[default_target]
lean_lib Move where
  -- Move bytecode VM semantics. Files under proofs/Move/.
  -- See proofs/Move/Example.lean for the proof-of-concept end-to-end
  -- bytecode ↔ spec equivalence.

@[default_target]
lean_exe kat where
  root := `KatRunner
  -- Cross-checks the Lean spec against noble-emitted vectors.

@[default_target]
lean_exe «kat-bc» where
  root := `KatBCRunner
  -- Same as `kat` but uses `Fips205.Move.Composition.verifyViaBC_full`,
  -- the 100%-bytecode verifier (modulo hmsg).
