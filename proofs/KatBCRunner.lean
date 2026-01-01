import Move.Composition
import Fips205.Bytes

/-! # `kat-bc` executable: bytecode-composition verifier driver.

  Same protocol as `kat` (JSONL on stdin, "accept"/"reject" lines on stdout)
  but invokes `Fips205.Move.Composition.verifyViaBC_total` instead of
  `Fips205.Verify.verify`.

  `verifyViaBC_total` is the 100%-bytecode verifier — every primitive
  (slice, hmsg, split_digest, pk_seed_padded, all ADRS setters,
  extract_fors_indices, thash, WOTS+ chain, HT path) runs through the
  Move VM `step` semantics. The only non-bytecode dependencies are the
  natives in `Move.Native` (sha2_256 + int casts).

  The runtime differential script (`packages/pqc/scripts/lean-diff-bc.ts`)
  runs both `kat` and `kat-bc` against the same fixture and asserts the
  two verifiers agree on every case — extending the per-case `native_decide`
  equivalence proofs in `Composition.lean` to the full 1000-case fixture
  without paying the kernel-reduction cost of 1000 separate proofs.
-/

open Fips205.Move.Composition Fips205.Bytes

def parseHexField (line : String) (key : String) : Option String :=
  let needle := "\"" ++ key ++ "\":\""
  match (line.splitOn needle) with
  | _ :: rest :: _ =>
    match (rest.splitOn "\"") with
    | h :: _ => some h
    | [] => none
  | _ => none

def runCase (line : String) : IO Unit := do
  let pkHex  := (parseHexField line "pk").getD ""
  let msgHex := (parseHexField line "msg").getD ""
  let sigHex := (parseHexField line "sig").getD ""
  let ctxHex := (parseHexField line "ctx").getD ""
  let pk  := hexDecode pkHex
  let msg := hexDecode msgHex
  let sig := hexDecode sigHex
  let ctx := hexDecode ctxHex
  let ok := verifyViaBC_total pk msg sig ctx
  IO.println (if ok then "accept" else "reject")

partial def loop : IO Unit := do
  let stdin ← IO.getStdin
  let line ← stdin.getLine
  if line.isEmpty then return
  let trimmed := line.trimAscii.toString
  if trimmed.length > 0 then
    runCase trimmed
  loop

def main : IO Unit := do
  loop
