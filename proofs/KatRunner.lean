import Fips205.Verify
import Fips205.Bytes

/-! # `kat` executable: differential harness driver.

  Usage:
    cat cases.jsonl | lake exe kat

  Each input line is one JSON object:
    {"pk": "<hex>", "msg": "<hex>", "sig": "<hex>", "ctx": "<hex>"}
  (`ctx` is optional; defaults to empty.)

  For each case the program prints one line: "accept" or "reject", matching
  the `Bool` returned by `Fips205.Verify.verify`. The TS driver in
  `packages/pqc/scripts/lean-diff-noble.ts` reads these lines back and asserts
  they match noble's verdict on the same inputs.

  We deliberately use line-delimited JSON rather than a single mega-object so
  the runner streams: it can process arbitrarily many cases without loading
  them all into memory at once.
-/

open Fips205.Verify Fips205.Bytes

/-- Extract a hex string value for `key` from a one-line JSON object.
    The parser is intentionally tiny — JSON objects emitted by the driver are
    always of the form `{"key":"hexstring", ...}` with no embedded escapes. -/
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
  let ok := verify pk msg sig ctx
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
