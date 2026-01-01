import Move.Value
import Move.Stack
import Move.Opcode
import Move.Step

/-! # Modeled Move stdlib functions as `Call` callees

The real compiled bytecode invokes `vector::append<u8>(&mut dst, src)` via
a `Call` to the Move stdlib. Our VM doesn't link the stdlib, so we model
`vector::append` as a tiny callee bytecode invoked through the same
cross-frame-ref `Call` machinery used for the project's own helpers.

`vector::append(dst: &mut vector<u8>, src: vector<u8>)` appends `src` to
`*dst` in place (void return). In our callee frame:
  local 0 = dst (arrives as a `locRef` to the caller's backing slot)
  local 1 = src (a value)

The body reads `*dst`, concatenates `src`, and writes the result back —
exactly `*dst := *dst ++ src`. The cross-frame copy-out in `step`'s `Call`
arm then propagates the mutation to the caller's vector.
-/

namespace Fips205.Move.MoveStdlib

open Fips205.Move Fips205.Move.Value

/-- Callee bytecode modeling `vector::append<u8>(&mut dst, src)`. -/
def vectorAppendCallee : Bytecode := #[
  .CopyLoc 0,        -- 0  push dst ref
  .ReadRef,          -- 1  push *dst (value)
  .MoveLoc 1,        -- 2  push src (value)
  .VecAppend,        -- 3  *dst ++ src
  .CopyLoc 0,        -- 4  push dst ref
  .WriteRef,         -- 5  *dst := result
  .Ret               -- 6  (void)
]

/-- `vector::append` has no declared non-arg locals. -/
def vectorAppendLocalsTail : Array Value := #[]

end Fips205.Move.MoveStdlib
