import Move.Value
import Move.Stack
import Move.Opcode
import Move.Step
import Move.Native
import Move.MoveStdlib
import Move.Thash
import Fips205.Bytes
import Fips205.Thash
import Fips205.MoveEquiv

/-! # `thash` — real disassembled Move bytecode

```
thash(prefix: &vector<u8>, adrs: &vector<u8>, m: &vector<u8>): vector<u8> {
  L3: buf, L4: h, L5: i
B0:
  0: MoveLoc[0] prefix ; 1: ReadRef ; 2: StLoc[3] buf      // buf := *prefix
  3: MutBorrowLoc[3] buf ; 4: MoveLoc[1] adrs ; 5: ReadRef
  6: Call vector::append<u8>                               // buf ++= *adrs
  7: MutBorrowLoc[3] buf ; 8: MoveLoc[2] m ; 9: ReadRef
  10: Call vector::append<u8>                              // buf ++= *m
  11: MoveLoc[3] buf ; 12: Call hash::sha2_256 ; 13: StLoc[4] h   // h := sha256(buf)
  14: LdU64(0) ; 15: StLoc[5] i
B1: truncate loop (pop 16 bytes off the 32-byte hash → keep first 16)
  16-19: i < 16 ?
  21: MutBorrowLoc[4] h ; 22: VecPopBack ; 23: Pop         // drop last byte
  24-28: i += 1 ; loop
B4:
  29: MoveLoc[4] h ; 30: Ret
}
```

First composite primitive: uses `Call vector::append` (modeled via
`MoveStdlib.vectorAppendCallee`), `CallNative sha2_256`, and ref-aware
`VecPopBack` truncation. The `buf := *prefix; append; append` pattern is
exactly how the Move compiler builds the SHA-256 preimage
`prefix ‖ adrs ‖ m`.
-/

namespace Fips205.Move.ThashReal

open Fips205.Move Fips205.Move.Value Fips205.Move.State Fips205 Fips205.Move.MoveStdlib

def thashRealBytecode : Bytecode := #[
  -- B0: buf := *prefix
  .MoveLoc 0,                                                  -- 0
  .ReadRef,                                                    -- 1
  .StLoc 3,                                                    -- 2
  -- buf ++= *adrs
  .MutBorrowLoc 3,                                             -- 3
  .MoveLoc 1,                                                  -- 4
  .ReadRef,                                                    -- 5
  .Call vectorAppendCallee vectorAppendLocalsTail 2,           -- 6
  -- buf ++= *m
  .MutBorrowLoc 3,                                             -- 7
  .MoveLoc 2,                                                  -- 8
  .ReadRef,                                                    -- 9
  .Call vectorAppendCallee vectorAppendLocalsTail 2,           -- 10
  -- h := sha256(buf)
  .MoveLoc 3,                                                  -- 11
  .CallNative "sha2_256" 1,                                    -- 12
  .StLoc 4,                                                    -- 13
  .LdU64 0,                                                    -- 14
  .StLoc 5,                                                    -- 15
  -- B1: truncate loop (i < 16)
  .CopyLoc 5,                                                  -- 16
  .LdU64 16,                                                   -- 17
  .Lt,                                                         -- 18
  .BrFalse 29,                                                 -- 19
  -- B2
  .Branch 21,                                                  -- 20
  -- B3: drop one byte
  .MutBorrowLoc 4,                                             -- 21
  .VecPopBack,                                                 -- 22
  .Pop,                                                        -- 23
  .MoveLoc 5,                                                  -- 24
  .LdU64 1,                                                    -- 25
  .Add,                                                        -- 26
  .StLoc 5,                                                    -- 27
  .Branch 16,                                                  -- 28
  -- B4: return h
  .MoveLoc 4,                                                  -- 29
  .Ret                                                         -- 30
]

def initialState (pre adrs m : ByteArray) : State :=
  { stack := #[]
    locals := #[Value.vecU8 pre,            -- 0: prefix
                Value.vecU8 adrs,            -- 1: adrs
                Value.vecU8 m,               -- 2: m
                Value.vecU8 ByteArray.empty, -- 3: buf
                Value.vecU8 ByteArray.empty, -- 4: h
                Value.u64 0],                -- 5: i
    pc := 0, error := none }

def thashRealMoveBC (pre adrs m : ByteArray) : ByteArray :=
  let final := runDefault thashRealBytecode (initialState pre adrs m)
  match final.stack.back? with
  | some (Value.vecU8 v) => v
  | _ => ByteArray.empty

/-! ## Equivalence theorems -/

example :
    let pkSeed := Fips205.Bytes.hexDecode "11223344556677889900aabbccddeeff"
    let pre := pkSeed ++ Fips205.Bytes.zeros 48
    let adrs := Fips205.Bytes.zeros 22
    let m := Fips205.Bytes.hexDecode "aabbccdd"
    thashRealMoveBC pre adrs m = Fips205.MoveEquiv.thashMove pre adrs m := by
  native_decide

example :
    let pkSeed := Fips205.Bytes.hexDecode "112233445566778899aabbccddeeff00"
    let pre := pkSeed ++ Fips205.Bytes.zeros 48
    let adrs := Fips205.Bytes.zeros 22
    let m := Fips205.Bytes.hexDecode "deadbeefcafebabe1234567890abcdef"
    thashRealMoveBC pre adrs m = Fips205.MoveEquiv.thashMove pre adrs m := by
  native_decide

/-- Output is exactly 16 bytes. -/
example :
    (thashRealMoveBC (Fips205.Bytes.zeros 64) (Fips205.Bytes.zeros 22) (Fips205.Bytes.zeros 16)).size = 16 := by
  native_decide

/-- The real-disassembly encoding matches our previous structural encoding. -/
example :
    let pkSeed := Fips205.Bytes.hexDecode "112233445566778899aabbccddeeff00"
    let pre := pkSeed ++ Fips205.Bytes.zeros 48
    let adrs := Fips205.Bytes.zeros 22
    let m := Fips205.Bytes.hexDecode "deadbeefcafebabe1234567890abcdef"
    thashRealMoveBC pre adrs m = Fips205.Move.Thash.thashMoveBC pre adrs m := by
  native_decide

end Fips205.Move.ThashReal
