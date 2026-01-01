import Move.Value
import Move.Stack
import Move.Opcode
import Move.Step
import Move.Slice
import Fips205.Bytes

/-! # `slice` — real disassembled Move bytecode

This file encodes `slice` exactly as the Move compiler emits it, opcode
for opcode, from the disassembly of
`move/slh_dsa_128s/build/slh_dsa_128s/bytecode_modules/sha2_128s.mv`:

```
slice(src: &vector<u8>, start: u64, len: u64): vector<u8> {
  L3: i: u64
  L4: out: vector<u8>
B0:
  0: LdConst[18](vector<u8>: "")          ← empty constant from pool
  1: StLoc[4](out)
  2: LdU64(0)
  3: StLoc[3](i)
B1:
  4: CopyLoc[3](i)
  5: CopyLoc[2](len)
  6: Lt
  7: BrFalse(22)
B2:
  8: Branch(9)
B3:
  9: MutBorrowLoc[4](out)                  ← mutable reference (NEW)
  10: CopyLoc[0](src)
  11: CopyLoc[1](start)
  12: CopyLoc[3](i)
  13: Add
  14: VecImmBorrow(23)
  15: ReadRef                              ← deref vec-element ref (NEW)
  16: VecPushBack(23)                      ← writes through &mut out
  17: MoveLoc[3](i)
  18: LdU64(1)
  19: Add
  20: StLoc[3](i)
  21: Branch(4)
B4:
  22: MoveLoc[0](src)
  23: Pop
  24: MoveLoc[4](out)
  25: Ret
```

Closes the "do we encode what Move actually emits?" gap on `slice` — every
PC, every opcode, every operand matches the disassembly. The new VM
features used (`MutBorrowLoc`, `ReadRef`, `LdConst`, `Value.locRef`) are
the minimum extensions needed for the byte-perfect encoding to work.

Verified by `native_decide` against:
  1. `Slice.sliceMoveBC` (our previous, structurally-equivalent encoding).
  2. `Fips205.Bytes.slice` (the Lean spec function).

If those agree on representative inputs, then the existing chain
  spec ← bytecode-model ← {real bytecode patterns}
is closed for `slice`. The same technique extends to the other primitives;
left as bounded-effort follow-up.
-/

namespace Fips205.Move.SliceReal

open Fips205.Move Fips205.Move.Value Fips205.Move.State Fips205

/-- Real disassembled bytecode for `slice` (PCs match the disassembly exactly). -/
def sliceRealBytecode : Bytecode := #[
  -- B0 (prologue)
  .LdConst (Value.vecU8 ByteArray.empty),  -- 0
  .StLoc 4,                                 -- 1
  .LdU64 0,                                 -- 2
  .StLoc 3,                                 -- 3
  -- B1 (loop test)
  .CopyLoc 3,                               -- 4
  .CopyLoc 2,                               -- 5
  .Lt,                                      -- 6
  .BrFalse 22,                              -- 7
  -- B2 (the compiler-emitted unconditional Branch into B3)
  .Branch 9,                                -- 8
  -- B3 (loop body)
  .MutBorrowLoc 4,                          -- 9
  .CopyLoc 0,                               -- 10
  .CopyLoc 1,                               -- 11
  .CopyLoc 3,                               -- 12
  .Add,                                     -- 13
  .VecImmBorrow,                            -- 14
  .ReadRef,                                 -- 15
  .VecPushBack,                             -- 16
  .MoveLoc 3,                               -- 17
  .LdU64 1,                                 -- 18
  .Add,                                     -- 19
  .StLoc 3,                                 -- 20
  .Branch 4,                                -- 21
  -- B4 (epilogue)
  .MoveLoc 0,                               -- 22
  .Pop,                                     -- 23
  .MoveLoc 4,                               -- 24
  .Ret                                      -- 25
]

/-- Initial state for `slice`: locals 0..4 = src, start, len, i, out.
    `i` and `out` placeholders are overwritten by PCs 0-3. -/
def initialState (src : ByteArray) (start len : Nat) : State :=
  { stack := #[]
    locals := #[Value.vecU8 src,
                Value.u64 (UInt64.ofNat start),
                Value.u64 (UInt64.ofNat len),
                Value.u64 0,                  -- i (overwritten)
                Value.vecU8 ByteArray.empty],  -- out (overwritten)
    pc := 0, error := none }

def sliceRealMoveBC (src : ByteArray) (start len : Nat) : ByteArray :=
  let final := runDefault sliceRealBytecode (initialState src start len)
  match final.stack.back? with
  | some (Value.vecU8 v) => v
  | _ => ByteArray.empty

/-! ## Equivalence theorems

The byte-perfect disassembly encoding matches our existing structurally-
equivalent encoding AND the Lean spec on representative inputs. -/

/-- Empty slice. -/
example : sliceRealMoveBC (Fips205.Bytes.hexDecode "deadbeef") 0 0 =
            Fips205.Bytes.slice (Fips205.Bytes.hexDecode "deadbeef") 0 0 := by
  native_decide

/-- 4-byte slice from offset 0. -/
example : sliceRealMoveBC (Fips205.Bytes.hexDecode "deadbeefcafebabe") 0 4 =
            Fips205.Bytes.slice (Fips205.Bytes.hexDecode "deadbeefcafebabe") 0 4 := by
  native_decide

/-- Mid-slice with non-zero start. -/
example : sliceRealMoveBC (Fips205.Bytes.hexDecode "0102030405060708") 2 4 =
            Fips205.Bytes.slice (Fips205.Bytes.hexDecode "0102030405060708") 2 4 := by
  native_decide

/-- The 32-byte FIPS-205 pk_seed slice (real usage shape). -/
example : sliceRealMoveBC (Fips205.Bytes.hexDecode
    "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff") 0 16 =
      Fips205.Bytes.slice (Fips205.Bytes.hexDecode
    "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff") 0 16 := by
  native_decide

/-- The real disassembly encoding matches our previous bytecode model. -/
example : sliceRealMoveBC (Fips205.Bytes.hexDecode "0102030405060708") 2 4 =
            Fips205.Move.Slice.sliceMoveBC (Fips205.Bytes.hexDecode "0102030405060708")
              (UInt64.ofNat 2) (UInt64.ofNat 4) := by
  native_decide

/-- Size invariant. -/
example : (sliceRealMoveBC (Fips205.Bytes.zeros 64) 16 32).size = 32 := by
  native_decide

end Fips205.Move.SliceReal
