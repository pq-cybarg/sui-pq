import Move.Value
import Move.Stack
import Move.Opcode
import Move.Step
import Fips205.Bytes

/-! # `bytes_eq` — real disassembled Move bytecode

From `sui move disassemble`. Returns `bool` (whether two byte arrays are
equal). The verify path uses it implicitly via `htRoot == pkRoot` at the
top level; encoding it explicitly here covers the bool-returning,
early-return-on-mismatch pattern that no other primitive we've encoded
so far exercises.

```
bytes_eq(a: &vector<u8>, b: &vector<u8>): bool {
  L2: i: u64
  L3: n: u64
B0:
  0: CopyLoc[0](a)
  1: VecLen
  2: StLoc[3](n)
  3: CopyLoc[3](n)
  4: CopyLoc[1](b)
  5: VecLen
  6: Neq
  7: BrFalse(14)        ← lengths equal → jump to loop init
B1 (lengths differ → return false):
  8: MoveLoc[1](b) ; 9: Pop ; 10: MoveLoc[0](a) ; 11: Pop
  12: LdFalse ; 13: Ret
B2 (init i):
  14: LdU64(0) ; 15: StLoc[2](i)
B3 (loop test):
  16: CopyLoc[2](i) ; 17: CopyLoc[3](n) ; 18: Lt ; 19: BrFalse(42)
B4 (body):
  20: CopyLoc[0](a) ; 21: CopyLoc[2](i) ; 22: VecImmBorrow ; 23: ReadRef
  24: CopyLoc[1](b) ; 25: CopyLoc[2](i) ; 26: VecImmBorrow ; 27: ReadRef
  28: Neq
  29: BrFalse(37)       ← bytes equal → continue loop
B5 (compiler-emitted Branch into B6):
  30: Branch(31)
B6 (early return false):
  31: MoveLoc[1](b) ; 32: Pop ; 33: MoveLoc[0](a) ; 34: Pop
  35: LdFalse ; 36: Ret
B7 (loop step):
  37: MoveLoc[2](i) ; 38: LdU64(1) ; 39: Add ; 40: StLoc[2](i) ; 41: Branch(16)
B8 (all bytes matched → return true):
  42: MoveLoc[1](b) ; 43: Pop ; 44: MoveLoc[0](a) ; 45: Pop
  46: LdTrue ; 47: Ret
```

The repeated `MoveLoc + Pop` pairs at function exits are the Move
compiler's affine-types bookkeeping (consuming the reference args before
return). In our value-semantics model they're no-op pop-and-discards.
-/

namespace Fips205.Move.BytesEqReal

open Fips205.Move Fips205.Move.Value Fips205.Move.State Fips205

/-- Disassembly-accurate bytecode for `bytes_eq`. PCs match. -/
def bytesEqRealBytecode : Bytecode := #[
  -- B0
  .CopyLoc 0,                       -- 0
  .VecLen,                          -- 1
  .StLoc 3,                         -- 2
  .CopyLoc 3,                       -- 3
  .CopyLoc 1,                       -- 4
  .VecLen,                          -- 5
  .Neq,                             -- 6
  .BrFalse 14,                      -- 7
  -- B1 (early return false: lengths differ)
  .MoveLoc 1,                       -- 8
  .Pop,                             -- 9
  .MoveLoc 0,                       -- 10
  .Pop,                             -- 11
  .LdFalse,                         -- 12
  .Ret,                             -- 13
  -- B2
  .LdU64 0,                         -- 14
  .StLoc 2,                         -- 15
  -- B3 (loop test)
  .CopyLoc 2,                       -- 16
  .CopyLoc 3,                       -- 17
  .Lt,                              -- 18
  .BrFalse 42,                      -- 19
  -- B4 (body)
  .CopyLoc 0,                       -- 20
  .CopyLoc 2,                       -- 21
  .VecImmBorrow,                    -- 22
  .ReadRef,                         -- 23
  .CopyLoc 1,                       -- 24
  .CopyLoc 2,                       -- 25
  .VecImmBorrow,                    -- 26
  .ReadRef,                         -- 27
  .Neq,                             -- 28
  .BrFalse 37,                      -- 29
  -- B5 (compiler-emitted Branch into B6)
  .Branch 31,                       -- 30
  -- B6 (early return false: bytes differ)
  .MoveLoc 1,                       -- 31
  .Pop,                             -- 32
  .MoveLoc 0,                       -- 33
  .Pop,                             -- 34
  .LdFalse,                         -- 35
  .Ret,                             -- 36
  -- B7 (loop step)
  .MoveLoc 2,                       -- 37
  .LdU64 1,                         -- 38
  .Add,                             -- 39
  .StLoc 2,                         -- 40
  .Branch 16,                       -- 41
  -- B8 (all matched → return true)
  .MoveLoc 1,                       -- 42
  .Pop,                             -- 43
  .MoveLoc 0,                       -- 44
  .Pop,                             -- 45
  .LdTrue,                          -- 46
  .Ret                              -- 47
]

def initialState (a b : ByteArray) : State :=
  { stack := #[]
    locals := #[Value.vecU8 a,        -- 0: a
                Value.vecU8 b,        -- 1: b
                Value.u64 0,           -- 2: i
                Value.u64 0],          -- 3: n
    pc := 0, error := none }

def bytesEqRealMoveBC (a b : ByteArray) : Bool :=
  let final := runDefault bytesEqRealBytecode (initialState a b)
  match final.stack.back? with
  | some (Value.bool x) => x
  | _ => false

/-! ## Equivalence theorems

The disassembled `bytes_eq` matches plain `ByteArray` equality on
representative inputs: equal, length-mismatch, byte-mismatch, both-empty. -/

/-- Both empty: true. -/
example : bytesEqRealMoveBC ByteArray.empty ByteArray.empty = true := by
  native_decide

/-- Identical short arrays. -/
example : bytesEqRealMoveBC (Fips205.Bytes.hexDecode "deadbeef")
                            (Fips205.Bytes.hexDecode "deadbeef") = true := by
  native_decide

/-- Length mismatch → early return false at B1. -/
example : bytesEqRealMoveBC (Fips205.Bytes.hexDecode "deadbeef")
                            (Fips205.Bytes.hexDecode "deadbeefca") = false := by
  native_decide

/-- Byte mismatch mid-loop → early return false at B6. -/
example : bytesEqRealMoveBC (Fips205.Bytes.hexDecode "0102030405")
                            (Fips205.Bytes.hexDecode "0102030406") = false := by
  native_decide

/-- 32-byte identical (real FIPS-205 sizing). -/
example : bytesEqRealMoveBC
    (Fips205.Bytes.hexDecode "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff")
    (Fips205.Bytes.hexDecode "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff") = true := by
  native_decide

/-- 32-byte differing in last byte. -/
example : bytesEqRealMoveBC
    (Fips205.Bytes.hexDecode "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff")
    (Fips205.Bytes.hexDecode "00112233445566778899aabbccddeeff00112233445566778899aabbccddee00") = false := by
  native_decide

/-- The bytecode result agrees with `==` on `ByteArray`. -/
example : bytesEqRealMoveBC (Fips205.Bytes.zeros 16) (Fips205.Bytes.zeros 16) =
            ((Fips205.Bytes.zeros 16) == (Fips205.Bytes.zeros 16)) := by
  native_decide

end Fips205.Move.BytesEqReal
