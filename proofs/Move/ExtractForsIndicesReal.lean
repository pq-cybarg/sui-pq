import Move.Value
import Move.Stack
import Move.Opcode
import Move.Step
import Move.ExtractForsIndices
import Fips205.Bytes
import Fips205.Verify

/-! # `extract_fors_indices` — real disassembled Move bytecode

Nested-loop bit-extraction: 14 outputs × 12 bits each. The outer loop
counts `i` from 0 to 14; the inner loop reads 12 successive bits from
`md` (a 21-byte digest) starting at `bit_off`, packs them MSB-first into
a u32 `v`, then `out.push_back(v)`.

The bit extraction pattern at PC 24-39 is interesting:
  md[bit_idx >> 3]                 — fetch the byte holding the bit
  >> (7 - (bit_idx & 7))           — shift to LSB
  & 1                              — isolate the bit
This is the canonical big-endian bit-stream reader: bit 0 of the stream
is the MSB of byte 0, bit 8 is the MSB of byte 1, etc.

Exercises:
  * Nested loops with shared `MutBorrowLoc` of a `vector<u32>` local.
  * Polymorphic `Shl` on a `u32` shifted by `u8`.
  * `CastU8` of a `u64 & 7` for the dynamic shift count.
-/

namespace Fips205.Move.ExtractForsIndicesReal

open Fips205.Move Fips205.Move.Value Fips205.Move.State Fips205

def extractForsIndicesRealBytecode : Bytecode := #[
  -- B0
  .LdConst (Value.vecU32 #[]),                -- 0
  .StLoc 6,                                    -- 1
  .LdU64 0,                                    -- 2
  .StLoc 4,                                    -- 3
  .LdU64 0,                                    -- 4
  .StLoc 5,                                    -- 5
  -- B1 (outer test: i < 14)
  .CopyLoc 5,                                  -- 6
  .LdU64 14,                                   -- 7
  .Lt,                                         -- 8
  .BrFalse 64,                                 -- 9
  -- B2
  .Branch 11,                                  -- 10
  -- B3 (per-output init: v := 0, b := 0)
  .LdU32 0,                                    -- 11
  .StLoc 7,                                    -- 12
  .LdU64 0,                                    -- 13
  .StLoc 1,                                    -- 14
  -- B4 (inner test: b < 12)
  .CopyLoc 1,                                  -- 15
  .LdU64 12,                                   -- 16
  .Lt,                                         -- 17
  .BrFalse 52,                                 -- 18
  -- B5
  .Branch 20,                                  -- 19
  -- B6 (extract one bit and append to v)
  .CopyLoc 4,                                  -- 20
  .CopyLoc 1,                                  -- 21
  .Add,                                        -- 22
  .StLoc 3,                                    -- 23  bit_idx := bit_off + b
  .CopyLoc 0,                                  -- 24
  .CopyLoc 3,                                  -- 25
  .LdU8 3,                                     -- 26
  .Shr,                                        -- 27  bit_idx >> 3 (u64 >> u8)
  .VecImmBorrow,                               -- 28
  .ReadRef,                                    -- 29  md[bit_idx>>3]
  .LdU8 7,                                     -- 30
  .MoveLoc 3,                                  -- 31  bit_idx
  .LdU64 7,                                    -- 32
  .BitAnd,                                     -- 33  bit_idx & 7
  .CastU8,                                     -- 34
  .Sub,                                        -- 35  7 - (bit_idx&7)
  .Shr,                                        -- 36  byte >> shift
  .LdU8 1,                                     -- 37
  .BitAnd,                                     -- 38  & 1
  .CastU32,                                    -- 39
  .StLoc 2,                                    -- 40  bit := …
  .MoveLoc 7,                                  -- 41  v
  .LdU8 1,                                     -- 42
  .Shl,                                        -- 43  v << 1 (u32 << u8 → u32)
  .MoveLoc 2,                                  -- 44  bit
  .BitOr,                                      -- 45  | bit
  .StLoc 7,                                    -- 46  v := …
  .MoveLoc 1,                                  -- 47
  .LdU64 1,                                    -- 48
  .Add,                                        -- 49
  .StLoc 1,                                    -- 50  b := b + 1
  .Branch 15,                                  -- 51
  -- B7 (emit v)
  .MutBorrowLoc 6,                             -- 52
  .MoveLoc 7,                                  -- 53
  .VecU32PushBack,                             -- 54  out.push_back(v)
  .MoveLoc 4,                                  -- 55
  .LdU64 12,                                   -- 56
  .Add,                                        -- 57
  .StLoc 4,                                    -- 58  bit_off += 12
  .MoveLoc 5,                                  -- 59
  .LdU64 1,                                    -- 60
  .Add,                                        -- 61
  .StLoc 5,                                    -- 62  i += 1
  .Branch 6,                                   -- 63
  -- B8 (epilogue)
  .MoveLoc 0,                                  -- 64
  .Pop,                                        -- 65
  .MoveLoc 6,                                  -- 66
  .Ret                                         -- 67
]

def initialState (md : ByteArray) : State :=
  { stack := #[]
    locals := #[Value.vecU8 md,           -- 0: md
                Value.u64 0,                -- 1: b
                Value.u32 0,                -- 2: bit
                Value.u64 0,                -- 3: bit_idx
                Value.u64 0,                -- 4: bit_off
                Value.u64 0,                -- 5: i
                Value.vecU32 #[],           -- 6: out
                Value.u32 0],               -- 7: v
    pc := 0, error := none }

def extractForsIndicesRealMoveBC (md : ByteArray) : Array UInt32 :=
  let final := runDefault extractForsIndicesRealBytecode (initialState md)
  match final.stack.back? with
  | some (Value.vecU32 v) => v
  | _ => #[]

/-! ## Equivalence theorems -/

example : (extractForsIndicesRealMoveBC (Fips205.Bytes.zeros 21)).size = 14 := by
  native_decide

example : extractForsIndicesRealMoveBC (Fips205.Bytes.zeros 21) = Array.replicate 14 0 := by
  native_decide

example :
    let md := Fips205.Bytes.hexDecode "deadbeefcafebabe123456789aabbccddef0fef0aa"
    (extractForsIndicesRealMoveBC md).map (·.toNat) = Verify.extractForsIndices md := by
  native_decide

/-- All-0xff input: every 12-bit window is 0xfff. -/
example :
    let md := Fips205.Bytes.hexDecode "ffffffffffffffffffffffffffffffffffffffffff"
    extractForsIndicesRealMoveBC md = Array.replicate 14 0xfff := by
  native_decide

/-- The real-disassembly encoding matches our previous structural encoding. -/
example :
    let md := Fips205.Bytes.hexDecode "deadbeefcafebabe123456789aabbccddef0fef0aa"
    extractForsIndicesRealMoveBC md =
      Fips205.Move.ExtractForsIndices.extractForsIndicesMoveBC md := by
  native_decide

end Fips205.Move.ExtractForsIndicesReal
