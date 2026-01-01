import Move.Value
import Move.Stack
import Move.Opcode
import Move.Step
import Move.BaseWReal
import Move.WotsChecksum
import Fips205.Bytes
import Fips205.Wots

/-! # `wots_checksum` — real disassembled Move bytecode

```
wots_checksum(digits: &vector<u32>): vector<u32> {
  L1: csum, L2: csum_bytes, L3: i, L4: j, L5: k, L6: len_bytes, L7: shift
B0-B3 (csum accumulator loop over 32 digits):
  csum += (16 - 1) - (digits[i] as u64)
B4 (compute shift + pack):
  29-38: shift := (8 - (3*4) % 8) % 8 as u8           → 4
  40-43: csum <<= shift
  44-51: len_bytes := (3*4 + 7) / 8                     → 2
  52-53: csum_bytes := vec[]
B5-B7 (zero-fill csum_bytes to len_bytes):
  k loop: csum_bytes.push_back(0)
B8-B11 (BE-pack: j countdown from len_bytes):
  csum_bytes[j-1] := (csum & 0xff) as u8 ; csum >>= 8
B12 (call base_w):
  93: ImmBorrowLoc[2] csum_bytes
  94: LdConst[3](u64: 3)
  95: Call base_w(&vector<u8>, u64): vector<u32>
  96: Ret
}
```

This is the capstone of the bit-math primitives — it exercises EVERY new
VM feature added this session: `Mul`/`Div`/`Mod`/`CastU64`/`CastU8`,
the `Gt` countdown loop, `VecMutBorrow`+`WriteRef` BE-packing, `Call`
into `base_w` (with cross-frame ref via `ImmBorrowLoc`), and polymorphic
mixed-width arithmetic (u64 csum, u32 digit borrow, u8 shift).

The `Call base_w` is the second real `Call`-into-loop-function we've
encoded (after `concat3` and the ADRS setters), and the first where the
callee itself contains nested control flow.
-/

namespace Fips205.Move.WotsChecksumReal

open Fips205.Move Fips205.Move.Value Fips205.Move.State Fips205

/-- `base_w` callee: 5 declared non-arg locals (bits, i, in_idx, out, total).
    Layout in base_w's frame: 0:msg, 1:outlen, then L2..L6.
    From the disassembly's local declaration order:
      L2 bits, L3 i, L4 in_idx, L5 out, L6 total. -/
def baseWLocalsTail : Array Value :=
  #[Value.u64 0,        -- 2: bits
    Value.u64 0,        -- 3: i
    Value.u64 0,        -- 4: in_idx
    Value.vecU32 #[],   -- 5: out
    Value.u32 0]        -- 6: total

def wotsChecksumRealBytecode : Bytecode := #[
  -- B0
  .LdU64 0,                                   -- 0
  .StLoc 1,                                    -- 1  csum := 0
  .LdU64 0,                                    -- 2
  .StLoc 3,                                    -- 3  i := 0
  -- B1 (accumulator test: i < 32)
  .CopyLoc 3,                                  -- 4
  .LdU64 32,                                   -- 5
  .Lt,                                         -- 6
  .BrFalse 27,                                 -- 7
  -- B2
  .Branch 9,                                   -- 8
  -- B3 (csum += (16-1) - digits[i])
  .MoveLoc 1,                                  -- 9   csum
  .LdU64 16,                                   -- 10  (LdConst[0] u64:16)
  .CastU64,                                    -- 11
  .LdU64 1,                                    -- 12
  .Sub,                                        -- 13  16 - 1 = 15
  .CopyLoc 0,                                  -- 14  digits
  .CopyLoc 3,                                  -- 15  i
  .VecU32ImmBorrow,                            -- 16
  .ReadRef,                                    -- 17  digits[i]
  .CastU64,                                    -- 18
  .Sub,                                        -- 19  15 - digits[i]
  .Add,                                        -- 20  csum + (15 - digits[i])
  .StLoc 1,                                    -- 21
  .MoveLoc 3,                                  -- 22
  .LdU64 1,                                    -- 23
  .Add,                                        -- 24
  .StLoc 3,                                    -- 25  i += 1
  .Branch 4,                                   -- 26
  -- B4 (shift + len_bytes + csum_bytes init)
  .LdU64 8,                                    -- 27
  .LdU64 3,                                    -- 28  (LdConst[3] u64:3 = len_2)
  .LdU64 4,                                    -- 29  (LdConst[1] u64:4 = lg_w)
  .Mul,                                        -- 30  3*4 = 12
  .LdU64 8,                                    -- 31
  .Mod,                                        -- 32  12 % 8 = 4
  .Sub,                                        -- 33  8 - 4 = 4
  .LdU64 8,                                    -- 34
  .Mod,                                        -- 35  4 % 8 = 4
  .CastU8,                                     -- 36
  .StLoc 7,                                    -- 37  shift := 4
  .MoveLoc 1,                                  -- 38  csum
  .MoveLoc 7,                                  -- 39  shift
  .Shl,                                        -- 40  csum << shift
  .StLoc 1,                                    -- 41
  .LdU64 3,                                    -- 42  len_2
  .LdU64 4,                                    -- 43  lg_w
  .Mul,                                        -- 44  12
  .LdU64 7,                                    -- 45
  .Add,                                        -- 46  19
  .LdU64 8,                                    -- 47
  .Div,                                        -- 48  19 / 8 = 2
  .StLoc 6,                                    -- 49  len_bytes := 2
  .LdConst (Value.vecU8 ByteArray.empty),      -- 50  (LdConst[18] empty vec)
  .StLoc 2,                                    -- 51  csum_bytes := vec[]
  .LdU64 0,                                    -- 52
  .StLoc 5,                                    -- 53  k := 0
  -- B5 (zero-fill loop: k < len_bytes)
  .CopyLoc 5,                                  -- 54
  .CopyLoc 6,                                  -- 55
  .Lt,                                         -- 56
  .BrFalse 67,                                 -- 57
  -- B6
  .Branch 59,                                  -- 58
  -- B7 (csum_bytes.push_back(0))
  .MutBorrowLoc 2,                             -- 59
  .LdU8 0,                                     -- 60
  .VecPushBack,                                -- 61
  .MoveLoc 5,                                  -- 62
  .LdU64 1,                                    -- 63
  .Add,                                        -- 64
  .StLoc 5,                                    -- 65  k += 1
  .Branch 54,                                  -- 66
  -- B8 (j := len_bytes)
  .MoveLoc 6,                                  -- 67
  .StLoc 4,                                    -- 68  j := len_bytes
  -- B9 (BE-pack countdown: j > 0)
  .CopyLoc 4,                                  -- 69
  .LdU64 0,                                    -- 70
  .Gt,                                         -- 71
  .BrFalse 91,                                 -- 72
  -- B10
  .Branch 74,                                  -- 73
  -- B11 (csum_bytes[j-1] := csum & 0xff ; csum >>= 8)
  .MoveLoc 4,                                  -- 74
  .LdU64 1,                                    -- 75
  .Sub,                                        -- 76
  .StLoc 4,                                    -- 77  j -= 1
  .CopyLoc 1,                                  -- 78  csum
  .LdU64 255,                                  -- 79
  .BitAnd,                                     -- 80
  .CastU8,                                     -- 81  (csum & 0xff) as u8
  .MutBorrowLoc 2,                             -- 82
  .CopyLoc 4,                                  -- 83  j
  .VecMutBorrow,                               -- 84
  .WriteRef,                                   -- 85  csum_bytes[j] := byte
  .MoveLoc 1,                                  -- 86  csum
  .LdU8 8,                                     -- 87
  .Shr,                                        -- 88  csum >> 8
  .StLoc 1,                                    -- 89
  .Branch 69,                                  -- 90
  -- B12 (call base_w(csum_bytes, 3))
  .ImmBorrowLoc 2,                             -- 91
  .LdU64 3,                                    -- 92  (LdConst[3] u64:3)
  .Call BaseWReal.baseWRealBytecode baseWLocalsTail 2,  -- 93
  .Ret                                         -- 94
]

def initialState (digits : Array UInt32) : State :=
  { stack := #[]
    locals := #[Value.vecU32 digits,           -- 0: digits
                Value.u64 0,                    -- 1: csum
                Value.vecU8 ByteArray.empty,    -- 2: csum_bytes
                Value.u64 0,                    -- 3: i
                Value.u64 0,                    -- 4: j
                Value.u64 0,                    -- 5: k
                Value.u64 0,                    -- 6: len_bytes
                Value.u8 0],                    -- 7: shift
    pc := 0, error := none }

def wotsChecksumRealMoveBC (digits : Array UInt32) : Array UInt32 :=
  let final := runDefault wotsChecksumRealBytecode (initialState digits)
  match final.stack.back? with
  | some (Value.vecU32 v) => v
  | _ => #[]

/-! ## Equivalence theorems -/

/-- All-zero digits: csum = 32*15 = 480 = 0x1e0 → shifted 0x1e00 → nibbles [1,14,0]. -/
example : (wotsChecksumRealMoveBC (Array.replicate 32 (0 : UInt32))).map (·.toNat) =
            Fips205.Wots.wotsChecksum (Array.replicate 32 0) := by
  native_decide

/-- All-0xf digits: csum = 0 → nibbles [0,0,0]. -/
example : (wotsChecksumRealMoveBC (Array.replicate 32 (0xf : UInt32))).map (·.toNat) =
            Fips205.Wots.wotsChecksum (Array.replicate 32 0xf) := by
  native_decide

/-- Real-shaped digit array from base_w of a 16-byte msg. -/
example :
    let msg := Fips205.Bytes.hexDecode "112233445566778899aabbccddeeff00"
    let digits := Fips205.Wots.baseW msg 32
    let digitsU32 : Array UInt32 := digits.map (fun n => UInt32.ofNat n)
    (wotsChecksumRealMoveBC digitsU32).map (·.toNat) =
      Fips205.Wots.wotsChecksum digits := by
  native_decide

/-- All-1 digits: csum = 32*14 = 448 = 0x1c0 → shifted 0x1c00 → nibbles [1,12,0]. -/
example : (wotsChecksumRealMoveBC (Array.replicate 32 (1 : UInt32))).map (·.toNat) =
            Fips205.Wots.wotsChecksum (Array.replicate 32 1) := by
  native_decide

/-- Size invariant: 3 digits. -/
example : (wotsChecksumRealMoveBC (Array.replicate 32 (0 : UInt32))).size = 3 := by
  native_decide

/-- The real-disassembly encoding matches our previous structural encoding. -/
example :
    let digits := (Fips205.Wots.baseW (Fips205.Bytes.zeros 16) 32).map (fun n => UInt32.ofNat n)
    wotsChecksumRealMoveBC digits =
      Fips205.Move.WotsChecksum.wotsChecksumMoveBC digits := by
  native_decide

end Fips205.Move.WotsChecksumReal
