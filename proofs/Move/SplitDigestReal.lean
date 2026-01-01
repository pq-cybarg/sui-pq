import Move.Value
import Move.Stack
import Move.Opcode
import Move.Step
import Move.SliceReal
import Move.SplitDigest
import Fips205.Bytes
import Fips205.Verify

/-! # `split_digest` — real disassembled Move bytecode

Returns a 3-tuple `(md: vector<u8>, tree_idx: u64, leaf_idx: u32)`. In
Move bytecode a multi-value return leaves each value on the stack at
`Ret` (leftmost at bottom). The function:

  * computes `md_bytes`, `tree_bits`, `tree_bytes`, `leaf_bytes` from the
    FIPS-205 params via `Mul`/`Add`/`Div`/`Sub` on the constant pool,
  * `Call slice(digest, 0, md_bytes)` → md,
  * BE-accumulates `tree_bytes` bytes into `tree_idx`, masks to `tree_bits`,
  * BE-accumulates `leaf_bytes` bytes into `leaf_idx`, masks to `h_prime=9`,
  * returns the triple.

Exercises `Mul`/`Div` on params, mixed `u64`/`u32` BE accumulation with
`CastU64`/`CastU32`, dynamic mask `(1 << bits) - 1` via polymorphic `Shl`,
and `Call slice` (a loop-bearing callee, like base_w).

## Locals (from disassembly)
  0: digest, 1: i, 2: leaf_bytes, 3: leaf_idx(u32), 4: leaf_mask(u32),
  5: md, 6: md_bytes, 7: p, 8: tree_bits, 9: tree_bytes, 10: tree_idx,
  11: tree_mask
-/

namespace Fips205.Move.SplitDigestReal

open Fips205.Move Fips205.Move.Value Fips205.Move.State Fips205

/-- `slice` callee: 2 declared non-arg locals (i, out) — see SliceReal. -/
def sliceLocalsTail : Array Value := #[Value.u64 0, Value.vecU8 ByteArray.empty]

def splitDigestRealBytecode : Bytecode := #[
  -- B0: param computation + Call slice
  .LdU64 14,                                   -- 0  (k = 14)
  .LdU64 12,                                   -- 1  (a = 12)
  .Mul,                                        -- 2  14*12 = 168
  .LdU64 7,                                    -- 3
  .Add,                                        -- 4  175
  .LdU64 8,                                    -- 5
  .Div,                                        -- 6  175/8 = 21
  .StLoc 6,                                    -- 7  md_bytes := 21
  .LdU64 9,                                    -- 8  (h_prime = 9)
  .LdU64 7,                                    -- 9
  .Mul,                                        -- 10  9*7 = 63
  .LdU64 9,                                    -- 11
  .Sub,                                        -- 12  63-9 = 54
  .StLoc 8,                                    -- 13  tree_bits := 54
  .CopyLoc 8,                                  -- 14
  .LdU64 7,                                    -- 15
  .Add,                                        -- 16  61
  .LdU64 8,                                    -- 17
  .Div,                                        -- 18  61/8 = 7
  .StLoc 9,                                    -- 19  tree_bytes := 7
  .LdU64 9,                                    -- 20
  .LdU64 7,                                    -- 21
  .Add,                                        -- 22  16
  .LdU64 8,                                    -- 23
  .Div,                                        -- 24  16/8 = 2
  .StLoc 2,                                    -- 25  leaf_bytes := 2
  .CopyLoc 0,                                  -- 26  digest
  .LdU64 0,                                    -- 27
  .CopyLoc 6,                                  -- 28  md_bytes
  .Call SliceReal.sliceRealBytecode sliceLocalsTail 3,  -- 29
  .StLoc 5,                                    -- 30  md := slice(digest, 0, md_bytes)
  .LdU64 0,                                    -- 31
  .StLoc 10,                                   -- 32  tree_idx := 0
  .LdU64 0,                                    -- 33
  .StLoc 1,                                    -- 34  i := 0
  -- B1 (tree accumulation test: i < tree_bytes)
  .CopyLoc 1,                                  -- 35
  .CopyLoc 9,                                  -- 36
  .Lt,                                         -- 37
  .BrFalse 57,                                 -- 38
  -- B2
  .Branch 40,                                  -- 39
  -- B3 (tree_idx = (tree_idx << 8) | digest[md_bytes + i])
  .MoveLoc 10,                                 -- 40
  .LdU8 8,                                     -- 41
  .Shl,                                        -- 42  tree_idx << 8
  .CopyLoc 0,                                  -- 43
  .CopyLoc 6,                                  -- 44  md_bytes
  .CopyLoc 1,                                  -- 45  i
  .Add,                                        -- 46
  .VecImmBorrow,                               -- 47
  .ReadRef,                                    -- 48
  .CastU64,                                    -- 49
  .BitOr,                                      -- 50
  .StLoc 10,                                   -- 51  tree_idx := …
  .MoveLoc 1,                                  -- 52
  .LdU64 1,                                    -- 53
  .Add,                                        -- 54
  .StLoc 1,                                    -- 55  i += 1
  .Branch 35,                                  -- 56
  -- B4 (tree_mask = (1 << tree_bits) - 1 ; tree_idx &= mask)
  .LdU64 1,                                    -- 57
  .MoveLoc 8,                                  -- 58  tree_bits
  .CastU8,                                     -- 59
  .Shl,                                        -- 60  1 << tree_bits
  .LdU64 1,                                    -- 61
  .Sub,                                        -- 62  mask
  .StLoc 11,                                   -- 63  tree_mask
  .MoveLoc 10,                                 -- 64
  .MoveLoc 11,                                 -- 65
  .BitAnd,                                     -- 66
  .StLoc 10,                                   -- 67  tree_idx &= mask
  .LdU32 0,                                    -- 68
  .StLoc 3,                                    -- 69  leaf_idx := 0 (u32)
  .LdU64 0,                                    -- 70
  .StLoc 7,                                    -- 71  p := 0
  -- B5 (leaf accumulation test: p < leaf_bytes)
  .CopyLoc 7,                                  -- 72
  .CopyLoc 2,                                  -- 73
  .Lt,                                         -- 74
  .BrFalse 96,                                 -- 75
  -- B6
  .Branch 77,                                  -- 76
  -- B7 (leaf_idx = (leaf_idx << 8) | digest[md_bytes + tree_bytes + p])
  .MoveLoc 3,                                  -- 77
  .LdU8 8,                                     -- 78
  .Shl,                                        -- 79  leaf_idx << 8 (u32)
  .CopyLoc 0,                                  -- 80
  .CopyLoc 6,                                  -- 81  md_bytes
  .CopyLoc 9,                                  -- 82  tree_bytes
  .Add,                                        -- 83
  .CopyLoc 7,                                  -- 84  p
  .Add,                                        -- 85
  .VecImmBorrow,                               -- 86
  .ReadRef,                                    -- 87
  .CastU32,                                    -- 88
  .BitOr,                                      -- 89
  .StLoc 3,                                    -- 90  leaf_idx := …
  .MoveLoc 7,                                  -- 91
  .LdU64 1,                                    -- 92
  .Add,                                        -- 93
  .StLoc 7,                                    -- 94  p += 1
  .Branch 72,                                  -- 95
  -- B8 (leaf_mask = (1 << 9) - 1 ; leaf_idx &= mask ; return triple)
  .MoveLoc 0,                                  -- 96
  .Pop,                                        -- 97
  .LdU32 1,                                    -- 98
  .LdU64 9,                                    -- 99
  .CastU8,                                     -- 100
  .Shl,                                        -- 101  1 << 9 (u32)
  .LdU32 1,                                    -- 102
  .Sub,                                        -- 103  0x1ff
  .StLoc 4,                                    -- 104  leaf_mask
  .MoveLoc 3,                                  -- 105
  .MoveLoc 4,                                  -- 106
  .BitAnd,                                     -- 107
  .StLoc 3,                                    -- 108  leaf_idx &= mask
  .MoveLoc 5,                                  -- 109  push md
  .MoveLoc 10,                                 -- 110  push tree_idx
  .MoveLoc 3,                                  -- 111  push leaf_idx
  .Ret                                         -- 112
]

def initialState (digest : ByteArray) : State :=
  { stack := #[]
    locals := #[Value.vecU8 digest,           -- 0: digest
                Value.u64 0,                    -- 1: i
                Value.u64 0,                    -- 2: leaf_bytes
                Value.u32 0,                    -- 3: leaf_idx
                Value.u32 0,                    -- 4: leaf_mask
                Value.vecU8 ByteArray.empty,    -- 5: md
                Value.u64 0,                    -- 6: md_bytes
                Value.u64 0,                    -- 7: p
                Value.u64 0,                    -- 8: tree_bits
                Value.u64 0,                    -- 9: tree_bytes
                Value.u64 0,                    -- 10: tree_idx
                Value.u64 0],                   -- 11: tree_mask
    pc := 0, error := none }

def splitDigestRealMoveBC (digest : ByteArray) : ByteArray × Nat × Nat :=
  let final := runDefault splitDigestRealBytecode (initialState digest)
  if final.stack.size ≥ 3 then
    let md      := final.stack[final.stack.size - 3]!
    let treeIdx := final.stack[final.stack.size - 2]!
    let leafIdx := final.stack[final.stack.size - 1]!
    (md.asVecU8!, treeIdx.asU64!.toNat, leafIdx.asU32!.toNat)
  else
    (ByteArray.empty, 0, 0)

/-! ## Equivalence theorems -/

example :
    let digest := Fips205.Bytes.zeros 30
    splitDigestRealMoveBC digest = Verify.splitDigest digest := by
  native_decide

example :
    let digest := Fips205.Bytes.hexDecode
      "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
    splitDigestRealMoveBC digest = Verify.splitDigest digest := by
  native_decide

example :
    let digest := Fips205.Bytes.hexDecode
      "0123456789abcdef0123456789abcdef0123456789aabbccddeeff112233abcd"
    splitDigestRealMoveBC digest = Verify.splitDigest digest := by
  native_decide

/-- The real-disassembly encoding matches our previous structural encoding. -/
example :
    let digest := Fips205.Bytes.hexDecode
      "0123456789abcdef0123456789abcdef0123456789aabbccddeeff112233abcd"
    splitDigestRealMoveBC digest = Fips205.Move.SplitDigest.splitDigestMoveBC digest := by
  native_decide

end Fips205.Move.SplitDigestReal
