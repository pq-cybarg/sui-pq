import Move.Value
import Move.Stack
import Move.Opcode
import Move.Step
import Move.Native
import Move.MoveStdlib
import Move.SliceReal
import Move.AdrsSetTypeReal
import Move.AdrsSetKeypairReal
import Move.WotsPkFromSigReal
import Move.AdrsNewAppendSliceReal
import Move.Slice
import Move.AdrsSetters
import Move.AdrsSetTreeIndex
import Move.Thash
import Fips205.Bytes
import Fips205.Params

/-! # `xmss_pk_from_sig` — real disassembled Move bytecode

One XMSS (Merkle) layer: reconstruct the WOTS+ leaf via `wots_pk_from_sig`,
then climb h'=9 auth-path levels. Calling `wots_pk_from_sig` makes this the
**5-deep** nesting case (`xmss` → `wots_pk_from_sig` → `chain` →
`adrs_set_tree_index` → `write_u32_be`), all sharing `&mut adrs`. Uses
`FreezeRef` (the `&mut → &` coercion the compiler inserts before passing
`adrs` to the `&`-typed `wots_pk_from_sig`), modeled as a stack no-op.

The Merkle walk reuses the `bit == 0` node-ordering conditional and the
`append_slice` sibling-copy pattern from FORS.

## Locals
  0:idx(u32) 1:sig 2:msg_n 3:pre 4:adrs(ref) 5:auth 6:bit 7:buf
  8:cur_idx(u32) 9:h 10:i 11:k 12:node 13:wots_sig
-/

namespace Fips205.Move.XmssPkFromSigReal

open Fips205.Move Fips205.Move.Value Fips205.Move.State Fips205
open Fips205.Move.MoveStdlib

def sliceLocalsTail : Array Value := #[Value.u64 0, Value.vecU8 ByteArray.empty]
def adrsSetTypeLocalsTail : Array Value := #[]
def adrsSetKeypairLocalsTail : Array Value := #[]
def adrsSetTreeHeightLocalsTail : Array Value := #[]
def adrsSetTreeIndexLocalsTail : Array Value := #[]
def appendSliceLocalsTail : Array Value := #[Value.u64 0]
/-- wots_pk_from_sig non-arg locals L4..L10: a, d, digits, i, piece, t_adrs, tmp. -/
def wotsPkLocalsTail : Array Value :=
  #[Value.vecU8 ByteArray.empty, Value.u32 0, Value.vecU32 #[], Value.u64 0,
    Value.vecU8 ByteArray.empty, Value.vecU8 ByteArray.empty, Value.vecU8 ByteArray.empty]

abbrev sliceCallee := SliceReal.sliceRealBytecode
abbrev adrsSetTypeCallee := AdrsSetTypeReal.adrsSetTypeRealBytecode
abbrev adrsSetKeypairCallee := AdrsSetKeypairReal.adrsSetKeypairRealBytecode
abbrev adrsSetTreeHeightCallee := AdrsSetKeypairReal.adrsSetTreeHeightRealBytecode
abbrev adrsSetTreeIndexCallee := AdrsSetKeypairReal.adrsSetTreeIndexRealBytecode
abbrev appendSliceCallee := AdrsNewAppendSliceReal.appendSliceRealBytecode
abbrev wotsPkCallee := WotsPkFromSigReal.wotsPkFromSigRealBytecode

def xmssPkFromSigRealBytecode : Bytecode := #[
  -- B0: wots_sig := slice(sig, 0, 35*16); auth := slice(sig, 560, 9*16)
  .CopyLoc 1,                                                      -- 0
  .LdU64 0,                                                        -- 1
  .LdU64 35,                                                       -- 2
  .LdU64 16,                                                       -- 3
  .Mul,                                                            -- 4  560
  .Call sliceCallee sliceLocalsTail 3,                             -- 5
  .StLoc 13,                                                       -- 6  wots_sig
  .MoveLoc 1,                                                      -- 7
  .LdU64 35,                                                       -- 8
  .LdU64 16,                                                       -- 9
  .Mul,                                                            -- 10  560
  .LdU64 9,                                                        -- 11
  .LdU64 16,                                                       -- 12
  .Mul,                                                            -- 13  144
  .Call sliceCallee sliceLocalsTail 3,                             -- 14
  .StLoc 5,                                                        -- 15  auth
  -- adrs_set_type(adrs, wots_hash=0); adrs_set_keypair(adrs, idx)
  .CopyLoc 4,                                                      -- 16
  .LdU8 0,                                                         -- 17
  .Call adrsSetTypeCallee adrsSetTypeLocalsTail 2,                 -- 18
  .CopyLoc 4,                                                      -- 19
  .CopyLoc 0,                                                      -- 20
  .Call adrsSetKeypairCallee adrsSetKeypairLocalsTail 2,           -- 21
  -- node := wots_pk_from_sig(wots_sig, msg_n, prefix, adrs)
  .ImmBorrowLoc 13,                                                -- 22
  .MoveLoc 2,                                                      -- 23
  .CopyLoc 3,                                                      -- 24
  .CopyLoc 4,                                                      -- 25
  .FreezeRef,                                                      -- 26
  .Call wotsPkCallee wotsPkLocalsTail 4,                           -- 27
  .StLoc 12,                                                       -- 28  node
  -- adrs_set_type(adrs, tree=2); adrs_set_keypair(adrs, 0)
  .CopyLoc 4,                                                      -- 29
  .LdU8 2,                                                         -- 30
  .Call adrsSetTypeCallee adrsSetTypeLocalsTail 2,                 -- 31
  .CopyLoc 4,                                                      -- 32
  .LdU32 0,                                                        -- 33
  .Call adrsSetKeypairCallee adrsSetKeypairLocalsTail 2,           -- 34
  .CopyLoc 0,                                                      -- 35
  .StLoc 8,                                                        -- 36  cur_idx := idx
  .LdU64 0,                                                        -- 37
  .StLoc 10,                                                       -- 38  i := 0
  -- B1 (loop: i < 9)
  .CopyLoc 10,                                                     -- 39
  .LdU64 9,                                                        -- 40
  .Lt,                                                            -- 41
  .BrFalse 123,                                                   -- 42
  -- B2
  .Branch 44,                                                     -- 43
  -- B3
  .CopyLoc 4,                                                      -- 44
  .CopyLoc 10,                                                     -- 45
  .CastU32,                                                        -- 46
  .LdU32 1,                                                        -- 47
  .Add,                                                            -- 48  i+1
  .Call adrsSetTreeHeightCallee adrsSetTreeHeightLocalsTail 2,     -- 49
  .CopyLoc 4,                                                      -- 50
  .CopyLoc 8,                                                      -- 51  cur_idx
  .LdU8 1,                                                         -- 52
  .Shr,                                                            -- 53  cur_idx >> 1
  .Call adrsSetTreeIndexCallee adrsSetTreeIndexLocalsTail 2,       -- 54
  .CopyLoc 0,                                                      -- 55  idx
  .CopyLoc 10,                                                     -- 56  i
  .CastU8,                                                         -- 57
  .Shr,                                                            -- 58  idx >> i
  .LdU32 1,                                                        -- 59
  .BitAnd,                                                         -- 60  & 1
  .StLoc 6,                                                        -- 61  bit
  .CopyLoc 3,                                                      -- 62  prefix
  .ReadRef,                                                       -- 63
  .StLoc 7,                                                        -- 64  buf := *prefix
  .MutBorrowLoc 7,                                                 -- 65
  .CopyLoc 4,                                                      -- 66  adrs
  .ReadRef,                                                       -- 67
  .Call vectorAppendCallee vectorAppendLocalsTail 2,               -- 68  buf ++= *adrs
  .MoveLoc 6,                                                      -- 69  bit
  .LdU32 0,                                                        -- 70
  .Eq,                                                            -- 71
  .BrFalse 84,                                                    -- 72
  -- B4 (bit == 0: buf ++= node ; buf ++= auth[i])
  .MutBorrowLoc 7,                                                 -- 73
  .MoveLoc 12,                                                     -- 74  node
  .Call vectorAppendCallee vectorAppendLocalsTail 2,               -- 75
  .MutBorrowLoc 7,                                                 -- 76
  .ImmBorrowLoc 5,                                                -- 77  auth
  .CopyLoc 10,                                                     -- 78  i
  .LdU64 16,                                                       -- 79
  .Mul,                                                            -- 80  i*16
  .LdU64 16,                                                       -- 81
  .Call appendSliceCallee appendSliceLocalsTail 4,                 -- 82
  .Branch 94,                                                     -- 83
  -- B5 (bit != 0: buf ++= auth[i] ; buf ++= node)
  .MutBorrowLoc 7,                                                 -- 84
  .ImmBorrowLoc 5,                                                -- 85
  .CopyLoc 10,                                                     -- 86
  .LdU64 16,                                                       -- 87
  .Mul,                                                            -- 88
  .LdU64 16,                                                       -- 89
  .Call appendSliceCallee appendSliceLocalsTail 4,                 -- 90
  .MutBorrowLoc 7,                                                 -- 91
  .MoveLoc 12,                                                     -- 92  node
  .Call vectorAppendCallee vectorAppendLocalsTail 2,               -- 93
  -- B6 (h := sha256(buf))
  .MoveLoc 7,                                                      -- 94
  .CallNative "sha2_256" 1,                                        -- 95
  .StLoc 9,                                                        -- 96
  .LdU64 0,                                                        -- 97
  .StLoc 11,                                                       -- 98  k := 0
  -- B7 (truncate to 16)
  .CopyLoc 11,                                                     -- 99
  .LdU64 16,                                                       -- 100
  .Lt,                                                            -- 101
  .BrFalse 112,                                                   -- 102
  -- B8
  .Branch 104,                                                    -- 103
  -- B9
  .MutBorrowLoc 9,                                                 -- 104
  .VecPopBack,                                                    -- 105
  .Pop,                                                           -- 106
  .MoveLoc 11,                                                     -- 107
  .LdU64 1,                                                        -- 108
  .Add,                                                           -- 109
  .StLoc 11,                                                      -- 110
  .Branch 99,                                                     -- 111
  -- B10 (node := h ; cur_idx >>= 1 ; i += 1)
  .MoveLoc 9,                                                      -- 112
  .StLoc 12,                                                      -- 113
  .MoveLoc 8,                                                      -- 114
  .LdU8 1,                                                        -- 115
  .Shr,                                                          -- 116
  .StLoc 8,                                                       -- 117  cur_idx >>= 1
  .MoveLoc 10,                                                    -- 118
  .LdU64 1,                                                       -- 119
  .Add,                                                          -- 120
  .StLoc 10,                                                      -- 121  i += 1
  .Branch 39,                                                    -- 122
  -- B11 (epilogue)
  .MoveLoc 3,                                                     -- 123
  .Pop,                                                          -- 124
  .MoveLoc 4,                                                     -- 125
  .Pop,                                                          -- 126
  .MoveLoc 12,                                                    -- 127
  .Ret                                                           -- 128
]

/-- Test wrapper. `adrs` (local 4) is `&mut` → `locRef 14`; backing at 14. -/
def initialState (idx : Nat) (sig msgN pre adrsBytes : ByteArray) : State :=
  { stack := #[]
    locals := #[Value.u32 (UInt32.ofNat idx),  -- 0: idx
                Value.vecU8 sig,                 -- 1: sig
                Value.vecU8 msgN,                -- 2: msg_n
                Value.vecU8 pre,                 -- 3: prefix
                Value.locRef 14,                 -- 4: adrs (ref → 14)
                Value.vecU8 ByteArray.empty,     -- 5: auth
                Value.u32 0,                     -- 6: bit
                Value.vecU8 ByteArray.empty,     -- 7: buf
                Value.u32 0,                     -- 8: cur_idx
                Value.vecU8 ByteArray.empty,     -- 9: h
                Value.u64 0,                     -- 10: i
                Value.u64 0,                     -- 11: k
                Value.vecU8 ByteArray.empty,     -- 12: node
                Value.vecU8 ByteArray.empty,     -- 13: wots_sig
                Value.vecU8 adrsBytes],          -- 14: adrs backing
    pc := 0, error := none }

def xmssPkFromSigRealMoveBC (idx : Nat) (sig msgN pre adrsBytes : ByteArray) : ByteArray :=
  let final := runDefault xmssPkFromSigRealBytecode (initialState idx sig msgN pre adrsBytes)
  match final.stack.back? with
  | some (Value.vecU8 v) => v
  | _ => ByteArray.empty

/-- Byte-level reference mirroring the bytecode, using `wotsPkFromSigRef`
    for the leaf and proven structural primitives for the Merkle walk. -/
def xmssRef (idx : Nat) (sig msgN pre adrsBytes : ByteArray) : ByteArray := Id.run do
  let wotsSig := Slice.sliceMoveBC sig 0 (UInt64.ofNat (35 * 16))
  let auth := Slice.sliceMoveBC sig (UInt64.ofNat (35 * 16)) (UInt64.ofNat (9 * 16))
  let aWots := AdrsSetters.adrsSetKeypairMoveBC
                 (AdrsSetters.adrsSetTypeMoveBC adrsBytes Fips205.AdrsType.wots_hash)
                 (UInt64.ofNat idx)
  let mut node := WotsPkFromSigReal.wotsPkFromSigRef wotsSig msgN pre aWots
  let mut a := AdrsSetters.adrsSetKeypairMoveBC
                 (AdrsSetters.adrsSetTypeMoveBC aWots Fips205.AdrsType.tree) 0
  let mut cur := idx
  for i in [0:9] do
    a := AdrsSetters.adrsSetTreeHeightMoveBC a (UInt64.ofNat (i + 1))
    a := AdrsSetTreeIndex.adrsSetTreeIndexMoveBC a (UInt64.ofNat (cur >>> 1))
    let bit := (idx >>> i) &&& 1
    let sib := Slice.sliceMoveBC auth (UInt64.ofNat (i * 16)) 16
    let merged := if bit = 0 then node ++ sib else sib ++ node
    node := Thash.thashMoveBC pre a merged
    cur := cur >>> 1
  return node

/-! ## Equivalence theorems -/

/-- idx = 0, all-zero sig. -/
example :
    let pkSeed := Fips205.Bytes.hexDecode "ebf2f900070e151c232a31383f464d54"
    let pre := pkSeed ++ Fips205.Bytes.zeros 48
    let adrs := Fips205.Bytes.zeros 22
    let sig := Fips205.Bytes.zeros ((35 + 9) * 16)
    let msg := Fips205.Bytes.zeros 16
    xmssPkFromSigRealMoveBC 0 sig msg pre adrs = xmssRef 0 sig msg pre adrs := by
  native_decide

/-- Non-zero idx (exercises both branches of the bit conditional + keypair). -/
example :
    let pkSeed := Fips205.Bytes.hexDecode "00112233445566778899aabbccddeeff"
    let pre := pkSeed ++ Fips205.Bytes.zeros 48
    let adrs := Fips205.Bytes.zeros 22
    let sig := Fips205.Bytes.zeros ((35 + 9) * 16)
    let msg := Fips205.Bytes.hexDecode "112233445566778899aabbccddeeff00"
    xmssPkFromSigRealMoveBC 0x155 sig msg pre adrs = xmssRef 0x155 sig msg pre adrs := by
  native_decide

/-- Output size invariant: 16 bytes. -/
example :
    let pre := Fips205.Bytes.zeros 64
    (xmssPkFromSigRealMoveBC 0 (Fips205.Bytes.zeros ((35+9)*16)) (Fips205.Bytes.zeros 16)
        pre (Fips205.Bytes.zeros 22)).size = 16 := by
  native_decide

end Fips205.Move.XmssPkFromSigReal
