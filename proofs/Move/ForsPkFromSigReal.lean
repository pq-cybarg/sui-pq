import Move.Value
import Move.Stack
import Move.Opcode
import Move.Step
import Move.Native
import Move.MoveStdlib
import Move.ExtractForsIndicesReal
import Move.SliceReal
import Move.AdrsSetTypeReal
import Move.AdrsSetKeypairReal
import Move.ThashReal
import Move.AdrsNewAppendSliceReal
import Move.Slice
import Move.AdrsSetters
import Move.AdrsSetTreeIndex
import Move.Thash
import Fips205.Bytes
import Fips205.Verify
import Fips205.Params

/-! # `fors_pk_from_sig` — real disassembled Move bytecode

FORS public-key reconstruction: K=14 Merkle trees of height A=12, each
producing one root; the K roots are concatenated and compressed with a
final `thash`. 193 opcodes — the largest function in the module.

New control-flow exercised: an `if bit == 0 { node‖sib } else { sib‖node }`
**conditional** inside the Merkle-walk (B6 → B7/B8), driven by the parity
of the current node index. Also uses `Call append_slice` (the `&mut dst`
extend-with-slice helper) for the auth-path sibling, in addition to the
now-familiar `Call`s into `extract_fors_indices`, `slice`, the ADRS
setters, `thash`, and `vector::append`.

## Locals (24 total, L0-L23)
  0:sig_fors 1:md 2:pre 3:adrs(ref) 4:auth_path 5:bit(u32) 6:buf
  7:chunk_bytes 8:cur(u32) 9:h 10:i 11:idx(u32) 12:indices(vecU32)
  13:j 14:leaf_adrs 15:leaf_tree_index(u32) 16:node 17:nodes_at_height(u32)
  18:off 19:p 20:parent_idx(u32) 21:roots_adrs 22:roots_buf 23:sk_leaf
-/

namespace Fips205.Move.ForsPkFromSigReal

open Fips205.Move Fips205.Move.Value Fips205.Move.State Fips205
open Fips205.Move.MoveStdlib

-- callee local tails
def extractForsLocalsTail : Array Value :=
  -- extract_fors_indices L1..L7: b,bit,bit_idx,bit_off,i,out,v
  #[Value.u64 0, Value.u32 0, Value.u64 0, Value.u64 0, Value.u64 0, Value.vecU32 #[], Value.u32 0]
def sliceLocalsTail : Array Value := #[Value.u64 0, Value.vecU8 ByteArray.empty]
def adrsSetTypeLocalsTail : Array Value := #[]
def adrsSetTreeHeightLocalsTail : Array Value := #[]
def adrsSetTreeIndexLocalsTail : Array Value := #[]
def thashLocalsTail : Array Value :=
  #[Value.vecU8 ByteArray.empty, Value.vecU8 ByteArray.empty, Value.u64 0]
/-- append_slice declares one non-arg local: i (L4). -/
def appendSliceLocalsTail : Array Value := #[Value.u64 0]

abbrev extractForsCallee := ExtractForsIndicesReal.extractForsIndicesRealBytecode
abbrev sliceCallee := SliceReal.sliceRealBytecode
abbrev adrsSetTypeCallee := AdrsSetTypeReal.adrsSetTypeRealBytecode
abbrev adrsSetTreeHeightCallee := AdrsSetKeypairReal.adrsSetTreeHeightRealBytecode
abbrev adrsSetTreeIndexCallee := AdrsSetKeypairReal.adrsSetTreeIndexRealBytecode
abbrev thashCallee := ThashReal.thashRealBytecode
abbrev appendSliceCallee := AdrsNewAppendSliceReal.appendSliceRealBytecode

def forsPkFromSigRealBytecode : Bytecode := #[
  -- B0
  .LdU64 1,                                                          -- 0
  .LdU64 12,                                                         -- 1
  .Add,                                                              -- 2  (1+a)
  .LdU64 16,                                                         -- 3
  .Mul,                                                              -- 4  chunk_bytes = 13*16 = 208
  .StLoc 7,                                                          -- 5
  .MoveLoc 1,                                                        -- 6  md
  .Call extractForsCallee extractForsLocalsTail 1,                   -- 7
  .StLoc 12,                                                         -- 8  indices
  .LdConst (Value.vecU8 ByteArray.empty),                           -- 9
  .StLoc 22,                                                         -- 10 roots_buf := vec[]
  .LdU64 0,                                                          -- 11
  .StLoc 10,                                                         -- 12 i := 0
  -- B1 (outer loop: i < 14)
  .CopyLoc 10,                                                       -- 13
  .LdU64 14,                                                         -- 14
  .Lt,                                                              -- 15
  .BrFalse 174,                                                     -- 16
  -- B2
  .Branch 18,                                                       -- 17
  -- B3
  .CopyLoc 10,                                                      -- 18
  .CopyLoc 7,                                                       -- 19
  .Mul,                                                            -- 20  off = i*chunk_bytes
  .StLoc 18,                                                       -- 21
  .CopyLoc 0,                                                      -- 22  sig_fors
  .CopyLoc 18,                                                     -- 23  off
  .LdU64 16,                                                       -- 24
  .Call sliceCallee sliceLocalsTail 3,                             -- 25  slice(sig_fors, off, 16)
  .StLoc 23,                                                       -- 26  sk_leaf
  .CopyLoc 0,                                                      -- 27
  .MoveLoc 18,                                                     -- 28  off
  .LdU64 16,                                                       -- 29
  .Add,                                                           -- 30  off+16
  .LdU64 12,                                                       -- 31
  .LdU64 16,                                                       -- 32
  .Mul,                                                           -- 33  12*16 = 192
  .Call sliceCallee sliceLocalsTail 3,                             -- 34  slice(sig_fors, off+16, 192)
  .StLoc 4,                                                        -- 35  auth_path
  .ImmBorrowLoc 12,                                                -- 36
  .CopyLoc 10,                                                     -- 37
  .VecU32ImmBorrow,                                               -- 38
  .ReadRef,                                                       -- 39
  .StLoc 11,                                                       -- 40  idx := indices[i]
  .CopyLoc 3,                                                      -- 41
  .ReadRef,                                                       -- 42
  .StLoc 14,                                                       -- 43  leaf_adrs := *adrs
  .MutBorrowLoc 14,                                                -- 44
  .LdU8 3,                                                         -- 45
  .Call adrsSetTypeCallee adrsSetTypeLocalsTail 2,                 -- 46  set_type(fors_tree)
  .MutBorrowLoc 14,                                                -- 47
  .LdU32 0,                                                        -- 48
  .Call adrsSetTreeHeightCallee adrsSetTreeHeightLocalsTail 2,     -- 49  set_tree_height(0)
  .CopyLoc 10,                                                     -- 50  i
  .CastU32,                                                        -- 51
  .LdU64 12,                                                       -- 52
  .CastU8,                                                         -- 53
  .Shl,                                                            -- 54  i << 12
  .CopyLoc 11,                                                     -- 55  idx
  .Add,                                                            -- 56  (i<<12) + idx
  .StLoc 15,                                                       -- 57  leaf_tree_index
  .MutBorrowLoc 14,                                                -- 58
  .MoveLoc 15,                                                     -- 59
  .Call adrsSetTreeIndexCallee adrsSetTreeIndexLocalsTail 2,       -- 60  set_tree_index(leaf_tree_index)
  .CopyLoc 2,                                                      -- 61  prefix
  .ImmBorrowLoc 14,                                                -- 62  leaf_adrs
  .ImmBorrowLoc 23,                                               -- 63  sk_leaf
  .Call thashCallee thashLocalsTail 3,                             -- 64  node := thash(pre, leaf_adrs, sk_leaf)
  .StLoc 16,                                                       -- 65
  .MoveLoc 11,                                                     -- 66
  .StLoc 8,                                                        -- 67  cur := idx
  .LdU64 0,                                                        -- 68
  .StLoc 13,                                                       -- 69  j := 0
  -- B4 (inner loop: j < 12)
  .CopyLoc 13,                                                     -- 70
  .LdU64 12,                                                       -- 71
  .Lt,                                                            -- 72
  .BrFalse 166,                                                   -- 73
  -- B5
  .Branch 75,                                                     -- 74
  -- B6
  .MutBorrowLoc 14,                                                -- 75
  .CopyLoc 13,                                                     -- 76
  .CastU32,                                                        -- 77
  .LdU32 1,                                                        -- 78
  .Add,                                                            -- 79  j+1
  .Call adrsSetTreeHeightCallee adrsSetTreeHeightLocalsTail 2,     -- 80  set_tree_height(j+1)
  .LdU32 1,                                                        -- 81
  .LdU64 12,                                                       -- 82
  .CopyLoc 13,                                                     -- 83
  .Sub,                                                            -- 84  12 - j
  .LdU64 1,                                                        -- 85
  .Sub,                                                            -- 86  12 - j - 1
  .CastU8,                                                         -- 87
  .Shl,                                                            -- 88  1 << (11-j) = nodes_at_height
  .StLoc 17,                                                       -- 89
  .CopyLoc 10,                                                     -- 90  i
  .CastU32,                                                        -- 91
  .MoveLoc 17,                                                     -- 92  nodes_at_height
  .Mul,                                                            -- 93  i * nodes_at_height
  .CopyLoc 8,                                                      -- 94  cur
  .LdU8 1,                                                         -- 95
  .Shr,                                                            -- 96  cur >> 1
  .Add,                                                            -- 97  parent_idx
  .StLoc 20,                                                       -- 98
  .MutBorrowLoc 14,                                                -- 99
  .MoveLoc 20,                                                     -- 100
  .Call adrsSetTreeIndexCallee adrsSetTreeIndexLocalsTail 2,       -- 101 set_tree_index(parent_idx)
  .CopyLoc 8,                                                      -- 102 cur
  .LdU32 1,                                                        -- 103
  .BitAnd,                                                         -- 104 cur & 1
  .StLoc 5,                                                        -- 105 bit
  .CopyLoc 2,                                                      -- 106 prefix
  .ReadRef,                                                       -- 107
  .StLoc 6,                                                        -- 108 buf := *prefix
  .MutBorrowLoc 6,                                                 -- 109
  .CopyLoc 14,                                                     -- 110 leaf_adrs
  .Call vectorAppendCallee vectorAppendLocalsTail 2,               -- 111 buf ++= leaf_adrs
  .MoveLoc 5,                                                      -- 112 bit
  .LdU32 0,                                                        -- 113
  .Eq,                                                            -- 114 bit == 0
  .BrFalse 127,                                                   -- 115
  -- B7 (bit == 0: buf ++= node ; buf ++= auth_path[j])
  .MutBorrowLoc 6,                                                 -- 116
  .MoveLoc 16,                                                     -- 117 node
  .Call vectorAppendCallee vectorAppendLocalsTail 2,               -- 118
  .MutBorrowLoc 6,                                                 -- 119
  .ImmBorrowLoc 4,                                                -- 120 auth_path
  .CopyLoc 13,                                                     -- 121 j
  .LdU64 16,                                                       -- 122
  .Mul,                                                            -- 123 j*16
  .LdU64 16,                                                       -- 124
  .Call appendSliceCallee appendSliceLocalsTail 4,                 -- 125 buf ++= auth_path[j*16..+16]
  .Branch 137,                                                    -- 126
  -- B8 (bit != 0: buf ++= auth_path[j] ; buf ++= node)
  .MutBorrowLoc 6,                                                 -- 127
  .ImmBorrowLoc 4,                                                -- 128
  .CopyLoc 13,                                                     -- 129
  .LdU64 16,                                                       -- 130
  .Mul,                                                            -- 131
  .LdU64 16,                                                       -- 132
  .Call appendSliceCallee appendSliceLocalsTail 4,                 -- 133
  .MutBorrowLoc 6,                                                 -- 134
  .MoveLoc 16,                                                     -- 135 node
  .Call vectorAppendCallee vectorAppendLocalsTail 2,               -- 136
  -- B9 (h := sha256(buf))
  .MoveLoc 6,                                                      -- 137
  .CallNative "sha2_256" 1,                                        -- 138
  .StLoc 9,                                                        -- 139
  .LdU64 0,                                                        -- 140
  .StLoc 19,                                                       -- 141 p := 0
  -- B10 (truncate h to 16)
  .CopyLoc 19,                                                     -- 142
  .LdU64 16,                                                       -- 143
  .Lt,                                                            -- 144
  .BrFalse 155,                                                   -- 145
  -- B11
  .Branch 147,                                                    -- 146
  -- B12
  .MutBorrowLoc 9,                                                 -- 147
  .VecPopBack,                                                    -- 148
  .Pop,                                                           -- 149
  .MoveLoc 19,                                                     -- 150
  .LdU64 1,                                                        -- 151
  .Add,                                                           -- 152
  .StLoc 19,                                                      -- 153
  .Branch 142,                                                    -- 154
  -- B13 (node := h ; cur >>= 1 ; j += 1)
  .MoveLoc 9,                                                      -- 155
  .StLoc 16,                                                      -- 156
  .MoveLoc 8,                                                      -- 157
  .LdU8 1,                                                        -- 158
  .Shr,                                                          -- 159
  .StLoc 8,                                                       -- 160 cur >>= 1
  .MoveLoc 13,                                                    -- 161
  .LdU64 1,                                                       -- 162
  .Add,                                                          -- 163
  .StLoc 13,                                                      -- 164 j += 1
  .Branch 70,                                                    -- 165
  -- B14 (roots_buf ++= node ; i += 1)
  .MutBorrowLoc 22,                                               -- 166
  .MoveLoc 16,                                                    -- 167
  .Call vectorAppendCallee vectorAppendLocalsTail 2,              -- 168
  .MoveLoc 10,                                                    -- 169
  .LdU64 1,                                                       -- 170
  .Add,                                                          -- 171
  .StLoc 10,                                                      -- 172 i += 1
  .Branch 13,                                                    -- 173
  -- B15 (roots_adrs := set_tree_index(set_tree_height(set_type(*adrs, fors_roots), 0), 0) ; thash)
  .MoveLoc 0,                                                     -- 174
  .Pop,                                                          -- 175
  .MoveLoc 3,                                                     -- 176
  .ReadRef,                                                      -- 177
  .StLoc 21,                                                      -- 178 roots_adrs := *adrs
  .MutBorrowLoc 21,                                               -- 179
  .LdU8 4,                                                        -- 180
  .Call adrsSetTypeCallee adrsSetTypeLocalsTail 2,                -- 181 set_type(fors_roots)
  .MutBorrowLoc 21,                                               -- 182
  .LdU32 0,                                                       -- 183
  .Call adrsSetTreeHeightCallee adrsSetTreeHeightLocalsTail 2,    -- 184 set_tree_height(0)
  .MutBorrowLoc 21,                                               -- 185
  .LdU32 0,                                                       -- 186
  .Call adrsSetTreeIndexCallee adrsSetTreeIndexLocalsTail 2,      -- 187 set_tree_index(0)
  .MoveLoc 2,                                                     -- 188 prefix
  .ImmBorrowLoc 21,                                               -- 189 roots_adrs
  .ImmBorrowLoc 22,                                              -- 190 roots_buf
  .Call thashCallee thashLocalsTail 3,                            -- 191 thash(pre, roots_adrs, roots_buf)
  .Ret                                                           -- 192
]

/-- Test wrapper. `adrs` (local 3) is `&` → `locRef 24`; backing store at 24. -/
def initialState (sigFors md pre adrsBytes : ByteArray) : State :=
  { stack := #[]
    locals := (#[Value.vecU8 sigFors,         -- 0
                 Value.vecU8 md,               -- 1
                 Value.vecU8 pre,              -- 2
                 Value.locRef 24,              -- 3: adrs (ref → 24)
                 Value.vecU8 ByteArray.empty,  -- 4: auth_path
                 Value.u32 0,                  -- 5: bit
                 Value.vecU8 ByteArray.empty,  -- 6: buf
                 Value.u64 0,                  -- 7: chunk_bytes
                 Value.u32 0,                  -- 8: cur
                 Value.vecU8 ByteArray.empty,  -- 9: h
                 Value.u64 0,                  -- 10: i
                 Value.u32 0,                  -- 11: idx
                 Value.vecU32 #[],             -- 12: indices
                 Value.u64 0,                  -- 13: j
                 Value.vecU8 ByteArray.empty,  -- 14: leaf_adrs
                 Value.u32 0,                  -- 15: leaf_tree_index
                 Value.vecU8 ByteArray.empty,  -- 16: node
                 Value.u32 0,                  -- 17: nodes_at_height
                 Value.u64 0,                  -- 18: off
                 Value.u64 0,                  -- 19: p
                 Value.u32 0,                  -- 20: parent_idx
                 Value.vecU8 ByteArray.empty,  -- 21: roots_adrs
                 Value.vecU8 ByteArray.empty,  -- 22: roots_buf
                 Value.vecU8 ByteArray.empty]  -- 23: sk_leaf
              ).push (Value.vecU8 adrsBytes),  -- 24: adrs backing
    pc := 0, error := none }

def forsPkFromSigRealMoveBC (sigFors md pre adrsBytes : ByteArray) : ByteArray :=
  let final := runDefault forsPkFromSigRealBytecode (initialState sigFors md pre adrsBytes)
  match final.stack.back? with
  | some (Value.vecU8 v) => v
  | _ => ByteArray.empty

/-- Byte-level reference mirroring the bytecode, from proven structural
    primitives. `adrsBytes` is expected to already carry `type = fors_tree`. -/
def forsRef (sigFors md pre adrsBytes : ByteArray) : ByteArray := Id.run do
  let chunkBytes := (1 + 12) * 16
  let indices := Fips205.Verify.extractForsIndices md
  let mut rootsBuf := ByteArray.empty
  for i in [0:14] do
    let off := i * chunkBytes
    let skLeaf := Slice.sliceMoveBC sigFors (UInt64.ofNat off) 16
    let authPath := Slice.sliceMoveBC sigFors (UInt64.ofNat (off + 16)) (UInt64.ofNat (12 * 16))
    let idx := indices[i]!
    let mut leafAdrs := AdrsSetters.adrsSetTypeMoveBC adrsBytes Fips205.AdrsType.fors_tree
    leafAdrs := AdrsSetters.adrsSetTreeHeightMoveBC leafAdrs 0
    leafAdrs := AdrsSetTreeIndex.adrsSetTreeIndexMoveBC leafAdrs (UInt64.ofNat ((i <<< 12) + idx))
    let mut node := Thash.thashMoveBC pre leafAdrs skLeaf
    let mut cur := idx
    for j in [0:12] do
      leafAdrs := AdrsSetters.adrsSetTreeHeightMoveBC leafAdrs (UInt64.ofNat (j + 1))
      let nodesAtHeight := 1 <<< (12 - j - 1)
      let parentIdx := i * nodesAtHeight + (cur >>> 1)
      leafAdrs := AdrsSetTreeIndex.adrsSetTreeIndexMoveBC leafAdrs (UInt64.ofNat parentIdx)
      let bit := cur &&& 1
      let sib := Slice.sliceMoveBC authPath (UInt64.ofNat (j * 16)) 16
      let merged := if bit = 0 then node ++ sib else sib ++ node
      node := Thash.thashMoveBC pre leafAdrs merged
      cur := cur >>> 1
    rootsBuf := rootsBuf ++ node
  let rootsAdrs := AdrsSetTreeIndex.adrsSetTreeIndexMoveBC
                     (AdrsSetters.adrsSetTreeHeightMoveBC
                       (AdrsSetters.adrsSetTypeMoveBC adrsBytes Fips205.AdrsType.fors_roots) 0) 0
  return Thash.thashMoveBC pre rootsAdrs rootsBuf

/-! ## Equivalence theorems -/

/-- Real-shaped FORS verify: 2912-byte sig (14×208), 21-byte md, 64-byte
    prefix, fors_tree-typed 22-byte ADRS. -/
example :
    let pkSeed := Fips205.Bytes.hexDecode "ebf2f900070e151c232a31383f464d54"
    let pre := pkSeed ++ Fips205.Bytes.zeros 48
    let adrs := AdrsSetters.adrsSetTypeMoveBC (Fips205.Bytes.zeros 22) Fips205.AdrsType.fors_tree
    let sigFors := Fips205.Bytes.zeros (14 * 208)
    let md := Fips205.Bytes.zeros 21
    forsPkFromSigRealMoveBC sigFors md pre adrs = forsRef sigFors md pre adrs := by
  native_decide

/-- Non-trivial md (exercises both branches of the bit==0 conditional). -/
example :
    let pkSeed := Fips205.Bytes.hexDecode "00112233445566778899aabbccddeeff"
    let pre := pkSeed ++ Fips205.Bytes.zeros 48
    let adrs := AdrsSetters.adrsSetTypeMoveBC (Fips205.Bytes.zeros 22) Fips205.AdrsType.fors_tree
    let sigFors := Fips205.Bytes.zeros (14 * 208)
    let md := Fips205.Bytes.hexDecode "0123456789abcdef0123456789abcdef0123456789abcd"
    forsPkFromSigRealMoveBC sigFors md pre adrs = forsRef sigFors md pre adrs := by
  native_decide

/-- Output size invariant: 16 bytes. -/
example :
    let pre := Fips205.Bytes.zeros 64
    let adrs := AdrsSetters.adrsSetTypeMoveBC (Fips205.Bytes.zeros 22) Fips205.AdrsType.fors_tree
    (forsPkFromSigRealMoveBC (Fips205.Bytes.zeros (14*208)) (Fips205.Bytes.zeros 21) pre adrs).size = 16 := by
  native_decide

end Fips205.Move.ForsPkFromSigReal
