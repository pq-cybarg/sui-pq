import Move.Value
import Move.Stack
import Move.Opcode
import Move.Step
import Move.MoveStdlib
import Move.SliceReal
import Move.AdrsNewAppendSliceReal
import Move.AdrsSetTypeReal       -- adrs_set_layer callee
import Move.WriteU64BeReal        -- adrs_set_tree callee
import Move.XmssPkFromSigReal
import Move.Slice
import Move.AdrsSetters
import Fips205.Bytes
import Fips205.Params

/-! # `ht_root_from_sig` — real disassembled Move bytecode

Hypertree root reconstruction: D=7 XMSS layers, each consuming the previous
layer's node as its message. Calling `xmss_pk_from_sig` per layer makes
this the **6-deep** nesting case
(`ht` → `xmss` → `wots_pk_from_sig` → `chain` → `adrs_set_tree_index` →
`write_u32_be`). Uses `Call adrs_new` (a 0-arg constructor), `adrs_set_layer`,
`adrs_set_tree` (which itself `Call`s `write_u64_be`), `slice`, and `xmss`.

With all-zero input, `native_decide` drives all 7 layers ≈ 1,900 SHA-256
calls through the VM end-to-end.

## Locals
  0:sig_ht 1:msg_n 2:tree_idx0(u64) 3:leaf_idx0(u32) 4:pre 5:a
  6:cur_leaf(u32) 7:cur_tree(u64) 8:j 9:leaf_mask(u64) 10:node
  11:slice_j 12:xmss_sig_bytes
-/

namespace Fips205.Move.HtRootFromSigReal

open Fips205.Move Fips205.Move.Value Fips205.Move.State Fips205
open Fips205.Move.MoveStdlib

/-- adrs_new declares L0:a, L1:i (no args). -/
def adrsNewLocalsTail : Array Value := #[Value.vecU8 ByteArray.empty, Value.u64 0]
def adrsSetLayerLocalsTail : Array Value := #[]
def adrsSetTreeLocalsTail : Array Value := #[]
def sliceLocalsTail : Array Value := #[Value.u64 0, Value.vecU8 ByteArray.empty]
/-- xmss non-arg locals L5..L13: auth,bit,buf,cur_idx,h,i,k,node,wots_sig. -/
def xmssLocalsTail : Array Value :=
  #[Value.vecU8 ByteArray.empty, Value.u32 0, Value.vecU8 ByteArray.empty,
    Value.u32 0, Value.vecU8 ByteArray.empty, Value.u64 0, Value.u64 0,
    Value.vecU8 ByteArray.empty, Value.vecU8 ByteArray.empty]

abbrev adrsNewCallee := AdrsNewAppendSliceReal.adrsNewRealBytecode
abbrev adrsSetLayerCallee := AdrsSetTypeReal.adrsSetLayerRealBytecode
abbrev adrsSetTreeCallee := WriteU64BeReal.adrsSetTreeRealBytecode
abbrev sliceCallee := SliceReal.sliceRealBytecode
abbrev xmssCallee := XmssPkFromSigReal.xmssPkFromSigRealBytecode

def htRootFromSigRealBytecode : Bytecode := #[
  -- B0
  .LdU64 35,                                                       -- 0
  .LdU64 9,                                                        -- 1
  .Add,                                                            -- 2  44
  .LdU64 16,                                                       -- 3
  .Mul,                                                            -- 4  xmss_sig_bytes = 704
  .StLoc 12,                                                       -- 5
  .MoveLoc 1,                                                      -- 6  msg_n
  .ReadRef,                                                       -- 7
  .StLoc 10,                                                       -- 8  node := *msg_n
  .MoveLoc 2,                                                      -- 9
  .StLoc 7,                                                        -- 10 cur_tree := tree_idx0
  .MoveLoc 3,                                                      -- 11
  .StLoc 6,                                                        -- 12 cur_leaf := leaf_idx0
  .LdU64 0,                                                        -- 13
  .StLoc 8,                                                        -- 14 j := 0
  -- B1 (loop: j < 7)
  .CopyLoc 8,                                                      -- 15
  .LdU64 7,                                                        -- 16
  .Lt,                                                            -- 17
  .BrFalse 65,                                                    -- 18
  -- B2
  .Branch 20,                                                     -- 19
  -- B3
  .Call adrsNewCallee adrsNewLocalsTail 0,                         -- 20 a := adrs_new()
  .StLoc 5,                                                        -- 21
  .MutBorrowLoc 5,                                                 -- 22
  .CopyLoc 8,                                                      -- 23
  .CastU8,                                                         -- 24
  .Call adrsSetLayerCallee adrsSetLayerLocalsTail 2,               -- 25 set_layer(j)
  .MutBorrowLoc 5,                                                 -- 26
  .CopyLoc 7,                                                      -- 27
  .Call adrsSetTreeCallee adrsSetTreeLocalsTail 2,                 -- 28 set_tree(cur_tree)
  .CopyLoc 0,                                                      -- 29 sig_ht
  .CopyLoc 8,                                                      -- 30 j
  .CopyLoc 12,                                                     -- 31 xmss_sig_bytes
  .Mul,                                                            -- 32 j*xmss_sig_bytes
  .CopyLoc 12,                                                     -- 33
  .Call sliceCallee sliceLocalsTail 3,                             -- 34 slice_j
  .StLoc 11,                                                       -- 35
  .MoveLoc 6,                                                      -- 36 cur_leaf  (arg0 idx)
  .ImmBorrowLoc 11,                                                -- 37 slice_j   (arg1 sig)
  .ImmBorrowLoc 10,                                                -- 38 node      (arg2 msg_n)
  .CopyLoc 4,                                                      -- 39 prefix    (arg3)
  .MutBorrowLoc 5,                                                 -- 40 a         (arg4 adrs)
  .Call xmssCallee xmssLocalsTail 5,                               -- 41 node := xmss(...)
  .StLoc 10,                                                       -- 42
  -- leaf_mask = (1 << 9) - 1 ; cur_leaf = cur_tree & leaf_mask ; cur_tree >>= 9
  .LdU64 1,                                                        -- 43
  .LdU64 9,                                                        -- 44
  .CastU8,                                                         -- 45
  .Shl,                                                            -- 46  1 << 9
  .LdU64 1,                                                        -- 47
  .Sub,                                                            -- 48  0x1ff
  .StLoc 9,                                                        -- 49 leaf_mask
  .CopyLoc 7,                                                      -- 50 cur_tree
  .MoveLoc 9,                                                      -- 51 leaf_mask
  .BitAnd,                                                         -- 52
  .CastU32,                                                        -- 53
  .StLoc 6,                                                        -- 54 cur_leaf := (cur_tree & mask) as u32
  .MoveLoc 7,                                                      -- 55 cur_tree
  .LdU64 9,                                                        -- 56
  .CastU8,                                                         -- 57
  .Shr,                                                            -- 58  cur_tree >> 9
  .StLoc 7,                                                        -- 59
  .MoveLoc 8,                                                      -- 60
  .LdU64 1,                                                        -- 61
  .Add,                                                            -- 62
  .StLoc 8,                                                        -- 63 j += 1
  .Branch 15,                                                      -- 64
  -- B4 (epilogue)
  .MoveLoc 0,                                                      -- 65
  .Pop,                                                           -- 66
  .MoveLoc 4,                                                      -- 67
  .Pop,                                                           -- 68
  .MoveLoc 10,                                                     -- 69 return node
  .Ret                                                            -- 70
]

def initialState (sigHt msgN : ByteArray) (treeIdx leafIdx : Nat) (pre : ByteArray) : State :=
  { stack := #[]
    locals := #[Value.vecU8 sigHt,                  -- 0
                Value.vecU8 msgN,                    -- 1
                Value.u64 (UInt64.ofNat treeIdx),    -- 2
                Value.u32 (UInt32.ofNat leafIdx),    -- 3
                Value.vecU8 pre,                     -- 4
                Value.vecU8 ByteArray.empty,         -- 5: a
                Value.u32 0,                         -- 6: cur_leaf
                Value.u64 0,                         -- 7: cur_tree
                Value.u64 0,                         -- 8: j
                Value.u64 0,                         -- 9: leaf_mask
                Value.vecU8 ByteArray.empty,         -- 10: node
                Value.vecU8 ByteArray.empty,         -- 11: slice_j
                Value.u64 0],                        -- 12: xmss_sig_bytes
    pc := 0, error := none }

def htRootFromSigRealMoveBC (sigHt msgN : ByteArray) (treeIdx leafIdx : Nat) (pre : ByteArray) : ByteArray :=
  let final := runDefault htRootFromSigRealBytecode (initialState sigHt msgN treeIdx leafIdx pre)
  match final.stack.back? with
  | some (Value.vecU8 v) => v
  | _ => ByteArray.empty

/-- Byte-level reference mirroring the bytecode, using `xmssRef` per layer. -/
def htRef (sigHt msgN : ByteArray) (treeIdx leafIdx : Nat) (pre : ByteArray) : ByteArray := Id.run do
  let xmssSigBytes := (35 + 9) * 16
  let mut node := msgN
  let mut curTree := treeIdx
  let mut curLeaf := leafIdx
  for j in [0:7] do
    let a := AdrsSetters.adrsSetTreeMoveBC
               (AdrsSetters.adrsSetLayerMoveBC (Fips205.Bytes.zeros 22) (UInt8.ofNat j))
               (UInt64.ofNat curTree)
    let sliceJ := Slice.sliceMoveBC sigHt (UInt64.ofNat (j * xmssSigBytes)) (UInt64.ofNat xmssSigBytes)
    node := XmssPkFromSigReal.xmssRef curLeaf sliceJ node pre a
    curLeaf := curTree &&& (2 ^ 9 - 1)
    curTree := curTree >>> 9
  return node

/-! ## Equivalence theorems -/

/-- All-zero hypertree sig, tree_idx=0, leaf_idx=0. -/
example :
    let pkSeed := Fips205.Bytes.hexDecode "ebf2f900070e151c232a31383f464d54"
    let pre := pkSeed ++ Fips205.Bytes.zeros 48
    let sigHt := Fips205.Bytes.zeros (7 * 704)
    let msg := Fips205.Bytes.zeros 16
    htRootFromSigRealMoveBC sigHt msg 0 0 pre = htRef sigHt msg 0 0 pre := by
  native_decide

/-- Non-zero tree/leaf indices (exercises layer addressing + bit selection). -/
example :
    let pkSeed := Fips205.Bytes.hexDecode "00112233445566778899aabbccddeeff"
    let pre := pkSeed ++ Fips205.Bytes.zeros 48
    let sigHt := Fips205.Bytes.zeros (7 * 704)
    let msg := Fips205.Bytes.hexDecode "112233445566778899aabbccddeeff00"
    htRootFromSigRealMoveBC sigHt msg 0x123456789 0x55 pre = htRef sigHt msg 0x123456789 0x55 pre := by
  native_decide

/-- Output size invariant: 16 bytes (hypertree root). -/
example :
    let pre := Fips205.Bytes.zeros 64
    (htRootFromSigRealMoveBC (Fips205.Bytes.zeros (7*704)) (Fips205.Bytes.zeros 16) 0 0 pre).size = 16 := by
  native_decide

end Fips205.Move.HtRootFromSigReal
