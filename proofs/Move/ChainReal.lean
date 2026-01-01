import Move.Value
import Move.Stack
import Move.Opcode
import Move.Step
import Move.Native
import Move.MoveStdlib
import Move.AdrsSetKeypairReal      -- adrs_set_tree_index real callee
import Move.ThashReal
import Move.AdrsSetTreeIndex
import Fips205.Bytes
import Fips205.MoveEquiv

/-! # `chain` — real disassembled Move bytecode

WOTS+ hash chain. Iterates `thash` `steps` times, updating the ADRS
tree-index each step. From the disassembly:

```
chain(src, src_off, i_start, steps, prefix, adrs: &mut): vector<u8> {
  L6: buf, L7: end, L8: h, L9: j, L10: k, L11: s, L12: tmp
B0-B4: tmp := src[src_off .. src_off+16]; j := i_start; end := i_start + steps
B5: while j < end:
  B7: adrs_set_tree_index(adrs, j)                    ← Call into setter
      buf := *prefix ; buf ++= *adrs ; buf ++= tmp    ← Call vector::append ×2
      h := sha256(buf)
  B8-B10: truncate h to 16 bytes (VecPopBack loop)
  B11: tmp := h ; j += 1
B12: return tmp
}
```

This is the most deeply-composed primitive yet: a `Call` to
`adrs_set_tree_index` (which itself `Call`s `write_u32_be`), two
`Call`s to `vector::append`, a `CallNative sha2_256`, and the ref-aware
`VecPopBack` truncation — all inside a `steps`-iteration outer loop.
Exercises three levels of nested `Call` with cross-frame `&mut` refs.

## Locals
  0: src, 1: src_off, 2: i_start(u32), 3: steps(u32), 4: prefix, 5: adrs(ref),
  6: buf, 7: end(u32), 8: h, 9: j(u32), 10: k, 11: s, 12: tmp
-/

namespace Fips205.Move.ChainReal

open Fips205.Move Fips205.Move.Value Fips205.Move.State Fips205
open Fips205.Move.MoveStdlib

/-- `adrs_set_tree_index` callee = its real bytecode (offset 18 write_u32_be).
    It has no declared non-arg locals at its own top level (the write_u32_be
    locals live inside that nested Call). -/
def adrsSetTreeIndexCallee : Bytecode := AdrsSetKeypairReal.adrsSetTreeIndexRealBytecode
def adrsSetTreeIndexLocalsTail : Array Value := #[]

def chainRealBytecode : Bytecode := #[
  -- B0: tmp := vec[]; s := 0
  .LdConst (Value.vecU8 ByteArray.empty),                      -- 0
  .StLoc 12,                                                    -- 1
  .LdU64 0,                                                     -- 2
  .StLoc 11,                                                    -- 3
  -- B1: copy 16 bytes src[src_off + s] into tmp
  .CopyLoc 11,                                                  -- 4
  .LdU64 16,                                                    -- 5
  .Lt,                                                          -- 6
  .BrFalse 22,                                                  -- 7
  -- B2
  .Branch 9,                                                    -- 8
  -- B3
  .MutBorrowLoc 12,                                             -- 9
  .CopyLoc 0,                                                   -- 10
  .CopyLoc 1,                                                   -- 11
  .CopyLoc 11,                                                  -- 12
  .Add,                                                         -- 13
  .VecImmBorrow,                                               -- 14
  .ReadRef,                                                    -- 15
  .VecPushBack,                                                -- 16
  .MoveLoc 11,                                                 -- 17
  .LdU64 1,                                                    -- 18
  .Add,                                                        -- 19
  .StLoc 11,                                                   -- 20
  .Branch 4,                                                   -- 21
  -- B4: j := i_start; end := i_start + steps
  .MoveLoc 0,                                                  -- 22
  .Pop,                                                        -- 23
  .CopyLoc 2,                                                  -- 24
  .StLoc 9,                                                    -- 25
  .MoveLoc 2,                                                  -- 26
  .MoveLoc 3,                                                  -- 27
  .Add,                                                        -- 28
  .StLoc 7,                                                    -- 29
  -- B5: while j < end
  .CopyLoc 9,                                                  -- 30
  .CopyLoc 7,                                                  -- 31
  .Lt,                                                         -- 32
  .BrFalse 73,                                                 -- 33
  -- B6
  .Branch 35,                                                  -- 34
  -- B7: adrs_set_tree_index(adrs, j)
  .CopyLoc 5,                                                  -- 35
  .CopyLoc 9,                                                  -- 36
  .Call adrsSetTreeIndexCallee adrsSetTreeIndexLocalsTail 2,   -- 37
  -- buf := *prefix
  .CopyLoc 4,                                                  -- 38
  .ReadRef,                                                    -- 39
  .StLoc 6,                                                    -- 40
  -- buf ++= *adrs
  .MutBorrowLoc 6,                                             -- 41
  .CopyLoc 5,                                                  -- 42
  .ReadRef,                                                    -- 43
  .Call vectorAppendCallee vectorAppendLocalsTail 2,           -- 44
  -- buf ++= tmp
  .MutBorrowLoc 6,                                             -- 45
  .MoveLoc 12,                                                 -- 46
  .Call vectorAppendCallee vectorAppendLocalsTail 2,           -- 47
  -- h := sha256(buf)
  .MoveLoc 6,                                                  -- 48
  .CallNative "sha2_256" 1,                                    -- 49
  .StLoc 8,                                                    -- 50
  .LdU64 0,                                                    -- 51
  .StLoc 10,                                                   -- 52
  -- B8: truncate h to 16
  .CopyLoc 10,                                                 -- 53
  .LdU64 16,                                                   -- 54
  .Lt,                                                         -- 55
  .BrFalse 66,                                                 -- 56
  -- B9
  .Branch 58,                                                  -- 57
  -- B10
  .MutBorrowLoc 8,                                             -- 58
  .VecPopBack,                                                 -- 59
  .Pop,                                                        -- 60
  .MoveLoc 10,                                                 -- 61
  .LdU64 1,                                                    -- 62
  .Add,                                                        -- 63
  .StLoc 10,                                                   -- 64
  .Branch 53,                                                  -- 65
  -- B11: tmp := h ; j += 1
  .MoveLoc 8,                                                  -- 66
  .StLoc 12,                                                   -- 67
  .MoveLoc 9,                                                  -- 68
  .LdU32 1,                                                    -- 69
  .Add,                                                        -- 70
  .StLoc 9,                                                    -- 71
  .Branch 30,                                                  -- 72
  -- B12: epilogue
  .MoveLoc 4,                                                  -- 73
  .Pop,                                                        -- 74
  .MoveLoc 5,                                                  -- 75
  .Pop,                                                        -- 76
  .MoveLoc 12,                                                 -- 77
  .Ret                                                         -- 78
]

/-- Test wrapper. `adrs` (local 5) is a `&mut` ref → set to `locRef 13` and
    store the actual 22-byte ADRS bytes in backing local 13. -/
def initialState (src : ByteArray) (srcOff iStart steps : Nat)
    (pre adrsBytes : ByteArray) : State :=
  { stack := #[]
    locals := #[Value.vecU8 src,                       -- 0: src
                Value.u64 (UInt64.ofNat srcOff),       -- 1: src_off
                Value.u32 (UInt32.ofNat iStart),       -- 2: i_start
                Value.u32 (UInt32.ofNat steps),        -- 3: steps
                Value.vecU8 pre,                        -- 4: prefix
                Value.locRef 13,                        -- 5: adrs (ref → 13)
                Value.vecU8 ByteArray.empty,            -- 6: buf
                Value.u32 0,                            -- 7: end
                Value.vecU8 ByteArray.empty,            -- 8: h
                Value.u32 0,                            -- 9: j
                Value.u64 0,                            -- 10: k
                Value.u64 0,                            -- 11: s
                Value.vecU8 ByteArray.empty,            -- 12: tmp
                Value.vecU8 adrsBytes],                 -- 13: adrs backing
    pc := 0, error := none }

def chainRealMoveBC (src : ByteArray) (srcOff iStart steps : Nat)
    (pre adrsBytes : ByteArray) : ByteArray :=
  let final := runDefault chainRealBytecode (initialState src srcOff iStart steps pre adrsBytes)
  match final.stack.back? with
  | some (Value.vecU8 v) => v
  | _ => ByteArray.empty

/-- Byte-level chain reference mirroring the bytecode: operate on `pre`
    (= pk_seed ‖ pad48) and the compressed 22-byte ADRS directly, using the
    proven structural primitives `thashMove` + `adrsSetTreeIndexMoveBC`. -/
def chainRef (src : ByteArray) (srcOff iStart steps : Nat)
    (pre adrsBytes : ByteArray) : ByteArray := Id.run do
  let mut tmp := Fips205.Bytes.slice src srcOff 16
  let mut a := adrsBytes
  for j in [iStart:iStart + steps] do
    a := AdrsSetTreeIndex.adrsSetTreeIndexMoveBC a (UInt64.ofNat j)
    tmp := Fips205.MoveEquiv.thashMove pre a tmp
  return tmp

/-! ## Equivalence theorems -/

/-- Single step. -/
example :
    let src := Fips205.Bytes.hexDecode "00112233445566778899aabbccddeeff"
    let pre := (Fips205.Bytes.hexDecode "112233445566778899aabbccddeeff00") ++ Fips205.Bytes.zeros 48
    let adrs := Fips205.Bytes.zeros 22
    chainRealMoveBC src 0 0 1 pre adrs = chainRef src 0 0 1 pre adrs := by
  native_decide

/-- Multi-step (steps=5), non-zero i_start. -/
example :
    let src := Fips205.Bytes.hexDecode "00112233445566778899aabbccddeeff"
    let pre := (Fips205.Bytes.hexDecode "112233445566778899aabbccddeeff00") ++ Fips205.Bytes.zeros 48
    let adrs := Fips205.Bytes.hexDecode "0001020304050607080900010203040506070809abcd"
    chainRealMoveBC src 0 3 5 pre adrs = chainRef src 0 3 5 pre adrs := by
  native_decide

/-- Zero steps: tmp = src[src_off..+16] unchanged. -/
example :
    let src := Fips205.Bytes.hexDecode "0102030405060708090a0b0c0d0e0f10deadbeef"
    let pre := Fips205.Bytes.zeros 64
    let adrs := Fips205.Bytes.zeros 22
    chainRealMoveBC src 0 7 0 pre adrs = Fips205.Bytes.slice src 0 16 := by
  native_decide

/-- Non-zero src_off (slice from the middle of a multi-share signature). -/
example :
    let src := Fips205.Bytes.hexDecode
      "00000000000000000000000000000000112233445566778899aabbccddeeff00"
    let pre := Fips205.Bytes.zeros 64
    let adrs := Fips205.Bytes.zeros 22
    chainRealMoveBC src 16 0 2 pre adrs = chainRef src 16 0 2 pre adrs := by
  native_decide

/-- Output size invariant: 16 bytes. -/
example :
    let src := Fips205.Bytes.hexDecode "00112233445566778899aabbccddeeff"
    let pre := Fips205.Bytes.zeros 64
    (chainRealMoveBC src 0 0 4 pre (Fips205.Bytes.zeros 22)).size = 16 := by
  native_decide

end Fips205.Move.ChainReal
