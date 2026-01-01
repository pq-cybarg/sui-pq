import Move.Value
import Move.Stack
import Move.Opcode
import Move.Step
import Move.Native
import Move.MoveStdlib
import Move.MsgToChainDigitsReal
import Move.AdrsSetTypeReal
import Move.AdrsSetKeypairReal
import Move.ChainReal
import Move.ThashReal
import Move.AdrsSetters
import Move.AdrsSetTreeIndex
import Fips205.Bytes
import Fips205.Wots
import Fips205.MoveEquiv

/-! # `wots_pk_from_sig` — real disassembled Move bytecode

WOTS+ public-key reconstruction: 35 hash chains over the signature shares,
concatenated and compressed with one final `thash`. This is the deepest
composite in the verifier — it `Call`s `msg_to_chain_digits`,
`adrs_set_type`, `adrs_set_tree_height`, `chain`, `vector::append`,
`adrs_set_tree_index`, and `thash`. The `chain` calls nest 4 levels deep
(`wots_pk_from_sig` → `chain` → `adrs_set_tree_index` → `write_u32_be`),
all carrying a shared `&mut adrs` through the cross-frame ref machinery.

PCs match the disassembly exactly (B0–B4, 70 opcodes).

## Locals
  0: sig, 1: msg_n, 2: pre, 3: adrs(ref), 4: a, 5: d(u32),
  6: digits(vec u32), 7: i, 8: piece, 9: t_adrs, 10: tmp
-/

namespace Fips205.Move.WotsPkFromSigReal

open Fips205.Move Fips205.Move.Value Fips205.Move.State Fips205
open Fips205.Move.MoveStdlib

/-- callee localsTails (declared non-arg locals of each callee). -/
def msgToChainDigitsLocalsTail : Array Value :=
  #[Value.vecU32 #[], Value.vecU32 #[], Value.u64 0]   -- csum_digits, digits, i
def adrsSetTypeLocalsTail : Array Value := #[]
def adrsSetTreeHeightLocalsTail : Array Value := #[]
def adrsSetTreeIndexLocalsTail : Array Value := #[]
/-- chain non-arg locals: buf, end, h, j, k, s, tmp (L6..L12). -/
def chainLocalsTail : Array Value :=
  #[Value.vecU8 ByteArray.empty, Value.u32 0, Value.vecU8 ByteArray.empty,
    Value.u32 0, Value.u64 0, Value.u64 0, Value.vecU8 ByteArray.empty]
/-- thash non-arg locals: buf, h, i (L3..L5). -/
def thashLocalsTail : Array Value :=
  #[Value.vecU8 ByteArray.empty, Value.vecU8 ByteArray.empty, Value.u64 0]

def wotsPkFromSigRealBytecode : Bytecode := #[
  -- B0: digits := msg_to_chain_digits(msg_n); tmp := vec[]; a := *adrs; adrs_set_type(a, 0)
  .MoveLoc 1,                                                                -- 0
  .Call MsgToChainDigitsReal.msgToChainDigitsRealBytecode msgToChainDigitsLocalsTail 1, -- 1
  .StLoc 6,                                                                  -- 2
  .LdConst (Value.vecU8 ByteArray.empty),                                    -- 3
  .StLoc 10,                                                                 -- 4
  .CopyLoc 3,                                                                -- 5
  .ReadRef,                                                                  -- 6
  .StLoc 4,                                                                  -- 7  a := *adrs
  .MutBorrowLoc 4,                                                           -- 8
  .LdU8 0,                                                                   -- 9
  .Call AdrsSetTypeReal.adrsSetTypeRealBytecode adrsSetTypeLocalsTail 2,     -- 10
  .LdU64 0,                                                                  -- 11
  .StLoc 7,                                                                  -- 12  i := 0
  -- B1: for i in 0..35
  .CopyLoc 7,                                                                -- 13
  .LdU64 35,                                                                 -- 14
  .Lt,                                                                       -- 15
  .BrFalse 51,                                                               -- 16
  -- B2
  .Branch 18,                                                                -- 17
  -- B3: adrs_set_tree_height(a, i); d := digits[i]; piece := chain(...); tmp ++= piece
  .MutBorrowLoc 4,                                                           -- 18
  .CopyLoc 7,                                                                -- 19
  .CastU32,                                                                  -- 20
  .Call AdrsSetKeypairReal.adrsSetTreeHeightRealBytecode adrsSetTreeHeightLocalsTail 2, -- 21
  .ImmBorrowLoc 6,                                                           -- 22
  .CopyLoc 7,                                                                -- 23
  .VecU32ImmBorrow,                                                          -- 24
  .ReadRef,                                                                  -- 25
  .CastU32,                                                                  -- 26
  .StLoc 5,                                                                  -- 27  d := digits[i]
  .CopyLoc 0,                                                                -- 28  sig
  .CopyLoc 7,                                                                -- 29
  .LdU64 16,                                                                 -- 30
  .Mul,                                                                      -- 31  i*16
  .CopyLoc 5,                                                                -- 32  d (i_start)
  .LdU64 16,                                                                 -- 33
  .CastU32,                                                                  -- 34
  .LdU32 1,                                                                  -- 35
  .Sub,                                                                      -- 36  15
  .MoveLoc 5,                                                                -- 37  d
  .Sub,                                                                      -- 38  15 - d (steps)
  .CopyLoc 2,                                                                -- 39  pre
  .MutBorrowLoc 4,                                                           -- 40  &mut a
  .Call ChainReal.chainRealBytecode chainLocalsTail 6,                       -- 41
  .StLoc 8,                                                                  -- 42  piece
  .MutBorrowLoc 10,                                                          -- 43
  .MoveLoc 8,                                                                -- 44
  .Call vectorAppendCallee vectorAppendLocalsTail 2,                         -- 45  tmp ++= piece
  .MoveLoc 7,                                                                -- 46
  .LdU64 1,                                                                  -- 47
  .Add,                                                                      -- 48
  .StLoc 7,                                                                  -- 49  i += 1
  .Branch 13,                                                                -- 50
  -- B4: t_adrs := set_tree_index(set_tree_height(set_type(*adrs, 1), 0), 0); thash
  .MoveLoc 0,                                                                -- 51
  .Pop,                                                                      -- 52
  .MoveLoc 3,                                                                -- 53
  .ReadRef,                                                                  -- 54
  .StLoc 9,                                                                  -- 55  t_adrs := *adrs
  .MutBorrowLoc 9,                                                           -- 56
  .LdU8 1,                                                                   -- 57
  .Call AdrsSetTypeReal.adrsSetTypeRealBytecode adrsSetTypeLocalsTail 2,     -- 58
  .MutBorrowLoc 9,                                                           -- 59
  .LdU32 0,                                                                  -- 60
  .Call AdrsSetKeypairReal.adrsSetTreeHeightRealBytecode adrsSetTreeHeightLocalsTail 2, -- 61
  .MutBorrowLoc 9,                                                           -- 62
  .LdU32 0,                                                                  -- 63
  .Call AdrsSetKeypairReal.adrsSetTreeIndexRealBytecode adrsSetTreeIndexLocalsTail 2, -- 64
  .MoveLoc 2,                                                                -- 65
  .ImmBorrowLoc 9,                                                           -- 66
  .ImmBorrowLoc 10,                                                          -- 67
  .Call ThashReal.thashRealBytecode thashLocalsTail 3,                       -- 68
  .Ret                                                                       -- 69
]

/-- Test wrapper. `adrs` (local 3) is `&` → set to `locRef 11`, store the
    22-byte ADRS in backing local 11. -/
def initialState (sig msgN pre adrsBytes : ByteArray) : State :=
  { stack := #[]
    locals := #[Value.vecU8 sig,                       -- 0: sig
                Value.vecU8 msgN,                       -- 1: msg_n
                Value.vecU8 pre,                     -- 2: pre
                Value.locRef 11,                        -- 3: adrs (ref → 11)
                Value.vecU8 ByteArray.empty,            -- 4: a
                Value.u32 0,                            -- 5: d
                Value.vecU32 #[],                       -- 6: digits
                Value.u64 0,                            -- 7: i
                Value.vecU8 ByteArray.empty,            -- 8: piece
                Value.vecU8 ByteArray.empty,            -- 9: t_adrs
                Value.vecU8 ByteArray.empty,            -- 10: tmp
                Value.vecU8 adrsBytes],                 -- 11: adrs backing
    pc := 0, error := none }

def wotsPkFromSigRealMoveBC (sig msgN pre adrsBytes : ByteArray) : ByteArray :=
  let final := runDefault wotsPkFromSigRealBytecode (initialState sig msgN pre adrsBytes)
  match final.stack.back? with
  | some (Value.vecU8 v) => v
  | _ => ByteArray.empty

/-- Byte-level reference mirroring the bytecode, built from proven structural
    primitives (`msgToChainDigits`, `chainRef`, byte-level ADRS setters,
    `thashMove`). -/
def wotsPkFromSigRef (sig msgN pre adrsBytes : ByteArray) : ByteArray := Id.run do
  let digits := Fips205.Wots.msgToChainDigits msgN
  let mut tmp := ByteArray.empty
  let mut a := AdrsSetters.adrsSetTypeMoveBC adrsBytes 0   -- wots_hash
  for i in [0:35] do
    a := AdrsSetters.adrsSetTreeHeightMoveBC a (UInt64.ofNat i)
    let d := digits[i]!
    let piece := ChainReal.chainRef sig (i * 16) d (15 - d) pre a
    tmp := tmp ++ piece
  let tAdrs := AdrsSetTreeIndex.adrsSetTreeIndexMoveBC
                 (AdrsSetters.adrsSetTreeHeightMoveBC
                   (AdrsSetters.adrsSetTypeMoveBC adrsBytes 1) 0) 0
  return Fips205.MoveEquiv.thashMove pre tAdrs tmp

/-! ## Equivalence theorems -/

/-- Real-shaped inputs: 560-byte WOTS+ sig (35×16), 16-byte msg, 64-byte
    pre, 22-byte ADRS. -/
example :
    let sig := Fips205.Bytes.zeros 560
    let msgN := Fips205.Bytes.hexDecode "112233445566778899aabbccddeeff00"
    let pre := (Fips205.Bytes.hexDecode "00112233445566778899aabbccddeeff") ++ Fips205.Bytes.zeros 48
    let adrs := Fips205.Bytes.zeros 22
    wotsPkFromSigRealMoveBC sig msgN pre adrs = wotsPkFromSigRef sig msgN pre adrs := by
  native_decide

/-- Non-trivial signature bytes + non-zero ADRS. -/
example :
    let sig := Fips205.Bytes.zeros 560
    let msgN := Fips205.Bytes.zeros 16
    let pre := Fips205.Bytes.zeros 64
    let adrs := Fips205.Bytes.hexDecode "0001020304050607080900010203040506070809abcd"
    wotsPkFromSigRealMoveBC sig msgN pre adrs = wotsPkFromSigRef sig msgN pre adrs := by
  native_decide

/-- Output size invariant: 16 bytes (one thash). -/
example :
    (wotsPkFromSigRealMoveBC (Fips205.Bytes.zeros 560) (Fips205.Bytes.zeros 16)
        (Fips205.Bytes.zeros 64) (Fips205.Bytes.zeros 22)).size = 16 := by
  native_decide

end Fips205.Move.WotsPkFromSigReal
