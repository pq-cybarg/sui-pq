import Move.Value
import Move.Stack
import Move.Opcode
import Move.Step
import Fips205.Bytes
import Fips205.Adrs

/-! # `adrs_set_tree_index` Move bytecode → Lean spec equivalence

Real Move source (from `move/slh_dsa_128s/sources/sha2_128s.move`):

```move
fun adrs_set_tree_index(a: &mut vector<u8>, idx: u32) {
    write_u32_be(a, 18, idx);
}
fun write_u32_be(buf: &mut vector<u8>, off: u64, v: u32) {
    *buf.borrow_mut(off + 0) = ((v >> 24) & 0xff) as u8;
    *buf.borrow_mut(off + 1) = ((v >> 16) & 0xff) as u8;
    *buf.borrow_mut(off + 2) = ((v >> 8)  & 0xff) as u8;
    *buf.borrow_mut(off + 3) = ( v        & 0xff) as u8;
}
```

This is called once per WOTS+ chain step inside `chain` (2,099+ times per
verify). The mutation rewrites the last 4 bytes of the 22-byte compressed
ADRS (the `tree_index`/`hash_address` field, per FIPS-205 §4.2.2).

Spec equivalent: a fresh 22-byte buffer with bytes [0..17] copied unchanged
and [18..21] = `u32BE idx`. We model this directly using `Bytes.slice ++ u32BE`.

## Locals
  Local 0: a   (vector<u8>, 22 bytes)
  Local 1: idx (u64 — Move's u32 widens through bytecode, we use u64 here)

## Bytecode
  -- a[18] = (idx >> 24) & 0xff
   0: CopyLoc 0        // push a
   1: LdU64 18         // push 18
   2: CopyLoc 1        // push idx
   3: LdU64 24
   4: Shr              // idx >> 24
   5: LdU64 255
   6: BitAnd           // ((idx>>24) & 0xff) : u64
   7: CallNative "u64_to_u8" 1
   8: VecSet           // a := a[18 := byte]
   9: StLoc 0
  -- a[19] = (idx >> 16) & 0xff
  10: CopyLoc 0
  11: LdU64 19
  12: CopyLoc 1
  13: LdU64 16
  14: Shr
  15: LdU64 255
  16: BitAnd
  17: CallNative "u64_to_u8" 1
  18: VecSet
  19: StLoc 0
  -- a[20] = (idx >> 8) & 0xff
  20: CopyLoc 0
  21: LdU64 20
  22: CopyLoc 1
  23: LdU64 8
  24: Shr
  25: LdU64 255
  26: BitAnd
  27: CallNative "u64_to_u8" 1
  28: VecSet
  29: StLoc 0
  -- a[21] = idx & 0xff
  30: CopyLoc 0
  31: LdU64 21
  32: CopyLoc 1
  33: LdU64 255
  34: BitAnd
  35: CallNative "u64_to_u8" 1
  36: VecSet
  37: StLoc 0
  -- return a
  38: CopyLoc 0
  39: Ret

We use a `u64_to_u8` native (just truncates to the low byte) rather than
modelling Move's typed casts as a separate opcode family. This is faithful
to the Move semantics on the runtime side; the static `as u8` cast is
checked by the bytecode verifier offline.
-/

namespace Fips205.Move.AdrsSetTreeIndex

open Fips205.Move Fips205.Move.Value Fips205.Move.State Fips205

def adrsSetTreeIndexBytecode : Bytecode := #[
  -- a[18] = (idx >> 24) & 0xff
  .CopyLoc 0, .LdU64 18, .CopyLoc 1, .LdU64 24, .Shr, .LdU64 255, .BitAnd,
  .CallNative "u64_to_u8" 1, .VecSet, .StLoc 0,
  -- a[19] = (idx >> 16) & 0xff
  .CopyLoc 0, .LdU64 19, .CopyLoc 1, .LdU64 16, .Shr, .LdU64 255, .BitAnd,
  .CallNative "u64_to_u8" 1, .VecSet, .StLoc 0,
  -- a[20] = (idx >> 8) & 0xff
  .CopyLoc 0, .LdU64 20, .CopyLoc 1, .LdU64 8, .Shr, .LdU64 255, .BitAnd,
  .CallNative "u64_to_u8" 1, .VecSet, .StLoc 0,
  -- a[21] = idx & 0xff
  .CopyLoc 0, .LdU64 21, .CopyLoc 1, .LdU64 255, .BitAnd,
  .CallNative "u64_to_u8" 1, .VecSet, .StLoc 0,
  .CopyLoc 0,
  .Ret
]

def initialState (a : ByteArray) (idx : UInt64) : State :=
  { stack := #[]
    locals := #[Value.vecU8 a, Value.u64 idx],
    pc := 0, error := none }

def adrsSetTreeIndexMoveBC (a : ByteArray) (idx : UInt64) : ByteArray :=
  let final := runDefault adrsSetTreeIndexBytecode (initialState a idx)
  match final.stack.back? with
  | some (Value.vecU8 v) => v
  | _ => ByteArray.empty

/-- Spec: take bytes [0..18) from a, append `u32BE idx`. -/
def adrsSetTreeIndexSpec (a : ByteArray) (idx : Nat) : ByteArray :=
  Bytes.slice a 0 18 ++ Bytes.u32BE idx

/-! ## Equivalence theorems

Each example confirms the bytecode-set produces the same 22-byte buffer
as the spec form, on a representative ADRS + index. -/

example :
    adrsSetTreeIndexMoveBC (Fips205.Bytes.zeros 22) 0 =
      adrsSetTreeIndexSpec (Fips205.Bytes.zeros 22) 0 := by
  native_decide

example :
    adrsSetTreeIndexMoveBC (Fips205.Bytes.zeros 22) 5 =
      adrsSetTreeIndexSpec (Fips205.Bytes.zeros 22) 5 := by
  native_decide

example :
    adrsSetTreeIndexMoveBC (Fips205.Bytes.zeros 22) 0x12345678 =
      adrsSetTreeIndexSpec (Fips205.Bytes.zeros 22) 0x12345678 := by
  native_decide

/-- Tree-index typically fits in a single byte (chain hash addr ≤ 15);
    boundary case of 0xff. -/
example :
    adrsSetTreeIndexMoveBC (Fips205.Bytes.zeros 22) 0xff =
      adrsSetTreeIndexSpec (Fips205.Bytes.zeros 22) 0xff := by
  native_decide

/-- Full-width 4-byte index. -/
example :
    adrsSetTreeIndexMoveBC (Fips205.Bytes.zeros 22) 0xdeadbeef =
      adrsSetTreeIndexSpec (Fips205.Bytes.zeros 22) 0xdeadbeef := by
  native_decide

/-- Non-zero ADRS body — confirms the first 18 bytes are preserved. -/
example :
    let a := Fips205.Bytes.hexDecode "0102030405060708090a0b0c0d0e0f10111200000000"
    adrsSetTreeIndexMoveBC a 0x42 = adrsSetTreeIndexSpec a 0x42 := by
  native_decide

/-- Composition sanity: setting twice keeps only the last write. -/
example :
    let a := Fips205.Bytes.zeros 22
    let a1 := adrsSetTreeIndexMoveBC a 5
    adrsSetTreeIndexMoveBC a1 99 = adrsSetTreeIndexSpec a 99 := by
  native_decide

end Fips205.Move.AdrsSetTreeIndex
