import Move.Value
import Move.Stack
import Move.Opcode
import Move.Step
import Move.AdrsSetters
import Fips205.Bytes

/-! # `adrs_set_type` — real disassembled Move bytecode

```
adrs_set_type(a: &mut vector<u8>, t: u8) {
B0:
  0: MoveLoc[1](t)
  1: MoveLoc[0](a)
  2: LdU64(9)
  3: VecMutBorrow(23)        ← (locRef, idx) → vecElemRef
  4: WriteRef                ← *vecElemRef := value
  5: Ret
}
```

First mutating-in-place primitive — exercises the `vec[idx] := v` pattern
that no value-returning primitive uses. New VM machinery:

  * `Value.vecElemRef (locIdx, elemIdx)` — a mutable reference to a
    specific byte position inside a `vector<u8>` stored at a local.
  * `VecMutBorrow` on a `locRef` produces a `vecElemRef`.
  * `WriteRef` pops a ref and a value and does the in-place write.

To test a mutating function whose result is observed through a passed-in
reference, our test convention adds a third local that holds the actual
storage. Local 0 is set to `Value.locRef 2`; after running, `locals[2]`
contains the modified vector. The disassembled bytecode declares only
locals 0–1 (= a, t) — locals[2] is harness scaffolding, ignored by the
bytecode itself.
-/

namespace Fips205.Move.AdrsSetTypeReal

open Fips205.Move Fips205.Move.Value Fips205.Move.State Fips205

/-- Disassembly-accurate bytecode for `adrs_set_type`. -/
def adrsSetTypeRealBytecode : Bytecode := #[
  .MoveLoc 1,                       -- 0
  .MoveLoc 0,                       -- 1
  .LdU64 9,                         -- 2
  .VecMutBorrow,                    -- 3
  .WriteRef,                        -- 4
  .Ret                              -- 5
]

/-- Test state: locals = [locRef 2, t value, storage].
    The bytecode mutates storage via the ref; after running we read it back. -/
def initialState (a : ByteArray) (t : UInt8) : State :=
  { stack := #[]
    locals := #[Value.locRef 2,
                Value.u8 t,
                Value.vecU8 a],
    pc := 0, error := none }

/-- Run the real `adrs_set_type` bytecode against `a` and `t`, return the
    modified vector (read out of the storage slot). -/
def adrsSetTypeRealMoveBC (a : ByteArray) (t : UInt8) : ByteArray :=
  let final := runDefault adrsSetTypeRealBytecode (initialState a t)
  match final.locals[2]? with
  | some (Value.vecU8 v) => v
  | _ => ByteArray.empty

/-! ## Equivalence theorems against `adrsSetTypeSpec` (replace byte at 9) -/

/-- All-zero 22-byte ADRS, set type to fors_tree (= 3). -/
example : adrsSetTypeRealMoveBC (Fips205.Bytes.zeros 22) AdrsType.fors_tree =
            AdrsSetters.adrsSetTypeSpec (Fips205.Bytes.zeros 22) AdrsType.fors_tree := by
  native_decide

/-- Real-shaped 22-byte ADRS, set type to wots_hash. -/
example :
    let a := Fips205.Bytes.hexDecode "0102030405060708090a0b0c0d0e0f1011120000abcd"
    adrsSetTypeRealMoveBC a AdrsType.wots_hash =
      AdrsSetters.adrsSetTypeSpec a AdrsType.wots_hash := by
  native_decide

/-- Real-shaped 22-byte ADRS, set type to tree. -/
example :
    let a := Fips205.Bytes.hexDecode "0102030405060708090a0b0c0d0e0f1011120000abcd"
    adrsSetTypeRealMoveBC a AdrsType.tree =
      AdrsSetters.adrsSetTypeSpec a AdrsType.tree := by
  native_decide

/-- The real-disassembly encoding matches the existing structural encoding. -/
example : adrsSetTypeRealMoveBC (Fips205.Bytes.zeros 22) AdrsType.fors_tree =
            AdrsSetters.adrsSetTypeMoveBC (Fips205.Bytes.zeros 22) AdrsType.fors_tree := by
  native_decide

/-- Only the byte at offset 9 changes. -/
example :
    let a := Fips205.Bytes.hexDecode "0102030405060708090a0b0c0d0e0f1011120000abcd"
    let result := adrsSetTypeRealMoveBC a AdrsType.fors_tree
    result.size = a.size ∧ result.get! 9 = AdrsType.fors_tree := by
  native_decide

/-! ## Companion: `adrs_set_layer`

Identical structure to `adrs_set_type`, just offset 0 instead of 9. -/

def adrsSetLayerRealBytecode : Bytecode := #[
  .MoveLoc 1,                       -- 0
  .MoveLoc 0,                       -- 1
  .LdU64 0,                         -- 2  (offset 0)
  .VecMutBorrow,                    -- 3
  .WriteRef,                        -- 4
  .Ret                              -- 5
]

def adrsSetLayerRealMoveBC (a : ByteArray) (layer : UInt8) : ByteArray :=
  let s : State :=
    { stack := #[]
      locals := #[Value.locRef 2, Value.u8 layer, Value.vecU8 a],
      pc := 0, error := none }
  let final := runDefault adrsSetLayerRealBytecode s
  match final.locals[2]? with
  | some (Value.vecU8 v) => v
  | _ => ByteArray.empty

example : adrsSetLayerRealMoveBC (Fips205.Bytes.zeros 22) 0 =
            AdrsSetters.adrsSetLayerSpec (Fips205.Bytes.zeros 22) 0 := by
  native_decide

example : adrsSetLayerRealMoveBC (Fips205.Bytes.zeros 22) 5 =
            AdrsSetters.adrsSetLayerSpec (Fips205.Bytes.zeros 22) 5 := by
  native_decide

example :
    let a := Fips205.Bytes.hexDecode "ff112233445566778899aabbccddeeff00112233aabb"
    adrsSetLayerRealMoveBC a 6 = AdrsSetters.adrsSetLayerSpec a 6 := by
  native_decide

end Fips205.Move.AdrsSetTypeReal
