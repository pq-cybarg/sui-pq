import Move.Value
import Move.Stack
import Move.Opcode
import Move.Step
import Move.AdrsSetters
import Move.WriteU32BeReal
import Fips205.Bytes

/-! # `adrs_set_keypair` — real disassembled Move bytecode

```
adrs_set_keypair(a: &mut vector<u8>, kp: u32) {
B0:
  0: MoveLoc[0](a)
  1: LdU64(10)
  2: MoveLoc[1](kp)
  3: Call write_u32_be(&mut vector<u8>, u64, u32)
  4: Ret
}
```

This is the first real-bytecode primitive that BOTH uses `Call` AND
needs the cross-frame `&mut` reference handling we added to `Call`:
the caller's `&mut adrs` is passed into `write_u32_be`, which mutates
through it via `VecMutBorrow + WriteRef`. The copy-in-copy-out semantics
in `step` ensure the caller's local is updated to reflect the callee's
mutation.

Same pattern is shared by `adrs_set_tree_height` (offset 14) and
`adrs_set_tree_index` (offset 18) — they differ only in the constant
loaded at PC 1. Encoded together so we exercise the cross-frame ref
machinery on every callsite.
-/

namespace Fips205.Move.AdrsSetKeypairReal

open Fips205.Move Fips205.Move.Value Fips205.Move.State Fips205

/-- `write_u32_be` packaged for use as the callee in a `.Call`. Localstail
    is empty because `write_u32_be` has no declared non-arg locals. -/
def writeU32BeCallee : Bytecode := WriteU32BeReal.writeU32BeRealBytecode
def writeU32BeLocalsTail : Array Value := #[]

/-- Real-disassembly bytecode for `adrs_set_keypair`. Offset 10. -/
def adrsSetKeypairRealBytecode : Bytecode := #[
  .MoveLoc 0,                                                   -- 0
  .LdU64 10,                                                    -- 1
  .MoveLoc 1,                                                   -- 2
  .Call writeU32BeCallee writeU32BeLocalsTail 3,                -- 3
  .Ret                                                          -- 4
]

/-- Real-disassembly bytecode for `adrs_set_tree_height`. Offset 14. -/
def adrsSetTreeHeightRealBytecode : Bytecode := #[
  .MoveLoc 0,                                                   -- 0
  .LdU64 14,                                                    -- 1
  .MoveLoc 1,                                                   -- 2
  .Call writeU32BeCallee writeU32BeLocalsTail 3,                -- 3
  .Ret                                                          -- 4
]

/-- Real-disassembly bytecode for `adrs_set_tree_index`. Offset 18. -/
def adrsSetTreeIndexRealBytecode : Bytecode := #[
  .MoveLoc 0,                                                   -- 0
  .LdU64 18,                                                    -- 1
  .MoveLoc 1,                                                   -- 2
  .Call writeU32BeCallee writeU32BeLocalsTail 3,                -- 3
  .Ret                                                          -- 4
]

/-- Test wrapper: locals = [locRef 2, kp, adrs_storage]. Run the bytecode;
    the Call's cross-frame handling copies the modified buf back into
    locals[2], which we read out as the result. -/
def initialState (a : ByteArray) (kp : UInt32) : State :=
  { stack := #[]
    locals := #[Value.locRef 2,
                Value.u32 kp,
                Value.vecU8 a],
    pc := 0, error := none }

def runAdrsSetter (bc : Bytecode) (a : ByteArray) (kp : UInt32) : ByteArray :=
  let final := runDefault bc (initialState a kp)
  match final.locals[2]? with
  | some (Value.vecU8 v) => v
  | _ => ByteArray.empty

def adrsSetKeypairRealMoveBC (a : ByteArray) (kp : UInt32) : ByteArray :=
  runAdrsSetter adrsSetKeypairRealBytecode a kp

def adrsSetTreeHeightRealMoveBC (a : ByteArray) (h : UInt32) : ByteArray :=
  runAdrsSetter adrsSetTreeHeightRealBytecode a h

def adrsSetTreeIndexRealMoveBC (a : ByteArray) (idx : UInt32) : ByteArray :=
  runAdrsSetter adrsSetTreeIndexRealBytecode a idx

/-! ## Equivalence theorems

Each setter writes 4 BE bytes at its specific offset (10, 14, 18). -/

example : adrsSetKeypairRealMoveBC (Fips205.Bytes.zeros 22) 0 =
            AdrsSetters.adrsSetKeypairSpec (Fips205.Bytes.zeros 22) 0 := by
  native_decide

example : adrsSetKeypairRealMoveBC (Fips205.Bytes.zeros 22) 0xdeadbeef =
            AdrsSetters.adrsSetKeypairSpec (Fips205.Bytes.zeros 22) 0xdeadbeef := by
  native_decide

example :
    let a := Fips205.Bytes.hexDecode "0102030405060708090a0b0c0d0e0f1011120000abcd"
    adrsSetKeypairRealMoveBC a 0xcafebabe =
      AdrsSetters.adrsSetKeypairSpec a 0xcafebabe := by
  native_decide

example : adrsSetTreeHeightRealMoveBC (Fips205.Bytes.zeros 22) 0xdeadbeef =
            AdrsSetters.adrsSetTreeHeightSpec (Fips205.Bytes.zeros 22) 0xdeadbeef := by
  native_decide

example : adrsSetTreeHeightRealMoveBC (Fips205.Bytes.zeros 22) 5 =
            AdrsSetters.adrsSetTreeHeightSpec (Fips205.Bytes.zeros 22) 5 := by
  native_decide

example : adrsSetTreeIndexRealMoveBC (Fips205.Bytes.zeros 22) 0x12345678 =
            AdrsSetters.replaceMid (Fips205.Bytes.zeros 22)
              (Fips205.Bytes.u32BE 0x12345678) 18 22 := by
  native_decide

/-- Real-disassembly encoding matches our previous structural encoding. -/
example : adrsSetKeypairRealMoveBC (Fips205.Bytes.zeros 22) 0xdeadbeef =
            AdrsSetters.adrsSetKeypairMoveBC (Fips205.Bytes.zeros 22) 0xdeadbeef.toUInt64 := by
  native_decide

end Fips205.Move.AdrsSetKeypairReal
