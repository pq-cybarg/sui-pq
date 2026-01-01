import Move.Value
import Move.Stack
import Move.Opcode
import Move.Step
import Move.Native
import Move.ConcatReal
import Move.Mgf1
import Move.Hmsg
import Fips205.Bytes
import Fips205.Thash

/-! # `hmsg` — real disassembled Move bytecode

```
hmsg(r, pk_seed, pk_root, m): vector<u8> {
  L4: inner, L5: seed
  0-3: push r, pk_seed, pk_root, m
  4: Call concat4 ; 5: Call hash::sha2_256 ; 6: StLoc[4] inner
  7-9: push r, pk_seed, &inner
  10: Call concat3 ; 11: StLoc[5] seed
  12: ImmBorrowLoc[5] seed ; 13: LdConst[9](u64: 30)
  14: Call mgf1_sha256 ; 15: Ret
}
```

The randomized message hash. Composes three `Call`s — `concat4` (itself a
3-deep concat nest), `concat3`, and `mgf1_sha256` (the iterated SHA-256
MGF) — plus a direct `CallNative sha2_256`. `seed` reaches `mgf1` as a
`&` ref, exercising the `locRef`-deref path in `VecAppend`.
-/

namespace Fips205.Move.HmsgReal

open Fips205.Move Fips205.Move.Value Fips205.Move.State Fips205

/-- concat4 non-arg locals: i, n, out (L4..L6). -/
def concat4LocalsTail : Array Value := #[Value.u64 0, Value.u64 0, Value.vecU8 ByteArray.empty]
/-- concat3 non-arg locals: i, n, out (L3..L5). -/
def concat3LocalsTail : Array Value := #[Value.u64 0, Value.u64 0, Value.vecU8 ByteArray.empty]
/-- mgf1_sha256 non-arg locals: out, counter, ctr, block, j (L2..L6). -/
def mgf1LocalsTail : Array Value :=
  #[Value.vecU8 ByteArray.empty, Value.u64 0, Value.vecU8 ByteArray.empty,
    Value.vecU8 ByteArray.empty, Value.u64 0]

def hmsgRealBytecode : Bytecode := #[
  -- inner := sha256(concat4(r, pk_seed, pk_root, m))
  .CopyLoc 0,                                                       -- 0
  .CopyLoc 1,                                                       -- 1
  .MoveLoc 2,                                                       -- 2
  .MoveLoc 3,                                                       -- 3
  .Call ConcatReal.concat4RealBytecode concat4LocalsTail 4,         -- 4
  .CallNative "sha2_256" 1,                                         -- 5
  .StLoc 4,                                                         -- 6
  -- seed := concat3(r, pk_seed, inner)
  .MoveLoc 0,                                                       -- 7
  .MoveLoc 1,                                                       -- 8
  .ImmBorrowLoc 4,                                                  -- 9
  .Call ConcatReal.concat3RealBytecode concat3LocalsTail 3,         -- 10
  .StLoc 5,                                                         -- 11
  -- mgf1_sha256(&seed, 30)
  .ImmBorrowLoc 5,                                                  -- 12
  .LdU64 30,                                                        -- 13
  .Call Mgf1.mgf1Bytecode mgf1LocalsTail 2,                         -- 14
  .Ret                                                             -- 15
]

def initialState (r pkSeed pkRoot m : ByteArray) : State :=
  { stack := #[]
    locals := #[Value.vecU8 r,                  -- 0
                Value.vecU8 pkSeed,              -- 1
                Value.vecU8 pkRoot,              -- 2
                Value.vecU8 m,                   -- 3
                Value.vecU8 ByteArray.empty,     -- 4: inner
                Value.vecU8 ByteArray.empty],    -- 5: seed
    pc := 0, error := none }

def hmsgRealMoveBC (r pkSeed pkRoot m : ByteArray) : ByteArray :=
  let final := runDefault hmsgRealBytecode (initialState r pkSeed pkRoot m)
  match final.stack.back? with
  | some (Value.vecU8 v) => v
  | _ => ByteArray.empty

/-! ## Equivalence theorems -/

/-- All-zero 16-byte inputs, empty message. -/
example :
    hmsgRealMoveBC (Fips205.Bytes.zeros 16) (Fips205.Bytes.zeros 16)
                   (Fips205.Bytes.zeros 16) ByteArray.empty =
      Fips205.Thash.hmsg (Fips205.Bytes.zeros 16) (Fips205.Bytes.zeros 16)
                          (Fips205.Bytes.zeros 16) ByteArray.empty := by
  native_decide

/-- Real-shaped inputs + short message. -/
example :
    let r       := Fips205.Bytes.hexDecode "0102030405060708090a0b0c0d0e0f10"
    let pk_seed := Fips205.Bytes.hexDecode "1112131415161718191a1b1c1d1e1f20"
    let pk_root := Fips205.Bytes.hexDecode "2122232425262728292a2b2c2d2e2f30"
    let m       := Fips205.Bytes.hexDecode "deadbeef"
    hmsgRealMoveBC r pk_seed pk_root m = Fips205.Thash.hmsg r pk_seed pk_root m := by
  native_decide

/-- Longer message (multi-block inner SHA-256). -/
example :
    let r       := Fips205.Bytes.zeros 16
    let pk_seed := Fips205.Bytes.zeros 16
    let pk_root := Fips205.Bytes.zeros 16
    let m       := Fips205.Bytes.hexDecode (String.ofList (List.replicate 200 'f'))
    hmsgRealMoveBC r pk_seed pk_root m = Fips205.Thash.hmsg r pk_seed pk_root m := by
  native_decide

/-- The real-disassembly encoding matches our previous structural encoding. -/
example :
    let r       := Fips205.Bytes.hexDecode "0102030405060708090a0b0c0d0e0f10"
    let pk_seed := Fips205.Bytes.hexDecode "1112131415161718191a1b1c1d1e1f20"
    let pk_root := Fips205.Bytes.hexDecode "2122232425262728292a2b2c2d2e2f30"
    let m       := Fips205.Bytes.hexDecode "deadbeef"
    hmsgRealMoveBC r pk_seed pk_root m = Fips205.Move.Hmsg.hmsgMoveBC r pk_seed pk_root m := by
  native_decide

/-- Output is exactly m_bytes = 30. -/
example :
    (hmsgRealMoveBC (Fips205.Bytes.zeros 16) (Fips205.Bytes.zeros 16)
                    (Fips205.Bytes.zeros 16) ByteArray.empty).size = Fips205.m_bytes := by
  native_decide

end Fips205.Move.HmsgReal
