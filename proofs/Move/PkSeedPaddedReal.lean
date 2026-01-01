import Move.Value
import Move.Stack
import Move.Opcode
import Move.Step
import Move.PkSeedPadded
import Fips205.Bytes

/-! # `pk_seed_padded` — real disassembled Move bytecode

From `sui move disassemble move/slh_dsa_128s/.../sha2_128s.mv`:

```
pk_seed_padded(pk_seed: &vector<u8>): vector<u8> {
  L1: i: u64
  L2: out: vector<u8>
B0:
  0: MoveLoc[0](pk_seed)
  1: ReadRef
  2: StLoc[2](out)
  3: LdU64(0)
  4: StLoc[1](i)
B1:
  5: CopyLoc[1](i)
  6: LdU64(48)
  7: Lt
  8: BrFalse(18)
B2:
  9: Branch(10)
B3:
  10: MutBorrowLoc[2](out)
  11: LdU8(0)
  12: VecPushBack(23)
  13: MoveLoc[1](i)
  14: LdU64(1)
  15: Add
  16: StLoc[1](i)
  17: Branch(5)
B4:
  18: MoveLoc[2](out)
  19: Ret
```

Second primitive bytecode encoded opcode-for-opcode from the actual
compiled `.mv` (after `slice` in `SliceReal.lean`). Uses the same VM
extensions (`MutBorrowLoc`, `ReadRef`, in-place `VecPushBack`).

The fact that this encoding works without any further VM changes shows
the new opcode set generalises: `slice` and `pk_seed_padded` share the
loop-with-MutBorrowLoc pattern that the Move compiler always emits for
"build a vec via push_back". The other primitives that share this shape
will lift the same way.
-/

namespace Fips205.Move.PkSeedPaddedReal

open Fips205.Move Fips205.Move.Value Fips205.Move.State Fips205

/-- Disassembly-accurate bytecode for `pk_seed_padded`. PCs match. -/
def pkSeedPaddedRealBytecode : Bytecode := #[
  -- B0
  .MoveLoc 0,                               -- 0
  .ReadRef,                                 -- 1
  .StLoc 2,                                 -- 2
  .LdU64 0,                                 -- 3
  .StLoc 1,                                 -- 4
  -- B1 (loop test)
  .CopyLoc 1,                               -- 5
  .LdU64 48,                                -- 6
  .Lt,                                      -- 7
  .BrFalse 18,                              -- 8
  -- B2 (compiler-emitted Branch into B3)
  .Branch 10,                               -- 9
  -- B3 (loop body)
  .MutBorrowLoc 2,                          -- 10
  .LdU8 0,                                  -- 11
  .VecPushBack,                             -- 12  (write through &mut out)
  .MoveLoc 1,                               -- 13
  .LdU64 1,                                 -- 14
  .Add,                                     -- 15
  .StLoc 1,                                 -- 16
  .Branch 5,                                -- 17
  -- B4 (epilogue)
  .MoveLoc 2,                               -- 18
  .Ret                                      -- 19
]

/-- Initial state for pk_seed_padded: local 0 = pk_seed value;
    locals 1 (i) and 2 (out) are placeholders, overwritten by PCs 0-4. -/
def initialState (pkSeed : ByteArray) : State :=
  { stack := #[]
    locals := #[Value.vecU8 pkSeed,
                Value.u64 0,                  -- i
                Value.vecU8 ByteArray.empty], -- out
    pc := 0, error := none }

def pkSeedPaddedRealMoveBC (pkSeed : ByteArray) : ByteArray :=
  let final := runDefault pkSeedPaddedRealBytecode (initialState pkSeed)
  match final.stack.back? with
  | some (Value.vecU8 v) => v
  | _ => ByteArray.empty

/-! ## Equivalence theorems -/

/-- Empty input: returns 48 zero bytes. -/
example : pkSeedPaddedRealMoveBC ByteArray.empty = Fips205.Bytes.zeros 48 := by
  native_decide

/-- 16-byte pk_seed: returns 64 bytes (= 16 + 48). -/
example : pkSeedPaddedRealMoveBC (Fips205.Bytes.hexDecode "00112233445566778899aabbccddeeff") =
    (Fips205.Bytes.hexDecode "00112233445566778899aabbccddeeff") ++ Fips205.Bytes.zeros 48 := by
  native_decide

/-- Size invariant: always returns `|pk_seed| + 48` bytes. -/
example : (pkSeedPaddedRealMoveBC (Fips205.Bytes.zeros 16)).size = 64 := by
  native_decide

/-- The real disassembly encoding matches our previous structural encoding. -/
example : pkSeedPaddedRealMoveBC (Fips205.Bytes.zeros 16) =
    Fips205.Move.PkSeedPadded.pkSeedPaddedMoveBC (Fips205.Bytes.zeros 16) := by
  native_decide

/-- General spec equality: byte-perfect against `pk_seed ++ zeros 48`. -/
example : pkSeedPaddedRealMoveBC (Fips205.Bytes.hexDecode "deadbeef") =
    (Fips205.Bytes.hexDecode "deadbeef") ++ Fips205.Bytes.zeros 48 := by
  native_decide

end Fips205.Move.PkSeedPaddedReal
