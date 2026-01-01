import Move.Value
import Move.Stack
import Move.Opcode
import Move.Step
import Fips205.Bytes

/-! # `adrs_new` and `append_slice` — real disassembled Move bytecode

Two tiny utility primitives from `sha2_128s.move`. Both use only the VM
features we've already exercised — listed here to round out the
disassembled-bytecode coverage of the small-helper layer.

```
adrs_new(): vector<u8> {
  L0: a, L1: i
  0: LdConst[18](vec<u8>: empty) ; 1: StLoc[0] a
  2: LdU64(0) ; 3: StLoc[1] i
  4: CopyLoc[1] i ; 5: LdConst[11](u64:22) ; 6: Lt ; 7: BrFalse 17
  8: Branch 9
  9: MutBorrowLoc[0] a ; 10: LdU8(0) ; 11: VecPushBack(23)
  12: MoveLoc[1] i ; 13: LdU64(1) ; 14: Add ; 15: StLoc[1] i ; 16: Branch 4
  17: MoveLoc[0] a ; 18: Ret
}
```

```
append_slice(dst: &mut vector<u8>, src: &vector<u8>, start: u64, len: u64) {
  L4: i
  0: LdU64(0) ; 1: StLoc[4] i
  2: CopyLoc[4] i ; 3: CopyLoc[3] len ; 4: Lt ; 5: BrFalse 20
  6: Branch 7
  7: CopyLoc[0] dst ; 8: CopyLoc[1] src ; 9: CopyLoc[2] start ; 10: CopyLoc[4] i
  11: Add ; 12: VecImmBorrow(23) ; 13: ReadRef ; 14: VecPushBack(23)
  15: MoveLoc[4] i ; 16: LdU64(1) ; 17: Add ; 18: StLoc[4] i ; 19: Branch 2
  20: MoveLoc[1] src ; 21: Pop ; 22: MoveLoc[0] dst ; 23: Pop ; 24: Ret
}
```
-/

namespace Fips205.Move.AdrsNewAppendSliceReal

open Fips205.Move Fips205.Move.Value Fips205.Move.State Fips205

/-! ## `adrs_new` — produce a 22-byte zero buffer -/

def adrsNewRealBytecode : Bytecode := #[
  .LdConst (Value.vecU8 ByteArray.empty),     -- 0
  .StLoc 0,                                    -- 1
  .LdU64 0,                                    -- 2
  .StLoc 1,                                    -- 3
  .CopyLoc 1,                                  -- 4
  .LdU64 22,                                   -- 5
  .Lt,                                         -- 6
  .BrFalse 17,                                 -- 7
  .Branch 9,                                   -- 8
  .MutBorrowLoc 0,                             -- 9
  .LdU8 0,                                     -- 10
  .VecPushBack,                                -- 11
  .MoveLoc 1,                                  -- 12
  .LdU64 1,                                    -- 13
  .Add,                                        -- 14
  .StLoc 1,                                    -- 15
  .Branch 4,                                   -- 16
  .MoveLoc 0,                                  -- 17
  .Ret                                         -- 18
]

def adrsNewRealMoveBC : ByteArray :=
  let s : State := { stack := #[], locals := #[Value.vecU8 ByteArray.empty, Value.u64 0],
                     pc := 0, error := none }
  let final := runDefault adrsNewRealBytecode s
  match final.stack.back? with
  | some (Value.vecU8 v) => v
  | _ => ByteArray.empty

example : adrsNewRealMoveBC = Fips205.Bytes.zeros 22 := by native_decide
example : adrsNewRealMoveBC.size = 22 := by native_decide

/-! ## `append_slice` — extend dst in-place with src[start..start+len] -/

def appendSliceRealBytecode : Bytecode := #[
  .LdU64 0,                                    -- 0
  .StLoc 4,                                    -- 1
  .CopyLoc 4,                                  -- 2
  .CopyLoc 3,                                  -- 3
  .Lt,                                         -- 4
  .BrFalse 20,                                 -- 5
  .Branch 7,                                   -- 6
  .CopyLoc 0,                                  -- 7
  .CopyLoc 1,                                  -- 8
  .CopyLoc 2,                                  -- 9
  .CopyLoc 4,                                  -- 10
  .Add,                                        -- 11
  .VecImmBorrow,                               -- 12
  .ReadRef,                                    -- 13
  .VecPushBack,                                -- 14  write-through dst
  .MoveLoc 4,                                  -- 15
  .LdU64 1,                                    -- 16
  .Add,                                        -- 17
  .StLoc 4,                                    -- 18
  .Branch 2,                                   -- 19
  .MoveLoc 1,                                  -- 20
  .Pop,                                        -- 21
  .MoveLoc 0,                                  -- 22
  .Pop,                                        -- 23
  .Ret                                         -- 24
]

/-- Test wrapper for the void mutating `append_slice`: storage at locals[5]. -/
def appendSliceInitialState (dst src : ByteArray) (start len : Nat) : State :=
  { stack := #[]
    locals := #[Value.locRef 5,                       -- 0: dst (ref)
                Value.vecU8 src,                      -- 1: src
                Value.u64 (UInt64.ofNat start),       -- 2: start
                Value.u64 (UInt64.ofNat len),         -- 3: len
                Value.u64 0,                          -- 4: i
                Value.vecU8 dst],                     -- 5: backing storage for dst
    pc := 0, error := none }

def appendSliceRealMoveBC (dst src : ByteArray) (start len : Nat) : ByteArray :=
  let final := runDefault appendSliceRealBytecode (appendSliceInitialState dst src start len)
  match final.locals[5]? with
  | some (Value.vecU8 v) => v
  | _ => ByteArray.empty

/-- Spec: `append_slice(dst, src, start, len)` mutates dst to `dst ++ src[start..start+len]`. -/
example : appendSliceRealMoveBC (Fips205.Bytes.hexDecode "0102")
                                (Fips205.Bytes.hexDecode "deadbeef") 0 4 =
            (Fips205.Bytes.hexDecode "0102") ++ (Fips205.Bytes.hexDecode "deadbeef") := by
  native_decide

example : appendSliceRealMoveBC (Fips205.Bytes.hexDecode "0102")
                                (Fips205.Bytes.hexDecode "deadbeefcafe") 2 3 =
            (Fips205.Bytes.hexDecode "0102") ++ (Fips205.Bytes.hexDecode "beefca") := by
  native_decide

/-- Empty append: dst unchanged. -/
example : appendSliceRealMoveBC (Fips205.Bytes.hexDecode "abcd")
                                (Fips205.Bytes.hexDecode "deadbeef") 0 0 =
            Fips205.Bytes.hexDecode "abcd" := by
  native_decide

end Fips205.Move.AdrsNewAppendSliceReal
