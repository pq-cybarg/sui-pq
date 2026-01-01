import Move.Value
import Move.Stack
import Move.Opcode
import Move.Step
import Fips205.Bytes

/-! # `concat` and `concat3` — real disassembled Move bytecode

`concat(a, b) = a ++ b` and `concat3(a, b, c) = a ++ b ++ c`. From
`sui move disassemble`. The pair is interesting because:

  * `concat` exercises the same `MutBorrowLoc + VecPushBack` write pattern
    we've already covered.
  * `concat3` uses the real Move `Call` opcode to invoke `concat`
    (PC 2 in the disassembly: `Call concat(&vector<u8>, &vector<u8>)`).
    Our VM's `Call` opcode encodes the callee bytecode directly — this
    file is the empirical validation that our `Call` ABI agrees with
    Move's actual function-call semantics.

```
concat(a, b): vector<u8> {
  L2: i, L3: n, L4: out
  0:  MoveLoc[0] (a)        ; 1: ReadRef    ; 2: StLoc[4] out := *a
  3:  LdU64(0)              ; 4: StLoc[2] i := 0
  5:  CopyLoc[1] (b)        ; 6: VecLen     ; 7: StLoc[3] n := |b|
  loop:
  8:  CopyLoc[2] i ; 9: CopyLoc[3] n ; 10: Lt ; 11: BrFalse 24
  12: Branch 13
  13: MutBorrowLoc[4] out
  14: CopyLoc[1] b ; 15: CopyLoc[2] i ; 16: VecImmBorrow ; 17: ReadRef ; 18: VecPushBack
  19: MoveLoc[2] i ; 20: LdU64(1) ; 21: Add ; 22: StLoc[2] i
  23: Branch 8
  24: MoveLoc[1] b ; 25: Pop ; 26: MoveLoc[4] out ; 27: Ret
}
```
-/

namespace Fips205.Move.ConcatReal

open Fips205.Move Fips205.Move.Value Fips205.Move.State Fips205

/-- Disassembly-accurate bytecode for `concat`. -/
def concatRealBytecode : Bytecode := #[
  -- B0: out := *a, i := 0, n := |b|
  .MoveLoc 0,                       -- 0
  .ReadRef,                         -- 1
  .StLoc 4,                         -- 2
  .LdU64 0,                         -- 3
  .StLoc 2,                         -- 4
  .CopyLoc 1,                       -- 5
  .VecLen,                          -- 6
  .StLoc 3,                         -- 7
  -- B1: loop test
  .CopyLoc 2,                       -- 8
  .CopyLoc 3,                       -- 9
  .Lt,                              -- 10
  .BrFalse 24,                      -- 11
  -- B2 (compiler-emitted Branch)
  .Branch 13,                       -- 12
  -- B3: body — out.push_back(b[i])
  .MutBorrowLoc 4,                  -- 13
  .CopyLoc 1,                       -- 14
  .CopyLoc 2,                       -- 15
  .VecImmBorrow,                    -- 16
  .ReadRef,                         -- 17
  .VecPushBack,                     -- 18
  .MoveLoc 2,                       -- 19
  .LdU64 1,                         -- 20
  .Add,                             -- 21
  .StLoc 2,                         -- 22
  .Branch 8,                        -- 23
  -- B4: epilogue
  .MoveLoc 1,                       -- 24
  .Pop,                             -- 25
  .MoveLoc 4,                       -- 26
  .Ret                              -- 27
]

/-- Initial state for concat: locals 0,1 = a,b values; 2,3,4 placeholders. -/
def concatInitialState (a b : ByteArray) : State :=
  { stack := #[]
    locals := #[Value.vecU8 a, Value.vecU8 b,
                Value.u64 0, Value.u64 0,
                Value.vecU8 ByteArray.empty],
    pc := 0, error := none }

def concatRealMoveBC (a b : ByteArray) : ByteArray :=
  let final := runDefault concatRealBytecode (concatInitialState a b)
  match final.stack.back? with
  | some (Value.vecU8 v) => v
  | _ => ByteArray.empty

/-- The non-arg portion of concat's initial locals (i, n, out). -/
def concatLocalsTail : Array Value :=
  #[Value.u64 0,                    -- 2: i
    Value.u64 0,                    -- 3: n
    Value.vecU8 ByteArray.empty]    -- 4: out

/-- Disassembly-accurate bytecode for `concat3`. PC 2 uses our `Call` opcode
    embedding `concatRealBytecode` — exactly the Move VM's `Call concat`
    pattern, just with the callee inlined rather than looked up by symbol. -/
def concat3RealBytecode : Bytecode := #[
  -- B0: out := concat(a, b); i := 0; n := |c|
  .MoveLoc 0,                                              -- 0
  .MoveLoc 1,                                              -- 1
  .Call concatRealBytecode concatLocalsTail 2,             -- 2
  .StLoc 5,                                                -- 3
  .LdU64 0,                                                -- 4
  .StLoc 3,                                                -- 5
  .CopyLoc 2,                                              -- 6
  .VecLen,                                                 -- 7
  .StLoc 4,                                                -- 8
  -- B1: loop test
  .CopyLoc 3,                                              -- 9
  .CopyLoc 4,                                              -- 10
  .Lt,                                                     -- 11
  .BrFalse 25,                                             -- 12
  -- B2 (compiler-emitted Branch)
  .Branch 14,                                              -- 13
  -- B3: body — out.push_back(c[i])
  .MutBorrowLoc 5,                                         -- 14
  .CopyLoc 2,                                              -- 15
  .CopyLoc 3,                                              -- 16
  .VecImmBorrow,                                           -- 17
  .ReadRef,                                                -- 18
  .VecPushBack,                                            -- 19
  .MoveLoc 3,                                              -- 20
  .LdU64 1,                                                -- 21
  .Add,                                                    -- 22
  .StLoc 3,                                                -- 23
  .Branch 9,                                               -- 24
  -- B4: epilogue
  .MoveLoc 2,                                              -- 25
  .Pop,                                                    -- 26
  .MoveLoc 5,                                              -- 27
  .Ret                                                     -- 28
]

def concat3InitialState (a b c : ByteArray) : State :=
  { stack := #[]
    locals := #[Value.vecU8 a, Value.vecU8 b, Value.vecU8 c,
                Value.u64 0, Value.u64 0,
                Value.vecU8 ByteArray.empty],
    pc := 0, error := none }

def concat3RealMoveBC (a b c : ByteArray) : ByteArray :=
  let final := runDefault concat3RealBytecode (concat3InitialState a b c)
  match final.stack.back? with
  | some (Value.vecU8 v) => v
  | _ => ByteArray.empty

/-- concat3 declared non-arg locals: i, n, out (L3..L5). -/
def concat3LocalsTail : Array Value := #[Value.u64 0, Value.u64 0, Value.vecU8 ByteArray.empty]

/-- Disassembly-accurate bytecode for `concat4` (= concat3(a,b,c) ++ d). PC 3
    uses `Call concat3`, which itself `Call`s `concat` — a 3-deep concat nest. -/
def concat4RealBytecode : Bytecode := #[
  -- B0: out := concat3(a, b, c); i := 0; n := |d|
  .MoveLoc 0,                                              -- 0
  .MoveLoc 1,                                              -- 1
  .MoveLoc 2,                                              -- 2
  .Call concat3RealBytecode concat3LocalsTail 3,           -- 3
  .StLoc 6,                                                -- 4
  .LdU64 0,                                                -- 5
  .StLoc 4,                                                -- 6
  .CopyLoc 3,                                              -- 7
  .VecLen,                                                 -- 8
  .StLoc 5,                                                -- 9
  -- B1: loop test
  .CopyLoc 4,                                              -- 10
  .CopyLoc 5,                                              -- 11
  .Lt,                                                     -- 12
  .BrFalse 26,                                             -- 13
  -- B2
  .Branch 15,                                              -- 14
  -- B3: out.push_back(d[i])
  .MutBorrowLoc 6,                                         -- 15
  .CopyLoc 3,                                              -- 16
  .CopyLoc 4,                                              -- 17
  .VecImmBorrow,                                           -- 18
  .ReadRef,                                                -- 19
  .VecPushBack,                                            -- 20
  .MoveLoc 4,                                              -- 21
  .LdU64 1,                                                -- 22
  .Add,                                                    -- 23
  .StLoc 4,                                                -- 24
  .Branch 10,                                              -- 25
  -- B4: epilogue
  .MoveLoc 3,                                              -- 26
  .Pop,                                                    -- 27
  .MoveLoc 6,                                              -- 28
  .Ret                                                     -- 29
]

def concat4InitialState (a b c d : ByteArray) : State :=
  { stack := #[]
    locals := #[Value.vecU8 a, Value.vecU8 b, Value.vecU8 c, Value.vecU8 d,
                Value.u64 0, Value.u64 0,
                Value.vecU8 ByteArray.empty],
    pc := 0, error := none }

def concat4RealMoveBC (a b c d : ByteArray) : ByteArray :=
  let final := runDefault concat4RealBytecode (concat4InitialState a b c d)
  match final.stack.back? with
  | some (Value.vecU8 v) => v
  | _ => ByteArray.empty

/-! ## Equivalence theorems -/

/-- concat: empty + empty = empty. -/
example : concatRealMoveBC ByteArray.empty ByteArray.empty = ByteArray.empty := by
  native_decide

/-- concat matches `++` on representative inputs. -/
example : concatRealMoveBC (Fips205.Bytes.hexDecode "deadbeef")
                           (Fips205.Bytes.hexDecode "cafebabe") =
            (Fips205.Bytes.hexDecode "deadbeef") ++ (Fips205.Bytes.hexDecode "cafebabe") := by
  native_decide

/-- concat3 matches `++` chained, using the cross-bytecode `Call` opcode. -/
example : concat3RealMoveBC (Fips205.Bytes.hexDecode "0102")
                            (Fips205.Bytes.hexDecode "0304")
                            (Fips205.Bytes.hexDecode "0506") =
            (Fips205.Bytes.hexDecode "010203040506") := by
  native_decide

/-- concat3 on real-shaped 16-byte inputs (= FIPS-205 hmsg inner concat). -/
example :
    let a := Fips205.Bytes.hexDecode "00112233445566778899aabbccddeeff"
    let b := Fips205.Bytes.hexDecode "1010101010101010101010101010101a"
    let c := Fips205.Bytes.hexDecode "2020202020202020202020202020202b"
    concat3RealMoveBC a b c = a ++ b ++ c := by
  native_decide

/-- concat3 with empties on the ends. -/
example :
    concat3RealMoveBC ByteArray.empty (Fips205.Bytes.hexDecode "abcd") ByteArray.empty =
      Fips205.Bytes.hexDecode "abcd" := by
  native_decide

/-- Size invariant for concat3. -/
example : (concat3RealMoveBC (Fips205.Bytes.zeros 16)
                              (Fips205.Bytes.zeros 16)
                              (Fips205.Bytes.zeros 32)).size = 64 := by
  native_decide

/-- concat4 (3-deep Call nest: concat4 → concat3 → concat) matches `++`. -/
example :
    concat4RealMoveBC (Fips205.Bytes.hexDecode "01") (Fips205.Bytes.hexDecode "0203")
                      (Fips205.Bytes.hexDecode "040506") (Fips205.Bytes.hexDecode "0708090a") =
      Fips205.Bytes.hexDecode "0102030405060708090a" := by
  native_decide

/-- concat4 on real hmsg-shaped inputs (16+16+16 + message). -/
example :
    let r := Fips205.Bytes.hexDecode "00112233445566778899aabbccddeeff"
    let pkSeed := Fips205.Bytes.hexDecode "102132435465768798a9bacbdcedfe0f"
    let pkRoot := Fips205.Bytes.hexDecode "2030405060708090a0b0c0d0e0f00010"
    let m := Fips205.Bytes.hexDecode "deadbeef"
    concat4RealMoveBC r pkSeed pkRoot m = r ++ pkSeed ++ pkRoot ++ m := by
  native_decide

end Fips205.Move.ConcatReal
