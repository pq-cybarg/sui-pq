import Move.Value
import Move.Stack
import Move.Opcode
import Move.Step
import Move.BaseW
import Fips205.Bytes
import Fips205.Wots

/-! # `base_w` — real disassembled Move bytecode

```
base_w(msg: &vector<u8>, outlen: u64): vector<u32> {
  L2: bits, L3: i, L4: in_idx, L5: out, L6: total
B0 prologue (PCs 0-9):
  0: LdConst[20](vec<u32>: empty)
  1: StLoc[5] out
  2: LdU64(0) ; 3: StLoc[4] in_idx
  4: LdU64(0) ; 5: StLoc[2] bits
  6: LdU32(0) ; 7: StLoc[6] total
  8: LdU64(0) ; 9: StLoc[3] i
B1 (loop test):
  10-13: CopyLoc[3] i ; CopyLoc[1] outlen ; Lt ; BrFalse 51
B2:  14: Branch 15
B3 (refill check `if bits == 0`):
  15-18: CopyLoc[2] bits ; LdU64(0) ; Eq ; BrFalse 31
B4 (refill: total := msg[in_idx] as u32; in_idx += 1; bits := 8):
  19-30: CopyLoc[0] msg ; CopyLoc[4] in_idx ; VecImmBorrow ; ReadRef ; CastU32
         ; StLoc[6] total ; MoveLoc[4] in_idx ; LdU64(1) ; Add ; StLoc[4] in_idx
         ; LdU64(8) ; StLoc[2] bits
B5 (digit emit + i += 1):
  31-34: MoveLoc[2] bits ; LdConst[1](u64: 4) ; Sub ; StLoc[2] bits
  35-45: MutBorrowLoc[5] out ; CopyLoc[6] total ; CopyLoc[2] bits ; CastU8
         ; Shr ; LdConst[0](u64: 16) ; CastU32 ; LdU32(1) ; Sub ; BitAnd
         ; VecPushBack(32)                    ← VecU32PushBack with locRef
  46-50: MoveLoc[3] i ; LdU64(1) ; Add ; StLoc[3] i ; Branch 10
B6 (epilogue): 51-54
```

Exercises:
  * `LdConst (Value.vecU32 #[])` — typed constant pool load.
  * `CastU32` / `CastU8` polymorphic casts.
  * `MutBorrowLoc` of a `vector<u32>` local + `VecU32PushBack`
    write-through-`locRef` (just added).
  * Mixed `u32 >> u8` shift via polymorphic Shr.
-/

namespace Fips205.Move.BaseWReal

open Fips205.Move Fips205.Move.Value Fips205.Move.State Fips205

def baseWRealBytecode : Bytecode := #[
  -- B0: prologue
  .LdConst (Value.vecU32 #[]),               -- 0
  .StLoc 5,                                   -- 1
  .LdU64 0,                                   -- 2
  .StLoc 4,                                   -- 3
  .LdU64 0,                                   -- 4
  .StLoc 2,                                   -- 5
  .LdU32 0,                                   -- 6
  .StLoc 6,                                   -- 7
  .LdU64 0,                                   -- 8
  .StLoc 3,                                   -- 9
  -- B1: loop test
  .CopyLoc 3,                                 -- 10
  .CopyLoc 1,                                 -- 11
  .Lt,                                        -- 12
  .BrFalse 51,                                -- 13
  -- B2: compiler-emitted Branch
  .Branch 15,                                 -- 14
  -- B3: refill check (bits == 0?)
  .CopyLoc 2,                                 -- 15
  .LdU64 0,                                   -- 16
  .Eq,                                        -- 17
  .BrFalse 31,                                -- 18
  -- B4: refill block
  .CopyLoc 0,                                 -- 19
  .CopyLoc 4,                                 -- 20
  .VecImmBorrow,                              -- 21
  .ReadRef,                                   -- 22
  .CastU32,                                   -- 23
  .StLoc 6,                                   -- 24  total := msg[in_idx] as u32
  .MoveLoc 4,                                 -- 25
  .LdU64 1,                                   -- 26
  .Add,                                       -- 27
  .StLoc 4,                                   -- 28  in_idx += 1
  .LdU64 8,                                   -- 29
  .StLoc 2,                                   -- 30  bits := 8
  -- B5: digit emit
  .MoveLoc 2,                                 -- 31
  .LdU64 4,                                   -- 32  (LdConst[1] u64:4)
  .Sub,                                       -- 33
  .StLoc 2,                                   -- 34  bits -= 4
  .MutBorrowLoc 5,                            -- 35  &mut out
  .CopyLoc 6,                                 -- 36  total
  .CopyLoc 2,                                 -- 37  bits
  .CastU8,                                    -- 38
  .Shr,                                       -- 39  total >> bits (u32 >> u8 → u32)
  .LdU64 16,                                  -- 40  (LdConst[0] u64:16)
  .CastU32,                                   -- 41
  .LdU32 1,                                   -- 42
  .Sub,                                       -- 43  16 - 1 = 0xf as u32
  .BitAnd,                                    -- 44  & 0xf
  .VecU32PushBack,                            -- 45  out.push_back(digit)  ← write-through-locRef
  .MoveLoc 3,                                 -- 46
  .LdU64 1,                                   -- 47
  .Add,                                       -- 48
  .StLoc 3,                                   -- 49  i += 1
  .Branch 10,                                 -- 50
  -- B6: epilogue
  .MoveLoc 0,                                 -- 51
  .Pop,                                       -- 52
  .MoveLoc 5,                                 -- 53
  .Ret                                        -- 54
]

def initialState (msg : ByteArray) (outlen : Nat) : State :=
  { stack := #[]
    locals := #[Value.vecU8 msg,                       -- 0: msg
                Value.u64 (UInt64.ofNat outlen),       -- 1: outlen
                Value.u64 0,                            -- 2: bits
                Value.u64 0,                            -- 3: i
                Value.u64 0,                            -- 4: in_idx
                Value.vecU32 #[],                       -- 5: out
                Value.u32 0],                           -- 6: total
    pc := 0, error := none }

def baseWRealMoveBC (msg : ByteArray) (outlen : Nat) : Array UInt32 :=
  let final := runDefault baseWRealBytecode (initialState msg outlen)
  match final.stack.back? with
  | some (Value.vecU32 v) => v
  | _ => #[]

/-! ## Equivalence theorems -/

/-- 2 digits from 1 byte. -/
example : (baseWRealMoveBC (Fips205.Bytes.hexDecode "ab") 2).map (·.toNat) =
            Fips205.Wots.baseW (Fips205.Bytes.hexDecode "ab") 2 := by
  native_decide

/-- 4 digits from 2 bytes. -/
example : (baseWRealMoveBC (Fips205.Bytes.hexDecode "abcd") 4).map (·.toNat) =
            Fips205.Wots.baseW (Fips205.Bytes.hexDecode "abcd") 4 := by
  native_decide

/-- All-zero 16 bytes → 32 digits of 0. -/
example : (baseWRealMoveBC (Fips205.Bytes.zeros 16) 32).map (·.toNat) =
            Fips205.Wots.baseW (Fips205.Bytes.zeros 16) 32 := by
  native_decide

/-- Real WOTS+ msg_n (full 16 bytes → len_1=32 digits). -/
example :
    let msg := Fips205.Bytes.hexDecode "112233445566778899aabbccddeeff00"
    (baseWRealMoveBC msg 32).map (·.toNat) = Fips205.Wots.baseW msg 32 := by
  native_decide

/-- All-0xff input yields all 0xf digits. -/
example : (baseWRealMoveBC (Fips205.Bytes.hexDecode "ffffffffffffffffffffffffffffffff") 32).map (·.toNat) =
            Array.replicate 32 0xf := by
  native_decide

/-- The real-disassembly encoding matches our previous structural encoding. -/
example : baseWRealMoveBC (Fips205.Bytes.zeros 16) 32 =
            Fips205.Move.BaseW.baseWMoveBC (Fips205.Bytes.zeros 16) 32 := by
  native_decide

end Fips205.Move.BaseWReal
