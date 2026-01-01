import Move.Value
import Move.Stack
import Move.Opcode
import Move.Step
import Move.BaseWReal
import Move.WotsChecksumReal
import Fips205.Bytes
import Fips205.Wots

/-! # `msg_to_chain_digits` — real disassembled Move bytecode

```
msg_to_chain_digits(msg_n: &vector<u8>): vector<u32> {
  L1: csum_digits, L2: digits, L3: i
B0:
  0: MoveLoc[0] msg_n ; 1: LdConst[2](u64:32)
  2: Call base_w ; 3: StLoc[2] digits              // digits := base_w(msg_n, 32)
  4: ImmBorrowLoc[2] digits
  5: Call wots_checksum ; 6: StLoc[1] csum_digits   // csum := wots_checksum(&digits)
  7: LdU64(0) ; 8: StLoc[3] i
B1: for i in 0..3:                                   // append the 3 checksum digits
  14: MutBorrowLoc[2] digits ; 15: ImmBorrowLoc[1] csum_digits
  16: CopyLoc[3] i ; 17: VecImmBorrow(32) ; 18: ReadRef ; 19: VecPushBack(32)
  ...
B4: 25: MoveLoc[2] digits ; 26: Ret
}
```

First orchestrator: composes `Call base_w` and `Call wots_checksum` (the
latter itself `Call`s `base_w` internally — so this is 2-deep nested Call
on the vector<u32> path). The append loop uses `VecU32ImmBorrow` /
`VecU32PushBack` with `locRef` deref + write-through.
-/

namespace Fips205.Move.MsgToChainDigitsReal

open Fips205.Move Fips205.Move.Value Fips205.Move.State Fips205

/-- wots_checksum callee: 7 declared non-arg locals (csum, csum_bytes, i, j,
    k, len_bytes, shift) — see WotsChecksumReal.initialState locals 1..7. -/
def wotsChecksumLocalsTail : Array Value :=
  #[Value.u64 0,                   -- 1: csum
    Value.vecU8 ByteArray.empty,   -- 2: csum_bytes
    Value.u64 0,                   -- 3: i
    Value.u64 0,                   -- 4: j
    Value.u64 0,                   -- 5: k
    Value.u64 0,                   -- 6: len_bytes
    Value.u8 0]                    -- 7: shift

def msgToChainDigitsRealBytecode : Bytecode := #[
  -- B0
  .MoveLoc 0,                                                  -- 0
  .LdU64 32,                                                   -- 1
  .Call BaseWReal.baseWRealBytecode WotsChecksumReal.baseWLocalsTail 2,  -- 2
  .StLoc 2,                                                    -- 3  digits
  .ImmBorrowLoc 2,                                             -- 4
  .Call WotsChecksumReal.wotsChecksumRealBytecode wotsChecksumLocalsTail 1,  -- 5
  .StLoc 1,                                                    -- 6  csum_digits
  .LdU64 0,                                                    -- 7
  .StLoc 3,                                                    -- 8  i := 0
  -- B1 (append loop: i < 3)
  .CopyLoc 3,                                                  -- 9
  .LdU64 3,                                                    -- 10
  .Lt,                                                         -- 11
  .BrFalse 25,                                                 -- 12
  -- B2
  .Branch 14,                                                  -- 13
  -- B3: digits.push_back(csum_digits[i])
  .MutBorrowLoc 2,                                             -- 14
  .ImmBorrowLoc 1,                                             -- 15
  .CopyLoc 3,                                                  -- 16
  .VecU32ImmBorrow,                                            -- 17
  .ReadRef,                                                    -- 18
  .VecU32PushBack,                                             -- 19
  .MoveLoc 3,                                                  -- 20
  .LdU64 1,                                                    -- 21
  .Add,                                                        -- 22
  .StLoc 3,                                                    -- 23
  .Branch 9,                                                   -- 24
  -- B4
  .MoveLoc 2,                                                  -- 25
  .Ret                                                         -- 26
]

def initialState (msgN : ByteArray) : State :=
  { stack := #[]
    locals := #[Value.vecU8 msgN,           -- 0: msg_n
                Value.vecU32 #[],            -- 1: csum_digits
                Value.vecU32 #[],            -- 2: digits
                Value.u64 0],                -- 3: i
    pc := 0, error := none }

def msgToChainDigitsRealMoveBC (msgN : ByteArray) : Array UInt32 :=
  let final := runDefault msgToChainDigitsRealBytecode (initialState msgN)
  match final.stack.back? with
  | some (Value.vecU32 v) => v
  | _ => #[]

/-! ## Equivalence theorems -/

/-- Full 35-digit chain decomposition (32 base_w + 3 checksum). -/
example :
    let msg := Fips205.Bytes.hexDecode "112233445566778899aabbccddeeff00"
    (msgToChainDigitsRealMoveBC msg).map (·.toNat) = Fips205.Wots.msgToChainDigits msg := by
  native_decide

/-- All-zero msg_n. -/
example :
    (msgToChainDigitsRealMoveBC (Fips205.Bytes.zeros 16)).map (·.toNat) =
      Fips205.Wots.msgToChainDigits (Fips205.Bytes.zeros 16) := by
  native_decide

/-- All-0xff msg_n. -/
example :
    let msg := Fips205.Bytes.hexDecode "ffffffffffffffffffffffffffffffff"
    (msgToChainDigitsRealMoveBC msg).map (·.toNat) = Fips205.Wots.msgToChainDigits msg := by
  native_decide

/-- Size invariant: len = 35 digits. -/
example :
    (msgToChainDigitsRealMoveBC (Fips205.Bytes.zeros 16)).size = 35 := by
  native_decide

end Fips205.Move.MsgToChainDigitsReal
