import Move.Value
import Move.Stack
import Move.Opcode
import Move.Step
import Move.AdrsSetters
import Fips205.Bytes

/-! # `write_u64_be` + `adrs_set_tree` — real disassembled Move bytecode

```
write_u64_be(buf: &mut vector<u8>, off: u64, v: u64) {
  L3: i: u64       // countdown (8 → 0)
  L4: n: u64       // shifted value
B0:
  0: MoveLoc[2] v ; 1: StLoc[4] n       // n := v
  2: LdU64(8) ; 3: StLoc[3] i           // i := 8
B1: loop test (i > 0)
  4: CopyLoc[3] i ; 5: LdU64(0) ; 6: Gt ; 7: BrFalse(28)
B2 (Branch into B3):
  8: Branch(9)
B3: body
  9: MoveLoc[3] i ; 10: LdU64(1) ; 11: Sub ; 12: StLoc[3] i   // i := i - 1
  13: CopyLoc[4] n ; 14: LdU64(255) ; 15: BitAnd ; 16: CastU8
  17: CopyLoc[0] buf ; 18: CopyLoc[1] off ; 19: CopyLoc[3] i ; 20: Add
  21: VecMutBorrow ; 22: WriteRef                         // buf[off+i] := …
  23: MoveLoc[4] n ; 24: LdU8(8) ; 25: Shr ; 26: StLoc[4] n
  27: Branch(4)
B4 epilogue:
  28: MoveLoc[0] buf ; 29: Pop ; 30: Ret
}

adrs_set_tree(a: &mut vector<u8>, tree: u64) {
  0: MoveLoc[0] a
  1: LdU64(1)
  2: MoveLoc[1] tree
  3: Call write_u64_be
  4: Ret
}
```

Exercises the count-down `Gt` loop and 8-byte BE pack pattern — the
shape every Move u64 BE write uses.
-/

namespace Fips205.Move.WriteU64BeReal

open Fips205.Move Fips205.Move.Value Fips205.Move.State Fips205

/-- Disassembly-accurate bytecode for `write_u64_be`. -/
def writeU64BeRealBytecode : Bytecode := #[
  -- B0
  .MoveLoc 2,                       -- 0
  .StLoc 4,                         -- 1
  .LdU64 8,                         -- 2
  .StLoc 3,                         -- 3
  -- B1 (loop test)
  .CopyLoc 3,                       -- 4
  .LdU64 0,                         -- 5
  .Gt,                              -- 6
  .BrFalse 28,                      -- 7
  -- B2 (compiler-emitted Branch)
  .Branch 9,                        -- 8
  -- B3 (body)
  .MoveLoc 3,                       -- 9   i
  .LdU64 1,                         -- 10
  .Sub,                             -- 11  i - 1
  .StLoc 3,                         -- 12  i := i - 1
  .CopyLoc 4,                       -- 13  n
  .LdU64 255,                       -- 14
  .BitAnd,                          -- 15  n & 0xff
  .CastU8,                          -- 16
  .CopyLoc 0,                       -- 17  buf
  .CopyLoc 1,                       -- 18  off
  .CopyLoc 3,                       -- 19  i
  .Add,                             -- 20  off + i
  .VecMutBorrow,                    -- 21
  .WriteRef,                        -- 22  buf[off+i] := byte
  .MoveLoc 4,                       -- 23  n
  .LdU8 8,                          -- 24
  .Shr,                             -- 25  n >> 8
  .StLoc 4,                         -- 26
  .Branch 4,                        -- 27
  -- B4
  .MoveLoc 0,                       -- 28
  .Pop,                             -- 29
  .Ret                              -- 30
]

/-- write_u64_be has 2 declared non-arg locals (i, n). When invoked via Call
    these go after the 3 args, before the cross-frame backing slot. -/
def writeU64BeLocalsTail : Array Value :=
  #[Value.u64 0, Value.u64 0]     -- 3: i, 4: n

/-- Standalone test wrapper for write_u64_be: locals 0..4 + backing storage. -/
def writeU64BeInitState (buf : ByteArray) (off : Nat) (v : UInt64) : State :=
  { stack := #[]
    locals := #[Value.locRef 5,            -- 0: buf (ref)
                Value.u64 (UInt64.ofNat off),  -- 1: off
                Value.u64 v,                -- 2: v
                Value.u64 0,                -- 3: i
                Value.u64 0,                -- 4: n
                Value.vecU8 buf],           -- 5: backing storage
    pc := 0, error := none }

def writeU64BeRealMoveBC (buf : ByteArray) (off : Nat) (v : UInt64) : ByteArray :=
  let final := runDefault writeU64BeRealBytecode (writeU64BeInitState buf off v)
  match final.locals[5]? with
  | some (Value.vecU8 r) => r
  | _ => ByteArray.empty

def writeU64BeSpec (buf : ByteArray) (off : Nat) (v : UInt64) : ByteArray :=
  AdrsSetters.replaceMid buf (Fips205.Bytes.u64BE v.toNat) off (off + 8)

/-- `adrs_set_tree(a, tree)` writes u64BE(tree) at offset 1. -/
def adrsSetTreeRealBytecode : Bytecode := #[
  .MoveLoc 0,                                                  -- 0
  .LdU64 1,                                                    -- 1
  .MoveLoc 1,                                                  -- 2
  .Call writeU64BeRealBytecode writeU64BeLocalsTail 3,         -- 3
  .Ret                                                         -- 4
]

def adrsSetTreeInitState (a : ByteArray) (tree : UInt64) : State :=
  { stack := #[]
    locals := #[Value.locRef 2,
                Value.u64 tree,
                Value.vecU8 a],
    pc := 0, error := none }

def adrsSetTreeRealMoveBC (a : ByteArray) (tree : UInt64) : ByteArray :=
  let final := runDefault adrsSetTreeRealBytecode (adrsSetTreeInitState a tree)
  match final.locals[2]? with
  | some (Value.vecU8 v) => v
  | _ => ByteArray.empty

/-! ## Equivalence theorems -/

example : writeU64BeRealMoveBC (Fips205.Bytes.zeros 22) 1 0 =
            writeU64BeSpec (Fips205.Bytes.zeros 22) 1 0 := by
  native_decide

example : writeU64BeRealMoveBC (Fips205.Bytes.zeros 22) 1 0x0123456789abcdef =
            writeU64BeSpec (Fips205.Bytes.zeros 22) 1 0x0123456789abcdef := by
  native_decide

example : writeU64BeRealMoveBC (Fips205.Bytes.zeros 22) 1 0xff =
            writeU64BeSpec (Fips205.Bytes.zeros 22) 1 0xff := by
  native_decide

/-- adrs_set_tree via real bytecode matches the spec. -/
example : adrsSetTreeRealMoveBC (Fips205.Bytes.zeros 22) 0 =
            AdrsSetters.adrsSetTreeSpec (Fips205.Bytes.zeros 22) 0 := by
  native_decide

example : adrsSetTreeRealMoveBC (Fips205.Bytes.zeros 22) 0xcafebabedeadbeef =
            AdrsSetters.adrsSetTreeSpec (Fips205.Bytes.zeros 22) 0xcafebabedeadbeef := by
  native_decide

example :
    let a := Fips205.Bytes.hexDecode "ff112233445566778899aabbccddeeff00112233aabb"
    adrsSetTreeRealMoveBC a 0x123456789 =
      AdrsSetters.adrsSetTreeSpec a 0x123456789 := by
  native_decide

/-- The real-bytecode adrs_set_tree matches our structural encoding. -/
example : adrsSetTreeRealMoveBC (Fips205.Bytes.zeros 22) 42 =
            AdrsSetters.adrsSetTreeMoveBC (Fips205.Bytes.zeros 22) 42 := by
  native_decide

end Fips205.Move.WriteU64BeReal
