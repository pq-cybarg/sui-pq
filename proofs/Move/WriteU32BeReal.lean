import Move.Value
import Move.Stack
import Move.Opcode
import Move.Step
import Move.AdrsSetters
import Fips205.Bytes

/-! # `write_u32_be` — real disassembled Move bytecode

Helper used by `adrs_set_keypair`, `adrs_set_tree_height`, and
`adrs_set_tree_index`. Writes a u32 in big-endian order at a given
byte offset inside a `vector<u8>`. From the disassembly: four-times
unrolled (`v >> 24`, `v >> 16`, `v >> 8`, `v`) each `& 0xff`,
`CastU8`, then `WriteRef` at `off+i`.

The `write_u32_be` body is void (Ret with empty stack); the
mutation is observed through the `&mut buf` arg. Tested here via a
direct wrapper; further used through the cross-frame `Call` semantics
when invoked from `adrs_set_keypair` and friends.
-/

namespace Fips205.Move.WriteU32BeReal

open Fips205.Move Fips205.Move.Value Fips205.Move.State Fips205

/-- Disassembly-accurate bytecode for `write_u32_be`. -/
def writeU32BeRealBytecode : Bytecode := #[
  -- byte 0 (highest) at off+0: (v >> 24) & 0xff
  .CopyLoc 2,                       -- 0
  .LdU8 24,                         -- 1
  .Shr,                             -- 2
  .LdU32 255,                       -- 3
  .BitAnd,                          -- 4
  .CastU8,                          -- 5
  .CopyLoc 0,                       -- 6
  .CopyLoc 1,                       -- 7
  .LdU64 0,                         -- 8
  .Add,                             -- 9
  .VecMutBorrow,                    -- 10
  .WriteRef,                        -- 11
  -- byte 1 at off+1: (v >> 16) & 0xff
  .CopyLoc 2,                       -- 12
  .LdU8 16,                         -- 13
  .Shr,                             -- 14
  .LdU32 255,                       -- 15
  .BitAnd,                          -- 16
  .CastU8,                          -- 17
  .CopyLoc 0,                       -- 18
  .CopyLoc 1,                       -- 19
  .LdU64 1,                         -- 20
  .Add,                             -- 21
  .VecMutBorrow,                    -- 22
  .WriteRef,                        -- 23
  -- byte 2 at off+2: (v >> 8) & 0xff
  .CopyLoc 2,                       -- 24
  .LdU8 8,                          -- 25
  .Shr,                             -- 26
  .LdU32 255,                       -- 27
  .BitAnd,                          -- 28
  .CastU8,                          -- 29
  .CopyLoc 0,                       -- 30
  .CopyLoc 1,                       -- 31
  .LdU64 2,                         -- 32
  .Add,                             -- 33
  .VecMutBorrow,                    -- 34
  .WriteRef,                        -- 35
  -- byte 3 (lowest) at off+3: v & 0xff
  .MoveLoc 2,                       -- 36
  .LdU32 255,                       -- 37
  .BitAnd,                          -- 38
  .CastU8,                          -- 39
  .MoveLoc 0,                       -- 40
  .MoveLoc 1,                       -- 41
  .LdU64 3,                         -- 42
  .Add,                             -- 43
  .VecMutBorrow,                    -- 44
  .WriteRef,                        -- 45
  .Ret                              -- 46
]

/-- Test wrapper: locals = [locRef 3, off, v, buf]. Bytecode mutates locals[3];
    we read out the modified buf. -/
def initialState (buf : ByteArray) (off : Nat) (v : UInt32) : State :=
  { stack := #[]
    locals := #[Value.locRef 3,
                Value.u64 (UInt64.ofNat off),
                Value.u32 v,
                Value.vecU8 buf],
    pc := 0, error := none }

def writeU32BeRealMoveBC (buf : ByteArray) (off : Nat) (v : UInt32) : ByteArray :=
  let final := runDefault writeU32BeRealBytecode (initialState buf off v)
  match final.locals[3]? with
  | some (Value.vecU8 r) => r
  | _ => ByteArray.empty

/-- The spec: replace buf[off..off+4] with the big-endian bytes of v. -/
def writeU32BeSpec (buf : ByteArray) (off : Nat) (v : UInt32) : ByteArray :=
  AdrsSetters.replaceMid buf (Fips205.Bytes.u32BE v.toNat) off (off + 4)

/-! ## Equivalence theorems -/

/-- v = 0: writes four zero bytes. -/
example : writeU32BeRealMoveBC (Fips205.Bytes.zeros 22) 10 0 =
            writeU32BeSpec (Fips205.Bytes.zeros 22) 10 0 := by
  native_decide

/-- v = 0xdeadbeef: writes [0xde, 0xad, 0xbe, 0xef]. -/
example : writeU32BeRealMoveBC (Fips205.Bytes.zeros 22) 10 0xdeadbeef =
            writeU32BeSpec (Fips205.Bytes.zeros 22) 10 0xdeadbeef := by
  native_decide

/-- v = 0x42: writes [0x00, 0x00, 0x00, 0x42]. -/
example : writeU32BeRealMoveBC (Fips205.Bytes.zeros 22) 10 0x42 =
            writeU32BeSpec (Fips205.Bytes.zeros 22) 10 0x42 := by
  native_decide

/-- Different offset (0). -/
example : writeU32BeRealMoveBC (Fips205.Bytes.zeros 22) 0 0x12345678 =
            writeU32BeSpec (Fips205.Bytes.zeros 22) 0 0x12345678 := by
  native_decide

/-- Pre-populated buffer: only the targeted 4 bytes change. -/
example :
    let buf := Fips205.Bytes.hexDecode "0102030405060708090a0b0c0d0e0f1011120000abcd"
    writeU32BeRealMoveBC buf 10 0xcafebabe =
      writeU32BeSpec buf 10 0xcafebabe := by
  native_decide

end Fips205.Move.WriteU32BeReal
