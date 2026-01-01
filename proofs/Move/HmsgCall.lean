import Move.Value
import Move.Stack
import Move.Opcode
import Move.Step
import Move.Native
import Move.Mgf1
import Move.Hmsg
import Fips205.Bytes
import Fips205.Thash

/-! # `hmsg` via cross-bytecode `Call` opcode

This file demonstrates the `Call` opcode by re-encoding `hmsg` as a
true two-function composition: the bytecode here computes the SHA-256
inner hash and the seed concatenation, then literally `Call`s into
`Mgf1.mgf1Bytecode` as a subroutine (rather than inlining the MGF1
loop body).

The semantics match `Move/Hmsg.lean` exactly — proven via `native_decide`
on the same set of representative inputs. The Move VM `Call` opcode
allocates a fresh frame for the callee, runs it to `Ret`, and pushes
its top-of-stack result onto the caller's stack.

This is a sanity check of the VM's `Call` semantics (mutual recursion
between `step` and `run`) and of the principle that proven-bytecode
modules compose: `Mgf1` is proven on its own, and using it via `Call`
inside `Hmsg` does not require re-proving anything.

## Locals
  0: r           (vector<u8>)
  1: pk_seed     (vector<u8>)
  2: pk_root     (vector<u8>)
  3: m           (vector<u8>)
  4: out_len     (u64)
  5: out         (vector<u8>)
  6: inner       (vector<u8>)
  7: seed        (vector<u8>)
-/

namespace Fips205.Move.HmsgCall

open Fips205.Move Fips205.Move.Value Fips205.Move.State Fips205

/-- The non-arg portion of MGF1's initial locals (matches `Mgf1.initialState`,
    locals 2..6 — out, counter, ctr, block, j — initialized empty/zero). -/
def mgf1LocalsTail : Array Value :=
  #[Value.vecU8 ByteArray.empty,   -- 2: out
    Value.u64 0,                    -- 3: counter
    Value.vecU8 ByteArray.empty,    -- 4: ctr
    Value.vecU8 ByteArray.empty,    -- 5: block
    Value.u64 0]                    -- 6: j

/-- Bytecode for hmsg using cross-bytecode `Call`: computes inner + seed,
    then invokes the proven `Mgf1.mgf1Bytecode` as a subroutine. -/
def hmsgCallBytecode : Bytecode :=
  #[ -- ── inner = sha256(r ++ pk_seed ++ pk_root ++ m) ──
     .CopyLoc 0, .CopyLoc 1, .VecAppend,
     .CopyLoc 2, .VecAppend,
     .CopyLoc 3, .VecAppend,
     .CallNative "sha2_256" 1,
     .StLoc 6,
     -- ── seed = r ++ pk_seed ++ inner ──
     .CopyLoc 0, .CopyLoc 1, .VecAppend,
     .CopyLoc 6, .VecAppend,
     .StLoc 7,
     -- ── Call mgf1_sha256(seed, out_len) ──
     .CopyLoc 7,                   -- arg 0: seed
     .CopyLoc 4,                   -- arg 1: out_len
     .Call Mgf1.mgf1Bytecode mgf1LocalsTail 2,
     .StLoc 5,
     -- ── return out ──
     .CopyLoc 5, .Ret ]

def initialState (r pk_seed pk_root m : ByteArray) (outLen : Nat) : State :=
  { stack := #[]
    locals := #[Value.vecU8 r,                       -- 0
                Value.vecU8 pk_seed,                  -- 1
                Value.vecU8 pk_root,                  -- 2
                Value.vecU8 m,                        -- 3
                Value.u64 (UInt64.ofNat outLen),      -- 4
                Value.vecU8 ByteArray.empty,          -- 5 out
                Value.vecU8 ByteArray.empty,          -- 6 inner
                Value.vecU8 ByteArray.empty],         -- 7 seed
    pc := 0, error := none }

def hmsgCallMoveBC (r pk_seed pk_root m : ByteArray) : ByteArray :=
  let final := runDefault hmsgCallBytecode (initialState r pk_seed pk_root m Fips205.m_bytes)
  match final.stack.back? with
  | some (Value.vecU8 v) => v
  | _ => ByteArray.empty

/-! ## Equivalence theorems

The Call-based hmsg agrees with the spec `Fips205.Thash.hmsg` on
representative inputs, AND with the inlined `Hmsg.hmsgMoveBC`. -/

/-- All-zero inputs. -/
example :
    hmsgCallMoveBC (Fips205.Bytes.zeros 16) (Fips205.Bytes.zeros 16)
                   (Fips205.Bytes.zeros 16) ByteArray.empty =
      Fips205.Thash.hmsg (Fips205.Bytes.zeros 16) (Fips205.Bytes.zeros 16)
                          (Fips205.Bytes.zeros 16) ByteArray.empty := by
  native_decide

/-- Real-shaped 16-byte inputs and a short message. -/
example :
    let r       := Fips205.Bytes.hexDecode "0102030405060708090a0b0c0d0e0f10"
    let pk_seed := Fips205.Bytes.hexDecode "1112131415161718191a1b1c1d1e1f20"
    let pk_root := Fips205.Bytes.hexDecode "2122232425262728292a2b2c2d2e2f30"
    let m       := Fips205.Bytes.hexDecode "deadbeef"
    hmsgCallMoveBC r pk_seed pk_root m = Fips205.Thash.hmsg r pk_seed pk_root m := by
  native_decide

/-- Call-based hmsg agrees with the inlined `Hmsg.hmsgMoveBC` byte-for-byte. -/
example :
    let r       := Fips205.Bytes.hexDecode "0102030405060708090a0b0c0d0e0f10"
    let pk_seed := Fips205.Bytes.hexDecode "1112131415161718191a1b1c1d1e1f20"
    let pk_root := Fips205.Bytes.hexDecode "2122232425262728292a2b2c2d2e2f30"
    let m       := Fips205.Bytes.hexDecode "deadbeef"
    hmsgCallMoveBC r pk_seed pk_root m = Fips205.Move.Hmsg.hmsgMoveBC r pk_seed pk_root m := by
  native_decide

/-- Size invariant: output is exactly `m_bytes = 30` bytes (single MGF1 block). -/
example :
    (hmsgCallMoveBC (Fips205.Bytes.zeros 16) (Fips205.Bytes.zeros 16)
                    (Fips205.Bytes.zeros 16) ByteArray.empty).size = Fips205.m_bytes := by
  native_decide

end Fips205.Move.HmsgCall
