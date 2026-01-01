import Move.Value
import Move.Stack
import Move.Opcode
import Move.Step
import Move.Native
import Move.Mgf1
import Fips205.Bytes
import Fips205.Thash

/-! # `hmsg` Move bytecode → Lean spec equivalence

Real Move source (FIPS-205 §10.2, randomized message hash):

```move
fun hmsg(
    r: &vector<u8>,
    pk_seed: &vector<u8>,
    pk_root: &vector<u8>,
    m: &vector<u8>,
    out_len: u64,
): vector<u8> {
    let inner = hash::sha2_256(concat4(r, pk_seed, pk_root, m));
    let seed = concat3(r, pk_seed, &inner);
    mgf1_sha256(&seed, out_len)
}
```

For SLH-DSA-SHA2-128s, `out_len = m_bytes = 30`, with `|r| = |pk_seed| = |pk_root| = n = 16`.
So `|inner| = 32`, `|seed| = 64`, `|output| = 30`.

This is the LAST spec call in `verifyViaBC_full` that isn't yet bytecode.
With it encoded, the entire FIPS-205 verifier flow reduces to Move VM
bytecode + verified native primitives (SHA-256 + int casts).

We inline the MGF1 loop structure here (rather than calling out to
`Mgf1.mgf1Bytecode`), because our VM model has no `Call` opcode for
cross-bytecode invocation. The MGF1 loop itself is independently
verified in `Move.Mgf1` against the same spec function.

## Locals
  0: r           (vector<u8>)
  1: pk_seed     (vector<u8>)
  2: pk_root     (vector<u8>)
  3: m           (vector<u8>)
  4: out_len     (u64)
  5: out         (vector<u8>)
  6: inner       (vector<u8>) — 32-byte SHA-256 of (r ++ pk_seed ++ pk_root ++ m)
  7: seed        (vector<u8>) — 64 bytes (r ++ pk_seed ++ inner)
  8: counter     (u64)         — MGF1 outer counter (kept as u64; truncated for ctr-bytes)
  9: ctr         (vector<u8>) — 4-byte BE counter buffer
  10: block      (vector<u8>) — 32-byte SHA-256 block
  11: j          (u64)         — inner copy counter
-/

namespace Fips205.Move.Hmsg

open Fips205.Move Fips205.Move.Value Fips205.Move.State Fips205

/-- Bytecode for hmsg: composes a 4-arg concat + SHA-256 (for `inner`),
    then 3-arg concat (for `seed`), then the inlined MGF1 loop. -/
def hmsgBytecode : Bytecode := Id.run do
  let mut code : Bytecode := #[]
  -- ── inner = sha256(r ++ pk_seed ++ pk_root ++ m) ──
  code := code.push (.CopyLoc 0)            -- r
  code := code.push (.CopyLoc 1)            -- pk_seed
  code := code.push .VecAppend              -- r ++ pk_seed
  code := code.push (.CopyLoc 2)            -- pk_root
  code := code.push .VecAppend              -- r ++ pk_seed ++ pk_root
  code := code.push (.CopyLoc 3)            -- m
  code := code.push .VecAppend              -- r ++ pk_seed ++ pk_root ++ m
  code := code.push (.CallNative "sha2_256" 1)
  code := code.push (.StLoc 6)
  -- ── seed = r ++ pk_seed ++ inner ──
  code := code.push (.CopyLoc 0)
  code := code.push (.CopyLoc 1)
  code := code.push .VecAppend
  code := code.push (.CopyLoc 6)
  code := code.push .VecAppend
  code := code.push (.StLoc 7)
  -- ── inlined MGF1(seed, out_len) ──
  -- out := vec[]
  code := code.push .VecEmpty
  code := code.push (.StLoc 5)
  -- counter := 0
  code := code.push (.LdU64 0)
  code := code.push (.StLoc 8)
  -- ── outer loop: while out.length() < out_len ──
  let outerTest := code.size
  code := code.push (.CopyLoc 5)
  code := code.push .VecLen
  code := code.push (.CopyLoc 4)
  code := code.push .Lt
  code := code.push (.BrFalse 0)            -- patched → exit
  let outerExitJump := code.size - 1
  -- ctr := vec[]; pack u32-BE(counter) into 4 bytes via repeated PushBack
  code := code.push .VecEmpty
  code := code.push (.StLoc 9)
  for shift in [24, 16, 8, 0] do
    code := code.push (.CopyLoc 9)          -- ctr
    code := code.push (.CopyLoc 8)          -- counter
    code := code.push (.LdU64 (UInt64.ofNat shift))
    code := code.push .Shr
    code := code.push (.LdU64 0xff)
    code := code.push .BitAnd
    code := code.push (.CallNative "u64_to_u8" 1)
    code := code.push .VecPushBack
    code := code.push (.StLoc 9)
  -- block := sha256(seed ++ ctr)
  code := code.push (.CopyLoc 7)
  code := code.push (.CopyLoc 9)
  code := code.push .VecAppend
  code := code.push (.CallNative "sha2_256" 1)
  code := code.push (.StLoc 10)
  -- j := 0
  code := code.push (.LdU64 0)
  code := code.push (.StLoc 11)
  -- ── inner loop: while j < 32 ∧ out.length() < out_len ──
  let innerTest := code.size
  code := code.push (.CopyLoc 11)
  code := code.push (.LdU64 32)
  code := code.push .Lt
  code := code.push (.BrFalse 0)            -- patched → afterInner
  let innerExitJumpJ := code.size - 1
  code := code.push (.CopyLoc 5)
  code := code.push .VecLen
  code := code.push (.CopyLoc 4)
  code := code.push .Lt
  code := code.push (.BrFalse 0)            -- patched → afterInner
  let innerExitJumpOut := code.size - 1
  -- out.push_back(block[j])
  code := code.push (.CopyLoc 5)
  code := code.push (.CopyLoc 10)
  code := code.push (.CopyLoc 11)
  code := code.push .VecImmBorrow
  code := code.push .VecPushBack
  code := code.push (.StLoc 5)
  -- j += 1
  code := code.push (.CopyLoc 11)
  code := code.push (.LdU64 1)
  code := code.push .Add
  code := code.push (.StLoc 11)
  code := code.push (.Branch innerTest)
  -- afterInner: counter += 1; branch back to outerTest
  let afterInner := code.size
  code := code.push (.CopyLoc 8)
  code := code.push (.LdU64 1)
  code := code.push .Add
  code := code.push (.StLoc 8)
  code := code.push (.Branch outerTest)
  -- ── exit ──
  let exitAddr := code.size
  code := code.push (.CopyLoc 5)
  code := code.push .Ret
  -- patch placeholders
  code := code.set! outerExitJump (.BrFalse exitAddr)
  code := code.set! innerExitJumpJ (.BrFalse afterInner)
  code := code.set! innerExitJumpOut (.BrFalse afterInner)
  return code

def initialState (r pk_seed pk_root m : ByteArray) (outLen : Nat) : State :=
  { stack := #[]
    locals := #[Value.vecU8 r,                       -- 0
                Value.vecU8 pk_seed,                  -- 1
                Value.vecU8 pk_root,                  -- 2
                Value.vecU8 m,                        -- 3
                Value.u64 (UInt64.ofNat outLen),      -- 4
                Value.vecU8 ByteArray.empty,          -- 5 out
                Value.vecU8 ByteArray.empty,          -- 6 inner
                Value.vecU8 ByteArray.empty,          -- 7 seed
                Value.u64 0,                          -- 8 counter
                Value.vecU8 ByteArray.empty,          -- 9 ctr
                Value.vecU8 ByteArray.empty,          -- 10 block
                Value.u64 0],                         -- 11 j
    pc := 0, error := none }

def hmsgMoveBC (r pk_seed pk_root m : ByteArray) : ByteArray :=
  let final := runDefault hmsgBytecode (initialState r pk_seed pk_root m Fips205.m_bytes)
  match final.stack.back? with
  | some (Value.vecU8 v) => v
  | _ => ByteArray.empty

/-! ## Equivalence theorems

Compare `hmsgMoveBC` against `Fips205.Thash.hmsg` on representative inputs.
Each case proves byte-for-byte equality via `native_decide`. -/

/-- All-zero 16-byte r / pk_seed / pk_root; empty message. -/
example :
    hmsgMoveBC (Fips205.Bytes.zeros 16) (Fips205.Bytes.zeros 16)
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
    hmsgMoveBC r pk_seed pk_root m = Fips205.Thash.hmsg r pk_seed pk_root m := by
  native_decide

/-- Longer message (forces multiple SHA-256 blocks in the inner hash). -/
example :
    let r       := Fips205.Bytes.zeros 16
    let pk_seed := Fips205.Bytes.zeros 16
    let pk_root := Fips205.Bytes.zeros 16
    let m       := Fips205.Bytes.hexDecode (String.ofList (List.replicate 200 'f'))
    hmsgMoveBC r pk_seed pk_root m = Fips205.Thash.hmsg r pk_seed pk_root m := by
  native_decide

/-- Size invariant: output is exactly `m_bytes = 30` bytes. -/
example :
    (hmsgMoveBC (Fips205.Bytes.zeros 16) (Fips205.Bytes.zeros 16)
                (Fips205.Bytes.zeros 16) ByteArray.empty).size = Fips205.m_bytes := by
  native_decide

end Fips205.Move.Hmsg
