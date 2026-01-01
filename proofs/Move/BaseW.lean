import Move.Value
import Move.Stack
import Move.Opcode
import Move.Step
import Move.Native
import Fips205.Bytes
import Fips205.Wots

/-! # `base_w` Move bytecode → Lean spec equivalence

Real Move source:

```move
fun base_w(msg: &vector<u8>, outlen: u64): vector<u32> {
    let mut out = vector[];
    let mut in_idx: u64 = 0;
    let mut bits: u64 = 0;
    let mut total: u32 = 0;        // we use u64 internally for arithmetic uniformity
    let mut i: u64 = 0;
    while (i < outlen) {
        if (bits == 0) {
            total = (*msg.borrow(in_idx) as u32);
            in_idx = in_idx + 1;
            bits = 8;
        };
        bits = bits - LG_W;        // LG_W = 4
        out.push_back((total >> (bits as u8)) & 0xf);
        i = i + 1;
    };
    out
}
```

Used by WOTS+ to extract `outlen` base-16 digits (lg_w=4 bits each) from a
byte array. Called twice per WOTS+ verify: once on the message digest to
get `len_1=32` digits, once on the checksum bytes to get `len_2=3` digits.

## Locals
  0: msg      (vector<u8>)
  1: outlen   (u64)
  2: out      (vector<u32>)
  3: in_idx   (u64)
  4: bits     (u64)
  5: total    (u64)
  6: i        (u64)
-/

namespace Fips205.Move.BaseW

open Fips205.Move Fips205.Move.Value Fips205.Move.State Fips205

/-
  ── HISTORY: rejected first-attempt bytecode (DO NOT REVIVE) ──

  My first encoding of `base_w` was a flat array literal with hand-counted
  `pc` comments and hand-set `BrFalse 26` / `BrFalse 40` / `Branch 10`
  targets. Two problems showed up that make this pattern fundamentally
  hostile to encoding any non-trivial Move source:

    1. The Move source's `if (bits == 0) { refill } else { skip }` has
       NO explicit `else` jump — the if-tail just falls through. In
       bytecode that means the `BrFalse <skip-target>` has to point
       past the refill block, AND the refill block must NOT itself
       contain a Branch (otherwise the after-refill path is re-entered).
       Manually counting where the refill block ends is error-prone:
       I had the BrFalse target landing on the StLoc that was supposed
       to be the FIRST instruction AFTER the refill, mid-instruction.

    2. The `BrFalse <exit>` target for the outer loop was 40, but
       loop-body had grown past pc 40 after I added a few more ops, so
       the target landed in the middle of the body. Renumbering the
       hand-typed pc comments to fix this was tedious and bug-prone.

  Lesson: hand-counted bytecode offsets don't scale. Use the
  computed-label `Id.run do` pattern below: emit each instruction,
  record `code.size` for each branch target as you go, push placeholder
  `BrFalse 0` / `Branch 0` ops and patch them once the label PCs are
  known. The build either succeeds or `native_decide` falsifies your
  bytecode — no silent miscounting.

  (See `proofs/Move/SplitDigest.lean` for an earlier example where I
  hit the same BrFalse-landing-on-Branch-back bug; that file shows
  the literal-array pattern, kept there because the loops are simpler
  and rebuilding it now would obscure the diff history.)

  ── Original (broken) bytecode preserved verbatim for reference ──

  def baseWBytecode_BROKEN : Bytecode := #[
    -- out = vec<u32>[]
    .VecU32Empty,                  -- pc 0
    .StLoc 2,                      -- pc 1
    -- in_idx = 0
    .LdU64 0,                      -- pc 2
    .StLoc 3,                      -- pc 3
    -- bits = 0
    .LdU64 0,                      -- pc 4
    .StLoc 4,                      -- pc 5
    -- total = 0
    .LdU64 0,                      -- pc 6
    .StLoc 5,                      -- pc 7
    -- i = 0
    .LdU64 0,                      -- pc 8
    .StLoc 6,                      -- pc 9
    -- loop test (pc 10): i < outlen
    .CopyLoc 6,                    -- pc 10
    .CopyLoc 1,                    -- pc 11
    .Lt,                           -- pc 12
    .BrFalse 40,                   -- pc 13 → exit-and-push-out at pc 40
    -- if bits == 0 then refill
    .CopyLoc 4,                    -- pc 14: push bits
    .LdU64 0,                      -- pc 15
    .Eq,                           -- pc 16: bits == 0
    .BrFalse 26,                   -- pc 17: if false, skip refill (to pc 26)
    -- total = msg[in_idx] as u64
    .CopyLoc 0,                    -- pc 18
    .CopyLoc 3,                    -- pc 19
    .VecImmBorrow,                 -- pc 20 → u8
    .CallNative "u8_to_u64" 1,     -- pc 21
    .StLoc 5,                      -- pc 22
    -- in_idx += 1
    .CopyLoc 3,                    -- pc 23
    .LdU64 1,                      -- pc 24
    .Add,                          -- pc 25
    .StLoc 3,                      -- pc 26 — BUT this is the branch target;
                                   --         the refill block actually ends here
                                   --         and the BrFalse target lands mid-block.
    .LdU64 8,                      -- pc 27
    .StLoc 4,                      -- pc 28: bits = 8 (still inside refill)
    -- after refill (pc 29): bits -= lg_w = 4
    .CopyLoc 4,                    -- pc 29 (also reachable via BrFalse 29)
    .LdU64 4,                      -- pc 30
    .Sub,                          -- pc 31
    .StLoc 4,                      -- pc 32
    -- out.push_back((total >> bits) & 0xf)
    .CopyLoc 2,                    -- pc 33
    .CopyLoc 5,                    -- pc 34: total
    .CopyLoc 4,                    -- pc 35: bits
    .Shr,                          -- pc 36: total >> bits
    .LdU64 0xf,                    -- pc 37
    .BitAnd,                       -- pc 38
    .CallNative "u64_to_u32" 1,    -- pc 39
    .VecU32PushBack,               -- pc 40
    .StLoc 2,                      -- pc 41
    -- i += 1
    .CopyLoc 6,                    -- pc 42
    .LdU64 1,                      -- pc 43
    .Add,                          -- pc 44
    .StLoc 6,                      -- pc 45
    .Branch 10,                    -- pc 46
    -- exit (pc 47): push out, Ret
    .CopyLoc 2,                    -- pc 47
    .Ret                           -- pc 48
  ]
-/

/-- Bytecode assembled stepwise with computed labels, so PC offsets are
    correct by construction rather than hand-counted. -/
def baseWBytecode : Bytecode := Id.run do
  let mut code : Bytecode := #[]
  -- ── prologue: out := vec[], in_idx = 0, bits = 0, total = 0, i = 0 ──
  code := code.push .VecU32Empty
  code := code.push (.StLoc 2)
  code := code.push (.LdU64 0); code := code.push (.StLoc 3)
  code := code.push (.LdU64 0); code := code.push (.StLoc 4)
  code := code.push (.LdU64 0); code := code.push (.StLoc 5)
  code := code.push (.LdU64 0); code := code.push (.StLoc 6)
  -- loop test (label LOOP)
  let loopAddr := code.size  -- pc 10
  code := code.push (.CopyLoc 6)         -- i
  code := code.push (.CopyLoc 1)         -- outlen
  code := code.push .Lt
  -- placeholder; will patch BrFalse target after we know exitAddr
  code := code.push (.BrFalse 0)
  let brFalseExitPc := code.size - 1     -- the pc holding the BrFalse op
  -- if (bits == 0) then refill
  code := code.push (.CopyLoc 4)         -- bits
  code := code.push (.LdU64 0)
  code := code.push .Eq
  code := code.push (.BrFalse 0)          -- placeholder; will patch
  let brFalseRefillPc := code.size - 1
  -- refill: total = msg[in_idx] as u64; in_idx += 1; bits = 8
  code := code.push (.CopyLoc 0); code := code.push (.CopyLoc 3)
  code := code.push .VecImmBorrow
  code := code.push (.CallNative "u8_to_u64" 1)
  code := code.push (.StLoc 5)
  code := code.push (.CopyLoc 3); code := code.push (.LdU64 1); code := code.push .Add
  code := code.push (.StLoc 3)
  code := code.push (.LdU64 8); code := code.push (.StLoc 4)
  -- after-refill (label AFTER_REFILL = current pc)
  let afterRefillAddr := code.size
  -- bits -= 4
  code := code.push (.CopyLoc 4); code := code.push (.LdU64 4); code := code.push .Sub
  code := code.push (.StLoc 4)
  -- out.push_back((total >> bits) & 0xf)
  code := code.push (.CopyLoc 2)         -- out
  code := code.push (.CopyLoc 5); code := code.push (.CopyLoc 4); code := code.push .Shr
  code := code.push (.LdU64 0xf); code := code.push .BitAnd
  code := code.push (.CallNative "u64_to_u32" 1)
  code := code.push .VecU32PushBack
  code := code.push (.StLoc 2)
  -- i += 1
  code := code.push (.CopyLoc 6); code := code.push (.LdU64 1); code := code.push .Add
  code := code.push (.StLoc 6)
  code := code.push (.Branch loopAddr)
  -- exit (label EXIT)
  let exitAddr := code.size
  code := code.push (.CopyLoc 2)
  code := code.push .Ret
  -- Patch the placeholder targets:
  code := code.set! brFalseExitPc (.BrFalse exitAddr)
  code := code.set! brFalseRefillPc (.BrFalse afterRefillAddr)
  return code

def initialState (msg : ByteArray) (outlen : Nat) : State :=
  { stack := #[]
    locals := #[Value.vecU8 msg,
                Value.u64 (UInt64.ofNat outlen),
                Value.vecU32 #[],
                Value.u64 0,
                Value.u64 0,
                Value.u64 0,
                Value.u64 0],
    pc := 0, error := none }

def baseWMoveBC (msg : ByteArray) (outlen : Nat) : Array UInt32 :=
  let final := runDefault baseWBytecode (initialState msg outlen)
  match final.stack.back? with
  | some (Value.vecU8 _) => #[]          -- shouldn't happen
  | some (Value.vecU32 v) => v
  | _ => #[]

/-! ## Equivalence theorems

The bytecode result (`Array UInt32`) is compared via `.toNat` to the spec's
`Array Nat`. -/

example :
    (baseWMoveBC (Fips205.Bytes.hexDecode "ab") 2).map (·.toNat) =
      Fips205.Wots.baseW (Fips205.Bytes.hexDecode "ab") 2 := by
  native_decide

example :
    (baseWMoveBC (Fips205.Bytes.hexDecode "abcd") 4).map (·.toNat) =
      Fips205.Wots.baseW (Fips205.Bytes.hexDecode "abcd") 4 := by
  native_decide

example :
    (baseWMoveBC (Fips205.Bytes.zeros 16) 32).map (·.toNat) =
      Fips205.Wots.baseW (Fips205.Bytes.zeros 16) 32 := by
  native_decide

/-- A full WOTS+ msg_n (16 bytes) decoded to len_1=32 digits, matching the
    spec exactly. -/
example :
    let msg := Fips205.Bytes.hexDecode "112233445566778899aabbccddeeff00"
    (baseWMoveBC msg 32).map (·.toNat) = Fips205.Wots.baseW msg 32 := by
  native_decide

/-- All-0xff input yields all 0xf digits. -/
example :
    (baseWMoveBC (Fips205.Bytes.hexDecode "ffffffffffffffffffffffffffffffff") 32).map (·.toNat) =
      Array.replicate 32 0xf := by
  native_decide

/-- The size invariant holds. -/
example :
    (baseWMoveBC (Fips205.Bytes.zeros 16) 32).size = 32 := by
  native_decide

/-! ## Companion module: `wots_checksum`

`wots_checksum` is encoded in `Move/WotsChecksum.lean`. It:
  1. Sums `W - 1 - digits[i]` over LEN_1=32 digits (accumulator loop)
  2. Left-shifts the u64 sum by SHIFT=4
  3. Packs the result as a 2-byte BE buffer via `VecPushBack`
  4. Inlines the base-w decomposition for the 2-byte → 3-digit fixed shape

See that file for 6 `native_decide` examples including a composition
with `baseWMoveBC` (this file's verifier).
-/

end Fips205.Move.BaseW
