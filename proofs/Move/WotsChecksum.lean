import Move.Value
import Move.Stack
import Move.Opcode
import Move.Step
import Move.Native
import Move.BaseW
import Fips205.Bytes
import Fips205.Wots

/-! # `wots_checksum` Move bytecode → Lean spec equivalence

Real Move source (FIPS-205 §5.1, base-w decomposition of the WOTS+ checksum):

```move
fun wots_checksum(msg_digits: &vector<u32>): vector<u32> {
    let mut csum: u64 = 0;
    let mut i: u64 = 0;
    while (i < LEN_1) {                                  // LEN_1 = 32
        csum = csum + (W - 1 - (*msg_digits.borrow(i) as u64));
        i = i + 1;
    };
    csum = csum << SHIFT;                                // SHIFT = 4
    let mut buf = vector[];
    buf.push_back(((csum >> 8) & 0xff) as u8);           // high byte
    buf.push_back((csum & 0xff) as u8);                  // low byte
    base_w(&buf, LEN_2)                                  // LEN_2 = 3
}
```

For SLH-DSA-SHA2-128s: `len_1 = 32`, `len_2 = 3`, `lg_w = 4`, `w = 16`.
The shift `(8 - (len_2 * lg_w) % 8) % 8 = (8 - 12 % 8) % 8 = (8 - 4) % 8 = 4`.
The byte length `(len_2 * lg_w + 7) / 8 = (12 + 7) / 8 = 2`.

This file composes the `baseWBytecode` from `Move.BaseW` — we invoke it as a
function call by inlining its bytecode (since our VM model doesn't have a
cross-bytecode `Call` opcode yet, we splice the loop in directly via a
helper) — or alternatively we just compute base_w on the 2-byte buffer
inline, which is exactly 3 nibble extractions on 2 bytes. The latter is
simpler and avoids modelling cross-function calls.

## Locals
  0: msg_digits  (vector<u32>)  — input, 32 u32 digits
  1: out         (vector<u32>)  — return value, 3 u32 digits
  2: csum        (u64)
  3: i           (u64)          — accumulator-loop counter, then base-w outlen
  4: hi          (u8)           — high byte of csum
  5: lo          (u8)           — low byte of csum
  6: buf         (vector<u8>)   — the 2-byte BE buffer
-/

namespace Fips205.Move.WotsChecksum

open Fips205.Move Fips205.Move.Value Fips205.Move.State Fips205

/-- Bytecode for the WOTS+ checksum: accumulates `csum = Σ (15 - msg_digits[i])`
    over `len_1=32` digits, shifts left by 4, packs into a 2-byte BE buffer,
    then base-w decodes to 3 nibbles using inline nibble-extraction.

    We INLINE base_w(buf, 3) rather than calling out, because (a) our VM
    has no Call opcode for cross-bytecode invocation yet, and (b) for the
    fixed shape 2-byte input → 3 nibbles the inline form is 3 ops per
    nibble. The full general base_w bytecode is separately verified in
    `Move.BaseW`. -/
def wotsChecksumBytecode : Bytecode := Id.run do
  let mut code : Bytecode := #[]
  -- ── csum := 0, i := 0 ──
  code := code.push (.LdU64 0); code := code.push (.StLoc 2)
  code := code.push (.LdU64 0); code := code.push (.StLoc 3)
  -- ── accumulator loop: while i < 32, csum += (15 - msg_digits[i]) ──
  let accLoop := code.size
  code := code.push (.CopyLoc 3)
  code := code.push (.LdU64 32)
  code := code.push .Lt
  code := code.push (.BrFalse 0)          -- patched → afterAcc
  let brExitAcc := code.size - 1
  -- csum := csum + (15 - (msg_digits[i] as u64))
  code := code.push (.CopyLoc 2)          -- csum
  code := code.push (.LdU64 15)           -- (w - 1)
  code := code.push (.CopyLoc 0)          -- msg_digits
  code := code.push (.CopyLoc 3)          -- i
  code := code.push .VecU32ImmBorrow      -- msg_digits[i] : u32
  code := code.push (.CallNative "u32_to_u64" 1)
  code := code.push .Sub                  -- 15 - digit
  code := code.push .Add                  -- csum + (15 - digit)
  code := code.push (.StLoc 2)
  -- i := i + 1
  code := code.push (.CopyLoc 3)
  code := code.push (.LdU64 1)
  code := code.push .Add
  code := code.push (.StLoc 3)
  code := code.push (.Branch accLoop)
  -- afterAcc: csum <<= 4
  let afterAcc := code.size
  code := code.push (.CopyLoc 2)
  code := code.push (.LdU64 4)
  code := code.push .Shl
  code := code.push (.StLoc 2)
  -- ── pack csum into 2 BE bytes via hi/lo locals ──
  -- hi := ((csum >> 8) & 0xff) as u8
  code := code.push (.CopyLoc 2)
  code := code.push (.LdU64 8)
  code := code.push .Shr
  code := code.push (.LdU64 0xff)
  code := code.push .BitAnd
  code := code.push (.CallNative "u64_to_u8" 1)
  code := code.push (.StLoc 4)
  -- lo := (csum & 0xff) as u8
  code := code.push (.CopyLoc 2)
  code := code.push (.LdU64 0xff)
  code := code.push .BitAnd
  code := code.push (.CallNative "u64_to_u8" 1)
  code := code.push (.StLoc 5)
  -- buf := vec[hi, lo]
  code := code.push .VecEmpty
  code := code.push (.CopyLoc 4)
  code := code.push .VecPushBack
  code := code.push (.CopyLoc 5)
  code := code.push .VecPushBack
  code := code.push (.StLoc 6)
  -- ── inline base_w(buf, 3) → out: 3 nibbles, big-endian within each byte ──
  -- digit[0] = (hi >> 4) & 0xf
  -- digit[1] = hi & 0xf
  -- digit[2] = (lo >> 4) & 0xf
  -- out := vec<u32>[]
  code := code.push .VecU32Empty
  code := code.push (.StLoc 1)
  -- out.push_back((hi >> 4) & 0xf as u32)
  code := code.push (.CopyLoc 1)
  code := code.push (.CopyLoc 4)              -- hi : u8
  code := code.push (.CallNative "u8_to_u64" 1)
  code := code.push (.LdU64 4)
  code := code.push .Shr
  code := code.push (.LdU64 0xf)
  code := code.push .BitAnd
  code := code.push (.CallNative "u64_to_u32" 1)
  code := code.push .VecU32PushBack
  code := code.push (.StLoc 1)
  -- out.push_back(hi & 0xf as u32)
  code := code.push (.CopyLoc 1)
  code := code.push (.CopyLoc 4)              -- hi
  code := code.push (.CallNative "u8_to_u64" 1)
  code := code.push (.LdU64 0xf)
  code := code.push .BitAnd
  code := code.push (.CallNative "u64_to_u32" 1)
  code := code.push .VecU32PushBack
  code := code.push (.StLoc 1)
  -- out.push_back((lo >> 4) & 0xf as u32)
  code := code.push (.CopyLoc 1)
  code := code.push (.CopyLoc 5)              -- lo
  code := code.push (.CallNative "u8_to_u64" 1)
  code := code.push (.LdU64 4)
  code := code.push .Shr
  code := code.push (.LdU64 0xf)
  code := code.push .BitAnd
  code := code.push (.CallNative "u64_to_u32" 1)
  code := code.push .VecU32PushBack
  code := code.push (.StLoc 1)
  -- return out
  code := code.push (.CopyLoc 1)
  code := code.push .Ret
  -- patch BrFalse
  code := code.set! brExitAcc (.BrFalse afterAcc)
  return code

def initialState (msgDigits : Array UInt32) : State :=
  { stack := #[]
    locals := #[Value.vecU32 msgDigits,        -- 0
                Value.vecU32 #[],               -- 1: out
                Value.u64 0,                    -- 2: csum
                Value.u64 0,                    -- 3: i
                Value.u8 0,                     -- 4: hi
                Value.u8 0,                     -- 5: lo
                Value.vecU8 ByteArray.empty],   -- 6: buf
    pc := 0, error := none }

def wotsChecksumMoveBC (msgDigits : Array UInt32) : Array UInt32 :=
  let final := runDefault wotsChecksumBytecode (initialState msgDigits)
  match final.stack.back? with
  | some (Value.vecU32 v) => v
  | _ => #[]

/-! ## Equivalence theorems

Compare bytecode result against `Fips205.Wots.wotsChecksum` (which takes
`Array Nat`); convert via `(·.toNat)`. -/

/-- All-zero digits: csum = 32 * 15 = 480 = 0x1e0; shifted = 0x1e00.
    Bytes = [0x1e, 0x00]. Nibbles = [1, 14, 0]. -/
example :
    (wotsChecksumMoveBC (Array.replicate 32 (0 : UInt32))).map (·.toNat) =
      Fips205.Wots.wotsChecksum (Array.replicate 32 0) := by
  native_decide

/-- All-0xf digits: csum = 0; shifted = 0; nibbles = [0, 0, 0]. -/
example :
    (wotsChecksumMoveBC (Array.replicate 32 (0xf : UInt32))).map (·.toNat) =
      Fips205.Wots.wotsChecksum (Array.replicate 32 0xf) := by
  native_decide

/-- A real-shaped digit array from base_w of a 16-byte msg. -/
example :
    let msg := Fips205.Bytes.hexDecode "112233445566778899aabbccddeeff00"
    let digits := Fips205.Wots.baseW msg 32
    let digitsU32 : Array UInt32 := digits.map (fun n => UInt32.ofNat n)
    (wotsChecksumMoveBC digitsU32).map (·.toNat) =
      Fips205.Wots.wotsChecksum digits := by
  native_decide

/-- All-1 digits: csum = 32 * 14 = 448 = 0x1c0; shifted = 0x1c00.
    Bytes = [0x1c, 0x00]. Nibbles = [1, 12, 0]. -/
example :
    (wotsChecksumMoveBC (Array.replicate 32 (1 : UInt32))).map (·.toNat) =
      Fips205.Wots.wotsChecksum (Array.replicate 32 1) := by
  native_decide

/-- Composition with base_w: feed full WOTS+ msg → digits → checksum, matching
    the way `Fips205.Wots.msgToChainDigits` is structured. -/
example :
    let msg := Fips205.Bytes.zeros 16
    let digits := Fips205.Move.BaseW.baseWMoveBC msg 32
    (wotsChecksumMoveBC digits).map (·.toNat) =
      Fips205.Wots.wotsChecksum (Fips205.Wots.baseW msg 32) := by
  native_decide

/-- Size invariant: always emits exactly 3 u32 digits. -/
example :
    (wotsChecksumMoveBC (Array.replicate 32 (0 : UInt32))).size = 3 := by
  native_decide

end Fips205.Move.WotsChecksum
