/-! # SHA-256 (pure Lean, bit-precise, FIPS 180-4)

We deliberately don't pull this in from an external library: the whole point of
this verification project is to have the spec under our control. ~150 LOC of Lean
is the SHA-256 reference. The FIPS-205 verifier is layered on top of it.

KAT tests at the bottom catch any transcription error against the published spec.
-/

namespace Fips205.Sha256

-- ── round constants K[0..63] (cube roots of first 64 primes, fractional × 2^32) ─
def K : Array UInt32 := #[
  0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
  0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
  0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
  0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
  0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
  0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
  0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
  0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
]

-- ── initial hash value H0 (square roots of first 8 primes, fractional × 2^32) ─
def H0 : Array UInt32 := #[
  0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
  0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
]

-- ── round mixing functions (FIPS 180-4 §4.1.2) ──
@[inline] def rotr (x : UInt32) (n : UInt32) : UInt32 :=
  (x >>> n) ||| (x <<< (32 - n))

@[inline] def ch (x y z : UInt32) : UInt32 := (x &&& y) ^^^ ((~~~ x) &&& z)
@[inline] def maj (x y z : UInt32) : UInt32 := (x &&& y) ^^^ (x &&& z) ^^^ (y &&& z)
-- `Σ` is reserved Lean syntax. Use FIPS names BSig0/BSig1 ("big sigma") and SSig0/SSig1 ("small sigma").
@[inline] def BSig0 (x : UInt32) : UInt32 := rotr x 2 ^^^ rotr x 13 ^^^ rotr x 22
@[inline] def BSig1 (x : UInt32) : UInt32 := rotr x 6 ^^^ rotr x 11 ^^^ rotr x 25
@[inline] def SSig0 (x : UInt32) : UInt32 := rotr x 7 ^^^ rotr x 18 ^^^ (x >>> 3)
@[inline] def SSig1 (x : UInt32) : UInt32 := rotr x 17 ^^^ rotr x 19 ^^^ (x >>> 10)

-- ── padding (FIPS 180-4 §5.1.1) ──
def pad (msg : ByteArray) : ByteArray := Id.run do
  let bitLen : Nat := msg.size * 8
  let mut out := msg
  out := out.push 0x80
  -- zero-pad until size mod 64 = 56
  while (out.size % 64) ≠ 56 do
    out := out.push 0x00
  -- 8-byte BE length-in-bits
  let mut i : Nat := 8
  while i > 0 do
    i := i - 1
    let shift : Nat := i * 8
    out := out.push (UInt8.ofNat ((bitLen >>> shift) &&& 0xff))
  return out

/-- Read a 32-bit big-endian word from `b` starting at byte `off`. -/
def readU32BE (b : ByteArray) (off : Nat) : UInt32 :=
  (b.get! off).toUInt32  <<< 24
  ||| (b.get! (off+1)).toUInt32 <<< 16
  ||| (b.get! (off+2)).toUInt32 <<< 8
  ||| (b.get! (off+3)).toUInt32

/-- Extract the four big-endian bytes of `w`. -/
@[inline] def u32ToBE (w : UInt32) : UInt8 × UInt8 × UInt8 × UInt8 :=
  ( UInt8.ofNat ((w >>> 24).toNat &&& 0xff),
    UInt8.ofNat ((w >>> 16).toNat &&& 0xff),
    UInt8.ofNat ((w >>> 8).toNat &&& 0xff),
    UInt8.ofNat (w.toNat &&& 0xff) )

/-- Process one 512-bit block: message schedule + 64-round compression. -/
def processBlock (h : Array UInt32) (b : ByteArray) (off : Nat) : Array UInt32 := Id.run do
  let mut W : Array UInt32 := Array.replicate 64 0
  -- W[0..16] from message
  for t in [0:16] do
    W := W.set! t (readU32BE b (off + t * 4))
  -- W[16..64] from recurrence
  for t in [16:64] do
    let wm2  : UInt32 := W[t - 2]!
    let wm7  : UInt32 := W[t - 7]!
    let wm15 : UInt32 := W[t - 15]!
    let wm16 : UInt32 := W[t - 16]!
    W := W.set! t (SSig1 wm2 + wm7 + SSig0 wm15 + wm16)
  -- working vars
  let mut a := h[0]!
  let mut bv := h[1]!
  let mut c := h[2]!
  let mut dv := h[3]!
  let mut e := h[4]!
  let mut f := h[5]!
  let mut g := h[6]!
  let mut hv := h[7]!
  for t in [0:64] do
    let T1 := hv + BSig1 e + ch e f g + K[t]! + W[t]!
    let T2 := BSig0 a + maj a bv c
    hv := g
    g := f
    f := e
    e := dv + T1
    dv := c
    c := bv
    bv := a
    a := T1 + T2
  return #[h[0]! + a, h[1]! + bv, h[2]! + c, h[3]! + dv,
           h[4]! + e, h[5]! + f, h[6]! + g, h[7]! + hv]

-- ── top-level hash ──
def sha256 (msg : ByteArray) : ByteArray := Id.run do
  let padded := pad msg
  let mut h := H0
  let mut off : Nat := 0
  while off < padded.size do
    h := processBlock h padded off
    off := off + 64
  -- serialise 8 × u32 BE → 32 bytes
  let mut out := ByteArray.empty
  for i in [0:8] do
    let (b0, b1, b2, b3) := u32ToBE h[i]!
    out := (((out.push b0).push b1).push b2).push b3
  return out

-- ── KAT tests catch any transcription error in K, H0, or the round loop ──
/-- SHA-256("") = e3b0c442… -/
example :
    sha256 ByteArray.empty =
    ByteArray.mk #[0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14,
                   0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f, 0xb9, 0x24,
                   0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c,
                   0xa4, 0x95, 0x99, 0x1b, 0x78, 0x52, 0xb8, 0x55] := by
  native_decide

/-- SHA-256("abc") = ba7816bf… -/
example :
    sha256 (ByteArray.mk #[0x61, 0x62, 0x63]) =
    ByteArray.mk #[0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea,
                   0x41, 0x41, 0x40, 0xde, 0x5d, 0xae, 0x22, 0x23,
                   0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c,
                   0xb4, 0x10, 0xff, 0x61, 0xf2, 0x00, 0x15, 0xad] := by
  native_decide

end Fips205.Sha256
