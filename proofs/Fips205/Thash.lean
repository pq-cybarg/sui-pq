import Fips205.Params
import Fips205.Bytes
import Fips205.Sha256
import Fips205.Adrs

/-! # Tweakable hash + H_msg (FIPS-205 §11.2)

For SHA-2 instantiation with `n = 16`:

    F = H = T_l = SHA-256(pk_seed ‖ toByte(0, 64-n) ‖ ADRS_c ‖ M)[0..n]

H_msg(R, PK.seed, PK.root, M) = MGF1-SHA-256(R ‖ PK.seed ‖ SHA-256(R ‖ PK.full ‖ M), m)
where `m = 30` for 128s.
-/

namespace Fips205.Thash

open Fips205 Fips205.Bytes Fips205.Sha256

/-- Truncate `b` to its first `n` bytes. -/
def truncate (b : ByteArray) (n : Nat) : ByteArray := Id.run do
  let mut out := ByteArray.empty
  let mut i : Nat := 0
  while i < n do
    out := out.push (b.get! i)
    i := i + 1
  return out

/-- thash(pk_seed, adrs_c, m) = SHA-256(pk_seed ‖ pad48 ‖ adrs_c ‖ m)[0..n]

The 48-byte zero pad is `toByte(0, 64-n)` for n=16 — the FIPS-205-required
SHA-256 block-aligned prefix. -/
def thash (pk_seed : ByteArray) (adrs : Fips205.Adrs.Adrs) (m : ByteArray) : ByteArray :=
  let input := pk_seed ++ zeros 48 ++ (Fips205.Adrs.compress adrs) ++ m
  truncate (sha256 input) Fips205.n

/-- MGF1-SHA-256 (PKCS#1 §B.2.1). Produces `outLen` bytes. -/
def mgf1 (seed : ByteArray) (outLen : Nat) : ByteArray := Id.run do
  let mut out := ByteArray.empty
  let mut counter : Nat := 0
  while out.size < outLen do
    let block := sha256 (seed ++ u32BE counter)
    let mut j : Nat := 0
    while j < block.size && out.size < outLen do
      out := out.push (block.get! j)
      j := j + 1
    counter := counter + 1
  return out

/-- H_msg(R, PK.seed, PK.root, M) → 30 bytes for 128s. -/
def hmsg (r pk_seed pk_root m : ByteArray) : ByteArray :=
  let inner := sha256 (r ++ pk_seed ++ pk_root ++ m)
  let seed := r ++ pk_seed ++ inner
  mgf1 seed Fips205.m_bytes

end Fips205.Thash
