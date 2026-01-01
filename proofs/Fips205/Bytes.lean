/-! # Byte primitives.

Big-endian integer→bytes helpers. We keep these obvious — no clever endianness
tricks — so the spec/impl correspondence can be read at a glance.
-/

namespace Fips205.Bytes

/-- Big-endian encoding of a `Nat` into `len` bytes. Higher-order bytes first.
    If `n` exceeds `len` bytes the high bits are silently dropped — callers
    must keep `n < 256 ^ len`. -/
def natToBytesBE (n : Nat) (len : Nat) : ByteArray := Id.run do
  let mut out := ByteArray.empty
  let mut i : Nat := len
  while i > 0 do
    i := i - 1
    let shift : Nat := i * 8
    let b : UInt8 := UInt8.ofNat ((n >>> shift) &&& 0xff)
    out := out.push b
  return out

/-- 4-byte big-endian encoding. -/
def u32BE (n : Nat) : ByteArray := natToBytesBE n 4

/-- 8-byte big-endian encoding. -/
def u64BE (n : Nat) : ByteArray := natToBytesBE n 8

/-- Slice `b[start .. start + len]` as a fresh `ByteArray`. -/
def slice (b : ByteArray) (start len : Nat) : ByteArray := Id.run do
  let mut out := ByteArray.empty
  let mut i : Nat := 0
  while i < len do
    out := out.push (b.get! (start + i))
    i := i + 1
  return out

/-- Concatenation. Trivial; named for readability. -/
def concat (a b : ByteArray) : ByteArray := a ++ b

/-- `len` zero bytes. -/
def zeros (len : Nat) : ByteArray := Id.run do
  let mut out := ByteArray.empty
  let mut i : Nat := 0
  while i < len do
    out := out.push 0
    i := i + 1
  return out

/-- Decode one hex digit (panics on invalid input). -/
@[inline] def hexNibble (c : Char) : Nat :=
  if c.toNat ≥ 0x30 ∧ c.toNat ≤ 0x39 then c.toNat - 0x30
  else if c.toNat ≥ 0x61 ∧ c.toNat ≤ 0x66 then c.toNat - 0x61 + 10
  else if c.toNat ≥ 0x41 ∧ c.toNat ≤ 0x46 then c.toNat - 0x41 + 10
  else 0

/-- Decode a lowercase-or-uppercase hex string to a `ByteArray`. Even-length only.
    Used to embed multi-kilobyte KAT vectors without blowing Lean's literal-parser
    recursion limit. -/
def hexDecode (s : String) : ByteArray := Id.run do
  let chars := s.toList
  let mut out := ByteArray.empty
  let mut iter := chars
  while !iter.isEmpty do
    match iter with
    | h :: l :: rest =>
      out := out.push (UInt8.ofNat (hexNibble h * 16 + hexNibble l))
      iter := rest
    | _ => iter := []
  return out

example : u32BE 0x000000c8 = ByteArray.mk #[0, 0, 0, 0xc8] := by native_decide
example : u32BE 0x12345678 = ByteArray.mk #[0x12, 0x34, 0x56, 0x78] := by native_decide
example : (zeros 5).size = 5 := by native_decide

end Fips205.Bytes
