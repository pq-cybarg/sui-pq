import Fips205.Params
import Fips205.Bytes
import Fips205.Adrs
import Fips205.Thash

/-! # WOTS+ verify path (FIPS-205 §5)

`wotsPkFromSig(sig, msg, pk_seed, adrs)` reconstructs the WOTS+ public key from
a signature + message. Used as the leaf computation of an XMSS tree.

Layout per leaf: `len = 35` chains, each `n = 16` bytes. Each chain takes a
WOTS+ secret-share (16 bytes from `sig`) and applies the F-iteration `w-1-digit`
times to compute the public key share.

This file is byte-for-byte spec-faithful and matches our Move/TS implementations.
-/

namespace Fips205.Wots

open Fips205 Fips205.Bytes Fips205.Adrs Fips205.Thash

/-- Decode `msg` into `outlen` base-`w` digits, big-endian within each byte.
    For lg_w = 4 this is "extract nibbles, high nibble first". -/
def baseW (msg : ByteArray) (outlen : Nat) : Array Nat := Id.run do
  let mut out : Array Nat := Array.empty
  let mut inIdx : Nat := 0
  let mut bits : Nat := 0
  let mut total : Nat := 0
  for _ in [0:outlen] do
    if bits = 0 then
      total := (msg.get! inIdx).toNat
      inIdx := inIdx + 1
      bits := 8
    bits := bits - lg_w
    out := out.push ((total >>> bits) &&& (w - 1))
  return out

/-- Append the `len_2`-digit checksum to the WOTS+ message digits (FIPS-205 §5.1).

  csum = ∑ (w - 1 - msg_digit_i) for i in 0..len_1
  csum <<= (8 - (len_2 * lg_w) % 8) % 8
  encode csum as ceil(len_2*lg_w/8) BE bytes, then base-w decode to len_2 digits.
-/
def wotsChecksum (msgDigits : Array Nat) : Array Nat :=
  let csum0 : Nat := (List.range len_1).foldl
    (fun acc i => acc + (w - 1 - msgDigits[i]!)) 0
  let shift : Nat := (8 - (len_2 * lg_w) % 8) % 8
  let csum := csum0 <<< shift
  let lenBytes : Nat := (len_2 * lg_w + 7) / 8
  baseW (Bytes.natToBytesBE csum lenBytes) len_2

/-- Full base-w decomposition (msg digits ++ checksum) for one WOTS+ instance. -/
def msgToChainDigits (msg_n : ByteArray) : Array Nat :=
  baseW msg_n len_1 ++ wotsChecksum (baseW msg_n len_1)

/-- WOTS+ chain step (FIPS-205 §5.1). Iterates `F = thash(pk_seed, adrs, ·)`
    `steps` times starting from `x`, updating the hash_address each iter. -/
def chain (x : ByteArray) (iStart steps : Nat) (pk_seed : ByteArray) (adrs : Adrs) : ByteArray := Id.run do
  let mut tmp := x
  let mut a := adrs
  for j in [iStart:iStart + steps] do
    a := setTreeIndex a j
    tmp := thash pk_seed a tmp
  return tmp

/-- WOTS+ pubkey from sig (FIPS-205 §5.4).

  Input `adrs` has layer/tree/keypair set; we set type=WOTS_HASH and chain
  each of the `len` shares to its endpoint, then compress via T_len with
  type=WOTS_PK. -/
def wotsPkFromSig (sig : ByteArray) (msg_n : ByteArray) (pk_seed : ByteArray)
    (adrs : Adrs) : ByteArray := Id.run do
  let digits := msgToChainDigits msg_n
  let mut tmp := ByteArray.empty
  let mut a := setType adrs AdrsType.wots_hash
  for i in [0:len] do
    a := setTreeHeight a i
    let piece := chain (slice sig (i * n) n) digits[i]! (w - 1 - digits[i]!) pk_seed a
    tmp := tmp ++ piece
  let tAdrs := (setTreeIndex (setTreeHeight (setType adrs AdrsType.wots_pk) 0) 0)
  return thash pk_seed tAdrs tmp

end Fips205.Wots
