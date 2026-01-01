/-! # FIPS-205 SLH-DSA-SHA2-128s parameters

Direct transcription of FIPS 205 §10.1 (Table 2, row `SLH-DSA-SHA2-128s`).
Every constant here is verifiable against the published spec without running code.

Naming follows the spec's `lower_snake` rather than Lean's `camelCase` so reviewers
can diff against §10.1 mechanically.
-/

namespace Fips205

/-- Hash output length in bytes (SHA-256 truncated to 16). -/
def n : Nat := 16

/-- Winternitz log: each WOTS+ digit is `lg_w` bits, so the base is `w = 2^lg_w`. -/
def lg_w : Nat := 4
def w     : Nat := 16          -- = 2 ^ lg_w

/-- WOTS+ chain count. `len_1` covers the message digits; `len_2` the checksum. -/
def len_1 : Nat := 32          -- = ceil(8 * n / lg_w)
def len_2 : Nat := 3           -- = floor(log_w(len_1 * (w-1))) + 1
def len   : Nat := 35          -- = len_1 + len_2

/-- Hypertree total height; layered as `d` XMSS trees of height `h_prime`. -/
def h       : Nat := 63
def d       : Nat := 7
def h_prime : Nat := 9         -- = h / d

/-- FORS: `k` trees, each of depth `a`. -/
def a : Nat := 12
def k : Nat := 14

/-- Hmsg output in bytes: `ceil(k·a/8) + ceil((h - h_prime)/8) + ceil(h_prime/8)`. -/
def m_bytes : Nat := 30        -- = 21 + 7 + 2

/-- Public key length: `PK.seed (n) || PK.root (n) = 32 bytes`. -/
def pk_bytes : Nat := 32

/-- Signature byte length:
    `R (n) + FORS (k·(1+a)·n) + HT (d·(len + h_prime)·n) = 16 + 2912 + 4928 = 7856`. -/
def sig_bytes : Nat := 7856

/-- Compressed ADRS byte size for SHA-2 variants (FIPS-205 §11.2.1). -/
def adrs_bytes : Nat := 22

end Fips205

/-! ## ADRS type-byte registry (FIPS-205 §4.2.2) -/
namespace Fips205.AdrsType
  def wots_hash  : UInt8 := 0
  def wots_pk    : UInt8 := 1
  def tree       : UInt8 := 2
  def fors_tree  : UInt8 := 3
  def fors_roots : UInt8 := 4
  -- 5 (WOTS_PRF) and 6 (FORS_PRF) only appear in keygen / signing.
end Fips205.AdrsType

/-! ## Self-checks: spec constants are internally consistent. -/
section
  open Fips205
  example : len = len_1 + len_2 := by native_decide
  example : w = 2 ^ lg_w := by native_decide
  example : h_prime = h / d := by native_decide
  example : pk_bytes = 2 * n := by native_decide
  example : sig_bytes = n + k * (1 + a) * n + d * (len + h_prime) * n := by native_decide
  example : m_bytes = (k * a + 7) / 8 + ((h - h_prime) + 7) / 8 + (h_prime + 7) / 8 := by
    native_decide
end
