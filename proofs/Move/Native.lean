import Move.Value
import Fips205.Sha256

/-! # Native function registry

Move calls into native functions (compiled Rust, exposed to bytecode) by
module + function name. Our model captures just the ones the FIPS-205
verifier needs:

  - `std::hash::sha2_256(data: vector<u8>): vector<u8>`

We provide a single dispatch function `applyNative` that takes the symbolic
name + arg arity + popped argument values, and returns the result `Value`.
This lets the VM model treat native calls as black boxes whose mathematical
behaviour we trust the host (Sui's Rust runtime) to implement correctly.

For our equivalence proofs, that's a SOUNDNESS assumption — we're modelling
the native's behaviour mathematically. The host code is separately audited
(it's in `crates/sui-framework`); for SHA-256 specifically it's well-tested
against FIPS 180-4 KATs which we also self-check in `Fips205.Sha256`.
-/

namespace Fips205.Move

open Fips205.Move.Value

/-- Dispatch a native call by symbolic name. Returns the result `Value` or
    `none` on unknown/mismatched-arity calls.

    For SHA-256: arity=1, argument is `vector<u8>`, returns `vector<u8>`. -/
def applyNative (name : String) (arity : Nat) (args : Array Value) : Option Value :=
  match name with
  | "sha2_256" =>
    if arity = 1 ∧ args.size = 1 then
      match args[0]! with
      | .vecU8 data => some (.vecU8 (Fips205.Sha256.sha256 data))
      | _ => none
    else none
  | "u64_to_u8" =>
    -- Move's `as u8` cast applied to a u64: returns the low byte.
    if arity = 1 ∧ args.size = 1 then
      match args[0]! with
      | .u64 n => some (.u8 (UInt8.ofNat (n.toNat &&& 0xff)))
      | _ => none
    else none
  | "u64_to_u32" =>
    -- Move's `as u32` cast applied to a u64: returns the low 32 bits.
    if arity = 1 ∧ args.size = 1 then
      match args[0]! with
      | .u64 n => some (.u32 (UInt32.ofNat (n.toNat &&& 0xffffffff)))
      | _ => none
    else none
  | "u8_to_u64" =>
    -- Move's `as u64` cast applied to a u8: zero-extend.
    if arity = 1 ∧ args.size = 1 then
      match args[0]! with
      | .u8 n => some (.u64 (UInt64.ofNat n.toNat))
      | _ => none
    else none
  | "u32_to_u64" =>
    -- Move's `as u64` cast applied to a u32: zero-extend.
    if arity = 1 ∧ args.size = 1 then
      match args[0]! with
      | .u32 n => some (.u64 (UInt64.ofNat n.toNat))
      | _ => none
    else none
  | _ => none

end Fips205.Move
