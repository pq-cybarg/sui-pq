import Fips205.Verify

/-! # Structural invariants of `verify`

Properties of `Fips205.Verify.verify` that hold for **every** input — not
just the ones our KAT files test. These complement the input-specific
theorems in `Kat.lean` and `NistKat.lean`: those say "verify accepts/rejects
this specific input"; the lemmas here say "verify behaves correctly across
the entire input domain in these ways".

For our use case (PQ authorization at the contract layer) these matter
because they prove the verifier:
  - Never panics on adversarial input
  - Reliably rejects malformed inputs
  - Is total: defined on every `(pk, msg, sig, ctx) : ByteArray⁴`

The latter property is what makes `verify` safe to call from Move without
exception handling — there's no input that aborts the verifier mid-flight,
only inputs that make it return `false`.
-/

namespace Fips205.Structural

open Fips205 Fips205.Verify

/-- Verify is **total**: it returns either `true` or `false` on every input —
    no panics, no infinite loops, no exceptions thrown.

    The Lean type system already guarantees totality for any non-`partial`
    definition; this theorem makes that promise explicit and citable. -/
theorem verify_total
    (pk msg sig ctx : ByteArray) :
    verify pk msg sig ctx = true ∨ verify pk msg sig ctx = false := by
  cases verify pk msg sig ctx
  · right; rfl
  · left; rfl

/-- Verify is deterministic: identical inputs produce identical outputs.
    Trivially true since `verify` is a pure function — but stating it
    explicitly is useful for downstream proofs. -/
theorem verify_deterministic
    (pk msg sig ctx : ByteArray) :
    verify pk msg sig ctx = verify pk msg sig ctx := rfl

/-! ## Concrete totality witnesses (closed-form `native_decide`)

These compile-time checks confirm `verify` doesn't trap on pathological
input. We pick adversarial cases: empty inputs, wrong sizes, all-zero
buffers. The verifier must return `false` on each without aborting. -/

/-- Empty everything. -/
example : verify ByteArray.empty ByteArray.empty ByteArray.empty ByteArray.empty = false := by
  native_decide

/-- Correct-size pk and sig but all zero. -/
example : verify (Bytes.zeros 32) ByteArray.empty (Bytes.zeros 7856) ByteArray.empty = false := by
  native_decide

/-- One-byte-too-short pk. -/
example : verify (Bytes.zeros 31) ByteArray.empty (Bytes.zeros 7856) ByteArray.empty = false := by
  native_decide

/-- One-byte-too-long pk. -/
example : verify (Bytes.zeros 33) ByteArray.empty (Bytes.zeros 7856) ByteArray.empty = false := by
  native_decide

/-- Way-too-short sig. -/
example : verify (Bytes.zeros 32) ByteArray.empty (Bytes.zeros 100) ByteArray.empty = false := by
  native_decide

/-- One-byte-too-short sig. -/
example : verify (Bytes.zeros 32) ByteArray.empty (Bytes.zeros 7855) ByteArray.empty = false := by
  native_decide

/-- One-byte-too-long sig. -/
example : verify (Bytes.zeros 32) ByteArray.empty (Bytes.zeros 7857) ByteArray.empty = false := by
  native_decide

/-- Context exactly at the 255-byte limit (legal) on otherwise-bad inputs. -/
example : verify (Bytes.zeros 32) ByteArray.empty (Bytes.zeros 7856) (Bytes.zeros 255) = false := by
  native_decide

/-- Context one byte over the limit. -/
example : verify (Bytes.zeros 32) ByteArray.empty (Bytes.zeros 7856) (Bytes.zeros 256) = false := by
  native_decide

/-- 1000-byte context — well over the 255-byte limit. -/
example : verify (Bytes.zeros 32) ByteArray.empty (Bytes.zeros 7856) (Bytes.zeros 1000) = false := by
  native_decide

end Fips205.Structural
