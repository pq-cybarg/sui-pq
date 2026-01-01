# Superseded: SLH-DSA-LITE validator patches

These two patches were the **first** attempt at native post-quantum transaction
authentication in the Sui validator. They are kept for the record — they
document a design decision that turned out to be wrong, and the reasoning is
worth preserving.

- `0001-add-slh-dsa-lite-signature-scheme.patch` — added a `SignatureScheme::SlhDsaLite`
  at flag byte `0x06`, wired through address derivation and `GenericSignature`.
- `0002-fastcrypto-slh-dsa-lite.patch` — a custom hash-based verifier in
  `fastcrypto-experimental` for a bespoke "SLH-DSA-LITE" profile (`n = 32`
  rather than FIPS-205's `n = 16`, with a simplified message-digest function).

## Why they were abandoned

SLH-DSA-LITE was a **non-standard** parameter set invented for this workspace.
Its verifier was hand-written, never matched a published test vector, and (as it
turned out) had subtle bugs — the salvaged Rust verifier rejected valid
signatures because of an `ADRS` layout mismatch and a hard-coded WOTS checksum.
A signature it accepted would interoperate with *nothing*.

The replacement uses **standard FIPS-205 SLH-DSA-SHA2-128s** via the RustCrypto
[`slh-dsa`](https://crates.io/crates/slh-dsa) crate, at flag byte `0x07`. Because
it is a standard parameter set, the patched validator accepts exactly the
signatures `@noble/post-quantum` produces and that any FIPS-205 implementation
verifies — byte-for-byte interop, machine-checked by the KAT tests in
[`../../crates/slh-dsa-sui`](../../crates/slh-dsa-sui).

The lesson: don't invent a crypto profile when a standardized one fits. Reach for
the standard parameter set and a maintained implementation first.

## The current patch

See [`../sui-1.72.2-native-slh-dsa.patch`](../sui-1.72.2-native-slh-dsa.patch)
and [`../../docs/local-pq-validator.md`](../../docs/local-pq-validator.md). These
LITE patches are **not** applied by `scripts/build-pq-validator.sh`.
