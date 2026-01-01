# slh-dsa-sui

Verify-only **FIPS-205 SLH-DSA-SHA2-128s** for a native, post-quantum Sui
signature scheme — the verify call behind a patched-validator
`SignatureScheme::SlhDsa`, enabling transactions authenticated with **only** a
PQ signature (no elliptic curve anywhere). See
`../../demos/localnet-pq/pq-only-account.ts` for the account/signing side and
`../../docs/local-pq-validator.md` for the validator context.

## The pivot (why this isn't the LITE port)

The first attempt assumed the workspace's custom **SLH-DSA-LITE** (n=32) and
tried to salvage the verifier from `patches/0002`. That code is wrong (it
returns `false` on a valid signature: ADRS layout + WOTS checksum bugs). Rather
than hand-port + debug a bespoke SPHINCS+ variant, this uses the **complete,
standard** scheme:

- **SLH-DSA-SHA2-128s** (FIPS-205): pk 32 B, sig 7,856 B — the same scheme this
  workspace already machine-checks in `proofs/` and `move/slh_dsa_128s`.
- Verifier = RustCrypto's maintained [`slh-dsa`](https://crates.io/crates/slh-dsa) crate.
- **Confirmed interoperable** with the workspace signer: a signature from
  `@sui-gen/pqc` (via `@noble/post-quantum`) verifies here byte-for-byte
  (`tests/kat.rs`, 4 passing tests incl. tamper / wrong-msg / bad-length
  rejection). `tests/kat.txt` is that noble-produced KAT.

So the crypto for on-chain PQ-only execution is solved with a drop-in
dependency; what remains is Sui plumbing, not cryptography.

## API

```rust
slh_dsa_sui::verify(pk: &[u8], message: &[u8], sig: &[u8]) -> bool
```

Never panics; returns `false` on any length/parse/verify failure — suitable for
a validator hot path.

## Remaining work to execute a zero-EC tx on-chain

1. Add this crate (or `slh-dsa` directly) as a dep of `sui-types`.
2. Add `SignatureScheme::SlhDsa` (a free flag byte, e.g. `0x07`) in
   `crates/sui-types/src/crypto.rs`, with address derivation
   `blake2b256(flag || pk)`.
3. `GenericSignature` parse + `verify_authenticator` dispatch in `signature.rs`:
   on the flag, read `pk(32) || sig(7856)` and call `slh_dsa_sui::verify` over
   the intent message Sui already computes (`blake2b256(intent || tx_bytes)`).
4. Protocol-config feature flag to enable it at genesis.
5. Build the patched `sui-node` (~30 min), run a localnet, point the
   `pq-only-account` demo's flag/wire-format at this scheme, submit -> executes.

Sui 1.72.2 source is cloned at `~/.local/share/pq-sui/sui`; the enum is at
`crates/sui-types/src/crypto.rs:1715`.

## Develop loop

```bash
cd crates/slh-dsa-sui && cargo test
```
