# slh-dsa-lite-verifier (WIP)

A standalone, verify-only Rust implementation of the workspace's **SLH-DSA-LITE**
post-quantum signature scheme (n=32; the variant in `move/slh_dsa` +
`packages/pqc/src/slh-dsa-ref.ts`). Its purpose: become the verifier behind a
**native `SignatureScheme::SlhDsaLite` in a patched Sui validator**, so a
transaction can be authenticated with **only** a PQ signature — no elliptic
curve anywhere. (See `../../docs/local-pq-validator.md` and the
`demos/localnet-pq/pq-only-account.ts` proof of the account/signing side.)

## Why this crate exists

Getting on-chain zero-EC execution requires the validator to register a PQ
scheme. The repo's `patches/0001,0002` were meant to do that, but they are
illustrative: `git apply` reports "corrupt patch", and — more importantly —
the verifier *code* inside them is wrong (see below). So the verifier is being
re-done here as a faithful, KAT-tested port of the canonical reference, then it
will be wired into Sui.

## Status

- [x] Skeleton salvaged from `patches/0002` (`src/lib.rs`): correct *shape*
      (`verify` → `fors_root_from_sig` / `ht_root_from_sig` / `xmss_root_from_sig`
      / `wots_pk_from_sig` / `thash` / `adrs` / `split_digest`).
- [x] Cross-impl KAT committed (`tests/kat.txt`) — a (pk, msg, sig) from the TS
      signer, which self-verifies and matches the Move verifier + Lean spec.
- [ ] **Make `verify` accept the KAT.** Known divergences from the reference
      (`slh-dsa-ref.ts`) to fix:
  1. **ADRS byte layout.** Salvaged `adrs()` writes `keypair@20`. The reference
     (and `move/slh_dsa`) write `type@16`, `chain/keypair@24`, `hash/height@28`
     within the 32-byte ADRS, and use the full 32-byte ADRS in
     `thash = sha256(seed ‖ adrs ‖ m)`. Align the offsets per `chainStep` /
     the tweakable-hash callers in the TS ref.
  2. **WOTS checksum.** Salvaged `msg_to_chains` hard-codes
     `(csum>>8)&0xF, (csum>>4)&0xF`. The reference base-w-decodes the checksum
     into `len_2 = 3` nibbles. Port `baseW` + checksum exactly.
  3. Re-check FORS / XMSS auth-path ordering and the HT layer iteration against
     `forsRootFromSig` / `xmssRootFromSig` / `htRootFromSig` in the TS ref.
- [ ] Wire into Sui (`SignatureScheme::SlhDsaLite`, address derivation
      `blake2b256(0x07 ‖ pk)`, `GenericSignature` parse + dispatch in
      `crates/sui-types/src/{crypto,signature}.rs`, protocol-config flag).
- [ ] Build the patched `sui-node`, run a localnet, submit the
      `pq-only-account` transaction → executes with no EC signature.

When `verify` matches, **un-ignore** `verifies_reference_signature` in
`tests/kat.rs`; that test is then the regression gate locking the wire format.

## Develop loop

```bash
cd crates/slh-dsa-lite-verifier
cargo test -- --include-ignored      # the KAT test must go green
```

The reference to port against is `../../packages/pqc/src/slh-dsa-ref.ts`
(SLH-DSA-LITE: n=32, lg_w=4, len=67, h=8, d=2, h'=4, a=3, k=4), cross-checked
by the Lean spec in `../../proofs` and the Move verifier in `../../move/slh_dsa`.
