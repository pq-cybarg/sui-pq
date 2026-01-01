# Validator-side PQ roadmap

The remaining workspace-external gap: Sui validators don't natively accept
post-quantum signature schemes for transaction authentication. This is a
**validator-protocol change**, not an SDK feature — only Mysten Labs (and
network governance) can ship it. This doc captures what *would* need to change,
with concrete pointers, so you can track progress and review PRs intelligently.

## Where signature schemes live in the Sui stack

| Layer | File / module | What it does |
| --- | --- | --- |
| **Scheme enum** | [`sui-types/src/crypto.rs`](https://github.com/MystenLabs/sui/blob/main/crates/sui-types/src/crypto.rs) | `SignatureScheme` enum: `ED25519`, `Secp256k1`, `Secp256r1`, `BLS12381`, `MultiSig`, `ZkLoginAuthenticator`, `PasskeyAuthenticator`. Each has a 1-byte flag. |
| **Signature container** | [`sui-types/src/signature.rs`](https://github.com/MystenLabs/sui/blob/main/crates/sui-types/src/signature.rs) | `GenericSignature` wraps every accepted scheme; `verify_authenticator` dispatches per scheme. |
| **Crypto primitives** | [`fastcrypto`](https://github.com/MystenLabs/fastcrypto) | Where the actual `Ed25519PublicKey::verify` etc. live. PQ schemes need to land here first. |
| **Validator verify path** | [`sui-types/src/transaction.rs::verify_signature`](https://github.com/MystenLabs/sui/blob/main/crates/sui-types/src/transaction.rs) | Hot path: every tx goes through this. New schemes need a switch arm. |
| **Address derivation** | `crypto.rs::SuiAddress::from(...)` | `addr = blake2b(scheme_flag || pubkey)`. Adding a scheme adds a new derivation case. |

## What landing native ML-DSA would look like

A concrete PR series. None of these exist as PRs yet — this is the shape of
the change.

### PR 1 — fastcrypto: expose ML-DSA-65

- **Where**: `fastcrypto/src/ml_dsa/` (new dir).
- **What**: wrap a reviewed Rust ML-DSA crate (`pq-crystals/dilithium-rust` or
  port from `pqclean`). Implement `fastcrypto::traits::{KeyPair, Signer, VerifyingKey, ToFromBytes}`.
- **Status**: not started. The `fastcrypto/src/sphincs/` work (SLH-DSA) is the
  current PQ focus; ML-DSA follows.

### PR 2 — sui-types: add `MlDsa65` to `SignatureScheme`

```rust
#[repr(u8)]
pub enum SignatureScheme {
    ED25519     = 0x00,
    Secp256k1   = 0x01,
    Secp256r1   = 0x02,
    BLS12381    = 0xff,        // multisig only
    MlDsa65     = 0x04,        // new
    SlhDsa128s  = 0x05,        // new (eventually)
    // ...
}
```

The flag byte goes into the address derivation, so a new scheme is a new
address family. Existing addresses remain valid; only **new** keys get the
PQ-prefixed addresses.

### PR 3 — sui-types: GenericSignature dispatch

Add a `MlDsa65SuiSignature` variant carrying `(pubkey: [u8; 1952], sig: [u8; 3309])`.
Wire it through `verify_authenticator`.

```rust
match self {
    GenericSignature::MlDsa65(s) => s.verify(message),
    // …
}
```

### PR 4 — protocol-config: feature flag the new scheme

Sui has explicit protocol versioning. PQ schemes must be gated:

```rust
// sui-protocol-config/src/lib.rs
pub fn ml_dsa_signatures_enabled(&self) -> bool { ... }
```

Validators that haven't upgraded yet must reject MLDsa-flagged txs. After a
protocol upgrade epoch, all validators accept them.

### PR 5 — sdk: surface the new scheme

[`@mysten/sui`](https://github.com/MystenLabs/sui/tree/main/sdk/typescript) needs:

- `MlDsa65Keypair extends Keypair` in `keypairs/ml-dsa-65.ts`
- `bcs.MlDsa65Signature` BCS schema
- `decodeSuiPrivateKey('mldsa65')` support
- Signature builder dispatch in `Transaction.build()`

### PR 6 — dApp Kit + wallets

`@mysten/dapp-kit` is mostly transparent — it forwards signing to wallets via
the Wallet Standard. The wallet implementations (Slush etc.) need to add ML-DSA
support; that's per-wallet UX work. Until then, dApps continue to use the hybrid
pattern (`@sui-gen/pqc/hybrid`).

## Hypertree-style on-chain verification (alternative path)

A radically simpler path that doesn't require validator changes: a **Move
contract that verifies the signature itself**. This workspace's `move/slh_dsa`
demonstrates the technique with hash-based schemes; lattice schemes would
require either:

1. **Native Move precompiles** for `Z_q[X] / (X^N + 1)` arithmetic and NTT.
   Mysten could expose these from fastcrypto (same precompile pattern as the
   existing `BLS12_381` group ops in `sui::group_ops`). ~1k SLOC of Rust glue.
2. **Pure-Move polynomial arithmetic**. Possible in principle but every
   `Z_q[X]` multiplication is hundreds of u64 ops; ML-DSA verify would be
   gas-prohibitive without precompiles.

For SLH-DSA / hash-based schemes, no precompiles are needed — SHA-256 is
already a Move primitive (`std::hash::sha2_256`). The workspace's
`slh_dsa::verifier::verify` works today.

## The hybrid pattern is the right answer until ML-DSA lands

Until PRs 1–6 ship, applications that want post-quantum guarantees should:

1. **Sign the tx classically** (Ed25519 etc.) — required by the validator.
2. **Sign the same tx digest with a PQ key** via `@sui-gen/pqc/hybridSign`.
3. **Store the PQ co-signature alongside the tx** — `pq_attestation::register`
   on-chain, or as a `vector<u8>` argument to your own Move call, or on Walrus.
4. **Verify both halves off-chain** via `@sui-gen/pqc/hybridVerify`.

When validators support native PQ sigs, your existing PQ-attested data is a
seamless migration anchor: the on-chain PQ pubkey is already there, the
binding is already attested.

## How to track progress

- **fastcrypto repo**: watch [`MystenLabs/fastcrypto`](https://github.com/MystenLabs/fastcrypto) for PRs touching `src/sphincs/` and `src/ml_dsa/`.
- **sui repo**: watch [`MystenLabs/sui`](https://github.com/MystenLabs/sui/pulls?q=is%3Apr+post-quantum) for PRs to `sui-types/src/crypto.rs` and `sui-types/src/signature.rs`.
- **Sui Improvement Proposals**: a PQ scheme switchover would justify a SIP. Look for it in [`sips`](https://github.com/sui-foundation/sips/pulls).
- **Mysten blog**: scheme rollouts are usually announced ahead of testnet activation.

## Predicted timeline (best guess, May 2026)

| Quarter | Expected milestone |
| --- | --- |
| 2026 Q3 | fastcrypto SLH-DSA promoted out of `--features experimental`; first Move-level PQ verify precompile RFC |
| 2026 Q4 | ML-DSA arrives in fastcrypto; SDK keypair scaffolding |
| 2027 H1 | Protocol-config gated PQ scheme on devnet; SDK + dApp Kit |
| 2027 H2 | Testnet ML-DSA tx auth; wallets ship support |
| 2028+ | Mainnet rollout, in line with NIST 2030 mandates |

This is speculative; the actual schedule will be driven by the EU/NIST regulatory
deadlines and Mysten's own roadmap. Don't quote this table as authoritative.

## How this workspace bridges the gap

| Feature | Available today via |
| --- | --- |
| Off-chain PQ signing & verification | `@sui-gen/pqc` — ML-DSA, SLH-DSA, FALCON, ML-KEM |
| Hybrid classical + PQ tx signing | `@sui-gen/pqc/hybridSign` |
| Move-native PQ signature verification | `move/wots` (WOTS+ only) + `move/slh_dsa` (full SLH-DSA-LITE) |
| On-chain PQ attestation storage | `move/pq_attestation::registry` |
| zkLogin → PQ binding | `@sui-gen/pqc/createZkLoginPqBinding` + `pqWrapZkLoginTx` |
| Future-proof migration anchor | The above attestation + binding registry is the migration anchor itself |
