# Patching Sui 1.72.2 for a native SLH-DSA signature scheme

Exact, edit-by-edit recipe to add `GenericSignature::SlhDsaAuthenticator` so a
transaction is authenticated with **only** a FIPS-205 SLH-DSA-SHA2-128s
signature — no elliptic curve. Crypto is the `slh-dsa-sui` crate (verified to
interoperate with the `@sui-gen/pqc`/noble signer). Line numbers are against
`mainnet-v1.72.2` (cloned at `~/.local/share/pq-sui/sui`).

The address derivation needs **no special code**: `SuiAddress::from(&PublicKey)`
already hashes `flag || pk.as_ref()`, so adding a `PublicKey::SlhDsa` variant
with a `flag()` and `as_ref()` makes `blake2b256(0x07 || pk)` fall out for free.

## 0. Dependency

`crates/sui-types/Cargo.toml` → `[dependencies]`:
```toml
slh-dsa-sui = { path = "../../../<this-repo>/crates/slh-dsa-sui" }
# or vendor crates/slh-dsa-sui into the Sui workspace and use a workspace path.
```

## 1. New module

Copy `slh_dsa_authenticator.rs` (next to this file) →
`crates/sui-types/src/slh_dsa_authenticator.rs`, and register it in
`crates/sui-types/src/lib.rs`:
```rust
pub mod slh_dsa_authenticator;
```

## 2. `crates/sui-types/src/crypto.rs`

- **SignatureScheme enum** (`pub enum SignatureScheme`, ~1715): add `SlhDsa,`.
- **`flag()`** (~1726): add `SignatureScheme::SlhDsa => 0x07,` (0x07 is the first
  free flag after PasskeyAuthenticator=0x06).
- **`from_flag_byte()`** (~1745): add `0x07 => Ok(SignatureScheme::SlhDsa),`.
- **PublicKey enum** (~264): add `SlhDsa(Vec<u8>),`.
- **`PublicKey::as_ref`** (~335): add `PublicKey::SlhDsa(b) => &b[..],`.
- **`PublicKey::flag`** (~387) and **`scheme()`** (~414): map
  `PublicKey::SlhDsa(_) => SignatureScheme::SlhDsa`.
- **`PublicKey::try_from_bytes`** (~396): add
  `SignatureScheme::SlhDsa => Ok(PublicKey::SlhDsa(bytes[1..].to_vec())),`
  (validate `bytes.len() == 1 + 32`).
- **CompressedSignature enum** (~1760): add `SlhDsa(Vec<u8>),` (used only by the
  `to_compressed` plumbing in signature.rs).

## 3. `crates/sui-types/src/signature.rs`

- `use crate::slh_dsa_authenticator::SlhDsaAuthenticator;`
- **GenericSignature enum** (~98): add `SlhDsaAuthenticator(SlhDsaAuthenticator),`.
- **`to_compressed`** (~179): add a `GenericSignature::SlhDsaAuthenticator(s) =>
  Ok(CompressedSignature::SlhDsa(s.as_ref().to_vec()))` arm.
- **`get_pk`** (~225): `GenericSignature::SlhDsaAuthenticator(s) => s.get_pk(),`.
- **`from_bytes`** (~257): add
  ```rust
  SignatureScheme::SlhDsa => {
      Ok(GenericSignature::SlhDsaAuthenticator(
          SlhDsaAuthenticator::from_bytes(bytes)?,
      ))
  }
  ```
- **`as_ref`** (~278): `GenericSignature::SlhDsaAuthenticator(s) => s.as_ref(),`.
- **`impl AuthenticatorTrait for GenericSignature`**: add the
  `GenericSignature::SlhDsaAuthenticator(s) => s.verify_claims(...)` /
  `verify_user_authenticator_epoch(...)` arms (mirror the
  `PasskeyAuthenticator` arms).

## 4. Enable the scheme

Two options:
- **Simplest for a localnet:** find where accepted user signature schemes are
  gated (search `PasskeyAuthenticator` in `verify_authenticator` /
  `signature.rs` / `transaction.rs`) and add `SignatureScheme::SlhDsa` to the
  allowed set unconditionally.
- **Protocol-config (clean):** add a `enable_slhdsa_auth: bool` feature flag in
  `crates/sui-protocol-config/src/lib.rs` (mirror the passkey flag at the
  versions noted ~196/252), default it on for the localnet protocol version,
  and check it at the dispatch site.

## 5. Build, run, execute

```bash
cd ~/.local/share/pq-sui/sui
cargo build --release --bin sui --bin sui-node      # ~30 min first time
# launch a localnet on the patched binary, then:
```
Point `demos/localnet-pq/pq-only-account.ts` at the standard scheme:
- address = `blake2b256(0x07 || pk)` where `pk` is the 32-byte noble
  `slh_dsa_sha2_128s` public key,
- wire blob = `0x07 || pk(32) || sig(7856)` (sign the tx-intent digest with
  `slh_dsa_sha2_128s.sign(message, sk)`),
- submit via `executeTransactionBlock` → the patched validator verifies it with
  `slh_dsa_sui::verify` and **executes with no elliptic-curve signature**.

## Compile-error cascade

Adding enum variants will surface non-exhaustive `match` errors across
`sui-types` (and a few in `sui-core`/SDK). They are mechanical: add the
`SlhDsa` / `SlhDsaAuthenticator` arm wherever the compiler points. Build
`-p sui-types` first to clear the bulk before the full node build.
