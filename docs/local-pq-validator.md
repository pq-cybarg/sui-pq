# Local PQ validator fork

Run a locally-patched `sui-node` that natively verifies **FIPS-205
SLH-DSA-SHA2-128s** transaction signatures — so a post-quantum-derived address
can authorize and pay for its own transactions, with **no classical key and no
sponsor** in the loop.

This is the "fully native" end of the post-quantum story. The rest of the
workspace ([`docs/post-quantum.md`](./post-quantum.md)) works on **stock
mainnet/testnet** today by either verifying PQ signatures *inside Move*
(`move/slh_dsa`, `move/pq_guard`) or by having a classical sponsor pay gas for
a PQ-authorized action (`pnpm cli sponsor-serve`). The piece neither of those
can provide on an unmodified network is *native transaction authentication*
under a PQ scheme — the validator's signature-verification hot path only knows
the built-in schemes. Patching that path is the gap this doc closes, locally.

> **Local-only.** Addresses and signatures produced under this scheme are valid
> **only** on validators that apply the same patch. This is a research/dev
> harness, not an interop format. For the upstream, network-wide version of
> this change, see [`docs/pq-validator-roadmap.md`](./pq-validator-roadmap.md).

## What's in the box

| Artifact | Purpose |
| --- | --- |
| [`patches/sui-1.72.2-native-slh-dsa.patch`](../patches/sui-1.72.2-native-slh-dsa.patch) | The complete diff against Sui `mainnet-v1.72.2`: adds `SignatureScheme::SlhDsa` (flag `0x07`), a native `GenericSignature::SlhDsaAuthenticator`, a `SuiKeyPair::SlhDsa` signing key with BIP-39 mnemonic derivation, and wires all of it through address derivation, signing, and the keystore/CLI. |
| [`scripts/build-pq-validator.sh`](../scripts/build-pq-validator.sh) | Clone Sui at the pinned revision, apply the patch, build `sui` + `sui-node`, and launch a one-validator localnet with a faucet. |
| [`crates/slh-dsa-sui/`](../crates/slh-dsa-sui) | A standalone, verify-only FIPS-205 wrapper crate + KAT tests proving byte-for-byte interop with [`@noble/post-quantum`](https://github.com/paulmillr/noble-post-quantum) (the signer the dApp/CLI use). |
| [`patches/superseded/`](../patches/superseded) | The earlier **SLH-DSA-LITE** attempt (flag `0x06`, custom `n = 32` profile). Kept as a record of the design that was abandoned once we confirmed the standard FIPS-205 path was viable — see its README. |

The crypto comes from the RustCrypto [`slh-dsa`](https://crates.io/crates/slh-dsa)
crate (`0.2.0-rc.5`). FIPS-205 SLH-DSA-SHA2-128s is a **standard** parameter
set — a signature the patched validator accepts is the same signature
`@noble/post-quantum`'s `slh_dsa_sha2_128s` produces and that any FIPS-205
implementation verifies. Sizes: public key **32 B**, signature **7856 B**,
signing key **64 B**; the on-the-wire authenticator blob is
`flag(0x07) ‖ pk(32) ‖ sig(7856)` = **7889 B**.

## Quickstart

```bash
# Build the patched node + start a localnet (first run: 10–30 min, multi-GB).
bash scripts/build-pq-validator.sh

# Re-launch the localnet later without rebuilding:
bash scripts/build-pq-validator.sh --launch-only

# Build vanilla Sui (no PQ scheme) — useful for diffing behaviour:
bash scripts/build-pq-validator.sh --skip-patches
```

Once it's up:

- RPC: `http://127.0.0.1:9000`
- Faucet: `http://127.0.0.1:9123/v2/gas`

| Env var | Default | Meaning |
| --- | --- | --- |
| `PQ_SUI_HOME` | `~/.local/share/pq-sui` | Where Sui is cloned, built, and the binaries are copied. |
| `SUI_REPO` | `https://github.com/MystenLabs/sui.git` | Source repo to clone. |
| `SUI_REV` | `mainnet-v1.72.2` | Revision the patch was authored against. Bump and re-test before changing. |

Prerequisite: a Rust toolchain (`cargo`) — install via <https://rustup.rs>.

## How it works

1. **Scheme flag.** `SignatureScheme::SlhDsa = 0x07` is added to the enum in
   `crates/sui-types/src/crypto.rs`. The flag byte prefixes both the public key
   (for address derivation) and the serialized authenticator.
2. **Address derivation.** `SuiAddress = blake2b256(0x07 ‖ pk)`, the standard
   Sui construction with the new flag — so a PQ public key maps to a
   deterministic on-chain address with no classical key material anywhere.
3. **Native authenticator.** A new `GenericSignature::SlhDsaAuthenticator`
   (`crates/sui-types/src/slh_dsa_authenticator.rs`, modeled on
   `passkey_authenticator.rs`) verifies `(pk, sig)` over the standard signing
   digest `Blake2b256(bcs(intent_msg))` — the exact digest every other scheme
   signs. Verification calls the RustCrypto `slh-dsa` verifier and never panics.
4. **Signing key + mnemonic derivation.** `SuiKeyPair::SlhDsa` holds a FIPS-205
   signing key. `SuiKeyPair::sign_secure_generic` produces the authenticator
   directly (SLH-DSA cannot be expressed as Sui's compact `Signature`, whose
   wire layout and size differ), and the keystore/`WalletContext` transaction
   path uses that generic signer so any scheme — including post-quantum — works.

### Mnemonic derivation

SLH-DSA accounts derive from a BIP-39 mnemonic just like the elliptic-curve
schemes. SLH-DSA is seed-based rather than a curve, so it follows a fully
hardened SLIP-0010 path like Ed25519:

```
m/84'/784'/0'/0'/{index}'
```

The 32-byte SLIP-0010 secret is expanded into the three `n = 16` FIPS-205
keygen seeds (`SK.seed`, `SK.prf`, `PK.seed`) via domain-separated Blake2b256,
then run through `slh_keygen_internal`. The derivation is deterministic: the
same mnemonic always yields the same address.

```bash
PQ=~/.local/share/pq-sui/sui/target/release/sui

# Generate a brand-new post-quantum account (prints a 0x07 address + mnemonic):
$PQ client new-address slhdsa my-pq-key word15

# Re-derive the exact same address from the mnemonic, anywhere:
$PQ keytool --keystore-path /tmp/ks.keystore import "<mnemonic>" slhdsa
```

## Demos

With the patched localnet running, from the repo root:

```bash
pnpm demo:pq-mnemonic     # mnemonic → SLH-DSA account → real on-chain transfer (no EC key)
pnpm demo:pq-exhaustive   # 9 Sui feature categories, each signed by SLH-DSA alone
pnpm demo:pq-native       # a single zero-elliptic-curve transaction, end to end
```

`demo:pq-mnemonic` exercises the full path this doc adds: it derives an account
from a fresh BIP-39 mnemonic via the patched CLI (`sui client new-address
slhdsa`), re-derives the same address in two independent isolated keystores
(proving determinism), funds it, and executes a real on-chain transfer
authenticated by **only** the SLH-DSA key the CLI manages — submitting over
JSON-RPC, which the node verifies natively (see the gRPC caveat below).

Rust-level coverage lives alongside the patch: `from_ikm` determinism and a
sign→verify round-trip in `crates/sui-types/src/slh_dsa_authenticator.rs`, and a
mnemonic-derivation integration test in `crates/sui-keys/tests/tests.rs`.

## Caveats & rebasing

- **The patch is illustrative.** It was authored against `SUI_REV` above; Sui's
  internals move fast. If `git apply --3way` fails on a hunk, the build script
  stops and tells you to re-rebase by hand. The patch is a single readable diff
  precisely so a human can re-apply the intent against current Sui code.
- **Off-path conversions are stubbed.** Proto/SDK/multisig conversion arms for
  the new scheme are left as `error`/`unimplemented` where SLH-DSA can't be
  represented (e.g. Rosetta's `CurveType` has no PQ variant); the address,
  signing, and verification paths are fully wired.
- **Transaction submission: JSON-RPC, not gRPC.** The patched node verifies
  SLH-DSA transactions on both interfaces, but the CLI's *gRPC* submission path
  serializes the user signature through the external
  [`sui-sdk-types`](https://crates.io/crates/sui-sdk-types) crate, whose
  `SignatureScheme` enum stops at `Passkey` (`0x06`) — so it rejects scheme
  `0x07` before the bytes ever leave the client. Submitting the same transaction
  over JSON-RPC (`sui_executeTransactionBlock`, what `@sui-gen/sdk-core` and the
  demos use) works natively. Making `sui client transfer …` submit SLH-DSA over
  gRPC would require teaching `sui-sdk-types` (and the gRPC proto) the new
  scheme — a change to an upstream dependency, out of scope for this fork. Key
  *derivation, storage, and signing* in the CLI/keystore are fully wired; only
  the gRPC submission wire-format is gated by the external crate.
- **Divergent ledger.** A node running this patch will not agree with stock Sui
  validators on the validity of `0x07`-flagged transactions. Keep it on an
  isolated localnet.
- **Not a substitute for the upstream path.** Native PQ auth on a *public* Sui
  network is a validator-protocol change only Mysten + network governance can
  ship. The realistic rollout — fastcrypto first, then `sui-types`, then a
  protocol upgrade — is tracked in
  [`docs/pq-validator-roadmap.md`](./pq-validator-roadmap.md).

## See also

- [`docs/post-quantum.md`](./post-quantum.md) — the on-stock-network PQ story
  (Move-layer verification + PQ-sponsored gas).
- [`docs/pq-validator-roadmap.md`](./pq-validator-roadmap.md) — the Mysten-side
  changes that would make this native everywhere.
