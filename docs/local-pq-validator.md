# Local PQ validator fork

Run a locally-patched `sui-node` that natively verifies **SLH-DSA-LITE**
transaction signatures — so a post-quantum-derived address can authorize and
pay for its own transactions, with **no classical key and no sponsor** in the
loop.

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
| [`scripts/build-pq-validator.sh`](../scripts/build-pq-validator.sh) | Clone Sui at a pinned revision, apply the patches, build `sui` + `sui-node`, and launch a one-validator localnet with a faucet. |
| [`patches/0001-add-slh-dsa-lite-signature-scheme.patch`](../patches/0001-add-slh-dsa-lite-signature-scheme.patch) | `sui-types`: adds `SignatureScheme::SlhDsaLite` (flag byte `0x06`), wired through address derivation, `GenericSignature` dispatch, and protocol-config flags. |
| [`patches/0002-fastcrypto-slh-dsa-lite.patch`](../patches/0002-fastcrypto-slh-dsa-lite.patch) | `fastcrypto-experimental`: the hash-based SLH-DSA-LITE verifier the scheme dispatch calls into. |

The SLH-DSA-LITE byte format these patches verify is the **same** one produced
by the workspace's reference signer (`packages/pqc/src/slh-dsa-ref.ts`) and
consumed by the Move verifier (`move/slh_dsa/sources/slh_dsa.move`) — so a
signature you can verify on-chain in Move is byte-for-byte the signature the
patched validator accepts natively.

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
| `SUI_REV` | `mainnet-v1.72.2` | Revision the patches were authored against. Bump and re-test before changing. |

Prerequisite: a Rust toolchain (`cargo`) — install via <https://rustup.rs>.

## How it works

1. **Scheme flag.** `SignatureScheme::SlhDsaLite = 0x06` is added to the enum in
   `crates/sui-types/src/crypto.rs`. The flag byte prefixes both the public key
   (for address derivation) and the serialized authenticator.
2. **Address derivation.** `SuiAddress = blake2b(0x06 ‖ pk)`, the standard Sui
   construction with the new flag — so a PQ public key maps to a deterministic
   on-chain address with no classical key material anywhere.
3. **Verification dispatch.** `GenericSignature::verify_authenticator` (in
   `signature.rs`) gains an arm that hands `(message, pk, sig)` to the
   `fastcrypto-experimental` SLH-DSA-LITE verifier from patch `0002`.
4. **Protocol config.** A feature flag in `sui-protocol-config` gates the new
   scheme so the localnet's genesis enables it.

SLH-DSA-LITE is the workspace's own profile (`n = 32` rather than FIPS-205's
`n = 16`, with a simplified message-digest function); patch `0002` documents
the swap path for when fastcrypto's mainline FIPS-205 SLH-DSA verifier (today
behind `--features experimental` at `fastcrypto/src/sphincs/`) graduates out of
experimental.

## Caveats & rebasing

- **The patches are illustrative.** They were authored against `SUI_REV`
  above; Sui's internals move fast. If `git apply --3way` fails on a hunk, the
  build script stops and tells you to re-rebase by hand. Each patch's header
  documents *what* it changes in plain English precisely so a human can
  re-apply the intent against current Sui code.
- **Divergent ledger.** A node running this patch will not agree with stock Sui
  validators on the validity of `0x06`-flagged transactions. Keep it on an
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
