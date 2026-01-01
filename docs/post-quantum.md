# Post-quantum cryptography on Sui

## State of the world (as of May 2026)

| Layer | Status |
| --- | --- |
| Sui validators verify PQ signatures on mainnet/testnet? | **No.** Only Ed25519, secp256k1, secp256r1, BLS12-381, zkLogin (Groth16+RSA). |
| `fastcrypto` PQ primitives? | **SLH-DSA (FIPS 205) experimental.** Behind `--features experimental`. WOTS+ PR #947, FORS+XMSS+Hypertree PR #950. No ML-DSA / ML-KEM yet. |
| Published Mysten research? | *Post-Quantum Readiness in EdDSA Chains*, [eprint 2025/1368](https://eprint.iacr.org/2025/1368). First backward-compatible migration path; works on Sui, Solana, Near, Cosmos. |
| Timeline | NIST: deprecate classical by 2030, phase out by 2035. EU mandates 2030. Sui targets rollout ahead. |

## What this workspace ships

The matrix below is the full inventory. Test counts are real (`pnpm -r test` + `sui move test` across every package). The TS↔Move byte format is locked together — regenerating `move/pq_guard/tests/test_vectors.move` from `@sui-gen/pqc` produces a byte-identical file.

| Capability | Where | Tests |
| --- | --- | --- |
| Off-chain ML-DSA / SLH-DSA / FALCON sign + verify | `@sui-gen/pqc` (keygen / sign / verify) | covered by cross-impl integration tests |
| ML-KEM-512/768/1024 + AES-256-GCM wrap | `@sui-gen/pqc` (kemKeygen / kemEncrypt / kemDecrypt) | 4 tests |
| Hybrid classical + PQ tx signing | `@sui-gen/pqc/hybridSign + hybridVerify + packHybrid` | covered |
| zkLogin → PQ binding + co-signed txs | `@sui-gen/pqc/createZkLoginPqBinding + pqWrapZkLoginTx` | 4 tests |
| On-chain attestation registry | `move/pq_attestation` | 3 tests |
| **Move-native WOTS+ verification** | `move/wots` | 6 tests |
| **Move-native full SLH-DSA verification** | `move/slh_dsa` (WOTS+ + XMSS + Hypertree + FORS + top-level) | 6 tests |
| **PQ authorization at the contract layer** | `move/pq_guard` (replay-safe, action-bound witness) | 8 tests |
| Example PQ-gated app | `move/pq_vault` | 4 tests |
| **PQ-sponsored gas** (user has no classical key) | `@sui-gen/pqc/PqSponsoredClient + sponsorPqOperation` + `pnpm cli sponsor-serve` | covered |
| **Native PQ tx auth on a local Sui validator** | [`patches/`](../patches) + [`scripts/build-pq-validator.sh`](../scripts/build-pq-validator.sh) | see [`docs/local-pq-validator.md`](./local-pq-validator.md) |

## Architectural picture

```
                       ┌──────────────────────────────────────┐
                       │  User (no classical key required)    │
                       └──────────────┬───────────────────────┘
                                      │ SLH-DSA-LITE sign
                                      ▼
              ┌───────────────────────────────────────────────┐
              │  @sui-gen/pqc (browser / CLI / server)        │
              │    keygen → sign → pack                       │
              └───────────────────────────────────────────────┘
                                      │
                                      ▼ HTTP POST
              ┌───────────────────────────────────────────────┐
              │  sponsor service (pnpm cli sponsor-serve)     │
              │    builds PTB:                                │
              │      cmd 1: pq_guard::unlock(sig)             │
              │      cmd 2: gated::call(witness, ...)         │
              │    signs as gas_owner with classical key      │
              └──────────────┬────────────────────────────────┘
                             ▼
              ┌───────────────────────────────────────────────┐
              │  Sui validator                                │
              │   - verifies sponsor's classical sig (gas)    │
              │   - executes PTB atomically:                  │
              │     · slh_dsa::verifier::verify (Move-side)   │
              │     · pq_guard::unlock returns witness        │
              │     · gated call consumes witness             │
              │   - aborts the whole tx if PQ verify fails    │
              └───────────────────────────────────────────────┘
```

For a **fully native** flow (no sponsor, gas paid by the PQ-derived address itself) run a locally-patched `sui-node` — see [`docs/local-pq-validator.md`](./local-pq-validator.md).

## Quick recipes

### 1. Off-chain PQ signature

```ts
import { keygen, sign, verify } from '@sui-gen/pqc';
const kp = keygen('ML_DSA_65');
const sig = sign(kp, new TextEncoder().encode('hello'));
verify('ML_DSA_65', kp.publicKey, new TextEncoder().encode('hello'), sig); // → true
```

### 2. PQ-authorize a Move call (production-ready today)

```move
// In your gated module:
public fun gated_op(witness: pq_guard::PqAuthorized, ...) {
    let expected = compute_action_digest(...);
    assert!(pq_guard::action_digest(&witness) == &expected, 0);
    // ...do the work...
    pq_guard::consume(witness);
}
```

```ts
import { buildUnlockMessageBytes, addPqGuardUnlock, slh } from '@sui-gen/pqc';
import { Transaction } from '@mysten/sui/transactions';

const msg = buildUnlockMessageBytes({ sender, nonce, actionDigest });
const sig = slh.packSignature(slh.sign(slhSecretKey, msg));

const tx = new Transaction();
const witness = addPqGuardUnlock(tx, { guardPackageId, identityId, actionDigest, signature: sig });
tx.moveCall({ target: `${myPkg}::gated::op`, arguments: [witness, ...] });
```

### 3. PQ-sponsored gas (user has no classical key)

```bash
# Run the sponsor service:
PQ_GUARD_PKG=0x…  PQ_SPONSOR_KEY=suiprivkey1…  \
  pnpm cli sponsor-serve --port 4000 --allow 0xPKG::vault::withdraw
```

```ts
// User side — no classical signer instantiated:
import { PqSponsoredClient } from '@sui-gen/pqc';
const client = new PqSponsoredClient({ endpoint: 'http://localhost:4000/sponsor' });
const { digest } = await client.submit({ pqIdentityId, actionDigest, pqSignature, gatedCall });
```

### 4. Local validator with native PQ tx auth

```bash
bash scripts/build-pq-validator.sh           # one-time: clone + patch + build (~10–30 min)
bash scripts/build-pq-validator.sh --launch-only   # subsequent runs
```

Two patch files in [`patches/`](../patches) add `SignatureScheme::SlhDsaLite` (flag `0x07`) to a local Sui fork. The patched `sui-node` accepts SLH-DSA-LITE signatures directly — gas paid by the PQ-derived address, no classical key anywhere.

## Scheme reference

`@sui-gen/pqc` and `move/pq_attestation` use the same 1-byte scheme identifier:

| Byte | Scheme | NIST cat | pk bytes | sig bytes |
| --- | --- | --- | --- | --- |
| `0x10` | ML-DSA-44 | 2 | 1,312 | 2,420 |
| `0x11` | ML-DSA-65 | 3 | 1,952 | 3,309 |
| `0x12` | ML-DSA-87 | 5 | 2,592 | 4,627 |
| `0x20` | SLH-DSA-SHA2-128s | 1 | 32 | 7,856 |
| `0x21` | SLH-DSA-SHA2-128f | 1 | 32 | 17,088 |
| `0x22..0x25` | SLH-DSA-SHA2-{192,256}-{s,f} | 3 / 5 | 48–64 | 16K–50K |
| `0x28..0x2D` | SLH-DSA-SHAKE-{128,192,256}-{s,f} | 1 / 3 / 5 | 32–64 | 8K–50K |
| `0x30` | FALCON-512 | 1 | 897 | 666 |
| `0x31` | FALCON-1024 | 5 | 1,793 | 1,280 |
| `0x60` | SLH-DSA-LITE (workspace-local; Move-verifiable) | 1 (approx) | 64 | 5,056 |

For most app use cases, **ML-DSA-65** is the right default for off-chain work (security cat 3, ~3.3 KB sigs, fastest lattice ops). **SLH-DSA-LITE** is the one the on-chain Move verifier consumes — use it when you need PQ verification *inside* a Move function.

## What you can actually do today

1. **Off-chain PQ sign/verify** any of ML-DSA, SLH-DSA, FALCON via `@sui-gen/pqc`. ✅
2. **Verify a PQ signature inside Move** (SLH-DSA-LITE). ✅
3. **PQ-authorize a Move call** via `pq_guard::unlock` — the validator's classical sig is just gas-paying. ✅
4. **Run a backend that pays gas in exchange for a PQ proof** — user has no classical key. ✅
5. **Pre-commit a PQ public key** to your address for forward-compatible migration. ✅
6. **Run a local Sui validator that natively verifies PQ signatures**. ✅

## What's still out of reach

| Gap | Why | Workaround in this workspace |
| --- | --- | --- |
| Native PQ tx auth on Mysten-managed mainnet/testnet | Network governance decision | Run the patched local validator for CI/dev; use `pq_guard` in production |
| FIPS-205-byte-exact SLH-DSA in Move | `move/slh_dsa` uses n=32 (full SHA-256), FIPS uses n=16 truncated | `move/slh_dsa` ships SLH-DSA-LITE today; fastcrypto's `sphincs` would supersede when exposed as a Move primitive |
| ML-DSA / lattice schemes inside Move | Polynomial arithmetic over Z_q + NTT needs precompiles | Off-chain via `@sui-gen/pqc`; hybrid pattern + attestation carry the guarantee on-chain |

## See also

- Interactive in-browser demos: `pnpm web:start` then `http://localhost:3000/pqc`
- Architectural walkthrough: `pnpm tutorial:start` then `http://localhost:3030/pqc`
- Mysten paper: [eprint.iacr.org/2025/1368](https://eprint.iacr.org/2025/1368)
- fastcrypto SLH-DSA: [MystenLabs/fastcrypto/tree/main/fastcrypto/src/sphincs](https://github.com/MystenLabs/fastcrypto/tree/main/fastcrypto/src/sphincs)
- [`docs/local-pq-validator.md`](./local-pq-validator.md) — local fork workflow
- [`docs/pq-validator-roadmap.md`](./pq-validator-roadmap.md) — Mysten-side rollout plan
- NIST PQC: [FIPS 203 (ML-KEM)](https://csrc.nist.gov/pubs/fips/203/final), [FIPS 204 (ML-DSA)](https://csrc.nist.gov/pubs/fips/204/final), [FIPS 205 (SLH-DSA)](https://csrc.nist.gov/pubs/fips/205/final)
