# sui-pq documentation

A Sui-ecosystem monorepo whose centrepiece is a **FIPS-205 SLH-DSA-SHA2-128s**
post-quantum signature verifier — implemented in Move and TypeScript, with a
**Lean 4 machine-checked formal specification** and opcode-for-opcode
bytecode-equivalence proofs.

[![CI](https://github.com/pq-cybarg/sui-pq/actions/workflows/ci.yml/badge.svg)](https://github.com/pq-cybarg/sui-pq/actions/workflows/ci.yml)
&nbsp;·&nbsp; [Source on GitHub](https://github.com/pq-cybarg/sui-pq)

## Post-quantum

- [Post-quantum cryptography](./post-quantum.md) — off-chain `@sui-gen/pqc`; on-chain `wots` / `slh_dsa` / `pq_guard`.
- [Local PQ validator fork](./local-pq-validator.md) — patch + build script for a Sui node that natively verifies SLH-DSA-LITE.
- [Mysten-side PQ validator roadmap](./pq-validator-roadmap.md) — the upstream changes that would close the last gap.
- [**Formal verification**](https://github.com/pq-cybarg/sui-pq/blob/main/VERIFICATION.md) — the FIPS-205 verifier, machine-checked in Lean 4: spec ≡ noble/NIST KATs, a 100%-bytecode verifier, and every compiled `sha2_128s.mv` function proven ≡ spec opcode-for-opcode (403 theorems).

## Ecosystem

- [Architecture](./architecture.md)
- [Move conventions](./move.md)
- [Slush wallet integration](./slush.md)
- [Walrus protocol](./walrus.md)
- [Seal secrets](./seal.md)
- [Lumiwave](./lumiwave.md)
- [zkLogin](./zk-login.md)
- [DeepBook](./deepbook.md)
- [Sponsored transactions](./sponsored-tx.md)

---

<sub>This site is published from the [`docs/`](https://github.com/pq-cybarg/sui-pq/tree/main/docs)
folder of the repository; the source is versioned and reviewed alongside the code.</sub>
