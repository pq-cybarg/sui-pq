# Local-only post-quantum demonstrations

End-to-end scenarios that run entirely on a local Sui network — no public
endpoint is ever contacted — with **post-quantum SLH-DSA (FIPS-205)** crypto as
the through-line. The on-chain authorization is verified by the same Move
verifier that is machine-checked in [`proofs/`](../../proofs).

## Run it

```bash
# 1. start a local Sui network (separate terminal)
sui start --with-faucet --force-regenesis      # RPC :9000, faucet :9123

# 2. run the demo
pnpm demo:localnet
# (equivalently: SUI_NETWORK=localnet pnpm exec tsx demos/localnet-pq/run.ts)
```

Expected tail:

```
Sui localnet <chain-id> @ 127.0.0.1:9000 — local-only PQ demo
  ✓ pqc-core      SLH-DSA-128s sign/verify (pk 32B, sig 7856B), tamper rejected
  ✓ counter       published 0x…, Counter.value == 1 on-chain
  ✓ pq-guard      on-chain SLH-DSA-128s unlock verified by Move verifier (Unlocked emitted)
  ✓ pq-guard-neg  tampered SLH-DSA signature correctly aborted on-chain
  ✓ nft           minted GenesisNFT 0x… on-chain
  ✓ coin          minted 1,000,000 DEMO_COIN on-chain
  ✓ pq-vault      PQ-authorized withdraw of 0.2 SUI executed on-chain
  ✓ indexer       queried recent on-chain events via localnet RPC
localnet PQ demo: 8/8 scenarios passed
```

## What each scenario proves (all local, all PQ where applicable)

| Scenario | What runs locally | Post-quantum property |
| --- | --- | --- |
| **pqc-core** | `@sui-gen/pqc` SLH-DSA-SHA2-128s keygen/sign/verify | the FIPS-205 signature primitive itself; tamper rejected |
| **counter** | publish + `create` + `increment` on the Sui localnet | — (baseline on-chain liveness) |
| **pq-guard** | register a PQ identity, then `unlock` with a real SLH-DSA signature | **on-chain SLH-DSA verification** by the machine-checked Move verifier → `PqAuthorized` |
| **pq-guard-neg** | submit a tampered signature | the on-chain verifier **aborts** — soundness, not just liveness |
| **nft** | permissionless `genesis_nft::mint` | — |
| **coin** | `TreasuryCap`-gated `demo_coin::mint` | — |
| **pq-vault** | open a SUI vault, then `withdraw` gated by a `PqAuthorized` witness | **PQ-authorized value transfer**: the SLH-DSA signature binds `(vault, recipient, amount)`; it can't be replayed for a different payee/amount |
| **indexer** | query emitted events back off the localnet RPC | — |

The flagship is **pq-vault**: a real on-chain SUI withdrawal whose *authority*
is a post-quantum signature checked inside Move. The validator's classical
signature only pays gas — the actual authorization is quantum-resistant, with
no validator-side change.

## Every ecosystem package, post-quantum (`pnpm demo:pq-ecosystem`)

`pq-ecosystem.ts` proves that **all 13 `@sui-gen/*` packages** work when their
on-chain operations are driven by an **SLH-DSA-only account** (scheme `0x07`, no
elliptic curve) on the patched validator. The linchpin is
[`pq-signer.ts`](./pq-signer.ts)'s `SlhDsaSigner` — a drop-in `@mysten/sui`
`Signer` backed by a post-quantum key, so anything that takes a signer
(`sdk-core`'s `executeTx`, `@mysten/kiosk`, sponsored-tx, the dapp-kit wallet
hooks…) accepts it unchanged.

Public testnets do **not** have the PQ scheme (it's a local validator patch), so
the off-Sui services are exercised against **local mocks/stand-ins** (an
in-process Walrus publisher/aggregator; a locally-published LWA stand-in coin for
Lumiwave; `seal_demo`'s on-chain allowlist gate for Seal). Status per package:

| Status | Packages | What's proven |
| --- | --- | --- |
| **EXECUTED** (PQ-only on-chain) | `pqc`, `sdk-core`, `sponsored-tx`, `indexer`, `kiosk` | a real PQ-signed transaction executed on-chain via the package |
| **LOCAL** (stand-in round-trip) | `lumiwave`, `walrus-client` | end-to-end against a local mock/stand-in |
| **GATE** (PQ-only on-chain) | `seal-client` | the `seal_approve` allowlist gate ran under a PQ account |
| **BUILD+SIGN** (external infra) | `wallet-kit`, `zk-login`, `oracles`, `deepbook`, `bridge` | the package builds its tx and the PQ signer produces a valid native signature; on-chain execution needs an external protocol (mainnet pools / bridge / oracle / prover / browser wallet) absent on a local node |

`sponsored-tx` is notable: a **PQ user authorizes** while a classical Ed25519
**sponsor pays gas** — a post-quantum account that holds no SUI still transacts.

The `BUILD+SIGN` packages target protocols that only exist on mainnet (DeepBook
v3 pools, Sui Bridge `0xb` + Wormhole guardians, Pyth Hermes + on-chain state)
or in the browser (dapp-kit wallets) or off-chain (zkLogin's Groth16 prover) —
so they can't be *executed* on a bare localnet, but the post-quantum
*integration point* (their unsigned `Transaction` is signed by the PQ signer) is
verified. zkLogin is classical by construction; PQ co-signing of a zkLogin tx is
provided by `@sui-gen/pqc`'s `pqWrapZkLoginTx`.

## Real upstream protocols, run locally (`pnpm demo:pq-deepbook`)

The `BUILD+SIGN` row above is the honest floor, not the ceiling. Where an
upstream protocol is **pure on-chain Move**, we can do better than sign a
representative tx — we can publish the *real* upstream packages to the localnet
and drive them for real. **DeepBook v3** is proven this way:

```bash
bash demos/localnet-pq/setup-deepbook.sh   # clone MystenLabs/deepbookv3, unpin for localnet
pnpm demo:pq-deepbook
```

`pq-deepbook.ts` publishes the **actual upstream** `deepbookv3` (`token` +
`deepbook`) to the local validator, then — signed only by an SLH-DSA key —
admin-creates a real `Pool<DEMO,SUI>`, opens a real `BalanceManager`, funds it,
and **places a real limit order on DeepBook's CLOB** (`OrderPlaced` emitted). No
mock: this is Mysten's production DeepBook code, republished locally (the
mainnet-pinned package ids are unpinned so it deploys fresh), executing a real
trade authorized by a post-quantum account.

The same recipe (republish the real Move packages, drive with the PQ signer)
extends to any pure-on-chain protocol. The remaining `BUILD+SIGN` packages need
an off-chain counterparty — Walrus storage nodes, Seal key servers, a Wormhole
guardian for Pyth/bridge, a zkLogin prover — or, for the Sui Bridge (`0xb`,
genesis-reserved) and Lumiwave (closed-source coin), can't be republished at
all; those would each require standing up the upstream service locally.

## Design notes

- `lib.ts` — localnet client, the active CLI keypair (holds publish caps + gas),
  faucet-funded throwaway keypairs, `test-publish` helpers, a PTB runner, and
  the PASS/FAIL matrix. Everything binds to `127.0.0.1`.
- `run.ts` — the scenarios. SLH-DSA via `@noble/post-quantum`
  (`sign(message, secretKey)`, `verify(signature, message, publicKey)`);
  on-chain PTBs via `@sui-gen/pqc`'s `buildUnlockMessageBytes` /
  `addPqGuardUnlock`.
- Move packages are published with `sui client test-publish --build-env mainnet`
  (localnet needs an explicit build env), each to a fresh ephemeral pubfile so
  re-runs publish clean.
