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

## The off-Sui technologies

The workspace also ships clients for technologies that are **separate
decentralized networks**, not things a bare Sui localnet provides: Walrus
(storage nodes), Seal (key servers), zkLogin (OAuth + prover), DeepBook
(deployed pools + indexer), Pyth oracles (state objects + Hermes), the bridge
(Wormhole guardians), and Lumiwave (its own RPC + deployed LWA coin).

On a **bare** Sui localnet these have no service to talk to, so they are not in
the 8 end-to-end scenarios above. What *is* verified for them today:

- **Unit tests** (`pnpm test`) exercise their client logic offline (request
  construction, encoding, PQ envelopes) — see each package's `*.test.ts`.
- They are **localnet-configurable**: every client reads `SUI_NETWORK` /
  `*_RPC_URL` / endpoint env vars and points at `127.0.0.1` when asked.
- The **post-quantum layer is transport-independent**: `@sui-gen/pqc` signs and
  attests payloads the same way regardless of which network carries them, and
  on-chain PQ attestations (`pq_attestation`) anchor any off-chain artifact
  (e.g. a Walrus blob id) to the Sui localnet.

A fully-local end-to-end demo for these requires standing up `127.0.0.1`
stand-in services that speak each protocol (a local Walrus publisher/aggregator,
a local Seal key server, a local prover, a local Hermes price feed, a local
guardian). That stand-in tier is the natural next addition to this harness; the
PQ-secured client code it would drive already exists and is unit-tested.

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
