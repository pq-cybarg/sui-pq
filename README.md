# Sui Ecosystem Development Workspace

A comprehensive monorepo for building across the Sui blockchain ecosystem. Covers Move smart contracts, the TypeScript SDK, wallets (Slush, Suiet, Phantom), Walrus decentralized storage, Seal decentralized secrets, Lumiwave, DeepBook, zkLogin, sponsored transactions, oracles, bridges, and more.

## What's inside

| Area | Path | Description |
| --- | --- | --- |
| Move contracts | [`move/`](./move) | On-chain modules: counter, NFT, coin, Kiosk, DeepBook, Seal demo, WOTS+, **full SLH-DSA verifier**, PQ-attestation registry, **PQ-Guard authorization primitive**, PQ-gated vault example |
| Core SDK utilities | [`packages/sdk-core`](./packages/sdk-core) | Clients, signers, BCS helpers, transaction utilities |
| Wallet integration | [`packages/wallet-kit`](./packages/wallet-kit) | Slush / Suiet / Phantom via `@mysten/dapp-kit` |
| Walrus storage | [`packages/walrus-client`](./packages/walrus-client) | Upload/read blobs on Walrus |
| Seal secrets | [`packages/seal-client`](./packages/seal-client) | Threshold-encrypted secrets via Seal |
| Lumiwave | [`packages/lumiwave`](./packages/lumiwave) | LWA token + Lumiwave entertainment-platform helpers |
| zkLogin | [`packages/zk-login`](./packages/zk-login) | Google/Apple/Facebook zkLogin auth flow |
| Sponsored tx | [`packages/sponsored-tx`](./packages/sponsored-tx) | Gasless tx via sponsor service |
| DeepBook | [`packages/deepbook`](./packages/deepbook) | DeepBook V3 (CLOB) client wrappers |
| Oracles | [`packages/oracles`](./packages/oracles) | Pyth + Switchboard price feeds |
| Bridge | [`packages/bridge`](./packages/bridge) | Sui Bridge + Wormhole helpers |
| Kiosk | [`packages/kiosk`](./packages/kiosk) | Kiosk SDK wrappers |
| Indexer | [`packages/indexer`](./packages/indexer) | Event indexer over Sui RPC + GraphQL |
| Post-quantum | [`packages/pqc`](./packages/pqc) + [`move/wots`](./move/wots) + [`move/slh_dsa`](./move/slh_dsa) + [`move/pq_guard`](./move/pq_guard) + [`move/pq_vault`](./move/pq_vault) + [`move/pq_attestation`](./move/pq_attestation) | ML-DSA / SLH-DSA / FALCON / ML-KEM off-chain; **on-chain SLH-DSA-LITE verification in Move**; **contract-layer PQ authorization** (replay-safe, action-bound); PQ-sponsored gas via `pnpm cli sponsor-serve`; local-validator patches in [`patches/`](./patches) — see [`docs/local-pq-validator.md`](./docs/local-pq-validator.md) |
| Web dApp | [`apps/web`](./apps/web) | Next.js app showcasing wallet connect, Walrus, Seal, zkLogin |
| Tutorial | [`apps/tutorial`](./apps/tutorial) | Standalone server: 14 MDX lessons + live testnet demos |
| CLI | [`apps/cli`](./apps/cli) | TS scripts for common ops (faucet, publish, query) |

## Prerequisites

- **Node** ≥ 22 (this workspace is tested on 25)
- **pnpm** ≥ 10
- **Rust** stable (for building Sui / Walrus CLIs from source if needed)
- **Sui CLI** — install via `pnpm setup:sui`
- **Walrus CLI** — install via `pnpm setup:walrus`

## Quick start

```bash
# One-shot setup: installs Sui + Walrus CLIs, configures testnet, drips faucet
# (Use `bootstrap` — `pnpm setup` is reserved by pnpm itself for PNPM_HOME config.)
pnpm bootstrap

# Install dependencies
pnpm install

# Build everything
pnpm build

# Run tests
pnpm test

# Lint
pnpm lint

# Run the dev servers (web on :3000, tutorial on :3030)
pnpm servers:start           # both, backgrounded
pnpm tutorial:open           # open tutorial in your browser
pnpm servers:status          # see liveness + port state
pnpm tutorial:logs           # tail-f the captured log
pnpm servers:stop            # SIGTERM + cleanup

# (Per-app: `pnpm web:start`, `pnpm web:stop`, `pnpm tutorial:restart`, etc.)

# Or run them attached, the old-fashioned way:
pnpm --filter @sui-gen/web dev
pnpm --filter @sui-gen/tutorial dev

# Publish a Move package to testnet
pnpm cli publish move/counter
```

## Networks

| Name | RPC | Faucet |
| --- | --- | --- |
| `mainnet` | `https://fullnode.mainnet.sui.io:443` | n/a |
| `testnet` | `https://fullnode.testnet.sui.io:443` | `https://faucet.testnet.sui.io/v2/gas` |
| `devnet`  | `https://fullnode.devnet.sui.io:443`  | `https://faucet.devnet.sui.io/v2/gas`  |
| `localnet`| `http://127.0.0.1:9000` | `http://127.0.0.1:9123/v2/gas` |

Switch network via `SUI_NETWORK=testnet` (default) or per-command `--network`.

## Documentation

Per-area deep dives live under [`docs/`](./docs):

- [Architecture](./docs/architecture.md)
- [Slush wallet integration](./docs/slush.md)
- [Walrus protocol](./docs/walrus.md)
- [Seal secrets](./docs/seal.md)
- [Lumiwave](./docs/lumiwave.md)
- [zkLogin](./docs/zk-login.md)
- [DeepBook](./docs/deepbook.md)
- [Sponsored transactions](./docs/sponsored-tx.md)
- [Move conventions](./docs/move.md)
- [Post-quantum cryptography](./docs/post-quantum.md) — off-chain `@sui-gen/pqc`, on-chain `wots`/`slh_dsa`/`pq_guard`
- [Local PQ validator fork](./docs/local-pq-validator.md) — patch + build script for a Sui node that natively verifies SLH-DSA-LITE
- [Mysten-side PQ validator roadmap](./docs/pq-validator-roadmap.md) — the upstream changes that would close the last remaining gap
- [Formal verification](./VERIFICATION.md) — the FIPS-205 verifier, machine-checked in Lean 4 ([`proofs/`](./proofs)): spec ≡ noble/NIST KATs, a 100%-bytecode verifier, and every compiled `sha2_128s.mv` function proven ≡ spec opcode-for-opcode (403 theorems)

## License

MIT
