# @sui-gen/tutorial

Interactive, server-rendered tutorial that walks through the entire Sui stack
from zero. Each of the 14 lessons is an MDX page with embedded "Try it" demos
that execute against live testnet.

## Run it

```bash
pnpm --filter @sui-gen/tutorial dev
# → http://localhost:3030
```

Static build:

```bash
pnpm --filter @sui-gen/tutorial build
pnpm --filter @sui-gen/tutorial start
```

## Sections

1. **Setup** — sui + walrus CLIs, testnet config, gas
2. **Move basics** — objects, abilities, the counter contract
3. **Publishing** — sources → package id, gas budgets
4. **TypeScript SDK** — SuiClient, Transaction, signers
5. **Slush wallet** — dApp Kit, ConnectButton, signing in the browser
6. **Walrus storage** — public publisher + wallet-paid uploads
7. **Seal secrets** — threshold encryption gated by on-chain Move logic
8. **zkLogin** — OAuth → Sui address with no key custody
9. **DeepBook** — first-party CLOB, on-chain limit orders
10. **Sponsored tx** — gasless flows
11. **Kiosk + NFTs** — Display, royalties, the canonical NFT pattern
12. **Lumiwave** — LWA token + partner service API
13. **Indexer** — events, polling, GraphQL
14. **Capstone** — Walrus + Sui composed: mint an NFT from a Walrus blob

## Live interactive demos

Each demo writes to (or reads from) the live testnet packages that the workspace
bootstraps:

- `TryWallet` — Wallet Standard handshake (any installed wallet works)
- `TryBalance` — `useSuiClient().getBalance()` on the connected address
- `TryCounter` — increment a shared counter, wallet-signed
- `TryWalrus` — upload + download a blob via the public publisher
- `TryDeepBookSnapshot` — fetch orderbook snapshot from the public indexer
- `TryEvents` — stream `Incremented` events live (polls every 8s)
- `TryMintNft` — upload to Walrus + mint a `GenesisNFT` in one flow

## Architecture

Built on Next.js 15 + MDX + the workspace's `@sui-gen/wallet-kit` and
`@sui-gen/walrus-client` packages. Tutorial state (which sections you've
completed) is kept in `localStorage` and surfaces as ✓ checkmarks in the
sidebar — no auth, no database.

The deployed testnet artifacts the demos rely on are pinned in
`src/lib/deployed.ts`; redeploy your own copies with
`pnpm cli publish move/<package>` and update the constants.
