# Architecture

```
┌──────────────────────────────────────────────────────────────────────────┐
│                              apps/web (Next.js)                          │
│  pages: /, /walrus, /seal, /zk-login, /lumiwave, /deepbook               │
└────────────┬─────────────────────────────────────────────────────────────┘
             │ React/dApp-Kit
             ▼
┌──────────────────────────────────────────────────────────────────────────┐
│                            packages/wallet-kit                           │
│   <SuiKitProvider>  ConnectButton  useActiveAddress  useSignAndExecute…  │
└────┬──────────────────────────────────────────────────────────────────┬──┘
     │                                                                   │
     ▼                                                                   ▼
┌─────────────────────┐  ┌──────────────────┐  ┌──────────────────────────┐
│  packages/sdk-core  │  │ packages/walrus  │  │   packages/seal-client   │
│   client, signers,  │  │   http + sui     │  │ encrypt/decrypt + ident. │
│   tx, bcs, faucet   │  │      client      │  │  + key-server registry   │
└──────────┬──────────┘  └──────────────────┘  └──────────────────────────┘
           │
           ▼
┌──────────────────────────────────────────────────────────────────────────┐
│  Move packages: counter | nft | coin | kiosk | deepbook_client | seal_demo│
└──────────────────────────────────────────────────────────────────────────┘
```

## Why a monorepo

Every ecosystem package shares the same TypeScript baseline, the same
`SuiClient`/`Signer` types, and the same network resolution logic. Keeping them
side-by-side means refactors stay atomic (e.g. updating to a new `@mysten/sui`
release happens in one commit) and the apps can import everything via
`workspace:*` without publishing.

## Package conventions

- Each package is ESM-only (`"type": "module"`, `"module": "ESNext"`).
- Source under `src/`, build output under `dist/`.
- Tests live next to source as `*.test.ts` and run via `vitest`.
- The package's main entry re-exports its public surface in `index.ts`.
- Cross-package imports use the published name (`@sui-gen/sdk-core`) — never relative paths.

## Network conventions

`resolveNetwork()` (in `sdk-core`) is the single source of truth. It reads
`SUI_NETWORK` (server) or `NEXT_PUBLIC_SUI_NETWORK` (browser) and validates
against `mainnet | testnet | devnet | localnet`. All other packages accept a
`network?: Network` opt and default to that.
