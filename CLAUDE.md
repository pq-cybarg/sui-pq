# sui-gen — agent guide

A monorepo for the Sui ecosystem. Don't recreate the architecture overview — read
[`docs/architecture.md`](./docs/architecture.md). This file tells future agents how to
work in this repo without re-deriving conventions.

## Layout

- `move/` — independent Move packages (each has its own `Move.toml`)
- `packages/` — ESM TypeScript libraries (`@sui-gen/*`), built with `tsc -b`
- `apps/web` — Next.js 15 / App Router demo dApp
- `apps/cli` — `cac`-based CLI exposing common operations
- `scripts/` — bash helpers, mostly bootstrapping (Sui CLI, Walrus CLI, faucet)

## Always

- Use `pnpm` (workspaces); never `npm install` or `yarn`.
- Cross-package imports go through `@sui-gen/<pkg>`, never relative paths across package boundaries.
- Add the package to `apps/web/package.json` and `apps/cli/package.json` when introducing a new `packages/*` dep used by either app.
- New packages need a `tsconfig.json` extending `../../tsconfig.base.json` with `composite: true`, plus an entry in the root `tsconfig.json` references array.

## Never

- Don't import from `@mysten/sui/*` deep paths in the apps directly — go through `@sui-gen/sdk-core` or `@sui-gen/wallet-kit` so the apps stay isolated from SDK upgrades.
- Don't commit `.env`, `sui_config/`, or any `keystore.json`. `.gitignore` already covers these.
- Don't pin a Move dependency to `framework/main` — use `framework/mainnet` for stability.

## Versions & networks

- **Move framework**: `framework/mainnet`
- **Default network**: `testnet` (set via `SUI_NETWORK` / `NEXT_PUBLIC_SUI_NETWORK`)
- **TS target**: ES2023, ESM-only
- **React**: 19 for the web app

## Common tasks

```bash
pnpm setup          # install Sui + Walrus CLIs, configure testnet, faucet, pnpm install
pnpm build          # tsc -b across all packages
pnpm test           # vitest run across all packages
pnpm move:test      # sui move test across move/*
pnpm cli publish move/counter   # convenience wrapper
```

## When adding a new ecosystem package

1. `mkdir packages/<name>/src`
2. Copy the structure of an existing package's `package.json` + `tsconfig.json`.
3. Export from `src/index.ts`.
4. Add to the references list in `/tsconfig.json`.
5. Add a `docs/<name>.md` deep-dive.
6. Update README's "What's inside" table.
