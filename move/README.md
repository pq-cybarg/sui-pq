# Move packages

Each subdirectory is an independent `sui move` package. Build/test all of them at once with:

```bash
pnpm move:build
pnpm move:test
```

Or per-package:

```bash
cd move/counter && sui move build && sui move test
```

| Package | What it shows |
| --- | --- |
| `counter` | Shared object + entry functions + events + owner-only authz |
| `nft` | One-time witness → `Publisher` → `Display` → `transfer::public_transfer` (canonical NFT pattern) |
| `coin` | Regulated fungible token via `coin::create_currency` + `TreasuryCap` |
| `kiosk` | Royalty `TransferPolicy` rule for marketplace flows |
| `deepbook_client` | Scaffolding for calling DeepBook V3 from your package |
| `seal_demo` | `seal_approve` entry function — gates Seal threshold decryption against an allowlist |

After publishing a package (`sui client publish --gas-budget 200000000`), the resulting `packageId` should be plumbed into the TypeScript side via `.env` (see `.env.example`) or constructor args.
