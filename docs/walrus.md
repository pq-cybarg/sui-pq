# Walrus

Walrus is Mysten Labs' decentralized storage protocol. Blobs are erasure-coded into slivers, stored across a network of storage nodes, and their lifetime/state is tracked on Sui. WAL is the native token paid for storage.

## Two clients, two trust models

`@sui-gen/walrus-client` exposes both:

| Client | Pays storage | Use when |
| --- | --- | --- |
| `WalrusHttpClient` | The public publisher (rate-limited, dev-friendly) | Prototyping, demos, ephemeral data |
| `WalrusClient` (from `@mysten/walrus`) | Your signer's WAL | Production, where you control storage cost & lifetime |

```ts
import { WalrusHttpClient } from '@sui-gen/walrus-client';

const client = new WalrusHttpClient();
const { blobId } = await client.put('hello, walrus', { epochs: 5 });
const text = await client.getText(blobId);
```

## Wallet-paid uploads

```ts
import { createWalrusClient } from '@sui-gen/walrus-client';
import { signerFromEnv } from '@sui-gen/sdk-core';

const walrus = createWalrusClient({ network: 'testnet' });
const signer = signerFromEnv();
const { blobId } = await walrus.writeBlob({
  blob: new TextEncoder().encode('hello'),
  deletable: false,
  epochs: 5,
  signer,
});
```

## Reading blobs in the browser

Aggregators serve blobs over plain HTTP, so you can use `<img src>` / `<video src>` directly:

```tsx
const url = client.url(blobId);
<img src={url} alt="" />
```

## Costs

- Storage fee is denominated in WAL and scales with `epochs × size`.
- Each testnet epoch is ≈ 1 day; mainnet epochs are 2 weeks.
- The publisher pays the cost on your behalf when using `WalrusHttpClient` — that's why it's rate-limited.
- Use `pnpm setup:walrus` to install the `walrus` CLI for diagnostics (`walrus blob-status <id>`).

## Move-side reference

The Walrus `Blob` object has `key`, `id`, `registered_epoch`, `cert_epoch`, `storage`. You can read blob state from Move via the published Walrus package id — pin the version once you go to mainnet.
