# Lumiwave

[Lumiwave](https://lumiwave.io) is a Web3 entertainment platform that issues the LWA token on Sui and exposes a partner service API for game integrations, NFT drops, and IP licensing.

## What this package gives you

`@sui-gen/lumiwave` is **transport-only**: it doesn't try to guess Lumiwave's evolving REST schema. Instead, it gives you:

1. A **coin-type indirection** so you can change the LWA `0xPKG::lwa::LWA` address via `LUMIWAVE_COIN_TYPE` without touching code.
2. Helpers for balance lookups, transfers, and metadata (works for any Sui Coin<T>, defaulting to LWA).
3. A thin `LumiwaveService` HTTP client with bearer-token auth, ready to be extended with typed wrappers for whichever endpoints you actually use (`/v1/users/:handle`, partner mint endpoints, etc.).

## Usage

```ts
import { DEFAULT_LUMIWAVE_CONFIG, getLwaBalance, buildLwaTransfer, LumiwaveService } from '@sui-gen/lumiwave';

const balance = await getLwaBalance('0x…');
// → bigint, in base units (divide by 10^decimals for display)

const tx = await buildLwaTransfer({
  from: signer.toSuiAddress(),
  to: '0xrecipient…',
  amount: 1_000_000n,
});

const lumi = new LumiwaveService({ apiKey: process.env.LUMIWAVE_API_KEY });
const user = await lumi.resolveHandle('alice');
```

## Configuration

Set these env vars (or pass them to `LumiwaveService`):

```bash
LUMIWAVE_COIN_TYPE=0xPKG::lwa::LWA           # canonical Sui coin type
LUMIWAVE_RPC_URL=https://rpc-mainnet.lumiwave.io
LUMIWAVE_API_KEY=lwk_xxx                      # partner API key, if you have one
```

The default `coinType` is a zero placeholder — point it at the real Lumiwave package id (Suiscan: search for "LWA") before running on mainnet.

## Ecosystem notes

- **Wallets.** Slush, Suiet, Phantom all surface LWA in the same way as any custom coin once `CoinMetadata` is published.
- **Game SDK.** Lumiwave ships a Unity package + REST SDK for game studios; treat this TS package as the gateway between that SDK and your dApp.
- **NFTs.** Lumiwave issues entertainment NFTs via the standard Sui `Display` flow — reuse the `move/nft` template.
