# DeepBook V3

DeepBook is Sui's first-party central limit orderbook, built into the Sui framework. It supports limit / market orders, post-only, fill-or-kill, and is composable from Move modules.

## TS side

```ts
import { createDeepBookClient } from '@sui-gen/deepbook';

const db = createDeepBookClient({
  address: signer.toSuiAddress(),
  network: 'mainnet',
  balanceManagers: {
    SUI_USDC: { address: '0xmybalancemanager…' },
  },
});

const tx = new Transaction();
db.placeLimitOrder({
  poolKey: 'SUI_USDC',
  balanceManagerKey: 'SUI_USDC',
  clientOrderId: '1',
  price: 2.50,
  quantity: 100,
  isBid: true,
  payWithDeep: false,
})(tx);
```

## Indexer

`getOrderbookSnapshot('SUI_USDC')` queries the public Mysten Labs DeepBook indexer. It returns
sorted bid/ask levels and a server timestamp — handy for charting without running your own
indexer.

## Move side

If your package wants to route through DeepBook, depend on `deepbookv3` in `Move.toml` and call:

```move
let trade_proof = balance_manager::generate_proof_as_trader(balance_manager, trade_cap, ctx);
pool::place_limit_order(pool, balance_manager, &trade_proof, /* … */);
```

See `move/deepbook_client` for the scaffolding.
