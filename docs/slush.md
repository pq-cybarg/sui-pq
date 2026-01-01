# Slush wallet integration

Slush is Mysten Labs' first-party Sui wallet (renamed from "Sui Wallet" in 2024 and again to "Slush — A Sui wallet" in early 2025). It implements the [Wallet Standard](https://github.com/wallet-standard/wallet-standard), so any app using `@mysten/dapp-kit` will detect it automatically alongside Suiet, Phantom, Nightly, and OKX.

## Drop-in setup

```tsx
import { SuiKitProvider, ConnectButton, useActiveAddress } from '@sui-gen/wallet-kit';

export default function RootLayout({ children }) {
  return <SuiKitProvider defaultNetwork="testnet">{children}</SuiKitProvider>;
}

export function Page() {
  const address = useActiveAddress();
  return (
    <>
      <ConnectButton />
      {address && <p>Connected: {address}</p>}
    </>
  );
}
```

The provider configures, in this order:

1. `QueryClientProvider` (TanStack Query) — required by dApp Kit.
2. `SuiClientProvider` — multi-network config with sane defaults from `sdk-core/networks`.
3. `WalletProvider` — auto-connect on mount, with `preferredWallets` ordered so Slush appears first.

## Signing a transaction

```tsx
import { Transaction } from '@mysten/sui/transactions';
import { useSignAndExecuteTransaction } from '@sui-gen/wallet-kit';

const { mutate: signAndExecute } = useSignAndExecuteTransaction();

function send() {
  const tx = new Transaction();
  const [coin] = tx.splitCoins(tx.gas, [1_000_000n]);
  tx.transferObjects([coin], '0xrecipient...');
  signAndExecute({ transaction: tx });
}
```

## Slush-specific features

- **Account discovery.** Slush exposes multiple addresses per install; `useAccounts()` enumerates them and `useSwitchAccount()` switches.
- **dApp permissions.** Slush surfaces a per-origin permission UI — your app should call `useDisconnectWallet()` rather than just clearing state.
- **Mobile.** Slush mobile supports WalletConnect; pass a Mysten-provided `walletConnectProjectId` to `<WalletProvider>` to enable QR pairing.

## Detection table

| Wallet | `wallet.name` | Notes |
| --- | --- | --- |
| Slush  | `Slush — A Sui wallet` | Also reports legacy `Sui Wallet` alias |
| Suiet  | `Suiet` | |
| Phantom| `Phantom` | Added Sui support in 2024 |
| Nightly| `Nightly` | |
| OKX    | `OKX Wallet` | |

The `RECOMMENDED_WALLETS` constant in `@sui-gen/wallet-kit/wallets` carries Chrome Web Store links so you can show install hints when no compatible wallet is present.
