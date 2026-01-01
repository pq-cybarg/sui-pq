import { SuiClientProvider, WalletProvider, createNetworkConfig } from '@mysten/dapp-kit';
import { NETWORKS, type Network } from '@sui-gen/sdk-core';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import type { ReactNode } from 'react';
import '@mysten/dapp-kit/dist/index.css';

const { networkConfig } = createNetworkConfig({
  mainnet: { url: NETWORKS.mainnet.url },
  testnet: { url: NETWORKS.testnet.url },
  devnet: { url: NETWORKS.devnet.url },
  localnet: { url: NETWORKS.localnet.url },
});

export interface SuiKitProviderProps {
  children: ReactNode;
  /** Default network. Users can still switch via `useSwitchAccount`. */
  defaultNetwork?: Network;
  /** Auto-connect to the previously selected wallet on mount. Defaults to true. */
  autoConnect?: boolean;
  /** Show only these wallets, in this order. Slush is always preferred when installed. */
  preferredWallets?: string[];
  /** Override the inner QueryClient if your app already provides one. */
  queryClient?: QueryClient;
}

const DEFAULT_PREFERRED = [
  'Slush — A Sui wallet',
  'Slush',
  'Sui Wallet',
  'Suiet',
  'Phantom',
  'Nightly',
  'OKX Wallet',
];

/**
 * One-shot provider for any React app: Query → SuiClient → Wallet.
 * Drop into your root layout and you're done.
 */
export function SuiKitProvider({
  children,
  defaultNetwork = 'testnet',
  autoConnect = true,
  preferredWallets = DEFAULT_PREFERRED,
  queryClient,
}: SuiKitProviderProps) {
  const qc = queryClient ?? new QueryClient();
  return (
    <QueryClientProvider client={qc}>
      <SuiClientProvider networks={networkConfig} defaultNetwork={defaultNetwork}>
        <WalletProvider autoConnect={autoConnect} preferredWallets={preferredWallets}>
          {children}
        </WalletProvider>
      </SuiClientProvider>
    </QueryClientProvider>
  );
}
