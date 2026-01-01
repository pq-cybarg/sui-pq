'use client';
import { SuiKitProvider } from '@sui-gen/wallet-kit';
import type { ReactNode } from 'react';

export function Providers({ children }: { children: ReactNode }) {
  const network = (process.env.NEXT_PUBLIC_SUI_NETWORK ?? 'testnet') as
    | 'mainnet'
    | 'testnet'
    | 'devnet'
    | 'localnet';
  return <SuiKitProvider defaultNetwork={network}>{children}</SuiKitProvider>;
}
