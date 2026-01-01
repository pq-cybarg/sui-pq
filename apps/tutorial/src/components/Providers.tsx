'use client';
import { SuiKitProvider } from '@sui-gen/wallet-kit';
import type { ReactNode } from 'react';

export function Providers({ children }: { children: ReactNode }) {
  return <SuiKitProvider defaultNetwork="testnet">{children}</SuiKitProvider>;
}
