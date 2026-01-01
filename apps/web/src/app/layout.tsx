import { Providers } from '@/components/providers';
import type { ReactNode } from 'react';
import './globals.css';

export const metadata = {
  title: 'sui-gen',
  description: 'Comprehensive Sui ecosystem demo dApp',
};

export default function RootLayout({ children }: { children: ReactNode }) {
  return (
    <html lang="en">
      <body>
        <Providers>{children}</Providers>
      </body>
    </html>
  );
}
