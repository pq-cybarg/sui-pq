import { Providers } from '@/components/Providers';
import { Sidebar } from '@/components/Sidebar';
import type { ReactNode } from 'react';
import './globals.css';

export const metadata = {
  title: 'sui-gen tutorial',
  description: 'Build on Sui from zero — every primitive, end-to-end, on live testnet.',
};

export default function RootLayout({ children }: { children: ReactNode }) {
  return (
    <html lang="en">
      <body>
        <Providers>
          <div className="app">
            <Sidebar />
            <main className="main">
              <div className="content">{children}</div>
            </main>
          </div>
        </Providers>
      </body>
    </html>
  );
}
