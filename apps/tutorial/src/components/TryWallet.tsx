'use client';
import { ConnectButton, useActiveAddress, useCurrentWallet } from '@sui-gen/wallet-kit';

export function TryWallet() {
  const address = useActiveAddress();
  const { currentWallet } = useCurrentWallet();
  return (
    <div className="card">
      <h3 style={{ margin: '0 0 0.75rem' }}>Try it</h3>
      <p className="muted" style={{ marginTop: 0 }}>
        Connect Slush (or Suiet / Phantom / Nightly / OKX). Nothing is sent — this is just the
        Wallet Standard handshake. dApp Kit detects every installed wallet automatically.
      </p>
      <ConnectButton />
      {address && (
        <div className="result ok" style={{ marginTop: '0.75rem' }}>
          ✓ wallet: <strong>{currentWallet?.name}</strong>
          {'\n'}✓ address: {address}
        </div>
      )}
    </div>
  );
}
