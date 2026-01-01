'use client';
import { DEFAULT_LUMIWAVE_CONFIG, getLwaBalance } from '@sui-gen/lumiwave';
import { useActiveAddress } from '@sui-gen/wallet-kit';
import { useState } from 'react';

export default function LumiwavePage() {
  const address = useActiveAddress();
  const [balance, setBalance] = useState<string | null>(null);
  const [err, setErr] = useState<string | null>(null);

  async function load() {
    if (!address) return;
    setErr(null);
    try {
      const bal = await getLwaBalance(address);
      setBalance(bal.toString());
    } catch (e) {
      setErr(String(e));
    }
  }

  return (
    <main style={{ maxWidth: 720, margin: '4rem auto', padding: '0 1rem' }}>
      <h1>Lumiwave</h1>
      <p className="muted">LWA token balance for the connected wallet.</p>
      <p className="muted">
        Coin type: <code>{DEFAULT_LUMIWAVE_CONFIG.coinType}</code>
      </p>
      <button type="button" onClick={load} disabled={!address}>
        Refresh
      </button>
      {balance !== null && <p>Balance: {balance}</p>}
      {err && <p style={{ color: '#ff6b6b' }}>{err}</p>}
    </main>
  );
}
