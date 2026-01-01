'use client';
import { useActiveAddress, useSuiClient } from '@sui-gen/wallet-kit';
import { useEffect, useState } from 'react';

export function TryBalance() {
  const address = useActiveAddress();
  const client = useSuiClient();
  const [bal, setBal] = useState<string | null>(null);
  const [err, setErr] = useState<string | null>(null);

  useEffect(() => {
    if (!address) return;
    setErr(null);
    client
      .getBalance({ owner: address })
      .then((b) => setBal(`${(Number(b.totalBalance) / 1e9).toFixed(4)} SUI`))
      .catch((e) => setErr(String(e)));
  }, [address, client]);

  return (
    <div className="card">
      <h3 style={{ margin: '0 0 0.5rem' }}>Try it: read your testnet balance</h3>
      <p className="muted" style={{ marginTop: 0 }}>
        One read, no signing required. Powered by <code>useSuiClient().getBalance()</code>.
      </p>
      {!address && <span className="chip warn">connect a wallet to enable</span>}
      {bal && <div className="result ok">{bal}</div>}
      {err && <div className="result bad">{err}</div>}
    </div>
  );
}
