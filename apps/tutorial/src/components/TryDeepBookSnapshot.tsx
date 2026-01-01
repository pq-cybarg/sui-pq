'use client';
import { useState } from 'react';

const INDEXER = 'https://deepbook-indexer.mainnet.mystenlabs.com';

export function TryDeepBookSnapshot() {
  const [pool, setPool] = useState('SUI_USDC');
  const [data, setData] = useState<unknown>(null);
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);

  async function load() {
    setBusy(true);
    setErr(null);
    setData(null);
    try {
      const res = await fetch(`${INDEXER}/get_order_book/${encodeURIComponent(pool)}`);
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      setData(await res.json());
    } catch (e) {
      setErr(String(e));
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="card">
      <h3 style={{ margin: '0 0 0.5rem' }}>Try it: DeepBook orderbook snapshot</h3>
      <p className="muted" style={{ marginTop: 0 }}>
        Reads from the public Mysten DeepBook indexer (mainnet). Try <code>SUI_USDC</code>,
        <code> DEEP_SUI</code>, <code>WUSDC_USDC</code>.
      </p>
      <div style={{ display: 'flex', gap: '0.5rem' }}>
        <input
          value={pool}
          onChange={(e) => setPool(e.target.value)}
          style={{
            background: 'var(--code-bg)',
            color: 'var(--fg)',
            border: '1px solid var(--border)',
            borderRadius: 6,
            padding: '0.4rem 0.7rem',
            flex: 1,
          }}
        />
        <button type="button" className="primary" onClick={load} disabled={busy}>
          {busy ? '…' : 'snapshot'}
        </button>
      </div>
      {data != null && (
        <div className="result" style={{ maxHeight: 240, overflow: 'auto' }}>
          {JSON.stringify(data, null, 2).slice(0, 1800)}
        </div>
      )}
      {err && <div className="result bad">{err}</div>}
    </div>
  );
}
