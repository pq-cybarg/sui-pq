'use client';
import { getOrderbookSnapshot } from '@sui-gen/deepbook';
import { useState } from 'react';

export default function DeepBookPage() {
  const [pool, setPool] = useState('SUI_USDC');
  const [snapshot, setSnapshot] = useState<unknown>(null);
  const [err, setErr] = useState<string | null>(null);

  async function load() {
    setErr(null);
    try {
      setSnapshot(await getOrderbookSnapshot(pool));
    } catch (e) {
      setErr(String(e));
    }
  }

  return (
    <main style={{ maxWidth: 720, margin: '4rem auto', padding: '0 1rem' }}>
      <h1>DeepBook</h1>
      <p className="muted">Read orderbook snapshots from the public DeepBook indexer.</p>
      <input value={pool} onChange={(e) => setPool(e.target.value)} placeholder="SUI_USDC" />
      <div style={{ marginTop: '0.5rem' }}>
        <button type="button" onClick={load}>
          Snapshot
        </button>
      </div>
      {snapshot != null && (
        <pre style={{ maxHeight: 400, overflow: 'auto' }}>{JSON.stringify(snapshot, null, 2)}</pre>
      )}
      {err && <p style={{ color: '#ff6b6b' }}>{err}</p>}
    </main>
  );
}
