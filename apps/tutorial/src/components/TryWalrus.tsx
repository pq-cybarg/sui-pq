'use client';
import { WalrusHttpClient } from '@sui-gen/walrus-client/http';
import { useState } from 'react';

const client = new WalrusHttpClient({
  publisher: 'https://publisher.walrus-testnet.walrus.space',
  aggregator: 'https://aggregator.walrus-testnet.walrus.space',
});

export function TryWalrus() {
  const [text, setText] = useState('Hello from the sui-gen tutorial.');
  const [blobId, setBlobId] = useState<string | null>(null);
  const [fetched, setFetched] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);

  async function upload() {
    setBusy(true);
    setErr(null);
    setFetched(null);
    try {
      const res = await client.put(text, { epochs: 2 });
      setBlobId(res.blobId);
    } catch (e) {
      setErr(String(e));
    } finally {
      setBusy(false);
    }
  }
  async function download() {
    if (!blobId) return;
    setBusy(true);
    setErr(null);
    try {
      setFetched(await client.getText(blobId));
    } catch (e) {
      setErr(String(e));
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="card">
      <h3 style={{ margin: '0 0 0.5rem' }}>Try it: upload + download a Walrus blob</h3>
      <p className="muted" style={{ marginTop: 0 }}>
        The public testnet publisher pays the WAL storage cost (rate-limited, fine for prototypes).
      </p>
      <label htmlFor="walrus-text" className="muted" style={{ fontSize: '0.8rem' }}>
        content
      </label>
      <textarea
        id="walrus-text"
        rows={3}
        value={text}
        onChange={(e) => setText(e.target.value)}
        style={{
          width: '100%',
          background: 'var(--code-bg)',
          color: 'var(--fg)',
          border: '1px solid var(--border)',
          borderRadius: 6,
          padding: '0.5rem 0.75rem',
          font: 'inherit',
          fontSize: '0.9rem',
        }}
      />
      <div style={{ display: 'flex', gap: '0.5rem', marginTop: '0.5rem' }}>
        <button type="button" className="primary" onClick={upload} disabled={busy}>
          upload
        </button>
        <button type="button" className="ghost" onClick={download} disabled={!blobId || busy}>
          download
        </button>
      </div>
      {blobId && (
        <div className="result ok">
          blobId: {blobId}
          {'\n'}aggregator url: {client.url(blobId)}
        </div>
      )}
      {fetched && <div className="result">{fetched}</div>}
      {err && <div className="result bad">{err}</div>}
    </div>
  );
}
