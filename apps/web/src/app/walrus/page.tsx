'use client';
import { WalrusHttpClient } from '@sui-gen/walrus-client';
import { useState } from 'react';

export default function WalrusPage() {
  const [text, setText] = useState('Hello from sui-gen!');
  const [blobId, setBlobId] = useState<string | null>(null);
  const [fetched, setFetched] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);

  const client = new WalrusHttpClient({
    publisher:
      process.env.NEXT_PUBLIC_WALRUS_PUBLISHER_URL ??
      'https://publisher.walrus-testnet.walrus.space',
    aggregator:
      process.env.NEXT_PUBLIC_WALRUS_AGGREGATOR_URL ??
      'https://aggregator.walrus-testnet.walrus.space',
  });

  async function upload() {
    setBusy(true);
    setErr(null);
    try {
      const res = await client.put(text, { epochs: 5 });
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
    <main style={{ maxWidth: 720, margin: '4rem auto', padding: '0 1rem' }}>
      <h1>Walrus</h1>
      <p className="muted">Upload to the testnet publisher and download from the aggregator.</p>

      <div className="card" style={{ marginTop: '1rem' }}>
        <label htmlFor="walrus-text">Text to upload</label>
        <textarea
          id="walrus-text"
          rows={4}
          value={text}
          onChange={(e) => setText(e.target.value)}
        />
        <div style={{ marginTop: '0.5rem' }}>
          <button type="button" onClick={upload} disabled={busy}>
            Upload
          </button>
        </div>
        {blobId && (
          <div style={{ marginTop: '1rem' }}>
            <div className="muted">Blob id</div>
            <code style={{ wordBreak: 'break-all' }}>{blobId}</code>
            <div style={{ marginTop: '0.5rem' }}>
              <button type="button" onClick={download} disabled={busy}>
                Download
              </button>
            </div>
          </div>
        )}
        {fetched && (
          <div style={{ marginTop: '1rem' }}>
            <div className="muted">Fetched</div>
            <pre>{fetched}</pre>
          </div>
        )}
        {err && <p style={{ color: '#ff6b6b' }}>{err}</p>}
      </div>
    </main>
  );
}
