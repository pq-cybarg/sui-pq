'use client';
import { DEPLOYED, suiscan } from '@/lib/deployed';
import { useSuiClient } from '@sui-gen/wallet-kit';
import { useEffect, useState } from 'react';

interface Ev {
  digest: string;
  by: string;
  value: string;
  timestampMs?: string;
}

export function TryEvents() {
  const client = useSuiClient();
  const [events, setEvents] = useState<Ev[]>([]);
  const [err, setErr] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    let mounted = true;
    async function load() {
      try {
        const page = await client.queryEvents({
          query: {
            MoveEventType: `${DEPLOYED.counter.packageId}::counter::Incremented`,
          },
          limit: 8,
          order: 'descending',
        });
        if (!mounted) return;
        setEvents(
          page.data.map((e) => ({
            digest: e.id.txDigest,
            value: String((e.parsedJson as { value?: string })?.value ?? '?'),
            by: String((e.parsedJson as { by?: string })?.by ?? '?'),
            timestampMs: e.timestampMs ?? undefined,
          })),
        );
      } catch (e) {
        setErr(String(e));
      } finally {
        setLoading(false);
      }
    }
    load();
    const id = setInterval(load, 8000);
    return () => {
      mounted = false;
      clearInterval(id);
    };
  }, [client]);

  return (
    <div className="card">
      <h3 style={{ margin: '0 0 0.5rem' }}>Live: Counter::Incremented events</h3>
      <p className="muted" style={{ marginTop: 0 }}>
        Last 8 increments across all users on testnet (refreshed every 8s). Anyone clicking +1
        anywhere will appear here.
      </p>
      {loading && <span className="chip">loading…</span>}
      {err && <div className="result bad">{err}</div>}
      {events.length > 0 && (
        <div className="result" style={{ maxHeight: 280, overflow: 'auto' }}>
          {events.map((e) => (
            <div
              key={e.digest}
              style={{
                marginBottom: '0.6rem',
                paddingBottom: '0.4rem',
                borderBottom: '1px solid var(--border)',
              }}
            >
              <div>
                <span style={{ color: 'var(--accent)' }}>value={e.value}</span>{' '}
                <span style={{ color: 'var(--muted)' }}>
                  by {e.by.slice(0, 10)}…{e.by.slice(-6)}
                </span>
              </div>
              <div style={{ fontSize: '0.75rem', color: 'var(--muted)' }}>
                {e.timestampMs && new Date(Number(e.timestampMs)).toLocaleString()}
                {' · '}
                <a
                  href={`https://suiscan.xyz/testnet/tx/${e.digest}`}
                  target="_blank"
                  rel="noreferrer"
                >
                  tx {e.digest.slice(0, 10)}…
                </a>
              </div>
            </div>
          ))}
        </div>
      )}
      <p className="muted" style={{ fontSize: '0.8rem', marginTop: '0.5rem' }}>
        <a href={suiscan(DEPLOYED.counter.objectId)} target="_blank" rel="noreferrer">
          counter object on Suiscan ↗
        </a>
      </p>
    </div>
  );
}
