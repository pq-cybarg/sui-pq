'use client';

import { Transaction } from '@mysten/sui/transactions';
import {
  ConnectButton,
  useActiveAddress,
  useSignAndExecuteTransaction,
  useSuiClient,
  useSuiClientQuery,
} from '@sui-gen/wallet-kit';
import { useState } from 'react';

const PKG = process.env.NEXT_PUBLIC_COUNTER_PACKAGE_ID ?? '';

export default function CounterPage() {
  const address = useActiveAddress();
  const suiClient = useSuiClient();
  const [counterId, setCounterId] = useState<string>(
    () =>
      (typeof window !== 'undefined' && window.localStorage.getItem('counter-id')) ||
      process.env.NEXT_PUBLIC_COUNTER_OBJECT_ID ||
      '',
  );
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);

  const { data, refetch, isFetching } = useSuiClientQuery(
    'getObject',
    { id: counterId, options: { showContent: true } },
    { enabled: counterId.length > 0 },
  );

  const { mutateAsync: signAndExecute } = useSignAndExecuteTransaction();

  const value =
    data?.data?.content?.dataType === 'moveObject'
      ? ((data.data.content.fields as { value?: string }).value ?? '0')
      : null;

  async function create() {
    if (!PKG) return setErr('NEXT_PUBLIC_COUNTER_PACKAGE_ID not set');
    setBusy(true);
    setErr(null);
    try {
      const tx = new Transaction();
      tx.moveCall({ target: `${PKG}::counter::create` });
      const res = await signAndExecute({ transaction: tx });
      // Look up the created Counter object id
      const full = await suiClient.waitForTransaction({
        digest: res.digest,
        options: { showObjectChanges: true },
      });
      const created = full.objectChanges?.find(
        (c) => c.type === 'created' && c.objectType.includes('::counter::Counter'),
      );
      if (created && 'objectId' in created) {
        setCounterId(created.objectId);
        window.localStorage.setItem('counter-id', created.objectId);
      }
    } catch (e) {
      setErr(String(e));
    } finally {
      setBusy(false);
    }
  }

  async function increment() {
    if (!PKG || !counterId) return;
    setBusy(true);
    setErr(null);
    try {
      const tx = new Transaction();
      tx.moveCall({
        target: `${PKG}::counter::increment`,
        arguments: [tx.object(counterId)],
      });
      const res = await signAndExecute({ transaction: tx });
      await suiClient.waitForTransaction({ digest: res.digest });
      await refetch();
    } catch (e) {
      setErr(String(e));
    } finally {
      setBusy(false);
    }
  }

  async function reset() {
    if (!PKG || !counterId) return;
    setBusy(true);
    setErr(null);
    try {
      const tx = new Transaction();
      tx.moveCall({
        target: `${PKG}::counter::reset`,
        arguments: [tx.object(counterId)],
      });
      const res = await signAndExecute({ transaction: tx });
      await suiClient.waitForTransaction({ digest: res.digest });
      await refetch();
    } catch (e) {
      setErr(String(e));
    } finally {
      setBusy(false);
    }
  }

  return (
    <main style={{ maxWidth: 720, margin: '4rem auto', padding: '0 1rem' }}>
      <header style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
        <h1 style={{ margin: 0 }}>Counter</h1>
        <ConnectButton />
      </header>

      <p className="muted" style={{ marginBottom: '1.5rem' }}>
        Live Move package on Sui testnet. Connect a wallet, create or load a counter, then increment
        / reset.
      </p>

      <div className="card" style={{ marginBottom: '1rem' }}>
        <div className="muted" style={{ fontSize: '0.85rem' }}>
          Package
        </div>
        <code style={{ wordBreak: 'break-all' }}>
          {PKG || '(set NEXT_PUBLIC_COUNTER_PACKAGE_ID)'}
        </code>
      </div>

      <div className="card" style={{ marginBottom: '1rem' }}>
        <label htmlFor="counter-id" className="muted" style={{ fontSize: '0.85rem' }}>
          Counter object id
        </label>
        <input
          id="counter-id"
          value={counterId}
          placeholder="0x… (paste an existing counter or create one)"
          onChange={(e) => {
            setCounterId(e.target.value);
            window.localStorage.setItem('counter-id', e.target.value);
          }}
        />
        <div style={{ display: 'flex', gap: '0.5rem', marginTop: '0.75rem', flexWrap: 'wrap' }}>
          <button type="button" onClick={create} disabled={!address || busy}>
            Create new
          </button>
          <button type="button" onClick={() => refetch()} disabled={!counterId || isFetching}>
            Refresh
          </button>
          <button type="button" onClick={increment} disabled={!address || !counterId || busy}>
            +1
          </button>
          <button type="button" onClick={reset} disabled={!address || !counterId || busy}>
            Reset
          </button>
        </div>
      </div>

      {value !== null && (
        <div className="card">
          <div className="muted" style={{ fontSize: '0.85rem' }}>
            Current value
          </div>
          <div style={{ fontSize: '3rem', fontWeight: 700 }}>{value}</div>
        </div>
      )}

      {!address && (
        <p className="muted" style={{ marginTop: '1rem' }}>
          Connect a wallet (Slush / Suiet / Phantom / Nightly / OKX) to send transactions.
        </p>
      )}

      {err && <p style={{ color: '#ff6b6b', marginTop: '1rem', wordBreak: 'break-all' }}>{err}</p>}
    </main>
  );
}
