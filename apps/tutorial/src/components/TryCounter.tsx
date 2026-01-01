'use client';
import { DEPLOYED, suiscan } from '@/lib/deployed';
import { Transaction } from '@mysten/sui/transactions';
import {
  useActiveAddress,
  useSignAndExecuteTransaction,
  useSuiClient,
  useSuiClientQuery,
} from '@sui-gen/wallet-kit';
import { useState } from 'react';

export function TryCounter() {
  const address = useActiveAddress();
  const suiClient = useSuiClient();
  const { mutateAsync: signAndExecute } = useSignAndExecuteTransaction();
  const [busy, setBusy] = useState(false);
  const [msg, setMsg] = useState<string | null>(null);

  const { data, refetch } = useSuiClientQuery('getObject', {
    id: DEPLOYED.counter.objectId,
    options: { showContent: true },
  });
  const value =
    data?.data?.content?.dataType === 'moveObject'
      ? (data.data.content.fields as { value?: string }).value
      : null;

  async function increment() {
    if (!address) return;
    setBusy(true);
    setMsg(null);
    try {
      const tx = new Transaction();
      tx.moveCall({
        target: `${DEPLOYED.counter.packageId}::counter::increment`,
        arguments: [tx.object(DEPLOYED.counter.objectId)],
      });
      const res = await signAndExecute({ transaction: tx });
      await suiClient.waitForTransaction({ digest: res.digest });
      await refetch();
      setMsg(`✓ tx ${res.digest.slice(0, 12)}…`);
    } catch (e) {
      setMsg(`✗ ${String(e).slice(0, 220)}`);
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="card">
      <h3 style={{ margin: '0 0 0.5rem' }}>Try it: increment the shared counter</h3>
      <p className="muted" style={{ marginTop: 0, marginBottom: '0.75rem' }}>
        This counter is a shared object anyone on testnet can write to.{' '}
        <a href={suiscan(DEPLOYED.counter.objectId)} target="_blank" rel="noreferrer">
          view on Suiscan ↗
        </a>
      </p>
      <div
        className="result"
        style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}
      >
        <span>
          current value:{' '}
          <strong style={{ color: 'var(--accent)', fontSize: '1.5rem' }}>{value ?? '…'}</strong>
        </span>
        <button type="button" className="primary" onClick={increment} disabled={!address || busy}>
          {busy ? 'signing…' : '+1'}
        </button>
      </div>
      {!address && (
        <p className="muted" style={{ fontSize: '0.85rem', marginTop: '0.5rem' }}>
          connect a wallet to send the tx
        </p>
      )}
      {msg && <div className={`result ${msg.startsWith('✓') ? 'ok' : 'bad'}`}>{msg}</div>}
    </div>
  );
}
