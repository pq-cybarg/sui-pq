'use client';
import { DEPLOYED, suiscan } from '@/lib/deployed';
import { Transaction } from '@mysten/sui/transactions';
import { useActiveAddress, useSignAndExecuteTransaction, useSuiClient } from '@sui-gen/wallet-kit';
import { WalrusHttpClient } from '@sui-gen/walrus-client/http';
import { useState } from 'react';

const walrus = new WalrusHttpClient({
  publisher: 'https://publisher.walrus-testnet.walrus.space',
  aggregator: 'https://aggregator.walrus-testnet.walrus.space',
});

export function TryMintNft() {
  const address = useActiveAddress();
  const suiClient = useSuiClient();
  const { mutateAsync: signAndExecute } = useSignAndExecuteTransaction();

  const [name, setName] = useState('My Genesis NFT');
  const [desc, setDesc] = useState('Minted from the sui-gen tutorial.');
  const [imgText, setImgText] = useState('🐳');
  const [busy, setBusy] = useState(false);
  const [stage, setStage] = useState<string>('');
  const [mintedId, setMintedId] = useState<string | null>(null);
  const [err, setErr] = useState<string | null>(null);

  async function mint() {
    if (!address) return;
    setBusy(true);
    setErr(null);
    setMintedId(null);
    try {
      setStage('Uploading image to Walrus…');
      const { blobId } = await walrus.put(imgText, { epochs: 2 });
      const imgUrl = walrus.url(blobId);

      setStage('Building + signing mint transaction…');
      const tx = new Transaction();
      tx.moveCall({
        target: `${DEPLOYED.nft.packageId}::genesis_nft::mint`,
        arguments: [
          tx.pure.vector('u8', Array.from(new TextEncoder().encode(name))),
          tx.pure.vector('u8', Array.from(new TextEncoder().encode(desc))),
          tx.pure.vector('u8', Array.from(new TextEncoder().encode(imgUrl))),
          tx.pure.address(address),
        ],
      });
      const res = await signAndExecute({ transaction: tx });

      setStage('Waiting for confirmation…');
      const full = await suiClient.waitForTransaction({
        digest: res.digest,
        options: { showObjectChanges: true },
      });
      const created = full.objectChanges?.find(
        (c) => c.type === 'created' && c.objectType.includes('GenesisNFT'),
      );
      if (created && 'objectId' in created) setMintedId(created.objectId);
      setStage('');
    } catch (e) {
      setErr(String(e).slice(0, 240));
      setStage('');
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="card">
      <h3 style={{ margin: '0 0 0.5rem' }}>Try it: mint your own NFT (Walrus + Sui in one flow)</h3>
      <p className="muted" style={{ marginTop: 0 }}>
        This (1) uploads your image text to Walrus, (2) mints a GenesisNFT pointing at the Walrus
        URL.
      </p>

      <div className="grid-2">
        <div>
          <label className="muted" style={{ fontSize: '0.8rem' }} htmlFor="nft-name">
            name
          </label>
          <input
            id="nft-name"
            value={name}
            onChange={(e) => setName(e.target.value)}
            style={inputStyle}
          />
        </div>
        <div>
          <label className="muted" style={{ fontSize: '0.8rem' }} htmlFor="nft-desc">
            description
          </label>
          <input
            id="nft-desc"
            value={desc}
            onChange={(e) => setDesc(e.target.value)}
            style={inputStyle}
          />
        </div>
      </div>
      <label
        className="muted"
        style={{ fontSize: '0.8rem', marginTop: '0.5rem', display: 'block' }}
        htmlFor="nft-img"
      >
        "image" content (anything — emoji, text, base64 image)
      </label>
      <textarea
        id="nft-img"
        rows={2}
        value={imgText}
        onChange={(e) => setImgText(e.target.value)}
        style={{ ...inputStyle, fontFamily: 'ui-monospace, monospace' }}
      />

      <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem', marginTop: '0.75rem' }}>
        <button type="button" className="primary" onClick={mint} disabled={!address || busy}>
          {busy ? 'minting…' : 'mint NFT'}
        </button>
        {!address && (
          <span className="muted" style={{ fontSize: '0.85rem' }}>
            connect a wallet to enable
          </span>
        )}
        {stage && (
          <span className="dim" style={{ fontSize: '0.85rem' }}>
            {stage}
          </span>
        )}
      </div>

      {mintedId && (
        <div className="result ok">
          ✓ minted NFT id: {mintedId}
          {'\n'}
          <a href={suiscan(mintedId)} target="_blank" rel="noreferrer">
            view on Suiscan ↗
          </a>
        </div>
      )}
      {err && <div className="result bad">{err}</div>}
    </div>
  );
}

const inputStyle: React.CSSProperties = {
  width: '100%',
  background: 'var(--code-bg)',
  color: 'var(--fg)',
  border: '1px solid var(--border)',
  borderRadius: 6,
  padding: '0.5rem 0.75rem',
  font: 'inherit',
  fontSize: '0.9rem',
};
