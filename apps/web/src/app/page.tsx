'use client';
import { ConnectButton, useActiveAddress } from '@sui-gen/wallet-kit';
import Link from 'next/link';

export default function HomePage() {
  const address = useActiveAddress();
  return (
    <main style={{ maxWidth: 960, margin: '4rem auto', padding: '0 1rem' }}>
      <header
        style={{
          display: 'flex',
          justifyContent: 'space-between',
          alignItems: 'center',
          marginBottom: '2rem',
        }}
      >
        <h1 style={{ margin: 0 }}>sui-gen</h1>
        <ConnectButton />
      </header>

      <p className="muted" style={{ marginBottom: '2rem' }}>
        A reference Sui dApp. Connect a wallet (Slush, Suiet, Phantom, Nightly, OKX) and try the
        demos below.
      </p>

      {address && (
        <div className="card" style={{ marginBottom: '2rem' }}>
          <div className="muted">Connected as</div>
          <code style={{ fontSize: '0.9rem', wordBreak: 'break-all' }}>{address}</code>
        </div>
      )}

      <div className="grid" style={{ gridTemplateColumns: 'repeat(auto-fit, minmax(260px, 1fr))' }}>
        <DemoCard
          href="/counter"
          title="Counter"
          body="Live Move counter on testnet — create, increment, reset via wallet."
        />
        <DemoCard
          href="/walrus"
          title="Walrus"
          body="Upload + read blobs from decentralized storage."
        />
        <DemoCard
          href="/seal"
          title="Seal"
          body="Threshold-encrypt secrets with on-chain access control."
        />
        <DemoCard
          href="/zk-login"
          title="zkLogin"
          body="Sign in with Google and derive a Sui address."
        />
        <DemoCard
          href="/lumiwave"
          title="Lumiwave"
          body="Check LWA balances + service-API integration."
        />
        <DemoCard
          href="/deepbook"
          title="DeepBook"
          body="Read orderbook snapshots from Sui's CLOB."
        />
        <DemoCard
          href="/pqc"
          title="Post-quantum"
          body="ML-DSA / SLH-DSA / ML-KEM in-browser. Sign + verify; the Move-verifiable variant."
        />
      </div>
    </main>
  );
}

function DemoCard({ href, title, body }: { href: string; title: string; body: string }) {
  return (
    <Link href={href} style={{ textDecoration: 'none', color: 'inherit' }}>
      <div className="card" style={{ height: '100%' }}>
        <h3 style={{ marginTop: 0 }}>{title}</h3>
        <p className="muted" style={{ margin: 0 }}>
          {body}
        </p>
      </div>
    </Link>
  );
}
