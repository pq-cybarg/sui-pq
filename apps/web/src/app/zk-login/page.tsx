'use client';
import { beginZkLogin, buildAuthorizeUrl } from '@sui-gen/zk-login';
import { useState } from 'react';

export default function ZkLoginPage() {
  const [nonce, setNonce] = useState<string | null>(null);

  async function start() {
    const setup = beginZkLogin(/* currentEpoch */ 0, 2);
    sessionStorage.setItem(
      'zk_login_setup',
      JSON.stringify({
        sk: Array.from(setup.ephemeralKeyPair.getSecretKey() as unknown as Uint8Array),
        randomness: setup.randomness,
        maxEpoch: setup.maxEpoch,
      }),
    );
    setNonce(setup.nonce);

    const clientId = process.env.NEXT_PUBLIC_GOOGLE_CLIENT_ID;
    if (!clientId) return;
    const url = buildAuthorizeUrl(
      {
        name: 'google',
        authorizeUrl: 'https://accounts.google.com/o/oauth2/v2/auth',
        clientId,
        redirectUri: `${window.location.origin}/zk-login/callback`,
      },
      setup.nonce,
    );
    window.location.href = url;
  }

  return (
    <main style={{ maxWidth: 720, margin: '4rem auto', padding: '0 1rem' }}>
      <h1>zkLogin</h1>
      <p className="muted">Sign in with Google → derive a Sui address with no key custody.</p>
      <button type="button" onClick={start}>
        Sign in with Google
      </button>
      {nonce && (
        <p className="muted" style={{ marginTop: '1rem' }}>
          Nonce: <code style={{ wordBreak: 'break-all' }}>{nonce}</code>
        </p>
      )}
    </main>
  );
}
