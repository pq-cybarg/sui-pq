'use client';
export default function SealPage() {
  return (
    <main style={{ maxWidth: 720, margin: '4rem auto', padding: '0 1rem' }}>
      <h1>Seal</h1>
      <p className="muted">
        Encrypt a payload to an on-chain identity and decrypt via Seal&apos;s threshold-MPC key
        servers. The decryption tx must call <code>seal_demo::allowlist::seal_approve</code>
        on a deployed package whose allowlist includes you.
      </p>
      <p>
        To wire this end-to-end, deploy <code>move/seal_demo</code>, set{' '}
        <code>SEAL_PACKAGE_ID</code>
        in <code>.env.local</code>, and add yourself to the allowlist. See <code>docs/seal.md</code>
        .
      </p>
    </main>
  );
}
