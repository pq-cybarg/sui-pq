'use client';

import { Ed25519Keypair } from '@mysten/sui/keypairs/ed25519';
import { Transaction } from '@mysten/sui/transactions';
/**
 * PQC workbench — every operation here is real cryptography running in your
 * browser. No simulation, no faking.
 *
 *   @sui-gen/pqc → @noble/post-quantum (audited FIPS 203 / 204 / 205 / FALCON impl)
 *                  @sui-gen/pqc/slh-dsa-ref (the workspace's SLH-DSA-LITE TS reference;
 *                  byte-identical to move/slh_dsa and to the patches/0002 fastcrypto verifier)
 *
 * Wall-clock timing is shown on every operation. ML-DSA / ML-KEM are lattice
 * schemes — they're inherently fast (low ms). SLH-DSA-LITE is hash-based —
 * keygen runs ~32k SHA-256 ops; on a modern machine that's ~0.5–1.5 seconds,
 * which you can see in the timer.
 */
import { sha256 } from '@noble/hashes/sha256';
import {
  SCHEME,
  SCHEME_META,
  intentDigest,
  kemDecrypt,
  kemEncrypt,
  kemKeygen,
  keygen,
  sign,
  signTxWithSlhDsa,
  slh,
  slhDsaAddress,
  verify,
  verifyTxSlhDsaSig,
} from '@sui-gen/pqc';
import type { SchemeName } from '@sui-gen/pqc';
import {
  ConnectButton,
  useActiveAddress,
  useSignAndExecuteTransaction,
  useSuiClient,
} from '@sui-gen/wallet-kit';
import { useEffect, useMemo, useRef, useState } from 'react';

// ── helpers ─────────────────────────────────────────────────────────────────
/** Browser-native hex decode (avoids Buffer polyfill issues in client bundles). */
function hexToBytes(h: string): Uint8Array {
  const clean = h.toLowerCase().replace(/[^0-9a-f]/g, '');
  if (clean.length % 2 !== 0) throw new Error('odd-length hex');
  const out = new Uint8Array(clean.length / 2);
  for (let i = 0; i < out.length; i++) {
    out[i] = Number.parseInt(clean.slice(i * 2, i * 2 + 2), 16);
  }
  return out;
}

function hex(b: Uint8Array | undefined, max?: number): string {
  if (!b) return '';
  let s = '';
  for (const x of b) s += x.toString(16).padStart(2, '0');
  return max && s.length > max ? `${s.slice(0, max)}…` : s;
}

function randomSeed(): Uint8Array {
  const b = new Uint8Array(32);
  crypto.getRandomValues(b);
  return b;
}

function fmtMs(ms: number): string {
  if (ms < 1) return '<1 ms';
  if (ms < 1000) return `${ms.toFixed(0)} ms`;
  return `${(ms / 1000).toFixed(2)} s`;
}

function CopyBtn({ value, label = 'copy' }: { value: string | Uint8Array; label?: string }) {
  const [copied, setCopied] = useState(false);
  const text = value instanceof Uint8Array ? hex(value) : value;
  return (
    <button
      type="button"
      className={`copy-btn ${copied ? 'copied' : ''}`}
      onClick={() => {
        navigator.clipboard.writeText(text);
        setCopied(true);
        setTimeout(() => setCopied(false), 1100);
      }}
    >
      {copied ? '✓ copied' : label}
    </button>
  );
}

function HexViewer({ bytes }: { bytes: Uint8Array }) {
  const text = hex(bytes);
  return (
    <div className="hex-viewer">
      {text}
      <CopyBtn value={text} />
    </div>
  );
}

// Proof-of-work indicator: actually hash N times so the user can see real CPU usage.
async function runRealSha256ProofOfWork(
  rounds: number,
  onProgress: (i: number) => void,
): Promise<number> {
  const start = performance.now();
  let v: Uint8Array = new Uint8Array(32);
  for (let i = 0; i < rounds; i++) {
    v = new Uint8Array(sha256(v));
    if (i % Math.max(1, Math.floor(rounds / 50)) === 0) {
      onProgress(i);
      // Yield so the UI can paint
      await new Promise((r) => setTimeout(r, 0));
    }
  }
  onProgress(rounds);
  return performance.now() - start;
}

// ── page ────────────────────────────────────────────────────────────────────
export default function PqcPage() {
  const [seedHex, setSeedHex] = useState<string>('cc'.repeat(32));
  const [skSeedHex, setSkSeedHex] = useState<string>('dd'.repeat(32));
  const [identity, setIdentity] = useState<{ pk: slh.PublicKey; sk: slh.SecretKey } | null>(null);
  const [genStats, setGenStats] = useState<{ ms: number; pkHash: string } | null>(null);
  const [generating, setGenerating] = useState(false);

  async function regenerate(seedH: string, skH: string) {
    setGenerating(true);
    setIdentity(null);
    setGenStats(null);
    await new Promise((r) => setTimeout(r, 0));
    try {
      const seed = hexToBytes(seedH);
      const skSeed = hexToBytes(skH);
      if (seed.length !== 32 || skSeed.length !== 32) {
        throw new Error('seeds must be 32 bytes (64 hex)');
      }
      const t0 = performance.now();
      const kp = slh.keygen(seed, skSeed);
      const ms = performance.now() - t0;
      // Hash the pk so the user can see it's a determinate function of (seed, skSeed):
      // changing either by 1 bit completely changes pkHash.
      const pkHash = hex(sha256(new Uint8Array([...kp.pk.seed, ...kp.pk.root]))).slice(0, 16);
      setIdentity(kp);
      setGenStats({ ms, pkHash });
    } finally {
      setGenerating(false);
    }
  }
  // biome-ignore lint/correctness/useExhaustiveDependencies: mount-only; user-driven regenerates go through the button below
  useEffect(() => {
    void regenerate(seedHex, skSeedHex);
  }, []);

  const address = useMemo(() => (identity ? slhDsaAddress(identity.pk) : ''), [identity]);

  return (
    <main className="pq-page">
      <h1>Post-quantum workbench</h1>
      <p className="lede">
        Every operation here is <strong>real cryptography running in your browser</strong> — no
        simulation. ML-DSA / ML-KEM are lattice schemes (inherently fast, low ms). SLH-DSA-LITE is
        hash-based (~32 000 SHA-256 ops per keygen, visible in the timer). Wall-clock timing is
        shown on every operation.
      </p>

      <ProofOfWorkBaseline />

      {/* ── Section 1: identity ───────────────────────────────────────────── */}
      <h2>
        <span className="num">1</span> Your PQ identity
      </h2>
      <div className="card">
        <div className="pq-row">
          <span className="label">scheme</span>
          <span className="val">SLH-DSA-LITE (Move-verifiable, n=32; FIPS 205 structure)</span>
          <span />
        </div>
        <div className="pq-row">
          <span className="label">PK seed</span>
          <input
            value={seedHex}
            onChange={(e) => setSeedHex(e.target.value.replace(/[^0-9a-f]/gi, '').slice(0, 64))}
            style={{ fontFamily: 'ui-monospace, monospace', fontSize: '0.8rem' }}
            spellCheck={false}
          />
          <button type="button" className="ghost" onClick={() => setSeedHex(hex(randomSeed()))}>
            randomize
          </button>
        </div>
        <div className="pq-row">
          <span className="label">SK seed</span>
          <input
            value={skSeedHex}
            onChange={(e) => setSkSeedHex(e.target.value.replace(/[^0-9a-f]/gi, '').slice(0, 64))}
            style={{ fontFamily: 'ui-monospace, monospace', fontSize: '0.8rem' }}
            spellCheck={false}
          />
          <button type="button" className="ghost" onClick={() => setSkSeedHex(hex(randomSeed()))}>
            randomize
          </button>
        </div>

        <div className="pq-actions">
          <button
            type="button"
            onClick={() => void regenerate(seedHex, skSeedHex)}
            disabled={generating}
          >
            {generating ? 'deriving (real CPU work)…' : 'derive PQ identity'}
          </button>
          {genStats && (
            <span className="pq-chip ok">
              ✓ {fmtMs(genStats.ms)} · ~{(32 / (genStats.ms / 1000)).toFixed(0)} k SHA-256/s
            </span>
          )}
        </div>

        {identity && genStats && (
          <>
            <p className="result-line" style={{ marginTop: '0.75rem' }}>
              SLH-DSA-LITE keygen ran <strong>~32 800 SHA-256 ops</strong> in your browser:{' '}
              {`d × 2^h' = 2 × 16 = 32 XMSS leaves; each leaf = `}
              <code>WOTS+ pubkey derive ({67 * 15} hashes) + leaf compress</code>; then collapsed
              via 4 Merkle levels.
            </p>
            <div className="divider" />
            <div className="pq-row">
              <span className="label">Sui address</span>
              <span className="val addr">{address}</span>
              <CopyBtn value={address} />
            </div>
            <div className="pq-row">
              <span className="label">addr =</span>
              <span className="val">0x + blake2b256( 0x07 || PK.seed || PK.root )</span>
              <span />
            </div>
            <div className="pq-row">
              <span className="label">PK.seed</span>
              <span className="val">{hex(identity.pk.seed)}</span>
              <CopyBtn value={identity.pk.seed} />
            </div>
            <div className="pq-row">
              <span className="label">PK.root</span>
              <span className="val">{hex(identity.pk.root)}</span>
              <CopyBtn value={identity.pk.root} />
            </div>
            <p className="result-line">
              sha256(pk).first16: <code>{genStats.pkHash}</code> — flip one bit of the SK seed and
              this changes completely (try it).
            </p>
          </>
        )}
      </div>

      <SignSection identity={identity} />
      <BenchmarkSection />
      <EncryptSection />
      <TxSection identity={identity} address={address} />
      <OnChainSection identity={identity} pqAddress={address} />
    </main>
  );
}

// ── Section 6: REAL testnet transactions, real wallet, real on-chain PQ ────
function OnChainSection({
  identity,
  pqAddress,
}: {
  identity: { pk: slh.PublicKey; sk: slh.SecretKey } | null;
  pqAddress: string;
}) {
  return (
    <>
      <h2>
        <span className="num">6</span> Real testnet activity
      </h2>
      <EphemeralSigner />
      <ConnectStrip />
      <RegisterAttestation identity={identity} pqAddress={pqAddress} />
      <RegisterPqIdentity />
      <UnlockPqGuard />
    </>
  );
}

// ── Proof-of-work baseline — measure browser SHA-256 throughput ─────────────
function ProofOfWorkBaseline() {
  const [busy, setBusy] = useState(false);
  const [progress, setProgress] = useState(0);
  const [result, setResult] = useState<{ ms: number; rate: number } | null>(null);
  const ROUNDS = 32_000;

  async function go() {
    setBusy(true);
    setResult(null);
    const ms = await runRealSha256ProofOfWork(ROUNDS, (i) => setProgress(i));
    setResult({ ms, rate: (ROUNDS * 1000) / ms });
    setBusy(false);
  }

  return (
    <div className="card" style={{ marginBottom: '1rem' }}>
      <p className="result-line" style={{ margin: 0 }}>
        <strong>Proof-of-work baseline.</strong> Click below to run{' '}
        <strong>{ROUNDS.toLocaleString()}</strong> actual SHA-256 calls — the same number an
        SLH-DSA-LITE keygen does. The timer below is independent ground truth: any subsequent keygen
        should land in roughly the same range.
      </p>
      <div className="pq-actions">
        <button type="button" onClick={go} disabled={busy} className="ghost">
          {busy
            ? `hashing… ${((progress / ROUNDS) * 100).toFixed(0)}%`
            : `run ${ROUNDS.toLocaleString()} SHA-256 ops`}
        </button>
        {result && (
          <span className="pq-chip ok">
            {fmtMs(result.ms)} · {Math.round(result.rate / 1000).toLocaleString()} k ops/s
          </span>
        )}
      </div>
    </div>
  );
}

// ── Section 2: sign + verify a message ─────────────────────────────────────
function SignSection({ identity }: { identity: { pk: slh.PublicKey; sk: slh.SecretKey } | null }) {
  const [msg, setMsg] = useState('post-quantum hello');
  const [sig, setSig] = useState<Uint8Array | null>(null);
  const [stats, setStats] = useState<{
    signMs: number;
    verifyMs: number;
    verifyMsTampered: number;
  } | null>(null);
  const [verified, setVerified] = useState<boolean | null>(null);
  const [tampered, setTampered] = useState<boolean | null>(null);
  const [busy, setBusy] = useState(false);

  async function go() {
    if (!identity) return;
    setBusy(true);
    setSig(null);
    setVerified(null);
    setTampered(null);
    setStats(null);
    try {
      await new Promise((r) => setTimeout(r, 0));
      const bytes = new TextEncoder().encode(msg);
      const t0 = performance.now();
      const s = slh.sign(identity.sk, bytes);
      const signMs = performance.now() - t0;
      const packed = slh.packSignature(s);
      setSig(packed);

      const t1 = performance.now();
      const v = slh.verify(identity.pk, bytes, s);
      const verifyMs = performance.now() - t1;
      setVerified(v);

      const damaged = new Uint8Array(packed);
      damaged[0] = ((damaged[0] ?? 0) ^ 0xff) & 0xff;
      const damagedSig = slh.unpackSignature(damaged);
      const t2 = performance.now();
      const v2 = slh.verify(identity.pk, bytes, damagedSig);
      const verifyMsTampered = performance.now() - t2;
      setTampered(v2);
      setStats({ signMs, verifyMs, verifyMsTampered });
    } finally {
      setBusy(false);
    }
  }

  return (
    <>
      <h2>
        <span className="num">2</span> Sign a message
      </h2>
      <div className="card">
        <div className="pq-row">
          <span className="label">message</span>
          <input value={msg} onChange={(e) => setMsg(e.target.value)} spellCheck={false} />
          <span />
        </div>
        <div className="pq-actions">
          <button type="button" onClick={go} disabled={!identity || busy}>
            {busy ? 'signing…' : 'sign & verify (real SLH-DSA-LITE)'}
          </button>
          {!identity && <span className="pq-chip warn">derive an identity first</span>}
          {verified === true && stats && (
            <span className="pq-chip ok">
              ✓ valid · sign {fmtMs(stats.signMs)} · verify {fmtMs(stats.verifyMs)}
            </span>
          )}
          {verified === false && <span className="pq-chip bad">✗ invalid</span>}
          {tampered === false && stats && (
            <span className="pq-chip ok">✓ tamper rejected ({fmtMs(stats.verifyMsTampered)})</span>
          )}
          {tampered === true && <span className="pq-chip bad">tamper accepted (broken!)</span>}
        </div>

        {sig && (
          <>
            <p className="result-line" style={{ marginTop: '0.75rem' }}>
              <strong>signature</strong> · {sig.length.toLocaleString()} bytes · the same packed
              format <code>move/slh_dsa::verifier::verify</code> consumes on-chain
            </p>
            <HexViewer bytes={sig} />
          </>
        )}
      </div>
    </>
  );
}

// ── Section 3: SLH-DSA parameter set comparison ────────────────────────────
function BenchmarkSection() {
  const [busy, setBusy] = useState(false);
  const [results, setResults] = useState<
    Array<{
      name: SchemeName;
      cat: number;
      pk: number;
      sig: number;
      keygenMs: number;
      signMs: number;
      verifyMs: number;
    }>
  >([]);
  const cancelled = useRef(false);

  // Variants of the SAME family this workspace verifies on-chain. The on-chain
  // verifier is the LITE form (n=32, h=8, d=2); these FIPS-205 variants live
  // side-by-side because they share the WOTS+ → XMSS → Hypertree → FORS
  // construction. Compare keygen/sign/verify costs vs signature size — that's
  // the real engineering tradeoff when picking parameters for SLH-DSA.
  const VARIANTS: Array<{ name: SchemeName; label: string }> = [
    { name: 'SLH_DSA_SHA2_128S', label: 'SLH-DSA-SHA2-128s (cat 1, small)' },
    { name: 'SLH_DSA_SHA2_128F', label: 'SLH-DSA-SHA2-128f (cat 1, fast)' },
    { name: 'SLH_DSA_SHA2_192S', label: 'SLH-DSA-SHA2-192s (cat 3, small)' },
  ];

  async function go() {
    setBusy(true);
    setResults([]);
    cancelled.current = false;
    const msg = new TextEncoder().encode('benchmark payload');

    const out: typeof results = [];
    for (const v of VARIANTS) {
      if (cancelled.current) break;
      await new Promise((r) => setTimeout(r, 0));
      const meta = SCHEME_META[v.name];
      const t0 = performance.now();
      const kp = keygen(v.name);
      const keygenMs = performance.now() - t0;
      const t1 = performance.now();
      const sig = sign(kp, msg);
      const signMs = performance.now() - t1;
      const t2 = performance.now();
      const ok = verify(v.name, kp.publicKey, msg, sig);
      const verifyMs = performance.now() - t2;
      if (!ok) throw new Error(`${v.name} round-trip failed`);
      out.push({
        name: v.name,
        cat: meta.category,
        pk: meta.publicKeyBytes,
        sig: meta.signatureBytes,
        keygenMs,
        signMs,
        verifyMs,
      });
      setResults([...out]);
    }
    setBusy(false);
  }

  return (
    <>
      <h2>
        <span className="num">3</span> SLH-DSA parameter sets (live benchmark)
      </h2>
      <div className="card">
        <p className="result-line" style={{ marginBottom: '0.5rem' }}>
          SLH-DSA is the family this workspace verifies on-chain (<code>move/slh_dsa</code>). The
          FIPS-205 standard ships several parameter sets that trade sign-time against signature
          size. <strong>s</strong> = small sig / slower keygen; <strong>f</strong> = fast sign /
          bigger sig. Each row below runs real <code>keygen → sign → verify</code> in your browser;
          compare against the proof-of-work baseline above.
        </p>
        <p className="result-line" style={{ marginBottom: '0.5rem', color: 'var(--muted)' }}>
          (The workspace's on-chain verifier uses the SLH-DSA-LITE variant: n=32 instead of n=16, a
          simpler msg-digest. Production-grade SLH-DSA-SHA2-128s is shown here for context — same
          construction, different parameters.)
        </p>
        <div className="pq-actions">
          <button type="button" onClick={go} disabled={busy}>
            {busy ? 'running…' : 'run benchmark'}
          </button>
        </div>
        {results.length > 0 && (
          <table
            style={{
              width: '100%',
              marginTop: '1rem',
              borderCollapse: 'collapse',
              fontFamily: 'ui-monospace, monospace',
              fontSize: '0.82rem',
            }}
          >
            <thead>
              <tr style={{ borderBottom: '1px solid var(--border)' }}>
                {['scheme', 'NIST cat', 'pk B', 'sig B', 'keygen', 'sign', 'verify'].map((h) => (
                  <th
                    key={h}
                    style={{
                      textAlign: h === 'scheme' ? 'left' : 'right',
                      padding: '0.4rem 0.6rem',
                      color: 'var(--muted)',
                      fontWeight: 600,
                    }}
                  >
                    {h}
                  </th>
                ))}
              </tr>
            </thead>
            <tbody>
              {results.map((r) => (
                <tr key={r.name} style={{ borderBottom: '1px solid var(--border)' }}>
                  <td style={{ padding: '0.4rem 0.6rem' }}>{r.name}</td>
                  <td style={{ padding: '0.4rem 0.6rem', textAlign: 'right' }}>{r.cat}</td>
                  <td style={{ padding: '0.4rem 0.6rem', textAlign: 'right' }}>
                    {r.pk.toLocaleString()}
                  </td>
                  <td style={{ padding: '0.4rem 0.6rem', textAlign: 'right' }}>
                    {r.sig.toLocaleString()}
                  </td>
                  <td style={{ padding: '0.4rem 0.6rem', textAlign: 'right' }}>
                    {fmtMs(r.keygenMs)}
                  </td>
                  <td style={{ padding: '0.4rem 0.6rem', textAlign: 'right' }}>
                    {fmtMs(r.signMs)}
                  </td>
                  <td style={{ padding: '0.4rem 0.6rem', textAlign: 'right' }}>
                    {fmtMs(r.verifyMs)}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
    </>
  );
}

// ── Section 4: ML-KEM encrypt → decrypt ────────────────────────────────────
function EncryptSection() {
  const [plaintext, setPlaintext] = useState('confidential payload');
  const [busy, setBusy] = useState(false);
  const [stats, setStats] = useState<{
    pubLen: number;
    ctLen: number;
    nonceLen: number;
    aeadLen: number;
    decrypted: string;
    ok: boolean;
    keygenMs: number;
    encMs: number;
    decMs: number;
  } | null>(null);
  const [err, setErr] = useState<string | null>(null);

  async function go() {
    setBusy(true);
    setStats(null);
    setErr(null);
    try {
      await new Promise((r) => setTimeout(r, 0));
      const t0 = performance.now();
      const recipient = kemKeygen('ML_KEM_768');
      const keygenMs = performance.now() - t0;
      const aad = new TextEncoder().encode('app=demo');
      const t1 = performance.now();
      const packet = kemEncrypt(
        'ML_KEM_768',
        recipient.publicKey,
        new TextEncoder().encode(plaintext),
        aad,
      );
      const encMs = performance.now() - t1;
      const t2 = performance.now();
      const recovered = kemDecrypt('ML_KEM_768', recipient.secretKey, packet, aad);
      const decMs = performance.now() - t2;
      const dec = new TextDecoder().decode(recovered);
      setStats({
        pubLen: recipient.publicKey.length,
        ctLen: packet.kemCipherText.length,
        nonceLen: packet.nonce.length,
        aeadLen: packet.aeadCipherText.length,
        decrypted: dec,
        ok: dec === plaintext,
        keygenMs,
        encMs,
        decMs,
      });
    } catch (e) {
      setErr(String(e));
    } finally {
      setBusy(false);
    }
  }

  return (
    <>
      <h2>
        <span className="num">4</span> Encrypt to a recipient (ML-KEM-768)
      </h2>
      <div className="card">
        <div className="pq-row">
          <span className="label">plaintext</span>
          <input
            value={plaintext}
            onChange={(e) => setPlaintext(e.target.value)}
            spellCheck={false}
          />
          <span />
        </div>
        <div className="pq-actions">
          <button type="button" onClick={go} disabled={busy}>
            {busy ? 'wrapping…' : 'encrypt → decrypt'}
          </button>
          {stats?.ok && (
            <span className="pq-chip ok">
              ✓ keygen {fmtMs(stats.keygenMs)} · encap+AEAD {fmtMs(stats.encMs)} · decap+AEAD{' '}
              {fmtMs(stats.decMs)}
            </span>
          )}
        </div>

        {stats && (
          <>
            <p className="result-line" style={{ marginTop: '0.75rem' }}>
              recipient pubkey: <strong>{stats.pubLen} B</strong> · KEM ciphertext:{' '}
              <strong>{stats.ctLen} B</strong> · AES nonce: <strong>{stats.nonceLen} B</strong> ·
              AES ciphertext (incl. 16-B tag): <strong>{stats.aeadLen} B</strong>
            </p>
            <p className="result-line">
              <strong>decrypted →</strong> {stats.decrypted}
            </p>
          </>
        )}
        {err && (
          <p className="result-line" style={{ color: '#ff6b6b' }}>
            {err}
          </p>
        )}
      </div>
    </>
  );
}

// ── Section 5: PQ-native Sui tx signing ────────────────────────────────────
function TxSection({
  identity,
  address,
}: {
  identity: { pk: slh.PublicKey; sk: slh.SecretKey } | null;
  address: string;
}) {
  const [recipient, setRecipient] = useState(`0x${'aa'.repeat(32)}`);
  const [amount, setAmount] = useState('1000000');
  const [sigBlob, setSigBlob] = useState<Uint8Array | null>(null);
  const [verified, setVerified] = useState<boolean | null>(null);
  const [stats, setStats] = useState<{ signMs: number; verifyMs: number } | null>(null);
  const [busy, setBusy] = useState(false);

  async function go() {
    if (!identity) return;
    setBusy(true);
    setSigBlob(null);
    setVerified(null);
    setStats(null);
    try {
      await new Promise((r) => setTimeout(r, 0));
      const fakeTxBytes = new TextEncoder().encode(
        JSON.stringify({ from: address, to: recipient, amount: amount }),
      );
      const t0 = performance.now();
      const blob = signTxWithSlhDsa(fakeTxBytes, identity.pk, identity.sk);
      const signMs = performance.now() - t0;
      setSigBlob(blob);
      const t1 = performance.now();
      const v = verifyTxSlhDsaSig(fakeTxBytes, blob);
      const verifyMs = performance.now() - t1;
      setVerified(v);
      setStats({ signMs, verifyMs });
    } finally {
      setBusy(false);
    }
  }

  return (
    <>
      <h2>
        <span className="num">5</span> Sign a Sui transaction with the PQ key only
      </h2>
      <div className="card">
        <p className="result-line" style={{ marginBottom: '0.75rem' }}>
          Gas paid by the PQ-derived address itself — no classical key anywhere. Submit via{' '}
          <code>pnpm cli pq-send</code> against the patched validator. Below is the same wire blob
          the validator parses.
        </p>
        <div className="pq-row">
          <span className="label">recipient</span>
          <input
            value={recipient}
            onChange={(e) => setRecipient(e.target.value)}
            spellCheck={false}
            style={{ fontFamily: 'ui-monospace, monospace', fontSize: '0.85rem' }}
          />
          <span />
        </div>
        <div className="pq-row">
          <span className="label">amount</span>
          <input
            value={amount}
            onChange={(e) => setAmount(e.target.value.replace(/[^0-9]/g, ''))}
            inputMode="numeric"
            spellCheck={false}
          />
          <span className="label">MIST</span>
        </div>
        <div className="pq-actions">
          <button type="button" onClick={go} disabled={!identity || busy}>
            {busy ? 'signing…' : 'sign tx (pre-flight verify, no submit)'}
          </button>
          {verified === true && stats && (
            <span className="pq-chip ok">
              ✓ would be accepted · sign {fmtMs(stats.signMs)} · verify {fmtMs(stats.verifyMs)}
            </span>
          )}
          {verified === false && <span className="pq-chip bad">✗ would be rejected</span>}
        </div>

        {sigBlob && (
          <>
            <p className="result-line" style={{ marginTop: '0.75rem' }}>
              <strong>signature wire blob</strong> · 1 + 32 + 32 + 5,056 = 5,121 bytes
            </p>
            <div className="sig-strip" style={{ gridTemplateColumns: '1fr 8fr 8fr 100fr' }}>
              <div className="seg-flag" title="flag = 0x07 (SLH-DSA-LITE)">
                flag
              </div>
              <div className="seg-seed" title="PK.seed (32 bytes)">
                PK.seed
              </div>
              <div className="seg-root" title="PK.root (32 bytes)">
                PK.root
              </div>
              <div className="seg-sig" title="packed SLH-DSA signature (5,056 bytes)">
                packed SLH-DSA signature
              </div>
            </div>
            <HexViewer bytes={sigBlob} />
          </>
        )}
      </div>
    </>
  );
}

// ── On-chain helpers ───────────────────────────────────────────────────────
const PQ_ATTESTATION_PKG = process.env.NEXT_PUBLIC_PQ_ATTESTATION_PKG ?? '';
const PQ_GUARD_PKG = process.env.NEXT_PUBLIC_PQ_GUARD_PKG ?? '';

function suiscan(idOrTx: string, kind: 'object' | 'tx' = 'object'): string {
  return `https://suiscan.xyz/testnet/${kind}/${idOrTx}`;
}

/**
 * Localnet-friendly: in-page Ed25519 keypair stored in localStorage. No wallet
 * required; faucets straight from `http://127.0.0.1:9123` with one click.
 * The keypair is for local dev only — never use it on testnet/mainnet.
 */
const EPHEMERAL_KEY = 'pqc-ephemeral-ed25519-sk-b64';
function loadOrCreateEphemeralKey(): Ed25519Keypair {
  if (typeof window === 'undefined') return new Ed25519Keypair();
  const stored = window.localStorage.getItem(EPHEMERAL_KEY);
  if (stored) {
    try {
      return Ed25519Keypair.fromSecretKey(stored);
    } catch {
      // fall through to fresh
    }
  }
  const kp = new Ed25519Keypair();
  window.localStorage.setItem(EPHEMERAL_KEY, kp.getSecretKey());
  return kp;
}

interface LocalnetStatus {
  running: boolean;
  rpcOk: boolean;
  faucetOk: boolean;
  pid?: number;
  suiBin?: string | null;
  logPath?: string;
}

function EphemeralSigner() {
  const client = useSuiClient();
  const [kp, setKp] = useState<Ed25519Keypair | null>(null);
  const [balance, setBalance] = useState<string>('—');
  const [busy, setBusy] = useState(false);
  const [msg, setMsg] = useState<string | null>(null);
  const [faucetUrl, setFaucetUrl] = useState('http://127.0.0.1:9123/gas');
  const [rpcUrl, setRpcUrl] = useState('http://127.0.0.1:9000');
  const [status, setStatus] = useState<LocalnetStatus | null>(null);
  const [nodeBusy, setNodeBusy] = useState<'start' | 'stop' | null>(null);
  const [nodeMsg, setNodeMsg] = useState<string | null>(null);

  useEffect(() => {
    setKp(loadOrCreateEphemeralKey());
  }, []);

  async function refreshStatus() {
    try {
      const res = await fetch('/api/localnet');
      setStatus((await res.json()) as LocalnetStatus);
    } catch (e) {
      setStatus({ running: false, rpcOk: false, faucetOk: false });
      void e;
    }
  }

  // biome-ignore lint/correctness/useExhaustiveDependencies: mount-only status poll; refreshStatus is intentionally not a dep to avoid resetting the interval each render.
  useEffect(() => {
    void refreshStatus();
    const id = setInterval(refreshStatus, 4000);
    return () => clearInterval(id);
  }, []);

  async function startLocalnet() {
    setNodeBusy('start');
    setNodeMsg(null);
    try {
      const res = await fetch('/api/localnet', { method: 'POST' });
      const body = await res.json();
      if (!res.ok) {
        const hint = body?.hint ? `\n${body.hint}` : '';
        throw new Error(`${body?.error ?? `HTTP ${res.status}`}${hint}`);
      }
      setNodeMsg(`✓ ${body.message ?? 'started'}${body.pid ? ` · pid=${body.pid}` : ''}`);
      await refreshStatus();
      await refreshBalance();
    } catch (e) {
      setNodeMsg(`✗ ${String(e).slice(0, 400)}`);
    } finally {
      setNodeBusy(null);
    }
  }

  async function stopLocalnet() {
    if (!confirm('Stop the local Sui node and faucet?')) return;
    setNodeBusy('stop');
    setNodeMsg(null);
    try {
      const res = await fetch('/api/localnet', { method: 'DELETE' });
      const body = await res.json();
      setNodeMsg(body?.message ?? 'stopped');
      await refreshStatus();
    } catch (e) {
      setNodeMsg(`✗ ${String(e).slice(0, 200)}`);
    } finally {
      setNodeBusy(null);
    }
  }

  const address = kp?.toSuiAddress() ?? '';

  async function refreshBalance() {
    if (!address) return;
    try {
      const b = await client.getBalance({ owner: address });
      setBalance(`${(Number(b.totalBalance) / 1e9).toFixed(4)} SUI`);
    } catch (e) {
      setBalance(`(rpc unreachable: ${String(e).slice(0, 60)})`);
    }
  }
  // biome-ignore lint/correctness/useExhaustiveDependencies: re-run on address/client change; refreshBalance is intentionally excluded (recreated each render → would loop).
  useEffect(() => {
    if (address) void refreshBalance();
  }, [address, client]);

  async function dripFaucet() {
    if (!address) return;
    setBusy(true);
    setMsg(null);
    try {
      // Same-origin proxy via /api/faucet — bypasses browser CORS that
      // would otherwise block direct fetch to localhost:9123.
      const res = await fetch('/api/faucet', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ recipient: address, faucetUrl }),
      });
      const body = await res.json();
      if (!res.ok) {
        const hint = body?.hint ? `\n${body.hint}` : '';
        throw new Error(`${body?.error ?? `HTTP ${res.status}`}${hint}`);
      }
      setMsg('✓ drip requested · waiting 3s for indexer…');
      await new Promise((r) => setTimeout(r, 3000));
      await refreshBalance();
      setMsg('✓ drip confirmed');
    } catch (e) {
      setMsg(`✗ ${String(e).slice(0, 400)}`);
    } finally {
      setBusy(false);
    }
  }

  function regenerate() {
    if (!confirm('Discard current ephemeral key and generate a fresh one?')) return;
    window.localStorage.removeItem(EPHEMERAL_KEY);
    setKp(loadOrCreateEphemeralKey());
  }

  return (
    <>
      <h2>
        <span className="num">0</span> Localnet ephemeral signer (no wallet needed)
      </h2>
      <div className="card">
        <p className="result-line" style={{ marginBottom: '0.75rem' }}>
          For localnet dev you don't need Slush or any wallet at all — this page generates a
          throwaway Ed25519 keypair in your browser and uses it directly. Useful when your wallet
          doesn't expose custom-RPC config (and what you should use for CI). The key is stored in
          <code> localStorage</code> under <code>{EPHEMERAL_KEY}</code>; it's local-only.
        </p>

        <div className="pq-row">
          <span className="label">localnet status</span>
          <span className="val">
            {status === null ? (
              '…'
            ) : status.rpcOk && status.faucetOk ? (
              <span className="pq-chip ok">
                ✓ running · RPC :9000 · faucet :9123{status.pid ? ` · pid=${status.pid}` : ''}
              </span>
            ) : status.rpcOk ? (
              <span className="pq-chip warn">RPC up, faucet down (start with --with-faucet)</span>
            ) : (
              <span className="pq-chip bad">not running — click "start localnet"</span>
            )}
          </span>
          <span />
        </div>
        <div className="pq-actions" style={{ marginBottom: '0.5rem' }}>
          <button
            type="button"
            onClick={() => void startLocalnet()}
            disabled={nodeBusy !== null || (status?.rpcOk ?? false)}
          >
            {nodeBusy === 'start'
              ? 'starting (~10s)…'
              : status?.rpcOk
                ? 'localnet already up'
                : 'start localnet'}
          </button>
          <button
            type="button"
            className="ghost"
            onClick={() => void stopLocalnet()}
            disabled={nodeBusy !== null || !(status?.pid ?? 0)}
          >
            {nodeBusy === 'stop' ? 'stopping…' : 'stop localnet'}
          </button>
          {status?.suiBin && (
            <span
              className="result-line"
              style={{ margin: 0, color: 'var(--muted)', fontSize: '0.75rem' }}
            >
              <code>{status.suiBin}</code>
            </span>
          )}
          {nodeMsg && (
            <span className={nodeMsg.startsWith('✓') ? 'pq-chip ok' : 'pq-chip bad'}>
              {nodeMsg}
            </span>
          )}
        </div>

        <div className="pq-row">
          <span className="label">RPC URL</span>
          <input
            value={rpcUrl}
            onChange={(e) => setRpcUrl(e.target.value)}
            spellCheck={false}
            style={{ fontFamily: 'ui-monospace, monospace', fontSize: '0.82rem' }}
          />
          <span />
        </div>
        <div className="pq-row">
          <span className="label">faucet URL</span>
          <input
            value={faucetUrl}
            onChange={(e) => setFaucetUrl(e.target.value)}
            spellCheck={false}
            style={{ fontFamily: 'ui-monospace, monospace', fontSize: '0.82rem' }}
          />
          <span />
        </div>
        <div className="pq-row">
          <span className="label">address</span>
          <span className="val addr">{address || '…'}</span>
          {address && <CopyBtn value={address} />}
        </div>
        <div className="pq-row">
          <span className="label">balance</span>
          <span className="val">{balance}</span>
          <button type="button" className="copy-btn" onClick={() => void refreshBalance()}>
            refresh
          </button>
        </div>
        <div className="pq-actions">
          <button type="button" onClick={() => void dripFaucet()} disabled={!address || busy}>
            {busy ? 'requesting drip…' : 'drip from localnet faucet'}
          </button>
          <button type="button" className="ghost" onClick={regenerate} disabled={busy}>
            regenerate keypair
          </button>
          {msg && <span className={msg.startsWith('✓') ? 'pq-chip ok' : 'pq-chip bad'}>{msg}</span>}
        </div>
        <p className="result-line" style={{ marginTop: '0.75rem' }}>
          To use this signer for the on-chain section below instead of a wallet:{' '}
          <strong>
            set <code>NEXT_PUBLIC_SUI_NETWORK=localnet</code>
          </strong>{' '}
          in <code>apps/web/.env.local</code>, restart with <code>pnpm web:restart</code>, then the
          dApp will route to <code>{rpcUrl}</code> and the on-chain buttons will sign with this
          ephemeral keypair directly (skipping the wallet popup).
        </p>
      </div>
    </>
  );
}

const FAUCETS: Record<string, string> = {
  testnet: 'https://faucet.testnet.sui.io/v2/gas',
  devnet: 'https://faucet.devnet.sui.io/v2/gas',
  localnet: 'http://127.0.0.1:9123/gas',
};
const NETWORK = (process.env.NEXT_PUBLIC_SUI_NETWORK ?? 'testnet') as keyof typeof FAUCETS;

function ConnectStrip() {
  const addr = useActiveAddress();
  const client = useSuiClient();
  const [bal, setBal] = useState<string | null>(null);
  const [dripBusy, setDripBusy] = useState(false);
  const [dripMsg, setDripMsg] = useState<string | null>(null);
  async function refresh() {
    if (!addr) return setBal(null);
    try {
      const b = await client.getBalance({ owner: addr });
      setBal((Number(b.totalBalance) / 1e9).toFixed(4));
    } catch {
      setBal('?');
    }
  }
  // biome-ignore lint/correctness/useExhaustiveDependencies: re-run on addr/client change; refresh is intentionally excluded (recreated each render → would loop).
  useEffect(() => {
    void refresh();
  }, [addr, client]);

  async function drip() {
    if (!addr) return;
    setDripBusy(true);
    setDripMsg(null);
    try {
      const url = FAUCETS[NETWORK] ?? FAUCETS.testnet;
      const res = await fetch('/api/faucet', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ recipient: addr, faucetUrl: url }),
      });
      const body = await res.json();
      if (!res.ok) {
        const hint = body?.hint ? `\n${body.hint}` : '';
        throw new Error(`${body?.error ?? `HTTP ${res.status}`}${hint}`);
      }
      setDripMsg('✓ faucet drip requested · indexer ~3s');
      await new Promise((r) => setTimeout(r, 3000));
      await refresh();
    } catch (e) {
      setDripMsg(`✗ ${String(e).slice(0, 400)}`);
    } finally {
      setDripBusy(false);
    }
  }

  return (
    <div
      className="card"
      style={{
        display: 'flex',
        justifyContent: 'space-between',
        alignItems: 'center',
        gap: '1rem',
        marginBottom: '1rem',
        flexWrap: 'wrap',
      }}
    >
      <div style={{ minWidth: 0, flex: 1 }}>
        {addr ? (
          <>
            <div className="result-line" style={{ margin: 0 }}>
              <strong>connected:</strong> <code style={{ wordBreak: 'break-all' }}>{addr}</code>
            </div>
            <div className="result-line" style={{ margin: 0 }}>
              <strong>{NETWORK} balance:</strong> {bal ?? '…'} SUI · network: {NETWORK}
            </div>
            <div className="pq-actions" style={{ marginTop: '0.5rem' }}>
              <button
                type="button"
                className="ghost"
                onClick={() => void drip()}
                disabled={dripBusy}
              >
                {dripBusy ? 'requesting…' : `drip from ${NETWORK} faucet`}
              </button>
              <button type="button" className="ghost" onClick={() => void refresh()}>
                refresh balance
              </button>
              {dripMsg && (
                <span className={dripMsg.startsWith('✓') ? 'pq-chip ok' : 'pq-chip bad'}>
                  {dripMsg}
                </span>
              )}
            </div>
          </>
        ) : (
          <div className="result-line" style={{ margin: 0, color: 'var(--muted)' }}>
            Connect Slush / Suiet / Phantom / Nightly / OKX to enable real testnet txs below.
          </div>
        )}
      </div>
      <ConnectButton />
    </div>
  );
}

function RegisterAttestation({
  identity,
  pqAddress,
}: {
  identity: { pk: slh.PublicKey; sk: slh.SecretKey } | null;
  pqAddress: string;
}) {
  const wallet = useActiveAddress();
  const client = useSuiClient();
  const { mutateAsync: signAndExecute } = useSignAndExecuteTransaction();
  const [appTag, setAppTag] = useState('pqc-workbench-demo');
  const [busy, setBusy] = useState(false);
  const [out, setOut] = useState<{ digest: string; objectId?: string } | null>(null);
  const [err, setErr] = useState<string | null>(null);

  async function go() {
    if (!identity || !wallet) return;
    setBusy(true);
    setErr(null);
    setOut(null);
    try {
      // Build the BCS-encoded commit and PQ-sign it (FIPS-205-style structure).
      const nonce = crypto.getRandomValues(new Uint8Array(16));
      const tagBytes = new TextEncoder().encode(appTag);
      const senderBytes = new Uint8Array(32);
      const walletHex = wallet.replace(/^0x/, '').padStart(64, '0');
      for (let i = 0; i < 32; i++) {
        senderBytes[i] = Number.parseInt(walletHex.slice(i * 2, i * 2 + 2), 16);
      }
      // commit = sui_address || u32-le(nonce.len) || nonce || u32-le(tag.len) || tag
      // (a simple framing — the on-chain module just stores the digest, so any
      // framing your verifier replays off-chain works)
      const commit = new Uint8Array(32 + 4 + nonce.length + 4 + tagBytes.length);
      let off = 0;
      commit.set(senderBytes, off);
      off += 32;
      new DataView(commit.buffer).setUint32(off, nonce.length, true);
      off += 4;
      commit.set(nonce, off);
      off += nonce.length;
      new DataView(commit.buffer).setUint32(off, tagBytes.length, true);
      off += 4;
      commit.set(tagBytes, off);

      const digest = sha256(commit);
      const sig = slh.packSignature(slh.sign(identity.sk, digest));

      // pq_attestation::registry::register stores everything verbatim.
      const tx = new Transaction();
      tx.moveCall({
        target: `${PQ_ATTESTATION_PKG}::registry::register`,
        arguments: [
          tx.pure.u8(SCHEME.SLH_DSA_SHA2_128S), // closest standard byte; the workspace-local 0x60 isn't a published constant
          tx.pure.vector(
            'u8',
            Array.from(new Uint8Array([...identity.pk.seed, ...identity.pk.root])),
          ),
          tx.pure.vector('u8', Array.from(sig)),
          tx.pure.vector('u8', Array.from(digest)),
          tx.pure.vector('u8', Array.from(nonce)),
          tx.pure.vector('u8', Array.from(tagBytes)),
        ],
      });

      const res = await signAndExecute({ transaction: tx });
      const full = await client.waitForTransaction({
        digest: res.digest,
        options: { showObjectChanges: true },
      });
      const created = full.objectChanges?.find(
        (c) => c.type === 'created' && c.objectType.includes('::registry::Attestation'),
      );
      setOut({
        digest: res.digest,
        objectId: created && 'objectId' in created ? created.objectId : undefined,
      });
    } catch (e) {
      setErr(String(e).slice(0, 240));
    } finally {
      setBusy(false);
    }
  }

  return (
    <>
      <h2 style={{ marginTop: '1rem' }}>
        <span className="num">6a</span> Store an on-chain attestation
      </h2>
      <div className="card">
        <p className="result-line" style={{ marginBottom: '0.75rem' }}>
          Signs <code>(your wallet address, random nonce, app tag)</code> with your
          browser-generated PQ key and stores{' '}
          <strong>{`(scheme, public_key, signature, message_digest, nonce,
          app_tag, created_at_ms)`}</strong>{' '}
          on testnet as a real Sui object. Your wallet pays gas (~0.01 SUI). Anyone can re-verify
          the binding off-chain by reading the object.
        </p>
        <div className="pq-row">
          <span className="label">app tag</span>
          <input value={appTag} onChange={(e) => setAppTag(e.target.value)} spellCheck={false} />
          <span />
        </div>
        {pqAddress && (
          <div className="pq-row">
            <span className="label">PQ-derived address</span>
            <span className="val addr" style={{ fontSize: '0.78rem' }}>
              {pqAddress}
            </span>
            <CopyBtn value={pqAddress} />
          </div>
        )}
        <p
          className="result-line"
          style={{ marginTop: '0.25rem', fontSize: '0.78rem', opacity: 0.8 }}
        >
          The attestation binds two identities: the <strong>wallet address</strong> (which pays gas
          and is the sender field inside the signed commit) and the <strong>PQ public key</strong>
          (which signed the commit and would itself derive the address shown above if used as a
          primary identity).
        </p>
        <div className="pq-row">
          <span className="label">package</span>
          <code style={{ wordBreak: 'break-all', fontSize: '0.78rem' }}>{PQ_ATTESTATION_PKG}</code>
          <CopyBtn value={PQ_ATTESTATION_PKG} />
        </div>
        <div className="pq-actions">
          <button type="button" onClick={go} disabled={!identity || !wallet || busy}>
            {busy ? 'sending tx…' : 'register attestation (real testnet tx)'}
          </button>
          {!wallet && <span className="pq-chip warn">connect a wallet first</span>}
        </div>
        {out && (
          <>
            <p className="result-line" style={{ marginTop: '0.75rem' }}>
              <span className="pq-chip ok">✓ on testnet</span>
            </p>
            <p className="result-line">
              <strong>tx digest:</strong>{' '}
              <a href={suiscan(out.digest, 'tx')} target="_blank" rel="noreferrer">
                {out.digest}
              </a>
            </p>
            {out.objectId && (
              <p className="result-line">
                <strong>attestation object:</strong>{' '}
                <a href={suiscan(out.objectId)} target="_blank" rel="noreferrer">
                  {out.objectId}
                </a>
              </p>
            )}
          </>
        )}
        {err && (
          <p className="result-line" style={{ color: '#ff6b6b' }}>
            {err}
          </p>
        )}
      </div>
    </>
  );
}

/**
 * Lazily build (and cache in localStorage) a FIPS-205 SLH-DSA-SHA2-128s keypair
 * for the PQ-Guard demo. We don't reuse the LITE identity from Section 1 because
 * the on-chain verifier is FIPS-205 byte-exact — see move/slh_dsa_128s. Cache key
 * `pq-fips205-sk-b64` holds the 64-byte secret key (noble format); the pubkey is
 * re-derived deterministically from it.
 */
function loadOrCreateFips205Identity(): { publicKey: Uint8Array; secretKey: Uint8Array } {
  const cachedSeed = window.localStorage.getItem('pq-fips205-seed-b64');
  if (cachedSeed) {
    const seed = Uint8Array.from(atob(cachedSeed), (c) => c.charCodeAt(0));
    const kp = keygen('SLH_DSA_SHA2_128S', seed);
    return { publicKey: kp.publicKey, secretKey: kp.secretKey };
  }
  const seed = crypto.getRandomValues(new Uint8Array(48));
  const kp = keygen('SLH_DSA_SHA2_128S', seed);
  let str = '';
  for (let i = 0; i < seed.length; i++) str += String.fromCharCode(seed[i] ?? 0);
  window.localStorage.setItem('pq-fips205-seed-b64', btoa(str));
  return { publicKey: kp.publicKey, secretKey: kp.secretKey };
}

function RegisterPqIdentity() {
  const wallet = useActiveAddress();
  const client = useSuiClient();
  const { mutateAsync: signAndExecute } = useSignAndExecuteTransaction();
  const [busy, setBusy] = useState(false);
  const [out, setOut] = useState<{ digest: string; objectId?: string } | null>(null);
  const [err, setErr] = useState<string | null>(null);
  const [pkHex, setPkHex] = useState<string>('');

  useEffect(() => {
    try {
      const kp = loadOrCreateFips205Identity();
      setPkHex(hex(kp.publicKey));
    } catch (e) {
      setErr(`failed to derive FIPS-205 keypair: ${String(e).slice(0, 200)}`);
    }
  }, []);

  async function go() {
    if (!wallet) return;
    setBusy(true);
    setErr(null);
    setOut(null);
    try {
      const kp = loadOrCreateFips205Identity();
      const tx = new Transaction();
      tx.moveCall({
        target: `${PQ_GUARD_PKG}::pq_guard::register`,
        arguments: [
          tx.pure.u8(SCHEME.SLH_DSA_SHA2_128S), // 0x20 — FIPS-205 SLH-DSA-SHA2-128s
          tx.pure.vector('u8', Array.from(kp.publicKey)),
        ],
      });
      const res = await signAndExecute({ transaction: tx });
      const full = await client.waitForTransaction({
        digest: res.digest,
        options: { showObjectChanges: true },
      });
      const created = full.objectChanges?.find(
        (c) => c.type === 'created' && c.objectType.includes('::pq_guard::PqIdentity'),
      );
      const objectId = created && 'objectId' in created ? created.objectId : undefined;
      if (objectId) {
        window.localStorage.setItem('pqIdentityId', objectId);
      }
      setOut({ digest: res.digest, objectId });
    } catch (e) {
      setErr(String(e).slice(0, 280));
    } finally {
      setBusy(false);
    }
  }

  return (
    <>
      <h2 style={{ marginTop: '1rem' }}>
        <span className="num">6b</span> Register a `PqIdentity` for on-chain authorization
      </h2>
      <div className="card">
        <p className="result-line" style={{ marginBottom: '0.75rem' }}>
          Creates an owned <code>PqIdentity</code> object on testnet that stores your{' '}
          <strong>FIPS-205 SLH-DSA-SHA2-128s</strong> pubkey (32 bytes) and a replay-protection
          nonce. The on-chain verifier (<code>slh_dsa_128s::verifier</code>) is byte-exact against
          <code>@noble/post-quantum</code>'s audited signer. Wallet pays gas. Once registered, the
          next section can PQ-authorize Move calls — the validator's classical sig becomes just a
          gas-paying trampoline.
        </p>
        <div className="pq-row">
          <span className="label">scheme byte</span>
          <code style={{ fontSize: '0.78rem' }}>0x20 (SLH_DSA_SHA2_128S)</code>
          <span />
        </div>
        <div className="pq-row">
          <span className="label">package</span>
          <code style={{ wordBreak: 'break-all', fontSize: '0.78rem' }}>{PQ_GUARD_PKG}</code>
          <CopyBtn value={PQ_GUARD_PKG} />
        </div>
        {pkHex && (
          <div className="pq-row">
            <span className="label">PK (32B)</span>
            <span className="val" style={{ fontSize: '0.78rem' }}>
              {pkHex}
            </span>
            <CopyBtn value={pkHex} />
          </div>
        )}
        <div className="pq-actions">
          <button type="button" onClick={go} disabled={!wallet || busy || !pkHex}>
            {busy ? 'sending tx…' : 'register PqIdentity (real testnet tx)'}
          </button>
          {!wallet && <span className="pq-chip warn">connect a wallet first</span>}
        </div>
        {out && (
          <>
            <p className="result-line" style={{ marginTop: '0.75rem' }}>
              <span className="pq-chip ok">✓ on testnet</span>
            </p>
            <p className="result-line">
              <strong>tx digest:</strong>{' '}
              <a href={suiscan(out.digest, 'tx')} target="_blank" rel="noreferrer">
                {out.digest}
              </a>
            </p>
            {out.objectId && (
              <p className="result-line">
                <strong>PqIdentity object:</strong>{' '}
                <a href={suiscan(out.objectId)} target="_blank" rel="noreferrer">
                  {out.objectId}
                </a>{' '}
                (saved to localStorage so the unlock section below can use it)
              </p>
            )}
          </>
        )}
        {err && (
          <p className="result-line" style={{ color: '#ff6b6b' }}>
            {err}
          </p>
        )}
      </div>
    </>
  );
}

function UnlockPqGuard() {
  const wallet = useActiveAddress();
  const client = useSuiClient();
  const { mutateAsync: signAndExecute } = useSignAndExecuteTransaction();
  const [identityId, setIdentityId] = useState<string>('');
  const [busy, setBusy] = useState(false);
  const [out, setOut] = useState<{ digest: string; newNonce?: string } | null>(null);
  const [err, setErr] = useState<string | null>(null);

  useEffect(() => {
    const stored =
      typeof window !== 'undefined' ? window.localStorage.getItem('pqIdentityId') : null;
    if (stored) setIdentityId(stored);
  }, []);

  async function go() {
    if (!wallet || !identityId) return;
    setBusy(true);
    setErr(null);
    setOut(null);
    try {
      const kp = loadOrCreateFips205Identity();

      // Fetch the on-chain PqIdentity to learn its current nonce.
      const obj = await client.getObject({ id: identityId, options: { showContent: true } });
      const fields = (obj.data?.content as { fields?: { nonce?: string } } | undefined)?.fields;
      const nonce = BigInt(fields?.nonce ?? '0');

      // Build the unlock-message bytes EXACTLY as the Move module does:
      // tag || sender(32) || u64-be(nonce) || action_digest(32).
      const tag = new TextEncoder().encode('PQ_GUARD:UNLOCK:v1');
      const sender = new Uint8Array(32);
      const walletHex = wallet.replace(/^0x/, '').padStart(64, '0');
      for (let i = 0; i < 32; i++) {
        sender[i] = Number.parseInt(walletHex.slice(i * 2, i * 2 + 2), 16);
      }
      const nonceBytes = new Uint8Array(8);
      const dv = new DataView(nonceBytes.buffer);
      dv.setBigUint64(0, nonce, false);
      const actionDigest = sha256(new TextEncoder().encode('demo-action-unlock'));

      const msg = new Uint8Array(tag.length + 32 + 8 + 32);
      let off = 0;
      msg.set(tag, off);
      off += tag.length;
      msg.set(sender, off);
      off += 32;
      msg.set(nonceBytes, off);
      off += 8;
      msg.set(actionDigest, off);

      // FIPS-205 SLH-DSA-SHA2-128s sign via noble (the same impl that the
      // on-chain verifier is byte-exact against).
      const sig = sign({ scheme: 'SLH_DSA_SHA2_128S', secretKey: kp.secretKey }, msg);

      const tx = new Transaction();
      const [_authWitness] = tx.moveCall({
        target: `${PQ_GUARD_PKG}::pq_guard::unlock`,
        arguments: [
          tx.object(identityId),
          tx.pure.vector('u8', Array.from(actionDigest)),
          tx.pure.vector('u8', Array.from(sig)),
        ],
      });
      // The witness has no `drop`, so we must consume it. The package exposes `consume`.
      tx.moveCall({
        target: `${PQ_GUARD_PKG}::pq_guard::consume`,
        arguments: [_authWitness],
      });

      const res = await signAndExecute({ transaction: tx });
      const full = await client.waitForTransaction({
        digest: res.digest,
        options: { showEvents: true },
      });
      // Read the new nonce from the updated object
      const after = await client.getObject({ id: identityId, options: { showContent: true } });
      const newNonce = (after.data?.content as { fields?: { nonce?: string } } | undefined)?.fields
        ?.nonce;
      setOut({ digest: res.digest, newNonce });
      void full;
    } catch (e) {
      setErr(String(e).slice(0, 360));
    } finally {
      setBusy(false);
    }
  }

  return (
    <>
      <h2 style={{ marginTop: '1rem' }}>
        <span className="num">6c</span> PQ-authorize a Move call (on-chain verify)
      </h2>
      <div className="card">
        <p className="result-line" style={{ marginBottom: '0.75rem' }}>
          Sends a tx that calls <code>pq_guard::unlock</code> on testnet. The on-chain Move code
          runs the <strong>FIPS-205 SLH-DSA-SHA2-128s</strong> verifier (~2,099 SHA-256 ops inside
          Move), checks your sig over the unlock-message, increments the identity's replay nonce,
          and produces a non-storable <code>PqAuthorized</code> witness — which we immediately
          consume.{' '}
          <strong>
            The validator only ever sees your wallet's classical signature; the actual authorization
            is the PQ check inside the contract.
          </strong>
        </p>
        <div className="pq-row">
          <span className="label">PqIdentity id</span>
          <input
            value={identityId}
            onChange={(e) => setIdentityId(e.target.value)}
            placeholder="0x… (paste from section 6b or its localStorage)"
            spellCheck={false}
            style={{ fontFamily: 'ui-monospace, monospace', fontSize: '0.82rem' }}
          />
          <span />
        </div>
        <div className="pq-actions">
          <button type="button" onClick={go} disabled={!wallet || !identityId || busy}>
            {busy ? 'sending tx…' : 'unlock (real testnet tx, ~2,099 SHA-256 ops in Move)'}
          </button>
          {!wallet && <span className="pq-chip warn">connect a wallet first</span>}
          {wallet && !identityId && (
            <span className="pq-chip warn">register an identity in 6b first</span>
          )}
        </div>
        {out && (
          <>
            <p className="result-line" style={{ marginTop: '0.75rem' }}>
              <span className="pq-chip ok">✓ PQ-verify passed on-chain</span>
            </p>
            <p className="result-line">
              <strong>tx digest:</strong>{' '}
              <a href={suiscan(out.digest, 'tx')} target="_blank" rel="noreferrer">
                {out.digest}
              </a>
            </p>
            <p className="result-line">
              <strong>identity nonce advanced to:</strong> <code>{out.newNonce ?? '?'}</code> (next
              unlock must sign nonce=N+1 — replay rejected)
            </p>
          </>
        )}
        {err && (
          <p className="result-line" style={{ color: '#ff6b6b' }}>
            {err}
          </p>
        )}
      </div>
    </>
  );
}
