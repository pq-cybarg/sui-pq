/**
 * Pre-generate a deterministic fixture of N (pk, msg, sig, expected) tuples
 * for use as a CI gate. The expensive part (noble keygen + sign) runs once;
 * CI just compares the Lean exe's verdicts to the embedded expectations.
 *
 *   pnpm exec tsx packages/pqc/scripts/gen-diff-fixture.ts [N=1000] > test-vectors/fips205-diff.jsonl
 *
 * Each output line is one JSON object:
 *   {"pk":"<hex>", "msg":"<hex>", "sig":"<hex>", "ctx":"<hex>", "expected":true|false}
 *
 * Tampered cases use a deterministic byte-flip pattern so the fixture is
 * fully reproducible from the seed. Re-running the generator should produce
 * byte-identical output.
 */
import { slh_dsa_sha2_128s } from '@noble/post-quantum/slh-dsa.js';

const N = Number.parseInt(process.argv[2] ?? '1000', 10);
if (!Number.isFinite(N) || N <= 0) {
  process.stderr.write('Usage: gen-diff-fixture.ts [N=1000]\n');
  process.exit(2);
}

function hex(bytes: Uint8Array): string {
  let s = '';
  for (let i = 0; i < bytes.length; i++) s += bytes[i]!.toString(16).padStart(2, '0');
  return s;
}

function deterministicSeed(i: number): Uint8Array {
  // Stable, salted-by-index seed so each case is reproducible.
  const seed = new Uint8Array(48);
  for (let j = 0; j < 48; j++) seed[j] = (i * 251 + j * 37 + 19) & 0xff;
  return seed;
}

function deterministicMessage(i: number): Uint8Array {
  // Vary message length 0..199 deterministically; content too.
  const len = (i * 7) % 200;
  const m = new Uint8Array(len);
  for (let j = 0; j < len; j++) m[j] = (i * 13 + j * 41 + 5) & 0xff;
  return m;
}

process.stderr.write(`[gen-fixture] generating ${N} cases…\n`);
const startMs = Date.now();
for (let i = 0; i < N; i++) {
  const kp = slh_dsa_sha2_128s.keygen(deterministicSeed(i));
  const msg = deterministicMessage(i);
  let sig = slh_dsa_sha2_128s.sign(msg, kp.secretKey, { extraEntropy: false });

  // Tamper roughly half the cases deterministically.
  const tampered = i % 2 === 0;
  if (tampered) {
    const sigBuf = new Uint8Array(sig);
    const offset = (i * 137) % sigBuf.length;
    sigBuf[offset] = (sigBuf[offset]! ^ 0xff) & 0xff;
    sig = sigBuf;
  }

  const expected = slh_dsa_sha2_128s.verify(sig, msg, kp.publicKey);

  const line = JSON.stringify({
    pk: hex(kp.publicKey),
    msg: hex(msg),
    sig: hex(sig),
    ctx: '',
    expected,
  });
  process.stdout.write(`${line}\n`);

  if ((i + 1) % 100 === 0) {
    const elapsed = (Date.now() - startMs) / 1000;
    const rate = (i + 1) / elapsed;
    process.stderr.write(`[gen-fixture] ${i + 1}/${N} (${rate.toFixed(1)} cases/s)\n`);
  }
}
const elapsed = ((Date.now() - startMs) / 1000).toFixed(1);
process.stderr.write(`[gen-fixture] ✓ ${N} cases in ${elapsed}s\n`);
