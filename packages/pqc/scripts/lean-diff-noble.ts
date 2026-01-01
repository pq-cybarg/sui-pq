import { spawn } from 'node:child_process';
import { randomBytes } from 'node:crypto';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
/**
 * Differential equivalence test: noble vs Lean spec on N random cases.
 *
 *   pnpm exec tsx packages/pqc/scripts/lean-diff-noble.ts [N]
 *
 * For each case we:
 *   - Generate a noble keypair from a random 48-byte seed.
 *   - Sign a random-length, random-content message.
 *   - With 50% probability, intentionally tamper one signature byte.
 *   - Compute noble's verify verdict (the audited oracle).
 *   - Stream a JSONL line {pk, msg, sig, ctx} into the `lake exe kat` binary.
 *   - Read Lean's verdict back.
 *   - Assert they agree.
 *
 * This is differential testing, not formal proof — but it covers thousands of
 * inputs that no `native_decide`-based proof could practically enumerate, and
 * any disagreement immediately falsifies "Lean spec ≡ noble" on the diverging
 * input. The pairwise companions are the per-case `native_decide` proofs in
 * `Fips205/Kat.lean` and `Fips205/NistKat.lean` — those give zero-doubt
 * machine-checked equivalence on specific vectors; this harness sweeps the
 * input space.
 */
import { slh_dsa_sha2_128s } from '@noble/post-quantum/slh-dsa.js';

const N = Number.parseInt(process.argv[2] ?? '100', 10);
if (!Number.isFinite(N) || N <= 0) {
  process.stderr.write('Usage: lean-diff-noble.ts [N=100]\n');
  process.exit(2);
}

const __dirname = dirname(fileURLToPath(import.meta.url));
const katExe = resolve(__dirname, '../../../proofs/.lake/build/bin/kat');

function hex(bytes: Uint8Array): string {
  let s = '';
  for (let i = 0; i < bytes.length; i++) s += bytes[i]!.toString(16).padStart(2, '0');
  return s;
}

interface Case {
  pk: Uint8Array;
  msg: Uint8Array;
  sig: Uint8Array;
  ctx: Uint8Array;
  expectedAccept: boolean;
  tampered: boolean;
}

function genCase(i: number): Case {
  const seed = randomBytes(48);
  const kp = slh_dsa_sha2_128s.keygen(seed);
  const msgLen = (i * 7) % 200; // varying message lengths, 0..199
  const msg = randomBytes(msgLen);
  let sig = slh_dsa_sha2_128s.sign(msg, kp.secretKey, { extraEntropy: false });

  // Tamper roughly half the cases.
  const tampered = i % 2 === 0;
  if (tampered) {
    const sigBuf = new Uint8Array(sig);
    const tamperOffset = (i * 137) % sigBuf.length;
    sigBuf[tamperOffset] = (sigBuf[tamperOffset]! ^ 0xff) & 0xff;
    sig = sigBuf;
  }

  const expectedAccept = slh_dsa_sha2_128s.verify(sig, msg, kp.publicKey);
  if (tampered && expectedAccept) {
    // 2^-128 chance — but if it happens we shouldn't claim the tamper rejects.
    process.stderr.write(`[diff] case ${i}: tampered sig still verified (cosmic)\n`);
  }
  return { pk: kp.publicKey, msg, sig, ctx: new Uint8Array(0), expectedAccept, tampered };
}

process.stderr.write(`[diff] generating ${N} random cases…\n`);
const cases: Case[] = [];
for (let i = 0; i < N; i++) cases.push(genCase(i));

const child = spawn(katExe, [], { stdio: ['pipe', 'pipe', 'inherit'] });

const leanLines: string[] = [];
let leanBuf = '';
child.stdout.on('data', (chunk: Buffer) => {
  leanBuf += chunk.toString('utf-8');
  const lines = leanBuf.split('\n');
  leanBuf = lines.pop() ?? '';
  for (const ln of lines) leanLines.push(ln.trim());
});

const childDone = new Promise<void>((res, rej) => {
  child.on('close', (code) => {
    if (leanBuf.trim().length > 0) leanLines.push(leanBuf.trim());
    if (code !== 0) rej(new Error(`kat exited with code ${code}`));
    else res();
  });
});

const startMs = Date.now();
for (const c of cases) {
  const line = JSON.stringify({ pk: hex(c.pk), msg: hex(c.msg), sig: hex(c.sig), ctx: hex(c.ctx) });
  child.stdin.write(`${line}\n`);
}
child.stdin.end();
await childDone;
const elapsed = ((Date.now() - startMs) / 1000).toFixed(2);

if (leanLines.length !== N) {
  process.stderr.write(`[diff] expected ${N} verdicts from Lean, got ${leanLines.length}\n`);
  process.exit(1);
}

let mismatches = 0;
let acceptedCount = 0;
let rejectedCount = 0;
for (let i = 0; i < N; i++) {
  const leanAccepts = leanLines[i] === 'accept';
  const nobleAccepts = cases[i]!.expectedAccept;
  if (leanAccepts) acceptedCount++;
  else rejectedCount++;
  if (leanAccepts !== nobleAccepts) {
    mismatches++;
    process.stderr.write(
      `[diff] case ${i}: MISMATCH — noble=${nobleAccepts}, Lean=${leanAccepts}, tampered=${cases[i]!.tampered}\n`,
    );
  }
}

process.stderr.write(
  `[diff] processed ${N} cases in ${elapsed}s; accepted=${acceptedCount}, rejected=${rejectedCount}, mismatches=${mismatches}\n`,
);
if (mismatches > 0) process.exit(1);
process.stderr.write(`[diff] ✓ Lean spec and noble agree on all ${N} cases\n`);
