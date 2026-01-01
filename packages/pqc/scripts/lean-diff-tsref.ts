import { spawn } from 'node:child_process';
import { randomBytes } from 'node:crypto';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
/**
 * Three-way differential equivalence check: noble ↔ Lean spec ↔ our TS reference.
 *
 *   pnpm exec tsx packages/pqc/scripts/lean-diff-tsref.ts [N=100]
 *
 * The Lean spec is the verification-proven reference. Noble is the audited
 * external impl. Our TS reference (`packages/pqc/src/slh-dsa-128s-ref.ts`)
 * is the bridge between the Lean spec and the Move impl: we already prove
 * Lean ≡ Move at the source level (in MoveEquiv) and Lean ≡ noble
 * (in Kat/NistKat), so adding Lean ≡ TS closes the triangle and catches
 * any drift in our own TS reference.
 *
 * For each random (pk, msg, sig) we assert all three impls return the same
 * accept/reject verdict. The TS reference is the most subtle of the three
 * since it's hand-written and not formally checked outside this harness.
 */
import { slh_dsa_sha2_128s } from '@noble/post-quantum/slh-dsa.js';
import { verify as tsRefVerify } from '../src/slh-dsa-128s-ref.js';

const N = Number.parseInt(process.argv[2] ?? '100', 10);
if (!Number.isFinite(N) || N <= 0) {
  process.stderr.write('Usage: lean-diff-tsref.ts [N=100]\n');
  process.exit(2);
}

const __dirname = dirname(fileURLToPath(import.meta.url));
const katExe = resolve(__dirname, '../../../proofs/.lake/build/bin/kat');

function hex(b: Uint8Array): string {
  let s = '';
  for (let i = 0; i < b.length; i++) s += b[i]!.toString(16).padStart(2, '0');
  return s;
}

interface Case {
  pk: Uint8Array;
  msg: Uint8Array;
  sig: Uint8Array;
  ctx: Uint8Array;
  noble: boolean;
  tsRef: boolean;
}

function genCase(i: number): Case {
  const seed = randomBytes(48);
  const kp = slh_dsa_sha2_128s.keygen(seed);
  const msg = randomBytes((i * 11) % 250);
  let sig = slh_dsa_sha2_128s.sign(msg, kp.secretKey, { extraEntropy: false });
  if (i % 2 === 0) {
    // Tamper half the cases.
    const buf = new Uint8Array(sig);
    const off = (i * 89) % buf.length;
    buf[off] = (buf[off]! ^ 0xff) & 0xff;
    sig = buf;
  }
  const noble = slh_dsa_sha2_128s.verify(sig, msg, kp.publicKey);
  let tsRef: boolean;
  try {
    tsRef = tsRefVerify(kp.publicKey, msg, sig);
  } catch {
    tsRef = false;
  }
  return { pk: kp.publicKey, msg, sig, ctx: new Uint8Array(0), noble, tsRef };
}

process.stderr.write(`[diff3] generating ${N} random cases…\n`);
const cases: Case[] = [];
for (let i = 0; i < N; i++) cases.push(genCase(i));

// Stream cases into the Lean exe.
const child = spawn(katExe, [], { stdio: ['pipe', 'pipe', 'inherit'] });
const lines: string[] = [];
let buf = '';
child.stdout.on('data', (chunk: Buffer) => {
  buf += chunk.toString('utf-8');
  const split = buf.split('\n');
  buf = split.pop() ?? '';
  for (const l of split) lines.push(l.trim());
});
const done = new Promise<void>((res, rej) => {
  child.on('close', (code) => {
    if (buf.trim()) lines.push(buf.trim());
    if (code !== 0) rej(new Error(`kat exit ${code}`));
    else res();
  });
});

for (const c of cases) {
  child.stdin.write(
    `${JSON.stringify({ pk: hex(c.pk), msg: hex(c.msg), sig: hex(c.sig), ctx: hex(c.ctx) })}\n`,
  );
}
child.stdin.end();
await done;

let nobleVsLean = 0;
let tsVsLean = 0;
let tsVsNoble = 0;
let acc = 0;
let rej = 0;

for (let i = 0; i < N; i++) {
  const lean = lines[i] === 'accept';
  const c = cases[i]!;
  if (lean) acc++;
  else rej++;
  if (lean !== c.noble) {
    nobleVsLean++;
    process.stderr.write(`[diff3] case ${i}: noble=${c.noble}, Lean=${lean} (mismatch)\n`);
  }
  if (lean !== c.tsRef) {
    tsVsLean++;
    process.stderr.write(`[diff3] case ${i}: tsRef=${c.tsRef}, Lean=${lean} (mismatch)\n`);
  }
  if (c.noble !== c.tsRef) {
    tsVsNoble++;
    process.stderr.write(`[diff3] case ${i}: noble=${c.noble}, tsRef=${c.tsRef} (mismatch)\n`);
  }
}

process.stderr.write(
  `[diff3] processed ${N} cases; accepted=${acc}, rejected=${rej}\n` +
    `[diff3]   noble↔Lean mismatches:  ${nobleVsLean}\n` +
    `[diff3]   tsRef↔Lean mismatches:  ${tsVsLean}\n` +
    `[diff3]   noble↔tsRef mismatches: ${tsVsNoble}\n`,
);
if (nobleVsLean + tsVsLean + tsVsNoble > 0) process.exit(1);
process.stderr.write(
  `[diff3] ✓ all three impls (Lean, noble, TS reference) agree on all ${N} cases\n`,
);
