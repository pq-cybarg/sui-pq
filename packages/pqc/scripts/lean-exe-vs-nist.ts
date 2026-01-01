import { spawn } from 'node:child_process';
/**
 * Extraction fidelity check: run NIST ACVP test vectors through the compiled
 * Lean executable (lake exe kat) and confirm its accept/reject matches NIST's
 * published `testPassed` flag — same property already proven inside Lean via
 * `native_decide` in `Fips205/NistKat.lean`.
 *
 * This script demonstrates that the **extracted binary** (Lean → native via
 * `lake build kat`) computes the same function as the **proven-correct spec**
 * (`Fips205.Verify.verify`), for inputs that have both:
 *
 *   1. A machine-checked proof inside Lean (NistKat.lean's `nist_*` theorems).
 *   2. An official NIST-published expected result.
 *
 * If both checks pass for all NIST vectors, the extraction-time fidelity
 * holds. The residual trust is in Lean's compiler — see the README's
 * "Verified extraction" section for the honest assessment.
 */
import { existsSync, readFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = dirname(fileURLToPath(import.meta.url));
const katExe = resolve(__dirname, '../../../proofs/.lake/build/bin/kat');

// The full NIST ACVP prompt set (~30MB) is fetched out-of-band from
// usnistgov/ACVP-Server; override the locations with SLHDSA_PROMPT /
// SLHDSA_EXPECTED if you keep them elsewhere.
const promptPath = process.env.SLHDSA_PROMPT ?? '/tmp/slhdsa-prompt.json';
const expectedPath = process.env.SLHDSA_EXPECTED ?? '/tmp/slhdsa-expected.json';

// This is a *supplementary* extraction-fidelity check over the full ACVP set.
// The authoritative NIST equivalence is the `nist_*` `native_decide` theorems
// in `Fips205/NistKat.lean`, already verified by `lake build`. When the ACVP
// JSON isn't present (e.g. CI, fresh checkout) skip rather than fail — the
// proof, not this cross-check, is the gate.
if (!existsSync(promptPath) || !existsSync(expectedPath)) {
  console.warn(
    `[nist-exe] skipping: ${promptPath} / ${expectedPath} not found.
[nist-exe] (the NIST equivalence is machine-checked in Fips205/NistKat.lean;
[nist-exe]  fetch the ACVP vectors and set SLHDSA_PROMPT/SLHDSA_EXPECTED to run this cross-check.)`,
  );
  process.exit(0);
}

const prompt = JSON.parse(readFileSync(promptPath, 'utf-8'));
const expected = JSON.parse(readFileSync(expectedPath, 'utf-8'));

interface PromptGroup {
  tgId: number;
  parameterSet: string;
  signatureInterface: string;
  preHash: string;
  tests: { tcId: number; pk: string; message: string; signature: string; context?: string }[];
}
interface ExpectedGroup {
  tgId: number;
  tests: { tcId: number; testPassed: boolean }[];
}

const pg = (prompt.testGroups as PromptGroup[]).find(
  (g) =>
    g.parameterSet === 'SLH-DSA-SHA2-128s' &&
    g.signatureInterface === 'external' &&
    g.preHash === 'pure',
);
if (!pg) throw new Error('no SLH-DSA-SHA2-128s/external/pure group');
const eg = (expected.testGroups as ExpectedGroup[]).find((g) => g.tgId === pg.tgId);
if (!eg) throw new Error(`no expectedResults for tgId=${pg.tgId}`);
const expectedByTc = new Map<number, boolean>();
for (const t of eg.tests) expectedByTc.set(t.tcId, t.testPassed);

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

const sent: { tcId: number; expected: boolean }[] = [];
for (const t of pg.tests) {
  const exp = expectedByTc.get(t.tcId);
  if (exp === undefined) continue;
  const ctxHex = t.context ?? '';
  child.stdin.write(
    `${JSON.stringify({
      pk: t.pk.toLowerCase(),
      msg: t.message.toLowerCase(),
      sig: t.signature.toLowerCase(),
      ctx: ctxHex.toLowerCase(),
    })}\n`,
  );
  sent.push({ tcId: t.tcId, expected: exp });
}
child.stdin.end();
await done;

if (lines.length !== sent.length) {
  process.stderr.write(`[ext-vs-nist] expected ${sent.length} verdicts, got ${lines.length}\n`);
  process.exit(1);
}
let mismatches = 0;
let pass = 0;
let fail = 0;
for (let i = 0; i < sent.length; i++) {
  const leanAccepts = lines[i] === 'accept';
  if (leanAccepts) pass++;
  else fail++;
  if (leanAccepts !== sent[i]!.expected) {
    mismatches++;
    process.stderr.write(
      `[ext-vs-nist] tcId=${sent[i]!.tcId}: MISMATCH — NIST expected=${sent[i]!.expected}, Lean exe=${leanAccepts}\n`,
    );
  }
}
process.stderr.write(
  `[ext-vs-nist] processed ${sent.length} NIST vectors; accepted=${pass}, rejected=${fail}, mismatches=${mismatches}\n`,
);
if (mismatches > 0) process.exit(1);
process.stderr.write(
  `[ext-vs-nist] ✓ Lean-extracted binary agrees with NIST on all ${sent.length} vectors\n`,
);
