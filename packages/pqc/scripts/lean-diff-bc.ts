import { spawn } from 'node:child_process';
/**
 * Runtime fixture differential between the Lean spec verifier and the
 * bytecode-composition verifier.
 *
 *   pnpm exec tsx packages/pqc/scripts/lean-diff-bc.ts [path/to/fixture.jsonl]
 *
 * Default fixture: test-vectors/fips205-diff.jsonl (1000 cases).
 *
 * Runs every case through BOTH `kat` (Fips205.Verify.verify) and `kat-bc`
 * (Fips205.Move.Composition.verifyViaBC_full) and asserts each pair agrees.
 *
 * This extends the per-case `native_decide` equivalence proofs in
 * Composition.lean (`verifyViaBC_equiv_spec_on_*`) from ~17 specific
 * vectors to 1000 random cases — without paying the kernel-reduction cost
 * of 1000 native_decide proofs. Each `kat-bc` execution is a *runtime*
 * call into the compiled bytecode-composition function, dispatched
 * through the Move VM `step` semantics that we've already proven correct
 * via the per-primitive proofs.
 *
 * If this passes, we have empirical evidence on 1000 random tuples that
 * the bytecode-composition verifier is functionally equivalent to the
 * spec verifier — a much broader coverage than the 17 native_decide proofs.
 */
import { readFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = dirname(fileURLToPath(import.meta.url));
const fixturePath = resolve(
  process.argv[2] ?? resolve(__dirname, '../../../test-vectors/fips205-diff.jsonl'),
);
const katExe = resolve(__dirname, '../../../proofs/.lake/build/bin/kat');
const katBcExe = resolve(__dirname, '../../../proofs/.lake/build/bin/kat-bc');

interface FixtureCase {
  pk: string;
  msg: string;
  sig: string;
  ctx: string;
  expected: boolean;
}

const text = readFileSync(fixturePath, 'utf-8');
const cases: FixtureCase[] = text
  .split('\n')
  .filter((l) => l.trim().length > 0)
  .map((l) => JSON.parse(l) as FixtureCase);
process.stderr.write(`[diff-bc] loaded ${cases.length} cases from ${fixturePath}\n`);

async function runExe(exe: string, label: string): Promise<string[]> {
  const child = spawn(exe, [], { stdio: ['pipe', 'pipe', 'inherit'] });
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
      if (code !== 0) rej(new Error(`${label} exit ${code}`));
      else res();
    });
  });
  const t0 = Date.now();
  for (const c of cases) {
    child.stdin.write(`${JSON.stringify({ pk: c.pk, msg: c.msg, sig: c.sig, ctx: c.ctx })}\n`);
  }
  child.stdin.end();
  await done;
  const elapsed = ((Date.now() - t0) / 1000).toFixed(2);
  process.stderr.write(`[diff-bc] ${label}: ${lines.length} verdicts in ${elapsed}s\n`);
  return lines;
}

const [specLines, bcLines] = await Promise.all([
  runExe(katExe, 'spec (kat)'),
  runExe(katBcExe, 'bytecode (kat-bc)'),
]);

if (specLines.length !== cases.length) {
  process.stderr.write(
    `[diff-bc] expected ${cases.length} spec verdicts, got ${specLines.length}\n`,
  );
  process.exit(1);
}
if (bcLines.length !== cases.length) {
  process.stderr.write(
    `[diff-bc] expected ${cases.length} bytecode verdicts, got ${bcLines.length}\n`,
  );
  process.exit(1);
}

let mismatches = 0;
let specBcDisagree = 0;
let bcExpectedDisagree = 0;
let specExpectedDisagree = 0;
let acc = 0;
let rej = 0;
for (let i = 0; i < cases.length; i++) {
  const spec = specLines[i] === 'accept';
  const bc = bcLines[i] === 'accept';
  const exp = cases[i]!.expected;
  if (bc) acc++;
  else rej++;
  if (spec !== bc) {
    specBcDisagree++;
    process.stderr.write(`[diff-bc] case ${i}: spec=${spec}, bytecode=${bc} (mismatch)\n`);
  }
  if (bc !== exp) bcExpectedDisagree++;
  if (spec !== exp) specExpectedDisagree++;
  if (spec !== bc || bc !== exp) mismatches++;
}

process.stderr.write(
  `[diff-bc] processed ${cases.length} cases\n` +
    `[diff-bc]   bytecode accepted/rejected: ${acc}/${rej}\n` +
    `[diff-bc]   spec ↔ bytecode mismatches: ${specBcDisagree}\n` +
    `[diff-bc]   bytecode ↔ fixture mismatches: ${bcExpectedDisagree}\n` +
    `[diff-bc]   spec ↔ fixture mismatches: ${specExpectedDisagree}\n`,
);
if (mismatches > 0) process.exit(1);
process.stderr.write(
  `[diff-bc] ✓ spec and bytecode-composition verifiers agree on all ${cases.length} fixture cases\n`,
);
