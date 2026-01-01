import { spawn } from 'node:child_process';
/**
 * CI-fast differential check: replay a pre-generated fixture through the Lean
 * `kat` executable and assert every case matches the embedded expected verdict.
 *
 *   pnpm exec tsx packages/pqc/scripts/run-diff-fixture.ts [path/to/fixture.jsonl]
 *
 * Default path: test-vectors/fips205-diff.jsonl
 *
 * The fixture is generated once (offline, slow noble path) by gen-diff-fixture.ts
 * and checked into the repo. CI runs only the Lean exe over it — typically
 * seconds rather than the ~30 minutes the live differential takes.
 */
import { readFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = dirname(fileURLToPath(import.meta.url));
const fixturePath = resolve(
  process.argv[2] ?? resolve(__dirname, '../../../test-vectors/fips205-diff.jsonl'),
);
const katExe = resolve(__dirname, '../../../proofs/.lake/build/bin/kat');

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
process.stderr.write(`[fixture] loaded ${cases.length} cases from ${fixturePath}\n`);

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

const startMs = Date.now();
for (const c of cases) {
  child.stdin.write(`${JSON.stringify({ pk: c.pk, msg: c.msg, sig: c.sig, ctx: c.ctx })}\n`);
}
child.stdin.end();
await done;
const elapsed = ((Date.now() - startMs) / 1000).toFixed(2);

if (lines.length !== cases.length) {
  process.stderr.write(`[fixture] expected ${cases.length} verdicts, got ${lines.length}\n`);
  process.exit(1);
}

let mismatches = 0;
let accepted = 0;
let rejected = 0;
for (let i = 0; i < cases.length; i++) {
  const leanAccepts = lines[i] === 'accept';
  if (leanAccepts) accepted++;
  else rejected++;
  if (leanAccepts !== cases[i]!.expected) {
    mismatches++;
    process.stderr.write(
      `[fixture] case ${i}: MISMATCH — fixture expected=${cases[i]!.expected}, Lean=${leanAccepts}\n`,
    );
  }
}
process.stderr.write(
  `[fixture] processed ${cases.length} cases in ${elapsed}s; accepted=${accepted}, rejected=${rejected}, mismatches=${mismatches}\n`,
);
if (mismatches > 0) process.exit(1);
process.stderr.write(`[fixture] ✓ Lean spec agrees with fixture on all ${cases.length} cases\n`);
