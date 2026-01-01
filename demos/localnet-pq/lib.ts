/**
 * Shared helpers for the local-only post-quantum demonstration harness.
 *
 * Everything here binds to 127.0.0.1 — a Sui localnet on :9000 with its faucet
 * on :9123, and (for the off-Sui technologies) local stand-in HTTP services the
 * demos spin up themselves. No public endpoint is ever contacted.
 */
import { execFileSync } from 'node:child_process';
import { SuiClient } from '@mysten/sui/client';
import { Ed25519Keypair } from '@mysten/sui/keypairs/ed25519';
import type { Transaction } from '@mysten/sui/transactions';

export const LOCALNET_RPC = process.env.SUI_RPC_URL ?? 'http://127.0.0.1:9000';
export const LOCALNET_FAUCET = process.env.SUI_FAUCET_URL ?? 'http://127.0.0.1:9123';
const SUI_BIN = `${process.env.HOME}/.local/bin`;

export function client(): SuiClient {
  return new SuiClient({ url: LOCALNET_RPC });
}

/** The Sui CLI's active localnet keypair — it owns the packages published by
 *  `test-publish` (so it holds TreasuryCaps etc.) and is already gas-funded. */
export function activeKeypair(): Ed25519Keypair {
  const addr = execFileSync('sui', ['client', 'active-address'], {
    env: { ...process.env, PATH: `${SUI_BIN}:${process.env.PATH}` },
  })
    .toString()
    .trim();
  const out = execFileSync('sui', ['keytool', 'export', '--key-identity', addr, '--json'], {
    env: { ...process.env, PATH: `${SUI_BIN}:${process.env.PATH}` },
  }).toString();
  const bech32 = JSON.parse(out.slice(out.indexOf('{'))).exportedPrivateKey as string;
  return Ed25519Keypair.fromSecretKey(bech32);
}

/** Generate a throwaway Ed25519 keypair and fund it from the localnet faucet. */
export async function fundedKeypair(c: SuiClient): Promise<Ed25519Keypair> {
  const kp = Ed25519Keypair.generate();
  const addr = kp.toSuiAddress();
  const res = await fetch(`${LOCALNET_FAUCET}/v2/gas`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ FixedAmountRequest: { recipient: addr } }),
  });
  if (!res.ok) throw new Error(`faucet ${res.status}: ${await res.text()}`);
  // Wait for the gas coin to land.
  for (let i = 0; i < 30; i++) {
    const { totalBalance } = await c.getBalance({ owner: addr });
    if (BigInt(totalBalance) > 0n) return kp;
    await sleep(300);
  }
  throw new Error(`faucet did not fund ${addr}`);
}

/** test-publish a Move package to localnet; returns its packageId.
 *  Each call uses a fresh ephemeral pubfile so re-runs always publish clean. */
let pubCounter = 0;
export function publishPackage(path: string): string {
  const name = path.split('/').filter(Boolean).pop();
  const pubfile = `${process.env.TMPDIR ?? '/tmp'}/sui-pub-${name}-${process.pid}-${pubCounter++}.toml`;
  let out: string;
  try {
    out = execFileSync(
      'sui',
      [
        'client',
        'test-publish',
        path,
        '--build-env',
        'mainnet',
        '--with-unpublished-dependencies',
        '--pubfile-path',
        pubfile,
        '--json',
      ],
      {
        env: { ...process.env, PATH: `${SUI_BIN}:${process.env.PATH}` },
        maxBuffer: 64 * 1024 * 1024,
      },
    ).toString();
  } catch (e) {
    const err = e as { stdout?: Buffer; stderr?: Buffer };
    throw new Error(
      `publish ${path} failed: ${(err.stderr?.toString() ?? '') + (err.stdout?.toString() ?? '')}`
        .replace(/INCLUDING DEPENDENCY.*\n|BUILDING.*\n|\[NOTE\].*\n/g, '')
        .slice(0, 300),
    );
  }
  const json = JSON.parse(out.slice(out.indexOf('{')));
  if (json.effects?.status?.status !== 'success') {
    throw new Error(`publish ${path} failed: ${JSON.stringify(json.effects?.status)}`);
  }
  const pubs = (json.objectChanges ?? []).filter((o: { type: string }) => o.type === 'published');
  if (pubs.length === 0) throw new Error(`no published object for ${path}`);
  // The root package is the one whose modules include the package's own name.
  const root = pubs.find((p: { modules?: string[] }) => p.modules?.includes(name ?? '')) ?? pubs[0];
  return root.packageId as string;
}

/** Like publishPackage but returns a module→packageId map across the package
 *  and all its (unpublished) dependencies — needed when a demo spans packages
 *  that share a type (e.g. pq_vault consumes pq_guard's PqAuthorized). */
export function publishWithDeps(path: string): Record<string, string> {
  const name = path.split('/').filter(Boolean).pop();
  const pubfile = `${process.env.TMPDIR ?? '/tmp'}/sui-pub-${name}-${process.pid}-${pubCounter++}.toml`;
  const out = execFileSync(
    'sui',
    [
      'client',
      'test-publish',
      path,
      '--build-env',
      'mainnet',
      '--with-unpublished-dependencies',
      '--pubfile-path',
      pubfile,
      '--json',
    ],
    {
      env: { ...process.env, PATH: `${SUI_BIN}:${process.env.PATH}` },
      maxBuffer: 64 * 1024 * 1024,
    },
  ).toString();
  const json = JSON.parse(out.slice(out.indexOf('{')));
  if (json.effects?.status?.status !== 'success') throw new Error(`publish ${path} failed`);
  const map: Record<string, string> = {};
  for (const p of json.objectChanges ?? []) {
    if (p.type === 'published') for (const mod of p.modules ?? []) map[mod] = p.packageId;
  }
  return map;
}

/** Sign + execute a PTB, returning created objects and asserting success. */
export async function run(
  c: SuiClient,
  kp: Ed25519Keypair,
  tx: Transaction,
): Promise<{ digest: string; created: { type: string; objectId: string }[]; events: unknown[] }> {
  tx.setSenderIfNotSet(kp.toSuiAddress());
  const res = await c.signAndExecuteTransaction({
    signer: kp,
    transaction: tx,
    options: { showEffects: true, showObjectChanges: true, showEvents: true },
  });
  await c.waitForTransaction({ digest: res.digest });
  if (res.effects?.status?.status !== 'success') {
    throw new Error(`tx failed: ${JSON.stringify(res.effects?.status)}`);
  }
  const created = (res.objectChanges ?? [])
    .filter(
      (o): o is { type: 'created'; objectType: string; objectId: string } => o.type === 'created',
    )
    .map((o) => ({ type: o.objectType, objectId: o.objectId }));
  return { digest: res.digest, created, events: res.events ?? [] };
}

export function sleep(ms: number): Promise<void> {
  return new Promise((r) => setTimeout(r, ms));
}

/** Pretty PASS/FAIL row accumulator. */
export class Matrix {
  private rows: { tech: string; ok: boolean; detail: string }[] = [];
  pass(tech: string, detail: string): void {
    this.rows.push({ tech, ok: true, detail });
    console.log(`  \x1b[32m✓\x1b[0m ${tech.padEnd(16)} ${detail}`);
  }
  fail(tech: string, detail: string): void {
    this.rows.push({ tech, ok: false, detail });
    console.log(`  \x1b[31m✗\x1b[0m ${tech.padEnd(16)} ${detail}`);
  }
  summary(): boolean {
    const ok = this.rows.filter((r) => r.ok).length;
    console.log(`\n${'─'.repeat(60)}`);
    console.log(`localnet PQ demo: ${ok}/${this.rows.length} scenarios passed`);
    return ok === this.rows.length;
  }
}
