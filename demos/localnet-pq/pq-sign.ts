/**
 * Reusable PQ-only account + transaction executor for the patched validator.
 * Every transaction is authenticated by ONLY an SLH-DSA-SHA2-128s signature
 * (flag 0x07) — no elliptic-curve key exists. Shared by the exhaustive
 * feature suite (pq-exhaustive.ts) and pq-only-native.ts.
 */
import { execFileSync } from 'node:child_process';
import type { SuiClient } from '@mysten/sui/client';
import type { Transaction } from '@mysten/sui/transactions';
import { blake2b } from '@noble/hashes/blake2b';
import { slh_dsa_sha2_128s } from '@noble/post-quantum/slh-dsa.js';
import { LOCALNET_FAUCET, sleep } from './lib.js';

const FLAG = 0x07;
const SUI_BIN = `${process.env.HOME}/.local/share/pq-sui/sui/target/release`;

export function cat(...xs: Uint8Array[]): Uint8Array {
  const o = new Uint8Array(xs.reduce((a, x) => a + x.length, 0));
  let n = 0;
  for (const x of xs) {
    o.set(x, n);
    n += x.length;
  }
  return o;
}
const toHex = (b: Uint8Array) => Buffer.from(b).toString('hex');

export interface PqAccount {
  pk: Uint8Array;
  sk: Uint8Array;
  address: string;
}

/** Deterministic PQ-only account: address = blake2b256(0x07 || pk). No EC key. */
export function pqAccount(label: string): PqAccount {
  const seed = new Uint8Array(48);
  const h = blake2b(new TextEncoder().encode(label), { dkLen: 48 });
  seed.set(h);
  const kp = slh_dsa_sha2_128s.keygen(seed);
  const address = `0x${toHex(blake2b(cat(new Uint8Array([FLAG]), kp.publicKey), { dkLen: 32 }))}`;
  return { pk: kp.publicKey, sk: kp.secretKey, address };
}

/** Fund a PQ address from the localnet faucet. */
export async function fund(c: SuiClient, address: string): Promise<bigint> {
  const r = await fetch(`${LOCALNET_FAUCET}/v2/gas`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ FixedAmountRequest: { recipient: address } }),
  });
  if (!r.ok) throw new Error(`faucet ${r.status}`);
  for (let i = 0; i < 40; i++) {
    const bal = BigInt((await c.getBalance({ owner: address })).totalBalance);
    if (bal > 0n) return bal;
    await sleep(300);
  }
  throw new Error(`faucet did not fund ${address}`);
}

export interface PqResult {
  digest: string;
  created: { type: string; objectId: string }[];
  published: string[];
  events: { type: string }[];
}

/** Sign a built transaction with ONLY SLH-DSA and execute it. */
export async function pqExec(c: SuiClient, acct: PqAccount, tx: Transaction): Promise<PqResult> {
  tx.setSenderIfNotSet(acct.address);
  if (!tx.blockData?.gasConfig?.budget) tx.setGasBudget(200_000_000n);
  const txBytes = await tx.build({ client: c });
  const digestToSign = blake2b(cat(new Uint8Array([0, 0, 0]), txBytes), { dkLen: 32 });
  const sig = slh_dsa_sha2_128s.sign(digestToSign, acct.sk); // 7856B
  const blob = cat(new Uint8Array([FLAG]), acct.pk, sig); // 0x07 || pk || sig
  const res = await c.executeTransactionBlock({
    transactionBlock: txBytes,
    signature: Buffer.from(blob).toString('base64'),
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
  const published = (res.objectChanges ?? [])
    .filter((o): o is { type: 'published'; packageId: string } => o.type === 'published')
    .map((o) => o.packageId);
  return {
    digest: res.digest,
    created,
    published,
    events: (res.events ?? []) as { type: string }[],
  };
}

/** Compile a Move package to publishable bytecode (modules + dependency ids). */
export function dumpBytecode(path: string): { modules: string[]; dependencies: string[] } {
  const out = execFileSync(
    'sui',
    ['move', 'build', '--dump-bytecode-as-base64', '--build-env', 'mainnet', '--path', path],
    {
      env: { ...process.env, PATH: `${SUI_BIN}:${process.env.PATH}` },
      maxBuffer: 64 * 1024 * 1024,
    },
  ).toString();
  const json = JSON.parse(out.slice(out.indexOf('{')));
  return { modules: json.modules, dependencies: json.dependencies };
}
