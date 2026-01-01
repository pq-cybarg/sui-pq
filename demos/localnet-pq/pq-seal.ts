/**
 * REAL Seal (threshold IBE) end-to-end, locally, gated by a post-quantum
 * SLH-DSA-only account on the patched localnet.
 *
 * Uses the *actual upstream* `seal-cli` (MystenLabs/seal: Boneh-Franklin IBKEM
 * over BLS12-381 + AES-256-GCM) as a LOCAL key server, and enforces Seal's
 * on-chain access policy for real: the `seal_demo::allowlist::seal_approve`
 * entry function — the exact gate a Seal key server dry-runs before releasing a
 * key share — is checked on-chain against an allowlist whose membership is
 * managed by the PQ account (PQ-signed). Decryption only proceeds because the PQ
 * account passes the on-chain gate; a non-member is rejected (negative control).
 *
 * Prereq: build seal-cli once (a sibling of the sui checkout):
 *   bash demos/localnet-pq/setup-seal.sh
 */
import { execFileSync } from 'node:child_process';
import { SuiClient } from '@mysten/sui/client';
import type { SuiObjectChange } from '@mysten/sui/client';
import { Transaction } from '@mysten/sui/transactions';
import { dumpBytecode } from './pq-sign.js';
import { SlhDsaSigner, faucet, pqRun } from './pq-signer.js';

const RPC = 'http://127.0.0.1:9000';
const FAUCET = 'http://127.0.0.1:9123';
const SEAL = `${process.env.HOME}/.local/share/pq-sui/seal/target/release/seal-cli`;
const RUN = process.env.PQ_RUN ?? `${process.pid}`;
const sui = new SuiClient({ url: RPC });
// A fixed on-chain id binding for the local key server (seal-cli plays the server).
const KEY_SERVER = `0x${'a'.repeat(64)}`;

const cli = (...args: string[]) =>
  execFileSync(SEAL, args, { maxBuffer: 16 * 1024 * 1024 }).toString();
const grab = (s: string, label: string) =>
  s
    .split('\n')
    .find((l) => l.includes(label))
    ?.match(/0x[0-9a-f]+/i)?.[0] ?? '';
const ok = (label: string, detail: string) => console.log(`  ✓ ${label.padEnd(16)} ${detail}`);

async function sealApprovePasses(pkg: string, allowlist: string, sender: string): Promise<boolean> {
  // Dry-run the key server's gate: seal_approve(id, allowlist) as `sender`.
  const tx = new Transaction();
  tx.moveCall({
    target: `${pkg}::allowlist::seal_approve`,
    arguments: [
      tx.pure.vector('u8', [...Buffer.from(allowlist.slice(2), 'hex')]),
      tx.object(allowlist),
    ],
  });
  const r = await sui.devInspectTransactionBlock({ sender, transactionBlock: tx });
  return r.effects?.status?.status === 'success';
}

async function main() {
  console.log(`\nREAL Seal IBE, PQ-gated — localnet ${await sui.getChainIdentifier()}\n`);
  const pq = SlhDsaSigner.fromLabel(`pq-seal:${RUN}`);
  await faucet(sui, pq.toSuiAddress(), FAUCET);
  console.log(`PQ actor: ${pq.toSuiAddress()}\n`);

  // 0. Local key server keypair (real Seal master/public key).
  const gk = cli('genkey');
  const master = grab(gk, 'Master key');
  const pub = grab(gk, 'Public key');
  ok('key server', `local seal-cli key server (BLS12-381 pub ${pub.slice(0, 14)}…)`);

  // 1. Publish the seal_demo access-policy package (PQ-signed).
  const { modules, dependencies } = dumpBytecode('move/seal_demo');
  const pubTx = new Transaction();
  pubTx.transferObjects([pubTx.publish({ modules, dependencies })], pq.toSuiAddress());
  const pubRes = await pqRun(sui, pq, pubTx);
  const pkg = (pubRes.objectChanges ?? []).find(
    (o): o is Extract<SuiObjectChange, { type: 'published' }> => o.type === 'published',
  )?.packageId as string;

  // 2. Create the allowlist + add the PQ account (the on-chain access policy).
  const createTx = new Transaction();
  createTx.moveCall({ target: `${pkg}::allowlist::create` });
  const cRes = await pqRun(sui, pq, createTx);
  const allowlist = (cRes.objectChanges ?? []).find(
    (o): o is Extract<SuiObjectChange, { type: 'created' }> =>
      o.type === 'created' && o.objectType.endsWith('::allowlist::Allowlist'),
  )?.objectId as string;
  const addTx = new Transaction();
  addTx.moveCall({
    target: `${pkg}::allowlist::add`,
    arguments: [addTx.object(allowlist), addTx.pure.address(pq.toSuiAddress())],
  });
  await pqRun(sui, pq, addTx);
  ok(
    'access policy',
    `seal_demo ${pkg.slice(0, 10)}…, PQ account added to allowlist ${allowlist.slice(0, 10)}…`,
  );

  // 3. Encrypt a secret to the allowlist identity with the REAL Seal IBE.
  const secret = `post-quantum seal secret ${RUN}`;
  const msgHex = Buffer.from(secret).toString('hex');
  const encOut = cli(
    'encrypt-aes',
    '--message',
    msgHex,
    '--package-id',
    pkg,
    '--id',
    allowlist,
    '--threshold',
    '1',
    pub,
    '--',
    KEY_SERVER,
  );
  const encObj = grab(encOut, 'Encrypted object');
  ok('encrypt', `real Boneh-Franklin/BLS IBKEM + AES-256-GCM (object ${encObj.length} hex chars)`);

  // 4. The key server's gate, on-chain: seal_approve must pass for the PQ
  //    account and FAIL for a non-member (real access control, PQ-signed policy).
  const memberOk = await sealApprovePasses(pkg, allowlist, pq.toSuiAddress());
  const outsider = SlhDsaSigner.fromLabel(`pq-seal:outsider:${RUN}`).toSuiAddress();
  const outsiderOk = await sealApprovePasses(pkg, allowlist, outsider);
  if (!memberOk) throw new Error('PQ member failed the seal_approve gate');
  if (outsiderOk) throw new Error('non-member passed the gate (should be rejected)');
  ok(
    'on-chain gate',
    'seal_approve PASSES for PQ member, ABORTS for non-member (key server check)',
  );

  // 5. Gate passed → key server releases the share (extract), client decrypts.
  const usk = grab(
    cli('extract', '--package-id', pkg, '--id', allowlist, '--master-key', master),
    '0x',
  );
  const decOut = cli('decrypt', encObj, usk, '--', KEY_SERVER);
  const recovered = Buffer.from(grab(decOut, 'Decrypted message').slice(2), 'hex').toString();
  if (recovered !== secret) throw new Error(`decrypt mismatch: ${recovered}`);
  ok('decrypt', `recovered plaintext via key-server share: "${recovered}"`);

  console.log('\n✅ Real Seal IBE round-trip, with the on-chain access policy enforced and');
  console.log('   managed by an SLH-DSA-only account — the key server only releases the');
  console.log('   share because the PQ account passes seal_approve on the patched localnet.');
}

main().catch((e) => {
  console.error('✗', e?.message ?? e);
  process.exitCode = 1;
});
