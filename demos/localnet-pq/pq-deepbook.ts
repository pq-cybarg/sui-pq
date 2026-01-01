/**
 * REAL (not mocked) DeepBook v3 integration, driven by a post-quantum
 * SLH-DSA-only account on the patched localnet.
 *
 * This publishes the *actual upstream* MystenLabs/deepbookv3 Move packages
 * (token + deepbook) to the local validator, then — signed only by an SLH-DSA
 * key (scheme 0x07, no elliptic curve) — creates a real DeepBook pool, a real
 * BalanceManager (DeepBook's on-chain trading account), funds it, and places a
 * real on-chain limit order on DeepBook's CLOB.
 *
 * Prereq: clone the upstream once (a sibling of the sui checkout):
 *   git clone https://github.com/MystenLabs/deepbookv3 ~/.local/share/pq-sui/deepbookv3
 *   # point the token dep local + strip mainnet published-ids so it republishes:
 *   (handled by demos/localnet-pq/setup-deepbook.sh)
 */
import { execFileSync } from 'node:child_process';
import { SuiClient } from '@mysten/sui/client';
import type { SuiObjectChange } from '@mysten/sui/client';
import { Transaction } from '@mysten/sui/transactions';
import { SlhDsaSigner, faucet, pqRun } from './pq-signer.js';

const RPC = 'http://127.0.0.1:9000';
const FAUCET = 'http://127.0.0.1:9123';
const SUI_BIN = `${process.env.HOME}/.local/share/pq-sui/bin`;
const DEEPBOOK = `${process.env.HOME}/.local/share/pq-sui/deepbookv3`;
const RUN = process.env.PQ_RUN ?? `${process.pid}`;
const sui = new SuiClient({ url: RPC });

type Created = Extract<SuiObjectChange, { type: 'created' }>;
type Published = Extract<SuiObjectChange, { type: 'published' }>;
const created = (cs: SuiObjectChange[], f: (t: string) => boolean) =>
  cs.filter((o): o is Created => o.type === 'created').find((o) => f(o.objectType));

function buildPkg(path: string, withDeps: boolean): { modules: string[]; dependencies: string[] } {
  const args = [
    'move',
    'build',
    '--dump-bytecode-as-base64',
    '--build-env',
    'mainnet',
    '--path',
    path,
  ];
  if (withDeps) args.push('--with-unpublished-dependencies');
  const out = execFileSync('sui', args, {
    env: { ...process.env, PATH: `${SUI_BIN}:${process.env.PATH}` },
    maxBuffer: 256 * 1024 * 1024,
  }).toString();
  return JSON.parse(out.slice(out.indexOf('{')));
}

async function publish(signer: SlhDsaSigner, path: string, withDeps: boolean) {
  const { modules, dependencies } = buildPkg(path, withDeps);
  const tx = new Transaction();
  const cap = tx.publish({ modules, dependencies });
  tx.transferObjects([cap], signer.toSuiAddress());
  const res = await pqRun(sui, signer, tx);
  const changes = res.objectChanges ?? [];
  const published = changes.filter((o): o is Published => o.type === 'published');
  return { published, changes };
}

const ok = (label: string, detail: string) => console.log(`  ✓ ${label.padEnd(18)} ${detail}`);

async function main() {
  console.log(
    `\nREAL DeepBook v3 on localnet ${await sui.getChainIdentifier()}, PQ-only signer (0x07)\n`,
  );
  const pq = SlhDsaSigner.fromLabel(`pq-deepbook:${RUN}`);
  await faucet(sui, pq.toSuiAddress(), FAUCET);
  await faucet(sui, pq.toSuiAddress(), FAUCET); // extra gas for the large publish
  console.log(`PQ trader: ${pq.toSuiAddress()}\n`);

  // 1. Publish the real upstream deepbook + token, plus a base coin (DEMO).
  const demo = await publish(pq, 'move/coin', false);
  const demoPkg = demo.published[0].packageId;
  const BASE = `${demoPkg}::demo_coin::DEMO_COIN`;
  const QUOTE = '0x2::sui::SUI';

  const db = await publish(pq, `${DEEPBOOK}/packages/deepbook`, true);
  // two packages publish (token + deepbook); deepbook is the one with `pool`.
  const deepbookPkg = db.published.find((p) => p.modules.includes('pool'))?.packageId;
  if (!deepbookPkg) throw new Error('deepbook package not found among published');
  const registry = created(db.changes, (t) => t.endsWith('::registry::Registry'))?.objectId;
  const adminCap = created(db.changes, (t) => t.endsWith('::registry::DeepbookAdminCap'))?.objectId;
  if (!registry || !adminCap) throw new Error('Registry / DeepbookAdminCap not created');
  ok('publish', `real deepbook ${deepbookPkg.slice(0, 10)}… (Registry + AdminCap owned by PQ)`);

  // 2. Admin-create a REAL whitelisted pool DEMO/SUI (zero DEEP fee), PQ-signed.
  const poolTx = new Transaction();
  poolTx.moveCall({
    target: `${deepbookPkg}::pool::create_pool_admin`,
    typeArguments: [BASE, QUOTE],
    arguments: [
      poolTx.object(registry),
      poolTx.pure.u64(1000n), // tick_size
      poolTx.pure.u64(1_000_000n), // lot_size
      poolTx.pure.u64(1_000_000n), // min_size
      poolTx.pure.bool(true), // whitelisted_pool (no DEEP fees)
      poolTx.pure.bool(false), // stable_pool
      poolTx.object(adminCap),
    ],
  });
  const poolRes = await pqRun(sui, pq, poolTx);
  const poolId = created(poolRes.objectChanges ?? [], (t) => t.includes('::pool::Pool<'))?.objectId;
  if (!poolId) throw new Error('Pool not created');
  ok('create pool', `real DeepBook Pool<DEMO,SUI> ${poolId.slice(0, 10)}… (admin, whitelisted)`);

  // 3. REAL BalanceManager + deposit SUI quote + place a REAL limit bid — one PTB, PQ-signed.
  const t = new Transaction();
  const bm = t.moveCall({ target: `${deepbookPkg}::balance_manager::new` });
  const proof = t.moveCall({
    target: `${deepbookPkg}::balance_manager::generate_proof_as_owner`,
    arguments: [bm],
  });
  const [quoteCoin] = t.splitCoins(t.gas, [100_000_000n]); // 0.1 SUI as quote
  t.moveCall({
    target: `${deepbookPkg}::balance_manager::deposit`,
    typeArguments: [QUOTE],
    arguments: [bm, quoteCoin],
  });
  t.moveCall({
    target: `${deepbookPkg}::pool::place_limit_order`,
    typeArguments: [BASE, QUOTE],
    arguments: [
      t.object(poolId),
      bm,
      proof,
      t.pure.u64(1n), // client_order_id
      t.pure.u8(0), // order_type = NO_RESTRICTION
      t.pure.u8(0), // self_matching_option = SELF_MATCHING_ALLOWED
      t.pure.u64(1_000_000_000n), // price (1.0 at 1e9 float scaling)
      t.pure.u64(2_000_000n), // quantity (≥ min_size, multiple of lot_size)
      t.pure.bool(true), // is_bid
      t.pure.bool(false), // pay_with_deep (whitelisted pool)
      t.pure.u64(18446744073709551615n), // expire_timestamp = max u64
      t.object('0x6'), // Clock
    ],
  });
  t.moveCall({
    target: '0x2::transfer::public_share_object',
    typeArguments: [`${deepbookPkg}::balance_manager::BalanceManager`],
    arguments: [bm],
  });
  const orderRes = await pqRun(sui, pq, t);
  const placed = (orderRes.events ?? []).some((e) => e.type.includes('OrderPlaced'));
  ok(
    'limit order',
    `placed on-chain → ${orderRes.digest.slice(0, 12)}…${placed ? ' (OrderPlaced emitted)' : ''}`,
  );

  console.log('\n✅ Real upstream DeepBook v3 CLOB: pool created, balance manager funded, and a');
  console.log('   limit order placed on-chain — authorized by an SLH-DSA key, no elliptic curve.');
}

main().catch((e) => {
  console.error('✗', e?.message ?? e);
  process.exitCode = 1;
});
