import { Transaction } from '@mysten/sui/transactions';
/**
 * Exhaustive Sui-feature test suite driven entirely by a PQ-only account —
 * every transaction authenticated by ONLY an SLH-DSA-SHA2-128s signature
 * (flag 0x07), no elliptic-curve key anywhere — against the patched validator.
 *
 *   SUI_NETWORK=localnet pnpm exec tsx demos/localnet-pq/pq-exhaustive.ts
 *
 * Covers: SUI transfer, multi-recipient pay, coin split/merge, publish a Move
 * package FROM the PQ account, owned-object move calls (create + mutate),
 * NFT mint + object transfer, TreasuryCap coin mint, a multi-command PTB, and
 * (PQ-on-PQ) a contract-layer pq_guard/pq_vault flow whose outer transaction is
 * itself PQ-only — a shared object plus a PQ-authorized withdrawal.
 */
import { sha256 } from '@noble/hashes/sha256';
import { slh_dsa_sha2_128s } from '@noble/post-quantum/slh-dsa.js';
import { addPqGuardUnlock, buildUnlockMessageBytes } from '@sui-gen/pqc';
import { Matrix, client, publishWithDeps } from './lib.js';
import { type PqAccount, cat, dumpBytecode, fund, pqAccount, pqExec } from './pq-sign.js';

const SLH_DSA_SHA2_128S = 0x20;

function enc(s: string): number[] {
  return Array.from(new TextEncoder().encode(s));
}
function addr32(hex: string): Uint8Array {
  const h = (hex.startsWith('0x') ? hex.slice(2) : hex).padStart(64, '0');
  const out = new Uint8Array(32);
  for (let i = 0; i < 32; i++) out[i] = Number.parseInt(h.slice(i * 2, i * 2 + 2), 16);
  return out;
}
function u64be(v: bigint): Uint8Array {
  const out = new Uint8Array(8);
  let n = v;
  for (let i = 7; i >= 0; i--) {
    out[i] = Number(n & 0xffn);
    n >>= 8n;
  }
  return out;
}

async function main(): Promise<void> {
  const c = client();
  const m = new Matrix();
  const run = process.env.PQ_RUN ?? `${process.pid}`; // fresh recipients each run
  const A = pqAccount('pq-exhaustive:A');
  const B = pqAccount(`pq-exhaustive:B:${run}`);
  const C = pqAccount(`pq-exhaustive:C:${run}`);
  console.log(`\nExhaustive PQ-only feature suite — Sui localnet ${await c.getChainIdentifier()}`);
  console.log(`account A (PQ): ${A.address}\n`);
  await fund(c, A.address);

  // 1. transfer SUI A -> B
  try {
    const tx = new Transaction();
    const [coin] = tx.splitCoins(tx.gas, [tx.pure.u64(50_000_000n)]);
    tx.transferObjects([coin], B.address);
    await pqExec(c, A, tx);
    const bal = BigInt((await c.getBalance({ owner: B.address })).totalBalance);
    bal === 50_000_000n
      ? m.pass('transfer-sui', `0.05 SUI -> B (B balance ${bal})`)
      : m.fail('transfer-sui', `B=${bal}`);
  } catch (e) {
    m.fail('transfer-sui', String(e));
  }

  // 2. pay multiple recipients in one tx
  try {
    const tx = new Transaction();
    const [c1, c2] = tx.splitCoins(tx.gas, [tx.pure.u64(20_000_000n), tx.pure.u64(30_000_000n)]);
    tx.transferObjects([c1], B.address);
    tx.transferObjects([c2], C.address);
    await pqExec(c, A, tx);
    const cb = BigInt((await c.getBalance({ owner: C.address })).totalBalance);
    cb === 30_000_000n
      ? m.pass('pay-multiple', `split to B and C (C=${cb})`)
      : m.fail('pay-multiple', `C=${cb}`);
  } catch (e) {
    m.fail('pay-multiple', String(e));
  }

  // 3. split then merge coins (object consumption)
  try {
    const tx = new Transaction();
    const [a, b] = tx.splitCoins(tx.gas, [tx.pure.u64(10_000_000n), tx.pure.u64(10_000_000n)]);
    tx.mergeCoins(a, [b]);
    tx.transferObjects([a], A.address);
    const r = await pqExec(c, A, tx);
    m.pass('coin-merge', `split+merge+return in one PTB, tx ${r.digest.slice(0, 8)}…`);
  } catch (e) {
    m.fail('coin-merge', String(e));
  }

  // 4. publish a Move package FROM the PQ account
  let counterPkg = '';
  try {
    const { modules, dependencies } = dumpBytecode('move/counter');
    const tx = new Transaction();
    const cap = tx.publish({ modules, dependencies });
    tx.transferObjects([cap], A.address);
    const r = await pqExec(c, A, tx);
    counterPkg = r.published[0] ?? '';
    counterPkg
      ? m.pass('publish', `counter published by PQ account: ${counterPkg.slice(0, 12)}…`)
      : m.fail('publish', 'no package id');
  } catch (e) {
    m.fail('publish', String(e));
  }

  // 5 + 6. owned-object move call: create + mutate
  try {
    const tx = new Transaction();
    tx.moveCall({ target: `${counterPkg}::counter::create` });
    const r1 = await pqExec(c, A, tx);
    const counter = r1.created.find((o) => o.type.endsWith('::counter::Counter'));
    if (!counter) throw new Error('no Counter');
    const tx2 = new Transaction();
    tx2.moveCall({
      target: `${counterPkg}::counter::increment`,
      arguments: [tx2.object(counter.objectId)],
    });
    await pqExec(c, A, tx2);
    const v = (await c.getObject({ id: counter.objectId, options: { showContent: true } })).data
      ?.content as { fields?: { value?: string } } | undefined;
    v?.fields?.value === '1'
      ? m.pass('movecall', 'counter::create + increment, value==1')
      : m.fail('movecall', `value=${v?.fields?.value}`);
  } catch (e) {
    m.fail('movecall', String(e));
  }

  // 7. NFT mint + object transfer (A mints, transfers to B)
  try {
    const { modules, dependencies } = dumpBytecode('move/nft');
    const tx = new Transaction();
    const cap = tx.publish({ modules, dependencies });
    tx.transferObjects([cap], A.address);
    const pkg = (await pqExec(c, A, tx)).published[0];
    const tx2 = new Transaction();
    tx2.moveCall({
      target: `${pkg}::genesis_nft::mint`,
      arguments: [
        tx2.pure.vector('u8', enc('PQ NFT')),
        tx2.pure.vector('u8', enc('minted by PQ acct')),
        tx2.pure.vector('u8', enc('https://x.invalid/p.png')),
        tx2.pure.address(A.address),
      ],
    });
    const nft = (await pqExec(c, A, tx2)).created.find((o) =>
      o.type.endsWith('::genesis_nft::GenesisNFT'),
    );
    if (!nft) throw new Error('no NFT');
    const tx3 = new Transaction();
    tx3.transferObjects([tx3.object(nft.objectId)], B.address);
    await pqExec(c, A, tx3);
    const owner = (await c.getObject({ id: nft.objectId, options: { showOwner: true } })).data
      ?.owner as { AddressOwner?: string };
    owner?.AddressOwner === B.address
      ? m.pass('nft+transfer', 'minted then transferred NFT to B')
      : m.fail('nft+transfer', `owner=${JSON.stringify(owner)}`);
  } catch (e) {
    m.fail('nft+transfer', String(e));
  }

  // 8. TreasuryCap coin mint (publish demo_coin from PQ, cap owned by A, mint)
  try {
    const { modules, dependencies } = dumpBytecode('move/coin');
    const tx = new Transaction();
    const cap = tx.publish({ modules, dependencies });
    tx.transferObjects([cap], A.address);
    const pub = await pqExec(c, A, tx);
    const pkg = pub.published[0];
    const treasury = pub.created.find((o) => o.type.includes('TreasuryCap'));
    if (!treasury) throw new Error('no TreasuryCap');
    const tx2 = new Transaction();
    tx2.moveCall({
      target: `${pkg}::demo_coin::mint`,
      arguments: [
        tx2.object(treasury.objectId),
        tx2.pure.u64(1_000_000n),
        tx2.pure.address(A.address),
      ],
    });
    const minted = (await pqExec(c, A, tx2)).created.find((o) => o.type.includes('DEMO_COIN'));
    minted
      ? m.pass('coin-mint', 'published coin + minted 1,000,000 DEMO_COIN')
      : m.fail('coin-mint', 'no coin minted');
  } catch (e) {
    m.fail('coin-mint', String(e));
  }

  // 9. multi-command atomic PTB: split + moveCall(increment) + transfer
  try {
    const tx = new Transaction();
    tx.moveCall({ target: `${counterPkg}::counter::create` });
    const [tip] = tx.splitCoins(tx.gas, [tx.pure.u64(1_000_000n)]);
    tx.transferObjects([tip], C.address);
    const r = await pqExec(c, A, tx);
    r.created.some((o) => o.type.endsWith('::counter::Counter'))
      ? m.pass('multi-ptb', 'create + split + transfer atomic in one PTB')
      : m.fail('multi-ptb', 'no Counter');
  } catch (e) {
    m.fail('multi-ptb', String(e));
  }

  // 10. shared object + PQ-on-PQ: pq_vault opened + PQ-authorized withdraw,
  //     the OUTER tx itself signed only by SLH-DSA. (pq_vault has inter-package
  //     deps, so it is published via CLI; every CALL below is PQ-signed.)
  try {
    const active = (await import('node:child_process'))
      .execFileSync('sui', ['client', 'active-address'], {
        env: { ...process.env, PATH: `${process.env.HOME}/.local/bin:${process.env.PATH}` },
      })
      .toString()
      .trim();
    await fund(c, active);
    const pkgs = publishWithDeps('move/pq_vault');
    const vaultPkg = pkgs.vault ?? pkgs.pq_vault;
    const guardPkg = pkgs.pq_guard;

    // register a PQ identity (contract-layer), owned by A
    const vseed = new Uint8Array([
      ...sha256(new TextEncoder().encode('vault-id:0')),
      ...sha256(new TextEncoder().encode('vault-id:1')).slice(0, 16),
    ]);
    const pq = slh_dsa_sha2_128s.keygen(vseed);
    const reg = new Transaction();
    reg.moveCall({
      target: `${guardPkg}::pq_guard::register`,
      arguments: [reg.pure.u8(SLH_DSA_SHA2_128S), reg.pure.vector('u8', Array.from(pq.publicKey))],
    });
    const identity = (await pqExec(c, A, reg)).created.find((o) =>
      o.type.endsWith('::pq_guard::PqIdentity'),
    );
    if (!identity) throw new Error('no PqIdentity');

    // open a shared Vault with 0.5 SUI
    const open = new Transaction();
    const [seed] = open.splitCoins(open.gas, [open.pure.u64(500_000_000n)]);
    open.moveCall({ target: `${vaultPkg}::vault::open`, arguments: [seed] });
    const vault = (await pqExec(c, A, open)).created.find((o) => o.type.endsWith('::vault::Vault'));
    if (!vault) throw new Error('no shared Vault');

    // PQ-authorized withdraw of 0.2 SUI to B
    const amount = 200_000_000n;
    const actionDigest = sha256(
      cat(
        new TextEncoder().encode('PQ_VAULT:WITHDRAW:v1'),
        addr32(vault.objectId),
        addr32(B.address),
        u64be(amount),
      ),
    );
    const idObj = await c.getObject({ id: identity.objectId, options: { showContent: true } });
    const nonce = BigInt(
      (idObj.data?.content as { fields?: { nonce?: string } })?.fields?.nonce ?? '0',
    );
    const sig = slh_dsa_sha2_128s.sign(
      buildUnlockMessageBytes({ sender: A.address, nonce, actionDigest }),
      pq.secretKey,
    );
    const wd = new Transaction();
    wd.setGasBudget(5_000_000_000n); // on-chain Move SLH-DSA verify is gas-heavy (~1.5 SUI)
    const authorized = addPqGuardUnlock(wd, {
      guardPackageId: guardPkg,
      identityId: identity.objectId,
      actionDigest,
      signature: sig,
    });
    const [coin] = wd.moveCall({
      target: `${vaultPkg}::vault::withdraw`,
      arguments: [
        wd.object(vault.objectId),
        authorized,
        wd.pure.address(B.address),
        wd.pure.u64(amount),
      ],
    });
    wd.transferObjects([coin], B.address);
    await pqExec(c, A, wd);
    m.pass('shared+pq-on-pq', 'shared Vault + PQ-authorized withdraw, outer tx PQ-only');
  } catch (e) {
    m.fail('shared+pq-on-pq', String(e));
  }

  const ok = m.summary();
  process.exit(ok ? 0 : 1);
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
