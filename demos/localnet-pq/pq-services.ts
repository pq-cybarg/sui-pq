/**
 * Run each ecosystem package's REAL client flow against a LOCAL MIMIC of its
 * live network, with every on-chain action signed by an SLH-DSA-only account
 * (0x07, no elliptic curve) on the patched localnet.
 *
 * Public networks don't carry the PQ scheme (it's a validator patch), so we run
 * a local instance/mimic of each off-Sui service (Walrus publisher/aggregator,
 * Lumiwave REST) and drive the unmodified package against it. The crypto-bearing
 * networks (Pyth/Wormhole guardian, Seal key server, zkLogin prover) are stood
 * up in their own demos (pq-pyth.ts, …) because they need real key material.
 */
import { SuiClient } from '@mysten/sui/client';
import type { SuiObjectChange } from '@mysten/sui/client';
import { Transaction } from '@mysten/sui/transactions';
import { buildLwaTransfer, getLwaBalance } from '@sui-gen/lumiwave';
import { LumiwaveService } from '@sui-gen/lumiwave';
import { WalrusHttpClient } from '@sui-gen/walrus-client';
import { startLumiwave, startWalrus } from './local-mimics.js';
import { dumpBytecode } from './pq-sign.js';
import { SlhDsaSigner, faucet, pqRun } from './pq-signer.js';

const RPC = 'http://127.0.0.1:9000';
const FAUCET = 'http://127.0.0.1:9123';
const RUN = process.env.PQ_RUN ?? `${process.pid}`;
const sui = new SuiClient({ url: RPC });
const ok = (label: string, detail: string) => console.log(`  ✓ ${label.padEnd(14)} ${detail}`);

type Created = Extract<SuiObjectChange, { type: 'created' }>;
const created = (cs: SuiObjectChange[], f: (t: string) => boolean) =>
  cs.filter((o): o is Created => o.type === 'created').find((o) => f(o.objectType));

async function main() {
  console.log(`\nLocal-mimic services, PQ-signed — localnet ${await sui.getChainIdentifier()}\n`);
  const pq = SlhDsaSigner.fromLabel(`pq-svc:${RUN}`);
  await faucet(sui, pq.toSuiAddress(), FAUCET);
  console.log(`PQ actor: ${pq.toSuiAddress()}\n`);

  // ── walrus: real WalrusHttpClient against a local publisher/aggregator ──
  {
    const walrus = await startWalrus();
    process.env.WALRUS_PUBLISHER_URL = walrus.url;
    process.env.WALRUS_AGGREGATOR_URL = walrus.url;
    try {
      const w = new WalrusHttpClient();
      const payload = `pq walrus payload ${RUN}`;
      const put = await w.put(payload);
      const got = await w.getText(put.blobId);
      if (got !== payload) throw new Error('walrus round-trip mismatch');
      ok(
        'walrus',
        `real WalrusHttpClient put/get vs local node mimic (blob ${put.blobId.slice(0, 14)}…)`,
      );
    } finally {
      walrus.close();
    }
  }

  // ── lumiwave: real LumiwaveService.resolveHandle → real on-chain LWA xfer ──
  {
    // publish a stand-in LWA coin and mint to the PQ account
    const { modules, dependencies } = dumpBytecode('move/coin');
    const pubTx = new Transaction();
    const cap0 = pubTx.publish({ modules, dependencies });
    pubTx.transferObjects([cap0], pq.toSuiAddress());
    const pub = await pqRun(sui, pq, pubTx);
    const published = (pub.objectChanges ?? []).find(
      (o): o is Extract<SuiObjectChange, { type: 'published' }> => o.type === 'published',
    );
    const pkg = published?.packageId ?? '';
    const coinType = `${pkg}::demo_coin::DEMO_COIN`;
    const cap = created(pub.objectChanges ?? [], (t) => t.includes('TreasuryCap'))
      ?.objectId as string;

    const recipient = SlhDsaSigner.fromLabel(`pq-svc:gamer:${RUN}`).toSuiAddress();
    const mint = new Transaction();
    mint.moveCall({
      target: `${pkg}::demo_coin::mint`,
      arguments: [
        mint.object(cap),
        mint.pure.u64(5_000_000n),
        mint.pure.address(pq.toSuiAddress()),
      ],
    });
    await pqRun(sui, pq, mint);

    // start the Lumiwave REST mimic; map a handle → the recipient address
    const lumi = await startLumiwave({ gamer123: recipient });
    try {
      const svc = new LumiwaveService({ rpcUrl: lumi.url });
      const resolved = await svc.resolveHandle('gamer123'); // REAL client → local mimic
      if (resolved?.address !== recipient) throw new Error('handle resolution mismatch');
      // real on-chain LWA transfer to the resolved address, PQ-signed
      const tx = await buildLwaTransfer({
        client: sui,
        from: pq.toSuiAddress(),
        to: resolved.address,
        amount: 1_000_000n,
        coinType,
      });
      const res = await pqRun(sui, pq, tx);
      const bal = await getLwaBalance(resolved.address, { client: sui, coinType });
      ok(
        'lumiwave',
        `resolveHandle('gamer123')→${resolved.address.slice(0, 10)}… then on-chain LWA xfer ${res.digest.slice(0, 10)}…, bal ${bal}`,
      );
    } finally {
      lumi.close();
    }
  }

  console.log('\n✅ Walrus and Lumiwave: each package drives its real client against a local');
  console.log('   network mimic, with on-chain actions authorized by an SLH-DSA key.');
}

main().catch((e) => {
  console.error('✗', e?.message ?? e);
  process.exitCode = 1;
});
