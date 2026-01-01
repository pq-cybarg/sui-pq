import { Transaction } from '@mysten/sui/transactions';
/**
 * Execute a transaction authenticated by ONLY a post-quantum signature, on a
 * Sui localnet running the PATCHED validator (native `SignatureScheme::SlhDsa`,
 * flag 0x07, verified by the RustCrypto `slh-dsa` crate). No elliptic curve
 * anywhere — the PQ-derived address is sender AND gas payer.
 *
 *   SUI_NETWORK=localnet pnpm exec tsx demos/localnet-pq/pq-only-native.ts
 *
 * Standard FIPS-205 SLH-DSA-SHA2-128s (pk 32B, sig 7,856B). Matches the
 * validator patch in crates/slh-dsa-sui/integration/:
 *   address     = blake2b256( 0x07 || pk )
 *   sign over   = blake2b256( [0,0,0] || tx_bytes )   (Sui's TransactionData intent)
 *   wire blob   = 0x07 || pk(32) || sig(7856)
 */
import { blake2b } from '@noble/hashes/blake2b';
import { slh_dsa_sha2_128s } from '@noble/post-quantum/slh-dsa.js';
import { LOCALNET_FAUCET, client, sleep } from './lib.js';

const FLAG = 0x07;
const hex = (b: Uint8Array) => Buffer.from(b).toString('hex');
const cat = (...xs: Uint8Array[]) => {
  const o = new Uint8Array(xs.reduce((a, x) => a + x.length, 0));
  let n = 0;
  for (const x of xs) {
    o.set(x, n);
    n += x.length;
  }
  return o;
};

async function main(): Promise<void> {
  const c = client();
  const chainId = await c.getChainIdentifier();
  console.log(`\nPQ-NATIVE on-chain execution — Sui localnet ${chainId} @ 127.0.0.1:9000\n`);

  // 1. SLH-DSA keypair (no elliptic curve key is ever created).
  const seed = new Uint8Array(48);
  for (let i = 0; i < 48; i++) seed[i] = (i * 11 + 7) & 0xff;
  const kp = slh_dsa_sha2_128s.keygen(seed);
  const pk = kp.publicKey; // 32 bytes

  // 2. Address derived purely from the PQ public key (matches the patch).
  const address = `0x${hex(blake2b(cat(new Uint8Array([FLAG]), pk), { dkLen: 32 }))}`;
  console.log(`  PQ address    : ${address}`);
  console.log('                  = blake2b256(0x07 || pk32) — no EC key exists\n');

  // 3. Fund it from the localnet faucet (gas owned by the PQ address).
  const r = await fetch(`${LOCALNET_FAUCET}/v2/gas`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ FixedAmountRequest: { recipient: address } }),
  });
  if (!r.ok) throw new Error(`faucet ${r.status}`);
  let funded = 0n;
  for (let i = 0; i < 40; i++) {
    funded = BigInt((await c.getBalance({ owner: address })).totalBalance);
    if (funded > 0n) break;
    await sleep(300);
  }
  console.log(`  funded        : ${funded} MIST owned by the PQ address\n`);
  if (funded === 0n) throw new Error('faucet did not fund the PQ address');

  // 4. Build a real tx (PQ address = sender + gas payer): pay itself 0.01 SUI.
  const tx = new Transaction();
  tx.setSender(address);
  tx.setGasBudget(5_000_000n);
  const [coin] = tx.splitCoins(tx.gas, [tx.pure.u64(10_000_000n)]);
  tx.transferObjects([coin], address);
  const txBytes = await tx.build({ client: c });

  // 5. Sign ONLY with SLH-DSA over the intent digest the validator checks.
  const digest = blake2b(cat(new Uint8Array([0, 0, 0]), txBytes), { dkLen: 32 });
  const sig = slh_dsa_sha2_128s.sign(digest, kp.secretKey); // 7856 bytes
  const blob = cat(new Uint8Array([FLAG]), pk, sig); // 0x07 || pk || sig
  console.log(`  signature     : ${blob.length}B blob (0x07 || pk32 || sig7856) — purely PQ\n`);

  // 6. Submit. On the patched validator this EXECUTES with no EC signature.
  try {
    const res = await c.executeTransactionBlock({
      transactionBlock: txBytes,
      signature: Buffer.from(blob).toString('base64'),
      options: { showEffects: true, showBalanceChanges: true },
    });
    const status = res.effects?.status?.status;
    console.log(`  on-chain      : status=${status}, digest=${res.digest}`);
    console.log('─'.repeat(64));
    if (status === 'success') {
      console.log('✓ PQ-ONLY TRANSACTION EXECUTED ON-CHAIN — authenticated by an');
      console.log('  SLH-DSA signature alone, zero elliptic-curve material.');
      process.exit(0);
    }
    console.log(`✗ executed but status=${status}`);
    process.exit(1);
  } catch (e) {
    console.log(`  on-chain      : REJECTED — ${String(e).slice(0, 200)}`);
    console.log('─'.repeat(64));
    console.log('✗ Not accepted. Is the localnet running the PATCHED sui-node?');
    process.exit(1);
  }
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
