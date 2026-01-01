import { execSync } from 'node:child_process';
/**
 * Dry-run a FIPS-205 PQ-Guard unlock against the deployed testnet pq_guard
 * package. Measures the actual gas cost without spending SUI.
 *
 *   pnpm exec tsx scripts/pq-unlock-dryrun.ts
 *
 * Requires:
 *   PQ_GUARD_PKG    — package id (default: the latest deploy)
 *   PQ_IDENTITY_ID  — existing identity to dry-run against
 */
import { SuiClient, getFullnodeUrl } from '@mysten/sui/client';
import { Transaction } from '@mysten/sui/transactions';
import { sha256 } from '@noble/hashes/sha256';
import { slh_dsa_sha2_128s } from '@noble/post-quantum/slh-dsa.js';

const PKG = process.env.PQ_GUARD_PKG ?? '';
const IDENTITY_ID = process.env.PQ_IDENTITY_ID ?? '';
if (!PKG || !IDENTITY_ID) {
  console.error('Set PQ_GUARD_PKG and PQ_IDENTITY_ID');
  process.exit(1);
}

function activeAddress(): string {
  return execSync('sui client active-address', {
    env: { ...process.env, PATH: `${process.env.HOME}/.local/bin:${process.env.PATH}` },
  })
    .toString()
    .trim();
}

async function main(): Promise<void> {
  const sender = activeAddress();
  const network =
    (process.env.SUI_NETWORK as 'testnet' | 'mainnet' | 'devnet' | 'localnet' | undefined) ??
    'testnet';
  const url =
    process.env.SUI_RPC_URL ??
    (network === 'localnet' ? 'http://127.0.0.1:9000' : getFullnodeUrl(network));
  const client = new SuiClient({ url });

  // Reuse the script's deterministic seed convention if PQ_SEED_HEX set — otherwise
  // fail loudly, since the identity is bound to a specific pk.
  if (!process.env.PQ_SEED_HEX || process.env.PQ_SEED_HEX.length !== 96) {
    throw new Error(
      'PQ_SEED_HEX must be set (96 hex chars) and match the seed used at register time',
    );
  }
  const seed = new Uint8Array(48);
  for (let i = 0; i < 48; i++) {
    seed[i] = Number.parseInt(process.env.PQ_SEED_HEX.slice(i * 2, i * 2 + 2), 16);
  }
  const kp = slh_dsa_sha2_128s.keygen(seed);

  const obj = await client.getObject({ id: IDENTITY_ID, options: { showContent: true } });
  const fields = (obj.data?.content as { fields?: { nonce?: string; pk?: number[] } } | undefined)
    ?.fields;
  const onchainPk = new Uint8Array(fields?.pk ?? []);
  if (onchainPk.length !== 32 || !onchainPk.every((b, i) => b === kp.publicKey[i])) {
    throw new Error('On-chain pk does not match the keypair from PQ_SEED_HEX');
  }
  const nonce = BigInt(fields?.nonce ?? '0');

  const tag = new TextEncoder().encode('PQ_GUARD:UNLOCK:v1');
  const senderBytes = new Uint8Array(32);
  const hexAddr = sender.replace(/^0x/, '').padStart(64, '0');
  for (let i = 0; i < 32; i++) {
    senderBytes[i] = Number.parseInt(hexAddr.slice(i * 2, i * 2 + 2), 16);
  }
  const nonceBytes = new Uint8Array(8);
  new DataView(nonceBytes.buffer).setBigUint64(0, nonce, false);
  const actionDigest = sha256(new TextEncoder().encode('demo-action-unlock'));

  const msg = new Uint8Array(tag.length + 32 + 8 + 32);
  msg.set(tag, 0);
  msg.set(senderBytes, tag.length);
  msg.set(nonceBytes, tag.length + 32);
  msg.set(actionDigest, tag.length + 32 + 8);

  const sig = slh_dsa_sha2_128s.sign(msg, kp.secretKey);

  const tx = new Transaction();
  tx.setSender(sender);
  tx.setGasBudget(50_000_000_000n); // 50 SUI ceiling; we just want the dry-run measurement
  const [auth] = tx.moveCall({
    target: `${PKG}::pq_guard::unlock`,
    arguments: [
      tx.object(IDENTITY_ID),
      tx.pure.vector('u8', Array.from(actionDigest)),
      tx.pure.vector('u8', Array.from(sig)),
    ],
  });
  tx.moveCall({ target: `${PKG}::pq_guard::consume`, arguments: [auth!] });

  const built = await tx.build({ client });
  const res = await client.dryRunTransactionBlock({ transactionBlock: built });

  const used = res.effects.gasUsed;
  const comp = BigInt(used.computationCost);
  const stor = BigInt(used.storageCost);
  const rebate = BigInt(used.storageRebate);
  const total = comp + stor - rebate;
  console.log(`status: ${res.effects.status.status}`);
  if (res.effects.status.status !== 'success') {
    console.log(`error: ${res.effects.status.error}`);
  }
  console.log(`computation: ${comp} mist (${(Number(comp) / 1e9).toFixed(3)} SUI)`);
  console.log(`storage:     ${stor} mist (${(Number(stor) / 1e9).toFixed(3)} SUI)`);
  console.log(`rebate:      -${rebate} mist`);
  console.log(`net:         ${total} mist (${(Number(total) / 1e9).toFixed(3)} SUI)`);
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
