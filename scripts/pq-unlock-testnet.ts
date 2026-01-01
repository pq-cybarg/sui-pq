import { execSync } from 'node:child_process';
import { randomBytes } from 'node:crypto';
/**
 * End-to-end FIPS-205 PQ-Guard unlock against the deployed testnet pq_guard
 * package.
 *
 * Proves the on-chain SLH-DSA-SHA2-128s verifier (move/slh_dsa_128s) accepts a
 * signature produced by @noble/post-quantum's audited signer. Uses the CLI's
 * active testnet wallet as the gas payer (the "classical-sig trampoline"); the
 * actual authorization is the PQ check inside the contract.
 *
 *   pnpm exec tsx scripts/pq-unlock-testnet.ts
 *
 * Env vars:
 *   PQ_GUARD_PKG   — package id of the pq_guard publication to use (required;
 *                    defaults to the existing LITE-flavored deployment, which
 *                    will NOT accept FIPS-205 sigs — redeploy from
 *                    move/pq_guard after updating it).
 *   PQ_IDENTITY_ID — reuse an existing PqIdentity instead of registering fresh
 *                    (optional).
 *   PQ_SEED_HEX    — 96-hex-char deterministic seed for the FIPS-205 keypair
 *                    (optional; default is a fresh `crypto.randomBytes(48)`
 *                    so each run produces a genuinely new keypair).
 */
import { SuiClient, getFullnodeUrl } from '@mysten/sui/client';
import { decodeSuiPrivateKey } from '@mysten/sui/cryptography';
import { Ed25519Keypair } from '@mysten/sui/keypairs/ed25519';
import { Transaction } from '@mysten/sui/transactions';
import { sha256 } from '@noble/hashes/sha256';
import { slh_dsa_sha2_128s } from '@noble/post-quantum/slh-dsa.js';

const PKG =
  process.env.PQ_GUARD_PKG ?? '0x444ba4085ecb14e7db320128266b0b29c1ca2f024beaf49dbd8413bb0da17142';
const SCHEME_BYTE = 0x20; // FIPS-205 SLH-DSA-SHA2-128s (workspace registry)

function suiCliSigner(): Ed25519Keypair {
  const out = execSync('sui keytool export --key-identity $(sui client active-address) --json', {
    env: { ...process.env, PATH: `${process.env.HOME}/.local/bin:${process.env.PATH}` },
  }).toString();
  const m = out.match(/"exportedPrivateKey":\s*"([^"]+)"/);
  if (!m) throw new Error(`could not export CLI active key:\n${out}`);
  const { secretKey } = decodeSuiPrivateKey(m[1]!);
  return Ed25519Keypair.fromSecretKey(secretKey);
}

function hex(b: Uint8Array): string {
  return Array.from(b)
    .map((x) => x.toString(16).padStart(2, '0'))
    .join('');
}

async function main(): Promise<void> {
  // FIPS-205 keypair: default to fresh entropy so the pk shown is genuinely random.
  // PQ_SEED_HEX is opt-in for deterministic re-runs (useful when reusing
  // PQ_IDENTITY_ID across runs).
  let seed: Uint8Array;
  if (process.env.PQ_SEED_HEX) {
    if (process.env.PQ_SEED_HEX.length !== 96) {
      throw new Error('PQ_SEED_HEX must be 96 hex chars (48 bytes)');
    }
    seed = new Uint8Array(48);
    for (let i = 0; i < 48; i++) {
      seed[i] = Number.parseInt(process.env.PQ_SEED_HEX.slice(i * 2, i * 2 + 2), 16);
    }
    console.log('[pq-unlock] using deterministic seed from PQ_SEED_HEX');
  } else {
    seed = randomBytes(48);
    console.log(`[pq-unlock] generated random keygen seed (48B): ${hex(seed).slice(0, 24)}…`);
  }
  const kp = slh_dsa_sha2_128s.keygen(seed);
  console.log(`[pq-unlock] FIPS-205 pk (32B) = ${hex(kp.publicKey)}`);

  const wallet = suiCliSigner();
  const sender = wallet.toSuiAddress();
  console.log(`[pq-unlock] sender (classical, pays gas) = ${sender}`);

  const network =
    (process.env.SUI_NETWORK as 'testnet' | 'mainnet' | 'devnet' | 'localnet' | undefined) ??
    'testnet';
  const url =
    process.env.SUI_RPC_URL ??
    (network === 'localnet' ? 'http://127.0.0.1:9000' : getFullnodeUrl(network));
  console.log(`[pq-unlock] using ${network} RPC at ${url}`);
  const client = new SuiClient({ url });

  // 1. Register a fresh PqIdentity unless an existing one is supplied.
  let identityId = process.env.PQ_IDENTITY_ID;
  if (!identityId) {
    console.log('[pq-unlock] registering a fresh FIPS-205 PqIdentity…');
    const tx = new Transaction();
    tx.moveCall({
      target: `${PKG}::pq_guard::register`,
      arguments: [tx.pure.u8(SCHEME_BYTE), tx.pure.vector('u8', Array.from(kp.publicKey))],
    });
    const res = await client.signAndExecuteTransaction({
      transaction: tx,
      signer: wallet,
      options: { showObjectChanges: true, showEffects: true },
    });
    if (res.effects?.status?.status !== 'success') {
      throw new Error(`register failed: ${JSON.stringify(res.effects?.status)}`);
    }
    const created = res.objectChanges?.find(
      (c) => c.type === 'created' && c.objectType.includes('::pq_guard::PqIdentity'),
    );
    if (!created || !('objectId' in created)) throw new Error('no PqIdentity created');
    identityId = created.objectId;
    console.log(`[pq-unlock] registered: ${identityId}`);
    console.log(`[pq-unlock] tx: ${res.digest}`);
  } else {
    console.log(`[pq-unlock] reusing identity ${identityId}`);
  }

  // 2. Read current nonce.
  const obj = await client.getObject({ id: identityId, options: { showContent: true } });
  const fields = (obj.data?.content as { fields?: { nonce?: string } } | undefined)?.fields;
  const nonce = BigInt(fields?.nonce ?? '0');
  console.log(`[pq-unlock] identity.nonce = ${nonce}`);

  // 3. Build the exact bytes that Move's unlock_message_bytes computes.
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

  // 4. Sign with FIPS-205 SLH-DSA-SHA2-128s.
  const sig = slh_dsa_sha2_128s.sign(msg, kp.secretKey);
  console.log(`[pq-unlock] signed (${sig.length}B)`);

  // 5. Submit unlock + consume.
  const tx = new Transaction();
  // FIPS-205 verify is ~2,099 SHA-256 calls + heavy vector work; default-only is far too low.
  // 10 SUI ceiling; tx consumes only what's actually used.
  tx.setGasBudget(10_000_000_000n);
  const [auth] = tx.moveCall({
    target: `${PKG}::pq_guard::unlock`,
    arguments: [
      tx.object(identityId),
      tx.pure.vector('u8', Array.from(actionDigest)),
      tx.pure.vector('u8', Array.from(sig)),
    ],
  });
  tx.moveCall({ target: `${PKG}::pq_guard::consume`, arguments: [auth!] });

  console.log(
    '[pq-unlock] submitting unlock tx (on-chain FIPS-205 SLH-DSA verify, ~2,099 SHA-256 ops in Move)…',
  );
  const res = await client.signAndExecuteTransaction({
    transaction: tx,
    signer: wallet,
    options: { showEffects: true, showEvents: true },
  });
  const status = res.effects?.status?.status;
  console.log(`[pq-unlock] status: ${status}`);
  console.log(`[pq-unlock] tx: ${res.digest}`);
  if (status !== 'success') {
    console.log('[pq-unlock] effects.status.error:', res.effects?.status?.error);
    process.exit(1);
  }

  // 6. Wait for the tx to land + the object state to be indexed, then re-read.
  await client.waitForTransaction({ digest: res.digest });
  const after = await client.getObject({ id: identityId, options: { showContent: true } });
  const newNonce = (after.data?.content as { fields?: { nonce?: string } })?.fields?.nonce;
  console.log(`[pq-unlock] identity.nonce = ${newNonce} (was ${nonce})`);
  if (BigInt(newNonce ?? '0') !== nonce + 1n) {
    throw new Error('nonce did not advance by 1');
  }
  console.log('[pq-unlock] ✓ on-chain FIPS-205 PQ verification succeeded end-to-end');
}

main().catch((e) => {
  console.error('[pq-unlock] ✗', e);
  process.exit(1);
});
