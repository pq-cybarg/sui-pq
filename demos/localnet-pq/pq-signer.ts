import type { SuiClient } from '@mysten/sui/client';
/**
 * A drop-in `@mysten/sui` Signer backed by a post-quantum FIPS-205
 * SLH-DSA-SHA2-128s key (scheme flag 0x07) — no elliptic curve.
 *
 * Because SLH-DSA has no compact `Signature` form (the wire layout is
 * `flag || pk || sig`, not `flag || sig || pk`), we override `signTransaction`
 * /`signPersonalMessage` to emit the native authenticator blob the patched
 * validator accepts, instead of routing through the base class's
 * `toSerializedSignature` (which only knows the elliptic-curve schemes).
 *
 * This is the single piece that makes every ecosystem package work
 * post-quantum: anything that takes a `Signer` (sdk-core's `executeTx`,
 * `@mysten/kiosk`, `@mysten/walrus`, sponsored-tx, the dapp-kit wallet hooks…)
 * accepts it unchanged, and `client.signAndExecuteTransaction({ signer })`
 * only ever calls `toSuiAddress()` + `signTransaction()`.
 */
import { Signer } from '@mysten/sui/cryptography';
import type { PublicKey, SignatureScheme } from '@mysten/sui/cryptography';
import type { Transaction } from '@mysten/sui/transactions';
import { fromBase64, toBase64 } from '@mysten/sui/utils';
import { blake2b } from '@noble/hashes/blake2b';
import { slh_dsa_sha2_128s } from '@noble/post-quantum/slh-dsa.js';

const FLAG = 0x07;

function cat(...parts: Uint8Array[]): Uint8Array {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let o = 0;
  for (const p of parts) {
    out.set(p, o);
    o += p.length;
  }
  return out;
}
const flag = () => new Uint8Array([FLAG]);
const hex = (b: Uint8Array) => Buffer.from(b).toString('hex');

export class SlhDsaSigner extends Signer {
  readonly #pk: Uint8Array;
  readonly #sk: Uint8Array;
  readonly #address: string;

  constructor(publicKey: Uint8Array, secretKey: Uint8Array) {
    super();
    this.#pk = publicKey;
    this.#sk = secretKey;
    this.#address = `0x${hex(blake2b(cat(flag(), publicKey), { dkLen: 32 }))}`;
  }

  /** Deterministic key pair from a 48-byte FIPS-205 keygen seed. */
  static fromSeed(seed48: Uint8Array): SlhDsaSigner {
    const kp = slh_dsa_sha2_128s.keygen(seed48);
    return new SlhDsaSigner(kp.publicKey, kp.secretKey);
  }

  /** Throwaway deterministic key pair from a label (demo convenience). */
  static fromLabel(label: string): SlhDsaSigner {
    const seed = new Uint8Array(48);
    seed.set(blake2b(new TextEncoder().encode(label), { dkLen: 48 }));
    return SlhDsaSigner.fromSeed(seed);
  }

  publicKeyBytes(): Uint8Array {
    return this.#pk;
  }

  override toSuiAddress(): string {
    return this.#address;
  }

  /** Raw SLH-DSA signature over the given bytes (used by the base helpers). */
  override sign(bytes: Uint8Array): Promise<Uint8Array> {
    return Promise.resolve(slh_dsa_sha2_128s.sign(bytes, this.#sk));
  }

  #blobOverIntent(intent: number[], message: Uint8Array): string {
    // digest = Blake2b256(intent || message) — the digest the validator
    // recomputes; SLH-DSA-sign it and pack the native authenticator blob.
    const digest = blake2b(cat(new Uint8Array(intent), message), { dkLen: 32 });
    const sig = slh_dsa_sha2_128s.sign(digest, this.#sk); // 7856 B
    return toBase64(cat(flag(), this.#pk, sig)); // 0x07 || pk(32) || sig
  }

  override signTransaction(bytes: Uint8Array): Promise<{ bytes: string; signature: string }> {
    // Intent scope for TransactionData is [0, 0, 0].
    return Promise.resolve({
      bytes: toBase64(bytes),
      signature: this.#blobOverIntent([0, 0, 0], bytes),
    });
  }

  override signPersonalMessage(bytes: Uint8Array): Promise<{ bytes: string; signature: string }> {
    // Intent scope for PersonalMessage is [3, 0, 0]; message is bcs vector<u8>.
    const len = bytes.length;
    if (len >= 0x80) throw new Error('demo: personal message length > 127 not encoded');
    const wrapped = cat(new Uint8Array([len]), bytes); // ULEB length prefix (small)
    return Promise.resolve({
      bytes: toBase64(bytes),
      signature: this.#blobOverIntent([3, 0, 0], wrapped),
    });
  }

  // Not on the signing path for SLH-DSA; present to satisfy the abstract class.
  override getKeyScheme(): SignatureScheme {
    return 'SLHDSA' as unknown as SignatureScheme;
  }
  override getPublicKey(): PublicKey {
    throw new Error('SLH-DSA has no @mysten/sui PublicKey representation');
  }
}

/** Verify a transaction signature we produced (round-trip sanity check). */
export function verifyTxSig(txBytes: Uint8Array, signatureB64: string): boolean {
  const blob = fromBase64(signatureB64);
  if (blob[0] !== FLAG) return false;
  const pk = blob.slice(1, 33);
  const sig = blob.slice(33);
  const digest = blake2b(cat(new Uint8Array([0, 0, 0]), txBytes), { dkLen: 32 });
  return slh_dsa_sha2_128s.verify(sig, digest, pk);
}

/** Fund any address from the localnet faucet and wait for the gas coin. */
export async function faucet(client: SuiClient, address: string, faucetUrl: string): Promise<void> {
  const r = await fetch(`${faucetUrl}/v2/gas`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ FixedAmountRequest: { recipient: address } }),
  });
  if (!r.ok) throw new Error(`faucet ${r.status}`);
  for (let i = 0; i < 40; i++) {
    if (BigInt((await client.getBalance({ owner: address })).totalBalance) > 0n) return;
    await new Promise((res) => setTimeout(res, 300));
  }
  throw new Error(`faucet did not fund ${address}`);
}

/** Build → PQ-sign → execute, asserting success. Returns the response. */
export async function pqRun(client: SuiClient, signer: SlhDsaSigner, tx: Transaction) {
  tx.setSenderIfNotSet(signer.toSuiAddress());
  if (!tx.blockData?.gasConfig?.budget) tx.setGasBudget(2_500_000_000n);
  const res = await client.signAndExecuteTransaction({
    signer,
    transaction: tx,
    options: { showEffects: true, showObjectChanges: true, showEvents: true },
  });
  await client.waitForTransaction({ digest: res.digest });
  if (res.effects?.status?.status !== 'success') {
    throw new Error(`tx failed: ${JSON.stringify(res.effects?.status)}`);
  }
  return res;
}
