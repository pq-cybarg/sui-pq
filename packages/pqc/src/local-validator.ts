import type { SuiClient, SuiTransactionBlockResponse } from '@mysten/sui/client';
import type { Transaction } from '@mysten/sui/transactions';
/**
 * PQ-native transaction signing — no sponsor, no classical key anywhere.
 *
 * Pair this with the locally-patched validator from `scripts/build-pq-validator.sh`,
 * which adds `SignatureScheme::SlhDsaLite` (flag byte `0x07`) to Sui's signature
 * scheme registry. The user signs a normal Sui transaction with their SLH-DSA-LITE
 * keypair; gas is paid by the PQ-derived address itself.
 *
 * Address derivation:
 *     address = '0x' + blake2b256( 0x07 || PK.seed || PK.root )
 *
 * Signature wire format (what the patched validator parses):
 *     0x07 (1 byte flag) || PK.seed (32) || PK.root (32) || packed_signature (5,056)
 *     = 5,121 bytes total
 *
 * Sui's intent-signing convention applies: the bytes that are PQ-signed are
 *     blake2b256( intent_msg || tx_bytes )
 * where `intent_msg = [0, 0, 0]` (scope=TransactionData, version=V0, app_id=Sui).
 *
 * Against Mysten-managed mainnet/testnet, the validator rejects flag `0x07`
 * with `InvalidSignatureScheme`. Against the patched local validator, the tx
 * goes through with the PQ-derived address as both sender and gas payer.
 */
import { blake2b } from '@noble/hashes/blake2b';
import * as slh from './slh-dsa-ref.js';
type SlhPublicKey = slh.PublicKey;
type SlhSecretKey = slh.SecretKey;

/** Workspace-local flag byte for SLH-DSA-LITE. Matches the patch in `patches/0001-add-slh-dsa-lite-signature-scheme.patch`. */
export const SLH_DSA_LITE_FLAG = 0x07;

/** Sui intent message for TransactionData (scope=0, version=0, app_id=Sui=0). */
const INTENT_TX_DATA = new Uint8Array([0, 0, 0]);

const SIG_BLOB_LEN = 1 + 32 + 32 + 5056;

function toHex(b: Uint8Array): string {
  let s = '';
  for (const x of b) s += x.toString(16).padStart(2, '0');
  return s;
}

function toBase64(b: Uint8Array): string {
  if (typeof Buffer !== 'undefined') return Buffer.from(b).toString('base64');
  let s = '';
  for (const x of b) s += String.fromCharCode(x);
  return typeof btoa !== 'undefined' ? btoa(s) : '';
}

/**
 * Derive the Sui address for an SLH-DSA-LITE public key.
 *
 *     addr = '0x' + blake2b256( 0x07 || PK.seed || PK.root )
 *
 * This is the address that owns gas and operations under this keypair.
 */
export function slhDsaAddress(pk: SlhPublicKey): string {
  const input = new Uint8Array(1 + 32 + 32);
  input[0] = SLH_DSA_LITE_FLAG;
  input.set(pk.seed, 1);
  input.set(pk.root, 33);
  const h = blake2b(input, { dkLen: 32 });
  return `0x${toHex(h)}`;
}

/**
 * The intent-tagged digest that the SLH-DSA-LITE signature actually commits to.
 *
 *     digest = blake2b256( [0, 0, 0] || tx_bytes )
 *
 * The patched validator computes the same digest on its end and feeds it to the
 * SLH-DSA-LITE verifier as `message`.
 */
export function intentDigest(txBytes: Uint8Array): Uint8Array {
  const buf = new Uint8Array(INTENT_TX_DATA.length + txBytes.length);
  buf.set(INTENT_TX_DATA, 0);
  buf.set(txBytes, INTENT_TX_DATA.length);
  return blake2b(buf, { dkLen: 32 });
}

/**
 * Sign already-built transaction bytes with an SLH-DSA-LITE keypair and produce
 * the signature blob in the wire format the patched validator parses.
 */
export function signTxWithSlhDsa(
  txBytes: Uint8Array,
  pk: SlhPublicKey,
  sk: SlhSecretKey,
): Uint8Array {
  const digest = intentDigest(txBytes);
  const sig = slh.sign(sk, digest);
  const packed = slh.packSignature(sig);

  const out = new Uint8Array(SIG_BLOB_LEN);
  out[0] = SLH_DSA_LITE_FLAG;
  out.set(pk.seed, 1);
  out.set(pk.root, 33);
  out.set(packed, 65);
  return out;
}

/**
 * Verify a signature blob locally — independent of the patched validator.
 *
 * Useful as a "would this tx be accepted" check before submission, and as the
 * reference for the test suite that locks the wire format.
 */
export function verifyTxSlhDsaSig(txBytes: Uint8Array, sigBlob: Uint8Array): boolean {
  if (sigBlob.length !== SIG_BLOB_LEN) return false;
  if (sigBlob[0] !== SLH_DSA_LITE_FLAG) return false;
  const pk: SlhPublicKey = { seed: sigBlob.slice(1, 33), root: sigBlob.slice(33, 65) };
  const packed = sigBlob.slice(65);
  const sig = slh.unpackSignature(packed);
  const digest = intentDigest(txBytes);
  return slh.verify(pk, digest, sig);
}

export interface SignAndExecuteSlhDsaOptions {
  client: SuiClient;
  transaction: Transaction;
  pk: SlhPublicKey;
  sk: SlhSecretKey;
  /** Set to true to skip the local pre-flight verify (saves ~1s; default: pre-flight on). */
  skipLocalVerify?: boolean;
}

/**
 * Build, sign, and submit a transaction whose authentication is *purely*
 * SLH-DSA-LITE. The sender (and gas payer) is the PQ-derived address.
 *
 * Throws if the local pre-flight verify fails (signs over the same digest the
 * patched validator computes, so any mismatch is caught before we hit RPC).
 */
export async function signAndExecuteSlhDsa(
  opts: SignAndExecuteSlhDsaOptions,
): Promise<SuiTransactionBlockResponse> {
  const sender = slhDsaAddress(opts.pk);
  opts.transaction.setSenderIfNotSet(sender);
  const txBytes = await opts.transaction.build({ client: opts.client });
  const sigBlob = signTxWithSlhDsa(txBytes, opts.pk, opts.sk);

  if (!opts.skipLocalVerify) {
    if (!verifyTxSlhDsaSig(txBytes, sigBlob)) {
      throw new Error('signTxWithSlhDsa produced a signature that does not verify locally');
    }
  }

  return opts.client.executeTransactionBlock({
    transactionBlock: txBytes,
    signature: toBase64(sigBlob),
    options: { showEffects: true, showEvents: true, showObjectChanges: true },
  });
}
