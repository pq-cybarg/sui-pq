/**
 * PQ-Guard PTB builder: assemble a transaction whose authorization comes from
 * a smart-contract-level SLH-DSA verification, not from the validator's
 * classical signature scheme.
 *
 * Usage pattern:
 *
 *   1. Off-chain, compute the `action_digest` matching the gated function's
 *      `*_action_digest` view (e.g. `pq_vault::vault::withdraw_action_digest`).
 *   2. Build the `unlock_message_bytes` exactly as the on-chain `pq_guard`
 *      module would (`buildUnlockMessageBytes` below).
 *   3. SLH-DSA-sign that message with the keypair registered in the
 *      `PqIdentity` (via `@sui-gen/pqc/slh.sign` and `packSignature`).
 *   4. Build a PTB whose first command is `pq_guard::unlock(...)` and whose
 *      subsequent commands consume the returned `PqAuthorized` witness.
 *
 * The PTB is signed by a (cheap, throwaway) classical key just to satisfy
 * the validator; the actual authority is the SLH-DSA proof inside the tx.
 */
import type { Transaction, TransactionArgument } from '@mysten/sui/transactions';

const TAG = new TextEncoder().encode('PQ_GUARD:UNLOCK:v1');

/** Construct the bytes that the on-chain `pq_guard::unlock_message_bytes` produces.
 *  Caller passes the current `nonce` (read off-chain from the `PqIdentity`
 *  object) and a 32-byte `action_digest`. */
export function buildUnlockMessageBytes(opts: {
  sender: string;
  nonce: bigint;
  actionDigest: Uint8Array;
}): Uint8Array {
  if (opts.actionDigest.length !== 32) {
    throw new Error(`actionDigest must be 32 bytes, got ${opts.actionDigest.length}`);
  }
  const senderBytes = addressTo32Bytes(opts.sender);
  const nonceBytes = u64BigEndian(opts.nonce);
  const total = TAG.length + senderBytes.length + nonceBytes.length + opts.actionDigest.length;
  const out = new Uint8Array(total);
  let off = 0;
  out.set(TAG, off);
  off += TAG.length;
  out.set(senderBytes, off);
  off += senderBytes.length;
  out.set(nonceBytes, off);
  off += nonceBytes.length;
  out.set(opts.actionDigest, off);
  return out;
}

export interface AddUnlockOptions {
  /** The published `pq_guard` package id. */
  guardPackageId: string;
  /** Object id of the user's `PqIdentity` (mutable ref will be taken). */
  identityId: string;
  /** Caller-defined 32-byte commit to the operation. */
  actionDigest: Uint8Array;
  /** SLH-DSA-LITE signature over `buildUnlockMessageBytes(sender, current_nonce, actionDigest)`. */
  signature: Uint8Array;
}

/**
 * Append a `pq_guard::unlock` call to the given PTB. Returns the
 * `PqAuthorized` argument that downstream Move calls can consume.
 */
export function addPqGuardUnlock(tx: Transaction, opts: AddUnlockOptions): TransactionArgument {
  const [authorized] = tx.moveCall({
    target: `${opts.guardPackageId}::pq_guard::unlock`,
    arguments: [
      tx.object(opts.identityId),
      tx.pure.vector('u8', Array.from(opts.actionDigest)),
      tx.pure.vector('u8', Array.from(opts.signature)),
    ],
  });
  return authorized!;
}

// ── helpers ──────────────────────────────────────────────────────────────────
function u64BigEndian(v: bigint): Uint8Array {
  const out = new Uint8Array(8);
  let n = v;
  for (let i = 7; i >= 0; i--) {
    out[i] = Number(n & 0xffn);
    n >>= 8n;
  }
  return out;
}

function addressTo32Bytes(addr: string): Uint8Array {
  // Accept 0x-prefixed hex, allow short forms (e.g. "0xa") by left-padding.
  const hex = addr.startsWith('0x') ? addr.slice(2) : addr;
  if (hex.length === 0 || hex.length > 64) throw new Error(`bad address: ${addr}`);
  const padded = hex.padStart(64, '0');
  const out = new Uint8Array(32);
  for (let i = 0; i < 32; i++) out[i] = Number.parseInt(padded.slice(i * 2, i * 2 + 2), 16);
  return out;
}
