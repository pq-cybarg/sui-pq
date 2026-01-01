/**
 * Build a `Transaction` that registers a `PqAttestation` Move object on-chain.
 * The on-chain object stores `(scheme, publicKey, signature, message_digest)`
 * as raw byte vectors so any future Move verifier can read them without a
 * schema migration.
 */
import { Transaction } from '@mysten/sui/transactions';
import type { Attestation } from './attestation.js';
import { SCHEME_META } from './schemes.js';

export interface RegisterOptions {
  /** Move package id that publishes `pq_attestation::registry`. */
  packageId: string;
  /** App-defined namespace tag (must match what was signed). */
  attestation: Attestation;
}

export function buildRegisterTx(opts: RegisterOptions): Transaction {
  const tx = new Transaction();
  const meta = SCHEME_META[opts.attestation.scheme];
  tx.moveCall({
    target: `${opts.packageId}::registry::register`,
    arguments: [
      tx.pure.u8(meta.byte),
      tx.pure.vector('u8', Array.from(opts.attestation.publicKey)),
      tx.pure.vector('u8', Array.from(opts.attestation.signature)),
      tx.pure.vector('u8', Array.from(opts.attestation.messageDigest)),
      tx.pure.vector('u8', Array.from(opts.attestation.nonce)),
      tx.pure.vector('u8', Array.from(opts.attestation.appTag)),
    ],
  });
  return tx;
}
