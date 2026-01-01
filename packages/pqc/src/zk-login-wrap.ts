import type { SuiClient } from '@mysten/sui/client';
/**
 * PQ-wrapped zkLogin sessions.
 *
 * Current zkLogin uses Groth16 over BN254 (the proof) and RSA (the OIDC JWT
 * signature). Both are quantum-vulnerable: a sufficiently large quantum
 * computer breaks RSA via Shor's algorithm, and BN254 discrete log via the
 * same. NIST's mandated transition target is 2030–2035; the migration to a
 * PQ-zkSNARK + PQ-JWT is research-stage at Mysten today.
 *
 * **What this module does:** wraps a zkLogin signing session with a PQ
 * attestation over the same transaction digest. The zkLogin signature still
 * authorizes the transaction (validators only accept that), but the PQ
 * co-signature provides:
 *   - **post-quantum auditability** — anyone can independently verify the
 *     operation was approved by the holder of a registered PQ keypair, even
 *     if the underlying zkLogin proof is later broken.
 *   - **bridge to future PQ-zkLogin** — when Mysten ships a PQ-zkSNARK
 *     prover, your existing zkLogin → PQ-attestation bindings provide a
 *     migration anchor: prove possession of *both* the JWT and the PQ key.
 *
 * The PQ keypair is bound to the user's zkLogin **address** (not the JWT
 * itself), via the same `pq_attestation::register` flow used elsewhere in
 * this workspace.
 */
import type { Transaction } from '@mysten/sui/transactions';
import { sha256 } from '@noble/hashes/sha256';
import { type Attestation, buildAttestation } from './attestation.js';
import type { SchemeName } from './schemes.js';
import { type Keypair, keygen, sign, verify } from './signing.js';

export interface ZkLoginPqBinding {
  /** The zkLogin-derived Sui address. */
  zkLoginAddress: string;
  /** PQ scheme used for the binding. ML-DSA-65 is the recommended default. */
  scheme: SchemeName;
  /** PQ public key the user controls. */
  pqPublicKey: Uint8Array;
  /** Attestation proving the binding, signed by `pqSecretKey`. */
  attestation: Attestation;
}

export interface CreateZkLoginPqBindingOptions {
  zkLoginAddress: string;
  scheme?: SchemeName;
  /** App-defined namespace; recommended: `zk-login-binding`. */
  appTag?: string;
  /** Reuse an existing PQ keypair (e.g. from secure storage). */
  keypair?: Keypair;
}

/**
 * One-time binding: generate (or reuse) a PQ keypair, build an Attestation
 * that links it to a zkLogin address. The Attestation is meant to be
 * registered on-chain via `pq_attestation::register`.
 */
export function createZkLoginPqBinding(opts: CreateZkLoginPqBindingOptions): {
  binding: ZkLoginPqBinding;
  secretKey: Uint8Array;
} {
  const scheme = opts.scheme ?? 'ML_DSA_65';
  const kp = opts.keypair ?? keygen(scheme);
  const { attestation, secretKey } = buildAttestation({
    scheme,
    suiAddress: opts.zkLoginAddress,
    appTag: opts.appTag ?? 'zk-login-binding',
    keypair: { publicKey: kp.publicKey, secretKey: kp.secretKey },
  });
  return {
    binding: {
      zkLoginAddress: opts.zkLoginAddress,
      scheme,
      pqPublicKey: kp.publicKey,
      attestation,
    },
    secretKey,
  };
}

export interface PqWrappedZkLoginTx {
  /** Raw transaction bytes — what zkLogin signs and the validator executes. */
  txBytes: Uint8Array;
  /** SHA-256(txBytes) — the canonical digest both sigs cover. */
  txDigest: Uint8Array;
  /** PQ co-signature over `txDigest`. */
  pqSignature: Uint8Array;
  /** Public key required to verify `pqSignature`. */
  pqPublicKey: Uint8Array;
  scheme: SchemeName;
  /** Address whose PQ binding this co-signature claims to satisfy. */
  zkLoginAddress: string;
}

export interface WrapZkLoginTxOptions {
  client: SuiClient;
  transaction: Transaction;
  /** PQ keypair previously bound via `createZkLoginPqBinding`. */
  pqKeypair: Keypair;
  zkLoginAddress: string;
}

/**
 * Co-sign a transaction with the user's PQ keypair. The caller still
 * submits the tx with their zkLogin signature; the PQ co-signature is
 * carried alongside (in an `Attestation` object, in a Move arg, or in a
 * Walrus blob — any side channel works).
 */
export async function pqWrapZkLoginTx(opts: WrapZkLoginTxOptions): Promise<PqWrappedZkLoginTx> {
  const txBytes = await opts.transaction.build({ client: opts.client });
  const txDigest = sha256(txBytes);
  const pqSignature = sign(opts.pqKeypair, txDigest);
  return {
    txBytes,
    txDigest,
    pqSignature,
    pqPublicKey: opts.pqKeypair.publicKey,
    scheme: opts.pqKeypair.scheme,
    zkLoginAddress: opts.zkLoginAddress,
  };
}

export interface PqWrappedVerifyResult {
  ok: boolean;
  reason?: string;
  /** Matches the binding stored on-chain in `pq_attestation::register`? */
  digestMatches: boolean;
  /** PQ co-signature itself is valid? */
  pqSignatureOk: boolean;
}

/**
 * Verify a `PqWrappedZkLoginTx` against a pre-registered binding.
 *
 * - Does NOT verify the zkLogin proof — that's the validator's job and
 *   requires the full zkLogin prover/verifier stack.
 * - Does verify that the PQ co-signature is valid for *this exact*
 *   transaction and binds to the claimed zkLogin address.
 */
export function verifyPqWrappedZkLoginTx(
  wrapped: PqWrappedZkLoginTx,
  binding: ZkLoginPqBinding,
): PqWrappedVerifyResult {
  if (binding.zkLoginAddress !== wrapped.zkLoginAddress) {
    return {
      ok: false,
      pqSignatureOk: false,
      digestMatches: false,
      reason: `binding is for ${binding.zkLoginAddress}, wrapped tx claims ${wrapped.zkLoginAddress}`,
    };
  }
  if (binding.scheme !== wrapped.scheme) {
    return {
      ok: false,
      pqSignatureOk: false,
      digestMatches: false,
      reason: `binding scheme ${binding.scheme} != wrapped scheme ${wrapped.scheme}`,
    };
  }
  // Pubkey bytes must match (binding pin)
  if (binding.pqPublicKey.length !== wrapped.pqPublicKey.length) {
    return {
      ok: false,
      pqSignatureOk: false,
      digestMatches: false,
      reason: `pubkey length mismatch: binding ${binding.pqPublicKey.length} vs wrapped ${wrapped.pqPublicKey.length}`,
    };
  }
  for (let i = 0; i < binding.pqPublicKey.length; i++) {
    if (binding.pqPublicKey[i] !== wrapped.pqPublicKey[i]) {
      return {
        ok: false,
        pqSignatureOk: false,
        digestMatches: false,
        reason: 'pqPublicKey bytes mismatch — possible binding-replay attempt',
      };
    }
  }
  const expectedDigest = sha256(wrapped.txBytes);
  const digestMatches = bytesEq(expectedDigest, wrapped.txDigest);
  const pqSignatureOk = verify(
    wrapped.scheme,
    wrapped.pqPublicKey,
    expectedDigest,
    wrapped.pqSignature,
  );
  return {
    ok: digestMatches && pqSignatureOk,
    pqSignatureOk,
    digestMatches,
    reason:
      digestMatches && pqSignatureOk
        ? undefined
        : `digestMatches=${digestMatches}, pqSignatureOk=${pqSignatureOk}`,
  };
}

function bytesEq(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) if (a[i] !== b[i]) return false;
  return true;
}
