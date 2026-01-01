import type { SuiClient } from '@mysten/sui/client';
import type { Signer } from '@mysten/sui/cryptography';
/**
 * Hybrid signing — classical + post-quantum in one envelope.
 *
 * Sui validators only verify classical signatures (Ed25519 / secp256k1 /
 * secp256r1 / BLS12-381 / zkLogin) today. So the tx itself MUST be signed
 * classically. The hybrid pattern adds a PQ co-signature over **the same
 * transaction digest**, sealed inside the tx as a `vector<u8>` argument or
 * as a dedicated Attestation object.
 *
 * Verification semantics: anyone — including a future PQ-aware validator —
 * can replay the digest and check the PQ signature alongside the classical
 * one. If the classical scheme is later broken by a quantum attacker, the
 * PQ co-signature still provides authenticity.
 *
 * This file is the engine; `move/pq_attestation` is the on-chain home for
 * the result.
 */
import type { Transaction } from '@mysten/sui/transactions';
import { sha256 } from '@noble/hashes/sha256';
import { sign, verify } from './signing.js';
import type { Keypair, SchemeName } from './signing.js';

export interface HybridSignature {
  /** Bytes of the tx that was classically signed (the BCS-encoded TransactionData). */
  txBytes: Uint8Array;
  /** Classical signature produced by the user's Sui signer. */
  classicalSignature: string;
  /** PQ scheme name (must match the keypair). */
  scheme: SchemeName;
  /** PQ public key bytes — included so the verifier doesn't need an out-of-band lookup. */
  pqPublicKey: Uint8Array;
  /** PQ signature over `sha256(txBytes)`. */
  pqSignature: Uint8Array;
}

export interface HybridSignOptions {
  client: SuiClient;
  classicalSigner: Signer;
  pqKeypair: Keypair;
  transaction: Transaction;
}

/**
 * Build, classically-sign, and PQ-co-sign a Sui transaction.
 *
 * The returned `HybridSignature` contains everything a verifier needs to
 * replay both checks. The user/relayer can submit the tx via
 * `client.executeTransactionBlock({ transactionBlock: txBytes, signature: classicalSignature })`
 * exactly as they would today — the PQ bits are extra metadata.
 */
export async function hybridSign(opts: HybridSignOptions): Promise<HybridSignature> {
  const txBytes = await opts.transaction.build({ client: opts.client });
  const classical = await opts.classicalSigner.signTransaction(txBytes);
  const digest = sha256(txBytes);
  const pqSignature = sign(opts.pqKeypair, digest);
  return {
    txBytes,
    classicalSignature: classical.signature,
    scheme: opts.pqKeypair.scheme,
    pqPublicKey: opts.pqKeypair.publicKey,
    pqSignature,
  };
}

export interface HybridVerifyOptions {
  client: SuiClient;
  signature: HybridSignature;
  /** If provided, require the classical sig's recovered address to match this address.
   *  Otherwise we only check that the signature is valid for the tx bytes. */
  expectedSuiAddress?: string;
}

export interface HybridVerifyResult {
  classicalOk: boolean;
  pqOk: boolean;
  ok: boolean;
  reasons: string[];
}

/**
 * Independently verify the classical signature, the PQ co-signature, and
 * optionally that the classical sig came from the expected address.
 *
 * Returns a structured result rather than throwing — callers usually want to
 * surface both check results in their UI.
 */
export async function hybridVerify(opts: HybridVerifyOptions): Promise<HybridVerifyResult> {
  const reasons: string[] = [];
  const { signature: sig } = opts;

  let classicalOk = false;
  try {
    // verifyTransactionSignature returns the publicKey object on success or throws
    const { verifyTransactionSignature } = await import('@mysten/sui/verify');
    const pub = await verifyTransactionSignature(sig.txBytes, sig.classicalSignature);
    classicalOk = true;
    if (opts.expectedSuiAddress && pub.toSuiAddress() !== opts.expectedSuiAddress) {
      classicalOk = false;
      reasons.push(
        `classical sig is for ${pub.toSuiAddress()}, expected ${opts.expectedSuiAddress}`,
      );
    }
  } catch (e) {
    reasons.push(`classical sig invalid: ${String(e).slice(0, 200)}`);
  }

  const digest = sha256(sig.txBytes);
  const pqOk = verify(sig.scheme, sig.pqPublicKey, digest, sig.pqSignature);
  if (!pqOk) reasons.push(`PQ co-signature invalid (scheme=${sig.scheme})`);

  return {
    classicalOk,
    pqOk,
    ok: classicalOk && pqOk,
    reasons,
  };
}

/**
 * BCS-pack a `HybridSignature` for storage on Walrus, in an event payload, or
 * as a `vector<u8>` argument to a Move function that wants to record the bundle.
 *
 * Wire format:
 *   u8  scheme byte
 *   u32 txBytes.length    (LE)
 *   …   txBytes
 *   u16 classicalSig.length
 *   …   classicalSig (utf-8 base64)
 *   u16 pqPublicKey.length
 *   …   pqPublicKey
 *   u32 pqSignature.length
 *   …   pqSignature
 */
import { SCHEME_META } from './schemes.js';

export function packHybrid(sig: HybridSignature): Uint8Array {
  const meta = SCHEME_META[sig.scheme];
  const classicalBytes = new TextEncoder().encode(sig.classicalSignature);
  const out: number[] = [];
  out.push(meta.byte);
  appendU32(out, sig.txBytes.length);
  for (const b of sig.txBytes) out.push(b);
  appendU16(out, classicalBytes.length);
  for (const b of classicalBytes) out.push(b);
  appendU16(out, sig.pqPublicKey.length);
  for (const b of sig.pqPublicKey) out.push(b);
  appendU32(out, sig.pqSignature.length);
  for (const b of sig.pqSignature) out.push(b);
  return new Uint8Array(out);
}

function appendU32(arr: number[], n: number): void {
  arr.push(n & 0xff, (n >> 8) & 0xff, (n >> 16) & 0xff, (n >> 24) & 0xff);
}
function appendU16(arr: number[], n: number): void {
  arr.push(n & 0xff, (n >> 8) & 0xff);
}
