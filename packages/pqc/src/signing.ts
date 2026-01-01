/**
 * Off-chain post-quantum signing + verification.
 *
 * Sui validators do not (as of 2026-05) accept ML-DSA / SLH-DSA / FALCON signatures
 * as transaction authentication. Mysten's fastcrypto has an experimental SLH-DSA
 * implementation (FIPS 205, behind `--features experimental`), but it isn't wired
 * into the validator's signature-verification path yet.
 *
 * What this module IS for, today: signing arbitrary payloads with a PQ scheme
 * off-chain, and persisting `(scheme, publicKey, signature)` as `vector<u8>`s on
 * Sui (see `move/pq_attestation`). When fastcrypto's PQ verifier is exposed as a
 * Move primitive, the same on-chain attestations become verifiable on-chain
 * without changing the storage layout.
 *
 * Wraps `@noble/post-quantum` — audited, FIPS-compliant, dependency-light.
 */
import { ml_dsa44, ml_dsa65, ml_dsa87 } from '@noble/post-quantum/ml-dsa.js';
import {
  slh_dsa_sha2_128f,
  slh_dsa_sha2_128s,
  slh_dsa_sha2_192f,
  slh_dsa_sha2_192s,
  slh_dsa_sha2_256f,
  slh_dsa_sha2_256s,
} from '@noble/post-quantum/slh-dsa.js';
import { SCHEME, SCHEME_META, type SchemeName } from './schemes.js';

interface NobleSignatureAlgorithm {
  keygen(seed?: Uint8Array): { publicKey: Uint8Array; secretKey: Uint8Array };
  sign(message: Uint8Array, secretKey: Uint8Array): Uint8Array;
  verify(signature: Uint8Array, message: Uint8Array, publicKey: Uint8Array): boolean;
}

const ALG: Partial<Record<SchemeName, NobleSignatureAlgorithm>> = {
  ML_DSA_44: ml_dsa44 as unknown as NobleSignatureAlgorithm,
  ML_DSA_65: ml_dsa65 as unknown as NobleSignatureAlgorithm,
  ML_DSA_87: ml_dsa87 as unknown as NobleSignatureAlgorithm,
  SLH_DSA_SHA2_128S: slh_dsa_sha2_128s as unknown as NobleSignatureAlgorithm,
  SLH_DSA_SHA2_128F: slh_dsa_sha2_128f as unknown as NobleSignatureAlgorithm,
  SLH_DSA_SHA2_192S: slh_dsa_sha2_192s as unknown as NobleSignatureAlgorithm,
  SLH_DSA_SHA2_192F: slh_dsa_sha2_192f as unknown as NobleSignatureAlgorithm,
  SLH_DSA_SHA2_256S: slh_dsa_sha2_256s as unknown as NobleSignatureAlgorithm,
  SLH_DSA_SHA2_256F: slh_dsa_sha2_256f as unknown as NobleSignatureAlgorithm,
};

function getAlg(scheme: SchemeName): NobleSignatureAlgorithm {
  const a = ALG[scheme];
  if (!a) throw new Error(`scheme ${scheme} is not currently exposed by @sui-gen/pqc`);
  return a;
}

export interface Keypair {
  scheme: SchemeName;
  publicKey: Uint8Array;
  secretKey: Uint8Array;
}

/** Generate a fresh PQ keypair. `seed` is optional (32 bytes for ML-DSA, scheme-dependent for SLH-DSA). */
export function keygen(scheme: SchemeName, seed?: Uint8Array): Keypair {
  const alg = getAlg(scheme);
  const { publicKey, secretKey } = alg.keygen(seed);
  return { scheme, publicKey, secretKey };
}

export function sign(kp: Pick<Keypair, 'scheme' | 'secretKey'>, message: Uint8Array): Uint8Array {
  const alg = getAlg(kp.scheme);
  return alg.sign(message, kp.secretKey);
}

export function verify(
  scheme: SchemeName,
  publicKey: Uint8Array,
  message: Uint8Array,
  signature: Uint8Array,
): boolean {
  const alg = getAlg(scheme);
  // Length sanity-check so a wrong-scheme blob doesn't crash inside noble
  const meta = SCHEME_META[scheme];
  if (publicKey.length !== meta.publicKeyBytes) return false;
  if (signature.length !== meta.signatureBytes) return false;
  try {
    return alg.verify(signature, message, publicKey);
  } catch {
    return false;
  }
}

export { SCHEME, SCHEME_META };
export type { SchemeName } from './schemes.js';
