/**
 * PQ attestation: a (scheme, publicKey, signature, message_digest) tuple stored
 * on-chain in a Sui object owned by the user's classical address. Acts as a
 * pre-commitment to a post-quantum key so that, when fastcrypto's SLH-DSA / ML-DSA
 * verifier is exposed as a Move primitive, anyone can verify the on-chain
 * binding without trusting an off-chain oracle.
 *
 * The message that's signed is the BCS encoding of:
 *     CommitMessage { sui_address: address, nonce: vector<u8>, app_tag: vector<u8> }
 * so the signature can't be replayed against a different account or app context.
 */
import { sha256 } from '@noble/hashes/sha256';
import { bcs } from '@mysten/sui/bcs';
import { SCHEME_META, type SchemeName } from './schemes.js';
import { keygen, sign, verify } from './signing.js';

export const CommitMessage = bcs.struct('PqCommit', {
  sui_address: bcs.Address,
  nonce: bcs.vector(bcs.u8()),
  app_tag: bcs.vector(bcs.u8()),
});

export interface Attestation {
  scheme: SchemeName;
  publicKey: Uint8Array;
  signature: Uint8Array;
  messageDigest: Uint8Array; // sha256(commitBytes) — what the verifier re-derives
  suiAddress: string;
  nonce: Uint8Array;
  appTag: Uint8Array;
}

export interface BuildOptions {
  scheme: SchemeName;
  suiAddress: string;
  /** App-defined namespace string ("game-x", "wallet-recovery", etc.). */
  appTag: string | Uint8Array;
  /** Caller-supplied nonce. Default: 16 random bytes. */
  nonce?: Uint8Array;
  /** Reuse an existing keypair. Otherwise a fresh one is generated. */
  keypair?: { publicKey: Uint8Array; secretKey: Uint8Array };
}

function asBytes(v: string | Uint8Array): Uint8Array {
  return typeof v === 'string' ? new TextEncoder().encode(v) : v;
}

/** Build (and PQ-sign) a fresh attestation. Returns the on-chain payload plus the secret key. */
export function buildAttestation(opts: BuildOptions): { attestation: Attestation; secretKey: Uint8Array } {
  const nonce = opts.nonce ?? crypto.getRandomValues(new Uint8Array(16));
  const appTag = asBytes(opts.appTag);

  const commitBytes = CommitMessage.serialize({
    sui_address: opts.suiAddress,
    nonce: Array.from(nonce),
    app_tag: Array.from(appTag),
  }).toBytes();
  const messageDigest = sha256(commitBytes);

  const kp = opts.keypair ?? keygen(opts.scheme);
  const signature = sign({ scheme: opts.scheme, secretKey: kp.secretKey }, messageDigest);

  return {
    attestation: {
      scheme: opts.scheme,
      publicKey: kp.publicKey,
      signature,
      messageDigest,
      suiAddress: opts.suiAddress,
      nonce,
      appTag,
    },
    secretKey: kp.secretKey,
  };
}

export interface VerifyResult {
  ok: boolean;
  reason?: string;
}

/** Re-derive the commit hash and PQ-verify the signature. */
export function verifyAttestation(a: Attestation): VerifyResult {
  const meta = SCHEME_META[a.scheme];
  if (!meta) return { ok: false, reason: `unknown scheme ${a.scheme}` };
  if (a.publicKey.length !== meta.publicKeyBytes)
    return { ok: false, reason: `publicKey length ${a.publicKey.length} != ${meta.publicKeyBytes}` };
  if (a.signature.length !== meta.signatureBytes)
    return { ok: false, reason: `signature length ${a.signature.length} != ${meta.signatureBytes}` };

  const expected = sha256(
    CommitMessage.serialize({
      sui_address: a.suiAddress,
      nonce: Array.from(a.nonce),
      app_tag: Array.from(a.appTag),
    }).toBytes(),
  );
  if (Buffer.from(expected).toString('hex') !== Buffer.from(a.messageDigest).toString('hex')) {
    return { ok: false, reason: 'message digest mismatch (commit fields tampered with)' };
  }
  return { ok: verify(a.scheme, a.publicKey, a.messageDigest, a.signature) };
}
