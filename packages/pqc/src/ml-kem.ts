/**
 * ML-KEM (FIPS 203) — key encapsulation. Use this whenever you need to
 * encrypt-to-recipient without an interactive handshake. Pairs naturally
 * with Walrus blobs (encrypt the blob's symmetric key with ML-KEM, store
 * the ciphertext + KEM ciphertext on Walrus).
 *
 * Three parameter sets, all NIST-approved:
 *   ML_KEM_512   — cat 1, pk 800 / sk 1632 / ct 768 / ss 32
 *   ML_KEM_768   — cat 3, pk 1184 / sk 2400 / ct 1088 / ss 32  ← recommended default
 *   ML_KEM_1024  — cat 5, pk 1568 / sk 3168 / ct 1568 / ss 32
 *
 * Shared secret (`ss`) is always 32 bytes — feed it into AES-256-GCM or
 * ChaCha20-Poly1305 to actually encrypt your payload.
 */
import { ml_kem512, ml_kem768, ml_kem1024 } from '@noble/post-quantum/ml-kem.js';

export type KemSchemeName = 'ML_KEM_512' | 'ML_KEM_768' | 'ML_KEM_1024';

interface NobleKem {
  keygen(seed?: Uint8Array): { publicKey: Uint8Array; secretKey: Uint8Array };
  encapsulate(publicKey: Uint8Array, randomness?: Uint8Array): {
    cipherText: Uint8Array;
    sharedSecret: Uint8Array;
  };
  decapsulate(cipherText: Uint8Array, secretKey: Uint8Array): Uint8Array;
}

const KEM: Record<KemSchemeName, NobleKem> = {
  ML_KEM_512: ml_kem512 as unknown as NobleKem,
  ML_KEM_768: ml_kem768 as unknown as NobleKem,
  ML_KEM_1024: ml_kem1024 as unknown as NobleKem,
};

export interface KemKeypair {
  scheme: KemSchemeName;
  publicKey: Uint8Array;
  secretKey: Uint8Array;
}

export interface Encapsulated {
  cipherText: Uint8Array;
  sharedSecret: Uint8Array;
}

export function kemKeygen(scheme: KemSchemeName = 'ML_KEM_768', seed?: Uint8Array): KemKeypair {
  const { publicKey, secretKey } = KEM[scheme].keygen(seed);
  return { scheme, publicKey, secretKey };
}

/** Sender side: pick a random shared secret, encrypt it under the recipient's pubkey. */
export function encapsulate(scheme: KemSchemeName, publicKey: Uint8Array): Encapsulated {
  const { cipherText, sharedSecret } = KEM[scheme].encapsulate(publicKey);
  return { cipherText, sharedSecret };
}

/** Recipient side: recover the same 32-byte shared secret from the ciphertext. */
export function decapsulate(scheme: KemSchemeName, cipherText: Uint8Array, secretKey: Uint8Array): Uint8Array {
  return KEM[scheme].decapsulate(cipherText, secretKey);
}

/**
 * Convenience: end-to-end encrypt a payload to a recipient's ML-KEM public key.
 * Returns `(kem_ct, aead_iv, aead_ct, aead_tag)` — store on Walrus or wherever.
 *
 * The recipient calls `kemDecrypt(scheme, secretKey, packet)` to recover the plaintext.
 */
import { gcm } from '@noble/ciphers/aes';
import { randomBytes } from '@noble/post-quantum/utils.js';

export interface KemPacket {
  /** ML-KEM ciphertext encapsulating the AES key. */
  kemCipherText: Uint8Array;
  /** 12-byte AES-GCM nonce. */
  nonce: Uint8Array;
  /** AES-256-GCM ciphertext (includes 16-byte tag). */
  aeadCipherText: Uint8Array;
}

export function kemEncrypt(
  scheme: KemSchemeName,
  recipientPubKey: Uint8Array,
  plaintext: Uint8Array,
  associatedData?: Uint8Array,
): KemPacket {
  const { cipherText, sharedSecret } = encapsulate(scheme, recipientPubKey);
  const nonce = randomBytes(12);
  const aead = gcm(sharedSecret, nonce, associatedData);
  const aeadCipherText = aead.encrypt(plaintext);
  return { kemCipherText: cipherText, nonce, aeadCipherText };
}

export function kemDecrypt(
  scheme: KemSchemeName,
  secretKey: Uint8Array,
  packet: KemPacket,
  associatedData?: Uint8Array,
): Uint8Array {
  const sharedSecret = decapsulate(scheme, packet.kemCipherText, secretKey);
  const aead = gcm(sharedSecret, packet.nonce, associatedData);
  return aead.decrypt(packet.aeadCipherText);
}
