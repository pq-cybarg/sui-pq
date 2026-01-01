import { describe, expect, it } from 'vitest';
import { decapsulate, encapsulate, kemDecrypt, kemEncrypt, kemKeygen } from './ml-kem.js';

describe('ML-KEM', () => {
  it('encapsulates and decapsulates the same 32-byte shared secret', () => {
    const kp = kemKeygen('ML_KEM_768');
    const { cipherText, sharedSecret } = encapsulate('ML_KEM_768', kp.publicKey);
    const recovered = decapsulate('ML_KEM_768', cipherText, kp.secretKey);
    expect(recovered).toEqual(sharedSecret);
    expect(sharedSecret.length).toBe(32);
  });

  it('two encapsulations to the same pubkey produce different ciphertexts', () => {
    const kp = kemKeygen('ML_KEM_512');
    const a = encapsulate('ML_KEM_512', kp.publicKey);
    const b = encapsulate('ML_KEM_512', kp.publicKey);
    expect(Buffer.from(a.cipherText).toString('hex')).not.toEqual(
      Buffer.from(b.cipherText).toString('hex'),
    );
  });

  it('end-to-end AEAD wrap round-trips', () => {
    const kp = kemKeygen('ML_KEM_768');
    const plaintext = new TextEncoder().encode('confidential walrus blob');
    const aad = new TextEncoder().encode('app=demo');
    const packet = kemEncrypt('ML_KEM_768', kp.publicKey, plaintext, aad);
    const recovered = kemDecrypt('ML_KEM_768', kp.secretKey, packet, aad);
    expect(new TextDecoder().decode(recovered)).toBe('confidential walrus blob');
  });

  it('tampering with AEAD ciphertext is rejected', () => {
    const kp = kemKeygen('ML_KEM_512');
    const pt = new Uint8Array([1, 2, 3, 4, 5]);
    const packet = kemEncrypt('ML_KEM_512', kp.publicKey, pt);
    const tampered = new Uint8Array(packet.aeadCipherText);
    tampered[0] = (tampered[0] ?? 0) ^ 0xff;
    expect(() => kemDecrypt('ML_KEM_512', kp.secretKey, { ...packet, aeadCipherText: tampered })).toThrow();
  });
});
