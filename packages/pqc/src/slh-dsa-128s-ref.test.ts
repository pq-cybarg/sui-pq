/**
 * Cross-check our hand-rolled FIPS-205 SLH-DSA-SHA2-128s verify against the
 * audited @noble/post-quantum implementation. If both sides agree, the Move
 * verifier (which mirrors the structure of slh-dsa-128s-ref.ts) is verifying
 * the same byte format.
 */
import { slh_dsa_sha2_128s } from '@noble/post-quantum/slh-dsa.js';
import { describe, expect, it } from 'vitest';
import { FIPS205, verify } from './slh-dsa-128s-ref.js';

describe('FIPS-205 SLH-DSA-SHA2-128s — TS verify vs noble', () => {
  it('parameter sizes match the spec', () => {
    expect(FIPS205.n).toBe(16);
    expect(FIPS205.pkBytes).toBe(32);
    expect(FIPS205.sigBytes).toBe(7856);
  });

  it('our verify accepts a noble-produced signature', () => {
    const kp = slh_dsa_sha2_128s.keygen();
    const msg = new TextEncoder().encode('hello, FIPS-205');
    const sig = slh_dsa_sha2_128s.sign(msg, kp.secretKey);
    expect(sig.length).toBe(FIPS205.sigBytes);
    expect(kp.publicKey.length).toBe(FIPS205.pkBytes);
    expect(verify(kp.publicKey, msg, sig)).toBe(true);
  });

  it('round-trips multiple distinct messages', () => {
    const kp = slh_dsa_sha2_128s.keygen();
    for (const text of ['', 'a', 'short', 'a longer message with spaces and bytes \x00\xff']) {
      const msg = new TextEncoder().encode(text);
      const sig = slh_dsa_sha2_128s.sign(msg, kp.secretKey);
      expect(verify(kp.publicKey, msg, sig)).toBe(true);
    }
  });

  it('our verify rejects a tampered signature (byte 100 flipped)', () => {
    const kp = slh_dsa_sha2_128s.keygen();
    const msg = new TextEncoder().encode('hello');
    const sig = slh_dsa_sha2_128s.sign(msg, kp.secretKey);
    const bad = new Uint8Array(sig);
    bad[100] = ((bad[100] ?? 0) ^ 0xff) & 0xff;
    expect(verify(kp.publicKey, msg, bad)).toBe(false);
  });

  it('our verify rejects a sig for a different message', () => {
    const kp = slh_dsa_sha2_128s.keygen();
    const sig = slh_dsa_sha2_128s.sign(new TextEncoder().encode('A'), kp.secretKey);
    expect(verify(kp.publicKey, new TextEncoder().encode('B'), sig)).toBe(false);
  });

  it('our verify rejects with a different public key', () => {
    const kpA = slh_dsa_sha2_128s.keygen();
    const kpB = slh_dsa_sha2_128s.keygen();
    const msg = new TextEncoder().encode('hello');
    const sig = slh_dsa_sha2_128s.sign(msg, kpA.secretKey);
    expect(verify(kpB.publicKey, msg, sig)).toBe(false);
  });
});
