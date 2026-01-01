import { describe, expect, it } from 'vitest';
import { keygen, sign, verify, packSignature, unpackSignature, SLH } from './slh-dsa-ref.js';

describe('SLH-DSA-LITE', () => {
  const seed = new Uint8Array(SLH.n).fill(0x11);
  const skSeed = new Uint8Array(SLH.n).fill(0x22);

  it('keygen produces seed + root of n bytes each', () => {
    const { pk } = keygen(seed, skSeed);
    expect(pk.seed.length).toBe(SLH.n);
    expect(pk.root.length).toBe(SLH.n);
  });

  it('round-trips: sign → verify', () => {
    const { pk, sk } = keygen(seed, skSeed);
    const msg = new TextEncoder().encode('full SLH-DSA stack in Move');
    const sig = sign(sk, msg);
    expect(verify(pk, msg, sig)).toBe(true);
  });

  it('tampering with a single signature byte fails verify', () => {
    const { pk, sk } = keygen(seed, skSeed);
    const msg = new TextEncoder().encode('hello');
    const sig = sign(sk, msg);
    const packed = packSignature(sig);
    packed[0] = (packed[0] ?? 0) ^ 0xff;
    expect(verify(pk, msg, unpackSignature(packed))).toBe(false);
  });

  it('different message fails verify', () => {
    const { pk, sk } = keygen(seed, skSeed);
    const sig = sign(sk, new TextEncoder().encode('a'));
    expect(verify(pk, new TextEncoder().encode('b'), sig)).toBe(false);
  });

  it('packed signature has the expected length', () => {
    const { sk } = keygen(seed, skSeed);
    const sig = sign(sk, new Uint8Array([1, 2, 3]));
    const packed = packSignature(sig);
    const forsLen = SLH.k * (SLH.n + SLH.a * SLH.n); // 4 * (32 + 96) = 512
    const xmssLen = SLH.len * SLH.n + SLH.h_prime * SLH.n; // 67*32 + 4*32 = 2272
    expect(packed.length).toBe(forsLen + SLH.d * xmssLen); // 512 + 2*2272 = 5056
  });
});
