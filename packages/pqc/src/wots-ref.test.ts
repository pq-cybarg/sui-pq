import { describe, expect, it } from 'vitest';
import { buildAdrs, msgToChains, wotsKeygen, wotsSign, wotsVerify, WOTS } from './wots-ref.js';

const master = new Uint8Array(32).fill(0xab);
const seed = new Uint8Array(32).fill(0xcd);
const adrs = buildAdrs({ keypair: 7 });

describe('WOTS+ reference', () => {
  it('msgToChains output has correct length and checksum range', () => {
    const msg = new Uint8Array(32).fill(0x37);
    const c = msgToChains(msg);
    expect(c.length).toBe(WOTS.len);
    for (const x of c) expect(x).toBeGreaterThanOrEqual(0);
    for (const x of c) expect(x).toBeLessThan(WOTS.w);
  });

  it('keygen, sign, verify round-trips', () => {
    const kp = wotsKeygen(master, seed, adrs);
    const msg = new Uint8Array(32);
    for (let i = 0; i < 32; i++) msg[i] = (i * 17) & 0xff;
    const sig = wotsSign(kp, msg);
    expect(wotsVerify(seed, adrs, msg, sig, kp.publicKey)).toBe(true);
  });

  it('a single flipped bit in the signature is rejected', () => {
    const kp = wotsKeygen(master, seed, adrs);
    const msg = new Uint8Array(32).fill(0x42);
    const sig = wotsSign(kp, msg);
    sig[0] = (sig[0] ?? 0) ^ 0x01;
    expect(wotsVerify(seed, adrs, msg, sig, kp.publicKey)).toBe(false);
  });

  it('a wrong message is rejected', () => {
    const kp = wotsKeygen(master, seed, adrs);
    const msg = new Uint8Array(32).fill(0x01);
    const sig = wotsSign(kp, msg);
    const other = new Uint8Array(32).fill(0x02);
    expect(wotsVerify(seed, adrs, other, sig, kp.publicKey)).toBe(false);
  });
});
