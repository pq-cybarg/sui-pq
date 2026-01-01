import { describe, expect, it } from 'vitest';
import {
  SLH_DSA_LITE_FLAG,
  intentDigest,
  signTxWithSlhDsa,
  slhDsaAddress,
  verifyTxSlhDsaSig,
} from './local-validator.js';
import * as slh from './slh-dsa-ref.js';

const SEED = new Uint8Array(32).fill(0xcc);
const SK_SEED = new Uint8Array(32).fill(0xdd);

describe('SLH-DSA-LITE PQ-native tx signing', () => {
  it('slhDsaAddress derives a 32-byte hex address with 0x prefix', () => {
    const { pk } = slh.keygen(SEED, SK_SEED);
    const addr = slhDsaAddress(pk);
    expect(addr).toMatch(/^0x[0-9a-f]{64}$/);
  });

  it('slhDsaAddress is deterministic for the same pk', () => {
    const { pk } = slh.keygen(SEED, SK_SEED);
    expect(slhDsaAddress(pk)).toBe(slhDsaAddress(pk));
  });

  it('slhDsaAddress differs when the pk differs', () => {
    const a = slh.keygen(SEED, SK_SEED);
    const b = slh.keygen(SEED, new Uint8Array(32).fill(0xee));
    expect(slhDsaAddress(a.pk)).not.toBe(slhDsaAddress(b.pk));
  });

  it('intentDigest is blake2b256 of [0,0,0] || txBytes — 32 bytes', () => {
    const tx = new Uint8Array([1, 2, 3, 4, 5]);
    const d = intentDigest(tx);
    expect(d.length).toBe(32);
  });

  it('signed tx bytes pass the local pre-flight verify', () => {
    const { pk, sk } = slh.keygen(SEED, SK_SEED);
    const tx = new TextEncoder().encode('hello, PQ-native transaction');
    const sig = signTxWithSlhDsa(tx, pk, sk);
    expect(sig.length).toBe(1 + 32 + 32 + 5056);
    expect(sig[0]).toBe(SLH_DSA_LITE_FLAG);
    expect(verifyTxSlhDsaSig(tx, sig)).toBe(true);
  });

  it('embedded pk in the sig blob is the keypair pk', () => {
    const { pk, sk } = slh.keygen(SEED, SK_SEED);
    const tx = new Uint8Array([9, 9, 9]);
    const sig = signTxWithSlhDsa(tx, pk, sk);
    expect(Array.from(sig.slice(1, 33))).toEqual(Array.from(pk.seed));
    expect(Array.from(sig.slice(33, 65))).toEqual(Array.from(pk.root));
  });

  it('tampering with even one byte of txBytes invalidates the sig', () => {
    const { pk, sk } = slh.keygen(SEED, SK_SEED);
    const tx = new TextEncoder().encode('the original tx');
    const sig = signTxWithSlhDsa(tx, pk, sk);

    const tamperedTx = new Uint8Array(tx);
    tamperedTx[0] = ((tamperedTx[0] ?? 0) ^ 0x01) & 0xff;
    expect(verifyTxSlhDsaSig(tamperedTx, sig)).toBe(false);
  });

  it('tampering with the sig payload invalidates the sig', () => {
    const { pk, sk } = slh.keygen(SEED, SK_SEED);
    const tx = new TextEncoder().encode('payload integrity');
    const sig = signTxWithSlhDsa(tx, pk, sk);

    const tamperedSig = new Uint8Array(sig);
    tamperedSig[100] = ((tamperedSig[100] ?? 0) ^ 0xff) & 0xff;
    expect(verifyTxSlhDsaSig(tx, tamperedSig)).toBe(false);
  });

  it('wrong flag byte is rejected', () => {
    const { pk, sk } = slh.keygen(SEED, SK_SEED);
    const tx = new Uint8Array([1, 2, 3]);
    const sig = signTxWithSlhDsa(tx, pk, sk);
    sig[0] = 0x00; // pretend it's ed25519
    expect(verifyTxSlhDsaSig(tx, sig)).toBe(false);
  });

  it('truncated signature is rejected', () => {
    const { pk, sk } = slh.keygen(SEED, SK_SEED);
    const tx = new Uint8Array([7, 7, 7]);
    const sig = signTxWithSlhDsa(tx, pk, sk);
    expect(verifyTxSlhDsaSig(tx, sig.slice(0, sig.length - 1))).toBe(false);
  });

  it('signing a different message with the same key produces a different sig', () => {
    const { pk, sk } = slh.keygen(SEED, SK_SEED);
    const a = signTxWithSlhDsa(new Uint8Array([1]), pk, sk);
    const b = signTxWithSlhDsa(new Uint8Array([2]), pk, sk);
    expect(Buffer.from(a).toString('hex')).not.toEqual(Buffer.from(b).toString('hex'));
  });
});
