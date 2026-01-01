import { describe, expect, it } from 'vitest';
import { buildUnlockMessageBytes } from './pq-guard.js';

describe('PQ-Guard message construction', () => {
  it('packs tag || sender(32) || nonce(8 BE) || action_digest(32) — 86 bytes', () => {
    const m = buildUnlockMessageBytes({
      sender: `0x${'0a'.repeat(32)}`,
      nonce: 0n,
      actionDigest: new Uint8Array(32).fill(0x55),
    });
    expect(m.length).toBe(18 + 32 + 8 + 32);
    // Tag bytes
    expect(new TextDecoder().decode(m.slice(0, 18))).toBe('PQ_GUARD:UNLOCK:v1');
    // Sender bytes
    expect(Array.from(m.slice(18, 50))).toEqual(Array(32).fill(0x0a));
    // Nonce bytes (all zero for nonce=0)
    expect(Array.from(m.slice(50, 58))).toEqual(Array(8).fill(0));
    // Action digest
    expect(Array.from(m.slice(58, 90))).toEqual(Array(32).fill(0x55));
  });

  it('encodes nonce big-endian', () => {
    const m = buildUnlockMessageBytes({
      sender: `0x${'00'.repeat(32)}`,
      nonce: 0x0102030405060708n,
      actionDigest: new Uint8Array(32),
    });
    expect(Array.from(m.slice(50, 58))).toEqual([0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08]);
  });

  it('left-pads short addresses', () => {
    const m = buildUnlockMessageBytes({
      sender: '0xa',
      nonce: 1n,
      actionDigest: new Uint8Array(32),
    });
    expect(Array.from(m.slice(18, 49))).toEqual(Array(31).fill(0));
    expect(m[49]).toBe(0x0a);
  });

  it('rejects an action_digest of wrong length', () => {
    expect(() =>
      buildUnlockMessageBytes({
        sender: `0x${'aa'.repeat(32)}`,
        nonce: 0n,
        actionDigest: new Uint8Array(16),
      }),
    ).toThrow(/32 bytes/);
  });
});
