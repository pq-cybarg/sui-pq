import { describe, expect, it } from 'vitest';
import { identityHex, makeIdentity } from './identity.js';

describe('makeIdentity', () => {
  const pkg = '0x0000000000000000000000000000000000000000000000000000000000000001';

  it('prepends 32-byte package id to namespace bytes', () => {
    const id = makeIdentity(pkg, new Uint8Array([1, 2, 3]));
    expect(id.length).toBe(32 + 3);
    expect(id[32]).toBe(1);
    expect(id[33]).toBe(2);
    expect(id[34]).toBe(3);
  });

  it('handles string namespaces via utf-8', () => {
    const id = makeIdentity(pkg, 'hi');
    expect(id.length).toBe(32 + 2);
  });

  it('hex form is hex', () => {
    const hex = identityHex(pkg, 'x');
    expect(hex).toMatch(/^[0-9a-f]+$/);
  });
});
