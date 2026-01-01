import { describe, expect, it } from 'vitest';
import { newEphemeralSigner } from './signers.js';

describe('signers', () => {
  it('newEphemeralSigner produces a valid Sui address', () => {
    const s = newEphemeralSigner();
    const addr = s.toSuiAddress();
    expect(addr).toMatch(/^0x[0-9a-f]{64}$/);
  });
});
