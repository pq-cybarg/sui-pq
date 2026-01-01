import { describe, expect, it } from 'vitest';
import { RECOMMENDED_WALLETS, SLUSH_DISPLAY_NAME } from './wallets.js';

describe('wallet registry', () => {
  it('lists Slush first', () => {
    const keys = Object.keys(RECOMMENDED_WALLETS);
    expect(keys[0]).toBe('slush');
  });

  it('uses the official Slush display name', () => {
    expect(SLUSH_DISPLAY_NAME).toBe('Slush — A Sui wallet');
    expect(RECOMMENDED_WALLETS.slush.name).toBe(SLUSH_DISPLAY_NAME);
  });

  it('covers Slush, Suiet, Phantom, Nightly, OKX', () => {
    expect(Object.keys(RECOMMENDED_WALLETS).sort()).toEqual(
      ['nightly', 'okx', 'phantom', 'slush', 'suiet'].sort(),
    );
  });
});
