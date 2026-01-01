import { describe, expect, it } from 'vitest';
import { DEFAULT_LUMIWAVE_CONFIG } from './config.js';

describe('Lumiwave config', () => {
  it('exposes a coin type', () => {
    expect(DEFAULT_LUMIWAVE_CONFIG.coinType).toContain('::lwa::LWA');
  });
  it('exposes a default RPC URL', () => {
    expect(DEFAULT_LUMIWAVE_CONFIG.rpcUrl).toMatch(/^https?:\/\//);
  });
});
