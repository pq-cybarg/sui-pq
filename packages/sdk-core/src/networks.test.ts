import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { NETWORKS, resolveNetwork } from './networks.js';

describe('networks', () => {
  let saved: string | undefined;
  beforeEach(() => {
    saved = process.env.SUI_NETWORK;
    Reflect.deleteProperty(process.env, 'SUI_NETWORK');
  });
  afterEach(() => {
    if (saved === undefined) Reflect.deleteProperty(process.env, 'SUI_NETWORK');
    else process.env.SUI_NETWORK = saved;
  });

  it('exposes a URL for every named network', () => {
    for (const n of ['mainnet', 'testnet', 'devnet', 'localnet'] as const) {
      expect(NETWORKS[n].url).toMatch(/^https?:\/\//);
    }
  });

  it('defaults to testnet when nothing is provided', () => {
    expect(resolveNetwork()).toBe('testnet');
  });

  it('reads from env', () => {
    process.env.SUI_NETWORK = 'devnet';
    expect(resolveNetwork()).toBe('devnet');
  });

  it('throws on unknown', () => {
    expect(() => resolveNetwork('atlantis')).toThrow();
  });
});
