import { describe, expect, it } from 'vitest';
import { TESTNET_ENDPOINTS } from './config.js';
import { WalrusHttpClient } from './http-client.js';

describe('WalrusHttpClient', () => {
  it('builds aggregator URLs', () => {
    const c = new WalrusHttpClient();
    const url = c.url('abc123');
    expect(url).toContain('/v1/blobs/abc123');
  });

  it('respects endpoint overrides', () => {
    const c = new WalrusHttpClient({ aggregator: 'https://example.com' });
    expect(c.endpoints.aggregator).toBe('https://example.com');
    expect(c.endpoints.publisher).toBe(TESTNET_ENDPOINTS.publisher);
  });
});
