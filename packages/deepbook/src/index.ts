/**
 * DeepBook V3 helpers — Sui's first-party CLOB.
 * Pool addresses + base/quote ratios are network-specific; cache them at startup.
 */
import { DeepBookClient } from '@mysten/deepbook-v3';
import { type Network, getClient } from '@sui-gen/sdk-core';

export interface CreateOptions {
  network?: Network;
  /** The sui address that orders will be associated with. */
  address: string;
  /** Map of pool symbol → constructor metadata. */
  balanceManagers?: Record<string, { address: string; tradeCap?: string }>;
}

export function createDeepBookClient(opts: CreateOptions): DeepBookClient {
  const network = opts.network ?? 'mainnet';
  const suiClient = getClient({ network });
  return new DeepBookClient({
    address: opts.address,
    env: network === 'testnet' ? 'testnet' : 'mainnet',
    client: suiClient as unknown as ConstructorParameters<typeof DeepBookClient>[0]['client'],
    balanceManagers: opts.balanceManagers ?? {},
  });
}

export const INDEXER_URL =
  process.env.DEEPBOOK_INDEXER_URL ?? 'https://deepbook-indexer.mainnet.mystenlabs.com';

/** Fetch the spread on a DeepBook pool from the public indexer. */
export async function getOrderbookSnapshot(poolKey: string) {
  const res = await fetch(`${INDEXER_URL}/get_order_book/${encodeURIComponent(poolKey)}`);
  if (!res.ok) throw new Error(`DeepBook indexer failed: ${res.status}`);
  return res.json() as Promise<{
    timestamp: number;
    bids: Array<[number, number]>;
    asks: Array<[number, number]>;
  }>;
}

export { DeepBookClient };
