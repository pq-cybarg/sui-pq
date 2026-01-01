import { SuiClient } from '@mysten/sui/client';
import { NETWORKS, type Network, resolveNetwork } from './networks.js';

export interface ClientOptions {
  network?: Network;
  url?: string;
}

const cache = new Map<string, SuiClient>();

/** Returns a memoized SuiClient for the requested network. */
export function getClient(opts: ClientOptions = {}): SuiClient {
  const network = opts.network ?? resolveNetwork();
  const url = opts.url ?? process.env.SUI_RPC_URL ?? NETWORKS[network].url;
  const key = `${network}:${url}`;
  let client = cache.get(key);
  if (!client) {
    client = new SuiClient({ url });
    cache.set(key, client);
  }
  return client;
}

export type { SuiClient };
