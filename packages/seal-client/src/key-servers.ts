/**
 * Seal key-server registry. In production you'd discover these from the on-chain
 * registry object — these defaults match Mysten Labs' public testnet servers.
 */
export interface KeyServer {
  objectId: string;
  url: string;
}

/** Public Seal testnet key servers maintained by Mysten Labs. */
export const TESTNET_KEY_SERVERS: KeyServer[] = [
  {
    objectId: '0x73d05d62c18d9374e3ea529e8e0ed6161da1a141a94d3f76ae3fe4e99356db75',
    url: 'https://seal-key-server-testnet-1.mystenlabs.com',
  },
  {
    objectId: '0xf5d14a81a982144ae441cd7d64b09027f116a468bd36e7eca494f750591623c8',
    url: 'https://seal-key-server-testnet-2.mystenlabs.com',
  },
];

export function keyServersFromEnv(): KeyServer[] {
  const urls = process.env.SEAL_KEY_SERVERS?.split(',')
    .map((s) => s.trim())
    .filter(Boolean);
  if (!urls?.length) return TESTNET_KEY_SERVERS;
  return urls.map((url, i) => ({ objectId: TESTNET_KEY_SERVERS[i]?.objectId ?? '0x0', url }));
}

export function defaultThreshold(): number {
  return Number(process.env.SEAL_THRESHOLD ?? 2);
}
