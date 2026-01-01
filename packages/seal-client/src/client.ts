/**
 * High-level wrapper around @mysten/seal.
 *
 * Encryption flow:
 *   - Caller chooses an `id` (bytes) — typically `bcs(packageId || allowlistId || nonce)`.
 *   - SealClient.encrypt(...) returns a ciphertext that can ONLY be decrypted if a quorum
 *     of key servers run `seal_approve(id, ...)` on the user-specified Move package and the
 *     function does NOT abort.
 *
 * On decryption:
 *   - Caller assembles a Transaction that calls `<pkg>::<module>::seal_approve(id, …)` as a
 *     dev-inspect / dry-run. The key servers execute that tx; if it succeeds, they release
 *     their key shares. The SDK combines shares ≥ threshold and decrypts locally.
 */
import { SealClient as Inner, SessionKey } from '@mysten/seal';
import { type Network, getClient } from '@sui-gen/sdk-core';
import { type KeyServer, defaultThreshold, keyServersFromEnv } from './key-servers.js';

export interface CreateSealOptions {
  network?: Network;
  keyServers?: KeyServer[];
  threshold?: number;
  verifyKeyServers?: boolean;
}

export function createSealClient(opts: CreateSealOptions = {}): InstanceType<typeof Inner> {
  const network = opts.network ?? 'testnet';
  const keyServers = opts.keyServers ?? keyServersFromEnv();
  const suiClient = getClient({ network });
  return new Inner({
    suiClient: suiClient as unknown as ConstructorParameters<typeof Inner>[0]['suiClient'],
    serverConfigs: keyServers.map((k) => ({ objectId: k.objectId, weight: 1 })),
    verifyKeyServers: opts.verifyKeyServers ?? false,
  });
}

export { SessionKey, Inner as SealClient };
export { defaultThreshold };
export type { KeyServer };
