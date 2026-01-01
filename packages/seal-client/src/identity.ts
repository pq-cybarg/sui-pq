import { toHex } from '@mysten/bcs';
import { bcs } from '@mysten/sui/bcs';

/**
 * Compose an `id` byte string for Seal encryption.
 *
 * Convention used by Mysten Labs in the Seal examples:
 *   id = packageId || appSpecificBytes
 * where `packageId` is the 32-byte Move package id and `appSpecificBytes` is whatever
 * your `seal_approve` expects (commonly the namespaced object id + nonce).
 *
 * `seal_approve(id: vector<u8>, …)` should reject if the namespace bytes don't match
 * the object being accessed — otherwise an attacker could ask a key server to release
 * a key for some other object using your contract's authz.
 */
export function makeIdentity(packageId: string, namespace: Uint8Array | string): Uint8Array {
  const pkg = bcs.Address.serialize(packageId).toBytes();
  const ns = typeof namespace === 'string' ? new TextEncoder().encode(namespace) : namespace;
  const out = new Uint8Array(pkg.length + ns.length);
  out.set(pkg, 0);
  out.set(ns, pkg.length);
  return out;
}

export function identityHex(packageId: string, namespace: Uint8Array | string): string {
  return toHex(makeIdentity(packageId, namespace));
}
