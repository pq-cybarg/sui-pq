import { bcs, fromBase64, fromHex, toBase64, toHex } from '@mysten/bcs';

export { bcs, fromBase64, toBase64, fromHex, toHex };

/** Convenience for serializing a `vector<u8>` arg in transactions. */
export function bytesArg(value: Uint8Array | string): Uint8Array {
  if (typeof value === 'string') return new TextEncoder().encode(value);
  return value;
}
