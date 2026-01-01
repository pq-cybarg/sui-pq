/**
 * Pure-TS WOTS+ reference implementation. Byte-identical to `move/wots`'s
 * verifier:
 *   F(seed, ADRS, M) = SHA-256(seed || ADRS || M)
 *   parameters: n=32, lg_w=4 (w=16), len_1=64, len_2=3, len=67
 *
 * Used to (a) generate Move-side test vectors, (b) verify an attestation
 * off-chain when the on-chain Move call would be too expensive, (c) sanity-
 * check arbitrary signatures before submitting them.
 *
 * NB: this is NOT the WOTS+ from FIPS 205's full SLH-DSA — that one uses
 * separate `PRF`, `F`, `T_l` tweakable hashes. This is a simplified WOTS+
 * that's good enough to demonstrate Move-native PQ verification end-to-end.
 */
import { sha256 } from '@noble/hashes/sha256';

export const WOTS = {
  n: 32,
  w: 16,
  lg_w: 4,
  len_1: 64,
  len_2: 3,
  len: 67,
} as const;

const TYPE_WOTS_HASH = 0;
const TYPE_WOTS_PK = 1;

function writeU32BE(buf: Uint8Array, off: number, v: number): void {
  buf[off + 0] = (v >>> 24) & 0xff;
  buf[off + 1] = (v >>> 16) & 0xff;
  buf[off + 2] = (v >>> 8) & 0xff;
  buf[off + 3] = v & 0xff;
}

export function buildAdrs(opts: {
  layer?: number;
  tree?: bigint;
  type?: number;
  keypair?: number;
  chain?: number;
  hash?: number;
}): Uint8Array {
  const a = new Uint8Array(32);
  if (opts.layer !== undefined) writeU32BE(a, 0, opts.layer);
  if (opts.tree !== undefined) {
    const lo = Number(opts.tree & 0xffffffffn);
    const hi = Number((opts.tree >> 32n) & 0xffffffffn);
    writeU32BE(a, 8, hi);
    writeU32BE(a, 12, lo);
  }
  if (opts.type !== undefined) writeU32BE(a, 16, opts.type);
  if (opts.keypair !== undefined) writeU32BE(a, 20, opts.keypair);
  if (opts.chain !== undefined) writeU32BE(a, 24, opts.chain);
  if (opts.hash !== undefined) writeU32BE(a, 28, opts.hash);
  return a;
}

function concat(...parts: Uint8Array[]): Uint8Array {
  const total = parts.reduce((a, p) => a + p.length, 0);
  const out = new Uint8Array(total);
  let off = 0;
  for (const p of parts) {
    out.set(p, off);
    off += p.length;
  }
  return out;
}

function F(seed: Uint8Array, adrs: Uint8Array, m: Uint8Array): Uint8Array {
  return sha256(concat(seed, adrs, m));
}

/** Base-16 decode with FIPS 205 checksum, identical to the Move impl. */
export function msgToChains(msg: Uint8Array): number[] {
  if (msg.length !== WOTS.n) throw new Error(`msg must be ${WOTS.n} bytes`);
  const out: number[] = [];
  for (let i = 0; i < WOTS.n; i++) {
    const b = msg[i]!;
    out.push((b >> 4) & 0x0f);
    out.push(b & 0x0f);
  }
  let csum = 0;
  for (let k = 0; k < WOTS.len_1; k++) csum += WOTS.w - 1 - out[k]!;
  csum <<= 4;
  // 12-bit checksum → 2 high bytes
  const hi = (csum >> 8) & 0xff;
  const lo = csum & 0xff;
  out.push((hi >> 4) & 0x0f);
  out.push(hi & 0x0f);
  out.push((lo >> 4) & 0x0f);
  return out;
}

/** Climb a single chain from `start` for `steps` applications of F. */
function chainStep(seed: Uint8Array, baseAdrs: Uint8Array, chainIdx: number, start: number, steps: number, value: Uint8Array): Uint8Array {
  const adrs = baseAdrs.slice();
  writeU32BE(adrs, 16, TYPE_WOTS_HASH);
  writeU32BE(adrs, 24, chainIdx);
  let v = value;
  for (let j = 0; j < steps; j++) {
    writeU32BE(adrs, 28, start + j);
    v = F(seed, adrs, v);
  }
  return v;
}

export interface WotsKeypair {
  seed: Uint8Array;
  adrs: Uint8Array;
  secretChains: Uint8Array; // len * n
  publicKey: Uint8Array; // len * n
}

/**
 * Deterministic keygen from a 32-byte master + ADRS. Each chain's secret
 * start is `SHA-256(master || "wots-sk" || u32(i))`.
 */
export function wotsKeygen(master: Uint8Array, seed: Uint8Array, adrs: Uint8Array): WotsKeypair {
  if (master.length !== 32) throw new Error('master must be 32 bytes');
  if (seed.length !== 32) throw new Error('seed must be 32 bytes');
  if (adrs.length !== 32) throw new Error('adrs must be 32 bytes');

  const sk = new Uint8Array(WOTS.len * WOTS.n);
  const pk = new Uint8Array(WOTS.len * WOTS.n);
  const tag = new TextEncoder().encode('wots-sk');

  for (let i = 0; i < WOTS.len; i++) {
    const counter = new Uint8Array(4);
    writeU32BE(counter, 0, i);
    const sk_i = sha256(concat(master, tag, counter));
    sk.set(sk_i, i * WOTS.n);

    // Public key chunk = F^(w-1) applied to sk_i along the i-th chain.
    const top_i = chainStep(seed, adrs, i, 0, WOTS.w - 1, sk_i);
    pk.set(top_i, i * WOTS.n);
  }
  return { seed, adrs, secretChains: sk, publicKey: pk };
}

/** Sign a 32-byte message digest. */
export function wotsSign(kp: WotsKeypair, msgDigest: Uint8Array): Uint8Array {
  if (msgDigest.length !== WOTS.n) throw new Error('msgDigest must be 32 bytes');
  const chains = msgToChains(msgDigest);
  const sig = new Uint8Array(WOTS.len * WOTS.n);
  for (let i = 0; i < WOTS.len; i++) {
    const sk_i = kp.secretChains.slice(i * WOTS.n, (i + 1) * WOTS.n);
    const v = chainStep(kp.seed, kp.adrs, i, 0, chains[i]!, sk_i);
    sig.set(v, i * WOTS.n);
  }
  return sig;
}

/** Reference verifier — mirrors the Move logic. */
export function wotsVerify(
  seed: Uint8Array,
  adrs: Uint8Array,
  msgDigest: Uint8Array,
  signature: Uint8Array,
  pk: Uint8Array,
): boolean {
  if (seed.length !== WOTS.n) return false;
  if (adrs.length !== 32) return false;
  if (msgDigest.length !== WOTS.n) return false;
  if (signature.length !== WOTS.len * WOTS.n) return false;
  if (pk.length !== WOTS.len * WOTS.n) return false;

  const chains = msgToChains(msgDigest);
  for (let i = 0; i < WOTS.len; i++) {
    const start = chains[i]!;
    const steps = WOTS.w - 1 - start;
    const sig_i = signature.slice(i * WOTS.n, (i + 1) * WOTS.n);
    const derived = chainStep(seed, adrs, i, start, steps, sig_i);
    const pk_i = pk.slice(i * WOTS.n, (i + 1) * WOTS.n);
    for (let k = 0; k < WOTS.n; k++) {
      if (derived[k] !== pk_i[k]) return false;
    }
  }
  return true;
}
