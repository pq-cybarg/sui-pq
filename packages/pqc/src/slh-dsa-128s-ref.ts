/**
 * FIPS-205 SLH-DSA-SHA2-128s — verify path, reproduced from spec.
 *
 * Cross-checked byte-exact against @noble/post-quantum's audited
 * `slh_dsa_sha2_128s`: every SHA-256 call (Hmsg + tweakable hashes) in this
 * implementation produces an identical input and output to noble's, including
 * the 22-byte compressed ADRS layout, the MGF1-SHA-256 derived message digest,
 * WOTS+ chain walk, FORS auth-path walk, and the d-layer Hypertree.
 *
 * The full off-chain path in this workspace still routes through noble (which
 * is audited); this module is the spec-traceable reference used to derive the
 * Move verifier in `move/slh_dsa_128s` with confidence that the byte format
 * matches.
 *
 * Parameters (FIPS-205 §10.1):
 *   n      = 16          (hash bytes, SHA-256 truncated to 16)
 *   lg_w   = 4, w = 16   (Winternitz)
 *   len_1  = ceil(8n / lg_w)                      = 32
 *   len_2  = floor(log(len_1·(w-1)) / lg_w) + 1   = 3
 *   len    = len_1 + len_2                         = 35
 *   h      = 63          (total Merkle height)
 *   d      = 7           (XMSS layers; h' = h/d = 9)
 *   h_prime= 9
 *   a      = 12          (FORS leaf depth)
 *   k      = 14          (FORS trees)
 *   m      = (k·a) bits ⌈ /8 ⌉ + h bits ⌈ /8 ⌉ = 30  (msg digest bytes)
 *
 * Address structure (FIPS-205 §4.2.2.2, the compressed form for SHA2):
 *   layer_addr     1 byte
 *   tree_addr      8 bytes
 *   type           1 byte
 *   keypair_addr   4 bytes (or tree_height/tree_index depending on type)
 *   tree_height    4 bytes
 *   tree_index     4 bytes
 *   = 22 bytes total
 *
 * Tweakable hashes (FIPS-205 §11.2.1 — "simple" variant):
 *   F(seed, ADRS, M_1)      = SHA-256(seed || toByte(0, 64-n) || ADRS_c || M_1)[0..n]
 *   H(seed, ADRS, M_2)      = SHA-256(seed || toByte(0, 64-n) || ADRS_c || M_2)[0..n]
 *   T_l(seed, ADRS, M_l)    = SHA-256(seed || toByte(0, 64-n) || ADRS_c || M_l)[0..n]
 *   H_msg(R, PK.seed, PK.root, M) = MGF1-SHA-256(R || PK.seed || PK.root || M, m)
 *
 *   where toByte(0, 64-n) = 48 zero bytes (n=16 ⇒ 64-16=48).
 *   ADRS_c is the 22-byte compressed address.
 */
import { sha256 } from '@noble/hashes/sha256';

export const FIPS205 = {
  n: 16,
  lg_w: 4,
  w: 16,
  len_1: 32,
  len_2: 3,
  len: 35,
  h: 63,
  d: 7,
  h_prime: 9,
  a: 12,
  k: 14,
  m: 30,
  pkBytes: 32,
  sigBytes: 7856,
  /** ADRS-c size (compressed for SHA2-128s). */
  adrsBytes: 22,
} as const;

// ADRS types (FIPS-205 §4.2.2.2)
const WOTS_HASH = 0;
const WOTS_PK = 1;
const TREE = 2;
const FORS_TREE = 3;
const FORS_ROOTS = 4;
// types 5 (WOTS_PRF) and 6 (FORS_PRF) only appear in keygen / signing.

// ── byte helpers ───────────────────────────────────────────────────────────
function concat(...parts: Uint8Array[]): Uint8Array {
  let n = 0;
  for (const p of parts) n += p.length;
  const out = new Uint8Array(n);
  let off = 0;
  for (const p of parts) {
    out.set(p, off);
    off += p.length;
  }
  return out;
}

function writeU8(buf: Uint8Array, off: number, v: number): void {
  buf[off] = v & 0xff;
}
function writeU32BE(buf: Uint8Array, off: number, v: number): void {
  buf[off + 0] = (v >>> 24) & 0xff;
  buf[off + 1] = (v >>> 16) & 0xff;
  buf[off + 2] = (v >>> 8) & 0xff;
  buf[off + 3] = v & 0xff;
}
function writeU64BE(buf: Uint8Array, off: number, v: bigint): void {
  let n = v;
  for (let i = 7; i >= 0; i--) {
    buf[off + i] = Number(n & 0xffn);
    n >>= 8n;
  }
}

/**
 * Compressed 22-byte ADRS as defined in FIPS-205 §11.2.1.
 *
 *   ADRS_c[0]     = ADRS.layer_addr (low byte)
 *   ADRS_c[1..9]  = ADRS.tree_addr  (low 8 bytes BE)
 *   ADRS_c[9]     = ADRS.type
 *   ADRS_c[10..14]= ADRS.keypair_addr  (or tree_height for non-WOTS)
 *   ADRS_c[14..18]= ADRS.tree_height
 *   ADRS_c[18..22]= ADRS.tree_index
 *
 * Field positions inferred from FIPS-205 + cross-check against noble.
 */
export interface Adrs {
  layer: number;
  tree: bigint;
  type: number;
  keypair: number;
  treeHeight: number;
  treeIndex: number;
}

export function newAdrs(): Adrs {
  return { layer: 0, tree: 0n, type: 0, keypair: 0, treeHeight: 0, treeIndex: 0 };
}

export function compressAdrs(a: Adrs): Uint8Array {
  const out = new Uint8Array(FIPS205.adrsBytes);
  writeU8(out, 0, a.layer);
  writeU64BE(out, 1, a.tree);
  writeU8(out, 9, a.type);
  // The remaining 12 bytes are 3 u32s. Their semantic depends on ADRS type
  // but the byte positions are fixed.
  writeU32BE(out, 10, a.keypair);
  writeU32BE(out, 14, a.treeHeight);
  writeU32BE(out, 18, a.treeIndex);
  return out;
}

// ── tweakable hashes (FIPS-205 §11.2.1 "simple" variant for SHA2) ──────────
const PAD48 = new Uint8Array(48); // toByte(0, 64-n) when n=16

function thash(pkSeed: Uint8Array, adrs: Adrs, msg: Uint8Array): Uint8Array {
  const adrsC = compressAdrs(adrs);
  return sha256(concat(pkSeed, PAD48, adrsC, msg)).slice(0, FIPS205.n);
}

// F = H = T_l in the "simple" SHA-2 variant — same primitive, different input length.
export const F = thash;
export const H = thash;
export const T_l = thash;

/**
 * MGF1-SHA-256 from PKCS#1 §B.2.1.
 * Produces `outLen` bytes by hashing (seed || u32_be(counter)) repeatedly.
 */
function mgf1Sha256(seed: Uint8Array, outLen: number): Uint8Array {
  const out: number[] = [];
  let counter = 0;
  while (out.length < outLen) {
    const c = new Uint8Array(4);
    writeU32BE(c, 0, counter);
    const block = sha256(concat(seed, c));
    for (const b of block) out.push(b);
    counter++;
  }
  return new Uint8Array(out.slice(0, outLen));
}

/**
 * H_msg(R, PK.seed, PK.root, M) → 30 bytes (FIPS-205 §11.2.2).
 *
 *   inner = SHA-256(R || PK.seed || PK.root || M)        // 32 bytes
 *   seed  = R || PK.seed || inner                         // n + n + 32 bytes
 *   out   = MGF1-SHA-256(seed, m)
 *
 * Pre-hashing M is what lets the spec keep `seed` short (n + n + 32 = 64 bytes
 * for 128s) regardless of message length.
 */
export function Hmsg(
  R: Uint8Array,
  pkSeed: Uint8Array,
  pkRoot: Uint8Array,
  M: Uint8Array,
): Uint8Array {
  const inner = sha256(concat(R, pkSeed, pkRoot, M));
  const seed = concat(R, pkSeed, inner);
  return mgf1Sha256(seed, FIPS205.m);
}

// ── base-w decode + checksum for WOTS+ (FIPS-205 §5) ──────────────────────
/** Decode `msg` into `outlen` base-`w` digits, w = 2^lg_w. */
function baseW(msg: Uint8Array, outlen: number): number[] {
  const out: number[] = [];
  let inIdx = 0;
  let bits = 0;
  let total = 0;
  for (let i = 0; i < outlen; i++) {
    if (bits === 0) {
      total = msg[inIdx++]!;
      bits = 8;
    }
    bits -= FIPS205.lg_w;
    out.push((total >> bits) & (FIPS205.w - 1));
  }
  return out;
}

function wotsChecksum(msgDigits: number[]): number[] {
  let csum = 0;
  for (let i = 0; i < FIPS205.len_1; i++) csum += FIPS205.w - 1 - msgDigits[i]!;
  // shift to align to bit boundary; FIPS-205 spec: csum << ((8 - ((len_2 * lg_w) % 8)) % 8)
  csum = csum << ((8 - ((FIPS205.len_2 * FIPS205.lg_w) % 8)) % 8);
  const lenBytes = Math.ceil((FIPS205.len_2 * FIPS205.lg_w) / 8);
  const csumBytes = new Uint8Array(lenBytes);
  for (let i = lenBytes - 1; i >= 0; i--) {
    csumBytes[i] = csum & 0xff;
    csum >>>= 8;
  }
  return baseW(csumBytes, FIPS205.len_2);
}

/** Compute the full base-w decomposition (msg digits + checksum) for WOTS+. */
export function msgToChainDigits(msg16: Uint8Array): number[] {
  const m = baseW(msg16, FIPS205.len_1);
  const c = wotsChecksum(m);
  return [...m, ...c];
}

// ── WOTS+ chain step (FIPS-205 §5.1, chain function) ──────────────────────
//
// In a WOTS_HASH ADRS:
//   ADRS.chain_address (byte 17 in compressed form) — which chain, set by caller.
//   ADRS.hash_address  (byte 21)                    — position within chain, varies per F-call.
// In our Adrs struct, those map to (treeHeight, treeIndex) respectively because
// the spec's compressed layout puts them at exactly those byte positions.
function chain(x: Uint8Array, i: number, s: number, pkSeed: Uint8Array, adrs: Adrs): Uint8Array {
  let tmp = x;
  for (let j = i; j < i + s; j++) {
    adrs.treeIndex = j; // hash_address (byte 21) increments along the chain
    tmp = F(pkSeed, adrs, tmp);
  }
  return tmp;
}

// ── WOTS+ pubkey from signature (FIPS-205 §5.4) ───────────────────────────
export function wotsPkFromSig(
  sig: Uint8Array,
  msg16: Uint8Array,
  pkSeed: Uint8Array,
  adrs: Adrs, // ADRS arriving with type=WOTS_HASH; layer/tree/keypair set by caller
): Uint8Array {
  const digits = msgToChainDigits(msg16);
  const tmp = new Uint8Array(FIPS205.len * FIPS205.n);
  for (let i = 0; i < FIPS205.len; i++) {
    const a: Adrs = { ...adrs };
    a.type = WOTS_HASH;
    a.treeHeight = i; // chain_address (byte 17)
    const piece = chain(
      sig.slice(i * FIPS205.n, (i + 1) * FIPS205.n),
      digits[i]!,
      FIPS205.w - 1 - digits[i]!,
      pkSeed,
      a,
    );
    tmp.set(piece, i * FIPS205.n);
  }
  // Compress all len chain-tops to a single n-byte WOTS+ pubkey via T_len.
  // The T_l call uses a WOTS_PK ADRS that inherits layer/tree/keypair from the
  // WOTS_HASH ADRS — so the caller's keypair_address is what binds the pk to
  // this XMSS leaf.
  const tAdrs: Adrs = { ...adrs };
  tAdrs.type = WOTS_PK;
  tAdrs.treeHeight = 0;
  tAdrs.treeIndex = 0;
  return T_l(pkSeed, tAdrs, tmp);
}

// ── XMSS root from sig (FIPS-205 §6.4) ────────────────────────────────────
export function xmssPkFromSig(
  idx: number,
  sig: Uint8Array, // WOTS+ sig || auth path (h_prime nodes of n bytes)
  msg16: Uint8Array,
  pkSeed: Uint8Array,
  adrs: Adrs,
): Uint8Array {
  const wotsSig = sig.slice(0, FIPS205.len * FIPS205.n);
  const auth = sig.slice(
    FIPS205.len * FIPS205.n,
    FIPS205.len * FIPS205.n + FIPS205.h_prime * FIPS205.n,
  );

  adrs.type = WOTS_HASH;
  adrs.keypair = idx;
  let node = wotsPkFromSig(wotsSig, msg16, pkSeed, adrs);

  // TREE address: keypair word is padding (zero) per FIPS-205 §4.2.2.
  // Clear it before reusing the address for the auth-path walk.
  adrs.type = TREE;
  adrs.keypair = 0;
  adrs.treeIndex = idx;
  for (let i = 0; i < FIPS205.h_prime; i++) {
    adrs.treeHeight = i + 1;
    adrs.treeIndex = adrs.treeIndex >>> 1;
    const sibling = auth.slice(i * FIPS205.n, (i + 1) * FIPS205.n);
    const bit = (idx >>> i) & 1;
    const merged = bit === 0 ? concat(node, sibling) : concat(sibling, node);
    node = H(pkSeed, adrs, merged);
  }
  return node;
}

// ── Hypertree (HT) root from sig (FIPS-205 §7.2) ──────────────────────────
export function htRootFromSig(
  sigHt: Uint8Array,
  msg16: Uint8Array,
  treeIdx: bigint,
  leafIdx: number,
  pkSeed: Uint8Array,
): Uint8Array {
  const xmssSigBytes = (FIPS205.len + FIPS205.h_prime) * FIPS205.n;
  let node = msg16;
  let curTree = treeIdx;
  let curLeaf = leafIdx;
  for (let j = 0; j < FIPS205.d; j++) {
    const adrs = newAdrs();
    adrs.layer = j;
    adrs.tree = curTree;
    const sliceJ = sigHt.slice(j * xmssSigBytes, (j + 1) * xmssSigBytes);
    node = xmssPkFromSig(curLeaf, sliceJ, node, pkSeed, adrs);
    // promote: next layer
    const leafMask = (1n << BigInt(FIPS205.h_prime)) - 1n;
    curLeaf = Number(curTree & leafMask);
    curTree = curTree >> BigInt(FIPS205.h_prime);
  }
  return node;
}

// ── FORS pubkey from sig (FIPS-205 §8.4) ──────────────────────────────────
export function forsPkFromSig(
  sigFors: Uint8Array,
  md: Uint8Array, // first ⌈ka/8⌉ bytes of H_msg output
  pkSeed: Uint8Array,
  adrs: Adrs,
): Uint8Array {
  const chunkBytes = (1 + FIPS205.a) * FIPS205.n; // 13 * 16 = 208 per tree
  const roots: number[] = [];

  // Extract k indices, each `a` bits wide
  const indices: number[] = [];
  let bitOff = 0;
  for (let i = 0; i < FIPS205.k; i++) {
    let v = 0;
    for (let b = 0; b < FIPS205.a; b++) {
      const bitIdx = bitOff + b;
      const byte = md[bitIdx >> 3]!;
      v = (v << 1) | ((byte >> (7 - (bitIdx & 7))) & 1);
    }
    indices.push(v);
    bitOff += FIPS205.a;
  }

  for (let i = 0; i < FIPS205.k; i++) {
    const sk = sigFors.slice(i * chunkBytes, i * chunkBytes + FIPS205.n);
    const authPath = sigFors.slice(i * chunkBytes + FIPS205.n, (i + 1) * chunkBytes);
    const idx = indices[i]!;

    // Leaf = F(pkSeed, ADRS, sk) with ADRS.type=FORS_TREE, treeHeight=0, treeIndex = i*2^a + idx
    const leafAdrs: Adrs = { ...adrs };
    leafAdrs.type = FORS_TREE;
    leafAdrs.treeHeight = 0;
    leafAdrs.treeIndex = i * (1 << FIPS205.a) + idx;
    let node = F(pkSeed, leafAdrs, sk);

    let cur = idx;
    for (let j = 0; j < FIPS205.a; j++) {
      const sib = authPath.slice(j * FIPS205.n, (j + 1) * FIPS205.n);
      leafAdrs.treeHeight = j + 1;
      leafAdrs.treeIndex = i * (1 << (FIPS205.a - j - 1)) + (cur >>> 1);
      const merged = (cur & 1) === 0 ? concat(node, sib) : concat(sib, node);
      node = H(pkSeed, leafAdrs, merged);
      cur >>>= 1;
    }
    for (const b of node) roots.push(b);
  }

  const rootsAdrs: Adrs = { ...adrs };
  rootsAdrs.type = FORS_ROOTS;
  rootsAdrs.treeHeight = 0;
  rootsAdrs.treeIndex = 0;
  return T_l(pkSeed, rootsAdrs, new Uint8Array(roots));
}

// ── digest splitting (FIPS-205 §10.2) ─────────────────────────────────────
export function splitDigest(digest: Uint8Array): {
  md: Uint8Array;
  treeIdx: bigint;
  leafIdx: number;
} {
  const mdBytes = Math.ceil((FIPS205.k * FIPS205.a) / 8); // 21
  const treeBits = FIPS205.h - FIPS205.h_prime; // 54
  const treeBytes = Math.ceil(treeBits / 8); // 7
  const leafBytes = Math.ceil(FIPS205.h_prime / 8); // 2

  const md = digest.slice(0, mdBytes);
  let treeIdx = 0n;
  for (let i = 0; i < treeBytes; i++) {
    treeIdx = (treeIdx << 8n) | BigInt(digest[mdBytes + i]!);
  }
  // Mask to `treeBits` bits
  treeIdx = treeIdx & ((1n << BigInt(treeBits)) - 1n);

  let leafIdx = 0;
  for (let i = 0; i < leafBytes; i++) {
    leafIdx = (leafIdx << 8) | digest[mdBytes + treeBytes + i]!;
  }
  // Mask to h_prime bits
  leafIdx = leafIdx & ((1 << FIPS205.h_prime) - 1);

  return { md, treeIdx, leafIdx };
}

// ── top-level verify (FIPS-205 §10.3) ─────────────────────────────────────
//
// Per FIPS-205 §10.2.2 the public verify interface wraps the message before
// feeding it to H_msg:
//
//   M' = [0x00, ctx.length] || ctx || M     // 0x00 = "non-prehash" domain byte
//
// For the default "no context" path that's [0x00, 0x00] || M.
export function verify(
  pk: Uint8Array,
  msg: Uint8Array,
  sig: Uint8Array,
  ctx: Uint8Array = new Uint8Array(0),
): boolean {
  if (pk.length !== FIPS205.pkBytes) return false;
  if (sig.length !== FIPS205.sigBytes) return false;
  if (ctx.length > 255) return false;
  const pkSeed = pk.slice(0, FIPS205.n);
  const pkRoot = pk.slice(FIPS205.n, 2 * FIPS205.n);

  const wrappedM = concat(new Uint8Array([0x00, ctx.length]), ctx, msg);

  const R = sig.slice(0, FIPS205.n);
  const sigFors = sig.slice(FIPS205.n, FIPS205.n + FIPS205.k * (1 + FIPS205.a) * FIPS205.n);
  const sigHt = sig.slice(FIPS205.n + FIPS205.k * (1 + FIPS205.a) * FIPS205.n);

  const digest = Hmsg(R, pkSeed, pkRoot, wrappedM);
  const { md, treeIdx, leafIdx } = splitDigest(digest);

  const adrs = newAdrs();
  adrs.layer = 0;
  adrs.tree = treeIdx;
  adrs.type = FORS_TREE;
  adrs.keypair = leafIdx;

  const forsRoot = forsPkFromSig(sigFors, md, pkSeed, adrs);

  const htRoot = htRootFromSig(sigHt, forsRoot, treeIdx, leafIdx, pkSeed);

  if (htRoot.length !== pkRoot.length) return false;
  for (let i = 0; i < htRoot.length; i++) if (htRoot[i] !== pkRoot[i]) return false;
  return true;
}
