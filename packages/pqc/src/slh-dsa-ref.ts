/**
 * Move-mirroring SLH-DSA-LITE reference implementation.
 *
 * This is NOT byte-compatible with FIPS 205 SLH-DSA — it uses our n=32 WOTS+
 * (full SHA-256) instead of FIPS 205's n=16 truncated form, and it omits the
 * randomized message-digest hash. The point is to demonstrate the full
 * hash-based signature construction (WOTS+ → XMSS → Hypertree → FORS →
 * top-level SLH-DSA) and provide test vectors for the Move-native verifier in
 * `move/slh_dsa`.
 *
 * Parameters (chosen small for fast Move test execution; all configurable):
 *
 *   n      = 32                  (hash bytes)
 *   lg_w   = 4, w = 16           (WOTS+ Winternitz parameter)
 *   len    = 67                  (WOTS+ chains; from msgToChains)
 *   h      = 8                   (total Merkle tree height across hypertree)
 *   d      = 2                   (XMSS layers in the hypertree; h' = h/d = 4)
 *   a      = 3, k = 4            (FORS: k trees of height a; 4 trees of 8 leaves)
 *
 * Total signature bytes:
 *   FORS:     k·(1+a)·n         = 4·4·32          = 512
 *   HT:       d·(len + h')·n    = 2·(67+4)·32     = 4544
 *   ----------------------------------------
 *   total                                          = 5056 bytes
 */
import { sha256 } from '@noble/hashes/sha256';
import { buildAdrs, msgToChains, WOTS } from './wots-ref.js';

export const SLH = {
  n: 32,
  h: 8,
  d: 2,
  h_prime: 4,
  a: 3,
  k: 4,
  len: WOTS.len, // 67
  /** Bytes of (digest, tree_idx, leaf_idx) extracted from H_msg output. */
  msgDigestBytes: 32,
} as const;

// ADRS type-byte constants (FIPS 205 §4.2.2)
const TYPE_WOTS_HASH = 0;
const TYPE_WOTS_PK = 1;
const TYPE_TREE = 2;
const TYPE_FORS_TREE = 3;
const TYPE_FORS_ROOTS = 4;

function writeU32BE(buf: Uint8Array, off: number, v: number): void {
  buf[off + 0] = (v >>> 24) & 0xff;
  buf[off + 1] = (v >>> 16) & 0xff;
  buf[off + 2] = (v >>> 8) & 0xff;
  buf[off + 3] = v & 0xff;
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

// ── tweakable hashes (all are sha256(seed || ADRS || M) at varying M lengths) ─
function F(seed: Uint8Array, adrs: Uint8Array, m: Uint8Array): Uint8Array {
  return sha256(concat(seed, adrs, m));
}
function H(seed: Uint8Array, adrs: Uint8Array, m: Uint8Array): Uint8Array {
  return sha256(concat(seed, adrs, m));
}
function T_len(seed: Uint8Array, adrs: Uint8Array, m: Uint8Array): Uint8Array {
  return sha256(concat(seed, adrs, m));
}

// ── WOTS+ chain helpers (n=32) ─────────────────────────────────────────────
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

function wotsSk(skSeed: Uint8Array, keyPair: number, chain: number): Uint8Array {
  const tag = new TextEncoder().encode('wots-sk');
  const counter = new Uint8Array(8);
  writeU32BE(counter, 0, keyPair);
  writeU32BE(counter, 4, chain);
  return sha256(concat(skSeed, tag, counter));
}

function wotsPk(seed: Uint8Array, skSeed: Uint8Array, keyPair: number, baseAdrs: Uint8Array): Uint8Array {
  const out = new Uint8Array(SLH.len * SLH.n);
  for (let i = 0; i < SLH.len; i++) {
    const sk = wotsSk(skSeed, keyPair, i);
    const top = chainStep(seed, baseAdrs, i, 0, WOTS.w - 1, sk);
    out.set(top, i * SLH.n);
  }
  return out;
}

function wotsSign(seed: Uint8Array, skSeed: Uint8Array, keyPair: number, baseAdrs: Uint8Array, msgDigest: Uint8Array): Uint8Array {
  const chains = msgToChains(msgDigest);
  const out = new Uint8Array(SLH.len * SLH.n);
  for (let i = 0; i < SLH.len; i++) {
    const sk = wotsSk(skSeed, keyPair, i);
    const v = chainStep(seed, baseAdrs, i, 0, chains[i]!, sk);
    out.set(v, i * SLH.n);
  }
  return out;
}

function wotsPkFromSig(seed: Uint8Array, baseAdrs: Uint8Array, msgDigest: Uint8Array, sig: Uint8Array): Uint8Array {
  const chains = msgToChains(msgDigest);
  const out = new Uint8Array(SLH.len * SLH.n);
  for (let i = 0; i < SLH.len; i++) {
    const start = chains[i]!;
    const steps = WOTS.w - 1 - start;
    const sigI = sig.slice(i * SLH.n, (i + 1) * SLH.n);
    const v = chainStep(seed, baseAdrs, i, start, steps, sigI);
    out.set(v, i * SLH.n);
  }
  return out;
}

// ── XMSS ─────────────────────────────────────────────────────────────────────
/**
 * Compute the XMSS root from a leaf index by climbing the auth path. Used
 * during both keygen (to publish the root) and verification (to re-derive it).
 */
function xmssRootFromLeafChunk(
  seed: Uint8Array,
  initialAdrs: Uint8Array,
  leafIdx: number,
  leaf: Uint8Array,
  authPath: Uint8Array, // h_prime * n
): Uint8Array {
  let node = leaf;
  const adrs = initialAdrs.slice();
  writeU32BE(adrs, 16, TYPE_TREE);
  for (let i = 0; i < SLH.h_prime; i++) {
    writeU32BE(adrs, 20, i + 1);        // tree_height (offset 20 in our ADRS layout)
    writeU32BE(adrs, 24, leafIdx >> (i + 1));
    const sibling = authPath.slice(i * SLH.n, (i + 1) * SLH.n);
    const merged = ((leafIdx >> i) & 1) === 0
      ? concat(node, sibling)
      : concat(sibling, node);
    node = H(seed, adrs, merged);
  }
  return node;
}

function xmssLeafFromKeypair(seed: Uint8Array, skSeed: Uint8Array, layer: number, treeIdx: number, keyPair: number): Uint8Array {
  // ADRS for the WOTS+ chains at this keypair index
  const baseAdrs = buildAdrs({ layer, tree: BigInt(treeIdx), keypair: keyPair });
  const wpk = wotsPk(seed, skSeed, keyPair, baseAdrs);
  // Compress the WOTS+ pk down to a single leaf via T_len
  const tAdrs = buildAdrs({ layer, tree: BigInt(treeIdx), type: TYPE_WOTS_PK, keypair: keyPair });
  return T_len(seed, tAdrs, wpk);
}

function xmssRoot(seed: Uint8Array, skSeed: Uint8Array, layer: number, treeIdx: number): Uint8Array {
  // Compute all 2^h_prime leaves, then collapse via Merkle tree.
  const nLeaves = 1 << SLH.h_prime;
  let nodes: Uint8Array[] = [];
  for (let i = 0; i < nLeaves; i++) {
    nodes.push(xmssLeafFromKeypair(seed, skSeed, layer, treeIdx, i));
  }
  const adrs = buildAdrs({ layer, tree: BigInt(treeIdx), type: TYPE_TREE });
  for (let height = 1; height <= SLH.h_prime; height++) {
    writeU32BE(adrs, 20, height);
    const next: Uint8Array[] = [];
    for (let i = 0; i < nodes.length; i += 2) {
      writeU32BE(adrs, 24, i / 2);
      next.push(H(seed, adrs, concat(nodes[i]!, nodes[i + 1]!)));
    }
    nodes = next;
  }
  return nodes[0]!;
}

function xmssAuthPath(seed: Uint8Array, skSeed: Uint8Array, layer: number, treeIdx: number, leafIdx: number): Uint8Array {
  // Compute every leaf, collapse, capture siblings of the path from leafIdx → root.
  const nLeaves = 1 << SLH.h_prime;
  let nodes: Uint8Array[] = [];
  for (let i = 0; i < nLeaves; i++) {
    nodes.push(xmssLeafFromKeypair(seed, skSeed, layer, treeIdx, i));
  }
  const auth = new Uint8Array(SLH.h_prime * SLH.n);
  let idx = leafIdx;
  const adrs = buildAdrs({ layer, tree: BigInt(treeIdx), type: TYPE_TREE });
  for (let height = 1; height <= SLH.h_prime; height++) {
    writeU32BE(adrs, 20, height);
    const siblingIdx = idx ^ 1;
    auth.set(nodes[siblingIdx]!, (height - 1) * SLH.n);
    const next: Uint8Array[] = [];
    for (let i = 0; i < nodes.length; i += 2) {
      writeU32BE(adrs, 24, i / 2);
      next.push(H(seed, adrs, concat(nodes[i]!, nodes[i + 1]!)));
    }
    nodes = next;
    idx >>= 1;
  }
  return auth;
}

interface XmssSig {
  wotsSig: Uint8Array;      // len * n
  authPath: Uint8Array;     // h_prime * n
}

function xmssSign(seed: Uint8Array, skSeed: Uint8Array, layer: number, treeIdx: number, leafIdx: number, msgDigest: Uint8Array): XmssSig {
  const baseAdrs = buildAdrs({ layer, tree: BigInt(treeIdx), keypair: leafIdx });
  const wotsSig = wotsSign(seed, skSeed, leafIdx, baseAdrs, msgDigest);
  const authPath = xmssAuthPath(seed, skSeed, layer, treeIdx, leafIdx);
  return { wotsSig, authPath };
}

function xmssRootFromSig(seed: Uint8Array, layer: number, treeIdx: number, leafIdx: number, msgDigest: Uint8Array, sig: XmssSig): Uint8Array {
  const baseAdrs = buildAdrs({ layer, tree: BigInt(treeIdx), keypair: leafIdx });
  const wpk = wotsPkFromSig(seed, baseAdrs, msgDigest, sig.wotsSig);
  const tAdrs = buildAdrs({ layer, tree: BigInt(treeIdx), type: TYPE_WOTS_PK, keypair: leafIdx });
  const leaf = T_len(seed, tAdrs, wpk);
  const initialAdrs = buildAdrs({ layer, tree: BigInt(treeIdx) });
  return xmssRootFromLeafChunk(seed, initialAdrs, leafIdx, leaf, sig.authPath);
}

// ── Hypertree (stacked XMSS) ────────────────────────────────────────────────
export interface HtSig {
  /** Concatenated XMSS signatures, one per layer. */
  layers: XmssSig[];
}

function htSign(seed: Uint8Array, skSeed: Uint8Array, msgDigest: Uint8Array, treeIdx: bigint, leafIdx: number): HtSig {
  // Layer 0 signs msgDigest; each subsequent layer signs the previous XMSS root.
  const layers: XmssSig[] = [];
  let payload = msgDigest;
  let curTree = treeIdx;
  let curLeaf = leafIdx;
  for (let layer = 0; layer < SLH.d; layer++) {
    const sig = xmssSign(seed, skSeed, layer, Number(curTree), curLeaf, payload);
    layers.push(sig);
    payload = xmssRoot(seed, skSeed, layer, Number(curTree));
    // Promote: next layer's leaf is the low h_prime bits of curTree; tree is the rest.
    curLeaf = Number(curTree & ((1n << BigInt(SLH.h_prime)) - 1n));
    curTree = curTree >> BigInt(SLH.h_prime);
  }
  return { layers };
}

function htRootFromSig(seed: Uint8Array, msgDigest: Uint8Array, treeIdx: bigint, leafIdx: number, sig: HtSig): Uint8Array {
  let payload = msgDigest;
  let curTree = treeIdx;
  let curLeaf = leafIdx;
  for (let layer = 0; layer < SLH.d; layer++) {
    payload = xmssRootFromSig(seed, layer, Number(curTree), curLeaf, payload, sig.layers[layer]!);
    curLeaf = Number(curTree & ((1n << BigInt(SLH.h_prime)) - 1n));
    curTree = curTree >> BigInt(SLH.h_prime);
  }
  return payload;
}

// ── FORS (Forest Of Random Subsets) ─────────────────────────────────────────
export interface ForsSig {
  /** k pairs of (secret leaf, auth path of `a` siblings). Flat: k * (n + a*n). */
  bytes: Uint8Array;
}

function forsSk(skSeed: Uint8Array, treeIdx: bigint, treeNum: number, leafNum: number): Uint8Array {
  const tag = new TextEncoder().encode('fors-sk');
  const counter = new Uint8Array(8 + 4 + 4);
  // pack treeIdx (8 bytes BE), then treeNum (4), then leafNum (4)
  const hi = Number((treeIdx >> 32n) & 0xffffffffn);
  const lo = Number(treeIdx & 0xffffffffn);
  writeU32BE(counter, 0, hi);
  writeU32BE(counter, 4, lo);
  writeU32BE(counter, 8, treeNum);
  writeU32BE(counter, 12, leafNum);
  return sha256(concat(skSeed, tag, counter));
}

function forsLeavesAndAuth(seed: Uint8Array, skSeed: Uint8Array, treeIdx: bigint, treeNum: number, leafNum: number): { secret: Uint8Array; auth: Uint8Array } {
  // Build a full Merkle tree of 2^a leaves for tree #treeNum
  const nLeaves = 1 << SLH.a;
  const adrsF = buildAdrs({ tree: treeIdx, type: TYPE_FORS_TREE });
  let nodes: Uint8Array[] = [];
  for (let i = 0; i < nLeaves; i++) {
    const sk = forsSk(skSeed, treeIdx, treeNum, i);
    writeU32BE(adrsF, 24, treeNum * nLeaves + i);
    nodes.push(F(seed, adrsF, sk));
  }
  const adrsTree = buildAdrs({ tree: treeIdx, type: TYPE_FORS_TREE });
  const auth = new Uint8Array(SLH.a * SLH.n);
  let idx = leafNum;
  for (let height = 1; height <= SLH.a; height++) {
    writeU32BE(adrsTree, 20, height);
    const sib = idx ^ 1;
    auth.set(nodes[sib]!, (height - 1) * SLH.n);
    const next: Uint8Array[] = [];
    for (let i = 0; i < nodes.length; i += 2) {
      writeU32BE(adrsTree, 24, treeNum * (1 << (SLH.a - height)) + i / 2);
      next.push(H(seed, adrsTree, concat(nodes[i]!, nodes[i + 1]!)));
    }
    nodes = next;
    idx >>= 1;
  }
  const secret = forsSk(skSeed, treeIdx, treeNum, leafNum);
  return { secret, auth };
}

function forsSign(seed: Uint8Array, skSeed: Uint8Array, treeIdx: bigint, indices: number[]): ForsSig {
  const chunkSize = SLH.n + SLH.a * SLH.n;
  const out = new Uint8Array(SLH.k * chunkSize);
  for (let i = 0; i < SLH.k; i++) {
    const { secret, auth } = forsLeavesAndAuth(seed, skSeed, treeIdx, i, indices[i]!);
    out.set(secret, i * chunkSize);
    out.set(auth, i * chunkSize + SLH.n);
  }
  return { bytes: out };
}

function forsRootFromSig(seed: Uint8Array, treeIdx: bigint, indices: number[], sig: ForsSig): Uint8Array {
  const chunkSize = SLH.n + SLH.a * SLH.n;
  const roots: Uint8Array[] = [];
  const adrsLeaf = buildAdrs({ tree: treeIdx, type: TYPE_FORS_TREE });
  const adrsTree = buildAdrs({ tree: treeIdx, type: TYPE_FORS_TREE });
  for (let i = 0; i < SLH.k; i++) {
    const off = i * chunkSize;
    const secret = sig.bytes.slice(off, off + SLH.n);
    const auth = sig.bytes.slice(off + SLH.n, off + chunkSize);
    const leafIdx = indices[i]!;
    writeU32BE(adrsLeaf, 24, i * (1 << SLH.a) + leafIdx);
    let node = F(seed, adrsLeaf, secret);
    let idx = leafIdx;
    for (let height = 1; height <= SLH.a; height++) {
      writeU32BE(adrsTree, 20, height);
      writeU32BE(adrsTree, 24, i * (1 << (SLH.a - height)) + (idx >> 1));
      const sib = auth.slice((height - 1) * SLH.n, height * SLH.n);
      const merged = (idx & 1) === 0 ? concat(node, sib) : concat(sib, node);
      node = H(seed, adrsTree, merged);
      idx >>= 1;
    }
    roots.push(node);
  }
  // Compress all k roots
  const adrsRoots = buildAdrs({ tree: treeIdx, type: TYPE_FORS_ROOTS });
  return T_len(seed, adrsRoots, concat(...roots));
}

// ── Top-level SLH-DSA-LITE ──────────────────────────────────────────────────
export interface PublicKey {
  seed: Uint8Array;
  root: Uint8Array;
}

export interface SecretKey {
  seed: Uint8Array;
  skSeed: Uint8Array;
}

export function keygen(seed: Uint8Array, skSeed: Uint8Array): { pk: PublicKey; sk: SecretKey } {
  // Top XMSS tree is layer d-1, tree 0. Its root is the public key.
  const root = xmssRoot(seed, skSeed, SLH.d - 1, 0);
  return { pk: { seed, root }, sk: { seed, skSeed } };
}

/**
 * Derive FORS leaf indices from the message digest, along with the top-tree
 * `treeIdx` and `leafIdx` used to address the hypertree.
 *
 * Layout (8 bytes total for tree + leaf addressing; with h=8, that fits in 1
 * byte for the path bits): the high a*k bits go to FORS indices, the rest
 * splits into treeIdx + leafIdx.
 */
function splitDigest(digest: Uint8Array): { fors: number[]; treeIdx: bigint; leafIdx: number } {
  // FORS: k indices each `a` bits wide. Use first ceil(k*a/8) bytes.
  const forsBits = SLH.k * SLH.a; // 4 * 3 = 12 bits
  const forsBytes = Math.ceil(forsBits / 8);
  let v = 0n;
  for (let i = 0; i < forsBytes; i++) v = (v << 8n) | BigInt(digest[i] ?? 0);
  const fors: number[] = [];
  for (let i = SLH.k - 1; i >= 0; i--) {
    fors[i] = Number(v & BigInt((1 << SLH.a) - 1));
    v = v >> BigInt(SLH.a);
  }
  // Remaining h bits for the hypertree address: h_prime → leafIdx, rest → treeIdx
  const offset = forsBytes;
  let path = 0n;
  for (let i = 0; i < Math.ceil(SLH.h / 8); i++) path = (path << 8n) | BigInt(digest[offset + i] ?? 0);
  const leafMask = (1n << BigInt(SLH.h_prime)) - 1n;
  const treeBits = SLH.h - SLH.h_prime;
  // Take low `leafIdx_bits` for leafIdx, then `treeBits` for treeIdx
  // (We have exactly h bits laid out; we're loading 8 bits here.)
  // Use only the lowest h bits of `path`.
  path = path & ((1n << BigInt(SLH.h)) - 1n);
  const leafIdx = Number(path & leafMask);
  const treeIdx = path >> BigInt(SLH.h_prime);
  // Mask treeIdx to treeBits
  const treeMask = (1n << BigInt(treeBits)) - 1n;
  return { fors, treeIdx: treeIdx & treeMask, leafIdx };
}

export interface Signature {
  fors: ForsSig;
  ht: HtSig;
}

export function sign(sk: SecretKey, message: Uint8Array): Signature {
  const digest = sha256(concat(sk.seed, message));
  const { fors, treeIdx, leafIdx } = splitDigest(digest);
  const forsSig = forsSign(sk.seed, sk.skSeed, treeIdx, fors);
  const forsRoot = forsRootFromSig(sk.seed, treeIdx, fors, forsSig);
  const htSig = htSign(sk.seed, sk.skSeed, forsRoot, treeIdx, leafIdx);
  return { fors: forsSig, ht: htSig };
}

export function verify(pk: PublicKey, message: Uint8Array, signature: Signature): boolean {
  const digest = sha256(concat(pk.seed, message));
  const { fors, treeIdx, leafIdx } = splitDigest(digest);
  const forsRoot = forsRootFromSig(pk.seed, treeIdx, fors, signature.fors);
  const derivedRoot = htRootFromSig(pk.seed, forsRoot, treeIdx, leafIdx, signature.ht);
  if (derivedRoot.length !== pk.root.length) return false;
  for (let i = 0; i < derivedRoot.length; i++) {
    if (derivedRoot[i] !== pk.root[i]) return false;
  }
  return true;
}

/** Serialize a Signature to the wire format consumed by the Move verifier. */
export function packSignature(sig: Signature): Uint8Array {
  const forsBytes = sig.fors.bytes;
  const parts: Uint8Array[] = [forsBytes];
  for (const l of sig.ht.layers) {
    parts.push(l.wotsSig);
    parts.push(l.authPath);
  }
  return concat(...parts);
}

export function unpackSignature(bytes: Uint8Array): Signature {
  const forsLen = SLH.k * (SLH.n + SLH.a * SLH.n);
  const forsSig: ForsSig = { bytes: bytes.slice(0, forsLen) };
  const layers: XmssSig[] = [];
  let off = forsLen;
  const xmssLen = SLH.len * SLH.n + SLH.h_prime * SLH.n;
  for (let i = 0; i < SLH.d; i++) {
    const wotsSig = bytes.slice(off, off + SLH.len * SLH.n);
    const authPath = bytes.slice(off + SLH.len * SLH.n, off + xmssLen);
    layers.push({ wotsSig, authPath });
    off += xmssLen;
  }
  return { fors: forsSig, ht: { layers } };
}
