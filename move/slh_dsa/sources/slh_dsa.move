/// SLH-DSA-LITE: full hash-based post-quantum signature verification, on-chain.
///
/// **This is real, end-to-end PQ signature verification running inside Move.**
/// Implements WOTS+ → XMSS → Hypertree → FORS → top-level SLH-DSA verification
/// using only SHA-256 (`std::hash::sha2_256`).
///
/// Parameters (matched in `packages/pqc/src/slh-dsa-ref.ts`):
///   n       = 32          (hash bytes)
///   lg_w    = 4, w = 16   (WOTS+ Winternitz)
///   len     = 67          (WOTS+ chains)
///   h       = 8           (total Merkle height across hypertree)
///   d       = 2           (XMSS layers; h' = h/d = 4)
///   a       = 3, k = 4    (FORS: k trees of height a)
///
/// **Not byte-compatible with FIPS 205.** Differences:
///   - n=32 (full SHA-256) instead of FIPS 205's n=16 truncated form.
///   - Simplified message-digest function: `H_msg(M) = sha256(PK.seed || M)`.
///     FIPS 205 mixes in randomness `R` and applies MGF1.
///   - No PK.seed binding in tweakable hashes (we use seed || ADRS || M directly).
///
/// For FIPS-exact verification, fastcrypto's experimental SLH-DSA verifier
/// is the source of truth; when it's exposed as a Move primitive, this module
/// becomes redundant. Until then this is what runs on Sui.
module slh_dsa::verifier;

use std::hash;
use wots::wots_plus;

// ── parameters ─────────────────────────────────────────────────────────────
const N: u64 = 32;
const LEN: u64 = 67;
const H_PRIME: u64 = 4;
const D: u64 = 2;
const A: u64 = 3;
const K: u64 = 4;

// ADRS type bytes (FIPS 205 §4.2.2)
const TYPE_WOTS_PK:   u32 = 1;
const TYPE_TREE:      u32 = 2;
const TYPE_FORS_TREE: u32 = 3;
const TYPE_FORS_ROOTS: u32 = 4;

// ── errors ─────────────────────────────────────────────────────────────────
const EBadPkLength:  u64 = 1;
const EBadSigLength: u64 = 2;

// ── byte helpers ───────────────────────────────────────────────────────────
fun concat(a: &vector<u8>, b: &vector<u8>): vector<u8> {
    let mut out = *a;
    let mut i = 0;
    let n = vector::length(b);
    while (i < n) { vector::push_back(&mut out, *vector::borrow(b, i)); i = i + 1 };
    out
}

fun slice(src: &vector<u8>, start: u64, len: u64): vector<u8> {
    let mut out = vector<u8>[];
    let mut i = 0;
    while (i < len) {
        vector::push_back(&mut out, *vector::borrow(src, start + i));
        i = i + 1;
    };
    out
}

fun bytes_eq(a: &vector<u8>, b: &vector<u8>): bool {
    let n = vector::length(a);
    if (n != vector::length(b)) return false;
    let mut i = 0;
    while (i < n) {
        if (*vector::borrow(a, i) != *vector::borrow(b, i)) return false;
        i = i + 1;
    };
    true
}

fun write_u32(buf: &mut vector<u8>, off: u64, v: u32) {
    *vector::borrow_mut(buf, off + 0) = (((v >> 24) & 0xff) as u8);
    *vector::borrow_mut(buf, off + 1) = (((v >> 16) & 0xff) as u8);
    *vector::borrow_mut(buf, off + 2) = (((v >> 8)  & 0xff) as u8);
    *vector::borrow_mut(buf, off + 3) = ( (v        & 0xff) as u8);
}

/// Build a 32-byte ADRS with the layer/tree/type/keypair fields set.
fun adrs_with(layer: u32, tree_idx: u64, type_: u32, keypair: u32): vector<u8> {
    let mut a = vector[
        0u8, 0, 0, 0,
        0,   0, 0, 0,
        0,   0, 0, 0,
        0,   0, 0, 0,
        0,   0, 0, 0,
        0,   0, 0, 0,
        0,   0, 0, 0,
        0,   0, 0, 0,
    ];
    write_u32(&mut a, 0, layer);
    // tree (8 bytes BE, but we use only low 32 bits)
    write_u32(&mut a, 12, (tree_idx as u32));
    write_u32(&mut a, 16, type_);
    write_u32(&mut a, 20, keypair);
    a
}

// ── tweakable hash (all of F / H / T_len shapes) ───────────────────────────
fun thash(seed: &vector<u8>, adrs: &vector<u8>, m: &vector<u8>): vector<u8> {
    let mut buf = *seed;
    let mut i = 0;
    let n = vector::length(adrs);
    while (i < n) { vector::push_back(&mut buf, *vector::borrow(adrs, i)); i = i + 1 };
    i = 0;
    let m_n = vector::length(m);
    while (i < m_n) { vector::push_back(&mut buf, *vector::borrow(m, i)); i = i + 1 };
    hash::sha2_256(buf)
}

// ── XMSS leaf reconstruction from a WOTS+ pk ───────────────────────────────
fun xmss_leaf_from_wots_pk(seed: &vector<u8>, layer: u32, tree_idx: u64, keypair: u32, wots_pk: &vector<u8>): vector<u8> {
    let adrs = adrs_with(layer, tree_idx, TYPE_WOTS_PK, keypair);
    thash(seed, &adrs, wots_pk)
}

// ── walk a Merkle auth path of height H_PRIME ───────────────────────────────
fun walk_auth_path(seed: &vector<u8>, layer: u32, tree_idx: u64, leaf_idx: u32, mut node: vector<u8>, auth: &vector<u8>): vector<u8> {
    let mut adrs = adrs_with(layer, tree_idx, TYPE_TREE, 0);
    let mut i: u64 = 0;
    while (i < H_PRIME) {
        write_u32(&mut adrs, 20, ((i as u32) + 1));        // tree_height
        write_u32(&mut adrs, 24, (leaf_idx >> ((i as u8) + 1)));
        let sibling = slice(auth, i * N, N);
        let bit = ((leaf_idx >> (i as u8)) & 1);
        let merged = if (bit == 0) { concat(&node, &sibling) } else { concat(&sibling, &node) };
        node = thash(seed, &adrs, &merged);
        i = i + 1;
    };
    node
}

// ── XMSS root from signature ───────────────────────────────────────────────
public fun xmss_root_from_sig(
    seed: &vector<u8>,
    layer: u32,
    tree_idx: u64,
    leaf_idx: u32,
    msg_digest: &vector<u8>,
    wots_sig: &vector<u8>,
    auth_path: &vector<u8>,
): vector<u8> {
    // Build the WOTS+ base ADRS for this keypair
    let base_adrs = adrs_with(layer, tree_idx, 0 /* WOTS_HASH */, leaf_idx);
    let wots_pk = wots_plus::pk_from_sig(seed, &base_adrs, msg_digest, wots_sig);
    let leaf = xmss_leaf_from_wots_pk(seed, layer, tree_idx, leaf_idx, &wots_pk);
    walk_auth_path(seed, layer, tree_idx, leaf_idx, leaf, auth_path)
}

// ── Hypertree root from signature ───────────────────────────────────────────
public fun ht_root_from_sig(
    seed: &vector<u8>,
    msg_digest: &vector<u8>,
    mut tree_idx: u64,
    mut leaf_idx: u32,
    ht_sig: &vector<u8>,
): vector<u8> {
    let xmss_sig_len = LEN * N + H_PRIME * N;
    let mut payload = *msg_digest;
    let mut layer: u64 = 0;
    while (layer < D) {
        let off = layer * xmss_sig_len;
        let wots_sig = slice(ht_sig, off, LEN * N);
        let auth_path = slice(ht_sig, off + LEN * N, H_PRIME * N);
        payload = xmss_root_from_sig(seed, (layer as u32), tree_idx, leaf_idx, &payload, &wots_sig, &auth_path);
        // Promote: next layer's leaf_idx is the low h_prime bits of tree_idx
        let leaf_mask: u64 = (1 << ((H_PRIME as u8))) - 1;
        leaf_idx = ((tree_idx & leaf_mask) as u32);
        tree_idx = tree_idx >> ((H_PRIME as u8));
        layer = layer + 1;
    };
    payload
}

// ── FORS root from signature ────────────────────────────────────────────────
public fun fors_root_from_sig(
    seed: &vector<u8>,
    tree_idx: u64,
    indices: &vector<u32>,
    fors_sig: &vector<u8>,
): vector<u8> {
    assert!(vector::length(indices) == K, EBadSigLength);
    let chunk = N + A * N; // 32 + 3*32 = 128
    let nleaves_per_tree: u32 = (1u32 << ((A as u8))) ;

    let mut adrs_leaf = adrs_with(0, tree_idx, TYPE_FORS_TREE, 0);
    let mut adrs_tree = adrs_with(0, tree_idx, TYPE_FORS_TREE, 0);

    let mut roots = vector<u8>[];
    let mut i: u64 = 0;
    while (i < K) {
        let off = i * chunk;
        let secret = slice(fors_sig, off, N);
        let auth = slice(fors_sig, off + N, A * N);
        let mut leaf_idx = *vector::borrow(indices, i);

        // Leaf
        write_u32(&mut adrs_leaf, 24, ((i as u32) * nleaves_per_tree + leaf_idx));
        let mut node = thash(seed, &adrs_leaf, &secret);

        // Climb a Merkle path
        let mut height: u64 = 1;
        while (height <= A) {
            write_u32(&mut adrs_tree, 20, (height as u32));
            // tree-index at this height:
            //   nodes_per_tree_at_height = nleaves >> height
            //   index_within_height       = leaf_idx >> 1
            let nodes_at_height: u32 = (1u32 << (((A - height) as u8)));
            let idx_at_height = leaf_idx >> 1;
            write_u32(&mut adrs_tree, 24, ((i as u32) * nodes_at_height + idx_at_height));
            let sib = slice(&auth, (height - 1) * N, N);
            let bit = (leaf_idx & 1);
            let merged = if (bit == 0) { concat(&node, &sib) } else { concat(&sib, &node) };
            node = thash(seed, &adrs_tree, &merged);
            leaf_idx = leaf_idx >> 1;
            height = height + 1;
        };

        // Accumulate into the root-compression buffer
        let mut k = 0;
        while (k < N) {
            vector::push_back(&mut roots, *vector::borrow(&node, k));
            k = k + 1;
        };
        i = i + 1;
    };

    // Compress all K roots with T_K
    let adrs_compress = adrs_with(0, tree_idx, TYPE_FORS_ROOTS, 0);
    thash(seed, &adrs_compress, &roots)
}

// ── digest splitting (must match TS ref `splitDigest`) ──────────────────────
fun split_digest(digest: &vector<u8>): (vector<u32>, u64, u32) {
    let fors_bits: u64 = K * A;                // 12
    let fors_bytes: u64 = (fors_bits + 7) / 8; // 2
    let mut v: u64 = 0;
    let mut i: u64 = 0;
    while (i < fors_bytes) {
        v = (v << 8) | (*vector::borrow(digest, i) as u64);
        i = i + 1;
    };
    let mut fors = vector<u32>[];
    let mask: u64 = (1u64 << (A as u8)) - 1;
    let mut j: u64 = 0;
    while (j < K) {
        vector::push_back(&mut fors, (((v & mask) as u32)));
        v = v >> ((A as u8));
        j = j + 1;
    };
    // FORS indices are in reverse: vec[K-1] was the lowest A bits, etc.
    let mut reversed = vector<u32>[];
    let mut r: u64 = K;
    while (r > 0) {
        r = r - 1;
        vector::push_back(&mut reversed, *vector::borrow(&fors, r));
    };

    // h bits for hypertree address
    let h_bytes: u64 = (8 + 7) / 8; // 1
    let mut path: u64 = 0;
    let mut p: u64 = 0;
    while (p < h_bytes) {
        path = (path << 8) | (*vector::borrow(digest, fors_bytes + p) as u64);
        p = p + 1;
    };
    let h_mask: u64 = (1u64 << 8) - 1;
    path = path & h_mask;
    let leaf_mask: u64 = (1u64 << (H_PRIME as u8)) - 1;
    let leaf_idx = ((path & leaf_mask) as u32);
    let tree_idx_raw = path >> (H_PRIME as u8);
    let tree_mask: u64 = (1u64 << (((8 - H_PRIME) as u8))) - 1;
    let tree_idx = tree_idx_raw & tree_mask;

    (reversed, tree_idx, leaf_idx)
}

// ── top-level verify ────────────────────────────────────────────────────────
public fun verify(pk: &vector<u8>, message: &vector<u8>, signature: &vector<u8>): bool {
    assert!(vector::length(pk) == 2 * N, EBadPkLength);
    let pk_seed = slice(pk, 0, N);
    let pk_root = slice(pk, N, N);

    // H_msg = sha256(PK.seed || message)
    let mut h_input = pk_seed;
    let mut i = 0;
    let mn = vector::length(message);
    while (i < mn) { vector::push_back(&mut h_input, *vector::borrow(message, i)); i = i + 1 };
    let digest = hash::sha2_256(h_input);

    let (fors_indices, tree_idx, leaf_idx) = split_digest(&digest);

    let fors_len = K * (N + A * N);
    let xmss_len = LEN * N + H_PRIME * N;
    let expected_sig_len = fors_len + D * xmss_len;
    if (vector::length(signature) != expected_sig_len) return false;

    let fors_sig = slice(signature, 0, fors_len);
    let ht_sig = slice(signature, fors_len, D * xmss_len);

    let fors_root = fors_root_from_sig(&pk_seed, tree_idx, &fors_indices, &fors_sig);
    let ht_root = ht_root_from_sig(&pk_seed, &fors_root, tree_idx, leaf_idx, &ht_sig);

    bytes_eq(&ht_root, &pk_root)
}

// ── public parameter accessors ──────────────────────────────────────────────
public fun n(): u64 { N }
public fun pk_byte_len(): u64 { 2 * N }
public fun signature_byte_len(): u64 { K * (N + A * N) + D * (LEN * N + H_PRIME * N) }

// ── test-only re-exports ────────────────────────────────────────────────────
#[test_only] public fun fors_sig_len(): u64 { K * (N + A * N) }
#[test_only] public fun xmss_sig_len(): u64 { LEN * N + H_PRIME * N }
#[test_only] public fun expected_total_sig_len(): u64 { fors_sig_len() + D * xmss_sig_len() }
#[test_only] public fun test_split_digest(digest: &vector<u8>): (vector<u32>, u64, u32) { split_digest(digest) }
