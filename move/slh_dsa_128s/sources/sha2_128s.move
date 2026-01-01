/// FIPS-205 SLH-DSA-SHA2-128s — byte-exact verify, on-chain.
///
/// Cross-checked against @noble/post-quantum's audited `slh_dsa_sha2_128s` via
/// `packages/pqc/src/slh-dsa-128s-ref.ts`: this module produces the identical
/// SHA-256 call sequence (Hmsg + every tweakable-hash call across WOTS+, FORS,
/// XMSS, Hypertree) and arrives at the same 16-byte XMSS root for any sig that
/// noble accepts.
///
/// Parameters (FIPS-205 §10.1, row "128s"):
///   n        = 16          (hash bytes, SHA-256 truncated to 16)
///   lg_w     = 4, w = 16   (Winternitz)
///   len_1    = 32, len_2 = 3, len = 35
///   h        = 63          (total Merkle height)
///   d        = 7           (XMSS layers; h' = h/d = 9)
///   h_prime  = 9
///   a        = 12          (FORS leaf depth)
///   k        = 14          (FORS trees)
///   m_bytes  = 30          (Hmsg output)
///   pk_bytes = 32, sig_bytes = 7856
///
/// Tweakable hashes (FIPS-205 §11.2.1 "simple" variant):
///   F = H = T_l = sha256(pk_seed || toByte(0, 48) || adrs_c || msg)[0..n]
///   H_msg = MGF1-SHA-256(R || pk_seed || sha256(R || pk_full || M), m_bytes)
module slh_dsa_128s::sha2_128s;

use std::hash;

// ── parameters ─────────────────────────────────────────────────────────────
const N: u64 = 16;
const LG_W: u64 = 4;
const W: u64 = 16;
const LEN_1: u64 = 32;
const LEN_2: u64 = 3;
const LEN: u64 = 35; // LEN_1 + LEN_2
const H_PRIME: u64 = 9;
const D: u64 = 7;
const A: u64 = 12;
const K: u64 = 14;
const M_BYTES: u64 = 30;
const PK_BYTES: u64 = 32;
const SIG_BYTES: u64 = 7856;
const ADRS_BYTES: u64 = 22;

// ADRS type bytes (FIPS-205 §4.2.2)
const ADRS_WOTS_HASH: u8 = 0;
const ADRS_WOTS_PK:   u8 = 1;
const ADRS_TREE:      u8 = 2;
const ADRS_FORS_TREE: u8 = 3;
const ADRS_FORS_ROOTS: u8 = 4;

// ── errors ─────────────────────────────────────────────────────────────────
const EBadPkLength: u64 = 1;

// ── byte helpers ───────────────────────────────────────────────────────────
fun concat(a: &vector<u8>, b: &vector<u8>): vector<u8> {
    let mut out = *a;
    let mut i = 0;
    let n = b.length();
    while (i < n) { out.push_back(*b.borrow(i)); i = i + 1 };
    out
}

fun concat3(a: &vector<u8>, b: &vector<u8>, c: &vector<u8>): vector<u8> {
    let mut out = concat(a, b);
    let mut i = 0;
    let n = c.length();
    while (i < n) { out.push_back(*c.borrow(i)); i = i + 1 };
    out
}

fun concat4(a: &vector<u8>, b: &vector<u8>, c: &vector<u8>, d: &vector<u8>): vector<u8> {
    let mut out = concat3(a, b, c);
    let mut i = 0;
    let n = d.length();
    while (i < n) { out.push_back(*d.borrow(i)); i = i + 1 };
    out
}

fun slice(src: &vector<u8>, start: u64, len: u64): vector<u8> {
    let mut out = vector[];
    let mut i = 0;
    while (i < len) { out.push_back(*src.borrow(start + i)); i = i + 1 };
    out
}

/// Append bytes [start..start+len) of `src` to `dst` without materialising an
/// intermediate `slice(src, start, len)` vector.
fun append_slice(dst: &mut vector<u8>, src: &vector<u8>, start: u64, len: u64) {
    let mut i = 0;
    while (i < len) { dst.push_back(*src.borrow(start + i)); i = i + 1 };
}

fun bytes_eq(a: &vector<u8>, b: &vector<u8>): bool {
    let n = a.length();
    if (n != b.length()) return false;
    let mut i = 0;
    while (i < n) {
        if (*a.borrow(i) != *b.borrow(i)) return false;
        i = i + 1;
    };
    true
}

// ── BE writers ──────────────────────────────────────────────────────────────
fun write_u32_be(buf: &mut vector<u8>, off: u64, v: u32) {
    *buf.borrow_mut(off + 0) = ((v >> 24) & 0xff) as u8;
    *buf.borrow_mut(off + 1) = ((v >> 16) & 0xff) as u8;
    *buf.borrow_mut(off + 2) = ((v >> 8) & 0xff) as u8;
    *buf.borrow_mut(off + 3) = (v & 0xff) as u8;
}

fun write_u64_be(buf: &mut vector<u8>, off: u64, v: u64) {
    let mut n = v;
    let mut i: u64 = 8;
    while (i > 0) {
        i = i - 1;
        *buf.borrow_mut(off + i) = (n & 0xff) as u8;
        n = n >> 8;
    }
}

// ── compressed ADRS (FIPS-205 §11.2.1) ─────────────────────────────────────
/// Returns a fresh 22-byte ADRS_c with all fields zero.
fun adrs_new(): vector<u8> {
    let mut a = vector[];
    let mut i: u64 = 0;
    while (i < ADRS_BYTES) { a.push_back(0u8); i = i + 1 };
    a
}

fun adrs_set_layer(a: &mut vector<u8>, layer: u8) {
    *a.borrow_mut(0) = layer;
}
fun adrs_set_tree(a: &mut vector<u8>, tree: u64) {
    write_u64_be(a, 1, tree);
}
fun adrs_set_type(a: &mut vector<u8>, t: u8) {
    *a.borrow_mut(9) = t;
}
fun adrs_set_keypair(a: &mut vector<u8>, kp: u32) {
    write_u32_be(a, 10, kp);
}
fun adrs_set_tree_height(a: &mut vector<u8>, h: u32) {
    write_u32_be(a, 14, h);
}
fun adrs_set_tree_index(a: &mut vector<u8>, idx: u32) {
    write_u32_be(a, 18, idx);
}

// ── tweakable hash F = H = T_l (FIPS-205 §11.2.1 "simple" for SHA2) ────────
//
// Performance: `thash` is called ~2,099 times per verify, so it dominates gas.
// We pass a precomputed `prefix = pk_seed || toByte(0, 48)` (64 bytes) from the
// top-level verify and use `vector::append` for in-place bulk copies — much
// cheaper than per-byte push_back loops.
//
// Truncating SHA-256's 32-byte output to N=16 is done by popping the trailing
// 16 bytes (constant-time pops, no allocation), which is cheaper than building
// a fresh 16-byte vector.

/// Build pk_seed || pad48 = 64 bytes. Computed once at the top of `verify`.
fun pk_seed_padded(pk_seed: &vector<u8>): vector<u8> {
    let mut out = *pk_seed;
    let mut i: u64 = 0;
    while (i < 48) { out.push_back(0u8); i = i + 1 };
    out
}

/// thash(prefix, adrs_c, m) = SHA-256(prefix || adrs_c || m)[0..N]
/// where prefix = pk_seed || toByte(0, 48).
fun thash(prefix: &vector<u8>, adrs: &vector<u8>, m: &vector<u8>): vector<u8> {
    let mut buf = *prefix;
    buf.append(*adrs);
    buf.append(*m);
    let mut h = hash::sha2_256(buf);
    // Truncate to N=16 via 16 pop_backs.
    let mut i: u64 = 0;
    while (i < 16) { h.pop_back(); i = i + 1 };
    h
}

// ── MGF1-SHA-256 (PKCS#1 §B.2.1) ───────────────────────────────────────────
fun mgf1_sha256(seed: &vector<u8>, out_len: u64): vector<u8> {
    let mut out = vector[];
    let mut counter: u32 = 0;
    while (out.length() < out_len) {
        let mut ctr = vector[0u8, 0u8, 0u8, 0u8];
        write_u32_be(&mut ctr, 0, counter);
        let block = hash::sha2_256(concat(seed, &ctr));
        let mut j: u64 = 0;
        while (j < 32 && out.length() < out_len) {
            out.push_back(*block.borrow(j));
            j = j + 1;
        };
        counter = counter + 1;
    };
    out
}

/// H_msg(R, PK.seed, PK.root, M) → 30 bytes (FIPS-205 §11.2.2 for n=16).
///   inner = SHA-256(R || PK.seed || PK.root || M)
///   seed  = R || PK.seed || inner
///   out   = MGF1-SHA-256(seed, 30)
fun hmsg(r: &vector<u8>, pk_seed: &vector<u8>, pk_root: &vector<u8>, m: &vector<u8>): vector<u8> {
    let inner = hash::sha2_256(concat4(r, pk_seed, pk_root, m));
    let seed = concat3(r, pk_seed, &inner);
    mgf1_sha256(&seed, M_BYTES)
}

// ── base-w / WOTS+ checksum (FIPS-205 §5) ──────────────────────────────────
/// Decode `msg` into `outlen` base-(2^LG_W) = 16 digits, BE within each byte.
fun base_w(msg: &vector<u8>, outlen: u64): vector<u32> {
    let mut out = vector[];
    let mut in_idx: u64 = 0;
    let mut bits: u64 = 0;
    let mut total: u32 = 0;
    let mut i: u64 = 0;
    while (i < outlen) {
        if (bits == 0) {
            total = (*msg.borrow(in_idx) as u32);
            in_idx = in_idx + 1;
            bits = 8;
        };
        bits = bits - LG_W;
        out.push_back((total >> (bits as u8)) & ((W as u32) - 1));
        i = i + 1;
    };
    out
}

fun wots_checksum(digits: &vector<u32>): vector<u32> {
    let mut csum: u64 = 0;
    let mut i: u64 = 0;
    while (i < LEN_1) {
        csum = csum + ((W as u64) - 1 - (*digits.borrow(i) as u64));
        i = i + 1;
    };
    // align: csum << ((8 - ((LEN_2 * LG_W) % 8)) % 8); for LEN_2=3, LG_W=4 → 4
    let shift: u8 = (((8 - ((LEN_2 * LG_W) % 8)) % 8) as u8);
    csum = csum << shift;
    let len_bytes: u64 = (LEN_2 * LG_W + 7) / 8; // ceil(12/8)=2
    let mut csum_bytes = vector[];
    let mut k: u64 = 0;
    while (k < len_bytes) { csum_bytes.push_back(0u8); k = k + 1 };
    let mut j: u64 = len_bytes;
    while (j > 0) {
        j = j - 1;
        *csum_bytes.borrow_mut(j) = (csum & 0xff) as u8;
        csum = csum >> 8;
    };
    base_w(&csum_bytes, LEN_2)
}

fun msg_to_chain_digits(msg_n: &vector<u8>): vector<u32> {
    let mut digits = base_w(msg_n, LEN_1);
    let csum_digits = wots_checksum(&digits);
    let mut i: u64 = 0;
    while (i < LEN_2) {
        digits.push_back(*csum_digits.borrow(i));
        i = i + 1;
    };
    digits
}

// ── WOTS+ chain step (FIPS-205 §5.1) ───────────────────────────────────────
/// `chain` is the hottest inner loop in WOTS+. We inline `thash` here so the
/// 16-byte chain state is *moved* into the SHA-256 input buffer instead of
/// deref-cloned each iteration. The chain step body becomes:
///     buf := prefix.clone() ++ adrs ++ tmp ; tmp := truncate16(sha256(buf))
///
/// `tmp` is seeded by copying N bytes out of `src` starting at `src_off`,
/// avoiding the caller's need to materialise a separate 16-byte slice.
fun chain(
    src: &vector<u8>,
    src_off: u64,
    i_start: u32,
    steps: u32,
    prefix: &vector<u8>,
    adrs: &mut vector<u8>,
): vector<u8> {
    let mut tmp = vector[];
    let mut s: u64 = 0;
    while (s < N) { tmp.push_back(*src.borrow(src_off + s)); s = s + 1 };
    let mut j: u32 = i_start;
    let end = i_start + steps;
    while (j < end) {
        adrs_set_tree_index(adrs, j); // hash_address (byte 21) increments along the chain
        let mut buf = *prefix;
        buf.append(*adrs);
        buf.append(tmp);              // move (not clone) the previous chain state
        let mut h = hash::sha2_256(buf);
        let mut k: u64 = 0;
        while (k < 16) { h.pop_back(); k = k + 1 };
        tmp = h;
        j = j + 1;
    };
    tmp
}

// ── WOTS+ pk from sig (FIPS-205 §5.4) ──────────────────────────────────────
/// Input `adrs` has layer/tree/keypair set; type is set to WOTS_HASH here.
fun wots_pk_from_sig(sig: &vector<u8>, msg_n: &vector<u8>, prefix: &vector<u8>, adrs: &vector<u8>): vector<u8> {
    let digits = msg_to_chain_digits(msg_n);
    let mut tmp = vector[]; // LEN * N bytes
    let mut a = *adrs;
    adrs_set_type(&mut a, ADRS_WOTS_HASH);
    let mut i: u64 = 0;
    while (i < LEN) {
        adrs_set_tree_height(&mut a, (i as u32)); // chain_address (byte 17)
        let d = (*digits.borrow(i)) as u32;
        let piece = chain(sig, i * N, d, (W as u32) - 1 - d, prefix, &mut a);
        tmp.append(piece);
        i = i + 1;
    };
    // Compress LEN chain-tops via T_len with WOTS_PK ADRS.
    let mut t_adrs = *adrs;
    adrs_set_type(&mut t_adrs, ADRS_WOTS_PK);
    adrs_set_tree_height(&mut t_adrs, 0);
    adrs_set_tree_index(&mut t_adrs, 0);
    thash(prefix, &t_adrs, &tmp)
}

// ── XMSS pk from sig (FIPS-205 §6.4) ───────────────────────────────────────
fun xmss_pk_from_sig(
    idx: u32,
    sig: &vector<u8>,
    msg_n: &vector<u8>,
    prefix: &vector<u8>,
    adrs: &mut vector<u8>,
): vector<u8> {
    let wots_sig = slice(sig, 0, LEN * N);
    let auth = slice(sig, LEN * N, H_PRIME * N);

    adrs_set_type(adrs, ADRS_WOTS_HASH);
    adrs_set_keypair(adrs, idx);
    let mut node = wots_pk_from_sig(&wots_sig, msg_n, prefix, adrs);

    // TREE address: keypair word is padding (zero) per FIPS-205 §4.2.2.
    adrs_set_type(adrs, ADRS_TREE);
    adrs_set_keypair(adrs, 0);
    let mut cur_idx = idx;
    let mut i: u64 = 0;
    while (i < H_PRIME) {
        adrs_set_tree_height(adrs, (i as u32) + 1);
        adrs_set_tree_index(adrs, cur_idx >> 1);
        let bit = ((idx >> (i as u8)) & 1);
        // Inline thash: move `node` into buf, pull sibling directly from auth.
        let mut buf = *prefix;
        buf.append(*adrs);
        if (bit == 0) {
            buf.append(node);
            append_slice(&mut buf, &auth, i * N, N);
        } else {
            append_slice(&mut buf, &auth, i * N, N);
            buf.append(node);
        };
        let mut h = hash::sha2_256(buf);
        let mut k: u64 = 0;
        while (k < 16) { h.pop_back(); k = k + 1 };
        node = h;
        cur_idx = cur_idx >> 1;
        i = i + 1;
    };
    node
}

// ── Hypertree root from sig (FIPS-205 §7.2) ────────────────────────────────
fun ht_root_from_sig(
    sig_ht: &vector<u8>,
    msg_n: &vector<u8>,
    tree_idx0: u64,
    leaf_idx0: u32,
    prefix: &vector<u8>,
): vector<u8> {
    let xmss_sig_bytes = (LEN + H_PRIME) * N;
    let mut node = *msg_n;
    let mut cur_tree = tree_idx0;
    let mut cur_leaf = leaf_idx0;
    let mut j: u64 = 0;
    while (j < D) {
        let mut a = adrs_new();
        adrs_set_layer(&mut a, j as u8);
        adrs_set_tree(&mut a, cur_tree);
        let slice_j = slice(sig_ht, j * xmss_sig_bytes, xmss_sig_bytes);
        node = xmss_pk_from_sig(cur_leaf, &slice_j, &node, prefix, &mut a);
        // promote
        let leaf_mask: u64 = (1u64 << (H_PRIME as u8)) - 1;
        cur_leaf = (cur_tree & leaf_mask) as u32;
        cur_tree = cur_tree >> (H_PRIME as u8);
        j = j + 1;
    };
    node
}

// ── FORS pk from sig (FIPS-205 §8.4) ───────────────────────────────────────
/// Extract k indices, each `a` bits wide, BE within md.
fun extract_fors_indices(md: &vector<u8>): vector<u32> {
    let mut out = vector[];
    let mut bit_off: u64 = 0;
    let mut i: u64 = 0;
    while (i < K) {
        let mut v: u32 = 0;
        let mut b: u64 = 0;
        while (b < A) {
            let bit_idx = bit_off + b;
            let byte = *md.borrow(bit_idx >> 3);
            let bit = ((byte >> (7 - ((bit_idx & 7) as u8))) & 1) as u32;
            v = (v << 1) | bit;
            b = b + 1;
        };
        out.push_back(v);
        bit_off = bit_off + A;
        i = i + 1;
    };
    out
}

/// Input adrs has layer=0, tree=tree_idx, type=FORS_TREE, keypair=leaf_idx.
fun fors_pk_from_sig(sig_fors: &vector<u8>, md: &vector<u8>, prefix: &vector<u8>, adrs: &vector<u8>): vector<u8> {
    let chunk_bytes = (1 + A) * N; // 13 * 16 = 208 per tree
    let indices = extract_fors_indices(md);
    let mut roots_buf = vector[]; // K * N bytes

    let mut i: u64 = 0;
    while (i < K) {
        let off = i * chunk_bytes;
        let sk_leaf = slice(sig_fors, off, N);
        let auth_path = slice(sig_fors, off + N, A * N);
        let idx = *indices.borrow(i);

        // Leaf = F(prefix, adrs, sk) with type=FORS_TREE, height=0, index = i*2^a + idx.
        let mut leaf_adrs = *adrs;
        adrs_set_type(&mut leaf_adrs, ADRS_FORS_TREE);
        adrs_set_tree_height(&mut leaf_adrs, 0);
        let leaf_tree_index = ((i as u32) << (A as u8)) + idx;
        adrs_set_tree_index(&mut leaf_adrs, leaf_tree_index);
        let mut node = thash(prefix, &leaf_adrs, &sk_leaf);

        // Walk this FORS tree. Inline thash so we move `node` into the buf
        // instead of cloning it, and pull the sibling bytes directly out of
        // auth_path without materialising an intermediate slice.
        let mut cur = idx;
        let mut j: u64 = 0;
        while (j < A) {
            adrs_set_tree_height(&mut leaf_adrs, (j as u32) + 1);
            let nodes_at_height: u32 = 1u32 << (((A - j - 1) as u8));
            let parent_idx = (i as u32) * nodes_at_height + (cur >> 1);
            adrs_set_tree_index(&mut leaf_adrs, parent_idx);
            let bit = cur & 1;
            let mut buf = *prefix;
            buf.append(leaf_adrs);            // auto-clones (vector<u8> has `copy`)
            if (bit == 0) {
                buf.append(node);
                append_slice(&mut buf, &auth_path, j * N, N);
            } else {
                append_slice(&mut buf, &auth_path, j * N, N);
                buf.append(node);
            };
            let mut h = hash::sha2_256(buf);
            let mut p: u64 = 0;
            while (p < 16) { h.pop_back(); p = p + 1 };
            node = h;
            cur = cur >> 1;
            j = j + 1;
        };

        // Accumulate this FORS tree's root.
        roots_buf.append(node);
        i = i + 1;
    };

    // Compress K roots via T_K with FORS_ROOTS ADRS (keypair inherited).
    let mut roots_adrs = *adrs;
    adrs_set_type(&mut roots_adrs, ADRS_FORS_ROOTS);
    adrs_set_tree_height(&mut roots_adrs, 0);
    adrs_set_tree_index(&mut roots_adrs, 0);
    thash(prefix, &roots_adrs, &roots_buf)
}

// ── digest splitting (FIPS-205 §10.2) ──────────────────────────────────────
fun split_digest(digest: &vector<u8>): (vector<u8>, u64, u32) {
    let md_bytes: u64 = (K * A + 7) / 8;             // 21
    let tree_bits: u64 = (H_PRIME * D) - H_PRIME;   // 54 = 63 - 9
    let tree_bytes: u64 = (tree_bits + 7) / 8;       // 7
    let leaf_bytes: u64 = (H_PRIME + 7) / 8;         // 2

    let md = slice(digest, 0, md_bytes);

    let mut tree_idx: u64 = 0;
    let mut i: u64 = 0;
    while (i < tree_bytes) {
        tree_idx = (tree_idx << 8) | (*digest.borrow(md_bytes + i) as u64);
        i = i + 1;
    };
    let tree_mask: u64 = (1u64 << (tree_bits as u8)) - 1;
    tree_idx = tree_idx & tree_mask;

    let mut leaf_idx: u32 = 0;
    let mut p: u64 = 0;
    while (p < leaf_bytes) {
        leaf_idx = (leaf_idx << 8) | (*digest.borrow(md_bytes + tree_bytes + p) as u32);
        p = p + 1;
    };
    let leaf_mask: u32 = (1u32 << (H_PRIME as u8)) - 1;
    leaf_idx = leaf_idx & leaf_mask;

    (md, tree_idx, leaf_idx)
}

// ── top-level verify (FIPS-205 §10.3) ──────────────────────────────────────
/// Verify with empty context (FIPS-205 §10.2.2 wraps: M' = [0x00, 0x00] || M).
public fun verify(pk: &vector<u8>, msg: &vector<u8>, sig: &vector<u8>): bool {
    verify_with_context(pk, msg, sig, &vector[])
}

/// Verify with explicit context (length must be ≤ 255).
public fun verify_with_context(
    pk: &vector<u8>,
    msg: &vector<u8>,
    sig: &vector<u8>,
    ctx: &vector<u8>,
): bool {
    assert!(pk.length() == PK_BYTES, EBadPkLength);
    if (sig.length() != SIG_BYTES) return false;
    if (ctx.length() > 255) return false;

    let pk_seed = slice(pk, 0, N);
    let pk_root = slice(pk, N, N);

    // FIPS-205 §10.2.2: M' = [0x00, ctx.length] || ctx || M
    let mut wrapped = vector[0u8, (ctx.length() as u8)];
    wrapped.append(*ctx);
    wrapped.append(*msg);

    let r = slice(sig, 0, N);
    let fors_bytes_len = K * (1 + A) * N;             // 2912
    let sig_fors = slice(sig, N, fors_bytes_len);
    let sig_ht = slice(sig, N + fors_bytes_len, SIG_BYTES - N - fors_bytes_len);

    let digest = hmsg(&r, &pk_seed, &pk_root, &wrapped);
    let (md, tree_idx, leaf_idx) = split_digest(&digest);

    // Precompute pk_seed || pad48 (64 bytes) once — every thash call uses it.
    let prefix = pk_seed_padded(&pk_seed);

    let mut adrs = adrs_new();
    adrs_set_layer(&mut adrs, 0);
    adrs_set_tree(&mut adrs, tree_idx);
    adrs_set_type(&mut adrs, ADRS_FORS_TREE);
    adrs_set_keypair(&mut adrs, leaf_idx);

    let fors_root = fors_pk_from_sig(&sig_fors, &md, &prefix, &adrs);
    let ht_root = ht_root_from_sig(&sig_ht, &fors_root, tree_idx, leaf_idx, &prefix);

    bytes_eq(&ht_root, &pk_root)
}

// ── public parameter accessors ─────────────────────────────────────────────
public fun n(): u64 { N }
public fun pk_byte_len(): u64 { PK_BYTES }
public fun signature_byte_len(): u64 { SIG_BYTES }

// ── test-only re-exports ────────────────────────────────────────────────────
#[test_only] public fun test_split_digest(digest: &vector<u8>): (vector<u8>, u64, u32) { split_digest(digest) }
#[test_only] public fun test_hmsg(r: &vector<u8>, ps: &vector<u8>, pr: &vector<u8>, m: &vector<u8>): vector<u8> { hmsg(r, ps, pr, m) }
#[test_only] public fun test_thash(ps: &vector<u8>, a: &vector<u8>, m: &vector<u8>): vector<u8> {
    let prefix = pk_seed_padded(ps);
    thash(&prefix, a, m)
}
