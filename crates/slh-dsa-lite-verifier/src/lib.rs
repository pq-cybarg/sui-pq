//! SLH-DSA-LITE verifier — workspace-local PQ scheme.
//!
//! Parameters (matched to `move/slh_dsa` + `packages/pqc/src/slh-dsa-ref.ts`):
//!   n=32, lg_w=4 (w=16), len=67, h=8, d=2, h'=4, a=3, k=4
//!
//! Signature format: `fors || (wots_sig || auth_path) × d` = 5,056 bytes.
//! Public key format: `pk_seed || pk_root` = 64 bytes.
//!
//! This is verify-only; key generation happens off-chain (the SDK in
//! `@sui-gen/pqc` is the canonical signer).


use sha2::{Digest, Sha256};

const N: usize = 32;
const LEN: usize = 67;
const H_PRIME: usize = 4;
const D: usize = 2;
const A: usize = 3;
const K: usize = 4;
const W_MINUS_1: u8 = 15;

pub const PK_BYTES: usize = 2 * N;
pub const SIG_BYTES: usize = K * (N + A * N) + D * (LEN * N + H_PRIME * N);

#[derive(Debug, Clone)]
pub struct SlhDsaLitePublicKey(pub [u8; PK_BYTES]);

impl SlhDsaLitePublicKey {
    pub fn as_bytes(&self) -> &[u8] { &self.0 }
}

#[derive(Debug, Clone)]
pub struct SlhDsaLiteSignature(pub Vec<u8>);

pub fn verify(pk: &SlhDsaLitePublicKey, message: &[u8], sig: &SlhDsaLiteSignature) -> bool {
    if sig.0.len() != SIG_BYTES { return false; }
    let pk_seed = &pk.0[..N];
    let pk_root = &pk.0[N..];

    // H_msg = SHA-256(PK.seed || M)
    let mut h = Sha256::new();
    h.update(pk_seed);
    h.update(message);
    let digest = h.finalize();

    let (fors_indices, tree_idx, leaf_idx) = split_digest(&digest);

    let fors_len = K * (N + A * N);
    let xmss_len = LEN * N + H_PRIME * N;
    let fors_sig = &sig.0[..fors_len];
    let ht_sig = &sig.0[fors_len..];

    let fors_root = fors_root_from_sig(pk_seed, tree_idx, &fors_indices, fors_sig);
    let ht_root = ht_root_from_sig(pk_seed, &fors_root, tree_idx, leaf_idx, ht_sig, xmss_len);

    ht_root == pk_root
}

fn split_digest(d: &[u8]) -> ([u32; K], u64, u32) {
    // FORS bits: K * A = 12 → 2 bytes
    let mut v: u32 = ((d[0] as u32) << 8) | (d[1] as u32);
    let mut fors = [0u32; K];
    for i in (0..K).rev() { fors[i] = v & ((1 << A) - 1); v >>= A; }
    // h=8 → 1 byte
    let path = d[2] as u64 & ((1u64 << 8) - 1);
    let leaf_idx = (path & ((1 << H_PRIME) - 1)) as u32;
    let tree_idx = (path >> H_PRIME) & ((1 << (8 - H_PRIME)) - 1);
    (fors, tree_idx, leaf_idx)
}

fn thash(seed: &[u8], adrs: &[u8; 32], m: &[u8]) -> [u8; N] {
    let mut h = Sha256::new();
    h.update(seed); h.update(adrs); h.update(m);
    h.finalize().into()
}

fn write_u32(buf: &mut [u8; 32], off: usize, v: u32) {
    buf[off..off + 4].copy_from_slice(&v.to_be_bytes());
}

fn adrs(layer: u32, tree: u64, type_: u32, keypair: u32) -> [u8; 32] {
    let mut a = [0u8; 32];
    write_u32(&mut a, 0, layer);
    write_u32(&mut a, 12, tree as u32);
    write_u32(&mut a, 16, type_);
    write_u32(&mut a, 20, keypair);
    a
}

const TYPE_WOTS_HASH: u32 = 0;
const TYPE_WOTS_PK: u32 = 1;
const TYPE_TREE: u32 = 2;
const TYPE_FORS_TREE: u32 = 3;
const TYPE_FORS_ROOTS: u32 = 4;

fn msg_to_chains(msg: &[u8]) -> [u32; LEN] {
    let mut out = [0u32; LEN];
    for i in 0..N {
        out[2 * i]     = (msg[i] >> 4)  as u32;
        out[2 * i + 1] = (msg[i] & 0xF) as u32;
    }
    let mut csum: u32 = 0;
    for k in 0..64 { csum += (W_MINUS_1 as u32) - out[k]; }
    csum <<= 4;
    out[64] = (csum >> 8) & 0xF;
    out[65] = (csum >> 4) & 0xF;
    // out[66] is 0; rightmost nibble of csum is always 0 (we shifted)
    out
}

fn wots_pk_from_sig(seed: &[u8], base_adrs: &[u8; 32], msg_digest: &[u8], sig: &[u8]) -> [u8; LEN * N] {
    let chains = msg_to_chains(msg_digest);
    let mut out = [0u8; LEN * N];
    for i in 0..LEN {
        let start = chains[i] as u8;
        let steps = W_MINUS_1 - start;
        let mut local = *base_adrs;
        write_u32(&mut local, 16, TYPE_WOTS_HASH);
        write_u32(&mut local, 24, i as u32);
        let mut node = [0u8; N];
        node.copy_from_slice(&sig[i * N..(i + 1) * N]);
        for j in 0..steps {
            write_u32(&mut local, 28, (start + j) as u32);
            node = thash(seed, &local, &node);
        }
        out[i * N..(i + 1) * N].copy_from_slice(&node);
    }
    out
}

fn xmss_root_from_sig(
    seed: &[u8], layer: u32, tree_idx: u64, leaf_idx: u32,
    msg_digest: &[u8], wots_sig: &[u8], auth: &[u8],
) -> [u8; N] {
    let base = adrs(layer, tree_idx, TYPE_WOTS_HASH, leaf_idx);
    let wpk = wots_pk_from_sig(seed, &base, msg_digest, wots_sig);
    let t_adrs = adrs(layer, tree_idx, TYPE_WOTS_PK, leaf_idx);
    let leaf = thash(seed, &t_adrs, &wpk);

    let mut node = leaf;
    let mut a = adrs(layer, tree_idx, TYPE_TREE, 0);
    for i in 0..H_PRIME {
        write_u32(&mut a, 20, (i + 1) as u32);
        write_u32(&mut a, 24, leaf_idx >> (i + 1));
        let sib = &auth[i * N..(i + 1) * N];
        let mut merged = [0u8; 2 * N];
        if (leaf_idx >> i) & 1 == 0 {
            merged[..N].copy_from_slice(&node);
            merged[N..].copy_from_slice(sib);
        } else {
            merged[..N].copy_from_slice(sib);
            merged[N..].copy_from_slice(&node);
        }
        node = thash(seed, &a, &merged);
    }
    node
}

fn ht_root_from_sig(
    seed: &[u8], msg_digest: &[u8], mut tree_idx: u64, mut leaf_idx: u32,
    sig: &[u8], xmss_len: usize,
) -> [u8; N] {
    let mut payload = [0u8; N];
    payload.copy_from_slice(msg_digest);
    for layer in 0..D {
        let off = layer * xmss_len;
        let wots_sig = &sig[off..off + LEN * N];
        let auth = &sig[off + LEN * N..off + xmss_len];
        payload = xmss_root_from_sig(seed, layer as u32, tree_idx, leaf_idx, &payload, wots_sig, auth);
        let leaf_mask = (1u64 << H_PRIME) - 1;
        leaf_idx = (tree_idx & leaf_mask) as u32;
        tree_idx >>= H_PRIME;
    }
    payload
}

fn fors_root_from_sig(seed: &[u8], tree_idx: u64, indices: &[u32; K], sig: &[u8]) -> [u8; N] {
    let chunk = N + A * N;
    let mut roots = [0u8; K * N];
    let mut leaf_adrs = adrs(0, tree_idx, TYPE_FORS_TREE, 0);
    let mut tree_adrs = adrs(0, tree_idx, TYPE_FORS_TREE, 0);
    let nleaves_per_tree: u32 = 1 << A;

    for i in 0..K {
        let off = i * chunk;
        let secret = &sig[off..off + N];
        let auth = &sig[off + N..off + chunk];
        let mut leaf_idx = indices[i];
        write_u32(&mut leaf_adrs, 24, (i as u32) * nleaves_per_tree + leaf_idx);
        let mut node = thash(seed, &leaf_adrs, secret);
        for height in 1..=A {
            write_u32(&mut tree_adrs, 20, height as u32);
            let nodes_at_height: u32 = 1 << (A - height);
            write_u32(&mut tree_adrs, 24, (i as u32) * nodes_at_height + (leaf_idx >> 1));
            let sib = &auth[(height - 1) * N..height * N];
            let mut merged = [0u8; 2 * N];
            if leaf_idx & 1 == 0 {
                merged[..N].copy_from_slice(&node);
                merged[N..].copy_from_slice(sib);
            } else {
                merged[..N].copy_from_slice(sib);
                merged[N..].copy_from_slice(&node);
            }
            node = thash(seed, &tree_adrs, &merged);
            leaf_idx >>= 1;
        }
        roots[i * N..(i + 1) * N].copy_from_slice(&node);
    }

    let compress_adrs = adrs(0, tree_idx, TYPE_FORS_ROOTS, 0);
    thash(seed, &compress_adrs, &roots)
}
