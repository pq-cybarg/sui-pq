/// WOTS+ (Winternitz One-Time Signature) verification, in Move.
///
/// **This is real post-quantum cryptography running on-chain.** WOTS+ is the
/// building block underneath SPHINCS+ / SLH-DSA (FIPS 205); when fastcrypto
/// exposes its SLH-DSA verifier as a Move primitive, this module's surface
/// becomes redundant — but until then, it's the first thing on Sui that
/// actually verifies a hash-based PQ signature inside Move.
///
/// ## Scheme
///
/// WOTS+ over SHA-256, parameters from FIPS 205 Algorithm 6:
///   - `n` (hash output bytes)                  = 32   (SHA-256 full output)
///   - `lg_w` (Winternitz parameter)            = 4    → `w = 16`
///   - `len_1` (message-derived chains)         = ceil(8n / lg_w)     = 64
///   - `len_2` (checksum chains)                = floor(lg(len_1·(w-1)) / lg_w) + 1 = 3
///   - `len`                                    = len_1 + len_2       = 67
///
/// Each "chain" is a sequence of `w-1 = 15` applications of the chain hash F:
///     F(seed, ADRS, X) = SHA-256(seed || pad32 || ADRS || X)
/// where ADRS is the 32-byte FIPS 205 address structure.
///
/// **Compatibility with `@sui-gen/pqc`:** this module uses the *plain*
/// SHA-256 F-function (no SHAKE variant). Test vectors in `tests/` are
/// generated from a JS reference implementation that mirrors this code.
module wots::wots_plus;

use std::hash;
use sui::event;

// ── parameters (WOTS+ over SHA-256, lg_w=4) ────────────────────────────────
const N: u64 = 32;
const W: u8  = 16;
const LEN_1: u64 = 64;   // ceil(8 * 32 / 4)
const LEN:   u64 = 67;   // = len_1 (64) + len_2 (3)

// FIPS 205 type-byte constant for the address structure.
const TYPE_WOTS_HASH:  u32 = 0;

// ── error codes ────────────────────────────────────────────────────────────
const EBadLength:    u64 = 1;
const EVerifyFailed: u64 = 2;

// ── public API ─────────────────────────────────────────────────────────────

public struct VerifiedEvent has copy, drop {
    verifier: address,
    msg_digest: vector<u8>,
}

/// Verify a WOTS+ signature.
///
///   `seed`        — PK.seed (32 bytes), public salt the signer chose at keygen.
///   `adrs`        — 32-byte FIPS 205 address (key-pair id + chain markers).
///   `msg_digest`  — 32 bytes; the message digest the signer committed to.
///   `signature`   — `LEN * N = 2144` bytes, concatenated chain mid-points.
///   `pk`          — `LEN * N = 2144` bytes, the WOTS+ public key (chain tops).
///
/// Returns `true` iff every derived chain endpoint matches the corresponding
/// `pk` chunk. Aborts with `EBadLength` if any input is malformed.
public fun verify(
    seed: &vector<u8>,
    adrs: &vector<u8>,
    msg_digest: &vector<u8>,
    signature: &vector<u8>,
    pk: &vector<u8>,
): bool {
    assert!(vector::length(seed) == N,             EBadLength);
    assert!(vector::length(adrs) == 32,            EBadLength);
    assert!(vector::length(msg_digest) == N,       EBadLength);
    assert!(vector::length(signature) == LEN * N,  EBadLength);
    assert!(vector::length(pk)        == LEN * N,  EBadLength);

    // base-w decode message + checksum into LEN nibbles.
    let chains = msg_to_chains(msg_digest);

    let mut i = 0;
    while (i < LEN) {
        let start = (*vector::borrow(&chains, i) as u8);
        let steps = (W - 1) - start; // climb from sig[i] (at position `start`) to chain top

        // copy the i-th LEN-byte block of signature
        let mut node = slice(signature, i * N, N);

        // chain ADRS: copy of base ADRS with type, chain-address, hash-address updated
        let mut local_adrs = *adrs;
        write_u32(&mut local_adrs, 16, TYPE_WOTS_HASH);    // type = WOTS_HASH (offset 16, FIPS 205)
        write_u32(&mut local_adrs, 24, (i as u32));        // chain_address (offset 24)

        let mut j: u8 = 0;
        while (j < steps) {
            write_u32(&mut local_adrs, 28, ((start + j) as u32)); // hash_address (offset 28)
            node = chain_hash(seed, &local_adrs, &node);
            j = j + 1;
        };

        // node should now equal pk[i*N .. (i+1)*N]
        let expected = slice(pk, i * N, N);
        if (!bytes_eq(&node, &expected)) {
            return false
        };
        i = i + 1;
    };
    true
}

/// Same as `verify` but aborts on failure (use when the caller wants the abort
/// to roll back the surrounding transaction, e.g. in a custom auth flow).
public fun verify_assert(
    seed: &vector<u8>,
    adrs: &vector<u8>,
    msg_digest: &vector<u8>,
    signature: &vector<u8>,
    pk: &vector<u8>,
    ctx: &TxContext,
) {
    assert!(verify(seed, adrs, msg_digest, signature, pk), EVerifyFailed);
    event::emit(VerifiedEvent { verifier: ctx.sender(), msg_digest: *msg_digest });
}

/// Compute the WOTS+ public key from a signature + the corresponding message
/// digest. Useful when the verifier wants to compare against a pre-committed
/// `pk` hash rather than the full `pk` bytes (saves storage).
public fun pk_from_sig(
    seed: &vector<u8>,
    adrs: &vector<u8>,
    msg_digest: &vector<u8>,
    signature: &vector<u8>,
): vector<u8> {
    assert!(vector::length(seed) == N,            EBadLength);
    assert!(vector::length(adrs) == 32,           EBadLength);
    assert!(vector::length(msg_digest) == N,      EBadLength);
    assert!(vector::length(signature) == LEN * N, EBadLength);

    let chains = msg_to_chains(msg_digest);

    let mut tops = vector<u8>[];
    let mut i = 0;
    while (i < LEN) {
        let start = (*vector::borrow(&chains, i) as u8);
        let steps = (W - 1) - start;

        let mut node = slice(signature, i * N, N);
        let mut local_adrs = *adrs;
        write_u32(&mut local_adrs, 16, TYPE_WOTS_HASH);
        write_u32(&mut local_adrs, 24, (i as u32));

        let mut j: u8 = 0;
        while (j < steps) {
            write_u32(&mut local_adrs, 28, ((start + j) as u32));
            node = chain_hash(seed, &local_adrs, &node);
            j = j + 1;
        };

        let mut k = 0;
        while (k < N) {
            vector::push_back(&mut tops, *vector::borrow(&node, k));
            k = k + 1;
        };
        i = i + 1;
    };
    tops
}

// ── internal: chain hash F(seed, ADRS, M) = SHA-256(seed || ADRS || M) ─────
fun chain_hash(seed: &vector<u8>, adrs: &vector<u8>, m: &vector<u8>): vector<u8> {
    let mut buf = vector<u8>[];
    extend(&mut buf, seed);
    extend(&mut buf, adrs);
    extend(&mut buf, m);
    hash::sha2_256(buf)
}

// ── base-w decode of (msg_digest || checksum) into LEN nibbles ─────────────
fun msg_to_chains(msg: &vector<u8>): vector<u64> {
    // First LEN_1 nibbles come from the message digest (high nibble first).
    let mut out = vector<u64>[];
    let mut i = 0;
    while (i < N) {
        let b = *vector::borrow(msg, i);
        vector::push_back(&mut out, ((b >> 4) as u64));
        vector::push_back(&mut out, ((b & 0x0F) as u64));
        i = i + 1;
    };

    // Checksum = sum over i in [0, LEN_1): (w - 1 - out[i])
    let mut csum: u64 = 0;
    let mut k = 0;
    while (k < LEN_1) {
        csum = csum + ((W as u64) - 1 - *vector::borrow(&out, k));
        k = k + 1;
    };
    // Left-shift csum so its 12-bit encoding aligns with LEN_2 nibbles.
    // Per FIPS 205: csum <<= (8 - ((LEN_2 * lg_w) % 8)) % 8 = 4
    csum = csum << 4;

    // Encode csum into LEN_2 = 3 nibbles, MSB first.
    let csum_bytes = u64_to_be_bytes(csum, 2);
    let b0 = *vector::borrow(&csum_bytes, 0);
    let b1 = *vector::borrow(&csum_bytes, 1);
    vector::push_back(&mut out, ((b0 >> 4) as u64));
    vector::push_back(&mut out, ((b0 & 0x0F) as u64));
    vector::push_back(&mut out, ((b1 >> 4) as u64));

    out
}

// ── byte helpers ───────────────────────────────────────────────────────────
fun extend(dst: &mut vector<u8>, src: &vector<u8>) {
    let mut i = 0;
    let n = vector::length(src);
    while (i < n) {
        vector::push_back(dst, *vector::borrow(src, i));
        i = i + 1;
    }
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

/// Write a big-endian u32 at byte offset `off` into `buf`.
/// `as u8` aborts if the source value exceeds 255, so we mask before casting.
fun write_u32(buf: &mut vector<u8>, off: u64, v: u32) {
    *vector::borrow_mut(buf, off + 0) = (((v >> 24) & 0xff) as u8);
    *vector::borrow_mut(buf, off + 1) = (((v >> 16) & 0xff) as u8);
    *vector::borrow_mut(buf, off + 2) = (((v >> 8)  & 0xff) as u8);
    *vector::borrow_mut(buf, off + 3) = ( (v        & 0xff) as u8);
}

/// `width` bytes of `v`, big-endian.
fun u64_to_be_bytes(v: u64, width: u64): vector<u8> {
    let mut out = vector<u8>[];
    let mut i: u64 = 0;
    while (i < width) {
        let shift = (width - 1 - i) * 8;
        vector::push_back(&mut out, (((v >> (shift as u8)) & 0xff) as u8));
        i = i + 1;
    };
    out
}

// ── test helpers (re-exported for unit tests in tests/) ─────────────────────
#[test_only] public fun test_msg_to_chains(msg: &vector<u8>): vector<u64> { msg_to_chains(msg) }
#[test_only] public fun test_chain_hash(seed: &vector<u8>, adrs: &vector<u8>, m: &vector<u8>): vector<u8> { chain_hash(seed, adrs, m) }
#[test_only] public fun len(): u64 { LEN }
#[test_only] public fun n(): u64 { N }
