/// Post-quantum attestation registry.
///
/// Stores a (scheme, publicKey, signature, message_digest) tuple alongside a
/// user's Sui address. **No on-chain PQ verification is performed today** — Sui
/// validators do not (as of 2026-05) accept ML-DSA / SLH-DSA / FALCON signatures
/// for transaction authentication. fastcrypto has an experimental SLH-DSA
/// implementation (FIPS 205, behind --features experimental) but it isn't yet
/// exposed as a Move primitive.
///
/// This module is **storage-only on purpose**:
///   - When fastcrypto's PQ verifier is exposed, a `verify_attestation` entry
///     function can be added without changing the storage layout (the existing
///     attestation objects remain valid).
///   - Anyone scanning the chain can re-verify attestations off-chain TODAY
///     using `@sui-gen/pqc` and the published byte fields below.
///
/// Identifier scheme byte values match `@sui-gen/pqc` exactly:
///   0x10–0x12 → ML-DSA-{44, 65, 87}
///   0x20–0x2D → SLH-DSA-{SHA2|SHAKE}-{128|192|256}-{s|f}
///   0x30–0x31 → FALCON-{512, 1024}
module pq_attestation::registry;

use sui::event;

public struct Attestation has key, store {
    id: UID,
    owner: address,
    /// PQ scheme byte. See module docstring for the enum.
    scheme: u8,
    /// PQ public key bytes (raw, scheme-specific length).
    public_key: vector<u8>,
    /// PQ signature over `message_digest`.
    signature: vector<u8>,
    /// 32 bytes — SHA-256 of the BCS-encoded commit { sui_address, nonce, app_tag }.
    message_digest: vector<u8>,
    /// Caller-supplied randomness, kept on-chain so the commit can be recomputed.
    nonce: vector<u8>,
    /// Application namespace ("game-x", "wallet-recovery", ...). Bound into the signed digest.
    app_tag: vector<u8>,
    /// On-chain timestamp (epoch milliseconds), captured at register time.
    created_at_ms: u64,
}

public struct Registered has copy, drop {
    attestation: ID,
    owner: address,
    scheme: u8,
}

public struct Revoked has copy, drop {
    attestation: ID,
    owner: address,
}

const ENotOwner: u64 = 0;
const EBadDigestLen: u64 = 1;

public fun register(
    scheme: u8,
    public_key: vector<u8>,
    signature: vector<u8>,
    message_digest: vector<u8>,
    nonce: vector<u8>,
    app_tag: vector<u8>,
    ctx: &mut TxContext,
) {
    // Off-chain attestations use SHA-256 → 32 bytes. Enforce shape; everything else
    // is scheme-specific and best left to the off-chain verifier (or a future
    // on-chain `verify_attestation` once fastcrypto exposes its PQ verifier).
    assert!(vector::length(&message_digest) == 32, EBadDigestLen);

    let owner = ctx.sender();
    let att = Attestation {
        id: object::new(ctx),
        owner,
        scheme,
        public_key,
        signature,
        message_digest,
        nonce,
        app_tag,
        created_at_ms: ctx.epoch_timestamp_ms(),
    };
    event::emit(Registered { attestation: object::id(&att), owner, scheme });

    // Transferred to the user so revocation is gated by ownership.
    transfer::transfer(att, owner);
}

/// Owner-only deletion. Use when rotating to a fresh PQ keypair.
public fun revoke(att: Attestation, ctx: &TxContext) {
    assert!(att.owner == ctx.sender(), ENotOwner);
    let id = object::id(&att);
    let owner = att.owner;
    let Attestation {
        id: uid,
        owner: _,
        scheme: _,
        public_key: _,
        signature: _,
        message_digest: _,
        nonce: _,
        app_tag: _,
        created_at_ms: _,
    } = att;
    object::delete(uid);
    event::emit(Revoked { attestation: id, owner });
}

// ── views ──────────────────────────────────────────────────────────────────
public fun owner(att: &Attestation): address { att.owner }
public fun scheme(att: &Attestation): u8 { att.scheme }
public fun public_key(att: &Attestation): &vector<u8> { &att.public_key }
public fun signature(att: &Attestation): &vector<u8> { &att.signature }
public fun message_digest(att: &Attestation): &vector<u8> { &att.message_digest }
public fun nonce(att: &Attestation): &vector<u8> { &att.nonce }
public fun app_tag(att: &Attestation): &vector<u8> { &att.app_tag }
public fun created_at_ms(att: &Attestation): u64 { att.created_at_ms }
