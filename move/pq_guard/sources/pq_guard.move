/// PQ-Guard: post-quantum **authorization** at the smart-contract layer.
///
/// The Sui validator only accepts classical signatures for tx authentication.
/// PQ-Guard sidesteps that limit by moving the *real* authorization check
/// into a Move function: an operation gated by `PqAuthorized` cannot proceed
/// unless the same atomic transaction also produces a valid SLH-DSA proof.
///
/// Flow:
///
///   1. User registers a `PqIdentity` (owned) holding their SLH-DSA pubkey.
///   2. Each operation builds a `PqGuardMessage` BCS-encoding `{ identity_id,
///      sender, nonce, action_digest }` — domain-separated, replay-resistant.
///   3. User signs the SHA-256 of those bytes with their PQ secret key (off-chain
///      via `@sui-gen/pqc/slh.sign`).
///   4. The transaction's first PTB command calls
///      `pq_guard::unlock(&mut identity, action_digest, signature, ctx)`. If
///      the SLH-DSA verify aborts, the whole tx aborts. On success the call
///      returns a non-storable, non-copyable `PqAuthorized` witness.
///   5. Subsequent PTB commands accept that witness as a function argument —
///      proving PQ authorization for those calls.
///
/// **The classical signature on the outer transaction is just a gas-paying
/// trampoline.** It can be a freshly-rotated, single-use ed25519 key with no
/// long-term security significance: the actual authority is the SLH-DSA key
/// registered in the `PqIdentity`.
///
/// Replay protection: every successful `unlock` increments the `PqIdentity`
/// `nonce`. A signature produced for nonce N is only valid while the identity
/// still sits at nonce N; after one use it can never be replayed.
module pq_guard::pq_guard;

use std::hash;
use sui::event;
use slh_dsa::verifier as slh_lite;
use slh_dsa_128s::sha2_128s as slh_128s;

/// Workspace-local SLH-DSA-LITE (n=32 truncated SHA-256, h=8, d=2). Original
/// scheme; kept for back-compat with identities already on-chain.
const SLH_DSA_LITE: u8 = 0x60;
/// FIPS-205 SLH-DSA-SHA2-128s.  Scheme byte matches the workspace registry in
/// `packages/pqc/src/schemes.ts`.  Preferred for new identities.
const SLH_DSA_SHA2_128S: u8 = 0x20;

/// Owned object: the user's PQ pubkey + monotonic nonce.
public struct PqIdentity has key {
    id: UID,
    /// Address allowed to consume the identity's nonce (and rotate the key).
    owner: address,
    /// PQ scheme byte (`SLH_DSA_LITE` = 0x60, `SLH_DSA_SHA2_128S` = 0x20).
    scheme: u8,
    /// SLH-DSA public key.  Length depends on the scheme:
    ///   SLH_DSA_LITE       → 64 bytes (PK.seed || PK.root, 32 + 32)
    ///   SLH_DSA_SHA2_128S  → 32 bytes (PK.seed || PK.root, 16 + 16)
    pk: vector<u8>,
    /// Monotonically increasing per-identity counter — replay protection.
    nonce: u64,
}

/// Non-storable, non-copyable witness produced by a successful `unlock`.
/// Functions that want PQ authorization take this as an argument.
public struct PqAuthorized {
    identity_id: ID,
    sender: address,
    nonce: u64,
    /// The action digest the holder of `pk` committed to; gated functions
    /// check this matches the call they're about to make.
    action_digest: vector<u8>,
}

public struct Registered has copy, drop { identity: ID, owner: address, scheme: u8 }
public struct Unlocked   has copy, drop { identity: ID, sender: address, nonce: u64, action_digest: vector<u8> }
public struct Rotated    has copy, drop { identity: ID, owner: address }

const EBadScheme:     u64 = 1;
const EBadPkLength:   u64 = 2;
const EBadDigestLen:  u64 = 3;
const ENotOwner:      u64 = 4;
const EInvalidPqSig:  u64 = 5;

// ── lifecycle ─────────────────────────────────────────────────────────────

/// Expected pk byte length for a given scheme. Aborts on unknown scheme.
fun expected_pk_len(scheme: u8): u64 {
    if (scheme == SLH_DSA_LITE) { slh_lite::pk_byte_len() }
    else if (scheme == SLH_DSA_SHA2_128S) { slh_128s::pk_byte_len() }
    else { abort EBadScheme }
}

public fun register(scheme: u8, pk: vector<u8>, ctx: &mut TxContext) {
    assert!(vector::length(&pk) == expected_pk_len(scheme), EBadPkLength);
    let id = PqIdentity { id: object::new(ctx), owner: ctx.sender(), scheme, pk, nonce: 0 };
    event::emit(Registered { identity: object::id(&id), owner: id.owner, scheme });
    transfer::transfer(id, ctx.sender());
}

/// Owner-only: rotate to a fresh PQ pubkey (e.g. after a long-lived secret).
/// The new pk must have the byte length expected by the identity's scheme.
public fun rotate(identity: &mut PqIdentity, new_pk: vector<u8>, ctx: &TxContext) {
    assert!(identity.owner == ctx.sender(), ENotOwner);
    assert!(vector::length(&new_pk) == expected_pk_len(identity.scheme), EBadPkLength);
    identity.pk = new_pk;
    identity.nonce = 0; // reset replay counter under the new key
    event::emit(Rotated { identity: object::id(identity), owner: identity.owner });
}

// ── PQ message construction ───────────────────────────────────────────────

/// Build the canonical bytes signed by the PQ key for an unlock.
///
/// Layout (concatenated, no length prefixes — fixed-width fields only):
///   tag           = 18 bytes  b"PQ_GUARD:UNLOCK:v1"
///   sender        = 32 bytes  Sui address
///   nonce         =  8 bytes  identity nonce, big-endian
///   action_digest = 32 bytes  caller-defined commit to the intended operation
///
/// The pk is NOT included here because `slh::verify(pk, msg, sig)` already
/// binds the signature to the pk. Convention: one PQ keypair per `PqIdentity`
/// — don't reuse a PQ key across identities, or a sig valid for one identity
/// becomes valid for the other at the same nonce.
public fun unlock_message_bytes(identity: &PqIdentity, sender: address, action_digest: &vector<u8>): vector<u8> {
    assert!(vector::length(action_digest) == 32, EBadDigestLen);
    let mut out = vector[];
    append(&mut out, &b"PQ_GUARD:UNLOCK:v1");
    append(&mut out, &sui::address::to_bytes(sender));
    append(&mut out, &u64_be_bytes(identity.nonce));
    append(&mut out, action_digest);
    out
}

/// SHA-256 of `unlock_message_bytes`. This is what the off-chain SLH-DSA
/// signer commits to.
public fun unlock_message_digest(identity: &PqIdentity, sender: address, action_digest: &vector<u8>): vector<u8> {
    hash::sha2_256(unlock_message_bytes(identity, sender, action_digest))
}

// ── the unlock function — the heart of the primitive ─────────────────────

/// Dispatch verify across supported schemes. Aborts on unknown scheme.
fun verify_pq(scheme: u8, pk: &vector<u8>, msg: &vector<u8>, sig: &vector<u8>): bool {
    if (scheme == SLH_DSA_LITE) { slh_lite::verify(pk, msg, sig) }
    else if (scheme == SLH_DSA_SHA2_128S) { slh_128s::verify(pk, msg, sig) }
    else { abort EBadScheme }
}

public fun unlock(
    identity: &mut PqIdentity,
    action_digest: vector<u8>,
    signature: vector<u8>,
    ctx: &TxContext,
): PqAuthorized {
    assert!(vector::length(&action_digest) == 32, EBadDigestLen);
    let msg = unlock_message_bytes(identity, ctx.sender(), &action_digest);
    let ok = verify_pq(identity.scheme, &identity.pk, &msg, &signature);
    assert!(ok, EInvalidPqSig);

    let n = identity.nonce;
    identity.nonce = n + 1;
    let id = object::id(identity);

    event::emit(Unlocked { identity: id, sender: ctx.sender(), nonce: n, action_digest });

    PqAuthorized { identity_id: id, sender: ctx.sender(), nonce: n, action_digest }
}

// ── witness accessors ─────────────────────────────────────────────────────

public fun identity_id(auth: &PqAuthorized): ID { auth.identity_id }
public fun sender(auth: &PqAuthorized): address { auth.sender }
public fun nonce(auth: &PqAuthorized): u64 { auth.nonce }
public fun action_digest(auth: &PqAuthorized): &vector<u8> { &auth.action_digest }

/// Consume the witness — call from any gated function as the last step.
/// Required because `PqAuthorized` has no `drop` ability.
public fun consume(auth: PqAuthorized) {
    let PqAuthorized { identity_id: _, sender: _, nonce: _, action_digest: _ } = auth;
}

// ── views ─────────────────────────────────────────────────────────────────
public fun owner(identity: &PqIdentity): address { identity.owner }
public fun pk(identity: &PqIdentity): &vector<u8> { &identity.pk }
public fun current_nonce(identity: &PqIdentity): u64 { identity.nonce }
public fun scheme(identity: &PqIdentity): u8 { identity.scheme }
public fun slh_dsa_lite_scheme_byte(): u8 { SLH_DSA_LITE }
public fun slh_dsa_sha2_128s_scheme_byte(): u8 { SLH_DSA_SHA2_128S }

// ── test-only escape hatch ────────────────────────────────────────────────
/// Construct a `PqAuthorized` directly, bypassing SLH-DSA verification.
/// **Available only in tests.** Lets gated-app tests prove their own
/// witness-checking logic without re-generating PQ test vectors every time
/// the action digest changes.
#[test_only]
public fun test_only_forge_authorized(
    identity_id: ID,
    sender: address,
    nonce: u64,
    action_digest: vector<u8>,
): PqAuthorized {
    PqAuthorized { identity_id, sender, nonce, action_digest }
}

// ── helpers ───────────────────────────────────────────────────────────────
fun append(dst: &mut vector<u8>, src: &vector<u8>) {
    let mut i = 0;
    let n = vector::length(src);
    while (i < n) { vector::push_back(dst, *vector::borrow(src, i)); i = i + 1; }
}

fun u64_be_bytes(v: u64): vector<u8> {
    let mut out = vector[];
    let mut i: u64 = 0;
    while (i < 8) {
        let shift = (7 - i) * 8;
        vector::push_back(&mut out, (((v >> (shift as u8)) & 0xff) as u8));
        i = i + 1;
    };
    out
}
