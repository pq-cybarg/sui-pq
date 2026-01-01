#[test_only]
module wots::wots_tests;

use std::hash;
use wots::wots_plus;
use wots::test_vectors;

// ── happy path ──────────────────────────────────────────────────────────────
#[test]
fun verifies_valid_signature() {
    let seed = test_vectors::seed();
    let adrs = test_vectors::adrs();
    let msg  = test_vectors::msg();
    let sig  = test_vectors::signature();
    let pk   = test_vectors::public_key();

    assert!(wots_plus::verify(&seed, &adrs, &msg, &sig, &pk), 0);
}

// ── pk_from_sig matches pre-published pk ───────────────────────────────────
#[test]
fun pk_from_sig_recovers_public_key() {
    let seed = test_vectors::seed();
    let adrs = test_vectors::adrs();
    let msg  = test_vectors::msg();
    let sig  = test_vectors::signature();
    let pk   = test_vectors::public_key();

    let recovered = wots_plus::pk_from_sig(&seed, &adrs, &msg, &sig);
    assert!(recovered == pk, 1);
}

// ── tampered signature: derived pk should NOT match ─────────────────────────
#[test]
fun rejects_tampered_signature() {
    let seed = test_vectors::seed();
    let adrs = test_vectors::adrs();
    let msg  = test_vectors::msg();
    let mut sig = test_vectors::signature();
    let pk   = test_vectors::public_key();

    // Flip a bit in the first chain's signature.
    let first = *vector::borrow(&sig, 0);
    *vector::borrow_mut(&mut sig, 0) = first ^ 0x01;

    assert!(!wots_plus::verify(&seed, &adrs, &msg, &sig, &pk), 2);
}

// ── wrong message digest: derived pk should NOT match ──────────────────────
#[test]
fun rejects_wrong_message() {
    let seed = test_vectors::seed();
    let adrs = test_vectors::adrs();
    let sig  = test_vectors::signature();
    let pk   = test_vectors::public_key();

    // Re-hash a different payload; should yield an unrelated 32-byte digest.
    let bad = hash::sha2_256(b"a different message");
    assert!(!wots_plus::verify(&seed, &adrs, &bad, &sig, &pk), 3);
}

// ── shape checks ───────────────────────────────────────────────────────────
#[test]
#[expected_failure(abort_code = wots::wots_plus::EBadLength)]
fun rejects_wrong_signature_length() {
    let seed = test_vectors::seed();
    let adrs = test_vectors::adrs();
    let msg  = test_vectors::msg();
    let pk   = test_vectors::public_key();
    let bad  = vector[0u8, 1, 2, 3];
    let _ = wots_plus::verify(&seed, &adrs, &msg, &bad, &pk);
}

// ── chain decomposition basics ─────────────────────────────────────────────
#[test]
fun msg_to_chains_has_67_entries() {
    let msg = test_vectors::msg();
    let chains = wots_plus::test_msg_to_chains(&msg);
    assert!(vector::length(&chains) == wots_plus::len(), 4);
    let mut i = 0;
    let n = vector::length(&chains);
    while (i < n) {
        let v = *vector::borrow(&chains, i);
        assert!(v < 16, 5);
        i = i + 1;
    };
}
