#[test_only]
module pq_guard::pq_guard_128s_tests;

use pq_guard::pq_guard::{Self, PqIdentity};
use pq_guard::test_vectors_128s as tv;
use sui::test_scenario as ts;

/// Replay-protection and successive-unlock semantics are scheme-independent;
/// the LITE-flavored tests in `pq_guard_tests.move` already prove them through
/// the shared `verify_pq` dispatch.  Each FIPS-205 verify costs ~2,099 SHA-256
/// hashes and saturates Move's per-test budget, so these tests run at most one
/// verify each and focus on proving the FIPS-205 dispatch is correctly wired.
const SLH_DSA_SHA2_128S: u8 = 0x20;

#[test]
fun registers_with_fips205_scheme() {
    let sender = tv::sender();
    let mut scenario = ts::begin(sender);
    pq_guard::register(SLH_DSA_SHA2_128S, tv::pk(), scenario.ctx());

    scenario.next_tx(sender);
    let id = scenario.take_from_sender<PqIdentity>();
    assert!(pq_guard::scheme(&id) == SLH_DSA_SHA2_128S, 0);
    assert!(*pq_guard::pk(&id) == tv::pk(), 1);
    assert!(pq_guard::current_nonce(&id) == 0, 2);
    scenario.return_to_sender(id);
    scenario.end();
}

#[test]
fun fips205_unlock_succeeds_and_increments_nonce() {
    let sender = tv::sender();
    let mut scenario = ts::begin(sender);
    pq_guard::register(SLH_DSA_SHA2_128S, tv::pk(), scenario.ctx());

    scenario.next_tx(sender);
    let mut id = scenario.take_from_sender<PqIdentity>();
    let auth = pq_guard::unlock(
        &mut id,
        tv::action_digest_0(),
        tv::signature_for_nonce_0(),
        scenario.ctx(),
    );
    assert!(pq_guard::sender(&auth) == sender, 3);
    assert!(pq_guard::nonce(&auth) == 0, 4);
    assert!(pq_guard::current_nonce(&id) == 1, 5);
    pq_guard::consume(auth);
    scenario.return_to_sender(id);
    scenario.end();
}

#[test]
#[expected_failure(abort_code = pq_guard::EInvalidPqSig)]
fun fips205_tampered_signature_rejected() {
    let sender = tv::sender();
    let mut scenario = ts::begin(sender);
    pq_guard::register(SLH_DSA_SHA2_128S, tv::pk(), scenario.ctx());

    scenario.next_tx(sender);
    let mut id = scenario.take_from_sender<PqIdentity>();
    let mut sig = tv::signature_for_nonce_0();
    let b = *sig.borrow(0);
    *sig.borrow_mut(0) = b ^ 0x01;
    let _auth = pq_guard::unlock(
        &mut id,
        tv::action_digest_0(),
        sig,
        scenario.ctx(),
    );
    abort 99
}

#[test]
#[expected_failure(abort_code = pq_guard::EInvalidPqSig)]
fun fips205_wrong_message_rejected() {
    // Using the nonce-1 signature against the nonce-0 message must fail —
    // proves that the digest binds the scheme's verify to the right message.
    let sender = tv::sender();
    let mut scenario = ts::begin(sender);
    pq_guard::register(SLH_DSA_SHA2_128S, tv::pk(), scenario.ctx());

    scenario.next_tx(sender);
    let mut id = scenario.take_from_sender<PqIdentity>();
    let _auth = pq_guard::unlock(
        &mut id,
        tv::action_digest_0(),
        tv::signature_for_nonce_1(),  // mismatched: sig is for nonce-1's message
        scenario.ctx(),
    );
    abort 99
}

#[test]
#[expected_failure(abort_code = pq_guard::EBadPkLength)]
fun fips205_rejects_64_byte_pk() {
    // SLH_DSA_SHA2_128S requires 32-byte pk.  Passing a 64-byte LITE-sized pk
    // must abort at register time with EBadPkLength.
    let mut scenario = ts::begin(tv::sender());
    let lite_sized_pk = vector[
        0u8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    ];
    pq_guard::register(SLH_DSA_SHA2_128S, lite_sized_pk, scenario.ctx());
    scenario.end();
}

