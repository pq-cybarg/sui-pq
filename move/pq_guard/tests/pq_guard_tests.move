#[test_only]
module pq_guard::pq_guard_tests;

use pq_guard::pq_guard::{Self, PqIdentity};
use pq_guard::test_vectors;
use sui::test_scenario as ts;

const SLH_DSA_LITE: u8 = 0x60;

#[test]
fun register_creates_owned_identity_with_zero_nonce() {
    let sender = test_vectors::sender();
    let mut scenario = ts::begin(sender);
    pq_guard::register(SLH_DSA_LITE, test_vectors::pk(), scenario.ctx());

    scenario.next_tx(sender);
    let id = scenario.take_from_sender<PqIdentity>();
    assert!(pq_guard::owner(&id) == sender, 0);
    assert!(pq_guard::current_nonce(&id) == 0, 1);
    assert!(pq_guard::scheme(&id) == SLH_DSA_LITE, 2);
    assert!(*pq_guard::pk(&id) == test_vectors::pk(), 3);
    scenario.return_to_sender(id);
    scenario.end();
}

#[test]
fun unlock_with_valid_pq_signature_succeeds_and_increments_nonce() {
    let sender = test_vectors::sender();
    let mut scenario = ts::begin(sender);
    pq_guard::register(SLH_DSA_LITE, test_vectors::pk(), scenario.ctx());

    scenario.next_tx(sender);
    let mut id = scenario.take_from_sender<PqIdentity>();
    let auth = pq_guard::unlock(
        &mut id,
        test_vectors::action_digest_0(),
        test_vectors::signature_for_nonce_0(),
        scenario.ctx(),
    );
    assert!(pq_guard::sender(&auth) == sender, 4);
    assert!(pq_guard::nonce(&auth) == 0, 5);
    assert!(pq_guard::current_nonce(&id) == 1, 6);  // post-increment
    pq_guard::consume(auth);
    scenario.return_to_sender(id);
    scenario.end();
}

#[test]
fun two_successive_unlocks_at_consecutive_nonces() {
    let sender = test_vectors::sender();
    let mut scenario = ts::begin(sender);
    pq_guard::register(SLH_DSA_LITE, test_vectors::pk(), scenario.ctx());

    scenario.next_tx(sender);
    let mut id = scenario.take_from_sender<PqIdentity>();

    let a0 = pq_guard::unlock(&mut id, test_vectors::action_digest_0(), test_vectors::signature_for_nonce_0(), scenario.ctx());
    pq_guard::consume(a0);

    let a1 = pq_guard::unlock(&mut id, test_vectors::action_digest_1(), test_vectors::signature_for_nonce_1(), scenario.ctx());
    pq_guard::consume(a1);

    assert!(pq_guard::current_nonce(&id) == 2, 7);
    scenario.return_to_sender(id);
    scenario.end();
}

#[test]
#[expected_failure(abort_code = pq_guard::EInvalidPqSig)]
fun replay_of_nonce_0_signature_after_nonce_advances() {
    let sender = test_vectors::sender();
    let mut scenario = ts::begin(sender);
    pq_guard::register(SLH_DSA_LITE, test_vectors::pk(), scenario.ctx());

    scenario.next_tx(sender);
    let mut id = scenario.take_from_sender<PqIdentity>();
    // First unlock at nonce=0 consumes the nonce-0 signature.
    let a0 = pq_guard::unlock(&mut id, test_vectors::action_digest_0(), test_vectors::signature_for_nonce_0(), scenario.ctx());
    pq_guard::consume(a0);
    // identity.nonce is now 1; the same signature is no longer valid (different msg digest).
    let _a1 = pq_guard::unlock(&mut id, test_vectors::action_digest_0(), test_vectors::signature_for_nonce_0(), scenario.ctx());
    abort 99
}

#[test]
#[expected_failure(abort_code = pq_guard::EInvalidPqSig)]
fun tampered_signature_is_rejected() {
    let sender = test_vectors::sender();
    let mut scenario = ts::begin(sender);
    pq_guard::register(SLH_DSA_LITE, test_vectors::pk(), scenario.ctx());

    scenario.next_tx(sender);
    let mut id = scenario.take_from_sender<PqIdentity>();
    let mut sig = test_vectors::signature_for_nonce_0();
    let b = *vector::borrow(&sig, 0);
    *vector::borrow_mut(&mut sig, 0) = b ^ 0x01;
    let _auth = pq_guard::unlock(
        &mut id,
        test_vectors::action_digest_0(),
        sig,
        scenario.ctx(),
    );
    abort 99
}

#[test]
#[expected_failure(abort_code = pq_guard::EInvalidPqSig)]
fun signature_bound_to_one_action_digest_only() {
    let sender = test_vectors::sender();
    let mut scenario = ts::begin(sender);
    pq_guard::register(SLH_DSA_LITE, test_vectors::pk(), scenario.ctx());

    scenario.next_tx(sender);
    let mut id = scenario.take_from_sender<PqIdentity>();
    // Use the nonce-0 signature with a DIFFERENT action digest — must reject.
    let _auth = pq_guard::unlock(
        &mut id,
        test_vectors::action_digest_1(),
        test_vectors::signature_for_nonce_0(),
        scenario.ctx(),
    );
    abort 99
}

#[test]
#[expected_failure(abort_code = pq_guard::EBadScheme)]
fun rejects_unknown_scheme_byte() {
    let mut scenario = ts::begin(test_vectors::sender());
    pq_guard::register(0xFE, test_vectors::pk(), scenario.ctx());
    scenario.end();
}

#[test]
#[expected_failure(abort_code = pq_guard::EBadPkLength)]
fun rejects_pk_of_wrong_length() {
    let mut scenario = ts::begin(test_vectors::sender());
    pq_guard::register(SLH_DSA_LITE, vector[0u8, 1, 2, 3], scenario.ctx());
    scenario.end();
}
