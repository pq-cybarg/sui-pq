#[test_only]
module slh_dsa::slh_dsa_tests;

use std::hash;
use slh_dsa::verifier;
use slh_dsa::test_vectors;

#[test]
fun signature_has_expected_length() {
    let sig = test_vectors::signature();
    let expected = test_vectors::sig_len();
    assert!(vector::length(&sig) == expected, 0);
}

#[test]
fun verifies_a_valid_signature() {
    let pk = test_vectors::pk();
    let msg = test_vectors::message();
    let sig = test_vectors::signature();
    assert!(verifier::verify(&pk, &msg, &sig), 1);
}

#[test]
fun rejects_tampered_signature() {
    let pk = test_vectors::pk();
    let msg = test_vectors::message();
    let mut sig = test_vectors::signature();
    let b0 = *vector::borrow(&sig, 0);
    *vector::borrow_mut(&mut sig, 0) = b0 ^ 0x01;
    assert!(!verifier::verify(&pk, &msg, &sig), 2);
}

#[test]
fun rejects_different_message() {
    let pk = test_vectors::pk();
    let sig = test_vectors::signature();
    let bad = hash::sha2_256(b"a completely different message");
    assert!(!verifier::verify(&pk, &bad, &sig), 3);
}

#[test]
fun rejects_short_signature() {
    let pk = test_vectors::pk();
    let msg = test_vectors::message();
    let bad: vector<u8> = vector[0u8, 1, 2, 3];
    assert!(!verifier::verify(&pk, &msg, &bad), 4);
}

#[test]
#[expected_failure(abort_code = slh_dsa::verifier::EBadPkLength)]
fun rejects_wrong_pk_length() {
    let bad_pk: vector<u8> = vector[0u8, 1, 2];
    let _ = verifier::verify(&bad_pk, &test_vectors::message(), &test_vectors::signature());
}
