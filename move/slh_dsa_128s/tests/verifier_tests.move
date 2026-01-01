#[test_only]
module slh_dsa_128s::verifier_tests;

use slh_dsa_128s::sha2_128s as verifier;
use slh_dsa_128s::test_vectors;

#[test]
fun signature_has_expected_length() {
    let sig = test_vectors::signature();
    assert!(sig.length() == test_vectors::sig_len(), 0);
    assert!(sig.length() == verifier::signature_byte_len(), 0);
}

#[test]
fun pk_has_expected_length() {
    let pk = test_vectors::pk();
    assert!(pk.length() == test_vectors::pk_len(), 0);
    assert!(pk.length() == verifier::pk_byte_len(), 0);
}

#[test]
fun verifies_a_noble_produced_signature() {
    let pk = test_vectors::pk();
    let msg = test_vectors::message();
    let sig = test_vectors::signature();
    assert!(verifier::verify(&pk, &msg, &sig), 1);
}

#[test]
fun rejects_tampered_signature_first_byte() {
    let pk = test_vectors::pk();
    let msg = test_vectors::message();
    let mut sig = test_vectors::signature();
    let b0 = *sig.borrow(0);
    *sig.borrow_mut(0) = b0 ^ 0x01;
    assert!(!verifier::verify(&pk, &msg, &sig), 2);
}

#[test]
fun rejects_tampered_signature_middle_byte() {
    let pk = test_vectors::pk();
    let msg = test_vectors::message();
    let mut sig = test_vectors::signature();
    let idx = sig.length() / 2;
    let b = *sig.borrow(idx);
    *sig.borrow_mut(idx) = b ^ 0xff;
    assert!(!verifier::verify(&pk, &msg, &sig), 3);
}

#[test]
fun rejects_different_message() {
    let pk = test_vectors::pk();
    let sig = test_vectors::signature();
    let bad: vector<u8> = b"a completely different message that was not signed";
    assert!(!verifier::verify(&pk, &bad, &sig), 4);
}

#[test]
fun rejects_short_signature() {
    let pk = test_vectors::pk();
    let msg = test_vectors::message();
    let bad: vector<u8> = vector[0u8, 1, 2, 3];
    assert!(!verifier::verify(&pk, &msg, &bad), 5);
}

#[test]
fun rejects_wrong_pk_value() {
    let mut pk = test_vectors::pk();
    let b = *pk.borrow(0);
    *pk.borrow_mut(0) = b ^ 0x01;
    let msg = test_vectors::message();
    let sig = test_vectors::signature();
    assert!(!verifier::verify(&pk, &msg, &sig), 6);
}

#[test]
#[expected_failure(abort_code = slh_dsa_128s::sha2_128s::EBadPkLength)]
fun rejects_wrong_pk_length() {
    let bad_pk: vector<u8> = vector[0u8, 1, 2];
    let _ = verifier::verify(&bad_pk, &test_vectors::message(), &test_vectors::signature());
}
