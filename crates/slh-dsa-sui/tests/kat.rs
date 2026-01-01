//! Cross-implementation KAT: the workspace signer (`@sui-gen/pqc` →
//! `@noble/post-quantum` SLH-DSA-SHA2-128s) produces (pk, msg, sig); this
//! RustCrypto-backed verifier must accept it. This is the byte-format
//! contract a native Sui `SignatureScheme::SlhDsa` would rely on.
//!
//! `tests/kat.txt` is produced by the noble FIPS-205 signer (PK=…, MSG=…, SIG=…).

use slh_dsa_sui::{verify, PK_BYTES, SIG_BYTES};

fn kat() -> (Vec<u8>, Vec<u8>, Vec<u8>) {
    let mut pk = vec![];
    let mut msg = vec![];
    let mut sig = vec![];
    for line in include_str!("kat.txt").lines() {
        if let Some(h) = line.strip_prefix("PK=") {
            pk = hex::decode(h.trim()).unwrap();
        } else if let Some(h) = line.strip_prefix("MSG=") {
            msg = hex::decode(h.trim()).unwrap();
        } else if let Some(h) = line.strip_prefix("SIG=") {
            sig = hex::decode(h.trim()).unwrap();
        }
    }
    (pk, msg, sig)
}

#[test]
fn verifies_noble_fips205_signature() {
    let (pk, msg, sig) = kat();
    assert_eq!(pk.len(), PK_BYTES);
    assert_eq!(sig.len(), SIG_BYTES);
    assert!(verify(&pk, &msg, &sig), "must accept the noble FIPS-205 SLH-DSA-SHA2-128s signature");
}

#[test]
fn rejects_tampered_signature() {
    let (pk, msg, mut sig) = kat();
    sig[100] ^= 0xff;
    assert!(!verify(&pk, &msg, &sig));
}

#[test]
fn rejects_wrong_message() {
    let (pk, _msg, sig) = kat();
    assert!(!verify(&pk, b"different message", &sig));
}

#[test]
fn rejects_bad_lengths() {
    let (pk, msg, sig) = kat();
    assert!(!verify(&pk[..31], &msg, &sig));
    assert!(!verify(&pk, &msg, &sig[..7855]));
}
