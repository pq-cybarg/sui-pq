//! FIPS-205 **SLH-DSA-SHA2-128s** verification for a native Sui signature
//! scheme. This is the complete, standard scheme (pk 32B, sig 7,856B) — NOT
//! the workspace's custom SLH-DSA-LITE — implemented by the maintained
//! RustCrypto `slh-dsa` crate. It interoperates with the workspace signer
//! (`@sui-gen/pqc`, which signs via `@noble/post-quantum`) and matches the
//! verifier machine-checked in `proofs/` and `move/slh_dsa_128s`.
//!
//! Intended use: the verify call behind a patched-validator
//! `SignatureScheme::SlhDsa` (flag byte) whose authenticator is
//! `flag || pk(32) || sig(7856)` and whose address is `blake2b256(flag || pk)`.

use slh_dsa::signature::Verifier;
use slh_dsa::{Sha2_128s, Signature, VerifyingKey};

/// Public key / signature sizes for SLH-DSA-SHA2-128s.
pub const PK_BYTES: usize = 32;
pub const SIG_BYTES: usize = 7856;

/// Verify a FIPS-205 SLH-DSA-SHA2-128s signature.
///
/// `pk` must be 32 bytes, `sig` 7,856 bytes. Returns `false` on any parse
/// failure or verification mismatch (never panics) — suitable for a
/// validator hot path.
pub fn verify(pk: &[u8], message: &[u8], sig: &[u8]) -> bool {
    if pk.len() != PK_BYTES || sig.len() != SIG_BYTES {
        return false;
    }
    let Ok(vk) = VerifyingKey::<Sha2_128s>::try_from(pk) else {
        return false;
    };
    let Ok(signature) = Signature::<Sha2_128s>::try_from(sig) else {
        return false;
    };
    vk.verify(message, &signature).is_ok()
}
