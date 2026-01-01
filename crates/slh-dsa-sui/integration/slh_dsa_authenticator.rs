// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0
//
// Drop this file into `crates/sui-types/src/slh_dsa_authenticator.rs` of a Sui
// checkout and wire it up per ../INTEGRATION.md. It adds a native, post-quantum
// `GenericSignature::SlhDsaAuthenticator` so a transaction can be authenticated
// with ONLY a FIPS-205 SLH-DSA-SHA2-128s signature — no elliptic curve.
//
// Modeled on `passkey_authenticator.rs`; the verification is simpler (a raw
// pk+sig over the standard signing digest). Crypto comes from the workspace's
// `slh-dsa-sui` crate (RustCrypto `slh-dsa`), which interoperates with the
// `@sui-gen/pqc` / @noble signer (see crates/slh-dsa-sui/tests/kat.rs).

use crate::crypto::{DefaultHash, PublicKey, SignatureScheme};
use crate::signature_verification::VerifiedDigestCache;
use crate::{
    base_types::{EpochId, SuiAddress},
    digests::ZKLoginInputsDigest,
    error::{SuiError, SuiErrorKind, SuiResult},
    signature::{AuthenticatorTrait, VerifyParams},
};
use fastcrypto::error::FastCryptoError;
use fastcrypto::hash::HashFunction;
use fastcrypto::traits::ToFromBytes;
use once_cell::sync::OnceCell;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use shared_crypto::intent::IntentMessage;
use std::hash::{Hash, Hasher};
use std::sync::Arc;

pub const SLH_DSA_PK_BYTES: usize = slh_dsa_sui::PK_BYTES; // 32
pub const SLH_DSA_SIG_BYTES: usize = slh_dsa_sui::SIG_BYTES; // 7856

/// Native SLH-DSA-SHA2-128s authenticator.
///
/// Wire format (after the 1-byte `GenericSignature` scheme flag handled by
/// `GenericSignature::from_bytes`): `pk (32) || sig (7856)`.
#[derive(Debug, Clone, JsonSchema)]
pub struct SlhDsaAuthenticator {
    pk: Vec<u8>,
    sig: Vec<u8>,
    #[serde(skip)]
    bytes: OnceCell<Vec<u8>>,
}

/// Raw form used for (de)serialization: the flagged blob `flag || pk || sig`.
#[derive(Serialize, Deserialize, Debug)]
pub struct RawSlhDsaAuthenticator {
    pub pk: Vec<u8>,
    pub sig: Vec<u8>,
}

impl SlhDsaAuthenticator {
    pub fn get_pk(&self) -> SuiResult<PublicKey> {
        Ok(PublicKey::SlhDsa(self.pk.clone()))
    }
}

impl PartialEq for SlhDsaAuthenticator {
    fn eq(&self, other: &Self) -> bool {
        self.pk == other.pk && self.sig == other.sig
    }
}
impl Eq for SlhDsaAuthenticator {}
impl Hash for SlhDsaAuthenticator {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.as_ref().hash(state);
    }
}

impl AuthenticatorTrait for SlhDsaAuthenticator {
    fn verify_user_authenticator_epoch(
        &self,
        _epoch: EpochId,
        _max_epoch_upper_bound_delta: Option<u64>,
    ) -> SuiResult {
        Ok(())
    }

    fn verify_claims<T>(
        &self,
        intent_msg: &IntentMessage<T>,
        author: SuiAddress,
        _aux_verify_data: &VerifyParams,
        _zklogin_inputs_cache: Arc<VerifiedDigestCache<ZKLoginInputsDigest>>,
    ) -> SuiResult
    where
        T: Serialize,
    {
        // 1. Address must be derived from this public key.
        if author != SuiAddress::from(&self.get_pk()?) {
            return Err(SuiErrorKind::InvalidSignature {
                error: "Invalid author for SLH-DSA".to_string(),
            }
            .into());
        }

        // 2. Signing message = hash(intent || bcs(tx)) — the same digest Sui
        //    computes for every scheme.
        let message = to_signing_message(intent_msg);

        // 3. Verify the post-quantum signature (never panics; returns bool).
        if slh_dsa_sui::verify(&self.pk, &message, &self.sig) {
            Ok(())
        } else {
            Err(SuiErrorKind::InvalidSignature {
                error: "SLH-DSA signature verification failed".to_string(),
            }
            .into())
        }
    }
}

impl AsRef<[u8]> for SlhDsaAuthenticator {
    fn as_ref(&self) -> &[u8] {
        self.bytes
            .get_or_init(|| {
                let mut bytes = Vec::with_capacity(1 + self.pk.len() + self.sig.len());
                bytes.push(SignatureScheme::SlhDsa.flag());
                bytes.extend_from_slice(&self.pk);
                bytes.extend_from_slice(&self.sig);
                bytes
            })
            .as_slice()
    }
}

impl ToFromBytes for SlhDsaAuthenticator {
    fn from_bytes(bytes: &[u8]) -> Result<Self, FastCryptoError> {
        // `bytes` includes the leading scheme flag.
        if bytes.is_empty() || bytes[0] != SignatureScheme::SlhDsa.flag() {
            return Err(FastCryptoError::InvalidInput);
        }
        let body = &bytes[1..];
        if body.len() != SLH_DSA_PK_BYTES + SLH_DSA_SIG_BYTES {
            return Err(FastCryptoError::InputLengthWrong(
                1 + SLH_DSA_PK_BYTES + SLH_DSA_SIG_BYTES,
            ));
        }
        let (pk, sig) = body.split_at(SLH_DSA_PK_BYTES);
        Ok(SlhDsaAuthenticator {
            pk: pk.to_vec(),
            sig: sig.to_vec(),
            bytes: OnceCell::new(),
        })
    }
}

/// `hash(intent || bcs(tx))` — Blake2b256 (`DefaultHash`), matching every other scheme.
fn to_signing_message<T: Serialize>(
    intent_msg: &IntentMessage<T>,
) -> [u8; DefaultHash::OUTPUT_SIZE] {
    let mut hasher = DefaultHash::default();
    bcs::serialize_into(&mut hasher, intent_msg).expect("serialization should not fail");
    hasher.finalize().digest
}
