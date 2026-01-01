#[test_only]
module pq_attestation::registry_tests;

use pq_attestation::registry::{Self, Attestation};
use sui::test_scenario as ts;

const ALICE: address = @0xA;
const BOB:   address = @0xB;

// A 32-byte digest is required by `register`.
const DIGEST_32: vector<u8> = vector[
    0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
    0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00,
    0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
    0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00,
];

#[test]
fun register_then_revoke() {
    let mut scenario = ts::begin(ALICE);
    // ML-DSA-44 scheme byte = 0x10
    registry::register(
        0x10,
        vector[0xaa, 0xbb, 0xcc],
        vector[0x01, 0x02, 0x03],
        DIGEST_32,
        vector[0xde, 0xad, 0xbe, 0xef],
        b"unit-test",
        scenario.ctx(),
    );

    scenario.next_tx(ALICE);
    let att = scenario.take_from_sender<Attestation>();
    assert!(registry::owner(&att) == ALICE, 0);
    assert!(registry::scheme(&att) == 0x10, 1);
    registry::revoke(att, scenario.ctx());

    scenario.end();
}

#[test]
#[expected_failure(abort_code = pq_attestation::registry::ENotOwner)]
fun revoke_requires_owner() {
    let mut scenario = ts::begin(ALICE);
    registry::register(
        0x10,
        vector[0xaa],
        vector[0x01],
        DIGEST_32,
        vector[],
        b"x",
        scenario.ctx(),
    );

    scenario.next_tx(BOB);
    let att = ts::take_from_address<Attestation>(&scenario, ALICE);
    registry::revoke(att, scenario.ctx());

    scenario.end();
}

#[test]
#[expected_failure(abort_code = pq_attestation::registry::EBadDigestLen)]
fun rejects_wrong_digest_length() {
    let mut scenario = ts::begin(ALICE);
    registry::register(
        0x10,
        vector[],
        vector[],
        vector[0xaa, 0xbb], // 2 bytes, not 32
        vector[],
        b"x",
        scenario.ctx(),
    );
    scenario.end();
}
