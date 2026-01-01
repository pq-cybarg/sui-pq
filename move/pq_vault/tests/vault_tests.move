#[test_only]
module pq_vault::vault_tests;

use sui::coin::{Self, Coin};
use sui::sui::SUI;
use sui::test_scenario as ts;
use pq_guard::pq_guard;
use pq_vault::vault::{Self, Vault};

const ALICE: address = @0xA;
const BOB:   address = @0xB;

fun mint_sui(amount: u64, scenario: &mut ts::Scenario): Coin<SUI> {
    coin::mint_for_testing<SUI>(amount, scenario.ctx())
}

#[test]
fun open_then_pq_authorized_withdraw_succeeds() {
    let mut scenario = ts::begin(ALICE);
    let seed = mint_sui(10_000, &mut scenario);
    vault::open(seed, scenario.ctx());

    scenario.next_tx(ALICE);
    let mut v = scenario.take_shared<Vault>();
    assert!(vault::balance(&v) == 10_000, 0);

    // Compute the matching action_digest, then forge a PqAuthorized as if
    // SLH-DSA had verified successfully (the pq_guard tests prove that path).
    let action = vault::withdraw_action_digest(&v, BOB, 2_500);
    let auth = pq_guard::test_only_forge_authorized(
        object::id(&v),
        ALICE,
        0,
        action,
    );

    let payout = vault::withdraw(&mut v, auth, BOB, 2_500, scenario.ctx());
    assert!(coin::value(&payout) == 2_500, 1);
    assert!(vault::balance(&v) == 7_500, 2);

    transfer::public_transfer(payout, BOB);
    ts::return_shared(v);
    scenario.end();
}

#[test]
#[expected_failure(abort_code = pq_vault::vault::EWrongSender)]
fun rejects_witness_whose_sender_is_not_ctx_sender() {
    let mut scenario = ts::begin(ALICE);
    let seed = mint_sui(1_000, &mut scenario);
    vault::open(seed, scenario.ctx());

    scenario.next_tx(ALICE);
    let mut v = scenario.take_shared<Vault>();
    let action = vault::withdraw_action_digest(&v, BOB, 100);
    // Witness claims BOB signed it, but the tx sender is ALICE → reject.
    let auth = pq_guard::test_only_forge_authorized(object::id(&v), BOB, 0, action);
    let _payout = vault::withdraw(&mut v, auth, BOB, 100, scenario.ctx());
    abort 99
}

#[test]
#[expected_failure(abort_code = pq_vault::vault::EWrongAction)]
fun rejects_witness_signing_a_different_action() {
    let mut scenario = ts::begin(ALICE);
    let seed = mint_sui(1_000, &mut scenario);
    vault::open(seed, scenario.ctx());

    scenario.next_tx(ALICE);
    let mut v = scenario.take_shared<Vault>();
    // Witness commits to (to=BOB, amount=50) but the call asks for amount=500.
    let other_action = vault::withdraw_action_digest(&v, BOB, 50);
    let auth = pq_guard::test_only_forge_authorized(object::id(&v), ALICE, 0, other_action);
    let _payout = vault::withdraw(&mut v, auth, BOB, 500, scenario.ctx());
    abort 99
}

#[test]
#[expected_failure(abort_code = pq_vault::vault::ENotOwner)]
fun non_owner_cannot_withdraw_even_with_witness() {
    let mut scenario = ts::begin(ALICE);
    let seed = mint_sui(1_000, &mut scenario);
    vault::open(seed, scenario.ctx());

    scenario.next_tx(BOB);  // BOB is now the tx sender, but ALICE opened the vault
    let mut v = scenario.take_shared<Vault>();
    let action = vault::withdraw_action_digest(&v, BOB, 100);
    let auth = pq_guard::test_only_forge_authorized(object::id(&v), BOB, 0, action);
    let _payout = vault::withdraw(&mut v, auth, BOB, 100, scenario.ctx());
    abort 99
}
