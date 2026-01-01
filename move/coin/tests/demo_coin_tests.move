#[test_only]
module demo_coin::demo_coin_tests;

use demo_coin::demo_coin::{Self, DEMO_COIN};
use sui::coin::{Self, Coin, TreasuryCap};
use sui::test_scenario as ts;

const ADMIN: address = @0xA;
const USER:  address = @0xB;

#[test]
fun mint_then_burn() {
    let mut scenario = ts::begin(ADMIN);
    demo_coin::init_for_testing(scenario.ctx());

    scenario.next_tx(ADMIN);
    let mut cap = scenario.take_from_sender<TreasuryCap<DEMO_COIN>>();
    demo_coin::mint(&mut cap, 1_000_000, USER, scenario.ctx());

    scenario.next_tx(USER);
    let user_coin = scenario.take_from_sender<Coin<DEMO_COIN>>();
    assert!(coin::value(&user_coin) == 1_000_000, 0);

    scenario.next_tx(ADMIN);
    demo_coin::burn(&mut cap, user_coin);
    scenario.return_to_sender(cap);
    scenario.end();
}
