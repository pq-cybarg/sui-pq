#[test_only]
module counter::counter_tests;

use counter::counter::{Self, Counter};
use sui::test_scenario as ts;

const ALICE: address = @0xA;
const BOB:   address = @0xB;

#[test]
fun increment_and_reset() {
    let mut scenario = ts::begin(ALICE);
    counter::create(scenario.ctx());

    scenario.next_tx(ALICE);
    let mut c = scenario.take_shared<Counter>();
    counter::increment(&mut c, scenario.ctx());
    counter::increment(&mut c, scenario.ctx());
    assert!(counter::value(&c) == 2, 0);
    counter::reset(&mut c, scenario.ctx());
    assert!(counter::value(&c) == 0, 1);
    ts::return_shared(c);
    scenario.end();
}

#[test]
#[expected_failure(abort_code = counter::ENotOwner)]
fun reset_requires_owner() {
    let mut scenario = ts::begin(ALICE);
    counter::create(scenario.ctx());
    scenario.next_tx(BOB);
    let mut c = scenario.take_shared<Counter>();
    counter::reset(&mut c, scenario.ctx());
    ts::return_shared(c);
    scenario.end();
}
