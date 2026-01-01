#[test_only]
module nft::nft_tests;

use nft::genesis_nft::{Self, GenesisNFT};
use sui::test_scenario as ts;

const ALICE: address = @0xA;
const BOB:   address = @0xB;

#[test]
fun mint_then_transfer_chain() {
    let mut scenario = ts::begin(ALICE);
    genesis_nft::mint(
        b"Hello",
        b"world",
        b"https://example.com/img.png",
        BOB,
        scenario.ctx(),
    );

    scenario.next_tx(BOB);
    let nft = scenario.take_from_sender<GenesisNFT>();
    assert!(genesis_nft::creator(&nft) == ALICE, 0);
    genesis_nft::burn(nft, scenario.ctx());
    scenario.end();
}
