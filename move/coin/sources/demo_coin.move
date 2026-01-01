/// A regulated-style coin with `TreasuryCap`-gated mint/burn.
/// Pattern: one-time witness DEMO_COIN → `coin::create_currency` → freeze metadata + transfer cap.
module demo_coin::demo_coin;

use sui::coin::{Self, Coin, TreasuryCap};
use sui::url;

const DECIMALS: u8 = 9;
const SYMBOL:   vector<u8> = b"DEMO";
const NAME:     vector<u8> = b"Demo Coin";
const DESCRIPTION: vector<u8> = b"Reference custom token for the sui-gen workspace";
const ICON_URL: vector<u8> = b"https://example.com/demo-coin.png";

public struct DEMO_COIN has drop {}

// `coin::create_currency` is the established TreasuryCap pattern. The framework
// now also offers `coin_registry::new_currency_with_otw`; this reference coin
// intentionally keeps the simpler create_currency flow.
#[allow(deprecated_usage)]
fun init(witness: DEMO_COIN, ctx: &mut TxContext) {
    let (treasury, metadata) = coin::create_currency(
        witness,
        DECIMALS,
        SYMBOL,
        NAME,
        DESCRIPTION,
        option::some(url::new_unsafe_from_bytes(ICON_URL)),
        ctx,
    );
    transfer::public_freeze_object(metadata);
    transfer::public_transfer(treasury, ctx.sender());
}

public fun mint(cap: &mut TreasuryCap<DEMO_COIN>, amount: u64, recipient: address, ctx: &mut TxContext) {
    let coins = coin::mint(cap, amount, ctx);
    transfer::public_transfer(coins, recipient);
}

public fun burn(cap: &mut TreasuryCap<DEMO_COIN>, c: Coin<DEMO_COIN>) {
    coin::burn(cap, c);
}

#[test_only]
public fun init_for_testing(ctx: &mut TxContext) {
    init(DEMO_COIN {}, ctx);
}
