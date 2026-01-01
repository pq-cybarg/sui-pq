/// Example of using Sui's Kiosk primitive: a marketplace listing rule.
/// Pairs with a TransferPolicy to enforce a flat 2% royalty on resale.
module marketplace_kiosk::marketplace;

use sui::coin::{Self, Coin};
use sui::sui::SUI;
use sui::transfer_policy::{Self, TransferPolicy, TransferRequest, TransferPolicyCap};

const ROYALTY_BPS: u16 = 200; // 2%

public struct Royalty has drop {}

public struct RoyaltyConfig has store, drop {
    bps: u16,
    recipient: address,
}

public fun add_rule<T: key + store>(
    policy: &mut TransferPolicy<T>,
    cap: &TransferPolicyCap<T>,
    recipient: address,
) {
    transfer_policy::add_rule(
        Royalty {},
        policy,
        cap,
        RoyaltyConfig { bps: ROYALTY_BPS, recipient },
    );
}

public fun pay<T: key + store>(
    policy: &mut TransferPolicy<T>,
    request: &mut TransferRequest<T>,
    payment: Coin<SUI>,
) {
    let cfg: &RoyaltyConfig = transfer_policy::get_rule(Royalty {}, policy);
    let owed = ((transfer_policy::paid(request) as u128) * (cfg.bps as u128) / 10_000) as u64;
    assert!(coin::value(&payment) >= owed, 0);
    transfer::public_transfer(payment, cfg.recipient);
    transfer_policy::add_receipt(Royalty {}, request);
}
