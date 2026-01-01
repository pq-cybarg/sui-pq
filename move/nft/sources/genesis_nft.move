/// A minimal NFT with Display + transfer support.
/// Demonstrates one-time witness + Publisher + Display, the canonical Sui NFT pattern.
module nft::genesis_nft;

use std::string::{Self, String};
use sui::display;
use sui::event;
use sui::package;
use sui::url::{Self, Url};

public struct GenesisNFT has key, store {
    id: UID,
    name: String,
    description: String,
    image_url: Url,
    creator: address,
}

public struct Minted   has copy, drop { id: ID, recipient: address, name: String }
public struct Burned   has copy, drop { id: ID, by: address }

/// One-time witness — exactly one instance, created in `init`.
public struct GENESIS_NFT has drop {}

fun init(otw: GENESIS_NFT, ctx: &mut TxContext) {
    let publisher = package::claim(otw, ctx);
    let keys = vector[
        b"name".to_string(),
        b"description".to_string(),
        b"image_url".to_string(),
        b"creator".to_string(),
    ];
    let values = vector[
        b"{name}".to_string(),
        b"{description}".to_string(),
        b"{image_url}".to_string(),
        b"{creator}".to_string(),
    ];
    let mut disp = display::new_with_fields<GenesisNFT>(&publisher, keys, values, ctx);
    disp.update_version();

    transfer::public_transfer(publisher, ctx.sender());
    transfer::public_transfer(disp, ctx.sender());
}

public fun mint(
    name: vector<u8>,
    description: vector<u8>,
    image_url: vector<u8>,
    recipient: address,
    ctx: &mut TxContext,
) {
    let nft = GenesisNFT {
        id: object::new(ctx),
        name: string::utf8(name),
        description: string::utf8(description),
        image_url: url::new_unsafe_from_bytes(image_url),
        creator: ctx.sender(),
    };
    event::emit(Minted { id: object::id(&nft), recipient, name: nft.name });
    transfer::public_transfer(nft, recipient);
}

public fun burn(nft: GenesisNFT, ctx: &TxContext) {
    let GenesisNFT { id, name: _, description: _, image_url: _, creator: _ } = nft;
    event::emit(Burned { id: id.to_inner(), by: ctx.sender() });
    id.delete();
}

public fun name(n: &GenesisNFT): &String { &n.name }
public fun description(n: &GenesisNFT): &String { &n.description }
public fun image_url(n: &GenesisNFT): &Url { &n.image_url }
public fun creator(n: &GenesisNFT): address { n.creator }
