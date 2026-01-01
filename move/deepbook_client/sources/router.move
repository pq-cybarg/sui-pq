/// A thin wrapper module showing how to call into DeepBook V3 from another package.
/// Real integrations import the deployed `deepbook` package as a dependency in Move.toml
/// and invoke `pool::place_limit_order`, `pool::swap_exact_amount`, etc.
/// This file is intentionally skeletal — fill in once you've pinned a DeepBook version.
module deepbook_client::router;

use sui::coin::Coin;

/// Placeholder: in real code, parameterize on Base/Quote currency types and the Pool object.
public fun describe(): vector<u8> {
    b"deepbook_client::router — wire to deepbook::pool::* in production"
}

/// Example signature you'd expose, accepting a coin and routing through DeepBook.
public fun route<Base>(input: Coin<Base>): Coin<Base> {
    // Intentionally a no-op pass-through. Replace with real DeepBook swap
    // (which would add a `Quote` type parameter and return `Coin<Quote>`).
    input
}
