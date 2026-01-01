/// Minimal shared-object counter. Anyone can `increment`; only the creator can `reset`.
module counter::counter;

use sui::event;

public struct Counter has key {
    id: UID,
    owner: address,
    value: u64,
}

public struct Incremented has copy, drop { counter: ID, value: u64, by: address }
public struct Reset       has copy, drop { counter: ID, by: address }

const ENotOwner: u64 = 0;

public fun create(ctx: &mut TxContext) {
    let counter = Counter { id: object::new(ctx), owner: ctx.sender(), value: 0 };
    transfer::share_object(counter);
}

public fun increment(c: &mut Counter, ctx: &TxContext) {
    c.value = c.value + 1;
    event::emit(Incremented { counter: object::id(c), value: c.value, by: ctx.sender() });
}

public fun reset(c: &mut Counter, ctx: &TxContext) {
    assert!(c.owner == ctx.sender(), ENotOwner);
    c.value = 0;
    event::emit(Reset { counter: object::id(c), by: ctx.sender() });
}

public fun value(c: &Counter): u64 { c.value }
public fun owner(c: &Counter): address { c.owner }
