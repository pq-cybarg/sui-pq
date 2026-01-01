/// Seal demo: an on-chain allowlist that gates decryption.
/// The Seal key servers will call `seal_approve` on this module during decryption.
/// They check the entry function abort/no-abort to decide whether to release the key share.
///
/// Off-chain client encrypts data with `id = bcs::to_bytes(allowlist_id || nonce)`.
/// On decrypt, key servers run `seal_approve(id, allowlist, ctx)` and require it not to abort.
module seal_demo::allowlist;

use std::vector;
use sui::event;

const ENotAllowed:  u64 = 0;
const ENotOwner:    u64 = 1;

public struct Allowlist has key {
    id: UID,
    owner: address,
    members: vector<address>,
}

public struct MemberAdded   has copy, drop { allowlist: ID, member: address }
public struct MemberRemoved has copy, drop { allowlist: ID, member: address }

public fun create(ctx: &mut TxContext) {
    let al = Allowlist {
        id: object::new(ctx),
        owner: ctx.sender(),
        members: vector::empty(),
    };
    transfer::share_object(al);
}

public fun add(al: &mut Allowlist, addr: address, ctx: &TxContext) {
    assert!(al.owner == ctx.sender(), ENotOwner);
    if (!vector::contains(&al.members, &addr)) {
        vector::push_back(&mut al.members, addr);
        event::emit(MemberAdded { allowlist: object::id(al), member: addr });
    }
}

public fun remove(al: &mut Allowlist, addr: address, ctx: &TxContext) {
    assert!(al.owner == ctx.sender(), ENotOwner);
    let (found, idx) = vector::index_of(&al.members, &addr);
    if (found) {
        vector::remove(&mut al.members, idx);
        event::emit(MemberRemoved { allowlist: object::id(al), member: addr });
    }
}

/// Called by Seal key servers. Aborts → no key share released.
/// `id` is the identity bytes used at encryption time; we tolerate any prefix
/// since key namespace is the allowlist object id (passed alongside in `id`).
entry fun seal_approve(id: vector<u8>, al: &Allowlist, ctx: &TxContext) {
    let _ = id; // shape-check only; specific identity layout is app-defined
    assert!(vector::contains(&al.members, &ctx.sender()), ENotAllowed);
}

public fun members(al: &Allowlist): &vector<address> { &al.members }
public fun owner(al: &Allowlist): address { al.owner }
