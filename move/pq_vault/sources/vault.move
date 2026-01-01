/// Example PQ-gated app: a token vault that requires a post-quantum
/// authorization for every withdrawal.
///
/// The user's classical key authorizes the outer transaction (and pays gas).
/// The vault's `withdraw` function ALSO requires a `PqAuthorized` witness,
/// which means the same atomic transaction must produce a valid SLH-DSA proof
/// against the holder's `PqIdentity`. Without that witness the transaction
/// can never construct the call.
///
/// The witness binds:
///   - **sender** — must match the address calling `withdraw`
///   - **action_digest** — must match `H(target || amount)` so a signature
///     for "withdraw 100 SUI to A" can't be reused as "withdraw 100 SUI to B"
///
/// This achieves PQ tx authorization at the smart-contract layer, without any
/// validator-side change. The classical signature on the outer tx is just a
/// gas-paying trampoline.
module pq_vault::vault;

use std::hash;
use sui::coin::{Self, Coin};
use sui::event;
use sui::sui::SUI;
use pq_guard::pq_guard::{Self as guard, PqAuthorized};

public struct Vault has key {
    id: UID,
    /// The Sui address whose `PqIdentity` controls this vault.
    owner: address,
    /// The SUI balance currently held inside the vault.
    balance: u64,
    /// Pool of coins; merged on each deposit.
    pool: Coin<SUI>,
}

public struct Deposited has copy, drop { vault: ID, amount: u64 }
public struct Withdrew  has copy, drop { vault: ID, to: address, amount: u64, pq_nonce: u64 }

const ENotOwner:     u64 = 1;
const EWrongAction:  u64 = 2;
const EWrongSender:  u64 = 3;
const EInsufficient: u64 = 4;

// ── lifecycle ─────────────────────────────────────────────────────────────

public fun open(seed: Coin<SUI>, ctx: &mut TxContext) {
    let amount = coin::value(&seed);
    let v = Vault {
        id: object::new(ctx),
        owner: ctx.sender(),
        balance: amount,
        pool: seed,
    };
    let vid = object::id(&v);
    event::emit(Deposited { vault: vid, amount });
    transfer::share_object(v);
}

public fun deposit(vault: &mut Vault, top_up: Coin<SUI>) {
    let amount = coin::value(&top_up);
    coin::join(&mut vault.pool, top_up);
    vault.balance = vault.balance + amount;
    event::emit(Deposited { vault: object::id(vault), amount });
}

// ── PQ-gated withdraw ─────────────────────────────────────────────────────

/// Build the action_digest the user signs off-chain when authorizing a
/// withdrawal. Stable across implementations:
///   sha256(b"PQ_VAULT:WITHDRAW:v1" || vault_id (32) || to (32) || amount (8 BE))
public fun withdraw_action_digest(vault: &Vault, to: address, amount: u64): vector<u8> {
    let mut buf = vector::empty<u8>();
    append(&mut buf, &b"PQ_VAULT:WITHDRAW:v1");
    append(&mut buf, &object::id(vault).to_bytes());
    append(&mut buf, &sui::address::to_bytes(to));
    append(&mut buf, &u64_be(amount));
    hash::sha2_256(buf)
}

/// PQ-gated withdrawal. The `PqAuthorized` witness must:
///   - have `sender == ctx.sender()` (no impersonation)
///   - have `action_digest == withdraw_action_digest(vault, to, amount)` so
///     the same signature can't authorize a different recipient or amount
///
/// Without those, the call aborts. Combined with `slh_dsa::verify` inside
/// `pq_guard::unlock`, this is full PQ authorization for the operation —
/// the validator's classical signature check is only authenticating the
/// gas payer, not the actual authority.
public fun withdraw(
    vault: &mut Vault,
    auth: PqAuthorized,
    to: address,
    amount: u64,
    ctx: &mut TxContext,
): Coin<SUI> {
    assert!(vault.owner == ctx.sender(), ENotOwner);
    assert!(guard::sender(&auth) == ctx.sender(), EWrongSender);

    let expected = withdraw_action_digest(vault, to, amount);
    assert!(guard::action_digest(&auth) == &expected, EWrongAction);

    assert!(vault.balance >= amount, EInsufficient);
    vault.balance = vault.balance - amount;

    let pq_nonce = guard::nonce(&auth);
    guard::consume(auth); // single-use witness

    event::emit(Withdrew { vault: object::id(vault), to, amount, pq_nonce });
    coin::split(&mut vault.pool, amount, ctx)
}

// ── views ─────────────────────────────────────────────────────────────────
public fun balance(v: &Vault): u64 { v.balance }
public fun owner(v: &Vault): address { v.owner }

// ── helpers ───────────────────────────────────────────────────────────────
fun append(dst: &mut vector<u8>, src: &vector<u8>) {
    let mut i = 0; let n = vector::length(src);
    while (i < n) { vector::push_back(dst, *vector::borrow(src, i)); i = i + 1 }
}

fun u64_be(v: u64): vector<u8> {
    let mut out = vector::empty<u8>();
    let mut i: u64 = 0;
    while (i < 8) {
        let shift = (7 - i) * 8;
        vector::push_back(&mut out, (((v >> (shift as u8)) & 0xff) as u8));
        i = i + 1;
    };
    out
}
