# Move conventions

This workspace follows Sui's **Move 2024.beta** edition. Notable conventions:

## Modules

```move
module pkg::name;   // not `module pkg::name { … }` — flat form
```

## Objects vs values

- `UID` (unique on-chain id) is created by `object::new(ctx)`.
- Owned objects: `transfer::transfer(obj, addr)`.
- Shared objects: `transfer::share_object(obj)`.
- Frozen objects: `transfer::freeze_object(obj)`.

## Standard patterns

| Pattern | Demo |
| --- | --- |
| Shared counter w/ owner authz   | `move/counter` |
| One-time witness → Display      | `move/nft` |
| Custom coin w/ TreasuryCap      | `move/coin` |
| Kiosk royalty TransferPolicy    | `move/kiosk` |
| `seal_approve` access gate      | `move/seal_demo` |
| DeepBook integration scaffold   | `move/deepbook_client` |

## Tests

Use `sui::test_scenario` for multi-tx flows. Keep test addresses readable (`@0xA`, `@0xB`).
For one-time-witness modules, expose a `#[test_only] public fun init_for_testing(ctx)` so
tests can bypass the genesis-only witness restriction.

## Publishing

```bash
sui client publish --gas-budget 200000000 ./move/counter
```

Capture the `packageId` from the output and plumb it into `.env`. The CLI command
`pnpm cli publish move/counter` runs this for you.
