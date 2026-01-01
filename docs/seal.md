# Seal

Seal is Mysten Labs' decentralized secrets management protocol. Data is encrypted to an *identity* (an arbitrary byte string), and only released when a quorum of independently-operated key servers run a user-specified Move function `seal_approve(id, …)` that *does not abort*.

## End-to-end flow

```
  ┌───────────┐    ciphertext     ┌────────────────┐
  │  Encrypt  │ ─────────────►   │  Anywhere (e.g. │
  │  client   │                  │  Walrus, IPFS)  │
  └───────────┘                  └────────────────┘

  ┌───────────┐  SessionKey + tx  ┌──────────────────┐
  │  Decrypt  │ ─────────────► … │  Seal key servers │ × N
  │  client   │  shares          │  run seal_approve │
  └───────────┘ ◄───────────── … └──────────────────┘
        │
        ▼
    plaintext  (combined ≥ threshold)
```

## Move side

In your package, write an entry function that **reads** state and aborts on access denial:

```move
entry fun seal_approve(id: vector<u8>, al: &Allowlist, ctx: &TxContext) {
    assert!(vector::contains(&al.members, &ctx.sender()), ENotAllowed);
}
```

See `move/seal_demo/sources/allowlist.move` for the reference shape.

## TS side

```ts
import { createSealClient, makeIdentity, SessionKey } from '@sui-gen/seal-client';
import { Transaction } from '@mysten/sui/transactions';

const seal = createSealClient({ network: 'testnet' });
const id = makeIdentity(packageId, allowlistId);

const ciphertext = await seal.encrypt({
  threshold: 2,
  packageId,
  id,
  data: new TextEncoder().encode('secret'),
});

// later, in the user's wallet…
const sessionKey = await SessionKey.create({
  address,
  packageId,
  ttlMin: 10,
  suiClient,
});
// have the user sign sessionKey.getPersonalMessage()
await sessionKey.setPersonalMessageSignature(userSig);

const tx = new Transaction();
tx.moveCall({
  target: `${packageId}::allowlist::seal_approve`,
  arguments: [tx.pure.vector('u8', id), tx.object(allowlistId)],
});

const plaintext = await seal.decrypt({
  data: ciphertext,
  sessionKey,
  txBytes: await tx.build({ client: suiClient, onlyTransactionKind: true }),
});
```

## Identity discipline

Always include the namespace (e.g. the `allowlistId`) in the identity bytes — otherwise a key server might release a key for a *different* object that happens to share the same `seal_approve` signature.
