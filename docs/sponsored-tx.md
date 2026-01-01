# Sponsored transactions

A sponsored tx has two signers: the **sender** (who authorizes the action) and the **gas owner / sponsor** (who pays). Both signatures must accompany the tx.

## Pattern A: Backend gas station

User's wallet builds & signs a tx pointed at your sponsor's address. Your backend signs as the sponsor and submits both signatures.

```ts
// Wallet side
tx.setSender(userAddr);
tx.setGasOwner(sponsorAddr);
const bytes = await tx.build({ client });
const userSig = (await signer.signTransaction(bytes)).signature;
POST /sponsor { txBytes: toB64(bytes), userSignature: userSig };

// Backend
import { sponsorAndExecute } from '@sui-gen/sponsored-tx';
return sponsorAndExecute(client, sponsorSigner, txBytes, userSignature);
```

## Pattern B: Atomic flow with a hosted Gas Station

If you use a Mysten-style gas station (e.g. Shinami, Enoki), the wallet sends an unsigned tx → the gas station fills gas coins → returns a signed tx the wallet then countersigns and submits.

## Safety

- **Authorization scope.** The sponsor signs *all* commands in the tx. Never blindly sign whatever the user sends — your backend must inspect the `TransactionData` and reject anything outside your allowlisted package calls.
- **Replay.** Each gas object can be used at most once; pre-split a pool of small gas coins on the sponsor's account to avoid contention.
- **Rate limiting.** Throttle per user (zkLogin sub, JWT, wallet address) — sponsored gas is your money.
