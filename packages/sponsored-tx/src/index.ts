import type { SuiClient } from '@mysten/sui/client';
import type { Signer } from '@mysten/sui/cryptography';
/**
 * Sponsored transactions: a third party (the sponsor) pays the gas while the user
 * authorizes the actual operation. Two flows are supported:
 *
 *  • GasStation (Mysten Labs hosted): your backend has a SUI-funded sponsor key and
 *    co-signs every tx. Wallet sends `txBytes`, sponsor returns `signature`.
 *  • Sui's protocol-native sponsored tx: build tx with `gasOwner`, both parties sign,
 *    submit with both signatures.
 */
import type { Transaction } from '@mysten/sui/transactions';
import { type Network, getClient } from '@sui-gen/sdk-core';

export interface BuildSponsoredOptions {
  client?: SuiClient;
  network?: Network;
  /** User who initiated the action — pays for nothing, but authorises. */
  sender: string;
  /** Sponsor pays gas. */
  sponsor: string;
  /** Gas budget in MIST. */
  gasBudget?: bigint;
}

/** Resolve gas + freeze a Transaction's tx-data, ready for both parties to sign. */
export async function buildSponsoredTxBytes(
  tx: Transaction,
  opts: BuildSponsoredOptions,
): Promise<Uint8Array> {
  const client = opts.client ?? getClient({ network: opts.network });

  tx.setSender(opts.sender);
  tx.setGasOwner(opts.sponsor);
  if (opts.gasBudget !== undefined) tx.setGasBudget(opts.gasBudget);

  // Sponsor selects gas coins. The wallet provides nothing; the sponsor's signer
  // is expected to back this — `selectCoins` happens on the sponsor side, so we
  // leave the gas payment unset and let the sponsor fill it in just before signing.
  return await tx.build({ client });
}

export interface ExecuteSponsoredOptions {
  client?: SuiClient;
  network?: Network;
  /** Tx-bytes serialized by `buildSponsoredTxBytes`. */
  txBytes: Uint8Array;
  /** Signature from the user (sender). */
  userSignature: string;
  /** Signature from the sponsor (gas owner). */
  sponsorSignature: string;
}

export async function executeSponsoredTx(opts: ExecuteSponsoredOptions) {
  const client = opts.client ?? getClient({ network: opts.network });
  return await client.executeTransactionBlock({
    transactionBlock: opts.txBytes,
    signature: [opts.userSignature, opts.sponsorSignature],
    options: { showEffects: true, showEvents: true },
  });
}

/**
 * Convenience for fully-server-side sponsored flow: the sponsor signs the tx-bytes
 * a wallet sent and submits with both signatures.
 */
export async function sponsorAndExecute(
  client: SuiClient,
  sponsor: Signer,
  txBytes: Uint8Array,
  userSignature: string,
) {
  const sponsorSig = (await sponsor.signTransaction(txBytes)).signature;
  return client.executeTransactionBlock({
    transactionBlock: txBytes,
    signature: [userSignature, sponsorSig],
    options: { showEffects: true, showEvents: true },
  });
}
