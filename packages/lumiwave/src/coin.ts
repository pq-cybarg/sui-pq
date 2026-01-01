/**
 * LWA coin helpers — balance lookup, transfers, and metadata.
 * Generic enough that this works for any Sui Coin<T>; we just default T to LWA.
 */
import type { SuiClient } from '@mysten/sui/client';
import { Transaction } from '@mysten/sui/transactions';
import { type Network, getClient } from '@sui-gen/sdk-core';
import { DEFAULT_LUMIWAVE_CONFIG } from './config.js';

export interface BalanceOptions {
  coinType?: string;
  network?: Network;
  client?: SuiClient;
}

export async function getLwaBalance(address: string, opts: BalanceOptions = {}): Promise<bigint> {
  const client = opts.client ?? getClient({ network: opts.network });
  const coinType = opts.coinType ?? DEFAULT_LUMIWAVE_CONFIG.coinType;
  const { totalBalance } = await client.getBalance({ owner: address, coinType });
  return BigInt(totalBalance);
}

export interface TransferOptions extends BalanceOptions {
  /** Sender — needed to look up the coin objects to merge. */
  from: string;
  /** Recipient address. */
  to: string;
  /** Amount in base units. */
  amount: bigint;
}

/**
 * Build a Transaction that sends `amount` of `coinType` from `from` → `to`.
 * Merges all sender coins of the type and then splits off the payment.
 */
export async function buildLwaTransfer(opts: TransferOptions): Promise<Transaction> {
  const client = opts.client ?? getClient({ network: opts.network });
  const coinType = opts.coinType ?? DEFAULT_LUMIWAVE_CONFIG.coinType;

  const coins = await client.getCoins({ owner: opts.from, coinType });
  if (coins.data.length === 0) throw new Error(`No ${coinType} coins owned by ${opts.from}`);

  const tx = new Transaction();
  const [primary, ...rest] = coins.data;
  const primaryRef = tx.object(primary!.coinObjectId);
  if (rest.length > 0) {
    tx.mergeCoins(
      primaryRef,
      rest.map((c) => tx.object(c.coinObjectId)),
    );
  }
  const [payment] = tx.splitCoins(primaryRef, [opts.amount]);
  tx.transferObjects([payment], opts.to);
  return tx;
}

/** Fetch on-chain coin metadata (decimals, symbol, name). */
export async function getLwaMetadata(opts: BalanceOptions = {}) {
  const client = opts.client ?? getClient({ network: opts.network });
  const coinType = opts.coinType ?? DEFAULT_LUMIWAVE_CONFIG.coinType;
  return client.getCoinMetadata({ coinType });
}
