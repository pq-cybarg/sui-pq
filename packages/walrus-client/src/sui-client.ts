/**
 * Wallet-backed Walrus client. Uses @mysten/walrus to interact with the on-chain
 * Walrus system object directly, paying for storage with the signer's WAL.
 * Use this when the dApp (not a public publisher) is paying.
 */
import { WalrusClient as Inner } from '@mysten/walrus';
import { NETWORKS, type Network } from '@sui-gen/sdk-core';

export interface CreateOptions {
  network?: Network;
  /** Override the underlying Sui RPC. Defaults to the standard full-node URL. */
  suiRpcUrl?: string;
}

export function createWalrusClient(opts: CreateOptions = {}) {
  const network = opts.network ?? 'testnet';
  const suiRpcUrl = opts.suiRpcUrl ?? process.env.SUI_RPC_URL ?? NETWORKS[network].url;

  return new Inner({
    network: network === 'mainnet' ? 'mainnet' : 'testnet',
    suiRpcUrl,
  });
}

export { Inner as WalrusClient };
