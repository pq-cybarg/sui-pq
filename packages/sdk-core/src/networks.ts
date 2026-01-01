import { getFullnodeUrl } from '@mysten/sui/client';

export type Network = 'mainnet' | 'testnet' | 'devnet' | 'localnet';

export const NETWORKS: Record<Network, { url: string; faucet?: string; explorer: string }> = {
  mainnet: {
    url: getFullnodeUrl('mainnet'),
    explorer: 'https://suiscan.xyz/mainnet',
  },
  testnet: {
    url: getFullnodeUrl('testnet'),
    faucet: 'https://faucet.testnet.sui.io/v2/gas',
    explorer: 'https://suiscan.xyz/testnet',
  },
  devnet: {
    url: getFullnodeUrl('devnet'),
    faucet: 'https://faucet.devnet.sui.io/v2/gas',
    explorer: 'https://suiscan.xyz/devnet',
  },
  localnet: {
    url: 'http://127.0.0.1:9000',
    faucet: 'http://127.0.0.1:9123/v2/gas',
    explorer: 'http://localhost:9001',
  },
};

export function resolveNetwork(input?: string): Network {
  const value = (input ?? process.env.SUI_NETWORK ?? 'testnet').toLowerCase();
  if (value in NETWORKS) return value as Network;
  throw new Error(`Unknown network: ${value}`);
}
