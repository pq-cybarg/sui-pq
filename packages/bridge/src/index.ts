/**
 * Bridge helpers for moving assets to/from Sui.
 *
 *  • Sui Bridge — first-party bridge between Ethereum & Sui, run by Sui validators.
 *  • Wormhole   — generic message-passing protocol; covers many chains, used for
 *                 Wormhole-wrapped assets and Portal Bridge.
 *
 * On-chain operations differ; this module gives you the constants + URLs and a small
 * helper for tracking transfers via Wormhole's VAA pipeline.
 */
import { Transaction } from '@mysten/sui/transactions';

export const SUI_BRIDGE = {
  mainnet: {
    packageId: '0xb', // Sui Bridge runs at framework-reserved address 0xb
    bridgeObjectId: '0x9a5e8e3f4dba9c66e1bb2ad6e21e9c2b8d4dc6b3b9a1f4a4c8a4b1d2c9a3f0b1d', // placeholder
  },
  testnet: {
    packageId: '0xb',
    bridgeObjectId: '0x',
  },
} as const;

export const WORMHOLE = {
  mainnet: {
    coreBridge: '0xaeab97f96cf9877fee2883315d459552b2b921edc16d7ceac6eab944dd88919c',
    tokenBridge: '0xc57508ee0d4595e5a8728974a4a93a787d38f339757230d441e895422c07aba9',
    guardianRpc: 'https://wormhole-v2-mainnet-api.certus.one',
  },
  testnet: {
    coreBridge: '0x31358d198147da50db32eda2562951d53973a0c0ad5ed738e9b17d88b213d790',
    tokenBridge: '0x6fb10cdb7aa299e9a4308752dadecb049ff55a892de92992a1edbd7912b3d6da',
    guardianRpc: 'https://wormhole-v2-testnet-api.certus.one',
  },
} as const;

/** Construct a transfer-out tx via Wormhole token bridge (placeholder skeleton). */
export function buildWormholeTransferOutSkeleton(): Transaction {
  return new Transaction();
}

/** Poll for a Wormhole VAA (Verified Action Approval) after origin-chain confirmation. */
export async function fetchVaa(
  emitterChain: number,
  emitterAddress: string,
  sequence: string,
  guardianRpc = WORMHOLE.mainnet.guardianRpc,
): Promise<Uint8Array> {
  const url = `${guardianRpc}/v1/signed_vaa/${emitterChain}/${emitterAddress}/${sequence}`;
  const res = await fetch(url);
  if (!res.ok) throw new Error(`VAA fetch failed: ${res.status}`);
  const json = (await res.json()) as { vaaBytes: string };
  return Uint8Array.from(atob(json.vaaBytes), (c) => c.charCodeAt(0));
}
