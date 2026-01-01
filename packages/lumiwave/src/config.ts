/**
 * Lumiwave ($LWA) is a Web3 entertainment platform that issues a Sui-native token and
 * an off-chain service API for game/IP partnerships. Adjust these IDs to whatever the
 * Lumiwave team currently publishes — they're parameterised so the rest of the package
 * never needs to change when the token migrates.
 *
 * As of 2026 the canonical metadata to track is:
 *   - Coin type:          <package>::lwa::LWA  (Sui mainnet)
 *   - Treasury / minter:  multisig owned by Lumiwave Foundation
 *   - Off-chain RPC:      https://rpc-mainnet.lumiwave.io (REST + JSON-RPC)
 *
 * If/when the on-chain package id changes, set LUMIWAVE_COIN_TYPE in the environment
 * instead of editing this file.
 */
export interface LumiwaveConfig {
  /** Fully-qualified Sui coin type, e.g. `0xPKG::lwa::LWA`. */
  coinType: string;
  /** Lumiwave service RPC. */
  rpcUrl: string;
  /** Optional API key for partner endpoints. */
  apiKey?: string;
}

export const DEFAULT_LUMIWAVE_CONFIG: LumiwaveConfig = {
  // Placeholder — override via env. Real value lives in Lumiwave's docs / Suiscan.
  coinType:
    process.env.LUMIWAVE_COIN_TYPE ??
    '0x0000000000000000000000000000000000000000000000000000000000000000::lwa::LWA',
  rpcUrl: process.env.LUMIWAVE_RPC_URL ?? 'https://rpc-mainnet.lumiwave.io',
  apiKey: process.env.LUMIWAVE_API_KEY,
};
