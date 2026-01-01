import { Transaction } from '@mysten/sui/transactions';
import { SuiPriceServiceConnection, SuiPythClient } from '@pythnetwork/pyth-sui-js';
import { type Network, getClient } from '@sui-gen/sdk-core';

const PYTH_PACKAGE = {
  mainnet: {
    pythPkg: '0x8d97f1cd6ac663735be08d1d2b6d02a159e711586461306ce60a2b7a6a565a9e',
    pythState: '0x1f9310238ee9298fb703c3419030b35b22bb1cc37113e3bb5007c99aec79e5b8',
    wormholePkg: '0x5306f64e312b581766351c07af79c72fcb1cd25147157fdc2f8ad76de9a3fb6a',
    wormholeState: '0xaeab97f96cf9877fee2883315d459552b2b921edc16d7ceac6eab944dd88919c',
    hermes: 'https://hermes.pyth.network',
  },
  testnet: {
    pythPkg: '0xa6b67432a01ce6c2bdab14c11d1d9979e6c0e07f30b0cae1a44ee2c1e7e58495',
    pythState: '0x243759059f4c3111179da5878c12f68d612c21a8d54d85edc86164bb18be1c7c',
    wormholePkg: '0xf47329f4344f3bf0f8e436e2f7b485466cff300f12a166563995d3888c296a94',
    wormholeState: '0x31358d198147da50db32eda2562951d53973a0c0ad5ed738e9b17d88b213d790',
    hermes: 'https://hermes-beta.pyth.network',
  },
} as const;

export interface PythOptions {
  network?: Network;
}

export function createPythClient(opts: PythOptions = {}) {
  const network = opts.network ?? 'mainnet';
  const cfg = PYTH_PACKAGE[network === 'devnet' || network === 'localnet' ? 'testnet' : network];
  const suiClient = getClient({ network });
  return new SuiPythClient(suiClient, cfg.pythState, cfg.wormholePkg);
}

export function createPriceService(opts: PythOptions = {}) {
  const network = opts.network ?? 'mainnet';
  const cfg = PYTH_PACKAGE[network === 'devnet' || network === 'localnet' ? 'testnet' : network];
  return new SuiPriceServiceConnection(cfg.hermes);
}

/** Build a tx that pulls + verifies the latest Pyth price for the given feed ids. */
export async function buildUpdatePriceTx(
  feedIds: string[],
  opts: PythOptions = {},
): Promise<{ tx: Transaction; priceInfoObjectIds: string[] }> {
  const priceService = createPriceService(opts);
  const pyth = createPythClient(opts);
  const updates = await priceService.getPriceFeedsUpdateData(feedIds);
  const tx = new Transaction();
  const priceInfoObjectIds = await pyth.updatePriceFeeds(tx, updates, feedIds);
  return { tx, priceInfoObjectIds };
}
