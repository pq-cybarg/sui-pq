import { KioskClient, Network as KioskNetwork, KioskTransaction } from '@mysten/kiosk';
import { type Network, getClient } from '@sui-gen/sdk-core';

export function createKioskClient(opts: { network?: Network } = {}) {
  const network = opts.network ?? 'testnet';
  const suiClient = getClient({ network });
  return new KioskClient({
    client: suiClient as unknown as ConstructorParameters<typeof KioskClient>[0]['client'],
    network: network === 'mainnet' ? KioskNetwork.MAINNET : KioskNetwork.TESTNET,
  });
}

export { KioskClient, KioskTransaction };
