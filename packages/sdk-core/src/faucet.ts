import { NETWORKS, type Network } from './networks.js';

export async function requestFaucet(address: string, network: Network = 'testnet'): Promise<void> {
  const url = NETWORKS[network].faucet;
  if (!url) throw new Error(`No public faucet for ${network}`);

  const res = await fetch(url, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ FixedAmountRequest: { recipient: address } }),
  });
  if (!res.ok) {
    throw new Error(`Faucet request failed: ${res.status} ${await res.text()}`);
  }
}
