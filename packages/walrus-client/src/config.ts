export interface WalrusEndpoints {
  publisher: string;
  aggregator: string;
}

export const TESTNET_ENDPOINTS: WalrusEndpoints = {
  publisher: 'https://publisher.walrus-testnet.walrus.space',
  aggregator: 'https://aggregator.walrus-testnet.walrus.space',
};

export const MAINNET_ENDPOINTS: WalrusEndpoints = {
  publisher: 'https://publisher.walrus.space',
  aggregator: 'https://aggregator.walrus.space',
};

export function endpointsFromEnv(): WalrusEndpoints {
  return {
    publisher: process.env.WALRUS_PUBLISHER_URL ?? TESTNET_ENDPOINTS.publisher,
    aggregator: process.env.WALRUS_AGGREGATOR_URL ?? TESTNET_ENDPOINTS.aggregator,
  };
}
