/**
 * Live testnet deployments produced during the workspace's bootstrap.
 * The tutorial demos can read/interact with these without any user-side setup.
 *
 * To re-deploy on your own address: `pnpm cli publish move/counter` etc.
 */
export const DEPLOYED = {
  network: 'testnet' as const,
  counter: {
    packageId: '0x324394e4192a5b33b570063de9678376b3be657b6c134afd858a757e766925c3',
    objectId: '0xe1cd379516e0f8e5f310bff6de90caa3890903856f0f0a7827ff723735b44552',
  },
  nft: {
    packageId: '0x5031f46af0d6aa66b0a5a868a42a80ba0ece66a4129d4344ad40c6e54c6d6998',
    sampleObjectId: '0x272c588dd94090665cdf729a0c6bac5f110069c89db93bbc60d8d9b0d965f951',
  },
  coin: {
    packageId: '0x5a74de46c646429f0c17d4fda5967a834fb90261d7d73afacfa68959d6a6d48e',
    coinType:
      '0x5a74de46c646429f0c17d4fda5967a834fb90261d7d73afacfa68959d6a6d48e::demo_coin::DEMO_COIN',
  },
  seal: {
    packageId: '0x867e402dc0d8b7bd66bda7dba9e17227565b19e93c8ccb19adc00baf8a6915a9',
  },
  walrusBlob: 'JlT6Xtosxx9YefsoE1glyo0jGw3lb-3eu4IHum0DQEE',
};

export function suiscan(objectId: string): string {
  return `https://suiscan.xyz/testnet/object/${objectId}`;
}
