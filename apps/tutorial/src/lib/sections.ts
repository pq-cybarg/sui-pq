export interface Section {
  slug: string;
  title: string;
  subtitle: string;
  minutes: number;
}

export const SECTIONS: Section[] = [
  { slug: '', title: 'Welcome', subtitle: 'What the Sui stack actually is', minutes: 3 },
  { slug: 'setup', title: '1. Setup', subtitle: 'sui + walrus CLIs, testnet, gas', minutes: 5 },
  {
    slug: 'move-basics',
    title: '2. Move basics',
    subtitle: 'Objects, abilities, the counter',
    minutes: 8,
  },
  {
    slug: 'publishing',
    title: '3. Publishing',
    subtitle: 'From sources/ to a package id',
    minutes: 4,
  },
  {
    slug: 'sdk',
    title: '4. TypeScript SDK',
    subtitle: 'SuiClient, Transaction, signers',
    minutes: 7,
  },
  {
    slug: 'slush',
    title: '5. Slush wallet',
    subtitle: 'Connect, sign, query — dApp Kit',
    minutes: 6,
  },
  {
    slug: 'walrus',
    title: '6. Walrus storage',
    subtitle: 'Decentralized blobs, with a real upload',
    minutes: 6,
  },
  {
    slug: 'seal',
    title: '7. Seal secrets',
    subtitle: 'Threshold encryption with on-chain authz',
    minutes: 7,
  },
  {
    slug: 'zk-login',
    title: '8. zkLogin',
    subtitle: 'OAuth → Sui address, no key custody',
    minutes: 6,
  },
  {
    slug: 'deepbook',
    title: '9. DeepBook',
    subtitle: 'First-party CLOB, on-chain limit orders',
    minutes: 5,
  },
  {
    slug: 'sponsored-tx',
    title: '10. Sponsored tx',
    subtitle: 'Gasless flows; backend pays',
    minutes: 5,
  },
  {
    slug: 'kiosk',
    title: '11. Kiosk + NFTs',
    subtitle: 'Display, royalties, the canonical NFT pattern',
    minutes: 5,
  },
  {
    slug: 'lumiwave',
    title: '12. Lumiwave',
    subtitle: 'LWA balances + partner service API',
    minutes: 4,
  },
  { slug: 'indexer', title: '13. Indexer', subtitle: 'Streaming events, GraphQL', minutes: 5 },
  {
    slug: 'pqc',
    title: '14. Post-quantum',
    subtitle: 'ML-DSA / SLH-DSA: state of the art on Sui',
    minutes: 7,
  },
  {
    slug: 'capstone',
    title: '15. Capstone',
    subtitle: 'NFT minted from a Walrus blob, end-to-end',
    minutes: 4,
  },
];

export function nextOf(slug: string): Section | null {
  const i = SECTIONS.findIndex((s) => s.slug === slug);
  if (i < 0 || i === SECTIONS.length - 1) return null;
  return SECTIONS[i + 1] ?? null;
}

export function prevOf(slug: string): Section | null {
  const i = SECTIONS.findIndex((s) => s.slug === slug);
  if (i <= 0) return null;
  return SECTIONS[i - 1] ?? null;
}
