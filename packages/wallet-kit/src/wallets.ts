/**
 * Known Sui wallets and how to recognize them via the Wallet Standard.
 *
 * Slush is Mysten Labs' official wallet (renamed from "Sui Wallet" in 2024).
 * Suiet, Nightly, Phantom, and OKX implement the same Wallet Standard interface,
 * so they all light up automatically once `@mysten/dapp-kit`'s WalletProvider sees them.
 */
export type WalletName =
  | 'Slush'
  | 'Slush — A Sui wallet'
  | 'Suiet'
  | 'Phantom'
  | 'Nightly'
  | 'OKX Wallet'
  | 'Sui Wallet';

export const RECOMMENDED_WALLETS = {
  /** Mysten Labs' first-party wallet. Browser extension + mobile. */
  slush: {
    name: 'Slush — A Sui wallet',
    aliases: ['Slush', 'Sui Wallet'],
    chrome:
      'https://chrome.google.com/webstore/detail/slush-a-sui-wallet/opcgpfmipidbgpenhmajoajpbobppdil',
    homepage: 'https://slush.app',
  },
  suiet: {
    name: 'Suiet',
    aliases: [],
    chrome:
      'https://chromewebstore.google.com/detail/suiet-sui-wallet/khpkpbbcccdmmclmpigdgddabeilkdpd',
    homepage: 'https://suiet.app',
  },
  phantom: {
    name: 'Phantom',
    aliases: [],
    chrome: 'https://chromewebstore.google.com/detail/phantom/bfnaelmomeimhlpmgjnjophhpkkoljpa',
    homepage: 'https://phantom.com',
  },
  nightly: {
    name: 'Nightly',
    aliases: [],
    chrome: 'https://chromewebstore.google.com/detail/nightly/fiikommddbeccaoicoejoniammnalkfa',
    homepage: 'https://nightly.app',
  },
  okx: {
    name: 'OKX Wallet',
    aliases: [],
    chrome: 'https://chromewebstore.google.com/detail/okx-wallet/mcohilncbfahbmgdjkbpemcciiolgcge',
    homepage: 'https://www.okx.com/web3',
  },
} as const;

export type WalletKey = keyof typeof RECOMMENDED_WALLETS;

export const SLUSH_DISPLAY_NAME = 'Slush — A Sui wallet';
