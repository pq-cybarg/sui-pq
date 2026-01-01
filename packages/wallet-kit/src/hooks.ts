import {
  useConnectWallet,
  useCurrentAccount,
  useCurrentWallet,
  useDisconnectWallet,
  useSignAndExecuteTransaction,
  useSuiClient,
  useSuiClientQuery,
  useWallets,
} from '@mysten/dapp-kit';

export {
  useCurrentAccount,
  useCurrentWallet,
  useSignAndExecuteTransaction,
  useSuiClient,
  useSuiClientQuery,
  useWallets,
  useConnectWallet,
  useDisconnectWallet,
};

/** Convenience: returns the active address as a hex string, or null. */
export function useActiveAddress(): string | null {
  const account = useCurrentAccount();
  return account?.address ?? null;
}
