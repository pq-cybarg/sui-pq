#!/usr/bin/env bash
# End-to-end environment bootstrap.
# - Installs Sui & Walrus CLIs (if missing)
# - Configures Sui client for $SUI_NETWORK
# - Drips faucet
# - Installs pnpm deps
set -euo pipefail

NETWORK="${SUI_NETWORK:-testnet}"

log() { printf "\033[1;34m[setup]\033[0m %s\n" "$*"; }

bash "$(dirname "$0")/install-sui.sh" || true
bash "$(dirname "$0")/install-walrus.sh" || true

if command -v sui >/dev/null 2>&1; then
  log "Configuring sui client for $NETWORK"
  case "$NETWORK" in
    mainnet)  RPC="https://fullnode.mainnet.sui.io:443" ;;
    testnet)  RPC="https://fullnode.testnet.sui.io:443" ;;
    devnet)   RPC="https://fullnode.devnet.sui.io:443" ;;
    localnet) RPC="http://127.0.0.1:9000" ;;
    *) RPC="https://fullnode.testnet.sui.io:443" ;;
  esac
  sui client --yes new-env --alias "$NETWORK" --rpc "$RPC" 2>/dev/null || true
  sui client switch --env "$NETWORK" || true

  if ! sui client active-address >/dev/null 2>&1; then
    log "Creating a new keypair"
    sui client new-address ed25519 --json || true
  fi

  if [[ "$NETWORK" != "mainnet" ]]; then
    bash "$(dirname "$0")/faucet.sh" || true
  fi
else
  log "sui CLI not available; skipping client configuration"
fi

if command -v pnpm >/dev/null 2>&1; then
  log "Installing JS dependencies"
  pnpm install
fi

log "Done."
