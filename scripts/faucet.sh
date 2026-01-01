#!/usr/bin/env bash
# Request SUI from a public faucet for the active address.
set -euo pipefail

NETWORK="${SUI_NETWORK:-testnet}"
case "$NETWORK" in
  testnet)  FAUCET="${SUI_FAUCET_URL:-https://faucet.testnet.sui.io/v2/gas}" ;;
  devnet)   FAUCET="${SUI_FAUCET_URL:-https://faucet.devnet.sui.io/v2/gas}" ;;
  localnet) FAUCET="${SUI_FAUCET_URL:-http://127.0.0.1:9123/v2/gas}" ;;
  *) echo "No public faucet for $NETWORK"; exit 0 ;;
esac

ADDR="${1:-}"
if [[ -z "$ADDR" ]] && command -v sui >/dev/null 2>&1; then
  ADDR="$(sui client active-address 2>/dev/null || true)"
fi
[[ -n "$ADDR" ]] || { echo "No address provided and no active sui address"; exit 1; }

echo "Requesting gas for $ADDR from $FAUCET"
curl -sS --location --request POST "$FAUCET" \
  --header 'Content-Type: application/json' \
  --data-raw "{\"FixedAmountRequest\": {\"recipient\": \"$ADDR\"}}" \
  && echo
