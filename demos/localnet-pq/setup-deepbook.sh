#!/usr/bin/env bash
# Clone the real upstream MystenLabs/deepbookv3 as a sibling of the patched sui
# checkout and prepare it to REPUBLISH on a fresh localnet (the published
# packages are pinned to mainnet addresses; we unpin them so they publish fresh).
#
# After this, run:  pnpm demo:pq-deepbook
set -euo pipefail
HOME_DIR="${PQ_SUI_HOME:-$HOME/.local/share/pq-sui}"
DB="$HOME_DIR/deepbookv3"

if [ ! -d "$DB/.git" ]; then
  echo "[deepbook] cloning MystenLabs/deepbookv3 → $DB"
  git clone --depth 1 https://github.com/MystenLabs/deepbookv3.git "$DB"
fi

# Point the deepbook→token dependency at the local checkout (not git rev=main).
toml="$DB/packages/deepbook/Move.toml"
if grep -q 'rev = "main"' "$toml"; then
  echo "[deepbook] pointing token dependency local"
  sed -i.bak 's#token = { git = .*#token = { local = "../token" }#' "$toml"
fi

# Strip the mainnet/testnet published-ids from token's lock so --with-unpublished-
# dependencies treats it as fresh and bundles it into the localnet publish.
lock="$DB/packages/token/Move.lock"
if grep -q '^original-published-id = ' "$lock" 2>/dev/null; then
  echo "[deepbook] unpinning token published-ids for fresh localnet publish"
  sed -i.bak2 '/^original-published-id = /d; /^latest-published-id = /d; /^published-version = /d' "$lock"
fi

echo "[deepbook] ready — run: pnpm demo:pq-deepbook"
