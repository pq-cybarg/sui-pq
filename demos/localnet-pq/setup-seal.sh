#!/usr/bin/env bash
# Clone MystenLabs/seal and build the real `seal-cli` (Boneh-Franklin IBKEM over
# BLS12-381 + AES-256-GCM) as a sibling of the patched sui checkout, so it can
# act as a LOCAL Seal key server for pq-seal.ts.
#
# After this, run:  pnpm demo:pq-seal
set -euo pipefail
HOME_DIR="${PQ_SUI_HOME:-$HOME/.local/share/pq-sui}"
SEAL="$HOME_DIR/seal"

if [ ! -d "$SEAL/.git" ]; then
  echo "[seal] cloning MystenLabs/seal → $SEAL"
  git clone --depth 1 https://github.com/MystenLabs/seal.git "$SEAL"
fi

# The repo pins a toolchain whose extra components aren't always downloadable;
# build with the system stable toolchain instead.
rm -f "$SEAL/rust-toolchain.toml" "$SEAL/rust-toolchain"

if [ ! -x "$SEAL/target/release/seal-cli" ]; then
  echo "[seal] building seal-cli (release; first build is several minutes)"
  ( cd "$SEAL" && RUSTUP_TOOLCHAIN=stable cargo build --release -p seal-cli )
fi

echo "[seal] ready — run: pnpm demo:pq-seal"
