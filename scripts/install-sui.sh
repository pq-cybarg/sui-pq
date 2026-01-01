#!/usr/bin/env bash
# Install the Sui CLI.
# Strategy:
#   1) Prefer `suiup` (the official versioned installer)
#   2) Fall back to `cargo install --locked --git https://github.com/MystenLabs/sui.git`
#   3) On macOS, fall back to `brew install sui`
#
# Usage:
#   bash scripts/install-sui.sh                # latest mainnet binary
#   SUI_BRANCH=testnet bash scripts/install-sui.sh
set -euo pipefail

BRANCH="${SUI_BRANCH:-mainnet}"

log()  { printf "\033[1;34m[install-sui]\033[0m %s\n" "$*"; }
warn() { printf "\033[1;33m[install-sui]\033[0m %s\n" "$*" >&2; }
die()  { printf "\033[1;31m[install-sui]\033[0m %s\n" "$*" >&2; exit 1; }

if command -v sui >/dev/null 2>&1; then
  log "Sui already installed: $(sui --version)"
  exit 0
fi

# Strategy 1: suiup
if ! command -v suiup >/dev/null 2>&1; then
  log "Installing suiup (Sui version manager)…"
  if command -v cargo >/dev/null 2>&1; then
    cargo install --locked --git https://github.com/MystenLabs/suiup.git || warn "cargo install suiup failed"
  fi
fi

if command -v suiup >/dev/null 2>&1; then
  log "Installing sui via suiup (branch: ${BRANCH})…"
  # suiup prompts interactively to set as default; feed "y" so the binary lands on PATH.
  if printf 'y\n' | suiup install "sui@${BRANCH}"; then
    suiup default set "sui@${BRANCH}" 2>/dev/null || true
    LOCAL_BIN="$HOME/.local/bin"
    if [[ ":$PATH:" != *":$LOCAL_BIN:"* ]]; then
      warn "sui installed at $LOCAL_BIN/sui — add to your shell rc: export PATH=\"\$PATH:$LOCAL_BIN\""
    fi
    exit 0
  fi
  warn "suiup install failed; falling through"
fi

# Strategy 2: cargo install from source (slow but reliable)
if command -v cargo >/dev/null 2>&1; then
  log "Building sui from source via cargo (branch: ${BRANCH}) — this can take 20+ minutes…"
  cargo install --locked --git https://github.com/MystenLabs/sui.git --branch "${BRANCH}" sui && exit 0 || warn "cargo install sui failed"
fi

# Strategy 3: brew (macOS)
if [[ "$(uname)" == "Darwin" ]] && command -v brew >/dev/null 2>&1; then
  log "Installing sui via Homebrew…"
  brew install sui && exit 0 || warn "brew install sui failed"
fi

die "Could not install sui. Install suiup or cargo and retry, or grab a release: https://github.com/MystenLabs/sui/releases"
