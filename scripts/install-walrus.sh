#!/usr/bin/env bash
# Install the Walrus CLI from prebuilt releases.
# Falls back to cargo build from MystenLabs/walrus if no binary matches the host.
set -euo pipefail

NETWORK="${WALRUS_NETWORK:-testnet}"
INSTALL_DIR="${WALRUS_INSTALL_DIR:-$HOME/.local/bin}"

log()  { printf "\033[1;34m[install-walrus]\033[0m %s\n" "$*"; }
warn() { printf "\033[1;33m[install-walrus]\033[0m %s\n" "$*" >&2; }
die()  { printf "\033[1;31m[install-walrus]\033[0m %s\n" "$*" >&2; exit 1; }

if command -v walrus >/dev/null 2>&1; then
  log "walrus already installed: $(walrus --version 2>/dev/null || echo unknown)"
  exit 0
fi

mkdir -p "$INSTALL_DIR"

# Detect platform
case "$(uname -s)-$(uname -m)" in
  Darwin-arm64)     ASSET="walrus-${NETWORK}-latest-macos-arm64" ;;
  Darwin-x86_64)    ASSET="walrus-${NETWORK}-latest-macos-x86_64" ;;
  Linux-x86_64)     ASSET="walrus-${NETWORK}-latest-ubuntu-x86_64" ;;
  Linux-aarch64)    ASSET="walrus-${NETWORK}-latest-ubuntu-aarch64" ;;
  *) ASSET="" ;;
esac

if [[ -n "$ASSET" ]]; then
  URL="https://storage.googleapis.com/mysten-walrus-binaries/${ASSET}"
  log "Downloading $URL"
  if curl -fsSL "$URL" -o "$INSTALL_DIR/walrus"; then
    chmod +x "$INSTALL_DIR/walrus"
    log "Installed walrus to $INSTALL_DIR/walrus"
    if [[ ":$PATH:" != *":$INSTALL_DIR:"* ]]; then
      warn "Add to your shell rc:  export PATH=\"\$PATH:$INSTALL_DIR\""
    fi
    exit 0
  else
    warn "Prebuilt download failed, falling back to cargo build"
  fi
fi

if command -v cargo >/dev/null 2>&1; then
  log "Building walrus from source (cargo)…"
  cargo install --locked --git https://github.com/MystenLabs/walrus.git walrus && exit 0
fi

die "Could not install walrus. See https://docs.wal.app/usage/setup.html"
