#!/usr/bin/env bash
# Build a locally-forked sui-node binary that natively verifies FIPS-205
# SLH-DSA-SHA2-128s transaction signatures, then start a one-validator localnet
# using it.
#
# Output: $PQ_SUI_HOME/bin/sui-node (the patched binary), and a running localnet.
#
# This is genuinely a build-from-source workflow. It compiles Sui in release
# mode, which is multi-GB and takes 10–30 minutes the first time. After that,
# `--launch-only` re-runs the localnet without re-building.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
PATCHES="$ROOT/patches"

PQ_SUI_HOME="${PQ_SUI_HOME:-$HOME/.local/share/pq-sui}"
SUI_REPO="${SUI_REPO:-https://github.com/MystenLabs/sui.git}"
# Pin to a known-tested revision. Bump + re-test before changing.
SUI_REV="${SUI_REV:-mainnet-v1.72.2}"

color() { printf "\033[%sm%s\033[0m\n" "$1" "$2"; }
log()   { color "1;34" "[pq-validator] $1"; }
ok()    { color "1;32" "[pq-validator] $1"; }
warn()  { color "1;33" "[pq-validator] $1"; }
die()   { color "1;31" "[pq-validator] $1" >&2; exit 1; }

LAUNCH_ONLY=0
SKIP_PATCHES=0
for arg in "$@"; do
  case "$arg" in
    --launch-only)  LAUNCH_ONLY=1 ;;
    --skip-patches) SKIP_PATCHES=1 ;;
    --help|-h)
      cat <<EOF
Usage: bash scripts/build-pq-validator.sh [--launch-only] [--skip-patches]

Env:
  PQ_SUI_HOME  Where to clone + build (default: ~/.local/share/pq-sui)
  SUI_REPO     Repo to clone (default: MystenLabs/sui)
  SUI_REV      Commit / branch / tag (default: mainnet-v1.72.2)

  --launch-only   Skip clone + build; just start localnet from \$PQ_SUI_HOME
  --skip-patches  Clone + build vanilla Sui (no PQ scheme); useful for diffing
EOF
      exit 0
      ;;
    *) die "unknown arg: $arg" ;;
  esac
done

command -v cargo >/dev/null 2>&1 || die "cargo not found — install Rust: https://rustup.rs"

if (( LAUNCH_ONLY == 0 )); then
  if [ ! -d "$PQ_SUI_HOME/sui/.git" ]; then
    log "cloning $SUI_REPO to $PQ_SUI_HOME/sui at $SUI_REV (~5 min, ~3 GB)"
    mkdir -p "$PQ_SUI_HOME"
    git clone --depth 1 --branch "$SUI_REV" "$SUI_REPO" "$PQ_SUI_HOME/sui" 2>/dev/null \
      || { git clone "$SUI_REPO" "$PQ_SUI_HOME/sui"; \
           git -C "$PQ_SUI_HOME/sui" checkout "$SUI_REV"; }
  else
    ok "sui repo already present at $PQ_SUI_HOME/sui"
  fi

  if (( SKIP_PATCHES == 0 )); then
    cd "$PQ_SUI_HOME/sui"
    PATCH="$PATCHES/sui-1.72.2-native-slh-dsa.patch"
    # The patch's signature is the new authenticator module; if it's present,
    # the patch is already applied (it's a plain diff, not a commit).
    if [ -f crates/sui-types/src/slh_dsa_authenticator.rs ]; then
      ok "patch already applied"
    else
      log "applying PQ patch $(basename "$PATCH")"
      if ! git apply --3way --whitespace=fix "$PATCH"; then
        warn "patch $(basename "$PATCH") did not apply cleanly."
        warn "it is **illustrative** — it was authored against $SUI_REV."
        warn "Sui evolves quickly; if hunks fail you'll need to:"
        warn "  1) read the patch (it's a single readable diff)"
        warn "  2) hand-apply the changes against current Sui internals"
        warn "  3) re-run with --launch-only after the hand-edits build"
        die "stopping so you can resolve rejects"
      fi
    fi
  else
    warn "--skip-patches set; building vanilla Sui (no PQ scheme)"
  fi

  log "building sui + sui-node (release; takes 10–30 min the first time)"
  cd "$PQ_SUI_HOME/sui"
  cargo build --release --bin sui --bin sui-node || die "cargo build failed"

  mkdir -p "$PQ_SUI_HOME/bin"
  cp target/release/sui      "$PQ_SUI_HOME/bin/sui"
  cp target/release/sui-node "$PQ_SUI_HOME/bin/sui-node"
  ok "binaries at $PQ_SUI_HOME/bin/{sui,sui-node}"
fi

[ -x "$PQ_SUI_HOME/bin/sui" ] || die "patched sui binary missing; re-run without --launch-only"
log "starting one-validator localnet"
warn "RPC: http://127.0.0.1:9000  faucet: http://127.0.0.1:9123/v2/gas"
warn "Ctrl-C to stop"
exec "$PQ_SUI_HOME/bin/sui" start --with-faucet
