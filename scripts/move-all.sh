#!/usr/bin/env bash
# Run `sui move <cmd>` across every Move package under move/.
set -euo pipefail

CMD="${1:-build}"
shift || true

if ! command -v sui >/dev/null 2>&1; then
  echo "sui CLI not installed — run 'pnpm setup:sui'"
  exit 1
fi

for pkg in move/*/; do
  [[ -f "$pkg/Move.toml" ]] || continue
  echo "── $pkg ──"
  (cd "$pkg" && sui move "$CMD" "$@")
done
