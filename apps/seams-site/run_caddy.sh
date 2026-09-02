#!/bin/bash
set -euo pipefail

SCRIPT_PATH="${BASH_SOURCE[0]:-$0}"
SCRIPT_DIR="$(cd "$(dirname "$SCRIPT_PATH")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
CADDYFILE="$SCRIPT_DIR/Caddyfile"
SDK_PACKAGE_JSON="$(cd "$SCRIPT_DIR" && node -p "require.resolve('@seams/wallet/package.json')")"
WALLET_PUBLIC_ROOT="$(dirname "$SDK_PACKAGE_JSON")/dist/public"
CADDY_BIN="$(command -v caddy || true)"

if [[ -z "$CADDY_BIN" ]]; then
  echo "Caddy not found. Install it with: brew install caddy" >&2
  exit 1
fi

if [[ ! -f "$WALLET_PUBLIC_ROOT/wallet-assets.manifest.json" ]]; then
  echo "Wallet static assets not found at $WALLET_PUBLIC_ROOT" >&2
  echo "Install an @seams/wallet package that includes the built wallet assets." >&2
  exit 1
fi

export SEAMS_WALLET_PUBLIC_ROOT="$WALLET_PUBLIC_ROOT"

echo "Serving wallet assets from $SEAMS_WALLET_PUBLIC_ROOT"
echo "Validating Caddyfile..."
"$CADDY_BIN" validate --config "$CADDYFILE" --adapter caddyfile

echo "Starting Caddy"
exec "$CADDY_BIN" run --config "$CADDYFILE" --adapter caddyfile
