#!/bin/bash
set -euo pipefail

SCRIPT_PATH="${BASH_SOURCE[0]:-$0}"
SCRIPT_DIR="$(cd "$(dirname "$SCRIPT_PATH")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
CADDYFILE="$SCRIPT_DIR/Caddyfile"
WALLET_PUBLIC_ROOT="$REPO_ROOT/packages/sdk-web/dist/public"

if ! command -v caddy >/dev/null 2>&1; then
  echo "Caddy not found. Install it with: brew install caddy" >&2
  exit 1
fi

if [[ ! -f "$WALLET_PUBLIC_ROOT/wallet-assets.manifest.json" ]]; then
  echo "Wallet static assets not found at $WALLET_PUBLIC_ROOT" >&2
  echo "Run: pnpm -C packages/sdk-web build:sdk" >&2
  exit 1
fi

export SEAMS_WALLET_PUBLIC_ROOT="$WALLET_PUBLIC_ROOT"

caddy stop 2>/dev/null || true

echo "Validating Caddyfile..."
caddy validate --config "$CADDYFILE" --adapter caddyfile

# Best-effort local CA trust for tls internal.
caddy trust --config "$CADDYFILE" --adapter caddyfile >/dev/null 2>&1 || true

echo "Starting Caddy"
exec caddy run --config "$CADDYFILE" --adapter caddyfile
