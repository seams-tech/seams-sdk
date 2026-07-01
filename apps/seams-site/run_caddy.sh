#!/bin/bash
set -euo pipefail

SCRIPT_PATH="${BASH_SOURCE[0]:-$0}"
SCRIPT_DIR="$(cd "$(dirname "$SCRIPT_PATH")" && pwd)"
CADDYFILE="$SCRIPT_DIR/Caddyfile"

if ! command -v caddy >/dev/null 2>&1; then
  echo "Caddy not found. Install it with: brew install caddy" >&2
  exit 1
fi

caddy stop 2>/dev/null || true

echo "Validating Caddyfile..."
caddy validate --config "$CADDYFILE" --adapter caddyfile

# Best-effort local CA trust for tls internal.
caddy trust --config "$CADDYFILE" --adapter caddyfile >/dev/null 2>&1 || true

echo "Starting Caddy"
exec caddy run --config "$CADDYFILE" --adapter caddyfile
