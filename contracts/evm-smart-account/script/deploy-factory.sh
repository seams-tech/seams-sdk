#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

: "${RPC_URL:?RPC_URL is required}"
: "${PRIVATE_KEY:?PRIVATE_KEY is required}"

forge create \
  --rpc-url "$RPC_URL" \
  --private-key "$PRIVATE_KEY" \
  src/TatchiSmartAccountFactory.sol:TatchiSmartAccountFactory \
  "$@"
