#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

: "${RECOVERY_SESSION_HASH:?RECOVERY_SESSION_HASH is required}"
: "${NONCE:?NONCE is required}"
: "${OWNER:?OWNER is required}"
: "${NEAR_ACCOUNT_ID_HASH:?NEAR_ACCOUNT_ID_HASH is required}"
: "${NEW_NEAR_KEY_HASH:?NEW_NEAR_KEY_HASH is required}"
: "${AUTHORITY:?AUTHORITY is required}"

cast abi-encode-event \
  'RecoveryOwnerAdded(bytes32 indexed recoverySessionHash,bytes32 indexed nonce,address indexed owner,bytes32 nearAccountIdHash,bytes32 newNearKeyHash,address authority)' \
  "$RECOVERY_SESSION_HASH" \
  "$NONCE" \
  "$OWNER" \
  "$NEAR_ACCOUNT_ID_HASH" \
  "$NEW_NEAR_KEY_HASH" \
  "$AUTHORITY"
