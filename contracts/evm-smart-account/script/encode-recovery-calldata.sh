#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

: "${NEAR_ACCOUNT_ID_HASH:?NEAR_ACCOUNT_ID_HASH is required}"
: "${NEW_NEAR_KEY_HASH:?NEW_NEAR_KEY_HASH is required}"
: "${NEW_OWNER:?NEW_OWNER is required}"
: "${RECOVERY_SESSION_HASH:?RECOVERY_SESSION_HASH is required}"
: "${NONCE:?NONCE is required}"
: "${DEADLINE:?DEADLINE is required}"
: "${AUTHORITY_SIGNATURE:?AUTHORITY_SIGNATURE is required}"

CONTRACT_METHOD="${CONTRACT_METHOD:-verifyAndRecover}"

case "$CONTRACT_METHOD" in
  verifyAndRecover|recoverAddOwner) ;;
  *)
    echo "CONTRACT_METHOD must be verifyAndRecover or recoverAddOwner" >&2
    exit 1
    ;;
esac

cast calldata \
  "${CONTRACT_METHOD}(bytes32,bytes32,address,bytes32,uint256,uint256,bytes)" \
  "$NEAR_ACCOUNT_ID_HASH" \
  "$NEW_NEAR_KEY_HASH" \
  "$NEW_OWNER" \
  "$RECOVERY_SESSION_HASH" \
  "$NONCE" \
  "$DEADLINE" \
  "$AUTHORITY_SIGNATURE"
