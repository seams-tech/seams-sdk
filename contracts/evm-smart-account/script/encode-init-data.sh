#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

: "${NEAR_ACCOUNT_ID_HASH:?NEAR_ACCOUNT_ID_HASH is required}"
: "${RECOVERY_AUTHORITY:?RECOVERY_AUTHORITY is required}"
: "${OWNERS:?OWNERS is required as a comma-separated address list}"

ENTRY_POINT="${ENTRY_POINT:-0x0000000000000000000000000000000000000000}"
OWNERS_NORMALIZED="$(printf '%s' "$OWNERS" | tr -d '[:space:]')"

if [[ -z "$OWNERS_NORMALIZED" ]]; then
  echo "OWNERS must not be empty" >&2
  exit 1
fi

OWNERS_ARRAY="[${OWNERS_NORMALIZED}]"

cast abi-encode \
  'initialize((bytes32,address,address,address[]))' \
  "(${NEAR_ACCOUNT_ID_HASH},${RECOVERY_AUTHORITY},${ENTRY_POINT},${OWNERS_ARRAY})"
