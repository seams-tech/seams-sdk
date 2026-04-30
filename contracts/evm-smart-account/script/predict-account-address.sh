#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

: "${FACTORY_ADDRESS:?FACTORY_ADDRESS is required}"
: "${SALT:?SALT is required}"

if [[ -n "${INIT_DATA:-}" ]]; then
  INIT_DATA_HEX="$INIT_DATA"
else
  INIT_DATA_HEX="$(
    NEAR_ACCOUNT_ID_HASH="${NEAR_ACCOUNT_ID_HASH:?NEAR_ACCOUNT_ID_HASH is required when INIT_DATA is unset}" \
    RECOVERY_AUTHORITY="${RECOVERY_AUTHORITY:?RECOVERY_AUTHORITY is required when INIT_DATA is unset}" \
    ENTRY_POINT="${ENTRY_POINT:-0x0000000000000000000000000000000000000000}" \
    OWNERS="${OWNERS:?OWNERS is required when INIT_DATA is unset}" \
    bash ./script/encode-init-data.sh
  )"
fi

INIT_DATA_HASH="$(cast keccak "$INIT_DATA_HEX")"
DEPLOYMENT_SALT_PREIMAGE="$(cast abi-encode 'f(bytes32,bytes32)' "$SALT" "$INIT_DATA_HASH")"
DEPLOYMENT_SALT="$(cast keccak "$DEPLOYMENT_SALT_PREIMAGE")"
ACCOUNT_INIT_CODE="$(forge inspect src/SeamsSmartAccount.sol:SeamsSmartAccount bytecode)"
ACCOUNT_INIT_CODE_HASH="$(cast keccak "$ACCOUNT_INIT_CODE")"

cast create2 \
  --deployer "$FACTORY_ADDRESS" \
  --salt "$DEPLOYMENT_SALT" \
  --init-code-hash "$ACCOUNT_INIT_CODE_HASH"
