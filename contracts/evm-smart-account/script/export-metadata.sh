#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

mkdir -p abi

ACCOUNT_METHODS="$(forge inspect --json src/SeamsSmartAccount.sol:SeamsSmartAccount methodIdentifiers)"
ACCOUNT_ERRORS="$(forge inspect --json src/SeamsSmartAccount.sol:SeamsSmartAccount errors)"
ACCOUNT_EVENTS="$(forge inspect --json src/SeamsSmartAccount.sol:SeamsSmartAccount events)"
ACCOUNT_BYTECODE="$(forge inspect src/SeamsSmartAccount.sol:SeamsSmartAccount bytecode)"
ACCOUNT_DEPLOYED_BYTECODE="$(forge inspect src/SeamsSmartAccount.sol:SeamsSmartAccount deployedBytecode)"
ACCOUNT_BYTECODE_HASH="$(cast keccak "$ACCOUNT_BYTECODE")"
ACCOUNT_DEPLOYED_BYTECODE_HASH="$(cast keccak "$ACCOUNT_DEPLOYED_BYTECODE")"

FACTORY_METHODS="$(forge inspect --json src/SeamsSmartAccountFactory.sol:SeamsSmartAccountFactory methodIdentifiers)"
FACTORY_ERRORS="$(printf '{}')"
FACTORY_EVENTS="$(forge inspect --json src/SeamsSmartAccountFactory.sol:SeamsSmartAccountFactory events)"
FACTORY_BYTECODE="$(forge inspect src/SeamsSmartAccountFactory.sol:SeamsSmartAccountFactory bytecode)"
FACTORY_DEPLOYED_BYTECODE="$(forge inspect src/SeamsSmartAccountFactory.sol:SeamsSmartAccountFactory deployedBytecode)"
FACTORY_BYTECODE_HASH="$(cast keccak "$FACTORY_BYTECODE")"
FACTORY_DEPLOYED_BYTECODE_HASH="$(cast keccak "$FACTORY_DEPLOYED_BYTECODE")"

ACCOUNT_METHODS="$ACCOUNT_METHODS" \
ACCOUNT_ERRORS="$ACCOUNT_ERRORS" \
ACCOUNT_EVENTS="$ACCOUNT_EVENTS" \
ACCOUNT_BYTECODE_HASH="$ACCOUNT_BYTECODE_HASH" \
ACCOUNT_DEPLOYED_BYTECODE_HASH="$ACCOUNT_DEPLOYED_BYTECODE_HASH" \
FACTORY_METHODS="$FACTORY_METHODS" \
FACTORY_ERRORS="$FACTORY_ERRORS" \
FACTORY_EVENTS="$FACTORY_EVENTS" \
FACTORY_BYTECODE_HASH="$FACTORY_BYTECODE_HASH" \
FACTORY_DEPLOYED_BYTECODE_HASH="$FACTORY_DEPLOYED_BYTECODE_HASH" \
node <<'NODE'
const fs = require('node:fs');

function prefixHexMap(input) {
  const parsed = JSON.parse(input);
  return Object.fromEntries(
    Object.entries(parsed).map(([key, value]) => {
      const normalized = String(value);
      return [key, normalized.startsWith('0x') ? normalized : `0x${normalized}`];
    }),
  );
}

function writeMetadata(path, payload) {
  fs.writeFileSync(path, `${JSON.stringify(payload, null, 2)}\n`);
}

writeMetadata('abi/SeamsSmartAccount.metadata.json', {
  contract: 'SeamsSmartAccount',
  source: 'src/SeamsSmartAccount.sol',
  abiFile: 'abi/SeamsSmartAccount.json',
  methodIdentifiers: prefixHexMap(process.env.ACCOUNT_METHODS),
  errorSelectors: prefixHexMap(process.env.ACCOUNT_ERRORS),
  eventTopics: prefixHexMap(process.env.ACCOUNT_EVENTS),
  bytecodeHash: process.env.ACCOUNT_BYTECODE_HASH,
  deployedBytecodeHash: process.env.ACCOUNT_DEPLOYED_BYTECODE_HASH,
});

writeMetadata('abi/SeamsSmartAccountFactory.metadata.json', {
  contract: 'SeamsSmartAccountFactory',
  source: 'src/SeamsSmartAccountFactory.sol',
  abiFile: 'abi/SeamsSmartAccountFactory.json',
  methodIdentifiers: prefixHexMap(process.env.FACTORY_METHODS),
  errorSelectors: prefixHexMap(process.env.FACTORY_ERRORS),
  eventTopics: prefixHexMap(process.env.FACTORY_EVENTS),
  bytecodeHash: process.env.FACTORY_BYTECODE_HASH,
  deployedBytecodeHash: process.env.FACTORY_DEPLOYED_BYTECODE_HASH,
});
NODE
