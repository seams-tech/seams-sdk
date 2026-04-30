#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

mkdir -p abi

forge inspect src/SeamsSmartAccount.sol:SeamsSmartAccount abi > abi/SeamsSmartAccount.json
forge inspect src/SeamsSmartAccountFactory.sol:SeamsSmartAccountFactory abi > abi/SeamsSmartAccountFactory.json
