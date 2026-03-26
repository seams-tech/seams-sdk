#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

mkdir -p abi

forge inspect src/TatchiSmartAccount.sol:TatchiSmartAccount abi > abi/TatchiSmartAccount.json
forge inspect src/TatchiSmartAccountFactory.sol:TatchiSmartAccountFactory abi > abi/TatchiSmartAccountFactory.json
