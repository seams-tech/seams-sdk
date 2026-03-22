#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(cd "${SCRIPT_DIR}/../.." && pwd)"

cargo test \
  --manifest-path "${REPO_DIR}/crates/signer-core/Cargo.toml" \
  --test baseline_behavior \
  --features "secp256k1 near-crypto"

echo "ok: signer-core baseline parity test passed"
