#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
presign_manifest="${script_dir}/../../router-ab-ecdsa-presign/Cargo.toml"

if cargo tree --locked --offline --manifest-path "${presign_manifest}" -e normal,build \
    | rg 'threshold-signatures|router-ab-ecdsa-near-oracle-tests'; then
  echo "production dependency graph selects the NEAR oracle" >&2
  exit 1
fi

if cargo tree --locked --offline --manifest-path "${presign_manifest}" -e features \
    | rg 'router-ab-ecdsa-presign feature "test-utils"'; then
  echo "production dependency graph selects test-only protocol injection" >&2
  exit 1
fi

echo "production dependency graph excludes the NEAR oracle"
