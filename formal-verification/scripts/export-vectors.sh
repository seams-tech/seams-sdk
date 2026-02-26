#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
OUT_DIR="${ROOT_DIR}/vectors/generated"
OUT_FILE="${OUT_DIR}/starter.json"

mkdir -p "${OUT_DIR}"

cat >"${OUT_FILE}" <<'EOF'
{
  "version": "v1",
  "generator": "formal-verification/scripts/export-vectors.sh",
  "vectors": [
    {
      "name": "z_add_sub_cancel",
      "a": "123456789",
      "b": "987654321",
      "expected": "123456789"
    }
  ]
}
EOF

echo "ok: wrote ${OUT_FILE}"
