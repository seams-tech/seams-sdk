#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
THEORY_DIR="${ROOT_DIR}/coq/Theories"

if rg -n --glob '*.v' '\bAdmitted\.' "${THEORY_DIR}"; then
  echo "error: found Coq Admitted statements; replace with completed proofs"
  exit 1
fi

echo "ok: no Admitted statements found in ${THEORY_DIR}"
