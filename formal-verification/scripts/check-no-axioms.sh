#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
THEORY_DIR="${ROOT_DIR}/coq/Theories"

if rg -n --glob '*.v' '^[[:space:]]*Axiom[[:space:]]' "${THEORY_DIR}"; then
  echo "error: found Coq Axiom declarations; model assumptions must be explicit in docs and encoded without Axiom in theorem files"
  exit 1
fi

echo "ok: no Axiom declarations found in ${THEORY_DIR}"
