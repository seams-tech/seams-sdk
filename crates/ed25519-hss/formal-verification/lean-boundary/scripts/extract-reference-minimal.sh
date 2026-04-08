#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BOUNDARY_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
CRATE_DIR="$(cd "${BOUNDARY_DIR}/../.." && pwd)"
CHARON_BIN="${BOUNDARY_DIR}/tools/charon/bin/charon"
AENEAS_BIN="${BOUNDARY_DIR}/tools/aeneas/bin/aeneas"
LLBC_DIR="${BOUNDARY_DIR}/generated/reference-minimal"
LEAN_DIR="${BOUNDARY_DIR}/generated/reference-minimal-lean"
LLBC_FILE="${LLBC_DIR}/ed25519_hss.llbc"

if [[ ! -x "${CHARON_BIN}" ]]; then
  echo "missing charon binary at ${CHARON_BIN}" >&2
  exit 1
fi

if [[ ! -x "${AENEAS_BIN}" ]]; then
  echo "missing aeneas binary at ${AENEAS_BIN}" >&2
  exit 1
fi

mkdir -p "${LLBC_DIR}"
rm -rf "${LEAN_DIR}"
mkdir -p "${LEAN_DIR}"

(
  cd "${CRATE_DIR}"
  "${CHARON_BIN}" cargo \
    --preset aeneas \
    --start-from ed25519_hss::shared::reference::add_le_bytes_mod_2_256 \
    --start-from ed25519_hss::shared::reference::clamp_rfc8032 \
    --dest-file "${LLBC_FILE}" \
    -- --lib
)

"${AENEAS_BIN}" \
  -backend lean \
  -dest "${LEAN_DIR}" \
  -split-files \
  -gen-lib-entry \
  -lean-default-lakefile \
  "${LLBC_FILE}"
