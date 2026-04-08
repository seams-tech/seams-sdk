#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BOUNDARY_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
CRATE_DIR="$(cd "${BOUNDARY_DIR}/../.." && pwd)"
CHARON_BIN="${BOUNDARY_DIR}/tools/charon/bin/charon"
AENEAS_BIN="${BOUNDARY_DIR}/tools/aeneas/bin/aeneas"
LLBC_DIR="${BOUNDARY_DIR}/generated/visible-boundary-input"
LLBC_FILE="${LLBC_DIR}/ed25519_hss.llbc"
GENERATED_DIR="${BOUNDARY_DIR}/generated/visible-boundary-package"
TARGET_DIR="${BOUNDARY_DIR}/Ed25519Hss"

if [[ ! -x "${CHARON_BIN}" ]]; then
  echo "missing charon binary at ${CHARON_BIN}" >&2
  exit 1
fi

if [[ ! -x "${AENEAS_BIN}" ]]; then
  echo "missing aeneas binary at ${AENEAS_BIN}" >&2
  exit 1
fi

mkdir -p "${LLBC_DIR}"
rm -rf "${GENERATED_DIR}"
mkdir -p "${GENERATED_DIR}"

(
  cd "${CRATE_DIR}"
  "${CHARON_BIN}" cargo \
    --preset aeneas \
    --start-from ed25519_hss::shared::reference_boundary::eval_f_expand_visible_boundary \
    --opaque ed25519_hss::shared::reference::eval_f_expand \
    --dest-file "${LLBC_FILE}" \
    -- --lib
)

"${AENEAS_BIN}" \
  -backend lean \
  -dest "${GENERATED_DIR}" \
  -subdir Ed25519Hss \
  -split-files \
  "${LLBC_FILE}"

rm -rf "${TARGET_DIR}"
mkdir -p "${TARGET_DIR}"
cp "${GENERATED_DIR}/Ed25519Hss/Types.lean" "${TARGET_DIR}/Types.lean"
cp "${GENERATED_DIR}/Ed25519Hss/Funs.lean" "${TARGET_DIR}/Funs.lean"
cp "${GENERATED_DIR}/Ed25519Hss/FunsExternal_Template.lean" "${TARGET_DIR}/FunsExternal.lean"
