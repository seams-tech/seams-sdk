#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BOUNDARY_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
CRATE_DIR="$(cd "${BOUNDARY_DIR}/../.." && pwd)"
CHARON_BIN="${BOUNDARY_DIR}/tools/charon/bin/charon"
AENEAS_BIN="${BOUNDARY_DIR}/tools/aeneas/bin/aeneas"
LLBC_DIR="${BOUNDARY_DIR}/generated/visible-boundary-input"
LLBC_FILE="${LLBC_DIR}/ecdsa_hss.llbc"
GENERATED_DIR="${BOUNDARY_DIR}/generated/visible-boundary-package"
TARGET_DIR="${BOUNDARY_DIR}/EcdsaHss"

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
    --start-from ecdsa_hss::server::reference_boundary::visible_boundary_from_respond_response_v1 \
    --start-from ecdsa_hss::server::reference_boundary::hidden_eval_boundary_from_staged_request_and_response_v1 \
    --dest-file "${LLBC_FILE}" \
    -- --lib
)

"${AENEAS_BIN}" \
  -backend lean \
  -dest "${GENERATED_DIR}" \
  -subdir EcdsaHss \
  -split-files \
  "${LLBC_FILE}"

rm -rf "${TARGET_DIR}"
mkdir -p "${TARGET_DIR}"
cp "${GENERATED_DIR}/EcdsaHss/Types.lean" "${TARGET_DIR}/Types.lean"
cp "${GENERATED_DIR}/EcdsaHss/Funs.lean" "${TARGET_DIR}/Funs.lean"
cp "${GENERATED_DIR}/EcdsaHss/FunsExternal_Template.lean" "${TARGET_DIR}/FunsExternal.lean"
