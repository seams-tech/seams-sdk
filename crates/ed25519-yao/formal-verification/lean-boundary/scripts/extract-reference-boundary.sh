#!/usr/bin/env bash
set -euo pipefail

BOUNDARY_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
REPOSITORY_ROOT="$(cd "${BOUNDARY_DIR}/../../../.." && pwd)"
BASELINE_FILE="${BOUNDARY_DIR}/../toolchain.toml"
GENERATOR_DIR="${REPOSITORY_ROOT}/tools/ed25519-yao-generator"
AENEAS_BIN="${AENEAS_BIN:-${BOUNDARY_DIR}/tools/aeneas/bin/aeneas}"
CHARON_BIN="${CHARON_BIN:-${BOUNDARY_DIR}/tools/charon/bin/charon}"
TARGET_DIR="${BOUNDARY_DIR}/Ed25519Yao"
TEMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/ed25519-yao-aeneas.XXXXXX")"
LLBC_FILE="${TEMP_DIR}/ed25519_yao_generator.llbc"
LEAN_OUTPUT="${TEMP_DIR}/lean"
trap 'rm -rf "${TEMP_DIR}"' EXIT

if [[ ! -x "${AENEAS_BIN}" ]]; then
  echo "missing pinned Aeneas binary at ${AENEAS_BIN}; run scripts/setup-aeneas.sh" >&2
  exit 1
fi
if [[ ! -x "${CHARON_BIN}" ]]; then
  echo "missing pinned Charon binary at ${CHARON_BIN}; run scripts/setup-aeneas.sh" >&2
  exit 1
fi
if ! command -v python3 >/dev/null 2>&1; then
  echo "python3 is required to read and normalize the verification baseline" >&2
  exit 1
fi

SCOPE_VALUES="$(
  python3 - "${BASELINE_FILE}" <<'PY'
import sys
import tomllib

with open(sys.argv[1], "rb") as baseline_file:
    baseline = tomllib.load(baseline_file)

for function in baseline["extraction"]["functions"]:
    print(function)
PY
)"
SCOPE_ARGS=()
while IFS= read -r function; do
  if [[ -n "${function}" ]]; then
    SCOPE_ARGS+=(--start-from "${function}")
  fi
done <<< "${SCOPE_VALUES}"
if [[ "${#SCOPE_ARGS[@]}" -eq 0 ]]; then
  echo "verification baseline contains no Aeneas extraction functions" >&2
  exit 1
fi

mkdir -p "${LEAN_OUTPUT}"
(
  cd "${GENERATOR_DIR}"
  "${CHARON_BIN}" cargo \
    --preset aeneas \
    "${SCOPE_ARGS[@]}" \
    --dest-file "${LLBC_FILE}" \
    -- --locked --lib
)

python3 - "${LLBC_FILE}" <<'PY'
import pathlib
import sys

temporary_path = sys.argv[1]
llbc_path = pathlib.Path(temporary_path)
serialized = llbc_path.read_text()
occurrences = serialized.count(temporary_path)
if occurrences != 1:
    raise SystemExit(
        f"expected one temporary LLBC destination, found {occurrences}"
    )
llbc_path.write_text(serialized.replace(temporary_path, "ed25519_yao_generator.llbc"))
PY

"${AENEAS_BIN}" \
  -backend lean \
  -dest "${LEAN_OUTPUT}" \
  -subdir Ed25519Yao \
  -split-files \
  "${LLBC_FILE}"

for generated_file in Types.lean Funs.lean; do
  if [[ ! -f "${LEAN_OUTPUT}/Ed25519Yao/${generated_file}" ]]; then
    echo "Aeneas did not produce expected file ${generated_file}" >&2
    exit 1
  fi
done

rm -rf "${TARGET_DIR}"
mkdir -p "${TARGET_DIR}"
cp "${LEAN_OUTPUT}/Ed25519Yao/Types.lean" "${TARGET_DIR}/Types.lean"
cp "${LEAN_OUTPUT}/Ed25519Yao/Funs.lean" "${TARGET_DIR}/Funs.lean"

echo "Extracted wrapping_add_le_256 and clamp_rfc8032 into ${TARGET_DIR}"
