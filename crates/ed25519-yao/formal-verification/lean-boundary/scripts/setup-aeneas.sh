#!/usr/bin/env bash
set -euo pipefail

BOUNDARY_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PIN_FILE="${BOUNDARY_DIR}/../toolchain.toml"
TOOLS_DIR="${BOUNDARY_DIR}/tools"

for program in python3 git opam; do
  if ! command -v "${program}" >/dev/null 2>&1; then
    echo "${program} is required to bootstrap the pinned Aeneas toolchain" >&2
    exit 1
  fi
done

MAKE_BIN="make"
if command -v gmake >/dev/null 2>&1; then
  MAKE_BIN="gmake"
fi

PIN_VALUES="$(
  python3 - "${PIN_FILE}" <<'PY'
import sys
import tomllib

with open(sys.argv[1], "rb") as pin_file:
    pins = tomllib.load(pin_file)

print(pins["aeneas"]["repo"])
print(pins["aeneas"]["rev"])
print(pins["charon"]["repo"])
print(pins["charon"]["rev"])
PY
)"

AENEAS_REPO="$(printf '%s\n' "${PIN_VALUES}" | sed -n '1p')"
AENEAS_REV="$(printf '%s\n' "${PIN_VALUES}" | sed -n '2p')"
CHARON_REPO="$(printf '%s\n' "${PIN_VALUES}" | sed -n '3p')"
CHARON_REV="$(printf '%s\n' "${PIN_VALUES}" | sed -n '4p')"
AENEAS_DIR="${TOOLS_DIR}/aeneas"
CHARON_DIR="${TOOLS_DIR}/charon"

checkout_pin() {
  local repository="$1"
  local revision="$2"
  local destination="$3"
  if [[ ! -d "${destination}/.git" ]]; then
    git clone --no-checkout "${repository}" "${destination}"
  fi
  git -C "${destination}" fetch origin "${revision}"
  git -C "${destination}" checkout --detach "${revision}"
  test "$(git -C "${destination}" rev-parse HEAD)" = "${revision}"
}

mkdir -p "${TOOLS_DIR}"
checkout_pin "${AENEAS_REPO}" "${AENEAS_REV}" "${AENEAS_DIR}"
checkout_pin "${CHARON_REPO}" "${CHARON_REV}" "${CHARON_DIR}"

rm -rf "${AENEAS_DIR}/charon"
ln -s "${CHARON_DIR}" "${AENEAS_DIR}/charon"

opam install -y ppx_deriving visitors easy_logging zarith yojson core_unix odoc \
  ocamlgraph menhir ocamlformat.0.27.0 unionFind progress domainslib
"${MAKE_BIN}" -C "${AENEAS_DIR}" setup-charon
"${MAKE_BIN}" -C "${AENEAS_DIR}"

test -x "${AENEAS_DIR}/bin/aeneas"
test -x "${CHARON_DIR}/bin/charon"
echo "Pinned Aeneas and Charon toolchains are ready under ${TOOLS_DIR}"
