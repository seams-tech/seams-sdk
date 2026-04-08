#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PIN_FILE="$ROOT_DIR/aeneas-toolchain.toml"
TOOLS_DIR="$ROOT_DIR/tools"

if ! command -v python3 >/dev/null 2>&1; then
  echo "python3 is required to parse $PIN_FILE" >&2
  exit 1
fi

if ! command -v git >/dev/null 2>&1; then
  echo "git is required to install Aeneas" >&2
  exit 1
fi

if ! command -v opam >/dev/null 2>&1; then
  echo "opam is required to install Aeneas; see https://ocaml.org/docs/install.html" >&2
  exit 1
fi

MAKE_BIN="make"
if command -v gmake >/dev/null 2>&1; then
  MAKE_BIN="gmake"
fi

PIN_VALUES="$(
  python3 - <<'PY' "$PIN_FILE"
import sys, tomllib
path = sys.argv[1]
with open(path, "rb") as f:
    data = tomllib.load(f)
print(data["aeneas"]["repo"])
print(data["aeneas"]["rev"])
print(data["charon"]["repo"])
print(data["charon"]["rev"])
print(data["lean"]["toolchain"])
PY
)
"

AENEAS_REPO="$(printf '%s\n' "$PIN_VALUES" | sed -n '1p')"
AENEAS_REV="$(printf '%s\n' "$PIN_VALUES" | sed -n '2p')"
CHARON_REPO="$(printf '%s\n' "$PIN_VALUES" | sed -n '3p')"
CHARON_REV="$(printf '%s\n' "$PIN_VALUES" | sed -n '4p')"
LEAN_TOOLCHAIN="$(printf '%s\n' "$PIN_VALUES" | sed -n '5p')"

mkdir -p "$TOOLS_DIR"

AENEAS_DIR="$TOOLS_DIR/aeneas"
CHARON_DIR="$TOOLS_DIR/charon"

if [ ! -d "$AENEAS_DIR/.git" ]; then
  git clone "$AENEAS_REPO" "$AENEAS_DIR"
fi

git -C "$AENEAS_DIR" fetch --all --tags
git -C "$AENEAS_DIR" checkout "$AENEAS_REV"

if [ ! -d "$CHARON_DIR/.git" ]; then
  git clone "$CHARON_REPO" "$CHARON_DIR"
fi

git -C "$CHARON_DIR" fetch --all --tags
git -C "$CHARON_DIR" checkout "$CHARON_REV"

rm -rf "$AENEAS_DIR/charon"
ln -s "$CHARON_DIR" "$AENEAS_DIR/charon"

echo "Using Lean toolchain: $LEAN_TOOLCHAIN"
echo "Installing Aeneas OCaml dependencies via opam"
opam install -y ppx_deriving visitors easy_logging zarith yojson core_unix odoc \
  ocamlgraph menhir ocamlformat.0.27.0 unionFind zarith progress domainslib

echo "Building pinned Charon through Aeneas"
"$MAKE_BIN" -C "$AENEAS_DIR" setup-charon

echo "Building pinned Aeneas"
"$MAKE_BIN" -C "$AENEAS_DIR"

echo
echo "Aeneas bootstrap complete."
echo "Add the following to PATH for this shell:"
echo "  export PATH=\"$AENEAS_DIR/bin:\$PATH\""
