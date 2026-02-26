#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
REPO_DIR="$(cd "${ROOT_DIR}/.." && pwd)"
TRACKED_DIR="formal-verification/vectors/generated"

"${SCRIPT_DIR}/export-vectors.sh"

if ! git -C "${REPO_DIR}" diff --quiet -- "${TRACKED_DIR}"; then
  echo "error: generated vectors are out of date in ${TRACKED_DIR}"
  git -C "${REPO_DIR}" --no-pager diff -- "${TRACKED_DIR}"
  exit 1
fi

echo "ok: generated vectors are up to date"
