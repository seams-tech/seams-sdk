#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT_DIR"

missing=0

echo "[check-repo-paths] checking pnpm workspace package directories..."
while IFS= read -r pkg; do
  [[ -z "$pkg" ]] && continue
  if [[ ! -d "$pkg" ]]; then
    echo "[check-repo-paths] missing workspace package directory: $pkg"
    missing=1
  fi
done < <(awk '/^[[:space:]]*-[[:space:]]*/ { sub(/^[[:space:]]*-[[:space:]]*/, ""); print }' pnpm-workspace.yaml)

echo "[check-repo-paths] checking README local path references..."
while IFS= read -r ref; do
  [[ -z "$ref" ]] && continue
  ref="${ref%,}"
  ref="${ref%.}"

  if [[ "$ref" =~ ^https?:// ]]; then
    continue
  fi

  if [[ "$ref" == @* ]]; then
    continue
  fi

  if [[ "$ref" == */* ]] && [[ "$ref" != *" "* ]]; then
    if [[ ! -e "$ref" ]]; then
      echo "[check-repo-paths] missing README path reference: $ref"
      missing=1
    fi
  fi
done < <(grep -oE '`[^`]+`' README.md | tr -d '`' | sort -u)

if [[ "$missing" -ne 0 ]]; then
  echo "[check-repo-paths] failed"
  exit 1
fi

echo "[check-repo-paths] OK"
