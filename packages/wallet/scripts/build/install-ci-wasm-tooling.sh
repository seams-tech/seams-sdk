#!/usr/bin/env bash

set -euo pipefail

if [[ "$(uname -s)" != "Linux" || "$(uname -m)" != "x86_64" ]]; then
  echo "install-ci-wasm-tooling.sh supports x86_64 Linux CI runners only" >&2
  exit 2
fi

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../../.." && pwd)"
wasm_pack_version="0.13.1"
wasm_pack_sha256="c539d91ccab2591a7e975bcf82c82e1911b03335c80aa83d67ad25ed2ad06539"
tooling_root="$repo_root/packages/sdk-web/.tooling/wasm-bindgen"
temp_dir="$(mktemp -d)"

cleanup() {
  rm -rf "$temp_dir"
}
trap cleanup EXIT

expected_wasm_bindgen_sha256() {
  case "$1" in
    0.2.100) printf '%s\n' "63d6a38deb65bd7023c02bdf382ab66b0d2c0241c8582fd3413b5a808b8aeb5b" ;;
    0.2.108) printf '%s\n' "d15d7e476feec78d0ec9edc27b8f77279ec7a3e6227756e7036e5cd2066800f4" ;;
    0.2.113) printf '%s\n' "0366bf5936d5e2578b06fc318a5696ddecfb66382e671e51f469b83f3494712f" ;;
    0.2.118) printf '%s\n' "00b519c9fc2d6e087265da1a00f29160bfcc6a823993482bc2e691910287427b" ;;
    0.2.126) printf '%s\n' "064948d58e2d6c0a745216477a639ba696216d6309aaa902939d1b865b1d869d" ;;
    *)
      echo "No pinned wasm-bindgen checksum for version $1" >&2
      return 1
      ;;
  esac
}

verify_sha256() {
  local expected="$1"
  local path="$2"
  printf '%s  %s\n' "$expected" "$path" | sha256sum --check --status
}

install_wasm_pack() {
  local archive="$temp_dir/wasm-pack.tar.gz"
  local extracted="$temp_dir/wasm-pack"
  if command -v wasm-pack > /dev/null &&
    [[ "$(wasm-pack --version | awk '{print $2}')" == "$wasm_pack_version" ]]; then
    return
  fi
  curl --fail --location --silent --show-error \
    "https://github.com/rustwasm/wasm-pack/releases/download/v${wasm_pack_version}/wasm-pack-v${wasm_pack_version}-x86_64-unknown-linux-musl.tar.gz" \
    --output "$archive"
  verify_sha256 "$wasm_pack_sha256" "$archive"
  mkdir -p "$extracted" "$HOME/.cargo/bin"
  tar -xzf "$archive" --strip-components=1 --directory "$extracted"
  install -m 0755 "$extracted/wasm-pack" "$HOME/.cargo/bin/wasm-pack"
}

install_wasm_bindgen() {
  local version="$1"
  local expected_sha256
  local archive_name="wasm-bindgen-${version}-x86_64-unknown-linux-musl"
  local archive="$temp_dir/${archive_name}.tar.gz"
  local destination="$tooling_root/$version/bin"
  expected_sha256="$(expected_wasm_bindgen_sha256 "$version")"

  if [[ -x "$destination/wasm-bindgen" ]] &&
    [[ "$("$destination/wasm-bindgen" --version | awk '{print $2}')" == "$version" ]]; then
    return
  fi

  curl --fail --location --silent --show-error \
    "https://github.com/wasm-bindgen/wasm-bindgen/releases/download/${version}/${archive_name}.tar.gz" \
    --output "$archive"
  verify_sha256 "$expected_sha256" "$archive"
  mkdir -p "$destination"
  tar -xzf "$archive" --strip-components=1 --directory "$temp_dir"
  install -m 0755 "$temp_dir/wasm-bindgen" "$destination/wasm-bindgen"
  install -m 0755 "$temp_dir/wasm-bindgen-test-runner" "$destination/wasm-bindgen-test-runner"
  install -m 0755 "$temp_dir/wasm2es6js" "$destination/wasm2es6js"
}

mapfile -t wasm_bindgen_versions < <(
  find \
    "$repo_root/wasm" \
    "$repo_root/crates/router-ab-ed25519-yao-client" \
    -name Cargo.lock \
    -print0 |
    xargs -0 awk '
      $0 == "name = \"wasm-bindgen\"" { found = 1; next }
      found && $1 == "version" {
        gsub(/"/, "", $3)
        print $3
        found = 0
      }
    ' |
    sort -u
)

install_wasm_pack
for version in "${wasm_bindgen_versions[@]}"; do
  install_wasm_bindgen "$version"
done

echo "Installed wasm-pack ${wasm_pack_version} and wasm-bindgen versions: ${wasm_bindgen_versions[*]}"
