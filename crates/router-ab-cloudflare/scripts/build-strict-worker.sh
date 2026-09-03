#!/usr/bin/env bash

set -euo pipefail

role="${1:-}"
case "$role" in
  router|deriver-a|deriver-b|signing-worker|tenant-root-control-plane) ;;
  *)
    echo "usage: build-strict-worker.sh <router|deriver-a|deriver-b|signing-worker|tenant-root-control-plane>" >&2
    exit 2
    ;;
esac

worker_build_profile="${ROUTER_AB_WORKER_BUILD_PROFILE:-release}"
worker_rustflags=""
case "$worker_build_profile" in
  dev)
    worker_build_flags=(--dev --no-opt)
    worker_rustflags="${RUSTFLAGS:-}"
    if [[ -n "$worker_rustflags" ]]; then
      worker_rustflags+=" "
    fi
    worker_rustflags+="-C link-arg=-zstack-size=4194304"
    ;;
  release)
    worker_build_flags=(--release)
    ;;
  *)
    echo "invalid ROUTER_AB_WORKER_BUILD_PROFILE: $worker_build_profile (expected dev or release)" >&2
    exit 2
    ;;
esac

run_worker_build() {
  if [[ "$worker_build_profile" == "dev" ]]; then
    RUSTFLAGS="$worker_rustflags" worker-build "$@"
  else
    worker-build "$@"
  fi
}

run_worker_build \
  "${worker_build_flags[@]}" \
  --out-dir "build/$role" \
  --features "strict-worker-$role-entrypoint"
