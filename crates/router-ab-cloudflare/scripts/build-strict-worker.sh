#!/usr/bin/env bash

set -euo pipefail

role="${1:-}"
case "$role" in
  router|deriver-a|deriver-b|signing-worker) ;;
  *)
    echo "usage: build-strict-worker.sh <router|deriver-a|deriver-b|signing-worker>" >&2
    exit 2
    ;;
esac

worker_build_profile="${ROUTER_AB_WORKER_BUILD_PROFILE:-release}"
case "$worker_build_profile" in
  dev)
    worker_build_flags=(--dev --no-opt)
    ;;
  release)
    worker_build_flags=(--release)
    ;;
  *)
    echo "invalid ROUTER_AB_WORKER_BUILD_PROFILE: $worker_build_profile (expected dev or release)" >&2
    exit 2
    ;;
esac

worker-build \
  "${worker_build_flags[@]}" \
  --out-dir "build/$role" \
  --features "strict-worker-$role-entrypoint"
