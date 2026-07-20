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

if [[ "${ROUTER_AB_USE_PREBUILT:-0}" == "1" ]]; then
  : "${ROUTER_AB_DEPLOY_TARGET:?ROUTER_AB_DEPLOY_TARGET is required for prebuilt Workers}"
  : "${ROUTER_AB_DEPLOY_SHA:?ROUTER_AB_DEPLOY_SHA is required for prebuilt Workers}"
  artifact_identity_json="${ROUTER_AB_ARTIFACT_IDENTITY_JSON:-"{}"}"
  node ../../scripts/deployment-artifact.mjs verify \
    --kind "$role" \
    --target "$ROUTER_AB_DEPLOY_TARGET" \
    --sha "$ROUTER_AB_DEPLOY_SHA" \
    --root "build/$role" \
    --manifest ".release-artifacts/$role.json" \
    --identity-json "$artifact_identity_json"
  exit 0
fi

worker-build \
  "${worker_build_flags[@]}" \
  --out-dir "build/$role" \
  --features "strict-worker-$role-entrypoint"
