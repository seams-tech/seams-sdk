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

if [ "$role" = "router" ] || [ "$role" = "signing-worker" ]; then
  for name in \
    ROUTER_AB_ECDSA_COMMITMENT_POLICY_RELEASE_AUTHORITY_PUBLIC_KEY_HEX \
    ROUTER_AB_ECDSA_COMMITMENT_POLICY_DIGEST_HEX \
    ROUTER_AB_ECDSA_COMMITMENT_POLICY_MINIMUM_RELEASE_EPOCH
  do
    if [ -z "${!name:-}" ]; then
      echo "missing required ECDSA commitment-policy build pin: $name" >&2
      exit 1
    fi
  done
fi

worker-build \
  --release \
  --out-dir "build/$role" \
  --features "strict-worker-$role-entrypoint"
