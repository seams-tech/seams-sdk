#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../../.." && pwd)"

OUT_DIR="${OUT_DIR:-$REPO_ROOT/crates/ed25519-hss/docs/benchmarks/refactor-64/embedded}"
FIXTURE="${FIXTURE:-}"
PRIMITIVE_WARMUP="${PRIMITIVE_WARMUP:-0}"
PRIMITIVE_ITERATIONS="${PRIMITIVE_ITERATIONS:-1}"
STAGE_WARMUP="${STAGE_WARMUP:-1}"
STAGE_ITERATIONS="${STAGE_ITERATIONS:-1}"
STAGE_SAMPLES="${STAGE_SAMPLES:-8}"
ALLOCATION_WARMUP="${ALLOCATION_WARMUP:-1}"
ALLOCATION_SAMPLES="${ALLOCATION_SAMPLES:-5}"
CARGO_TARGET="${CARGO_TARGET:-}"
REQUIRE_ARM64_LINUX="${REQUIRE_ARM64_LINUX:-0}"

usage() {
  cat <<'USAGE'
Run the DDH hidden-eval embedded profile as a native ARM64 Linux benchmark.

Usage:
  bash crates/ed25519-hss/scripts/run_embedded_profile_arm64_linux.sh [options]

Options:
  --out-dir <path>             Output directory for JSON reports
  --fixture <name>             Deterministic fixture name
  --primitive-warmup <n>       Primitive warmup iterations
  --primitive-iterations <n>   Primitive iterations per timed sample
  --stage-warmup <n>           Hidden-eval warmup iterations
  --stage-iterations <n>       Hidden-eval executions per timed sample
  --stage-samples <n>          Number of hidden-eval timing samples
  --allocation-warmup <n>      Allocation warmup iterations
  --allocation-samples <n>     Number of allocation samples
  --cargo-target <triple>      Optional cargo target triple
  --require-arm64-linux        Fail unless running on Linux ARM64/aarch64
  -h, --help                   Show this help

Environment overrides:
  OUT_DIR, FIXTURE, PRIMITIVE_WARMUP, PRIMITIVE_ITERATIONS, STAGE_WARMUP,
  STAGE_ITERATIONS, STAGE_SAMPLES, ALLOCATION_WARMUP, ALLOCATION_SAMPLES,
  CARGO_TARGET, REQUIRE_ARM64_LINUX

Recommended use:
  Run this script directly on the target ARM64 Linux device. Cross-compiling
  with --cargo-target only builds the binary; it does not make execution native
  unless the target binary can run on the current machine.
USAGE
}

read_value() {
  local name="$1"
  shift
  if [[ $# -eq 0 || -z "$1" || "$1" == --* ]]; then
    echo "$name requires a value" >&2
    exit 2
  fi
  printf '%s' "$1"
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --out-dir)
      OUT_DIR="$(read_value "$1" "${2:-}")"
      shift 2
      ;;
    --fixture)
      FIXTURE="$(read_value "$1" "${2:-}")"
      shift 2
      ;;
    --primitive-warmup)
      PRIMITIVE_WARMUP="$(read_value "$1" "${2:-}")"
      shift 2
      ;;
    --primitive-iterations)
      PRIMITIVE_ITERATIONS="$(read_value "$1" "${2:-}")"
      shift 2
      ;;
    --stage-warmup)
      STAGE_WARMUP="$(read_value "$1" "${2:-}")"
      shift 2
      ;;
    --stage-iterations)
      STAGE_ITERATIONS="$(read_value "$1" "${2:-}")"
      shift 2
      ;;
    --stage-samples)
      STAGE_SAMPLES="$(read_value "$1" "${2:-}")"
      shift 2
      ;;
    --allocation-warmup)
      ALLOCATION_WARMUP="$(read_value "$1" "${2:-}")"
      shift 2
      ;;
    --allocation-samples)
      ALLOCATION_SAMPLES="$(read_value "$1" "${2:-}")"
      shift 2
      ;;
    --cargo-target)
      CARGO_TARGET="$(read_value "$1" "${2:-}")"
      shift 2
      ;;
    --require-arm64-linux)
      REQUIRE_ARM64_LINUX="1"
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "unknown argument: $1" >&2
      usage >&2
      exit 2
      ;;
  esac
done

HOST_OS="$(uname -s | tr '[:upper:]' '[:lower:]')"
HOST_ARCH="$(uname -m | tr '[:upper:]' '[:lower:]')"
case "$HOST_ARCH" in
  aarch64|arm64)
    HOST_IS_ARM64="1"
    ;;
  *)
    HOST_IS_ARM64="0"
    ;;
esac

if [[ "$REQUIRE_ARM64_LINUX" == "1" ]]; then
  if [[ "$HOST_OS" != "linux" || "$HOST_IS_ARM64" != "1" ]]; then
    echo "expected native Linux ARM64/aarch64, got ${HOST_OS}/${HOST_ARCH}" >&2
    exit 1
  fi
elif [[ "$HOST_OS" != "linux" || "$HOST_IS_ARM64" != "1" ]]; then
  echo "[embedded-profile] warning: expected Linux ARM64/aarch64, got ${HOST_OS}/${HOST_ARCH}; running as a smoke/profile on this host" >&2
fi

mkdir -p "$OUT_DIR"
RUN_ID="$(date -u +%Y%m%d-%H%M%SZ)"
OUT_JSON="$OUT_DIR/ddh-hidden-eval-embedded-profile-${HOST_OS}-${HOST_ARCH}-${RUN_ID}.json"

CARGO_ARGS=(
  run
  --release
  --manifest-path
  crates/ed25519-hss/Cargo.toml
)
if [[ -n "$CARGO_TARGET" ]]; then
  CARGO_ARGS+=(--target "$CARGO_TARGET")
fi
CARGO_ARGS+=(
  --bin
  benchmark_ddh_hidden_eval_embedded_profile
  --
  --primitive-warmup "$PRIMITIVE_WARMUP"
  --primitive-iterations "$PRIMITIVE_ITERATIONS"
  --stage-warmup "$STAGE_WARMUP"
  --stage-iterations "$STAGE_ITERATIONS"
  --stage-samples "$STAGE_SAMPLES"
  --allocation-warmup "$ALLOCATION_WARMUP"
  --allocation-samples "$ALLOCATION_SAMPLES"
  --output "$OUT_JSON"
)

if [[ -n "$FIXTURE" ]]; then
  CARGO_ARGS+=(--fixture "$FIXTURE")
fi

echo "[embedded-profile] host=${HOST_OS}/${HOST_ARCH} output=$OUT_JSON"
(
  cd "$REPO_ROOT"
  cargo "${CARGO_ARGS[@]}"
)
echo "[embedded-profile] wrote $OUT_JSON"
