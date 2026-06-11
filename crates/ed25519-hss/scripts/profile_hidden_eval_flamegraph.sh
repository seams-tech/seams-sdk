#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../../.." && pwd)"
OUT_DIR="${OUT_DIR:-$REPO_ROOT/crates/ed25519-hss/docs/benchmarks/refactor-64/flamegraphs}"
SAMPLES="${SAMPLES:-16}"
STAGE_WARMUP="${STAGE_WARMUP:-1}"
PRIMITIVE_WARMUP="${PRIMITIVE_WARMUP:-0}"
PRIMITIVE_ITERATIONS="${PRIMITIVE_ITERATIONS:-1}"
STAGE_ITERATIONS="${STAGE_ITERATIONS:-1}"
FIXTURE="${FIXTURE:-}"

usage() {
  cat <<'USAGE'
Profile native DDH hidden eval with cargo-flamegraph.

Usage:
  bash crates/ed25519-hss/scripts/profile_hidden_eval_flamegraph.sh [options]

Options:
  --samples <n>              Benchmark samples passed to benchmark_ddh_hidden_eval
  --stage-warmup <n>         Stage warmup iterations
  --stage-iterations <n>     Stage iterations per sample
  --primitive-warmup <n>     Primitive warmup iterations
  --primitive-iterations <n> Primitive iterations per sample
  --fixture <name>           Deterministic fixture name
  --out-dir <path>           Output directory for SVG files
  -h, --help                 Show this help

Environment overrides:
  SAMPLES, STAGE_WARMUP, STAGE_ITERATIONS, PRIMITIVE_WARMUP,
  PRIMITIVE_ITERATIONS, FIXTURE, OUT_DIR

Requires:
  cargo install flamegraph

On macOS, cargo-flamegraph may require dtrace permissions. On Linux, it usually
requires perf permissions. The script only sets up a stable benchmark command
and output location.
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
    --samples)
      SAMPLES="$(read_value "$1" "${2:-}")"
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
    --primitive-warmup)
      PRIMITIVE_WARMUP="$(read_value "$1" "${2:-}")"
      shift 2
      ;;
    --primitive-iterations)
      PRIMITIVE_ITERATIONS="$(read_value "$1" "${2:-}")"
      shift 2
      ;;
    --fixture)
      FIXTURE="$(read_value "$1" "${2:-}")"
      shift 2
      ;;
    --out-dir)
      OUT_DIR="$(read_value "$1" "${2:-}")"
      shift 2
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

if ! cargo flamegraph --help >/dev/null 2>&1; then
  echo "cargo-flamegraph is required. Install with: cargo install flamegraph" >&2
  exit 1
fi

mkdir -p "$OUT_DIR"
RUN_ID="$(date -u +%Y%m%d-%H%M%SZ)"
OUT_SVG="$OUT_DIR/ddh-hidden-eval-$RUN_ID.svg"

BENCH_ARGS=(
  --primitive-warmup "$PRIMITIVE_WARMUP"
  --primitive-iterations "$PRIMITIVE_ITERATIONS"
  --stage-warmup "$STAGE_WARMUP"
  --stage-iterations "$STAGE_ITERATIONS"
  --samples "$SAMPLES"
)

if [[ -n "$FIXTURE" ]]; then
  BENCH_ARGS+=(--fixture "$FIXTURE")
fi

echo "[profile-hidden-eval] writing $OUT_SVG"
(
  cd "$REPO_ROOT"
  CARGO_PROFILE_RELEASE_DEBUG=true cargo flamegraph \
    --manifest-path crates/ed25519-hss/Cargo.toml \
    --bin benchmark_ddh_hidden_eval \
    --output "$OUT_SVG" \
    -- "${BENCH_ARGS[@]}"
)

echo "[profile-hidden-eval] wrote $OUT_SVG"
