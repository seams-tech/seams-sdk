#!/bin/bash

if [ -z "${SDK_ROOT:-}" ]; then
  echo "SDK_ROOT must be set before sourcing build-output-lock.sh" >&2
  exit 1
fi

BUILD_OUTPUT_LOCK_DIR="$SDK_ROOT/.tooling/build-locks/wasm-package-output"
BUILD_OUTPUT_LOCK_ACQUIRED=0

build_output_lock_warning() {
  if declare -F print_warning >/dev/null 2>&1; then
    print_warning "$1"
    return
  fi
  echo "warning: $1"
}

release_build_output_lock() {
  if [ "$BUILD_OUTPUT_LOCK_ACQUIRED" != "1" ]; then
    return
  fi
  rm -f "$BUILD_OUTPUT_LOCK_DIR/pid" 2>/dev/null || true
  rmdir "$BUILD_OUTPUT_LOCK_DIR" 2>/dev/null || true
  BUILD_OUTPUT_LOCK_ACQUIRED=0
}

build_output_lock_process_is_running() {
  local pid="$1"
  [ -n "$pid" ] && kill -0 "$pid" 2>/dev/null
}

try_remove_stale_build_output_lock() {
  local lock_pid
  if [ ! -f "$BUILD_OUTPUT_LOCK_DIR/pid" ]; then
    build_output_lock_warning "Removing stale WASM package-output lock with missing pid"
    rm -rf "$BUILD_OUTPUT_LOCK_DIR"
    return
  fi
  lock_pid="$(cat "$BUILD_OUTPUT_LOCK_DIR/pid" 2>/dev/null || true)"
  if build_output_lock_process_is_running "$lock_pid"; then
    return
  fi
  build_output_lock_warning "Removing stale WASM package-output lock from pid ${lock_pid:-unknown}"
  rm -rf "$BUILD_OUTPUT_LOCK_DIR"
}

acquire_build_output_lock() {
  local lock_parent
  local attempts=0
  if [ "${SEAMS_SDK_BUILD_OUTPUT_LOCK_HELD:-}" = "1" ]; then
    return
  fi
  lock_parent="$(dirname "$BUILD_OUTPUT_LOCK_DIR")"
  mkdir -p "$lock_parent"
  until mkdir "$BUILD_OUTPUT_LOCK_DIR" 2>/dev/null; do
    attempts=$((attempts + 1))
    try_remove_stale_build_output_lock
    if [ $((attempts % 15)) -eq 0 ]; then
      build_output_lock_warning "Waiting for another SDK/WASM build to release $BUILD_OUTPUT_LOCK_DIR"
    fi
    sleep 2
  done
  BUILD_OUTPUT_LOCK_ACQUIRED=1
  export SEAMS_SDK_BUILD_OUTPUT_LOCK_HELD=1
  printf '%s\n' "$$" >"$BUILD_OUTPUT_LOCK_DIR/pid"
}
