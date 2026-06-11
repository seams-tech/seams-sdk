# iOS HSS Benchmark Procedure

This procedure is for measuring whether Ed25519 HSS should be default,
optional, or policy-gated in native iOS contexts.

The target measurement is the same work captured by
`benchmark_ddh_hidden_eval_embedded_profile`: hidden-eval stage timing,
delivery timing, total allocated bytes, allocation calls, peak live bytes above
start, artifact size, active windows, and total circuit steps.

## Targets

Run all measurements on physical devices. Simulator numbers are useful only for
smoke testing the bridge.

- Recent iPhone, release build
- Older supported iPhone, release build
- Recent iPad if iPad support is expected
- iOS WebView/WASM separately, because it uses browser-style runtime behavior

## Rust Build

Install iOS Rust targets:

```sh
rustup target add aarch64-apple-ios aarch64-apple-ios-sim
```

Smoke-check the crate before wiring Xcode:

```sh
cargo check --manifest-path crates/ed25519-hss/Cargo.toml --target aarch64-apple-ios --lib
cargo check --manifest-path crates/ed25519-hss/Cargo.toml --target aarch64-apple-ios-sim --lib
```

The benchmark should call library code directly rather than shelling out to the
CLI binary. Keep the measured profile equivalent to:

```rust
let timing = generate_ddh_hidden_eval_benchmark_report(&timing_config)?;
let mut recorder = NativeAllocationRecorderEquivalent::new();
let allocation = generate_ddh_hidden_eval_allocation_probe_report(
    &allocation_config,
    &mut recorder,
)?;
```

The iOS allocation recorder must wrap Swift or C allocation telemetry at the
benchmark boundary. If that is not available yet, report timing first and mark
allocation fields unavailable. Do not substitute simulator allocator numbers for
device allocation numbers.

## Xcode Harness

Create a small release-only benchmark app or XCTest target:

1. Link the Rust static or dynamic library produced for `aarch64-apple-ios`.
2. Expose one FFI function that returns the embedded profile JSON bytes.
3. Run the benchmark from a release build on the device.
4. Write the JSON report to the app documents directory.
5. Pull the report with Xcode Devices, `xcrun devicectl`, or an XCTest
   attachment.

The FFI boundary should return one of two states:

```text
ok(json_utf8_bytes)
err(code, message)
```

Keep raw C pointers and optional fields at the FFI boundary. Parse into precise
Rust or Swift result branches immediately after crossing the boundary.

## Recommended Profile Settings

Use the same defaults as the ARM64 Linux runner unless the device overheats or
thermal-throttles:

```text
primitive_warmup_iterations = 0
primitive_sample_iterations = 1
stage_warmup_iterations = 1
stage_sample_iterations = 1
stage_sample_count = 8
allocation_warmup_iterations = 1
allocation_sample_count = 5
```

For older devices, also run a short profile:

```text
stage_sample_count = 4
allocation_sample_count = 3
```

## Report Location

Copy reports into:

```text
crates/ed25519-hss/docs/benchmarks/refactor-64/ios/
```

Use filenames with device class and run id:

```text
ddh-hidden-eval-embedded-profile-ios-iphone15pro-20260610-120000Z.json
ddh-hidden-eval-embedded-profile-ios-iphone12-20260610-120000Z.json
```

## Decision Gate

Record HSS as the default for native iOS only if all are true on supported
physical devices:

- registration-visible HSS work stays below the product target after preauth
  overlap
- `total_hidden_eval` p50 and p95 are stable across repeated release runs
- peak live memory is acceptable for the lowest supported device
- thermal throttling does not materially change p95
- WebView/WASM remains separately evaluated for browser-context threat model

If native iOS is fast but WebView/WASM is slower, gate by runtime class rather
than platform name.
