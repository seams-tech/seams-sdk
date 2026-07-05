# Refactor 83C: Cloudflare HSS Native Service Decision

Date created: July 5, 2026
Updated: July 5, 2026

Status: shelved after measurement.

## Decision

Cloudflare registration Ed25519 HSS stays on the Worker/WASM path.

The native Rust sidecar and Cloudflare Container direction is shelved. The
measured latency win is too small to justify a second runtime, capacity
reservation model, preflight warmup API, Docker packaging, service-token trust
boundary, and local intended-service divergence.

Refactor 83B remains the active implementation path:

- early `/wallets/register/hss/advance-state` submission;
- durable `ed25519_hss_advanced_eval_v1` records;
- durable `ed25519_hss_finalized_report_v1` records for HSS-level retry;
- advance/finalize provenance diagnostics;
- no persisted WASM handles;
- no serialized replay as a normal registration finalize source.

## Historical Notes

The original 83C direction assumed Cloudflare workerd WASM would remain around
`2.8-2.9s` for registration HSS advance. That assumption came from stale
`wasm/near_signer/pkg-server` artifacts built before the `ed25519-hss` pool fix
was compiled into the server WASM bundle.

After rebuilding the server WASM, the measured sources were:

| Source | Median | p95 | Notes |
| --- | ---: | ---: | --- |
| Worker-class server WASM probe | `~325ms` | `~333ms` | rebuilt bundle with the pool fix |
| Native Rust sidecar, cold | `~329ms` | similar | no materialized-session warm cache |
| Native Rust sidecar, warm cache | `~267ms` | `~276ms` | about `60ms` faster before Worker-to-service hop costs |
| Stale pre-fix server WASM | `~2,478ms` | higher | obsolete artifact that caused the misleading baseline |

The useful fix was in the shared HSS implementation: one hidden-eval pool per
server advance operation, threaded through the validated stage methods. Once
that code reached the Worker WASM artifact, native execution no longer carried
the latency case.

## Cleanup Scope

- [x] Remove SDK preflight HSS warmup calls.
- [x] Remove `/wallets/register/hss/warmup` from the public route surface.
- [x] Remove `registrationHssWarmup*` timing buckets and diagnostics.
- [x] Remove Cloudflare/native sidecar configuration from D1 router options and
      staging Worker env mapping.
- [x] Remove native service startup from intended-test local services.
- [x] Make intended registration provenance accept only
      `durable_workerd_wasm` for advance.
- [x] Remove native service port, unit tests, Docker packaging, and container
      smoke scripts.
- [x] Update source guards so retired native/warmup hooks fail if reintroduced.

## What Stays

- The HSS pool fix in `crates/ed25519-hss`.
- The benchmark harness that compares advance sources. Optional native URLs may
  be supplied by an external experiment, while the repository runtime stays
  Worker/WASM-only.
- The 83B durable advance/finalized-report model.
- Provenance diagnostics for advance and finalize.

## Why 83B Still Matters

The rebuilt Worker WASM makes the HSS advance itself fast enough. It does not
replace the 83B durable protocol split.

83B still gives us:

- overlap between server advance and client artifact construction;
- deterministic retry behavior after a Worker restart;
- a claim/lease that prevents duplicate advance work;
- HSS-level idempotency before whole-route finalize completes;
- provenance that catches accidental serialized replay.

Those are correctness and critical-path properties independent of the execution
engine.

## Exit Criteria

- [x] `pnpm build:wasm` produces Worker WASM with the shared pool fix.
- [x] `benchmark:ed25519-hss:advance-sources -- --skip-optional` reports
      Worker-class WASM median below `600ms`.
- [x] Intended registration traces report advance source `durable_workerd_wasm`.
- [x] No product/runtime path imports a native HSS service port or starts a
      native HSS sidecar.

Final verification, July 5, 2026:

- `SEAMS_INTENDED_PERSIST_TRACE=1 SEAMS_INTENDED_SKIP_BUILD=1 pnpm -C tests exec playwright test -c playwright.intended.benchmark.ci.config.ts e2e/intended-behaviours/passkey.registration.benchmark.test.ts e2e/intended-behaviours/email-otp.registration.benchmark.test.ts --reporter=line`
  passed.
- Email OTP registration: total `2,766ms`, advance `561ms`, finalize `637ms`,
  advance source `durable_workerd_wasm`, finalize source
  `durable_advanced_eval`, violations `[]`.
- Passkey registration: total `3,122ms`, advance `542ms`, finalize `590ms`,
  advance source `durable_workerd_wasm`, finalize source
  `durable_advanced_eval`, violations `[]`.
