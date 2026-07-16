# `threshold-prf` Worker Benchmark Harness

This fixture benchmarks the exported `wasm/threshold_prf` Router A/B ECDSA derivation
functions inside a real Cloudflare Worker isolate.

Build the WASM package for the Worker fixture:

```bash
just threshold-prf-worker-bench-build
```

Run locally with Wrangler:

```bash
just threshold-prf-worker-bench-dev
```

Check that warm local Worker requests reuse initialized WASM state:

```bash
just threshold-prf-worker-bench-init-check
```

Deploy with Wrangler:

```bash
just threshold-prf-worker-bench-deploy
```

Collect deployed samples:

```bash
just threshold-prf-worker-bench-run https://threshold-prf-worker-bench.<account>.workers.dev
```

The harness uses deterministic public benchmark fixtures. Do not replace them
with production signing-root shares.

Endpoints:

- `/` returns harness metadata.
- `/noop` returns a minimal response for external request-overhead sampling.
- `/bench?iterations=1000&warmup=20` runs the in-isolate benchmark suite.

Cold-start measurements are sampled by the first request observed by an isolate.
For reliable cold-path measurements, deploy a fresh Worker version or wait for
the Worker to go idle, then call `/bench` once before warm sampling.
