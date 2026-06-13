# Benchmarking

Benchmarks must compare candidates under realistic deployment assumptions.

## Required Measurements

- local native release
- wasm32 release bundle
- Workers adapter cold-start bundle size
- registration ceremony latency
- export ceremony latency
- refresh ceremony latency
- A/B coordination round trips
- Router invocation count
- Deriver A invocation count
- Deriver B invocation count

## Candidate Gate

The faster candidate can be preferred only after leakage analysis passes.
Benchmark results must include p50, p95, and round-trip count.
