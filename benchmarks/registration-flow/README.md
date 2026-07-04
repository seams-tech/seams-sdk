# Registration Flow Benchmark

Status: retired during Refactor 88.

This benchmark depended on the deleted
`tests/e2e/thresholdEd25519.testUtils` managed-registration mock harness. The
Refactor 88 intended-behaviour suite now owns lifecycle correctness through the
real Router API, wallet iframe, IndexedDB, D1/DO, and workers, so the old mocked
benchmark runner was removed instead of resurrecting that broad helper.

Historical reports remain in `docs/benchmarks/registration-flow.md`.

A replacement registration latency benchmark should run against the real
intended-behaviour topology and reuse the public SDK/UI flow, with only external
network edges stubbed.
