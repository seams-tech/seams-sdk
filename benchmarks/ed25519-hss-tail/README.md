# Ed25519 HSS Tail Benchmark

Focused Refactor 83D benchmark for the registration HSS critical path.

It runs one deterministic durable Worker/D1-style fixture through:

- add-stage request preparation;
- client artifact build with explicit add-stage verification;
- durable server advance;
- durable-advanced finalize report;
- durable finalize with folded server output opening;
- optional folded seed output opening.

The harness forces `preparedSessionHandle: ""` for server advance/finalize/open
steps so it measures the durable path, not process-local handle caches.

Run:

```bash
pnpm benchmark:ed25519-hss:tail
```

Useful options:

```bash
node ./benchmarks/ed25519-hss-tail/src/runner.mjs --iterations 10
node ./benchmarks/ed25519-hss-tail/src/runner.mjs --warmup 2 --iterations 12
```

Outputs:

- `benchmarks/ed25519-hss-tail/out/<timestamp>/raw-summary.json`
- `benchmarks/ed25519-hss-tail/out/<timestamp>/summary.md`

The summary includes a Stage Loop Microbenchmarks table derived from the same
deterministic fixture. It isolates advance message-schedule, advance
round-core, advance output projection, and client hidden-eval sub-buckets for
Refactor 83D loop work.
