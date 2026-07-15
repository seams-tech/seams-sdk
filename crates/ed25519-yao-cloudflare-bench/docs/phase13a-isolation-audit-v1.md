# Phase 13A benchmark isolation audit v1

Recorded: July 13, 2026

Result: **pass — the benchmark protocol is unreachable from production code in
the audited workspace state**

The fail-closed audit in `scripts/audit_benchmark_isolation.mjs` records:

- four exact, authorized `ed25519-yao` dependents: the isolated Cloudflare
  benchmark, the isolated WASM benchmark, the formal-verification harness, and
  the circuit generator;
- zero dependents on `ed25519-yao-cloudflare-bench`;
- zero forbidden benchmark-protocol references across 5,743 product files;
- 19 benchmark Wrangler configurations, all named and classified as
  non-production benchmark artifacts, with zero production routes;
- unpublished core and benchmark crates, empty default feature sets, and
  compile-time gates around every passive benchmark export; and
- a fixed `/benchmark/activation` endpoint with
  `PRODUCTION_ELIGIBLE = false` in the isolated benchmark crate.

The product scan covers Router A/B, both HSS crates, threshold PRF, signer core,
embedded signer crates, applications, clients, examples, packages, tests, and
voice-ID code. It rejects references to benchmark crate names, benchmark
features, endpoints, deployment names, and `YAOS_AB_` protocol identifiers.

`scripts/test_benchmark_isolation.mjs` proves fail-closed behavior by mutating
each boundary: a product reference, unauthorized core dependency, benchmark
dependent, default feature, production route, production classification, and
production-eligibility marker must each fail the audit.

This is source-tree and checked-in deployment-configuration evidence. It does
not establish deployed Cloudflare routing, account policy, release provenance,
or production security. Those remain deployment and productionization gates.
