# Router A/B Signing Load And Runtime Evidence

Date updated: 2026-06-17

## Goal

Measure the Router A/B signing architecture that is now the only active product
signing path for Ed25519 and ECDSA-HSS. The old threshold-route load harnesses
were tied to deleted public signing endpoints and should not be used as release
evidence.

The release evidence must answer:

1. Ed25519 pool-hit signing latency through Router A/B.
2. Ed25519 pool-miss prepare/finalize latency through Router A/B.
3. ECDSA-HSS pool-hit signing latency through Router A/B.
4. ECDSA-HSS pool-miss pool-fill plus signing latency through Router A/B.
5. Strict Cloudflare configured-origin success, rejected-origin behavior,
   preflight behavior, and timing with preflight included.

## Current Evidence Sources

- [router-a-b-SPEC.md](./router-a-b-SPEC.md) is the canonical Ed25519 and
  ECDSA-HSS Router A/B architecture reference.
- [router-a-b-deployment.md](./router-a-b-deployment.md) tracks deployment
  profiles, release evidence, and deployed-browser gates.
- [router-a-b-cleanup.md](./router-a-b-cleanup.md) tracks deletion of the old
  public threshold signing routes, SDK helpers, tests, fixtures, and docs.
- [docs/deployment/README.md](./deployment/README.md) tracks Router A/B
  deployment and upload evidence commands.

## Required Metrics

Capture these per flow:

- end-to-end signing latency p50, p95, and p99
- success rate and rejection rate
- preflight latency when running in a browser against strict Cloudflare routes
- route-level Router latency for `/router-ab/ed25519/sign/prepare` and `/router-ab/ed25519/sign`
- private SigningWorker latency for the matching internal Router A/B route
- pool-hit ratio and pool-miss fallback ratio
- one-use nonce or presignature rejection counts

## Required Scenarios

| Scenario | Requirement |
| --- | --- |
| Ed25519 pool hit | One public Router finalize request after local pool reservation. |
| Ed25519 pool miss | Public Router prepare plus finalize path succeeds and records timing separately. |
| ECDSA-HSS pool hit | Prepared presignature is consumed once through Router A/B normal signing. |
| ECDSA-HSS pool miss | Router A/B pool-fill prepares material, then normal signing succeeds. |
| Deployed configured origin | Browser request from configured origin succeeds. |
| Deployed rejected origin | Browser request from unconfigured origin is rejected. |
| Deployed preflight | Browser preflight succeeds only for configured origins and its timing is included. |
| Deleted route proof | No deployed Worker serves old `/threshold-ed25519/*` or `/threshold-ecdsa/*` public signing routes. |

## Local Commands

Use the Router A/B release commands instead of the removed threshold-route
benchmark harnesses:

```sh
rtk pnpm router:deploy:check
rtk pnpm router:smoke
rtk pnpm router:smoke:bundled
rtk pnpm router:deploy:dry-run -- --env staging
```

Focused TypeScript and Rust checks are recorded in the Router A/B plans. Add
new load scripts only if they exercise the current Router A/B route shape and
emit machine-readable timing summaries.

## Completion Gate

Local evidence is sufficient for implementation readiness. Release readiness
still requires deployed Cloudflare browser/runtime evidence from staging, then
production evidence after deployment.
