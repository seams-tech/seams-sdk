# Refactor 93 staging evidence

Recorded 2026-07-24 in the `codex/refactor-93-role-lifecycle` worktree.

## Coherent deployment

The role workers, private MPC Router route, and Gateway were deployed against
the same protected staging keyset. The first manual role-worker upload used
the checked-in placeholder variables and was immediately replaced before the
Gateway cutover; the versions below are the corrected, coherent versions.

| Worker                             | Staging version                        | Deployment message            |
| ---------------------------------- | -------------------------------------- | ----------------------------- |
| `router-ab-deriver-a-staging`      | `5c9ea1f2-eb81-4990-b871-0ed840308db7` | `refactor-93-staging-keyset`  |
| `router-ab-deriver-b-staging`      | `54bab2c8-36f6-4546-947a-b07f83bf2ebe` | `refactor-93-staging-keyset`  |
| `router-ab-signing-worker-staging` | `319d2da7-a638-4a37-a920-e2f4601cb01c` | `refactor-93-staging-keyset`  |
| `router-ab-mpc-router-staging`     | `9e8c1734-4ad2-4dac-9c00-490bef0998dd` | `refactor-93-staging-keyset`  |
| `seams-sdk-d1-gateway-staging`     | `3764caf6-d8fb-43c7-a647-a16103368022` | `refactor-93-gateway-staging` |

The Gateway deployment reports the `MPC_ROUTER` service binding to
`router-ab-mpc-router-staging`. The role-worker public variables were rendered
from the protected GitHub staging environment values, and the Router and
Gateway deployment configuration were checked against that same keyset. No
secret values are recorded here.

## Boundary smoke checks

- `GET https://router-ab-mpc-router-staging.n6378056.workers.dev/` returned
  `405` with the Router's POST-only response.
- `GET https://router-ab-mpc-router-staging.n6378056.workers.dev/router-ab/router/ed25519-yao/execute`
  returned `405`, confirming the new route is present.
- An unauthenticated POST to the private execute route returned `403`
  (`InvalidLocalHttpRequest`), confirming service authentication is enforced
  before request admission.
- `GET https://seams-sdk-d1-gateway-staging.n6378056.workers.dev/.well-known/router-ab-ceremony-jwks.json`
  returned `200` with the staging Ed25519 ceremony JWKS.
- `pnpm -C tests exec playwright test -c playwright.unit.config.ts
./unit/routerAbEd25519YaoContracts.unit.test.ts --workers=1 --reporter=line`
  passed all 18 tests, including one-request execution, exact replay, and
  burned-execution terminal handling. The test runner emitted unrelated local
  Vite warnings for optional workspace packages that were not built.
- `pnpm -C tests exec playwright test -c playwright.unit.config.ts
./unit/routerAbEd25519YaoExport.server.unit.test.ts --workers=1
--reporter=line` passed all 10 export authorization and lifecycle tests.

These checks prove route presence, binding/authentication wiring, and the
operation-level contract surface. They do not prove a cryptographic staging
registration, recovery, or export, and they are not production latency
evidence.

## Remaining gates

The historical old-boundary validation cannot be replayed because this branch
already contains the Gateway cutover. The old role Stage/Result routes remain
deployed for the request-boundary drain. Route deletion is gated on a complete
staging registration/recovery/export run and the maximum in-flight ceremony
lifetime.

Production acceptance remains open: the current Wrangler OAuth token does not
include Workers Observability access, so no claim is made for 20 correlated
production traces, cold/warm cohorts, Durable Object reuse, p50/p95 latency,
or the product Touch-ID-to-wallet-ready budget.
