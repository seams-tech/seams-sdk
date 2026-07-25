# Refactor 93 Phase 5 deletion and drain audit

Recorded 2026-07-25 on `codex/refactor-93-role-lifecycle`.

This audit separates code that is no longer reachable from the current Gateway
Yao path from code that still has a rollback, protocol, or non-Yao owner. It
authorizes no destructive deployment action by itself. Cloudflare route and
binding deletion requires the deployed drain receipts listed below.

## Evidence checked

### Gateway Yao ownership

`packages/sdk-server-ts/src/router/routerAbEd25519YaoHttpRegistrationBackend.ts`
constructs exactly one Yao execution request at
`POST /router-ab/router/ed25519-yao/execute`; recovery promotion uses its
separate Router route. The backend configuration contains the MPC Router
origin and cryptographic recipient metadata. It contains no Deriver A,
Deriver B, or SigningWorker Yao origin fields.

The existing contract test
`tests/unit/routerAbEd25519YaoContracts.unit.test.ts` records one Router call
for the normal path and exactly one byte-identical replay after a transport
failure. That is the evidence for the Gateway orchestration deletion already
marked complete in Phase 5.

### Gateway service bindings

The generated Gateway Wrangler config still declares `DERIVER_A`, `DERIVER_B`,
`SIGNING_WORKER`, and `MPC_ROUTER` services in
`packages/console-server-ts/scripts/render-d1-gateway-config.mjs`.

The bindings have different owners:

| Binding | Current owner | Decision |
| --- | --- | --- |
| `MPC_ROUTER` | Yao coordinator and Router A/B ECDSA ports | Retain. |
| `SIGNING_WORKER` | Router A/B ECDSA threshold-store transport (`ROUTER_AB_SIGNING_WORKER_URL`) | Retain. This is not an obsolete Yao-only binding. |
| `DERIVER_A` | `RouterAbServiceBindingEnv` dispatcher and the old Gateway binary's direct role route | Drain target. No current Gateway source caller addresses it, but the binding remains required for rollback until the old binary and request lifetime have drained. |
| `DERIVER_B` | `RouterAbServiceBindingEnv` dispatcher and the old Gateway binary's direct role route | Drain target. No current Gateway source caller addresses it, but the binding remains required for rollback until the old binary and request lifetime have drained. |

The role-worker bindings are therefore deletion candidates, not safe deletion
targets today. Removing them from the generated config before the rollback
window closes would make the documented rollback to the pre-cutover Gateway
incomplete. `tests/unit/d1RouterApiStagingServiceBindings.unit.test.ts` remains
an intentional request-boundary compatibility test until this drain completes.

The following variables are active and must not be treated as obsolete direct
origins:

- `MPC_ROUTER_URL` and `MPC_ROUTER` for the current Yao request;
- `ROUTER_AB_SIGNING_WORKER_URL` and `SIGNING_WORKER` for Router A/B ECDSA
  threshold transport;
- the three HPKE public-key variables used to build opaque Yao envelopes.

### Legacy role routes and parsers

The strict Deriver Worker still dispatches the legacy Stage, Start, and Result
routes in `crates/router-ab-cloudflare/src/strict_worker/deriver.rs`, and the
legacy request contracts remain in
`crates/router-ab-cloudflare/src/ed25519_yao_lifecycle.rs`. The staging record
confirms those handlers remain deployed for the request-boundary drain and that
no complete staging registration, recovery, and export run has been recorded.

The configured role lifetimes are 60 seconds for staged input and 20 seconds
for running execution (`YAO_STAGED_INPUT_LIFETIME_MS` and
`YAO_RUNNING_LIFETIME_MS`). These values bound the old request lifetime only
after the deployment and transport failure budget is included in the drain
receipt. A source search or a green unit test cannot substitute for that
receipt, so the handlers, parsers, and their compatibility tests remain.

### Tenant runtime persistence

`ROUTER_API_RUNTIME` and its SQLite migration remain active. The Gateway
persistence follow-up has the per-ceremony CAS adapters and codec, but no route
composition has migrated to them. Deleting the binding or migration now would
remove the active replay and authorization snapshot boundary. This remains a
separate follow-up gate for Phase 5.

## Deletion receipt required

Before deleting any Phase 5 drain target, record all of the following in the
staging evidence and deployment plan:

1. A coherent Gateway/Router/Deriver/SigningWorker deployment where new
   Gateway requests produce no calls to the legacy role routes.
2. Successful staging registration, recovery, and export through the Router
   path, including exact replay and conflict checks.
3. The observed maximum in-flight lifetime after the last pre-cutover Gateway
   version was removed, including staged, running, transport, and rollback
   budgets.
4. A rollback rehearsal proving that the selected previous Gateway version is
   still deployable until the drain is declared complete.
5. A post-drain source and generated-config check showing that `DERIVER_A`,
   `DERIVER_B`, legacy Stage/Start/Result contracts, and compatibility parsers
   have no remaining owner.

No current repository or staging artifact satisfies all five conditions. The
Phase 5 route, binding, parser, and compatibility-test checkboxes remain open.
