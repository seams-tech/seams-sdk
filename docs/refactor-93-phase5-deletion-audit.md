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

| Binding          | Current owner                                                                         | Decision                                                                                                                                                           |
| ---------------- | ------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `MPC_ROUTER`     | Yao coordinator and Router A/B ECDSA ports                                            | Retain.                                                                                                                                                            |
| `SIGNING_WORKER` | Router A/B ECDSA threshold-store transport (`ROUTER_AB_SIGNING_WORKER_URL`)           | Retain. This is not an obsolete Yao-only binding.                                                                                                                  |
| `DERIVER_A`      | `RouterAbServiceBindingEnv` dispatcher and the old Gateway binary's direct role route | Drain target. No current Gateway source caller addresses it, but the binding remains required for rollback until the old binary and request lifetime have drained. |
| `DERIVER_B`      | `RouterAbServiceBindingEnv` dispatcher and the old Gateway binary's direct role route | Drain target. No current Gateway source caller addresses it, but the binding remains required for rollback until the old binary and request lifetime have drained. |

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

## Lifecycle source-guard review

The five remaining `source.contains` checks in
`crates/router-ab-cloudflare/tests/ed25519_yao_lifecycle_boundaries.rs` were
reviewed against the current Rust unit tests and route handlers. They remain
intentional boundary guards:

| Guard                                                               | Invariant protected                                                                                                       | Why a structural/type test is insufficient today                                                                                                                                                                |
| ------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Legacy record enum, terminal variants, lifetimes, and expiry helper | The legacy request boundary retains one discriminated record with absorbing `Failed`/`Expired` states and bounded leases. | The record is private to the Worker module; existing unit tests cover serialization and checked expiry, while this guard also detects accidental removal of a state or lease constant from the deployed source. |
| Absence of `STAGED_INPUT_STORAGE_KEY`                               | Legacy staged ciphertext is not split into a second storage key.                                                          | A behavior test cannot prove that a future code path has not reintroduced a second durable key when the current path happens not to exercise it.                                                                |
| Pair record fields and command variants                             | Pair binding, readiness, two-phase start, completion, and exact completed reads remain present at the role boundary.      | The command/state types are private and route dispatch is Worker-specific; the existing unit tests cover transitions, not the complete boundary command surface.                                                |
| Named completion-acknowledgement envelope and request validation    | B completed reads cross the Worker boundary through a typed acknowledgement that is validated before transcript use.      | Coordinator tests validate decoding, but do not prove that the B route still emits and validates the named envelope.                                                                                            |
| Root metadata loader plus staged WebSocket connector                | Root metadata validation remains ordered before external peer connection.                                                 | No local runtime test provides a real Cloudflare WebSocket and root-share binding; the source guard retains the ordering requirement until deployed evidence exists.                                            |

Removing any of these guards before the legacy route drain would reduce
coverage of the only tests that inspect those cross-worker ownership
boundaries. Native pair serving is implemented; the guards should be replaced
with route-level tests once the old handlers are deleted.

## Clippy review

Focused library clippy was run for each role entrypoint:

```text
cargo clippy -p router-ab-cloudflare --lib \
  --features strict-worker-router-entrypoint -- -W dead_code -W unused_imports
cargo clippy -p router-ab-cloudflare --lib \
  --features strict-worker-deriver-a-entrypoint -- -W dead_code -W unused_imports
cargo clippy -p router-ab-cloudflare --lib \
  --features strict-worker-deriver-b-entrypoint -- -W dead_code -W unused_imports
```

All three commands succeeded. None reported `peer_verifying_keys`, dead-code,
or unused-import warnings. Each role emits the existing broad clippy warnings
(large enum variants, argument count, and similar style lints); those warnings
are unrelated to the reported symbol and are not changed in this cleanup.

Running `--all-targets --all-features` is not a valid aggregate check for this
crate because the strict Worker entrypoint features are mutually exclusive,
and the lifecycle unit test intentionally calls a role-only helper behind its
Deriver feature gate. Per-entrypoint library checks are the meaningful warning
signal until the test harness is split by Worker role.

## Safe-cleanup review (2026-07-25)

The open Phase 5 items were re-audited against the current callers and owners.
No destructive cleanup is safe before the deployment drain:

- `DERIVER_A` and `DERIVER_B` remain in the generated Gateway service bindings
  because the old Gateway binary must remain rollbackable until the in-flight
  lifetime and transport-failure budget have elapsed. The same bindings are
  still consumed by the local strict-runtime dispatcher. `SIGNING_WORKER` is
  owned by the Router A/B ECDSA threshold transport, so it is not a Yao-only
  key. `MPC_ROUTER` is the sole current Yao origin.
- The production Yao backend configuration already accepts only
  `MPC_ROUTER_URL`; no Deriver or SigningWorker URL field remains in that
  configuration type. The Gateway contract test pins normal and exact-replay
  requests to the Router origin, so there is no additional safe key deletion
  in the SDK backend.
- The five lifecycle `source.contains` checks are still the only structural
  guards for private Worker command/state ownership. Native pair serving is
  implemented; the guards remain valid until legacy route deletion provides
  replacement route-level coverage.
- Legacy Stage/Start/Result parsers and their compatibility fixtures still
  have an explicit request-boundary owner during the drain. Their removal
  requires the staging receipts listed above, including the observed maximum
  in-flight lifetime and rollback rehearsal.
- Promotion and capability installation use typed `disposition` and `code`
  unions (`exact_retry`, `capability_conflict`, and `capability_retired`). The
  remaining `already active` phrase is a Deriver-A HTTP diagnostic only; no
  promotion branch matches an English error message.

This review therefore records a deliberate zero-deletion result. The next safe
Phase 5 deletion changes are gated on a coherent staging cutover and the
five-item deletion receipt; deleting bindings, parsers, or source guards before
those gates would remove rollback and boundary coverage.

The dry-run validator
`crates/router-ab-cloudflare/scripts/refactor93-deployment-drain.mjs` now
encodes the five-item receipt as a strict schema. It checks release coherence,
registration/recovery/export success with exact replay and conflict evidence,
the observed drain interval against staged/running/transport/rollback budgets,
rollback rehearsal, and an empty post-drain owner inventory. Its `inventory`
command reports references to direct-origin and tenant-runtime keys without
authorizing deletion. It performs no Cloudflare mutation and cannot turn
partial evidence into a green deployment gate.

The Gateway cutover has a separate two-boundary control. Keep
`ROUTER_AB_YAO_GATEWAY_ADMISSION_CUTOFF_MS` and
`ROUTER_AB_YAO_GATEWAY_DRAIN_UNTIL_MS` empty while the tenant runtime remains
authoritative. At quiescence, set the admission cutoff; after the observed
maximum in-flight lifetime, set the final drain boundary. The Worker rejects
new admissions during that interval and keeps legacy executions on the tenant
runtime. Both values must be present together before the D1 route can activate.
