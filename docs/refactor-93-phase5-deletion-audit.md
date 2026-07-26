# Refactor 93 Phase 5 deletion audit

Updated 2026-07-26 for the immediate hard cutover.

This audit records the repository deletion state. Partitioned D1 and the MPC
Router are the only supported Ed25519 Yao path. The former selector windows,
admission pause, tenant-runtime fallback, and direct Gateway-to-role routes are
retired architecture; they are not deployment or rollback options.

## Repository evidence

The current change set removes these legacy owners:

- `routerAbEd25519YaoGatewayCutover.ts` and its selector tests;
- all `legacy_runtime`, `legacy_stateful`, and `admission_blocked` Gateway
  branches;
- `RouterApiRuntimeDurableObject`, its `ROUTER_API_RUNTIME` binding, readiness
  probe, snapshot hydration, and serializer path;
- the six family cutoff/drain variables from configuration rendering,
  deployment validation, workflows, and Wrangler examples;
- the deployment-drain receipt script and its tests;
- direct Gateway `DERIVER_A` and `DERIVER_B` service bindings;
- the legacy Deriver Stage, Start, and Result request handlers and contracts.

`MPC_ROUTER` remains the Ed25519 Yao origin. `SIGNING_WORKER` also remains
because Router A/B ECDSA threshold-store transport owns that binding. Deriver
Workers remain deployed as Router-owned Yao roles; deleting direct Gateway
bindings does not delete either Worker.

The production Gateway constructs request-scoped product handlers and persists
mutable lifecycle authority in partitioned D1 records. No supported request can
select the tenant snapshot runtime or pause for a compatibility drain.

## Checklist classification

The following items are complete from visible source and configuration:

- [x] Delete the Gateway selector and all compatibility routing branches.
- [x] Delete the tenant runtime class, binding, readiness probe, and snapshot
      persistence path.
- [x] Delete family cutoff/drain configuration and deployment-drain tooling.
- [x] Delete direct Gateway Deriver service bindings.
- [x] Delete legacy Deriver Stage, Start, and Result request routes and parsers.
- [x] Retain `MPC_ROUTER` and the independently owned `SIGNING_WORKER` binding.

These operational checks remain open because source inspection cannot prove a
hosted rollout:

- [ ] Deploy the deletion revision to staging and production.
- [ ] Remove any retired cutoff/drain values still stored in GitHub
      Environments.
- [ ] Exercise staging registration, recovery, export, exact replay, conflict,
      disconnect, terminal redelivery, and rollback on the sole route.
- [ ] Confirm production smoke checks and Worker revision coherence.

## Historical audit disposition

The July 25 audit required per-family selector windows and an observed drain
before deletion. That was the superseded staged-cutover plan. The immediate
hard-cutover decision removed its compatibility path and receipt tooling from
the repository, so operators must not follow that earlier procedure.

Rollback now means deploying a revision that implements the current
partitioned-D1/MPC-Router architecture. A pre-cutover Gateway revision depends
on bindings, state, and routes that no longer exist and is not a valid rollback
target.
