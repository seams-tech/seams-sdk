# Signing Session Coordinator Migration Checklist

Date created: 2026-04-22

Current architecture now lives in
[docs/signing-session-architecture.md](/Users/pta/Dev/rust/simple-threshold-signer/docs/signing-session-architecture.md).
This document is the migration/checklist record and phased implementation log.

## Objective

Track the phased migration from scattered OTP/passkey signing-session policy toward
the current architecture documented in
[docs/signing-session-architecture.md](/Users/pta/Dev/rust/simple-threshold-signer/docs/signing-session-architecture.md).

State-machine hardening TODO:

1. [x] Introduce a `SigningExecutionMachine` around planner output and transaction confirmation.
2. [x] Split `WarmSessionManager` into provisioner, restorer, status reader, and capability reader.
   - [x] Introduce narrow capability, status, provisioner, and post-sign policy interfaces before physical extraction.
   - [x] Extract the implementation bodies into separate modules.
3. [x] Make side effects explicit commands: `requestOtp`, `requestPasskey`, `reconnectThreshold`, `spendBudget`, and `cleanup`.
4. [x] Add trace events from state transitions, not ad hoc scattered event emissions.
   - [x] Route EVM-family post-sign command transitions into an opt-in redacted runtime trace hook.
5. [x] Keep side effects contained in command executors with narrow typed dependencies.
   - [x] Introduce the command-executor boundary and runner around the pure machine.
   - [x] Wire EVM-family post-sign budget spend and cleanup through command execution.
   - [x] Wire transaction runtime side effects through command executors.
6. [x] Add transition-order tests for warm session, exhausted Email OTP, exhausted passkey, cancellation, and signing failure.
   - [x] Cover warm session, exhausted Email OTP, exhausted passkey, and not-ready plans in the pure machine.
   - [x] Cover cancellation and signing failure at the command-runner boundary.

Acceptance checks:

1. [x] The planner remains pure and only decides the next signing plan.
2. [x] The execution machine owns legal state transitions.
3. [x] Command executors own side effects and are simple to inspect.
4. [x] Trace events can explain each transition from lane selection to cleanup without exposing secrets.

Review-followup hardening TODO:

1. [x] Remove `missing_lane` from planner concerns and make lane resolution its own result union.
2. [x] Split operation identity from lane identity so `SigningLaneContext` stays stable across planning and reauth.
3. [x] Move budget-spend construction out of the planner and into the execution/finalization boundary.
4. [x] Decide that the current `SigningExecutionMachine` remains an ordering machine until a typed result-carrying machine is justified; document that boundary explicitly.
5. [x] Split this document into a short current-design doc plus an archived migration checklist.

## Historical Design Notes

The detailed current type shapes and flow model were moved to
[docs/signing-session-architecture.md](/Users/pta/Dev/rust/simple-threshold-signer/docs/signing-session-architecture.md)
so this migration document does not act as a second architecture spec.

This checklist originally introduced:

1. `SigningLaneContext` as the selected signing-lane identity.
2. `SigningOperationContext` as separate operation identity.
3. Branded ids for wallet sessions, threshold sessions, backing material, OTP challenges, and signing operations.
4. An idempotent wallet-budget ledger keyed by operation id.

Those concepts are now part of the implemented architecture and should be read in
the architecture doc, not redefined here.

## Follow-On Architecture Work

The checklist in this document is complete, but there are still two follow-on
architecture tracks worth planning explicitly.

### 1. Budget Reservation And Atomic Consume

Current state:

1. Successful wallet-budget spending is idempotent by `operationId`.
2. Zero-spend outcomes are recorded explicitly.
3. Budget spend construction happens at the execution boundary.
4. Transaction signing reserves budget before threshold signing and releases it
   on success, cancellation, or failure.

Remaining concern:

The implemented reservation boundary protects concurrent operations that share
one budget ledger instance. Cross-tab and cross-device atomicity belongs
server-side, where the authoritative wallet signing-session budget is consumed.

Follow-on TODO:

1. [x] Define the concurrency model for wallet signing-session budget:
       reservation-before-sign in the local transaction signing ledger.
2. [x] Introduce an explicit budget reservation or atomic consume boundary for
       transaction signing operations.
3. [x] Keep `operationId` idempotency for retries, but separate it from
       concurrency protection across distinct operations.
4. [x] Define failure semantics for reserved budget:
       cancellation, OTP failure, passkey failure, nonce failure, signing failure,
       timeout, and reconnect failure.
5. [x] Decide whether reservation release is explicit, implicit by expiry, or
       unnecessary because consume is atomic and late-bound.
6. [x] Add trace events for reservation started, reservation released, consume
       succeeded, consume deduped, and consume failed.
7. [x] Add the full matrix tests for two concurrent signing attempts against:
       remaining uses `1`, `N > 1`, same operation retry, and mixed OTP/passkey lanes.
8. [x] Ensure NEAR, Tempo, and EVM all use the same reservation/consume model.
9. [x] Decide whether cross-tab/cross-device atomicity should move into
       `WalletSigningSessionCoordinator` or the relayer: it belongs server-side.

Acceptance checks:

1. [x] Two distinct concurrent operations sharing one budget ledger instance
       cannot overspend the same wallet signing-session budget.
2. [x] A retry of the same operation still remains idempotent.
3. [x] Failed or cancelled operations do not leak reserved budget indefinitely.
4. [x] The reservation/consume boundary is visible in traces and easy to test.
5. [x] Cross-tab/cross-device overspend protection is explicitly accepted as out
       of scope for the client ledger and assigned to the server-side authoritative
       budget consume path.

### 2. Execution Machine Direction

Current state:

`SigningExecutionMachine` is intentionally an ordering machine. It owns command
order and transition traces, while command executors and finalizers hold side
effects and result data.

Remaining question:

Should the machine stay small and ordering-focused, or should it later become a
typed result-carrying execution machine?

Follow-on TODO:

1. [x] Write down the explicit decision criteria for keeping the current ordering
       machine versus promoting it to a typed result-carrying machine.
2. [ ] Inventory which results are currently side-channel state in executors:
       OTP result, passkey result, threshold reconnect result, nonce preparation
       result, signature result, send result, cleanup result.
3. [x] Decide whether those results need to become typed transition payloads, or
       whether they should remain executor-local.

Decision criteria:

1. Keep the ordering machine while its value is enforcing no-auth-before-confirm,
   nonce-before-budget, budget-before-sign, and post-sign finalization order.
2. Promote it to a typed result-carrying machine only if two or more flows need
   shared typed outputs from OTP, passkey, threshold reconnect, nonce
   preparation, signing, send, or cleanup.
3. Do not move executor-local data into the machine only for observability; emit
   transition trace events instead.
4. [ ] If the machine stays ordering-only, rename or document it more narrowly so
       it does not read like a full execution state machine.
5. [ ] If the machine becomes typed, define transition payload types and terminal
       outcome types before changing implementation.
6. [ ] Keep planner purity regardless of which machine direction is chosen.
7. [ ] Keep no-auth-before-confirm as a hard invariant in either design.
8. [ ] Add tests that assert the chosen ownership boundary:
       planner, machine, executor, and finalizer.

Acceptance checks:

1. [ ] The execution model has one clear owner for ordering, side effects, and
       post-sign finalization responsibilities.
2. [ ] The code and docs use the same term for the machine’s actual role.
3. [ ] New auth methods or signing flows can plug into the chosen model without
       duplicating wrapper logic.

### 3. Signing Session Coordinator Cleanup

Goal: finish moving transaction signing to a clean coordinator model where
`SigningSessionCoordinator` owns orchestration, `SigningSessionPlanner` owns the
pure decision, `SigningExecutionMachine` owns legal command order, and narrow
executors/finalizers own side effects.

Target naming:

1. `SigningSessionCoordinator` resolves or receives the selected lane, reads
   warm-session readiness, calls `SigningSessionPlanner`, drives
   `SigningExecutionMachine`, delegates side effects to executors, and finalizes
   budget plus cleanup.
2. `WarmSessionStore` is the persistence/read-model layer for warm-session
   records and claims.
3. `SigningSessionPlanner`, `SigningExecutionMachine`, and
   `WalletSigningBudgetLedger` keep their current names.

Implementation TODO:

1. [x] Rename/remove `WarmSessionManager` facade naming and old log prefixes.
2. [x] Replace transaction-signing `WalletAuthPlan` usage with planner-derived
       TouchConfirm auth payloads.
   - [x] Add one conversion from `SigningSessionPlan` to TouchConfirm
         `SigningAuthPlan`.
   - [x] Route EVM, Tempo, and NEAR transaction confirmation through that
         conversion.
   - [x] Leave non-transaction `WalletAuthPlan` call sites alone until they have
         their own planner path.
3. [x] Replace partial execution-machine trace lookup with a real command
       runner or a narrow explicit trace helper.
   - [x] Remove `buildSigningExecutionSteps(plan).find(...)` from runtime code.
   - [x] If the machine stays ordering-only, expose a direct command trace helper
         instead of treating the machine as a lookup table.
   - [x] If the machine becomes the runner, wire typed executors for confirmation,
         auth, reconnect, nonce, budget reservation, signing, spend, and cleanup.
4. [x] Unify budget reserve/spend construction under one transaction
       finalizer/executor.
   - [x] Move NEAR inline spend-plan construction into a shared transaction
         budget finalizer.
   - [x] Reuse the same finalizer from EVM and Tempo.
   - [x] Keep `WalletSigningBudgetLedger` as the idempotency and local
         reservation primitive.
5. [x] Remove leftover transaction-signing dependencies on old auth/facade
       types.
   - [x] Transaction signing modules should not import `WalletAuthPlan` once
         planner-derived TouchConfirm auth is in place.
   - [x] Transaction signing modules should use `SigningSessionCoordinator`
         ports instead of warm-session facade bundles.

Acceptance checks:

1. [x] Transaction signing has one auth-plan source: `SigningSessionPlan`.
2. [x] EVM, Tempo, and NEAR use the same conversion from planner output to
       TouchConfirm auth payload.
3. [x] Execution-machine traces are emitted by an explicit runner/helper, not by
       searching generated steps.
4. [x] Budget reservation, success spend, zero-spend, and cleanup are finalized
       by one transaction finalizer path.
5. [x] No transaction-signing production code imports obsolete warm-session
       facade names or transaction `WalletAuthPlan`.

### 4. Single Stateful Signing Session Coordinator

Goal: collapse the remaining almost-coordinators into one stateful
`SigningSessionCoordinator` so every chain and curve uses the same wallet-budget,
readiness, planning, reservation, execution, and cleanup boundary.

Current problem:

1. `WalletSigningSessionCoordinator`, `WalletSigningBudgetLedger`, and
   `SigningSessionPlanner` all sound like session-policy owners.
2. The real state is split across wallet budget maps, wallet status overrides,
   local backing-session reads, and chain-specific planning helpers.
3. Chain flows can still accidentally call a lower-level helper and bypass the
   authoritative wallet-budget readiness merge.

Target module shape:

```txt
client/src/core/signingEngine/session/
  SigningSessionCoordinator.ts
  signingSession/
    readiness.ts
    budget.ts
    planner.ts
    execution.ts
```

Target ownership:

1. `SigningSessionCoordinator.ts` is the only stateful signing-session object
   passed through runtime dependency bundles.
2. `signingSession/readiness.ts` contains stateless backing-status reads and
   wallet-budget/readiness merging helpers.
3. `signingSession/budget.ts` contains stateless budget normalization,
   fingerprint binding, reservation math, trace-event construction, and spend
   result helpers.
4. `signingSession/planner.ts` contains the pure `planSigningSession(...)`
   function. There is no independently constructed `SigningSessionPlanner`
   service.
5. `signingSession/execution.ts` contains pure execution-step construction,
   command ordering, and runner helpers.

Proposed coordinator API:

```ts
type SigningSessionCoordinator = {
  resolveAuthPlan(
    input: ResolveSigningSessionAuthPlanInput,
  ): Promise<ResolvedSigningSessionAuthPlan>;
  getAvailableStatus(input: SigningSessionStatusInput): Promise<SigningSessionStatus | null>;
  reserveBudget(input: SigningSessionBudgetInput): Promise<SigningSessionBudgetReservation | null>;
  recordSuccess(input: SigningSessionBudgetInput): Promise<SigningSessionStatus | null>;
  recordZeroSpend(input: SigningSessionZeroSpendInput): void;
  clear(input: SigningSessionClearInput): Promise<void>;
};
```

State to move into `SigningSessionCoordinator`:

1. Successful spends by operation id.
2. Reservations by operation id.
3. Reserved uses by wallet signing-session id.
4. Per-wallet reservation queues.
5. Wallet signing-session status overrides.

Implementation TODO:

1. [x] Create `session/signingSession/` and move the pure planner function to
       `signingSession/planner.ts`.
   - [x] Delete the `createSigningSessionPlanner(...)` service wrapper after
         all callers use the coordinator.
   - [x] Keep planner inputs and outputs pure and free of storage, worker,
         OTP, passkey, and budget imports.
2. [x] Create `signingSession/budget.ts` and move the stateless pieces of
       `WalletSigningBudgetLedger` into it.
   - [x] Move spend-plan normalization and operation-fingerprint matching.
   - [x] Move reservation availability math and reserved-use projection.
   - [x] Move trace-event construction into pure helpers.
   - [x] Keep only state mutation and dependency calls in
         `SigningSessionCoordinator`.
3. [x] Create `signingSession/readiness.ts` and move the stateless pieces of
       `WalletSigningSessionCoordinator` into it.
   - [x] Create `signingSession/readiness.ts`.
   - [x] Move lane discovery and backing-session claim reads behind explicit
         dependency parameters.
   - [x] Move wallet-scoped claim merging and status override application.
   - [x] Move wallet-budget-aware readiness merging used by Ed25519 and ECDSA.
   - [x] Keep backing-session consume and clear as stateless helpers with
         explicit deps; they must not retain maps or hidden state.
4. [x] Move `SigningExecutionMachine` step construction and command runner to
       `signingSession/execution.ts`.
   - [x] Preserve the current ordering-machine behavior.
   - [x] Keep command executors outside the pure execution module.
5. [x] Implement the new stateful `SigningSessionCoordinator`.
   - [x] Own all runtime budget maps and wallet status override maps.
   - [x] Expose one `resolveAuthPlanFromReadiness(...)` path that receives
         chain-specific backing readiness, merges wallet-budget status, applies policy, and calls
         `planSigningSession(...)`.
   - [x] Expose one reserve/success/zero-spend/clear boundary for all lanes.
6. [x] Migrate NEAR Ed25519 transaction signing first.
   - [x] Replace direct NEAR wallet-budget readiness merging and planner calls
         with `SigningSessionCoordinator.resolveAuthPlanFromReadiness(...)`.
   - [x] Replace the old NEAR threshold auth-plan wrapper with a direct
         `SigningSessionCoordinator` call at each remaining caller.
   - [x] Leave NEAR-specific code responsible only for lane construction,
         confirmation display data, nonce handling, signer execution, and
         result shaping.
   - [x] Delete the old wrapper in the same change that migrates its last
         caller.
7. [x] Migrate EVM-family ECDSA transaction signing.
   - [x] Replace EVM/Tempo local wallet-budget readiness merge and planner call
         with `SigningSessionCoordinator.resolveAuthPlanFromReadiness(...)`.
   - [x] Keep EVM-family lane selection and reconnect executors as adapters.
   - [x] Rename the EVM-family warm-session service adapter so only the
         stateful facade uses `SigningSessionCoordinator` naming.
8. [ ] Migrate ARC and any remaining signing lanes to the same coordinator API.
   - [ ] Chain-specific code may build `SigningLaneContext`.
   - [ ] Chain-specific code may execute signing and nonces.
   - [ ] Chain-specific code may not directly plan auth, merge budget status,
         reserve budget, or spend wallet budget.
9. [x] Update dependency bundles so only `SigningSessionCoordinator` is passed
       around as the signing-session stateful service.
   - [x] Remove direct `WalletSigningBudgetLedger` injection from chain deps.
   - [x] Remove direct `WalletSigningSessionCoordinator` construction from
         status readers and chain flows.
   - [x] Wire the orchestration dependency bundle around a single
         `SigningSessionCoordinator` facade instance.
10. [x] Add static guards for the new architecture.
    - [x] No chain transaction flow imports `SigningSessionPlanner` or
          `signingSession/planner.ts` directly.
    - [x] No chain transaction flow imports budget helper state directly.
    - [x] No production code outside `SigningSessionCoordinator` constructs
          `WalletSigningBudgetLedger`.
    - [x] No production code outside `SigningSessionCoordinator` constructs
          `WalletSigningSessionCoordinator`.
    - [x] Legacy `WalletSigningBudgetLedger.ts` has been deleted; budget state
          and public behavior live on `SigningSessionCoordinator`.
    - [x] Legacy `WalletSigningSessionCoordinator.ts` owns no mutable wallet
          status override map.
    - [x] Only `SigningSessionCoordinator.ts` owns mutable signing-session
          maps.
    - [x] EVM-family warm-session service adapters do not use
          `SigningSessionCoordinator` naming.
11. [ ] Add regression tests for the unified helper path.
    - [ ] NEAR Ed25519 exhausted passkey budget plans passkey reauth.
    - [ ] Tempo ECDSA exhausted passkey budget plans passkey reauth.
    - [ ] EVM ECDSA exhausted passkey budget plans passkey reauth.
    - [ ] Email OTP exhausted budget plans Email OTP reauth for every chain.
    - [ ] Mixed Ed25519/ECDSA lanes sharing one wallet budget cannot diverge in
          readiness after any sibling lane spends the last use.
12. [ ] Delete or rename legacy files after migration.
    - [x] Delete `WalletSigningBudgetLedger.ts` after its state and public API
          move into `SigningSessionCoordinator`.
    - [ ] Delete `WalletSigningSessionCoordinator.ts` after its stateless
          helpers move under `signingSession/readiness.ts`.
    - [ ] Delete the `SigningSessionPlanner` service wrapper after callers use
          the pure planner through the coordinator.

Acceptance checks:

1. [x] There is one stateful owner for signing-session readiness, budget
       reservation, budget consume, wallet status overrides, and cleanup:
       `SigningSessionCoordinator`.
2. [ ] Every transaction signer reaches auth planning through the same
       `resolveAuthPlan(...)` helper path.
3. [ ] Ed25519, ECDSA, Tempo, EVM, and ARC cannot bypass wallet-budget-aware
       readiness.
4. [ ] Planner and execution logic stay pure and easy to test, even though they
       are no longer separate service objects.
5. [ ] No legacy coordinator/ledger names remain in production dependency
       bundles.

## Large File Refactor Targets

This refactor should shrink the two most confusing files as part of the main work, not
as optional cleanup. The goal is to remove policy duplication and make the remaining
files boring orchestration.

### `client/src/core/signingEngine/api/evmSigning.ts`

Current problem: this file mixes EVM/Tempo orchestration, nonce management, smart
account deployment, dynamic signer loading, ECDSA lane selection, auth planning,
fresh-OTP detection, warm-session manager construction, budget spending, and post-sign
policy. That made ECDSA drift away from the Ed25519 flow and hid the source of the
standalone passkey prompt.

Target shape:

1. `evmSigning.ts` becomes a thin EVM-family transaction orchestrator.
2. It accepts a `SigningSessionPlan` from `SigningSessionPlanner`.
3. It invokes a chain-specific nonce lifecycle service.
4. It invokes a chain-specific transaction executor.
5. It records success through `WalletSigningBudgetLedger`.
6. It never reads generic ECDSA session records directly.
7. It never decides Email OTP vs passkey directly.
8. It never throws fresh-auth errors from wrapper-side checks.

Extraction TODO:

1. [x] Move EVM-family types and lifecycle event types to `evmFamily/types.ts`.
2. [x] Move error normalization, nonce-conflict mapping, and cancellation helpers to `evmFamily/errors.ts`.
3. [x] Move signing-flow and nonce metric emission to `evmFamily/events.ts`.
4. [x] Move managed nonce reservation, reconcile, finalized, dropped, and replaced logic to `evmFamily/nonceLifecycle.ts`.
5. [x] Move smart-account deployment checks to `evmFamily/smartAccount.ts`.
6. [x] Move dynamic signer module loading to a small signer-loader module.
7. [x] Replace local ECDSA lane-selection helpers with `SigningLaneContext` and planner calls.
8. [x] Replace local key-ref readiness helpers with planner-selected capability reads.
9. [x] Replace local budget-spend calls with `WalletSigningBudgetLedger.recordSuccess`.
   - [x] Replace the EVM/Tempo ECDSA transaction success spend call.
   - [x] Replace NEAR transaction success spend calls.
10. [x] Delete local fresh Email OTP reauth guards once planner owns reauth decisions.
11. [x] Delete duplicated Tempo/EVM post-sign policy blocks once `SigningPostSignPolicy` owns cleanup.

Module boundary rules:

1. [x] EVM-family orchestration may import `SigningSessionPlanner`, `SigningExecutor`, `WalletSigningBudgetLedger`, nonce lifecycle, and smart-account modules.
2. [x] EVM-family orchestration may not import raw ECDSA session stores, WebAuthn prompt helpers, Email OTP completion helpers, or wallet-session budget mutation helpers.
3. [x] Nonce lifecycle modules may not import signing-session planners, OTP, passkey, or threshold session stores.
4. [x] Smart-account modules may not import OTP, passkey, threshold session stores, or budget ledgers.

### `client/src/core/signingEngine/api/evmFamily/`

Current problem: the EVM-family implementation has been split into focused files, but
those files still live flat under `api/` with repeated `evmFamily*` prefixes. The
prefix is doing the job a folder should do, and the noise makes the top-level signing
API directory harder to scan.

Target shape:

```txt
client/src/core/signingEngine/api/
  evmSigning.ts
  nearSigning.ts
  tempoSigning.ts

  evmFamily/
    accountAuth.ts
    addresses.ts
    authPlanning.ts
    budgetSpending.ts
    ecdsaLanes.ts
    ecdsaReadiness.ts
    ecdsaSelection.ts
    emailOtpRefresh.ts
    errors.ts
    events.ts
    freshEmailOtpRetry.ts
    nonceLifecycle.ts
    nonceMetrics.ts
    nonceResolution.ts
    operationIds.ts
    postSignPolicy.ts
    signerLoader.ts
    signingFlowRuntime.ts
    warmSessionServices.ts
    smartAccount.ts
    transactionExecutor.ts
    types.ts
    evmNonceLifecycle.ts
    tempoNonceLifecycle.ts
```

`evmSigning.ts` should stay at the `api/` root as the public-ish EVM/Tempo signing
entrypoint. The `evmFamily/` folder should contain implementation modules used by
that wrapper. File names should drop the `evmFamily` prefix because the folder now
provides that context. Exported symbols can keep `EvmFamily` where the name is useful
outside the folder.

Refactor TODO:

1. [x] Create `client/src/core/signingEngine/api/evmFamily/`.
2. [x] Move EVM-family implementation modules into the folder and drop filename prefixes.
3. [x] Move `evmNonceLifecycle.ts`, `tempoNonceLifecycle.ts`, and nonce metrics into the folder as EVM-family internals.
4. [x] Keep `evmSigning.ts`, `nearSigning.ts`, and `tempoSigning.ts` at the API root.
5. [x] Update imports mechanically without changing behavior.
6. [x] Update guard-test path strings to target the folder layout.
7. [x] Add a guard that prevents new `api/evmFamily*.ts` files from being added at the API root.
8. [x] Avoid a barrel `evmFamily/index.ts` unless dependency direction is proven safe.
9. [x] Update this plan's completed checkpoints to reference the new paths.

Acceptance checks:

1. [x] The API root exposes top-level signing entrypoints and shared API folders, not EVM-family internals.
2. [x] EVM-family implementation imports are local to `api/evmFamily/` or explicit from `evmSigning.ts`.
3. [x] No `api/evmFamily*.ts` implementation files remain at the API root.
4. [x] Static guards still enforce no source-less ECDSA lookup, no pre-confirm auth side effects, and no nonce/smart-account auth-policy imports.
5. [x] The refactor is mechanical: focused EVM/Tempo tests pass with no behavior changes.

### `client/src/core/signingEngine/session/WarmSessionManager.ts`

Current problem: this file mixes capability reads, Ed25519 provisioning, ECDSA
provisioning, sealed-refresh restore, PRF claiming, status reporting, transaction auth
planning, secondary-lane checks, and wallet budget coordination. It became a second
policy owner beside the signing engine.

Target shape:

1. `WarmSessionManager` stops deciding transaction auth policy.
2. It stops choosing secondary lanes.
3. It stops exposing source-less signing-path ECDSA lookups.
4. It stops owning budget spending.
5. It becomes either a small composition root or disappears as callers move to focused services.
6. Focused services expose narrow interfaces that make illegal cross-lane operations hard to call.

Extraction TODO:

1. [x] Extract `SigningCapabilityReader` for lane-specific warm-session readiness and key-ref reads.
2. [x] Extract `Ed25519SigningSessionProvisioner` for existing Ed25519 threshold provisioning.
3. [x] Extract `EcdsaSigningSessionProvisioner` for ECDSA threshold provisioning and reconnect.
4. [x] Extract `SealedRefreshRestorer` for sealed refresh restore, parity checks, and cached-login fallback.
   - [x] Move Email OTP ECDSA sealed-refresh restore decisions and parity checks into `WarmSessionSealedRefreshRestorer.ts`.
5. [x] Extract `WarmSessionStatusReader` for user-visible wallet/session status.
   - [x] Extract threshold signing-session status reads and ECDSA readiness assertions to `WarmSessionStatusReader.ts`.
6. [x] Extract `SigningPostSignPolicy` for single-use Email OTP cleanup and ephemeral material clearing.
   - [x] Move WarmSessionManager's post-sign facade logic into `WarmSessionPostSignPolicyAdapter.ts`.
7. [x] Move wallet signing-session spend to `WalletSigningBudgetLedger`.
   - [x] Move EVM/Tempo transaction signing spends through the ledger.
   - [x] Move NEAR transaction signing spends through the ledger.
8. [x] Move auth-plan decisions to `SigningSessionPlanner`.
9. [x] Delete secondary-lane freshness checks from warm-session code.
10. [x] Delete source-less signing-path ECDSA lookup methods after call sites use lane-specific readers.
11. [x] Delete any temporary facade method in the same phase that migrates its last caller.

Module boundary rules:

1. [x] Capability readers require `SigningLaneContext`; they do not infer lane from account/chain alone.
2. [x] Provisioners can perform auth side effects only when called by confirmed signing execution.
3. [x] Status readers can inspect multiple lanes but must return grouped lane state instead of selecting one lane.
4. [x] Restorers can restore cached material but cannot decide transaction prompt type.
5. [x] Post-sign policy can clean up selected-lane material but cannot spend wallet budget directly.

## Phased TODO List

### Current Checkpoint And Next Steps

Completed in the current checkpoint:

1. [x] Renamed the old threshold readiness helper so `SigningSessionPlanner` now means the new transaction planner.
2. [x] Added shared branded session ids and the first curve-agnostic `SigningLaneContext`.
3. [x] Added a pure `SigningSessionPlanner` that plans warm session, Email OTP reauth, passkey reauth, and not-ready outcomes from one selected lane.
4. [x] Added planner matrix coverage for repeated exhausted Email OTP ECDSA on Tempo/EVM, active passkey with stale Email OTP lane present, active Email OTP with newer passkey lane present, single-use OTP, policy blocking, and budget-spend ids.
5. [x] Added shared lane builders for Ed25519/ECDSA and NEAR/Tempo/EVM transaction contexts.
6. [x] Added `SigningCapabilityReader`, a lane-required capability read port with source-specific ECDSA record/key-ref reads.
7. [x] Added import-boundary guards for pure planning modules, source-specific capability reads, and pre-confirm wallet transaction entrypoints.
8. [x] Started EVM/Tempo runtime wiring: selected ECDSA sessions now carry `SigningLaneContext`, selected-lane record/key-ref reads are validated through `SigningCapabilityReader`, and typed warm-session readiness routes through `SigningSessionPlanner`.
9. [x] Removed the EVM/Tempo transaction budget-spend fallback from threshold session id to wallet signing-session id.
10. [x] Added `WalletSigningBudgetLedger` and routed EVM/Tempo successful ECDSA transaction spends through it with retry-stable operation ids.
11. [x] Routed NEAR transaction signing spends through `WalletSigningBudgetLedger` and removed direct wallet-budget mutation from the NEAR transaction executor.
12. [x] Added NEAR transaction-flow budget ledger coverage for duplicate successful operation ids, confirmation cancellation, OTP resend, and worker signing failure.
13. [x] Added EVM/Tempo transaction-flow coverage that Email OTP confirmation cancellation does not complete OTP, sign, consume OTP state, or spend budget.
14. [x] Moved NEAR transaction `SigningOperationId` creation to confirmation-start in both the API wrapper and transaction executor while preserving caller-provided ids.
15. [x] Removed wallet-session fallback to threshold session id from wallet-budget lane discovery and WarmSessionManager sealed-restore wallet matching.
16. [x] Removed remaining sealed-store, session-policy, Email OTP coordinator, and Email OTP worker wallet-id fallbacks from threshold session ids, with a static guard against reintroduction.
17. [x] Lifted `WalletSigningBudgetLedger` into the signing dependency bundle so EVM/Tempo and NEAR transaction signing no longer accept raw wallet-budget mutation deps.
18. [x] Added EVM/Tempo signing-flow coverage that duplicate completions with the same `SigningOperationId` spend wallet budget once.
19. [x] Moved EVM/Tempo transaction spend ids to confirmation display while preserving separate pre-confirm planning ids and caller-provided operation ids.
20. [x] Routed selected EVM/Tempo ECDSA warm-session, Email OTP reauth, and passkey reauth auth-plan decisions through `SigningSessionPlanner` output.
21. [x] Removed the local `EcdsaSigningLaneContext` facade so EVM/Tempo signing carries `SigningLaneContext` directly plus explicit selection metadata.
22. [x] Moved EVM/Tempo Email OTP challenge preparation behind the confirmation-displayed boundary and added ordering coverage for exhausted OTP cancellation.
23. [x] Removed the EVM/Tempo ECDSA missing-lane passkey fallback; ECDSA transaction auth planning now fails closed when lane construction fails.
24. [x] Tightened EVM/Tempo transaction auth planning with a discriminated argument type that requires `SigningLaneContext` for `secp256k1` signing.
25. [x] Extracted EVM-family chain, lifecycle, nonce-status, and report-argument types into `evmFamily/types.ts`.
26. [x] Introduced named EVM-family dependency surfaces for ECDSA lane readers, account metadata reads, warm-session readiness, confirmed Email OTP auth, threshold ECDSA readiness, nonce lifecycle, and smart-account readiness.
27. [x] Extracted EVM-family cancellation, fresh-auth, nonce-conflict, and nonce-lane-blocked error normalization to `evmFamily/errors.ts`.
28. [x] Extracted EVM-family signing-flow event wrapping and nonce metric emission helpers to `evmFamily/events.ts`.
29. [x] Extracted cached dynamic signer and EVM/Tempo signing-flow module loading to `evmFamily/signerLoader.ts`.
30. [x] Extracted EVM-family managed nonce reservation, release, broadcast, reconcile, finalized, dropped, and replaced lifecycle logic to `evmFamily/nonceLifecycle.ts`.
31. [x] Extracted EVM-family smart-account deployment readiness to `evmFamily/smartAccount.ts`.
32. [x] Extracted EVM-family source-specific ECDSA lane record/key-ref readers to `evmFamily/ecdsaLanes.ts`.
33. [x] Extracted EVM-family active account auth resolution to `evmFamily/accountAuth.ts`.
34. [x] Moved EVM-family ECDSA lane-context construction and lane require helpers to `evmFamily/ecdsaLanes.ts`.
35. [x] Extracted EVM-family ECDSA signing-selection policy to `evmFamily/ecdsaSelection.ts`.
36. [x] Extracted the EVM-family warm-session service adapter to `evmFamily/warmSessionServices.ts`.
37. [x] Extracted EVM-family transaction auth planning and ECDSA planner-readiness to `evmFamily/authPlanning.ts`.
38. [x] Extracted EVM-family wallet signing-session budget-spend assembly to `evmFamily/budgetSpending.ts`.
39. [x] Extracted EVM-family ECDSA post-sign cleanup dispatch to `evmFamily/postSignPolicy.ts`.
40. [x] Split EVM and Tempo managed nonce reservation into `evmFamily/evmNonceLifecycle.ts` and `evmFamily/tempoNonceLifecycle.ts`, with shared nonce resolution in `evmFamily/nonceResolution.ts`.
41. [x] Extracted EVM/Tempo transaction execution branches to `evmFamily/transactionExecutor.ts`, leaving chain-specific nonce handling outside `evmSigning.ts`.
42. [x] Extracted EVM-family ECDSA key-ref readiness to `evmFamily/ecdsaReadiness.ts` and made it require the selected `SigningLaneContext`.
43. [x] Extracted EVM-family Email OTP completion refresh handling to `evmFamily/emailOtpRefresh.ts`.
44. [x] Extracted EVM-family signer-engine, commit-queue, smart-account, and readiness flow setup to `evmFamily/signingFlowRuntime.ts`.
45. [x] Added boundary guards that keep nonce lifecycle modules free of signing-session policy, auth prompts, threshold session stores, and budget spending.
46. [x] Added a boundary guard that keeps smart-account readiness free of OTP/passkey auth policy and wallet-budget spending.
47. [x] Extracted the EVM-family fresh Email OTP retry gate to `evmFamily/freshEmailOtpRetry.ts` so `evmSigning.ts` no longer owns that error classification locally.
48. [x] Extracted EVM-family planning and confirmation operation-id creation to `evmFamily/operationIds.ts`.
49. [x] Added a guard that prevents EVM-family transaction signing modules from calling source-less ECDSA session/key-ref lookup helpers.
50. [x] Extracted single-use ECDSA post-sign cleanup to `SigningPostSignPolicy.ts` and guarded it against wallet-budget spending.
51. [x] Added a guard that prevents export, add-signer, and link-device flows from depending on the transaction budget ledger.
52. [x] Organized EVM-family implementation modules under `api/evmFamily/`, dropped redundant filename prefixes, and added guard coverage against root-level regressions.
53. [x] Routed shared NEAR threshold auth-plan resolution through `SigningSessionPlanner` using the Ed25519 lane builder while preserving the existing touch-confirm payload shape.
54. [x] Deleted the legacy `WarmSessionManager.resolveEd25519SigningAuthPlan` policy owner after NEAR moved to the planner-backed resolver.
55. [x] Introduced narrower `WarmSessionCapabilityReader`, `ThresholdWarmSessionStatusReader`, `WarmSessionProvisioner`, and `WarmSessionPostSignPolicy` interfaces as the first WarmSessionManager split boundary.
56. [x] Added guard coverage that prevents `WarmSessionManager` transaction auth-plan policy from being reintroduced.
57. [x] Moved WarmSessionManager service boundary types into `WarmSessionServiceTypes.ts` and updated production call sites to import the smaller interfaces directly.
58. [x] Moved ECDSA sensitive-operation policy checks into `SigningPostSignPolicy` and left `WarmSessionManager` as a record-resolving adapter.
59. [x] Added direct `SigningPostSignPolicy` unit coverage for single-use cleanup, stale secondary-lane cleanup, consumed OTP rejection, and passkey-required sensitive policy.
60. [x] Extracted threshold signing-session status reads and ECDSA readiness assertions from `WarmSessionManager` into `WarmSessionStatusReader.ts`.
61. [x] Moved WarmSessionManager's ECDSA post-sign facade logic into `WarmSessionPostSignPolicyAdapter.ts`.
62. [x] Extracted Email OTP ECDSA sealed-refresh restore and parity checks into `WarmSessionSealedRefreshRestorer.ts`.
63. [x] Extracted ECDSA bootstrap request assembly into `WarmSessionEcdsaBootstrapRequest.ts` as the first provisioner split step.
64. [x] Extracted Ed25519 provisioning into `WarmSessionEd25519Provisioner.ts`.
65. [x] Extracted reusable warm ECDSA bootstrap lookup into `WarmSessionEcdsaProvisioner.ts`.
66. [x] Extracted ECDSA provisioning into `WarmSessionEcdsaProvisioner.ts`.
67. [x] Extracted ECDSA reconnect/readiness flow into `WarmSessionEcdsaProvisioner.ts`.
68. [x] Extracted warm-session envelope construction and threshold-session record/auth resolution into `WarmSessionCapabilityResolver.ts`.
69. [x] Moved wallet signing-session coordinator construction from `WarmSessionManager` into `WarmSessionStatusReader`.
70. [x] Reduced `WarmSessionManager` to a composition facade over capability, provisioner, restorer, status, and post-sign policy services.
71. [x] Added guard coverage that keeps `WarmSessionManager` as a composition facade and prevents focused service bodies from moving back in.
72. [x] Moved ECDSA seal-transport resolution into `WarmSessionCapabilityResolver.ts` and tightened the composition-facade guard.
73. [x] Verified the focused WarmSession/OTP architecture suite after the manager split and seal-transport extraction.
74. [x] Added the pure `SigningExecutionMachine` with explicit command steps, transition trace events, and initial warm/OTP/passkey/not-ready transition coverage.
75. [x] Added the `SigningExecutionMachine` command-runner boundary with ordered command execution, transition emission, cancellation short-circuiting, and signing-failure no-spend coverage.
76. [x] Threaded the EVM-family `SigningSessionPlan` from auth planning into the transaction executor boundary so runtime wiring can consume planner output directly.
77. [x] Routed EVM-family post-sign wallet-budget spend and cleanup through `SigningExecutionMachine` command execution while preserving the existing signing/confirmation flow.
78. [x] Added an opt-in EVM-family runtime trace hook for redacted post-sign execution-machine transitions.
79. [x] Extracted duplicated EVM/Tempo touch-confirm auth-method and progress mapping into the shared signing orchestration helper.
80. [x] Centralized signing lane/plan trace redaction summaries and added planner-wrapper trace coverage.
81. [x] Removed app-level source-less ECDSA reads from SeamsPasskey login metadata and login presign prefill helpers.
82. [x] Removed source-less ECDSA key-ref reads from the orchestration canonical-session resolver by enumerating passkey sources explicitly.
83. [x] Removed the source-less ECDSA record probe from `WarmSessionStatusReader` threshold-session resolution.
84. [x] Centralized the explicit ECDSA session-store source list and used it when collecting warm signing-session ids.
85. [x] Removed omitted-source ECDSA key-ref reads from `WarmSessionEcdsaProvisioner` by enumerating explicit source lanes.
86. [x] Added source-required warm ECDSA readiness/reuse APIs and routed EVM-family transaction readiness through them.
87. [x] Narrowed the EVM-family warm-session adapter type so transaction code only sees the source-required ECDSA readiness API.
88. [x] Made EVM-family ECDSA post-sign cleanup require the selected source and guarded against optional-source cleanup regressions.
89. [x] Made EVM-family ECDSA operation-policy checks require the selected source instead of falling back to source-less policy reads.
90. [x] Made EVM-family warm-session adapter record/key-ref callbacks reject source-less ECDSA reads.
91. [x] Added source-required WarmSession post-sign policy APIs and routed EVM-family transaction policy through them.
92. [x] Documented the current auth-plan, ECDSA lookup, auth side-effect, budget, and cleanup owners before the next extraction.
93. [x] Renamed generic optional-source ECDSA helpers from `ForSigning` to `ForLookup` so only source-specific Email OTP/passkey helpers keep signing-path names.
94. [x] Moved WarmSession status and wallet-budget ECDSA discovery from one-record generic lookup callbacks to multi-lane `listThresholdEcdsaSessionRecordsForLookup`.
95. [x] Moved WarmSession ECDSA provisioning/reconnect key-ref discovery from one-record generic lookup callbacks to multi-lane `listThresholdEcdsaKeyRefsForLookup`.
96. [x] Made the remaining one-record ECDSA lookup helpers source-required and moved source-less export/status selection onto multi-lane list reads.
97. [x] Replaced source-less ECDSA status selection with exact threshold-session status reads plus multi-lane ECDSA status lists.
98. [x] Removed EVM/Tempo post-sign budget and cleanup fallbacks that rebuilt an ECDSA lane from account/source instead of the selected `SigningLaneContext`.
99. [x] Moved EVM/Tempo Email OTP completion refresh record reads onto the completed ECDSA `SigningLaneContext`.
100. [x] Added exact Ed25519 threshold-session status reads and routed NEAR planner-readiness fallback through them instead of account-only status.
101. [x] Removed the Ed25519 account-only capability-reader fallback and made NEAR transaction lane builders require the selected threshold session id.
102. [x] Removed `WarmSessionManager` construction from NEAR transaction signing by injecting exact Ed25519 status reads and sealed-restore execution through narrow deps.
103. [x] Moved NEAR transaction sealed-restore ECDSA diagnostics out of `nearSigning.ts`; signing code now asks for restore by intent instead of listing ECDSA records itself.
104. [x] Routed NEAR API-wrapper transaction auth-plan selection through `SigningLaneContext` and `SigningSessionPlanner` instead of `WalletAuthModeResolver`.
105. [x] Fixed the unrelated unit-test type baselines so `type-check:sdk` passes again.
106. [x] Removed the EVM-family `WalletAuthModeResolver` fallback so exhausted ECDSA lanes cannot be re-decided by a second auth resolver.
107. [x] Removed the EVM-family pre-sign ECDSA operation-policy guard so fresh Email OTP routing stays planner-owned.
108. [x] Routed EVM-family and NEAR planner calls through the traced planner wrapper with redacted planner-decision debug events.
109. [x] Added redacted wallet signing budget ledger trace events for spend start, success, failure, skip, and dedupe.
110. [x] Added redacted lane-resolution trace events for EVM-family ECDSA lane selection and NEAR Ed25519 transaction auth planning.
111. [x] Added redacted pre-confirm readiness and Email OTP challenge-start boundary trace events for EVM-family and NEAR signing paths.
112. [x] Added execution-machine trace-order coverage for warm, exhausted Email OTP, exhausted passkey, and cancellation flows.
113. [x] Added EVM/Tempo confirmed passkey prompt and threshold reconnect start boundary traces, and hardened budget-ledger tracing so missing status summaries cannot break idempotency.
114. [x] Added NEAR confirmed passkey prompt and threshold reconnect start boundary traces, with explicit `SigningLaneContext` threaded from the API wrapper into transaction execution.
115. [x] Split EVM-family transaction auth planning into explicit pre-confirm deps and confirmed auth deps so OTP challenge/complete execution is no longer part of the planner's pre-confirm dependency type.
116. [x] Narrowed EVM-family transaction auth planning pre-confirm deps to cached status readers only, removing warm-session manager provisioning/rehydration capabilities from that boundary.
117. [x] Added EVM-family auth-planning coverage that an Email OTP reauth plan is lazy: planning does not request a challenge or complete OTP, while confirmed challenge preparation still uses the confirmed deps.
118. [x] Split NEAR transaction auth planning into pre-confirm status deps and confirmed Email OTP deps, then moved NEAR Email OTP challenge preparation behind the confirmation-displayed boundary with ordering coverage.
119. [x] Added transaction-flow order guards for EVM, Tempo, and NEAR so OTP preparation, OTP completion, and threshold reconnect cannot drift ahead of confirmation display.
120. [x] Added NEAR API-wrapper coverage for an exhausted Email OTP session: exact status reports exhaustion, confirmation display emits first, OTP challenge is requested next, and OTP completion happens only after confirmation.
121. [x] Added planner matrix coverage that NEAR single-transaction and batched-transaction flows both plan exactly one wallet signing-session budget spend per user-visible operation.
122. [x] Added the missing dual-auth planner mirror row: an active Email OTP lane still plans Email OTP reauth even when a newer passkey lane exists.
123. [x] Added planner matrix coverage that Ed25519 and ECDSA lanes can target the same wallet signing-session budget while retaining curve-specific threshold session ids.
124. [x] Added a fake planner lane store that exposes OTP-only, passkey-only, dual-auth active OTP, dual-auth active passkey, and ambiguous-lane cases before planning.
125. [x] Added fake confirmed-deps execution coverage that records OTP/passkey prompts and wallet-budget spends against the selected lane.
126. [x] Added hostile fake EVM-family pre-confirm deps that throw on OTP, provision, or rehydrate side effects if auth planning ever calls them.
127. [x] Added Ed25519 session-store boundary coverage for malformed canonical records, including missing/negative `remainingUses`, missing/invalid `expiresAtMs`, and missing JWT on JWT-backed sessions.
128. [x] Tightened ECDSA session-store codec boundaries so persisted records must carry `expiresAtMs` and `remainingUses`, and persisted lane keys must match the decoded record account, chain, source, threshold key, and signing-root binding.
129. [x] Hardened wallet-budget spending against wrong wallet signing-session ids: coordinator consumption now fails when no discovered lane owns the requested wallet session, and the budget ledger does not mark `not_found` spends as completed.
130. [x] Made Email OTP auth context strict at the store boundary for Ed25519 and ECDSA records: missing context, invalid auth method, invalid policy/reason, and impossible policy/retention pairs are rejected instead of defaulted.
131. [x] Added a wallet signing spend-plan codec and routed `WalletSigningBudgetLedger` through it so malformed ledger entries fail before coordinator mutation and do not get recorded as successful spends.
132. [x] Removed the remaining source-less passkey ECDSA signing lookup path: transaction signing now enumerates explicit passkey storage sources and the one-record passkey signing helpers require a source.
133. [x] Added typed invalid-record errors at the threshold session-store boundary so malformed persisted Ed25519/ECDSA records are no longer collapsed into missing sessions.
134. [x] Removed signing-flow coercion of `remainingUses` and `expiresAtMs` from typed Ed25519/ECDSA records so record-shape validation stays owned by the session-store codecs.
135. [x] Added `WalletSigningBudgetLedger.recordZeroSpend` with redacted trace coverage so failed/cancelled operations can be recorded without consuming or completing wallet budget.
136. [x] Wired zero-spend recording into final EVM/Tempo and NEAR transaction failure boundaries after retry/repair opportunities, with shared failure-reason classification for cancellation, OTP, passkey, nonce, and signing failures.
137. [x] Audited signing-session comments for obsolete legacy-flow guidance; remaining comments describe current nonce/threshold mechanics rather than superseded auth routing.
138. [x] Settled warm-session service lifetimes: extracted services are stateless per-manager composition objects, with request-scoped mutable state kept in signing execution and no module-level auth/session singletons.
139. [x] Removed temporary WarmSession `*ForSource` facade methods; EVM-family callers now use the normal narrow interfaces and pass the selected source explicitly.
140. [x] Added boundary coverage that keeps WarmSession provisioners/restorers out of transaction prompt policy and direct auth-prompt dependencies.
141. [x] Added EVM-family transaction-module boundary coverage against raw ECDSA store functions, WebAuthn prompt APIs, and direct wallet-budget mutation.
142. [x] Verified remaining Ed25519 warm-session transaction auth callers build `SigningLaneContext` and call `SigningSessionCoordinator.resolveAuthPlanFromReadiness(...)` directly.
143. [x] Migrated status-only `SigningEngine`, NEAR signing-dependency, and manager-convenience call sites from full `WarmSessionManager` construction to `createWarmSessionStatusReader`.
144. [x] Migrated bootstrap factory capability/auth-lane reads from full `WarmSessionManager` construction to `createWarmSessionCapabilityReader`.
145. [x] Removed production signing-code construction of `WarmSessionManager`; `SigningEngine`, NEAR flows, the secp256k1 signer, and EVM-family adapters now compose the extracted readers/provisioners/policy adapters directly.
146. [x] Added a production import-boundary guard so signing code cannot start importing the `WarmSessionManager` facade again.
147. [x] Migrated direct warm-session unit and browser-dist tests from the deleted `WarmSessionManager` facade to focused capability/status/provisioner services.
148. [x] Deleted the `WarmSessionManager` composition facade and removed the aggregate `WarmSessionManager` service type.
149. [x] Tightened stale Email OTP route-auth and persistence guards so static checks focus on boundary regressions while matrix tests own behavioral auth-routing coverage.
150. [x] Routed EVM-family Email OTP reauth prepare/resend and threshold reconnect runtime side effects through execution-command wrappers tied to planner output.

Next implementation steps:

1. [x] Add lane builders for Ed25519/ECDSA and Tempo/EVM/NEAR transaction contexts.
2. [x] Add lane-specific capability readers so signing execution cannot call generic account/chain session lookups.
3. [x] Add import-boundary guards for generic ECDSA lookups and pre-confirm auth side effects.
4. [x] Wire EVM and Tempo signing through the lane builders, capability reader, and planner while keeping auth side effects behind tx confirmation.
   - [x] Attach `SigningLaneContext` to EVM/Tempo ECDSA signing selection.
   - [x] Validate selected ECDSA record/key-ref reads through `SigningCapabilityReader`.
   - [x] Use `SigningSessionPlanner` for typed EVM/Tempo ECDSA warm-session readiness.
   - [x] Move confirmed Email OTP/passkey reauth execution onto planner output.
   - [x] Delete the remaining local `EcdsaSigningLaneContext` facade after confirmed execution consumes `SigningLaneContext` directly.
   - [x] Require a `SigningLaneContext` at the EVM/Tempo ECDSA auth-planning type boundary.
   - [x] Start splitting EVM/Tempo auth-planning dependencies into explicit reader, readiness, confirmed-auth, nonce, and smart-account surfaces.
5. [x] Extract the idempotent budget ledger and replace direct transaction-flow budget mutation.
   - [x] Add `WalletSigningBudgetLedger`.
   - [x] Route EVM/Tempo successful ECDSA transaction spends through `WalletSigningBudgetLedger.recordSuccess`.
   - [x] Keep the same EVM/Tempo `SigningOperationId` across fresh-OTP retry attempts.
   - [x] Move NEAR transaction budget spending through the ledger.
   - [x] Move operation id creation to transaction confirmation start.
     - [x] Move NEAR transaction operation id creation to confirmation-start.
     - [x] Move EVM/Tempo operation id creation to confirmation-start after planner lane construction no longer requires it pre-confirm.
   - [x] Add guard coverage that transaction signing cannot call the coordinator directly.
   - [x] Add NEAR signing-flow coverage that duplicate successful completion with the same operation id spends once.
   - [x] Add NEAR signing-flow coverage that confirmation cancellation and worker signing failure do not spend.
   - [x] Add NEAR signing-flow coverage that OTP resend does not spend before successful signing.
   - [x] Add EVM/Tempo signing-flow coverage that confirmation cancellation does not spend.
   - [x] Add EVM/Tempo signing-flow coverage that duplicate successful completion with the same operation id spends once.
6. [x] Migrate NEAR signing to the same planner after EVM/Tempo are stable.
   - [x] Route shared NEAR threshold auth-plan resolution through `SigningSessionPlanner`.
   - [x] Route NEAR API-wrapper per-operation Email OTP planning through the planner without splitting material acquisition policy.
7. [x] Split `WarmSessionManager` into capability, provisioner, restore, status, and post-sign policy services.
   - [x] Introduce narrow capability, status, provisioner, and post-sign policy interfaces.
   - [x] Delete the legacy Ed25519 transaction auth-plan method from `WarmSessionManager`.
   - [x] Guard against reintroducing transaction auth-plan policy into `WarmSessionManager`.
   - [x] Move the service boundary type definitions out of `WarmSessionManager.ts`.
   - [x] Move ECDSA sensitive-operation policy checks into `SigningPostSignPolicy`.
   - [x] Physically extract capability/status/provisioner/restorer implementations from `WarmSessionManager`.

### Phase 0: Resolve Planner Design Decisions

Goal: make the next code phases unambiguous before wiring runtime behavior.

1. [x] Free the planner name by renaming the old threshold readiness helper to `thresholdSigningSessionReadiness`.
2. [x] Define the first shared `SigningLaneContext` shape with operation id, key kind, storage source, session origin, retention, and wallet-budget ids.
3. [x] Decide whether Email OTP challenge issuance may happen before tx review or must be confirmed-only.
4. [x] Decide service lifetimes for extracted warm-session services.
   - [x] Use stateless per-manager composition services; keep mutable transaction/auth state request-scoped in signing execution.
5. [x] Classify which source-less lookups remain as admin/status APIs and rename them away from signing paths.
6. [x] Define planner trace event redaction rules before emitting trace logs.

### Phase 1: Inventory And Guard The Current Surface

Goal: make current policy ownership and ambiguous paths visible before moving code.

1. [x] List every caller that constructs or transforms a transaction `signingAuthPlan`.
2. [x] List every caller that reads ECDSA session records or key refs.
3. [x] List every caller that can trigger WebAuthn, Email OTP verification, threshold reconnect, or worker auth side effects.
4. [x] List every caller that spends or clears wallet signing-session budget.
5. [x] Add guard tests that transaction signing code cannot call generic ECDSA lookup helpers without an explicit lane.
6. [x] Add guard tests that transaction prep code cannot import WebAuthn prompt, Email OTP complete, threshold reconnect, or budget-spend helpers.
7. [x] Add guard tests that export/add-signer/link-device paths cannot call the transaction budget ledger.
8. [x] Document the current owners in this file before each extraction begins.

Current owner inventory:

1. Transaction auth-plan construction:
   `api/evmFamily/authPlanning.ts` owns EVM/Tempo transaction auth-plan resolution through `SigningSessionPlanner`; `api/nearSigning.ts` routes NEAR API-wrapper transaction auth-plan construction through `SigningSessionPlanner`; `SigningEngine.ts` owns key-export auth-plan construction; `SeamsPasskey/login.ts` and `threshold/workflows/connectEd25519Session.ts` own non-transaction login/connect auth-plan construction; touch-confirm modules only normalize and execute the provided plan.
2. ECDSA session record/key-ref reads:
   EVM/Tempo transaction signing reads selected ECDSA lanes through `api/evmFamily/ecdsaLanes.ts`, `SigningCapabilityReader`, and source-required WarmSession APIs. `WarmSessionStatusReader.ts` and `WalletSigningSessionCoordinator.ts` enumerate explicit sources for status and wallet-session discovery. Remaining generic `SigningEngine.getThresholdEcdsa*ForLookup` calls are admin/export/bootstrap/status compatibility surfaces and must not be used as transaction-signing policy inputs.
3. Auth side effects:
   `api/evmFamily/transactionExecutor.ts` and shared touch-confirm signing helpers execute transaction confirmation and confirmed EVM/Tempo OTP/passkey reauth. `api/nearSigning.ts` still owns NEAR per-operation OTP/passkey reauth execution. `EmailOtpThresholdSessionCoordinator.ts`, `SeamsPasskey/index.ts`, and `email-otp.worker.ts` own Email OTP challenge/verification mechanics. `WarmSessionEcdsaProvisioner.ts` owns ECDSA reconnect/provisioning mechanics and is now called by source-required EVM-family readiness APIs for transaction signing.
4. Budget and cleanup:
   `WalletSigningBudgetLedger.ts` owns idempotent transaction budget spending, operation-fingerprint binding, in-runtime reservation, and fail-closed success consume. `WalletSigningSessionCoordinator.ts` owns wallet-session spend discovery and low-level use consumption. `SigningPostSignPolicy.ts` owns selected-lane ECDSA single-use cleanup policy. `WarmSessionPostSignPolicyAdapter.ts` adapts store/status reads for cleanup. `SigningEngine.clearThresholdEcdsa*` and threshold session-store helpers remain low-level admin cleanup APIs.

Acceptance checks:

1. [x] `rg`-based guards fail if generic source-less ECDSA signing lookups are reintroduced.
2. [x] `rg`-based guards fail if pre-confirm paths gain auth side-effect deps.
3. [x] `rg`-based guards fail if transaction budget spend appears outside the budget ledger.

### Phase 2: Introduce Branded IDs And Session Codecs

Goal: stop leaking raw session storage shapes and plain string ids into signing policy.

1. [x] Add branded id helpers for wallet signing sessions, Ed25519 threshold sessions, ECDSA threshold sessions, backing material sessions, OTP challenges, and signing operation ids.
2. [x] Add codecs for canonical Ed25519 session records.
3. [x] Add codecs for canonical ECDSA session records.
4. [x] Add codecs for wallet signing-session ledger entries.
5. [x] Add codecs for Email OTP auth context and session-retention metadata.
6. [x] Make store readers return parsed records or typed invalid-record errors.
7. [x] Remove ad hoc record validation from signing flows once codecs own it.
8. [x] Add tests for malformed records, missing `remainingUses`, wrong chain, wrong source, wrong wallet session id, and wrong signing-root binding.
   - [x] Cover malformed canonical Ed25519 records at the store boundary.
   - [x] Cover missing and negative Ed25519 `remainingUses`.
   - [x] Cover malformed canonical ECDSA records at the store boundary.
   - [x] Cover missing and negative ECDSA `remainingUses`.
   - [x] Cover wrong chain.
   - [x] Cover wrong source.
   - [x] Cover wrong wallet session id.
   - [x] Cover wrong signing-root binding.

Acceptance checks:

1. [x] Signing code consumes typed records, not raw `sessionStorage` or IndexedDB payload shapes.
2. [x] Invalid records are rejected at store boundaries.
3. [x] No signing path manually interprets a partially valid session record.

### Phase 3: Generalize `EcdsaSigningLaneContext`

Goal: represent selected signing intent as one lane object shared by Ed25519 and ECDSA.

1. [x] Add `SigningLaneContext` under `client/src/core/signingEngine/session`.
2. [x] Split `source` into `authMethod`, `sessionOrigin`, and `retention`.
3. [x] Add lane builders for Ed25519 passkey, Ed25519 Email OTP, ECDSA passkey, and ECDSA Email OTP.
4. [x] Add lane builders for Tempo, EVM, and NEAR transaction contexts.
5. [x] Replace `EcdsaSigningLaneContext` in EVM/Tempo signing with `SigningLaneContext`.
   - [x] Carry `SigningLaneContext` inside the current EVM/Tempo ECDSA selection facade.
   - [x] Make EVM/Tempo signing consume `SigningLaneContext` directly and delete the ECDSA-only facade.
6. [x] Replace Ed25519 auth-plan inputs with `SigningLaneContext`.
7. [x] Ensure dual-auth accounts choose lane from active signer state, not from newest available session record.
   - [x] Cover active passkey plus stale Email OTP at ECDSA signing-flow level.
   - [x] Cover active Email OTP plus newer passkey in planner matrix coverage.
   - [x] Cover source-filtered session lookup selecting Email OTP over newer passkey.
8. [x] Add matrix tests for OTP-only, passkey-only, dual-auth active OTP, and dual-auth active passkey accounts.

Acceptance checks:

1. [x] A dual-auth active passkey account ignores stale Email OTP lanes.
2. [x] A dual-auth active OTP account ignores passkey lanes when OTP is the selected signer.
3. [x] No lane resolver returns an ambiguous lane.

### Phase 4: Remove Generic Session Lookups From Signing Code

Goal: make generic account/chain session lookup unavailable in signing paths.

1. [x] Replace optional-source ECDSA lookup helpers with explicit lane-specific ports.
2. [x] Remove legacy source-less `getThresholdEcdsaSessionRecordForSigning` use from transaction signing.
   - [x] Validate the selected EVM/Tempo ECDSA transaction lane through source-specific `SigningCapabilityReader` ports.
   - [x] Rename the remaining generic optional-source compatibility method to `getThresholdEcdsaSessionRecordForLookup`.
   - [x] Delete the remaining source-less compatibility methods after all EVM/Tempo and warm-session call sites are migrated.
3. [x] Remove legacy source-less `getThresholdEcdsaKeyRefForSigning` use from transaction signing.
   - [x] Validate selected EVM/Tempo ECDSA key refs through source-specific `SigningCapabilityReader` ports.
   - [x] Rename the remaining generic optional-source compatibility method to `getThresholdEcdsaKeyRefForLookup`.
   - [x] Delete the remaining source-less compatibility methods after all EVM/Tempo and warm-session call sites are migrated.
4. [x] Require `SigningLaneContext` for all ECDSA signing-session reads.
   - [x] Require the selected ECDSA `SigningLaneContext` for EVM/Tempo post-sign wallet-budget and cleanup record reads.
   - [x] Require the completed ECDSA `SigningLaneContext` for EVM/Tempo Email OTP completion refresh record reads.
5. [x] Require `SigningLaneContext` for all Ed25519 signing-session reads.
   - [x] Replace NEAR planner-readiness fallback with exact Ed25519 `thresholdSessionId` status reads.
   - [x] Remove Ed25519 account-only reads from `SigningCapabilityReader`.
6. [x] Move generic diagnostic lookup helpers outside signing execution code.
   - [x] Move NEAR transaction sealed-restore ECDSA list/read diagnostics behind a narrow restore dependency.
   - [x] Replace NEAR transaction inline warm-session status construction with exact Ed25519 session-status dependency injection.
7. [x] Update `WarmSessionManager` to reject source-less signing-path ECDSA lookups.
8. [x] Keep source-less admin/status APIs only if they return multi-lane results, not one chosen lane.
   - [x] Route WarmSession status and wallet signing-session discovery through multi-lane ECDSA record listing.
   - [x] Route WarmSession provisioning and reconnect key-ref discovery through multi-lane ECDSA key-ref listing.
   - [x] Replace source-less ECDSA status selection with `listEcdsaSigningSessionStatuses` and exact `thresholdSessionId` status reads.

Acceptance checks:

1. [x] Transaction signing cannot compile without passing a lane.
2. [x] A missing lane is an explicit planning error, not a passkey fallback.
3. [x] Session status APIs that inspect multiple lanes return multiple lanes or a grouped wallet-session view.

### Phase 5: Add A No-Auth-Before-Confirm Boundary

Goal: prevent standalone browser/passkey/OTP prompts before the tx confirmer owns user interaction.

1. [x] Split dependencies into `PreConfirmSigningDeps` and `ConfirmedSigningDeps`.
   - [x] Introduce named EVM-family dependency surfaces as the first compile-time boundary before the full split.
   - [x] Split EVM-family transaction auth planning args into `EvmFamilyPreConfirmSigningDeps` and `EvmFamilyConfirmedSigningDeps`.
   - [x] Split NEAR transaction auth planning args into pre-confirm status deps and confirmed Email OTP deps.
2. [x] Allow pre-confirm code to read public state, account metadata, nonce state, and cached session status only.
   - [x] Narrow EVM-family transaction auth-planning pre-confirm deps to cached warm-session status readers.
   - [x] Narrow NEAR transaction auth-planning pre-confirm deps to exact Ed25519 status and touch-confirm availability.
3. [x] Forbid pre-confirm deps from exposing WebAuthn prompt, Email OTP completion, threshold reconnect/provision, PRF claim, unseal, or budget spend.
   - [x] Guard EVM-family auth planning so `EvmFamilyTransactionWalletAuthDeps` does not expose Email OTP challenge or completion methods.
   - [x] Guard EVM-family auth planning so pre-confirm deps do not expose ECDSA provision or sealed rehydrate methods.
   - [x] Guard NEAR transaction auth planning so pre-confirm deps do not expose OTP challenge/completion or passkey reconnect methods.
4. [x] Move threshold reconnect and OTP completion behind the confirmed signing executor.
   - [x] Guard EVM, Tempo, and NEAR transaction flows so OTP completion and threshold reconnect stay after confirmation display.
5. [x] Ensure tx confirmer is mounted before any reauth side effect starts.
   - [x] Move EVM/Tempo Email OTP challenge preparation after confirmation display.
   - [x] Move NEAR Email OTP challenge preparation after confirmation display.
6. [x] Add runtime trace events for `pre_confirm_readiness_checked` and `auth_side_effect_started`.
7. [x] Add tests that fail if WebAuthn or OTP completion is called before tx confirmer display.
   - [x] Add NEAR Email OTP ordering coverage that challenge preparation happens after confirmation display and cancellation never completes OTP.
   - [x] Add static transaction-flow order guards for EVM, Tempo, and NEAR auth side effects.
   - [x] Add NEAR API-wrapper coverage for exhausted Email OTP challenge ordering after confirmation display.
   - [x] Assert EVM/Tempo exhausted Email OTP challenge preparation happens after confirmation display and cancellation never completes OTP.
   - [x] Assert EVM-family auth planning does not execute Email OTP challenge or completion side effects before confirmed preparation.
8. [x] Add tests for EVM and Tempo exhausted OTP sessions proving there is no standalone passkey prompt.

Acceptance checks:

1. [x] No WebAuthn prompt can happen before the tx confirmer modal/drawer exists.
2. [x] No Email OTP verify can happen before tx confirmer confirmation flow exists.
3. [x] No threshold reconnect can happen before selected auth method is known.

### Phase 6: Create One Signing Session Planner

Goal: centralize warm-session, OTP reauth, passkey reauth, and not-ready decisions.

1. [x] Add `client/src/core/signingEngine/session/SigningSessionPlanner.ts`.
2. [x] Move Ed25519 transaction auth-plan decision logic into the planner.
3. [x] Move ECDSA transaction auth-plan decision logic into the planner.
   - [x] Use planner output for EVM/Tempo typed ECDSA warm-session readiness decisions.
   - [x] Use planner output for confirmed EVM/Tempo Email OTP/passkey reauth decisions.
   - [x] Remove the EVM-family `WalletAuthModeResolver` fallback so the selected lane's planner output remains authoritative.
4. [x] Move warm-session readiness decision logic into the planner.
   - [x] Route EVM/Tempo typed ECDSA warm-session readiness through the planner.
   - [x] Route Ed25519 and remaining warm-session callers through the planner.
5. [x] Move single-use Email OTP reauth decision logic into the planner.
6. [x] Move passkey exhaustion/reconnect decision logic into the planner.
7. [x] Make planner output include selected lane, selected auth plan, key-ref intent, and budget-spend plan.
8. [x] Keep operation-specific rendering and transaction display outside the planner.
9. [x] Replace `resolveEvmFamilyTransactionWalletAuth` with planner usage.
10. [x] Replace NEAR transaction auth-plan construction with planner usage.

Acceptance checks:

1. [x] EVM, Tempo, and NEAR transaction signing call the same planner.
2. [x] `WarmSessionManager` no longer decides whether a transaction should prompt OTP or passkey.
3. [x] Signing execution consumes a plan and does not rediscover policy.

### Phase 7: Split `WarmSessionManager`

Goal: make `WarmSessionManager` stop being the policy, restore, readiness, provisioning, and budget facade.
Use the file-level extraction map in `Large File Refactor Targets` as the migration checklist.

1. [x] Extract `SigningCapabilityResolver` for current lane/session readiness reads.
   - [x] Introduce the narrow `WarmSessionCapabilityReader` interface for capability reads.
   - [x] Move the capability reader interface out of `WarmSessionManager.ts`.
   - [x] Move warm-session envelope construction and threshold-session record/auth resolution out of `WarmSessionManager.ts`.
2. [x] Extract `SigningSessionProvisioner` for Ed25519 and ECDSA provisioning/reconnect.
   - [x] Introduce the narrow `WarmSessionProvisioner` interface for provisioning/reconnect calls.
   - [x] Move provisioning argument/result types and interface out of `WarmSessionManager.ts`.
   - [x] Move ECDSA bootstrap request assembly out of `WarmSessionManager.ts`.
   - [x] Move Ed25519 provisioning out of `WarmSessionManager.ts`.
   - [x] Move reusable warm ECDSA bootstrap lookup out of `WarmSessionManager.ts`.
   - [x] Move ECDSA provisioning out of `WarmSessionManager.ts`.
   - [x] Move ECDSA reconnect/readiness out of `WarmSessionManager.ts`.
3. [x] Extract `SealedRefreshRestorer` for sealed refresh restore and parity checks.
   - [x] Move Email OTP ECDSA sealed-refresh restore and parity checks into `WarmSessionSealedRefreshRestorer.ts`.
4. [x] Extract `SigningSessionStatusReader` for wallet-session and lane-session status views.
   - [x] Introduce the narrow `ThresholdWarmSessionStatusReader` interface for threshold session status calls.
   - [x] Move the status reader interface out of `WarmSessionManager.ts`.
   - [x] Move threshold signing-session status implementation out of `WarmSessionManager.ts`.
5. [x] Extract `SigningPostSignPolicy` for single-use cleanup and ephemeral material clearing.
   - [x] Move ECDSA sensitive-operation checks into `SigningPostSignPolicy`.
   - [x] Add direct unit coverage for cleanup and sensitive-operation decisions.
   - [x] Move WarmSessionManager's cleanup and sensitive-operation adapter body into `WarmSessionPostSignPolicyAdapter.ts`.
6. [x] Delete secondary-lane policy checks from `WarmSessionManager` signing paths.
   - [x] Delete the legacy Ed25519 transaction auth-plan method.
   - [x] Guard against reintroducing transaction auth-plan policy into `WarmSessionManager`.
   - [x] Move ECDSA sensitive-operation policy checks out of `WarmSessionManager`.
7. [x] Make `WarmSessionManager` a thin composition facade only where existing call sites still need it.
8. [x] Gradually migrate call sites to smaller interfaces and then remove the facade methods.
   - [x] Move status-only `SigningEngine`, NEAR signing-dependency, and manager-convenience reads to `WarmSessionStatusReader`.
   - [x] Move bootstrap factory capability/auth-lane reads to `WarmSessionCapabilityReader`.
   - [x] Move production `SigningEngine`, NEAR orchestration, EVM-family adapter, and secp256k1 signer call sites to focused WarmSession services.
   - [x] Guard production signing code against new `WarmSessionManager` facade imports.
   - [x] Move direct `WarmSessionManager` unit coverage onto focused service tests, then delete the composition facade.

Acceptance checks:

1. [x] `WarmSessionManager` no longer imports or constructs `WalletSigningSessionCoordinator`.
2. [x] `WarmSessionManager` no longer has transaction auth-plan methods.
3. [x] `WarmSessionManager` no longer chooses secondary lanes for transaction policy.
4. [x] The `WarmSessionManager` composition facade has been deleted; production and unit coverage now target focused warm-session services.

### Phase 8: Make Budget Spending An Idempotent Ledger

Goal: replace post-sign ad hoc budget mutation with one operation-ledger API.

1. [x] Add `WalletSigningBudgetLedger`.
2. [x] Add stable `SigningOperationId` creation at transaction confirmation start.
   - [x] Preserve the same EVM/Tempo operation id across fresh-OTP retry attempts.
   - [x] Create the NEAR transaction operation id when tx confirmation starts.
   - [x] Create the EVM/Tempo operation id when tx confirmation starts after the pre-confirm planner no longer requires an operation id.
3. [x] Have planner include a `WalletSigningSpendPlan`.
4. [x] Record spend after successful signature production and before returning success to caller.
   - [x] Route EVM/Tempo successful ECDSA transaction spends through the ledger after signing succeeds.
   - [x] Route NEAR successful transaction spends through the ledger.
5. [x] Make spend idempotent by `operationId`.
6. [x] Record zero spend for cancellation, failed OTP, failed passkey, nonce preparation failures, and signing failures.
   - [x] Add a ledger API for explicit zero-spend records that does not call the coordinator and does not mark the operation as successfully spent.
   - [x] Wire EVM/Tempo zero-spend recording after fresh-OTP retry fails and nonce errors have been normalized.
   - [x] Wire NEAR zero-spend recording after relayer-key repair is no longer recoverable.
   - [x] Add NEAR signing-flow assertions that confirmation cancellation and worker signing failure do not record a positive spend.
   - [x] Add EVM/Tempo signing-flow assertions that confirmation cancellation does not record a positive spend.
7. [x] Remove direct `consumeWalletSigningSessionUse` calls from transaction flows.
8. [x] Remove fallback from missing wallet signing-session id to threshold session id.
   - [x] Removed the fallback in the EVM/Tempo transaction budget-spend path.
   - [x] Removed the fallback in the NEAR transaction budget-spend path.
   - [x] Removed wallet-budget lane discovery fallback from threshold session id to wallet signing-session id.
   - [x] Removed WarmSessionManager sealed-restore wallet matching fallback from threshold session id to wallet signing-session id.
   - [x] Removed and guarded remaining sealed-store/policy fallback paths outside transaction signing paths.
9. [x] Add ledger tests for retry, resend, cancellation, and duplicated completion callbacks.
   - [x] Add focused ledger unit coverage for duplicate successful record calls and failed-spend retry.
   - [x] Add NEAR signing-flow coverage for duplicate successful completion with the same operation id.
   - [x] Add NEAR signing-flow coverage for confirmation cancellation and worker signing failure.
   - [x] Add NEAR signing-flow coverage for OTP resend behavior.
   - [x] Add EVM/Tempo signing-flow coverage for cancellation.
   - [x] Add EVM/Tempo signing-flow coverage for duplicated completion callbacks.

Acceptance checks:

1. [x] Exactly one wallet signing-session use is consumed per successful user-visible transaction operation.
2. [x] A retry with the same operation id does not double-spend.
3. [x] Missing `walletSigningSessionId` is a hard error for transaction signing.

### Phase 9: Replace Source Guards With Matrix Tests

Goal: move confidence from string guards to behavior coverage.

Matrix dimensions:

1. auth method: Email OTP, passkey
2. account capability: OTP-only, passkey-only, dual-auth active OTP, dual-auth active passkey
3. curve: Ed25519, ECDSA
4. chain: NEAR, Tempo, EVM
5. budget state: active, exhausted, expired, missing, stale local record
6. operation result: success, cancel, OTP retry, passkey reject, resend

TODO:

1. [x] Add a table-driven planner test harness.
2. [x] Add a fake lane store that can expose conflicting OTP/passkey lanes.
3. [x] Add fake pre-confirm deps that throw if auth side effects are called.
   - [x] Add static guards for EVM-family and NEAR transaction pre-confirm dependency surfaces.
   - [x] Add NEAR API-wrapper coverage where confirmed OTP challenge deps are observable and only run after confirmation display.
   - [x] Add hostile EVM-family pre-confirm deps that fail if auth planning calls OTP, provision, or rehydrate side effects.
4. [x] Add fake confirmed deps that record auth prompts and budget spends.
5. [x] Cover two consecutive exhausted Email OTP ECDSA transactions for Tempo and EVM.
6. [x] Cover dual-auth active passkey plus stale Email OTP lane.
7. [x] Cover dual-auth active OTP plus newer passkey lane.
8. [x] Cover Ed25519 and ECDSA shared wallet-session budget spend.
9. [x] Keep a few source guards only for import-boundary enforcement.

Acceptance checks:

1. [x] Matrix tests assert selected lane, auth prompt, key-ref source, budget spend count, and trace events.
2. [x] Static guards only enforce module boundaries, not behavioral correctness.
3. [x] New auth methods can be added by adding matrix rows instead of duplicating signer tests.

### Phase 10: Add Trace-Level Decision Events

Goal: make future auth routing bugs diagnosable in minutes.

Add safe structured events:

```ts
type SigningSessionDecisionEvent =
  | { event: 'signing_lane_resolved'; operationId: SigningOperationId; lane: SigningLaneSummary }
  | {
      event: 'signing_session_plan_resolved';
      operationId: SigningOperationId;
      plan: SigningPlanSummary;
    }
  | { event: 'pre_confirm_readiness_checked'; operationId: SigningOperationId; result: string }
  | {
      event: 'auth_side_effect_started';
      operationId: SigningOperationId;
      authMethod: 'email_otp' | 'passkey';
    }
  | {
      event: 'email_otp_challenge_requested';
      operationId: SigningOperationId;
      challengeId: EmailOtpChallengeId;
    }
  | { event: 'passkey_reauth_requested'; operationId: SigningOperationId }
  | {
      event: 'wallet_budget_spent';
      operationId: SigningOperationId;
      walletSigningSessionId: WalletSigningSessionId;
    }
  | {
      event: 'threshold_session_consumed';
      operationId: SigningOperationId;
      thresholdSessionId: ThresholdSessionId;
    };
```

TODO:

1. [x] Add trace event types with redaction rules.
2. [x] Emit lane resolution events.
3. [x] Emit planner decision events.
4. [x] Emit no-auth-before-confirm boundary events.
5. [x] Emit auth prompt start events.
   - [x] Emit Email OTP challenge-start events.
   - [x] Emit EVM-family passkey and threshold reconnect prompt-start events at confirmed command boundaries.
   - [x] Emit NEAR passkey and threshold reconnect prompt-start events at confirmed command boundaries.
6. [x] Emit budget ledger events.
7. [x] Emit post-sign cleanup events.
8. [x] Add tests asserting trace order for warm, exhausted OTP, exhausted passkey, and cancellation flows.

Acceptance checks:

1. [x] Trace logs include no secrets, OTP codes, JWTs, share material, PRF material, or raw recovery material.
2. [x] A future "wrong prompt appeared" bug can be traced from lane selection to auth side effect.
3. [x] Trace events are stable enough for tests to assert order and key fields.

### Phase 11: Migrate EVM And Tempo Signing

Goal: shrink `evmSigning.ts` into orchestration and chain-specific nonce behavior.
Use the file-level extraction map in `Large File Refactor Targets` as the migration checklist.

1. [x] Extract ECDSA lane resolution from `evmSigning.ts`.
2. [x] Extract auth planning from `evmSigning.ts`.
3. [x] Extract budget spend from `evmSigning.ts`.
4. [x] Extract post-sign policy from `evmSigning.ts`.
5. [x] Extract EVM nonce lifecycle into an EVM-specific module.
6. [x] Extract Tempo nonce lifecycle into a Tempo-specific module.
7. [x] Keep `signEvmFamily` as a thin wrapper around planner plus executor.
8. [x] Delete duplicated EVM/Tempo post-sign blocks after extraction.

Acceptance checks:

1. [x] `evmSigning.ts` no longer owns auth policy decisions.
2. [x] `evmSigning.ts` no longer owns wallet budget mutation.
3. [x] EVM and Tempo share planner behavior but keep chain-specific nonce handling.

### Phase 12: Migrate NEAR Signing

Goal: bring Ed25519 signing under the same planner without regressing the currently correct OTP behavior.
NEAR planner migration must move auth-plan selection and threshold material acquisition together:
`transactionsFlow.ts` still has independent PRF/HSS reconstruction decisions, so wiring planner
output only in the API wrapper leaves two policy owners.

1. [x] Replace NEAR transaction auth-plan construction with planner output.
   - [x] Replace shared NEAR threshold auth-plan resolution with planner output.
   - [x] Replace remaining NEAR API-wrapper per-operation Email OTP planning with planner output.
2. [x] Replace NEAR wallet budget spend with ledger output.
3. [x] Ensure NEAR batches still consume one user-visible operation budget spend.
4. [x] Preserve Ed25519 Email OTP fresh reauth behavior.
5. [x] Preserve passkey reauth behavior after exhaustion.
6. [x] Add matrix rows for NEAR transaction batches and single transactions.

Acceptance checks:

1. [x] Ed25519 and ECDSA use the same planner.
2. [x] NEAR transaction batches still consume one wallet signing-session use per confirmation flow.
3. [x] The existing Ed25519 exhausted OTP behavior remains unchanged.

### Phase 13: Delete Ambiguous Fallbacks

Goal: remove code that can reintroduce ambiguous lane behavior.

1. [x] Delete source-less transaction ECDSA lookup helpers.
2. [x] Delete generic "try every source" lookup from signing paths.
3. [x] Delete secondary-lane policy fallbacks from transaction signing.
4. [x] Delete threshold-session-id fallback as wallet signing-session id.
5. [x] Delete wrapper-side freshness throws and policy preflights.
6. [x] Delete obsolete comments that describe superseded flows.
7. [x] Update docs to describe planner-owned auth routing only.

Acceptance checks:

1. [x] No transaction signing path can select a lane by newest persisted session.
2. [x] No transaction signing path can inspect a secondary lane for active-lane policy.
3. [x] No wrapper can throw fresh-auth errors before the planner and tx confirmer flow.

### Phase 14: Make Session Identity Non-Optional

Goal: remove optional security/session identity fields after the first
normalization boundary. Optional fields are acceptable in draft inputs, callbacks,
display metadata, and config knobs. They are not acceptable once code is choosing,
restoring, spending, signing, or cleaning up a specific lane.

The bug class to eliminate:

```ts
session?.sessionId || keyRef.thresholdSessionId || record?.thresholdSessionId;
```

Fallback chains like this hide identity ambiguity. They make it easy to pass an
Ed25519 companion id into an ECDSA restore path, omit a selected signing lane, or
spend wallet budget against a different session than the signer actually used.

Design rule:

1. Draft/bootstrap inputs may be partial.
2. A named resolver normalizes draft inputs into a resolved identity object.
3. Security/session code accepts only resolved identity objects.
4. Missing identity is a typed failure at the boundary, not a fallback inside the
   signing path.

Target type shape:

```ts
type ResolvedSigningSessionPurpose = {
  authMethod: 'email_otp' | 'passkey';
  curve: 'ed25519' | 'ecdsa';
  chain?: 'near' | 'tempo' | 'evm';
};

type ResolvedSigningLaneIdentity = ResolvedSigningSessionPurpose & {
  walletSigningSessionId: WalletSigningSessionId;
  thresholdSessionId: ThresholdSessionId;
  backingMaterialSessionId: BackingMaterialSessionId;
};

type ResolvedEmailOtpEcdsaSession = ResolvedSigningLaneIdentity & {
  authMethod: 'email_otp';
  curve: 'ecdsa';
  chain: 'tempo' | 'evm';
  signingRootId: string;
  relayerUrl: string;
  shamirPrimeB64u: string;
};
```

Implementation TODO:

1. [ ] Inventory optional identity fields in OTP and signing-session paths.
   - [ ] Classify each optional as draft/config/callback metadata or
         security/session identity.
   - [ ] Start with `authMethod?`, `curve?`, `chain?`,
         `walletSigningSessionId?`, `thresholdSessionId?`,
         `backingMaterialSessionId?`, `signingRootId?`, and `operationId?`.
2. [ ] Introduce phase-specific Email OTP session types.
   - [ ] `EmailOtpEcdsaBootstrapDraft` may keep optional server response fields.
   - [ ] `ResolvedEmailOtpEcdsaSession` requires auth method, curve, chain,
         wallet signing-session id, ECDSA threshold session id, signing root,
         relayer URL, key version, and Shamir prime.
   - [ ] `ResolvedEmailOtpEd25519Session` requires auth method, curve, wallet
         signing-session id, Ed25519 threshold session id, relayer URL, and
         participant ids.
3. [ ] Split lane types by phase.
   - [ ] Keep a draft lane only for discovery/planning.
   - [ ] Add `ResolvedEd25519SigningLane` and `ResolvedEcdsaSigningLane`.
   - [ ] Make budget reservation, budget finalization, execution, sealed-store
         restore, and post-sign cleanup accept only resolved lanes.
4. [ ] Replace identity fallback chains with named resolvers.
   - [ ] Add `resolveEmailOtpEcdsaSessionIdentity(...)`.
   - [ ] Add `resolveEmailOtpEd25519SessionIdentity(...)`.
   - [ ] Add `resolveSelectedEcdsaSigningLaneIdentity(...)`.
   - [ ] Make these return discriminated results: `{ ok: true, identity }` or
         `{ ok: false, code, message }`.
5. [x] Make sealed-session store ports purpose-required.
   - [x] Require `{ authMethod, curve }` for every read, write, update, delete,
         and lease operation.
   - [x] Remove optional `authMethod?` and `curve?` from production sealed-store
         write inputs.
   - [x] Keep compatibility parsing only inside the store codec, not at callers.
6. [ ] Replace optional dependency methods with required ports.
   - [ ] Inject a required `SigningSessionSealedStorePort`.
   - [ ] Inject required status/read/provision ports at service construction,
         using no-op or unavailable adapters only where the feature is genuinely
         disabled.
   - [ ] Remove `readSigningSessionSealedRecord?` and similar optional method
         checks from hot signing paths.
7. [ ] Normalize collection inputs at boundaries.
   - [ ] Convert optional budget arrays to required arrays before calling
         coordinator internals.
   - [ ] Internal budget/readiness functions should receive `[]`, not
         `undefined`.
8. [x] Tighten EVM-family ECDSA signing runtime inputs.
   - [x] Replace `getEcdsaSigningLane(): SigningLaneContext | undefined` with
         `getResolvedEcdsaSigningLane(): ResolvedEcdsaSigningLane`.
   - [x] Remove budget finalizer fallback to key-ref or record ids except inside
         the resolver that updates the resolved lane after successful reauth.
9. [ ] Tighten OTP sealed-refresh restore.
   - [ ] Treat Ed25519 companion resolution as an explicit resolver result.
   - [ ] Require the resolved ECDSA threshold session id before worker
         rehydration.
   - [ ] Log only sanitized identity summaries: auth method, curve, chain, and
         mismatch reason.
10. [ ] Add static guards and regression tests.
    - [x] Guard against `authMethod?:` and `curve?:` in resolved/session-store
          production input types.
    - [x] Guard against `thresholdSessionId?:` in resolved lane types.
    - [ ] Guard against identity fallback chains outside resolver modules.
    - [ ] Test Ed25519 companion restore resolving the ECDSA id before ECDSA
          sealed reads.
    - [x] Test ECDSA budget finalization cannot run without a resolved selected
          lane.

Acceptance checks:

1. [ ] All signing, restore, budget, and cleanup paths receive a resolved
       identity object before they touch worker material or wallet budget.
2. [ ] Optional identity fields are confined to draft/bootstrap types and store
       codecs.
3. [ ] Missing identity fails at resolver boundaries with a clear typed error.
4. [ ] No production signing path uses `a || b || c` to decide wallet session id,
       threshold session id, auth method, curve, or chain.
5. [ ] Static guards make this architecture hard to accidentally loosen.

## Final Acceptance Criteria

1. [x] One planner chooses warm session, Email OTP reauth, passkey reauth, or not-ready for every transaction signing flow.
2. [x] EVM, Tempo, and NEAR transaction signing use that planner.
3. [x] Ed25519 and ECDSA use one `SigningLaneContext` shape.
4. [x] `WarmSessionManager` is split into capability, provisioning, restore, status, and post-sign policy services.
5. [x] Wallet signing-session budget spending is idempotent by operation id.
6. [x] Transaction signing has a hard no-auth-before-confirm boundary.
7. [x] Signing code cannot perform generic source-less session lookups.
8. [x] Session stores return codec-validated records only.
9. [x] Branded ids prevent mixing wallet session ids, threshold session ids, backing material ids, and challenge ids.
10. [x] Matrix tests cover OTP/passkey, dual-auth, Ed25519/ECDSA, NEAR/Tempo/EVM, and budget-state combinations.
11. [x] Trace events explain every planner decision and auth side effect without exposing secrets.
