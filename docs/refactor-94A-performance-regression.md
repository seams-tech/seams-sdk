# Refactor 94: Registration Performance Regression

Date created: July 27, 2026

Status: in progress

## Objective

Restore Email OTP and passkey wallet registration to a typical 2–3 second
post-confirmation wall time in local release builds, staging, and production.

The current production flow completes successfully in approximately 5–7
seconds. A correlated Email OTP registration on July 27, 2026 measured 6.125
seconds with 97.3% span coverage:

| Concurrent branch or terminal step | Observed wall time |
| ---------------------------------- | -----------------: |
| ECDSA registration ceremony        |            4.734 s |
| Ed25519 Yao registration           |            3.544 s |
| Registration finalize request      |            0.513 s |
| Unattributed elapsed time          |            0.166 s |

ECDSA and Ed25519 Yao run concurrently. ECDSA currently determines when
finalization can begin. Refactor 94 removes serialized storage, Worker, and
Durable Object transitions from both branches while preserving the
cryptographic proof boundary, role-local secret custody, exact-once effects,
and crash convergence.

## Diagnosis

### Cryptographic compute is not the regression

The canonical Ed25519 Yao activation benchmark measured:

- 215.771 ms for its first local-workerd request;
- 143.418 ms warm p50;
- 147.640 ms warm p95;
- 149.819 ms warm p99.

That benchmark exercises two Workers connected by one Service Binding and one
full-duplex streaming request. It is a lower bound for the A/B protocol. It
does not exercise product admission, D1 ceremony persistence, role lifecycle
Durable Objects, result retrieval, or SigningWorker delivery.

The ECDSA derivation and bootstrap kernels are also sub-millisecond in the
crate benchmarks. Production registration spends its time in distributed
coordination around those kernels.

### Production builds already use release optimization

The backend deployment script sets `ROUTER_AB_WORKER_BUILD_PROFILE=release`.
The Router A/B Worker release profile uses optimization level 3, fat LTO, one
codegen unit, and `wasm-opt -O4`. Browser signer WASM is built with
`wasm-pack --release`.

Refactor 94 does not change Cargo optimization flags. Build-profile regression
is excluded as the primary cause of the measured production latency.

### ECDSA is the critical path

The browser currently performs these operations serially:

1. create the client registration ceremony;
2. call the Gateway derivation `respond` route;
3. verify both Deriver proof bundles in browser WASM;
4. call the Gateway derivation `activate` route;
5. finalize the client activation.

The Gateway and Router add the following serialized work:

1. read the registration ceremony from D1;
2. issue a Router ceremony JWT and call the Router;
3. reserve replay state in a Durable Object;
4. write `Requested` lifecycle state to a Durable Object;
5. write accepted/forwarded lifecycle state to a Durable Object;
6. call Deriver A and Deriver B;
7. update the registration ceremony in D1;
8. repeat the Gateway-to-Router boundary for activation;
9. activate the SigningWorker record;
10. provision the normal-signing session and signing budget through a session
    read, budget write, session write, and budget read-back;
11. update the registration ceremony in D1.

The browser proof-verification boundary is required. The replay, lifecycle,
session, and budget persistence boundaries can be collapsed.

### Ed25519 Yao multiplies the direct protocol latency

The browser Yao client sends a registration admission request followed by an
execution request.

Each request currently uses the generic two-phase persistence runner:

1. load shared and ceremony state;
2. commit a claim;
3. invoke the backend;
4. reload shared and ceremony state;
5. commit terminal state.

Admission and execution together can issue eight sequential D1 batch
roundtrips around one registration.

The Router execution path then:

1. prepares Deriver A and Deriver B concurrently;
2. validates both readiness receipts;
3. calls Deriver A to execute;
4. transitions A and B through separate role-local session Durable Objects;
5. loads role root metadata and execution material;
6. opens the A-to-B WebSocket and runs the Yao protocol;
7. commits both role completions;
8. calls Deriver B again to read its completed result;
9. delivers the pair to SigningWorker.

The direct streaming protocol remains fast. The surrounding request, D1, and
Durable Object graph accounts for the regression.

### Cold starts are secondary

Cloudflare cold starts can add variance. Repeated 5–7 second measurements in
local release builds and production establish a persistent orchestration cost.
Refactor 94 does not use cold-start mitigation as its primary strategy.

## Decision Summary

1. Optimize the measured ECDSA critical path first.
2. Preserve the two-phase client proof-verification boundary for strict ECDSA
   registration.
3. Replace multiple Router replay and lifecycle Durable Object calls with one
   atomic registration lifecycle operation.
4. Replace the four-operation ECDSA signing-session provisioning sequence with
   one atomic provisioning operation.
5. Fold Ed25519 Yao admission into the existing wallet registration start
   transaction.
6. Reduce Yao execution persistence to one atomic claim and one terminal CAS.
7. Remove shared tenant state from the registration ceremony hot path.
8. Fuse role-local Durable Object commands where one transaction can enforce
   the same lifecycle invariant.
9. Return Deriver B's sealed completion through the connected execution path,
   removing the separate completed-result fetch.
10. Keep Deriver A and Deriver B secret custody independent.
11. Keep root shares out of the Gateway, Router, D1, and ceremony coordinator
    state.
12. Add no runtime selector, legacy route, compatibility branch, or feature
    flag. Each replacement deletes its obsolete path in the same phase.
13. Use one focused local and one focused staging trace to validate each
    changed branch. No production trace cohort or telemetry-budget gate is
    required.
14. Consider a per-ceremony Router coordinator Durable Object only if the
    command-fusion work cannot meet the branch target. A third ledger is not
    part of the initial implementation.

## Scope

Refactor 94 owns:

- Email OTP and passkey registration latency after user confirmation;
- browser registration timing boundaries;
- strict ECDSA registration and activation orchestration;
- ECDSA Router replay and lifecycle persistence;
- ECDSA normal-signing session and budget provisioning;
- Ed25519 Yao wallet-registration admission and execution persistence;
- registration-specific Router A/B role transitions;
- exact sealed-result delivery to SigningWorker;
- a release-mode product-topology local benchmark;
- deletion of the replaced registration routes and storage commands.

Refactor 94 does not:

- change the ECDSA derivation construction or proof format;
- skip browser verification of Deriver A and Deriver B proof bundles;
- change the selected Yao circuit, garbling, OT, framing, or output-sharing
  construction;
- merge Deriver A and Deriver B secret-custody domains;
- centralize either role root share;
- change recovery, export, refresh, or add-signer semantics unless a shared
  primitive must change to support registration safely;
- introduce reusable garbled material or cryptographic preprocessing;
- introduce a performance-only correctness bypass;
- make production deployment depend on a trace cohort.

## Required Invariants

### Shared registration invariants

1. A wallet ID is admitted once for one canonical registration intent.
2. Every remote irreversible effect is preceded by a durable typed claim.
3. Retrying a completed step returns its exact stored result.
4. Retrying an ambiguous step performs reconciliation and never repeats the
   irreversible effect.
5. D1 conditional writes compare the complete canonical expected state or an
   exact version owned by that state.
6. No terminal result depends on mutable object aliasing.
7. Request and persistence compatibility parsing remains isolated at system
   boundaries.
8. Diagnostics and timing values never influence lifecycle control flow.
9. Registration response bodies remain stable unless a phase explicitly
   replaces a typed route contract.

### Strict ECDSA invariants

10. The client verifies exact proof bundles from both Derivers before
    activation.
11. SigningWorker activation requires the exact verified client facts and
    exact pending activation identity.
12. The Router atomically rejects replay identity conflicts before Deriver
    execution.
13. A replay of the same registration returns the same pending activation.
14. A conflicting replay cannot reuse a pending activation, lifecycle record,
    signing session, or budget.
15. Normal-signing session authority and signing-budget authority are committed
    atomically.
16. Registration never reports ECDSA activation before both SigningWorker and
    normal-signing session provisioning are durable.

### Ed25519 Yao invariants

17. Client factor material is consumed once and zeroized.
18. The admission receipt binds the exact wallet registration ceremony,
    application binding, participant pair, operation, circuit, root epoch, and
    signing authority.
19. The Gateway and Router never receive either role plaintext.
20. Role-local root shares remain available only to their owning Deriver.
21. A and B bind preparation, execution, completion, and redelivery to the
    exact input-pair digest.
22. Both roles independently enforce one-use execution.
23. `Running` never returns to `Prepared`.
24. Ambiguity after execution begins burns the execution identity unless an
    exact durable completion can be recovered.
25. `Completed` permits exact sealed-output redelivery without cryptographic
    reevaluation.
26. Deriver A can forward Deriver B's sealed completion bytes without parsing,
    modifying, or decrypting them.
27. SigningWorker activation remains atomic across the A/B package pair.
28. A Durable Object transaction never encloses the A/B WebSocket, Yao
    execution, another Worker request, a timer, or a polling loop.

## Target Registration Graph

The target product graph is:

```text
wallet registration start
  ├─ admit wallet intent and ECDSA branch
  └─ issue bound Ed25519 Yao admission receipt

parallel registration branches
  ├─ strict ECDSA
  │    ├─ client create
  │    ├─ Gateway respond
  │    │    ├─ atomic D1 claim
  │    │    └─ one Router registration call
  │    │         ├─ one atomic Router lifecycle claim
  │    │         └─ parallel Deriver A/B proof generation
  │    ├─ client verify proofs
  │    └─ Gateway activate
  │         ├─ one Router activation call
  │         ├─ SigningWorker activation
  │         ├─ atomic session + budget provisioning
  │         └─ terminal D1 CAS
  │
  └─ Ed25519 Yao
       ├─ client create from start receipt
       ├─ atomic D1 execution claim
       ├─ one Router execution call
       │    ├─ parallel A/B readiness
       │    ├─ connected A↔B protocol
       │    ├─ B sealed completion returned in-band
       │    └─ atomic SigningWorker pair delivery
       └─ terminal D1 CAS

wallet registration finalize
```

## Performance Targets

Targets are measured from confirmation of the selected wallet name, excluding
Google account selection, Touch ID, passkey creation, and other user-controlled
prompt time.

| Boundary                            |   Target |
| ----------------------------------- | -------: |
| Registration grant + intent + start | ≤ 500 ms |
| Strict ECDSA branch                 |  ≤ 2.0 s |
| Ed25519 Yao branch                  |  ≤ 1.5 s |
| Finalize request                    | ≤ 500 ms |
| Total wallet-ready wall time        |    2–3 s |

The ECDSA and Yao branch targets assume concurrent execution. A missed branch
target blocks completion only when total wall time exceeds three seconds or
the slower branch prevents finalization.

## Phase 0: Freeze The Measured Baseline

- [ ] Record the current commit, deployed Worker versions, frontend asset
      version, and build profile used for the first Refactor 94 comparison.
- [x] Preserve the July 27 production timing summary as the regression
      baseline: total 6.125 s, ECDSA 4.734 s, Yao 3.544 s, finalize 0.513 s.
- [x] Repair `measure-ed25519-yao-local.mjs`; its selected lifecycle test no
      longer exists and currently produces zero samples.
- [x] Add one release-mode local product-topology registration benchmark that
      exercises the current Gateway, D1, Router, role Workers, role Durable
      Objects, and SigningWorker.
- [x] Confirm the benchmark executes one real registration and fails when zero
      tests or zero samples run.
- [x] Record one local release-mode Router/role-process baseline. The first
      optimized sample completed the connected Yao branch in 90.426 ms. The
      browser timing-summary integration remains part of Phase 1.

Acceptance:

- the benchmark cannot silently pass with zero samples;
- the baseline separates product orchestration from cryptographic kernel
  benchmarks;
- no production behavior changes in this phase.

## Phase 1: Make The Critical Path Explicit

- [x] Rename the broad `walletRegisterDerivationRespondMs` timing bucket and
      split it into:
  - [x] client ceremony creation;
  - [x] Gateway derivation respond;
  - [x] browser proof verification;
  - [x] Gateway derivation activation;
  - [x] client activation finalization.
- [x] Split Yao registration timing into:
  - [x] admission or start-receipt handling;
  - [x] client session creation;
  - [x] D1 execution claim;
  - [x] Router execution;
  - [x] terminal D1 commit;
  - [x] client completion.

The Router emits its own breakdown as `Server-Timing` on
`/router-ab/ed25519/yao/registration/execute` (`yao_credential_digest`,
`yao_request_digest`, `yao_d1_claim`, `yao_router_execution`,
`yao_result_reconstruction`, `yao_d1_terminal_commit`,
`yao_router_prepare_pair`, `yao_router_verify_readiness`,
`yao_router_role_execution`, `yao_router_signing_worker_delivery`), with
`Access-Control-Expose-Headers: Server-Timing` set in `http.ts`.

The browser now captures that header in the Yao transport, threads it through
the registration Yao work, and folds it into the registration timing summary as
`yaoServer*Ms` buckets, alongside a client-observed `yaoClientCompletionMs`.
Parsing is absent-tolerant: an unexposed header, an unknown metric name, or a
malformed duration yields no bucket rather than an error, so a Router-side
rename can never break registration. Covered by
`tests/unit/registrationYaoServerTiming.unit.test.ts`.

`yaoClientCompletionMs` measures only how long the Yao branch kept registration
waiting *after* ECDSA finished — the branches run concurrently, so it is not the
ceremony duration. `yaoBranchTotalMs` is the branch wall time, for the ≤1.5 s
branch target. Both are recorded only when the branch actually ran, so an
ECDSA-only registration leaves every Yao bucket at zero.

### Measured local breakdown (2026-07-28, passkey, release profile)

End-to-end verified: the Router's `Server-Timing` is read in the browser and
folded into the registration timing summary. Total registration 1,682 ms.

| Bucket                                   |  ms |
| ---------------------------------------- | --: |
| `yaoServerRouterExecutionMs`             | 334 |
| `yaoServerRouterRoleExecutionMs`         | 199 |
| `yaoServerRouterPreparePairMs`           | 108 |
| `yaoClientCompletionMs`                  | 112 |
| `yaoServerRouterSigningWorkerDeliveryMs` |  15 |
| `yaoClientSessionCreateMs`               |   4 |
| `yaoServerD1ClaimMs`                     |   2 |
| `yaoServerResultReconstructionMs`        |   1 |
| `yaoServerD1TerminalCommitMs`            |   1 |
| `yaoServerRouterVerifyReadinessMs`       |   0 |
| `yaoAdmissionMs`                         |   0 |

Locally the Yao branch is ~334 ms of Router execution, of which role execution
is 199 ms and pair preparation 108 ms. D1 claim and terminal commit are 2 ms and
1 ms — the Phase 5 persistence reduction holds. `yaoAdmissionMs` is 0 because
registration now carries a verified admission receipt rather than issuing a
separate admission call (Phase 4).

This is the local lower bound. The same buckets will attribute the 2,348 ms
production interval once the instrumentation is deployed.

### Gap: Email OTP bypasses the capture point

Two production Email OTP registrations on 2026-07-28 returned **no**
`yaoServer*Ms` or `yaoBranchTotalMs` values. Two independent causes:

1. Production still served the older frontend, which predates the bucket
   commit — its `timings` object goes straight from `emailOtpYaoTotalMs` to
   `walletRegisterStartMs`. Redeploying fixes this one.
2. More fundamentally, **the capture only covers the passkey path.**
   `Server-Timing` is read in the main-thread
   `RouterAbEd25519YaoHttpActivationTransportV1`, but Email OTP runs its Yao
   ceremony inside the Email OTP worker
   (`startEmailOtpEd25519YaoWorkerRegistrationV1` →
   `workerContext.requestWorkerOperation`), which issues the execute call
   itself. The header never reaches the main thread.

So `emailOtpYaoWorkerRegistrationMs` — 2,171 ms warm, 4,017 ms cold in
production — is still unattributed, and cause 2 will persist after the
redeploy. Locating it requires the worker transport to capture the
header and return it alongside its result, mirroring what the main-thread
transport already does.

- [ ] Capture `Server-Timing` in the Email OTP worker's Yao transport and
      surface it through the worker result.

Note also that every `ecdsaRegistrationWarmSession*` bucket is 0 on those
production Email OTP runs, so the Shamir 3-pass seal path — the suspected cost in the local
613 ms window — is a **passkey** path. The Shamir prewarm therefore targets
passkey registration, not Email OTP. The Email OTP Yao prewarm already exists
and works: `emailOtpYaoPrewarm` reports 107 ms with 105 ms of WASM init.

`yaoAdmissionMs` (admission-receipt parse and scope validation) and
`yaoClientSessionCreateMs` (WASM registration-session construction) are
measured inside `yaoClient.ts` and returned on the success result, then
recorded at the same join point.
- [ ] Add Gateway spans around each registration D1 claim and terminal CAS.
- [ ] Add Router spans around the ECDSA replay/lifecycle transaction, parallel
      Deriver work, SigningWorker activation, and session/budget provisioning.
- [x] Keep the existing opaque trace correlation value across every new span.
      The Yao execute request still carries `ROUTER_AB_TRACE_ID_HEADER_V1`
      unchanged, and every new timing value rides the response of that same
      traced request.
- [x] Verify trace fields contain no wallet ID, email, credential ID, session
      secret, ciphertext, root-share identifier, or other identifying data.
      Audited 2026-07-28: the Gateway composes fixed metric names with
      `dur=<number.toFixed(1)>` only
      (`routerAbEd25519YaoRegistrationRequestScopedCloudflare.ts:509-524`);
      the Router formats four fixed names with numeric durations
      (`router_coordinator.rs:54-58`); the client parses only `dur=` values
      into buckets typed `number`, ignores unknown names, and never logs or
      emits the raw header string — it is held transiently on internal result
      types and consumed by the parser.
- [ ] Produce one local trace and one staging trace whose child intervals
      account for each ECDSA and Yao branch.

Acceptance:

- one trace identifies every serialized remote or durable boundary;
- timing code does not alter route bodies, ordering, retries, or lifecycle
  decisions;
- timing-summary type fixtures reject missing required branch timings.

## Phase 2: Collapse Strict ECDSA Registration Persistence

### Phase 2A: Gateway ceremony claims

- [x] Add a registration-specific D1 operation that atomically loads and claims
      the ECDSA `respond` step.
- [x] Return one of these typed states:
  - [x] `claimed` with the exact Router request;
  - [x] `completed` with the exact stored pending activation;
  - [x] `conflict`;
  - [x] `terminal_failure`.
- [x] Persist the pending activation with one terminal CAS after the Router
      returns.
- [x] Add the equivalent atomic claim and terminal CAS for the ECDSA
      `activate` step.
- [x] Preserve reconciliation after an uncertain Router or D1 result.
- [x] Delete separate read/update helpers that exist only for the replaced
      registration path.

### Phase 2B: Router replay and lifecycle

- [x] Define one strict ECDSA registration lifecycle Durable Object operation
      that atomically:
  - [x] reserves the replay identity;
  - [x] records the exact canonical request digest;
  - [x] persists the gate-applied lifecycle state in the same transaction;
  - [x] rejects conflicting replay identities.
- [x] Replace the replay reservation plus two serialized lifecycle writes with
      this one operation.
- [x] Persist the exact pending activation for completed-registration replay.
- [x] Keep Deriver A and Deriver B proof generation concurrent.
- [x] Delete the registration use of the old replay-reserve and lifecycle-put
      command chain.

Acceptance:

- ECDSA registration uses one Router lifecycle Durable Object request before
  parallel Deriver execution;
- concurrent identical requests converge to one pending activation;
- concurrent conflicting requests produce one typed conflict;
- a crash after Deriver execution returns the exact stored result or an
  explicit uncertain state without rerunning Deriver work.

## Phase 3: Make ECDSA Activation Atomic

- [x] Replace normal-signing provisioning's session read, budget write, session
      write, and budget read-back with one atomic provisioning operation.
- [x] Make the atomic input bind:
  - [x] wallet authority;
  - [x] ECDSA signing key slot;
  - [x] threshold session;
  - [x] signing grant;
  - [x] signing root epoch;
  - [x] exact participant pair;
  - [x] expiry and remaining-use policy.
- [x] Make exact replay return the same session and budget status without
      replenishing consumed session uses.
- [x] Make authority mismatch return a typed conflict.
- [x] Complete SigningWorker activation and session/budget provisioning through
      one Router activation execution path.
- [x] Persist Gateway terminal activation only after both durable operations
      succeed.
- [x] Add reconciliation for a response lost after durable activation.
- [x] Delete the four-operation Cloudflare production provisioning path and
      its read-back assertion. Non-Cloudflare stores retain their own backend
      implementation.

Acceptance:

- activation uses one Gateway-to-Router request;
- normal-signing authority and budget become durable atomically;
- a lost activation response resumes without repeating activation;
- the browser proof-verification boundary remains mandatory.

## Phase 4: Remove The Separate Yao Admission Route

- [x] Extend wallet registration start to issue the complete typed Yao
      admission receipt in the same wallet-start execution.
- [x] Bind the verified registration intent and persist the admitted Yao
      session with one atomic partitioned-product-state commit.
- [x] Bind the receipt to the exact registration intent, application binding,
      role pair, circuit, operation, root epoch, expiry, and authorization
      digest.
- [x] Pass the receipt directly into the browser Yao worker.
- [x] Start the local Yao client session from that receipt.
- [x] Remove the browser admission fetch.
- [x] Remove wallet registration from the admission HTTP path. The endpoint
      remains the current add-signer admission boundary and is therefore not
      legacy registration code.
- [x] Delete the request-scoped product runtime's registration-only standalone
      admission persistence path.
- [x] Keep recovery and export route contracts unchanged.

Acceptance:

- wallet registration sends no standalone Yao admission request;
- wallet start and Yao execution cannot disagree about lifecycle scope;
- client factor material remains one-use and zeroized on every terminal path;
- response and type fixtures reject a start response without its required Yao
  receipt when the Ed25519 signer branch is enabled.

## Phase 5: Reduce Yao D1 Persistence To Claim And Terminal CAS

- [x] Introduce a registration-execution record containing only the exact
      admitted authority, request digest, execution claim, version, expiry,
      terminal sealed result, and finalization-consumer binding.
- [x] Atomically claim an unclaimed execution with one D1 batch.
- [x] Return an exact stored result for a completed execution.
- [x] Reject a conflicting digest before the Router call.
- [x] Invoke the Router exactly once after a successful claim.
- [x] Commit completion with one terminal CAS using the claimed version.
- [x] Reconcile an uncertain Router response before deciding whether the
      execution is burned or completed.
- [x] Remove the terminal reload from the registration execution path.
- [x] Remove shared tenant-state reads and writes from the registration
      execution hot path.
- [x] Delete registration execution use of the generic
      load/claim/reload/commit runner. The same route module still uses the
      runner for add-signer admission, whose contract remains in scope.

Acceptance:

- Yao registration execution performs at most two D1 roundtrips on the
  successful path;
- terminal persistence does not depend on mutable `Map` or object aliasing;
- identical concurrency converges;
- conflicting concurrency fails before Router execution;
- exact completed output remains redeliverable.

## Phase 6: Fuse Role-Local Yao Commands

- [x] Combine Deriver B's `ReadPairPrepared` and `BeginPair` commands into one
      atomic session Durable Object command executed by the WebSocket handler.
- [x] Combine Deriver A's execution claim and `StartPair` transition into one
      atomic session Durable Object command.
- [x] Keep network and Yao execution outside each Durable Object transaction.
- [x] Make the final B-to-A protocol envelope carry B's sealed completion
      bytes as an opaque forward-only field.
- [x] Bind that sealed completion to the exact pair digest and protocol
      transcript.
- [x] Have Deriver A forward the sealed bytes unchanged in its Router response.
- [x] Validate the B completion in the Router.
- [x] Delete the Router-to-Deriver-B completed-result read.
- [x] Delete the B completed-read route, adapter, command, and tests that exist
      only for that route.
- [x] Collapse duplicate execution-time root metadata reads while retaining one
      execution-time role-secret load and exact root-epoch validation.

Acceptance:

- B preparation-to-running is one Durable Object transaction;
- A prepared-to-running is one Durable Object transaction;
- Router execution returns both sealed role results without a second B request;
- A cannot parse or decrypt B's sealed completion;
- each role still owns its one-use and exact-redelivery state;
- root shares remain role-local.

## Phase 7: Product-Topology Validation And Cleanup

- [x] Run focused ECDSA registration lifecycle tests.
- [x] Run focused Yao role-lifecycle and Router coordinator tests.
- [x] Run D1 claim, CAS, concurrency, rollback, and reconciliation tests
      against real local D1.
- [x] Run Rust vector and anti-drift tests for every touched protocol type.
- [x] Run affected TypeScript type fixtures.
- [ ] Run `pnpm test:intended` for registration lifecycle behavior.
- [x] Run the release-mode local product-topology benchmark. The post-change
      100-sample release run measured 88.954 ms p50, 93.989 ms p95, and
      96.647 ms p99 for the connected local Yao registration topology.
- [ ] Confirm one Email OTP and one passkey registration complete locally.
- [ ] Confirm one Email OTP and one passkey registration complete in staging.
- [ ] Verify the frontend timing summary reports:
  - [ ] ECDSA branch at or below 2.0 seconds;
  - [ ] Yao branch at or below 1.5 seconds;
  - [ ] wallet-ready wall time between 2 and 3 seconds under typical
        conditions.
- [ ] Run `pnpm check`.
- [x] Run `git diff --check`.
- [x] Delete obsolete routes, bindings, Durable Object commands, fixtures,
      mocks, source guards, environment variables, and documentation.
- [x] Confirm no runtime selector or legacy registration path remains.

Focused validation on July 27 completed 58 registration lifecycle tests with
two environment-gated store variants skipped, four real-local-D1 persistence
and concurrency tests, the affected SDK Server, SDK Web, and unit-workspace
typechecks, and `git diff --check`. The real-D1 concurrency test verifies one
Router effect under identical contention. `pnpm check` remains open because
the current workspace has unrelated Console package/export drift. The
source-guard build also remains environment-gated after its WASM dependency
download was denied; the generated release client package was restored and
all affected typechecks passed afterward.

Acceptance:

- local and staging manually exercise the same registration graph intended for
  production;
- the product-topology benchmark reports at least one real sample and fails
  when its selected test is absent;
- all exact-once, replay, crash-convergence, and role-separation tests pass;
- typical registration reaches wallet-ready state in 2–3 seconds.

## Phase 8: Conditional Router Coordinator Decision

This phase is entered only when Phase 7 shows Yao above 1.5 seconds and the
remaining time is dominated by role lifecycle Durable Object boundaries.

- [ ] Record the remaining role transition timings from one focused trace.
- [ ] Compare the existing role-local authority model with a single
      per-ceremony Router coordinator Durable Object that owns public lifecycle
      state and sealed outputs.
- [ ] Prove that root shares, role plaintext, and recipient plaintext remain
      outside coordinator storage and memory.
- [ ] Define one coordinator claim, one connected A/B execution, and one
      terminal coordinator commit.
- [ ] Update Refactor 93's `No Ceremony-Wide Ledger In V1` decision before
      implementation.
- [ ] Delete replaced role session Durable Objects if the coordinator becomes
      the sole lifecycle authority.

Acceptance:

- this phase adds no third duplicate lifecycle authority;
- any coordinator replacement removes more Durable Object transitions than it
  adds;
- role-secret custody and one-use execution remain independently enforced.

## Concurrency And Dependencies

After Phase 1 establishes stable timing boundaries:

- Phases 2 and 3 form the ECDSA lane and are sequential.
- Phases 4 and 5 form the Gateway Yao lane and are sequential.
- Phase 6 can proceed alongside the Gateway Yao lane after its receipt and
  execution contracts are frozen.
- ECDSA and Yao lanes can run concurrently in separate worktrees.
- Phase 7 depends on both lanes.
- Phase 8 depends on Phase 7 missing the Yao target for a demonstrated
  role-lifecycle reason.

```text
Phase 0 -> Phase 1
              ├─> Phase 2 -> Phase 3 ─┐
              └─> Phase 4 -> Phase 5 ─┼─> Phase 7 -> conditional Phase 8
                       └─> Phase 6 ────┘
```

## Expected Code Areas

Browser and worker:

- `packages/sdk-web/src/SeamsWeb/operations/registration/registration.ts`
- `packages/sdk-web/src/core/signingEngine/threshold/ed25519/yaoClient.ts`
- Email OTP and passkey signer worker registration adapters

Gateway and D1:

- `packages/sdk-server-ts/src/router/cloudflare/d1WalletRegistrationService.ts`
- `packages/sdk-server-ts/src/router/routerAbEcdsaStrictRegistration.ts`
- `packages/sdk-server-ts/src/router/routerAbEd25519YaoRegistrationRequestScopedCloudflare.ts`
- `packages/sdk-server-ts/src/router/routerAbEd25519YaoRegistrationTwoPhaseRunner.ts`
- `packages/sdk-server-ts/src/router/routerAbEd25519YaoProductRegistrationPartitionedStateStore.ts`
- `packages/sdk-server-ts/src/core/routerAbSigning/RouterAbNormalSigningRuntime.ts`

Router and roles:

- `crates/router-ab-cloudflare/src/lib.rs`
- `crates/router-ab-cloudflare/src/router_coordinator.rs`
- `crates/router-ab-cloudflare/src/ed25519_yao_lifecycle.rs`
- strict Router, Deriver A, Deriver B, and SigningWorker entrypoints

Local parity:

- `crates/router-ab-dev/scripts/measure-ed25519-yao-local.mjs`
- `crates/router-ab-dev/tests/local_worker_http.rs`

Tests:

- focused tests in `crates/router-ab-cloudflare/tests/`
- focused tests in `crates/router-ab-dev/tests/`
- intended-behavior, unit, and type fixtures in `tests/`

## Test Classification Rules

Before changing a failing test, apply the repository authority map:

- lifecycle behavior contracts own supported registration behavior;
- Rust vectors and type fixtures own cryptographic, wire, and invalid-state
  constraints;
- focused unit tests own current persistence and concurrency semantics;
- inline legacy fixtures and source-text guards have the highest staleness
  risk.

Classify each failure as `production_regression`, `valid_test_needs_update`,
`obsolete_test_or_fixture`, or `environment_or_infrastructure_failure`.
Delete tests and fixtures that protect the replaced registration graph. Do not
retain an obsolete route, state, command, field, or compatibility path to keep
such a test green.

## Completion Criteria

Refactor 94 is complete when:

1. typical Email OTP and passkey registration reaches wallet-ready state in
   2–3 seconds after user confirmation;
2. ECDSA no longer performs three serialized replay/lifecycle Durable Object
   calls;
3. ECDSA session and budget provisioning is one atomic operation;
4. wallet registration sends no separate Yao admission request;
5. successful Yao execution performs at most one D1 claim and one terminal
   D1 CAS;
6. Router obtains B's sealed completion through the connected execution path;
7. the separate B completed-result route is deleted;
8. exact replay, concurrency, uncertainty, crash convergence, and role-secret
   separation remain verified;
9. the release-mode product-topology benchmark exercises real samples;
10. no legacy registration route, runtime selector, or compatibility branch
    remains.
