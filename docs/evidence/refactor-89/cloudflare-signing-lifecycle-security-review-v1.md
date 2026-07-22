# Cloudflare signing lifecycle security review v1

Date: July 17, 2026

Status: **PARTIALLY REMEDIATED — INDEPENDENT DELTA REVIEW PENDING**

Decision scope: the newer Cloudflare SigningWorker ECDSA pool lifecycle,
Durable Object mutation boundary, prepare/finalize output ordering, resolved
production dependency graph, and the live same-account Ed25519 Yao lifecycle
and WebSocket adapter.

Cross-account status correction: the fixed binary WebSocket transport is
implemented in `crates/ed25519-yao-cloudflare-bench` and was deployed and
tested across independently administered Cloudflare accounts. The scoped
production adapter does not promote that transport into runtime negotiation.
This distinction is integration status, not implementation status.

This is a bounded spec-to-code compliance review. It supplements the
construction review in
[`docs/security/router-ab-ecdsa-phase4-review.md`](../../security/router-ab-ecdsa-phase4-review.md).
It does not reopen the approved fixed 2-of-2 equations, OT/MTA proof system,
Client IndexedDB implementation, or oracle corpus.

The machine-readable corpus receipt is
[`cloudflare-signing-lifecycle-manifest-v1.json`](./cloudflare-signing-lifecycle-manifest-v1.json),
SHA-256
`02fc9c95c49c3962f3700afb6439b836da4913b6d6b94f7b03ea8acb923b0791`.
Its 36-artifact corpus root is
`6fb71068f483fdfe1bf2acf5af0351a9e50f174c2c13ca5861a2003c6f35fe5a`.

## July 17, 2026 remediation checkpoint

The receipt and detailed review below describe the rejected pre-remediation
snapshot. The current tree implements the agreed compact lifecycle delta:

- `CF-LC-001` is closed in code. `Reserved -> Consumed` is one Durable Object
  mutation. Its persisted revision-2 record contains no secret material, while
  the mutation response returns the request-bound presignature exactly once.
  `Committed`, `FinishCommitted`, `Succeeded`, and ambiguous committed
  recovery have been deleted.
- `CF-LC-002` is partially closed. Every fallible prepare exit after
  reservation issues an exact-revision destructive mutation. Available and
  reserved records expose material/lease cleanup deadlines, and the
  SigningWorker server-output Durable Object schedules an idempotent alarm
  that replaces expired records with material-free tombstones. Exact key and
  activation retirement mutations exist. The activation-retirement owner
  still needs to enumerate and invoke those mutations when an epoch retires.
- `CF-LC-005` is closed in code. The adapter derives the lease as
  `min(request expiry, material expiry, checked(now + 60 seconds))`; callers
  cannot provide a longer lease.
- `CF-LC-004` is partially closed. Yao Deriver sessions now use one
  `Staged | Running | Completed | Failed | Expired` record. Entering `Running`
  removes staged ciphertext, execution failures are terminal, result reads
  surface failure/expiry without polling, and terminal sessions cannot
  reevaluate. Expiry is checked lazily on every session operation to avoid a
  successful-path alarm write. Restore-safe generation authority remains open.
- `CF-LC-003` remains open. This delta does not add a non-restorable generation
  floor for point-in-time restore.
- `CF-LC-006` remains deferred as agreed. Yao SigningWorker scalar
  deduplication is the next separate lifecycle change.

Focused evidence added by the delta:

- ten `router-ab-ecdsa-pool` unit tests and two compile-fail lifecycle tests;
- five Cloudflare ECDSA lifecycle tests covering exact consume, substituted
  burn, the lease cap and checked arithmetic, expiry, retirement, and stale
  compare-and-swap;
- a Durable Object test proving the consume response returns material while
  persisted state is material-free;
- eight ECDSA source-boundary tests proving consume precedes later fallible
  finalize work and every post-reservation prepare failure reaches destructive
  cleanup;
- three Yao lifecycle unit tests and three source-boundary tests covering
  secret-free terminal records, checked expiry, fixed input binding,
  setup-before-begin ordering, and immediate terminal result handling; and
- successful `workers-rs` library tests and Worker-feature compilation.

This checkpoint is implementation evidence. It does not replace the required
independent delta review or claim closure of the restore and scalar-ownership
findings.

---

## 1. Executive summary

The normal success path has the correct safety ordering:

1. Durable Object state advances from reserved revision 1 to committed revision
   2 before the online kernel can read SigningWorker presignature material.
2. The signature is held in memory.
3. Revision 2 is replaced by a material-free terminal tombstone at revision 3.
4. The HTTP response is serialized only after the terminal mutation succeeds.

Exact scope and pair identity, monotonic revisions, request-digest binding,
stale-CAS rejection, terminal material removal, private route authentication,
and the absence of the generic threshold-ECDSA backend are all implemented.
Cloudflare's documented input and output gates make the Durable Object
read-reduce-write sequence serializable and withhold its response until the
write completes.

The lifecycle is not ready for approval. Six open findings remain:

- `CF-LC-001` high: committed secret material stays durably serialized until a
  second mutation. `RecoverInterrupted` exists only as a reducer command and
  has no production invocation or enumeration path. A Worker termination
  between commit and finish therefore retains committed material indefinitely.
- `CF-LC-002` medium: prepare has fallible exits after reservation, and the
  adapter has no available-record expiry or epoch-retirement command. These
  paths leave material reserved or available instead of recording the required
  terminal reason.
- `CF-LC-003` medium: the SQLite Durable Object is restore-capable. The code
  has no independently authoritative monotonic generation that prevents a
  point-in-time restore from reviving a pre-tombstone record.
- `CF-LC-004` high for production promotion: the Ed25519 Yao Cloudflare
  lifecycle now claims each A/B session exactly once by durably moving it to
  `Running` before evaluation, and it redelivers the exact completed
  ciphertext. It has no `Failed`, `Expired`, or tombstone state, no recovery
  from `Running`, and no rollback-generation floor. Point-in-time restore can
  revive a pre-claim session, while a crash after claim strands it forever.
- `CF-LC-005` medium: prepare copies the authenticated request expiry directly
  into both request and reservation expiry. It does not enforce the specified
  `min(request expiry, material expiry, now + 60 seconds)` lease cap.
- `CF-LC-006` medium: the new Ed25519 activation lifecycle durably duplicates
  the plaintext SigningWorker scalar in its orchestration Durable Object and
  server-output Durable Object. Pending packages, staged recovery candidates,
  prior output records, and active material have no expiry or cleanup path.

No path was found that releases two signatures from one record through the
typed API or normal Durable Object handler. The present findings concern
  unbounded secret retention, missing destructive recovery, restore-based
  revival, and incomplete Yao failure/retention persistence. Formal Refactor
  89 closure remains blocked.

An independent cryptographic-review agent reviewed the ECDSA implementation
boundary and an intermediate same-turn Yao snapshot, returning `REJECTED` with
confidence `0.99`. It independently confirmed exact identity binding, forward
revisions, commit-before-access, and tombstone-before-output. It classified
unreachable recovery, fallible post-reservation exits, missing
expiry/retirement integration, the missing lease cap, and absent adapter fault
evidence as production-promotion blockers. It also confirmed same-account Yao
internal-service authentication. The primary review reconciled the later
`Running` claim and SigningWorker activation delta pinned by this receipt.

The sealed snapshot passes all 333 `router-ab-cloudflare` tests, all nine
`router-ab-ecdsa-pool` tests, the Deriver A, Deriver B, and SigningWorker
`wasm32-unknown-unknown` entrypoint checks, and both client/dependency boundary
guards. These are local source/native/Wasm checks. This review did not rerun
deployed Worker crash, concurrency, alarm, point-in-time restore, or
cross-account tests. The deployment record separately reports a successful
30-ceremony cross-account WebSocket campaign.

---

## 2. Documentation sources identified

| Source | Normative use |
| --- | --- |
| `crates/router-ab-ecdsa-pool/specs/persistent-pool-lifecycle-v1.md:14-65,80-89` | Exact identity, state machine, CAS, terminal policy, destructive recovery, and adapter invariants |
| `crates/router-ab-ecdsa-online/specs/online-lifecycle-v1.md:20-42,60-70,94-108` | One-use kernel, public coin, durable terminal consumption, substitution rejection |
| `crates/router-ab-ecdsa-presign/specs/assurance-ledger-v1.md:143-153,181-208` | One-use composition and assumption boundary |
| `docs/refactor-89-slimmer-near-ecdsa.md:698-776,876-895` | Product security invariants, secret hygiene, rollback, and footguns |
| `docs/router-ab/ed25519-yao/implementation-plan.md:1013-1092,1501-1592` | Fixed authenticated framing, role-bound sessions, topology-independent protocol, and cross-account authentication |
| `docs/router-ab/ed25519-yao/deployment.md:159-224,252-265,296-310` | Same-account selection, implemented cross-account WebSocket deployment, measured campaign, and remaining promotion evidence |
| Cloudflare Durable Objects documentation | Strong consistency, serializable private storage, input gates, output gates, and restore/PITR platform assumptions |

Cloudflare platform assumptions used by this review:

- [Durable Object storage is private, transactional, and strongly consistent](https://developers.cloudflare.com/durable-objects/best-practices/access-durable-objects-storage/).
- [Input and output gates protect storage operations and pending writes](https://developers.cloudflare.com/durable-objects/best-practices/rules-of-durable-objects/).
- [The Storage API is serializable](https://developers.cloudflare.com/durable-objects/reference/glossary/).

---

## 3. Spec intent breakdown (Spec-IR)

```yaml
spec_ir:
  - id: CF-SPEC-001
    spec_excerpt: "Each record binds exactly: wallet, account, signing scope, presignature pair, role, key epoch, activation epoch, protocol identifier, and one sealed-material locator."
    source_section: "Scope, lines 14-23"
    source_document: "crates/router-ab-ecdsa-pool/specs/persistent-pool-lifecycle-v1.md"
    semantic_type: "security_identity_invariant"
    normalized_form: "A pool record and every mutation MUST identify one complete authenticated role-local pair; substitution MUST NOT select another record."
    confidence: 1.0
  - id: CF-SPEC-002
    spec_excerpt: "available@revision_0 -> reserved@revision_1 -> committed-use@revision_2 -> tombstone@revision_3"
    source_section: "State machine, lines 25-36"
    source_document: "crates/router-ab-ecdsa-pool/specs/persistent-pool-lifecycle-v1.md"
    semantic_type: "state_machine"
    normalized_form: "State and revision move forward exactly once; Tombstone is absorbing."
    confidence: 1.0
  - id: CF-SPEC-003
    spec_excerpt: "compare the complete key and expected revision; store exactly the replacement record; delete the sealed material in the same transaction"
    source_section: "State machine, lines 38-46"
    source_document: "crates/router-ab-ecdsa-pool/specs/persistent-pool-lifecycle-v1.md"
    semantic_type: "atomicity_requirement"
    normalized_form: "Each transition MUST be one exact-key/exact-revision atomic replacement; terminal replacement MUST remove secret material."
    confidence: 1.0
  - id: CF-SPEC-004
    spec_excerpt: "Success, validation rejection, binding substitution, timeout, cancellation, crash recovery, peer abort, ambiguous delivery, persistence failure, material expiry, and epoch retirement all end in a permanent tombstone."
    source_section: "Terminal policy, lines 53-59"
    source_document: "crates/router-ab-ecdsa-pool/specs/persistent-pool-lifecycle-v1.md"
    semantic_type: "failure_policy"
    normalized_form: "Every used, failed, expired, retired, or uncertain record MUST become terminal."
    confidence: 1.0
  - id: CF-SPEC-005
    spec_excerpt: "an interrupted reservation becomes CrashRecovery; an interrupted committed use becomes AmbiguousDelivery"
    source_section: "Terminal policy, lines 61-65"
    source_document: "crates/router-ab-ecdsa-pool/specs/persistent-pool-lifecycle-v1.md"
    semantic_type: "crash_recovery"
    normalized_form: "Startup or enumerated recovery MUST destructively classify every interrupted Reserved and Committed record."
    confidence: 1.0
  - id: CF-SPEC-006
    spec_excerpt: "destructive recovery after process termination at every transition edge"
    source_section: "Adapter invariants, lines 80-89"
    source_document: "crates/router-ab-ecdsa-pool/specs/persistent-pool-lifecycle-v1.md"
    semantic_type: "adapter_obligation"
    normalized_form: "The concrete Cloudflare adapter MUST provide executable recovery, rather than only a domain transition."
    confidence: 1.0
  - id: CF-SPEC-007
    spec_excerpt: "A committed record must be tombstoned before an online output crosses the process boundary."
    source_section: "Terminal policy, lines 57-59"
    source_document: "crates/router-ab-ecdsa-pool/specs/persistent-pool-lifecycle-v1.md"
    semantic_type: "output_release"
    normalized_form: "A final signature MUST remain withheld until the terminal material-free replacement is durable."
    confidence: 1.0
  - id: CF-SPEC-008
    spec_excerpt: "Prepare binds client_commitment32 into the reservation digest ... Mismatch, timeout, abort, and ambiguous delivery are terminal burns."
    source_section: "Two-role rerandomization coin, lines 44-70"
    source_document: "crates/router-ab-ecdsa-online/specs/online-lifecycle-v1.md"
    semantic_type: "cryptographic_binding"
    normalized_form: "The committed request digest MUST bind the Client opening and persisted SigningWorker contribution before presign material is exposed."
    confidence: 0.99
  - id: CF-SPEC-009
    spec_excerpt: "atomic transition from available to reserved before either party starts"
    source_section: "Security boundary, lines 94-108"
    source_document: "crates/router-ab-ecdsa-online/specs/online-lifecycle-v1.md"
    semantic_type: "material_access"
    normalized_form: "Reserved material MUST be read only from a successfully persisted Reserved outcome; committed material MUST be read only from a persisted Committed outcome."
    confidence: 1.0
  - id: CF-SPEC-010
    spec_excerpt: "Persistence, backup, retry, and crash recovery cannot move a committed, destroyed, expired, aborted, or consumed presignature into an available state."
    source_section: "Security and Lifecycle Invariants, invariant 20, lines 766-768"
    source_document: "docs/refactor-89-slimmer-near-ecdsa.md"
    semantic_type: "rollback_protection"
    normalized_form: "Restore and rollback MUST be dominated by an authority outside the restorable record generation."
    confidence: 1.0
  - id: CF-SPEC-011
    spec_excerpt: "Secret values remain outside logs, errors, metrics, filenames, cache keys, and diagnostic payloads."
    source_section: "Security and Lifecycle Invariants, invariant 9, lines 726-727"
    source_document: "docs/refactor-89-slimmer-near-ecdsa.md"
    semantic_type: "secret_hygiene"
    normalized_form: "Secret scalar and presignature bytes MUST NOT enter logs, errors, storage keys, or public receipts."
    confidence: 1.0
  - id: CF-SPEC-012
    spec_excerpt: "Secret-bearing Rust types do not implement Clone, Copy, Debug, or general-purpose serialization unless a reviewed operation requires it."
    source_section: "Security and Lifecycle Invariants, invariant 21, lines 769-772"
    source_document: "docs/refactor-89-slimmer-near-ecdsa.md"
    semantic_type: "secret_type_surface"
    normalized_form: "Every Clone, Debug, and Serialize implementation on secret-bearing lifecycle types MUST have a specific persistence or transport justification and a no-log boundary."
    confidence: 1.0
  - id: CF-SPEC-013
    spec_excerpt: "Client and SigningWorker are the only threshold-ECDSA signing parties."
    source_section: "Security and Lifecycle Invariants, invariants 2-5, lines 704-711"
    source_document: "docs/refactor-89-slimmer-near-ecdsa.md"
    semantic_type: "role_and_access_control"
    normalized_form: "Normal ECDSA signing MUST remain Deriver-free and the internal SigningWorker route MUST authenticate before parsing."
    confidence: 1.0
  - id: CF-SPEC-014
    spec_excerpt: "Production dependency graphs contain no threshold-signatures package."
    source_section: "Goals, lines 676-679"
    source_document: "docs/refactor-89-slimmer-near-ecdsa.md"
    semantic_type: "dependency_boundary"
    normalized_form: "The Cloudflare production normal dependency closure MUST exclude the deleted generic threshold-ECDSA backend."
    confidence: 1.0
  - id: CF-SPEC-015
    spec_excerpt: "session authentication derived from a signed ephemeral peer handshake; a session MAC over the canonical frame header, previous-frame digest, and payload"
    source_section: "Streaming transport, lines 1070-1092"
    source_document: "docs/router-ab/ed25519-yao/implementation-plan.md"
    semantic_type: "transport_authentication"
    normalized_form: "A Yao transport session MUST authenticate both peer role and Router-admitted session, bind transcript order, and reject replay."
    confidence: 0.99
  - id: CF-SPEC-016
    spec_excerpt: "Service Bindings cannot cross Cloudflare accounts. Production uses direct authenticated HTTPS on pinned Custom Domains."
    source_section: "Cross-account Cloudflare, lines 1568-1592"
    source_document: "docs/router-ab/ed25519-yao/implementation-plan.md"
    semantic_type: "deployment_topology"
    normalized_form: "Same-account Service Binding is a distinct weaker topology; separate-account deployment requires a different authenticated connector without changing protocol identity."
    confidence: 1.0
  - id: CF-SPEC-017
    spec_excerpt: "Reservation expiry is min(request expiry, material expiry, now plus 60 seconds)."
    source_section: "Frozen 80/20 Pool Policy"
    source_document: "docs/refactor-89-slimmer-near-ecdsa.md"
    semantic_type: "resource_and_secret_retention_bound"
    normalized_form: "The SigningWorker MUST cap every reservation lease independently of the caller-supplied request expiry."
    confidence: 1.0
  - id: CF-SPEC-018
    spec_excerpt: "Implement the minimum durable lifecycle required for one-use execution, rollback safety, crash recovery, and exact ciphertext redelivery without reevaluation."
    source_section: "Phase 11: production hardening"
    source_document: "docs/router-ab/ed25519-yao/deployment.md"
    semantic_type: "yao_one_use_lifecycle"
    normalized_form: "A staged Yao role MUST be atomically consumed before evaluation, duplicate or restored sessions MUST NOT reevaluate, terminal ciphertext MAY be redelivered exactly, and failures MUST become durable terminal states."
    confidence: 1.0
  - id: CF-SPEC-019
    spec_excerpt: "The SigningWorker rejects activation-package replay after activation ... recovery accepts only the same stable key identity, promotion tombstones the retired credential, and ordinary signing succeeds under the replacement lifecycle."
    source_section: "Phase 9 implementation evidence, lines 4133-4146"
    source_document: "docs/router-ab/ed25519-yao/implementation-plan.md"
    semantic_type: "signing_worker_activation_lifecycle"
    normalized_form: "SigningWorker activation MUST combine one exact A/B package pair, preserve stable identity and public-key continuity, expose material only after activation, reject replay, and terminally retire superseded or failed material."
    confidence: 1.0
```

---

## 4. Code behavior summary (Code-IR)

The following records cover every function in the new lifecycle module, every
Cloudflare function on its live call chain, and every function in the new
WebSocket module. Repeated validation helpers are listed separately where their
failure semantics differ.

```yaml
code_ir:
  - id: CF-CODE-001
    file: "crates/router-ab-cloudflare/src/ecdsa_pool_lifecycle.rs"
    function: "CloudflareSigningWorkerEcdsaPoolCommandV1::validate"
    lines: "163-221"
    visibility: "public"
    modifiers: ["typed enum match"]
    behavior:
      preconditions: ["scope and pair validate at lines 176-179, 193-218", "timestamps are positive at lines 177-179, 194, 209, 218"]
      state_reads: ["command variant fields at lines 166-219"]
      state_writes: []
      computations: ["rejects Succeeded on DestroyReserved at lines 203-208"]
      external_calls: []
      events: []
      postconditions: ["well-shaped command or typed error"]
    invariants_enforced: ["known command variant", "positive time", "reserved cannot succeed"]
  - id: CF-CODE-002
    file: "crates/router-ab-cloudflare/src/ecdsa_pool_lifecycle.rs"
    function: "CloudflareSigningWorkerEcdsaPoolCommandV1::scope"
    lines: "223-233"
    visibility: "public"
    modifiers: ["const"]
    behavior:
      preconditions: ["constructed enum"]
      state_reads: ["material scope or explicit scope at lines 225-231"]
      state_writes: []
      computations: ["selects identity source by variant"]
      external_calls: []
      events: []
      postconditions: ["returns the scope used by Durable Object keying"]
    invariants_enforced: ["all variants have a scope", "PutAvailable uses material authority", "no fallback scope"]
  - id: CF-CODE-003
    file: "crates/router-ab-cloudflare/src/ecdsa_pool_lifecycle.rs"
    function: "CloudflareSigningWorkerEcdsaPoolCommandV1::server_presignature_id"
    lines: "235-260"
    visibility: "public"
    modifiers: []
    behavior:
      preconditions: ["constructed enum"]
      state_reads: ["material or explicit pair id at lines 237-258"]
      state_writes: []
      computations: ["selects pair identity by variant"]
      external_calls: []
      events: []
      postconditions: ["returns the pair id used by Durable Object keying"]
    invariants_enforced: ["all variants have a pair id", "PutAvailable uses material authority", "no generated alias"]
  - id: CF-CODE-004
    file: "crates/router-ab-cloudflare/src/ecdsa_pool_lifecycle.rs"
    function: "CloudflareSigningWorkerEcdsaPoolMutationOutcomeV1::validate"
    lines: "296-314"
    visibility: "public"
    modifiers: []
    behavior:
      preconditions: ["outcome carries a record"]
      state_reads: ["record lifecycle at lines 299-306"]
      state_writes: []
      computations: ["matches outcome tag to persisted lifecycle"]
      external_calls: []
      events: []
      postconditions: ["mismatched response tag rejects"]
    invariants_enforced: ["Available/Reserved/Committed tags match states", "Burned/Finished are Tombstone", "record validates first"]
  - id: CF-CODE-005
    file: "crates/router-ab-cloudflare/src/ecdsa_pool_lifecycle.rs"
    function: "CloudflareSigningWorkerEcdsaPoolMutationOutcomeV1::record"
    lines: "316-325"
    visibility: "public"
    modifiers: ["const"]
    behavior:
      preconditions: ["constructed outcome"]
      state_reads: ["record in every branch at lines 318-323"]
      state_writes: []
      computations: ["projects replacement record"]
      external_calls: []
      events: []
      postconditions: ["one replacement reference"]
    invariants_enforced: ["all outcomes replace one record", "no optional replacement", "no alternate key"]
  - id: CF-CODE-006
    file: "crates/router-ab-cloudflare/src/ecdsa_pool_lifecycle.rs"
    function: "apply_cloudflare_signing_worker_ecdsa_pool_command_v1"
    lines: "328-460"
    visibility: "public"
    modifiers: []
    behavior:
      preconditions: ["command validates at line 333", "non-Put commands require current at lines 367, 391, 415, 433, 449"]
      state_reads: ["current record", "expected scope/pair/revision at lines 368-373, 392-397, 416-421, 434-439, 450-455"]
      state_writes: ["returns a complete replacement outcome; persistence occurs in the adapter"]
      computations: ["idempotent exact Put at lines 338-353", "reserve at lines 356-382", "commit/burn at lines 384-405", "destroy/finish/recover at lines 407-457"]
      external_calls: []
      events: []
      postconditions: ["one validated replacement or no mutation error"]
    invariants_enforced: ["exact current identity", "exact revision", "forward transition", "different same-key Put rejects"]
  - id: CF-CODE-007
    file: "crates/router-ab-cloudflare/src/ecdsa_pool_lifecycle.rs"
    function: "CloudflareSigningWorkerEcdsaPoolLifecycleRecordV1::new_available"
    lines: "462-490"
    visibility: "public"
    modifiers: []
    behavior:
      preconditions: ["material and active scope validate at lines 467-470"]
      state_reads: ["scope, pair id, creation and expiry"]
      state_writes: ["constructs revision-0 Available and material state at lines 479-487"]
      computations: ["full pool key and material locator digests at lines 470-480"]
      external_calls: []
      events: []
      postconditions: ["validated Available record"]
    invariants_enforced: ["full scope", "fixed protocol", "material locator binding"]
  - id: CF-CODE-008
    file: "crates/router-ab-cloudflare/src/ecdsa_pool_lifecycle.rs"
    function: "CloudflareSigningWorkerEcdsaPoolLifecycleRecordV1::validate"
    lines: "493-546"
    visibility: "public"
    modifiers: []
    behavior:
      preconditions: ["record fields are present"]
      state_reads: ["scope, pair, lifecycle key, material variant"]
      state_writes: []
      computations: ["recomputes pool key at lines 493-503", "cross-validates every state/material pair at lines 504-545"]
      external_calls: []
      events: []
      postconditions: ["identity and lifecycle/material disagreement reject"]
    invariants_enforced: ["no state/material mismatch", "no pair drift", "no scope drift"]
  - id: CF-CODE-009
    file: "crates/router-ab-cloudflare/src/ecdsa_pool_lifecycle.rs"
    function: "CloudflareSigningWorkerEcdsaPoolLifecycleRecordV1::reserve"
    lines: "548-594"
    visibility: "public"
    modifiers: ["consumes self"]
    behavior:
      preconditions: ["record validates at line 559", "lifecycle is Available at lines 562-565", "material is Available at lines 567-572"]
      state_reads: ["scope, pair, material, request digest and time bounds"]
      state_writes: ["constructs revision-1 Reserved with request-bound material at lines 574-591"]
      computations: ["derives reservation binding at lines 560-561"]
      external_calls: []
      events: []
      postconditions: ["validated Reserved record or error with no replacement"]
    invariants_enforced: ["request binding", "one consuming transition", "material/state lockstep"]
  - id: CF-CODE-010
    file: "crates/router-ab-cloudflare/src/ecdsa_pool_lifecycle.rs"
    function: "CloudflareSigningWorkerEcdsaPoolLifecycleRecordV1::commit"
    lines: "596-646"
    visibility: "public"
    modifiers: ["consumes self"]
    behavior:
      preconditions: ["record validates", "state is Reserved"]
      state_reads: ["stored binding, request digest, lease and material expiry"]
      state_writes: ["returns revision-2 Committed with the same secret material at lines 619-625, or a material-free Tombstone at lines 632-642"]
      computations: ["binding/expiry/lease decision at lines 603-644"]
      external_calls: []
      events: []
      postconditions: ["Committed, Burned, or typed error"]
    invariants_enforced: ["mismatch and late use burn", "only Reserved commits", "Committed retains request binding"]
  - id: CF-CODE-011
    file: "crates/router-ab-cloudflare/src/ecdsa_pool_lifecycle.rs"
    function: "CloudflareSigningWorkerEcdsaPoolLifecycleRecordV1::destroy_reserved"
    lines: "648-672"
    visibility: "public"
    modifiers: ["consumes self"]
    behavior:
      preconditions: ["validated Reserved record"]
      state_reads: ["stored and attempted request bindings"]
      state_writes: ["returns a material-free tombstone"]
      computations: ["forces BindingRejected on substitution at lines 661-670"]
      external_calls: []
      events: []
      postconditions: ["terminal record"]
    invariants_enforced: ["reserved cannot revive", "substitution cannot choose reason", "material removed"]
  - id: CF-CODE-012
    file: "crates/router-ab-cloudflare/src/ecdsa_pool_lifecycle.rs"
    function: "CloudflareSigningWorkerEcdsaPoolLifecycleRecordV1::finish_committed"
    lines: "674-698"
    visibility: "public"
    modifiers: ["consumes self"]
    behavior:
      preconditions: ["validated Committed record"]
      state_reads: ["stored and attempted request bindings"]
      state_writes: ["returns a material-free tombstone"]
      computations: ["forces BindingRejected on substitution at lines 687-696"]
      external_calls: []
      events: []
      postconditions: ["terminal record"]
    invariants_enforced: ["only Committed finishes", "substitution burns", "material removed"]
  - id: CF-CODE-013
    file: "crates/router-ab-cloudflare/src/ecdsa_pool_lifecycle.rs"
    function: "CloudflareSigningWorkerEcdsaPoolLifecycleRecordV1::recover_after_crash"
    lines: "700-719"
    visibility: "public"
    modifiers: ["consumes self"]
    behavior:
      preconditions: ["validated Reserved or Committed record"]
      state_reads: ["current lifecycle"]
      state_writes: ["Reserved becomes CrashRecovery; Committed becomes AmbiguousDelivery"]
      computations: ["variant-specific terminal reason at lines 703-711"]
      external_calls: []
      events: []
      postconditions: ["material-free tombstone or invalid-state error"]
    invariants_enforced: ["recovery is destructive", "Available is not recovery", "Tombstone is not revived"]
  - id: CF-CODE-014
    file: "crates/router-ab-cloudflare/src/ecdsa_pool_lifecycle.rs"
    function: "CloudflareSigningWorkerEcdsaPoolLifecycleRecordV1::reserved_material"
    lines: "721-732"
    visibility: "public"
    modifiers: []
    behavior:
      preconditions: ["record validates"]
      state_reads: ["material_state"]
      state_writes: []
      computations: ["projects Reserved material only"]
      external_calls: []
      events: []
      postconditions: ["reference only for Reserved"]
    invariants_enforced: ["Available cannot leak", "Committed accessor is distinct", "Tombstone cannot leak"]
  - id: CF-CODE-015
    file: "crates/router-ab-cloudflare/src/ecdsa_pool_lifecycle.rs"
    function: "CloudflareSigningWorkerEcdsaPoolLifecycleRecordV1::committed_material"
    lines: "734-745"
    visibility: "public"
    modifiers: []
    behavior:
      preconditions: ["record validates"]
      state_reads: ["material_state"]
      state_writes: []
      computations: ["projects Committed material only"]
      external_calls: []
      events: []
      postconditions: ["reference only for Committed"]
    invariants_enforced: ["Reserved cannot enter online kernel", "Available cannot leak", "Tombstone cannot leak"]
  - id: CF-CODE-016
    file: "crates/router-ab-cloudflare/src/ecdsa_pool_lifecycle.rs"
    function: "CloudflareSigningWorkerEcdsaPoolLifecycleRecordV1::server_presignature_id"
    lines: "747-750"
    visibility: "public"
    modifiers: []
    behavior:
      preconditions: ["record exists"]
      state_reads: ["stable pair id"]
      state_writes: []
      computations: []
      external_calls: []
      events: []
      postconditions: ["pair id reference"]
    invariants_enforced: ["pair survives tombstoning", "no regenerated id", "no material access"]
  - id: CF-CODE-017
    file: "crates/router-ab-cloudflare/src/ecdsa_pool_lifecycle.rs"
    function: "CloudflareSigningWorkerEcdsaPoolLifecycleRecordV1::into_tombstone"
    lines: "752-760"
    visibility: "private"
    modifiers: ["consumes self"]
    behavior:
      preconditions: ["caller supplies terminal lifecycle"]
      state_reads: ["scope and pair"]
      state_writes: ["sets material_state to Tombstone"]
      computations: ["validates replacement"]
      external_calls: []
      events: []
      postconditions: ["material-free record"]
    invariants_enforced: ["scope retained", "pair retained", "secret variant removed"]
  - id: CF-CODE-018
    file: "crates/router-ab-cloudflare/src/ecdsa_pool_lifecycle.rs"
    function: "validate_bound_material"
    lines: "764-781"
    visibility: "private"
    modifiers: []
    behavior:
      preconditions: ["scope, lifecycle binding, and request-bound material"]
      state_reads: ["active state, pair id, request digest"]
      state_writes: []
      computations: ["rederives reservation binding at lines 769-775"]
      external_calls: []
      events: []
      postconditions: ["exact binding or error"]
    invariants_enforced: ["active state matches", "pair matches", "request matches"]
  - id: CF-CODE-019
    file: "crates/router-ab-cloudflare/src/ecdsa_pool_lifecycle.rs"
    function: "validate_material_pair_id; validate_command_scope; validate_positive_timestamp"
    lines: "783-811"
    visibility: "private"
    modifiers: []
    behavior:
      preconditions: ["raw boundary fields"]
      state_reads: ["pair strings, scope, time"]
      state_writes: []
      computations: ["equality, non-empty, and positive checks"]
      external_calls: []
      events: []
      postconditions: ["normalized validation result"]
    invariants_enforced: ["no empty pair", "no zero time", "no pair drift"]
  - id: CF-CODE-020
    file: "crates/router-ab-cloudflare/src/ecdsa_pool_lifecycle.rs"
    function: "require_current; validate_command_identity"
    lines: "813-843"
    visibility: "private"
    modifiers: []
    behavior:
      preconditions: ["optional persisted record and command identity"]
      state_reads: ["scope, pair id, revision"]
      state_writes: []
      computations: ["exact equality at lines 830-840"]
      external_calls: []
      events: []
      postconditions: ["missing, substituted, and stale commands reject"]
    invariants_enforced: ["no implicit create", "no cross-identity mutation", "no stale revision"]
  - id: CF-CODE-021
    file: "crates/router-ab-cloudflare/src/ecdsa_pool_lifecycle.rs"
    function: "validate_active_scope"
    lines: "845-853"
    visibility: "private"
    modifiers: []
    behavior:
      preconditions: ["normal signing scope and active state"]
      state_reads: ["scope-derived lookup and active identity"]
      state_writes: []
      computations: ["delegates exact active-state validation"]
      external_calls: []
      events: []
      postconditions: ["active state belongs to scope"]
    invariants_enforced: ["wallet/session binding", "SigningWorker binding", "epoch binding"]
  - id: CF-CODE-022
    file: "crates/router-ab-cloudflare/src/ecdsa_pool_lifecycle.rs"
    function: "pool_key"
    lines: "855-898"
    visibility: "private"
    modifiers: []
    behavior:
      preconditions: ["validated scope and non-empty pair"]
      state_reads: ["wallet key, wallet id, scope digest, pair, worker key epoch, activation epoch"]
      state_writes: []
      computations: ["domain-separated SHA-256 bindings at lines 863-897"]
      external_calls: []
      events: []
      postconditions: ["fixed SigningWorker PoolRecordKey"]
    invariants_enforced: ["fixed role", "fixed protocol", "all authority fields bound"]
  - id: CF-CODE-023
    file: "crates/router-ab-cloudflare/src/ecdsa_pool_lifecycle.rs"
    function: "reservation_binding"
    lines: "900-921"
    visibility: "private"
    modifiers: []
    behavior:
      preconditions: ["scope, pair, request digest"]
      state_reads: ["scope digest and exact identifiers"]
      state_writes: []
      computations: ["separate request and reservation domain hashes"]
      external_calls: []
      events: []
      postconditions: ["one exact ReservationBinding"]
    invariants_enforced: ["request/scope binding", "pair binding", "domain separation"]
  - id: CF-CODE-024
    file: "crates/router-ab-cloudflare/src/ecdsa_pool_lifecycle.rs"
    function: "binding_digest"
    lines: "923-931"
    visibility: "private"
    modifiers: []
    behavior:
      preconditions: ["domain and byte fields"]
      state_reads: ["field lengths and bytes"]
      state_writes: []
      computations: ["SHA-256(domain || len || field...)"]
      external_calls: []
      events: []
      postconditions: ["32-byte binding"]
    invariants_enforced: ["length-prefix ambiguity resistance", "field order", "domain separation"]
  - id: CF-CODE-025
    file: "crates/router-ab-cloudflare/src/ecdsa_pool_lifecycle.rs"
    function: "pool_identity_error; pool_transition_error; pool_state_error; pool_replay_error"
    lines: "933-952"
    visibility: "private"
    modifiers: []
    behavior:
      preconditions: ["domain error or static message"]
      state_reads: []
      state_writes: []
      computations: ["maps errors to InvalidLocalServiceConfig or ReplayedLocalRequest"]
      external_calls: []
      events: []
      postconditions: ["redacted protocol error"]
    invariants_enforced: ["no secret record formatting", "stale maps to replay", "no implicit retry"]
  - id: CF-CODE-026
    file: "crates/router-ab-cloudflare/src/durable_object/mod.rs"
    function: "CloudflareDurableObjectRequestV1::signing_worker_ecdsa_pool_mutate"
    lines: "3728-3735"
    visibility: "public"
    modifiers: []
    behavior:
      preconditions: ["validated command"]
      state_reads: ["command"]
      state_writes: []
      computations: ["wraps typed request"]
      external_calls: []
      events: []
      postconditions: ["validated request"]
    invariants_enforced: ["one operation tag", "command validation", "no generic body"]
  - id: CF-CODE-027
    file: "crates/router-ab-cloudflare/src/durable_object/mod.rs"
    function: "CloudflareDurableObjectRequestV1::required_scope; validate"
    lines: "3829-3916"
    visibility: "public"
    modifiers: ["exhaustive enum match"]
    behavior:
      preconditions: ["typed request"]
      state_reads: ["operation branch and command"]
      state_writes: []
      computations: ["maps pool mutation to SigningWorker server-output scope at lines 3863-3872", "validates command at line 3914"]
      external_calls: []
      events: []
      postconditions: ["role-local scope requirement"]
    invariants_enforced: ["SigningWorker ownership", "no Router scope", "no Deriver root scope"]
  - id: CF-CODE-028
    file: "crates/router-ab-cloudflare/src/durable_object/mod.rs"
    function: "CloudflareDurableObjectResponseV1::signing_worker_ecdsa_pool_mutate; validate_for_request"
    lines: "4334-4341, 4705-4719"
    visibility: "public"
    modifiers: []
    behavior:
      preconditions: ["validated outcome and matching request"]
      state_reads: ["outcome record scope and pair"]
      state_writes: []
      computations: ["validates branch and exact command identity"]
      external_calls: []
      events: []
      postconditions: ["wrong response identity rejects"]
    invariants_enforced: ["response/request branch match", "scope match", "pair match"]
  - id: CF-CODE-029
    file: "crates/router-ab-cloudflare/src/durable_object/mod.rs"
    function: "CloudflareDurableObjectCallV1::validate; storage_key"
    lines: "4753-4769, 4784-4970"
    visibility: "public"
    modifiers: []
    behavior:
      preconditions: ["binding is visible to role and required scope matches"]
      state_reads: ["binding prefix, wallet, active session, SigningWorker id, pair id"]
      state_writes: []
      computations: ["constructs one path key at lines 4958-4969"]
      external_calls: []
      events: []
      postconditions: ["server-output call and deterministic storage key"]
    invariants_enforced: ["role visibility", "scope equality", "record validates complete identity after lookup"]
  - id: CF-CODE-030
    file: "crates/router-ab-cloudflare/src/durable_object/handlers.rs"
    function: "handle_cloudflare_durable_object_call_v1 pool branch"
    lines: "480-490"
    visibility: "public"
    modifiers: ["in-memory/test adapter"]
    behavior:
      preconditions: ["validated call"]
      state_reads: ["current record at line 482"]
      state_writes: ["replacement put at lines 485-486"]
      computations: ["pure reducer at lines 481-484"]
      external_calls: []
      events: []
      postconditions: ["validated response"]
    invariants_enforced: ["read-reduce-replace", "same storage key", "no delete-based path"]
  - id: CF-CODE-031
    file: "crates/router-ab-cloudflare/src/durable_object/worker_storage.rs"
    function: "handle_cloudflare_durable_object_worker_request_v1 pool branch"
    lines: "716-736"
    visibility: "public"
    modifiers: ["workers-rs"]
    behavior:
      preconditions: ["validated class binding and request"]
      state_reads: ["strongly consistent storage.get at lines 717-722"]
      state_writes: ["storage.put replacement at lines 725-731"]
      computations: ["pure reducer at lines 723-724"]
      external_calls: ["Cloudflare Durable Object Storage get/put; errors abort before response"]
      events: []
      postconditions: ["response validated at line 735"]
    invariants_enforced: ["one key", "no non-storage I/O between read and write", "write before response"]
  - id: CF-CODE-032
    file: "crates/router-ab-cloudflare/src/durable_object/mod.rs"
    function: "worker_storage_get; worker_storage_put"
    lines: "5284-5322"
    visibility: "private"
    modifiers: ["workers-rs", "async"]
    behavior:
      preconditions: ["non-empty storage key"]
      state_reads: ["storage.get at line 5293"]
      state_writes: ["storage.put at line 5314"]
      computations: ["typed serde boundary"]
      external_calls: ["Cloudflare Storage API with mapped errors"]
      events: []
      postconditions: ["typed value or fail-closed error"]
    invariants_enforced: ["no silent storage error", "no alternate key", "no public output on write failure"]
  - id: CF-CODE-033
    file: "crates/router-ab-cloudflare/src/lib.rs"
    function: "CloudflareSigningWorkerRuntimeV1::signing_worker_ecdsa_pool_mutate_call"
    lines: "4776-4786"
    visibility: "public"
    modifiers: []
    behavior:
      preconditions: ["typed command"]
      state_reads: ["SigningWorker server-output binding"]
      state_writes: []
      computations: ["builds role-fixed DO call"]
      external_calls: []
      events: []
      postconditions: ["SigningWorker-owned call"]
    invariants_enforced: ["fixed role", "fixed binding", "validated request"]
  - id: CF-CODE-034
    file: "crates/router-ab-cloudflare/src/lib.rs"
    function: "handle_cloudflare_signing_worker_router_ab_ecdsa_derivation_presignature_pool_put_private_fetch_v1"
    lines: "9389-9586"
    visibility: "public"
    modifiers: ["workers-rs", "async", "private route"]
    behavior:
      preconditions: ["POST/path/body validation before line 9440", "active state and active material loaded and matched at lines 9441-9527"]
      state_reads: ["authenticated active SigningWorker state and material", "pool record"]
      state_writes: ["PutAvailable Durable Object mutation at lines 9536-9567"]
      computations: ["registry-bound pool record at line 9527"]
      external_calls: ["two DO lookups and one DO mutation; all errors withhold receipt"]
      events: []
      postconditions: ["public admission receipt after Available outcome"]
    invariants_enforced: ["active registry authority", "idempotent exact admission", "different pair material rejects"]
  - id: CF-CODE-035
    file: "crates/router-ab-cloudflare/src/lib.rs"
    function: "handle_cloudflare_signing_worker_router_ab_ecdsa_derivation_evm_digest_prepare_private_fetch_from_pool_v1"
    lines: "9594-9845"
    visibility: "public"
    modifiers: ["workers-rs", "async", "private route"]
    behavior:
      preconditions: ["POST/path/body validation at lines 9600-9632", "active material and request validation at lines 9633-9756"]
      state_reads: ["active SigningWorker state/material", "Reserved outcome material at lines 9805-9813"]
      state_writes: ["revision-0 to revision-1 reservation at lines 9757-9798"]
      computations: ["SigningWorker contribution generated before reservation", "response built after reservation at lines 9814-9844"]
      external_calls: ["DO lookups before reserve", "DO reserve at lines 9777-9786", "HTTP serialization at line 9844"]
      events: []
      postconditions: ["prepare response after durable reservation, or error"]
    invariants_enforced: ["fresh contribution after admission", "request/signing digest persisted", "material read after reserve"]
  - id: CF-CODE-036
    file: "crates/router-ab-cloudflare/src/lib.rs"
    function: "handle_cloudflare_signing_worker_router_ab_ecdsa_derivation_evm_digest_finalize_private_fetch_v1"
    lines: "9849-10092"
    visibility: "public"
    modifiers: ["workers-rs", "async", "private route"]
    behavior:
      preconditions: ["POST/path/body validation", "active material lookup", "prepare digest reconstruction"]
      state_reads: ["Committed outcome secret at lines 10007-10036"]
      state_writes: ["revision-1 to revision-2 commit at lines 9986-10023", "revision-2 to revision-3 terminal replacement at lines 10042-10084"]
      computations: ["online signature at lines 10024-10036", "terminal reason at lines 10037-10041"]
      external_calls: ["two active-material DO reads", "commit DO call", "finish DO call", "HTTP serialization only at lines 10085-10091"]
      events: []
      postconditions: ["signature/error emitted only after terminal tombstone validation"]
    invariants_enforced: ["commit-before-secret-access", "tombstone-before-output", "wrong terminal reason rejects"]
  - id: CF-CODE-037
    file: "crates/router-ab-cloudflare/src/lib.rs"
    function: "require_signing_worker_ecdsa_pool_mutate_response_v1"
    lines: "10874-10889"
    visibility: "private"
    modifiers: ["workers-rs"]
    behavior:
      preconditions: ["validated call and response"]
      state_reads: ["response branch"]
      state_writes: []
      computations: ["extracts exact mutation outcome"]
      external_calls: []
      events: []
      postconditions: ["wrong branch rejects"]
    invariants_enforced: ["response request match", "typed outcome", "no unchecked body"]
  - id: CF-CODE-038
    file: "crates/router-ab-cloudflare/src/lib.rs"
    function: "execute_cloudflare_signing_worker_ecdsa_pool_mutation_v1"
    lines: "10886-10895"
    visibility: "private"
    modifiers: ["workers-rs", "async"]
    behavior:
      preconditions: ["typed command"]
      state_reads: ["runtime binding"]
      state_writes: []
      computations: ["builds and validates call/response"]
      external_calls: ["Durable Object stub fetch at line 10893"]
      events: []
      postconditions: ["validated outcome or fail-closed error"]
    invariants_enforced: ["single mutation boundary", "no retry", "no output on transport error"]
  - id: CF-CODE-039
    file: "crates/router-ab-cloudflare/src/ed25519_yao_websocket.rs"
    function: "CloudflareEd25519YaoCircuitV1::protocol_label; parse"
    lines: "29-43"
    visibility: "private"
    modifiers: ["fixed enum"]
    behavior:
      preconditions: ["fixed enum or raw protocol token"]
      state_reads: []
      state_writes: []
      computations: ["maps only activation/export"]
      external_calls: []
      events: []
      postconditions: ["known circuit or InvalidProtocol"]
    invariants_enforced: ["no runtime circuit loader", "two circuit families", "unknown rejects"]
  - id: CF-CODE-040
    file: "crates/router-ab-cloudflare/src/ed25519_yao_websocket.rs"
    function: "CloudflareEd25519YaoWebSocketBindingV1::new; protocol; parse_protocol"
    lines: "55-97"
    visibility: "public"
    modifiers: []
    behavior:
      preconditions: ["non-zero 32-byte session"]
      state_reads: ["circuit and session"]
      state_writes: []
      computations: ["fixed subprotocol encoding and exact three-component parse"]
      external_calls: []
      events: []
      postconditions: ["round-trippable circuit/session binding"]
    invariants_enforced: ["non-zero session", "lowercase fixed-width hex", "no extra token components"]
  - id: CF-CODE-041
    file: "crates/router-ab-cloudflare/src/ed25519_yao_websocket.rs"
    function: "CloudflareEd25519YaoWebSocketErrorV1::fmt"
    lines: "115-124"
    visibility: "public trait implementation"
    modifiers: []
    behavior:
      preconditions: ["typed error"]
      state_reads: ["error variant"]
      state_writes: []
      computations: ["static redacted message"]
      external_calls: []
      events: []
      postconditions: ["no session or envelope bytes in display"]
    invariants_enforced: ["redaction", "stable category", "no peer payload"]
  - id: CF-CODE-042
    file: "crates/router-ab-cloudflare/src/ed25519_yao_websocket.rs"
    function: "connect_cloudflare_ed25519_yao_deriver_b_v1"
    lines: "131-173"
    visibility: "public"
    modifiers: ["async", "workers-rs"]
    behavior:
      preconditions: ["caller supplies validated binding"]
      state_reads: ["DERIVER_B Service Binding and fixed internal URL"]
      state_writes: []
      computations: ["sets Upgrade, subprotocol, and Cloudflare internal-service authentication; requires 101 and exact echo"]
      external_calls: ["internal-service auth header helper", "same-account Service Binding fetch"]
      events: []
      postconditions: ["WebSocket with exact echoed subprotocol"]
    invariants_enforced: ["fixed B binding", "fixed endpoint", "same-account internal-service authentication", "no subprotocol downgrade"]
  - id: CF-CODE-043
    file: "crates/router-ab-cloudflare/src/ed25519_yao_websocket.rs"
    function: "CloudflareEd25519YaoWebSocketTransportV1::deriver_a; deriver_b; new"
    lines: "183-237"
    visibility: "public constructors and private shared constructor"
    modifiers: []
    behavior:
      preconditions: ["accepted socket and session"]
      state_reads: ["role-selected directions"]
      state_writes: ["creates one encoder and decoder"]
      computations: ["sets binary mode, event stream, and accepts socket"]
      external_calls: ["WebSocket runtime methods"]
      events: []
      postconditions: ["role-fixed duplex transport"]
    invariants_enforced: ["opposite directions", "one encoder", "one decoder"]
  - id: CF-CODE-044
    file: "crates/router-ab-cloudflare/src/ed25519_yao_websocket.rs"
    function: "CloudflareEd25519YaoWebSocketTransportV1::decode_message"
    lines: "239-281"
    visibility: "private"
    modifiers: []
    behavior:
      preconditions: ["binary frame"]
      state_reads: ["directional decoder state"]
      state_writes: ["advances decoder or consumes it at EOF"]
      computations: ["rejects empty/zero-progress/missing/multiple messages"]
      external_calls: []
      events: []
      postconditions: ["one message or authenticated directional EOF evidence"]
    invariants_enforced: ["one frame result", "direction/session envelope validation delegated", "EOF consumes decoder"]
  - id: CF-CODE-045
    file: "crates/router-ab-cloudflare/src/ed25519_yao_websocket.rs"
    function: "YaoDuplexTransport::send; receive; close_local_direction; finish"
    lines: "284-347"
    visibility: "public trait implementation"
    modifiers: ["async"]
    behavior:
      preconditions: ["live encoder/decoder state"]
      state_reads: ["socket events and directional states"]
      state_writes: ["encoder/decoder consumed on directional close/EOF"]
      computations: ["encodes one envelope, zeroizes temporary byte copies, enforces clean terminal state"]
      external_calls: ["WebSocket send, receive, close"]
      events: ["message, directional EOF, clean close"]
      postconditions: ["typed message/EOF/completion or fail-closed transport error"]
    invariants_enforced: ["binary only", "single directional close", "finish requires both directions closed"]
  - id: CF-CODE-046
    file: "crates/router-ab-cloudflare/src/ed25519_yao_websocket.rs"
    function: "encode_hex; decode_hex_32; decode_nibble"
    lines: "350-378"
    visibility: "private"
    modifiers: []
    behavior:
      preconditions: ["32 bytes or raw token"]
      state_reads: ["fixed token bytes"]
      state_writes: []
      computations: ["lowercase exact-width hexadecimal conversion"]
      external_calls: []
      events: []
      postconditions: ["canonical bytes or InvalidProtocol"]
    invariants_enforced: ["exact length", "lowercase only", "no permissive decoder"]
  - id: CF-CODE-047
    file: "crates/router-ab-cloudflare/src/ed25519_yao_lifecycle.rs"
    function: "CloudflareEd25519YaoResultRequestV1::{session_id,input_kind,validate}"
    lines: "96-126"
    visibility: "private methods on public request"
    modifiers: []
    behavior:
      preconditions: ["strictly decoded activation or export request"]
      state_reads: ["family and session"]
      state_writes: []
      computations: ["maps family and rejects zero session"]
      external_calls: []
      events: []
      postconditions: ["typed family plus nonzero session"]
    invariants_enforced: ["family-route binding input", "nonzero session"]
  - id: CF-CODE-048
    file: "crates/router-ab-cloudflare/src/ed25519_yao_lifecycle.rs"
    function: "DeriverAYaoSessionCommandV1::{input,validate}"
    lines: "71-94"
    visibility: "private"
    modifiers: []
    behavior:
      preconditions: ["one tagged Deriver A command"]
      state_reads: ["encrypted input"]
      state_writes: []
      computations: ["validates encrypted input and Deriver A ownership"]
      external_calls: ["input validator"]
      events: []
      postconditions: ["role-correct typed A command"]
    invariants_enforced: ["Deriver A only", "validated payload"]
  - id: CF-CODE-049
    file: "crates/router-ab-cloudflare/src/ed25519_yao_lifecycle.rs"
    function: "DeriverBYaoSessionCommandV1::{session,validate}"
    lines: "128-185"
    visibility: "private"
    modifiers: []
    behavior:
      preconditions: ["one tagged session command"]
      state_reads: ["session, role, encrypted input or execution"]
      state_writes: []
      computations: ["validates nonzero session and Deriver B ownership"]
      external_calls: ["input/execution validators"]
      events: []
      postconditions: ["role-correct typed command"]
    invariants_enforced: ["Deriver B only", "nonzero session", "validated payload"]
  - id: CF-CODE-050
    file: "crates/router-ab-cloudflare/src/ed25519_yao_lifecycle.rs"
    function: "RouterAbDeriverAYaoSessionDurableObject::{new,fetch}"
    lines: "210-274"
    visibility: "public Durable Object"
    modifiers: ["async fetch"]
    behavior:
      preconditions: ["POST and valid role-A command"]
      state_reads: ["staged input, execution, and session status"]
      state_writes: ["stores exact input, persists Running before evaluation, then stores execution and Completed"]
      computations: ["rejects conflicting input, returns exact completed execution, rejects every nonterminal retry"]
      external_calls: ["Durable Object storage", "Deriver A Yao role execution"]
      events: ["one claimed A-side evaluation"]
      postconditions: ["Completed execution, or durable Running remains after failure"]
    invariants_enforced: ["one normal claim per session", "conflicting input rejection", "exact result redelivery"]
  - id: CF-CODE-051
    file: "crates/router-ab-cloudflare/src/ed25519_yao_lifecycle.rs"
    function: "RouterAbDeriverBYaoSessionDurableObject::{new,fetch}"
    lines: "276-386"
    visibility: "public Durable Object"
    modifiers: ["async fetch"]
    behavior:
      preconditions: ["POST and valid internal command"]
      state_reads: ["session-scoped input, status, and role execution"]
      state_writes: ["Staged on first input, Running on exact Begin, execution plus Completed on Complete"]
      computations: ["rejects conflicting input/output and every second Begin; returns exact completed execution"]
      external_calls: ["Durable Object storage get/put"]
      events: []
      postconditions: ["one normal claim and exact result redelivery, or durable Running remains after failure"]
    invariants_enforced: ["session-scoped DO id", "Staged-to-Running claim", "conflicting overwrite rejection"]
  - id: CF-CODE-052
    file: "crates/router-ab-cloudflare/src/ed25519_yao_lifecycle.rs"
    function: "handle_cloudflare_ed25519_yao_deriver_a_start_v1; execute_deriver_a_role"
    lines: "388-450"
    visibility: "public"
    modifiers: ["async"]
    behavior:
      preconditions: ["internally authenticated strict Deriver A route", "encrypted role-A input of route family"]
      state_reads: ["role-local HPKE key and root-share metadata/secret"]
      state_writes: ["session DO owns Running/Completed persistence"]
      computations: ["opens input, connects to B, runs fixed activation/export role under 15-second timeout, recipient-seals execution"]
      external_calls: ["Deriver A session DO", "Deriver B WebSocket", "root-share DO", "Yao role driver"]
      events: ["one claimed A-side evaluation"]
      postconditions: ["recipient-encrypted Deriver A role execution"]
    invariants_enforced: ["role/family match", "fixed circuit", "role-local root", "recipient encryption"]
  - id: CF-CODE-053
    file: "crates/router-ab-cloudflare/src/ed25519_yao_lifecycle.rs"
    function: "handle_cloudflare_ed25519_yao_deriver_b_stage_v1; handle_cloudflare_ed25519_yao_deriver_b_result_v1"
    lines: "453-516"
    visibility: "public"
    modifiers: ["async"]
    behavior:
      preconditions: ["internally authenticated strict Deriver B route", "matching role/family/session"]
      state_reads: ["stored role execution during bounded result polling"]
      state_writes: ["idempotently stages encrypted input"]
      computations: ["route-family validation and at most 100 result reads at 5ms interval"]
      external_calls: ["Deriver B session DO"]
      events: []
      postconditions: ["staged receipt or exact stored recipient-encrypted execution"]
    invariants_enforced: ["role/family match", "session match", "bounded result wait", "exact redelivery"]
  - id: CF-CODE-054
    file: "crates/router-ab-cloudflare/src/ed25519_yao_lifecycle.rs"
    function: "validate_deriver_input"
    lines: "518-535"
    visibility: "private"
    modifiers: []
    behavior:
      preconditions: ["decoded encrypted input and expected role/family"]
      state_reads: ["input metadata"]
      state_writes: []
      computations: ["validates payload, role, and family"]
      external_calls: []
      events: []
      postconditions: ["route-bound role input"]
    invariants_enforced: ["wrong role rejected", "wrong family rejected"]
  - id: CF-CODE-055
    file: "crates/router-ab-cloudflare/src/ed25519_yao_lifecycle.rs"
    function: "handle_cloudflare_ed25519_yao_deriver_b_websocket_v1"
    lines: "537-598"
    visibility: "public"
    modifiers: ["async"]
    behavior:
      preconditions: ["internally authenticated Deriver B route", "canonical WebSocket binding", "exact staged input"]
      state_reads: ["staged input by session"]
      state_writes: ["persists Running before WebSocket creation and background evaluation"]
      computations: ["matches circuit, requires one successful Begin, closes socket on background error"]
      external_calls: ["session DO", "WebSocketPair", "wait_until execution"]
      events: ["one claimed B-side evaluation"]
      postconditions: ["upgraded socket after durable claim; failure leaves Running"]
    invariants_enforced: ["one normal claim", "circuit/session match", "exact subprotocol echo"]
  - id: CF-CODE-056
    file: "crates/router-ab-cloudflare/src/ed25519_yao_lifecycle.rs"
    function: "execute_deriver_b_role; execute_deriver_b_session_command"
    lines: "600-683"
    visibility: "private"
    modifiers: ["async"]
    behavior:
      preconditions: ["claimed role-B input and accepted socket"]
      state_reads: ["role-local HPKE key/root plus session-derived DO id"]
      state_writes: ["stores exact recipient-encrypted execution and Completed"]
      computations: ["runs fixed role under timeout and strictly decodes DO response"]
      external_calls: ["root-share DO", "Yao driver", "Deriver B session DO"]
      events: ["one role execution"]
      postconditions: ["Completed or Running remains"]
    invariants_enforced: ["recipient encryption", "one DO per session", "non-2xx/malformed response rejection"]
  - id: CF-CODE-057
    file: "crates/router-ab-cloudflare/src/ed25519_yao_lifecycle.rs"
    function: "execute_deriver_a_session"
    lines: "686-728"
    visibility: "private"
    modifiers: ["async"]
    behavior:
      preconditions: ["validated Deriver A input"]
      state_reads: ["session-derived Durable Object id"]
      state_writes: ["delegates one-use execution to A session DO"]
      computations: ["validates returned role and session"]
      external_calls: ["DERIVER_A_YAO_SESSION_DO"]
      events: []
      postconditions: ["exact A execution or fail closed"]
    invariants_enforced: ["one DO per session", "role/session response identity", "malformed response rejection"]
  - id: CF-CODE-058
    file: "crates/router-ab-cloudflare/src/ed25519_yao_lifecycle.rs"
    function: "load_deriver_a_yao_root; load_deriver_b_yao_root; load_yao_root; load_deriver_input_private_key"
    lines: "730-803"
    visibility: "private"
    modifiers: ["async root helpers"]
    behavior:
      preconditions: ["configured role-local HPKE secret"]
      state_reads: ["Workers secret binding"]
      state_writes: ["zeroizes encoded secret string"]
      computations: ["strict private-key decode"]
      external_calls: ["Env::secret"]
      events: []
      postconditions: ["role-local Yao root or typed recipient private key"]
    invariants_enforced: ["role-specific metadata", "domain separation", "role-selected key", "encoded secret zeroization"]
  - id: CF-CODE-059
    file: "crates/router-ab-cloudflare/src/ed25519_yao_lifecycle.rs"
    function: "circuit_for_input; parse_request; json_response; with_yao_ceremony_timeout; encode_hex"
    lines: "805-866"
    visibility: "private"
    modifiers: ["parse/encode helpers"]
    behavior:
      preconditions: ["typed input or raw request"]
      state_reads: ["input family or request JSON"]
      state_writes: []
      computations: ["fixed family-to-circuit map and JSON boundary conversion"]
      external_calls: ["Workers request/response JSON"]
      events: []
      postconditions: ["fixed circuit or typed response/error"]
    invariants_enforced: ["no runtime circuit selector", "malformed JSON fails closed", "15-second execution bound", "fixed-width session id"]
  - id: CF-CODE-060
    file: "crates/router-ab-cloudflare/src/ed25519_yao_signing_worker.rs"
    function: "SigningWorkerYaoCommandV1::validate; SigningWorkerYaoDurableStateV1::validate"
    lines: "107-254"
    visibility: "private"
    modifiers: ["tagged unions"]
    behavior:
      preconditions: ["decoded command or persisted state"]
      state_reads: ["role packages, operation, stable identity, active/candidate material, receipts"]
      state_writes: []
      computations: ["validates exact role, operation, stable identity, and material/receipt binding"]
      external_calls: ["package/material validators"]
      events: []
      postconditions: ["one valid registration/recovery lifecycle branch"]
    invariants_enforced: ["role separation", "stable identity continuity", "registration/recovery branch separation"]
  - id: CF-CODE-061
    file: "crates/router-ab-cloudflare/src/ed25519_yao_signing_worker.rs"
    function: "RouterAbSigningWorkerEd25519YaoDurableObject::{fetch,execute_command,deliver_deriver_a}"
    lines: "271-444"
    visibility: "public Durable Object"
    modifiers: ["async"]
    behavior:
      preconditions: ["POST, valid command, stable-context DO identity"]
      state_reads: ["one persisted signing-worker Yao state"]
      state_writes: ["persists registration/recovery Pending or preserves exact idempotent state"]
      computations: ["rejects role/order/conflict/stable-identity drift"]
      external_calls: ["Durable Object storage"]
      events: []
      postconditions: ["exact A package retained pending B, or exact idempotent response"]
    invariants_enforced: ["one stable signing identity per DO", "A-before-B ordering", "conflicting replay rejection"]
  - id: CF-CODE-062
    file: "crates/router-ab-cloudflare/src/ed25519_yao_signing_worker.rs"
    function: "deliver_deriver_b; combine"
    lines: "446-539"
    visibility: "private"
    modifiers: ["async delivery"]
    behavior:
      preconditions: ["exact pending A package and role-B delivery"]
      state_reads: ["SigningWorker HPKE private key and active material for recovery"]
      state_writes: ["persists RegistrationStaged or RecoveryStaged with plaintext candidate"]
      computations: ["decrypts and combines exact A/B packages; preserves public-key continuity on recovery"]
      external_calls: ["Workers secret binding", "Yao package combiner"]
      events: []
      postconditions: ["validated staged candidate; registration proceeds to activation, recovery awaits promotion"]
    invariants_enforced: ["exact A/B binding", "role order", "state epoch increment", "recovery public-key continuity"]
  - id: CF-CODE-063
    file: "crates/router-ab-cloudflare/src/ed25519_yao_signing_worker.rs"
    function: "activate_registration; promote_recovery; persist_active_output"
    lines: "541-614"
    visibility: "private"
    modifiers: ["async"]
    behavior:
      preconditions: ["exact staged candidate; recovery additionally matches public promotion receipt"]
      state_reads: ["candidate scalar and receipt"]
      state_writes: ["first writes server-output DO, then stores local Active state"]
      computations: ["builds active material record; promotion verifies every public receipt field"]
      external_calls: ["server-output Durable Object"]
      events: []
      postconditions: ["active output is durable before active HTTP response; crash can leave a retryable Staged state"]
    invariants_enforced: ["public continuity confirmation for recovery", "idempotent cross-DO retry", "output-before-active response"]
  - id: CF-CODE-064
    file: "crates/router-ab-cloudflare/src/ed25519_yao_signing_worker.rs"
    function: "public delivery/promote handlers; execute_signing_worker_yao_command"
    lines: "617-773"
    visibility: "public/private boundary"
    modifiers: ["async"]
    behavior:
      preconditions: ["strict worker authenticates before handler; role-specific typed JSON"]
      state_reads: ["stable-context-derived DO"]
      state_writes: ["delegates state transition"]
      computations: ["requires response branch expected by route and emits public-only receipt"]
      external_calls: ["SIGNING_WORKER_ED25519_YAO_DO"]
      events: []
      postconditions: ["pending, staged, or active public response without scalar"]
    invariants_enforced: ["private edge", "one DO per stable identity", "role-specific route response"]
  - id: CF-CODE-065
    file: "crates/router-ab-cloudflare/src/ed25519_yao_signing_worker.rs"
    function: "persist_cloudflare_ed25519_yao_output_activation_v1; build_output_activation_record"
    lines: "775-864"
    visibility: "private"
    modifiers: ["async persistence"]
    behavior:
      preconditions: ["validated active material/receipt and SigningWorker runtime"]
      state_reads: ["server identity, key epoch, scalar, public receipt"]
      state_writes: ["sends one typed output record to server-output DO"]
      computations: ["derives material handle and active descriptor; checks returned descriptor byte-for-byte"]
      external_calls: ["SigningWorker server-output Durable Object"]
      events: []
      postconditions: ["active state and scalar record persisted or no active response"]
    invariants_enforced: ["server recipient scope", "transcript/public-key binding", "receipt cannot change active state"]
  - id: CF-CODE-066
    file: "crates/router-ab-cloudflare/src/durable_object/worker_storage.rs"
    function: "handle_cloudflare_ed25519_yao_output_activation_fetch_v1; persist_cloudflare_ed25519_yao_output_activation_v1"
    lines: "76-203"
    visibility: "private Durable Object boundary"
    modifiers: ["async"]
    behavior:
      preconditions: ["SigningWorker output scope, POST, Ed25519 Yao record, scoped material handle"]
      state_reads: ["existing exact material record and active-state index"]
      state_writes: ["atomically put_multiple writes material plus active index"]
      computations: ["exact duplicate is idempotent; conflicts and non-monotonic replacement reject"]
      external_calls: ["Durable Object storage"]
      events: []
      postconditions: ["material and active state become visible together"]
    invariants_enforced: ["scope prefix", "exact idempotency", "monotonic activation timestamp", "atomic paired write"]
  - id: CF-CODE-067
    file: "crates/router-ab-cloudflare/src/durable_object/mod.rs"
    function: "CloudflareSigningWorkerOutputActivationRecordV1::{ed25519_yao,validate,material accessors}"
    lines: "2552-2708"
    visibility: "public persisted record"
    modifiers: ["tagged enum"]
    behavior:
      preconditions: ["typed binding, receipt, active state, and material"]
      state_reads: ["all public binding fields and scalar record metadata"]
      state_writes: []
      computations: ["cross-validates session, transcript, public key, server identity, and receipt verifying share"]
      external_calls: ["component validators"]
      events: []
      postconditions: ["one protocol-specific activation record"]
    invariants_enforced: ["protocol discrimination", "active/material identity", "redacted nested material Debug"]
  - id: CF-CODE-068
    file: "crates/router-ab-cloudflare/src/strict_worker/signing_worker.rs"
    function: "handle_strict_signing_worker_fetch_v1"
    lines: "3-38"
    visibility: "private strict entrypoint"
    modifiers: ["async"]
    behavior:
      preconditions: ["internal-service secret validates before path dispatch"]
      state_reads: ["Workers secret and route path"]
      state_writes: ["route-dependent lifecycle mutation"]
      computations: ["dispatches A, B, and recovery promotion routes only after authentication"]
      external_calls: ["Yao lifecycle handlers"]
      events: []
      postconditions: ["unauthenticated requests fail before JSON parsing"]
    invariants_enforced: ["private SigningWorker edge", "constant-time shared-secret check", "fixed route ownership"]
  - id: CF-CODE-069
    file: "crates/router-ab-cloudflare/src/signing_worker/mod.rs"
    function: "CloudflareEd25519YaoNormalSigningHandlerV1 prepare/finalize implementations"
    lines: "787-930"
    visibility: "public handler"
    modifiers: ["normal signing traits"]
    behavior:
      preconditions: ["materialized active state and Yao-derived scalar record"]
      state_reads: ["scalar, active public key, stored one-use round-one nonces"]
      state_writes: ["returns persisted round-one state; outer lifecycle owns terminal deletion"]
      computations: ["FROST round one and server signature share with verifying-share checks"]
      external_calls: ["frost-ed25519"]
      events: []
      postconditions: ["bound round-one response or valid server signature share"]
    invariants_enforced: ["server verifying share equals active scalar", "group public key binding", "one stored round-one handle"]
```

The code uses general `Serialize`, `Clone`, and `Debug` on the lifecycle command,
record, material-state, and outcome types at
`ecdsa_pool_lifecycle.rs:31-65,77-161,263-294`. Serialization and cloning are
required by the Durable Object JSON/storage boundary and response validation.
`Debug` is not used by the reviewed route or storage error paths. Retaining
`Debug` is a reviewed exception only if a permanent source guard prevents
formatting these types into logs or public errors.

---

## 5. Full alignment matrix (Spec → Code → Status)

```yaml
alignment_ir:
  - id: CF-ALIGN-001
    spec_ref: CF-SPEC-001
    code_ref: [CF-CODE-007, CF-CODE-008, CF-CODE-020, CF-CODE-022, CF-CODE-023, CF-CODE-029]
    spec_claim: "Every record and mutation binds complete authenticated identity."
    code_behavior: "The adapter hashes full scope authority into PoolRecordKey, revalidates the full record, compares scope/pair/revision, and checks response identity."
    match_type: full_match
    confidence: 0.99
    reasoning: "The shorter storage path is only an index; the loaded record is rejected unless its complete identity equals the command."
    evidence:
      spec_quote: "Each record binds exactly"
      code_quote: "if current.scope != *scope || current.server_presignature_id != server_presignature_id"
      locations: ["persistent-pool-lifecycle-v1.md:14-23", "ecdsa_pool_lifecycle.rs:824-898", "durable_object/mod.rs:4958-4969"]
  - id: CF-ALIGN-002
    spec_ref: CF-SPEC-002
    code_ref: [CF-CODE-006, CF-CODE-009, CF-CODE-010, CF-CODE-012, CF-CODE-013]
    spec_claim: "The state machine is forward-only and Tombstone is absorbing."
    code_behavior: "Exact revisions 0/1/2 advance through typed branches; no reducer command accepts Tombstone as a source."
    match_type: full_match
    confidence: 0.99
    reasoning: "Stale or terminal commands fail. There is no transition back to Available."
    evidence:
      spec_quote: "Tombstones are absorbing"
      code_quote: "SigningWorker ECDSA material is not reserved"
      locations: ["persistent-pool-lifecycle-v1.md:25-36", "ecdsa_pool_lifecycle.rs:328-460,548-719"]
  - id: CF-ALIGN-003
    spec_ref: CF-SPEC-003
    code_ref: [CF-CODE-006, CF-CODE-030, CF-CODE-031, CF-CODE-032]
    spec_claim: "Exact CAS replacement and terminal material deletion are atomic."
    code_behavior: "The DO reads one record, computes one complete replacement, and puts it under the same key without non-storage I/O."
    match_type: full_match
    confidence: 0.96
    reasoning: "Cloudflare input gates serialize the async get/put sequence. Secret material is embedded in the record, so replacing it with a Tombstone variant removes it in the same write."
    evidence:
      spec_quote: "store exactly the replacement record; delete the sealed material in the same transaction"
      code_quote: "worker_storage_put(storage, &storage_key, outcome.record().clone()"
      locations: ["persistent-pool-lifecycle-v1.md:38-46", "durable_object/worker_storage.rs:716-732"]
  - id: CF-ALIGN-004
    spec_ref: CF-SPEC-004
    code_ref: [CF-CODE-006, CF-CODE-010, CF-CODE-011, CF-CODE-012, CF-CODE-013, CF-CODE-035, CF-CODE-036]
    spec_claim: "Every success, failure, expiry, retirement, or uncertainty becomes terminal."
    code_behavior: "Success/rejection and late/substituted commit burn, while available expiry, epoch retirement, prepare-tail failure, and process interruption have no live production transition."
    match_type: code_weaker_than_spec
    confidence: 1.0
    reasoning: "The domain crate can express the reasons, while the Cloudflare command enum and routes do not reach all of them."
    evidence:
      spec_quote: "all end in a permanent tombstone"
      code_quote: "CloudflareSigningWorkerEcdsaPoolCommandV1::{PutAvailable, Reserve, Commit, DestroyReserved, FinishCommitted, RecoverInterrupted}"
      locations: ["persistent-pool-lifecycle-v1.md:53-65", "ecdsa_pool_lifecycle.rs:80-161", "lib.rs:9588-10088"]
  - id: CF-ALIGN-005
    spec_ref: CF-SPEC-005
    code_ref: [CF-CODE-013]
    spec_claim: "Interrupted Reserved and Committed records are destructively recovered."
    code_behavior: "recover_after_crash assigns the correct reasons, but no production caller invokes RecoverInterrupted."
    match_type: partial_match
    confidence: 1.0
    reasoning: "The pure transition is correct and locally tested. Integration evidence is absent."
    evidence:
      spec_quote: "an interrupted committed use becomes AmbiguousDelivery"
      code_quote: "PoolRecord::Committed(record) => record.recover_ambiguous_delivery"
      locations: ["persistent-pool-lifecycle-v1.md:61-65", "ecdsa_pool_lifecycle.rs:700-719", "repository search for RecoverInterrupted"]
  - id: CF-ALIGN-006
    spec_ref: CF-SPEC-006
    code_ref: [CF-CODE-013, CF-CODE-031, CF-CODE-035, CF-CODE-036]
    spec_claim: "The concrete adapter recovers after termination at every edge."
    code_behavior: "No startup scan, alarm, indexed recovery endpoint, or live route calls RecoverInterrupted or DestroyReserved."
    match_type: missing_in_code
    confidence: 1.0
    reasoning: "The only non-definition occurrence of RecoverInterrupted is a source-presence test."
    evidence:
      spec_quote: "destructive recovery after process termination at every transition edge"
      code_quote: "RecoverInterrupted { ... }"
      locations: ["persistent-pool-lifecycle-v1.md:80-89", "ecdsa_pool_lifecycle.rs:150-160", "ecdsa_derivation_normal_signing_boundaries.rs:303-315"]
  - id: CF-ALIGN-007
    spec_ref: CF-SPEC-007
    code_ref: [CF-CODE-031, CF-CODE-036, CF-CODE-038]
    spec_claim: "Terminal persistence precedes final output."
    code_behavior: "The signature result is held until FinishCommitted returns and the material-free Tombstone/reason validate."
    match_type: full_match
    confidence: 0.99
    reasoning: "Every finish transport, storage, response, branch, or reason error returns without serializing the signature."
    evidence:
      spec_quote: "tombstoned before an online output crosses the process boundary"
      code_quote: "match signing_result { Ok(response) => worker::Response::from_json(&response)"
      locations: ["persistent-pool-lifecycle-v1.md:57-59", "lib.rs:10024-10091"]
  - id: CF-ALIGN-008
    spec_ref: CF-SPEC-008
    code_ref: [CF-CODE-009, CF-CODE-010, CF-CODE-035, CF-CODE-036]
    spec_claim: "Prepare binds the public coin and mismatch burns before material access."
    code_behavior: "Reserve stores request/signing digests and the SigningWorker contribution; finalize reconstructs the prepare digest and commit burns mismatch before committed_material."
    match_type: full_match
    confidence: 0.99
    reasoning: "The digest is supplied to Commit before the material accessor is reachable."
    evidence:
      spec_quote: "Mismatch, timeout, abort, and ambiguous delivery are terminal burns"
      code_quote: "expected_revision: 1, request_digest: prepare_request_digest"
      locations: ["online-lifecycle-v1.md:60-70", "lib.rs:9757-9766,9975-10027"]
  - id: CF-ALIGN-009
    spec_ref: CF-SPEC-009
    code_ref: [CF-CODE-014, CF-CODE-015, CF-CODE-035, CF-CODE-036]
    spec_claim: "Material access follows durable state transition."
    code_behavior: "Prepare reads only the Reserved outcome; finalize reads only the Committed outcome returned after DO persistence."
    match_type: full_match
    confidence: 0.98
    reasoning: "Cloudflare output gates are an explicit platform assumption for the returned committed outcome."
    evidence:
      spec_quote: "atomic transition from available to reserved before either party starts"
      code_quote: "let committed_record = match commit_outcome"
      locations: ["online-lifecycle-v1.md:94-108", "lib.rs:9798-9813,9986-10027"]
  - id: CF-ALIGN-010
    spec_ref: CF-SPEC-010
    code_ref: [CF-CODE-007, CF-CODE-009, CF-CODE-010, CF-CODE-029, CF-CODE-031]
    spec_claim: "Backup and restore cannot revive terminal or expired material."
    code_behavior: "The complete live lifecycle is stored in one SQLite DO key and has no external generation floor checked on every mutation."
    match_type: missing_in_code
    confidence: 0.95
    reasoning: "A point-in-time restore can restore both the record and its local active-state index. Deployment epoch advancement could mitigate this, but no enforced restore procedure is part of the reviewed code."
    evidence:
      spec_quote: "Persistence, backup, retry, and crash recovery cannot move ... into an available state"
      code_quote: "new_sqlite_classes = [\"RouterAbSigningWorkerServerOutputDurableObject\"]"
      locations: ["refactor-89-slimmer-near-ecdsa.md:766-768,891", "wrangler.signing-worker.toml:14-16"]
  - id: CF-ALIGN-011
    spec_ref: CF-SPEC-011
    code_ref: [CF-CODE-024, CF-CODE-025, CF-CODE-029, CF-CODE-032, CF-CODE-041]
    spec_claim: "Secret values stay out of keys and diagnostics."
    code_behavior: "Storage keys contain public identity only; error mappings format static messages and keys, never material records or scalar fields."
    match_type: full_match
    confidence: 0.97
    reasoning: "Search found no lifecycle command/outcome formatting in logs. Storage API serialization is the intended secret persistence boundary."
    evidence:
      spec_quote: "Secret values remain outside logs, errors, metrics, filenames, cache keys"
      code_quote: "format!(\"{} storage key `{}` failed: {message}\""
      locations: ["refactor-89-slimmer-near-ecdsa.md:726-727", "durable_object/mod.rs:5412-5425"]
  - id: CF-ALIGN-012
    spec_ref: CF-SPEC-012
    code_ref: [CF-CODE-006, CF-CODE-028, CF-CODE-031, CF-CODE-032]
    spec_claim: "Secret type traits require reviewed operational need."
    code_behavior: "Serialize and Clone are used for JSON/storage replacement and response ownership. Debug is derived and currently unused."
    match_type: partial_match
    confidence: 0.95
    reasoning: "The operational need justifies serialization and copies. Debug remains a latent footgun without a dedicated negative source guard."
    evidence:
      spec_quote: "unless a reviewed operation requires it"
      code_quote: "#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]"
      locations: ["refactor-89-slimmer-near-ecdsa.md:769-772", "ecdsa_pool_lifecycle.rs:31-65,77-80,263-265"]
  - id: CF-ALIGN-013
    spec_ref: CF-SPEC-013
    code_ref: [CF-CODE-027, CF-CODE-029, CF-CODE-033, CF-CODE-034, CF-CODE-035, CF-CODE-036]
    spec_claim: "Normal signing is Deriver-free and SigningWorker-private."
    code_behavior: "All pool calls use server-output scope and the strict SigningWorker dispatcher authenticates the internal request before route parsing."
    match_type: full_match
    confidence: 0.99
    reasoning: "The lifecycle matrix and source guards reject Deriver calls on ordinary prepare/finalize."
    evidence:
      spec_quote: "Client and SigningWorker are the only threshold-ECDSA signing parties"
      code_quote: "require_cloudflare_internal_service_auth_request_v1(&request, &env)"
      locations: ["refactor-89-slimmer-near-ecdsa.md:704-711", "strict_worker/signing_worker.rs:3-10,65-104"]
  - id: CF-ALIGN-014
    spec_ref: CF-SPEC-014
    code_ref: [CF-CODE-033, CF-CODE-034, CF-CODE-035, CF-CODE-036]
    spec_claim: "Production excludes generic threshold ECDSA."
    code_behavior: "Cargo normal dependencies include the purpose-built pool/online crates; signer-core is enabled only for Ed25519 features, and the old threshold-ECDSA feature/symbol is absent."
    match_type: full_match
    confidence: 1.0
    reasoning: "Resolved normal cargo tree and source search contain no threshold-ecdsa, threshold_ecdsa, Cait-Sith, or threshold-signatures edge."
    evidence:
      spec_quote: "production dependency graphs contain no threshold-signatures package"
      code_quote: "router-ab-ecdsa-pool = { path = \"../router-ab-ecdsa-pool\" }"
      locations: ["refactor-89-slimmer-near-ecdsa.md:676-679", "router-ab-cloudflare/Cargo.toml:27-49"]
  - id: CF-ALIGN-015
    spec_ref: CF-SPEC-015
    code_ref: [CF-CODE-040, CF-CODE-042, CF-CODE-043, CF-CODE-044, CF-CODE-045, CF-CODE-053, CF-CODE-055, CF-CODE-068]
    spec_claim: "Yao session authenticates role, Router admission, order, and replay."
    code_behavior: "Both strict Deriver entrypoints require constant-time internal-service authentication. The adapter binds circuit/session/direction and exact subprotocol echo. A and B each persist Running before evaluation, rejecting a second claim in the current generation."
    match_type: partial_match
    confidence: 0.99
    reasoning: "The current private-edge model has authenticated same-account transport and a normal one-use claim. It lacks the specified signed ephemeral peer handshake, terminal failure handling, and restore-safe replay authority."
    evidence:
      spec_quote: "session authentication derived from a signed ephemeral peer handshake"
      code_quote: "Sec-WebSocket-Protocol"
      locations: ["router-ab/ed25519-yao/implementation-plan.md:1070-1092", "ed25519_yao_websocket.rs:132-169"]
  - id: CF-ALIGN-016
    spec_ref: CF-SPEC-016
    code_ref: [CF-CODE-042]
    spec_claim: "Both deployment topologies preserve protocol identity; cross-account uses authenticated HTTPS."
    code_behavior: "The scoped product connector has a hard-coded DERIVER_B Service Binding and internal URL. A separate fixed cross-account WebSocket implementation exists in ed25519-yao-cloudflare-bench and has deployed two-account results; it is not part of product runtime negotiation."
    match_type: partial_match
    confidence: 1.0
    reasoning: "The selected product profile is same-account. Cross-account transport is implemented and tested in the benchmark deployment, while promotion into this production crate remains deferred."
    evidence:
      spec_quote: "Service Bindings cannot cross Cloudflare accounts"
      code_quote: "const DERIVER_B_BINDING: &str = \"DERIVER_B\""
      locations: ["router-ab/ed25519-yao/implementation-plan.md:1568-1592", "ed25519_yao_websocket.rs:14-18,132-169", "router-ab/ed25519-yao/deployment.md:196-224,252-265,296-310"]
  - id: CF-ALIGN-017
    spec_ref: CF-SPEC-017
    code_ref: [CF-CODE-035]
    spec_claim: "The reservation lease is capped at the earliest of request expiry, material expiry, and 60 seconds."
    code_behavior: "Prepare assigns request.expires_at_ms to both lease_expires_at_ms and request_expires_at_ms. Material expiry is checked by Reserve, but no independent 60-second cap is computed."
    match_type: code_weaker_than_spec
    confidence: 1.0
    reasoning: "Authentication constrains who can request a lease; it does not bound the duration. A long request expiry increases retained-secret and pool-exhaustion exposure."
    evidence:
      spec_quote: "min(request expiry, material expiry, now plus 60 seconds)"
      code_quote: "lease_expires_at_ms: request.expires_at_ms"
      locations: ["refactor-89-slimmer-near-ecdsa.md:1407-1431", "lib.rs:9757-9766"]
  - id: CF-ALIGN-018
    spec_ref: CF-SPEC-018
    code_ref: [CF-CODE-050, CF-CODE-051, CF-CODE-052, CF-CODE-053, CF-CODE-055, CF-CODE-056, CF-CODE-057]
    spec_claim: "Yao execution is durable, one-use, crash-safe, and exactly redeliverable without reevaluation."
    code_behavior: "A and B persist Running before evaluation, reject a second normal claim, and redeliver the exact completed execution. Failures remain Running, values never expire, and no independent generation rejects a restored pre-Running snapshot."
    match_type: code_weaker_than_spec
    confidence: 1.0
    reasoning: "The normal one-use transition is present. Crash recovery, failure/expiry terminality, secret-retention bounds, and rollback safety remain absent."
    evidence:
      spec_quote: "one-use execution, rollback safety, crash recovery, and exact ciphertext redelivery without reevaluation"
      code_quote: "if status != Some(YaoSessionStatusV1::Staged) { return ... cannot be evaluated more than once }"
      locations: ["router-ab/ed25519-yao/deployment.md:336-339", "ed25519_yao_lifecycle.rs:210-386,537-647"]
  - id: CF-ALIGN-019
    spec_ref: CF-SPEC-019
    code_ref: [CF-CODE-060, CF-CODE-061, CF-CODE-062, CF-CODE-063, CF-CODE-064, CF-CODE-065, CF-CODE-066, CF-CODE-067, CF-CODE-068, CF-CODE-069]
    spec_claim: "SigningWorker activation is exact, replay-safe, continuity-preserving, and terminally retires superseded or failed material."
    code_behavior: "Exact A/B package bindings, role order, stable identity, public-key continuity, state epochs, private routes, atomic output activation, and exact idempotency are enforced. The orchestration state has no Failed/Expired/Tombstone branch and retains duplicate active, pending, candidate, and superseded scalar material indefinitely."
    match_type: code_weaker_than_spec
    confidence: 0.99
    reasoning: "Activation and recovery promotion fail closed on mismatched public evidence. Secret-retention and terminal-retirement claims are missing from the Cloudflare implementation."
    evidence:
      spec_quote: "promotion tombstones the retired credential"
      code_quote: "SigningWorkerYaoDurableStateV1::{RegistrationPending, RegistrationStaged, Active, RecoveryPending, RecoveryStaged}"
      locations: ["router-ab/ed25519-yao/implementation-plan.md:4133-4146", "ed25519_yao_signing_worker.rs:146-254,329-614", "durable_object/worker_storage.rs:121-191"]
```

---

## 6. Divergence findings

```yaml
divergence_findings:
  - id: CF-LC-001
    severity: HIGH
    title: "Committed secret material survives Worker termination and has no production recovery path"
    spec_claim: "Interrupted committed use becomes AmbiguousDelivery, secret material is destroyed, and recovery runs at every transition edge."
    code_finding: "Commit writes a Committed record that still contains CloudflareSigningWorkerEcdsaPresignatureRecordV1. Finalization clones it into the Worker, computes the signature, and only then performs FinishCommitted. RecoverInterrupted and DestroyReserved have zero production callers."
    match_type: missing_in_code
    confidence: 1.0
    reasoning: "The success path withholds output correctly, but a termination after revision 2 leaves the material durably stored forever. The reducer can burn it only when a caller already knows the exact key/revision; no scan, alarm, startup recovery, or external command supplies that caller."
    evidence:
      spec:
        - "persistent-pool-lifecycle-v1.md:61-65"
        - "persistent-pool-lifecycle-v1.md:80-89"
        - "refactor-89-slimmer-near-ecdsa.md:714-721"
      code:
        - "ecdsa_pool_lifecycle.rs:619-625"
        - "ecdsa_pool_lifecycle.rs:700-719"
        - "lib.rs:9986-10062"
      exhaustive_search: "RecoverInterrupted and DestroyReserved occur only in ecdsa_pool_lifecycle.rs plus one source-presence assertion; no production route invokes them."
    exploitability:
      prerequisites: "A Worker termination, panic, deployment, or unrecoverable exception after committed persistence and before successful FinishCommitted."
      sequence:
        - "Finalize commits revision 1 to revision 2."
        - "The Durable Object stores the secret-bearing Committed record and returns a clone."
        - "The Worker terminates before revision 3 is persisted."
        - "Retries use expected revision 1 and fail stale; no recovery enumerator burns revision 2."
      impact: "Exactly one presignature half remains retained per interrupted attempt. No second signature was demonstrated through the typed API, so direct unauthorized-signing impact is unproven. Retained material count grows linearly with interrupted attempts and remains exposed for the lifetime of the restored/storage generation."
      economic_impact: "Direct proven transaction loss: 0. Availability loss: 1 usable pair per interrupted attempt. Storage/incident cost is unbounded in time because no retention deadline is enforced."
    remediation:
      design: "Make commitment an atomic destructive take: persist a material-free Committed marker and return the role-local material once under the Durable Object output gate. Add indexed recovery that converts material-free Committed to AmbiguousDelivery and Reserved to CrashRecovery."
      code_example: |
        enum PoolMaterialState {
            Available { material: SecretMaterial },
            Reserved { material: BoundSecretMaterial },
            CommittedTaken,
            Tombstone,
        }

        // One DO request:
        // 1. compare revision 1 and binding
        // 2. persist revision 2 + CommittedTaken
        // 3. return the moved material once
      tests:
        - "Workers/miniflare fault injection after storage commit and before response delivery"
        - "startup/alarm enumeration burns Reserved and CommittedTaken"
        - "duplicate commit cannot return material twice"
        - "serialized revision-2 record contains no scalar-share field names"
      breaking_change: "Bump the pool protocol/storage generation and reject or destructively tombstone old secret-bearing Committed records at the request boundary."
  - id: CF-LC-002
    severity: MEDIUM
    title: "Failure, expiry, and retirement coverage stops at the pure reducer"
    spec_claim: "Validation failure, timeout, persistence failure, material expiry, and epoch retirement all become permanent tombstones."
    code_finding: "After reserve succeeds, reserved_material validation, prepare-response construction, prepared-bundle construction, or response serialization can fail without DestroyReserved. AvailableRecord expiry and epoch retirement exist in router-ab-ecdsa-pool, but the Cloudflare command enum exposes neither transition."
    match_type: code_weaker_than_spec
    confidence: 0.99
    reasoning: "Most fallible tail operations are expected to be infallible after prior validation, yet the function types and branches explicitly permit failure. The persisted state is left live until an unavailable recovery action occurs."
    evidence:
      spec:
        - "persistent-pool-lifecycle-v1.md:53-65"
        - "online-lifecycle-v1.md:94-108"
      code:
        - "lib.rs:9798-9844"
        - "ecdsa_pool_lifecycle.rs:80-161"
        - "router-ab-ecdsa-pool/src/lib.rs:244-269"
    exploitability:
      prerequisites: "An internal invariant/configuration failure, serialization failure, expired available record, or activation/key epoch retirement."
      sequence:
        - "The record reaches Available or Reserved."
        - "A later local step rejects or the epoch expires/retires."
        - "The route returns an error or future reserve returns MaterialExpired."
        - "No terminal replacement is issued."
      impact: "At least one record is stranded for each affected pair. Reuse through the normal typed path remains blocked by revision and expiry checks. Secret retention and pool capacity loss continue until manual storage action or generation retirement."
      economic_impact: "Direct proven transaction loss: 0. Availability loss: 1 pair per affected failure. Refill compute and storage are wasted once per stranded pair."
    remediation:
      design: "Add ExpireAvailable and Retire commands, implement a prefix-indexed cleanup/alarm, and route every post-reserve error through a best-effort terminal mutation whose failure is recorded as a storage incident."
      code_example: |
        let prepared = build_prepared(...);
        if let Err(error) = prepared {
            destroy_reserved(env, runtime, identity, TombstoneReason::Rejected, now).await?;
            return Err(error);
        }
      tests:
        - "each fallible prepare tail branch persists Rejected"
        - "expired Available becomes MaterialExpired"
        - "key and activation retirement tombstone all matching states"
        - "cleanup is idempotent when a tombstone already exists"
      breaking_change: "Add new command variants under a new protocol/storage generation; no compatibility alias is needed."
  - id: CF-LC-003
    severity: MEDIUM
    title: "Point-in-time restore can revive pre-tombstone material"
    spec_claim: "Backup and rollback cannot restore consumed, expired, aborted, or committed material to Available."
    code_finding: "Pool state, tombstones, and active SigningWorker state share one restore-capable SQLite Durable Object. Every authority checked by the pool record is restored with the record; no non-restorable monotonic epoch floor is consulted by each mutation."
    match_type: missing_in_code
    confidence: 0.95
    reasoning: "The design document names this footgun explicitly. Current deployment work leaves restore and fail-closed rollback drills open. A restore to a point before reservation can make an already consumed pair Available again."
    evidence:
      spec:
        - "refactor-89-slimmer-near-ecdsa.md:766-768"
        - "refactor-89-slimmer-near-ecdsa.md:891"
      code:
        - "wrangler.signing-worker.toml:9-16"
        - "durable_object/mod.rs:267-293"
        - "durable_object/worker_storage.rs:716-732"
      deployment_gap: "docs/router-ab/deployment.md:200-201 leaves restore and fail-closed rollback drills open."
    exploitability:
      prerequisites: "An operator or platform restore of the SigningWorker Durable Object to a point before a record's terminal transition, without a separately advanced epoch."
      sequence:
        - "A pair is consumed and tombstoned."
        - "The DO is restored to a snapshot where the pair is Available."
        - "The restored active-state record also validates the old pool scope."
        - "A request in the restored authority generation can reserve the pair again."
      impact: "One restored pre-tombstone record can be reused once for each repeated rollback. This violates the one-use proof assumption. A complete forged-transaction path still requires the matching Client half and authorized Client participation."
      economic_impact: "Potential duplicate-use count equals the number of restored pair records, multiplied by the number of accepted rollback cycles. Dollar loss is workload-dependent and not derivable from repository evidence."
    remediation:
      design: "Store a monotonic deployment/key generation in an authority that is not rolled back with the pool, require it on every mutation, and advance it before any restore. Destructively reject every record below the floor."
      code_example: |
        if record.deployment_generation < authoritative_generation_floor {
            return persist_tombstone(record, TombstoneReason::ActivationEpochRetired);
        }
      tests:
        - "restore an old Available snapshot under a newer authoritative floor"
        - "verify reserve burns instead of returning material"
        - "run the documented restore and rollback drill"
      breaking_change: "Bump the generation and empty/refill the one-use pool after the floor advances."
  - id: CF-LC-004
    severity: HIGH
    title: "Ed25519 Yao one-use claims lack crash, expiry, and rollback terminality"
    spec_claim: "The selected Yao lifecycle durably consumes one admitted session, survives crashes, rejects replay, and redelivers terminal ciphertext without reevaluation."
    code_finding: "The integrated start, stage, result, and duplex routes authenticate the same-account private edge and bind role, family, session, circuit, and directional frames. Both A and B persist Running before evaluation and reject a second normal claim; successful executions persist Completed and exact ciphertext. The state enum has no Failed, Expired, or Tombstone branch. Failure after Running is permanent, stored input/output never expires, and no non-restorable generation prevents point-in-time restore from reviving a pre-Running session."
    match_type: code_weaker_than_spec
    confidence: 1.0
    reasoning: "The normal concurrent-claim gap found in the earlier snapshot is closed. Production approval still requires a complete terminal state machine: current failures strand sessions and restores can defeat the local one-use marker because every authority is restored together."
    evidence:
      spec:
        - "docs/router-ab/ed25519-yao/implementation-plan.md:1183-1254"
        - "docs/router-ab/ed25519-yao/deployment.md:333-338"
      code:
        - "ed25519_yao_lifecycle.rs:63-69"
        - "ed25519_yao_lifecycle.rs:210-386"
        - "ed25519_yao_lifecycle.rs:537-647"
        - "ed25519_yao_websocket.rs:135-179"
      exhaustive_search: "Running and Completed now exist. No Failed, Expired, Destroyed, Tombstone, alarm, generation-floor, or delete path exists, and no Cloudflare test names the new session Durable Objects."
    exploitability:
      prerequisites: "A Worker crash/timeout during evaluation, or an operator/platform restore to a point before Running was persisted."
      sequence:
        - "The session is Staged and then durably claimed as Running."
        - "A role fails before storing Completed, leaving Running indefinitely; a normal retry rejects."
        - "Alternatively, restore revives the same session at Staged or absent."
        - "The restored session can execute again because no external generation floor dominates the restored status."
      impact: "A crash permanently denies the admitted ceremony and retains ciphertext. A restore can reevaluate a one-use role and invalidate the construction's replay assumption. No direct key recovery or forged signature was demonstrated under the passive P0 claim."
      economic_impact: "A crash wastes one full Yao attempt and strands one session. Each accepted restore replay consumes another full Yao computation and A/B transfer."
    remediation:
      design: "Keep the existing Staged-to-Running claim. Replace the split keys with one discriminated record that adds Failed, Expired, and Tombstone, records bounded failure evidence, and expires staged ciphertext. Enforce a non-restorable generation floor before every claim. Retain only exactly redeliverable recipient ciphertext plus audit metadata after completion. If cross-account product deployment is selected later, promote the existing fixed WebSocket transport without changing session identity."
      code_example: |
        enum DeriverBYaoSessionState {
            Staged { input: EncryptedInput, expires_at_ms: u64 },
            Executing { binding: ExecutionBinding, claimed_at_ms: u64 },
            Completed { encrypted_output: RoleExecution, completed_at_ms: u64 },
            Failed { reason: TerminalReason, failed_at_ms: u64 },
            Tombstone { audit_digest: Digest32 },
        }
      tests:
        - "two concurrent duplex claims have exactly one winner"
        - "disconnect and execution failure become terminal without reevaluation or indefinite Running"
        - "exact completed ciphertext is redeliverable without rerunning Yao"
        - "expired, restored, and already-completed sessions cannot execute"
        - "same-account and cross-account connectors preserve the same transcript identity"
      breaking_change: "Bump the Yao session storage generation and terminally reject every split-key Staged/Running record at the boundary."
  - id: CF-LC-005
    severity: MEDIUM
    title: "SigningWorker reservation leases are not independently capped"
    spec_claim: "A reservation expires at the minimum of request expiry, material expiry, and now plus 60 seconds."
    code_finding: "Prepare passes request.expires_at_ms as both lease_expires_at_ms and request_expires_at_ms. Reserve checks material expiry, but no now-plus-60-seconds cap is applied."
    match_type: code_weaker_than_spec
    confidence: 1.0
    reasoning: "A valid internal caller can create a reservation whose duration follows an overly long request expiry. Missing recovery makes the longer lease more consequential."
    evidence:
      spec:
        - "refactor-89-slimmer-near-ecdsa.md:1407-1431"
      code:
        - "lib.rs:9757-9766"
        - "router-ab-ecdsa-pool/src/lib.rs:217-233"
    exploitability:
      prerequisites: "An authenticated internal request with an expiry more than 60 seconds in the future."
      sequence:
        - "Prepare validates the request."
        - "Reserve persists request expiry as the lease expiry."
        - "The pair remains reserved for the caller-selected duration unless finalized."
      impact: "One pair can be withheld per admitted long-lived reservation. No unauthorized signature or cross-identity access follows directly."
      economic_impact: "Pool capacity and refill compute are consumed for the excess lease duration."
    remediation:
      design: "Compute the lease at the request boundary from trusted current time, material expiry, request expiry, and a fixed 60-second maximum. Persist and return that derived value."
      tests:
        - "request expiry below 60 seconds controls the lease"
        - "request expiry above 60 seconds is capped"
        - "material expiry below both values controls the lease"
      breaking_change: "No compatibility behavior is required; enforce the cap for every new reservation."
  - id: CF-LC-006
    severity: MEDIUM
    title: "SigningWorker Yao activation retains duplicate and superseded scalar material"
    spec_claim: "SigningWorker activation rejects replay, promotes only continuity-preserving recovery, disposes failed candidates, and tombstones the retired credential."
    code_finding: "Registration and recovery use an authenticated stable-identity Durable Object and exact package matching. RegistrationStaged and RecoveryStaged persist plaintext candidate material; Active persists the plaintext scalar indefinitely. persist_active_output then stores the same scalar again in the server-output Durable Object. Recovery keeps old and candidate material together until promotion, while prior material-handle records are never deleted or tombstoned."
    match_type: code_weaker_than_spec
    confidence: 0.99
    reasoning: "Normal signing resolves the active server-output index and no route returning stale material was demonstrated. The duplication and absence of terminal cleanup expand the durable secret footprint, preserve failed candidates, and leave superseded shares recoverable from storage or backups."
    evidence:
      spec:
        - "docs/router-ab/ed25519-yao/implementation-plan.md:31"
        - "docs/router-ab/ed25519-yao/implementation-plan.md:4133-4146"
      code:
        - "ed25519_yao_signing_worker.rs:146-254"
        - "ed25519_yao_signing_worker.rs:446-614"
        - "ed25519_yao_signing_worker.rs:775-864"
        - "durable_object/worker_storage.rs:121-191"
      exhaustive_search: "SigningWorkerYaoDurableStateV1 has no Failed, Expired, Abandoned, Retired, or Tombstone branch. The Ed25519 material-handle path has put/get behavior and no delete or retirement caller."
    exploitability:
      prerequisites: "Compromise of either SigningWorker Durable Object namespace, its backups/PITR generation, or an internal path capable of reading an old exact material descriptor."
      sequence:
        - "A registration or recovery candidate is combined into plaintext scalar material."
        - "The orchestration DO persists it in Staged or Active."
        - "Activation persists a second scalar copy under a material handle."
        - "Recovery or failure does not delete the old/candidate copy."
      impact: "The number and lifetime of durable copies of one SigningWorker share increase. A single share does not reconstruct the client key, but compromise of the SigningWorker share weakens the two-party threshold to the remaining Client share and violates the intended retention boundary."
      economic_impact: "Direct transaction loss is unproven. Incident scope and rotation cost grow with every retained candidate and prior activation."
    remediation:
      design: "Make the orchestration DO persist public digests and opaque server-output handles after activation. Move the scalar exactly once into the server-output record, zeroize/drop the candidate, and replace pending/staged/retired states with material-free terminal evidence. Delete or cryptographically retire prior handles during recovery under a non-restorable epoch floor."
      tests:
        - "serialized Active orchestration state contains no scalar field"
        - "recovery promotion makes the prior handle unreadable"
        - "failed and expired candidates become material-free tombstones"
        - "crash between output persistence and orchestration commit is idempotent and leaves one scalar copy"
      breaking_change: "Use a new activation storage generation and destructively retire all existing duplicate candidate records."
```

---

## 7. Missing invariants

- No live invariant establishes that revision-2 persisted state contains zero
  secret material.
- No live invariant guarantees every Reserved or Committed record is discovered
  after process termination.
- No Cloudflare adapter invariant maps available expiry, activation retirement,
  key retirement, cancellation, peer abort, or persistence failure to a
  concrete command caller.
- No independently stored monotonic generation rejects a restored record.
- No live invariant caps a reservation independently of caller-supplied expiry.
- No source guard prevents `Debug` formatting of the serializable
  secret-bearing lifecycle types.
- The Yao session proves one normal `Staged -> Running` claim, while no
  `Running -> Failed|Expired|Tombstone` transition or rollback floor exists.
- No SigningWorker activation invariant limits plaintext scalar material to one
  Durable Object record or terminally destroys failed/superseded candidates.

---

## 8. Incorrect logic

No incorrect ECDSA arithmetic was found in the reviewed delta. Exact
request-digest mismatch burns before committed material access, and the final
signature is withheld until terminal persistence.

The incorrect lifecycle claims are architectural:

- the ECDSA documentation says the concrete Cloudflare adapter has destructive
  recovery and retirement evidence, while only the pure transition exists; and
- the Yao product contract requires crash/restore-safe terminal consumption,
  while the Cloudflare adapter stops at `Running` on failure and has no
  non-restorable generation; and
- the Yao product contract retires old SigningWorker material, while the
  Cloudflare activation path retains duplicate and prior scalar records.

These are covered by `CF-LC-001`, `CF-LC-002`, `CF-LC-004`, and `CF-LC-006`.

---

## 9. Math inconsistencies

No mathematical inconsistency was found. The adapter uses domain-separated,
length-prefixed SHA-256:

```text
binding = SHA-256(domain || len(field_0) || field_0 || ... || len(field_n) || field_n)
```

`pool_key` includes scope digest, pair, fixed role, key epoch, activation epoch,
and fixed protocol at `ecdsa_pool_lifecycle.rs:855-898`.
`reservation_binding` independently binds scope, pair, and request digest at
lines 900-921. The public-coin equations remain owned by the previously
approved online construction.

---

## 10. Flow/state-machine mismatches

Implemented success flow:

```text
Available r0
  -> Reserve DO write
Reserved r1 + secret
  -> Commit DO write
Committed r2 + secret
  -> online kernel
  -> Finish DO write
Tombstone r3, no secret
  -> HTTP output
```

Required crash-safe flow:

```text
Available r0
  -> Reserved r1
  -> atomic destructive take
CommittedTaken r2, no persisted secret
  -> online kernel
  -> Tombstone r3

startup/alarm:
Reserved r1       -> CrashRecovery tombstone
CommittedTaken r2 -> AmbiguousDelivery tombstone
```

The success-path ordering matches. The interruption, expiry, retirement, and
restore branches do not.

Implemented Yao B-side flow:

```text
absent
  -> Stage
Staged + encrypted input
  -> ReadStaged
  -> Begin DO write
Running + encrypted input
  -> one duplex evaluation
  -> Complete
Completed + encrypted input + encrypted output
  -> repeatable ReadResult

failure after Begin:
Running forever

point-in-time restore:
Staged/absent -> may execute the same admitted session again
```

Required flow:

```text
Absent -> Staged -> Executing -> Completed
                    \-> Failed

Expired/failed/completed/restored sessions cannot execute again.
Completed ciphertext may be redelivered without reevaluation.
```

Implemented SigningWorker activation flow:

```text
Pending(A package)
  -> Staged(A+B packages + plaintext candidate)
  -> server-output DO stores scalar + active index
  -> Active(plaintext scalar) in orchestration DO

RecoveryStaged retains old scalar + candidate scalar.
Prior server-output material handles are not retired.
```

---

## 11. Access-control drift

ECDSA access control is aligned:

- `strict_worker/signing_worker.rs:8-10` authenticates the internal service
  request before path dispatch.
- Pool mutations require the SigningWorker server-output scope at
  `durable_object/mod.rs:3863-3872`.
- `CloudflareDurableObjectCallV1::validate` rejects binding/scope mismatch at
  lines 4753-4769.
- Ordinary ECDSA prepare/finalize contain no Deriver call and the lifecycle
  matrix tests pass.

The same-account Yao private edge is authenticated: strict Deriver entrypoints
verify the internal-service secret before dispatch, and A attaches that secret
to the B WebSocket upgrade. Public Router admission is composed by the server
Router. The local `Running` claim rejects a second normal session claim.
Restore can revive the pre-claim generation because replay authority is stored
beside the session. The fixed cross-account WebSocket connector exists in the
benchmark deployment and has a successful two-account campaign. It is not
promoted into this scoped product adapter.

---

## 12. Undocumented behavior

- The Durable Object storage key uses a readable subset of identity
  (`wallet/session/SigningWorker/pair`) rather than the full hashed `PoolRecordKey`
  at `durable_object/mod.rs:4958-4969`. Complete record validation makes a
  collision fail closed, so this is stronger availability isolation only if
  path components are canonical. The spec is silent on the physical key shape.
- Exact duplicate `PutAvailable` is idempotent and returns `stored: false` at
  `ecdsa_pool_lifecycle.rs:345-349`. The spec asks for idempotent tombstone
  observation but does not explicitly state admission idempotency. This is a
  safe undocumented code path.
- `FinishCommitted` accepts terminal reasons beyond success/rejection. The
  production route emits only those two reasons. The broader reducer surface is
  safe and should be narrowed if no recovery owner needs the extra variants.
- The WebSocket EOF marker is a raw fixed byte string outside the directional
  envelope. The decoder accepts it only as terminal EOF, while the spec does
  not define this exact marker.

---

## 13. Ambiguity hotspots

- The pool specification permits a persisted Committed state, while Refactor 89
  invariant 7 says entering committed-use atomically transfers material once
  into memory and replaces storage with a tombstone. The stronger product
  invariant should control.
- Cloudflare input/output gates establish serial storage behavior, but they do
  not supply application-level crash recovery or restore monotonicity.
- `PersistenceFailure` cannot always be persisted by the same failing store.
  The spec should distinguish an attempted terminal mutation plus an external
  incident/generation burn from a guaranteed local write.
- The same-account connector supplies internal-service authentication, a
  bounded role-execution/result wait, and one normal durable claim. Phase 11
  still correctly leaves rollback safety, crash/failure terminality, retention,
  and deployed replay evidence open. Cross-account promotion still has a newer
  reconnect defect and incomplete Deriver B CPU/operational acceptance
  evidence; the transport implementation and original deployed campaign are
  complete.

---

## 14. Recommended remediations

Priority order:

1. Replace secret-bearing `Committed` persistence with atomic destructive
   `CommitAndTake`. This yields the largest security improvement and removes the
   crash-time secret-retention window.
2. Add a concrete recovery/cleanup owner. Use a DO alarm or explicit bounded
   prefix scan to tombstone interrupted, expired, and retired states. Do not
   delete records; retain terminal evidence.
3. Add a non-restorable generation floor and make restore advance the floor
   before serving traffic.
4. Route every fallible post-reserve branch through terminal destruction.
5. Enforce the fixed 60-second maximum reservation lease at the request
   boundary.
6. Add negative source tests for secret `Debug` formatting and serialization of
   revision-2 state.
7. Keep the Yao `Staged -> Running -> Completed` claim and complete it with
   `Failed|Expired|Tombstone`, bounded retention, a non-restorable generation
   floor, and fault/concurrency tests. If independent-account deployment is
   selected, promote the existing cross-account WebSocket connector behind the
   same authenticated transport contract after its reconnect defect and
   operational evidence gate close.
8. Make SigningWorker activation move the scalar into one authoritative
   server-output record. Persist only public orchestration evidence, and
   terminally retire failed candidates and superseded material handles.

The narrowest acceptable ECDSA 80/20 closure is items 1-5 plus focused failure
injection. Yao production promotion additionally requires items 7-8. Broad
formal verification can remain deferred.

---

## 15. Documentation update suggestions

- Change `persistent-pool-lifecycle-v1.md` status from complete/fault-tested to
  partial Cloudflare integration until `CF-LC-001` through `CF-LC-003` close.
- Change `POOL-STORE-01`, `OL-PERSIST-01`, and Refactor 89 Local Phase B from
  full/complete to partial.
- Add the exact `CommittedTaken` material-free storage invariant.
- Define how `PersistenceFailure` is evidenced when the local store cannot
  write: external generation invalidation, alarm, and incident receipt.
- Define the restore generation floor and required operator sequence.
- Mark the live same-account Yao adapter as development-only until rollback,
  failure persistence, and bounded scalar/ciphertext retention are complete.
  Track cross-account promotion separately from transport implementation.

---

## 16. Final risk assessment

Decision: **REJECTED PENDING REMEDIATION**

| Dimension | Assessment |
| --- | --- |
| Exact ECDSA identity and request binding | Low residual risk |
| Stale/replay resistance in normal DO execution | Low residual risk |
| Tombstone-before-final-output ordering | Low residual risk |
| Crash-time material destruction | High risk; incomplete |
| Expiry, retirement, and failure cleanup | Medium risk; incomplete |
| Reservation lease bound | Medium risk; caller expiry is not capped |
| Backup/restore one-use safety | Medium risk; incomplete operational authority |
| Generic threshold-ECDSA dependency removal | Low residual risk |
| Ed25519 Yao private-edge authentication | Low residual risk for same-account internal service |
| Ed25519 Yao normal one-use claim | Low residual risk within the current DO generation |
| Ed25519 Yao crash/rollback terminality | High risk; incomplete |
| Ed25519 Yao SigningWorker material retention | Medium risk; duplicate and prior scalar records persist |
| Ed25519 Yao cross-account transport | Implemented and deployed in the benchmark; product promotion, reconnect repair, and final operational evidence remain deferred |

The current implementation fails closed with respect to duplicate output in
the inspected normal path. It does not satisfy the stronger persistence claim
that every uncertain or restored state is irreversibly burned. Refactor 89
formal closure should wait for a material-free commit, live destructive
recovery, and rollback-generation enforcement, followed by a narrow independent
review of those exact bytes. Yao production promotion separately requires
terminal crash/expiry states, rollback-generation enforcement, single-copy
SigningWorker material, and focused concurrency/fault evidence. Cross-account
transport does not require a new implementation; it requires promotion work
only if the independent-account product topology is selected.
