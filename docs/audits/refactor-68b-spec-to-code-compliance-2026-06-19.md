# Refactor 68B Spec-To-Code Compliance Audit

Date: 2026-06-19

Scope: Router A/B local topology cleanup, public Router ownership, Wallet
Session signing admission, replay/quota/abuse checks, private SigningWorker
forwarding, Caddy topology, and local worker orchestration.

Result: No open Critical, High, or Medium divergences in the scoped audit.

## 1. Executive Summary

The scoped Router A/B implementation matches the 68B spec corpus for the local
runtime/package topology:

- Caddy forwards `https://localhost:9444` to one Router upstream.
- The SDK Router/API server owns the public Router A/B signing route table.
- Local Rust workers expose only Deriver A, Deriver B, and SigningWorker roles.
- Public Ed25519 and ECDSA-HSS signing routes require Wallet Session validation,
  request/scope admission, quota/abuse admission, replay reservation, and private
  SigningWorker forwarding.
- Source guards cover the one-upstream Caddy topology and reject the deleted
  local public Rust Router profile.

No divergence findings were opened. Residual deployment evidence remains outside
this audit scope and is already tracked in the Router A/B deployment phases.

## 2. Documentation Sources Identified

Spec corpus normalized from:

- `docs/refactor-68B-router-cleanup.md`
- `docs/router-a-b-local-dev.md`
- `docs/router-a-b-SPEC.md`
- `docs/router-a-b-deployment.md`

The minimum corpus named in `docs/refactor-68B-router-cleanup.md` lines 317-323
also includes broader cleanup/signing docs. This audit used the excerpts that
define public Router ownership, Wallet Session auth, replay, quota/abuse,
request binding, private worker boundaries, and Caddy topology.

## 3. Spec Intent Breakdown

```yaml
spec_ir:
  - id: S1
    source_document: docs/refactor-68B-router-cleanup.md
    source_section: Goal and Target Topology, lines 7-23
    semantic_type: topology_invariant
    spec_excerpt: "Make the Router the single browser-facing server/worker... Caddy forwards every request to one local Router server... Caddy must not path-split /router-ab/* or /router-ab/ecdsa-hss/sign* to a second public upstream."
    normalized_form: One browser-facing Router route table owns all public routes; Caddy is TLS-only and must use one upstream.
    confidence: 0.97
  - id: S2
    source_document: docs/refactor-68B-router-cleanup.md
    source_section: Target local ports, lines 25-36
    semantic_type: topology_ports
    spec_excerpt: "Router server/worker | 9090 | behind Caddy only... Deriver A 9091 private... Deriver B 9092 private... SigningWorker 9093 private."
    normalized_form: Public HTTPS enters at 9444, Router binds 9090, private workers bind 9091-9093.
    confidence: 0.96
  - id: S3
    source_document: docs/refactor-68B-router-cleanup.md
    source_section: Invariants, lines 52-64
    semantic_type: security_requirement
    spec_excerpt: "No public route is implemented by Caddy path selection... Router A/B signing-capable state requires Wallet Session bearer JWT auth... Deriver and SigningWorker routes are private service routes with internal service auth."
    normalized_form: Public signing cannot depend on proxy path selection; signing requires bearer Wallet Session; private routes require internal auth.
    confidence: 0.96
  - id: S4
    source_document: docs/refactor-68B-router-cleanup.md
    source_section: Phase 3, lines 98-121
    semantic_type: implementation_requirement
    spec_excerpt: "the main Router runtime is the SDK server route layer... Delete the separate public Rust Router role..."
    normalized_form: `packages/sdk-server-ts` plus `apps/web-server` must own public Router routes; public Rust Router role must be deleted or rejected.
    confidence: 0.96
  - id: S5
    source_document: docs/refactor-68B-router-cleanup.md
    source_section: Phase 4, lines 141-148
    semantic_type: signing_flow_requirement
    spec_excerpt: "Add main Router Wallet Session, scope, SigningWorker id, and expiry checks before active Ed25519 and ECDSA-HSS signing requests are forwarded... Forward... only to private SigningWorker routes with x-router-ab-internal-service-auth."
    normalized_form: Router must validate Wallet Session/scope/worker/expiry before private SigningWorker forward, and forward with internal-service auth.
    confidence: 0.96
  - id: S6
    source_document: docs/refactor-68B-router-cleanup.md
    source_section: Phase 4, lines 149-158
    semantic_type: request_binding_requirement
    spec_excerpt: "Preserve exact request-binding digest semantics... bind canonical typed protocol bytes."
    normalized_form: Ed25519 and ECDSA-HSS admission must bind typed canonical request data, not opaque or stale digest-only state.
    confidence: 0.93
  - id: S7
    source_document: docs/refactor-68B-router-cleanup.md
    source_section: Phase 4, lines 159-196
    semantic_type: admission_requirement
    spec_excerpt: "Preserve replay, expiry, quota, abuse, and abandoned-prepare cleanup semantics... typed normal-signing admission boundary for project-policy, quota, and abuse decisions."
    normalized_form: Main Router route layer must reject replay/expiry/quota/abuse before unsafe forwarding.
    confidence: 0.95
  - id: S8
    source_document: docs/router-a-b-local-dev.md
    source_section: Target local shape, lines 5-17
    semantic_type: actor_boundary
    spec_excerpt: "one SDK Router/API server plus three independently started private workers: SDK Router/API server; Deriver A; Deriver B; SigningWorker."
    normalized_form: Local dev topology has one public server and three private workers.
    confidence: 0.98
  - id: S9
    source_document: docs/router-a-b-local-dev.md
    source_section: Normal Signing Flow, lines 252-259
    semantic_type: workflow
    spec_excerpt: "Router reserves replay and checks local admission policy... forwards the active-signing request to SigningWorker... Deriver A and Deriver B receive zero requests."
    normalized_form: Normal signing hot path is Client to Router to SigningWorker only; Derivers stay idle.
    confidence: 0.94
  - id: S10
    source_document: docs/router-a-b-SPEC.md
    source_section: Target Model and Wallet Session Credential, lines 41-59 and 141-166
    semantic_type: auth_requirement
    spec_excerpt: "The SDK should send only the Wallet Session credential... verifies Wallet Session... validates account, session, policy, quota, replay, and SigningWorker scope... Wallet Session credential should not carry a per-signature intentDigest."
    normalized_form: Public normal-signing auth is Wallet Session bearer credential plus typed request validation.
    confidence: 0.95
  - id: S11
    source_document: docs/router-a-b-SPEC.md
    source_section: Request shape, lines 126-137
    semantic_type: request_binding_requirement
    spec_excerpt: "Router computes intent_digest... signing_payload_digest... admitted_signing_digest... validates that the typed intent, payload, account, session, prepare/finalize binding, and SigningWorker scope all agree."
    normalized_form: Router computes request authority from typed request data and Wallet Session claims.
    confidence: 0.93
  - id: S12
    source_document: docs/router-a-b-deployment.md
    source_section: Common invariants, lines 100-105 and 665-672
    semantic_type: deployment_invariant
    spec_excerpt: "Router is the only public wallet backend endpoint. Router handles auth, policy, rate limits, replay, and public lifecycle state... Router can reserve replay state and persist public lifecycle state."
    normalized_form: Deployment topology preserves one public Router and Router-owned replay/lifecycle responsibilities.
    confidence: 0.93
```

## 4. Code Behavior Summary

```yaml
code_ir:
  - id: C1
    file: apps/web-client/Caddyfile
    function: localhost:9444 site block
    lines: 38-51
    visibility: public_local_https
    behavior:
      preconditions:
        - "Request reaches localhost:9444."
      state_reads: []
      state_writes: []
      computations:
        - "Adds CORS response headers for allowed local origins, lines 40-44."
      external_calls:
        - "reverse_proxy to 127.0.0.1:9090, line 46."
      postconditions:
        - "The whole Router origin goes to one upstream."
    invariants_enforced:
      - "No path-specific Router A/B proxy handler appears in this block."
  - id: C2
    file: crates/router-ab-dev/scripts/dev-local-workers.mjs
    function: workerRoles and startup orchestration
    lines: 34-82, 152-163, 1161-1178
    visibility: repo_script
    behavior:
      preconditions:
        - "Generated env files must exist or be materialized, lines 176-210."
      state_reads:
        - "workerRoles contains deriver-a, deriver-b, signing-worker only, lines 34-82."
      state_writes:
        - "Starts Router server, then private workers, lines 152-163."
      external_calls:
        - "Runs cargo init/build and managed child processes."
      postconditions:
        - "Router server plus private workers are the managed local services."
    invariants_enforced:
      - "No worker role entry for router in workerRoles."
  - id: C3
    file: crates/router-ab-dev/src/bin/router_ab_local_worker.rs
    function: parse_args
    lines: 67-88
    visibility: local_worker_binary
    behavior:
      preconditions:
        - "--role must be supplied with a valid LocalServiceRoleV1 label, lines 73-78."
      state_reads: []
      state_writes: []
      computations:
        - "Rejects LocalServiceRoleV1::Router, lines 79-81."
      external_calls: []
      postconditions:
        - "The worker binary cannot start as a public Router role."
    invariants_enforced:
      - "Private worker binary exposes no public Router service."
  - id: C4
    file: crates/router-ab-dev/src/bin/local_dev_process/mod.rs
    function: LOCAL_WORKER_PROCESS_SPECS and write_materialized_envs_with_urls
    lines: 38-60, 286-302
    visibility: local_process_helper
    behavior:
      preconditions:
        - "Materialization plan exists, line 287."
      state_reads:
        - "Process specs include Deriver A, Deriver B, SigningWorker, lines 38-60."
      state_writes:
        - "Writes env files with Router, Deriver A/B, and SigningWorker URLs, lines 291-302."
      external_calls:
        - "Filesystem writes."
      postconditions:
        - "Detached worker process set excludes public Router."
    invariants_enforced:
      - "Only private worker roles are managed as Rust local workers."
  - id: C5
    file: packages/sdk-server-ts/src/router/express/routes/thresholdEd25519.ts
    function: handleRouterAbEd25519NormalSigningRoute
    lines: 196-244, 263-347, 568-604
    visibility: public_express_route
    behavior:
      preconditions:
        - "Request body is normalized from req.body, lines 200-205."
      state_reads:
        - "Wallet Session token inputs read from body, headers, and session, lines 211-215."
        - "Threshold service and private SigningWorker config read after admission, lines 246-300."
      state_writes:
        - "Prepare phase reserves replay state, lines 320-337."
      computations:
        - "Validates Wallet Session, lines 211-227."
        - "Validates normal-signing scope, lines 229-243."
        - "Evaluates admission, lines 263-283."
      external_calls:
        - "Private SigningWorker JSON POST, lines 340-347."
      postconditions:
        - "Prepare, presign-pool prepare, and finalize public routes share the validated handler, lines 568-604."
    invariants_enforced:
      - "Missing Wallet Session returns before threshold service access."
      - "Admission and replay checks happen before private forward."
  - id: C6
    file: packages/sdk-server-ts/src/router/express/routes/thresholdEcdsa.ts
    function: handleRouterAbEcdsaHssNormalSigningRoute
    lines: 520-666, 1068-1088
    visibility: public_express_route
    behavior:
      preconditions:
        - "Request body is normalized from req.body, lines 523-527."
      state_reads:
        - "Wallet Session inputs read from body, headers, session, lines 534-538."
        - "Threshold service and private SigningWorker config read after validation/admission, lines 575-630."
      state_writes:
        - "Prepare phase reserves replay state, lines 636-655."
      computations:
        - "Validates Wallet Session, lines 534-549."
        - "Validates prepare/finalize admission, lines 552-572."
        - "Evaluates quota/abuse/project-policy admission, lines 592-613."
      external_calls:
        - "Private SigningWorker JSON POST, lines 657-661."
      postconditions:
        - "Prepare and finalize public routes are registered on the main Router, lines 1068-1088."
    invariants_enforced:
      - "No ECDSA-HSS private forward before Wallet Session, scope, admission, and replay checks."
  - id: C7
    file: packages/sdk-server-ts/src/router/routerAbPrivateSigningWorker.ts
    function: validateRouterAbEd25519NormalSigningRequestScope
    lines: 336-413
    visibility: shared_server_validator
    behavior:
      preconditions:
        - "Claims are already parsed as RouterAbEd25519WalletSessionClaims."
      state_reads:
        - "Reads scope request_id, account_id, session_id, signing_worker_id, lines 340-344."
      state_writes: []
      computations:
        - "Rejects missing scope fields, lines 345-354."
        - "Rejects account/session drift, lines 355-364."
        - "Rejects SigningWorker drift, lines 365-374."
        - "Rejects invalid or expired expires_at_ms, lines 376-405."
      external_calls: []
      postconditions:
        - "Returns sessionId, requestId, expiresAtMs for downstream admission, lines 407-412."
    invariants_enforced:
      - "Ed25519 request scope must match Wallet Session claims."
  - id: C8
    file: packages/sdk-server-ts/src/router/routerAbPrivateSigningWorker.ts
    function: buildRouterAbEcdsaHssPrivateSigningWorkerBody and validators
    lines: 266-313, 415-535
    visibility: shared_server_validator
    behavior:
      preconditions:
        - "Input phase is prepare or finalize."
      state_reads:
        - "Reads ECDSA-HSS normal-signing scope from Wallet Session claims, lines 415-420 and 477-482."
      state_writes: []
      computations:
        - "Parses typed ECDSA-HSS request and computes request digest, lines 289-303."
        - "Builds trusted_admission with scope, request digest, signing digest, and expiry, lines 292-311."
        - "Rejects missing Router A/B normal-signing state, scope drift, expired request, and Wallet Session expiry drift, lines 420-535."
      external_calls:
        - "Digest functions for canonical ECDSA-HSS typed requests."
      postconditions:
        - "Private SigningWorker body contains parsed request plus trusted admission."
    invariants_enforced:
      - "ECDSA-HSS request binding and scope are carried into private worker request."
  - id: C9
    file: packages/sdk-server-ts/src/router/routerAbNormalSigningAdmissionStore.ts
    function: createRouterAbNormalSigningAdmissionAdapter
    lines: 400-470
    visibility: shared_server_adapter
    behavior:
      preconditions:
        - "Input contains normalized curve, phase, claims, scope, requestId, expiry, and runtime policy."
      state_reads:
        - "Reads project policy, abuse, and quota store decisions, lines 415-449."
      state_writes:
        - "Delegates quota reservation to store, line 449."
      computations:
        - "Rejects expired request, lines 407-413."
        - "Maps project-policy, abuse, rate-limit, and quota outcomes to route failures, lines 415-468."
      external_calls:
        - "Project policy, abuse, and quota store interfaces."
      postconditions:
        - "Returns ok only after all admission branches allow or reuse existing quota."
    invariants_enforced:
      - "Quota/abuse/project-policy are evaluated before route forwarding."
  - id: C10
    file: packages/sdk-server-ts/src/core/ThresholdService/routerAb/internalServiceHttp.ts
    function: postRouterAbInternalServiceJson
    lines: 1-69
    visibility: shared_server_http_client
    behavior:
      preconditions:
        - "authToken must normalize to printable non-empty ASCII, lines 9-15."
      state_reads: []
      state_writes: []
      computations:
        - "Adds x-router-ab-internal-service-auth header, lines 34-42."
      external_calls:
        - "POST to private service URL through fetchImpl, lines 34-43."
      postconditions:
        - "Returns discriminated HTTP/network/JSON result, lines 44-69."
    invariants_enforced:
      - "Private service forwarding carries internal service auth."
  - id: C11
    file: tests/unit/routerAbNormalSigningSdk.guard.unit.test.ts
    function: Router topology guards
    lines: 84-178
    visibility: source_guard
    behavior:
      preconditions:
        - "Reads Caddyfile, package.json, dev-local-workers, and worker source."
      state_reads:
        - "Asserts one reverse_proxy in localhost:9444 block, lines 84-103."
        - "Asserts no deleted router scripts and three private worker roles, lines 132-169."
        - "Asserts worker rejects public router role, lines 171-176."
      state_writes: []
      computations:
        - "Searches forbidden markers and worker role literals."
      external_calls: []
      postconditions:
        - "Source guard fails on Caddy path split or old public Rust Router topology."
    invariants_enforced:
      - "One public Router server plus three private workers."
  - id: C12
    file: tests/relayer/router-ab-normal-signing-auth-boundary.test.ts
    function: Auth, replay, quota, and abuse tests
    lines: 355-430, 594-855
    visibility: relayer_test
    behavior:
      preconditions:
        - "Creates focused Router route harnesses."
      state_reads:
        - "Reads forwarded call counts and private SigningWorker read counts."
      state_writes:
        - "Exercises replay-protected and admission-guarded route harnesses."
      computations:
        - "Asserts missing/legacy Wallet Session rejection before service access, lines 355-397."
        - "Asserts scope drift rejection before service access, lines 402-430."
        - "Asserts replayed prepare ids forward once, lines 594-698."
        - "Asserts quota/abuse failures do not read or forward to private SigningWorker, lines 700-855."
      external_calls:
        - "Local HTTP fetches against test server."
      postconditions:
        - "Regression coverage proves admission boundaries happen before private forwarding."
    invariants_enforced:
      - "Rejected public requests do not read private SigningWorker config or forward."
```

## 5. Full Alignment Matrix

```yaml
alignment_ir:
  - id: A1
    spec_ref: S1
    code_ref: [C1, C11]
    spec_claim: "Caddy forwards every request to one local Router server and must not path-split signing paths."
    code_behavior: "Caddy has one reverse_proxy to 127.0.0.1:9090; source guard counts one proxy and rejects signing path matchers."
    match_type: full_match
    confidence: 0.96
    reasoning: "The Caddy route block has a single reverse_proxy and the guard rejects the exact path-split markers named by the spec."
    evidence:
      spec_quote: "Caddy forwards every request to one local Router server... Caddy must not path-split..."
      spec_location: docs/refactor-68B-router-cleanup.md lines 16-23
      code_quote: "reverse_proxy 127.0.0.1:9090"
      code_location: apps/web-client/Caddyfile line 46; tests/unit/routerAbNormalSigningSdk.guard.unit.test.ts lines 84-103
  - id: A2
    spec_ref: S2
    code_ref: [C1, C2, C4]
    spec_claim: "Router uses 9090 behind Caddy; Deriver A/B and SigningWorker use private 9091-9093."
    code_behavior: "Caddy proxies to 9090; workerRoles define 9091, 9092, 9093; materializer replaces all four URLs."
    match_type: full_match
    confidence: 0.95
    reasoning: "The runtime ports match the documented target port table."
    evidence:
      spec_quote: "Router server/worker | 9090... Deriver A | 9091... Deriver B | 9092... SigningWorker | 9093"
      spec_location: docs/refactor-68B-router-cleanup.md lines 25-36
      code_quote: "defaultUrl: 'http://127.0.0.1:9091' ... '9092' ... '9093'"
      code_location: crates/router-ab-dev/scripts/dev-local-workers.mjs lines 34-82; apps/web-client/Caddyfile line 46
  - id: A3
    spec_ref: S3
    code_ref: [C5, C6, C10, C12]
    spec_claim: "Signing-capable state requires Wallet Session bearer JWT auth; private routes require internal service auth."
    code_behavior: "Public routes validate Wallet Session before threshold service access; private forward adds x-router-ab-internal-service-auth."
    match_type: full_match
    confidence: 0.94
    reasoning: "Both Ed25519 and ECDSA-HSS handlers return before service reads on auth failure and private POSTs normalize the internal auth header."
    evidence:
      spec_quote: "Router A/B signing-capable state requires Wallet Session bearer JWT auth... private service routes with internal service auth."
      spec_location: docs/refactor-68B-router-cleanup.md lines 59-62
      code_quote: "validateRouterAbEd25519WalletSessionTokenInputs... postRouterAbInternalServiceJson"
      code_location: packages/sdk-server-ts/src/router/express/routes/thresholdEd25519.ts lines 211-227; packages/sdk-server-ts/src/core/ThresholdService/routerAb/internalServiceHttp.ts lines 1-69
  - id: A4
    spec_ref: S4
    code_ref: [C2, C3, C4, C11]
    spec_claim: "SDK server route layer owns public Router routes; public Rust Router role is deleted."
    code_behavior: "Local scripts manage Router server and private worker roles; worker binary rejects Router role; guards reject old scripts."
    match_type: full_match
    confidence: 0.95
    reasoning: "No managed Rust worker spec contains Router and the binary fails explicit Router role selection."
    evidence:
      spec_quote: "the main Router runtime is the SDK server route layer... Delete the separate public Rust Router role"
      spec_location: docs/refactor-68B-router-cleanup.md lines 98-121
      code_quote: "no longer exposes a public router role"
      code_location: crates/router-ab-dev/src/bin/router_ab_local_worker.rs lines 77-82; crates/router-ab-dev/src/bin/local_dev_process/mod.rs lines 38-60
  - id: A5
    spec_ref: S5
    code_ref: [C5, C6, C10]
    spec_claim: "Validate Wallet Session, scope, SigningWorker id, expiry before forwarding; forward only to private SigningWorker with internal auth."
    code_behavior: "Handlers validate auth/scope/admission/replay before postRouterAbSigningWorkerJson; private POST adds internal-service auth."
    match_type: full_match
    confidence: 0.93
    reasoning: "Control flow orders validation and admission before private worker config and POST."
    evidence:
      spec_quote: "checks before active Ed25519 and ECDSA-HSS signing requests are forwarded... only to private SigningWorker routes with x-router-ab-internal-service-auth"
      spec_location: docs/refactor-68B-router-cleanup.md lines 141-144
      code_quote: "const forwarded = await postRouterAbSigningWorkerJson"
      code_location: packages/sdk-server-ts/src/router/express/routes/thresholdEd25519.ts lines 263-347; packages/sdk-server-ts/src/router/express/routes/thresholdEcdsa.ts lines 592-661
  - id: A6
    spec_ref: S6
    code_ref: [C8]
    spec_claim: "Request-binding digest semantics bind canonical typed protocol bytes."
    code_behavior: "ECDSA-HSS private body parses typed requests and computes canonical request digests for trusted_admission."
    match_type: full_match
    confidence: 0.9
    reasoning: "The audited ECDSA-HSS path carries request_digest and signing_digest into trusted_admission. Ed25519 digest-vector coverage is referenced by the plan and source guards but the full Rust vector suite was outside this scoped line inspection."
    evidence:
      spec_quote: "bind canonical typed protocol bytes"
      spec_location: docs/refactor-68B-router-cleanup.md lines 149-158
      code_quote: "requestDigest = await routerAbEcdsaHssEvmDigestSigningRequestDigestV1(request)"
      code_location: packages/sdk-server-ts/src/router/routerAbPrivateSigningWorker.ts lines 285-313
  - id: A7
    spec_ref: S7
    code_ref: [C5, C6, C9, C12]
    spec_claim: "Replay, expiry, quota, abuse, and admission semantics are preserved before private forwarding."
    code_behavior: "Route handlers reserve replay on prepare; adapter rejects expiry, project policy, abuse, rate limit, and quota; tests assert no private forward on failures."
    match_type: full_match
    confidence: 0.94
    reasoning: "Both route code and focused tests show replay/admission gates before private forwarding."
    evidence:
      spec_quote: "Preserve replay, expiry, quota, abuse... typed normal-signing admission boundary"
      spec_location: docs/refactor-68B-router-cleanup.md lines 159-196
      code_quote: "reserveRouterAbNormalSigningPrepareReplay... evaluateRouterAbNormalSigningAdmission"
      code_location: packages/sdk-server-ts/src/router/express/routes/thresholdEd25519.ts lines 263-337; packages/sdk-server-ts/src/router/routerAbNormalSigningAdmissionStore.ts lines 400-470
  - id: A8
    spec_ref: S8
    code_ref: [C2, C3, C4, C11]
    spec_claim: "Local dev topology has one SDK Router/API server plus three private workers."
    code_behavior: "dev-local-workers starts Router server plus workerRoles deriver-a, deriver-b, signing-worker; worker binary rejects router role."
    match_type: full_match
    confidence: 0.96
    reasoning: "The worker roles and rejection guard directly implement the target local shape."
    evidence:
      spec_quote: "one SDK Router/API server plus three independently started private workers"
      spec_location: docs/router-a-b-local-dev.md lines 5-13
      code_quote: "workerRoles = [deriver-a, deriver-b, signing-worker]"
      code_location: crates/router-ab-dev/scripts/dev-local-workers.mjs lines 34-82; tests/unit/routerAbNormalSigningSdk.guard.unit.test.ts lines 132-178
  - id: A9
    spec_ref: S9
    code_ref: [C5, C6, C12]
    spec_claim: "Normal signing path is Router to SigningWorker and Deriver A/B receive zero requests."
    code_behavior: "Public handlers forward to SigningWorker private paths only; auth-boundary tests verify rejected paths do not forward or read private service config."
    match_type: full_match
    confidence: 0.9
    reasoning: "The audited code has no Deriver call in normal-signing route handlers; tests focus on private SigningWorker forward counts."
    evidence:
      spec_quote: "Router forwards the active-signing request to SigningWorker... Deriver A and Deriver B receive zero requests."
      spec_location: docs/router-a-b-local-dev.md lines 252-259
      code_quote: "postRouterAbSigningWorkerJson"
      code_location: packages/sdk-server-ts/src/router/express/routes/thresholdEd25519.ts lines 340-347; packages/sdk-server-ts/src/router/express/routes/thresholdEcdsa.ts lines 657-661
  - id: A10
    spec_ref: S10
    code_ref: [C5, C6, C7, C8, C12]
    spec_claim: "SDK sends only Wallet Session credential; Router validates account, session, policy, quota, replay, and SigningWorker scope."
    code_behavior: "Routes validate Wallet Session token inputs, compare scope to claims, evaluate admission, reserve replay, and tests reject legacy threshold-session claims."
    match_type: full_match
    confidence: 0.93
    reasoning: "The route validator and tests enforce bearer Wallet Session-only public auth in the audited server routes."
    evidence:
      spec_quote: "The SDK should send only the Wallet Session credential... validates account, session, policy, quota, replay, and SigningWorker scope"
      spec_location: docs/router-a-b-SPEC.md lines 30-32 and 41-56
      code_quote: "rejects legacy threshold-session bearer claims before private SigningWorker forwarding"
      code_location: tests/relayer/router-ab-normal-signing-auth-boundary.test.ts lines 376-397
  - id: A11
    spec_ref: S11
    code_ref: [C7, C8]
    spec_claim: "Router derives authority from Wallet Session plus typed request data."
    code_behavior: "Ed25519 validates scope fields against claims; ECDSA-HSS parses typed requests, compares canonical scope, and builds trusted admission with request/signing digest."
    match_type: full_match
    confidence: 0.91
    reasoning: "The audited route validators use typed body parsing and claim/scope comparison, then derive admission fields for downstream forwarding."
    evidence:
      spec_quote: "Router computes... validates that the typed intent, payload, account, session, prepare/finalize binding, and SigningWorker scope all agree."
      spec_location: docs/router-a-b-SPEC.md lines 126-137
      code_quote: "accountId !== input.claims.walletId || sessionId !== input.claims.sessionId"
      code_location: packages/sdk-server-ts/src/router/routerAbPrivateSigningWorker.ts lines 336-413 and 477-535
  - id: A12
    spec_ref: S12
    code_ref: [C1, C5, C6, C9]
    spec_claim: "Router is the only public backend and owns auth, policy, rate limits, replay, and public lifecycle state."
    code_behavior: "Caddy has one public Router upstream; public route handlers own auth/admission/replay before private worker calls."
    match_type: full_match
    confidence: 0.92
    reasoning: "The local public edge and route-layer control flow match the deployment invariant."
    evidence:
      spec_quote: "Router is the only public wallet backend endpoint. Router handles auth, policy, rate limits, replay, and public lifecycle state."
      spec_location: docs/router-a-b-deployment.md lines 100-103
      code_quote: "evaluateRouterAbNormalSigningAdmission... reserveRouterAbNormalSigningPrepareReplay"
      code_location: packages/sdk-server-ts/src/router/express/routes/thresholdEcdsa.ts lines 592-655
```

## 6. Divergence Findings

```yaml
divergence_findings: []
```

## 7. Missing Invariants

No missing invariants were found in this scoped audit. The active invariants are
represented by source guards and route-level tests:

- one Caddy upstream and no Caddy path split,
- one SDK Router/API server plus three private workers,
- public Rust Router role rejection,
- bearer Wallet Session-only auth for public signing routes,
- admission/replay/quota/abuse checks before private forwarding.

## 8. Incorrect Logic

No incorrect logic was found in the scoped topology and admission paths.

## 9. Math Inconsistencies

No math inconsistency was found in the scoped audit. ECDSA-HSS request binding
uses canonical request digest helpers before constructing `trusted_admission`.
Ed25519 vector parity is referenced by the plan and covered by the existing
vector suite, but this audit did not rederive every vector manually.

## 10. Flow/State Machine Mismatches

No flow mismatch was found. Public Ed25519 and ECDSA-HSS routes validate
Wallet Session and request scope, then evaluate admission and replay, then
forward only to the private SigningWorker.

## 11. Access Control Drift

No access-control drift was found. Missing and legacy bearer credentials are
rejected before private SigningWorker service access.

## 12. Undocumented Behavior

No undocumented behavior was identified in the scoped code paths.

## 13. Ambiguity Hotspots

- The broader historical docs still contain out-of-scope Signer A/B or old-route
  context. This audit used the current 68B, local-dev, single-session, and
  deployment-choice excerpts as the normative corpus for this cleanup slice.
- Deployed Cloudflare browser/runtime evidence remains outside this audit and
  belongs to deployment readiness, not local topology correctness.

## 14. Recommended Remediations

No remediation is required from this audit.

## 15. Documentation Update Suggestions

No blocking documentation update is required. Keep historical docs clearly
classified as historical when they mention old local topologies.

## 16. Final Risk Assessment

Risk after this slice: Low for local Router A/B topology correctness. The
implementation has aligned route ownership, Caddy topology, local worker roles,
public signing admission, replay, quota/abuse, and private SigningWorker
forwarding with the scoped spec corpus. Remaining risk is deployment-evidence
based and should be handled by Cloudflare deployment validation phases.

## Completeness Checklist Result

```yaml
completeness:
  spec_ir:
    extracted_items: 12
    explicit_invariants: 5
    security_requirements: 4
    confidence_scores_present: true
  code_ir:
    analyzed_scoped_public_routes: true
    analyzed_private_forwarding: true
    analyzed_local_topology: true
    analyzed_guards: true
  alignment_ir:
    one_to_one_spec_mapping: true
    divergences_opened: 0
  final_report:
    sections_present: 16
    scope_limitations_documented: true
```
