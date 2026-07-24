# Refactor 93 Phase 0: current role-lifecycle map

This note records the Phase 0 observation-only work on
`codex/refactor-93-role-lifecycle`. It distinguishes the legacy request shape
that is still present in the last measured deployment from the Router-owned
request shape implemented by the branch. It does not claim that a production
trace cohort has been captured. No deployment is part of this lane.

## Current production registration path

The last measured production deployment still uses the legacy Stage → Start →
Result shape. The trace value is carried in an HTTP header and may be absent for
legacy callers that do not opt into correlation. The branch's Gateway backend
creates the trace value at the Router boundary and carries it through the
coordinator and role requests.

| Segment | Current transition | Durable Object/storage boundary | Observation span |
| --- | --- | --- | --- |
| B preparation | Gateway/private caller → Deriver B `POST /router-ab/deriver-b/ed25519-yao/activation/stage` (or export stage). The route validates B's encrypted input and sends `Stage` to the session stub selected by the 32-byte session name. | `DERIVER_B_YAO_SESSION_DO` → `/command`; key `session-record-v1`; `Staged` stores the encrypted B input, its digest, and the staging expiry. | `deriver_b.session_do` with `operation=stage` measures the request to the B session object. |
| A preparation/start | Gateway/private caller → Deriver A `POST /router-ab/deriver-a/ed25519-yao/activation/start` (or export start). The route validates A's encrypted input and sends `Execute` to the A session stub selected by the same session name. | `DERIVER_A_YAO_SESSION_DO` → `/execute`; key `session-record-v1`; the object moves through `Running` and later `Completed`, `Failed`, or `Expired`. | `deriver_a.session_do` measures the A session-object call; `deriver_a.role_execution` measures the complete A role inside that object. |
| A startup fan-out | Inside A role execution, the private envelope is opened before external work. Root-share startup metadata and the Deriver B WebSocket upgrade are started concurrently with `futures::try_join!`. | Root-share metadata uses the existing typed Durable Object call. The WebSocket crosses the `DERIVER_B` Service Binding and reaches the B duplex route. | `deriver_a.root_share` measures the root-share lookup; `deriver_a.websocket_connect` measures the Service Binding upgrade. |
| B WebSocket acceptance | Deriver B duplex route parses the negotiated circuit/session, reads the staged input, prepares the response, then sends `Begin` to the B session object before scheduling the role on `wait_until`. | `DERIVER_B_YAO_SESSION_DO` reads `Staged` and changes it to `Running`; the WebSocket is the A/B protocol boundary. | The B session-object reads are `deriver_b.session_do` with `operation=read_staged` and `operation=begin`. The role itself is covered by `deriver_b.role_execution`. |
| A/B protocol | A and B run the existing Yao duplex protocol over the same WebSocket. | No new calls or state transitions are introduced by Phase 0. | `deriver_a.yao_protocol` and `deriver_b.yao_protocol` measure activation/export protocol execution. |
| B completion | B seals its role output and sends `Complete` to the B session object. | The B object persists `Completed` with the sealed execution. | `deriver_b.session_do` with `operation=complete` measures the completion write. |
| B result retrieval | Gateway/private caller → Deriver B `POST /router-ab/deriver-b/ed25519-yao/activation/result` (or export result). The route polls the existing `ReadResult` command until the stored execution is available or the existing timeout/terminal result is reached. | `DERIVER_B_YAO_SESSION_DO` → `/command`; reads the same `session-record-v1` record. | `deriver_b.result_wait` measures the aggregate result wait; each `ReadResult` call is `deriver_b.session_do` with `operation=read_result`. |

SigningWorker delivery, D1 commit, Gateway finalization, and frontend
finalization are outside this role-local lane. They remain named Phase 0
follow-up owners until the required production trace cohort assigns their
durations.

## Branch Router-owned ceremony path

The branch replaces the serial Gateway → Stage → Start → Result sequence with
one Gateway → Router request. This is implemented code, not production timing
evidence:

| Segment | Current branch transition | Durable Object/storage boundary | Observation span |
| --- | --- | --- | --- |
| Router admission | Gateway sends one authenticated execute request containing both encrypted inputs and the canonical pair binding. | Router validates authority and pair binding; replay reconciliation reads role-local status only for an internal replay. | `router.parse_and_authorize`, `router.role_status_reconciliation` |
| Pair preparation | Router sends A and B `prepare-pair` requests concurrently through their Service Bindings. | Each role-local session object atomically stores its prepared pair and signed readiness material. | `router.prepare_pair`, `deriver_a.session_do(operation=pair)`, `deriver_b.session_do(operation=pair)` |
| Readiness gate | Router validates both signed receipts and their pair/session/operation bindings before dispatching A. | No ceremony-wide Durable Object is introduced. | `router.verify_readiness_receipts` |
| Two-party execution | Router sends one `execute-pair` request to A. A opens its role-local state and connects to B over the existing WebSocket protocol. | A and B retain independent role-local session objects and secret bindings. | `router.deriver_a_execute`, `deriver_a.websocket_connect`, `deriver_a.yao_protocol`, `deriver_b.yao_protocol` |
| B completed read | Router reads B's exact completed execution after A returns, then validates transcript and role bindings. | B session object returns the persisted completed result; no polling loop is used by the coordinator. | `router.deriver_b_completed_read` |
| Atomic delivery | Router sends the exact A/B package pair to SigningWorker once. | SigningWorker owns its existing activation state and idempotent delivery boundary. | `router.signing_worker_delivery` |

An internal transport failure may replay the exact serialized request once. A
completed pair is redelivered without cryptographic reevaluation; a running or
conflicting pair is burned. This branch behavior still needs deployed cold and
warm cohorts before the Phase 0 budget can be closed.

## Correlation and privacy contract

The role adapters accept the opaque `x-seams-trace-id` header. A value is
accepted only when it is exactly 32 lowercase hexadecimal characters (128 bits)
and is converted immediately to `CloudflareTraceIdV1`. The typed value is reused
within the request and revalidated when it crosses another HTTP/Service Binding
boundary. Missing correlation remains valid and produces no `trace_id` field.

The value is never read from a request body and is never derived from account,
wallet, credential, session-secret, ciphertext, root-share, token, or private
output data. Span events contain only:

```text
event       = router_ab_yao_role_span_v1
span        = stable role boundary name
role        = deriver_a | deriver_b
operation   = yao | activation | export | durable-object operation
outcome     = success | failure
duration_ms = non-negative elapsed wall-clock milliseconds
trace_id    = validated opaque value, when supplied
```

These are structured Workers log events. They do not alter response bodies,
request bodies, lifecycle records, retry behavior, or execution order.

The shared trace-header contract is `x-seams-trace-id`, validated as exactly 32
lowercase hexadecimal characters (128 bits). The Router and role adapters use
the same boundary parser; no second header format is introduced.

## Durable Object lifecycle signal

The Workers Rust API used by this crate does not expose a reliable per-request
signal that distinguishes a newly instantiated role object from an existing
isolate. The instrumentation records request/response timing and persisted
record transitions only. It intentionally does not infer isolate reuse from
duration, storage presence, or a warm-looking request.

## Validation evidence

- `rustfmt --check --edition 2021 src/refactor93_router.rs`
- `cargo check --manifest-path crates/router-ab-cloudflare/Cargo.toml --features strict-worker-router-entrypoint`
- strict Router library tests: 18 passed
- strict route-boundary and path tests: 7 + 1 passed
- pair/lifecycle boundary tests: 6 passed
- Cloudflare binding tests: 271 passed
- local-dev library tests: 13 passed
- `git diff --check`

The Phase 0 production requirements for 20 successful traces, cold/warm
cohorts, and the frozen `gateway.yao_execute` p50/p95 budget remain open until
deployment access and a production trace export are available.
