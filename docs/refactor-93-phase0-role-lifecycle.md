# Refactor 93 Phase 0: current role-lifecycle map

This note records the Phase 0 observation-only work on
`codex/refactor-93-role-lifecycle`. It describes the deployed request shape in
the branch and does not claim that a production trace cohort has been captured.
No deployment is part of this lane.

## Current production registration path

The current registration ceremony still uses the legacy Stage → Start → Result
shape. The trace value is carried in an HTTP header and is absent when the
caller does not opt into correlation.

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

There is no active Agent 3 in this worktree to reconcile a shared trace-header
definition with. The header name and validation contract therefore remain a
Phase 0 integration item before the coordinator lane adopts them; this branch
does not add a second header to any shared protocol type.

## Durable Object lifecycle signal

The Workers Rust API used by this crate does not expose a reliable per-request
signal that distinguishes a newly instantiated role object from an existing
isolate. The instrumentation records request/response timing and persisted
record transitions only. It intentionally does not infer isolate reuse from
duration, storage presence, or a warm-looking request.

## Validation evidence

- `cargo check --manifest-path crates/router-ab-cloudflare/Cargo.toml --lib`
- `cargo check --manifest-path crates/router-ab-cloudflare/Cargo.toml --lib --features strict-worker-deriver-a-entrypoint`
- `cargo check --manifest-path crates/router-ab-cloudflare/Cargo.toml --lib --features strict-worker-deriver-b-entrypoint`
- Focused route/lifecycle tests are recorded in the handoff after the code and
  formatting checks complete.

The Phase 0 production requirements for 20 successful traces, cold/warm
cohorts, and the frozen `gateway.yao_execute` p50/p95 budget remain open until
deployment access and a production trace export are available.
