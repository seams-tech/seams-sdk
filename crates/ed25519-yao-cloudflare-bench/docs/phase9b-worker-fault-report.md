# Phase 9B Local Worker Fault Report

Date: July 12, 2026

Status: benchmark-only local-workerd evidence against the compile-time
same-account fault artifacts. These artifacts cannot be selected at runtime and
have no production route.

## Results

| Scenario | Observed result | Security-relevant outcome |
| --- | --- | --- |
| deterministic fragmentation in both directions | ceremony completed; A emitted 2,513 fragments and B emitted 45, each at most 4,096 bytes | arbitrary adapter fragmentation preserved the transcript, exact one-envelope backpressure, and terminal EOF |
| non-empty public A body | HTTP 400, `YAOS_AB_PUBLIC_BODY_NONEMPTY` | caller bytes were rejected before session creation or B contact |
| A request stream error after `BaseChoices` | HTTP 500, A `YAOS_AB_INBOUND_BODY`; B `YAOS_AB_PROTOCOL_STATE` | no completion or directional EOF evidence was accepted |
| B response stream error after `Offer` | HTTP 500, A `YAOS_AB_INBOUND_BODY`; B `YAOS_AB_INJECTED_RESPONSE_DISCONNECT` | response failure remained distinct from successful physical EOF |
| bytes after B's terminal `Returned` envelope | HTTP 500, A `YAOS_AB_ENVELOPE` | the decoder rejected trailing data after the terminal message |

The request-disconnect stream emits an explicit Rust body error. Local workerd
exposes that failure to B as premature protocol termination, while A observes
the resulting B response-body failure. The result proves fail-closed behavior;
it does not claim that every Cloudflare topology preserves the same dependency
error classification.

## Validation

- normal build: 10 unit tests and 7 source guards;
- fault-feature host builds and targeted unit tests;
- strict WASM Clippy for fragmentation A/B, request-disconnect A,
  response-disconnect B, and trailing-terminal B;
- release Worker builds for all five fault artifacts;
- local workerd smoke assertions for every scenario;
- invalid role/fault feature combinations fail compilation.

The original ARM64 warning triage incorrectly classified every branch as
public. A follow-up review found that optimized ARM64 and exact Deriver A
Worker WASM branched on an IKNP base-choice bit. The kernel now uses
optimizer-resistant `subtle` selection for secret label, row, output, scalar,
and GF paths. The qualified codegen gate clean-builds optimized host assembly
and exact cross-account Deriver A/B Worker WASM, rejects the former
`tbz`/`i32.eqz; br_if` shape, and passes after the repair. This remains
benchmark-slice evidence; the production circuit, OT composition, runtime, and
selected-profile constant-time gates remain open.

## Follow-Up Evidence

Deterministic cancellation initiation, fixed wrong-service binding, wrong-role
injection, and session mismatch are completed in
[`phase9b-worker-fault-remaining-report.md`](phase9b-worker-fault-remaining-report.md).
Deployed same-account and separate-account failure behavior remains open.
