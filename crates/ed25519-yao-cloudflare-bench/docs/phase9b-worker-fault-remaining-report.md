# Phase 9B Remaining Local Worker Fault Report

Date: July 12, 2026

Status: benchmark-only local-workerd evidence for four compile-time-isolated
fault topologies. The normal same-account and cross-account artifacts contain
none of these behaviors.

## Results

| Scenario | Fixed artifacts | Observed result | Bound |
| --- | --- | --- | --- |
| B emits `Offer`, then stalls on a live 60-second timer | A uses a compile-time 250 ms ceremony timeout; B uses `fault-stall-after-offer` | HTTP 500, `YAOS_AB_TIMEOUT` | local workerd completed in 264 ms |
| A is bound to the fixed wrong-service module | the dev topology contains A and `src/wrong_service.mjs`; the real B artifact is absent | wrong-service invocation log, then HTTP 500, `YAOS_AB_PEER_STATUS` | 13 ms |
| B changes a legitimately encoded `Offer` envelope to the A-to-B `BaseOtChoices` tag | B uses `fault-wrong-role-offer-tag` | HTTP 500, `YAOS_AB_ENVELOPE` | 20 ms |
| B constructs its role with a session distinct from the header-selected framing session | B uses `fault-session-mismatch` | HTTP 500, `YAOS_AB_ROLE` | 30 ms |

The timeout path calls `AbortController::abort()` before returning
`YAOS_AB_TIMEOUT`. This proves bounded A behavior and deterministic local
cancellation initiation. The local logs provide no evidence that B observed
the cancellation, so this report makes no peer-observation claim.

The stalled response owns a live `Delay`. A bare `Poll::Pending` was rejected
by local workerd as a Worker that could never generate a response, producing an
inbound-body error before A's timeout. Keeping a real timer pending models a
reachable stalled peer and lets A's timeout win deterministically.

The wrong-service dev command loads only the A config and the fixed
wrong-service config. Its service binding names that module directly. The
observed `ed25519_yao_wrong_service_invoked` event and the absence of any real B
config in the topology establish that the real B Worker was not invoked.

## Validation

- host tests: 11 unit tests and 7 source guards;
- strict WASM Clippy for normal A/B, cross-account A/B, timeout A, stalled B,
  wrong-role B, and session-mismatch B;
- release Worker builds for every new Rust fault artifact;
- local workerd smoke assertions for all four exact nonsecret error codes;
- compile-fail checks for wrong-role, cross-topology, and multiple-fault feature
  combinations;
- Wrangler dry-runs for every new config, including the standalone JavaScript
  wrong-service module.

These are local-workerd results. Deployed same-account and separate-account
cancellation, disconnect, and isolate-memory evidence remain open.
