# Threshold ECDSA Signing

Last updated: 2026-02-25

## 1. Non-Negotiable Invariants

- Threshold ECDSA signing reads `keyRef` and session state from one canonical store only.
- `signTempo` does not trigger hidden bootstrap.
- There is no legacy fallback for participant IDs, JWT, or session ID.
- In `threshold-signer` warm-session mode, successful login must produce a valid threshold ECDSA `keyRef` and session bundle.
- Worker reset returns deterministic typed status (`not_found`, `expired`, `exhausted`) with explicit reconnect guidance, never silent retry with stale state.
- Threshold ECDSA sign requests for the same account are serialized FIFO across Tempo and EVM in the SDK path.
- Temporary threshold-trace debug instrumentation is not part of steady-state hot paths.

## 2. Architecture

### 2.1 Canonical Session Record

The SDK owns a single threshold ECDSA session record keyed by wallet/account context. The canonical record includes:

- `nearAccountId`
- `chain` (`tempo` or `evm`)
- `relayerUrl`, `relayerKeyId`
- `clientVerifyingShareB64u`
- `participantIds` (required)
- `thresholdSessionKind`, `thresholdSessionId`, `thresholdSessionJwt` (when JWT mode is used)
- `expiresAtMs`, `remainingUses`
- `updatedAtMs`
- `source` (`login`, `registration`, or `manual-bootstrap`)

### 2.2 Ownership Model

- Writers are limited to login warm-up, registration provisioning, and explicit reconnect/manual bootstrap.
- Readers are signing flows.
- UI components only mirror state for display and do not mutate canonical threshold session state directly.

### 2.3 Flow Boundaries

1. Login/provisioning mints threshold ECDSA session state and writes the canonical record.
2. Signing validates the canonical record and worker cache status (`peekPrfFirstForThresholdSession`) before confirmation/sign orchestration.
3. Missing or invalid state fails closed with typed errors and routes to explicit reconnect/provision flows.

### 2.4 Per-Account Commit Queue (Tempo + EVM)

- Queue scope is `nearAccountId`.
- Queue domain is threshold ECDSA commit stage (`senderSignatureAlgorithm=secp256k1`) across both chains.
- Ordering is FIFO.
- A second sign click is queued (not rejected) and begins after the prior request completes, fails, or is cancelled.
- Queued requests can be cancelled before execution via existing abort/cancel signals.
- Guardrails: bounded queue length (`commit_queue_overflow`), queue timeout budget (`commit_queue_timeout`), and deterministic teardown on logout/engine destroy.

## 3. Failure and Recovery Model

- Missing canonical session data is an immediate typed failure before authorize/sign.
- Worker reset never silently reuses stale in-memory state.
- Recovery happens through a single explicit reconnect/provision entrypoint.
- Removed fallback patterns (implicit participant IDs, stale JWT/session fallback) are treated as regressions and blocked by tests/architecture checks.

## 4. Runtime Caching Model

Current caches are intentionally minimal and mostly memory-scoped:

1. Canonical threshold ECDSA session record: memory + `sessionStorage` (not IndexedDB). File: `client/src/core/signingEngine/api/thresholdLifecycle/thresholdEcdsaSessionStore.ts`.

2. ECDSA auth-session policy/JWT: in-memory map. File: `client/src/core/signingEngine/threshold/session/ecdsaAuthSession.ts`.

3. Client presign pool: in-memory only (not persisted). File: `client/src/core/signingEngine/orchestration/walletOrigin/thresholdEcdsaCoordinator.ts`.

Implication: after refresh/new tab/new process, presign pool depth resets to `0`, so the next sign is cold unless pool entries are re-prepared in the same runtime.

## 5. Performance Notes

- The dominant cold-sign cost is the presign handshake (`/threshold-ecdsa/presign/init` + `/threshold-ecdsa/presign/step`), not bootstrap/authorize/sign-init/finalize.
- Historically, first-sign latency spikes came from concurrent foreground sign and background refill starting duplicate presign handshakes for the same pool key.
- Current mitigations: foreground sign waits for and reuses in-flight refill; refill skips while foreground sign is active; commit-start refill skips on true cold start (depth `0`); server presign routing prioritizes foreground over background.
- Observed result after mitigation: first sign reduced to around `~3s` in recent tests, with subsequent signs often around `~0.5-1s` when the pool is warm.

### 5.1 Latest Benchmark Gate Snapshot (2026-02-25)

- Run ID: `20260225-091017Z`
- Artifact path: `benchmarks/threshold-ecdsa-presign/out/20260225-091017Z`
- Full report: `docs/benchmarks/threshold-ecdsa-presign.md`
- SLO gate outcome: `5/5 passed`
- Key measurements:
  - `cold_first_sign_no_pool` p95: `2226ms`
  - `warm_sign_pool_hit` p95: `24ms`
  - `/threshold-ecdsa/presign/step` p95: `783ms`
  - `/threshold-ecdsa/presign/step` p99: `783ms`
  - Non-fallback replay ratio: `0.00` (gate max `0.01`)

## 6. Perf Ops and Observability

Server-side instrumentation for threshold ECDSA presign/sign should be treated as part of normal operations, not temporary debugging.

- Request-level latency logs include route and duration:
  - `[threshold-ecdsa] response { route, status, ok, durationMs, ... }`
- Presign request metadata distinguishes user-facing and refill traffic:
  - `requestTag` (`background_presign_pool_refill` for refill traffic),
  - `presignTrafficClass` (`foreground` or `background`),
  - `gateWaitMs`, `gateQueuedDepth`.
- Presign-step phase timing logs isolate bottlenecks:
  - `[threshold-ecdsa] presign/step perf { ... }`
  - Useful fields: `totalMs`, `storeGetSessionMs`, `liveResolveMs`, `liveResolveSource`, `replayRestoreMs`, `replayFallbackReason`, `wasmStepMs`, `storeCasMs`, `casCode`, `resultCode`.
- Replay fallback visibility:
  - `presign live-session fallback to replay` (warn),
  - `presign live-session fallback replay failed` (error),
  - `presign live-session fallback replay stage mismatch` (error).
- Hot-path store guidance:
  - For lower presign/sign p95/p99, configure Redis/Upstash (`UPSTASH_REDIS_REST_URL` + `UPSTASH_REDIS_REST_TOKEN`, or `REDIS_URL` in node runtime).
  - With those values present, hot-path threshold ECDSA stores prefer Redis/Upstash over slower defaults.

## 7. Key Code References

1. Session store and activation lifecycle: `client/src/core/signingEngine/api/thresholdLifecycle/thresholdEcdsaSessionStore.ts`, `client/src/core/signingEngine/api/thresholdLifecycle/thresholdSessionActivation.ts`.

2. Signing algorithm and queue/guardrail paths: `client/src/core/signingEngine/signers/algorithms/secp256k1.ts`, `client/src/core/signingEngine/api/thresholdLifecycle/thresholdEcdsaCommitQueue.ts`.

3. Wallet-origin coordinator and presign pool scheduling: `client/src/core/signingEngine/orchestration/walletOrigin/thresholdEcdsaCoordinator.ts`.

4. Login warm bootstrap path: `client/src/core/TatchiPasskey/login.ts`.

5. Server route timings and presign prioritization: `server/src/router/express/routes/thresholdEcdsa.ts`.
