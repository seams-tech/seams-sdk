# Refactor 15: Threshold ECDSA Presign Pool Wiring

Status: Planned  
Severity: High (sign latency + timeout risk under commit queue pressure)  
Last updated: 2026-02-22

## 1. Problem Statement

Current threshold ECDSA signing still pays presign handshake cost inline too often:

1. Client presign pool exists, but it is passive-only and usually empty at sign start.
2. `refillThresholdEcdsaClientPresignaturePool(...)` exists but is not wired to runtime call sites.
3. Sign path falls back to inline presign generation (`presign/init` + `presign/step`) before `sign/init`.
4. Server `presign/init` supports only `count=1` in v1, so batch prefill is not available yet.

Result: cold/warm-first sign latency stays high, and queued commits can hit timeout windows.

## 2. Scope and Decisions

1. Clean switch: move to actively managed client presign pool behavior (no legacy path, no feature flag).
2. Keep current signing correctness rules:
   - Tx confirmer UI remains concurrent.
   - Threshold commit remains serialized per account.
3. Refill is best-effort and non-blocking for user-visible sign completion.
4. Refill trigger strategy:
   - post-success top-up after commit,
   - low-watermark refill scheduling before/at commit start.
5. Do not fail a user sign because background refill fails.
6. Server should be policy authority for recommended pool depth, while client enforces local bounds.

## 3. Invariants

- Same-account threshold commit is still FIFO serialized.
- No silent fallback to old behavior or duplicate signing codepaths.
- Sign success path remains valid even with empty pool or refill errors.
- Client never runs duplicate refill jobs for the same pool key concurrently.
- Presign pool entries are bound to the same key/session context already used by signing.

## 4. Target Architecture

## 4.1 Client Pool Manager

Add an explicit pool manager layer in wallet-origin coordinator domain:

- pool depth introspection,
- low-watermark checks,
- refill scheduling with in-flight dedupe per pool key,
- best-effort background execution.

## 4.2 Policy Interface

Define a typed policy surface for presign pooling:

- `enabled`
- `targetDepth`
- `lowWatermark`
- `maxRefillInFlight`
- `refillAttemptTimeoutMs`

Client policy is resolved from:

1. local config defaults (safe baseline),
2. optional server hint (clamped to local min/max bounds).

## 4.3 Refill Timing

- After successful secp256k1 commit: schedule top-up to target depth.
- At commit start when depth <= low watermark: schedule refill without blocking current commit.
- Refill should run outside user-facing critical path.

## 5. Implementation Plan

## Phase 0: Types + Config Surface

- [ ] Add `ThresholdEcdsaPresignPoolPolicy` interface and resolved policy helper.
- [ ] Extend SDK config types for local bounds/defaults.
- [ ] Add policy defaults in config builder.

Files:

- `client/src/core/types/tatchi.ts`
- `client/src/core/config/defaultConfigs.ts`
- `client/src/core/signingEngine/bootstrap/orchestrationDependencyFactory.ts`

## Phase 1: Coordinator Pool Manager Wiring

- [ ] Add pool depth helper for existing client pool map.
- [ ] Add refill scheduler with in-flight dedupe map keyed by presign pool key.
- [ ] Add `ensurePoolDepth(...)` helper that fills toward target depth (best-effort).
- [ ] Keep existing `signThresholdEcdsaDigestWithPool(...)` fallback logic for correctness.

Files:

- `client/src/core/signingEngine/orchestration/walletOrigin/thresholdEcdsaCoordinator.ts`

## Phase 2: Runtime Call-Site Integration

- [ ] Wire post-sign top-up trigger from secp256k1 signing engine success path.
- [ ] Wire low-watermark scheduling at commit start (or immediately before commit task).
- [ ] Keep queue semantics unchanged; refill must not block queued commit completion path.
- [ ] Add minimal progress event hook for debugging (`presign-refill-scheduled`), if needed.

Files:

- `client/src/core/signingEngine/signers/algorithms/secp256k1.ts`
- `client/src/core/signingEngine/api/evmSigning.ts`

## Phase 3: Server Policy Hint (Recommended)

- [ ] Add server-side presign pool policy config fields (env + resolved config).
- [ ] Include optional pool-policy hint in threshold ECDSA authorize response.
- [ ] Clamp and apply hint in client policy resolver.
- [ ] Keep v1 `count=1` behavior intact for now; refill loops if target depth > current depth.

Files:

- `server/src/core/types.ts`
- `server/src/core/ThresholdService/ThresholdSigningService.ts`
- `server/src/core/ThresholdService/ecdsaSigningHandlers.ts`
- `client/src/core/signingEngine/threshold/workflows/authorizeEcdsa.ts`

## Phase 4: Tests and Guardrails

- [ ] Unit: post-sign success schedules refill.
- [ ] Unit: second sign can consume pooled presignature without inline presign in steady state.
- [ ] Unit: refill failure does not fail active user sign.
- [ ] Unit: dedupe prevents duplicate refill jobs for same pool key.
- [ ] Unit: policy hint clamp logic rejects unsafe values.
- [ ] Integration: repeated same-account signs reduce `presign/init` frequency after warm-up.
- [ ] Guard: prevent reintroduction of dead/unwired refill symbols.

Suggested tests/files:

- `tests/unit/thresholdEcdsa.tempoHighLevel.unit.test.ts`
- `tests/unit/thresholdEcdsa.presignPoolRefill.unit.test.ts`
- `tests/unit/thresholdEcdsa.policyHint.unit.test.ts`
- `tests/relayer/threshold-ecdsa.durable-stores.test.ts`

## 6. Risks and Mitigations

1. Refill race with active commits can create excess presign sessions.  
Mitigation: per-pool-key in-flight dedupe + bounded refill attempts.

2. Aggressive target depth can overload relayer/storage.  
Mitigation: server-owned policy hint + client clamp bounds.

3. Refill failures may look like sign failures in logs.  
Mitigation: typed refill diagnostics separated from sign result errors.

4. v1 `count=1` may increase refill loop chatter.  
Mitigation: keep low default target depth (for example 2) until batched prefill exists.

## 7. Done Criteria

- [ ] Refill path is actively wired from runtime signing flow.
- [ ] Warm steady-state signs usually avoid inline presign handshake.
- [ ] Same-account commit serialization remains unchanged.
- [ ] Refill errors are non-fatal to active sign requests.
- [ ] Policy source of truth is clear (server hint + client clamp), documented, and tested.
- [ ] No duplicate legacy or dead presign refill code remains.

## 8. Phased TODO List

## Immediate

- [ ] Land Phase 0 interfaces and defaults.
- [ ] Land Phase 1 coordinator refill manager.

## Next

- [ ] Wire Phase 2 runtime call sites and progress diagnostics.
- [ ] Add/refactor unit tests for refill scheduling and non-blocking behavior.

## Finalize

- [ ] Add optional Phase 3 server policy hint surface.
- [ ] Run focused threshold ECDSA suites and close checklist.
