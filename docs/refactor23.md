# Refactor 23: Session-Only ECDSA Commit Queue Keys

Status: ✅ All phased TODO items are complete.

## Goal
Simplify threshold ECDSA commit queue keying to one canonical strategy:
1. `session:${chain}:${thresholdSessionId}`

Remove all queue-key fallbacks (`lane:*`, `account:*`) and fail fast when session state is missing.
2. Unify implementation style across Ed25519 and ECDSA commit queue paths to reduce cognitive burden and keep both flows structurally consistent.

## Why
Current fallback-based resolver adds indirection and hides bugs:
1. Different paths can silently use different queue keys.
2. Missing session readiness can degrade into fallback serialization instead of failing clearly.
3. Debugging queue behavior becomes harder under race conditions.

Session-only keying is simpler, deterministic, and easier to reason about.

## Warnings / Guardrails
1. Do not couple Ed25519 and ECDSA runtime lanes. Shared implementation style is desired; shared execution lanes are not.
2. Keep curve-specific queue key domains separate to avoid cross-curve blocking and throughput regressions.
3. Do not introduce cross-curve fallback behavior while unifying style.
4. Sequence work to minimize risk:
- first land strict ECDSA session-only queue keying and pass gates,
- then land cross-curve style unification as a separate, focused change set.
5. Merge is blocked if unification changes alter existing signing semantics for either curve.

## Scope
In scope:
1. Queue key resolver + API contract changes for threshold ECDSA commit.
2. Runtime wiring in Tempo/EVM threshold commit paths.
3. Tests and docs updates for strict preconditions.
4. Shared queue implementation style across Ed25519 and ECDSA (common primitive + curve-specific key domains).

Out of scope:
1. Nonce manager behavior changes.
2. Ed25519 persistence/keying changes.
3. PRF crypto format changes.

## Hard Invariants
1. Queue key derivation uses session key only.
2. Missing `thresholdSessionId` at enqueue time is a hard error.
3. Same `chain + thresholdSessionId` serializes.
4. Different `chain + thresholdSessionId` can proceed concurrently.
5. No legacy fallback path remains in code.

## Coverage Audit (regression-sensitive touchpoints)
1. `thresholdEcdsaCommitQueue.ts`: fallback key derivation (`lane:*`, `account:*`) and fallback error formatting removed in this pass.
2. `thresholdEcdsa.commitQueue.unit.test.ts`: fallback assertions replaced with strict missing-session invariant assertions.
3. `evmSigning.ts`: queue key derivation now uses explicit enqueue `thresholdSessionId` context.
4. `secp256k1.ts`: enqueue contract now carries explicit session context (`thresholdSessionId`) to avoid stale-capture dependency.
5. Type plumbing for enqueue contract is spread across:
- `SigningEngine.ts`
- `bootstrap/orchestrationDependencyFactory.ts`
- `api/evmSigning.ts`
6. New shared primitive + curve wrappers:
- `thresholdCommitQueueShared.ts`
- `thresholdEcdsaCommitQueue.ts` (wrapper)
- `thresholdEd25519CommitQueue.ts` (wrapper)
7. `nearSigning.ts` now routes threshold Ed25519 signing through a strict session-scoped queue wrapper (`session:ed25519:${thresholdSessionId}`) while keeping non-threshold paths unchanged.
8. Docs describing fallback queue keys were updated:
- `docs/concurrent-signers.md`
- `docs/architecture-current.md`
9. Guard coverage now prevents reintroduction of fallback queue key formats in core source.

## Implementation Plan

## Phase 1: Contract Tightening
1. Update commit queue API to require `thresholdSessionId` and `chain` for queue key derivation.
2. Remove fallback key resolver branches (`lane:*`, `account:*`).
3. Add explicit invariant error for missing/empty `thresholdSessionId`.
4. Keep diagnostic context in errors/logs (`nearAccountId`, `chain`, `thresholdSessionId`).
5. Remove fallback error text synthesis that assumes `account:*` when queue key is empty.

## Phase 2: Runtime Wiring
1. Ensure all ECDSA enqueue callsites resolve/recover session before enqueue.
2. Route Tempo and EVM through the same strict session-key resolver.
3. Move missing-session failures earlier in flow where possible (before enqueue).
4. Preserve existing queue timeout/cancel behavior.
5. Pass explicit session context into commit enqueue contract to avoid reliance on mutable closure state.

## Phase 3: Cleanup
1. Delete obsolete types/constants/comments for fallback queue keys.
2. Remove tests that assert fallback behavior.
3. Remove any docs mentioning account/lane fallback queue keys.
4. Add/extend guard tests that fail if `lane:` or `account:` queue key formats reappear in commit queue resolver code.
5. Normalize queue naming, signatures, and error semantics across Ed25519 and ECDSA paths.

## Phase 4: Validation
1. Unit: same session key serializes.
2. Unit: different session keys run concurrently.
3. Unit: missing `thresholdSessionId` throws deterministic invariant error.
4. Integration: rapid Tempo/EVM signing with valid sessions remains concurrent.
5. E2E: refresh + sign flows stay prompt-stable and do not reintroduce TouchID regressions.
6. E2E: same-account cross-chain ordering (`Tempo->EVM` and `EVM->Tempo`) remains green.
7. Unit: no-legacy-surface guard blocks fallback queue key reintroduction.

## Phase 5: Rollout Safety
1. Add temporary debug logs for derived queue key and enqueue context.
2. Run targeted matrix before merge.
3. Remove/trim extra logs after stability confirmation.

## Phase 6: Cross-Curve Style Unification (Ed25519 + ECDSA)
1. Introduce/reuse one shared commit-queue primitive so both curves follow the same queue implementation style.
2. Align queue API naming and argument shape across Ed25519 and ECDSA wrappers.
3. Keep key domains curve-specific to avoid cross-curve blocking while preserving consistent structure.
4. Add tests/guards that verify style/API consistency across both curve paths.

## Phased TODO List

### Phase 1
- [x] Replace resolver with session-only key format (`session:${chain}:${thresholdSessionId}`).
- [x] Enforce non-empty `thresholdSessionId` invariant in queue API.
- [x] Remove fallback resolver helpers/constants.
- [x] Remove fallback queue-key defaults in commit queue error helpers.

### Phase 2
- [x] Update Tempo enqueue path to always pass resolved `thresholdSessionId`.
- [x] Update EVM enqueue path to always pass resolved `thresholdSessionId`.
- [x] Fail early when session is not ready, before queue enqueue.
- [x] Update `Secp256k1Engine` enqueue callback contract to include explicit session context.
- [x] Update `evmSigning` wiring to consume explicit enqueue session context (no mutable key-ref dependency).
- [x] Update `SigningEngine` and orchestration dependency type plumbing for new enqueue contract shape.

### Phase 3
- [x] Delete fallback-related tests and fixtures.
- [x] Remove fallback references from docs/comments.
- [x] Update `docs/concurrent-signers.md` queue-key section to session-only semantics.
- [x] Update `docs/architecture-current.md` commit queue section to lane/session scope.
- [x] Add guard assertion against `lane:` and `account:` commit queue key formats.

### Phase 4
- [x] Add/adjust unit tests for strict session-only keying.
- [x] Run queue + tempo high-level + sealed-refresh smoke tests.
- [x] Run nonce-related regression tests to confirm no side effects.
- [x] Run cross-chain tempo/evm concurrency e2e suite.

### Phase 5
- [x] Confirm no fallback code paths remain via repository grep.
- [x] Capture final validation snapshot in this doc.
- [x] Prepare merge PR notes.

### Phase 6
- [x] Introduce/reuse a shared commit-queue primitive so Ed25519 and ECDSA use the same queueing pattern.
- [x] Align Ed25519/ECDSA queue API shape (naming + argument structure) for consistency.
- [x] Keep curve-specific queue key domains to avoid cross-curve runtime blocking.
- [x] Add/extend tests or guards that assert cross-curve queue style/API consistency.

## Status Snapshot (2026-03-01)
Completed in this pass:
1. ECDSA commit queue resolver is strict session-only; `lane:*` / `account:*` fallback key derivation removed.
2. Missing `thresholdSessionId` now hard-fails in queue key resolution.
3. `Secp256k1Engine` enqueue contract now passes explicit `thresholdSessionId`.
4. `evmSigning` queue wiring now derives key from explicit enqueue session context (not mutable captured key-ref lane fallback fields).
5. Queue resolver tests updated to strict semantics (missing-session throws).
6. Legacy-surface guard now blocks reintroduction of fallback queue-key formats.
7. Architecture docs updated to session-lane queue semantics.
8. Added shared queue primitive (`thresholdCommitQueueShared.ts`) and refactored ECDSA queue wrapper to use it.
9. Added Ed25519 queue wrapper (`thresholdEd25519CommitQueue.ts`) with strict session-only key format `session:ed25519:${thresholdSessionId}`.
10. Routed threshold Ed25519 near-signing APIs through the Ed25519 commit queue wrapper in threshold mode only.
11. Added cross-curve style guard test (`thresholdCommitQueue.sharedPrimitive.guard.unit.test.ts`) and dedicated Ed25519 queue unit coverage (`thresholdEd25519.commitQueue.unit.test.ts`).

Validation run results:
1. `tests/unit/thresholdEcdsa.commitQueue.unit.test.ts`: `9 passed`
2. `tests/unit/thresholdEd25519.commitQueue.unit.test.ts`: `5 passed`
3. `tests/unit/thresholdCommitQueue.sharedPrimitive.guard.unit.test.ts`: `2 passed`
4. `tests/unit/thresholdEcdsa.tempoHighLevel.unit.test.ts`: `7 passed`
5. `tests/e2e/thresholdEd25519.batchSigning.test.ts`: `1 passed`
6. `tests/e2e/thresholdEcdsa.sealedRefresh.walletIframe.test.ts -g "same-tab refresh reuses sealed PRF session without extra TouchID prompt"`: `1 passed`
7. `pnpm -C sdk run build:check:fresh || pnpm -C sdk run build`: passed (`build:check:fresh` detected stale build and `build` completed successfully)

## File Targets
1. `client/src/core/signingEngine/api/thresholdLifecycle/thresholdEcdsaCommitQueue.ts`
2. `client/src/core/signingEngine/api/thresholdLifecycle/thresholdCommitQueueShared.ts`
3. `client/src/core/signingEngine/api/thresholdLifecycle/thresholdEd25519CommitQueue.ts`
4. `client/src/core/signingEngine/api/evmSigning.ts`
5. `client/src/core/signingEngine/api/nearSigning.ts`
6. `client/src/core/signingEngine/SigningEngine.ts`
7. `client/src/core/signingEngine/signers/algorithms/secp256k1.ts`
8. `client/src/core/signingEngine/bootstrap/orchestrationDependencyFactory.ts`
9. `tests/unit/thresholdEcdsa.commitQueue.unit.test.ts`
10. `tests/unit/thresholdEd25519.commitQueue.unit.test.ts`
11. `tests/unit/thresholdCommitQueue.sharedPrimitive.guard.unit.test.ts`
12. `tests/unit/thresholdEcdsa.tempoHighLevel.unit.test.ts`
13. `tests/e2e/thresholdEcdsa.sealedRefresh.walletIframe.test.ts`
14. `tests/e2e/thresholdEd25519.batchSigning.test.ts`
15. `docs/concurrent-signers.md`
16. `docs/architecture-current.md`

## Merge Gates
1. No fallback resolver code remains.
2. Missing-session invariant is tested and enforced.
3. Same-session serialization and cross-session concurrency tests are green.
4. Sealed-refresh same-tab smoke remains green with no extra prompt regression.
5. Cross-chain tempo/evm e2e ordering remains green.
6. Guard test prevents `lane:`/`account:` queue key fallback reintroduction.
7. Ed25519 and ECDSA queue paths use the same implementation style and API conventions.
