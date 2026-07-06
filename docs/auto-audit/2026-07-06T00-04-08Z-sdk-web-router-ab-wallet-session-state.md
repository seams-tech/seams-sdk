# Auto Audit Report

- Timestamp: `2026-07-06T00:04:08Z`
- Target file: `packages/sdk-web/src/core/signingEngine/session/routerAbSigningWalletSession.ts`
- Flow: `Wallet SDK Router A/B Ed25519 wallet-session authority parsing, persisted-state classification, runtime worker-material validation, and NEAR readiness gating`

## Scope / Call Graph Summary

This audit focused on [`/Users/pta/Dev/rust/seams-sdk/packages/sdk-web/src/core/signingEngine/session/routerAbSigningWalletSession.ts`](/Users/pta/Dev/rust/seams-sdk/packages/sdk-web/src/core/signingEngine/session/routerAbSigningWalletSession.ts), with the surrounding wallet-session restore/readiness flow in the SDK.

- Direct local imports inside the target file:
  - `./persistence/records` for canonical persisted Ed25519/ECDSA session records and material-state discriminants
  - `@shared/utils/sessionTokens` for wallet-session JWT payload decoding
  - `../threshold/ed25519/workerMaterialBinding` and `./keyMaterialBrands` for branded worker-material identity/session-binding construction
  - `./warmCapabilities/routerAbEcdsaWalletSessionAuth` and `@shared/utils/routerAbEcdsaHss` for the ECDSA sibling boundary

- Direct internal responsibilities inside the target file:
  - Parse Ed25519 wallet-session JWT identity claims and bind them to persisted session records
  - Construct runtime validation keys for Router A/B worker material
  - Parse signable Ed25519 and ECDSA wallet-session state from canonical persisted records
  - Classify persisted signing records into `runtime_validated`, `restore_available`, `auth_ready_material_pending`, `non_signing`, or `invalid`

- Direct local callers / consumers:
  - [`/Users/pta/Dev/rust/seams-sdk/packages/sdk-web/src/core/signingEngine/session/warmCapabilities/routerAbEd25519WalletSessionState.ts`](/Users/pta/Dev/rust/seams-sdk/packages/sdk-web/src/core/signingEngine/session/warmCapabilities/routerAbEd25519WalletSessionState.ts:37) turns `runtime_validated` records into executable Ed25519 wallet-session state.
  - [`/Users/pta/Dev/rust/seams-sdk/packages/sdk-web/src/core/signingEngine/flows/signNear/signNear.ts`](/Users/pta/Dev/rust/seams-sdk/packages/sdk-web/src/core/signingEngine/flows/signNear/signNear.ts:691) uses the classifier as part of NEAR signing readiness and reconnect planning.
  - [`/Users/pta/Dev/rust/seams-sdk/packages/sdk-web/src/core/signingEngine/session/availability/persistedAvailableSigningLanes.ts`](/Users/pta/Dev/rust/seams-sdk/packages/sdk-web/src/core/signingEngine/session/availability/persistedAvailableSigningLanes.ts:136) derives lane availability advisories from the classified state.
  - [`/Users/pta/Dev/rust/seams-sdk/packages/sdk-web/src/core/signingEngine/session/warmCapabilities/ed25519Authorization.ts`](/Users/pta/Dev/rust/seams-sdk/packages/sdk-web/src/core/signingEngine/session/warmCapabilities/ed25519Authorization.ts:260) reparses the same persisted record to enforce runtime auth constraints.
  - [`/Users/pta/Dev/rust/seams-sdk/packages/sdk-web/src/SeamsWeb/publicApi/near.ts`](/Users/pta/Dev/rust/seams-sdk/packages/sdk-web/src/SeamsWeb/publicApi/near.ts:46) reuses the authority parser to source a wallet-session JWT for implicit-account funding.

- Relevant transitive local flow:
  - `thresholdWarmSessionBootstrap.ts` persists the canonical Ed25519 record shape that this file consumes.
  - `routerAbWalletSessionCredential.ts` adds a later `expiresAtMs > Date.now()` check before normal-signing RPCs use the session.
  - `keyMaterialBrands.ts` provides throwing brand parsers that this file calls while classifying restorable material.

## Security / Correctness Findings

### 1. Medium: expired Ed25519 wallet sessions still parse as signable and can survive as `runtime_validated` ready state

- Evidence:
  - The Ed25519 authority parser only checks record/JWT identity binding and never enforces session lifetime: [`/Users/pta/Dev/rust/seams-sdk/packages/sdk-web/src/core/signingEngine/session/routerAbSigningWalletSession.ts:387`](/Users/pta/Dev/rust/seams-sdk/packages/sdk-web/src/core/signingEngine/session/routerAbSigningWalletSession.ts:387)
  - The main Ed25519 signing-session parser accepts any positive `remainingUses` and `expiresAtMs`, even when `expiresAtMs <= Date.now()`: [`/Users/pta/Dev/rust/seams-sdk/packages/sdk-web/src/core/signingEngine/session/routerAbSigningWalletSession.ts:814`](/Users/pta/Dev/rust/seams-sdk/packages/sdk-web/src/core/signingEngine/session/routerAbSigningWalletSession.ts:814)
  - Runtime validation and persisted-state classification build directly on that parser, so an expired record can still classify as `runtime_validated`: [`/Users/pta/Dev/rust/seams-sdk/packages/sdk-web/src/core/signingEngine/session/routerAbSigningWalletSession.ts:555`](/Users/pta/Dev/rust/seams-sdk/packages/sdk-web/src/core/signingEngine/session/routerAbSigningWalletSession.ts:555), [`/Users/pta/Dev/rust/seams-sdk/packages/sdk-web/src/core/signingEngine/session/routerAbSigningWalletSession.ts:1022`](/Users/pta/Dev/rust/seams-sdk/packages/sdk-web/src/core/signingEngine/session/routerAbSigningWalletSession.ts:1022)
  - The executable wallet-session resolver trusts `runtime_validated` classification as sufficient for a signable state: [`/Users/pta/Dev/rust/seams-sdk/packages/sdk-web/src/core/signingEngine/session/warmCapabilities/routerAbEd25519WalletSessionState.ts:37`](/Users/pta/Dev/rust/seams-sdk/packages/sdk-web/src/core/signingEngine/session/warmCapabilities/routerAbEd25519WalletSessionState.ts:37)
  - NEAR readiness then treats `runtime_validated` material as `ready` without an additional expiry check on the persisted record path: [`/Users/pta/Dev/rust/seams-sdk/packages/sdk-web/src/core/signingEngine/flows/signNear/signNear.ts:691`](/Users/pta/Dev/rust/seams-sdk/packages/sdk-web/src/core/signingEngine/flows/signNear/signNear.ts:691)
  - Available-lane policy can also advertise the same expired record as durable `ready` state when live warm status is unavailable: [`/Users/pta/Dev/rust/seams-sdk/packages/sdk-web/src/core/signingEngine/session/availability/persistedAvailableSigningLanes.ts:136`](/Users/pta/Dev/rust/seams-sdk/packages/sdk-web/src/core/signingEngine/session/availability/persistedAvailableSigningLanes.ts:136)
  - A later helper has to re-check expiry manually, which confirms the boundary is too permissive today: [`/Users/pta/Dev/rust/seams-sdk/packages/sdk-web/src/core/signingEngine/session/warmCapabilities/ed25519Authorization.ts:292`](/Users/pta/Dev/rust/seams-sdk/packages/sdk-web/src/core/signingEngine/session/warmCapabilities/ed25519Authorization.ts:292)

- Impact:
  - Expired persisted wallet sessions can remain discoverable as ready signing lanes and can progress further into planner/reconnect/UI flows than intended.
  - Failures shift downstream to later callers or relayer responses, which weakens the invariant that this module is the single boundary from raw persisted data to signable domain state.
  - The same split lets direct callers reuse a stale wallet-session JWT without any lifetime check, as shown by the implicit-account funding path: [`/Users/pta/Dev/rust/seams-sdk/packages/sdk-web/src/SeamsWeb/publicApi/near.ts:46`](/Users/pta/Dev/rust/seams-sdk/packages/sdk-web/src/SeamsWeb/publicApi/near.ts:46)

- Recommendation:
  - Make expiry a first-class branch in this boundary. `parseRouterAbEd25519SigningWalletSessionFromRecord` or the classifier should return an explicit `expired` or `budget_inactive` variant instead of treating positive-but-stale timestamps as signable.
  - Thread that narrower state into readiness, available-lane policy, and public API callers so downstream helpers can delete their duplicated expiry checks.
  - Add targeted fixtures that prove expired records cannot construct signable Ed25519 wallet-session state.

## Refactor / Slimming Findings

### 1. Session lifetime validation is fragmented across downstream helpers instead of encoded once at the boundary

- This file emits signable Ed25519 session state from `record.expiresAtMs > 0`, while downstream helpers each bolt on their own time check:
  - normal-signing ready state in [`/Users/pta/Dev/rust/seams-sdk/packages/sdk-web/src/core/signingEngine/session/warmCapabilities/routerAbWalletSessionCredential.ts`](/Users/pta/Dev/rust/seams-sdk/packages/sdk-web/src/core/signingEngine/session/warmCapabilities/routerAbWalletSessionCredential.ts:114)
  - warm authorization in [`/Users/pta/Dev/rust/seams-sdk/packages/sdk-web/src/core/signingEngine/session/warmCapabilities/ed25519Authorization.ts`](/Users/pta/Dev/rust/seams-sdk/packages/sdk-web/src/core/signingEngine/session/warmCapabilities/ed25519Authorization.ts:297)
  - NEAR readiness policy in [`/Users/pta/Dev/rust/seams-sdk/packages/sdk-web/src/core/signingEngine/flows/signNear/signNear.ts`](/Users/pta/Dev/rust/seams-sdk/packages/sdk-web/src/core/signingEngine/flows/signNear/signNear.ts:714)
- Recommendation:
  - Collapse these into one discriminated domain type at the persisted-session boundary: `signable`, `expired`, `exhausted`, `restore_only`, `invalid`.
  - Delete the repeated time/budget checks from downstream call sites once that state exists.

### 2. The boundary splits Ed25519 authority parsing, signing-session parsing, and current-state resolution into layers that still accept invalid lifetime state

- `parseRouterAbEd25519WalletSessionAuthorityFromRecord`, `parseRouterAbEd25519SigningWalletSessionFromRecord`, and `resolveRouterAbEd25519WalletSessionStateFromCurrentRecord` stack together, but none of them require an actually active lifetime: [`/Users/pta/Dev/rust/seams-sdk/packages/sdk-web/src/core/signingEngine/session/routerAbSigningWalletSession.ts:387`](/Users/pta/Dev/rust/seams-sdk/packages/sdk-web/src/core/signingEngine/session/routerAbSigningWalletSession.ts:387), [`/Users/pta/Dev/rust/seams-sdk/packages/sdk-web/src/core/signingEngine/session/routerAbSigningWalletSession.ts:814`](/Users/pta/Dev/rust/seams-sdk/packages/sdk-web/src/core/signingEngine/session/routerAbSigningWalletSession.ts:814), [`/Users/pta/Dev/rust/seams-sdk/packages/sdk-web/src/core/signingEngine/session/warmCapabilities/routerAbEd25519WalletSessionState.ts:49`](/Users/pta/Dev/rust/seams-sdk/packages/sdk-web/src/core/signingEngine/session/warmCapabilities/routerAbEd25519WalletSessionState.ts:49)
- Recommendation:
  - Replace the stacked loose helpers with one narrow builder for active Ed25519 wallet-session state and one separate parser for non-signable persisted states.
  - That split matches the repo’s “invalid states unrepresentable” guidance and removes a large class of downstream guard code.

### 3. Restorable-material classification still depends on throwing brand parsers instead of a local safe builder

- The classifier is positioned as a boundary that returns `invalid`, but its restorable-material helpers call throwing brand parsers directly: [`/Users/pta/Dev/rust/seams-sdk/packages/sdk-web/src/core/signingEngine/session/routerAbSigningWalletSession.ts:933`](/Users/pta/Dev/rust/seams-sdk/packages/sdk-web/src/core/signingEngine/session/routerAbSigningWalletSession.ts:933), [`/Users/pta/Dev/rust/seams-sdk/packages/sdk-web/src/core/signingEngine/session/keyMaterialBrands.ts:76`](/Users/pta/Dev/rust/seams-sdk/packages/sdk-web/src/core/signingEngine/session/keyMaterialBrands.ts:76)
- `records.ts` currently canonicalizes these fields before they reach this module, which limits the live risk. The escape hatch remains for unsafe casts, broad object-literal construction, or future non-canonical callers.
- Recommendation:
  - Introduce a local `tryBuildRouterAbEd25519RestorableWorkerMaterial` path that returns `null` on bad fields instead of throwing.
  - Add a targeted type fixture or regression case that proves malformed direct constructions fail cleanly at the boundary.

## Recommended Next Audit Candidates

1. `packages/sdk-web/src/core/signingEngine/flows/signNear/signNear.ts`
   - Audit NEAR readiness, reconnect, and lane-planning branches that currently trust the persisted Router A/B Ed25519 classifier.

2. `packages/sdk-web/src/core/signingEngine/session/persistence/records.ts`
   - Audit the canonical Ed25519 session-record boundary and current-session commit policy, especially lifetime and wallet-session JWT drift.

3. `packages/sdk-web/src/SeamsWeb/operations/session/thresholdWarmSessionBootstrap.ts`
   - Audit the warm-session bootstrap/update flow that writes the persisted Ed25519 facts consumed by this boundary.

## Finding Counts

- Security / correctness findings: `1`
- Refactor/slimming findings: `3`
- Total findings: `4`
