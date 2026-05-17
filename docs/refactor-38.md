# Refactor 38: Warm Session Lifetime Boundaries

Date created: 2026-05-16
Status: implemented

## Problem

Refactor 37 made ECDSA signing depend on exact canonical key and lane identity. That is the right model, and it exposed a lifecycle bug that older loose fallback behavior had been hiding.

Wallet unlock cleared warm signing sessions before warm-up. That clear path reached `UiConfirmManager.clearWarmSessionMaterial`, which cleared volatile worker memory and also performed durable session cleanup. The durable cleanup deleted sealed Shamir3pass restore records and resolved key identity. After that, reuse paths that expected exact ECDSA material could no longer find a valid sealed restore candidate and could fall into fresh bootstrap. Fresh bootstrap collects passkey credentials, so the SDK prompted TouchID during flows that should have been restore-only or reuse-only.

The failure mode is a lifetime boundary problem:

- Volatile worker material has a short lifetime and can be cleared during unlock, refresh, and normal session reset.
- Durable sealed Shamir3pass restore records have a longer lifetime and must survive normal unlock and warm-session cleanup.
- Resolved key/session identity also has a longer lifetime than worker memory and should survive ordinary volatile clears.
- Fresh bootstrap is the only path that may collect passkey credentials for ECDSA warm-up.
- Restore, reuse, status, and display-only address reads must be no-prompt paths.

The current APIs allow a single "clear warm session" operation to span multiple lifetimes. That makes it easy for future cleanup code to delete durable material from a caller that only intended to clear volatile memory.

## Solution / Proposal

Center the refactor on capability surfaces and operation commands. Abstract lifetime unions add weight unless code actually switches on the lifetime. The stronger guarantee is that each flow receives only the capabilities it is allowed to use.

The target architecture should make these states and permissions unrepresentable:

- A volatile clear command that can delete durable sealed restore records.
- A restore or reuse function that can call WebAuthn, TouchID, passkey collection, or fresh bootstrap.
- A missing exact ECDSA lane that silently becomes a fresh bootstrap request.
- A display-only owner/address read that can start credential collection.
- A diagnostics or cleanup object that can influence signing lifecycle control flow.

### Design Principle

Only prompt-capable flows may receive prompt-capable dependencies. Only durable-delete flows may receive durable-delete dependencies.

That gives the refactor one main safety property: `reuse_warm_ecdsa_bootstrap` cannot prompt because its dependency type cannot express prompting.

### Capability Surfaces

Use three top-level capability surfaces:

```ts
type VolatileWarmMaterialPort = {
  readStatus(command: ReadVolatileWarmMaterialCommand): Promise<WarmSessionStatusResult>;
  claimMaterial(command: ClaimVolatileWarmMaterialCommand): Promise<WarmSessionClaimResult>;
  clearVolatileMaterial(command: ClearVolatileWarmMaterialCommand): Promise<void>;
};

type DurableSealedSessionPort = {
  restoreExact(identity: ExactSealedSessionIdentity): Promise<RestoreSealedSessionResult>;
  readResolvedIdentity(
    identity: ExactResolvedSessionIdentity,
  ): Promise<ReadResolvedSessionIdentityResult>;
  deleteDurableRecord(command: DeleteDurableSealedSessionCommand): Promise<void>;
};

type PromptCapableBootstrapPort = {
  webauthnPrompt: WebAuthnPromptPort;
  passkeyCredentialCollector: PasskeyCredentialCollector;
  freshBootstrap: ThresholdEcdsaFreshBootstrapPort;
};
```

These can be composed into larger runtime objects at assembly boundaries. Core lifecycle functions should accept the narrowest surface they need.

### Operation Commands

Use command types for real operations. Avoid adding a generic `WarmSessionLifetime` union unless a module has a genuine exhaustive switch over lifetimes.

```ts
type ClearVolatileWarmMaterialCommand = {
  kind: 'clear_volatile_warm_material';
  scope: VolatileWarmSessionScope;
  durableRecord?: never;
  resolvedIdentity?: never;
  deleteReason?: never;
};

type DeleteDurableSealedSessionCommand = {
  kind: 'delete_durable_sealed_session';
  durableRecord: ExactSealedSessionIdentity;
  deleteReason: DurableSealedSessionDeleteReason;
  preserveResolvedIdentity: boolean;
  scope?: never;
};
```

Normal wallet unlock should only be able to construct `ClearVolatileWarmMaterialCommand`. Durable deletion should require `DeleteDurableSealedSessionCommand` and a narrow reason such as account removal, device removal, trusted persisted-record invalidation, or migration rejection.

Names should be direct at call sites:

- `clearWarmSigningSessions` becomes `clearVolatileWarmSigningMaterial`.
- `clearWarmSessionMaterial` becomes `clearVolatileWarmSessionMaterial`.
- Durable cleanup moves behind `deleteDurableSealedSessionRecord`.

### Prompt Capability Split

Give no-prompt reuse code a dependency set that cannot hold prompt-capable ports.

```ts
type NoPromptWarmSessionDeps = {
  volatile: Pick<VolatileWarmMaterialPort, 'readStatus' | 'claimMaterial'>;
  durable: Pick<DurableSealedSessionPort, 'restoreExact' | 'readResolvedIdentity'>;
  prompt?: never;
  webauthnPrompt?: never;
  touchIdPrompt?: never;
  passkeyCredentialCollector?: never;
  freshBootstrap?: never;
};

type PromptCapableWarmupDeps = {
  volatile: VolatileWarmMaterialPort;
  durable: DurableSealedSessionPort;
  prompt: PromptCapableBootstrapPort;
};
```

`reuse_warm_ecdsa_bootstrap` should restore and reuse exact material or return a typed failure.

```ts
type ReuseWarmEcdsaBootstrapResult =
  | {
      ok: true;
      source: 'volatile_material' | 'sealed_restore';
      bootstrap: ThresholdEcdsaSessionBootstrapResult;
    }
  | {
      ok: false;
      code:
        | 'missing_exact_material'
        | 'sealed_restore_failed'
        | 'sealed_record_expired'
        | 'sealed_record_exhausted';
      promptAllowed?: never;
      webauthnAuthentication?: never;
    };
```

Fresh bootstrap should be invoked only from explicit warm-up or enrollment flows that already have `PromptCapableWarmupDeps`.

### Flow Contracts

Wallet unlock should run as a restore-then-warm flow:

1. Clear volatile worker material for the wallet scope.
2. Read exact sealed session capabilities and resolved identities.
3. Restore sealed passkey sessions that are still valid.
4. Rebuild exact ECDSA warm material.
5. Return typed reuse status.
6. Run fresh warm-up only when the caller explicitly requested prompt-capable warm-up.

ECDSA reuse should run as a no-prompt exact-material flow:

1. Try exact volatile material.
2. Try exact sealed restore.
3. Try exact volatile material again.
4. If restored PRF/JWT material is warm but exact additive-share material is
   absent, reconnect through threshold-session auth without prompt-capable
   dependencies.
5. Return `ok: false` on miss.

Display-only session or address reads after login should use wallet session metadata and resolved identity. They should return a missing-state result when metadata is unavailable.

## Structs And Flows To Edit

### Volatile Cleanup Flow

Edit these first because they currently make the destructive lifetime boundary ambiguous:

- `client/src/core/signingEngine/session/warmCapabilities/clearWarmSigningSessions.ts`
  - Rename `clearWarmSigningSessions` to `clearVolatileWarmSigningMaterial`.
  - Rename `ClearWarmSigningSessionsDeps` to `ClearVolatileWarmSigningMaterialDeps`.
  - Make the dependency accept only volatile material clear ports.
  - Remove any dependency path that can delete sealed records or resolved identity.
- `client/src/core/signingEngine/session/warmCapabilities/public.ts`
  - Rename `WarmCapabilitiesPublicDeps.clearWarmSigningSessions`.
  - Rename the public API method to the volatile-only name or move it behind an internal-only session maintenance API.
  - Keep public persistence, hydration, and status reads separate from volatile cleanup.
- `client/src/core/signingEngine/assembly/ports/warmSigning.ts`
  - Wire the renamed volatile cleanup API.
  - Pass a volatile-only UiConfirm port into cleanup call sites.
- `client/src/core/signingEngine/uiConfirm/types.ts`
  - Split `WarmSessionMaterialClearer` and `WarmSessionMaterialClearAll` into `VolatileWarmSessionMaterialClearer` and `VolatileWarmSessionMaterialClearAll`.
  - Replace broad `WarmSessionMaterialPort` usage in core lifecycle code with `VolatileWarmMaterialPort`, `DurableSealedSessionPort`, and `PromptCapableBootstrapPort`.
  - Keep status, claim, consume, seal persistence, restore, delete, and prompt subports only where they reduce call-site dependencies.
- `client/src/core/types/secure-confirm-worker.ts`
  - Rename worker messages that clear in-memory material to volatile names.
  - Replace session-id-only durable delete payloads with exact durable delete commands.

### Durable Sealed Session Flow

Edit these after the volatile path is narrow:

- `client/src/core/signingEngine/uiConfirm/UiConfirmManager.ts`
  - Replace `deletePasskeySealedRecord` and `cleanupSigningSession` with explicit durable delete command handlers.
  - Rename `clearWarmSessionMaterial` to `clearVolatileWarmSessionMaterial` and keep it worker-memory-only.
  - Rename `clearAllWarmSessionMaterial` to `clearAllVolatileWarmSessionMaterial`; durable all-delete should use a separate explicit command.
  - Replace `deletePersistedWarmSessionMaterial` with an explicit durable deletion path that accepts exact purpose and reason commands.
- `client/src/core/signingEngine/session/persistence/sealedSessionStore.ts`
  - Introduce command-level entry points for durable deletion.
  - Keep `deleteExactSealedSession` behind the durable command parser or replace it with a command-shaped API.
  - Make resolved identity deletion an explicit branch of durable delete behavior.
- `client/src/core/signingEngine/session/sealedRecovery/recoveryRecord.ts`
  - Keep `RawSigningSessionSealedStoreRecord` as the persistence boundary shape.
  - Build exact internal identities from accepted `SealedRecoveryRecord` values.
- `client/src/core/signingEngine/session/sealedRecovery/types.ts`
  - Replace broad restore inputs with exact restore identities where core code needs exact records.
  - Keep list inputs as boundary queries.
- `client/src/core/signingEngine/session/sealedRecovery/restoreCoordinator.ts`
  - Make restore commands return typed results for `restored`, `ready`, `deferred`, and rejected/missing exact record states.
  - Keep restore no-prompt by dependency shape.

### ECDSA Reuse And Bootstrap Flow

Edit these to prevent reuse from becoming credential collection:

- `client/src/core/signingEngine/session/passkey/ecdsaBootstrap.ts`
  - Keep `ReuseWarmEcdsaBootstrapRequest` as no-prompt.
  - Ensure `PasskeyFreshEcdsaBootstrapRequest`, `PasskeyCookieReconnectEcdsaBootstrapRequest`, and `ThresholdSessionAuthReconnectEcdsaBootstrapRequest` are reachable only from prompt-capable or explicit reconnect flows.
  - Split `ThresholdSessionActivationDeps` away from no-prompt reuse dependencies.
- `client/src/core/signingEngine/session/passkey/ecdsaWarmCapabilityBootstrap.ts`
  - Split `BootstrapWarmEcdsaCapabilityDeps` into `NoPromptWarmSessionDeps` and `PromptCapableWarmupDeps`.
  - Change `bootstrapReuseWarmEcdsaCapability` to call only exact material restore/reuse helpers.
  - Remove reuse-branch calls to `claimPasskeyEcdsaPrfFirst`, `bootstrapPasskeyCookieReconnect`, and `bootstrapDirectEcdsaRequest`.
- `client/src/core/signingEngine/session/passkey/ecdsaProvisioner.ts`
  - Keep `tryReuseReadyWarmEcdsaBootstrap` exact-lane-only.
  - Return typed missing-material results instead of `null` where callers need lifecycle decisions.
- `client/src/core/signingEngine/session/warmCapabilities/types.ts`
  - Add no-prompt restore/reuse result unions.
  - Keep `WarmSessionEcdsaCapabilityState` exact about `record`, `key`, and `lane`.
- `client/src/core/signingEngine/flows/signEvmFamily/ecdsaMaterialState.ts`
  - Keep the refactor-37 material state collapsed to `missing | ready_material`.
  - Add tests if any new branch attempts to represent partial key/session material.

### Unlock, Status, And Display Reads

Edit these flows so status and address reads cannot trigger prompt-capable bootstrap:

- Wallet unlock warm-up flow in the SDK/signing engine assembly.
  - Clear volatile worker material.
  - Restore exact sealed sessions.
  - Rebuild exact ECDSA warm material.
  - Return typed reuse status.
  - Enter fresh warm-up only from an explicit prompt-capable branch.
- `client/src/core/signingEngine/session/availability/readiness.ts`
  - Review `clearWalletSigningSession` and `syncSealedRefreshPolicyForLanes`.
  - Keep budget/status expiry policy distinct from volatile cleanup.
  - Route durable deletion through exact durable delete commands.
- `examples/seams-site/src/flows/demo/hooks/useDemoThresholdAccountState.ts`
  - Replace display-only owner/address bootstrap calls with wallet metadata and resolved identity reads.
  - Return typed missing-state results for display gaps.
- `examples/seams-docs/src/getting-started/next-steps.md`
  - Update examples if `reuse_warm_ecdsa_bootstrap` result handling changes.

## Legacy Structs And Types To Delete Or Replace

Delete these broad or ambiguous shapes as soon as their replacements compile. Do not leave aliases or deprecated exports.

- `ClearWarmSigningSessionsDeps`
  - Replace with `ClearVolatileWarmSigningMaterialDeps`.
- `clearWarmSigningSessions`
  - Replace with `clearVolatileWarmSigningMaterial`.
- `clearWarmSessionMaterial`
  - Replace with `clearVolatileWarmSessionMaterial`.
- `WarmSessionMaterialClearer`
  - Replace with `VolatileWarmSessionMaterialClearer`.
- `WarmSessionMaterialClearAll`
  - Replace with `VolatileWarmSessionMaterialClearAll`.
- Broad `WarmSessionMaterialPort`
  - Replace with the three capability surfaces and smaller subports where call sites need narrower dependencies.
- `WarmSessionPersistedRecordDeleter`
  - Replace with `DurableSealedSessionRecordDeleter`.
- `WarmSessionDeletePersistedPayload`
  - Replace with a command that includes exact durable identity and a durable delete reason.
- `cleanupSigningSession`
  - Replace with branch-specific durable policy handlers such as `deleteExpiredDurableSealedSession`, `deleteTrustedPersistedSealedSession`, and `preserveIdentityForExhaustedSession`.
- `deletePasskeySealedRecord`
  - Replace with `deleteDurableSealedSessionRecord(command)`.
- `clearAllWarmSessionMaterial`
  - Replace with a volatile-only all-clear. Any durable all-delete operation should have a separate name and explicit command type.
- `BootstrapWarmEcdsaCapabilityDeps`
  - Replace with `NoPromptWarmSessionDeps` and `PromptCapableWarmupDeps`.
- `bootstrapReuseWarmEcdsaCapability` fallback branches that construct reconnect/fresh bootstrap requests.
  - Replace with typed failure results from exact restore/reuse.
- Session-id-only delete worker messages and payloads.
  - Replace with exact durable delete worker messages where durable deletion remains worker-owned.

Clean up compatibility during replacement:

- Remove old aliases and deprecated exports.
- Remove broad object-spread construction of lifecycle command objects.
- Remove helper overloads that accept raw strings for core lifecycle functions.
- Keep raw and compatibility shapes only at persistence, worker-message, iframe-message, and public-request boundaries.

## Shamir3pass WASM Scope

No Rust WASM changes are expected for this refactor.

`wasm/shamir3pass_runtime/src/lib.rs` exposes pure Shamir3pass operations: generate client lock keys, add a lock, and remove a lock. It has no wallet unlock lifecycle, durable sealed-record persistence, resolved identity store, or WebAuthn/TouchID prompt capability. The regression was caused by TypeScript lifecycle cleanup and bootstrap orchestration.

Keep the Rust crate unchanged unless the sealed-record cryptographic format or Shamir3pass wire protocol changes. The TypeScript worker wrapper can remain unchanged unless message names are renamed for clarity; even then the change should stay at `client/src/core/signingEngine/workerManager/workers/shamir3pass.worker.ts` and `client/src/core/signingEngine/workerManager/workers/shamir3pass/runtime.ts`.

## Implementation Plan

### Phase 1: Split Capability Surfaces And Commands

Audit warm-session cleanup entry points and classify each one by operation. Create `ClearVolatileWarmMaterialCommand` and `DeleteDurableSealedSessionCommand`. Wire core lifecycle code through `VolatileWarmMaterialPort`, `DurableSealedSessionPort`, and `PromptCapableBootstrapPort`.

Phase 1 todo:

- [x] Inventory every call to `clearWarmSigningSessions`, `clearWarmSessionMaterial`,
      durable sealed-session cleanup, and resolved identity deletion.
- [x] Rename `clearWarmSigningSessions` to
      `clearVolatileWarmSigningMaterial`.
- [x] Rename `ClearWarmSigningSessionsDeps` to
      `ClearVolatileWarmSigningMaterialDeps`.
- [x] Rename `clearWarmSessionMaterial` to
      `clearVolatileWarmSessionMaterial`.
- [x] Rename `clearAllWarmSessionMaterial` to
      `clearAllVolatileWarmSessionMaterial`.
- [x] Split `WarmSessionMaterialClearer` and `WarmSessionMaterialClearAll`
      into volatile-only clearer interfaces.
- [x] Rename worker messages that clear in-memory material to volatile names.
- [x] Remove durable sealed-session deletion from volatile all-clear.
- [x] Update SDK wallet lock/unlock clear call sites to use volatile naming.
- [x] Avoid adding a generic `WarmSessionLifetime` union.
- [x] Add and wire `DeleteDurableSealedSessionCommand` through the durable
      deletion path.
- [x] Replace session-id-only durable delete payloads with exact durable delete
      commands.
- [x] Split broad warm-session capability surfaces into
      `VolatileWarmMaterialPort`, `DurableSealedSessionPort`, and
      `PromptCapableBootstrapPort`.
- [x] Update any iframe/public worker bridge that exposes durable cleanup to
      accept command-shaped durable deletes only.

### Phase 2: Introduce Boundary Builders

Add builders/parsers for:

- `VolatileWarmSessionScope`
- `ExactSealedSessionIdentity`
- `ExactResolvedSessionIdentity`
- `DurableSealedSessionDeleteReason`
- `ResolvedIdentityDeleteReason`

These builders should validate raw DB records, worker responses, iframe messages, and route bodies once at the boundary. Core cleanup and reuse functions should accept only precise internal types.

Phase 2 todo:

- [x] Add a `VolatileWarmSessionScope` boundary builder for worker and public
      message payloads.
- [x] Add an `ExactSealedSessionIdentity` boundary parser for durable delete
      command payloads.
- [x] Add `ExactSealedSessionIdentity` builders from accepted sealed records
      and exact lane/session identity.
- [x] Add an `ExactResolvedSessionIdentity` builder for resolved key/session
      identity reads.
- [x] Add a `DurableSealedSessionDeleteReason` parser that rejects broad or
      display-only reasons.
- [x] Add a `ResolvedIdentityDeleteReason` parser and require it anywhere
      resolved identity is deleted.
- [x] Normalize raw DB records, worker responses, iframe messages, and route
      bodies once at boundaries.
- [x] Ensure core cleanup and reuse functions no longer accept raw strings,
      partial identity objects, or compatibility shapes.

### Phase 3: Make Reuse No-Prompt By Type

Change `reuse_warm_ecdsa_bootstrap` and adjacent restore paths to accept `NoPromptWarmSessionDeps`. Return `ReuseWarmEcdsaBootstrapResult` for missing material, restore failure, expired sealed records, and exhausted sealed records.

The reuse implementation should try exact volatile material, restore exact sealed material, try exact volatile material again, optionally reconnect through threshold-session auth using restored no-prompt PRF/JWT material, then fail closed with a typed result. Callers that want fresh bootstrap should handle the typed failure and enter an explicit prompt-capable flow.

Phase 3 todo:

- [x] Split `BootstrapWarmEcdsaCapabilityDeps` into
      `NoPromptWarmSessionDeps` and `PromptCapableWarmupDeps`.
- [x] Make `reuse_warm_ecdsa_bootstrap` accept no-prompt dependencies only.
- [x] Add `ReuseWarmEcdsaBootstrapResult` with typed miss, restore failure,
      expired, and exhausted branches.
- [x] Change reuse to try exact volatile material first.
- [x] Change reuse to restore exact sealed material second.
- [x] Change reuse to re-read exact volatile material after restore.
- [x] Return a typed failure on miss instead of throwing or entering a prompt
      path.
- [x] Remove reuse-branch calls to `claimPasskeyEcdsaPrfFirst`.
- [x] Remove reuse-branch calls to `bootstrapPasskeyCookieReconnect`.
- [x] Remove reuse-branch calls to `bootstrapDirectEcdsaRequest`.
- [x] Keep fresh bootstrap reachable only from explicit prompt-capable warm-up,
      enrollment, or reconnect flows.
- [x] Update callers to handle typed reuse failures and decide separately
      whether a prompt-capable flow is allowed.

### Phase 4: Keep Restore No-Prompt And Explicit Unlock Prompt-Capable

Update orchestration so no-prompt restore stays limited to page-refresh and signing-session rehydration paths. Explicit passkey wallet unlock should clear volatile material, then provision fresh Ed25519 and ECDSA warm lanes through the prompt-capable branch. Durable sealed records remain available for rehydration outside explicit unlock, but unlock must not silently reuse them.

Phase 4 todo:

- [x] Update wallet unlock orchestration to clear volatile worker material first.
- [x] Keep exact sealed passkey Ed25519 and ECDSA restore on no-prompt
      rehydration paths.
- [x] Prevent explicit passkey unlock from using restored warm material as its
      completed session.
- [x] Rebuild exact ECDSA warm material from canonical key identity during fresh
      unlock warm-up.
- [x] Enter fresh unlock warm-up only from the explicit prompt-capable branch.
- [x] Add regression coverage proving page refresh rehydration does not prompt
      when restore material is valid.
- [x] Add regression coverage proving explicit passkey unlock provisions fresh
      sessions even when restored sessions exist.
- [x] Add regression coverage proving missing exact material fails closed before
      fresh bootstrap is attempted.

### Phase 5: Protect Display-Only Reads

Route demo and SDK post-login address reads through wallet session metadata and resolved identity readers. These reads should have no prompt-capable dependencies and should fail closed with a typed missing-state result.

Phase 5 todo:

- [x] Inventory display-only owner/address/session reads after login.
- [x] Move display-only owner/address reads to wallet session metadata and
      resolved identity readers.
- [x] Remove display-only calls to `reuse_warm_ecdsa_bootstrap`.
- [x] Ensure display reads receive no prompt-capable dependencies.
- [x] Return typed missing-state results for display gaps.
- [x] Update demo hooks and docs examples if reuse result handling changes.

### Phase 6: Static Guards And Type Fixtures

Add targeted tests and type fixtures for lifecycle boundaries:

Phase 6 todo:

- [x] Add `@ts-expect-error` fixtures for
      `ClearVolatileWarmMaterialCommand` objects that include durable record
      fields.
- [x] Add `@ts-expect-error` fixtures for
      `DeleteDurableSealedSessionCommand` objects that include volatile clear
      scopes or omit exact ECDSA target identity.
- [x] Add unit coverage proving volatile clears preserve durable sealed
      Shamir3pass restore records.
- [x] Add `@ts-expect-error` fixtures for no-prompt reuse dependencies that
      include WebAuthn or TouchID prompt ports.
- [x] Add `@ts-expect-error` fixtures for reuse failure results that carry
      prompt or authentication payloads.
- [x] Add exhaustive `switch` checks over `ReuseWarmEcdsaBootstrapResult`.
- [x] Add exhaustive `switch` checks over durable delete reason unions.
- [x] Add unit coverage proving reuse restores exact ECDSA material without
      WebAuthn calls.
- [x] Add unit coverage proving missing exact material fails closed without
      prompt side effects.
- [x] Add static guard tests that fail if no-prompt paths import or reference
      `TouchIdPrompt`, `collectAuthenticationCredential`,
      `claimPasskeyEcdsaPrfFirst`, `bootstrapPasskeyCookieReconnect`,
      `bootstrapDirectEcdsaRequest`, or fresh bootstrap ports.

### Phase 7: Validation

Run the cheapest checks that cover the lifecycle boundary:

Phase 7 todo:

- [x] Run SDK type-check after the volatile clear split.
- [x] Run focused volatile clear and worker router tests after the volatile
      clear split.
- [x] Run SDK type-check and SDK build after durable delete command and
      volatile boundary parser wiring.
- [x] Run focused durable delete, volatile clear, worker router, and Email OTP
      coordinator tests after durable delete command and volatile boundary
      parser wiring.
- [x] Run targeted unit tests for unlock restore-before-warm-up behavior.
- [x] Run targeted unit tests for durable delete command behavior.
- [x] Run targeted unit tests for no-prompt ECDSA reuse.
- [x] Run type fixtures for invalid command and dependency shapes.
- [x] Run guard tests for forbidden prompt-capable calls in no-prompt paths.
- [x] Manually verify same-tab refresh, wallet unlock, and post-login address
      refresh prompt counts.

Run broader SDK or app suites only if the implementation touches shared public messages, persistence schemas, iframe protocol, or signing engine interfaces.

## Current Implementation Cursor

- Phase 1 volatile clear rename/split and durable delete command wiring are
  implemented and validated.
- Phase 1 named capability surfaces are introduced and narrow warm-session call
  sites now depend on volatile or durable slices instead of the full bridge.
- Phase 2 volatile scope parsing, exact durable identity parsing/builders,
  durable delete reason parsing, exact resolved identity building, and resolved
  identity delete reasons are implemented. Volatile session clears now require
  parsed `VolatileWarmSessionId` command objects at core call sites.
- Phase 3 no-prompt ECDSA reuse is narrowed to exact volatile material, exact
  sealed restore, threshold-session-auth reconnect from restored PRF/JWT
  material, and typed no-prompt failures. The public bootstrap wrapper still
  maps typed failures to the existing thrown error contract, and the
  warm-signing assembly caller handles typed reuse failures explicitly.
- Phase 4 explicit passkey unlock now clears volatile material first and
  provisions fresh three-use Ed25519 and ECDSA lanes through the prompt-capable
  branch. Page-refresh rehydration keeps using exact sealed restore without a
  prompt.
- Phase 5 display-only owner address reads now use wallet session metadata with
  typed missing-state results, and the stale `bootstrapIfMissing` hook option is
  removed from demo signing actions.
- Phase 7 validation is complete. Focused unit coverage exercises volatile
  clear, durable restore, no-prompt reuse, restored ECDSA reconnect, and worker
  router boundaries; the wallet-iframe same-tab sealed-refresh e2e verifies no
  extra WebAuthn prompt after reload.
