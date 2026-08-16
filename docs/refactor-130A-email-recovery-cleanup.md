# Refactor 130A — Legacy Email Recovery Cleanup

Status: implemented.

## Decision

Remove the legacy inbound-email recovery system without replacing it. Email
recovery V2 is a separate, deferred project recorded in
[Refactor 130B](./refactor-130B-email-recovery-v2.md).

The existing set of 10 one-time recovery codes remains supported. No successor
to the deleted DKIM flow is introduced. The cleanup is an accepted breaking
change for users who depended on recovery email configuration or the
DKIM/Outlayer flow.

## Goal

Delete the complete DKIM/Outlayer/on-chain EmailRecoverer path:

- recovery email configuration and local email/hash mappings;
- recovery preparation and execution state;
- raw RFC822 ingress and parsing;
- EmailDKIMVerifier and Outlayer cryptography;
- on-chain EmailRecoverer action construction;
- public SDK, wallet iframe, server, worker, demo, and documentation surfaces.

Leave the codebase in the state it would have had if this recovery system had
never shipped. Keep historical migrations immutable and use forward migrations
to remove retired durable data.

## Implementation status

The cleanup is implemented in the current branch. Legacy DKIM/Outlayer ingress,
server state, routes, public and iframe email-management APIs, browser email
records, demo enrollment UI, shared email-recovery helpers, and retired WASM
bindings have been removed. A forward D1 migration drops the retired server
tables, and the wallet database upgrade removes the old `recovery_emails` store.
Recovery codes, wallet-custody recovery, Email OTP, and account synchronization
remain supported. Refactor 130B remains deferred and has no runtime scaffolding.

Focused SDK/server type checks, the near-signer Cargo check, cleanup source
guards, and the rebuilt IndexedDB consolidation tests pass. The aggregate source
guard command currently stops on a stale allowlist entry from unrelated
concurrent work; that entry is outside this cleanup.

## Boundaries

This cleanup preserves:

- recovery-code generation, wrapping, backup acknowledgement, consumption,
  wallet-custody recovery, display, and rotation;
- Email OTP registration, authentication, unlock, and recovery-wrapped
  enrollment escrow;
- account synchronization after its email-recovery wrapper is removed;
- general WebAuthn, wallet replacement, Ed25519 Yao, ECDSA, ChaCha20, X25519,
  HKDF, and SHA-256 behavior that still has a non-legacy caller.

This cleanup does not:

- implement recovery contacts, social recovery, outbound approval links, or a
  replacement email-recovery schema;
- add feature flags, compatibility routes, request adapters, placeholder domain
  types, reserved tables, dual writes, or preparatory abstractions for 130B;
- modify historical D1 migration files;
- preserve tests, fixtures, exports, or configuration solely for the retired
  system.

## Cleanup Plan

Classify every failing legacy-only test or fixture as
`obsolete_test_or_fixture` before changing it. Delete obsolete coverage with the
production path it protects. Preserve tests that own supported recovery-code and
Email OTP behavior.

### 1. Server domain and route removal

- [ ] Delete `packages/sdk-server-ts/src/email-recovery/`, including RFC822
      parsing, Outlayer encryption, EmailDKIMVerifier lookup, EmailRecoverer
      action construction, WASM adapters, RPC calls, and test helpers.
- [ ] Delete the `/email-recovery/prepare` and `/recover-email` handlers, request
      parsers, route definitions, route-surface entries, execution-context
      services, and capability checks.
- [ ] Delete `EmailRecoveryPreparationStore` and
      `emailRecoveryAuthOperations`.
- [ ] Delete the legacy recovery-session and recovery-execution domain after
      confirming its production callers are confined to the retired flow. This
      includes `RecoverySessionStore`, `RecoveryExecutionStore`, record parsers,
      tracking operations, D1 session adapters, service ports, and
      `router/domains/emailRecovery/recoveryExecutionTracking.ts`.
- [ ] Remove construction and exposure of the retired services from
      `AuthService`, its store registry, D1 router assembly, router options, and
      `@seams/sdk-server` exports.
- [ ] Delete server defaults and SDK configuration for the DKIM verifier,
      Outlayer worker secret, recovery recipient, and any other setting whose
      only consumer was the retired flow.
- [ ] Remove raw recovery-email ingress from the Cloudflare email runtime and web
      server. If the runtime module has no remaining email consumer, delete the
      module and its worker hook.
- [ ] Remove `/recover-email` forwarding and retired table assumptions from the
      console D1 gateway, local worker, generated configuration, smoke commands,
      pricing metadata, and deployment examples.

### 2. Durable server data removal

- [ ] Add one forward D1 migration that drops
      `email_recovery_preparations`, `recovery_sessions`, and
      `recovery_executions`, including their indexes. Current production use of
      the last two tables must be rechecked immediately before writing the
      migration.
- [ ] Remove the three tables from current schema manifests, local D1 bootstrap,
      gateway allowlists, table-count smoke checks, fixtures, and D1 adapters.
- [ ] Keep `0001_signer_d1_initial.sql` and every other applied historical
      migration unchanged.
- [ ] Preserve `email_otp_recovery_wrapped_enrollment_escrows` and every current
      recovery-code table or record.

### 3. SDK and wallet surface removal

- [ ] Remove `getRecoveryEmails` and `setRecoveryEmails` from the public recovery
      capability, declarations, React forwarding surface, and public type
      fixtures.
- [ ] Delete the email-address branches in
      `SeamsWeb/operations/recovery/emailRecovery.ts`. Move `syncAccount` into an
      account-sync domain with a domain-accurate context name, then delete the
      email-recovery wrapper and types.
- [ ] Remove `PM_GET_RECOVERY_EMAILS` and `PM_SET_RECOVERY_EMAILS` from wallet
      iframe message unions, payloads, client methods, host handlers, request
      routing, runtime contexts, and fixtures.
- [ ] Delete `packages/sdk-web/src/utils/emailRecovery/`.
- [ ] Remove on-chain recovery-email hash reads and writes, recovery-email
      account data, legacy lifecycle events, and account-replacement branches
      only after their callers are confirmed to belong to this retired path.
- [ ] Remove `emailDkimVerifierContract` and the enclosing legacy
      `relayer.emailRecovery` configuration shape from defaults, builders,
      examples, comments, and public configuration types.

### 4. Browser data and demo removal

- [ ] Remove the `recovery_emails` IndexedDB store, record types, repository
      methods, manager methods, schema names, and exports.
- [ ] Increment the wallet database version and add `recovery_emails` to the
      scoped obsolete-store deletion list so existing records are removed during
      the normal database upgrade.
- [ ] Update the IndexedDB consolidation fixture and assertions to the new
      schema. Delete recovery-email-only fixture data.
- [ ] Delete `SetupEmailRecovery`, `EmailRecoveryFields`, their styles and color
      allowlist entries, and their integration from the demo `SyncAccount` flow.

### 5. Shared utilities and WASM removal

- [ ] Delete `packages/shared-ts/src/utils/recoveryEmail.ts` and its barrel export
      once the server parsers and execution tracker are gone.
- [ ] Delete `wasm/near_signer/src/threshold/email_recovery_crypto.rs` and its
      exports if the post-cleanup import graph confirms the functions have no
      supported caller. Current repository references indicate that the
      `email_recovery_*` bindings serve the retired server adapter.
- [ ] Keep shared cryptographic primitives under their existing domain owners
      when supported callers remain. Do not retain renamed wrappers solely in
      anticipation of 130B.

### 6. Tests, guards, and documentation

- [ ] Delete unit tests for email encryption, email subject or body parsing,
      `/recover-email` parsing, preparation, recovery session and execution
      stores, and execution tracking.
- [ ] Delete or narrow route, D1, source-guard, type, and fixture assertions that
      encode the retired services, tables, bindings, exports, or message kinds.
      Keep the portions that enforce current behavior.
- [ ] Remove active README and API documentation for `/recover-email`,
      `/email-recovery/prepare`, recovery email hashes, Outlayer, DKIM recovery,
      and the removed public methods. Historical refactor documents may retain
      historical references.
- [ ] Update `docs/intended-behaviours.md` to describe saved one-time recovery
      codes accurately and remove claims that the retired email flow is
      supported.
- [ ] Review UI copy that says “Recover Account with Email.” Preserve the Email
      OTP or Google authentication flow when it remains supported, and label it
      according to the behavior it actually performs so it does not advertise
      the deleted system.

## Verification

### Absence checks

- [ ] Production source and generated declarations contain no
      `EmailRecoveryService`, `EmailRecoveryPreparationStore`,
      `EmailRecoveryAuthOperations`, `RecoverySessionStore`,
      `RecoveryExecutionStore`, `PM_GET_RECOVERY_EMAILS`,
      `PM_SET_RECOVERY_EMAILS`, `emailDkimVerifierContract`,
      `RECOVER_EMAIL_RECIPIENT`, or `email_recovery_*` binding.
- [ ] Production route manifests and workers contain neither `/recover-email`
      nor `/email-recovery/prepare`.
- [ ] Public SDK declarations contain neither `getRecoveryEmails` nor
      `setRecoveryEmails`.
- [ ] The active D1 schema and local bootstrap contain none of
      `email_recovery_preparations`, `recovery_sessions`, or
      `recovery_executions`; the forward migration is the only active reference
      required to drop them.
- [ ] The wallet IndexedDB manifest contains no `recovery_emails` store, and the
      scoped upgrade deletes that old store.
- [ ] The retired HTTP routes return 404 through the production router.

### Preserved behavior

- [ ] Current wallet recovery-code status, backup acknowledgement, preparation,
      finalization, and rotation tests pass.
- [ ] Passkey and Email OTP registration and unlock intended-behavior contracts
      pass.
- [ ] Account synchronization still works through its renamed standalone
      domain.
- [ ] Email OTP escrow and recovery-code storage remain present in the D1 schema
      and runtime assembly.

### Commands

- [ ] Run the narrow recovery-code, account-sync, router-route, IndexedDB, and
      D1 migration tests touched by the cleanup.
- [ ] Run `pnpm test:intended` because this change removes a public lifecycle
      path and modifies shared public types and storage.
- [ ] Run `pnpm test:source-guards` and update or delete only guards that encode
      the retired design.
- [ ] Run `pnpm check` and `git diff --check`.

## Completion Criteria

- The legacy DKIM/Outlayer/on-chain email-recovery system is absent from runtime
  code, routes, worker handlers, public declarations, configuration, storage
  access, IndexedDB, demos, and active documentation.
- Applied historical migrations remain unchanged, and forward migrations remove
  retired server and browser data.
- Recovery codes remain documented and supported, with no claim that the
  retired email flow is available.
- Email OTP authentication, recovery-wrapped escrow, account synchronization,
  and wallet recovery-code behavior pass their authoritative coverage.
- No code, schema, flag, compatibility path, or placeholder for Refactor 130B is
  introduced.
