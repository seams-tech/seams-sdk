# Refactor 111 — Legacy Email Recovery Cleanup

Status: complete.

## Decision

Remove the legacy inbound-email recovery system without replacing it.
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
remain supported.

Focused SDK/server type checks, the near-signer Cargo check, cleanup source
guards, and the rebuilt IndexedDB consolidation tests passed when the cleanup
landed in `dc2eeb21f` (`refactor: remove legacy email recovery`). Migration
history was subsequently restored in `a3669caa3` without reintroducing the
retired tables or runtime paths.

## Completion audit — 2026-08-26

The cleanup is complete. A current absence scan found no retired runtime, route,
public SDK, iframe, configuration, browser-storage, or WASM symbols. The only
retired D1 table references are the immutable initial migration, the forward
drop migration, and the migration smoke assertion that confirms the tables are
absent. The surviving Outlayer references belong to the independent sponsored
gas-pricing feature.

The focused cleanup source guards, recovery-code tests, D1 migration smoke,
canonical IndexedDB schema tests, near-signer Cargo check, and `git diff --check`
pass. Broader current-branch checks expose unrelated in-progress device-linking,
route, fixture, billing, identity-store, and console allowlist failures. Those
failures do not reference or restore the retired email-recovery system.

## Boundaries

This cleanup preserves:

- recovery-code generation, wrapping, backup acknowledgement, consumption,
  wallet-custody recovery, display, and rotation;
- Email OTP registration, authentication, unlock, and recovery-wrapped
  enrollment escrow;
- account synchronization after its email-recovery wrapper is removed;
- general WebAuthn, wallet replacement, Ed25519 Yao, ECDSA, ChaCha20, X25519,
  HKDF, and SHA-256 behavior that still has a non-legacy caller.


## Cleanup Plan

Classify every failing legacy-only test or fixture as
`obsolete_test_or_fixture` before changing it. Delete obsolete coverage with the
production path it protects. Preserve tests that own supported recovery-code and
Email OTP behavior.

### 1. Server domain and route removal

- [x] Delete `packages/wallet-server/src/email-recovery/`, including RFC822
      parsing, Outlayer encryption, EmailDKIMVerifier lookup, EmailRecoverer
      action construction, WASM adapters, RPC calls, and test helpers.
- [x] Delete the `/email-recovery/prepare` and `/recover-email` handlers, request
      parsers, route definitions, route-surface entries, execution-context
      services, and capability checks.
- [x] Delete `EmailRecoveryPreparationStore` and
      `emailRecoveryAuthOperations`.
- [x] Delete the legacy recovery-session and recovery-execution domain after
      confirming its production callers are confined to the retired flow. This
      includes `RecoverySessionStore`, `RecoveryExecutionStore`, record parsers,
      tracking operations, D1 session adapters, service ports, and
      `router/domains/emailRecovery/recoveryExecutionTracking.ts`.
- [x] Remove construction and exposure of the retired services from
      `AuthService`, its store registry, D1 router assembly, router options, and
      `@seams/wallet-server` exports.
- [x] Delete server defaults and SDK configuration for the DKIM verifier,
      Outlayer worker secret, recovery recipient, and any other setting whose
      only consumer was the retired flow.
- [x] Remove raw recovery-email ingress from the Cloudflare email runtime and web
      server. If the runtime module has no remaining email consumer, delete the
      module and its worker hook.
- [x] Remove `/recover-email` forwarding and retired table assumptions from the
      console D1 gateway, local worker, generated configuration, smoke commands,
      pricing metadata, and deployment examples.

### 2. Durable server data removal

- [x] Add one forward D1 migration that drops
      `email_recovery_preparations`, `recovery_sessions`, and
      `recovery_executions`, including their indexes. Current production use of
      the last two tables must be rechecked immediately before writing the
      migration.
- [x] Remove the three tables from current schema manifests, local D1 bootstrap,
      gateway allowlists, table-count smoke checks, fixtures, and D1 adapters.
- [x] Keep `0001_signer_d1_initial.sql` and every other applied historical
      migration unchanged.
- [x] Preserve `email_otp_recovery_wrapped_enrollment_escrows` and every current
      recovery-code table or record.

### 3. SDK and wallet surface removal

- [x] Remove `getRecoveryEmails` and `setRecoveryEmails` from the public recovery
      capability, declarations, React forwarding surface, and public type
      fixtures.
- [x] Delete the email-address branches in
      `SeamsWeb/operations/recovery/emailRecovery.ts`. Move `syncAccount` into an
      account-sync domain with a domain-accurate context name, then delete the
      email-recovery wrapper and types.
- [x] Remove `PM_GET_RECOVERY_EMAILS` and `PM_SET_RECOVERY_EMAILS` from wallet
      iframe message unions, payloads, client methods, host handlers, request
      routing, runtime contexts, and fixtures.
- [x] Delete `packages/wallet/src/utils/emailRecovery/`.
- [x] Remove on-chain recovery-email hash reads and writes, recovery-email
      account data, legacy lifecycle events, and account-replacement branches
      only after their callers are confirmed to belong to this retired path.
- [x] Remove `emailDkimVerifierContract` and the enclosing legacy
      `relayer.emailRecovery` configuration shape from defaults, builders,
      examples, comments, and public configuration types.

### 4. Browser data and demo removal

- [x] Remove the `recovery_emails` IndexedDB store, record types, repository
      methods, manager methods, schema names, and exports.
- [x] Increment the wallet database version and ensure the canonical schema
      upgrade deletes the retired recovery-email store and its existing records.
- [x] Update the IndexedDB consolidation fixture and assertions to the new
      schema. Delete recovery-email-only fixture data.
- [x] Delete `SetupEmailRecovery`, `EmailRecoveryFields`, their styles and color
      allowlist entries, and their integration from the demo `SyncAccount` flow.

### 5. Shared utilities and WASM removal

- [x] Delete `packages/shared-ts/src/utils/recoveryEmail.ts` and its barrel export
      once the server parsers and execution tracker are gone.
- [x] Delete `wasm/near_signer/src/threshold/email_recovery_crypto.rs` and its
      exports if the post-cleanup import graph confirms the functions have no
      supported caller. Current repository references indicate that the
      `email_recovery_*` bindings serve the retired server adapter.
- [x] Keep shared cryptographic primitives under their existing domain owners
      when supported callers remain.

### 6. Tests, guards, and documentation

- [x] Delete unit tests for email encryption, email subject or body parsing,
      `/recover-email` parsing, preparation, recovery session and execution
      stores, and execution tracking.
- [x] Delete or narrow route, D1, source-guard, type, and fixture assertions that
      encode the retired services, tables, bindings, exports, or message kinds.
      Keep the portions that enforce current behavior.
- [x] Remove active README and API documentation for `/recover-email`,
      `/email-recovery/prepare`, recovery email hashes, Outlayer, DKIM recovery,
      and the removed public methods. Historical refactor documents may retain
      historical references.
- [x] Update `docs/intended-behaviours.md` to describe saved one-time recovery
      codes accurately and remove claims that the retired email flow is
      supported.
- [x] Review UI copy that says “Recover Account with Email.” Preserve the Email
      OTP or Google authentication flow when it remains supported, and label it
      according to the behavior it actually performs so it does not advertise
      the deleted system.

## Verification

### Absence checks

- [x] Production source and generated declarations contain no
      `EmailRecoveryService`, `EmailRecoveryPreparationStore`,
      `EmailRecoveryAuthOperations`, `RecoverySessionStore`,
      `RecoveryExecutionStore`, `PM_GET_RECOVERY_EMAILS`,
      `PM_SET_RECOVERY_EMAILS`, `emailDkimVerifierContract`,
      `RECOVER_EMAIL_RECIPIENT`, or `email_recovery_*` binding.
- [x] Production route manifests and workers contain neither `/recover-email`
      nor `/email-recovery/prepare`.
- [x] Public SDK declarations contain neither `getRecoveryEmails` nor
      `setRecoveryEmails`.
- [x] The active D1 schema and local bootstrap contain none of
      `email_recovery_preparations`, `recovery_sessions`, or
      `recovery_executions`; the forward migration is the only active reference
      required to drop them.
- [x] The wallet IndexedDB manifest contains no `recovery_emails` store, and the
      canonical schema upgrade deletes that old store.
- [x] The retired HTTP routes return 404 through the production router.

### Preserved behavior

- [x] Current wallet recovery-code status, backup acknowledgement, preparation,
      finalization, and rotation tests pass.
- [x] Passkey and Email OTP registration and unlock intended-behavior contracts
      pass.
- [x] Account synchronization still works through its renamed standalone
      domain.
- [x] At landing, Email OTP escrow and recovery-code storage remain present in
      the D1 schema and runtime assembly. Later refactors may retire or replace
      those structures independently of this cleanup.

### Verification record

- Focused recovery-code, IndexedDB, route-surface, public-surface, iframe, D1
  migration, and near-signer checks passed at implementation or closure audit.
- `pnpm test:source-guards` reaches the unrelated console `types.ts` inventory
  guard, which reports nine deleted allowlist entries from concurrent work. All
  cleanup-relevant guards pass.
- Current full TypeScript checks stop in the unrelated in-progress device-linking
  message changes. `git diff --check` passes.
- The intended-behavior suite is environment-gated and was not rerun during this
  closure audit. Its recovery-code and Email OTP contracts remain present; the
  focused recovery-code tests pass.

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
