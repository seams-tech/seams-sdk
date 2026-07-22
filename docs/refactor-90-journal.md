# Refactor 90 Progress Journal

Companion to the [Modular Auth And Capability Refactor Plan](./refactor-90-modular-auth-capabilities-plan.md).

This file holds dated progress entries so the plan stays a readable checklist.
The plan records only a one-line status per phase; the narrative history lives
here.

## July 22, 2026: Email OTP Exact-Material Unlock Reconciliation

- Implementation landed for
  [the Email OTP exact-material unlock patch](./refactor-patch-2-email-otp-local-rehydration.md)
  against the current wallet-first stack. The current implementation adds a
  worker-owned Email OTP Ed25519 active-Client envelope and reuses the canonical
  ECDSA role-local material owner. Same-device unlock follows fresh OTP
  verification; explicit Yao recovery remains available only for genuine
  Ed25519 envelope absence.
- Refactor 90 now treats `exact_material_ready | material_absent |
  material_invalid` as a capability-material-adapter custody observation that
  precedes fresh session binding. It is not a fifth Foundation A hydration
  branch. Imported material remains pending and non-signable until authority
  binding, durable commit, read-back, and exact canonical re-resolution.
- The patch may land before Foundations A and B. It does not complete either
  foundation: Foundation A still owns the four canonical hydration outcomes,
  and Foundation B still owns the sole active ECDSA manifest, activation
  journal, and manifest-plus-material commit.
- Phase 19 must preserve the worker-owned KDF/envelope boundary, exact identity
  verification, absent-versus-invalid semantics, and zero-Yao routine unlock
  behavior while replacing the tactical combined two-curve coordinator with
  capability-specific material adapters. It must preserve the new exact-local
  session versus missing-material recovery intent split and the pinned Yao
  lifecycle identity while rotating wallet authority. Phase 23 replaces the
  wallet-first Ed25519-envelope-plus-canonical-ECDSA registration commit with
  canonical per-capability provisioning.
- Phase 6 inventory, Phase 17 authority migration, and Phase 21 worker split now
  explicitly include the patch's new Ed25519 record, worker commands, stable
  custody binding, imported active-Client handle, route intents, combined unlock
  result types, and deletion targets.
- The companion patch reports implementation complete with manual latency and
  intended-behaviour acceptance pending. SDK and server type checks plus the
  focused worker regression tests pass at this checkpoint. Refactor 90 continues
  to treat the patch as in progress until the exact-local and missing-material
  server paths, persistence-failure activation rollback, distinct path audit and
  timing labels, intended-behaviour matrix, and performance gates pass. The
  current request boundary also accepts an omitted Ed25519 session intent
  without an explicit requested-capability set; Phase 19 must remove that
  implicit branch.

## July 20, 2026: Stable Wallet Lifecycle Checkpoint Reconciliation

- Reconciled stabilization commits after `06c923053` through checkpoint
  `f978ae98b`. Current head `ac22999de` adds a release guard for centralized
  worker service authentication and does not change the capability-state model.
- Production-shaped local execution now separates the Gateway, MPCRouter,
  Deriver A, Deriver B, and SigningWorker and uses Cloudflare service bindings.
  Router and SigningWorker persistence, activation lookup, presign routing,
  registration cleanup, and server key-selector persistence were repaired.
- ECDSA groundwork for Foundation B landed. Encrypted role-local material and
  presign records use `seams_wallet`; durable records contain sealed material
  references and public facts; volatile handles remain in worker memory; lookup
  is chain-qualified; and registration, unlock, signing, step-up, and export use
  the shared tactical material resolver. Passkey and Email OTP registration
  retain public reauthorization anchors.
- Foundation B remains in progress. The canonical
  `ActiveEcdsaCapabilityManifest`, activation commit journal, atomic
  manifest-plus-material transaction, exact manifest read/commit ports,
  required-field transition model, and
  `ThresholdEcdsaSessionRecordCore` deletion have not landed.
- Email OTP registration, immediate signing, step-up, ECDSA export, reload, and
  later unlock now preserve enrollment escrow and rehydrate exact durable ECDSA
  material.
- Passkey Near Ed25519 now persists an authenticated encrypted activated-Client
  envelope in `seams_wallet`. Routine passkey unlock, page-refresh restoration,
  signing, and budget refresh import it locally with zero Deriver A/B calls.
  Device linking and explicit same-root recovery retain the root-recovery
  lifecycle. Export retains its separate one-use material-acquisition ceremony.
- Foundation A's four decision branches remain the canonical target. The prior
  shared implementation and ECDSA adapter over the optional legacy session
  record are absent at this checkpoint. Reimplementation must begin with exact
  ECDSA and Near Ed25519 protocol observation unions, followed by the small
  shared decision contract, narrow proof constructors, and compile-time
  rejection fixtures.
- YAOS Phase 14B is complete. Refactor 90 must preserve the responsibility-local
  derivation, presign, and online-signing worker split and use Router A/B ECDSA
  derivation terminology in active tasks.
- The manually verified acceptance matrix and the intended-behaviour guard that
  rejects routine Deriver A/B recovery are recorded in `f978ae98b`.

Note: the Phase 2A entries below were originally appended to the plan out of
order. They are re-ordered here by the recorded `AuthService.ts` line count,
which decreased monotonically through the split. All entries were logged on
July 3, 2026.

## Phase 2A: AuthService Mechanical Module Split

- July 3, 2026: First mechanical helper extraction completed.
  `AuthService.ts` kept the public facade and route-facing method surface while
  WebAuthn/OIDC boundary helpers moved to
  `packages/sdk-server-ts/src/core/authService/webauthnOidcHelpers.ts` and NEAR
  private-key transaction signing helpers moved to
  `packages/sdk-server-ts/src/core/authService/nearPrivateKeySigning.ts`.
  Route files still have no direct dependency on `core/authService/**`.
  A dead registration-diagnostics extraction was deleted during the import audit
  to avoid carrying unused AuthService-era code. Line count: `AuthService.ts`
  dropped from 11,769 to 11,289 lines; the two live helper modules contain 325
  lines total.
- July 3, 2026: Split inventory and delete-candidate ledger added before
  moving stateful methods. The ledger names active helper owners, duplicated
  AuthService/D1 ownership, and delete phases for stale registration/session
  authority paths.
- July 3, 2026: Second pure helper extraction completed. Random-id helpers
  moved to `core/authService/bytes.ts`, boundary object checks to
  `core/authService/record.ts`, signer WASM URL resolution moved to
  `core/authService/signerWasmUrls.ts`, and threshold-store diagnostics moved to
  `core/authService/thresholdStoreSummary.ts`. The import audit deleted the
  unused timing helper instead of preserving stale diagnostics surface.
  `packages/sdk-server-ts` typecheck passed after the move.
- July 3, 2026: Additional pure helper extraction completed without route
  imports or broad dependency bags. WebAuthn authority and wallet-binding
  helpers moved to focused modules, portable crypto helpers moved to
  `core/authService/portableCrypto.ts`, threshold ECDSA key inventory helpers
  moved to `core/authService/thresholdEcdsaKeyInventory.ts`, threshold runtime
  policy helpers moved to `core/authService/thresholdRuntimePolicy.ts`, and
  wallet-registration planning helpers moved to
  `core/authService/walletRegistrationPlanning.ts`.
- July 3, 2026: Review pass completed for the current mechanical split.
  Router modules still import the public `AuthService` facade rather than
  `core/authService/**` internals. Extracted modules do not import Cloudflare D1
  route adapters, Express handlers, React, browser SDK code, or tests. No
  `AuthServiceContext`, `AuthServiceDeps`, or similar broad dependency bag was
  introduced. Line count: `AuthService.ts` is now 10,250 lines; live helper
  modules contain 1,052 lines total.
- July 3, 2026: WebAuthn login/listing slice moved into
  `core/authService/webauthn.ts`. `AuthService` now delegates WebAuthn
  registration-credential verification, lite assertion verification,
  authenticator listing, login option creation, and login verification through
  explicit `WebAuthn*Store` and `IdentityStore` inputs. No route imports were
  changed, and no broad dependency bag was introduced. Line count:
  `AuthService.ts` is now 9,843 lines; live helper modules contain 1,776 lines
  total.
- July 3, 2026: Email OTP boundary utility slice moved out without changing
  the public facade. Config/env reads moved to
  `core/authService/configValues.ts`, OTP policy parsing and masking moved to
  `core/authService/emailOtpConfig.ts`, OTP delivery moved to
  `core/authService/emailOtpDelivery.ts`, shared random ID/code generation
  moved into `core/authService/bytes.ts`, and Email OTP plus registration
  prepare rate-limit consumption moved to `core/authService/rateLimits.ts`.
  `AuthService` still owns the stores, caches, and public methods. Line count:
  `AuthService.ts` is now 9,485 lines; live helper modules contain 2,424 lines
  total. `packages/sdk-server-ts` typecheck passed after the move.
- July 3, 2026: Threshold ECDSA inventory facade loop moved into
  `core/authService/thresholdEcdsaKeyInventory.ts`. `AuthService` now passes the
  threshold service and logger explicitly; route imports and public method
  signatures stayed unchanged. Line count: `AuthService.ts` is now 9,403 lines;
  live helper modules contain 2,521 lines total. `packages/sdk-server-ts`
  typecheck passed after the move.
- July 3, 2026: OIDC verification moved into
  `core/authService/oidcVerification.ts`. `AuthService` now owns only provider
  subject linking and delegates JWT parsing, JWKS fetch/cache, signature
  validation, issuer/audience/time checks, and Google claim extraction to the
  helper. Route imports remain behind the public facade. Line count:
  `AuthService.ts` is now 8,825 lines; live helper modules contain 3,061 lines
  total. `packages/sdk-server-ts` typecheck passed after the move.
- July 3, 2026: Identity and app-session version facade logic moved into
  `core/authService/identity.ts`. `AuthService` now delegates identity listing,
  identity linking/unlinking, app-session version creation, rotation, and
  validation through an explicit `IdentityStore` input. Result types are modeled
  as branch unions in the helper module instead of the previous broad optional
  result object. Line count: `AuthService.ts` is now 8,776 lines; live helper
  modules contain 3,198 lines total.
- July 3, 2026: OIDC facade result shaping and provider-subject identity
  linking moved into `core/authService/oidcVerification.ts`. `AuthService` now
  supplies only OIDC config, JWKS cache state, and `IdentityStore` to the helper.
  The typecheck also exposed a partially deleted Router A/B ECDSA key-identities
  route; the stale shared path, parser, Express route, route definition, and type
  fixture are now consistently removed instead of reintroduced. Line count:
  `AuthService.ts` is now 8,657 lines; live helper modules contain 3,361 lines
  total.
- July 3, 2026: WebAuthn sync-account option creation moved into
  `core/authService/webauthn.ts`. The moved helper takes only
  `WebAuthnSyncChallengeStore` and `WebAuthnCredentialBindingStore`; sync
  verification remains in `AuthService` until its threshold/session dependencies
  can be split without a broad context bag. Line count: `AuthService.ts` is now
  8,567 lines; live helper modules contain 3,473 lines total.
- July 3, 2026: NEAR public-key metadata record/list logic moved into
  `core/authService/nearPublicKeyMetadata.ts`. `AuthService` now delegates
  metadata persistence and listing through an explicit `NearPublicKeyStore`
  input and keeps route-facing method names stable. Line count:
  `AuthService.ts` is now 8,491 lines; live helper modules contain 3,642 lines
  total.
- July 3, 2026: Recovery session/execution facade tracking moved into
  `core/authService/recoveryTracking.ts`. `AuthService` now delegates recovery
  session reads, status updates, execution reads/lists, and execution recording
  through explicit `RecoverySessionStore` and `RecoveryExecutionStore` inputs.
  The D1 adapter still owns its canonical route implementation until Refactor
  82 cleanup collapses the remaining parallel AuthService-era surfaces. Line
  count: `AuthService.ts` is now 8,332 lines; live helper modules contain 3,982
  lines total.
- July 3, 2026: NEAR RPC and relayer transaction helper logic moved into
  `core/authService/nearTransactions.ts`. `AuthService` now delegates
  access-key listing, signed Borsh dispatch, account-existence checks,
  access-key visibility checks, transaction context fetching, and gas-router
  transaction signing through explicit `MinimalNearClient`, relayer key, and
  logger inputs. Account creation and delegate execution remain in the facade
  because they still coordinate queueing and higher-level registration
  semantics. Line count: `AuthService.ts` is now 8,238 lines; live helper
  modules contain 4,204 lines total.
- July 3, 2026: Wallet ID allocation helpers were removed from
  `AuthService.ts` and kept in `core/authService/walletRegistrationPlanning.ts`.
  The canonical helper module now owns server-allocated wallet ID reservation,
  provided implicit wallet ID reservation, generic wallet selection, and
  signer-plan-aware registration wallet selection. The D1 registration intent
  service still has a parallel local copy because router code must not import
  `core/authService/**` internals during this mechanical split; collapse that
  duplicate through the Refactor 82 route-port cleanup. Line count:
  `AuthService.ts` is now 8,108 lines; live helper modules contain 4,338 lines
  total.
- July 3, 2026: Email OTP Shamir seal cipher setup moved into
  `core/authService/emailOtpSeal.ts`. `AuthService` now reads the four raw seal
  config values and delegates typed key-version, Shamir-prime, and cipher
  construction to the helper. Remaining local random/masking wrapper methods
  were also removed in favor of direct calls to the extracted helper functions.
  This keeps config-boundary validation isolated without adding a new service
  object. Line count: `AuthService.ts` is now 8,047 lines; live helper modules
  contain 4,415 lines total.
- July 3, 2026: Email OTP registration challenge-proof and challenge-purpose
  boundary modeling moved into `core/authService/emailOtpChallengeProof.ts`.
  `AuthService` now imports the typed proof, verified challenge, challenge
  purpose, and recovery escrow redaction helpers instead of defining them
  inline. The move keeps raw request proof parsing at the boundary and preserves
  the public facade. Line count: `AuthService.ts` is now 7,523 lines; live
  helper modules contain 4,978 lines total. `packages/sdk-server-ts` typecheck
  passed after the move.
- July 3, 2026: Registration threshold helper code moved into
  `core/authService/registrationThresholdHelpers.ts`. The helper owns
  threshold-Ed25519 registration input parsing, bootstrap session normalization,
  ECDSA bootstrap identity comparison, ECDSA wallet-key derivation from server
  bootstrap output, and NEAR add-key bootstrap action construction. `AuthService`
  still coordinates stores and route-facing methods. Line count:
  `AuthService.ts` is now 7,206 lines; live helper modules contain 5,337 lines
  total. `packages/sdk-server-ts` typecheck passed after the move.
- July 3, 2026: Signer WASM runtime setup and more Email OTP lifecycle
  helpers moved behind focused modules. `core/authService/wasm.ts` owns signer
  WASM initialization, `emailOtpDelivery.ts` owns dev outbox reads,
  `emailOtpSeal.ts` owns server seal operations, `emailOtpEnrollment.ts` owns
  enrollment/auth-state/strong-auth helpers, `emailOtpGrant.ts` owns grant
  consumption, and `googleEmailOtpRegistration.ts` owns Google Email OTP
  registration attempt/offer lifecycle. `AuthService` remains the public facade
  and supplies only explicit stores plus the two narrow callbacks needed for
  hosted wallet derivation and wallet-shape checks. Router modules still have no
  direct `core/authService/**` imports, and no `AuthServiceContext` or
  `AuthServiceDeps` bag was introduced. Line count: `AuthService.ts` is now
  6,085 lines; live helper modules contain 7,022 lines total.
  `packages/sdk-server-ts` typecheck passed after the move.
- July 3, 2026: Rate-limit backend construction moved out of
  `AuthService.ts` and into `core/authService/rateLimits.ts`. The helper now
  owns raw limiter-kind parsing and environment/config-backed limiter
  construction for Email OTP and registration-prepare throttles, while
  `AuthService` only caches limiter instances and delegates consumption. No
  route imports of helper internals were added. Line count: `AuthService.ts` is
  now 6,044 lines; live helper modules contain 7,122 lines total.
  `packages/sdk-server-ts` typecheck passed after the move.
- July 3, 2026: Email OTP challenge cleanup and active-challenge limiting
  moved into `core/authService/emailOtpChallenges.ts`. The helper owns
  challenge-store expiry pruning, active-context cap enforcement, and associated
  memory-outbox cleanup through explicit store and outbox inputs. `AuthService`
  still owns request parsing and challenge issuance orchestration. Line count:
  `AuthService.ts` is now 6,037 lines; live helper modules contain 7,198 lines
  total. `packages/sdk-server-ts` typecheck and build passed after the move.
- July 3, 2026: Public facade barrel move completed.
  `packages/sdk-server-ts/src/core/AuthService.ts` now re-exports the public
  `AuthService` class and Google Email OTP public result types from
  `core/authService/**`. The remaining implementation lives in
  `core/authService/AuthService.ts`; route and router layers still import the
  public facade path only. Line count: public `AuthService.ts` is now 7 lines,
  `authService/AuthService.ts` is 6,037 lines, and focused helper modules
  contain 7,198 lines total. `packages/sdk-server-ts` typecheck and build passed
  after the move.
- July 3, 2026: Email OTP challenge issuance moved into
  `core/authService/emailOtpChallenges.ts`. The helper now owns request-boundary
  parsing, active challenge reuse, challenge rate limiting, challenge record
  persistence, delivery rollback, and delivery result shaping through explicit
  operation ports. `AuthService` still owns stores, limiter caches, and the
  public method signatures. `packages/sdk-server-ts` typecheck passed after the
  move.
- July 3, 2026: Email OTP unlock challenge issuance and unlock-proof
  verification moved into `core/authService/emailOtpUnlock.ts`. The helper owns
  unlock challenge creation, secp256k1 unlock proof validation, challenge
  consumption, and Email OTP login auth-state marking through explicit operation
  ports. No route imports of helper internals were added. Line count:
  `authService/AuthService.ts` is now 5,509 lines and focused helper modules
  contain 7,905 lines total. `packages/sdk-server-ts` typecheck passed after the
  move.
- July 3, 2026: AuthService mechanical split checkpoint completed. The
  public barrel at `packages/sdk-server-ts/src/core/AuthService.ts` now
  re-exports the split facade from `core/authService/AuthService.ts`. Additional
  stateful slices moved behind explicit internal ports:
  `emailOtpChallengeVerification.ts`, `emailOtpRegistrationEnrollment.ts`,
  `emailOtpRecoveryKeys.ts`, `emailRecoveryAuthOperations.ts`,
  `nearAccountOperations.ts`, `identityOperations.ts`,
  `recoveryTrackingOperations.ts`, and the temporary assembly-only
  `storeRegistry.ts`. Route modules still import only the public facade, no
  `AuthServiceContext`/`AuthServiceDeps` bag was introduced, and the touched
  extracted modules contain no `any`. Line count: `core/authService/AuthService.ts`
  is now 1,999 lines, satisfying the Phase 2A pre-Phase-3 target.
- July 3, 2026: Follow-up AuthService split pass moved Google Email OTP/OIDC
  wallet-resolution facade logic into
  `core/authService/googleEmailOtpOperations.ts` and threshold ECDSA route-facing
  forwarding into `core/authService/thresholdEcdsaOperations.ts`. The public
  method names and route contracts stayed on `AuthService`; routes still have no
  direct imports of `core/authService/**`, no `AuthServiceContext`/`AuthServiceDeps`
  bag was introduced, and the new extracted modules contain no `any`. Line count:
  `core/authService/AuthService.ts` is now 1,908 lines.
- July 3, 2026: Email OTP public challenge composition moved into
  `core/authService/emailOtpChallengeOperations.ts`. `AuthService` now delegates
  login challenge issuing, enrollment challenge issuing, device-recovery
  challenge issuing, login grant minting, and device-recovery consume-grant
  minting through an explicit Email OTP challenge operation input. Route
  contracts stayed on the public `AuthService` facade; no route imports of
  `core/authService/**`, broad `AuthServiceContext`/`AuthServiceDeps` bag, or
  legacy compatibility path was introduced. Line count:
  `core/authService/AuthService.ts` is now 1,761 lines.
- July 3, 2026: AuthService runtime state moved into
  `core/authService/runtime.ts`. `AuthService` now keeps signer-WASM readiness,
  relayer public-key derivation, and service initialization state in one typed
  runtime state object while the facade still owns assembly. Route and app
  imports were audit-checked rather than guarded because this facade boundary is
  temporary. `core/authService/AuthService.ts` is now 1,751 lines.
- July 3, 2026: Phase 2A mechanical split closure review completed.
  Remaining methods in `core/authService/AuthService.ts` are constructor/config
  assembly, store wiring, runtime warm-up, or thin delegates whose next split
  belongs with Phase 3 route ports or Refactor 82B authority unions. Moving
  those now would require a broad context bag or route-contract churn, so the
  mechanical split stops here.
- Active Email OTP verification/recovery and WebAuthn helper clusters that
  can move without a broad dependency bag have moved. Remaining helper
  movement is deferred to route ports and typed authority cleanup.
