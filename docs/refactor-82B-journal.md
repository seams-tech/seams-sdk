# Refactor 82B Progress Journal

Companion to [Refactor 82B: Auth Authority Typing Cleanup](./refactor-82B.md).

Dated progress entries, validation evidence, and long tracking notes live here
so the plan stays a readable checklist. The plan carries one-line statuses and
open tasks only.

Note: the Phase 9 validation-evidence record below was originally one ~120-line
bullet in the plan, with one entry spliced into the middle of another ("focused
concurrent EVM-family budget coverage; plus July 3 route cleanup evidence: ...
reservation coverage in `signingSessionBudgetFinalizer.unit.test.ts`"). The
entries have been re-separated here; the budget-reservation phrase is rejoined
to its coverage entry and the route-cleanup evidence stands alone.

## July 3, 2026: Authority/ECDSA Regression Slice

- Added shared `WalletAuthAuthority`, `WalletAuthAuthorityRef`,
  request-boundary proof unions, `RegistrationWalletCandidate`,
  `ActiveWalletSession`, and canonical `WalletAuthAuthorityDigest` helpers in
  `packages/shared-ts/src/utils/walletAuthAuthority.ts`.
- Added domain ID brands and parsers for verified Email OTP addresses, Email OTP
  provider user IDs, WebAuthn credential IDs, wallet authority binding digests,
  and app-session JWTs.
- Renamed the wallet authority digest domain to
  `WalletAuthorityBindingDigest` and added the
  `seams:wallet-authority-binding:v1|` domain-separation prefix to the
  canonical digest preimage. The old `WalletAuthAuthorityDigest` parser and
  helper names are deleted.
- Collapsed the five shared per-operation proof unions into
  `AuthOperationPurpose`, `AuthMethodProof`, and purpose-bound
  `AuthBoundaryProof`. Shape-level proof/purpose validation now lives in
  `validateAuthBoundaryProofPurpose`; old per-operation proof kind names are
  rejected by type fixtures.
- Added shared pure `AuthFactorIdentity` branches and replaced
  `EmailOtpAuthorityProfile` with `EmailOtpFactorProfile`. The profile now
  attaches display email to `EmailOtpFactorIdentity`, carries no self-labeling
  `kind`, and does not accept wallet authority as a sibling shape.
- Added the shared `WalletAuthMethodId` brand and moved wallet-auth-method
  binding-id derivation to `walletAuthMethodRecordId` in the shared
  registration-intent model. The D1/in-memory server store now uses that shared
  helper, and `walletAuthMethodStore.unit.test.ts` proves passkey ids remain
  stable across mutable authenticator metadata while Email OTP ids remain stable
  across registration/enrollment refreshes for the same wallet and email hash.
- Replaced long-lived `ThresholdEcdsaEmailOtpAuthContext.authSubjectId` with a
  stable Email OTP authority branch plus `EmailOtpAuthUse`.
- Made Email OTP ECDSA session record parsing reject deleted `authSubjectId`
  shapes and require canonical `EmailOtpAuthUse` branches. Deleted lifecycle
  fields `retention`, `reason`, and top-level `consumedAtMs` are rejected by the
  persisted record parser.
- Dropped the constant `reason: 'sign'` field from the `single_use_pending` and
  `single_use_consumed` Email OTP auth-use branches. Builders now reject that
  stale field on single-use state, persisted-record parsing rejects
  single-use `use.reason`, and fixtures consume the branch-only shape.
- Introduced the first committed Email OTP ECDSA lane object in EVM/Tempo
  selection. The selected lane now carries the lane candidate, matching ECDSA
  auth lane, wallet-session authority, material state, and durable restore source
  together before signing proceeds.
- Converted the exported ECDSA committed-lane type to
  `EcdsaCommittedLane<A extends WalletAuthAuthority>` and removed the duplicate
  top-level `passkey_ecdsa_committed_lane` /
  `email_otp_ecdsa_committed_lane` method-kind fields from ECDSA committed-lane
  objects. The remaining runtime branch reads use `candidate.auth.kind` until
  lanes carry the Phase 2 wallet-bound `authority.factor.kind` directly.
- Removed the duplicate top-level `email_otp_ed25519_signing_committed_lane`
  and `email_otp_ed25519_export_committed_lane` kind fields from Ed25519
  committed-lane objects. Source guards now reject reintroducing the ECDSA and
  Ed25519 method-kind lane strings.
- Added the generic ECDSA `RecordBacked<L>` committed-lane primitive and
  `RecordBackedEcdsaCommittedLane<A>` helper. ECDSA key export ports now
  consume `EcdsaExportLane<EmailOtpWalletAuthAuthority>` and
  `ReadyEcdsaExportLane<PasskeyWalletAuthAuthority>` directly, and Email OTP
  companion selection consumes
  `RecordBackedEcdsaCommittedLane<EmailOtpWalletAuthAuthority>`.
- Rebound D1 Email OTP recovery grants to stable Email OTP authority
  (`userId`, `walletId`, channel, org) instead of app-session hash/version. This
  fixes recovery/export grants after unlock or app-session refresh.
- Updated targeted web type fixtures for strict Email OTP ECDSA context and
  committed-lane construction.
- Confirmed `budget_unknown` is not used as an Email OTP auth selector in SDK
  signing code. It remains a budget/planner terminal state while ECDSA ready
  lanes defer unreadable preflight budget status to admission and reservation.
- Removed the sealed-session `authSubjectId` compatibility alias from the SDK
  sealed restore readers and available-lane sealed recovery projection. Email
  OTP sealed restore now requires canonical `providerSubjectId` at those
  boundaries.
- Removed `ReadyEmailOtpEcdsaSessionRecord` from code. Companion selection now
  commits Email OTP ECDSA session records into wallet-scoped companion lanes
  before sorting or matching signing grants.
- Renamed fresh Email OTP ECDSA export domain state from `authSubjectId` to
  `providerUserId`, leaving the old field name only at the worker API boundary
  where the existing worker command still expects it.
- Deleted `google_oidc` and `google_sso_email_otp` provider aliases from the
  shared `WalletAuthAuthority` parser. The shared authority boundary now accepts
  only canonical `provider: 'google' | 'email'`; remaining D1/worker legacy
  values stay listed under their owning request/persistence readers.
- Removed `sessionHash`/`appSessionVersion` from D1 Email OTP recovery-grant
  consumption and failed-attempt normalization. D1 recovery grant use now binds
  to stable Email OTP authority plus wallet/org context at the service boundary;
  AuthService monolith cleanup remains tracked for the parallel split.
- Tightened the ECDSA key-export recovery-flow dependency so Email OTP
  authorization accepts a record-backed committed lane. The browser assembly is
  the adapter boundary that unwraps `record` and `authLane` for the existing
  Email OTP worker runtime.
- Added runtime companion-selection coverage for same-grant Tempo + Arc success,
  duplicate-chain failure, and same provider subject across different wallet IDs.
- Added focused Ed25519 export and reconstruction coverage that rejects stale
  top-level Email OTP lifecycle fields and verifies the canonical `use` branch
  after deferred runtime-scope login reconstruction.
- Added focused budget-coordinator coverage proving concurrent EVM-family
  reservations under one signing grant remain distinct by operation fingerprint,
  both finalize through the reserved-success branch, and fingerprint reuse is
  rejected as a reservation identity mismatch.
- Replaced flat Ed25519 material identity fields in the available-lane surface
  with an explicit material-state union. Durable and runtime lane builders now
  parse raw material fields once into `material_pending`,
  `sealed_worker_material`, or `loaded_worker_material`, and transaction/export
  selection consumes that union.
- Tightened the available-lanes runtime Ed25519 port so record-backed runtime
  lanes carry the material-state union directly. The persisted adapters now
  convert optional IndexedDB material fields into `material_pending` or
  `loaded_worker_material` at the boundary, and type fixtures reject direct
  runtime-lane construction with missing material state or obsolete flat
  material fields.
- Converted passkey Ed25519 reconnect recovery to branch on the normalized
  `ThresholdEd25519SessionRecord.materialState` discriminator before reading
  worker material facts, removing another core optional material-bag reader.
- Renamed remaining SDK login/registration/warm-session internal Email OTP
  authority variables from `authSubjectId` to `providerUserId`, leaving
  `authSubjectId` only where existing worker-command boundaries still require
  that wire field.
- Added an explicit `EmailOtpEcdsaProviderIdentity` union to the ECDSA login
  helper. Fresh unlock/login derives provider identity from route authority,
  while record-backed signing refresh, export, and Ed25519 companion warm-up now
  pass an explicit provider user from the committed Email OTP ECDSA record; the
  stale `authSubjectId` login input is rejected by type fixtures.
- Renamed Email OTP ECDSA registration enrollment and Ed25519 reconstruction
  provisioning internals to `providerUserId`, keeping `authSubjectId` only on
  worker/HSS authorization payloads that still use that wire field.
- Renamed the fresh ECDSA export runtime request shape to `providerUserId`;
  the old `authSubjectId` spelling is now confined to worker/HSS payloads,
  public worker result shapes, and explicit type-level rejection fixtures in
  the Email OTP session package.
- Renamed Email OTP Ed25519 recovery-code/HSS adapter inputs to
  `providerUserId`, while preserving the worker protocol and digest payload
  field name at the final command boundary.
- Hardened stale role-local, ECDSA material-state, post-sign-policy, Email OTP
  consumption, bootstrap, and warm-session fixtures so they now use canonical
  `evmFamilySigningKeySlotId`, branch-specific Email OTP authority/use state,
  exact ECDSA identity mutation, and complete Ed25519 material records.
- Narrowed Router A/B Ed25519 wallet-session material readers so signable
  material is built from the `material_ready` session-record branch and sealed
  restore material is built from the restorable material-state branches.
- Removed the Email OTP ECDSA wallet+chain session-record getter from the
  EVM-family dependency surface and browser assembly. EVM-family warm-session
  services now list boundary-normalized records by wallet/target, while Email
  OTP signing selection remains exact-lane based.
- Converted Email OTP ECDSA key export material to carry record-backed
  committed lanes for both ready export material and fresh route-auth export
  material. The export flow now consumes the committed lane's wallet-session
  authority instead of rebuilding a signing-session auth lane from loose record
  fields.
- Hardened the ECDSA export material boundary so ready export selection commits
  the record-backed lane before returning material, and fresh route-auth export
  tries the committed lane instead of probing wallet-session auth separately.
- Reworked Email OTP ECDSA companion selection for Ed25519 step-up so companion
  lanes wrap `RecordBackedEcdsaCommittedLane<EmailOtpWalletAuthAuthority>`;
  direct companion
  `record` and sibling `walletSessionAuthority` fields are rejected by type
  fixtures and source guards.
- Deleted the obsolete SDK `walletAuthModeResolver.ts` proof resolver and its
  unit test. The still-used `WalletAuthPolicyError` now lives in a focused
  policy-error module, and source guards reject the old `WalletAuthProof`,
  `WalletAuthPlan`, and adapter-builder names.
- Replaced the server Ed25519 session-mint `ThresholdEd25519SessionWalletAuthProof`
  projection with an `AuthorizedThresholdEd25519SessionAuth` union. Verified
  app-session and threshold-ECDSA wallet-session auth stay on their stable
  branches, and passkey challenge-response verification is handled by an
  exhaustive switch.
- Collapsed Email OTP Ed25519 authority scope to stable `{ kind: 'email_otp',
  provider, providerUserId }` authority in shared registration intent helpers,
  server threshold policy parsing, SDK session-policy drafting, D1 registration
  bootstrapping, and registration replay persistence. One-time `proofKind`, OTP
  `challengeId`, Google registration attempt/offer/candidate IDs, and display
  email now stay on registration proof/request objects and are rejected from
  reusable Ed25519 authority scope. The pre-proof registration precompute cache
  keeps a separate `email_otp_pre_auth` key and cannot mint reusable authority.
- Added branch-specific SDK Ed25519 session-policy builders for passkey and
  Email OTP authority branches. The warm-session request envelope now accepts an
  already-normalized `Ed25519AuthorityScope` and no longer reparses raw passkey
  authority internally; sync, recovery, and add-signer flows parse RP IDs at
  their operation boundaries before constructing passkey scope. NEAR passkey
  reauth now uses the passkey-specific builder with a parsed WebAuthn RP ID.
- Converted NEAR Email OTP Ed25519 step-up signing to build
  `Ed25519SigningLane` before challenge issuance and reuse it for OTP
  completion. The runtime and worker-facing port types now reject loose
  `record`, `routeAuth`, and `authLane` inputs for signing refresh; focused
  type fixtures and guard tests cover the boundary.

## Validation Runs

### July 3, 2026: pre-AuthService-split baseline

- `pnpm build:sdk` passed. Focused Playwright unit coverage passed
  for Email OTP wallet-session companion/restore/export ECDSA flows, sealed
  recovery method adapters, and signing-session restore coordination. Before
  the parallel AuthService mechanical split, July 3 validation also passed:
  `pnpm --dir packages/sdk-server-ts type-check`,
  `pnpm --dir tests exec playwright test -c playwright.unit.config.ts
  unit/refactor82CloudflareD1Runtime.guard.unit.test.ts
  unit/thresholdEcdsa.presignPoolRefill.unit.test.ts --reporter=line` with 64
  tests, `pnpm --dir tests exec playwright test -c playwright.relayer.config.ts
  relayer/threshold-ecdsa.durable-stores.test.ts --reporter=line` with 7 passed
  and 6 skipped external-store cases, focused Ed25519/export coverage with 34
  tests passing, focused Ed25519 available-lane material-state coverage with 31
  tests passing, Ed25519 export selection coverage with 18 tests passing,
  passkey Ed25519 reconnect recovery coverage with 4 tests passing, focused
  Email OTP coordinator/export/restore coverage with 70 tests passing, focused
  Email OTP coordinator registration/enrollment coverage with 35 tests passing,
  Router A/B Ed25519 wallet-session coverage with 17 tests passing, and
  `git diff --check`.

### July 3, 2026: current reruns

- `pnpm build:sdk`, `pnpm --dir packages/sdk-server-ts type-check`,
  `pnpm --dir packages/shared-ts type-check`, focused
  `walletAuthAuthority.shared.unit.test.ts`, focused D1 Email OTP recovery
  lifecycle coverage in `cloudflareD1RouterApiAuthService.unit.test.ts`, and
  `git diff --check` pass.
- Current `pnpm --dir packages/sdk-web type-check` also passes after the
  parallel AuthService split corrected its local import mismatch.
- Current focused fixture hardening rerun passed 56 Playwright unit tests across
  `walletAuthAuthority.shared.unit.test.ts`, `ecdsaRoleLocalRecords.unit.test.ts`,
  `signingPostSignPolicy.unit.test.ts`,
  `thresholdEcdsaEmailOtpConsumption.unit.test.ts`,
  `ecdsaMaterialState.unit.test.ts`,
  `warmSessionStore.capabilityResolution.unit.test.ts`, and
  `ecdsaBootstrapWarmPersistence.unit.test.ts`.
- Current sealed/warm-session boundary coverage passed 49 Playwright unit tests
  across `warmSessionStore.capabilityResolution.unit.test.ts`,
  `sealedSessionStore.unit.test.ts`, `sealedRecovery.methodAdapters.unit.test.ts`,
  and `warmSessionEd25519Persistence.unit.test.ts`.
- Source searches found no active SDK/test hits for the deleted generic Email
  OTP signing-session error, `ReadyEmailOtpEcdsaSessionRecord`, or stale
  `emailOtpAuthContext.(authSubjectId|retention|reason|consumedAtMs)` reads.
- Current Router A/B Ed25519 material-state parser cleanup passed
  `pnpm --dir packages/sdk-web type-check` and 21 focused Playwright unit/source
  guard tests across `routerAbEd25519.walletSessionState.unit.test.ts` and
  `routerAbNormalSigningSdk.guard.unit.test.ts`.
- Current EVM-family Email OTP loose-getter deletion passed
  `pnpm --dir packages/sdk-web type-check` and 29 focused Playwright unit tests
  across `ecdsaSelection.restorable.unit.test.ts`,
  `evmFamily.requestBoundary.unit.test.ts`, and
  `evmSigning.thresholdReconnectEvents.unit.test.ts`; source guards in
  `signingEngineArchitecture.flows.guard.unit.test.ts` and
  `emailOtpOperationSplit.guard.unit.test.ts` also passed for the deleted getter
  surface.
- Current broad TypeScript checks also pass:
  `pnpm --dir packages/sdk-server-ts type-check` and
  `pnpm --dir tests exec tsc -p tsconfig.playwright.json --noEmit`.
- Current NEAR Email OTP Ed25519 step-up committed-lane rerun passed
  `pnpm --dir packages/sdk-web type-check`,
  `pnpm --dir tests exec tsc -p tsconfig.playwright.json --noEmit`,
  `pnpm --dir tests exec playwright test -c playwright.unit.config.ts
  unit/emailOtpWalletSessionCoordinator.unit.test.ts
  unit/emailOtpOperationSplit.guard.unit.test.ts` with 50 tests,
  `git diff --check`, and `pnpm build:sdk`.
- Current Phase 2/7 follow-up rerun passed
  `pnpm --dir packages/shared-ts type-check`,
  `pnpm --dir packages/sdk-server-ts type-check`,
  `pnpm --dir packages/sdk-web type-check`,
  `pnpm --dir tests exec tsc -p tsconfig.playwright.json --noEmit`,
  focused `walletAuthAuthority.shared.unit.test.ts` +
  `walletAuthMethodStore.unit.test.ts` with 12 tests, focused ECDSA/Ed25519
  committed-lane coverage across `emailOtpOperationSplit.guard.unit.test.ts`,
  `ecdsaSelection.restorable.unit.test.ts`, `ecdsaExportMaterial.unit.test.ts`,
  `emailOtpEcdsaSigningSessionAuth.unit.test.ts`, and
  `emailOtpWalletSessionCoordinator.unit.test.ts` with 77 tests,
  `git diff --check`, and `pnpm build:sdk`.
- Current ECDSA record-backed generic follow-up rerun passed
  `pnpm --dir packages/sdk-web type-check`,
  `pnpm --dir tests exec tsc -p tsconfig.playwright.json --noEmit`, and
  focused Playwright coverage in `emailOtpOperationSplit.guard.unit.test.ts`,
  `ecdsaExportMaterial.unit.test.ts`, and
  `ecdsaSelection.restorable.unit.test.ts` with 36 tests passing.
- Current Email OTP Ed25519 registration-authority conversion rerun passed
  `pnpm --dir packages/sdk-server-ts type-check`,
  `pnpm --dir packages/sdk-web type-check`,
  `pnpm --dir tests exec tsc -p tsconfig.playwright.json --noEmit`,
  `pnpm --dir tests exec playwright test -c playwright.unit.config.ts
  unit/cloudflareD1RouterApiAuthService.unit.test.ts --grep "registration"
  --reporter=line` with 14 tests,
  `pnpm --dir tests exec playwright test -c playwright.unit.config.ts
  unit/relayWalletRegistration.boundary.unit.test.ts --reporter=line` with 65
  tests, and
  `pnpm --dir tests exec playwright test -c playwright.unit.config.ts
  unit/googleEmailOtpWalletAuthFlow.unit.test.ts --reporter=line` with 24 tests.
- Current Email OTP single-use auth-use cleanup passed
  `pnpm --dir packages/sdk-web type-check`,
  `pnpm --dir tests exec tsc -p tsconfig.playwright.json --noEmit`,
  `pnpm build:sdk`,
  `pnpm --dir tests exec playwright test -c playwright.unit.config.ts
  unit/thresholdEcdsaEmailOtpConsumption.unit.test.ts
  unit/routerAbEd25519.walletSessionState.unit.test.ts
  unit/emailOtpEcdsaPublication.unit.test.ts --reporter=line` with 29 tests,
  and `git diff --check`.
- Current wallet authority binding digest rename/prefix passed
  `pnpm --dir packages/shared-ts type-check`,
  `pnpm --dir tests exec tsc -p tsconfig.playwright.json --noEmit`,
  `pnpm --dir tests exec playwright test -c playwright.unit.config.ts
  unit/walletAuthAuthority.shared.unit.test.ts --reporter=line` with 5 tests,
  and `git diff --check`.
- Current shared boundary-proof collapse passed
  `pnpm --dir packages/shared-ts type-check`,
  `pnpm --dir tests exec tsc -p tsconfig.playwright.json --noEmit`, and
  `pnpm --dir tests exec playwright test -c playwright.unit.config.ts
  unit/walletAuthAuthority.shared.unit.test.ts --reporter=line` with 6 tests.
- Current Email OTP factor-profile cleanup passed
  `pnpm --dir packages/shared-ts type-check`,
  `pnpm --dir tests exec tsc -p tsconfig.playwright.json --noEmit`, and
  `pnpm --dir tests exec playwright test -c playwright.unit.config.ts
  unit/walletAuthAuthority.shared.unit.test.ts --reporter=line` with 8 tests.

## Phase Tracking Notes

Long dated notes moved out of the plan's tracking checklists.

### Phase 7: committed-lane threading (July 3, 2026)

- Make all ECDSA signing/export/step-up functions accept `EcdsaCommittedLane`:
  Email OTP ECDSA transaction step-up now threads
  `EmailOtpEcdsaCommittedLane` through `authPlanning`,
  `createEmailOtpEcdsaTransactionSigningBridge`,
  `loginWithEmailOtpEcdsaCapabilityForSigning`, and the EVM-family port
  adapters. The old step-up bootstrap input shape that accepted loose
  `record` + `authLane` or `record` + `routeAuth` is rejected by
  `ecdsaLogin.typecheck.ts` and guarded by
  `emailOtpOperationSplit.guard.unit.test.ts`.
- Follow-up: `loginWithEmailOtpEcdsaCapabilityForSigning` now requires
  `EmailOtpEcdsaCommittedLane`; the transaction signing bridge consumes
  `committedLane.authLane` directly and no longer accepts or calls
  `resolveEmailOtpSigningSessionAuthLane`, `reauthAuthLane`,
  `signingSessionRecord`, or a no-lane app-session reconnect fallback.
- Follow-up: ready ECDSA signing selections and ready ECDSA export materials
  now require a committed lane for both Email OTP and Passkey. Passkey export
  no longer uses a `committedLane?: never` branch; it carries a record-backed
  committed lane like Email OTP. Trusted budget status auth for ready ECDSA
  signing now reads the committed lane's wallet-session authority for both
  Email OTP and Passkey instead of rebuilding authority from the signer
  session.
- Follow-up: Email OTP ECDSA export runtime now accepts a record-backed
  committed lane directly. The recovery port adapter no longer unwraps
  `committedLane` back into `record` + `authLane`, and the worker export
  payload uses the committed lane's wallet-session authority JWT.
- Follow-up: Passkey ECDSA reauth selections now require
  `PasskeyEcdsaCommittedLane`, `passkeyReauthRequiredSelection` no longer
  accepts an optional committed lane, and prepare-time material binding
  validates Passkey committed lane identity/candidate/material consistency the
  same way as Email OTP. The guard test now rejects
  `committedLane?: PasskeyEcdsaCommittedLane`.
- Follow-up: ready ECDSA export material no longer exposes a sibling session
  `record`; both Passkey and Email OTP export paths read record identity
  through the record-backed committed lane. The Passkey HSS export helper now
  accepts `ReadyEcdsaExportLane<PasskeyWalletAuthAuthority>`.
- Delete runtime session records as authority inputs (in progress): the Email
  OTP ECDSA export runtime no longer accepts a loose session `record`,
  `routeAuth`, or `authLane`; those pieces are only read while building the
  committed export lane at the material boundary. Email OTP Ed25519 export now
  uses `Ed25519ExportLane`. The worker export
  argument type rejects loose `record`, `participantIds`,
  `thresholdSessionId`, `walletSessionJwt`, `relayerKeyId`,
  `expectedPublicKey`, `routeAuth`, and `authLane` fields; the NEAR export
  flow commits the record, wallet-session authority, auth lane, participant
  set, relayer key, and expected public key atomically before challenge
  issuance. NEAR Email OTP Ed25519 step-up signing now builds an
  `Ed25519SigningLane` from the selected lane and persisted record before OTP
  challenge issuance, and
  `EmailOtpEd25519Warmup.loginForSigning` rejects loose `record`, `routeAuth`,
  and `authLane` inputs. ECDSA export material selection now commits a
  record-backed lane before returning ready material, and Email OTP ECDSA
  companion selection for Ed25519 step-up returns committed lanes instead of a
  parallel `record` plus authority shape.
- Delete wallet-session authority probes across multiple stores (in
  progress): EVM/Tempo Email OTP ECDSA selection no longer probes
  `getEmailOtpThresholdEcdsaSessionRecordForSigning` by wallet and chain while
  committing a lane. The selection path now uses the exact selected record or
  durable exact signing-session lane, and
  `evmFamily.requestBoundary.unit.test.ts` guards against restoring the loose
  probe. `ecdsaExportMaterial.ts` no longer imports
  `resolveRouterAbEcdsaWalletSessionAuthFromRecord`; export route-auth
  readiness is determined by committing the record-backed lane. Companion
  selection for Ed25519 step-up now reads wallet-session authority through
  `committedLane.authLane` and `committedLane.walletSessionAuthority`.

### Phase 3: registration authority (July 3, 2026)

- The unused AuthService-era `registrationIntentNearEd25519SigningKeyId`
  helper was deleted because intent-only scope derivation cannot represent
  Email OTP provider identity. Remaining split AuthService internals stay
  listed in the plan as D1 cleanup delete candidates.
- The mechanical AuthService split is complete, and the current route-source
  scan for imports of `core/authService/*` under
  `packages/sdk-server-ts/src/router` returns no hits. Routes still use the
  public route-family/service surfaces while D1-owned ports replace
  AuthService-era behavior.

### Phase 5: route surface cleanup (July 3, 2026)

- Route audit: the current source scan for
  `authorityScope.kind !== 'passkey_rp'`, `must be passkey_rp`,
  `requires passkey authority`, and
  `requires passkey wallet-session authority` returns only the
  passkey-specific SDK login session-policy assertion. Remaining `passkey_rp`
  occurrences are the Ed25519 policy model tracked in Phase 2 or
  WebAuthn/passkey-only branches.
- Deleted the obsolete generic Router A/B ECDSA key-identities route:
  `packages/sdk-server-ts/src/router/cloudflare/routes/thresholdEcdsa.ts`,
  `packages/sdk-server-ts/src/router/express/routes/thresholdEcdsa.ts`,
  `packages/sdk-server-ts/src/router/routeDefinitions.ts`, shared route
  constants, route parser fixtures, and relayer cookie-mode tests no longer
  expose `/router-ab/ecdsa-hss/key-identities`. The current inventory boundary
  is wallet-scoped `/wallets/:walletId/signers/ecdsa/key-facts/inventory`.
- Deleted obsolete AuthService Email OTP recovery-grant app-session binding
  checks: `consumeEmailOtpGrantWithStore`, `consumeEmailOtpRecoveryKey`, and
  `recordEmailOtpRecoveryKeyAttemptFailure` now bind grants to stable Email
  OTP authority fields; `emailOtpGrantAuthorityBinding.unit.test.ts` covers
  app-session rotation and the Refactor 82 D1 guard scans both D1 and
  store-backed helpers. D1 progress: `d1EmailOtpRecoveryService.ts` recovery
  grants bind to stable Email OTP authority fields (`userId`, `walletId`,
  channel, and org) and no longer check `sessionHash` or `appSessionVersion`;
  `refactor82CloudflareD1Runtime.guard.unit.test.ts` now guards that D1 path
  while the split AuthService modules keep the remaining deletion task.
- Removed the Router API public port's type dependency on `AuthService`: the
  old `RouterApiAuthService` name is gone, method contracts are explicit, and
  `RouterApiServiceBag` is now a nested route-family object
  (`walletRegistration`, `walletAuthMethods`, `walletUnlock`, `emailOtp`,
  `webAuthn`, `identity`, `sessionVersions`, `thresholdRuntime`,
  `nearFunding`, `recovery`, and `router`). Follow-up: `RouterApiMethodInput`,
  `RouterApiMethodResult`, and `RouterApiMethodHandler` are deleted;
  route-family ports expose direct method signatures, D1 modules consume
  concrete route/domain contracts or capability-specific service interfaces,
  and the Refactor 82 runtime guard rejects restoring those generic helpers.
- Deleted the D1 Router API AuthService-shaped facade:
  `createCloudflareD1RouterApiAuthService(...)` now builds the D1 service
  assembly and returns route-family composition objects directly. The old
  `CloudflareD1RouterApiAuthMetadataService` monolith and flat delegating
  method layer are gone.
- Replaced Router API route required-service metadata with explicit facade
  service keys. `routeDefinitions.ts` now requires concrete route-family
  services such as `walletRegistration`, `walletAuthMethods`, `walletUnlock`,
  `emailOtp`, `webAuthn`, `identity`, `sessionVersions`, `thresholdRuntime`,
  `nearFunding`, `recovery`, and `router` instead of broad `authService` or
  stale `threshold` keys. The signed-delegate internal route-policy key is
  `signedDelegateAuth`; the public signed-delegate option name remains
  unchanged.
- Added guard coverage in
  `tests/unit/refactor82CloudflareD1Runtime.guard.unit.test.ts` so
  `routeDefinitions.ts` and `routeExecutionContext.ts` reject exact
  `authService` and `threshold` route metadata keys.
- Validation: `pnpm --dir packages/sdk-server-ts type-check`;
  `pnpm --dir tests exec tsc -p tsconfig.playwright.json --noEmit`; focused
  Playwright unit run for Refactor 82 route metadata, route-surface, and Router
  API router guards (11 tests passed).

### Phase 6: sealed session cleanup (July 3, 2026)

- Current sealed-session records now reject top-level `subjectId`, `userId`,
  and ECDSA `signingRootId`/`signingRootVersion` in both type fixtures and
  runtime `classifyRawSealedSessionRecord` parsing. `sealedRecordStorageRow`
  keeps the IndexedDB `wallet_id` index canonical and no longer writes a
  duplicate `user_id` row field. ECDSA sealed recovery now derives
  signing-root identity from `ecdsaRestore.runtimePolicyScope` only and
  rejects raw top-level ECDSA signing-root fields.
  `SealedSigningSessionEcdsaRestoreMetadata` and
  `SealedSigningSessionEd25519RestoreMetadata` now use strict auth branches:
  Email OTP records require canonical `providerSubjectId`, passkey records
  require credential identity, mixed auth branches are rejected, and the
  deleted `authSubjectId` alias is rejected at type level.
- SDK-web persisted Ed25519 available-lane readers now project runtime material
  through a shared Router A/B persisted-state classifier. The generic persisted
  available-lanes reader and Email OTP persisted-session snapshot no longer
  copy flat session-record `materialKeyId` /
  `ed25519WorkerMaterialBindingDigest` fields into core available-lane records.
  Focused fixture cleanup moved stale Email OTP records to bound
  `WalletAuthAuthority` shapes and complete sealed-worker-material metadata.
  Validation passed: `pnpm --dir packages/sdk-web exec tsc -p tsconfig.json
  --noEmit --pretty false`; `pnpm -C tests exec playwright test -c
  playwright.unit.config.ts
  ./unit/persistedAvailableSigningLanes.emailOtpEd25519.unit.test.ts
  ./unit/availableSigningLanes.ed25519Duplicates.unit.test.ts
  ./unit/routerAbEd25519.walletSessionState.unit.test.ts
  ./unit/thresholdEd25519.persistedRecords.unit.test.ts
  ./unit/warmEd25519SigningSessionAuthorization.unit.test.ts --reporter=line`
  with 45 tests passing.
- Sealed recovery exact lookup and durable available-lane assembly now compare
  Ed25519 material through `ed25519SealedRecoveryMaterialIdentity(...)`; direct
  `ed25519WorkerMaterialBindingDigest` / `materialKeyId` reads remain in
  boundary parsers or typed material-state helpers. Stale sealed-record test
  fixtures now include Email OTP `emailHashHex` binding metadata. Validation
  passed: `pnpm --dir packages/sdk-web exec tsc -p tsconfig.json --noEmit
  --pretty false`; `pnpm --dir tests exec tsc -p tsconfig.playwright.json
  --noEmit`; `pnpm -C tests exec playwright test -c
  playwright.unit.config.ts
  ./unit/availableSigningLanes.ed25519Duplicates.unit.test.ts
  ./unit/persistedAvailableSigningLanes.emailOtpEd25519.unit.test.ts
  ./unit/signingSessionRestoreCoordinator.unit.test.ts
  ./unit/sealedRecovery.methodAdapters.unit.test.ts
  ./unit/sealedSessionStore.unit.test.ts --reporter=line` with 77 tests
  passing.

### Phase 8: tests and guards (July 3, 2026)

- ECDSA export material committed-lane guard: the guard now rejects
  wallet-session auth probes in `ecdsaExportMaterial.ts`, and export material
  tests cover the committed-lane boundary with 9 tests passing.
- ECDSA reauth committed-lane guard: the guard also rejects
  committed-lane-optional signing args and bridge-level auth-lane resolver
  fallbacks, and `emailOtpEcdsaSigningSessionAuth.unit.test.ts` now builds
  committed-lane fixtures for bridge challenge/complete coverage.
- Obsolete Router API relayer harnesses deleted:
  `tests/relayer/email-otp.routes.test.ts`,
  `tests/relayer/email-otp.bootstrap-integration.test.ts`, and
  `tests/relayer/threshold-ecdsa.signature-harness.test.ts`. The remaining
  `new AuthService(` hits are web-server construction and explicitly
  AuthService-owned tests.

## Phase 9 Validation Evidence Record

SDK-side committed-lane slice evidence (re-separated from the plan's original
single bullet):

- `pnpm build:sdk`; `pnpm --dir packages/sdk-server-ts type-check`.
- Focused Email OTP ECDSA/companion unit coverage with 39 tests passing.
- Sealed recovery/restore coverage with 35 tests passing.
- D1 runtime and presign pool guard coverage with 64 tests passing.
- Relayer ECDSA durable store coverage with 7 passing and 6 skipped.
- Focused Ed25519/export coverage with 34 tests passing.
- Focused concurrent EVM-family budget reservation coverage in
  `signingSessionBudgetFinalizer.unit.test.ts`.
- July 3 route cleanup evidence:
  `pnpm --dir packages/sdk-server-ts type-check`;
  `pnpm --dir tests exec playwright test -c playwright.unit.config.ts
  unit/refactor80SwitchCase.guard.unit.test.ts --grep "key-identity inventory"
  --reporter=line`;
  `pnpm --dir tests exec playwright test -c playwright.unit.config.ts
  unit/routerAbNormalSigningSdk.guard.unit.test.ts --grep
  "legacy public threshold signing surfaces|legacy route literals"
  --reporter=line`; and
  `pnpm --dir tests exec playwright test -c playwright.relayer.config.ts
  relayer/threshold-ed25519.scheme-dispatch.test.ts --reporter=line`.
- Focused Email OTP public boundary coverage in
  `seamsWeb.emailOtp.unit.test.ts` with 8 tests passing.
- Focused strict-record coverage in
  `signingCapabilityStrictRecords.unit.test.ts` with 21 tests passing.
- Focused trusted ECDSA budget-authority coverage in
  `ecdsaMaterialState.unit.test.ts` and
  `evmFamily.requestBoundary.unit.test.ts` with 12 tests passing.
- Focused Email OTP ECDSA selection/auth coverage in
  `emailOtpEcdsaSigningSessionAuth.unit.test.ts`,
  `ecdsaSelection.restorable.unit.test.ts`, and
  `ecdsaMaterialState.unit.test.ts` with 24 tests passing.
- Focused shared wallet-auth authority parser coverage in
  `walletAuthAuthority.shared.unit.test.ts` with 5 tests passing.
- Focused Ed25519 warm-session persistence coverage in
  `warmSessionEd25519Persistence.unit.test.ts` with 3 tests passing.
- Focused Router A/B Ed25519 wallet-session state coverage in
  `routerAbEd25519.walletSessionState.unit.test.ts` with 17 tests passing.
- Focused Router A/B normal-signing and NEAR queue guard coverage with 41
  tests passing.
- Focused Ed25519 export wallet-session auth coverage in
  `nearEd25519ExportFlow.unit.test.ts` with 2 tests passing.
- Focused ECDSA export material/viewer coverage with 11 tests passing.
- Focused first ECDSA step-up budget ordering coverage in
  `signingFlow.readySigner.unit.test.ts` with 1 test passing.
- Focused stale-fixture hardening coverage in
  `walletAuthAuthority.shared.unit.test.ts`, `ecdsaRoleLocalRecords.unit.test.ts`,
  `signingPostSignPolicy.unit.test.ts`,
  `thresholdEcdsaEmailOtpConsumption.unit.test.ts`,
  `ecdsaMaterialState.unit.test.ts`,
  `warmSessionStore.capabilityResolution.unit.test.ts`, and
  `ecdsaBootstrapWarmPersistence.unit.test.ts` with 56 tests passing.
- Focused sealed/warm-session boundary coverage in
  `warmSessionStore.capabilityResolution.unit.test.ts`,
  `sealedSessionStore.unit.test.ts`, `sealedRecovery.methodAdapters.unit.test.ts`,
  and `warmSessionEd25519Persistence.unit.test.ts` with 49 tests passing.
- Focused Router A/B Ed25519 material-state parser cleanup in
  `routerAbEd25519.walletSessionState.unit.test.ts` and
  `routerAbNormalSigningSdk.guard.unit.test.ts` with 21 tests passing.
- Focused EVM-family Email OTP loose-getter deletion coverage in
  `ecdsaSelection.restorable.unit.test.ts`,
  `evmFamily.requestBoundary.unit.test.ts`, and
  `evmSigning.thresholdReconnectEvents.unit.test.ts` with 29 tests passing;
  focused deleted-getter source guards in
  `signingEngineArchitecture.flows.guard.unit.test.ts` and
  `emailOtpOperationSplit.guard.unit.test.ts` with 2 tests passing.
- Current available-lanes Ed25519 runtime material-state coverage in
  `availableSigningLanes.ed25519Duplicates.unit.test.ts` and
  `persistedAvailableSigningLanes.emailOtpEd25519.unit.test.ts` with 16 tests
  passing; a one-file TypeScript compiler-API check for
  `availableSigningLanes.typecheck.ts`.
- Current Ed25519 branch-specific policy-builder and warm-session envelope
  coverage in `thresholdWarmSessionPolicyDraft.unit.test.ts` with 4 tests
  passing and a compiler-API check for `session/public.typecheck.ts`,
  `thresholdWarmSessionBootstrap.typecheck.ts`, and
  `availableSigningLanes.typecheck.ts`; `pnpm --dir packages/sdk-web
  type-check`.
- Current ECDSA export committed-lane coverage in
  `ecdsaExportMaterial.unit.test.ts` with 9 tests passing; current ECDSA
  export recovery-flow committed-lane boundary coverage in
  `ecdsaExportMaterial.unit.test.ts` with 2 focused tests passing and
  `emailOtpOperationSplit.guard.unit.test.ts` with 1 focused guard passing.
- July 3 follow-up: ECDSA export boundary and Ed25519 companion committed-lane
  coverage passed with `ecdsaExportMaterial.unit.test.ts` (9 tests),
  `emailOtpWalletSessionCoordinator.unit.test.ts` focused companion tests (6
  tests), `emailOtpOperationSplit.guard.unit.test.ts` focused export/Ed25519
  guards (2 tests), `pnpm --dir packages/sdk-web exec tsc -p tsconfig.json
  --noEmit`, and `pnpm --dir tests exec tsc -p tsconfig.playwright.json
  --noEmit`; the full `emailOtpOperationSplit.guard.unit.test.ts` also passes
  with 15 tests.
- Current ECDSA restorable selection and reauth committed-lane coverage in
  `ecdsaSelection.restorable.unit.test.ts` with 11 focused tests passing.
- Current Email OTP operation split guards for exact ECDSA selection, Email
  OTP source-lane helpers, ECDSA export committed-lane route auth, and ECDSA
  reauth committed lanes in `emailOtpOperationSplit.guard.unit.test.ts` with 4
  tests passing.
- Current duplicate-proof cleanup coverage in
  `emailOtpOperationSplit.guard.unit.test.ts` with 2 focused tests passing,
  `thresholdEd25519.sessionPolicyDigest.unit.test.ts` with 4 tests passing,
  and `refactor80SwitchCase.guard.unit.test.ts` with 1 focused guard passing.
- Current Ed25519 authority-scope proof-ID cleanup coverage in
  `thresholdEd25519.sessionPolicyDigest.unit.test.ts` with 4 tests passing and
  the registration/warm-session focused batch
  (`registrationIntentDigest.unit.test.ts`,
  `registrationCeremonyStore.unit.test.ts`,
  `thresholdWarmSessionPolicyDraft.unit.test.ts`, and
  `googleEmailOtpWalletAuthFlow.unit.test.ts`) with 44 tests passing.
- Current `pnpm --dir tests exec tsc -p tsconfig.playwright.json --noEmit`
  passes. Source searches found no active SDK/test hits for the deleted
  generic Email OTP signing-session error, `ReadyEmailOtpEcdsaSessionRecord`,
  or stale `emailOtpAuthContext.(authSubjectId|retention|reason|consumedAtMs)`
  reads; `pnpm build:sdk`; `git diff --check`. Current
  `pnpm --dir packages/sdk-server-ts type-check` and
  `pnpm --dir tests exec tsc -p tsconfig.playwright.json --noEmit` runs pass.
- July 3 follow-up validation for transaction step-up committed-lane threading
  passed: `pnpm --dir packages/sdk-web type-check` and `pnpm --dir tests exec
  playwright test -c playwright.unit.config.ts
  unit/emailOtpOperationSplit.guard.unit.test.ts --reporter=line` with 12
  tests passing.
- July 3 record-backed lane collapse validation passed:
  `pnpm --dir packages/sdk-web type-check`,
  `pnpm --dir tests exec tsc -p tsconfig.playwright.json --noEmit`,
  `pnpm --dir tests exec playwright test -c playwright.unit.config.ts
  unit/emailOtpOperationSplit.guard.unit.test.ts
  unit/ecdsaExportMaterial.unit.test.ts
  unit/ecdsaSelection.restorable.unit.test.ts
  unit/emailOtpWalletSessionCoordinator.unit.test.ts --reporter=line` with 73
  tests passing, `pnpm build:sdk`, and `git diff --check`.
- July 3 passkey-bound authority slice: the shared Passkey
  `WalletAuthAuthority` branch now carries `walletId`, `factor`,
  `verifier.rpId`, and `bindingId`; flat Passkey authorities are rejected at
  the shared parser; SDK Passkey Ed25519 session-policy and warmup reads use
  `authority.verifier.rpId`. The authority-ref/digest helper now rejects a
  sibling `walletId` that disagrees with a bound Passkey authority's
  `walletId`, and the shared parser rejects missing or mismatched Passkey
  `bindingId` values. Pure factor parsing rejects wallet-bound verifier fields
  at the boundary. Focused validation passed: `pnpm --dir packages/sdk-web
  type-check`, `pnpm --dir tests exec tsc -p tsconfig.playwright.json
  --noEmit`, and `pnpm --dir tests exec playwright test -c
  playwright.unit.config.ts unit/walletAuthAuthority.shared.unit.test.ts
  unit/thresholdEd25519.sessionPolicyDigest.unit.test.ts --reporter=line`
  with 12 tests passing.
- July 3 Email OTP authority access cleanup: SDK signing/session consumers no
  longer read flat Email OTP authority `provider` or `providerUserId` fields
  directly. Those reads now go through shared authority/context accessors, so
  the later Email OTP bound-authority cut is localized to the authority module
  and boundary parsers. Focused validation passed: `pnpm --dir packages/sdk-web
  type-check`, `pnpm --dir tests exec tsc -p tsconfig.playwright.json
  --noEmit`, `pnpm --dir tests exec playwright test -c
  playwright.unit.config.ts unit/walletAuthAuthority.shared.unit.test.ts
  --reporter=line`, and a source search for direct `authority.provider` /
  `authority.providerUserId` reads under SDK signing/session code.
- July 3 guard follow-up: added
  `emailOtpOperationSplit.guard.unit.test.ts` coverage that fails on direct
  flat Email OTP authority provider reads in SDK signing/session sources.
  Focused validation passed: `pnpm --dir tests exec playwright test -c
  playwright.unit.config.ts unit/emailOtpOperationSplit.guard.unit.test.ts -g
  "SDK signing code reads Email OTP authority identity through accessors"
  --reporter=line`, `pnpm --dir tests exec tsc -p tsconfig.playwright.json
  --noEmit`, and `pnpm --dir packages/sdk-web type-check`.
- July 3 wallet-auth-method binding-id support: added shared
  `walletAuthMethodBindingId` for public SDK `WalletAuthMethodBinding` values
  and extended auth-method store coverage to compare the SDK formula with the
  server D1 store formula. The target Email OTP authority verifier now carries
  the wallet-auth-method email hash rather than an enrollment id, because
  enrollment ids belong to recovery/enrollment material and can rotate
  independently of the durable auth-method row.
- July 3 Ed25519 wallet-session policy bound-authority slice: SDK and server
  Ed25519 wallet-session policies now serialize one bound
  `WalletAuthAuthority` instead of `walletId + authorityScope`; wallet-session
  route parsers and threshold session minting derive stored
  `authorityScope` only at the persistence boundary. D1 wallet registration
  now upgrades `RegistrationAuthority` to bound `WalletAuthAuthority` before
  minting the finalized Ed25519 session, while pre-finalize registration
  request policies keep `authorityScope` as boundary data. Focused validation
  passed: `pnpm --dir packages/sdk-web exec tsc -p tsconfig.json --noEmit
  --pretty false`, `pnpm --dir packages/sdk-server-ts exec tsc -p
  tsconfig.json --noEmit --pretty false`, `pnpm build:sdk`, `pnpm -C tests
  exec playwright test -c playwright.unit.config.ts
  ./unit/emailOtpEcdsaSigningSessionAuth.unit.test.ts --reporter=line` with 4
  tests passing, and `pnpm -C tests exec playwright test -c
  playwright.unit.config.ts ./unit/emailOtpOperationSplit.guard.unit.test.ts
  ./unit/emailOtpWalletSessionCoordinator.unit.test.ts --reporter=line` with
  53 tests passing.
- July 3 consumption-rule fixture slice: added post-finalize static guards so
  ECDSA committed lanes and ECDSA export lanes reject pure
  `AuthFactorIdentity` / `EmailOtpFactorIdentity`, and pre-finalize
  registration ceremony state rejects wallet-bound `WalletAuthAuthority`.
  Focused validation passed: `pnpm --dir packages/sdk-web exec tsc -p
  tsconfig.json --noEmit --pretty false` and `pnpm --dir packages/sdk-server-ts
  exec tsc -p tsconfig.json --noEmit --pretty false`.
- July 3 Ed25519 registration policy boundary cleanup: D1 and AuthService-era
  registration/session-policy validators now reject `authorityScope` and root
  `rpId`, parse `sessionPolicy.authority` as a bound `WalletAuthAuthority`, and
  require it to match the authority resolved from the finalized registration or
  verified wallet binding. Deleted the duplicated AuthService-era
  `validateThresholdEd25519SessionPolicyBindings` helper; the passkey
  wallet-binding resolver now validates raw policy authority before building
  `Ed25519SessionPolicy`. Added shared exact authority comparison across wallet,
  binding, factor, and verifier fields, plus direct unit coverage for mismatch
  rejection. Updated stale registration-preparation fixtures to carry the
  now-required stored authority. Focused validation passed: `pnpm --dir
  packages/shared-ts exec tsc -p tsconfig.json --noEmit --pretty false`,
  `pnpm --dir packages/sdk-server-ts exec tsc -p tsconfig.json --noEmit
  --pretty false`, `pnpm build:sdk`, and `pnpm -C tests exec playwright test
  -c playwright.unit.config.ts ./unit/walletAuthAuthority.shared.unit.test.ts
  ./unit/relayWalletRegistration.boundary.unit.test.ts
  ./unit/registrationCeremonyStore.unit.test.ts --reporter=line` with 82 tests
  passing.
- July 3 Phase 7 resolver-backed ECDSA committed-lane slice: introduced
  `EmailOtpEcdsaSigningSessionAuthority` as the boundary output for warm and
  sealed Email OTP ECDSA signing-session authority. EVM-family selection now
  commits resolver-backed Email OTP lanes from that authority object when the
  exact runtime record is unavailable, preserving both wallet-session auth and
  bound `EmailOtpWalletAuthAuthority`. Passkey ECDSA committed-lane authority
  now comes from the selected session record's role-local auth method instead
  of the lane candidate. Fixed stale unit fixtures to use wallet-bound Email
  OTP contexts and complete Ed25519 material states, and repaired concurrent
  passkey/recovery envelope parser narrowing changes that blocked the SDK
  build. Validation passed: `pnpm --dir packages/sdk-web exec tsc -p
  tsconfig.json --noEmit --pretty false`, `pnpm --dir tests exec tsc -p
  tsconfig.playwright.json --noEmit`, `pnpm -C tests exec playwright test -c
  playwright.unit.config.ts ./unit/emailOtpOperationSplit.guard.unit.test.ts
  ./unit/ecdsaSelection.restorable.unit.test.ts
  ./unit/emailOtpEcdsaSigningSessionAuth.unit.test.ts
  ./unit/ecdsaExportMaterial.unit.test.ts --reporter=line` with 41 tests
  passing, `pnpm -C tests exec playwright test -c playwright.unit.config.ts
  ./unit/warmSessionStore.capabilityResolution.unit.test.ts
  ./unit/emailOtpEcdsaSigningSessionAuth.unit.test.ts
  ./unit/ed25519MaterialAuthPlan.unit.test.ts --reporter=line` with 14 tests
  passing, and `pnpm build:sdk`.
- July 3 Phase 7 committed-lane wallet-binding guard slice: added static
  fixtures for resolver-backed Email OTP ECDSA committed lanes and source
  guards for the resolver-backed branch. ECDSA committed-lane builders now
  validate that the bound authority wallet matches both the selected lane key
  wallet and the candidate wallet while those duplicated wallet facts remain
  present. Focused validation passed: `pnpm --dir packages/sdk-web exec tsc -p
  tsconfig.json --noEmit --pretty false` and `pnpm -C tests exec playwright
  test -c playwright.unit.config.ts
  ./unit/emailOtpOperationSplit.guard.unit.test.ts --reporter=line` with 16
  tests passing.
- July 3 Phase 7 Email OTP export challenge-boundary slice: split key-export
  challenge authority into explicit fresh-login ECDSA export and committed
  signing-session export branches. Committed ECDSA export, Ed25519 export, and
  transaction challenge surfaces now require branch-specific
  `EmailOtpSigningSessionAuthLane`; root `routeAuth` and optional `authLane`
  are rejected at the TypeScript boundary. Focused validation passed:
  `pnpm --dir packages/sdk-web exec tsc -p tsconfig.json --noEmit --pretty
  false`, `pnpm --dir tests exec tsc -p tsconfig.playwright.json --noEmit`,
  and `pnpm -C tests exec playwright test -c playwright.unit.config.ts
  ./unit/emailOtpWalletSessionCoordinator.unit.test.ts
  ./unit/ecdsaExportViewerPayload.unit.test.ts
  ./unit/ecdsaExportMaterial.unit.test.ts
  ./unit/emailOtpOperationSplit.guard.unit.test.ts --reporter=line` with 65
  tests passing.
- July 3 Phase 7 NEAR Ed25519 step-up authority slice: introduced
  `EmailOtpEd25519SigningSessionAuthority` as the warm-boundary output for
  Email OTP Ed25519 signing-session authority. The warm capability reader now
  exposes `resolveEmailOtpEd25519SigningSessionAuthority` and no longer exposes
  the generic `resolveEmailOtpSigningSessionAuthLane` surface. `signNear`
  resolves an `Ed25519SigningLane` from that authority object plus the
  persisted record, and `buildEd25519SigningLane` validates bound
  `EmailOtpWalletAuthAuthority`, threshold session id, and signing grant id
  together. Deleted the stale `emailOtpEd25519AuthLaneFromRecord` fallback and
  moved NEAR transaction challenge preparation to carry `Ed25519SigningLane`
  through `signNear` and `createNearSigningDeps`; the browser signing-surface
  adapter is the only NEAR transaction path that extracts
  `committedLane.authLane` for `emailOtpSessions`. Added source/type guards
  against rebuilding Ed25519 step-up authority from a loose auth lane.
  Validation passed: `pnpm --dir packages/sdk-web exec tsc -p
  tsconfig.json --noEmit --pretty false`, `pnpm --dir tests exec tsc -p
  tsconfig.playwright.json --noEmit`, `pnpm -C tests exec playwright test -c
  playwright.unit.config.ts ./unit/emailOtpOperationSplit.guard.unit.test.ts
  ./unit/warmSessionStore.capabilityResolution.unit.test.ts
  ./unit/emailOtpWalletSessionCoordinator.unit.test.ts
  ./unit/ed25519MaterialAuthPlan.unit.test.ts
  ./unit/emailOtpEcdsaSigningSessionAuth.unit.test.ts --reporter=line` with 67
  tests passing, `pnpm build:sdk`, and `git diff --check`.
- July 3 Phase 7 auth-projection tightening slice: narrowed
  `authLaneAppSessionJwt`, `appSessionJwtFromEmailOtpAuthLane`, and
  `appSessionSubjectFromEmailOtpAuthLane` to require concrete
  `EmailOtpAuthLane` input. Also narrowed `authLaneToRouteAuth` so callers
  must project from a validated lane, while cookie lanes still intentionally
  produce no bearer route auth. Added type fixtures so missing auth-lane state
  is rejected at compile time instead of being normalized to an empty JWT or
  missing route auth in core session code. Validation passed: `pnpm --dir
  packages/sdk-web exec tsc -p tsconfig.json --noEmit --pretty false`, `pnpm
  --dir tests exec tsc -p tsconfig.playwright.json --noEmit`, `pnpm -C tests
  exec playwright test -c playwright.unit.config.ts
  ./unit/emailOtpAuthLane.unit.test.ts --reporter=line` with 4 tests passing,
  and `pnpm build:sdk`.
- July 3 Phase 7 ECDSA login route-plan boundary slice: changed core Email OTP
  ECDSA login (`LoginEmailOtpEcdsaCapabilityArgs`) to require a committed
  `EmailOtpRoutePlan` and reject raw `appSessionJwt`, loose `routeAuth`, and
  `sessionKind` inputs. The `emailOtpPublic` facade now performs the boundary
  conversion for public unlock callers, then calls the coordinator with the
  strict core shape. Coordinator unit coverage now passes explicit route plans,
  and `ecdsaLogin.typecheck.ts` rejects raw login auth fields on the core
  surface. Focused validation passed: `pnpm --dir packages/sdk-web exec tsc -p
  tsconfig.json --noEmit --pretty false`, `pnpm --dir tests exec tsc -p
  tsconfig.playwright.json --noEmit`, and `pnpm -C tests exec playwright test
  -c playwright.unit.config.ts ./unit/emailOtpWalletSessionCoordinator.unit.test.ts
  ./unit/emailOtpOperationSplit.guard.unit.test.ts
  ./unit/emailOtpEcdsaSigningSessionAuth.unit.test.ts --reporter=line` with 57
  tests passing.
- July 3 Phase 7 Ed25519 login route-plan boundary slice: changed core Email
  OTP Ed25519 fresh login (`LoginEmailOtpEd25519CapabilityArgs`) to require
  `EmailOtpRoutePlan` and reject raw `appSessionJwt`, loose `routeAuth`, and
  `sessionKind` inputs. `emailOtpPublic` now builds the Ed25519 login route
  plan for public unlock callers before invoking `EmailOtpEd25519Warmup`.
  `ed25519Warmup.typecheck.ts` rejects the raw core fields. Focused validation
  passed: `pnpm --dir packages/sdk-web exec tsc -p tsconfig.json --noEmit
  --pretty false`, `pnpm --dir tests exec tsc -p tsconfig.playwright.json
  --noEmit`, and `pnpm -C tests exec playwright test -c
  playwright.unit.config.ts ./unit/emailOtpWalletSessionCoordinator.unit.test.ts
  ./unit/emailOtpOperationSplit.guard.unit.test.ts
  ./unit/seamsWeb.emailOtp.unit.test.ts
  ./unit/googleEmailOtpWalletAuthFlow.unit.test.ts --reporter=line` with 85
  tests passing.
- July 3 Phase 7 ECDSA registration route-plan boundary slice: changed core
  Email OTP ECDSA registration/enroll
  (`EnrollAndLoginEmailOtpEcdsaCapabilityArgs`) to require
  `EmailOtpRoutePlan` and reject raw `appSessionJwt`, loose `routeAuth`, and
  `sessionKind` inputs. `emailOtpPublic` now builds the registration route
  plan for public SDK/iframe registration callers before invoking the
  coordinator. `ecdsaEnrollment.typecheck.ts` rejects the raw core fields, and
  coordinator coverage now uses explicit registration route plans. Focused
  runtime validation passed: `pnpm -C tests exec playwright test -c
  playwright.unit.config.ts ./unit/emailOtpWalletSessionCoordinator.unit.test.ts
  ./unit/googleEmailOtpWalletAuthFlow.unit.test.ts
  ./unit/seamsWeb.emailOtpIframe.unit.test.ts --reporter=line` with 64 tests
  passing.
- July 3 Phase 7 Ed25519 HSS client/server ownership slice: finished the
  server-side split that keeps client-owned staged evaluator artifacts limited
  to `contextBindingB64u` and `stagedEvaluatorArtifactB64u`, while responded
  server sessions carry the server eval state through registration and durable
  session storage. Tightened `finalizeThresholdEd25519HssReport` to require a
  responded server session, added durable-store responded-session narrowing,
  refreshed registration HSS type fixtures, and updated orchestration fixtures
  to use canonical `evmFamilySigningKeySlotId`, real ECDSA application binding
  digests, and complete Ed25519 ready material state. Validation passed:
  `pnpm --dir packages/sdk-server-ts exec tsc -p tsconfig.json --noEmit
  --pretty false`, `pnpm --dir packages/sdk-web exec tsc -p tsconfig.json
  --noEmit --pretty false`, `pnpm --dir tests exec tsc -p
  tsconfig.playwright.json --noEmit --pretty false`, `pnpm -C tests exec
  playwright test -c playwright.unit.config.ts
  ./unit/thresholdEd25519.routeValidation.unit.test.ts
  ./unit/relayWalletRegistration.boundary.unit.test.ts
  ./unit/addWalletSigner.orchestration.unit.test.ts --reporter=line` with 84
  tests passing, `pnpm build:sdk`, and `git diff --check`.
- July 3 Phase 2 authority-ref API slice: removed the loose
  `walletId + authority` helper inputs from shared wallet-authority digest/ref
  construction. `canonicalWalletAuthorityBindingDigestInput`,
  `walletAuthorityBindingDigest`, and `walletAuthAuthorityRef` now consume the
  bound `WalletAuthAuthority` object as the single source of wallet identity;
  type fixtures reject sibling `walletId` inputs, and runtime coverage verifies
  digest separation plus authority-ref wallet derivation. Focused validation
  passed: `pnpm --dir packages/shared-ts exec tsc -p tsconfig.json --noEmit
  --pretty false` and `pnpm -C tests exec playwright test -c
  playwright.unit.config.ts ./unit/walletAuthAuthority.shared.unit.test.ts
  --reporter=line` with 9 tests passing.
- July 3 Phase 7 generic ECDSA committed-lane slice: converted the exported
  ECDSA committed-lane model to the single authority-parametrized
  `EcdsaCommittedLane<A extends WalletAuthAuthority>` shape. The Email OTP and
  Passkey aliases, ready-lane aliases, and record-backed lane projection now
  compose from that shape, and branch selection narrows through
  `authority.factor.kind` rather than method-specific lane objects. Type
  fixtures reject assigning an Email OTP lane to a Passkey-parametrized lane.
  Focused validation passed: `pnpm --dir packages/sdk-web exec tsc -p
  tsconfig.json --noEmit --pretty false`, `pnpm --dir tests exec tsc -p
  tsconfig.playwright.json --noEmit --pretty false`, and `pnpm -C tests exec
  playwright test -c playwright.unit.config.ts
  ./unit/emailOtpOperationSplit.guard.unit.test.ts
  ./unit/walletAuthAuthority.shared.unit.test.ts --reporter=line` with 25
  tests passing.
- July 3 Phase 5 Ed25519 wallet-session route authority slice: changed Router
  A/B Ed25519 wallet-session JWT signing input from loose `authorityScope` to
  bound `WalletAuthAuthority`, added authority parsing to Ed25519
  wallet-session claims, and made claims reject authority/scope drift at the
  boundary. Registration finalize and add-auth-method finalize responses now
  carry the bound authority; D1 and in-memory replay parsers reject persisted
  success payloads that lack authority or whose derived Ed25519 scope does not
  match the stored scope. Verified Ed25519 wallet-session auth now carries
  `WalletAuthAuthority`; signing-budget and private-admission adapters derive
  `ThresholdEd25519AuthorityScope` only when comparing with threshold-store or
  admission boundary records. Sync-account and recovery JWT signing build
  passkey authorities from resolved wallet bindings, and registration route
  attach logic rejects Ed25519 session results missing authority. Focused
  validation passed: `pnpm --dir packages/sdk-server-ts exec tsc -p
  tsconfig.json --noEmit --pretty false`, `pnpm --dir tests exec tsc -p
  tsconfig.playwright.json --noEmit --pretty false`, `pnpm -C tests exec
  playwright test -c playwright.unit.config.ts
  ./unit/thresholdSessionClaims.unit.test.ts
  ./unit/signingSessionBudgetFinalizer.unit.test.ts --reporter=line` with 39
  tests passing, and `pnpm build:sdk`.
- July 3 Phase 7 ECDSA reconnect wallet-session authority slice:
  `buildEcdsaReconnectMaterial` now verifies and carries
  `VerifiedEcdsaWalletSessionAuth` at the reconnect-material boundary.
  `buildWalletSessionEcdsaReconnect` consumes that verified auth and checks it
  against the requested reconnect identity, signing key context, and relayer
  identity instead of selecting a Wallet Session JWT from the persisted record.
  Type fixtures reject hand-built reconnect material without verified auth and
  reject raw `walletSessionJwt` beside the verified auth. Focused validation
  passed: `pnpm --dir packages/sdk-web exec tsc -p tsconfig.json --noEmit
  --pretty false`, `pnpm --dir tests exec tsc -p tsconfig.playwright.json
  --noEmit --pretty false`, and `pnpm -C tests exec playwright test -c
  playwright.unit.config.ts ./unit/evmFamilyStepUpProvisionPlan.unit.test.ts
  ./unit/evmSigning.thresholdReconnectEvents.unit.test.ts
  ./unit/warmSessionStore.reconnect.unit.test.ts --reporter=line` with 11
  tests passing.
- July 3 Phase 7 sealed recovery authority carrier slice: accepted sealed
  recovery records now carry branch-specific `WalletAuthAuthority` built by
  the sealed-record parser. Email OTP sealed signing-session authority,
  sealed Email OTP restore context builders, and exact sealed-record lookup
  consume that normalized authority instead of reconstructing identity from
  loose sealed-record sibling fields. Type fixtures reject wrong authority
  branches and parallel loose authority fields on accepted sealed recovery
  records. Focused validation passed: `pnpm --dir packages/sdk-web exec tsc
  -p tsconfig.json --noEmit --pretty false`, `pnpm --dir tests exec tsc -p
  tsconfig.playwright.json --noEmit --pretty false`, and `pnpm -C tests exec
  playwright test -c playwright.unit.config.ts
  ./unit/sealedRecovery.methodAdapters.unit.test.ts
  ./unit/sealedSessionStore.unit.test.ts --reporter=line` with 44 tests
  passing; `pnpm build:sdk`; and `git diff --check`.
- July 3 Phase 7 Router A/B ECDSA single-record wallet-session authority slice:
  `resolveRouterAbEcdsaWalletSessionAuthFromRecord` no longer probes the warm
  capability store when the selected record is missing a Wallet Session JWT.
  The resolver returns ready JWT authority only from the record it was passed,
  preserves the non-JWT `cookie_session` branch, and reports stale JWT records
  as `missing_wallet_session_jwt`. Type fixtures reject reintroducing
  `source: 'warm_capability'`. Focused validation passed: `pnpm -C tests exec
  playwright test -c playwright.unit.config.ts
  ./unit/thresholdEcdsaSessionAuthMaterial.unit.test.ts --reporter=line` with
  1 test passing.

## Line Count Record

- July 3 snapshot: tracked non-doc diff is +5,239/-5,948 lines; tracked docs
  diff is +960/-398 lines; untracked non-doc text is 4,696 lines. The
  untracked count is dominated by the parallel AuthService mechanical split
  modules plus the new shared wallet-auth authority boundary module.
