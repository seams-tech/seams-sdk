# Refactor 90 Deletion Ledger

Created: July 22, 2026. Reconstituted from the pre-slim plan at commit
`f5eb4ace9` after the July 22 slimming removed the symbol-level lists while the
symbols were still live in source.

Rules:

- Delete an entry in the same change that replaces its behavior
  (no third implementation, no compatibility alias).
- When an entry is deleted, strike it here and record the commit in the plan
  tracker or the applicable commit message.
- Execution units add newly discovered targets here instead of growing prose
  in the [plan](./refactor-90-modular-auth-capabilities-plan.md).

The headings retain their historical phase names so existing journal and
commit references stay understandable. Current ownership is:

- Unit 1: Foundations A/B, Phases 4–5, and the ECDSA portion of historical
  Phase 18;
- Unit 2: Phases 7–14;
- Unit 3a: Phases 17–21, 24, the authorization/wire portion of historical
  Phase 18, and MPC-owned final deletions;
- Unit 4: Phases 22–23 and UI-owned final deletions.

Historical Phase 6 inventory is absorbed by every unit. Unit 3b adds and closes
any concrete vault target discovered by its Satyr Phase 6 inventory.

## Foundation B / Phase 18 — legacy ECDSA record family

Replacement: the required-field `active | retired` ECDSA capability record,
exact parser, and two-state activation journal.

Unit 1 removes material ownership and all material readers/writers from this
family. Unit 3a deletes the remaining authorization/session/quota record types,
public APIs, runtime maps, and fixtures after Unit 2 supplies their narrow
replacement.

- ~~`ThresholdEcdsaSessionRecordCore`~~
- ~~`NormalizedThresholdEcdsaSessionRecordShared`~~
- ~~`NormalizedThresholdEcdsaSessionRecord`~~
- ~~`ThresholdEcdsaSessionRecord`~~
- ~~`ReadyPasskeyEcdsaSessionRecord`~~
- ~~`EmailOtpEcdsaSessionRecord`~~
- ~~`OperationUsableThresholdEcdsaSessionRecord`~~
- ~~`buildOperationUsableThresholdEcdsaSessionRecord`~~
- ~~`PASSKEY_ECDSA_SIGNING_SOURCE_PRIORITY`, Passkey material ranking, and
  newest-record selection~~
- ~~`recordsByLane` and module-level record maps as persistence or selection
  authority~~ (manifest-keyed hot observations remain independent)
- ~~ECDSA `restorable` as a core lifecycle label~~ — rejected by the concrete
  ECDSA lane type; ECDSA uses explicit hydration outcomes while Ed25519 retains
  `restorable` for its durable sealed-material state
- authority/lifecycle inference from `source`, provider identity, optional
  field presence, record timestamps, or diagnostics
- ~~registration-only and unlock-only capability publication paths~~ — absent
  at the `5d3518c98` audit; registration, unlock, and refresh publish through
  the canonical manifest/activation boundary
- ~~the orphaned bootstrap-era `ecdsaCapabilityReadiness.ts` classifier~~ —
  deleted by `18850e9d4`
- ~~obsolete IndexedDB ECDSA composite session records~~ — absent at the
  `5d3518c98` audit; the manifest and sealed-runtime stores are the canonical
  current schema and are retained
- ~~write-dead Ed25519 in-memory session-record family, lane readers, and
  cache maps~~ — no production or retained-test consumer remained after the
  canonical Ed25519 capability/sealed-runtime cutover; deleted with its stale
  architecture guard and README references in `a84f92b37`
- ~~`IndexedDbEcdsaRoleLocalSessionMaterialStore` and
  `ecdsaRoleLocalSessionMaterialStore.ts`~~ — deleted by `ab510dab8`
- ~~`ecdsa_role_local_sealing_keys` and
  `ecdsa_role_local_active_material` object stores~~ — removed from the v11
  schema and deleted during upgrade by `ab510dab8`

## Foundation A — tactical unions replaced by the shared hydration plan

- ~~`ExactEcdsaExportSession` (the `current session | public reauth authority`
  union)~~ — deleted by `643dde348`; its sole canonical branch is flattened
  into the required-field exact export lane
- ~~`EcdsaPublicReauthLane`~~ — removed with the public-reauthorization
  selection cutover (`f6ce0651e`).
- ~~`EvmFamilySharedEcdsaState`~~ — removed with the auth-neutral ECDSA state
  cutover (`5db9ad87e`).
- ~~Near tactical material-inspection unions superseded by the shared
  outcomes~~ — absent at the `5d3518c98` audit; protocol-local observation
  unions remain valid boundary inputs to the shared outcomes

## Phase 1 boundary residue — registration modes

- `ed25519_only`, `ecdsa_only`, `ed25519_and_ecdsa` in core registration,
  quota, session, and signing state (quota data shapes die in Phase 18/20)
- ~~`combined_registration` D1 ceremony state outside any named temporary
  boundary parser~~ — absent from production at the `5d3518c98` audit

## Phase 3 delete-candidate carryover

- ~~AuthService-era wallet registration authority branches → D1 registration
  route services (Phase 9 / Refactor 82B)~~ — absent at the `5d3518c98` audit;
  the request-scoped registration route service is canonical
- ~~Passkey-only Ed25519 authority checks inside shared session paths →
  `WalletAuthAuthorityRef` boundary parsers (Phase 17)~~ — implicit shared-path
  checks are absent at the `5d3518c98` audit; explicit Passkey protocol
  branches remain
- ~~AuthService generic registration bootstrap/finalize surfaces used by
  Cloudflare D1 routes (Phase 9)~~ — absent at the `5d3518c98` audit
- ~~parallel wallet-ID allocation copy in the D1 registration intent service
  beside `walletRegistrationPlanning.ts` (Phase 9)~~ — absent at the
  `5d3518c98` audit; one server-allocation path remains

## Phase 4 — subject and session-read residue

- ~~`evmFamilySigningKeySlotId` in `WalletUnlockSubject`~~ — replaced by exact
  `ecdsaThresholdKeyId` capability identity in `b54cd1bca`
- ~~`WalletSessionReadSubject` / `wallet_near_subject` sibling aliases~~ — the
  exact wallet capability subject resolver exposes no sibling subject alias
  after `ffdc64fdc`
- ~~`WalletSessionReadResolution`~~ — renamed directly to
  `WalletCapabilitySubjectResolution` in `ffdc64fdc`; no compatibility export
  remains
- ~~the `login.publicKey ? 'passkey' : null` auth-method inference fallback~~ —
  deleted by the exact wallet-subject restoration in `5d0465e7c`
- ~~silent signer-slot defaults in restore/session-read paths~~ — absent at the
  `5d3518c98` audit; boundary parsers reject missing or invalid slots
- ~~fallback paths inferring a wallet from `nearAccountId` outside explicit
  boundary parsers~~ — absent at the `5d3518c98` audit; exact subject
  resolution requires wallet, account, and slot
- ~~the missing-`ClientUserData.authMethod` → Passkey fallback during NEAR
  unlock~~ — deleted by `4f51048c5`; malformed stored projections now fail
  before a prompt
- ~~Wallet Session identity decoded from the bearer JWT during Near normal
  signing~~ — replaced by the correlated active authorization projection and
  branded `WalletSessionId` in `821167bf3`
- ~~Ed25519 runtime-policy scope inferred from the app-session bearer JWT~~ —
  the Wallet Session mint response now supplies the required scope explicitly
  in `f75154e88`
- ~~runtime-policy scope inferred from Wallet Session JWTs in login bootstrap,
  sealed recovery, Ed25519 cold recovery, and dormant record normalization~~ —
  replaced by exact bootstrap, sealed-record, authorization-record, and mint
  response fields in `ffdc64fdc`, `44c4e58c4`, `5971a3753`, and `ca6b86fa0`
- ~~runtime-policy scope inferred from the Email OTP ECDSA enrollment route
  JWT~~ — the obsolete standalone enrollment SDK/iframe route was deleted by
  `859961771`; canonical `registerWallet` retains the verified registration
  boundary.

## Phase 5 — role-local material identity

- ~~`evmFamilySigningKeySlotId` in `EcdsaRoleLocalPublicFacts`, activation and
  durable bindings, persistence keys, and sealing AAD~~ — deleted by
  `e7c1168a0`; provisioning/wire consumers derive it from wallet plus signing
  root/version.
- ~~`evmFamilySigningKeySlotId` in remaining runtime paths~~ (audit first: delete,
  or rename to `EvmFamilyEcdsaProvisioningReservationId` confined to
  registration/bootstrap). Forbidden in `ExactSigningLaneIdentity`,
  Wallet Session claims, Router A/B normal-signing scope,
  `EcdsaRoleLocalPublicFacts`, sealed recovery records, and remaining runtime
  identity surfaces. The zero-caller server-planned WASM context was deleted
  by `2b2d2f4b3`, and the unused server export-share request/response/parser
  contract by `84677131e`. The unused ECDSA connect adapter was deleted by
  `713fc967c`. Server normal-signing admission and durable ECDSA MPC session
  records dropped the slot in `a980592a0` and `9bada9733`; local normal-signing
  seed admission followed in `5f63b4de9`. Runtime wallet-key projections,
  persisted signer metadata, existing-key worker handles, and Email OTP sealed
  rehydration switched to exact key-handle identity in `6113b36bb`;
  registration handle branches retain their provisioning slot. The unused
  client ECDSA session-policy type, builder, digest, public exports, and
  slot-pinning source checks were deleted in `3d6c4c74b`. Registration,
  add-signer, and bootstrap persistence stopped copying the provisioning slot
  into durable IndexedDB signer metadata in `0fbbbb04b`. The zero-caller server
  role-local key-record parser and its in-memory, Redis, Upstash, and Durable
  Object stores were deleted in `a913d461f`. Unused slot projections in Wallet
  Session signing context, Email OTP capability lookup, and sealed refresh
  validation were removed in `45e495ddc`. Server-persisted ECDSA signer
  records and inventory responses switched to exact key-handle identity in
  `5f7075386`; the same change deleted the forbidden provisioning slot from
  post-registration normal-signing scope and rejects slot-bearing persisted
  records at the parser boundary. Exact-session bootstrap results stopped
  projecting the slot into activated runtime state in `1f04bb1bb`. Ready
  ECDSA use-case lanes and Email OTP runtime activation authority forbid the
  slot in `47070b2b0`. The keygen-derived activation projection was replaced
  by required slot-free activated key facts in `2768d24a0`. The zero-caller
  ECDSA keygen facade and dead normal-signing-state builder were deleted in
  `f762803df`. The registration-era enrollment activation/bootstrap variant
  was deleted in `1e317e433`; its obsolete request-shape tests followed in
  `499a9e00e`, while the client-root proof boundary test remains.
  Post-registration relayer-key derivation stopped accepting the provisioning
  slot in `fca3baaf2`; callers now supply exact wallet and signing-root facts.
  The final audit found positive uses only at registration/provisioning
  boundaries and explicit rejection in runtime shapes; the zero-consumer
  bootstrap relayer port family was deleted in `a843d8dbc`.
- ~~`evmFamilySigningKeySlotId` in ECDSA Wallet Session JWT binding facts and
  normal-signing claims~~ — deleted by `4986d279f`; the value remains only on
  the registration bootstrap request/response boundary in that path.
- ~~`evmFamilySigningKeySlotId` in server ECDSA Wallet Session claims,
  authorization projections, budget matching, and normal-signing admission~~ —
  deleted by `d18133431`; admission now keys ECDSA work by branded material
  activation and pool-fill derives its provisioning slot from material scope.
- ~~`evmFamilySigningKeySlotId` in server ECDSA Wallet Session records, budget
  bindings, Durable Object equality, and signing-session seal projections~~ —
  replaced by required branded `EcdsaKeyHandle` in `51ee85a29`; the slot remains
  only on the provisioning input where the runtime validates the plan.
- ~~`clientVerifyingShareB64u` inside `EcdsaRoleLocalMaterialBinding`, its
  digest, and material handle~~ — replaced by the strict
  `EcdsaClientVerifyingPublicKey33B64u` fact in `fcdf0ad3c`
- ~~`clientVerifyingShareB64u` as an internal ECDSA material-identity field~~ —
  internal material identity uses the branded
  `clientVerifyingPublicKey33B64u`; protocol and generated worker/wire field
  names remain boundary-owned and are not deletion targets
- ~~`chainTarget`, `thresholdSessionId`, `activeStateId`, and `signingGrantId`
  inside `EcdsaRoleLocalMaterialBinding`, its binding digest, and material
  handle~~ — deleted in `fcdf0ad3c`
- ~~`routerAbStateSessionId`, `CapabilityGrantId`,
  `MpcWalletSigningQuotaId`, and remaining-use/expiry fields inside role-local
  material identity~~ — forbidden by the canonical material-handle and
  manifest types at the `5d3518c98` audit; these identifiers remain only in
  their authorization, quota, or protocol-boundary domains
- ~~`ecdsaRoleLocalSigningMaterialHandleFromReadySignerSession`~~ — deleted in
  favor of constructing the exact handle from material facts in `fcdf0ad3c`
- ~~the legacy regression expectation that Tempo and ARC produce different
  role-local worker material handles for the same material~~ — deleted in
  `fcdf0ad3c`; the lane-level mismatch-rejection test remains open
- ~~`roleLocalDurableMaterialRef` as a standalone field on
  `ThresholdEcdsaSessionRecord*` and sealed ECDSA session/recovery payloads~~ —
  replaced by the exact `EcdsaRoleLocalPersistedMaterialRef`, including
  `MpcMaterialActivationRef`, in `fc0e4874e`

## Phase 17 — interim authority adapters

- ~~`signingGrantAdmissionAuthorityKeyFromAuth`~~ — deleted in `07016a7cb`;
  every lane uses the central exact auth-binding key builder
- ~~the branch-specific queue-key helper covered by Refactor 82B Phase 10D
  tests~~ — the retired auth-derived helper is absent; the two live branded
  queue keys serialize canonical reusable-grant admission and independent
  operation authorization respectively

## Phase 18 — durable restore fields and shared-type residue

- ~~`walletSessionJwt` and `signingGrantId` in durable Ed25519 restore
  records~~ — current records are grant-free and stale camel/snake-case grant
  fields are scrubbed at the persistence boundary (`d91e4bc9d`, `04b774f04`).
  `providerSubjectId` and `emailHashHex` remain required Email OTP material
  binding facts, while `registrationAuthorityId` remains a boundary concern.
- ambiguous `remainingUses` / `expiresAtMs` rows (classify each: branded
  recovery policy, quota, grant, session transport — never migrate ambiguously)
- every `signingGrantId` occurrence (classify: delete, map to operation grant,
  or map to `MpcWalletSigningQuotaId`; never a mechanical rename, never
  material identity)
- ~~zero-caller Email OTP HKDF tuples that included `signingGrantId`~~ — the
  obsolete helpers and their test vectors were deleted (`47455581e`).
- ~~`WalletSessionId = SigningGrantId`; replace it atomically with a distinct
  branded `WalletSessionId` and boundary parser~~ — `WalletSessionId` is an
  independent `DomainId<'WalletSessionId'>`; no alias remains
- interim shared exports of `SignerAuthMethod` / `WalletAuthMethod` only if a
  capability-local move ships both halves in one cut (Refactor 91's stable leaf
  module stays until then)

## Phases 18-20 — session-shaped material identity

Replacement: branded `MpcMaterialActivationId`, exact
`MpcMaterialActivationRef`, and an operation scope that carries an independent
discriminated `MpcOperationAuthorizationRef`.

- ~~`ActiveMpcMaterialSessionRef`~~ — absent
- ~~`ActiveEcdsaMaterialSession`~~ — absent
- ~~`rehydrate_active_session`~~ — absent
- ~~`active_state_session_id`~~ — absent
- ambiguous normal-signing `session_id` fields that represent authorization;
  the replacement wire field is the discriminated `authorization` branch
- ~~`evm_family_signing_key_slot_id` duplicated beside
  `material_activation.key_binding` on operation-step-up preparations~~ —
  deleted by `f6d3390e4`; the server derives the provisioning lookup key from
  the exact activation at its boundary
- unconditional `authorizationSessionId: SeamsSessionId | WalletSessionId` on
  MPC operation scopes; reusable-session authorization carries
  `WalletSessionId` plus `CapabilityGrantId`, while operation step-up carries
  only `CapabilityGrantId`
- every `thresholdSessionId` or Wallet Session ID used as a material activation
  locator, persistence key, worker-state key, or hydration identity
- compatibility aliases between authorization session IDs and material
  activation IDs

## Phases 18-23 — Refactor 92 lifecycle migration residue

Replacement: the frozen Refactor 92 classifier, canonical invalidator,
structured server result, secure-origin state/event transport, and
single-operation same-method step-up, composed with the new branded identities.

- any recreated expiry inference from JWT presence, optional session IDs,
  optional timestamps, diagnostics, or message text
- any capability-specific expiry/exhaustion classifier added beside the
  Refactor 92 classifier for NEAR, Tempo, EVM, delegate signing, or key export
- any step-up path that creates a reusable Wallet Session
- any expiry path that enters Yao recovery, device linking, or material
  reactivation
- any React/Lit host path that declares the wallet unlocked before exact iframe
  initialization or independently parses Wallet Session lifecycle
- fixtures that equate Wallet Session, signing grant, quota, threshold session,
  or material activation IDs solely to preserve pre-cutover behavior

## Phases 19/21/24/27 — Refactor 93 Yao server boundary

Retained foundation: request-scoped Gateway persistence, the operation-specific
MPC Router execute boundary, canonical ceremony/input-pair identity, pair-bound
role-local lifecycle, exact encrypted-output replay, explicit recovery
promotion, and atomic SigningWorker package delivery. These are Refactor 93
owners and are not Refactor 90 deletion targets.

Completed deletions that must stay absent:

- ~~Gateway serial Stage/Start/Result and direct Yao package-delivery
  orchestration~~ — deleted by `8a3c49145`
- ~~direct Gateway Deriver A/B and Yao SigningWorker origins~~ — deleted by
  `8a3c49145`
- ~~tenant-runtime Yao lifecycle ownership, family cutover selectors, and
  admission-drain routing~~ — deleted by `8a3c49145`
- ~~legacy serial Deriver Stage/Start/Result role routes and compatibility
  parsers~~ — deleted by `feba59d7a`
- lower-authority fixtures, mocks, or source guards that reconstruct any of
  those deleted paths

## Phase 19 — Email OTP patch tactical surface

Replacement: capability-local Near/ECDSA material adapters, generic session
ports, and the two-state recovery journal.

- ~~`canonicalizeWorkerProvisionedBootstrap`,
  `signingGrantIdFromEcdsaBootstrap`, and
  `ecdsaBootstrapWithSigningGrantId`~~ — deleted by `3fdeba8b7`; bootstrap
  session identity now has one required owner and publication validates it
- ~~`EmailOtpUnlockMaterialPlan`~~ — confirmed absent at `7495b5b44`
- ~~every combined two-curve request/result/commit object~~ — replaced by one
  unlock envelope containing exact sibling ECDSA and Ed25519-Yao outcomes in
  `def400d94`
- ~~`EmailOtpEd25519YaoSessionMaterialRequestV1`~~ — confirmed absent at
  `7495b5b44`
- `EmailOtpEd25519YaoExactLocalSessionBootstrapV1`
- `WalletUnlockEmailOtpSessionIntentV1`
- `RouterAbEd25519YaoEmailOtpSessionRequestV1`
- `RouterAbEd25519YaoEmailOtpLocalSessionRequestV1`
- `RouterAbEd25519YaoEmailOtpRecoverySessionRequestV1`
- `activateColdEmailOtpEd25519YaoLocalSessionV1`
- `recoverEd25519YaoEmailOtpWalletSession` (split into session-provisioning and
  recovery ports)
- `email_otp_exact_local_material`, `email_otp_no_ed25519_session`
- `router_ab_ed25519_yao_email_otp_local_session_v1`
- `router_ab_ed25519_yao_email_otp_recovery_session_v1`
- `shared_email_otp_recovery_wallet_session_v1`
- ~~`ecdsa_and_ed25519_yao_local_session`~~ — deleted by `def400d94`
- the implicit omitted-`sessionIntent` branch (explicit requested-capability
  set instead)

## Phase 19 — committed lanes, step-up, and resolvers

- ~~`PasskeyEcdsaCommittedLane` and `EmailOtpEcdsaCommittedLane`~~ — confirmed
  absent at `7495b5b44`; their ready aliases and method-specific builders were
  deleted with the same lane family
- ~~`EmailOtpEcdsaCommittedLaneStateError`~~ — deleted by `4962087ca`
- ~~`EvmFamilyEcdsaAuthMethod` and its committed-lane method dispatch~~ —
  deleted by `1f1d5bb11`; the required authority factor is the discriminant
- ~~the redundant `Ready*EcdsaCommittedLane` aliases and copy-builders~~ —
  deleted by `ed1db6664`
- Passkey source-priority and material-selection types
- the Email OTP ECDSA authority resolver
- method-specific reauth and restore assembly ports
- old signing step-up types/files and the passkey-only restore branch
- `reauth_required/missing_hot_material` as an implicit restore signal

## Phase 19 — Yao capability sources and reconnect hooks

- ~~`NearPasskeyEd25519ReconnectHook`, `NearEmailOtpEd25519ReconnectHook`~~ —
  confirmed absent at `7495b5b44`
- ~~`NearEd25519PasskeyReconnect`, `NearEd25519EmailOtpReconnect`~~ — confirmed
  absent at `7495b5b44`
- ~~`recoverPasskeyEd25519YaoCapabilityForSigning`~~ — confirmed absent at
  `7495b5b44`
- `NearEd25519YaoCapabilitySource`, `nearEd25519YaoCapabilitySource`
- `NearEd25519YaoSigningCapability` (replace with the branded committed shape;
  no broad source aggregate)
- ~~`emailOtpNearEd25519LaneRequiresFreshAuth`~~ — confirmed absent at
  `7495b5b44`
- `RouterAbEd25519YaoClientRootFactorV1`
- `RouterAbEd25519YaoBudgetRefreshAuthorizationV1`
- factor-labelled Yao root/export transport unions

## Phase 19 — sealed-refresh tactical surface

- `EmailOtpEd25519YaoSilentRecoveryResultV1`
- `EmailOtpEd25519YaoSilentRecoveryPorts`
- `EmailOtpEd25519YaoBudgetRecoveryResult`
- ~~`PreparedEmailOtpEd25519YaoRecoveryV1`~~ — confirmed absent at `7495b5b44`
- `PreparedColdEmailOtpEd25519YaoRecoveryV1`
- `recoverEmailOtpEd25519YaoFromSealedSessionV1`
- ~~`recoverEmailOtpEd25519CapabilityForSigningV1`~~ — confirmed absent at
  `7495b5b44`
- `recoverEmailOtpEd25519YaoCapabilitySilentlyForSigning`
- ~~`requestRehydrateEmailOtpEd25519YaoFactor`~~ — confirmed absent at
  `7495b5b44`
- the `rehydrateEmailOtpEd25519YaoFactor` worker operation
- Email-OTP-specific Yao root purpose/scope/handle shapes
- method-specific Browser recovery singleflight maps

## Phase 19 — export coordinator surface

- `PasskeyEd25519YaoLocalMaterialLocatorV1` (checkpoint shape embeds
  `signingGrantId` and refresh scope; replaced by the canonical sealed
  active-Client record)
- `Ed25519YaoExportFlowDeps.recoverPasskeyCapability` and the nested
  `emailOtp.resolveExportContext` callback bag
- ~~`exportEd25519YaoKeyWithFreshPasskey`,
  `exportEd25519YaoKeyWithFreshEmailOtp`~~ — replaced by one exhaustive
  same-method coordinator in `01bcabb29`
- ~~`ExactPasskeyEd25519SigningLaneIdentity`,
  `ExactEmailOtpEd25519SigningLaneIdentity`~~ — deleted by `a5fad3851`; export
  narrows the canonical generic lane by its factor authority.
- ~~`EmailOtpEd25519YaoExportSubjectV1`, `EmailOtpEd25519YaoExportContextV1`,
  `EmailOtpEd25519YaoExportContextPorts`~~ — replaced by the exact lane,
  independent Wallet Session authorization projection, and material-owned
  export context in `f20403de5`.
- `recoverExactPasskeyEd25519YaoCapabilityForExport`
- ~~matching Browser/assembly port aliases~~ — the resolver now accepts the
  exact Email OTP lane directly; the canonical resolver remains in place
  (`f20403de5`).
- ~~the `laneIdentity.auth.kind` dispatch in `exportKeypairOperation.ts`~~ —
  moved inside the exhaustive capability-owned coordinator in `01bcabb29`
- `EmailOtpEd25519YaoActiveCapabilityDescriptorV1` (destructive replace at the
  generic lifecycle/export-context boundary; strip `signingGrantId`, raw
  provider subject, and bearer JWT from the worker payload)
- `signingGrantId` in export subject/context/worker requests (the exact
  `near.export_key` grant lives only in operation authorization/claim state)

## Phase 19 — factor-labelled assembly ports and Browser shortcuts

- ~~`refreshPasskeyEd25519CapabilityForSigning`~~ — confirmed absent at
  `7495b5b44`
- `requestEmailOtpEd25519SigningChallenge`
- `recoverEmailOtpEd25519CapabilityForSigning`
- `resolveAccountAuthMethodForSigning`
- `ensureNearEd25519YaoCapabilityForSigning`
- `resolveActiveNearEd25519YaoSigningLane`
- `hasPasskeyAuthenticatorForNearEd25519Subject`
- `recoverNearEd25519YaoCapabilityForSigning`
- `recoverExactPasskeyEd25519YaoCapabilityForSigning`
- `recoverExactEmailOtpEd25519YaoCapabilitySilentlyForSigning`
- `recoverExactEd25519YaoCapability`
- `hasNearEd25519YaoPublicReference`
- `recoverNearEd25519YaoCapabilityFromSealedSession`
- `recoverNearEd25519YaoCapabilityWithPasskey`
- ~~`readNearEd25519RuntimeRecordForSelectedLane`~~ — deleted by `4f089b483`
- ~~`publishNearEd25519RuntimeIdentityForRecord`~~ — deleted by `4f089b483`
- ~~`resolveNearTransactionPlannerReadiness`~~ — absent after the canonical
  preparation cut, verified by `4f089b483`
- control-flow use of `getWarmThresholdEd25519SessionStatusForSession`
- `resolveThresholdEd25519SessionIdForNearAccount`
- the broad `resolveActiveEd25519YaoSigningCapability` port
- ~~the production-dead `thresholdSigningSessionReadiness.ts` classifier and
  its self-only unit test~~ — deleted by `18850e9d4`
- `withThresholdEd25519CommitQueue`, `ThresholdEd25519CommitQueueByKey`,
  `resolveThresholdEd25519CommitQueueKey`
- the `forceFreshAuth` and `retryingFreshAuth` planner booleans
- all `CreateSigningEnginePortsArgs` aliases/wiring for the ports above
- ~~stale cross-curve companion envelopes, including
  `ecdsa_and_ed25519_yao_recovery`~~ — replaced by capability-specific material
  requests and exact sibling results in `def400d94`; the obsolete combined
  fixture was deleted by `89e9cd4a5`

## Phase 19 — tests and fixtures (migrate valid assertions, then delete)

- ~~`nearRefreshYaoOrdering.guard.unit.test.ts`~~ — deleted by `6d6002e3c`;
  canonical hydration, cancellation, crash, and atomic-finalization behavior is
  covered directly.
- ~~`ed25519YaoSealedRefreshWiring.guard.unit.test.ts`~~ — deleted by
  `6d6002e3c`; it duplicated current recovery behavior through source markers.
- `emailOtpEd25519YaoBudgetRecovery.unit.test.ts` (migrate continuity,
  monotonic-policy, and cleanup assertions; delete grant/budget fixtures and
  the tactical sealed-recovery typecheck fixture)
- `emailOtpEd25519YaoExportRefresh.unit.test.ts` (migrate page-refresh,
  zero-Passkey-callback, durable-context, continuity, and zeroization
  assertions)
- `passkeyEd25519YaoExportRefresh.unit.test.ts` (migrate stale-grant/
  current-grant, current-credential, no-intervening-transaction, and
  authenticator-drift assertions)
- `ed25519YaoExportFlow.typecheck.ts` (replace with authority/adapter
  substitution fixtures that name no factor lane)
- obsolete positive capability-source fixtures in `nearSigning.typecheck.ts`

## Phase 20 — signing budget subsystem

Replacement: exact operation grants plus `MpcWalletSigningQuota` claims.

- `BudgetCoordinator`, `budgetProjection`, `budgetFinalizer`,
  `budgetStatusReader`
- `signingEngine/session/budget/**`
- ~~reusable NEAR transaction client admission, reservation, success/zero-spend
  finalization, and prepared-boundary budget state~~ — removed by `cc4cf26ab`;
  relayer operation claims and quota transactions own consumption
- ~~`DelegatedBudgetReservationStore`~~ — deleted in `20bd2297e`; it had no
  production consumer
- router reserve/commit/release budget methods
- old development `signingGrantId` budget rows (reject and clear at the
  persistence boundary; never fan one remaining-use count into multiple
  balances)
- the transitional blanket readmission path after recovery
- the legacy projection path copying `signingGrantId` or other operation
  authorization across EVM/Tempo targets
- keep only client-side concurrent-operation fingerprinting from the old
  subsystem

## Phase 21 — worker and WASM residue

- generic-named passkey-only WASM sessions (destructive rename to
  `WasmPasskeyClientRegistrationSessionV1` /
  `WasmPasskeyClientRecoverySessionV1`; no aliases)
- combined ECDSA enrollment requests
- ~~`ecdsa_and_ed25519_yao_recovery` unlock worker requests~~ — replaced by
  capability-specific commands inside one shared unlock proof envelope in
  `def400d94`
- replaced worker entrypoints, loaders, asset-manifest rows,
  `UiConfirmManager` factor branches, and adapter wrappers
- ~~`SignerWorkerManager.requestExportPrivateKeysWithUi` forwarding adapter~~
  — recovery now receives export directly from the current export owner
- ~~Passkey raw secp256k1 and Ed25519-Yao export runtime inside
  `passkey-confirm.worker.ts`~~ — moved atomically to the dedicated Passkey MPC
  export worker; generic confirmation no longer imports or dispatches it
- ~~Passkey MPC export transport, viewer lifecycle map, and export worker
  lifecycle inside `UiConfirmManager.ts`~~ — moved to the dedicated
  `PasskeyMpcExportManager`; recovery receives its narrow port directly
- ~~Passkey `WARM_SESSION_*`, PRF claim/cache, sealed-session,
  rehydration/policy, and Shamir3Pass runtime inside
  `passkey-confirm.worker.ts`~~ — moved atomically to the dedicated Passkey MPC
  session worker; generic confirmation now owns prompt interaction only
- ~~Passkey volatile warm-material writes, status reads, claims, consumption,
  clearing, session-worker lifecycle, prewarm, and session-worker request
  routing inside `UiConfirmManager.ts`~~ — moved to the dedicated
  `PasskeyMpcSessionManager`; durable seal persistence and restore followed
  into the same owner in `d9c303f3c`, and policy storage semantics followed in
  `fe07fea5b`
- ~~zero-caller auth-method-neutral
  `UiConfirmManager.deleteDurableSealedSessionRecord` public alias and port~~ —
  deleted; Passkey corruption cleanup remains private to its durable owner and
  Email OTP retains its exact store boundary
- ~~Passkey persisted-session discovery, exact sealed-record listing, and its
  optional host fallback inside generic confirmation~~ — moved to
  `PasskeyMpcSessionManager`; session-public and no-prompt ECDSA reuse call the
  factor owner directly
- ~~raw Passkey session-worker seal and rehydrate forwarding methods on
  `UiConfirmManager` and `DurableSealedSessionPort`~~ — removed; internal
  durable coordination calls the dedicated `PasskeyMpcSessionManager`
  directly
- ~~Passkey persisted restore command, exact-record restore orchestration,
  restore lease, and rehydrate single-flight ownership inside generic
  confirmation~~ — moved to `PasskeyMpcSessionManager`; the browser signing
  surface calls the factor owner directly
- ~~exported `PasskeyMpcSessionDurableWorkerPort` duplicate of the dedicated
  session port's raw seal/rehydrate methods~~ — deleted; generic confirmation
  retains no raw seal/rehydrate or durable-session port
- ~~`ensurePasskeySealedRecordPersisted` and
  `PasskeyWarmSessionPersistenceCoordinator` one-call adapter~~ — deleted; the
  dedicated session owner handles the optional missing-restore-metadata result
  before evaluating persistence failure
- ~~high-level Passkey seal persistence, exact-record registration/readback,
  persistence single-flight, and sealed-session policy coordination inside
  generic confirmation~~ — moved to `PasskeyMpcSessionManager` and its private
  durable-state owner by `d9c303f3c`, with policy storage semantics completed
  by `fe07fea5b` and inactive-material operating consumption completed by
  `fa1f21657`
- ~~ECDSA public-only reauthorization-anchor records produced by expiry and
  exhaustion~~ — replaced by authorization-free inactive sealed-material
  records that retain the encrypted material and exact activation binding in
  `fe07fea5b`
- ~~unused `UiConfirmSigningRuntimePort` and generic combined
  `UiConfirmSigningSessionPort` exports~~ — Near runtime dependencies name the
  required confirmation and warm-material ports directly
- ~~public wallet-host registration-preparation loader and module-type exports~~
  — deleted; the registration-surface preload entrypoint owns the private
  dynamic import
- ~~zero-caller Router A/B ECDSA refresh-client-proof worker operation~~ —
  deleted end to end by `4d0a1d8af`
- ~~unreachable Email OTP `session_bootstrap` worker branch and its JWT-derived
  relayer identity~~ — deleted by `1ee23703b`
- ~~zero-producer Passkey ECDSA warm-seal pending registry, its restore wait,
  and its registry-only unit suite~~ — deleted by `c72cbf31f`
- ~~forwarding-only `routerApiWalletUnlockRouteService` locator and its two
  Cloudflare route callers~~ — deleted by `5f989ea9f`; routes use the
  request-scoped wallet-unlock service directly

## Phase 27 — final sweep

- ~~`SigningAuthPlan` and remaining signer-auth aliases~~ — compatibility
  aliases are absent; `SigningAuthPlan` remains as the canonical exhaustive UI
  confirmation plan for warm-session, Passkey step-up, and Email OTP step-up
- ~~pure `SigningAuthMethod = SignerAuthMethod` alias and its lane-identity
  re-export~~ — consumers use canonical `SignerAuthMethod`
- remaining `signing-session` terminology and old route planes
  (`threshold_session`, `user_session` on migrated surfaces)
- wallet-only `AuthMethod` usages outside capability-local modules
- ~~optional `authMethod` and implicit Passkey defaults on generic
  `registerNearWallet` / `registerEvmWallet` host and iframe paths~~ — deleted
  by `4f51048c5`; Passkey-named convenience APIs remain explicit
- auto-signer registration paths
- public exports implying wallet-only auth/sessions/grants
- ~~one-use iframe aliases for ECDSA bootstrap and exact/missing Wallet Session
  payloads~~ — canonical payload types are used directly in the envelope
- ~~zero-caller Cloudflare route-registration wrapper and its wrapper-only
  unit test, plus the stale public-catalog assertion for the private 94C ECDSA
  bootstrap plane~~ — production routing uses the canonical route-definition
  dispatcher
- ~~standalone `routerAbEcdsaDerivationRefreshPort` HTTP adapter and its
  wrapper-only unit test~~ — deleted by `a89ede462` and `df478bfed`; the
  route-definition dispatcher and canonical threshold-ECDSA handler own the
  refresh path
- source guards and fixtures whose invariant became structural during the
  slices
- ~~architecture guard ranges for deleted `signEvmFamily/postSignFinalization.ts`
  and `threshold/ecdsa/keygen.ts`, plus the type-alias slicer false positive~~
  — retired or corrected in `944b619fe`; the guard now follows the live flow
  tree and stops each exported type slice at the next local declaration
- ~~optional auth-method discovery that silently searched both Passkey and
  Email OTP~~ — exact auth method is required by `e3fe3d32e`
- ~~`RestorePersistedEcdsaSessionPurpose`,
  `WalletSessionReconnectEcdsaBootstrapRouteAuth`,
  `PasskeyFreshEcdsaBootstrapRequest`,
  `EmailOtpEcdsaExactBootstrapRequest`, `EcdsaWalletSessionTransportAuth`, and
  `ReadyThresholdEcdsaSessionPolicy` aliases~~ — consumers use canonical types
  directly after `9c9c7aec6`, `fe9ed96f7`, and `df7c3d0b8`
- ~~the duplicate unused `EcdsaExportOperationAuthorization` projection and its
  projection-only unit test~~ — deleted by `9c9c7aec6`
- ~~zero-caller `privateKeyExportRecovery` coordinator, dependency object, and
  assembly/store wiring~~ — deleted by `d3201483b`; current export flows use
  the dedicated Passkey MPC export owner or Email OTP capability owner
- ~~the Ed25519 updated-at primary-lane fallback and
  `primaryEd25519LaneFromNormalizedCandidates`~~ — deleted by `ae8f7b72d`;
  canonicalized priority order now selects the lane
- ~~duplicate `ecdsaAvailableLaneMaterialKey` selector~~ — zero-caller
  material-key projection deleted by `5cc54814d`
- ~~zero-caller `routeAuthFromEmailOtpRoutePlan` forwarding selector~~ —
  deleted by `6910f4d94`; the canonical auth-lane adapter remains the sole
  projection owner
- ~~zero-caller `exactEcdsaSigningLaneSigner` and
  `exactEd25519SigningLaneSigner` projection selectors~~ — deleted by
  `151110bd8`; consumers narrow the canonical signer binding directly
- ~~local `routePlanSessionAuth` Email OTP worker wrapper~~ — deleted by
  `e90c3f09a`; callers use the canonical auth-lane projection directly
- ~~zero-caller `resolvePasskeyEd25519WalletSessionRouteAuthV1` JWT fallback~~
  — deleted by `563909459`; active authorization remains the canonical source
- ~~zero-caller `emailOtpEcdsaPublicationTargetPlans` duplicate planner~~ —
  deleted by `b6b691bce`; publication uses the canonical chain-target planner
- ~~zero-caller `requireEmailOtpExistingEcdsaPublicCapability` fallback~~ —
  deleted by `d51f1da06`; the canonical existing-key resolver remains live
- ~~zero-caller `exactSealedSessionIdentityFromFilter` converter~~ — deleted by
  `45a4222b2`; the canonical sealed-session filter remains the boundary
- ~~zero-caller `ecdsaCapabilityManifestIdentity` projection~~ — deleted by
  `19ec99d94`; manifest identity builders remain the canonical path
- ~~zero-caller `cacheCredentialBoundarySetupExportPrfFirstBestEffort` silent
  fallback~~ — deleted by `5a619687a`; strict cache setup remains live
- ~~zero-caller `EmailOtpEd25519SigningSessionAuthority` and its builder~~ —
  deleted with the two live README entrypoint references; canonical
  `EmailOtpSigningSessionAuthLane` is the active authority boundary
  (`4f11a1211`)
- ~~zero-caller `ecdsaRoleLocalActiveStateId` and
  `unavailableEcdsaRoleLocalMaterialSource` constructors~~ — deleted by
  `01521c796`; active-state builders and explicit unavailable branches remain
- ~~zero-caller `resolveActiveEcdsaCapabilityRuntimeForSealedRecord` wrapper~~ —
  deleted by `3f251b7cb`; active resolution uses canonical wallet/target or
  chain-kind selectors
- ~~zero-caller `exactSealedSessionIdentityFromRecoveryRecord` converter~~ —
  deleted by `750138097`; recovery commands use the canonical exact identity
  boundary directly
- ~~zero-caller `ThresholdSessionSealTransportAuthMaterial` and
  `WalletSessionJwtAuthSource` record aliases~~ — deleted by `6dc24c395`; live
  sealed-recovery transports own their protocol-specific shapes
- ~~zero-caller threshold status/error constants, formatters, and
  `normalizeUsesNeeded` in `warmCapabilities/statusReader.ts`~~ — deleted by
  `308910932` and `111345f7c`; the read model owns the live status mapping
- ~~zero-caller `hasSufficientWarmClaim`,
  `formatMissingWarmPrfMaterialError`, and
  `formatWarmSessionClaimUnavailableError` helpers~~ — deleted by
  `9427bc746`; live claim/status conversion remains in `readModel.ts`
- ~~stale registration/key-brand source-guard blocks for deleted persistence,
  lifecycle, and Shamir-seal paths~~ — retired by `703fa1d95`; remaining guard
  checks target live registration, branding, and WebAuthn boundaries
- ~~obsolete signing-session seal default-key source guard~~ — retired by
  `2744c6c02`; active seal configuration is checked through the current
  root/current/accepted-version boundary
- ~~stale EVM key-slot branding guard paths~~ — rewritten by `fc048026f` to
  cover the live provisioning, worker, Router validation, and
  registration/recovery boundaries
- ~~zero-caller `buildReauthAnchorIdentityFromEcdsaLaneCandidate` fallback and
  its candidate-only freshness helpers~~ — deleted by `24e0c2335`; live
  reauth uses the canonical operation-state builder
- ~~zero-caller `buildReauthAnchorIdentityFromAvailableLane` fallback and its
  lane-selection/version/source helpers~~ — deleted by `acb368888`; live
  reauth uses canonical operation-state freshness and lane admission
- ~~zero-caller `BaseEcdsaWalletId`, bootstrap route-auth/session-id helpers,
  and sealed-record auth-lane wrapper~~ — deleted by `6207cea1f`
- ~~exact aliases for ECDSA signing authorization, activation request/result,
  bootstrap args, and sealed resolved identity~~ — consumers use their
  canonical types directly after `dfee38d07`
- ~~optional `EcdsaSessionSuccess`, its unpopulated `sessionId`, bootstrap
  budget-projection alias, and `ecdsaOnlySigningSessionStatus` reconstruction~~
  — deleted by `04221828c`; the exact bootstrap session requires its runtime
  policy, Wallet Session bearer, and client verifying share
- ~~the duplicate bootstrap `keygen` result branch and its hand-written fixture
  copies~~ — deleted by `118f5c882` and `7d1e31bbd`; the exact key reference is
  the sole bootstrap material-facts owner
- ~~duplicate persisted Ed25519 capability fallback service locator~~ — deleted
  by `729ad4cdd`; the request-scoped product runtime owns persisted load,
  correlation, installation, and reread
- ~~forwarding-only Ed25519 recovery runtime locator and wrapper interface~~ —
  deleted by `868ba6dee`; the recovery service directly implements the narrow
  installation and lookup ports
- ~~zero-caller ECDSA activation-journal id projection~~ — deleted by
  `c51134bba`; journal owners read the required journal id directly
- ~~zero-caller budget owner, availability, and unknown-status adapters~~ —
  deleted by `20f1bcfca`, `1ce066cf9`, and `69b0e6b30`; live admission and
  status readers retain their direct budget paths
- ~~zero-caller network-only ECDSA chain-target adapter~~ — deleted by
  `4250a8871`; configured-request and chain-family boundary builders remain
- ~~zero-caller dual-PRF registration credential helper and allow-list adapter~~
  — deleted by `93958f9a6`; the canonical credential collector remains the sole
  registration boundary
- ~~zero-caller `clearRouterAbEcdsaDerivationClientPresignaturesForLane`~~ —
  deleted by `814616909`; the live global pool clear and worker retirement
  paths remain

## 6e gate — composite ECDSA record family (measured 2026-07-28, at `3b904b63a`)

Production scope is `packages/**` + `apps/**`, excluding `node_modules` and
`dist`. Match term is `ThresholdEcdsaSessionRecord`.

| Measurement | Before read-model cutover | At `3b904b63a` |
| --- | --- | --- |
| Production files | 57 | **54** |
| Total references | 415 | **398** |

Gate verdict: **deletion does not open.** The 6e condition is that every
remaining consumer is obsolete or replaceable within the deletion slice. It is
not met.

The store itself is inert. `storeThresholdEcdsaSessionFact` is reached only
from `commitCurrentThresholdEcdsaSession` and the two `upsert*` entry points,
and outside `records.ts` those have no production callers — only
`records.typecheck.ts` and unit tests. Both backing maps (`recordsByLane` from
`createSigningRuntime`, and the module-level `inMemoryEcdsaRecordsByLane`) are
therefore never populated in production. Every remaining reader observes an
empty store.

That makes the remaining work a signature exercise rather than a
behaviour-preservation one — there is no live data flowing through these
readers to regress — but it does not make the consumers deletable, because the
type is still threaded through surfaces that must keep compiling:

- SDK public API: `SeamsWeb/publicApi/types.ts`, `SeamsWeb/signingSurface/ports.ts`
  (including `getThresholdEcdsaSessionRecordByThresholdSessionId`, the bare
  `thresholdSessionId → record` API this refactor forbids)
- assembly/runtime ports: `assembly/ports/{warmSigning,stepUpRuntime,shared}.ts`,
  `core/runtime/runtime.types.ts`, `core/platform/index.ts`
- operating paths that are themselves the subject of the canonical-entry-point
  work: `flows/signEvmFamily/{signEvmFamily,ecdsaSelection,ecdsaLanes,ecdsaMaterialState}.ts`,
  `flows/recovery/{ecdsaExportMaterial,ecdsaDerivationExport}.ts`,
  `session/emailOtp/{ecdsaLogin,ecdsaEnrollment,ecdsaPublication,ecdsaRecovery}.ts`,
  `uiConfirm/UiConfirmManager.ts`

Deleting the type ahead of those cutovers breaks all 54 files at once with no
intermediate green state. The entry-point cutover must land first; the
reference count then collapses and the deletion becomes mechanical with zero
production references reachable.

### 6e completion

The canonical entry-point cutovers removed the final live consumers. The
production composite family, its public APIs, stores, parsers, readers,
writers, reconnect paths, and identity adapters are now deleted. A direct scan
of `packages/sdk-web/src` returns zero matches for
`ThresholdEcdsaSessionRecord*` and `ThresholdEcdsaStoredCapabilityRecord`;
SDK-web type-checks cleanly. Composite-record builders, stores, imports, and
mocks are also removed from the test tree; retained Email OTP coordinator
coverage now enters through canonical manifest, authorization, and sealed-runtime
fixtures.

### Prerequisite discovered while opening 4a: the unit suite collects nothing

`playwright test -c playwright.unit.config.ts --list` reports **0 tests in 0
files**. Ten stale imports of exports deleted by earlier Refactor-90 slices
abort collection suite-wide, and one bad import takes the whole suite with it:

| Missing export | Owning test files |
| --- | --- |
| `resolveEvmFamilyEcdsaRestoreMaterialLane` | `evmFamilyPreparedSigningAuthSelection` |
| `resolveReadySecp256k1SigningMaterialFromRecord` | `evmFamilyEcdsaIdentity`, `readySecp256k1Material.rehydration` |
| `listThresholdEcdsaRuntimeLanesForWallet` | `evmFamilyEcdsaIdentity`, `ecdsaExportEphemeralIsolation`, `walletRegistrationEcdsaRouterAbBootstrap` |
| `getThresholdEcdsaKeyRefByKey` | `evmFamilyEcdsaIdentity` |
| `consumeSingleUseEmailOtpEcdsaLane` | `signingPostSignPolicy`, `thresholdEcdsaEmailOtpConsumption` |
| `clearThresholdEcdsaSessionRecordForExactIdentity` | `refactor92.invalidationIdempotency`, `signingSessionReadiness.clearGrant` |
| `commitEmailOtpEcdsaLaneFromRecordForMaterial` | `emailOtpWalletSessionCoordinator` |
| `isSigningSessionAuthUnavailableError` | `thresholdSigningSessionReadiness` |
| `ROUTER_AB_ECDSA_DERIVATION_EXPORT_SHARE_PATH` | `router.routeDefinitions` |
| `buildRouterAbEcdsaDerivationEvmDigestSigningBudgetedFinalizeRequestV1` | `thresholdSessionClaims`, `routerAbEcdsaDerivationBudgetRouteCore`, `routerAbEcdsaDerivationNormalSigning` |

This predates the read-model cutover: none of these exports were removed by
`3b904b63a`, whose only `records.ts` change was moving a private classifier to
a shared import. Named-file runs still work, which is why the earlier focused
runs were green and this stayed hidden.

Consequence for the 4a–4e sequence: the per-vertical acceptance bar ("run one
focused operating-path test") cannot be met for the signing core until the
suite collects again. Both candidate tests for 4a
(`ecdsaSelection.restorable`, `evmFamilyPreparedSigningAuthSelection`) are
themselves among the stale files. Restoring collection is therefore a
prerequisite slice, not a cleanup that can trail the cutover.

Also note for 4a scope: `buildEcdsaMaterialStateForCandidate` already returns
`public_identity_unavailable` unconditionally, and nothing constructs
`ready_to_sign`, `public_identity_available`, or `reauth_required` for
`EcdsaMaterialState`. The EVM-family ECDSA signing path is currently
fail-closed, so 4a is a rebuild of that path on manifest + sealed runtime, not
a signature-only move.

Resolution: the shared sealed-session fixture now supplies a canonical
Ed25519 Email OTP material activation and a valid `project:environment` signing
root. The collection guard reports **1,975 tests in 349 files** again, and the
stale-record test that exposed the fixture defect passes (`e5cb737c8`).
