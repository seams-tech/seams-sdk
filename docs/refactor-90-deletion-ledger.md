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
- Unit 3c: the final `SigningGrantId` identity, Ed25519 Router budget flow, and
  cross-curve authorization/quota convergence;
- Unit 3d: synthetic capability-grant and grant-evidence identity on reusable
  Wallet Session operations, plus the divergent Ed25519/ECDSA claim adapters;
- Unit 4: Phases 22–23 and UI-owned final deletions.

Historical Phase 6 inventory is absorbed by every unit. Unit 3b adds and closes
any concrete vault target discovered by its Satyr Phase 6 inventory.

## Post-completion cleanup reconciliation — 2026-08-05

A direct production-source scan across `packages/*/src`, `apps/*/src`,
`crates/*/src`, and `wasm/*/src` finds no occurrence of the retired composite
ECDSA record family, `SigningGrantId` family, capability-grant-use model,
operation-claim model, or `active_state_session_id`.

The old public ECDSA budget identifiers and their dedicated rejection fixtures
are absent from current source and tests. Strict exact-key parsing remains the
general unknown-field boundary. Likewise, `lifecycle_mismatch` remains only in
tests and comments describing the rejected predecessor to the typed
`superseded` state.

The Rust helpers reported as dead code by a default-feature local server build
are consumed by the `workers-rs` production configuration and focused tests.
They are retained as live feature-gated code. The established `touchConfirm`
name denotes the UI-confirmation runtime throughout the current SDK and is not
the deleted MPC worker alias.

The broad unit result is historical diagnostic evidence rather than an open
Refactor 90 deletion gate. The healthy intended-behaviour suite passes 10/10,
the focused invariant owners are green, and no further Refactor 90 production
deletion is currently justified by a live caller or observed defect.

## Final bounded sweep — 2026-08-02

### Current wire checkpoint — `9196afd69`, `7512bf6a6`

The strict Rust/TypeScript ECDSA `authorization_claim` boundary now rejects
the retired public budget fields and binds reusable claims to the verified
Wallet Session plus canonical capability grant. Rust binding tests pass 31/31,
the shared TypeScript check passes, and the Email OTP warm worker names its
volatile map key `thresholdSessionId`. The final local-Yao public-signing
caller of the retired Router reserve/commit/release adapter was removed with
the obsolete route section in `a37dbb65b`; registration, retry, and disposal
coverage remains.

The final Unit 1/3a/4 sweep found one identity bug and one dead type surface.
Passkey ECDSA seal persistence now receives the actual `thresholdSessionId`
from bootstrap while retaining a material-activation-keyed single-flight map;
it no longer substitutes the activation ID for threshold runtime identity. The
focused regression test proves the two identifiers stay distinct
(`57849eda9`). The zero-caller `WarmSessionProvisioner` and its
`EnsureWarmEcdsaCapabilityReadyResult` carrier were deleted in the same
checkpoint. No additional safe production deletions were found.

Unit 3c has replaced the Ed25519 `signingGrantId` quota boundary with the
canonical Wallet Session/quota and capability-operation-claim flow. The public
NEAR route claims the operation atomically at Gateway D1 before forwarding to
the MPC router (`b166b0bf1`); replay, expiry, exhaustion, and claim-binding
coverage pass in the focused authorization suite. The Rust Router
reserve/validate/commit/release protocol, TypeScript runtime/store surface,
and obsolete fixtures are deleted (`cb7bc901c`, `882dfd681`, `4885bed62`).
The Email OTP NEAR challenge remains a live operation-owned interface;
generated passkey-only WASM class names require a coordinated binding rebuild
and are not safe source-only deletions. Historical `missing_hot_material` and
removed ECDSA budget fixture references in older refactor documents are
documentation history, not production symbols.

The broad unit gate was rerun after the build and WASM outputs were regenerated:
1,740 passed, 197 failed, and 11 skipped out of 1,948 collected tests. The
failures are lower-authority stale fixtures and environment-gated local D1/JWK,
Google-identity, and UI timing cases; the focused identity regression passed.
The broad acceptance box remains open until those failures are reconciled or
their owning environment is supplied.

The final focused closeout selection passes **97/97** with the local frontend
explicitly selected at `http://localhost:5180`. An earlier 92/97 attempt had
all five `sealedRefresh.parity` cases fail during harness setup with
`ECONNREFUSED`; the corrected rerun reached and passed every assertion.

The current post-fixture broad run collected the full 1,901-test unit surface:
1,745 passed, 147 failed, and 9 skipped. This supersedes the earlier
1,740/197/11 measurement for closeout tracking. The failures remain lower-tier
expectation and local-environment cases; the Refactor 90 focused matrices and
the complete `pnpm check` pass independently. Keep the broad gate open until
the failure classes are reconciled and the supported lifecycle subset is rerun
with the required local ceremony and identity configuration.

The follow-up focused operating-path run passes 72/72. The Rust Cloudflare
ECDSA binding subset passes 36/36, the ECDSA wire crate passes 1/1, the ECDSA
client protocol passes 9/9, the presign crate passes 44/44 plus 7/7 doctests,
and normal-signing vectors pass 3/3. The router-ab-core generated TypeScript
binding check passes 1/1, and the signer-core generated schema check passes
1/1. Intended-test typechecking passes after
the declaration build; the Google OIDC token prerequisite is absent, so the
intended browser run remains environment-gated.

The final `pnpm test:intended` attempt on 2026-08-02 completed declaration
generation and intended-test typechecking, then stopped at
`ensure:intended-google-token` because `SEAMS_INTENDED_GOOGLE_ID_TOKEN` is not
configured. No browser assertions were run.

The remaining generic-looking identifiers were audited before closeout. The
`sessionId` fields that remain in ECDSA code are not threshold-session aliases:
Rust registration/post-registration lifecycle records retain their ceremony
`session_id`, Email OTP client-root handles use a one-shot local handle id,
presign workers use an in-flight presign-session id, and UI/request surfaces
use request or viewer ids. Threshold-session identity is carried as
`thresholdSessionId`/`threshold_session_id` at the ECDSA activation, warm,
sealed-runtime, and authorization-sensitive signing boundaries. No old
`sessionId` compatibility parser remains there.
The ECDSA worker-share and presign handoff now use `thresholdSessionId`; the
one-shot Email OTP client-root handle retains its own local `sessionId`
(`fae146131`).
Volatile warm-material clear commands now use branded `ThresholdSessionId` in
their worker scope; the retired generic `sessionId` field and local volatile-ID
alias were deleted (`0c341f40a`).
The inert ECDSA Router A/B admission-policy `signingGrantId` input and its
ECDSA quota-key branches were deleted (`5cf433765`). The current Ed25519 and
ECDSA reusable-session routes both use the Gateway atomic claim/quota path;
neither curve retains a Router reserve/commit/release caller.
The Email OTP Ed25519 challenge request and the Passkey/Email OTP owner-local
single-flight maps remain live factor-owned operating paths, not generic
compatibility aliases.

### Unit 3d initial deletion inventory — 2026-08-02

Unit 3c removed the signing-specific grant identity and duplicate Router quota
owner. A follow-up review found that the generic authorization core still
forces capability-grant fields onto direct reusable Wallet Session operations.
Ed25519 fabricates those fields without a grant record, while ECDSA persists
temporary evidence and grant records for the same authority branch. Unit 3d
deletes that remaining model overlap.

- `CapabilityOperationClaimBase.grantId` and `.evidenceSetDigest` as required
  reusable-claim fields; replace the common base with exact reusable and
  operation-step-up branches
- `CapabilityGrantUseId`, `ClaimedCapabilityGrantUse`,
  `CompletedCapabilityGrantUse`, and grant-bearing completion references on
  reusable operations; introduce direct reusable operation-use identity and
  branch-specific results
- `ReusableWalletSessionClaimInput.grantId`,
  `claimReusableWalletSessionFromGrant`, and the synthetic
  `reusable-wallet-session-operation` evidence digest
- the fabricated Ed25519 `ed25519-operation-grant:*` identifier and its
  fixtures, receipts, diagnostics, and public-documentation projections
- reusable ECDSA `GrantEvidenceId`, `GrantEvidenceSetId`,
  `CapabilityBindingId`, `CapabilityGrantId`, `VerifiedGrantEvidenceSet`, and
  `ActiveCapabilityGrant` construction/persistence; retain these concepts for
  real operation step-up and the independent vault vertical
- `grant_id` and `evidence_set_digest` columns and parsers in reusable Wallet
  Session operation-use and audit rows; remove them through a forward D1
  migration without rewriting historical migrations
- duplicated reusable ECDSA claim/grant SQL and service ports after both curves
  use the direct reusable-session claim transaction
- current fixtures and public docs that describe
  `CapabilityGrantId + CapabilityGrantUseId` as reusable Wallet Session
  operation authority
- the raw cold-recovery `wallet_binding_mismatch` exception; route it through
  the existing typed recovery result boundary
- hard-coded D1 migration table counts, the stale runtime-readiness expectation,
  and missing local ceremony-JWT JWK setup that obscure broad authorization
  regressions

Unit 3d adds no compatibility types, source-text guards, quota reservation
layer, or duplicate E2E suite. Close each row with its replacing implementation
and focused behavioral evidence.

### Unit 3d completion — 2026-08-03

The destructive cutover replaces the initial inventory above with one
`AuthorizedOperation` store and port. Reusable Wallet Session operations carry
an `AuthorizationGrantRef` plus exact Wallet Session/quota identities; verified
step-up operations carry their evidence digest directly. Both branches use one
atomic fingerprint, quota, audit, replay, and completion transaction.

- deleted the reusable capability-grant/use tables, service methods, domain
  records, synthetic evidence construction, curve-specific operation-use IDs,
  fixtures, and wire fields;
- renamed the active API to `AuthorizedOperationPort`,
  `RouterApiAuthorizedOperationService`, and `admitAuthorizedOperation`;
- changed the strict Ed25519/ECDSA Router wire to `authorized_operation` and
  reject the retired nested `claim` field;
- separated authorization, Wallet Session, quota, authorized-operation,
  threshold-session, and material-activation identities at TypeScript, D1, and
  Rust boundaries;
- deleted the orphan Email OTP ECDSA registration-bootstrap worker operation,
  registration-handle branches, registration-bootstrap JWT/session fields, and
  their stale fixtures;
- made signing finalize revalidate the current operation source before an MPC
  effect; ECDSA also revalidates the exact material activation in the same
  admission path.

Focused D1 authorization/session tests, both SDK typechecks, unit typechecks,
Rust bindings/strict-route tests, the Email OTP coordinator, add-wallet
orchestration, vault vertical, and the retired-handle boundary test pass. The
healthy-environment intended-behavior and deployment gates remain outside this
deletion slice.

### Unit 3c pre-cutover live-occurrence inventory — 2026-08-02 (historical)

The first Unit 3c inventory found **118 production files / 1,245 references**
to `SigningGrantId`, `signingGrantId`, or `signing_grant_id` after excluding
type-fixture files and generated `dist` output. The references are grouped by
the boundary that must move them:

| Boundary | Representative owners | Replacement / disposition |
| --- | --- | --- |
| Wallet Session auth and JWT verification | `verifiedWalletSessionAuth.ts`, `validation.ts`, `routerAbSigningWalletSession.ts`, Rust `router/mod.rs` | `WalletSessionId` + `MpcWalletSigningQuotaId`, with claim verification at the authorization boundary |
| Ed25519 normal signing | `routerAbPrivateSigningWorker.ts`, `thresholdEd25519RequestValidation.ts`, `RouterAbNormalSigningRuntime.ts`, Rust `signing_worker/*` | Move reusable quota consumption to the shared atomic claim transaction; then delete Router reserve/commit/release and its rows |
| ECDSA registration and activation wire | `routerAbEcdsaDerivation.ts`, `thresholdEcdsa.ts`, `ecdsaSessionProvision.ts`, `bootstrapSession.ts` | Remove `signing_grant_id` atomically from Rust, TypeScript, generated bindings, and fixtures; retain `thresholdSessionId` and Wallet Session/quota identities separately |
| ECDSA/Ed25519 client lanes and lifecycle | `operationState/*`, `availability/*`, `SigningSessionCoordinator.ts`, `threshold/ecdsa/*`, `threshold/ed25519/*` | Use reusable Wallet Session authorization or `CapabilityGrantId`/`CapabilityGrantUseId`; never use a grant identifier as material identity |
| Persistence and worker boundaries | `sealedSessionStore.ts`, `schemaNames.ts`, `passkey-mpc-session.worker.ts`, Rust private D1 | Reject current-schema grant fields at the boundary; retain only immutable historical migration names where required |
| Registration, recovery, export, and status projections | `routerAbEd25519Yao*`, `d1WalletRegistrationService.ts`, `login.ts`, Email OTP flows | Replace live authorization projections together; delete legacy projections after their canonical consumer lands |

The ECDSA post-registration activation response was not an isolated deletion:
`thresholdEcdsa.ts` copied its grant into the Wallet Session JWT, while
`sessions.ts`, `ecdsaLogin.ts`, `bootstrapSession.ts`, and Email OTP
provisioning consumed the parsed field. The coordinated Rust/TypeScript
claim-verifier and JWT/schema cutover landed in `41ed8f9cb` and `9196afd69`.

The internal verified ECDSA authorization carrier and strict JWT/Rust wire
claims no longer expose the legacy grant identity. The targeted `verified
Wallet Session auth preserves authorization and threshold identities
separately` check passed 1/1; the current claims suite passes 29/29.

Inventory command (rerun before each Unit 3c deletion slice):

```sh
rg -l 'SigningGrantId|signingGrantId|signing_grant_id' \
  packages/wallet-server/src packages/wallet/src packages/shared-ts/src \
  packages/console-server-ts/src crates/router-ab-cloudflare/src wasm apps \
  --glob '!**/dist/**' --glob '!**/*.typecheck.ts'
```

### Unit 3c wire-boundary verification checkpoint — `41ed8f9cb`, `9196afd69`

The latest local `dev` tip is an ancestor of the Refactor-90 branch; the merge
is complete with no unresolved conflicts. The ECDSA wire uses the coordinated
breaking shape: `authorization_claim` is required, public budget fields and
legacy `sessionId` aliases are rejected, and reusable claims bind to the
verified Wallet Session plus canonical capability grant. Threshold-session,
Wallet Session, quota, and material-activation identities remain separate.

The existing canonical claim boundary was rechecked at this checkpoint:

- Rust `router-ab-cloudflare` ECDSA hostile-substitution test: **1/1 passed**.
- Rust ECDSA finalize parser rejects missing `authorization_claim`, legacy
  `sessionId`, and public budget fields: **1/1 passed**.
- TypeScript Router A/B normal-signing claim validation suite: **5/5 passed**.
- Shared TypeScript, SDK-server, and unit type checks remain green at the
  merge checkpoint; `git diff --check` is clean.

These checks verify the current claim boundary. Lifecycle, broad-gate, and
final conformance acceptance remain open.

### Unit 3c Ed25519 atomic-claim checkpoint — 2026-08-02

The Cloudflare Ed25519 public normal-signing route already owns the canonical
reusable-session flow: it claims a `CapabilityGrantUseId` atomically with the
Wallet Session quota, sends the accepted claim to the MPC router, and validates
the same claim before finalize. The direct
`handleRouterAbEd25519NormalSigningRouteCore` helper implemented the old
Router reserve/validate/commit/release protocol and had no production caller;
it and the obsolete local-Yao public-signing section were deleted in
`a37dbb65b`. The local-Yao registration, retry, and disposal coverage remains.
The live public route now supplies the Wallet Session/quota identities directly
to the Gateway claim transaction (`b166b0bf1`).
The standalone `routerAbEd25519BudgetRouteCore.unit.test.ts` was obsolete
coverage for that retired reservation protocol and was deleted in the same
checkpoint.
The canonical D1 authorization core remains covered independently: its
reusable-session, replay, expiry, quota, ECDSA binding, and hostile-substitution
cases pass 19/19 in the focused unit run.

The obsolete Router budget-only TypeScript coverage was deleted in
`5dbabdfc8`: the retired Yao reservation/provisioning suite, private budget
provisioner suite, and Wallet Session reservation-store suite had no remaining
canonical caller. Registration/retry/disposal coverage remains in the local-Yao
tests. The shared `SigningGrantId` brand/parser and sealed-record exclusion
fields were deleted in `53ab721df`; the remaining TypeScript Router budget
runtime/store surface was deleted in `882dfd681` and `4885bed62`.

Checkpoints `882dfd681`, `4885bed62`, `32be59fb1`, `fa5791630`, and
`f4c8c7423` close the Unit 3c deletion slice: the remaining
TypeScript Router budget persistence/parser surface, callerless local signing
seed runtime and factory wiring, obsolete wallet-budget status/parser tests,
grant-named admission/cache identities in the SDK and console admission
fixture, and the local smoke wire's legacy budget-field injection. SDK-server,
SDK-web,
console-server, and shared TypeScript typechecks pass. Focused admission,
claims, identity, recovery, export, hostile-substitution, and lifecycle
coverage is green. The Unit 3c implementation and focused conformance gate are
closed.

### Unit 3c current-source closeout — `4885bed62`, `fa5791630`, `f4c8c7423`

An exact source sweep over `packages`, `apps`, and `crates` finds no current
`SigningGrantId`, `signingGrantId`, or `signing_grant_id` occurrence outside
the immutable historical migration. Current tests and generated source are
clean as well. Historical refactor documents retain their original names as
archival evidence; current Refactor 90 documents describe the canonical
Wallet Session/quota and capability-grant identities.

`f4c8c7423` removes the last active local-smoke compatibility behavior: the
Router A/B ECDSA prepare response is parsed in its strict current shape, and
finalize/replay requests carry no retired public budget metadata. The
post-completion cleanup removes the dedicated negative fixtures as well;
generic exact-key parsing continues to reject unknown fields.

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
- ~~passkey ECDSA seal persistence substituting `materialActivationId` for the
  persisted `thresholdSessionId`~~ — the real threshold-session identity is
  threaded from bootstrap while in-flight coalescing remains keyed by material
  activation and chain target (`57849eda9`)
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
- ~~`EmailOtpEd25519YaoExactLocalSessionBootstrapV1`~~
- ~~`WalletUnlockEmailOtpSessionIntentV1`~~
- ~~`RouterAbEd25519YaoEmailOtpSessionRequestV1`~~
- ~~`RouterAbEd25519YaoEmailOtpLocalSessionRequestV1`~~
- ~~`RouterAbEd25519YaoEmailOtpRecoverySessionRequestV1`~~
- ~~`activateColdEmailOtpEd25519YaoLocalSessionV1`~~
- ~~`recoverEd25519YaoEmailOtpWalletSession`~~
- ~~`email_otp_exact_local_material`, `email_otp_no_ed25519_session`~~
- ~~`router_ab_ed25519_yao_email_otp_local_session_v1`~~
- ~~`router_ab_ed25519_yao_email_otp_recovery_session_v1`~~
- ~~`shared_email_otp_recovery_wallet_session_v1`~~ — all tactical symbols in
  this group are absent from production and retained tests at the final Unit 3a
  symbol audit (`rg`, 2026-08-02).
- ~~`ecdsa_and_ed25519_yao_local_session`~~ — deleted by `def400d94`
- ~~the implicit omitted-`sessionIntent` branch~~ — no production or retained
  test occurrence remains; capability requests are explicit.
- ~~dead generic `recordAndVerifyRestoredWarmSessions` readback helper~~ — no
  production or retained-test caller remained; the live
  `RestoredWarmSessionStatus` type moved to `sealedRecovery.types.ts`
  (`f8a56cc0f`).

## Phase 19 — committed lanes, step-up, and resolvers

- ~~`PasskeyEcdsaCommittedLane` and `EmailOtpEcdsaCommittedLane`~~ — confirmed
  absent at `7495b5b44`; their ready aliases and method-specific builders were
  deleted with the same lane family
- ~~`EmailOtpEcdsaCommittedLaneStateError`~~ — deleted by `4962087ca`
- ~~`EvmFamilyEcdsaAuthMethod` and its committed-lane method dispatch~~ —
  deleted by `1f1d5bb11`; the required authority factor is the discriminant
- ~~the redundant `Ready*EcdsaCommittedLane` aliases and copy-builders~~ —
  deleted by `ed1db6664`
- ~~Passkey source-priority and material-selection types~~ — retained as the
  canonical availability sort and factor-aware material-selection union; the
  record-era source branches are gone.
- ~~the Email OTP ECDSA authority resolver~~ — retained as the canonical
  sealed-runtime/manifest resolver used by refresh, signing, and export.
- ~~method-specific reauth and restore assembly ports~~ — retained where they
  are factor-owned operation boundaries; generic forwarding aliases are gone.
- ~~old signing step-up types/files and the passkey-only restore branch~~ —
  replaced by the shared ECDSA operation-step-up union and exact factor-owned
  restore paths.
- ~~`missing_hot_material` as an implicit restore signal~~ — no production or
  retained-test occurrence remains; `reauth_required` remains an explicit
  current sealed-recovery outcome.

## Phase 19 — Yao capability sources and reconnect hooks

- ~~`NearPasskeyEd25519ReconnectHook`, `NearEmailOtpEd25519ReconnectHook`~~ —
  confirmed absent at `7495b5b44`
- ~~`NearEd25519PasskeyReconnect`, `NearEd25519EmailOtpReconnect`~~ — confirmed
  absent at `7495b5b44`
- ~~`recoverPasskeyEd25519YaoCapabilityForSigning`~~ — confirmed absent at
  `7495b5b44`
- ~~`NearEd25519YaoCapabilitySource`, `nearEd25519YaoCapabilitySource`~~ — no
  production or retained-test occurrence remains.
- ~~`NearEd25519YaoSigningCapability`~~ — deleted in `a5d2d9ecc`; the volatile
  registry owns auth-neutral `NearEd25519YaoOperationMaterial`, while current
  Wallet Session authorization resolves independently at execution.
- ~~`emailOtpNearEd25519LaneRequiresFreshAuth`~~ — confirmed absent at
  `7495b5b44`
- ~~`RouterAbEd25519YaoClientRootFactorV1` deletion~~ — retained as the exact
  WASM protocol dispatch boundary for Passkey PRF-first and Email OTP factor
  sessions; it is not generic lifecycle state.
- ~~`RouterAbEd25519YaoBudgetRefreshAuthorizationV1`~~ — retained as the
  canonical Ed25519 Yao refresh authorization boundary; it is not a generic
  wallet-session alias.
- ~~`EmailOtpMixedWalletSigningBudgetV1` worker type~~ — deleted as a
  misleading cross-curve wire-shaped alias; the Email OTP login path keeps its
  narrow local session-policy value, while Ed25519 budget claims remain at the
  authenticated Router boundary (`f989273d4`).
- ~~factor-labelled Yao root/export transport unions deletion~~ — retained only
  at the Yao protocol boundary where the factors select different acquisition
  sessions.

## Phase 19 — sealed-refresh tactical surface

- ~~`EmailOtpEd25519YaoSilentRecoveryResultV1` and
  `EmailOtpEd25519YaoSilentRecoveryPorts` deletion~~ — retained as the current
  factor-specific sealed-recovery boundary; neither carries grant or budget
  material.
- ~~`EmailOtpEd25519YaoBudgetRecoveryResult`~~ — renamed to the
  capability-owned recovery result in `82b439fc5`; no budget/session authority
  remains in that carrier
- ~~`PreparedEmailOtpEd25519YaoRecoveryV1`~~ — confirmed absent at `7495b5b44`
- ~~`PreparedColdEmailOtpEd25519YaoRecoveryV1` broad capability state~~ — the
  prepared value now retains only exact prior active-client metadata rather
  than the combined signing capability (`e179600cf`).
- ~~`recoverEmailOtpEd25519YaoFromSealedSessionV1` deletion~~ — retained as the
  canonical Email OTP sealed-recovery entry point.
- ~~`recoverEmailOtpEd25519CapabilityForSigningV1`~~ — confirmed absent at
  `7495b5b44`
- ~~`recoverEmailOtpEd25519YaoCapabilitySilentlyForSigning`~~ — absent from
  production and retained tests.
- ~~`requestRehydrateEmailOtpEd25519YaoFactor`~~ — confirmed absent at
  `7495b5b44`
- ~~the `rehydrateEmailOtpEd25519YaoFactor` worker operation~~ — absent from
  production and retained tests.
- ~~Email-OTP-specific Yao root purpose/scope/handle deletion~~ — retained only
  at the factor-specific Yao acquisition boundary.
- ~~method-specific Browser recovery singleflight maps~~ — retained inside
  Passkey and Email OTP owners because each map coalesces that factor's exact
  sealed-material operation; no generic compatibility map remains.

## Phase 19 — export coordinator surface

- ~~`PasskeyEd25519YaoLocalMaterialLocatorV1` checkpoint shape~~ — the current
  exact IndexedDB locator carries no signing grant or refresh scope; its stale
  ledger description no longer applies.
- ~~`Ed25519YaoExportFlowDeps.recoverPasskeyCapability`~~ — deleted in
  `a5d2d9ecc`; the canonical Passkey durable-context resolver owns recovery and
  exact readback.
- ~~the nested `emailOtp.resolveExportContext` callback bag~~ — retained as the
  factor-specific Ed25519 export boundary; no ECDSA record or budget state
  crosses it.
- ~~the unused `signingGrantId` read in Email OTP Ed25519 sealed publication~~
  — the refresh transport is authenticated by the Wallet Session bearer and
  exact material activation; the dead local was removed (`afd2ba04c`).
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
- ~~`recoverExactPasskeyEd25519YaoCapabilityForExport`~~ — deleted with its
  flow/assembly port in `a5d2d9ecc`.
- ~~matching Browser/assembly port aliases~~ — the resolver now accepts the
  exact Email OTP lane directly; the canonical resolver remains in place
  (`f20403de5`).
- ~~the `laneIdentity.auth.kind` dispatch in `exportKeypairOperation.ts`~~ —
  moved inside the exhaustive capability-owned coordinator in `01bcabb29`
- ~~`EmailOtpEd25519YaoActiveCapabilityDescriptorV1` legacy payload~~ — the
  current worker descriptor contains activation, public facts, and lifecycle
  only; signing grant, provider JWT, and bearer state are absent.
- ~~`signingGrantId` in export subject/context/worker requests~~ — retained only
  for the live Ed25519 `near.export_key` operation authorization boundary; it
  is not persisted material identity and does not cross into ECDSA export.

## Phase 19 — factor-labelled assembly ports and Browser shortcuts

- ~~`refreshPasskeyEd25519CapabilityForSigning`~~ — confirmed absent at
  `7495b5b44`
- ~~`requestEmailOtpEd25519SigningChallenge`~~ — retained as the live
  factor-specific Email OTP challenge boundary for NEAR signing; it is not a
  generic auth-method selector or compatibility alias.
- ~~`recoverEmailOtpEd25519CapabilityForSigning`~~ — absent from production and
  retained tests.
- ~~`resolveAccountAuthMethodForSigning`~~ — absent from production; the one
  remaining source-guard literal asserts that assembly cannot recreate it.
- ~~`ensureNearEd25519YaoCapabilityForSigning` and
  `resolveActiveNearEd25519YaoSigningLane` deletion~~ — retained as private
  Browser exact-material orchestration, not generic assembly ports.
- ~~`hasPasskeyAuthenticatorForNearEd25519Subject`~~ — absent from production
  and retained tests.
- ~~`recoverNearEd25519YaoCapabilityForSigning`~~ — absent from production and
  retained tests.
- ~~`recoverExactPasskeyEd25519YaoCapabilityForSigning`~~ — absent from
  production and retained tests.
- ~~`recoverExactEmailOtpEd25519YaoCapabilitySilentlyForSigning` deletion~~ —
  retained as private Browser factor-owned recovery orchestration.
- ~~`recoverExactEd25519YaoCapability`~~
- ~~`hasNearEd25519YaoPublicReference`~~
- ~~`recoverNearEd25519YaoCapabilityFromSealedSession`~~
- ~~`recoverNearEd25519YaoCapabilityWithPasskey`~~ — all four obsolete Browser
  shortcuts are absent from production and retained tests.
- ~~`readNearEd25519RuntimeRecordForSelectedLane`~~ — deleted by `4f089b483`
- ~~`publishNearEd25519RuntimeIdentityForRecord`~~ — deleted by `4f089b483`
- ~~`resolveNearTransactionPlannerReadiness`~~ — absent after the canonical
  preparation cut, verified by `4f089b483`
- ~~control-flow use of `getWarmThresholdEd25519SessionStatusForSession`~~ — no
  production occurrence remains.
- ~~`resolveThresholdEd25519SessionIdForNearAccount`~~ — absent from production
  and retained tests.
- ~~the broad `resolveActiveEd25519YaoSigningCapability` port~~ — absent from
  production and retained tests.
- ~~the production-dead `thresholdSigningSessionReadiness.ts` classifier and
  its self-only unit test~~ — deleted by `18850e9d4`
- ~~`withThresholdEd25519CommitQueue`, `ThresholdEd25519CommitQueueByKey`, and
  `resolveThresholdEd25519CommitQueueKey` deletion~~ — retained as the one
  canonical exact-owner queue required by `R90-INV-008`; same-owner FIFO,
  stale-owner rejection, and different-owner concurrency are proved in
  `8c26a39bf`.
- ~~the `forceFreshAuth` and `retryingFreshAuth` planner booleans~~ — retained
  for the bounded Refactor 92 same-method expiry retry; they are control-flow
  state rather than identity aliases.
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
- ~~`emailOtpEd25519YaoBudgetRecovery.unit.test.ts`~~ — renamed to the
  capability-owned recovery suite in `82b439fc5`; its valid continuity,
  lifecycle, export, and cleanup assertions now build the durable record
  through the shared sealed-session fixture (`fc2383c93`). Current
  authorization grant/quota fields remain only where the live lane/JWT
  boundary requires them.
- ~~`emailOtpEd25519YaoExportRefresh.unit.test.ts` migration~~ — retained as
  current page-refresh, durable-context, continuity, zeroization, and
  wrong-factor-callback coverage. Its lane and authorization use production
  builders; the remaining inline value is the worker's plain capability
  descriptor, for which no shared domain-record factory is appropriate.
- ~~`passkeyEd25519YaoExportRefresh.unit.test.ts` migration~~ — retained as
  current credential, no-intervening-transaction, continuity, and
  authenticator-drift coverage. Lane, Wallet Session, and authorization use
  production/shared builders; the remaining values are test doubles rather
  than persisted lifecycle records.
- ~~`ed25519YaoExportFlow.typecheck.ts` migration~~ — the retained fixture now
  rejects the wrong factor lane at the current authority/adapter boundary and
  carries no legacy grant or budget material.
- ~~obsolete positive capability-source fixtures in `nearSigning.typecheck.ts`~~
  — absent; the retained exact-lane and reusable-vs-operation-grant negative
  checks describe the current domain.
- ~~`createEcdsaOnlyWalletSigningBudgetSessionStatus` and its
  `walletSigningBudgetStatus.fixtures.ts` helper~~ — zero callers remained
  after the ECDSA client-budget deletion; the fixture was removed without
  changing the live Ed25519 budget boundary (`afd2ba04c`).

## Phase 20 — signing budget subsystem

Replacement: exact operation grants plus `MpcWalletSigningQuota` claims.

- ~~`BudgetCoordinator`, the client reservation projection, client lifecycle
  finalizer, and their trace/typecheck/test surface~~ — deleted by
  `655a597c5`; live Refactor-92 status/admission classifiers remain open below
  until they are rehomed outside the legacy budget subsystem
- ~~`budgetFinalizer` and its finalizer-only type/test/source-guard surface~~ —
  deleted by `c838eeea0` after all production callers moved to relayer claims
- ~~the zero-caller client budget projection reducer, reservation projection,
  and dedicated type fixture~~ — deleted by `64f46362c`; the temporary
  `budgetUnknownSigningSessionStatus` helper was deleted with the neutral
  lifecycle-status move in `82b439fc5`
- ~~`signingEngine/session/budget/**`~~ — deleted in `82b439fc5`; the live
  Refactor-92 status classifier and authorization admission now live under
  `session/lifecycle` and `session/operationState`
- ~~reusable NEAR transaction client admission, reservation, success/zero-spend
  finalization, and prepared-boundary budget state~~ — removed by `cc4cf26ab`;
  relayer operation claims and quota transactions own consumption
- ~~`DelegatedBudgetReservationStore`~~ — deleted in `20bd2297e`; it had no
  production consumer
- ~~zero-caller `RouterAbEd25519YaoNormalSigningBudgetRefreshResult` alias~~ —
  budget refresh returns the canonical session-provision result directly
- ~~zero-caller `WalletSigningSpendPlan`, its Ed25519-only target type, and
  normalizer~~ — deleted after claim-owned quota consumption left no producer
  or consumer
- ~~router reserve/commit/release budget methods~~ — deleted
- ~~old development grant-keyed budget rows~~ (reject and clear at the
  persistence boundary; never fan one remaining-use count into multiple
  balances)
- ~~the transitional blanket readmission path after recovery~~ — deleted
- ~~the legacy projection path copying reusable authorization across EVM/Tempo
  targets~~ — deleted
- keep only client-side concurrent-operation fingerprinting from the old
  subsystem

Scope disposition: Unit 3c moved Ed25519 to the shared authorization core's
atomic claim-and-quota transaction and deleted the Router methods, inert rows,
wire fields, fixtures, and guards. The ECDSA public budget fields and
compatibility aliases were removed by `41ed8f9cb`; reusable authorization now
uses canonical capability-grant and Wallet Session/quota identities.

## Phase 21 — worker and WASM residue

Guard disposition: the stale registration-modal source assertion and the
deleted `session/budget/budgetStatusReader.ts` probe were removed, while the
remaining auth, worker, platform, and bundle guards stay active. The current
registration path uses the exact material-target rollback state and exhaustive
factor switches (`b37ce26b0`).

Verification disposition: the source guard suite is now 220/220. The D1
local-dev launcher again loads the sibling SDK `.dev.vars` before the console
`.dev.vars`, matching the retained launcher contract (`a610be9dc`).

- generic-named passkey-only WASM sessions (destructive rename to
  `WasmPasskeyClientRegistrationSessionV1` /
  `WasmPasskeyClientRecoverySessionV1`; no aliases)
- ~~combined ECDSA enrollment requests~~ — no production or retained-test
  occurrences remain at the final symbol audit (2026-08-02)
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
- remaining `signing-session` terminology on surfaces where it still conflates
  authorization with material lifecycle
- ~~old route-plane labels `threshold_session` and `user_session`~~ — internal
  policy planes are now `capability_grant` and `session_principal`
  (`f090ecde2`); deployed protocol schemes and error codes retain their exact
  wire names
- wallet-only `AuthMethod` usages outside capability-local modules
- ~~optional `authMethod` and implicit Passkey defaults on generic
  `registerNearWallet` / `registerEvmWallet` host and iframe paths~~ — deleted
  by `4f51048c5`; Passkey-named convenience APIs remain explicit
- ~~auto-signer registration paths~~ — no production occurrence remains at
  `f090ecde2`
- public exports implying wallet-only auth/sessions/grants
- ~~zero-caller generic `ThresholdSigningKeyOpsPort` export alias~~ — the
  Ed25519-specific `ThresholdEd25519ClientShareDeriverPort` is the sole
  signing-key operation contract
- ~~one-use `RouterApiThresholdRuntimeService` alias~~ — the Router service bag
  now names the canonical `RouterAbSigningRuntimeService` directly
  (`80bb11a3f`)
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
- ~~zero-caller `WarmSessionProvisioner` and
  `EnsureWarmEcdsaCapabilityReadyResult` declarations~~ — removed with their
  threshold-session-id persistence alias; the live capability reader and
  provisioning entry points use lane-qualified canonical types
  (`57849eda9`)
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
of `packages/wallet/src` returns zero matches for
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
| `clearThresholdEcdsaSessionRecordForExactIdentity` | `walletSessionExpiry.invalidationIdempotency`, `signingSessionReadiness.clearGrant` |
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
