# Modular Auth And Capability Refactor Plan

Date created: June 28, 2026

Status: planning. Phase 0A is complete through Refactor 82 Phase 8; the remaining
phases are still planning.

Companion spec: [Modular Auth And Capability Refactor SPEC](./refactor-87-modular-auth-capabilities-SPEC.md).

Companion plans:

- [Refactor 82B: Auth Authority Typing Cleanup](./refactor-82B.md)
- [Refactor 85: IndexedDB Minimization](./refactor-85-indexedDB.md)
- [Refactor 86: Static Wallet Assets And Vite Plugin Removal](./refactor-86-static-wallet-assets.md)

This document is the implementation checklist. Requirements, architecture
decisions, domain sketches, persistence defaults, and security model live in the
companion SPEC.

Refactor 82B is a prerequisite typing cleanup for this plan. It separates stable
auth authority from one-time registration proof data so the modular auth-method
and capability surfaces here can be implemented without carrying Passkey-specific
session assumptions into Email OTP and future auth methods.

## Implementation Rules

- Keep the completed signer-set registration cut intact so local D1 registration
  does not revive the `ed25519_and_ecdsa` cross-product request shape. Then ship
  the auth/capability vertical slice: Better Auth session -> `SeamsSession` ->
  vault proxy use -> passkey grant evidence -> vault reveal -> audit.
- Keep Better Auth as the development auth provider until Seams authorization is
  stable.
- Keep capability modules as typed route/service modules. Add only the small SDK
  runtime config surface needed to select hosted wallet iframe mode and requested
  browser capabilities; avoid a framework or bundler plugin registry.
- Keep `mpc_signer_proof` optional. Baseline vault access must work without MPC.
- Phase-one automation uses service-account API keys that can request narrow
  capability grants. Defer OIDC workload federation, mTLS, KMS-bound proof, and
  customer workload identity until the grant model is stable.
- Treat public exports, host apps, env vars, migrations, fixtures, and docs as
  refactor surfaces. A shared type rename is incomplete until those surfaces are
  inventoried and either moved, updated, or explicitly parked.
- Use static route assembly plus import guards for Cloudflare Workers.
- Keep compatibility logic at request and persistence boundaries, then delete it.
- Delete wallet-first fixtures when they only protect obsolete behavior.
- Treat browser `walletRuntime`, `authMethods`, and `capabilities` as SDK module
  selection only. Server tenant runtime config is authoritative for enabled auth
  methods, capabilities, and policies.

## Simplified End State

Target source ownership:

```text
authMethod/
  passkey
  emailOtp
  slackOtp
  walletLogin
  recoveryCode

session/
  seamsSession
  providerSessionAdapters

authorization/
  grantEvidence
  capabilityGrants
  policies
  audit

capability/
  vault
  nearEd25519Mpc
  evmEcdsaMpc

router/
  routeModules
  cloudflareAdapter
  expressAdapter

sdkWeb/
  config
  walletRuntime/hostedIframe
  authMethodUi
  capabilityUi
```

Use this as the implementation compass. Package extraction is deferred until
these internal module boundaries are stable.

## Phase 0A: Signer-Set Registration Cut

Status: complete through Refactor 82 Phase 8.

Goal: fix the registration request and D1 ceremony shape before staging or public
API hardening can normalize the two-signer cross-product model.

This is the tactical bridge from Refactor 82 into Refactor 83. It keeps the
current auth/session stack for now, but changes wallet registration to request a
set of signer capabilities instead of one mode enum.

Do:

- Replace the public registration request shape:

```ts
type RegistrationSignerSetSelection = {
  kind: 'signer_set';
  signers: readonly RegistrationSignerRequest[];
};

type RegistrationSignerRequest =
  | {
      kind: 'near_ed25519';
      accountProvisioning: RegistrationNearAccountProvisioning;
      signerSlot: PositiveSignerSlot;
      participantIds: readonly number[];
      derivationVersion: 1;
    }
  | {
      kind: 'evm_family_ecdsa';
      participantIds: readonly number[];
      chainTargets: readonly ThresholdEcdsaChainTarget[];
    };
```

- Delete `ed25519_only`, `ecdsa_only`, and `ed25519_and_ecdsa` from core
  registration logic. If a temporary request-boundary parser accepts old mode
  shapes while tests are updated, keep it outside core and delete it before this
  phase is marked complete.
- Normalize raw signer-set requests once into a `RegistrationSignerPlan`.
- Reject duplicate signer identities at the boundary. Examples: two
  `near_ed25519` entries with the same `signerSlot`, or two
  `evm_family_ecdsa` entries that resolve to the same wallet key.
- Replace D1 `combined_registration` ceremony state with branch-set state keyed
  by stable signer branch identity.
- Split the wallet-registration parts of
  `packages/sdk-server-ts/src/router/cloudflare/d1WalletRegistrationService.ts` into
  a registration orchestrator plus NEAR Ed25519 and EVM-family ECDSA branch
  helpers.
- Update SDK web defaults, iframe messages, wallet-registration RPC parsing,
  registration timing events, and type fixtures to use signer-set terminology.
- Update or delete fixtures that preserve the old mode enum behavior.

Check:

- Local D1 registration provisions both NEAR Ed25519 and EVM-family ECDSA from
  the signer-set request.
- Ed25519-only and ECDSA-only registration use the same signer-set machinery.
- D1 prepare/start/respond/finalize has targeted coverage for a two-signer set.
- Duplicate signer branches fail at the request boundary.
- Source guards reject production references to `ed25519_and_ecdsa`,
  `ed25519_only`, `ecdsa_only`, and `combined_registration` outside any
  temporary boundary parser named in this phase.
- `pnpm --dir packages/sdk-server-ts type-check`, `pnpm --dir packages/sdk-web
  type-check`, focused D1 registration tests, registration intent allocation
  tests, and `git diff --check` pass.

Long-term path:

- Phase 0A is still wallet-registration work. Phase 10 promotes the same shape
  into auth-first capability provisioning where registration creates an auth
  account by default and provisions only requested `CapabilityInstance` records.
- `near_ed25519` becomes `near_ed25519_mpc_signing` capability provisioning.
- `evm_family_ecdsa` becomes `evm_ecdsa_mpc_signing` capability provisioning.
- The branch identity used by D1 ceremony state becomes the capability
  provisioning identity or `capabilityId` once Phase 10 lands.
- Vault-only, IdP-only, and auth-only registration paths must not create signer
  records or load signer/HSS/WASM code.
- Capability policies bind requested signer capabilities to registered auth
  evidence kinds through Seams authorization, replacing the current wallet-first
  registration authority checks.

## Phase 0B: Wallet-Rooted Confirmation Subjects

Status: complete.

Goal: align existing signing confirmation payloads with the modular capability
model before the larger auth/capability split lands.

Do:

- Treat `walletId` as the canonical wallet identity in sign-intent confirmation
  payloads.
- Represent NEAR signing as a wallet plus NEAR account metadata:

```ts
{ kind: 'near_wallet'; walletId: WalletId; nearAccountId: AccountId }
```

- Represent EVM-family and Tempo signing as wallet-scoped capability use:

```ts
{ kind: 'evm_wallet'; walletId: WalletId }
```

- Delete the ambiguous `near_account` / `wallet` sign-intent subject names from
  the intent-digest confirmation boundary.
- Add type fixtures that reject `nearAccountId` on EVM-family subjects and
  reject NEAR subjects without `walletId`.
- Keep chain-specific protocol identifiers as branch metadata. Do not use them
  as wallet identity.

Check:

- Passkey confirmation for EVM/Tempo no longer validates `walletId` as a NEAR
  account id.
- NEAR sign-intent confirmation has both `walletId` and `nearAccountId`, so
  split identity works for implicit accounts.
- `SignIntentDigestSubject` is a discriminated union with no compatibility
  branch for the old names.

## Phase 0D: Exact Capability Subject Type Hardening

Status: in progress. Phase 0D.1 exact ECDSA material identity and durable NEAR
unlock subject resolution is implemented; Phase 0D.2 full branch-specific
`unlockCore(subject)` remains.

Goal: close the type holes that let exact capability identity drift after
Refactor 79 and before the modular capability model lands.

This phase addresses two concrete bug classes found during local D1 testing:

- EVM-family role-local material was exact in its binding digest, while the
  worker cache key was narrower than that digest. Tempo and ARC could reuse one
  `materialHandle` while expecting different chain-bound material.
- Wallet unlock was exposed as wallet-scoped, while the local unlock wrapper
  still required a NEAR binding before it could enter capability-specific logic.

Do:

- Add a single ECDSA role-local material identity builder. It must derive the
  binding digest and worker material handle from the same typed input:

```ts
type EcdsaRoleLocalMaterialBinding = {
  walletId: WalletId;
  evmFamilySigningKeySlotId: EvmFamilySigningKeySlotId;
  thresholdSessionId: ThresholdEcdsaSessionId;
  chainTarget: EvmFamilyChainTarget;
  routerAbStateSessionId: RouterAbStateSessionId;
};

type EcdsaRoleLocalMaterialHandle = Brand<string, 'EcdsaRoleLocalMaterialHandle'>;
type EcdsaRoleLocalBindingDigest = Brand<string, 'EcdsaRoleLocalBindingDigest'>;

function buildEcdsaRoleLocalMaterialIdentity(
  binding: EcdsaRoleLocalMaterialBinding,
): {
  bindingDigest: EcdsaRoleLocalBindingDigest;
  materialHandle: EcdsaRoleLocalMaterialHandle;
};
```

- Delete direct string construction of ECDSA role-local `materialHandle` values
  outside the identity module.
- Make worker storage, parser output, runtime records, tests, and diagnostics
  accept the branded `EcdsaRoleLocalMaterialHandle`.
- Add type fixtures that reject a material handle built from
  `{ thresholdSessionId, keyHandle }` without `chainTarget` and
  `evmFamilySigningKeySlotId`.
- Add a source guard that rejects `router-ab-ecdsa-role-local:` string
  interpolation outside the identity builder.
- Add a chain-split regression test proving Tempo and ARC with the same wallet,
  session, and router state produce different `bindingDigest` and
  `materialHandle` values.
- Introduce branch-specific wallet unlock subjects:

```ts
type WalletUnlockSubject =
  | {
      kind: 'near_ed25519_wallet';
      walletId: WalletId;
      nearAccountId: NearAccountId;
      nearEd25519SigningKeyId: NearEd25519SigningKeyId;
      signerSlot: SignerSlot;
    }
  | {
      kind: 'evm_family_ecdsa_wallet';
      walletId: WalletId;
      evmFamilySigningKeySlotId: EvmFamilySigningKeySlotId;
    };
```

- Replace local `unlock(walletId) -> requireNearAccountForWallet(walletId) ->
  unlockCore(nearAccountId)` with `resolveWalletUnlockSubject(walletId,
  requestedCapabilities) -> unlockCore(subject)`.
- Resolve `WalletUnlockSubject` once at the IndexedDB/request boundary from
  active wallet signers and auth-method records. Core unlock code must receive
  the discriminated subject, not raw wallet strings, broad profile records, or
  optional identity bags.
- Keep `nearAccountId` required only for the `near_ed25519_wallet` branch.
- Let `evm_family_ecdsa_wallet` unlock, restore, and warm ECDSA material without
  reading or validating any NEAR account identity.
- When unlock requests both NEAR Ed25519 and EVM-family ECDSA, represent it as
  a set of exact `WalletUnlockSubject` branches rather than one flattened object.
- Update passkey and Email OTP unlock flows so auth prompts bind to wallet/auth
  subject identity, while capability warmup binds to the selected branch subject.
- Move display names, recent unlock lists, and account picker labels to wallet
  identity plus auth-method display data. Implicit NEAR account IDs remain
  capability metadata.
- Delete fallback paths that infer a wallet from `nearAccountId` in unlock,
  except request/persistence boundary parsers with explicit deletion notes.

Check:

- [x] EVM-family signing cannot compile when a call site constructs role-local
  material from a cache key narrower than the binding digest.
- [x] Tempo and ARC signing share no role-local worker material handle unless their
  full material binding is identical.
- [ ] Wallet unlock for an ECDSA-only wallet does not call `toAccountId`, read NEAR
  projections, or require a NEAR operational key.
- [x] Wallet unlock for a NEAR Ed25519 wallet still requires
  `nearAccountId`, `nearEd25519SigningKeyId`, and positive `signerSlot`.
- [ ] Combined NEAR+ECDSA wallet unlock warms the requested branches from a typed
  subject set and does not flatten `walletId`, `nearAccountId`, and ECDSA key
  identity into one object.
- [ ] Source guards reject:
  - direct `materialHandle` string interpolation for role-local ECDSA;
  - optional `nearAccountId` in wallet unlock core subject types;
  - `wallet-scoped auth requires a resolved NEAR account binding` in
    wallet-scoped unlock code;
  - ECDSA unlock paths importing NEAR account validators.
- [ ] Focused tests cover:
  - [x] chain-specific ECDSA role-local material identity;
  - [ ] ECDSA-only wallet unlock;
  - [x] NEAR Ed25519 wallet unlock;
  - [ ] combined wallet unlock with requested branch set;
  - [x] page-reload unlock where runtime session records are empty but durable wallet
    signer records exist.

Implementation progress:

- [x] Added branded `EcdsaRoleLocalMaterialHandle` and
  `EcdsaRoleLocalBindingDigest`.
- [x] Moved ECDSA role-local handle construction behind a single typed builder
  that includes `walletId`, `evmFamilySigningKeySlotId`, `thresholdSessionId`,
  `signingGrantId`, `chainTarget`, and Router A/B state session identity.
- [x] Made `ThresholdEcdsaSecp256k1KeyRef` carry
  `evmFamilySigningKeySlotId` explicitly.
- [x] Added `WalletUnlockSubject` and durable wallet-signer resolution for the
  NEAR Ed25519 unlock branch.
- [ ] Replace local `unlockCore(nearAccountId)` with a branch-aware
  `unlockCore(subject)` flow that can authenticate and warm ECDSA-only wallets
  without NEAR account identity.

Cross-plan notes:

- Refactor 79 remains the owner for `ExactSigningLaneIdentity` and exact signing
  lane mutation rules. This phase uses the same authority model for worker
  material handles.
- Refactor 87 owns `WalletUnlockSubject` because unlock is an auth/capability
  entrypoint, not a NEAR account API.
- Refactor 84b HSS slimming must keep HSS crate contexts digest-only; SDK
  capability subjects may include app-specific identity before digesting.

## Phase 0E: SDK Runtime Surface For Hosted Wallet Capabilities

Status: planning.

Goal: make the wallet iframe an SDK-level runtime selection instead of an app
Vite/Next/build plugin. Application code should import the SDK, provide its
environment and publishable key, and opt into wallet capabilities with typed
runtime, auth-method, and capability config.

Client config selects SDK modules and UI/runtime loading only. Server tenant
runtime config owns the enabled auth methods, enabled capabilities, and
capability policies:

```ts
type TenantRuntimeConfig = {
  tenantId: TenantId;
  authMethods: readonly AuthMethodKind[];
  capabilities: readonly CapabilityKind[];
  policies: readonly CapabilityPolicyRef[];
};
```

Validated against current code:

- `SeamsWebProvider` already accepts one `config` object.
- `SeamsConfigsInput.iframeWallet` already carries the required runtime fields:
  wallet origin, service path, SDK base path, wallet host variant, and RP ID
  override.
- `SeamsWalletConfig` already resolves into a discriminated runtime shape:
  `direct` or `iframe`.
- `WalletIframeRouter` already requires `walletOrigin` when iframe mode is used.

Target public API:

```ts
import {
  createSeamsConfig,
  hostedWalletIframe,
  passkeyAuth,
  nearEd25519MpcSigning,
  evmFamilyEcdsaMpcSigning,
} from '@seams/sdk';

const config = createSeamsConfig({
  environmentId: 'proj_...',
  publishableKey: 'pk_...',
  walletRuntime: hostedWalletIframe({
    origin: 'https://wallet.seams.sh',
    rpId: 'example.com',
  }),
  authMethods: [
    passkeyAuth(),
  ],
  capabilities: [
    nearEd25519MpcSigning(),
    evmFamilyEcdsaMpcSigning(),
  ],
});
```

React usage:

```tsx
<SeamsWebProvider config={config}>{children}</SeamsWebProvider>
```

Auth-only usage:

```ts
const config = createSeamsConfig({
  environmentId: 'proj_...',
  publishableKey: 'pk_...',
  authMethods: [passkeyAuth()],
});
```

Internal normalized shape:

```ts
type BrowserWalletRuntimeSelection =
  | { kind: 'none' }
  | {
      kind: 'hosted_wallet_iframe';
      origin: WalletOrigin;
      servicePath: WalletServicePath;
      sdkBasePath: WalletSdkBasePath;
      rpId?: WebAuthnRpId;
      walletHostVariant: WalletHostVariant;
    };

type BrowserCapabilitySelection =
  | { kind: 'near_ed25519_mpc_signing'; walletRuntime: 'hosted_wallet_iframe' }
  | { kind: 'evm_family_ecdsa_mpc_signing'; walletRuntime: 'hosted_wallet_iframe' };

type BrowserAuthMethodSelection =
  | { kind: 'passkey_auth' }
  | { kind: 'email_otp_auth' };
```

Do:

- Add builder functions for the three distinct config axes:
  - wallet runtime: `hostedWalletIframe`;
  - auth methods: `passkeyAuth` and later `emailOtpAuth`;
  - capabilities: `nearEd25519MpcSigning` and `evmFamilyEcdsaMpcSigning`.
- Add `createSeamsConfig(...)` as the single public browser config constructor.
  It should parse raw config input once and return the existing
  `SeamsConfigsInput`/resolved config bridge only as an internal adapter while
  the old config shape is being removed.
- Parse `origin`, `servicePath`, `sdkBasePath`, and `rpId` at the config
  boundary into branded runtime types.
- Allow at most one wallet runtime selection at the config boundary.
- Reject duplicate auth method kinds and duplicate capability kinds at the
  config boundary.
- Reject `nearEd25519MpcSigning()` or `evmFamilyEcdsaMpcSigning()` without
  `hostedWalletIframe(...)` for browser builds.
- Keep `passkeyAuth()` usable without a wallet iframe for auth-only customers.
- Keep passkey and OTP out of wallet runtime config; they are auth methods.
- Replace app examples that set `iframeWallet.walletOrigin` with the
  `walletRuntime` API.
- Keep any temporary `iframeWallet` acceptance at the public config boundary
  only, then delete it before this phase is complete.
- Keep Vite/Next plugins out of the runtime API. Wallet runtime selection is a
  plain typed SDK config value.
- Update `SeamsWebProvider` examples to use `config={...}`.
- Add type fixtures for:
  - duplicate auth method and capability rejection;
  - signer capability without hosted wallet runtime rejection;
  - auth-only config without hosted wallet runtime;
  - old `iframeWallet` public examples absent from docs and app examples.

Check:

- A minimal Vite React app can import `@seams/sdk/react` and use
  `SeamsWebProvider config={createSeamsConfig(...)}` with no SDK Vite plugin.
- Auth-only passkey login can initialize without wallet iframe code.
- Browser NEAR/EVM MPC signing refuses to initialize without
  `hostedWalletIframe(...)`.
- Browser NEAR/EVM MPC signing initializes the hosted wallet iframe and never
  requests app-origin `/sdk/*`.
- `packages/sdk-web/src/plugins/vite.ts` is no longer part of any public
  browser wallet setup path.

## Phase 0F: ECDSA Role-Local Material Cache Slimming

Status: in progress. The `evmFamilySigningKeySlotId` role-local material-handle
slice is complete; broader Phase 0F slimming remains pending.

Goal: replace the Phase 0D tactical chain-specific worker-material handle with a
smaller material-cache identity. Exact signing lanes and signed Router A/B
normal-signing state remain the authority for chain/session use.

Evidence from the current implementation:

- `routerAbStateSessionId` is derived from
  `RouterAbEcdsaHssNormalSigningStateV1.scope` and the state's
  `activation_epoch` is issued from `thresholdSessionId`.
- ECDSA `thresholdSessionId` values are generated with the `tehss_` prefix and
  24 random bytes, so they can serve as the unique live session identifier.
- `chainTarget` is required in exact signing lane/session-record identity. The
  HSS worker opens a role-local state blob by material handle and binding digest;
  chain selection should be checked before the worker material is opened.
- `evmFamilySigningKeySlotId` currently behaves like a deterministic
  provisioning/key-allocation handle derived from wallet and signing-root scope.
  If it has no runtime semantics after ECDSA key material exists, keep it out of
  signing authority, worker material identity, and generic capability records.

Implementation inventory:

- Shared TS protocol and ID helpers:
  - `packages/shared-ts/src/signing-lanes/evmFamilySigningKeySlotId.ts`
  - `packages/shared-ts/src/signing-lanes/index.ts`
  - `packages/shared-ts/src/threshold/ecdsaHssRoleLocalBootstrap.ts`
  - `packages/shared-ts/src/utils/routerAbEcdsaHss.ts`
  - `packages/shared-ts/src/utils/signingSessionSeal.ts`
- Rust Router A/B protocol and local smoke code:
  - `crates/router-ab-core/src/protocol/ecdsa_hss.rs`
  - `crates/router-ab-cloudflare/src/lib.rs`
  - `crates/router-ab-dev/src/bin/router_ab_local_smoke.rs`
- Server route, JWT, budget, and D1 ceremony surfaces:
  - `packages/sdk-server-ts/src/router/commonRouterUtils.ts`
  - `packages/sdk-server-ts/src/router/routerAbPrivateSigningWorker.ts`
  - `packages/sdk-server-ts/src/router/signingBudgetStatus.ts`
  - `packages/sdk-server-ts/src/router/verifiedWalletSessionAuth.ts`
  - `packages/sdk-server-ts/src/router/cloudflare/routes/thresholdEcdsa.ts`
  - `packages/sdk-server-ts/src/router/cloudflare/d1EvmFamilyEcdsaRegistrationBranch.ts`
  - `packages/sdk-server-ts/src/router/cloudflare/d1RegistrationCeremonyRecords.ts`
  - `packages/sdk-server-ts/src/core/AuthService.ts`
  - `packages/sdk-server-ts/src/core/ThresholdService/**`
- Web protocol clients and registration/bootstrap adapters:
  - `packages/sdk-web/src/core/rpcClients/relayer/thresholdEcdsa.ts`
  - `packages/sdk-web/src/core/rpcClients/relayer/walletRegistration.ts`
  - `packages/sdk-web/src/core/signingEngine/flows/registration/services/ecdsaRegistrationBootstrap.ts`
  - `packages/sdk-web/src/core/signingEngine/threshold/ecdsa/**`
- Web runtime, persistence, worker, and lane authority surfaces:
  - `packages/sdk-web/src/core/platform/ecdsaRoleLocalRecords.ts`
  - `packages/sdk-web/src/core/platform/secretSources.ts`
  - `packages/sdk-web/src/core/platform/ports.ts`
  - `packages/sdk-web/src/core/signingEngine/session/persistence/ecdsaRoleLocalRecords.ts`
  - `packages/sdk-web/src/core/signingEngine/session/persistence/records.ts`
  - `packages/sdk-web/src/core/signingEngine/session/persistence/sealedSessionStore.ts`
  - `packages/sdk-web/src/core/signingEngine/session/routerAbSigningWalletSession.ts`
  - `packages/sdk-web/src/core/signingEngine/session/identity/ecdsaHssSigningMaterialHandle.ts`
  - `packages/sdk-web/src/core/signingEngine/session/identity/evmFamilyEcdsaIdentity.ts`
  - `packages/sdk-web/src/core/signingEngine/session/identity/exactSigningLaneIdentity.ts`
  - `packages/sdk-web/src/core/signingEngine/flows/signEvmFamily/**`
  - `packages/sdk-web/src/core/signingEngine/session/warmCapabilities/**`
  - `packages/sdk-web/src/core/signingEngine/workerManager/**`
- Tests and guards:
  - `tests/unit/evmFamilyEcdsaIdentity.unit.test.ts`
  - `tests/unit/ecdsaRoleLocalRecords.unit.test.ts`
  - `tests/unit/routerAbEcdsaHssNormalSigning.unit.test.ts`
  - `tests/unit/routerAbEcdsaHssBudgetRouteCore.unit.test.ts`
  - `tests/unit/walletRegistrationEcdsaRouterAbBootstrap.unit.test.ts`
  - `tests/unit/thresholdEcdsa.*.unit.test.ts`
  - `tests/unit/refactor76BrandedKeys.guard.unit.test.ts`
  - `tests/unit/refactor79ExactSigningLane.guard.unit.test.ts`
  - `tests/unit/refactor83CapabilitySubjects.guard.unit.test.ts`
  - `tests/relayer/router-ab-normal-signing-auth-boundary.test.ts`
  - `tests/relayer/threshold-ecdsa.signature-harness.test.ts`

Side effects to account for:

- Removing `wallet_key_id` from Router A/B ECDSA-HSS normal-signing scope
  changes canonical scope bytes, budget request digests, admission lifecycle ids,
  Rust protocol structs, and TS route parsers together.
- Removing or renaming `evmFamilySigningKeySlotId` changes Wallet Session JWT
  claims, signing-session seal bindings, D1 ceremony records, IndexedDB session
  records, sealed recovery records, and source guards. In development, delete
  local D1 and IndexedDB state after this lands rather than preserving
  compatibility readers.
- If `ecdsaThresholdKeyId` derivation stops hashing
  `evmFamilySigningKeySlotId`, existing ECDSA-HSS key identities change. Update
  registration bootstrap, add-signer, export/recovery, and test fixtures in the
  same commit.
- A chain-agnostic role-local `materialHandle` must not be used as a per-chain
  authority key or UI/session identity. Any `workerSessionId` field populated
  from the material handle must be treated as a worker cache reference only.
- Rename only ECDSA role-local public verifier fields in this phase. Ed25519
  `clientVerifyingShareB64u` fields remain out of scope unless a separate
  Ed25519 naming cleanup is planned.

Do:

- Audit `evmFamilySigningKeySlotId` before changing runtime material identity:
  - if it is only a registration/bootstrap reservation id, rename it to
    `EvmFamilyEcdsaProvisioningReservationId` and keep it only in
    registration/bootstrap request, ceremony, and server validation code;
  - if it is intended to identify a durable EVM-family signing capability,
    replace it with a real capability identity such as
    `EvmFamilyEcdsaSignerId`, document the cardinality it represents, and stop
    deriving it as a cosmetic alias for wallet plus signing-root scope.
- Do not carry a provisioning reservation id in:
  - `ExactSigningLaneIdentity`;
  - `WalletUnlockSubject`;
  - Wallet Session claims;
  - Router A/B normal-signing scope;
  - `EcdsaRoleLocalPublicFacts`;
  - `ThresholdEcdsaSessionRecord`;
  - sealed recovery records;
  - role-local material handles or binding digests.
- If no multi-ECDSA-key-per-wallet use case exists today, use
  `ecdsaThresholdKeyId` plus wallet/signing-root facts as the durable signer
  identity and delete `evmFamilySigningKeySlotId` from runtime paths.
- Replace the current role-local material binding:

```ts
type EcdsaRoleLocalMaterialBinding = {
  walletId: WalletId;
  evmFamilySigningKeySlotId: EvmFamilySigningKeySlotId;
  thresholdSessionId: ThresholdEcdsaSessionId;
  signingGrantId: SigningGrantId;
  keyHandle: EcdsaKeyHandle;
  routerAbStateSessionId: RouterAbStateSessionId;
  chainTarget: EvmFamilyChainTarget;
  clientVerifyingShareB64u: EcdsaClientVerifyingShareB64u;
  ecdsaThresholdKeyId: EcdsaThresholdKeyId;
  participantIds: readonly number[];
  relayerKeyId: EcdsaRelayerKeyId;
};
```

  with a material-only binding:

```ts
type EcdsaRoleLocalMaterialBinding = {
  thresholdSessionId: ThresholdEcdsaSessionId;
  signingGrantId: SigningGrantId;
  keyHandle: EcdsaKeyHandle;
  ecdsaThresholdKeyId: EcdsaThresholdKeyId;
  clientVerifyingPublicKey33B64u: EcdsaClientVerifyingPublicKey33B64u;
  participantIds: readonly number[];
  relayerKeyId: EcdsaRelayerKeyId;
};
```

- Remove `routerAbStateSessionId` from `EcdsaRoleLocalMaterialBinding`,
  `EcdsaRoleLocalBindingDigest`, `EcdsaRoleLocalMaterialHandle`, worker-store
  payloads, runtime material validation keys, tests, and diagnostics.
- Remove `chainTarget` from `EcdsaRoleLocalMaterialBinding`,
  `EcdsaRoleLocalBindingDigest`, and `EcdsaRoleLocalMaterialHandle`.
- [x] Remove `evmFamilySigningKeySlotId` from `EcdsaRoleLocalMaterialBinding`,
  `EcdsaRoleLocalBindingDigest`, and `EcdsaRoleLocalMaterialHandle`.
- Rename `clientVerifyingShareB64u` to `clientVerifyingPublicKey33B64u` in
  ECDSA role-local material binding, public facts, worker payloads, diagnostics,
  tests, and type fixtures. This value is public verifier identity, not a masked
  or secret signing share.
- Keep `chainTarget` in `ExactSigningLaneIdentity`,
  `ThresholdEcdsaSessionRecord`, ECDSA lane selection, ready-record lookup, and
  signer-session validation.
- Keep `routerAbEcdsaHssNormalSigning` as signed state in wallet-session claims
  and persisted session records. Use `routerAbEcdsaHssActiveStateSessionId()`
  only at Router A/B request/admission boundaries that need the canonical
  normal-signing state session key.
- Move lane/session chain checks before worker-material access. A selected ECDSA
  lane must prove:
  - lane signer `walletId` matches the session record wallet;
  - lane signer `chainTarget` matches the session record chain target;
  - lane `thresholdSessionId` and `signingGrantId` match the session record;
  - lane signer key handle and ECDSA threshold key match the session record.
- Make `buildEcdsaRoleLocalMaterialIdentity()` accept only branded domain types.
  Parse raw strings in record/JWT/worker-response boundary builders before
  calling it.
- Delete the Phase 0D regression test that expects Tempo and ARC to produce
  different role-local worker material handles for the same material. Replace it
  with a test proving a Tempo lane cannot open/sign through an ARC session
  record, even when the worker material handle is shared.
- Add a guard rejecting `chainTarget` and `routerAbStateSessionId` inside
  `EcdsaRoleLocalMaterialBinding` and the role-local material handle/digest
  builder.
- Add a guard rejecting `evmFamilySigningKeySlotId` in runtime authority types
  unless the audit proves it is a durable signer identity and renames it away
  from the provisioning/reservation vocabulary.
- Update diagnostics to report the exact lane/session mismatch that blocked
  signing instead of reporting a worker material binding mismatch for chain
  selection failures.

Check:

- [x] `buildEcdsaRoleLocalMaterialIdentity()` and
  `buildEcdsaRoleLocalSigningMaterialHandle()` have no
  `evmFamilySigningKeySlotId` / `wallet_key_id` input.
- [x] Role-local worker material-handle call sites no longer pass
  `evmFamilySigningKeySlotId`.
- [x] Focused regression test covers the narrowed material-handle API:
  `pnpm -C tests exec playwright test unit/evmFamilyEcdsaIdentity.unit.test.ts -g "without signing key slot identity"`.
- [ ] `buildEcdsaRoleLocalMaterialIdentity()` has no `chainTarget`,
  `walletId`, `evmFamilySigningKeySlotId`, or `routerAbStateSessionId` input.
- [ ] `evmFamilySigningKeySlotId` is either deleted from runtime paths or renamed
  to a provisioning-reservation id that appears only in registration/bootstrap
  code.
- [ ] ECDSA role-local and EVM-family signing paths no longer use
  `clientVerifyingShareB64u`; public verifier fields use
  `clientVerifyingPublicKey33B64u`. Ed25519 paths are out of scope for this
  rename unless a separate Ed25519 naming cleanup chooses the same vocabulary.
- [ ] ECDSA role-local material handles are stable for the same material across
  Tempo, ARC, and other EVM-family chain targets.
- [ ] Cross-chain signing still fails closed through exact lane/session-record
  validation before the worker material handle is opened.
- [ ] Router A/B signing requests still carry and validate the signed
  `routerAbEcdsaHssNormalSigning.scope` against Wallet Session claims.
- [ ] `routerAbStateSessionId` appears only in Router A/B state/admission
  helpers, request builders, and diagnostics that describe the signed Router A/B
  scope.
- [ ] Focused ECDSA signing tests cover same-material cross-chain reuse,
  cross-chain lane mismatch rejection, page-reload restored material, and
  registration-created material.

## Phase 0: Inventory

Goal: map current wallet-first coupling before moving code.

Do:

- Inventory `signing-session`, `signingGrantId`, `thresholdSessionId`,
  `SigningAuthPlan`, `WalletAuthIntent`, `WalletAuthCurve`, `AuthMethod`,
  `user_session`, and `threshold_session` call sites.
- Classify each route and method as auth provider, Seams authorization, auth
  factor, route assembly, vault, IdP, Ed25519 MPC, or ECDSA MPC.
- Inventory frontend demo and SDK surfaces, including `apps/seams-site`,
  `apps/docs`, `examples/*`, `packages/sdk-web/src/SeamsWeb`,
  `packages/sdk-web/src/react`, and
  `packages/sdk-web/src/core/signingEngine`.
- Inventory shared and public API surfaces, including `packages/shared-ts`,
  `packages/sdk-web/package.json`, `packages/sdk-server-ts/package.json`,
  package export maps, public README/docs snippets, generated `.d.ts` surfaces,
  and `advanced`/`threshold`/`worker`/`wasm` entrypoints.
- Inventory deployment hosts and examples, including `apps/web-server`,
  `examples/self-host-cloudflare-worker`, wrangler configs, startup scripts, env
  var names, and package scripts that construct `AuthService`, threshold stores,
  signing-session seal routes, console routers, or router API workers.
- Inventory console management surfaces, including RBAC roles, API key scopes,
  policy assignment scopes, wallet index, key exports, approvals, audit,
  webhooks, observability, and seed data.
- Inventory auth-factor runtimes and sealed storage, including Email OTP WASM,
  signing-session seal records, wallet session IndexedDB stores, and any HKDF
  salt/info labels that currently bind to wallet or threshold identities.
- Inventory test helpers and tooling, including Playwright configs, setup
  scripts, source guards, helper flows, fake relayers, fixture imports, and
  generated test env files.
- Classify `voiceId`, native clients, Rust crates, and WASM packages as
  capability-local, future grant evidence, or explicitly out of scope for this
  refactor.
- Classify frontend call sites as auth UI, session exchange, grant-evidence
  confirmation, vault UI, IdP UI, wallet UI, MPC signing, worker/runtime, or demo
  glue.
- Record imports that pull threshold, HSS, signer WASM, chain, wallet UI, or
  recovery code into generic auth/router/frontend paths.
- Mark tests to preserve, rewrite, or delete.

Check:

- Every current auth/wallet/signing route has one target owner.
- Every frontend demo, SDK component, React hook/context, SeamsWeb operation, and
  browser worker has one target owner.
- Every public package export either remains capability-local, moves behind an
  auth/capability-neutral entrypoint, or is scheduled for deletion.
- Every deployment host and example has a target assembly model: auth-only,
  vault-only, MPC-only, IdP-only, or full-platform.
- Every console table, role, API scope, policy scope, and seed fixture has a
  target owner or deletion note.
- Every non-test helper that manufactures signing sessions, signing grants,
  threshold sessions, wallet auth, or wallet policy has a target owner.
- Every shared type slated for deletion has a replacement.

## Phase 0C: Public Surface And Deployment Inventory

Status: planning.

Goal: make the repo-wide blast radius concrete before shared vocabulary changes
land.

Do:

- Write an inventory ledger with rows for:
  - package exports and public entrypoints;
  - deployment hosts and examples;
  - D1 migrations and seed data;
  - console management services and dashboard API clients;
  - test helpers, source guards, and Playwright scripts;
  - docs and generated diagrams that teach the old model;
  - optional workspaces such as `voiceId`, native clients, Rust crates, and WASM
    packages.
- For each row, record current owner, target owner, phase, action
  (`keep_capability_local`, `move_to_auth`, `move_to_authorization`,
  `move_to_vault`, `delete`, or `park`), and validation check.
- Treat `apps/web-server` as a first-class deployment host. It must have the
  same module boundary decisions as Cloudflare and Express.
- Treat `packages/shared-ts` as the highest-risk vocabulary surface. Shared
  exports cannot mention wallet/signing concepts unless the file is explicitly
  capability-local.
- Treat `voiceId` as parked future grant evidence unless this refactor explicitly
  chooses to add `voice_id_owner_presence` to `GrantEvidenceKind`.

Check:

- The ledger names all current `signingGrantId`, `thresholdSessionId`,
  `signing-session`, `AuthMethod`, `wallet_auth`, `wallet_session`,
  `user_session`, and `threshold_session` surfaces outside generated build
  output.
- Export maps for `@seams/sdk`, `@seams/sdk-server`, and
  `@seams-internal/shared-ts` have target shapes before Phase 1 type changes.
- Host assembly targets are recorded for Cloudflare, Express, Node web server,
  self-hosted Worker examples, and local test servers.
- Parked surfaces have explicit source guards or issue links so they do not
  silently become generic auth dependencies.

## Phase 1: Shared Auth Vocabulary

Goal: define auth and capability-grant vocabulary independent of wallets.

Do:

- Turn the Phase 0 test inventory into a redundant-test ledger.
- Remove tests/fixtures that only assert obsolete wallet-first behavior.
- Adapt tests that still protect valid behavior so they use auth/capability
  terminology before changing shared types.
- Add `AuthFactorKind`, `SessionEvidenceKind`, `GrantEvidenceKind`,
  tenant/principal/session/capability/grant IDs, `SeamsSession`,
  `GrantEvidenceRef`, `CapabilityGrantRequest`, `CapabilityOperationEnvelope`,
  `CapabilityGrant`, `CapabilityGrantPolicy`, and
  `CapabilityOperationGrantPolicyBinding`.
- Add `MpcSignerProof` as derived grant evidence.
- Move `SignerAuthMethod` and `WalletAuthMethod` into capability-local code.
- Delete `AuthMethod = SignerAuthMethod`.

Check:

- Redundant wallet-first tests are deleted or adapted before shared vocabulary
  changes land.
- Frontend demo and SDK owner map is complete before shared vocabulary changes
  land.
- Phase 0C public-surface ledger is complete for shared exports, package exports,
  deployment hosts, console schemas, helper scripts, and parked workspaces.
- Generic auth imports no signer domain files.
- Type fixtures reject invalid sessions, grant evidence records, grants, and
  signer fields on auth records.

## Phase 2: Persistence And Schema

Goal: make the SPEC persistence model concrete.

Do:

- Add migrations for shared auth/authorization tables, session refresh tokens,
  grant evidence, capability grants, capability grant policies, capability
  instances, capability bindings, audit, and vault tables.
- Expand or replace console tables for principals, agents, vault approvals,
  capability provisioning, audit, and new API scopes.
- Remap existing D1 console/signer migrations before adding new tables:
  `api_keys`, `policies`, `policy_assignments`, `wallet_index`,
  `key_exports`, `approvals`, `audit_events`, webhook categories,
  observability tables, signer wallet tables, wallet auth methods, WebAuthn
  tables, Email OTP tables, and signing-root secret share tables.
- Add migration notes for wallet-scoped records that become capability-scoped,
  principal-scoped, tenant/project/environment-scoped, or capability-local MPC
  records.
- Add row parsers at the adapter boundary.
- Add tenant indexes, replay indexes, CHECK constraints, and seed policies.
- Store raw OTPs, grant tokens, refresh tokens, vault secrets, auth headers, and
  signer material only as hashes, sealed envelopes, or external references.

Check:

- A vault-only tenant can persist principals, factors, sessions, capability
  grants, capability instances, vaults, and vault items without signer material.
- A service-account principal can persist API credentials, grant-request scopes,
  capability bindings, and capability grant policy records.
- Console roles, API scopes, policy assignment scopes, and seed data can express
  vault-only and auth-only tenants without wallet-operation roles.
- Raw provider rows and old wallet-session rows cannot enter core logic.

## Phase 2A: AuthService Mechanical Module Split

Goal: split `packages/sdk-server-ts/src/core/AuthService.ts` into smaller source
modules without changing behavior, route contracts, storage semantics, public
exports, or runtime wiring. This is a mechanical bug-fixing and cleanup
preparation pass: smaller modules should make current bugs easier to localize
and make obsolete AuthService-era paths obvious before the D1/capability-port
cleanup deletes them.

Rules:

- Move code mechanically. Do not rename domain concepts, change request/response
  shapes, introduce new service ports, or add compatibility paths.
- Keep `AuthService` as the temporary assembler class and public facade.
- Extract pure helpers first. Move stateful public methods only when their
  dependencies are explicit and small.
- Leave a method in `AuthService` when moving it would require a broad
  `AuthServiceContext`, callback bag, or object full of class internals.
- Do not create one-method wrapper classes. Use plain functions and narrow
  module-local helper types.
- Keep trust-boundary parsing and validation behavior externally equivalent.
- Keep tests focused on compile/type-check and a small smoke path. This phase is
  limited to a mechanical split; auth authority, D1 ports, and capability
  modules stay in later phases.
- Do not create a `legacy/`, `compat/`, `postgres/`, or generic fallback module.
  If a path looks obsolete after the D1 migration, record it as a delete
  candidate instead of giving it a new home.

Target first-pass module shape:

```text
packages/sdk-server-ts/src/core/authService/
  index.ts
  AuthService.ts
  ids.ts
  wasm.ts
  webauthn.ts
  emailOtp/
    challenge.ts
    config.ts
    delivery.ts
    enrollment.ts
    grant.ts
    outbox.ts
    rateLimit.ts
    recovery.ts
    registrationAttempt.ts
    seal.ts
    unlock.ts
    index.ts
  googleOidc.ts
  oidcExchange.ts
  walletRegistration.ts
  walletStores.ts
  recovery.ts
  nearAccounts.ts
  thresholdEd25519.ts
  thresholdEcdsa.ts
  transactions.ts
```

Do:

- Add an AuthService split inventory before moving code. For each method/helper
  cluster, record current callers, current D1-backed owner if one exists,
  whether the path is still active, and the replacement path when it appears
  duplicated.
- Move top-level diagnostics, random-id, JWT, and WASM-location helpers into
  focused files under `authService/`. Delete unused helper candidates during
  the import audit.
- Move WebAuthn login/sync/credential-binding helpers and methods into
  `authService/webauthn.ts`.
- Move Email OTP challenge, enrollment, unlock, registration-attempt, recovery,
  outbox, seal, delivery, config, grant, and rate-limit helpers into
  `authService/emailOtp/*` files by lifecycle owner.
- Move Google login and generic OIDC JWKS/exchange helpers into
  `authService/googleOidc.ts` and `authService/oidcExchange.ts`.
- Move registration intent, wallet allocation, registration ceremony, and
  registration-finalize helpers into `authService/walletRegistration.ts`.
- Move store getters with their owning domain. WebAuthn stores live with
  WebAuthn, Email OTP stores live under `authService/emailOtp/`, wallet
  metadata/auth-method store helpers live in `authService/walletStores.ts`, and
  recovery stores live with recovery. Do not add a catch-all `stores.ts`.
- Move recovery session/execution helpers into `authService/recovery.ts`.
- Move NEAR account creation, funding, access-key checks, transaction dispatch,
  and gas-router signing helpers into `authService/nearAccounts.ts` and
  `authService/transactions.ts`.
- Move threshold Ed25519/ECDSA bootstrap, inventory, export, and signer WASM
  helpers into `authService/thresholdEd25519.ts` and
  `authService/thresholdEcdsa.ts`.
- Leave the constructor, config normalization handoff, public facade method
  exports, and assembly fields in `authService/AuthService.ts`.
- Re-export `AuthService` from the existing
  `packages/sdk-server-ts/src/core/AuthService.ts` path so package consumers do
  not change during this mechanical split. Treat that path as the canonical
  public barrel while `AuthService` exists.
- Audit route imports after each split pass. Routes should import the public
  `AuthService` facade during this phase and route ports after Phase 3. Do not
  add a source guard for this temporary boundary.
- Add a delete-candidate ledger for stale or duplicated AuthService-era paths.
  Each entry should name the symbol/path, why it appears obsolete, the current
  D1/capability path that replaces it, and the phase that will delete it.

Split inventory:

| Cluster | Current owner | Status | Next action |
| --- | --- | --- | --- |
| WebAuthn/OIDC boundary parsing and provider loading | `core/authService/webauthnOidcHelpers.ts` | Active provider helper | Keep behind `AuthService` facade until WebAuthn route ports land. |
| NEAR private-key transaction signing helpers | `core/authService/nearPrivateKeySigning.ts` | Active facade helper | Keep isolated from D1 route adapters; no route imports. |
| Random ID generation | `core/authService/bytes.ts` | Active facade helper | Reuse from remaining facade methods; move callers with owning domains later. |
| Boundary object guard | `core/authService/record.ts` | Active boundary helper | Replace only raw boundary checks; do not use for core domain objects. |
| Signer WASM URL resolution | `core/authService/signerWasmUrls.ts` | Active provider helper | Keep module-local source and built-package candidates. |
| Threshold store configuration summary | `core/authService/thresholdStoreSummary.ts` | Active diagnostics helper | Keep config diagnostics in helper; no service selection side effects. |
| WebAuthn login/listing helpers | `core/authService/webauthn.ts` | Active facade helper | Keep behind `AuthService` facade until WebAuthn route ports land. |
| WebAuthn sync-account helpers | `core/AuthService.ts` | Active facade methods | Move only after the threshold/session dependencies are narrowed enough to avoid a broad context bag. |
| Email OTP challenge, enrollment, unlock, registration, recovery | `core/AuthService.ts` plus D1 route adapters | Active but duplicated ownership | Split by lifecycle owner; delete AuthService-era branches once D1 ports are canonical. |
| Wallet registration intent/ceremony/finalize helpers | `core/AuthService.ts` plus D1 registration services | Active but duplicated ownership | Route through D1 canonical adapters, then delete old AuthService authority paths. |
| Threshold Ed25519/ECDSA bootstrap, inventory, export | `core/AuthService.ts` plus threshold services and D1/DO stores | Active but too broad | Move pure helpers first; defer stateful split until 82B authority unions are stable. |
| NEAR account creation, funding, access-key checks, transactions | `core/AuthService.ts` | Active facade methods | Split into account and transaction modules only after method dependencies are explicit. |

Delete-candidate ledger:

| Candidate | Why it is stale or risky | Replacement | Delete phase |
| --- | --- | --- | --- |
| AuthService-era wallet registration authority branches | D1 registration is the canonical registration owner; duplicate authority branches caused passkey-only and Email OTP drift. | D1 registration route services plus typed Router API adapter ports. | Refactor 82 Phase 12 / Refactor 82B authority cleanup. |
| Passkey-only Ed25519 authority checks inside shared session paths | Shared Ed25519 session code must accept the discriminated auth authority, not assume `passkey_rp` or `rpId`. | `WalletAuthAuthority` / auth-specific authority unions from Refactor 82B. | Refactor 82B. |
| AuthService generic registration bootstrap/finalize surfaces used by Cloudflare D1 routes | They keep old AuthService request shapes alive beside D1 request models. | D1 route adapter boundary with raw parsing at route/persistence edges only. | Refactor 82 Phase 12. |
| Helper code that only supports removed registration diagnostics | The extracted diagnostics module had no active callers after import audit. | None; deleted instead of moved. | Completed July 3, 2026. |

Progress:

- [x] July 3, 2026: First mechanical helper extraction completed.
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
- [x] July 3, 2026: Split inventory and delete-candidate ledger added before
  moving stateful methods. The ledger names active helper owners, duplicated
  AuthService/D1 ownership, and delete phases for stale registration/session
  authority paths.
- [x] July 3, 2026: Second pure helper extraction completed. Random-id helpers
  moved to `core/authService/bytes.ts`, boundary object checks to
  `core/authService/record.ts`, signer WASM URL resolution moved to
  `core/authService/signerWasmUrls.ts`, and threshold-store diagnostics moved to
  `core/authService/thresholdStoreSummary.ts`. The import audit deleted the
  unused timing helper instead of preserving stale diagnostics surface.
  `packages/sdk-server-ts` typecheck passed after the move.
- [x] July 3, 2026: Additional pure helper extraction completed without route
  imports or broad dependency bags. WebAuthn authority and wallet-binding
  helpers moved to focused modules, portable crypto helpers moved to
  `core/authService/portableCrypto.ts`, threshold ECDSA key inventory helpers
  moved to `core/authService/thresholdEcdsaKeyInventory.ts`, threshold runtime
  policy helpers moved to `core/authService/thresholdRuntimePolicy.ts`, and
  wallet-registration planning helpers moved to
  `core/authService/walletRegistrationPlanning.ts`.
- [x] July 3, 2026: Review pass completed for the current mechanical split.
  Router modules still import the public `AuthService` facade rather than
  `core/authService/**` internals. Extracted modules do not import Cloudflare D1
  route adapters, Express handlers, React, browser SDK code, or tests. No
  `AuthServiceContext`, `AuthServiceDeps`, or similar broad dependency bag was
  introduced. Line count: `AuthService.ts` is now 10,250 lines; live helper
  modules contain 1,052 lines total.
- [x] July 3, 2026: WebAuthn login/listing slice moved into
  `core/authService/webauthn.ts`. `AuthService` now delegates WebAuthn
  registration-credential verification, lite assertion verification,
  authenticator listing, login option creation, and login verification through
  explicit `WebAuthn*Store` and `IdentityStore` inputs. No route imports were
  changed, and no broad dependency bag was introduced. Line count:
  `AuthService.ts` is now 9,843 lines; live helper modules contain 1,776 lines
  total.
- [x] July 3, 2026: AuthService mechanical split checkpoint completed. The
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
- [x] July 3, 2026: Follow-up AuthService split pass moved Google Email OTP/OIDC
  wallet-resolution facade logic into
  `core/authService/googleEmailOtpOperations.ts` and threshold ECDSA route-facing
  forwarding into `core/authService/thresholdEcdsaOperations.ts`. The public
  method names and route contracts stayed on `AuthService`; routes still have no
  direct imports of `core/authService/**`, no `AuthServiceContext`/`AuthServiceDeps`
  bag was introduced, and the new extracted modules contain no `any`. Line count:
  `core/authService/AuthService.ts` is now 1,908 lines.
- [x] July 3, 2026: Email OTP public challenge composition moved into
  `core/authService/emailOtpChallengeOperations.ts`. `AuthService` now delegates
  login challenge issuing, enrollment challenge issuing, device-recovery
  challenge issuing, login grant minting, and device-recovery consume-grant
  minting through an explicit Email OTP challenge operation input. Route
  contracts stayed on the public `AuthService` facade; no route imports of
  `core/authService/**`, broad `AuthServiceContext`/`AuthServiceDeps` bag, or
  legacy compatibility path was introduced. Line count:
  `core/authService/AuthService.ts` is now 1,761 lines.
- [x] July 3, 2026: AuthService runtime state moved into
  `core/authService/runtime.ts`. `AuthService` now keeps signer-WASM readiness,
  relayer public-key derivation, and service initialization state in one typed
  runtime state object while the facade still owns assembly. Route and app
  imports were audit-checked rather than guarded because this facade boundary is
  temporary. `core/authService/AuthService.ts` is now 1,751 lines.
- [x] July 3, 2026: Phase 2A mechanical split closure review completed.
  Remaining methods in `core/authService/AuthService.ts` are constructor/config
  assembly, store wiring, runtime warm-up, or thin delegates whose next split
  belongs with Phase 3 route ports or Refactor 82B authority unions. Moving
  those now would require a broad context bag or route-contract churn, so the
  mechanical split stops here.
- [x] July 3, 2026: Identity and app-session version facade logic moved into
  `core/authService/identity.ts`. `AuthService` now delegates identity listing,
  identity linking/unlinking, app-session version creation, rotation, and
  validation through an explicit `IdentityStore` input. Result types are modeled
  as branch unions in the helper module instead of the previous broad optional
  result object. Line count: `AuthService.ts` is now 8,776 lines; live helper
  modules contain 3,198 lines total.
- [x] July 3, 2026: OIDC facade result shaping and provider-subject identity
  linking moved into `core/authService/oidcVerification.ts`. `AuthService` now
  supplies only OIDC config, JWKS cache state, and `IdentityStore` to the helper.
  The typecheck also exposed a partially deleted Router A/B ECDSA key-identities
  route; the stale shared path, parser, Express route, route definition, and type
  fixture are now consistently removed instead of reintroduced. Line count:
  `AuthService.ts` is now 8,657 lines; live helper modules contain 3,361 lines
  total.
- [x] July 3, 2026: WebAuthn sync-account option creation moved into
  `core/authService/webauthn.ts`. The moved helper takes only
  `WebAuthnSyncChallengeStore` and `WebAuthnCredentialBindingStore`; sync
  verification remains in `AuthService` until its threshold/session dependencies
  can be split without a broad context bag. Line count: `AuthService.ts` is now
  8,567 lines; live helper modules contain 3,473 lines total.
- [x] July 3, 2026: NEAR public-key metadata record/list logic moved into
  `core/authService/nearPublicKeyMetadata.ts`. `AuthService` now delegates
  metadata persistence and listing through an explicit `NearPublicKeyStore`
  input and keeps route-facing method names stable. Line count:
  `AuthService.ts` is now 8,491 lines; live helper modules contain 3,642 lines
  total.
- [x] July 3, 2026: Recovery session/execution facade tracking moved into
  `core/authService/recoveryTracking.ts`. `AuthService` now delegates recovery
  session reads, status updates, execution reads/lists, and execution recording
  through explicit `RecoverySessionStore` and `RecoveryExecutionStore` inputs.
  The D1 adapter still owns its canonical route implementation until Refactor
  82 cleanup collapses the remaining parallel AuthService-era surfaces. Line
  count: `AuthService.ts` is now 8,332 lines; live helper modules contain 3,982
  lines total.
- [x] July 3, 2026: NEAR RPC and relayer transaction helper logic moved into
  `core/authService/nearTransactions.ts`. `AuthService` now delegates
  access-key listing, signed Borsh dispatch, account-existence checks,
  access-key visibility checks, transaction context fetching, and gas-router
  transaction signing through explicit `MinimalNearClient`, relayer key, and
  logger inputs. Account creation and delegate execution remain in the facade
  because they still coordinate queueing and higher-level registration
  semantics. Line count: `AuthService.ts` is now 8,238 lines; live helper
  modules contain 4,204 lines total.
- [x] July 3, 2026: Wallet ID allocation helpers were removed from
  `AuthService.ts` and kept in `core/authService/walletRegistrationPlanning.ts`.
  The canonical helper module now owns server-allocated wallet ID reservation,
  provided implicit wallet ID reservation, generic wallet selection, and
  signer-plan-aware registration wallet selection. The D1 registration intent
  service still has a parallel local copy because router code must not import
  `core/authService/**` internals during this mechanical split; collapse that
  duplicate through the Refactor 82 route-port cleanup. Line count:
  `AuthService.ts` is now 8,108 lines; live helper modules contain 4,338 lines
  total.
- [x] July 3, 2026: Email OTP Shamir seal cipher setup moved into
  `core/authService/emailOtpSeal.ts`. `AuthService` now reads the four raw seal
  config values and delegates typed key-version, Shamir-prime, and cipher
  construction to the helper. Remaining local random/masking wrapper methods
  were also removed in favor of direct calls to the extracted helper functions.
  This keeps config-boundary validation isolated without adding a new service
  object. Line count: `AuthService.ts` is now 8,047 lines; live helper modules
  contain 4,415 lines total.
- [x] July 3, 2026: Email OTP boundary utility slice moved out without changing
  the public facade. Config/env reads moved to
  `core/authService/configValues.ts`, OTP policy parsing and masking moved to
  `core/authService/emailOtpConfig.ts`, OTP delivery moved to
  `core/authService/emailOtpDelivery.ts`, shared random ID/code generation
  moved into `core/authService/bytes.ts`, and Email OTP plus registration
  prepare rate-limit consumption moved to `core/authService/rateLimits.ts`.
  `AuthService` still owns the stores, caches, and public methods. Line count:
  `AuthService.ts` is now 9,485 lines; live helper modules contain 2,424 lines
  total. `packages/sdk-server-ts` typecheck passed after the move.
- [x] July 3, 2026: Threshold ECDSA inventory facade loop moved into
  `core/authService/thresholdEcdsaKeyInventory.ts`. `AuthService` now passes the
  threshold service and logger explicitly; route imports and public method
  signatures stayed unchanged. Line count: `AuthService.ts` is now 9,403 lines;
  live helper modules contain 2,521 lines total. `packages/sdk-server-ts`
  typecheck passed after the move.
- [x] July 3, 2026: OIDC verification moved into
  `core/authService/oidcVerification.ts`. `AuthService` now owns only provider
  subject linking and delegates JWT parsing, JWKS fetch/cache, signature
  validation, issuer/audience/time checks, and Google claim extraction to the
  helper. Route imports remain behind the public facade. Line count:
  `AuthService.ts` is now 8,825 lines; live helper modules contain 3,061 lines
  total. `packages/sdk-server-ts` typecheck passed after the move.
- [x] July 3, 2026: Email OTP registration challenge-proof and challenge-purpose
  boundary modeling moved into `core/authService/emailOtpChallengeProof.ts`.
  `AuthService` now imports the typed proof, verified challenge, challenge
  purpose, and recovery escrow redaction helpers instead of defining them
  inline. The move keeps raw request proof parsing at the boundary and preserves
  the public facade. Line count: `AuthService.ts` is now 7,523 lines; live
  helper modules contain 4,978 lines total. `packages/sdk-server-ts` typecheck
  passed after the move.
- [x] July 3, 2026: Registration threshold helper code moved into
  `core/authService/registrationThresholdHelpers.ts`. The helper owns
  threshold-Ed25519 registration input parsing, bootstrap session normalization,
  ECDSA bootstrap identity comparison, ECDSA wallet-key derivation from server
  bootstrap output, and NEAR add-key bootstrap action construction. `AuthService`
  still coordinates stores and route-facing methods. Line count:
  `AuthService.ts` is now 7,206 lines; live helper modules contain 5,337 lines
  total. `packages/sdk-server-ts` typecheck passed after the move.
- [x] July 3, 2026: Signer WASM runtime setup and more Email OTP lifecycle
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
- [x] July 3, 2026: Rate-limit backend construction moved out of
  `AuthService.ts` and into `core/authService/rateLimits.ts`. The helper now
  owns raw limiter-kind parsing and environment/config-backed limiter
  construction for Email OTP and registration-prepare throttles, while
  `AuthService` only caches limiter instances and delegates consumption. No
  route imports of helper internals were added. Line count: `AuthService.ts` is
  now 6,044 lines; live helper modules contain 7,122 lines total.
  `packages/sdk-server-ts` typecheck passed after the move.
- [x] July 3, 2026: Email OTP challenge cleanup and active-challenge limiting
  moved into `core/authService/emailOtpChallenges.ts`. The helper owns
  challenge-store expiry pruning, active-context cap enforcement, and associated
  memory-outbox cleanup through explicit store and outbox inputs. `AuthService`
  still owns request parsing and challenge issuance orchestration. Line count:
  `AuthService.ts` is now 6,037 lines; live helper modules contain 7,198 lines
  total. `packages/sdk-server-ts` typecheck and build passed after the move.
- [x] July 3, 2026: Public facade barrel move completed.
  `packages/sdk-server-ts/src/core/AuthService.ts` now re-exports the public
  `AuthService` class and Google Email OTP public result types from
  `core/authService/**`. The remaining implementation lives in
  `core/authService/AuthService.ts`; route and router layers still import the
  public facade path only. Line count: public `AuthService.ts` is now 7 lines,
  `authService/AuthService.ts` is 6,037 lines, and focused helper modules
  contain 7,198 lines total. `packages/sdk-server-ts` typecheck and build passed
  after the move.
- [x] July 3, 2026: Email OTP challenge issuance moved into
  `core/authService/emailOtpChallenges.ts`. The helper now owns request-boundary
  parsing, active challenge reuse, challenge rate limiting, challenge record
  persistence, delivery rollback, and delivery result shaping through explicit
  operation ports. `AuthService` still owns stores, limiter caches, and the
  public method signatures. `packages/sdk-server-ts` typecheck passed after the
  move.
- [x] July 3, 2026: Email OTP unlock challenge issuance and unlock-proof
  verification moved into `core/authService/emailOtpUnlock.ts`. The helper owns
  unlock challenge creation, secp256k1 unlock proof validation, challenge
  consumption, and Email OTP login auth-state marking through explicit operation
  ports. No route imports of helper internals were added. Line count:
  `authService/AuthService.ts` is now 5,509 lines and focused helper modules
  contain 7,905 lines total. `packages/sdk-server-ts` typecheck passed after the
  move.
- [x] Active Email OTP verification/recovery and WebAuthn helper clusters that
      can move without a broad dependency bag have moved. Remaining helper
      movement is deferred to route ports and typed authority cleanup.

Check:

- `packages/sdk-server-ts/src/core/AuthService.ts` becomes a small public barrel
  or thin re-export.
- `authService/AuthService.ts` contains assembly and delegation only; it should
  shrink below 2,000 lines before Phase 3 begins.
- Every moved module has a single stated owner and a current runtime purpose:
  active facade, active D1-backed path, active provider helper, or
  delete-candidate.
- No route file gains a new direct dependency on moved helper modules.
- No moved module imports Cloudflare D1 route adapters, Express handlers, React,
  browser SDK code, or tests.
- Public package exports and existing route wiring typecheck unchanged.
- No `AuthServiceContext`, `AuthServiceDeps`, or similar broad dependency bag is
  introduced.
- Duplicated legacy candidates are listed with replacements before Phase 3 route
  port work starts.
- Line count for the old monolith is recorded before and after the split.

## Phase 3: Route And D1 Ports

Goal: stop exposing monolithic service surfaces to routes, and avoid creating a
second route-port registry beside route modules.

Do:

- Replace router-facing `Pick<AuthService, ...>` with a service map keyed by the
  same `RouteServiceKey` values declared by route modules.
- Split `CloudflareD1RouterApiAuthMetadataService` into D1-backed adapters for
  session, auth provider, auth factors, authorization, wallet, recovery,
  Ed25519 MPC, and ECDSA MPC.
- Split Node `apps/web-server` assembly into the same narrow ports used by
  Cloudflare and Express. It should construct enabled modules from config rather
  than directly wiring wallet, threshold, signing-session seal, router, and
  console services together.
- Update self-hosted Cloudflare Worker examples to use capability modules and
  explicit MPC-only assembly instead of constructing `AuthService` directly.
- Keep `AuthService` and the old D1 facade as temporary assemblers only.
- Delete facade methods as routes move to owning ports.

Check:

- Route handlers can access only declared service methods.
- Changes to wallet/threshold services do not typecheck through unrelated auth,
  vault, IdP, or session routes.
- Node web-server, Cloudflare, Express, and self-hosted Worker examples share
  the same route module manifest decisions.

## Phase 4: Seams Authorization Core

Goal: build the authorization module that owns grant evidence, grants, policy,
digests, budgets, and audit envelopes. Session lifecycle belongs in the
`session/` module and feeds authorization as evidence.

Do:

- Create internal `authorization/` and `session/` source modules first. Defer
  package extraction until the module boundary is stable.
- Implement session exchange domain types, session lifecycle parsing, operation
  digest envelopes, policy evaluation, grant lifecycle, replay checks, and audit
  envelopes.
- Implement the generic grant issuer:
  `CapabilityGrantRequest` + `GrantEvidenceRef[]` + capability binding + operation
  envelope + `CapabilityGrantPolicy` -> `CapabilityGrant`.
- Implement two evidence providers first: `seams_session` and
  `service_account_api_key`.
- Implement fail-closed `mpc_signer_proof` evaluation.
- Add architecture guards proving auth provider adapters cannot mint grants.

Check:

- A synthetic capability operation can be authorized without vault or MPC imports.
- A service-account API key can request only policy-approved, short-lived
  grants for bound capabilities through `service_account_api_key` evidence.
- Missing/inactive/mismatched MPC proof-producing capability fails closed.

## Phase 5: Seams Auth Provider

Goal: normalize external login evidence into `SeamsSession`.

Do:

- Use Better Auth first through `betterAuthSessionProvider(auth)`.
- Implement `exchangeAuthProviderEvidence(command)` for Better Auth, Seams
  native factors, OIDC, wallet-login proof, and refresh.
- Add `seamsPasskeyGrantEvidence()` as a Better Auth plugin bridge.
- Add `seamsAuth({ database, ... })` plus D1/PostgreSQL-compatible adapters.
- Implement multi-session revoke, forced logout, refresh rotation, and refresh
  family replay handling.

Check:

- All login paths create `SeamsSession` through the same exchange boundary.
- Session exchange cannot mint grants, provision capabilities, or satisfy grant
  evidence requirements by itself.

## Phase 6: Route Policy V2

Goal: make route auth speak management, session, and exact capability grants.

Do:

- Replace `console`, `api_credentials`, `user_session`, and `threshold_session`
  with `management_console`, `management_api_key`, `seams_session`, and
  `capability_grant`.
- Add `ManagementOperationKind`, `ManagementResourceScope`, capability kind,
  operation kind, and grant use.
- Resolve console users and API keys into tenant-scoped principals.
- Replace wallet-only API scopes with the management scope taxonomy from the
  SPEC.
- Split API credential scopes into management scopes and capability grant-request
  scopes. Operation grant-request scopes can ask for a grant; they cannot reveal
  secrets, inject credentials, export keys, or sign by themselves.
- Replace console RBAC role names that are wallet-operation-specific with
  management roles that can govern auth, vault, IdP, and MPC capabilities.
- Add service-account capability grant policies for phase-one automation:
  `vault.proxy.use`, `vault.rotate`, and optional non-production `mpc.sign`.
- Move `/session/exchange`, refresh, and revoke onto the new session exchange
  service.
- Move threshold-session claim parsing into MPC route handlers.

Check:

- Management roles and API scopes cannot satisfy capability-grant routes by
  themselves.
- Service-account API keys cannot directly call capability-grant routes; they
  must request and consume a short-lived grant.
- Old wallet-only API scopes are gone.
- Old wallet-operation console roles are gone or capability-local.

## Phase 6A: Service-Account Grant Evidence

Goal: support non-interactive automation as a first grant-evidence provider.

Do:

- Add service-account API keys that authenticate to `management_api_key`.
- Normalize a valid key into `GrantEvidenceRef` with
  `evidenceKind: "service_account_api_key"`.
- Add grant-request scopes:

```text
grants.request.vault_proxy_use
grants.request.vault_rotate
grants.request.mpc_sign
```

- Add `CapabilityGrantPolicy` records for service-account API-key evidence with
  service account, capability, operation kind, resource scope, max TTL, max
  uses, and environment limit.
- Require a matching `CapabilityBinding` before issuing a grant.
- Resolve policy server-side from service account, API key scope, capability
  binding, resource scope, operation kind, and environment.
- Mint one-use or short-TTL `CapabilityGrant` records.
- Defer OIDC workload federation, mTLS, KMS-bound proof, and customer workload
  identity adapters.

Check:

- A service-account API key with only management scopes cannot request
  capability grants.
- A service-account API key with grant-request scope still fails without a
  capability binding and capability grant policy.
- Phase-one capability grants allow vault proxy use and rotation.
- Reveal, export, break-glass, key export, and production high-risk signing
  remain blocked unless an explicit later policy enables them.

## Phase 7: Client Grant Evidence And Worker Split

Goal: make browser grant evidence generic while keeping vault-only/IdP-only bundles
free of MPC runtime code.

Do:

- Add `CapabilityGrantPlan` and `CapabilityGrantChallenge`.
- Replace shared `signingGrantId` fields with `capabilityGrantId`.
- Keep `thresholdSessionId` inside MPC branches.
- Split `passkey-confirm.worker.ts` into generic auth confirmation and MPC
  capability workers.
- Make generic confirmation workers return `GrantEvidenceRef` records, then let
  Seams authorization mint grants.
- Move threshold warm-session cache, signer WASM, HSS, chain adapters, and
  wallet restore code out of generic confirmation paths.
- Split `UiConfirmManager` into generic confirmation coordination and MPC
  signing coordination.
- Split public browser entrypoints so auth-only and vault-only imports do not
  traverse `./advanced`, `./threshold`, `./worker`, `./wasm`, wallet iframe
  signer hosts, or signing-engine modules.
- Add export-map source guards for `@seams/sdk`, `@seams/sdk-server`, and
  `@seams-internal/shared-ts`.

Check:

- Vault/IdP prompts use generic confirmation without signing-engine imports.
- Vault-only and IdP-only bundles exclude MPC worker chunks and signer WASM.
- Public auth/vault entrypoints compile without importing MPC workers, signer
  WASM, threshold stores, HSS, or chain adapters.

## Phase 8: React And Lit UI Adapter

Goal: keep the UI shell while replacing wallet-first runtime assumptions.

Do:

- Keep `PasskeyAuthMenu`, Lit transaction confirmation, theme scope, and layout.
- Replace runtime ports so the shell can use Better Auth or current `SeamsWeb`
  flows.
- Rename wallet/account UI fields to auth-account/principal fields at the UI
  boundary.
- Hide wallet-only features behind capability checks.
- Point generic operation prompts at the auth confirmation worker.
- Load transaction confirmers and signer bridges only through MPC adapters.
- Update dashboard API clients and routes for team RBAC, API keys, approvals,
  policies, audit, key exports, wallets, and future vault pages so each route is
  classified as management, session, capability grant, or capability-local MPC.
- Update docs app pages and diagrams that teach wallet sessions, signing
  sessions, and auth planes so public documentation matches the new vocabulary
  or is marked capability-local.

Check:

- Vault-only and IdP-only tenants do not see wallet controls.
- Seams passkey grant evidence works without local wallet signer metadata.
- Docs and dashboard pages do not present wallet-only terms as generic auth.

## Phase 9: Capability Modules

Goal: move capability-specific operation lanes, intents, and display data out of
shared auth.

Do:

- Define `vault_access`, `near_ed25519_mpc_signing`, and
  `evm_ecdsa_mpc_signing`.
- Move Ed25519 and ECDSA operation lane and intent construction into their
  capability modules.
- Define vault operation lanes for proxy use, reveal, export, permission
  change, and break-glass reveal.
- Add `produceAuthProof` to MPC capabilities.
- Validate capability grant policies against registered grant evidence kinds and
  capability operation descriptors.

Check:

- Vault-only compilation excludes MPC modules.
- Ed25519, ECDSA, and vault operation lanes are not interchangeable.

## Phase 10: Registration And Provisioning

Goal: make account creation auth-first.

Do:

- Create only auth account, principal, factor, device, and session records by
  default.
- Add explicit capability provisioning.
- Promote the Phase 0A signer-set request into protected capability
  provisioning. Wallet registration should request MPC capabilities through the
  same capability list used by vault and future capabilities.
- Support vault-only registration and wallet registration with requested
  capabilities.
- Keep embedded wallet login as an auth factor independent of signer material.
- Delete automatic signer provisioning from auth-only registration.

Check:

- New auth accounts do not create signer records unless provisioning requests
  them.
- Phase 0A signer-set branch identities map cleanly to protected capability
  records or capability provisioning identities.

## Phase 11: Route Module Assembly And Runtime Adapters

Goal: evolve the existing router module system into runtime-neutral capability
route manifests and runtime-specific handler factories.

Do:

- Evolve `RouterApiModule` from extension-only modules into runtime-neutral
  route manifests.
- Add module-owned route definitions, required service ports, capability
  metadata, import guards, and runtime-specific handler factories.
- Replace the static Cloudflare handler list with registered modules.
- Add modules for auth, session, IdP, vault, Ed25519 MPC, and ECDSA MPC.
- Assemble modules through named builders such as
  `buildCloudflareRouteModules(...)`. The builder may use normal `if` blocks
  and a final spread to combine base and optional module lists; do not use
  spread-plus-ternary arrays for optional modules.
- Keep Express only as a thin adapter over the same modules, or remove it.
- Delete duplicated Express route implementations when they cannot consume the
  shared module contract.
- Move Node web-server startup to the same module manifest and runtime handler
  factory model.
- Keep self-hosted Worker examples capability-specific. A signing-only example
  should remain MPC-only, and a future vault example should omit signer WASM.

Check:

- Disabled capabilities are absent from route tables and bundles.
- Cloudflare bundles do not import Express handlers.
- Retained Express routes match Cloudflare route policy, parser, service
  requirements, and response envelope.
- Node web-server and example Workers cannot mount disabled capability routes by
  accident.

## Phase 12: Vault Integration

Goal: connect the vault to Seams authorization and team RBAC.

Do:

- Implement vault access through `SeamsSession`, `GrantEvidenceRef`, and
  `CapabilityGrant`.
- Enforce vault operation lanes, `direct_member`, `delegate_member`, proxy-only
  use, reveal, export, permission change, and break-glass.
- Support service-account capability grants for vault proxy use and rotation.
- Add optional MPC-backed authorization for high-assurance tenants.
- Audit tenant, principal, capability, operation, lane digest, intent digest,
  display digest, evidence, and device.

Check:

- Humans and agents share the principal model.
- Delegate access can use secrets through proxy without receiving plaintext.
- Service accounts can use vault proxy and rotation grants without reveal/export
  authority.

## Phase 13: IdP Integration

Goal: let Seams act as an identity provider.

Do:

- Implement tenant OIDC discovery, JWKS, authorization-code + PKCE, token issue,
  refresh rotation, reuse detection, revocation, relying-party config, and claim
  policies.
- Keep IdP tokens separate from Seams capability grants.
- Add optional grant evidence requirements for high-risk scopes.

Check:

- Relying-party apps can use Seams login.
- Tokens never contain vault secrets, signer material, raw OTPs, raw auth
  headers, or operation-grant IDs.

## Phase 14: Deletion And Hardening

Goal: delete obsolete paths once new boundaries own the flows.

Do:

- Delete old signing-session terminology and old route planes.
- Delete `SigningAuthPlan`, signer-auth aliases, wallet-only API scopes,
  auto-signer registration paths, and any remaining legacy fixtures.
- Delete or capability-localize old public exports whose names imply wallet-only
  auth, wallet sessions, signing sessions, threshold sessions, or signer grants.
- Delete generic imports of MPC confirmation workers, threshold stores, signer
  WASM, HSS, chain adapters, and wallet UI.
- Delete duplicated Express behavior if Express is retained through shared
  modules.
- Delete public docs, diagrams, source guards, and helper scripts that preserve
  obsolete generic terminology.

Check:

- Vault-only, IdP-only, wallet-only, and full-platform builds pass targeted
  tests.
- Import guards cover the intended boundaries.

## Validation Plan

Static checks:

- Phase 0C inventory ledger exists and every row has an owner, phase, action,
  and validation check.
- Domain records require tenant, principal/session/capability IDs where
  applicable.
- Raw provider rows, decoded tokens, route bodies, and DB rows are parsed once at
  boundaries.
- Auth accounts cannot include signer material.
- Capability grant policies cannot reference unregistered grant evidence.
- Vault-only/IdP-only entry points cannot import MPC workers, signer WASM, HSS,
  threshold stores, chain adapters, or wallet UI.
- Management/API-key principals cannot satisfy capability-grant routes
  without short-lived grants.
- Public export maps expose auth/vault entrypoints that stay free of MPC imports.
- Source guards reject old generic terms outside capability-local modules:
  `signing-session`, `signingGrantId`, `thresholdSessionId`,
  `threshold_session`, `user_session`, wallet-only `AuthMethod`, and wallet-only
  API credential scopes.
- Parked workspaces such as `voiceId` cannot import auth core internals unless
  a future phase promotes them to `GrantEvidenceKind`.

Targeted tests:

- Better Auth session -> `SeamsSession`.
- Session exchange creation, refresh, revoke, replay denial, and tenant
  isolation.
- Frontend demo, SDK React components, SeamsWeb operations, and browser workers
  compile against the new owner map.
- Seams passkey grant-evidence challenge and verify.
- Grant lifecycle, digest mismatch, expiry, replay, and consumption.
- Management route policy and API scope parsing.
- Service-account API key grant request: management-only denial, missing binding
  denial, missing capability grant policy denial, successful vault proxy-use
  grant, and reveal/export denial.
- Console RBAC, API keys, policies, approvals, key exports, audit, webhooks, and
  wallet index routes compile against the new management/capability owner map.
- Router module construction, duplicate rejection, and Cloudflare/Express
  manifest parity when Express is retained.
- Node web-server startup, self-hosted Worker examples, and local test servers
  mount only enabled capability modules.
- Vault proxy use, reveal/export, permission change, break-glass, and
  delegate-member denial.
- `mpc_signer_proof` missing capability, inactive capability, principal
  mismatch, unsupported operation, and success.
- IdP OIDC flow, JWKS rotation, refresh-token rotation/replay, and claim policy.
- Bundle/dependency checks for vault-only, IdP-only, MPC-only, and full-platform
  browser runtimes.
- Package export smoke tests for `@seams/sdk`, `@seams/sdk-server`, and
  `@seams-internal/shared-ts` auth-only, vault-only, MPC-only, and full-platform
  imports.

Security tests:

- Auth provider outputs, IdP tokens, refresh tokens, and session exchange cannot
  mint Seams grants.
- Reused, expired, cross-session, cross-tenant, cross-origin, cross-device, and
  digest-mismatched challenges fail closed.
- Vault-only sessions cannot call MPC signing endpoints.
- Delegates cannot reveal or export vault secrets.
- Audit records omit signer secrets, vault secrets, raw OTPs, and raw auth
  headers.
- Sealed session, Email OTP, and grant-evidence records do not reuse wallet or
  threshold identifiers as generic auth identifiers.

## Open Questions

- Should the public SDK expose `SeamsSession`?
- Should `vault_access` be provisioned automatically for every tenant?
- Should Ed25519 and ECDSA MPC capabilities be provisioned separately by default?
- Which MPC capability should produce `mpc_signer_proof` by default?
- Which customer signal should trigger SAML support after the OIDC IdP path
  ships?
- Should embedded wallet login be a default auth factor for wallet customers?
- Should VoiceID become a future `GrantEvidenceKind`, or remain a separate
  optional workspace until the auth/capability split is stable?
- Which IdP scopes require additional grant evidence by default?
- Should audit writing live in `seams-authorization` or `audit-core`?

## Related Docs

- [Modular Auth And Capability Refactor SPEC](./refactor-87-modular-auth-capabilities-SPEC.md)
- [Centaur Secrets Vault Architecture Plan](./centaur-secrets-vault.md)
- [Slack OTP Step-Up Spec](./otp-slack.md)
- [Optional HSS Bootstrap Profiles](./refactor-8X-hss-optional.md)
- [Step-Up Adaptor Refactor Plan](./refactor-34b-stepup-adaptor.md)
