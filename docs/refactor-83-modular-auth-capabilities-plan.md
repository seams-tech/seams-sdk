# Modular Auth And Capability Refactor Plan

Date created: June 28, 2026

Status: planning. Phase 0A is complete through Refactor 82 Phase 8; the remaining
phases are still planning.

Companion spec: [Modular Auth And Capability Refactor SPEC](./refactor-83-modular-auth-capabilities-SPEC.md).

This document is the implementation checklist. Requirements, architecture
decisions, domain sketches, persistence defaults, and security model live in the
companion SPEC.

## Implementation Rules

- Keep the completed signer-set registration cut intact so local D1 registration
  does not revive the `ed25519_and_ecdsa` cross-product request shape. Then ship
  the auth/capability vertical slice: Better Auth session -> `SeamsSession` ->
  vault proxy use -> passkey step-up -> vault reveal -> audit.
- Keep Better Auth as the development auth provider until Seams authorization is
  stable.
- Keep capability modules as typed route/service modules. Runtime plugin
  infrastructure can wait.
- Keep `mpc_signer_proof` optional. Baseline vault access must work without MPC.
- Use static route assembly plus import guards for Cloudflare Workers.
- Keep compatibility logic at request and persistence boundaries, then delete it.
- Delete wallet-first fixtures when they only protect obsolete behavior.

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
  account by default and provisions only requested `ProtectedCapability` records.
- `near_ed25519` becomes `near_ed25519_mpc_signing` capability provisioning.
- `evm_family_ecdsa` becomes `evm_ecdsa_mpc_signing` capability provisioning.
- The branch identity used by D1 ceremony state becomes the capability
  provisioning identity or `capabilityId` once Phase 10 lands.
- Vault-only, IdP-only, and auth-only registration paths must not create signer
  records or load signer/HSS/WASM code.
- Capability policies bind requested signer capabilities to registered auth
  factor kinds through Seams authorization, replacing the current wallet-first
  registration authority checks.

## Phase 0: Inventory

Goal: map current wallet-first coupling before moving code.

Do:

- Inventory `signing-session`, `signingGrantId`, `thresholdSessionId`,
  `SigningAuthPlan`, `WalletAuthIntent`, `WalletAuthCurve`, `AuthMethod`,
  `user_session`, and `threshold_session` call sites.
- Classify each route and method as auth provider, Seams authorization, auth
  factor, route assembly, vault, IdP, Ed25519 MPC, or ECDSA MPC.
- Record imports that pull threshold, HSS, signer WASM, chain, wallet UI, or
  recovery code into generic auth/router paths.
- Mark tests to preserve, rewrite, or delete.

Check:

- Every current auth/wallet/signing route has one target owner.
- Every shared type slated for deletion has a replacement.

## Phase 1: Shared Auth Vocabulary

Goal: define auth and sensitive-operation vocabulary independent of wallets.

Do:

- Add `AuthFactorKind`, tenant/principal/session/capability/grant IDs,
  `SeamsSession`, `StepUpAuthorization`, `SensitiveOperationIntent`,
  `SensitiveOperationGrant`, and `SensitiveOperationPolicy`.
- Add `MpcSignerProof` as a derived auth factor.
- Move `SignerAuthMethod` and `WalletAuthMethod` into capability-local code.
- Delete `AuthMethod = SignerAuthMethod`.

Check:

- Generic auth imports no signer domain files.
- Type fixtures reject invalid sessions, step-up records, grants, and signer
  fields on auth records.

## Phase 2: Persistence And Schema

Goal: make the SPEC persistence model concrete.

Do:

- Add migrations for shared auth/authorization tables, session refresh tokens,
  grants, capabilities, capability bindings, audit, and vault tables.
- Expand or replace console tables for principals, agents, vault approvals,
  capability provisioning, audit, and new API scopes.
- Add row parsers at the adapter boundary.
- Add tenant indexes, replay indexes, CHECK constraints, and seed policies.
- Store raw OTPs, grant tokens, refresh tokens, vault secrets, auth headers, and
  signer material only as hashes, sealed envelopes, or external references.

Check:

- A vault-only tenant can persist principals, factors, sessions, grants,
  capabilities, vaults, and vault items without signer material.
- Raw provider rows and old wallet-session rows cannot enter core logic.

## Phase 3: Route And D1 Ports

Goal: stop exposing monolithic service surfaces to routes.

Do:

- Replace router-facing `Pick<AuthService, ...>` with narrow route ports.
- Split `CloudflareD1RouterApiAuthMetadataService` into D1-backed adapters for
  session, auth provider, auth factors, authorization, wallet, recovery,
  Ed25519 MPC, and ECDSA MPC.
- Keep `AuthService` and the old D1 facade as temporary assemblers only.
- Delete facade methods as routes move to owning ports.

Check:

- Route handlers can access only declared service methods.
- Changes to wallet/threshold services do not typecheck through unrelated auth,
  vault, IdP, or session routes.

## Phase 4: Seams Authorization Core

Goal: build the package that owns sessions, step-up, grants, policy, digests,
budgets, and audit envelopes.

Do:

- Create `packages/seams-authorization/`.
- Implement session exchange domain types, session lifecycle parsing, operation
  digest envelopes, policy evaluation, grant lifecycle, replay checks, and audit
  envelopes.
- Implement fail-closed `mpc_signer_proof` evaluation.
- Add architecture guards proving auth provider adapters cannot mint grants.

Check:

- A synthetic sensitive operation can be authorized without vault or MPC imports.
- Missing/inactive/mismatched MPC proof-producing capability fails closed.

## Phase 5: Seams Auth Provider

Goal: normalize external login evidence into `SeamsSession`.

Do:

- Use Better Auth first through `betterAuthSessionProvider(auth)`.
- Implement `exchangeAuthProviderEvidence(command)` for Better Auth, Seams
  native factors, OIDC, SAML, wallet-login proof, and refresh.
- Add `seamsPasskeyStepUp()` as a Better Auth plugin bridge.
- Add `seamsAuth({ database, ... })` plus D1/PostgreSQL-compatible adapters.
- Implement multi-session revoke, forced logout, refresh rotation, and refresh
  family replay handling.

Check:

- All login paths create `SeamsSession` through the same exchange boundary.
- Session exchange cannot mint grants, provision capabilities, or satisfy
  operation step-up.

## Phase 6: Route Policy V2

Goal: make route auth speak management, session, and exact operation grants.

Do:

- Replace `console`, `api_credentials`, `user_session`, and `threshold_session`
  with `management_console`, `management_api_key`, `seams_session`, and
  `sensitive_operation`.
- Add `ManagementOperationKind`, `ManagementResourceScope`, capability kind,
  operation kind, and grant use.
- Resolve console users and API keys into tenant-scoped principals.
- Replace wallet-only API scopes with the management scope taxonomy from the
  SPEC.
- Move `/session/exchange`, refresh, and revoke onto the new session exchange
  service.
- Move threshold-session claim parsing into MPC route handlers.

Check:

- Management roles and API scopes cannot satisfy sensitive-operation routes by
  themselves.
- Old wallet-only API scopes are gone.

## Phase 7: Client Step-Up And Worker Split

Goal: make browser step-up generic while keeping vault-only/IdP-only bundles
free of MPC runtime code.

Do:

- Add `SensitiveOperationAuthPlan` and `SensitiveOperationChallenge`.
- Replace shared `signingGrantId` fields with `sensitiveOperationGrantId`.
- Keep `thresholdSessionId` inside MPC branches.
- Split `passkey-confirm.worker.ts` into generic auth confirmation and MPC
  capability workers.
- Move threshold warm-session cache, signer WASM, HSS, chain adapters, and
  wallet restore code out of generic confirmation paths.
- Split `UiConfirmManager` into generic confirmation coordination and MPC
  signing coordination.

Check:

- Vault/IdP prompts use generic confirmation without signing-engine imports.
- Vault-only and IdP-only bundles exclude MPC worker chunks and signer WASM.

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

Check:

- Vault-only and IdP-only tenants do not see wallet controls.
- Seams passkey step-up works without local wallet signer metadata.

## Phase 9: Capability Modules

Goal: move capability-specific lanes out of shared auth.

Do:

- Define `vault_access`, `near_ed25519_mpc_signing`, and
  `evm_ecdsa_mpc_signing`.
- Move Ed25519 and ECDSA lane construction into their capability modules.
- Define vault lanes for proxy use, reveal, export, permission change, and
  break-glass reveal.
- Add `produceAuthProof` to MPC capabilities.
- Validate operation policies against registered auth factor kinds.

Check:

- Vault-only compilation excludes MPC modules.
- Ed25519, ECDSA, and vault lanes are not interchangeable.

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

Goal: evolve the existing router module system into the capability route
assembly.

Do:

- Evolve `RouterApiModule` from extension-only modules into the canonical route
  module contract.
- Add module-owned route definitions, runtime handlers, required service ports,
  capability metadata, and import guards.
- Replace the static Cloudflare handler list with registered modules.
- Add modules for auth, session, IdP, vault, Ed25519 MPC, and ECDSA MPC.
- Keep Express only as a thin adapter over the same modules, or remove it.
- Delete duplicated Express route implementations when they cannot consume the
  shared module contract.

Check:

- Disabled capabilities are absent from route tables and bundles.
- Retained Express routes match Cloudflare route policy, parser, service
  requirements, and response envelope.

## Phase 12: Vault Integration

Goal: connect the vault to Seams authorization and team RBAC.

Do:

- Implement vault access through `SeamsSession`, `StepUpAuthorization`, and
  `SensitiveOperationGrant`.
- Enforce vault lanes, `direct_member`, `delegate_member`, proxy-only use, reveal,
  export, permission change, and break-glass.
- Add optional MPC-backed authorization for high-assurance tenants.
- Audit tenant, principal, capability, operation, lane, digest, factor, and
  device.

Check:

- Humans and agents share the principal model.
- Delegate access can use secrets through proxy without receiving plaintext.

## Phase 13: IdP Integration

Goal: let Seams act as an identity provider.

Do:

- Implement tenant OIDC discovery, JWKS, authorization-code + PKCE, token issue,
  refresh rotation, reuse detection, revocation, relying-party config, and claim
  policies.
- Keep IdP tokens separate from Seams operation grants.
- Add optional step-up for high-risk scopes.

Check:

- Relying-party apps can use Seams login.
- Tokens never contain vault secrets, signer material, raw OTPs, raw auth
  headers, or operation-grant IDs.

## Phase 14: Deletion And Hardening

Goal: delete obsolete paths once new boundaries own the flows.

Do:

- Delete old signing-session terminology and old route planes.
- Delete `SigningAuthPlan`, signer-auth aliases, wallet-only API scopes,
  auto-signer registration paths, and legacy fixtures.
- Delete generic imports of MPC confirmation workers, threshold stores, signer
  WASM, HSS, chain adapters, and wallet UI.
- Delete duplicated Express behavior if Express is retained through shared
  modules.

Check:

- Vault-only, IdP-only, wallet-only, and full-platform builds pass targeted
  tests.
- Import guards cover the intended boundaries.

## Validation Plan

Static checks:

- Domain records require tenant, principal/session/capability IDs where
  applicable.
- Raw provider rows, decoded tokens, route bodies, and DB rows are parsed once at
  boundaries.
- Auth accounts cannot include signer material.
- Capability policy maps cannot reference unregistered auth factors.
- Vault-only/IdP-only entry points cannot import MPC workers, signer WASM, HSS,
  threshold stores, chain adapters, or wallet UI.
- Management/API-key principals cannot satisfy sensitive-operation routes without
  grants.

Targeted tests:

- Better Auth session -> `SeamsSession`.
- Session exchange creation, refresh, revoke, replay denial, and tenant
  isolation.
- Seams passkey step-up challenge and verify.
- Grant lifecycle, digest mismatch, expiry, replay, and consumption.
- Management route policy and API scope parsing.
- Router module construction, duplicate rejection, and Cloudflare/Express
  manifest parity when Express is retained.
- Vault proxy use, reveal/export, permission change, break-glass, and
  delegate-member denial.
- `mpc_signer_proof` missing capability, inactive capability, principal
  mismatch, unsupported operation, and success.
- IdP OIDC flow, JWKS rotation, refresh-token rotation/replay, and claim policy.
- Bundle/dependency checks for vault-only, IdP-only, MPC-only, and full-platform
  browser runtimes.

Security tests:

- Auth provider outputs, IdP tokens, refresh tokens, and session exchange cannot
  mint Seams grants.
- Reused, expired, cross-session, cross-tenant, cross-origin, cross-device, and
  digest-mismatched challenges fail closed.
- Vault-only sessions cannot call MPC signing endpoints.
- Delegates cannot reveal or export vault secrets.
- Audit records omit signer secrets, vault secrets, raw OTPs, and raw auth
  headers.

## Open Questions

- Should the public SDK expose `SeamsSession`?
- Should `vault_access` be provisioned automatically for every tenant?
- Should Ed25519 and ECDSA MPC capabilities be provisioned separately by default?
- Which MPC capability should produce `mpc_signer_proof` by default?
- Should IdP mode ship OIDC first and defer SAML IdP?
- Should embedded wallet login be a default auth factor for wallet customers?
- Which IdP scopes require step-up by default?
- Should audit writing live in `seams-authorization` or `audit-core`?

## Related Docs

- [Modular Auth And Capability Refactor SPEC](./refactor-83-modular-auth-capabilities-SPEC.md)
- [Centaur Secrets Vault Architecture Plan](./centaur-secrets-vault.md)
- [Slack OTP Step-Up Spec](./otp-slack.md)
- [Optional HSS Bootstrap Profiles](./refactor-8X-hss-optional.md)
- [Step-Up Adaptor Refactor Plan](./refactor-34b-stepup-adaptor.md)
