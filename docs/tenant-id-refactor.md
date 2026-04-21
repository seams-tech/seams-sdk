# Signing Root Scope Refactor Plan

Date created: 2026-04-17

## Objective

Revamp the signing system scope model so organization, project, environment,
and signing-root custody identifiers have distinct names and responsibilities.

This plan replaces ambiguous root naming and overloaded `projectId`
surfaces with explicit signing-root terminology and a single canonical
mapping from runtime scope to signing-root scope.

Breaking changes are allowed. There are no real customer wallets yet, so the
goal is to remove ambiguity now rather than preserve compatibility aliases.

## Target Model

Use four distinct concepts:

```ts
type RuntimePolicyScope = {
  orgId: string;     // organization/account/policy/billing ownership
  projectId: string; // parent project, e.g. "proj_abc"
  envId: string;     // project environment, e.g. "dev" | "staging" | "production"
};

type SigningRootScope = {
  signingRootId: string;       // hosted: `${projectId}:${envId}`
  signingRootVersion?: string; // signing root share version
};
```

Canonical hosted mapping:

```ts
function signingRootScopeFromRuntimePolicyScope(scope: RuntimePolicyScope): SigningRootScope {
  return {
    signingRootId: `${scope.projectId}:${scope.envId}`,
  };
}
```

Meaning:

- `orgId` is organization/account ownership, billing ownership, audit
  ownership, and policy ownership.
- `projectId` is the parent product/project id used for dashboard grouping,
  searching, filtering, quotas, wallet inventory, and database queries.
- `envId` is the concrete runtime environment within a project.
- `signingRootId` is the crypto custody/key-derivation scope.
- `signingRootVersion` identifies the active version of signing-root shares.

The signing system must not derive signing material from `orgId`, parent
`projectId`, or `envId` directly. It must derive only from `SigningRootScope`.

## Design Rules

1. Only `SigningRootScope` can reach signing-root share resolution.
2. Runtime policy scope must be explicitly converted into signing-root scope.
3. No resolver accepts `orgId`, parent `projectId`, or `envId` directly.
4. Hosted SaaS sets `signingRootId = projectId + ":" + envId`.
5. Self-hosted deployments can choose any stable `signingRootId` in their import
   bundle, but hosted migration exports should default to the hosted value.
6. Ed25519 HSS and ECDSA derivation contexts must bind `signingRootId`, not
   `orgId` or parent `projectId`.
7. `orgId` remains in session claims and route auth for authorization and
   policy checks.
8. Parent `projectId` and `envId` remain available to dashboard, billing,
   audit, and quota code for filtering without string parsing.
9. No compatibility aliases for `SigningRoot*`, `signingRoot*`, `SigningRoot*`,
   or root `projectId` surfaces should remain after this refactor.
10. Tests must use different-looking values for every scope:

```text
orgId = org_123
projectId = proj_abc
envId = dev
signingRootId = proj_abc:dev
signingRootVersion = root-v1
```

## Naming Map

Replace the current signing-root terminology everywhere in public and internal
signing APIs.

| Current Name | New Name |
| --- | --- |
| `SigningRootShareResolver` | `SigningRootShareResolver` |
| `SigningRootSecret` | `SigningRootSecret` |
| `SigningRootSecretShare` | `SigningRootSecretShare` |
| `SigningRootSecretShareWireV1` | `SigningRootSecretShareWireV1` |
| `SigningRootSecretShareId` | `SigningRootSecretShareId` |
| `SealedSigningRootSecretShare` | `SealedSigningRootSecretShare` |
| `SigningRootSecretStore` | `SigningRootSecretStore` |
| `SigningRootSecretResolver` | `SigningRootSecretResolver` |
| `SigningRootSecretShareSource` | `SigningRootSecretShareSource` |
| `SigningRootSecretDecryptAdapter` | `SigningRootSecretDecryptAdapter` |
| `SigningRootSecretResolverAdapters` | `SigningRootSecretResolverAdapters` |
| `SigningRootSecretShareKekResolver` | `SigningRootSecretShareKekResolver` |
| `createHostedSigningRootShareResolver` | `createHostedSigningRootShareResolver` |
| `createSelfHostedSigningRootShareResolver` | `createSelfHostedSigningRootShareResolver` |
| `createSealedSelfHostedSigningRootShareResolver` | `createSealedSelfHostedSigningRootShareResolver` |
| `CloudflareDurableObjectSigningRootSecretStore` | `CloudflareDurableObjectSigningRootSecretStore` |
| `PostgresSigningRootSecretStore` | `PostgresSigningRootSecretStore` |
| `InMemorySigningRootSecretStore` | `InMemorySigningRootSecretStore` |
| `signingRootVersion` | `signingRootVersion` |
| `rootVersion` in signing-root APIs | `signingRootVersion` |
| resolver input `projectId` | `signingRootId` |
| storage key `projectId` for signing roots | `signingRootId` |
| `SIGNING_ROOT_SECRET_SHARE_KEK_B64U` | `SIGNING_ROOT_SECRET_SHARE_KEK_B64U` |
| self-host route `/self-host/signing-root/*` | `/self-host/signing-root/*` |

The word `tenant` may still appear in old migration docs only when describing
history. It should not appear in active code, public SDK exports, route names,
environment variables, storage prefixes, or new specs for signing root custody.

Local/self-host signing-root configuration:

- Hosted relays must not configure a process-wide signing-root id. They derive
  `signingRootId` from the authenticated project/environment runtime scope for
  each request and resolve signing-root shares from per-project storage.
- Local-dev fixtures may accept the request `signingRootId` dynamically while
  reusing development-only fixture shares. This is only for localhost harnesses
  and must not be used for real funds.
- Direct single-root self-host deployments may wire a fixed resolver in code,
  but that mode is not the hosted relay path and must not be represented as a
  hosted relay environment variable.
- Remove old tenant-named signing-root env vars entirely. Do not keep them as
  fallbacks or compatibility aliases.

## Target Resolver API

```ts
interface SigningRootShareResolver {
  readonly fixedSigningRootScope?: SigningRootScope;

  resolveSigningRootSharePair(input: {
    signingRootId: string;
    signingRootVersion?: string;
    preferredShareIds?: readonly [1 | 2 | 3, 1 | 2 | 3];
  }): Promise<readonly [Uint8Array, Uint8Array]>;
}
```

Hosted resolver behavior:

- Requires `signingRootId`.
- Uses `signingRootVersion` to select sealed shares.
- Rejects missing signing-root scope.
- Does not infer from `orgId`.
- Does not infer from parent `projectId`.

Self-host direct resolver behavior:

- Has a fixed `SigningRootScope`.
- Accepts omitted `signingRootVersion` as the fixed root version.
- Rejects explicit wrong `signingRootVersion`.
- Rejects explicit wrong `signingRootId`.

Self-host sealed resolver behavior:

- Same fixed-scope semantics as direct resolver.
- Composes customer-owned storage and decrypt adapters.

## Runtime Scope API

Replace current `runtimeSnapshotScope` shapes that carry ambiguous
`projectId`/`environmentId` with:

```ts
type RuntimePolicyScope = {
  orgId: string;
  projectId: string;
  envId: string;
};
```

Recommended route/session claim field:

```ts
runtimePolicyScope: RuntimePolicyScope
```

If keeping the existing property name temporarily during a single patch is
unavoidable, the value must still use the new fields:

```ts
runtimeSnapshotScope: {
  orgId: string;
  projectId: string;
  envId: string;
}
```

Do not keep both `environmentId` and `envId` long term. Pick `envId` for the
new model because it is the small environment label, not the full
`projectId:envId` compound identifier.

Environment naming boundary:

- `envId` is the short stable runtime environment label used by signing-root
  mapping, such as `dev`, `staging`, or `production`.
- `environmentRecordId` is the database row id when the dashboard needs a
  durable environment record identifier.
- `environmentDisplayName` is the human-readable dashboard label.
- `environmentId` may remain only in dashboard/product APIs where it already
  means a product environment record id. It must not appear in signing runtime
  policy scope, signing-root derivation, signing-root resolver inputs, threshold
  session claims, or signing-root storage records.
- Public managed-registration config, headers, and SDK request fields must be
  explicitly audited. If they are signing/runtime fields, rename
  `environmentId` to `envId`; if they are dashboard/product fields, keep
  `environmentId` and prevent those values from flowing directly into signing
  code.

## Signing-Root Derivation Context

ECDSA and Ed25519 HSS must bind the same signing-root custody scope.

Target shared context fields:

```ts
type SigningRootDerivationContext = {
  signingRootId: string;
  signingRootVersion?: string;
  accountId: string;
  keyPurpose: string;
  keyVersion: string;
  derivationVersion: number;
};
```

Ed25519 HSS may additionally include:

```ts
participantIds: number[];
```

Rules:

- `orgId` must not be a cryptographic derivation domain separator.
- Parent `projectId` must not be a cryptographic derivation domain separator.
- `envId` must not be used directly by crypto code; use `signingRootId`.
- `signingRootId` must be included in threshold-PRF context encoding.
- `signingRootId` must be included in Ed25519 HSS context binding.
- Existing dev wallets should be considered invalid after the context change.

## Route And Session Propagation

Every route that can derive, validate, or use server-side signing material must
carry the correct scopes.

Registration routes:

- `/registration/bootstrap`
- `/registration/threshold-ed25519/hss/prepare`
- `/registration/threshold-ed25519/hss/respond`
- `/registration/threshold-ed25519/hss/finalize`
- `/threshold-ecdsa/hss/prepare`
- `/threshold-ecdsa/hss/respond`
- `/threshold-ecdsa/hss/finalize`

Session routes:

- `/session/exchange`
- `/threshold-ed25519/session`
- `/threshold-ecdsa/session`
- `/threshold-ecdsa/authorize`

Signing routes:

- `/threshold-ed25519/hss/*`
- `/threshold-ecdsa/presign/*`
- `/threshold-ecdsa/sign/*`

Required propagation:

1. Publishable key auth resolves `orgId`, parent `projectId`, and `envId`.
2. Bootstrap grants persist `orgId`, `projectId`, and `envId`.
3. Route principals expose `runtimePolicyScope`.
4. Threshold session claims persist `runtimePolicyScope`.
5. Signing code derives `SigningRootScope` via
   `signingRootScopeFromRuntimePolicyScope`.
6. Signing-root resolver receives only `signingRootId` and
   `signingRootVersion`.
7. Persisted key records store `signingRootId`, `signingRootVersion`,
   `keyVersion`, and `derivationVersion`.

Route payload audit:

- Build a route payload matrix before implementation that lists request fields,
  response fields, JWT/session claims, persisted grant fields, route principal
  fields, old names to delete, and new names to emit.
- Include `/session/exchange`, Email OTP enroll/challenge/authorize/unseal
  routes, threshold ECDSA routes, threshold Ed25519 routes, sponsorship routes,
  relay API credential routes, registration bootstrap routes, and self-host
  signing-root routes.
- Old `runtimeSnapshotScope` claims and payloads must be rejected after the
  refactor. Do not silently map them into `runtimePolicyScope`.
- Runtime signing claims containing `environmentId` instead of `envId` must be
  rejected after the refactor.

## Storage Changes

Signing-root sealed share storage should key by:

```text
signingRootId + signingRootVersion + shareId
```

Storage key families:

- `threshold-prf:signing-root-secret:`
- `idx:${signingRootId}\0${signingRootVersionKey}`
- `rec:${signingRootId}\0${signingRootVersionKey}\0${shareId}`

No migration is required for customer data because there are no real customers.
Local dev data and test stores can be wiped.

Database columns:

- For signing-root storage, use `signing_root_id` and
  `signing_root_version`.
- For product/dashboard grouping, keep `project_id` and `env_id`.
- Do not store the compound `project_id:env_id` in a column called
  `project_id`.

Local reset requirements:

- Local development must use a clean breaking reset after this refactor. Do
  not try to migrate stale local signing sessions, IndexedDB records, or
  Durable Object state across the naming and crypto-context change.
- Browser reset for the demo origin:

  ```js
  await Promise.all(
    (await indexedDB.databases()).map((db) => db.name && indexedDB.deleteDatabase(db.name)),
  );
  localStorage.clear();
  sessionStorage.clear();
  ```

- Postgres signer-state reset for local dev:

  ```bash
  psql "$POSTGRES_URL" -v ON_ERROR_STOP=1 <<'SQL'
  TRUNCATE
    signing_root_secret_shares,
    threshold_ed25519_keys,
    threshold_ecdsa_keys,
    threshold_ed25519_sessions,
    threshold_ecdsa_signing_sessions,
    threshold_ecdsa_presign_sessions,
    threshold_ecdsa_presignatures,
    webauthn_authenticators,
    webauthn_credential_bindings,
    email_otp_challenges,
    email_otp_grants,
    email_otp_wallet_enrollments,
    email_otp_unlock_challenges,
    near_public_keys,
    account_signers
  RESTART IDENTITY CASCADE;
  SQL
  ```

- Cloudflare local Durable Object reset:

  ```bash
  rm -rf examples/relay-cloudflare-worker/.wrangler/state
  rm -rf examples/self-host-cloudflare-worker/.wrangler/state
  ```

- Startup warnings for old local storage prefixes are optional. The current
  decision is to rely on an explicit local reset because there are no real
  customer wallets and stale dev records can encode the wrong crypto context.

## Client Changes

Client SDK should:

- Treat managed runtime scope as `{ orgId, projectId, envId }`.
- Stop using `environmentId` as a compound scope in signing code.
- Keep dashboard/product APIs free to use parent `projectId`.
- Convert runtime scope to signing-root scope only inside signing bootstrap
  helpers.
- Persist threshold session records with `runtimePolicyScope` and signing-root
  metadata where applicable.
- Clear or invalidate local dev IndexedDB records created under old
  `orgId`/signing-root context.
- Reject stale client threshold session records carrying `runtimeSnapshotScope`,
  `environmentId`, `signingRootVersion`, or signing-root resolver `projectId`.
- Keep parent `projectId` in dashboard, billing, wallet inventory, quota, API
  key, and console APIs unless the field is used as signing-root custody input.

Email OTP requirements:

- Email OTP registration must produce both ECDSA and Ed25519 threshold signers.
- Email OTP managed registration tests must use `orgId !== projectId` and
  `signingRootId === projectId + ":" + envId`.
- Email OTP must not infer signing-root scope from email/user id.
- Email OTP enrollment records must store `runtimePolicyScope` and signing-root
  metadata needed to validate future OTP authorizations.
- Email OTP challenge and grant records must bind `orgId`, `projectId`, `envId`,
  `signingRootId`, `walletId`, `userId`, and OTP action.
- Email OTP grants from one `envId` must not bootstrap signing for another
  `envId`.

Passkey registration requirements:

- Managed passkey registration must use the same runtime policy scope shape.
- Ed25519 and ECDSA registration ceremonies must derive from the same
  signing-root scope.
- WebAuthn credential binding records must carry or resolve the same
  `runtimePolicyScope` used for signing bootstrap.
- Passkey login must mint threshold sessions with `runtimePolicyScope`.
- Passkey authentication for one project/environment must not bootstrap signing
  under another `signingRootId`.

## Server Changes

Server SDK:

- Rename all `SigningRoot*` exports to `SigningRoot*`.
- Remove all `SigningRoot*` compatibility exports.
- Change resolver input from `projectId` to `signingRootId`.
- Change `rootVersion`/`signingRootVersion` to `signingRootVersion`.
- Add `RuntimePolicyScope` and `SigningRootScope` helpers.
- Require explicit conversion from runtime scope to signing-root scope.
- Remove fallback from Ed25519 HSS context `orgId` to signing-root id.

Router:

- Bootstrap grants should persist `orgId`, `projectId`, and `envId`.
- API credential principals should expose `runtimePolicyScope`.
- Session exchange should mint claims with `runtimePolicyScope`.
- Registration HSS routes should forward runtime policy scope, not only `orgId`.
- ECDSA and Ed25519 routes should call the same helper to resolve
  `SigningRootScope`.

Threshold signing service:

- ECDSA first bootstrap uses `signingRootId`.
- ECDSA integrated key records store signing-root metadata.
- ECDSA session, presign, and signing records validate signing-root metadata.
- Ed25519 HSS prepare uses `signingRootId` in server input derivation.
- Ed25519 HSS context binding uses `signingRootId`.
- No derivation path may call a signing-root resolver with `orgId`.

Rust/WASM:

- Rename threshold-prf Rust types from `SigningRoot*` to `SigningRoot*`.
- Rename threshold-prf WASM exports and JS wrapper names from `SigningRoot*` or
  `SigningRoot*` to `SigningRoot*`.
- Regenerate WASM bindings after the context/type rename.
- Regenerate or delete stale generated formal-verification and WASM boundary
  artifacts that contain `SigningRoot`, `signing-root`, `SigningRoot`, or
  `signing-root`.

## Cloudflare Worker Changes

Hosted worker:

- Uses hosted `SigningRootShareResolver`.
- Derives `signingRootId` from runtime scope.
- Persists sealed signing-root shares under signing-root storage prefixes.

Self-host worker:

- Renames admin routes to `/self-host/signing-root/*`.
- Imports signing-root share bundles, not signing-root bundles.
- Status/delete/verify routes use `signingRootId` and `signingRootVersion`.
- Direct-share self-host mode requires no KEK env var.
- Sealed-share self-host mode uses `SIGNING_ROOT_SECRET_SHARE_KEK_B64U` only
  for local AES-GCM mode.
- Hosted export artifacts include `signingRootId` and `signingRootVersion`.
- Self-host import rejects missing `signingRootId`.
- Self-host import rejects bundles whose wallet inventory signing-root metadata
  differs from the bundle signing-root metadata.
- Verify-wallet uses `signingRootId` and `signingRootVersion`, never
  `projectId` or `signingRootVersion`.

Cloudflare Durable Object:

- Rename public object/export names to signing-root terminology where they
  expose signing-root custody concepts.
- Preserve neutral threshold-store names where they are not root-specific.

## Test Plan

Add or update tests so every critical path uses:

```text
orgId = org_test
projectId = proj_test
envId = dev
signingRootId = proj_test:dev
signingRootVersion = root-v1
```

Required unit tests:

- Runtime scope to signing-root scope conversion.
- Runtime scope parser rejects `environmentId` in signing scope payloads.
- Runtime scope parser rejects old `runtimeSnapshotScope` after the refactor.
- Hosted signing-root resolver rejects missing `signingRootId`.
- Hosted signing-root resolver rejects wrong `signingRootVersion`.
- Direct self-host signing-root resolver accepts omitted fixed version.
- Direct self-host signing-root resolver rejects explicit wrong version.
- Sealed self-host signing-root resolver pins fixed scope.
- ECDSA derivation uses `signingRootId`.
- Ed25519 derivation uses `signingRootId`.
- Ed25519 HSS context binding changes when `signingRootId` changes.
- Existing threshold-prf vectors still pass after context rename/regeneration.
- Email OTP grant scoped to `envId=dev` cannot bootstrap signing for
  `envId=production`.
- Passkey auth scoped to one `signingRootId` cannot bootstrap a different
  `signingRootId`.
- WebAuthn credential binding stores and resolves `runtimePolicyScope`.

Required integration tests:

- Managed passkey registration creates Ed25519 and ECDSA keys with
  `orgId !== projectId`.
- Email OTP registration creates Ed25519 and ECDSA keys with
  `orgId !== projectId`.
- Email OTP sign transaction succeeds after registration.
- ECDSA presign/sign succeeds with persisted signing-root metadata.
- Ed25519 signing session succeeds with persisted runtime policy scope.
- Self-host direct import derives the same wallet address as hosted export.
- Self-host sealed import derives the same wallet address as hosted export.
- Self-host import rejects mismatched bundle and wallet-inventory
  `signingRootId`.
- Old threshold sessions and old Email OTP grants are invalid after the scope
  rename.

Required negative tests:

- Missing `projectId` in runtime scope fails before derivation.
- Missing `envId` in runtime scope fails before derivation.
- Missing `signingRootId` fails at resolver boundary.
- Resolver receives `orgId`-looking value and fails in tests where
  `orgId !== signingRootId`.
- Old root-share compatibility exports are absent.
- Old self-host root route aliases are absent.
- Old tenant-named signing-root env vars are absent.
- Old root-share KEK env aliases are absent.
- Old `runtimeSnapshotScope` claims are absent.
- Runtime signing claims with `environmentId` are rejected.

## Static Refactor Guards

Update `check-signing-root-refactor-boundaries` into
`check-signing-root-refactor-boundaries`.

It must fail on:

- legacy tenant/project root spellings
- old tenant-named signing-root env vars
- `THRESHOLD_*MASTER_SECRET`
- `projectId: context.orgId`
- `signingRootId: orgId`
- `signingRootId: projectId`
- resolver input containing `projectId`
- signing runtime scope containing `environmentId`
- session claim containing `runtimeSnapshotScope`
- public routes containing `/signing-root`

Allowlist only:

- this migration plan, if needed
- archived historical docs, if explicitly isolated

Prefer no allowlist in active code and active docs.

Wire the renamed guard into the normal architecture check path in `package.json`,
the `justfile`, and CI. The guard must run on active code, active docs, tests,
examples, generated bindings, and generated formal-verification artifacts unless
a path is explicitly archived.

## Comprehensive Todo List

Use this checklist as the source of truth for the current implementation state.
Completed items are checked only when they are implemented in active code and
covered by at least one static guard, typecheck, unit test, or startup smoke
check.

### Completed

- [x] Added the canonical `RuntimePolicyScope` with `orgId`, `projectId`, and
      `envId` in shared code.
- [x] Added the canonical `SigningRootScope` with `signingRootId` and optional
      `signingRootVersion`.
- [x] Added `deriveSigningRootId({ projectId, envId })` and
      `signingRootScopeFromRuntimePolicyScope(scope)`.
- [x] Changed signing-root resolver input from `projectId/rootVersion` to
      `signingRootId/signingRootVersion`.
- [x] Updated hosted, direct self-host, and sealed self-host resolver paths to
      pin and validate signing-root scope.
- [x] Renamed public server SDK root-share APIs to `SigningRoot*` names.
- [x] Removed active legacy tenant/project root symbols from the TypeScript
      signing boundary.
- [x] Renamed signing-root storage fields and Postgres signing-root columns to
      `signing_root_id` and `signing_root_version`.
- [x] Kept dashboard/product APIs on their existing product identifiers instead
      of forcing product `environmentId` into signing runtime scope.
- [x] Updated ECDSA threshold-PRF context to bind `signingRootId`.
- [x] Updated Ed25519 HSS server-side context binding to use `signingRootId`
      instead of `orgId` for the crypto domain.
- [x] Regenerated threshold-PRF protocol vectors after the context byte change.
- [x] Rebuilt threshold-PRF WASM bindings after the Rust/WASM rename.
- [x] Renamed threshold-PRF Rust and WASM public root-share symbols to
      signing-root terminology.
- [x] Updated local relay-server fixture signing-root resolver to pass
      `signingRootId/signingRootVersion`.
- [x] Verified relay-server startup reaches the HTTP listener with local-dev
      signing-root fixtures.
- [x] Updated self-host Cloudflare worker examples and Wrangler config to use
      signing-root naming.
- [x] Updated `docs/korg_secrets.md` and
      `docs/cloudflare-signing-worker-self-host.md` to use signing-root naming
      for active APIs.
- [x] Replaced the stale legacy-root boundary check with
      `check-signing-root-refactor-boundaries.mjs`.
- [x] Extended the static guard across `server`, `client`, `examples`, `tests`,
      `docs`, `crates/threshold-prf`, and `wasm/threshold_prf`.
- [x] Made the static guard reject legacy root spellings in active guarded
      paths.
- [x] Made the static guard reject signing-root resolver calls that pass
      `projectId`.
- [x] Made the static guard reject `signingRootId` derived directly from
      `context.orgId`.
- [x] Ran SDK build typecheck successfully.
- [x] Ran SDK full development build successfully after bypassing the
      wasm-pack release post-optimization failure for the server HSS WASM build.
- [x] Ran relay-server TypeScript build successfully.
- [x] Ran self-host and relay Cloudflare worker Wrangler dry-run builds
      successfully.
- [x] Ran the signing-root static guard successfully.
- [x] Ran threshold-PRF Rust tests and vector tests successfully.
- [x] Ran targeted signing-root resolver, sealing, storage, wire, ECDSA,
      Ed25519, Cloudflare self-host, threshold-PRF handoff, and shared scope
      Playwright unit tests successfully.
- [x] Ran threshold-PRF native benchmark smoke and benchmark guard
      successfully.

### Remaining

- [x] Run a Cloudflare worker typecheck/build for the self-host and relay worker
      examples.
- [x] Fix the SDK full dev build failure caused by wasm-pack parsing generated
      `package.json.repository` metadata during the server HSS release WASM
      build by using the release Rust profile without wasm-pack's post-pass.
- [x] Run targeted Email OTP registration smoke tests and verify both ECDSA and
      Ed25519 signers are available immediately after OTP registration.
- [x] Run targeted passkey registration smoke tests with distinct `orgId`,
      `projectId`, and `envId`.
- [x] Run targeted transaction-signing smoke tests for Ed25519 NEAR signing and
      ECDSA EVM/Tempo signing after registration.
- [x] Add or run a self-host route regression proving old self-host route names
      are absent and signing-root route names work.
- [x] Add or run self-host import verification proving direct-share and
      sealed-share imports preserve wallet addresses.
- [x] Add explicit regression coverage that changing only `orgId` does not
      change ECDSA or Ed25519 derived server shares.
- [x] Add explicit regression coverage that changing `signingRootId` changes
      ECDSA and Ed25519 derived server shares.
- [x] Decide whether to reject stale browser IndexedDB/session records
      automatically or document a mandatory local-dev reset.
- [x] Document local reset commands for browser IndexedDB, Postgres threshold
      state, and Cloudflare Durable Object dev state.
- [x] Review remaining product docs that are outside the active signing-root
      specs and update them only where they describe signing runtime scope.

### Current E2E Results

- [x] SDK full development build passes after signing reconnect scope propagation
      changes.
- [x] Static signing-root refactor guard passes.
- [x] Managed passkey Ed25519 NEAR batch signing smoke passes with distinct
      `orgId`, `projectId`, and `envId`.
- [x] Managed passkey ECDSA Tempo/EVM ordering smoke passes, including the
      signing reconnect path.
- [x] Managed Email OTP ECDSA Tempo session-mode smoke passes.
- [x] Managed Email OTP ECDSA EVM session-mode smoke passes.
- [x] Managed bootstrap-grant relayer suite passes with bounded 3-use
      registration-flow token semantics.
- [x] Email OTP Ed25519 NEAR signing coverage has a focused smoke test.
- [x] Single-flow passkey registration assertion verifies both Ed25519 and
      ECDSA signers are present.

## Phased Implementation Plan

### Phase 0. Freeze And Baseline

- [x] Confirm no real customer wallets exist, so breaking crypto-context changes
      are acceptable.
- [x] Establish the static guard before considering the rename complete.
- [x] Preserve product/dashboard `environmentId` boundaries instead of forcing
      all product APIs into signing runtime naming.
- [x] Record current end-to-end registration/signing flow results after the
      remaining smoke tests run.
- [x] Decide and document local reset commands for stale dev state.

### Phase 1. Introduce Scope Types

- [x] Add `RuntimePolicyScope`.
- [x] Add `SigningRootScope`.
- [x] Add `deriveSigningRootId({ projectId, envId })`.
- [x] Add `signingRootScopeFromRuntimePolicyScope(scope)`.
- [x] Replace signing-path ad-hoc scope parsing with shared normalization in the
      server and client paths touched by the registration/signing flows.
- [x] Add focused unit coverage for the shared scope helper itself.

### Phase 2. Rename Root APIs

- [x] Rename server SDK root-share files, exports, resolvers, stores, sealing,
      config, and tests to signing-root names.
- [x] Rename threshold-PRF Rust root-share symbols to signing-root names.
- [x] Rename threshold-PRF WASM wrapper internals to signing-root names.
- [x] Remove active compatibility aliases for legacy root names.
- [x] Update active docs and examples covered by the static guard.

### Phase 3. Change Resolver Boundary

- [x] Replace resolver input `projectId` with `signingRootId`.
- [x] Replace resolver input `rootVersion` with `signingRootVersion`.
- [x] Update hosted resolver storage queries.
- [x] Update direct self-host resolver validation.
- [x] Update sealed self-host resolver validation.
- [x] Update local-dev hosted fixtures to use explicit signing-root scope.
- [x] Update failure messages to say `signingRootId` and
      `signingRootVersion`.
- [x] Add targeted resolver tests for wrong scope and duplicate shares.

### Phase 4. Update Runtime Scope Propagation

- [x] Route signing paths through `runtimePolicyScope` where the registration
      and threshold-session flows need signing-root derivation.
- [x] Ensure threshold signing derives `signingRootId` from `projectId/envId`,
      not from `orgId`.
- [x] Keep product API credential/environment IDs isolated from signing-root
      resolver input.
- [x] Complete end-to-end smoke coverage for publishable-key and Email OTP
      grant paths with distinct `orgId`, `projectId`, and `envId`.
- [x] Add explicit stale-payload rejection tests for `runtimeSnapshotScope` and
      signing runtime `environmentId`.

### Phase 5. Update Cryptographic Contexts

- [x] Update threshold-PRF context encoding to bind signing-root identity.
- [x] Regenerate threshold-PRF vectors.
- [x] Update Ed25519 HSS context to bind `signingRootId`.
- [x] Update ECDSA HSS context to bind `signingRootId`.
- [x] Update Rust/WASM bindings.
- [x] Cover generated threshold-PRF artifacts with the static guard.
- [x] Run benchmark smoke after the final context/vector update.

### Phase 6. Update Persisted Records

- [x] Rename signing-root share storage records and Postgres signing-root share
      columns.
- [x] Update ECDSA integrated-key metadata to carry signing-root identifiers.
- [x] Update threshold session claims and metadata paths touched by the signing
      resolver tests.
- [x] Update IndexedDB/session types touched by the client typecheck.
- [x] Add or run stale-record rejection tests for old client/session records.
- [x] Decide whether to add startup warnings for old local-dev storage prefixes
      or rely on clean breaking reset instructions.

### Phase 7. Update Self-Host Worker

- [x] Rename self-host Cloudflare worker configuration to signing-root names.
- [x] Expose direct-share and sealed-share resolver creation for self-hosted
      customers.
- [x] Ensure direct-share mode does not require a KEK env var.
- [x] Update Wrangler examples for signing-root env vars.
- [x] Run Cloudflare worker build/typecheck.
- [x] Add route-level tests for signing-root self-host import/status/verify.

### Phase 8. Full Flow Verification

- [x] Passkey registration produces Ed25519 and ECDSA signers.
- [x] Email OTP registration produces Ed25519 and ECDSA signers.
- [x] Email OTP NEAR transaction signing works immediately after registration.
- [x] ECDSA EVM/Tempo signing works after registration.
- [x] Self-host direct import preserves wallet addresses.
- [x] Self-host sealed import preserves wallet addresses.
- [x] Cloudflare worker typecheck passes.
- [x] Relay server TypeScript build passes.
- [x] SDK build typecheck passes.
- [x] SDK full development build passes.
- [x] Static refactor guard passes.
- [x] Threshold-PRF Rust/vector tests pass.
- [x] Targeted signing-root unit tests pass.

### Phase 9. Cleanup

- [x] Remove active legacy root naming from guarded paths.
- [x] Remove ambiguous resolver `projectId` input from guarded signing-root
      resolver calls.
- [x] Remove threshold master-secret env references from guarded signing paths.
- [x] Update remaining non-guarded/generated docs only if they describe active
      signing runtime behavior.
- [x] Document stale dev-state reset steps before relying on the new context in
      day-to-day local development.

## Acceptance Criteria

The refactor is complete only when:

- Active guarded paths contain no legacy root symbols.
- Active signing-root resolver calls do not accept a field named `projectId`.
- No signing-root derivation path depends on `orgId`.
- No signing runtime policy scope uses product `environmentId` as the signing
  environment label.
- No active session claim uses `runtimeSnapshotScope` for new signing sessions.
- Ed25519 and ECDSA both derive server shares from `signingRootId`.
- Managed passkey and Email OTP registration both work when
  `orgId !== projectId` and `signingRootId = projectId + ":" + envId`.
- Email OTP grants cannot cross project/environment/signing-root boundaries.
- Passkey authentication cannot bootstrap signing under the wrong
  `signingRootId`.
- Self-host import/export uses signing-root terminology end to end.
- Static refactor guards are part of the normal architecture check.
- The two older plans reference this document as the active scope/naming
  refactor plan.

## Migration Note

Because no real customer wallets exist, this should be treated as a clean
breaking refactor.

Local developers should clear:

- browser IndexedDB wallet/session state
- relay in-memory or local Postgres threshold signing state
- Cloudflare Durable Object dev state
- old generated test fixtures if they encode `orgId` as signing-root context
