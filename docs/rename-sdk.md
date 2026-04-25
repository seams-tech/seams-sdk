# Tatchi to Seams SDK Rename Plan

Date created: 2026-04-22
Last rescanned: 2026-04-24

## Objective

Rename the SDK, examples, docs, server helpers, EVM smart-account surface, tests,
and local development tooling from Tatchi to Seams.

This is a breaking cleanup. Do not keep legacy aliases, deprecated exports,
fallback environment variables, duplicate docs, or compatibility package paths.
After the rename, the active codebase should read as if Seams had always been
the product name.

## Target Naming

Use direct casing-preserving replacement unless a section below gives a more
specific target.

| Current | Target |
| --- | --- |
| `Tatchi` | `Seams` |
| `tatchi` | `seams` |
| `TATCHI` | `SEAMS` |
| `@tatchi-xyz/sdk` | `@seams/sdk` |
| `TatchiPasskey` | `SeamsPasskey` |
| `TatchiPasskeyProvider` | `SeamsPasskeyProvider` |
| `TatchiContextProvider` | `SeamsContextProvider` |
| `useTatchi` | `useSeams` |
| `TatchiConfigsInput` | `SeamsConfigsInput` |
| `TatchiConfigsReadonly` | `SeamsConfigsReadonly` |
| `TatchiSmartAccount` | `SeamsSmartAccount` |
| `ITatchiSmartAccount` | `ISeamsSmartAccount` |
| `getTatchiSmartAccountMethodSelector` | `getSeamsSmartAccountMethodSelector` |
| `tatchiDev` | `seamsDev` |
| `tatchiBuildHeaders` | `seamsBuildHeaders` |
| `tatchiWalletService` | `seamsWalletService` |
| `tatchiNextApp` | `seamsNextApp` |
| `tatchiAppServer` | `seamsAppServer` |
| `tatchi-jwt` | `seams-jwt` |
| `x-tatchi-*` | `x-seams-*` |
| `VITE_TATCHI_*` | `VITE_SEAMS_*` |

Package scope decision: the target package name is `@seams/sdk`.

## Rename Rules

1. Do not export old Tatchi symbols from public SDK entrypoints.
2. Do not keep old package imports in examples, docs, tests, or tsconfig paths.
3. Do not keep fallback support for old `VITE_TATCHI_*`, `x-tatchi-*`, cookie,
   storage, or protocol-domain strings.
4. Do not keep duplicate files such as both `TatchiPasskeyProvider.tsx` and
   `SeamsPasskeyProvider.tsx`.
5. Rename files and directories when their names contain Tatchi or tatchi.
6. Regenerate generated artifacts after renaming sources instead of editing
   generated output by hand.
7. Update tests to assert the absence of old names on the active source surface.
8. Use "specs" when referring to specifications.

## Current Hotspots

The current scan shows Tatchi references in these major areas:

- Root package metadata and workspace config:
  `package.json`, `pnpm-workspace.yaml`, `pnpm-lock.yaml`, and
  `eslint.config.mjs`.
- GitHub workflow config:
  `.github/workflows/ci.yml` and `.github/workflows/deploy-pages.yml`.
  CI Postgres service credentials already use `seams`, but Pages deploy paths
  and Pages build env names still point at `examples/tatchi-site` and
  `VITE_TATCHI_*`, so those workflow edits must land with the corresponding
  directory/env rename.
- SDK package metadata and build scripts:
  `sdk/package.json`, `sdk/tsconfig.json`, `sdk/build-paths.*`, and
  `sdk/scripts/build/*`.
- Public client SDK:
  `client/src/index.ts`, `client/src/core/TatchiPasskey`, `client/src/react`,
  `client/src/plugins`, and `client/src/core/types/tatchi.ts`.
- Wallet iframe runtime:
  `client/src/core/WalletIframe/TatchiPasskeyIframe.ts`,
  `client/src/core/WalletIframe/host`, and shared wallet iframe message types.
- Current signing-session architecture docs:
  `docs/signing-session-architecture.md`,
  `docs/signing-session-coordinator.md`, and
  `docs/signing-session-coordinator-tests.md`.
  The old `docs/signing-session-planner.md` path no longer exists.
- Current signing-session implementation:
  `client/src/core/signingEngine/session/SigningSessionPlanner.ts`,
  `SigningExecutionMachine.ts`, `SigningCapabilityReader.ts`,
  `SigningLaneBuilders.ts`, `SigningPostSignPolicy.ts`,
  `WalletSigningBudgetLedger.ts`, and
  `client/src/core/signingEngine/api/evmFamily/signingSessionCoordinator.ts`.
- Server package and relayer examples:
  `server/src`, `examples/relay-server`, `examples/relay-cloudflare-worker`,
  and `examples/self-host-cloudflare-worker`.
- Example apps and docs:
  `examples/tatchi-site`, `examples/tatchi-docs`, root `README.md`,
  `sdk/README.md`, and docs under `docs/`.
- EVM smart-account package:
  Solidity source, interfaces, ABI metadata, deploy scripts, shared selector
  helpers, and tests using `TatchiSmartAccount`.
- Persistent/runtime identifiers:
  IndexedDB names, local storage keys, cookie names, email recovery prefixes,
  AAD/domain-separation strings, threshold prefixes, auth headers, and route
  examples.
- Rust/WASM crates and formal verification fixtures:
  domain strings in signer crates, WASM runtime comments/types, and anti-drift
  fixtures.
- Test harnesses:
  unit/e2e imports, direct dynamic `/sdk/esm/core/TatchiPasskey/*` paths,
  global `window.tatchi`, and guard tests.

## Phase 1: Decide Canonical Public Surface

Lock the public naming before touching code.

Target public imports:

```ts
import { SeamsPasskey } from '@seams/sdk';
import { SeamsPasskeyProvider, useSeams } from '@seams/sdk/react';
import { seamsDev, seamsBuildHeaders } from '@seams/sdk/plugins/vite';
import { seamsNextApp } from '@seams/sdk/plugins/next';
```

Target route/package exports:

- `@seams/sdk`
- `@seams/sdk/threshold`
- `@seams/sdk/plugins/headers`
- `@seams/sdk/plugins/next`
- `@seams/sdk/plugins/vite`
- `@seams/sdk/server`
- `@seams/sdk/server/router/express`
- `@seams/sdk/server/router/cloudflare`
- `@seams/sdk/server/router/ror`
- `@seams/sdk/server/wasm/signer`
- `@seams/sdk/react`
- `@seams/sdk/react/provider`
- `@seams/sdk/react/profile`
- `@seams/sdk/react/passkey-auth-menu`
- `@seams/sdk/react/styles`

Acceptance checks:

- Public exports expose Seams names only.
- Type declarations expose Seams names only.
- Example code imports from `@seams/sdk` only.
- No package export path points to a file with `Tatchi` in its path.

## Phase 2: Rename Workspace and Package Metadata

Update package/workspace names first so TypeScript path aliases and examples can
move together.

Tasks:

1. Rename root package metadata:
   - `tatchi-xyz-monorepo` to a Seams monorepo name.
   - root scripts that contain `VITE_TATCHI_*`.
2. Rename SDK package:
   - `sdk/package.json` name to `@seams/sdk`.
   - package description, repository, homepage, bugs URL, and build log output.
   - `sdk/tsconfig.json` paths from `@tatchi-xyz/sdk/*` to `@seams/sdk/*`.
3. Rename workspace example packages:
   - `examples/tatchi-site` to `examples/seams-site`.
   - `examples/tatchi-docs` to `examples/seams-docs`.
   - package names to `seams-site` and `seams-docs`.
4. Update `pnpm-workspace.yaml`, `pnpm-lock.yaml`, and root scripts.
5. Update lint ignores and any generated-output allowlists.
6. Update `.github/workflows/deploy-pages.yml` paths and env names in the same
   commit that renames the referenced directories and `VITE_TATCHI_*` vars.

Acceptance checks:

- `pnpm install --lockfile-only` updates the lockfile without old package names.
- `rg -n "@tatchi-xyz/sdk|tatchi-site|tatchi-docs|tatchi-xyz" package.json pnpm-workspace.yaml sdk examples` returns no active references.
- `rg -n "examples/tatchi-site|examples/tatchi-docs|VITE_TATCHI_" .github package.json pnpm-workspace.yaml` returns no active references.

## Phase 3: Rename Client Core

Rename the core class, directory, source files, and types in one pass.

Tasks:

1. Move `client/src/core/TatchiPasskey` to `client/src/core/SeamsPasskey`.
2. Rename `client/src/core/WalletIframe/TatchiPasskeyIframe.ts` to
   `SeamsPasskeyIframe.ts`.
3. Rename `client/src/core/types/tatchi.ts` to `seams.ts`.
4. Replace public type names:
   - `TatchiPasskey` to `SeamsPasskey`.
   - `TatchiConfigsInput` to `SeamsConfigsInput`.
   - `TatchiConfigsReadonly` to `SeamsConfigsReadonly`.
   - `TatchiContextType` to `SeamsContextType`.
5. Replace local variable names where the value is the SDK instance:
   - `tatchi` to `seams`.
   - `getTatchiPasskey` to `getSeamsPasskey`.
   - `tatchiPasskey` to `seamsPasskey`.
6. Update all internal imports from `@/core/TatchiPasskey` and
   `../TatchiPasskey` to the new `SeamsPasskey` path.
7. Update log prefixes from `[TatchiPasskey]` and `[TatchiContextProvider]` to
   Seams names.

Acceptance checks:

- `rg -n "TatchiPasskey|TatchiConfigs|TatchiContext|useTatchi|\\btatchi\\b" client/src` returns no active references, excluding third-party text only if explicitly justified.
- `pnpm -C sdk run type-check` passes.

## Phase 4: Rename React Surface

Update React exports, provider files, context hooks, examples, and SSR-safe
entrypoints without compatibility aliases.

Tasks:

1. Rename provider file:
   - `client/src/react/context/TatchiPasskeyProvider.tsx` to
     `SeamsPasskeyProvider.tsx`.
2. Rename exports in `client/src/react/index.ts` and subpath entrypoints.
3. Rename context APIs:
   - `useTatchi` to `useSeams`.
   - `TatchiContextProvider` to `SeamsContextProvider`.
   - `TatchiPasskeyProvider` to `SeamsPasskeyProvider`.
4. Rename React adapter files that contain Tatchi in names:
   - `PasskeyAuthMenu/adapters/tatchi.ts` to `adapters/seams.ts`.
5. Update docs, comments, story/test names, and dynamic import paths.
6. Update `sdk/package.json` export paths for `./react/provider`.

Acceptance checks:

- `@seams/sdk/react` exports `SeamsPasskeyProvider` and `useSeams`.
- `@seams/sdk/react/provider` points at the Seams provider file.
- SSR tests and passkey auth menu tests use Seams names only.

## Phase 5: Rename Plugins and Build Tooling

Plugins are public API and should be renamed as breaking changes.

Tasks:

1. Rename Vite plugin exports:
   - `tatchiDev` to `seamsDev`.
   - `tatchiBuildHeaders` to `seamsBuildHeaders`.
   - `tatchiWalletService` to `seamsWalletService`.
2. Rename Next plugin exports:
   - `tatchiNextApp` to `seamsNextApp`.
3. Rename server/app helper exports:
   - `tatchiAppServer` to `seamsAppServer`.
4. Update plugin docs and tests.
5. Update build-path freshness checks from `TatchiPasskey` paths to
   `SeamsPasskey` paths.

Acceptance checks:

- `rg -n "tatchiDev|tatchiBuildHeaders|tatchiWalletService|tatchiNextApp|tatchiAppServer" client/src sdk tests examples docs` returns no matches.
- `pnpm -C tests test:unit -- vite-wallet-corp` passes or the renamed equivalent passes.

## Phase 6: Rename Environment, Headers, Cookies, and Config

Replace all environment and wire-level product names without accepting old
fallbacks.

Target names:

| Current | Target |
| --- | --- |
| `VITE_TATCHI_ENVIRONMENT_ID` | `VITE_SEAMS_ENVIRONMENT_ID` |
| `VITE_TATCHI_PUBLISHABLE_KEY` | `VITE_SEAMS_PUBLISHABLE_KEY` |
| `VITE_TATCHI_BROKER_URL` | `VITE_SEAMS_BROKER_URL` |
| `x-tatchi-environment-id` | `x-seams-environment-id` |
| `x-tatchi-publishable-key` | `x-seams-publishable-key` |
| `tatchi-jwt` | `seams-jwt` |
| `THRESHOLD_PREFIX=tatchi:*` | `THRESHOLD_PREFIX=seams:*` |

Tasks:

1. Update example env files, root scripts, Caddy/Vite config, and docs.
2. Update server auth header parsing and relay API key tests.
3. Update default session cookie names in server and examples.
4. Update Cloudflare worker wrangler examples.
5. Remove old fallback parsing entirely.

Acceptance checks:

- Tests fail if old env/header/cookie names are used.
- `rg -n "VITE_TATCHI_|x-tatchi-|tatchi-jwt|THRESHOLD_PREFIX = \"tatchi|THRESHOLD_PREFIX=tatchi" .` returns no active references outside historical notes in this plan.

## Phase 7: Rename Persistent Domains and Protocol Strings

These strings affect local storage, IndexedDB, domain separation, email parsing,
recovery flows, and cryptographic derivation labels. Because breaking changes
are allowed, rename them directly and do not support reading old Tatchi values.

Tasks:

1. Update browser persistence:
   - IndexedDB names such as `tatchi_wallet_v1`.
   - local/session storage keys with `tatchi:`.
   - global test names such as `window.tatchi`.
2. Update recovery/email identifiers:
   - `tatchi-recovery-v1:` payload prefixes.
   - email parser error text.
3. Update AAD/domain separation strings:
   - `tatchi/email-otp/*`.
   - `tatchi/signing-session/*`.
   - `tatchi/signing-root-share/*`.
   - `tatchi/lite/threshold-secp256k1-ecdsa/*`.
4. Update recovery authority typed-data domain names:
   - `TatchiSmartAccountRecovery` to `SeamsSmartAccountRecovery`.
5. Update Rust fixtures, anti-drift tests, and WASM generated bindings.

Versioning rule:

- Keep semantic version suffixes such as `/v1` when the format did not change.
- Rename the product namespace itself to Seams.
- Do not add dual-read migration code from Tatchi namespaces.

Acceptance checks:

- Cryptographic fixture tests and anti-drift tests pass after fixture
  regeneration.
- `rg -n "tatchi/|tatchi:|tatchi-|TatchiSmartAccountRecovery|tatchi_wallet" shared server client crates wasm tests examples docs` returns no active references outside this plan before the rename is marked done.

## Phase 8: Rename EVM Smart-Account Surface

Rename the EVM smart-account package source, ABI artifacts, selector helpers,
deployment scripts, tests, and docs.

Tasks:

1. Rename Solidity files:
   - `TatchiSmartAccount.sol` to `SeamsSmartAccount.sol`.
   - `TatchiSmartAccountFactory.sol` to `SeamsSmartAccountFactory.sol`.
   - `ITatchiSmartAccount.sol` to `ISeamsSmartAccount.sol`.
2. Rename Solidity symbols:
   - `TatchiSmartAccount` to `SeamsSmartAccount`.
   - `TatchiSmartAccountFactory` to `SeamsSmartAccountFactory`.
   - `ITatchiSmartAccount*` to `ISeamsSmartAccount*`.
3. Regenerate ABI and metadata JSON:
   - `TatchiSmartAccount.metadata.json` to `SeamsSmartAccount.metadata.json`.
   - `TatchiSmartAccountFactory.metadata.json` to
     `SeamsSmartAccountFactory.metadata.json`.
4. Rename shared selector helper exports:
   - `TatchiSmartAccountMethod` to `SeamsSmartAccountMethod`.
   - `getTatchiSmartAccountMethodSignature` to
     `getSeamsSmartAccountMethodSignature`.
   - `getTatchiSmartAccountMethodSelector` to
     `getSeamsSmartAccountMethodSelector`.
5. Update deployment-plan helpers, recovery authority code, and tests.

Acceptance checks:

- ABI metadata imports point to Seams filenames.
- Selector tests still assert the same method selectors where function
  signatures are unchanged.
- No active Solidity package source contains `Tatchi`.

## Phase 9: Rename Examples and Docs

Rename user-facing examples and docs after code paths are stable.

Tasks:

1. Move example app directories:
   - `examples/tatchi-site` to `examples/seams-site`.
   - `examples/tatchi-docs` to `examples/seams-docs`.
2. Update all imports from `@tatchi-xyz/sdk` to `@seams/sdk`.
3. Update copy from Tatchi to Seams.
4. Rename components and assets:
   - `TatchiLogo` to `SeamsLogo`.
   - `TatchiProfileSettingsButton` to `SeamsProfileSettingsButton`.
   - `tatchiQRSvg` to `seamsQRSvg`.
5. Update root README, SDK README, server README, deployment docs, and SaaS docs.
6. Update existing plan/docs references to old file paths only when the docs are
   still active. Delete obsolete docs rather than preserving stale Tatchi
   references.

Acceptance checks:

- `pnpm run docs:build` passes after script/path updates.
- `rg -n "Tatchi|tatchi|TATCHI|@tatchi-xyz/sdk" README.md sdk/README.md server/src/README.md docs examples` returns no active references outside this plan.

## Phase 10: Rename Tests and Guardrails

Update test names, fixtures, dynamic imports, source guard tests, and browser
globals.

Tasks:

1. Rename test files with `tatchiPasskey` in the filename to `seamsPasskey`.
2. Update dynamic imports:
   - `/sdk/esm/core/TatchiPasskey/*` to `/sdk/esm/core/SeamsPasskey/*`.
   - `/sdk/esm/react/context/TatchiPasskeyProvider.js` to the Seams provider.
3. Rename globals:
   - `window.TatchiPasskey` to `window.SeamsPasskey`.
   - `window.tatchi` to `window.seams`.
   - `testUtils.tatchi` to `testUtils.seams`.
4. Update guard tests to ban the old names from active source.
5. Update test descriptions and expected error strings.

Add a dedicated no-legacy guard test that scans active source for:

```text
Tatchi
tatchi
TATCHI
@tatchi-xyz/sdk
VITE_TATCHI_
x-tatchi-
tatchi-jwt
```

The guard may exclude:

- `docs/rename-sdk.md` while the plan is being executed.
- generated lockfile metadata only during the phase that regenerates it.
- third-party package internals if any appear under ignored build outputs.

Acceptance checks:

- `pnpm -C tests test:unit` passes.
- `pnpm -C tests test:e2e` passes or the renamed project-specific subset passes
  before merging.
- The no-legacy guard fails on any reintroduced Tatchi symbol in active source.

## Phase 11: Regenerate Build Outputs

Regenerate outputs only after source renames are complete.

Tasks:

1. Run SDK build scripts so `sdk/dist` paths and type declarations use Seams
   filenames and symbols.
2. Regenerate WASM JS bindings if Rust/WASM exported names or comments changed
   in generated files.
3. Regenerate EVM smart-account ABI metadata.
4. Regenerate lockfile.
5. Remove stale generated files with Tatchi names.

Acceptance checks:

- No generated output under tracked paths contains old names.
- Build freshness checks use Seams paths and pass.

## Phase 12: Final Verification

Run verification in this order:

```bash
pnpm install --lockfile-only
pnpm -C sdk run type-check
pnpm -C sdk run build:sdk-full
pnpm -C tests test:unit
pnpm -C tests test:relayer
pnpm -C tests test:wallet-iframe
pnpm run docs:build
rg -n "Tatchi|tatchi|TATCHI|@tatchi-xyz/sdk|VITE_TATCHI_|x-tatchi-|tatchi-jwt" .
```

The final `rg` should return only intentionally retained historical mentions in
this plan until this plan is deleted or archived. If any active source, docs,
test, build script, package metadata, generated artifact, or example still uses
Tatchi, the rename is not complete.

## Implementation Order

Use this order to avoid mixed states:

1. Package/workspace metadata and import path target.
2. Core SDK directory/type/class rename.
3. React context/provider/hook rename.
4. Plugin and build helper rename.
5. Env/header/cookie/config rename.
6. Persistent domain strings and fixtures.
7. EVM smart-account source and generated ABI rename.
8. Examples/docs directory and copy rename.
9. Test harness, dynamic import, and guard rename.
10. Generated output regeneration.
11. Full verification and stale file deletion.

## Done Criteria

The rename is done only when:

- Public SDK consumers can install and import `@seams/sdk`.
- Public SDK docs show Seams names only.
- Source code exposes no Tatchi public or internal symbols.
- Runtime env vars, headers, cookies, storage keys, and domain strings use
  Seams names only.
- Example apps and docs build from Seams-named directories.
- Tests use Seams names and contain guard coverage that rejects Tatchi names.
- Generated artifacts and lockfiles are refreshed.
- No legacy compatibility layer remains.
