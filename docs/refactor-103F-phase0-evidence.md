# R103F Phase 0 evidence — baseline slice

Recorded 2026-08-29 on branch `codex/r103f-phase0-baseline`.

## Baseline

- Baseline commit: `4d52dd438fbb527ef420caef095dff2e6e24e742`
  (`fix(wallet): polish recovery modal transition`)
- `git status --short`: empty.
- No pre-existing working-tree changes required attribution to R103F.
- No production behavior, server source, or client source was changed in this
  slice. The tracked changes are the three focused test repairs and this
  evidence record.

## Tracked production inventory

The exact baseline file list is checked in at
[`refactor-103F-phase0-production-files.txt`](./refactor-103F-phase0-production-files.txt).
It is the tracked regular source/config text under `apps/`, `packages/`,
`crates/`, `wasm/`, and `voiceId/` that contains a `src/` path. The list
excludes documentation (`docs/`, `apps/docs/`, Markdown), tests (`tests/` and
`src` test directories), SQL, generated/build artifacts (`dist`, `target`,
`pkg`, `generated`, `__generated__`, `coverage`, `test-results`,
`playwright-report`, and `artifacts`), generated filename variants, lock
metadata, and non-source static/binary assets.

The reproducible inventory command and measurements were:

```sh
BASELINE_SHA=4d52dd438fbb527ef420caef095dff2e6e24e742
git ls-tree -r --name-only "$BASELINE_SHA" -- apps packages crates wasm voiceId | awk '
  $0 !~ /(^|\/)src(\/|$)/ { next }
  $0 ~ /(^|\/)(docs|tests|test)(\/|$)/ ||
  $0 ~ /(^|\/)(dist|target|pkg|generated|__generated__|coverage|test-results|playwright-report|artifacts)(\/|$)/ ||
  $0 ~ /\.(generated|gen)\./ ||
  $0 ~ /\.sql$/ ||
  $0 ~ /\.(md|lock|png|jpe?g|gif|ico|svg|pdf|wasm|bin|o|a|rlib|so|dylib|ttf|woff2?|zip|gz|tgz)$/ { next }
  { print }
' > docs/refactor-103F-phase0-production-files.txt
wc -l < docs/refactor-103F-phase0-production-files.txt
xargs wc -l < docs/refactor-103F-phase0-production-files.txt | tail -1
shasum -a 256 docs/refactor-103F-phase0-production-files.txt
```

Recorded output:

```text
2231
844081 total
6e4073a0a0150e46c5ad9d0132c59f0dafef8c6757c551536940e81a530202d4  docs/refactor-103F-phase0-production-files.txt
```

The nine named preparatory targets were present in the list. Their baseline
line counts were:

| File | Lines |
| --- | ---: |
| `packages/wallet/src/SeamsWeb/operations/auth/login.ts` | 7,973 |
| `packages/wallet/src/SeamsWeb/signingSurface/BrowserSigningSurface.ts` | 6,699 |
| `packages/wallet/src/core/indexedDB/seamsWalletDB/repositories.ts` | 5,750 |
| `packages/wallet-server/src/router/cloudflare/d1/registration/d1WalletRegistrationService.ts` | 5,557 |
| `packages/wallet/src/SeamsWeb/operations/registration/registration.ts` | 4,667 |
| `packages/wallet/src/core/rpcClients/relayer/walletRegistration.ts` | 4,010 |
| `packages/wallet-server/src/router/domains/signingOperations/routerAbPrivateSigningWorker.ts` | 4,633 |
| `packages/wallet-server/src/router/transport/fetch/routes/thresholdEcdsa.ts` | 3,608 |
| `packages/wallet/src/SeamsWeb/operations/recovery/walletRecovery.ts` | 1,442 |
| **Total** | **44,339** |

The nine-target total is the sum of the individual `wc -l` values above; the
full inventory total is 844,081 lines. This Phase 0 slice deleted and moved
zero production lines, so the net live production-line delta is zero.

## Liveness ledger

The ledger uses two evidence sources for every retained responsibility:

1. export declarations and import/call-site search; and
2. assembly, route registration, or focused component coverage.

No path is classified `obsolete_or_unreachable` in this baseline. Consequently,
there is no deletion claim requiring the two-source obsolete proof. Existing
V1 paths remain explicit `rollout_boundary` entries until their named drain
gates close.

| Target | `live_r103f` | `live_unrelated` | `rollout_boundary` | Evidence roots |
| --- | --- | --- | --- | --- |
| `operations/auth/login.ts` | Exact local/linked authority selection, unlock, session read, and lock (`resolveLoginWalletUnlockSelectionForSubjectSet` 355, `resolveExactLinkedEmailOtpAuthority` 706, `unlock*` 2228–3542, `getWalletSession` 6235, `lock` 7936) | Threshold warmup and NEAR operational-key selection (`runThresholdLoginWarmupTasks` 5212, `selectNearOperationalPublicKeyForLogin` 7690) | `ActiveWalletSessionV1` and opaque-session adapter branches (imports 54, 1022, 1348, 4485, 6044, 6815) | `SeamsWeb.ts`, auth-menu controller/passkey callers; focused auth-menu continuation suite |
| `signingSurface/BrowserSigningSurface.ts` | Browser exact-record construction/replacement and signing surface (`BrowserSigningSurface` 2071; warm-session helper 779) | Generic signer-engine and NEAR locator operations (`nearEd25519PublicLocatorObservation` 866 and class methods) | Opaque-session auth materialization at 3060 | `SeamsWeb.ts:1056`, `browserSigningSurfaceAssembly.ts:611`; signing-surface imports |
| `core/indexedDB/seamsWalletDB/repositories.ts` | Authority installation, recovery projection, founding registration, and transactional local publication (types 287–455, repository 2601) | Other IndexedDB wallet and signer persistence methods on `SeamsWalletRepositories` | V1 session record comparison (`ActiveWalletSessionV1` import 104, comparator 1751) | `indexedDB/index.ts:16`, `unifiedIndexedDBManager.ts:99`, registration/signing-flow imports |
| `d1/registration/d1WalletRegistrationService.ts` | Registration activation, credential-free side-effect/replay boundary, and direct issuance (`CloudflareD1WalletRegistrationService` 1865; side-effect ports 970–1026) | ECDSA registration bootstrap and validation helpers (1336–1843) | V1 wallet-session mint calls (import 55, calls 2766 and 3058) | `d1RouterApiAuthService.ts:1774` constructs the service and supplies both side-effect stores |
| `operations/registration/registration.ts` | Hosted preparation, registration completion, activation, deferred provisioning, and public registration entrypoints (881, 1049, 2628, 4014, 4544) | ECDSA/NEAR ceremony-specific orchestration (1704) | Legacy browser-session writer `persistActiveWalletSessionAuthorizationFromRegistration` (import 190; calls 2094, 2466, 3467, 3828) | `SeamsWeb.ts`, public API near/evm modules, iframe registration callers |
| `core/rpcClients/relayer/walletRegistration.ts` | Strict registration response parsers and terminal completion boundary (1914, 2275, 2849, 2971, 3404) | Add-auth-method/add-signer and test-funding request clients (1957–3854) | Opaque-session ECDSA inventory adapter (`fetchWalletEcdsaKeyFactsInventoryWithOpaqueWalletSession` 3908, response construction 3940) | Registration operation imports, `walletRegistration` route, and auth-method/signer callers |
| `domains/signingOperations/routerAbPrivateSigningWorker.ts` | Exact normal-signing and step-up admission, replay, and worker route cores (1024, 2944, 4163, 4426, 4583) | Protocol/material source parsing and worker body builders (1393, 1854, 2037, 2179) | Reusable-session authorization/admission branches (`reusable_wallet_session` markers 134, 224–267, 1301, 3617) | `thresholdEd25519.ts`, `thresholdEcdsa.ts`, `normalSigningRouterProxy.ts`, and Cloudflare/Express adapters |
| `transport/fetch/routes/thresholdEcdsa.ts` | ECDSA route admission, strict activation, exact custody resolution, and pool-fill entrypoints (1616, 2438, 3252, 3449) | Derivation, presignature, and route transport helpers outside the session cutover | `not_v2` resolution (719–757), opaque fallback (2057, 2272), and reusable-session issue path (3187–3205) | `createFetchRouter.ts:255` and self-hosted worker `createSelfHostedCloudflareSigningWorker.ts:137` register the route |
| `operations/recovery/walletRecovery.ts` | Recovery coordinator handles and prepare/verify/finalize result boundaries (types 71–135, `WalletRecoveryCoordinator` 917) | None identified | None identified | `recovery-entrypoint.ts:2,28`, `SeamsWeb.ts`, and recovery public API imports |

## Focused test triage and repair

The default unit runner attempted to start a frontend web server that was not
available in this isolated worktree. `pnpm install --offline --frozen-lockfile`
also stopped at the environment boundary with
`ERR_PNPM_NO_OFFLINE_TARBALL` for `concurrently@9.2.0`. The focused runs used
the existing no-server Playwright configuration and temporary ignored dependency
links; those links were removed before commit.

Initial focused results, before test edits:

| Test | Result | Classification and evidence |
| --- | --- | --- |
| `authMenuPasskeyContinuation.unit.test.ts` | 17 passed, 4 failed | All four were `valid_test_needs_update`: discoverable local-wallet sync intentionally emits `walletId: null`; the Email OTP link fixture omitted the required target email and its callback mock used the pre-change target nesting; two Google OTP fixtures used flow IDs rejected by the exact login-flow parser. |
| `walletRecoverySourceSelection.unit.test.ts` | 1 passed, 3 failed | `valid_test_needs_update`: the three source-selection cases constructed retired flat `provenanceKind`; current selection requires a full active authority and reads `authority.provenance.kind`. |
| `passkeyCustodyRouteService.unit.test.ts` | 2 passed, 1 failed | `valid_test_needs_update`: the inline envelope-store port stub omitted `listWalletCredentialActivity`, so the replay invariant was never reached. |

Repairs stayed within the assigned tests. The auth-menu fixtures now use the
current null discoverable-sync result, required Email OTP target data and target
shape, and parser-valid Google flow identities. Recovery authority fixtures now
come from `buildLinkedDeviceManagementAuthorityFixture` with full owner
permissions. The custody-route stub implements the current
`listWalletCredentialActivity` port method. No production regression or
obsolete assertion was identified.

Final focused commands and results:

```text
pnpm exec playwright test -c playwright.local-no-server.config.ts unit/authMenuPasskeyContinuation.unit.test.ts --reporter=line
21 passed (969ms)

pnpm exec playwright test -c playwright.local-no-server.config.ts unit/walletRecoverySourceSelection.unit.test.ts --reporter=line
4 passed (503ms)

pnpm exec playwright test -c playwright.local-no-server.config.ts unit/passkeyCustodyRouteService.unit.test.ts --reporter=line
3 passed (487ms)
```
