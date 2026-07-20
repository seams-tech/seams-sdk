# Refactor 89: Clean Source Guards

Date created: June 26, 2026
Renamed: July 3, 2026 — from `refactor-9x-clean-source-guards.md`; all
referencing plans were updated.

Status: source guard profile green; Phase 0 complete; cleanup in progress.
Verified July 5, 2026: `pnpm -C tests run test:source-guards` passes
end-to-end after `build:sdk-full`, with all standalone source scripts passing
and 190/190 Playwright source-profile tests green.
This file is both a standing ledger (new temporary guards are recorded here as
they are added) and a cleanup plan.

Sequencing:

- Cleanup executes after [Refactor 88](./refactor-88-intended-behaviour-e2e.md)
  lands: the e2e contract suite is the replacement coverage that justifies
  deleting transitional guards. Do not delete lifecycle-seam guards before
  `test:intended` covers those seams.
- Guard retirement runs incrementally at Refactor 90 slice exits (90 plan
  Decided Point 14): a guard retires in the slice that makes its invariant
  structural (closed unions, branded IDs, generic lanes, boundary parsers).
- The final sweep is Refactor 90 Phase P3, which requires that no guard
  remains whose invariant is structurally enforced.

Related plans:

- [refactor-77-near-implicit-accounts.md](./refactor-77-near-implicit-accounts.md)
- [refactor-78-wallet-capability-bindings.md](./refactor-78-wallet-capability-bindings.md)
- [refactor-79-exact-signing-lane.md](./refactor-79-exact-signing-lane.md)
- [refactor-80-switch-case.md](./refactor-80-switch-case.md)
- [refactor-81-trim-rename-v1-v2.md](./refactor-81-trim-rename-v1-v2.md)
- [refactor-53-test-inventory.csv](./refactor-53-test-inventory.csv)

## Goal

Reduce temporary refactor guard debt after the current architecture stabilizes.

Source guards have been useful while broad identity, Router A/B, HSS, and route
boundary refactors were moving quickly. Many of those guards freeze transitional
source text, old symbol bans, route-shape bans, and implementation-specific
call-chain checks. They should be deleted once the same invariant is enforced by
domain types, boundary parsers, focused behavior tests, protocol vectors, or
formal verification.

This plan is the ledger for temporary guards. When a new temporary source guard
is added, add it here with its cleanup trigger.

## Policy

- Every new guard must be classified as `temporary`, `durable`, or `runtime`.
- Temporary guards need a cleanup trigger in this file.
- Durable guards protect security boundaries, platform boundaries, protocol
  vectors, or public API contracts. They stay unless replaced by stronger
  coverage.
- Runtime guards are production validation helpers, such as config validation.
  They are not cleanup debt.
- Prefer deleting temporary source guards after replacement coverage exists.
- Prefer behavior tests, type fixtures, discriminated unions, parser tests, and
  protocol vectors over source-text scans.
- Keep source guards narrow while they exist. Avoid broad string bans that make
  harmless refactors expensive.

## Removal Criteria

A temporary guard can be deleted when all of these are true:

- [ ] The protected behavior is enforced by a type, parser, protocol vector,
      formal check, or behavior test.
- [ ] The guard no longer catches an active migration risk.
- [ ] Any allowlist owned by the guard is empty or replaced by a typed boundary.
- [ ] `rg` confirms the obsolete symbol, route, or pattern is absent from active
      source outside historical docs and this cleanup plan.
- [ ] The replacement validation command is documented in the guard ledger row.

## New Guard Intake Template

Add a row here when adding a temporary guard:

| Field | Value |
| --- | --- |
| Guard | `path/to/guard.test.ts` |
| Owner refactor | `refactor-NN-name.md` |
| Why it exists | One sentence. |
| Cleanup trigger | Exact condition for deletion. |
| Replacement coverage | Test/type/parser/vector expected to replace it. |
| Status | `active`, `ready_to_delete`, or `deleted`. |

## Phase 0: Inventory

- [x] Inventory all current guard files and classify them as temporary, durable,
      or runtime.
- [x] Split large guard suites into rows by invariant when one file contains
      both durable and temporary checks.
- [x] Mark guard-owned allowlist files separately.
- [x] Add deletion triggers for every temporary guard.

Seed inventory from current source:

- `crates/router-ab-cloudflare/tests/secret_material_boundaries.rs`
- `crates/router-ab-core/tests/source_guards.rs`
- `crates/ed25519-hss/tests/materialization_graph_guard.rs`
- `tests/unit/*.guard.unit.test.ts`
- `tests/unit/*.behavior.guard.unit.test.ts`
- `tests/unit/*.domain.guard.unit.test.ts`
- `tests/unit/walletCapabilityBindings.sourceGuard.unit.test.ts`

Browser-dependent guardrails are guard-owned inventory, but they do not run in
`playwright.source.config.ts` because that profile intentionally has no
`webServer`. They remain explicit retained tests under the normal browser/unit
setup: `tests/unit/seamsWeb.duplicateIframes.guardrails.unit.test.ts` and
`tests/unit/signer-worker.guards.test.ts`.

Live scan, July 4, 2026:

- `rg --files -g '!**/target/**' tests crates | rg '(^|/)(.*guard.*|source_guards\.rs|materialization_graph_guard\.rs)$'`
  finds 49 guard/source-guard files.
- Extended guard-owned scan:
  `rg --files -g '!**/target/**' tests crates | rg -i '(^|/)(.*guard.*|source_guards\.rs|materialization_graph_guard\.rs|.*sourceguard.*)$'`
  finds 54 files after including camel-case `sourceGuard`, guard helper
  modules, and `walletIframeHost.configGuards.test.ts`.
- The refactor-numbered cleanup candidates have row-level verdicts in Phase 1,
  and `tests/unit/refactor73TypeFilename.guard.unit.test.ts` is deleted.
- Phase 0 mixed-suite split is recorded below for the large temporary suites
  that still bundle multiple invariants in one file:
  `tests/scripts/check-cloudflare-d1-runtime-boundaries.mjs`,
  `tests/scripts/check-intended-behaviour-contract-boundaries.mjs`.

Large mixed-suite invariant split, July 4, 2026:

| Guard shard | Invariant family | Cleanup trigger | Replacement coverage | Status |
| --- | --- | --- | --- | --- |
| `tests/scripts/check-cloudflare-d1-runtime-boundaries.mjs` D1/DO runtime graph | Cloudflare Router runtime remains D1/DO-only at persistence boundaries; Postgres runtime adapters, cron fallbacks, helper tooling, staging smoke jobs, and compiler scaffolding stay deleted. | Refactor 82 Phase 11/12 finishes the D1 route-family harness and the runtime graph is enforced by adapter tests and build config. | D1 adapter tests, route-family tests, CI workflow checks, and package build graph checks. | active |
| `tests/scripts/check-cloudflare-d1-runtime-boundaries.mjs` D1 staging/docs | D1 staging scripts, manifests, staging READMEs, billing/policy/observability docs, and current package links describe the D1-era system. | Staging/release scripts share typed helpers and docs lint or release probes own the current module paths. | Staging script unit tests, release probes, docs lint checks. | active |
| `tests/scripts/check-cloudflare-d1-runtime-boundaries.mjs` Router API service shape | Router API route capabilities are selected by structural service ports; routes are not mounted through an AuthService facade; service metadata stays explicit. | Refactor 82 Phase 11/12 route-family tests cover service-bag construction and route mounting directly. | `routes-d1` harness, service-port parser tests, route metadata tests. | active |
| `tests/scripts/check-cloudflare-d1-runtime-boundaries.mjs` registration ceremony split | Durable registration intent writers keep signer-set state; D1 ECDSA, Ed25519, and add-signer mechanics stay split from mixed ceremony service paths. | Deleted the ECDSA/Ed25519/add-signer source-shape shard after the D1 route-family split landed focused coverage. The remaining durable-intent and combined-state checks stay active. | `tests/unit/cloudflareD1RouterApiRegistrationCeremony.unit.test.ts`, `tests/unit/cloudflareD1RouterApiWalletAuthMethods.unit.test.ts`, durable registration intent parser tests, type fixtures. | narrowed |
| `tests/scripts/check-cloudflare-d1-runtime-boundaries.mjs` HSS/authority boundaries | Ed25519 HSS ceremony state is DO-backed; wallet registration and Email OTP grant authority bind to stable fields. | D1 route-family tests and HSS protocol tests cover ceremony durability and authority binding. | DO-backed HSS ceremony tests, grant parser tests, route-family tests. | active |
| `tests/scripts/check-intended-behaviour-contract-boundaries.mjs` contract shape | The intended suite stays five Chromium lifecycle specs with zero retries, high-level harness scripts, public action sequences, and no private SDK/runtime imports. | The suite is remote-CI enforced and the lifecycle contract shape is owned by CI plus public API contract tests. | `pnpm test:intended`, `pnpm test:intended:ci`, public SDK contract tests. | active |
| `tests/scripts/check-intended-behaviour-contract-boundaries.mjs` retired mock surfaces | Deleted mocked runtime files, fake relay launchers, setup wrappers, `window.testUtils`, `__testOverrides`, and broad browser mutation hooks stay absent. | Retired surfaces stay absent for one release branch and source/package lint owns the file/hook bans. | Source-layout checks, package-script checks, setup/harness unit tests. | active |
| `tests/scripts/check-intended-behaviour-contract-boundaries.mjs` retained boundary audit | Generic browser bootstrap consumers, wallet-iframe tests, Lit component tests, SeamsWeb setup tests, and confirm-flow tests have explicit `keep` rows. | Deleted the retained-boundary audit shard from the broad contract-boundary checker after moving the row/evidence checks into the ledger verifier. | `check:refactor88-test-ledger:complete`, retained-boundary source evidence checks. | deleted |
| `tests/scripts/check-refactor88-test-ledger.mjs` retained boundary audit | The Refactor 88 ledger owns retained focused browser/unit coverage rows and source evidence for wallet-iframe, Lit component, SeamsWeb setup, confirm-flow, and generic bootstrap consumers. | Refactor 88 closes and retained-boundary coverage is either durable behavior coverage or no longer part of the cleanup ledger. | `check:refactor88-test-ledger:complete`, `test:source-guards`. | active |
| `tests/scripts/check-intended-behaviour-contract-boundaries.mjs` startup/OIDC gate | Intended commands, Google OIDC service-account token refresh, CI startup, route gating, suite timeout, and sibling pre-merge gate references stay wired. | Remote CI owns startup and sibling plans no longer need local checklist guards. | CI workflow gate, `ensure:intended-google-token`, `playwright.intended.ci.config.ts`. | active |
| `tests/scripts/check-intended-behaviour-contract-boundaries.mjs` runtime oracles | Failure-string tripwires stay versioned; NEAR and ECDSA signatures are cryptographically verified; structured auth-path events and external-only request stubs stay enforced. | Intended harness behavior is covered by direct harness tests or remote CI artifact assertions. | Harness unit tests, intended contracts, compact trace assertions. | active |
| `tests/scripts/check-intended-behaviour-contract-boundaries.mjs` mutation proof | Mutation manifest rows, exact oracles, proof statuses, detected evidence, and blocker policy stay machine-readable. | Deleted the source-shaped mutation row assertions after Phase 3B completion passed with all rows `detected`; the dedicated mutation self-check now owns this invariant. | `check:intended-mutation-self-check:complete`, scratch-branch mutation evidence. | deleted |
| `crates/router-ab-cloudflare/tests/secret_material_boundaries.rs` secret-material boundaries | Cloudflare route and worker code avoid joined-state material, recipient-output combining, and signer plaintext decoding. | Renamed out of the broad `source_guards.rs` file; protocol/vector tests and type-level material boundaries later cover secret material flow directly. | `cargo test --manifest-path crates/router-ab-cloudflare/Cargo.toml --test secret_material_boundaries`; later HSS protocol vectors, worker request parser tests, materialization graph checks. | active |
| `crates/router-ab-cloudflare/tests/source_guards.rs` route boundaries | Strict router routes apply CORS, boundary parsers, bearer-JWT admission, replay reservation, and public-keyset boundaries. | Deleted the broad source-guard file after moving route literal assertions to `route_paths.rs`, strict-router CORS assertions to `strict_router_cors_boundaries.rs`, bearer-admission/parser/replay assertions to `strict_router_route_boundaries.rs`, and secret-material assertions to `secret_material_boundaries.rs`. | `cargo test --manifest-path crates/router-ab-cloudflare/Cargo.toml --test route_paths`; `cargo test --manifest-path crates/router-ab-cloudflare/Cargo.toml --test strict_router_cors_boundaries`; `cargo test --manifest-path crates/router-ab-cloudflare/Cargo.toml --test strict_router_route_boundaries`; `cargo test --manifest-path crates/router-ab-cloudflare/Cargo.toml --test secret_material_boundaries`. | deleted |
| `crates/router-ab-cloudflare/tests/ecdsa_hss_activation_boundaries.rs` ECDSA HSS activation/export split | ECDSA HSS export, registration, activation, direct activation delivery, sanitized export audit events, and no-canonical-export-key boundaries stay on protocol-specific deriver/activation paths. | Moved out of `source_guards.rs` into a focused Rust integration test; later typed route commands and protocol tests can narrow or replace the remaining source-shape assertions. | `cargo test --manifest-path crates/router-ab-cloudflare/Cargo.toml --test ecdsa_hss_activation_boundaries`; later ECDSA HSS route tests, activation parser tests, protocol vectors. | active |
| `crates/router-ab-cloudflare/tests/ecdsa_hss_normal_signing_boundaries.rs` ECDSA HSS normal-signing/presignature split | ECDSA HSS normal signing uses active material only, binds full active-state identity, materializes before handler calls, uses one-use presignature storage, and keeps presignature pool state distinct. | Moved out of `source_guards.rs` into a focused Rust integration test; later handler/storage tests and protocol vectors can narrow or replace the remaining source-shape assertions. | `cargo test --manifest-path crates/router-ab-cloudflare/Cargo.toml --test ecdsa_hss_normal_signing_boundaries`; later ECDSA HSS normal-signing handler tests, presignature pool tests, protocol vectors. | active |
| `crates/router-ab-cloudflare/tests/normal_signing_worker_boundaries.rs` normal-signing worker flow | Normal signing stays off A/B derivation handlers, loads active material before handlers, uses SigningWorker names, routes through strict worker dispatch, keeps private worker dispatch behind internal auth, rejects legacy v1 flow symbols, and keeps private routes away from Wallet Session parsing. | Moved out of `source_guards.rs` into a focused Rust integration test; later public/private handler tests, worker-auth tests, and protocol fixtures can narrow or replace the remaining source-shape assertions. | `cargo test --manifest-path crates/router-ab-cloudflare/Cargo.toml --test normal_signing_worker_boundaries`; later Router normal-signing handler tests, worker auth tests, protocol fixture tests. | active |
| `tests/unit/ed25519HssMaterialBoundaries.guard.unit.test.ts` no-HSS login material | Shared HSS setup helpers, old reconstruction input shapes, raw material names, and stale HSS material paths stay out of active login/signing flows. | Playwright wrapper deleted; source-shaped assertions moved to `tests/scripts/check-ed25519-hss-material-boundaries.mjs`. Later worker command type fixtures and Ed25519 HSS route/material tests can narrow or delete the standalone check. | `tests/scripts/check-ed25519-hss-material-boundaries.mjs`; later worker command type fixtures and Ed25519 HSS route/material tests. | deleted |
| `tests/unit/ed25519HssMaterialBoundaries.guard.unit.test.ts` Ed25519 session state | Current finalized Ed25519 material-state and login unseal resolver shapes stay aligned with session records. | Playwright wrapper deleted; source-shaped assertions moved to `tests/scripts/check-ed25519-hss-material-boundaries.mjs`. Later material-state and parser tests can narrow or delete the standalone check. | `tests/scripts/check-ed25519-hss-material-boundaries.mjs`; later Ed25519 material-state tests and session-record parser tests. | deleted |
| `tests/unit/ed25519HssMaterialBoundaries.guard.unit.test.ts` restore/sync/link-device exceptions | Recovery, sync, and the Refactor 84 link-device stub stay explicitly recorded while they share no-HSS setup helpers. | Playwright wrapper deleted; source-shaped assertions moved to `tests/scripts/check-ed25519-hss-material-boundaries.mjs`. Later recovery/link-device coverage can narrow or delete the standalone check. | `tests/scripts/check-ed25519-hss-material-boundaries.mjs`; later recovery fifth spec and link-device route/session tests. | deleted |
| `tests/unit/routerAbNormalSigningSdk.guard.unit.test.ts` local topology | Local Caddy, Router ports, `pnpm router`, docs, committed smoke fixtures, and active route namespace stay aligned. | Playwright wrapper deleted; source-shaped assertions moved to `tests/scripts/check-router-ab-normal-signing-sdk-boundaries.mjs`. Later route-definition and parity tests can narrow or delete the standalone check. | `tests/scripts/check-router-ab-normal-signing-sdk-boundaries.mjs`; later route-definition tests, local/cloudflare parity tests, release probes. | deleted |
| `tests/unit/routerAbNormalSigningSdk.guard.unit.test.ts` SDK/session auth surface | SDK helper surface uses Wallet Session request builders, bearer JWT discriminators, JWT-only session issuance, and shared Router A/B claim boundaries. | Playwright wrapper deleted; source-shaped assertions moved to `tests/scripts/check-router-ab-normal-signing-sdk-boundaries.mjs`. Later SDK relayer and parser tests can narrow or delete the standalone check. | `tests/scripts/check-router-ab-normal-signing-sdk-boundaries.mjs`; later SDK relayer tests, JWT claim parser tests. | deleted |
| `tests/unit/routerAbNormalSigningSdk.guard.unit.test.ts` active material/readiness | Ed25519 and ECDSA signing read Router A/B ready state and worker material handles without implicit persistence fallbacks or HSS repair. | Playwright wrapper deleted; source-shaped assertions moved to `tests/scripts/check-router-ab-normal-signing-sdk-boundaries.mjs`. Later signing behavior and material-state tests can narrow or delete the standalone check. | `tests/scripts/check-router-ab-normal-signing-sdk-boundaries.mjs`; later Ed25519/ECDSA signing tests, material-state parser tests. | deleted |
| `tests/unit/routerAbNormalSigningSdk.guard.unit.test.ts` budget/reconciliation | Public normal-signing route cores keep server budget reservation hooks; budget projection uses committed `remainingUses`; wallet-budget reconciliation avoids local warm-session consume ports. | Playwright wrapper deleted; source-shaped assertions moved to `tests/scripts/check-router-ab-normal-signing-sdk-boundaries.mjs`. Later grant-use migration and operation-fingerprint tests can narrow or delete the standalone check. | `tests/scripts/check-router-ab-normal-signing-sdk-boundaries.mjs`; later intended spend contracts, grant-use tests, operation-fingerprint concurrency tests. | deleted |
| `tests/unit/exactSigningLaneAuthorityBoundaries.guard.unit.test.ts` exact lane identity | Playwright wrapper deleted after the source-shaped assertion moved to a standalone check. | Exact-lane type fixtures and builders reject broad or partial identity states. | `tests/scripts/check-exact-signing-lane-authority-boundaries.mjs`; later type fixtures and lane builder parser tests can narrow the source check. | deleted |
| `tests/unit/exactSigningLaneAuthorityBoundaries.guard.unit.test.ts` fallback selector bans | Playwright wrapper deleted after the source-shaped assertion moved to a standalone check. | Duplicate-record behavior tests and exact lookup APIs make fallback selection impossible. | `tests/scripts/check-exact-signing-lane-authority-boundaries.mjs`; later duplicate-record tests, exact lookup tests, and type fixtures can narrow the source check. | deleted |
| `tests/unit/exactSigningLaneAuthorityBoundaries.guard.unit.test.ts` HSS context scope | Playwright wrapper deleted after the source-shaped assertion moved to a standalone check. | HSS digest-boundary vectors own context-field composition. | `tests/scripts/check-exact-signing-lane-authority-boundaries.mjs`; later HSS vector tests and protocol fixtures can narrow the source check. | deleted |
| `tests/unit/exactSigningLaneAuthorityBoundaries.guard.unit.test.ts` Ed25519 mutation authority | Playwright wrapper deleted after the source-shaped assertion moved to a standalone check. | Ed25519 lane mutation tests and `@ts-expect-error` fixtures reject broad casts. | `tests/scripts/check-exact-signing-lane-authority-boundaries.mjs`; later Ed25519 lane tests and type fixtures can narrow the source check. | deleted |
| `tests/unit/exactSigningLaneAuthorityBoundaries.guard.unit.test.ts` ECDSA session records | Playwright wrapper deleted after the source-shaped assertion moved to a standalone check. | ECDSA parser tests and server record type fixtures own the record shape. | `tests/scripts/check-exact-signing-lane-authority-boundaries.mjs`; later ECDSA parser tests and server record type fixtures can narrow the source check. | deleted |
| `tests/unit/emailOtpOperationSplit.guard.unit.test.ts` challenge separation | Transaction signing APIs cannot issue export challenges; signing and export challenge issuance stay separate. | Operation-specific APIs and parser tests make cross-operation challenge issuance unrepresentable. | `tests/scripts/check-email-otp-operation-split.mjs`; later Email OTP operation parser tests and coordinator behavior tests can narrow the source check. | deleted |
| `tests/unit/emailOtpOperationSplit.guard.unit.test.ts` coordinator/runtime facade | Email OTP coordinator remains a thin runtime facade; obsolete wallet-auth proof resolver stays deleted; authority identity is read through accessors. | Coordinator behavior tests and auth-subject builders cover runtime boundaries. | `tests/scripts/check-email-otp-operation-split.mjs`; later coordinator unit tests and auth-subject parser tests can narrow the source check. | deleted |
| `tests/unit/emailOtpOperationSplit.guard.unit.test.ts` ECDSA exact-lane reauth | Fresh Email OTP decisions are planner-owned; ECDSA signing selects exact lanes before material lookup; ready and reauth branches carry committed lanes. | ECDSA selection tests and reauth behavior tests cover every branch. | `tests/scripts/check-email-otp-operation-split.mjs`; later ECDSA selection tests, reauth tests, and type fixtures can narrow the source check. | deleted |
| `tests/unit/emailOtpOperationSplit.guard.unit.test.ts` export/sign/step-up committed lanes | ECDSA export, Ed25519 export, NEAR step-up, and exhausted ECDSA lanes consume committed lanes with explicit wallet-session authority. | Intended export/step-up contracts plus focused committed-lane tests cover these flows. | `tests/scripts/check-email-otp-operation-split.mjs`; later intended contracts and committed-lane unit tests can narrow the source check. | deleted |
| `tests/unit/emailOtpOperationSplit.guard.unit.test.ts` diagnostics and restore boundaries | EVM-family signing avoids legacy read-side restore fallbacks; diagnostics remain observational. | Restore behavior tests and diagnostics type boundaries replace source scans. | `tests/scripts/check-email-otp-operation-split.mjs`; later restore tests and diagnostics/type fixtures can narrow the source check. | deleted |

Current guard-owned inventory:

| File | Classification | Cleanup trigger / owner |
| --- | --- | --- |
| `crates/ed25519-hss/tests/materialization_graph_guard.rs` | durable | Keep as the Ed25519 HSS materialization graph/doc-boundary guard unless protocol vectors replace the documented-helper invariant. |
| `crates/router-ab-cloudflare/tests/source_guards.rs` | deleted | Deleted after all remaining checks moved into named boundary files: `route_paths.rs`, `strict_router_cors_boundaries.rs`, `strict_router_route_boundaries.rs`, `ecdsa_hss_activation_boundaries.rs`, `ecdsa_hss_normal_signing_boundaries.rs`, `normal_signing_worker_boundaries.rs`, and `secret_material_boundaries.rs`. |
| `crates/router-ab-cloudflare/tests/secret_material_boundaries.rs` | durable | Focused secret-material boundary tests split out of the broad Cloudflare source guard. Keep until protocol vectors and worker request parser tests directly assert joined-state, recipient-output-combine, and signer-plaintext boundaries. |
| `crates/router-ab-cloudflare/tests/ecdsa_hss_activation_boundaries.rs` | durable | Focused ECDSA-HSS activation/export boundary tests split out of the broad Cloudflare source guard. Keep until ECDSA-HSS route behavior tests, activation parser tests, and protocol vectors directly assert client-only export, protocol-specific registration, direct activation delivery, sanitized export audit events, and no canonical export-key reconstruction. |
| `crates/router-ab-cloudflare/tests/ecdsa_hss_normal_signing_boundaries.rs` | durable | Focused ECDSA-HSS normal-signing and presignature boundary tests split out of the broad Cloudflare source guard. Keep until ECDSA-HSS handler/storage tests and protocol vectors directly assert active-material binding, full active-state identity, request-bound presignature use, pool reservation ordering, and one-use storage separation. |
| `crates/router-ab-cloudflare/tests/normal_signing_worker_boundaries.rs` | durable | Focused normal-signing worker and legacy-symbol boundary tests split out of the broad Cloudflare source guard. Keep until handler, worker-auth, and protocol-fixture tests directly assert normal-signing call-chain boundaries, strict worker dispatch, active-material ordering, and legacy v1 symbol deletion. |
| `crates/router-ab-cloudflare/tests/strict_router_cors_boundaries.rs` | durable | Stable strict-router CORS boundary tests split out of the broad Cloudflare source guard. Keep until Cloudflare route behavior/parity tests directly assert public-keyset wildcard CORS and exact-origin bearer-route CORS. |
| `crates/router-ab-cloudflare/tests/strict_router_route_boundaries.rs` | durable | Stable strict-router bearer-admission, parser-boundary, normal-signing replay-order, and admission-candidate tests split out of the broad Cloudflare source guard. Keep until route-family behavior/parity tests directly assert bearer JWT admission, boundary parser usage, replay reservation ordering, and admission candidate naming. |
| `crates/router-ab-core/tests/source_guards.rs` | temporary | Phase 2 retires core Router boundary scans after module visibility, core protocol unit tests, and protocol vectors own the invariant. |
| `tests/unit/accountSignerLifecycle.domain.guard.unit.test.ts` | deleted | Deleted after signer lifecycle write-field and shared signer-domain constant source checks moved into `tests/scripts/check-account-signer-lifecycle-boundaries.mjs`, wired through `test:source-guards`. |
| `tests/unit/authSecretTerminology.guard.unit.test.ts` | deleted | Deleted after the auth-neutral docs terminology invariant moved into `tests/scripts/check-auth-secret-terminology.mjs`, wired through `test:source-guards`. |
| `tests/unit/crossPlatformBoundaries.guard.unit.test.ts` | deleted | Deleted after its platform API, secret-material, runtime-port, role-local persistence, signer-command schema, and export-material boundary checks moved into `tests/scripts/check-cross-platform-boundaries.mjs`, wired through `test:source-guards`. |
| `tests/unit/emailOtpEcdsaBranchIsolation.guard.unit.test.ts` | deleted | Deleted after central domain-brand ownership, passkey PRF persistence, wallet-subject vocabulary, and temporary diagnostic cleanup checks moved into `tests/scripts/check-email-otp-ecdsa-branch-isolation.mjs`, wired through `test:source-guards`. |
| `tests/unit/emailOtpOperationSplit.guard.unit.test.ts` | deleted | Deleted after transaction/export challenge separation, coordinator facade, exact-lane reauth, committed-lane export/sign/step-up, seal-transport, and diagnostics source checks moved into `tests/scripts/check-email-otp-operation-split.mjs`, wired through `test:source-guards`. |
| `tests/unit/emailOtpRecoveryCodeLeakage.guard.unit.test.ts` | deleted | Deleted after generated-key containment, plaintext-backup confinement, iframe exposure, logging/telemetry, storage, brand-cast, and backup-repository checks moved into `tests/scripts/check-email-otp-recovery-code-leakage.mjs`, wired through `test:source-guards`. |
| `tests/unit/emailOtpSigningSession.deviceEscrow.behavior.guard.unit.test.ts` | deleted | Deleted after the fifth recovery intended spec covered email recovery into signing and the surviving device-local `enc_s(S)`, recovery-wrapped escrow, zeroization, and lock-path checks moved into `tests/scripts/check-email-otp-device-escrow-boundaries.mjs`, wired through `test:source-guards`. |
| `tests/unit/helpers/signingEngineArchitectureGuard.ts` | deleted | Deleted 118-line helper after the final `signingEngineArchitecture.*` Playwright importer moved to `tests/scripts/check-signing-engine-architecture-boundaries.mjs`. |
| `tests/unit/helpers/signingEngineEcdsaIdentityGuard.ts` | deleted | Deleted 255-line helper after the final `signingEngineEcdsaIdentity.*` Playwright importer moved to `tests/scripts/check-signing-engine-ecdsa-identity-boundaries.mjs`. |
| `tests/unit/indexedDBConsolidation.guard.unit.test.ts` | deleted | Deleted after browser-backed IndexedDB schema/repository tests owned persistence behavior and the remaining raw IndexedDB/clientDB escape checks moved into `tests/scripts/check-indexeddb-consolidation-boundaries.mjs`, wired through `test:source-guards`. |
| `tests/unit/keyExport.behavior.guard.unit.test.ts` | deleted | Deleted after intended contracts owned public exact-lane export success and the remaining AccountMenuButton/export-modal source-boundary checks moved into `tests/scripts/check-key-export-boundaries.mjs`, wired through `test:source-guards`. |
| `tests/unit/nonceCoordinator.durableArchitecture.guard.unit.test.ts` | durable | Keep as the nonce coordinator architecture guard unless package-boundary tests and nonce-lane repository tests cover the same storage/import boundaries. |
| `tests/unit/seamsAuthMenuPublicEntry.guard.unit.test.ts` | deleted | Deleted after package export checks and `tests/unit/seamsAuthMenu.ssr.unit.test.ts` owned the public entrypoint; pre-delete `rg` found no product/test use of `seamsAuthMenuCompat` outside the guard, and the package export contract now rejects compat keys. The public shell no longer statically imports component CSS, leaving styles behind `@seams/sdk/react/styles` for SSR-safe loading. |
| `tests/unit/passkeyRegistrationRollback.guard.unit.test.ts` | deleted | Deleted after its rollback-state, signer-set registration, and deleted continuation-auth checks moved into `tests/scripts/check-passkey-registration-rollback-boundaries.mjs`, wired through `test:source-guards`. |
| `tests/unit/legacySeamsWebFacadeNames.guard.unit.test.ts` | deleted | Deleted after the retired facade-name invariant moved to durable public package-export coverage in `tests/unit/packageExports.contract.unit.test.ts`. |
| `tests/unit/platformRuntimeBoundaries.guard.unit.test.ts` | deleted | Deleted after runtime, browser adapter, native facade, WalletIframe import, and chain-signer routing boundary checks moved into `tests/scripts/check-platform-runtime-boundaries.mjs`, wired through `test:source-guards`. |
| `tests/unit/webauthnOriginPolicy.guard.unit.test.ts` | deleted | Deleted after the WebAuthn expected-origin invariant moved into `tests/scripts/check-webauthn-origin-policy.mjs`, wired through `test:source-guards`. |
| `tests/unit/seamsWebPublicSurfaceBoundaries.guard.unit.test.ts` | deleted | Deleted after moving namespace split, signing-surface dependency, root export, import-direction, iframe primitive, auth-method folder, and native-facade checks into `tests/scripts/check-seams-web-public-surface-boundaries.mjs`, wired through `test:source-guards`. |
| `tests/unit/headlessGoogleEmailOtpFlowBoundaries.guard.unit.test.ts` | deleted | Deleted after `googleEmailOtpWalletAuthFlow`, wallet-iframe handle, and SeamsAuthMenu headless tests covered the runtime paths and the remaining demo/public API/source-boundary checks moved into `tests/scripts/check-headless-google-email-otp-flow-boundaries.mjs`, wired through `test:source-guards`. |
| `tests/unit/emailOtpRegistrationBoundaries.guard.unit.test.ts` | deleted | Deleted after Email OTP registration flow, reroll, iframe-handle, route, and parser tests covered the runtime paths and the remaining source-boundary checks moved into `tests/scripts/check-email-otp-registration-boundaries.mjs`, wired through `test:source-guards`. |
| `tests/unit/workspacePackageBoundaries.guard.unit.test.ts` | deleted | Deleted after moving package-root, type-path, deployable-app import, and native import checks into `tests/scripts/check-workspace-package-boundaries.mjs`, wired through `test:source-guards`. |
| `tests/unit/walletSessionVocabularyBoundaries.guard.unit.test.ts` | deleted | Deleted after old signing-grant name bans, Router A/B Wallet Session JWT claim checks, docs terminology checks, signing auth-token naming checks, and `sessionId` classification allowlists moved into `tests/scripts/check-wallet-session-vocabulary-boundaries.mjs`, wired through `test:source-guards`. |
| `tests/unit/exactLookupNoFallbackBoundaries.guard.unit.test.ts` | deleted | Deleted after exact lookup / no-fallback source checks moved into `tests/scripts/check-exact-lookup-no-fallback-boundaries.mjs`, wired through `test:source-guards`. |
| `tests/unit/ed25519HssMaterialBoundaries.guard.unit.test.ts` | deleted | Deleted after prepared issuer command, worker-owned handle, raw material marker, restore persistence, recovery-code authorization, and active session-state source checks moved into `tests/scripts/check-ed25519-hss-material-boundaries.mjs`, wired through `test:source-guards`. |
| `tests/unit/keyMaterialBrandingBoundaries.guard.unit.test.ts` | deleted | Deleted after key-material branding and grant-lifecycle source checks moved into `tests/scripts/check-key-material-branding-boundaries.mjs`, wired through `test:source-guards`. |
| `tests/unit/exactSigningLaneAuthorityBoundaries.guard.unit.test.ts` | deleted | Deleted after exact identity, fallback selector, export transport, HSS context, Ed25519 mutation, ECDSA server-record, signer-slot, lane-key, grant-clearing, availability, unsafe-cast, and selected-wallet profile checks moved into `tests/scripts/check-exact-signing-lane-authority-boundaries.mjs`, wired through `test:source-guards`. |
| `tests/unit/routeLifecycleDomainBoundaries.guard.unit.test.ts` | deleted | Deleted after route/lifecycle source checks moved into `tests/scripts/check-route-lifecycle-domain-boundaries.mjs`, wired through `test:source-guards`. |
| `tests/scripts/check-cloudflare-d1-runtime-boundaries.mjs` | temporary | Refactor 82 owns retirement after D1 runtime, CI, docs, route capability, and no-Postgres checks are converted to durable route/runtime tests. |
| `tests/unit/registrationCapabilitySubjects.guard.unit.test.ts` | deleted | Deleted after role-local ECDSA handle ownership, wallet unlock subject, visible iframe passkey registration, prepared registration route, registration precompute, active-state/persistence-subject, Email OTP commit, and unlock activation-plan checks moved into `tests/scripts/check-registration-capability-subjects.mjs`, wired through `test:source-guards`. |
| `tests/scripts/check-intended-behaviour-contract-boundaries.mjs` | temporary | Refactor 88 owns retirement after `test:intended` is remote-CI enforced and retired setup/runtime files stay absent for one release branch; the Phase 3B mutation-proof shard has moved to `check:intended-mutation-self-check:complete`, and retained-boundary audit ownership has moved to `check:refactor88-test-ledger:complete`. |
| `tests/scripts/check-refactor88-test-ledger.mjs` | temporary | Refactor 88 owns retirement after the exhaustive test ledger closes; currently guards ledger completeness plus retained-boundary audit evidence while the cleanup/deletion sweep is active. |
| `tests/unit/passkeyRegistrationButtonBoundaries.guard.unit.test.ts` | deleted | Deleted after retained Lit component tests owned button behavior and the import-independence check moved into `tests/scripts/check-passkey-registration-button-boundaries.mjs`, wired through `test:source-guards`. |
| `tests/unit/routerAbNormalSigningSdk.guard.unit.test.ts` | deleted | Deleted after local topology, Wallet Session request-builder, active material/readiness, route-core, legacy-route, and budget/reconciliation source checks moved into `tests/scripts/check-router-ab-normal-signing-sdk-boundaries.mjs`, wired through `test:source-guards`. |
| `tests/unit/routerAbServerWalletSessionClaimBoundary.guard.unit.test.ts` | deleted | Deleted after Router A/B wallet-session legacy claim-kind, exact claim-builder, canonical ECDSA-HSS scope comparison, and internal-auth helper checks moved into `tests/scripts/check-router-ab-server-wallet-session-claim-boundaries.mjs`, wired through `test:source-guards`. |
| `tests/unit/seamsWeb.duplicateIframes.guardrails.unit.test.ts` | durable | Keep as browser behavior coverage for duplicate wallet-overlay prevention. |
| `tests/unit/signer-worker.guards.test.ts` | durable | Keep as worker secret-field rejection coverage unless generated worker protocol fixtures cover the same request-policy boundary. |
| `tests/unit/signerDomain.guard.unit.test.ts` | deleted | Deleted after folding its wallet/signer shared-constant checks into account signer lifecycle coverage; those checks now live in `tests/scripts/check-account-signer-lifecycle-boundaries.mjs`, including `packages/sdk-web/src/core/types/seams.ts` coverage. |
| `tests/unit/signingEngineArchitecture.flows.guard.unit.test.ts` | deleted | Deleted 380-line flow architecture Playwright source guard after moving the same flow, import-direction, confirmation-boundary, and prompt-owner checks into `tests/scripts/check-signing-engine-architecture-boundaries.mjs`, wired through `test:source-guards`. |
| `tests/unit/signingEngineArchitecture.ownership.guard.unit.test.ts` | deleted | Deleted 297-line ownership architecture Playwright source guard after moving the same README, session-domain, coordinator, and sibling-import checks into `tests/scripts/check-signing-engine-architecture-boundaries.mjs`, wired through `test:source-guards`. |
| `tests/unit/signingEngineArchitecture.state.guard.unit.test.ts` | deleted | Deleted 244-line state architecture Playwright source guard after moving the same selected-lane, lifecycle-state, execution-boundary, and duplicate-shape checks into `tests/scripts/check-signing-engine-architecture-boundaries.mjs`, wired through `test:source-guards`. |
| `tests/unit/signingEngineArchitecture.threshold.guard.unit.test.ts` | deleted | Deleted 109-line threshold architecture Playwright source guard after moving the same threshold/session-boundary and warm-session cache checks into `tests/scripts/check-signing-engine-architecture-boundaries.mjs`, wired through `test:source-guards`. |
| `tests/unit/signingEngineEcdsaIdentity.exportAndFixtures.guard.unit.test.ts` | deleted | Deleted 214-line ECDSA export/fixture identity Playwright source guard after moving Email OTP export identity, HSS export digest, budget fallback, BrowserSigningSurface, and public fixture checks into `tests/scripts/check-signing-engine-ecdsa-identity-boundaries.mjs`, wired through `test:source-guards`. |
| `tests/unit/signingEngineEcdsaIdentity.lifecycle.guard.unit.test.ts` | deleted | Deleted 385-line ECDSA lifecycle identity Playwright source guard after moving optional lifecycle field, provision-plan builder, raw parser, wallet-unlock, recovery/link-device, logging, activation branch, cast, and spread checks into `tests/scripts/check-signing-engine-ecdsa-identity-boundaries.mjs`, wired through `test:source-guards`. |
| `tests/unit/signingEngineEcdsaIdentity.publicSurfaces.guard.unit.test.ts` | deleted | Deleted 449-line ECDSA public-surface identity Playwright source guard after moving public API, iframe payload, key-ref, role-local bootstrap, and WASM export checks into `tests/scripts/check-signing-engine-ecdsa-identity-boundaries.mjs`, wired through `test:source-guards`. |
| `tests/unit/stableExperimentalExportBoundaries.guard.unit.test.ts` | deleted | Deleted after moving the stable/experimental package export boundary assertions into `tests/unit/packageExports.contract.unit.test.ts`. |
| `tests/unit/thresholdEcdsa.behavior.guard.unit.test.ts` | deleted | Deleted after the ECDSA HSS old-v1 deletion, role-local authorization, refill wiring, and no-export-material checks moved into `tests/scripts/check-threshold-ecdsa-hss-boundaries.mjs`, wired through `test:source-guards`. |
| `tests/unit/thresholdEd25519.nearSigningQueue.guard.unit.test.ts` | deleted | Deleted after threshold Ed25519 NEAR signing queue source checks moved into `tests/scripts/check-threshold-ed25519-near-signing-queue.mjs`, wired through `test:source-guards`. |
| `tests/unit/thresholdEd25519PresignNonceLifecycle.guard.unit.test.ts` | deleted | Deleted after the Ed25519 presign nonce burn-order and CSPRNG handle checks moved into `tests/scripts/check-threshold-ed25519-presign-nonce-lifecycle.mjs`, wired through `test:source-guards`. |
| `tests/unit/walletCapabilityBindings.sourceGuard.allowlist.json` | deleted | Deleted after the remaining wallet-scoped event/trace compatibility projections moved from `accountId` payloads to explicit `walletId` payloads. `tests/scripts/check-wallet-capability-bindings-source-guard.mjs` now fails if the JSON allowlist is recreated and still rejects stale built-in boundary exemptions. |
| `tests/unit/walletCapabilityBindings.sourceGuard.unit.test.ts` | deleted | Deleted after wallet capability source checks moved into `tests/scripts/check-wallet-capability-bindings-source-guard.mjs`, wired through `test:source-guards`; the JSON allowlist is retired and the standalone check enforces that it stays deleted. |
| `tests/unit/walletIframeHost.configGuards.test.ts` | runtime | Keep as unit coverage for production iframe host config guard helpers. |
| `tests/unit/walletScopedLookups.guard.unit.test.ts` | deleted | Deleted after the D1 wallet-id parser behavior assertion moved into `tests/unit/domainIds.boundary.unit.test.ts` and the remaining wallet-scoped lookup / NEAR projection source checks moved into `tests/scripts/check-wallet-scoped-lookup-boundaries.mjs`, wired through `test:source-guards`. |

## Phase 1: Remove Refactor-Number Guard Suites

These are the easiest cleanup candidates because their names already encode a
past refactor rather than a durable product invariant.

Status: initial July 4 checklist complete for the refactor-numbered guard
family. Refactor 73 reached `ready_to_delete` and was removed; the generic
source guards now use stable invariant names. No refactor-numbered guard
filenames remain under `tests/unit`; the 82/83 owner-plan gate invariants
continue under stable guard names until replacement coverage lands.

| Guard | Owner refactor | Cleanup trigger | Replacement coverage | Status |
| --- | --- | --- | --- | --- |
| `tests/unit/refactor79ExactSigningLane.guard.unit.test.ts` | Refactor 79 | Refactor-numbered file was moved to stable exact signing-lane authority coverage. | `tests/unit/exactSigningLaneAuthorityBoundaries.guard.unit.test.ts`. | moved |
| `tests/unit/refactor80SwitchCase.guard.unit.test.ts` | Refactor 80 | Refactor-numbered file first moved to stable route/lifecycle domain-boundary coverage, then the source-shaped invariant moved out of Playwright. | `tests/scripts/check-route-lifecycle-domain-boundaries.mjs`, run by `pnpm -C tests run check:route-lifecycle-domain-boundaries` and `pnpm -C tests run test:source-guards`. | deleted |
| `tests/unit/refactor74LegacyFallbacks.guard.unit.test.ts` | Refactor 74 | Refactor-numbered file first moved to stable exact lookup / no-fallback boundary coverage, then the source-shaped invariant moved out of Playwright. | `tests/scripts/check-exact-lookup-no-fallback-boundaries.mjs`, run by `pnpm -C tests run check:exact-lookup-no-fallback-boundaries` and `pnpm -C tests run test:source-guards`. | deleted |
| `tests/unit/refactor74LoginNoHss.guard.unit.test.ts` | Refactor 74 | Refactor-numbered file was moved to stable Ed25519 HSS material-boundary coverage, then the stable Playwright wrapper was retired. | `tests/scripts/check-ed25519-hss-material-boundaries.mjs`, wired through `test:source-guards`. | deleted |
| `tests/unit/refactor76BrandedKeys.guard.unit.test.ts` | Refactor 76 | Refactor-numbered file first moved to stable key-material branding and grant-lifecycle coverage, then the source-shaped invariant moved out of Playwright. | `tests/scripts/check-key-material-branding-boundaries.mjs`, run by `pnpm -C tests run check:key-material-branding-boundaries` and `pnpm -C tests run test:source-guards`. | deleted |
| `tests/unit/refactor71WalletSessionNaming.guard.unit.test.ts` | Refactor 71 | Refactor-numbered file first moved to stable wallet-session vocabulary boundary coverage, then the source-shaped invariant moved out of Playwright. | `tests/scripts/check-wallet-session-vocabulary-boundaries.mjs`, run by `pnpm -C tests run check:wallet-session-vocabulary-boundaries` and `pnpm -C tests run test:source-guards`. | deleted |
| `tests/unit/refactor73TypeFilename.guard.unit.test.ts` | Refactor 73 | Type-only file naming is enforced by lint/build tooling. | `tests/scripts/check-type-filename-source.mjs`, run by `pnpm -C tests run check:type-filename-source` and `pnpm -C tests run test:source-guards`. | deleted |
| `tests/unit/refactor67ReorgFolders.guard.unit.test.ts` | Refactor 67 | Refactor-numbered workspace package-boundary guard was replaced by a standalone build-graph check. | `tests/scripts/check-workspace-package-boundaries.mjs`, run by `pnpm -C tests run check:workspace-package-boundaries` and `pnpm -C tests run test:source-guards`. | deleted |
| `tests/unit/refactor58OtpRegistrationSlim.guard.unit.test.ts` | Refactor 58 | Refactor-numbered file first moved to stable Email OTP registration boundary coverage, then the source-shaped invariant moved out of Playwright. | `tests/scripts/check-email-otp-registration-boundaries.mjs`, run by `pnpm -C tests run check:email-otp-registration-boundaries` and `pnpm -C tests run test:source-guards`. | deleted |
| `tests/unit/refactor56HeadlessAuth.guard.unit.test.ts` | Refactor 56 | Refactor-numbered file first moved to stable headless Google Email OTP flow-boundary coverage, then the source-shaped invariant moved out of Playwright. | `tests/scripts/check-headless-google-email-otp-flow-boundaries.mjs`, run by `pnpm -C tests run check:headless-google-email-otp-flow-boundaries` and `pnpm -C tests run test:source-guards`. | deleted |
| `tests/unit/refactor54Simplify.guard.unit.test.ts` | Refactor 54 | Refactor-numbered SeamsWeb public-surface guard was replaced by a standalone public-surface boundary check. | `tests/scripts/check-seams-web-public-surface-boundaries.mjs`, run by `pnpm -C tests run check:seams-web-public-surface-boundaries` and `pnpm -C tests run test:source-guards`. | deleted |
| `tests/unit/refactor51bPlatformBoundaries.guard.unit.test.ts` | Refactor 51B | Refactor-numbered platform-runtime guard was replaced by a standalone platform-runtime boundary check. | `tests/scripts/check-platform-runtime-boundaries.mjs`, run by `pnpm -C tests run check:platform-runtime-boundaries` and `pnpm -C tests run test:source-guards`. | deleted |
| `tests/unit/refactor51bSeamsWebRename.guard.unit.test.ts` | Refactor 51B | Refactor-numbered file first moved to stable facade-name coverage, then the invariant moved to the public package boundary. | `tests/unit/packageExports.contract.unit.test.ts`, run by the unit suite. | deleted |
| `tests/unit/refactor51bWebauthnOriginPolicy.guard.unit.test.ts` | Refactor 51B | Refactor-numbered file first moved to stable WebAuthn origin-policy coverage, then the invariant moved out of Playwright. | `tests/scripts/check-webauthn-origin-policy.mjs`, run by `pnpm -C tests run check:webauthn-origin-policy` and `pnpm -C tests run test:source-guards`. | deleted |
| `tests/unit/refactor8xRegistrationButton.guard.unit.test.ts` | Refactor 8X | Refactor-numbered passkey registration-button boundary guard was replaced by retained component coverage plus a standalone import-boundary check. | `tests/lit-components/passkey-registration-btn.test.ts` and `tests/scripts/check-passkey-registration-button-boundaries.mjs`, run by `pnpm -C tests run check:passkey-registration-button-boundaries` and `pnpm -C tests run test:source-guards`. | deleted |

Checklist run, July 4, 2026:

| Guard | Verdict | Evidence / next action |
| --- | --- | --- |
| `tests/unit/seamsWebPublicSurfaceBoundaries.guard.unit.test.ts` | deleted | SeamsWeb public namespace split, signing-surface dependency direction, root export size, import-direction, iframe primitive, auth-method folder, and native-facade checks are now owned by `tests/scripts/check-seams-web-public-surface-boundaries.mjs`, wired into `test:source-guards`. |
| `tests/unit/headlessGoogleEmailOtpFlowBoundaries.guard.unit.test.ts` | deleted | Runtime paths are covered by `tests/unit/googleEmailOtpWalletAuthFlow.unit.test.ts`, `tests/unit/googleEmailOtpWalletIframeHandles.unit.test.ts`, and SeamsAuthMenu headless tests; remaining source-boundary checks moved to `tests/scripts/check-headless-google-email-otp-flow-boundaries.mjs`, wired through `test:source-guards`. |
| `tests/unit/emailOtpRegistrationBoundaries.guard.unit.test.ts` | deleted | Runtime behavior is covered by Google Email OTP flow, iframe-handle, route, and parser tests; remaining source-boundary checks moved to `tests/scripts/check-email-otp-registration-boundaries.mjs`, wired through `test:source-guards`. |
| `tests/unit/workspacePackageBoundaries.guard.unit.test.ts` | deleted | Package-root, package type-path, deployable-app import, and native import boundaries are now owned by `tests/scripts/check-workspace-package-boundaries.mjs`, wired into `test:source-guards`. |
| `tests/unit/walletSessionVocabularyBoundaries.guard.unit.test.ts` | deleted | Source-shaped vocabulary and `sessionId` classification checks moved to `tests/scripts/check-wallet-session-vocabulary-boundaries.mjs`, wired through `test:source-guards`; Refactor 90 can later narrow or delete that standalone check when the remaining names are rehomed. |
| `tests/unit/refactor73TypeFilename.guard.unit.test.ts` | deleted | Fired in Refactor 88 cleanup: the guard was replaced by `tests/scripts/check-type-filename-source.mjs`, wired through `pnpm -C tests run check:type-filename-source` and `pnpm -C tests run test:source-guards`. |
| `tests/unit/exactLookupNoFallbackBoundaries.guard.unit.test.ts` | deleted | Source-shaped exact lookup / no-fallback checks moved to `tests/scripts/check-exact-lookup-no-fallback-boundaries.mjs`, wired through `test:source-guards`; later direct exact lookup/session tests can narrow or delete that standalone check. |
| `tests/unit/ed25519HssMaterialBoundaries.guard.unit.test.ts` | deleted | Source-shaped worker-owned Ed25519/HSS material boundaries, deleted raw-material names, and active restore persistence checks moved to `tests/scripts/check-ed25519-hss-material-boundaries.mjs`, wired through `test:source-guards`; later worker command type fixtures, HSS tests, and parser tests can narrow or delete that standalone check. |
| `tests/unit/keyMaterialBrandingBoundaries.guard.unit.test.ts` | deleted | Source-shaped key-material branding and grant-lifecycle checks moved to `tests/scripts/check-key-material-branding-boundaries.mjs`, wired through `test:source-guards`; later constructor/parser tests and type fixtures can narrow or delete that standalone check. |
| `tests/unit/exactSigningLaneAuthorityBoundaries.guard.unit.test.ts` | deleted | Source-shaped exact lane identity, fallback selector, HSS context, Ed25519 mutation, and ECDSA session-record checks moved to `tests/scripts/check-exact-signing-lane-authority-boundaries.mjs`, wired through `test:source-guards`; later exact-lane builders, behavior tests, HSS vectors, and type fixtures can narrow or delete that standalone check. |
| `tests/unit/routeLifecycleDomainBoundaries.guard.unit.test.ts` | deleted | Source-shaped route/lifecycle boundary checks moved to `tests/scripts/check-route-lifecycle-domain-boundaries.mjs`, wired through `test:source-guards`; later parser tests and exhaustive-union fixtures can narrow or delete that standalone check. |

## Phase 2: Collapse Router A/B Source Guards

Router A/B source guards grew while Router, Deriver A/B, SigningWorker, local
dev, and Cloudflare shapes were changing together. After deployment settles,
prune them to security-critical boundaries.

- [x] Narrow `tests/scripts/check-cloudflare-d1-runtime-boundaries.mjs` after
      D1 route-family tests covered the registration/add-signer source-shape
      shard.
- [x] Continue collapsing Router A/B Rust source guards by deleting the broad
      Cloudflare `source_guards.rs` file and moving the last remaining
      secret-material checks to `secret_material_boundaries.rs`.
- [ ] Retire the Refactor 88 ledger guard after Refactor 88 closes. Blocked
      until the remaining Refactor 90-gated ledger rows fire.

| Guard | Cleanup trigger | Replacement coverage | Status |
| --- | --- | --- | --- |
| `crates/router-ab-cloudflare/tests/source_guards.rs` route-shape checks | Refactor 81 route rename has shipped and old `/v1`/`/v2` routes are absent from all active clients. | Deleted the broad source-guard file. Route literal checks moved to `crates/router-ab-cloudflare/tests/route_paths.rs`; CORS boundary checks moved to `crates/router-ab-cloudflare/tests/strict_router_cors_boundaries.rs`; bearer-admission, parser-boundary, replay-order, and admission-candidate checks moved to `crates/router-ab-cloudflare/tests/strict_router_route_boundaries.rs`; secret-material checks moved to `crates/router-ab-cloudflare/tests/secret_material_boundaries.rs`. | deleted |
| `crates/router-ab-cloudflare/tests/normal_signing_worker_boundaries.rs` ECDSA/Ed25519 call-chain checks | Handler boundaries are enforced by typed route commands and behavior tests. | ECDSA-HSS activation/export checks moved to `crates/router-ab-cloudflare/tests/ecdsa_hss_activation_boundaries.rs`; ECDSA-HSS normal-signing/presignature checks moved to `crates/router-ab-cloudflare/tests/ecdsa_hss_normal_signing_boundaries.rs`; Ed25519 and strict worker call-chain checks moved to `crates/router-ab-cloudflare/tests/normal_signing_worker_boundaries.rs`. | active |
| `crates/router-ab-cloudflare/tests/secret_material_boundaries.rs` secret-material checks | Protocol vectors and parser tests directly cover joined-state, recipient-output-combine, and signer-plaintext boundaries. | Focused secret-material boundary test after deleting the broad source-guard file. | active |
| `crates/router-ab-core/tests/source_guards.rs` Router boundary checks | Core protocol boundaries are covered by module visibility, type ownership, or protocol vectors. | Core protocol unit tests and vector tests. | active |
| `tests/unit/routerAbNormalSigningSdk.guard.unit.test.ts` route/topology checks | Refactor 81 unversioned route shape has shipped and active docs/scripts use one namespace. | Source-shaped route/topology checks moved to `tests/scripts/check-router-ab-normal-signing-sdk-boundaries.mjs`; later route-definition tests, SDK relayer tests, and local worker parity tests can narrow or delete that standalone check. | deleted |
| `tests/unit/routerAbServerWalletSessionClaimBoundary.guard.unit.test.ts` | Wallet Session claim parsing is enforced by server route parser tests. | Standalone source check `tests/scripts/check-router-ab-server-wallet-session-claim-boundaries.mjs`, wired into `test:source-guards`; later parser/JWT tests can delete or narrow that script. | deleted |

Keep a small durable guard or test for each security boundary that cannot be
represented by types alone.

## Phase 3: Collapse Identity Split Guards

These guards protected the wallet/account/key split while the code still had
old account-id-shaped paths. They should shrink once branded bindings and exact
lane identity cover construction.

| Guard | Cleanup trigger | Replacement coverage | Status |
| --- | --- | --- | --- |
| `tests/unit/walletCapabilityBindings.sourceGuard.unit.test.ts` | Playwright wrapper deleted; standalone check can narrow or delete once `walletCapabilityBindings.sourceGuard.allowlist.json` is empty and builders reject invalid wallet/account/signer combinations. | `tests/scripts/check-wallet-capability-bindings-source-guard.mjs`; later builder parser tests and type fixtures. | deleted |
| `tests/unit/walletCapabilityBindings.sourceGuard.allowlist.json` | Deleted after every entry was removed or converted to a typed/boundary-owned shape; recreated JSON allowlists fail `tests/scripts/check-wallet-capability-bindings-source-guard.mjs`. | Same as above. | deleted |
| `tests/unit/walletScopedLookups.guard.unit.test.ts` | Account-scoped fallback lookups are impossible through function signatures. | D1 wallet-id parser behavior in `tests/unit/domainIds.boundary.unit.test.ts`; remaining wallet-scoped lookup / NEAR projection source checks in `tests/scripts/check-wallet-scoped-lookup-boundaries.mjs`, wired into `test:source-guards`. | deleted |
| `tests/unit/signingEngineEcdsaIdentity.*.guard.unit.test.ts` | ECDSA identity no longer has NEAR-shaped compatibility fields or fallback paths. | `tests/scripts/check-signing-engine-ecdsa-identity-boundaries.mjs`, wired into `test:source-guards`; later ECDSA identity parser/export/lifecycle tests can narrow or delete that standalone check. | deleted |
| `tests/unit/accountSignerLifecycle.domain.guard.unit.test.ts` | Signer lifecycle write-field and shared signer-domain constant checks no longer need the Playwright source shard. | Standalone source check `tests/scripts/check-account-signer-lifecycle-boundaries.mjs`, wired into `test:source-guards`; later lifecycle type fixtures can delete or narrow that script. | deleted |

## Phase 4: Collapse Architecture Guard Families

Some architecture guards should become durable package-boundary tests. Others
can be deleted after refactor-specific path bans are obsolete.

| Guard family | Cleanup trigger | Replacement coverage | Status |
| --- | --- | --- | --- |
| `tests/unit/signingEngineArchitecture.*.guard.unit.test.ts` | Signing engine ownership boundaries are stable and represented by package/module boundaries. | `tests/scripts/check-signing-engine-architecture-boundaries.mjs`, wired into `test:source-guards`; later durable package-boundary tests can narrow or delete that standalone check. | deleted |
| `tests/unit/crossPlatformBoundaries.guard.unit.test.ts` | Browser/native/server boundaries are enforced by package exports and build configs. | `tests/scripts/check-cross-platform-boundaries.mjs`, wired into `test:source-guards`. | deleted |
| `tests/unit/platformRuntimeBoundaries.guard.unit.test.ts` | Runtime, browser adapter, native facade, WalletIframe import, and chain-signer routing boundaries are enforced by build-graph checks. | `tests/scripts/check-platform-runtime-boundaries.mjs`, wired into `test:source-guards`. | deleted |
| `tests/unit/indexedDBConsolidation.guard.unit.test.ts` | IndexedDB ownership is stable and schema tests cover persistence behavior. | Browser-backed IndexedDB schema/repository tests plus `tests/scripts/check-indexeddb-consolidation-boundaries.mjs`. | deleted |
| `tests/unit/stableExperimentalExportBoundaries.guard.unit.test.ts` | Stable/experimental exports are enforced by package entrypoint tests. | `tests/unit/packageExports.contract.unit.test.ts`. | deleted |

## Phase 5: Delete Or Move Redundant Guards

- [x] For each `ready_to_delete` row, remove the guard and its allowlist data.
      July 5 update: no live `ready_to_delete` rows remain; the only
      `ready_to_delete` mentions are the intake template and historical notes.
      Active allowlist rows remain explicitly gated in the ledger.
- [x] Move any remaining durable invariant out of refactor-number files into a
      stable test name.
      July 4 update: the durable Refactor 51B package/RP/runtime tests moved to
      `tests/unit/packageExports.contract.unit.test.ts`,
      `tests/unit/sdkPackageInstallSmoke.unit.test.ts`,
      `tests/unit/rpIdContract.unit.test.ts`, and
      `tests/unit/runtimeEntryBundles.unit.test.ts`. The final 82
      owner-plan gate moved to
      `tests/scripts/check-cloudflare-d1-runtime-boundaries.mjs`; no
      refactor-numbered guard filenames remain under `tests/unit`.
- [x] Update `tests/playwright.source.config.ts` if guard file patterns or
      source-guard scope change.
- [x] Update `tests/package.json` scripts only if the source-guard command
      itself changes.
- [x] Run the replacement validation commands listed in each row.
      July 5 update: the current replacement profile is green through
      `pnpm -C tests run test:source-guards`; this validates the migrated
      standalone checks plus the remaining active Playwright source-profile
      guards. The deletion checklist remains open for rows still marked active
      or gated on Refactor 82/90/recovery coverage.
- [x] Run `pnpm -C tests run test:source-guards` once after each cleanup batch.
      July 5 validation: `pnpm -C tests run test:source-guards` passed
      end-to-end after `build:sdk-full`; all standalone source checks passed
      and Playwright reported 190/190 source-profile tests passing.

## Future Guard Ledger

Append new temporary guards here.

| Guard | Owner refactor | Why it exists | Cleanup trigger | Replacement coverage | Status |
| --- | --- | --- | --- | --- | --- |
| `tests/unit/refactor79ExactSigningLane.guard.unit.test.ts` | Refactor 79 | Refactor-numbered file was moved to stable exact signing-lane authority coverage. | Exact lane identity is stable and behavior/type tests catch the same regressions. | `tests/unit/exactSigningLaneAuthorityBoundaries.guard.unit.test.ts`. | moved |
| `tests/unit/refactor80SwitchCase.guard.unit.test.ts` | Refactor 80 | Refactor-numbered file first moved to stable route/lifecycle domain-boundary coverage, then the source-shaped invariant moved out of Playwright. | Route parser tests and lifecycle union fixtures cover every guarded branch. | `tests/scripts/check-route-lifecycle-domain-boundaries.mjs`, run by `pnpm -C tests run check:route-lifecycle-domain-boundaries` and `pnpm -C tests run test:source-guards`. | deleted |
| `tests/unit/routerAbNormalSigningSdk.guard.unit.test.ts` | Refactors 68, 69, 81 | Prevented Router A/B topology and route-shape regressions while local/cloudflare routing was settling. | Source-shaped checks moved to `tests/scripts/check-router-ab-normal-signing-sdk-boundaries.mjs`, wired through `test:source-guards`; later route constants and parity tests can narrow or delete the standalone check. | `tests/scripts/check-router-ab-normal-signing-sdk-boundaries.mjs`; later route-definition tests, SDK relayer tests, local/cloudflare parity tests. | deleted |
| `crates/router-ab-cloudflare/tests/source_guards.rs` | Router A/B / Refactors 79-81 | Broad Cloudflare source guard deleted after every shard moved to a named boundary file. | Route literal checks moved to `route_paths.rs`, CORS checks moved to `strict_router_cors_boundaries.rs`, bearer-admission/parser/replay checks moved to `strict_router_route_boundaries.rs`, ECDSA-HSS activation/export checks moved to `ecdsa_hss_activation_boundaries.rs`, ECDSA-HSS normal-signing/presignature checks moved to `ecdsa_hss_normal_signing_boundaries.rs`, normal-signing worker checks moved to `normal_signing_worker_boundaries.rs`, and secret-material checks moved to `secret_material_boundaries.rs`. | `cargo test --manifest-path crates/router-ab-cloudflare/Cargo.toml --test route_paths`; `cargo test --manifest-path crates/router-ab-cloudflare/Cargo.toml --test strict_router_cors_boundaries`; `cargo test --manifest-path crates/router-ab-cloudflare/Cargo.toml --test strict_router_route_boundaries`; `cargo test --manifest-path crates/router-ab-cloudflare/Cargo.toml --test ecdsa_hss_activation_boundaries`; `cargo test --manifest-path crates/router-ab-cloudflare/Cargo.toml --test ecdsa_hss_normal_signing_boundaries`; `cargo test --manifest-path crates/router-ab-cloudflare/Cargo.toml --test normal_signing_worker_boundaries`; `cargo test --manifest-path crates/router-ab-cloudflare/Cargo.toml --test secret_material_boundaries`; later Cloudflare handler tests, route parity tests, protocol vectors. | deleted |
| `tests/unit/walletCapabilityBindings.sourceGuard.unit.test.ts` | Refactor 78 | Playwright wrapper deleted after the source-shaped guard moved to a standalone check. | Builders and type fixtures make the collapse unrepresentable. | `tests/scripts/check-wallet-capability-bindings-source-guard.mjs`; later builder tests, `@ts-expect-error` fixtures, parser tests. | deleted |
| `tests/unit/walletCapabilityBindings.sourceGuard.allowlist.json` | Refactor 78 | Tracked known temporary exceptions to wallet/account source bans. | Allowlist reached zero entries and the standalone guard rejects recreation. | `tests/scripts/check-wallet-capability-bindings-source-guard.mjs`; wallet-scoped flow events now use `walletId` payloads. | deleted |
| `tests/unit/registrationCapabilitySubjects.guard.unit.test.ts` role-local ECDSA material handles | Refactor 83 | Playwright wrapper deleted after the source-shaped assertion moved to a standalone check. | ECDSA material-handle construction is enforced by branded builders and type fixtures for one release branch. | `tests/scripts/check-registration-capability-subjects.mjs`; later ECDSA material-handle builder tests and `@ts-expect-error` fixtures can narrow the source check. | deleted |
| `tests/unit/registrationCapabilitySubjects.guard.unit.test.ts` wallet-scoped unlock subject | Refactor 83 | Playwright wrapper deleted after the source-shaped assertion moved to a standalone check. | Wallet unlock subject builders and unlock behavior tests own wallet-scoped identity without source text checks. | `tests/scripts/check-registration-capability-subjects.mjs`; later wallet unlock subject parser tests and Email OTP/passkey unlock behavior tests can narrow the source check. | deleted |
| `tests/unit/registrationCapabilitySubjects.guard.unit.test.ts` visible iframe passkey registration checks | Refactor 83 | Playwright wrapper deleted after the source-shaped assertion moved to a standalone check. | Activation/public/message types, host parser tests, SeamsAuthMenu behavior tests, and WebAuthn option tests are stable for one release branch. | `tests/scripts/check-registration-capability-subjects.mjs`; later activation type fixtures, host activation parser tests, and lit WebAuthn option tests can narrow the source check. | deleted |
| `tests/unit/registrationCapabilitySubjects.guard.unit.test.ts` prepared registration route boundary | Refactor 83 | Playwright wrapper deleted after the source-shaped assertion moved to a standalone check. | Route parser tests and ceremony-store parser tests own raw/request boundary parsing directly. | `tests/scripts/check-registration-capability-subjects.mjs`; later wallet registration route parser tests, ceremony-store parser tests, and prepared-registration contract tests can narrow the source check. | deleted |
| `tests/unit/registrationCapabilitySubjects.guard.unit.test.ts` registration precompute ownership | Refactor 83 | Playwright wrapper deleted after the source-shaped assertion moved to a standalone check. | Registration precompute builder tests and intended registration contracts cover one-handle ownership without source scans. | `tests/scripts/check-registration-capability-subjects.mjs`; later precompute-scope unit tests and Refactor 88 registration contracts can narrow the source check. | deleted |
| `tests/unit/registrationCapabilitySubjects.guard.unit.test.ts` registration active state and persistence subjects | Refactor 83 | Playwright wrapper deleted after the source-shaped assertion moved to a standalone check. | Registration active-state builders, persistence-plan tests, and intended registration contracts cover registration success without source scans. | `tests/scripts/check-registration-capability-subjects.mjs`; later registration active-state unit tests, persistence-plan parser/builder tests, and Refactor 88 registration contracts can narrow the source check. | deleted |
| `tests/unit/registrationCapabilitySubjects.guard.unit.test.ts` Email OTP unlock current-session commits | Refactor 83 | Playwright wrapper deleted after the source-shaped assertion moved to a standalone check. | Ed25519/ECDSA session commit tests and restore tests cover commit-vs-fact-write behavior for one release branch. | `tests/scripts/check-registration-capability-subjects.mjs`; later current-session commit tests, sealed-restore tests, and Email OTP unlock intended contracts can narrow the source check. | deleted |
| `tests/unit/registrationCapabilitySubjects.guard.unit.test.ts` Email OTP unlock activation plan | Refactor 83 | Playwright wrapper deleted after the source-shaped assertion moved to a standalone check. | Email OTP unlock behavior contracts and activation-plan builder tests cover readiness ordering without source scans. | `tests/scripts/check-registration-capability-subjects.mjs`; later activation-plan builder tests and Refactor 88 Email OTP unlock contracts can narrow the source check. | deleted |
| `tests/scripts/check-intended-behaviour-contract-boundaries.mjs` | Refactor 88 | Keeps the intended-behaviour contract suite small, public-flow based, and protected from retired mocked setup/runtime surfaces while the harness and cleanup land together. | `test:intended` is wired into remote CI and retired setup/runtime files are absent for one release branch; mutation proof is now owned by `check:intended-mutation-self-check:complete`, and retained-boundary audit evidence is owned by `check:refactor88-test-ledger:complete`. | `pnpm test:intended`, `pnpm test:intended:ci`, mutation self-check evidence, ledger evidence checks, and focused setup/harness unit tests. | active |
| `tests/scripts/check-refactor88-test-ledger.mjs` | Refactor 88 | Keeps the exhaustive test ledger complete and keeps retained focused coverage rows tied to live source evidence while legacy tests are deleted. | Refactor 88 closes with all ungated deletion accounting complete and remaining gated rows owned by later plans. | `pnpm -C tests run check:refactor88-test-ledger:complete`, `pnpm -C tests run test:source-guards`. | active |
| `packages/sdk-web/scripts/checks/assert-hosted-wallet-docs.mjs` | Refactor 86 | Prevents app-facing docs/examples/package exports from reintroducing SDK plugin-based wallet hosting while hosted wallet assets are the runtime contract. | Refactor 90 0E public config replaces the current `iframeWallet` docs and plugin helper exports are deleted or moved to private Seams-internal tooling for one release branch. | `pnpm --dir packages/sdk-web check:hosted-wallet-docs`; hosted-origin static smoke and intended browser lifecycle smoke. | active |
| `tests/scripts/check-static-wallet-asset-boundaries.mjs` | Refactor 86 | Prevents the remaining Vite helpers from reintroducing default wallet MIME/header behavior after hosted static assets became the runtime contract. | The plugin helpers are deleted or moved to private Seams-internal tooling after Refactor 90 0E public config lands and hosted wallet deployment owns headers through generated manifests. | `pnpm -C tests run check:static-wallet-asset-boundaries`; `pnpm -C packages/sdk-web run check:static-wallet-assets`; `tests/wallet-iframe/static-wallet-assets.browser.test.ts`. | active |

## Retired Cleanup Ledger

These rows record deleted tests, fixtures, and setup hooks whose old behavior is
replaced by the Refactor 88 intended-behaviour contracts.

| Surface | Owner refactor | Why it was removed | Replacement coverage | Status |
| --- | --- | --- | --- | --- |
| `tests/e2e/docs.thresholdRegisterAndSigning.integration.test.ts` | Refactor 88 | Mocked docs/demo registration -> signing through `setupBasicPasskeyTest`, `__testOverrides`, mocked SDK methods, and fake chain responses. | Passkey intended registration contract plus `tests/scripts/check-intended-behaviour-contract-boundaries.mjs`. | deleted |
| `tests/e2e/docs.thresholdSigningActions.smoke.test.ts` | Refactor 88 | Mocked docs/demo signing actions through a fake logged-in SDK surface. | Passkey intended registration/unlock contracts covering NEAR, Tempo, and Arc/EVM signing. | deleted |
| `tests/unit/passkeyLoginMenu.thresholdProvision.unit.test.ts` | Refactor 88 | Kept a production `__testOverrides` path alive to fake SDK hook state. | Demo surfaces no longer expose `__testOverrides`; guarded by `tests/scripts/check-intended-behaviour-contract-boundaries.mjs`. | deleted |
| `tests/unit/seamsWeb.loginThresholdWarm.unit.test.ts` | Refactor 88 | Used a large in-memory runtime fixture graph for unlock -> warm signing behavior. | Passkey and Email OTP intended contracts plus focused boundary/domain tests. | deleted |
| `tests/unit/helpers/warmSessionStore.fixtures.ts` | Refactor 88 | Bundled broad warm-session, ECDSA chain-target, signing-session record, status, and touch-confirm fixtures into one runtime-shape fixture. | Focused helpers: `ecdsaChainTarget.fixtures.ts`, `ecdsaBootstrap.fixtures.ts`, `signingSessionRecord.fixtures.ts`, `warmSessionUiConfirm.fixtures.ts`, and `warmSessionTestServices.fixtures.ts`. | deleted |
| `tests/setup/fixtures.ts`, `tests/setup/flows.ts`, `tests/setup/test-utils.ts` | Refactor 88 | Fed broad `window.testUtils` browser mutation helpers into mocked lifecycle tests. | Intended harness drives public SDK/UI flows directly and guards against mocked setup imports. | deleted |
| `tests/setup/webauthn-mocks.ts` | Refactor 88 | Overrode `navigator.credentials.create/get` with a bespoke WebAuthn/PRF mock and kept browser setup on a second authenticator path. | Generic setup and intended contracts both use the PRF-capable CDP virtual authenticator (`hasPrf: true`) plus `tests/scripts/check-intended-behaviour-contract-boundaries.mjs`. | deleted |
| `tests/scripts/provision-router-api-server.mjs`, `tests/scripts/start-servers.mjs`, `tests/scripts/test-router-api-server.mjs` | Refactor 88 | Launched a fake AuthService Router API server through generic Playwright scripts and preserved a flag-controlled fake-relay topology. | Generic Playwright scripts use the Vite-only browser setup; intended contracts own real Router/site lifecycle coverage. Guarded by `tests/scripts/check-intended-behaviour-contract-boundaries.mjs`. | deleted |
| `benchmarks/registration-flow/playwright.config.ts`, `benchmarks/registration-flow/src/report.mjs`, `benchmarks/registration-flow/src/runner.mjs`, `benchmarks/registration-flow/src/scenario-harness.ts`, `benchmarks/registration-flow/src/scenarios.mjs` | Refactor 88 | The runner depended on the deleted `tests/e2e/thresholdEd25519.testUtils` managed-registration mock harness. | Historical reports are retained; any replacement benchmark must use the real intended-behaviour topology. | deleted |
| Browser setup hooks `failureMocks`, `rollbackVerification`, `verifyAccountExists`, `webAuthnUtils`, `loginStatus`, `window.testUtils`, and `createConsoleCapture` | Refactor 88 | Preserved obsolete browser-side mock/control surfaces unrelated to public intended lifecycle behavior. | Refactor 88 guard rejects reintroducing the retired hooks in active setup surfaces. | deleted |
| `tests/unit/refactor73TypeFilename.guard.unit.test.ts` | Refactor 89 / Refactor 73 | Kept a refactor-numbered Playwright source guard alive for a source-layout rule. | Standalone lint-style check `tests/scripts/check-type-filename-source.mjs`, wired into `test:source-guards`. | deleted |
| `tests/unit/authSecretTerminology.guard.unit.test.ts` | Refactor 89 | Kept auth-neutral docs terminology coverage inside the Playwright source shard. | Standalone docs/source lint check `tests/scripts/check-auth-secret-terminology.mjs`, wired into `test:source-guards`. | deleted |
| `tests/unit/legacySeamsWebFacadeNames.guard.unit.test.ts` | Refactor 89 / Refactor 51B | Kept retired SeamsWeb facade-name coverage inside the Playwright source shard. | Public entrypoint assertions in `tests/unit/packageExports.contract.unit.test.ts`. | deleted |
| `tests/unit/webauthnOriginPolicy.guard.unit.test.ts` | Refactor 89 / Refactor 51B | Kept WebAuthn expected-origin coverage inside the Playwright source shard. | Standalone source check `tests/scripts/check-webauthn-origin-policy.mjs`, wired into `test:source-guards`. | deleted |
| `tests/unit/thresholdEd25519PresignNonceLifecycle.guard.unit.test.ts` | Refactor 89 | Kept Ed25519 presign nonce burn-order and CSPRNG handle coverage inside the Playwright source shard. | Standalone source check `tests/scripts/check-threshold-ed25519-presign-nonce-lifecycle.mjs`, wired into `test:source-guards`. | deleted |
| `tests/unit/thresholdEcdsa.behavior.guard.unit.test.ts` | Refactor 89 | Kept ECDSA HSS security-boundary coverage inside the Playwright source shard. | Standalone source check `tests/scripts/check-threshold-ecdsa-hss-boundaries.mjs`, wired into `test:source-guards`. | deleted |
| `tests/unit/routerAbServerWalletSessionClaimBoundary.guard.unit.test.ts` | Refactor 89 | Kept Router A/B wallet-session claim-boundary coverage inside the Playwright source shard. | Standalone source check `tests/scripts/check-router-ab-server-wallet-session-claim-boundaries.mjs`, wired into `test:source-guards`. | deleted |
| `tests/unit/headlessGoogleEmailOtpFlowBoundaries.guard.unit.test.ts` | Refactor 89 / Refactor 56 | Kept headless Google Email OTP demo/public API/wallet-iframe source-boundary checks inside the Playwright source shard. | Runtime coverage in `tests/unit/googleEmailOtpWalletAuthFlow.unit.test.ts`, `tests/unit/googleEmailOtpWalletIframeHandles.unit.test.ts`, and SeamsAuthMenu headless tests; remaining source checks in `tests/scripts/check-headless-google-email-otp-flow-boundaries.mjs`, wired into `test:source-guards`. | deleted |
| `tests/unit/emailOtpRegistrationBoundaries.guard.unit.test.ts` | Refactor 89 / Refactor 58 | Kept Google Email OTP registration/reroll, backup-material, D1 activation-ordering, and registration-offer parser source checks inside the Playwright source shard. | Runtime coverage in Email OTP flow, iframe-handle, route, and parser tests; remaining source checks in `tests/scripts/check-email-otp-registration-boundaries.mjs`, wired into `test:source-guards`. | deleted |
| `tests/unit/accountSignerLifecycle.domain.guard.unit.test.ts` | Refactor 89 | Kept signer lifecycle write-field and shared signer-domain constant source checks inside the Playwright source shard. | Standalone source check `tests/scripts/check-account-signer-lifecycle-boundaries.mjs`, wired into `test:source-guards`. | deleted |
| `tests/unit/walletScopedLookups.guard.unit.test.ts` | Refactor 89 | Kept wallet-scoped lookup, NEAR projection, D1 wallet-boundary, and wallet-persistence parser source checks inside the Playwright source shard. | D1 wallet-id parser behavior in `tests/unit/domainIds.boundary.unit.test.ts`; remaining source checks in `tests/scripts/check-wallet-scoped-lookup-boundaries.mjs`, wired into `test:source-guards`. | deleted |
| `tests/unit/emailOtpOperationSplit.guard.unit.test.ts` | Refactor 89 | Kept Email OTP signing/export operation split, coordinator facade, exact-lane reauth, committed-lane export/sign/step-up, seal-transport, and diagnostics source checks inside the Playwright source shard. | Standalone source check `tests/scripts/check-email-otp-operation-split.mjs`, wired into `test:source-guards`; later parser/behavior/type coverage can narrow or delete the script. | deleted |

## Validation

Recommended cleanup-batch validation:

```text
pnpm -C tests run test:source-guards
pnpm -C tests exec playwright test tests/unit/<replacement-test>.unit.test.ts --reporter=line
cargo test --manifest-path crates/router-ab-cloudflare/Cargo.toml --test route_paths
cargo test --manifest-path crates/router-ab-cloudflare/Cargo.toml --test secret_material_boundaries
cargo test --manifest-path crates/router-ab-core/Cargo.toml --test source_guards
git diff --check
```

Run broader suites only when deleting a guard changes package boundaries,
public exports, route parsing, HSS material flow, or persisted schema behavior.

Validation checkpoint, July 4, 2026:

- `git diff --check` passes.
- `pnpm -C tests run test:source-guards` passes end-to-end: type-filename
  source check, SDK full build, and the Playwright source profile all completed;
  the source profile reported 643/643 passing tests.
- Re-run after the Phase 0 mixed-suite invariant split: `pnpm -C tests run
  test:source-guards` passed again with 643/643 source-profile tests.
- Re-run after moving the Refactor 51B guard files to stable names: `pnpm -C
  tests exec playwright test -c playwright.source.config.ts
  ./unit/legacySeamsWebFacadeNames.guard.unit.test.ts
  ./unit/webauthnOriginPolicy.guard.unit.test.ts
  ./unit/platformRuntimeBoundaries.guard.unit.test.ts --reporter=line` passed
  12/12, `pnpm -C tests run check:refactor88-test-ledger:complete` reported
  `scope=455 ledger_existing=455 ledger_deleted=6 missing=0`, and `pnpm -C
  tests run test:source-guards` passed with 644/644 source-profile tests.
- Re-run after moving the Refactor 8X registration-button guard to
  `tests/unit/passkeyRegistrationButtonBoundaries.guard.unit.test.ts`: the
  focused guard passed 1/1, `pnpm -C tests run
  check:refactor88-test-ledger:complete` again reported
  `scope=455 ledger_existing=455 ledger_deleted=6 missing=0`, and `pnpm -C
  tests run test:source-guards` passed with 644/644 source-profile tests.
- Re-run after moving the Refactor 56 and Refactor 67 guards to
  `tests/unit/headlessGoogleEmailOtpFlowBoundaries.guard.unit.test.ts` and
  `tests/unit/workspacePackageBoundaries.guard.unit.test.ts`: the focused batch
  passed 11/11, `pnpm -C tests run check:refactor88-test-ledger:complete`
  reported `scope=455 ledger_existing=455 ledger_deleted=6 missing=0`, the
  stale Refactor 76 signing-grant source-shape assertion was refreshed for the
  current `requireRegistrationActiveStateString` wrapper and its focused check
  passed 1/1, and `pnpm -C tests run test:source-guards` passed with 645/645
  source-profile tests.
- Re-run after moving the Refactor 54, Refactor 58, and Refactor 76 guards to
  `tests/unit/seamsWebPublicSurfaceBoundaries.guard.unit.test.ts`,
  `tests/unit/emailOtpRegistrationBoundaries.guard.unit.test.ts`, and
  `tests/unit/keyMaterialBrandingBoundaries.guard.unit.test.ts`: the focused
  batch passed 39/39, `pnpm -C tests run
  check:refactor88-test-ledger:complete` reported
  `scope=455 ledger_existing=455 ledger_deleted=6 missing=0`, and `pnpm -C
  tests run test:source-guards` passed with 645/645 source-profile tests after
  a transient WASM output-check miss passed on rerun.
- Re-run after moving the Refactor 80 guard to
  `tests/unit/routeLifecycleDomainBoundaries.guard.unit.test.ts`: the focused
  guard passed 15/15, `pnpm -C tests run
  check:refactor88-test-ledger:complete` reported
  `scope=455 ledger_existing=455 ledger_deleted=6 missing=0`, `git diff
  --check` passed, and `pnpm -C tests run test:source-guards` passed with
  644/644 source-profile tests.
- Re-run after moving the Refactor 79 guard to
  `tests/unit/exactSigningLaneAuthorityBoundaries.guard.unit.test.ts`: the
  focused guard passed 29/29, `pnpm -C tests run
  check:refactor88-test-ledger:complete` reported
  `scope=455 ledger_existing=455 ledger_deleted=6 missing=0`, `git diff
  --check` passed, and `pnpm -C tests run test:source-guards` passed with
  645/645 source-profile tests after a transient generated-WASM wrapper import
  miss passed on rerun.
- Re-run after moving the Refactor 74 guards to
  `tests/unit/exactLookupNoFallbackBoundaries.guard.unit.test.ts` and
  `tests/unit/ed25519HssMaterialBoundaries.guard.unit.test.ts`: the focused
  guards passed 10/10 and 26/26, `pnpm -C tests run
  check:refactor88-test-ledger:complete` reported
  `scope=455 ledger_existing=455 ledger_deleted=6 missing=0`, `git diff
  --check` passed, and `pnpm -C tests run test:source-guards` passed with
  645/645 source-profile tests after a transient build-stage TypeScript error
  passed on rerun without source changes.
- Re-run after moving the Refactor 71 guard to
  `tests/unit/walletSessionVocabularyBoundaries.guard.unit.test.ts`: the
  focused guard passed 6/6, `pnpm -C tests run
  check:refactor88-test-ledger:complete` reported
  `scope=455 ledger_existing=455 ledger_deleted=6 missing=0`, `git diff
  --check` passed, and `pnpm -C tests run test:source-guards` passed with
  645/645 source-profile tests.
- Final re-run for the Phase 1 cleanup batch: `pnpm -C tests run
  test:source-guards` passed end-to-end, including the type-filename source
  check, SDK full build, and 645/645 Playwright source-profile tests.
- `pnpm -C packages/sdk-server-ts type-check` passes after the current
  registration ceremony shape work.
- `pnpm -C tests exec playwright test -c playwright.source.config.ts
  unit/authSecretTerminology.guard.unit.test.ts --reporter=line` passes after
  refreshing the guard to current docs paths.
- `pnpm -C tests exec playwright test -c playwright.source.config.ts
  unit/legacySeamsWebFacadeNames.guard.unit.test.ts --reporter=line` passes
  after classifying `docs/refactor-36-narrow-lifecycle-types.md` as historical
  rename documentation.
- `pnpm -C tests exec playwright test -c playwright.source.config.ts
  unit/cloudflareD1RuntimeBoundaries.guard.unit.test.ts --grep "stale staging"
  --reporter=line` passes after removing the deleted
  `benchmarks/registration-flow/src/scenario-harness.ts` path from the active
  shim scan.
- `tests/playwright.source.config.ts` now excludes the two browser-dependent
  guardrail patterns, `*.guards.test.ts` and `*.guardrails.unit.test.ts`; those
  files remain retained browser/unit tests with explicit validation commands.
- `pnpm -C tests exec playwright test -c playwright.source.config.ts
  unit/thresholdEd25519.separatedRoles.script.unit.test.ts --reporter=line`
  passes after localizing the guard to this repo's `crates/ed25519-hss`
  example instead of the deleted sibling checkout path.
- `pnpm -C tests exec playwright test -c playwright.source.config.ts
  unit/workspacePackageBoundaries.guard.unit.test.ts --reporter=line` passes after
  moving the site Vite config from direct package source import to
  `@seams/sdk/plugins/vite`; `pnpm -C apps/seams-site exec tsc --noEmit
  --pretty false` passes after narrowing the intended Email OTP helper return
  types to their core summaries.
- `pnpm -C tests exec playwright test -c playwright.source.config.ts
  unit/refactor71WalletSessionNaming.guard.unit.test.ts --reporter=line`
  passes 6/6 after classifying the current recovery-session and
  signing-session `sessionId` public surfaces. This keeps the temporary guard
  green while Refactor 90 owns the remaining vocabulary cleanup.
- `pnpm -C tests exec playwright test -c playwright.source.config.ts
  unit/cloudflareD1RuntimeBoundaries.guard.unit.test.ts --reporter=line`
  passes 58/58 after updating the Ed25519 HSS durable ceremony token check to
  the current field-level `evaluationResult` durability checks.
- `pnpm -C tests exec playwright test -c playwright.source.config.ts
  unit/refactor74LegacyFallbacks.guard.unit.test.ts --reporter=line` passes
  10/10 after moving the authority-bearing reconnect assertion from the removed
  candidate-selector block to the current exact reconnect-material builder and
  type fixtures.
- `pnpm -C tests exec playwright test -c playwright.source.config.ts
  unit/refactor74LoginNoHss.guard.unit.test.ts --reporter=line` passes 26/26
  after moving its Ed25519 session-record check to the current material-state
  union, checking the current login unseal resolver, and recording the
  Refactor 84 link-device stub while recovery/sync still use the shared
  no-HSS setup helpers.
- `pnpm -C tests exec playwright test -c playwright.source.config.ts
  unit/emailOtpRegistrationBoundaries.guard.unit.test.ts --reporter=line`
  passes 8/8 after moving the stale AuthService persistence checks to the D1
  wallet registration finalizer and moving prepared Email OTP enrollment
  persistence before D1 wallet subject/signer writes.
- `pnpm -C tests exec playwright test -c playwright.source.config.ts
  unit/keyMaterialBrandingBoundaries.guard.unit.test.ts --reporter=line` passes 9/9
  after moving stale AuthService/export-default assertions to the current
  auth-service modules, D1 seal-config boundaries, and multi-line EVM slot
  parser checks.
- `pnpm -C tests exec playwright test -c playwright.source.config.ts
  unit/cloudflareSelfHostedSigningWorker.script.unit.test.ts --reporter=line`
  passes 6/6 after replacing the fake AuthService fixture with the current
  `RouterApiServiceBag` threshold-runtime boundary.
- `pnpm -C tests exec playwright test -c playwright.source.config.ts
  unit/thresholdEcdsa.signingRootResolver.script.unit.test.ts --reporter=json`
  reports 0/3 failures after replacing the generic ECDSA `walletKeyId`
  fixture with a derived `evmFamilySigningKeySlotId` in bootstrap and
  signing-root verification requests.
- `pnpm -C tests exec playwright test -c playwright.source.config.ts
  unit/signingEngineEcdsaIdentity.lifecycle.guard.unit.test.ts --reporter=line`
  passes 13/13 after narrowing the ECDSA-only NEAR residue check and recording
  the current Refactor 84 link-device stub.
- `pnpm -C tests exec playwright test -c playwright.source.config.ts
  unit/signingEngineEcdsaIdentity.publicSurfaces.guard.unit.test.ts
  --reporter=line` passes 5/5 after moving public ECDSA identity checks to
  `evmFamilySigningKeySlotId`.
- Refactor 88 cleanup retired the three synthetic recovery/profile
  source-script wrappers and fixtures:
  `emailRecoveryVerifiedRequest.source.script.*`,
  `profileContinuity.source.script.*`, and `recoveryDomain.source.script.*`.
  Recovery request, profile continuity, and recovery-domain behavior now stay
  covered by retained parser/domain tests plus the intended recovery contract.
- `pnpm -C tests exec playwright test -c playwright.source.config.ts
  unit/keyMaterialBrandingBoundaries.guard.unit.test.ts --reporter=line` passes 9/9
  after retargeting the registration active runtime-state assertion.
- `pnpm -C tests exec playwright test -c playwright.source.config.ts
  unit/refactor74LoginNoHss.guard.unit.test.ts --reporter=line` passes 26/26
  after moving the material-state check to the current finalized Ed25519 shape.
- `pnpm -C tests exec playwright test -c playwright.source.config.ts
  unit/crossPlatformBoundaries.guard.unit.test.ts --reporter=line` passes 15/15
  after using the current HSS client-share public-key naming in production code.
- `pnpm -C tests exec playwright test -c playwright.source.config.ts
  unit/routerAbNormalSigningSdk.guard.unit.test.ts --reporter=line` passes
  25/25 after recognizing lazy role-local ECDSA HSS signing-material loading.
- `pnpm -C tests exec playwright test -c playwright.source.config.ts
  unit/nonceCoordinator.durableArchitecture.guard.unit.test.ts --reporter=line`
  passes 15/15 after routing NEAR execution-readiness exports through the
  `NonceCoordinator` facade.
- `pnpm -C tests exec playwright test -c playwright.source.config.ts
  unit/emailOtpSigningSession.deviceEscrow.behavior.guard.unit.test.ts
  --reporter=line` passes 7/7 after moving its AuthService read to the active
  server AuthService path. July 5 update: this Playwright guard is now deleted;
  its surviving source checks run through
  `pnpm -C tests run check:email-otp-device-escrow-boundaries`.
- `pnpm -C tests exec playwright test -c playwright.source.config.ts
  unit/thresholdEcdsa.behavior.guard.unit.test.ts --reporter=line` passes 5/5
  after the secp256k1 signing path gained explicit commit-start and
  post-sign-success refill scheduling hooks.
- `pnpm -C tests exec playwright test -c playwright.source.config.ts
  unit/signingEngineArchitecture.ownership.guard.unit.test.ts --reporter=line`
  passes 10/10 after recording the current Email OTP flow imports and
  session-domain sibling boundaries.
- `pnpm -C tests exec playwright test -c playwright.unit.config.ts
  unit/seamsWeb.duplicateIframes.guardrails.unit.test.ts
  unit/signer-worker.guards.test.ts --reporter=line` passes 4/4.
- Re-run after moving durable Refactor 51B package/RP/runtime tests to stable
  names: `pnpm -C tests exec playwright test -c playwright.unit.config.ts
  unit/packageExports.contract.unit.test.ts unit/sdkPackageInstallSmoke.unit.test.ts
  unit/rpIdContract.unit.test.ts unit/runtimeEntryBundles.unit.test.ts
  --reporter=line` passed 15/15; `pnpm -C tests run
  check:refactor88-test-ledger:complete` reported
  `scope=455 ledger_existing=455 ledger_deleted=6 missing=0`; and
  `pnpm -C tests exec playwright test -c playwright.source.config.ts
  unit/intendedBehaviourContracts.guard.unit.test.ts --reporter=line` passed
  55/55.
- Re-run after moving the Refactor 88 intended-behaviour guard to
  `tests/scripts/check-intended-behaviour-contract-boundaries.mjs`: `pnpm -C
  tests run check:intended-behaviour-contract-boundaries` passed, `pnpm -C
  tests run check:refactor88-test-ledger:complete` reported
  `scope=415 ledger_existing=415 ledger_deleted=51 missing=0`, and `git diff
  --check` passed.
- Re-run after moving the D1 runtime boundary guard to
  `tests/scripts/check-cloudflare-d1-runtime-boundaries.mjs`: `pnpm -C tests
  run check:cloudflare-d1-runtime-boundaries` passed, `pnpm -C tests run
  check:refactor88-test-ledger:complete` reported
  `scope=414 ledger_existing=414 ledger_deleted=52 missing=0`, and the
  Playwright source-profile shard passed 190/190.
- Re-run after moving the final 82/83 owner-plan guards to stable filenames:
  `pnpm -C tests exec playwright test -c playwright.unit.config.ts
  unit/cloudflareD1RuntimeBoundaries.guard.unit.test.ts
  unit/registrationCapabilitySubjects.guard.unit.test.ts --reporter=line`
  passed 67/67; `pnpm -C tests run check:refactor88-test-ledger:complete`
  reported `scope=455 ledger_existing=455 ledger_deleted=6 missing=0`;
  `pnpm -C tests run test:source-guards` passed after `build:sdk-full` with
  648/648 source-profile tests; and `git diff --check` passed.
- Re-run after deleting
  `tests/unit/stableExperimentalExportBoundaries.guard.unit.test.ts` and moving
  its assertions into `tests/unit/packageExports.contract.unit.test.ts`:
  `pnpm -C tests exec playwright test -c playwright.unit.config.ts
  unit/packageExports.contract.unit.test.ts --reporter=line` passed 10/10,
  `pnpm -C tests run check:refactor88-test-ledger:complete` reported
  `scope=454 ledger_existing=454 ledger_deleted=7 missing=0`,
  `pnpm -C tests run test:source-guards` passed after `build:sdk-full` with
  647/647 source-profile tests, and `git diff --check` passed.
- Re-run after deleting `tests/unit/seamsAuthMenuPublicEntry.guard.unit.test.ts`
  and moving its public-entrypoint assertions into
  `tests/unit/packageExports.contract.unit.test.ts`:
  `pnpm -C tests exec playwright test -c playwright.unit.config.ts
  unit/packageExports.contract.unit.test.ts unit/seamsAuthMenu.ssr.unit.test.ts
  --reporter=line` passed 12/12, `pnpm -C tests run
  check:refactor88-test-ledger:complete` reported
  `scope=453 ledger_existing=453 ledger_deleted=8 missing=0`,
  `pnpm -C tests run test:source-guards` passed after `build:sdk-full` with
  646/646 source-profile tests, and `git diff --check` passed.
- Re-run after deleting `tests/unit/signerDomain.guard.unit.test.ts` and
  folding its wallet/signer shared-constant checks into
  `tests/unit/accountSignerLifecycle.domain.guard.unit.test.ts`:
  `pnpm -C tests exec playwright test -c playwright.source.config.ts
  unit/accountSignerLifecycle.domain.guard.unit.test.ts --reporter=line`
  passed 2/2; `pnpm -C packages/sdk-web exec tsc --noEmit` passed after the
  Email OTP unlock ECDSA record assertion made the required JWT-backed branch
  explicit; `pnpm -C tests run check:refactor88-test-ledger:complete`
  reported `scope=452 ledger_existing=452 ledger_deleted=9 missing=0`;
  `pnpm -C tests run test:source-guards` passed after `build:sdk-full` with
  645/645 source-profile tests; and `git diff --check` passed.
- Re-run after deleting `tests/unit/workspacePackageBoundaries.guard.unit.test.ts`
  and moving its package-root, type-path, deployable-app import, and native
  import checks into `tests/scripts/check-workspace-package-boundaries.mjs`:
  `node --check tests/scripts/check-workspace-package-boundaries.mjs` passed;
  `pnpm -C tests run check:workspace-package-boundaries` passed;
  `pnpm -C tests exec playwright test -c playwright.source.config.ts
  unit/cloudflareD1RuntimeBoundaries.guard.unit.test.ts -g "stale staging and
  relayer names stay deleted" --reporter=line` passed after dropping stale
  deleted example-path literals from the new checker; `pnpm -C tests run
  check:refactor88-test-ledger:complete` reported
  `scope=451 ledger_existing=451 ledger_deleted=10 missing=0`; and
  `pnpm -C tests run test:source-guards` passed after `build:sdk-full` with
  642/642 source-profile tests.
- Re-run after deleting
  `tests/unit/passkeyRegistrationButtonBoundaries.guard.unit.test.ts` and
  moving its registration-button import-independence check into
  `tests/scripts/check-passkey-registration-button-boundaries.mjs`:
  `node --check tests/scripts/check-passkey-registration-button-boundaries.mjs`
  passed; `pnpm -C tests run check:passkey-registration-button-boundaries`
  passed; and `pnpm -C tests run check:refactor88-test-ledger:complete`
  reported `scope=450 ledger_existing=450 ledger_deleted=11 missing=0`;
  `pnpm -C tests run test:source-guards` passed after `build:sdk-full` with
  641/641 source-profile tests.
- Re-run after deleting
  `tests/unit/seamsWebPublicSurfaceBoundaries.guard.unit.test.ts` and moving
  its SeamsWeb namespace, signing-surface dependency, root export,
  import-direction, iframe primitive, auth-method folder, and native-facade
  checks into `tests/scripts/check-seams-web-public-surface-boundaries.mjs`:
  `node --check tests/scripts/check-seams-web-public-surface-boundaries.mjs`
  passed; `pnpm -C tests run check:seams-web-public-surface-boundaries`
  passed; `pnpm -C tests run check:refactor88-test-ledger:complete` reported
  `scope=449 ledger_existing=449 ledger_deleted=12 missing=0`; and
  `pnpm -C tests run test:source-guards` passed after `build:sdk-full` with
  619/619 source-profile tests.
- Re-run after deleting
  `tests/unit/indexedDBConsolidation.guard.unit.test.ts` and moving raw
  IndexedDB/clientDB escape checks into
  `tests/scripts/check-indexeddb-consolidation-boundaries.mjs`:
  `node --check tests/scripts/check-indexeddb-consolidation-boundaries.mjs`
  passed; `pnpm -C tests run check:indexeddb-consolidation-boundaries` passed;
  `pnpm -C tests run check:refactor88-test-ledger:complete` reported
  `scope=448 ledger_existing=448 ledger_deleted=13 missing=0`; and
  `pnpm -C tests run test:source-guards` passed after `build:sdk-full` with
  616/616 source-profile tests.
- Re-run after deleting `tests/unit/keyExport.behavior.guard.unit.test.ts`
  and moving AccountMenuButton/export-modal source-boundary checks into
  `tests/scripts/check-key-export-boundaries.mjs`:
  `node --check tests/scripts/check-key-export-boundaries.mjs` passed;
  `pnpm -C tests run check:key-export-boundaries` passed;
  `pnpm -C tests run check:refactor88-test-ledger:complete` reported
  `scope=447 ledger_existing=447 ledger_deleted=14 missing=0`; and
  `pnpm -C tests run test:source-guards` passed after `build:sdk-full` with
  612/612 source-profile tests.
- Re-run after deleting
  `tests/unit/passkeyRegistrationRollback.guard.unit.test.ts` and moving
  rollback-state, signer-set registration, and deleted continuation-auth checks
  into `tests/scripts/check-passkey-registration-rollback-boundaries.mjs`:
  `node --check tests/scripts/check-passkey-registration-rollback-boundaries.mjs`
  passed; `pnpm -C tests run check:passkey-registration-rollback-boundaries`
  passed; `pnpm -C tests run check:refactor88-test-ledger:complete` reported
  `scope=446 ledger_existing=446 ledger_deleted=15 missing=0`; and
  `pnpm -C tests run test:source-guards` passed after `build:sdk-full` with
  609/609 source-profile tests after one transient WASM build rerun.
- Re-run after deleting `tests/unit/crossPlatformBoundaries.guard.unit.test.ts`
  and moving platform API, secret-material, runtime-port, role-local
  persistence, signer-command schema, and export-material boundary checks into
  `tests/scripts/check-cross-platform-boundaries.mjs`:
  `node --check tests/scripts/check-cross-platform-boundaries.mjs` passed;
  `pnpm -C tests run check:cross-platform-boundaries` passed;
  `pnpm -C tests run check:refactor88-test-ledger:complete` reported
  `scope=445 ledger_existing=445 ledger_deleted=16 missing=0`; and
  `pnpm -C tests run test:source-guards` passed after `build:sdk-full` with
  594/594 source-profile tests.
- Re-run after deleting
  `tests/unit/platformRuntimeBoundaries.guard.unit.test.ts` and moving
  runtime, browser adapter, native facade, WalletIframe import, and
  chain-signer routing boundary checks into
  `tests/scripts/check-platform-runtime-boundaries.mjs`:
  `node --check tests/scripts/check-platform-runtime-boundaries.mjs` passed;
  `pnpm -C tests run check:platform-runtime-boundaries` passed;
  `pnpm -C tests run check:refactor88-test-ledger:complete` reported
  `scope=444 ledger_existing=444 ledger_deleted=17 missing=0`; and
  `pnpm -C tests run test:source-guards` passed after `build:sdk-full` with
  585/585 source-profile tests after one transient WASM build rerun.
- Re-run after deleting
  `tests/unit/emailOtpRecoveryCodeLeakage.guard.unit.test.ts` and moving
  generated-key containment, plaintext-backup confinement, iframe exposure,
  logging/telemetry, storage, brand-cast, and backup-repository checks into
  `tests/scripts/check-email-otp-recovery-code-leakage.mjs`:
  `node --check tests/scripts/check-email-otp-recovery-code-leakage.mjs`
  passed; `pnpm -C tests run check:email-otp-recovery-code-leakage` passed;
  `pnpm -C tests run check:refactor88-test-ledger:complete` reported
  `scope=443 ledger_existing=443 ledger_deleted=18 missing=0`; and
  `pnpm -C tests run test:source-guards` passed after `build:sdk-full` with
  576/576 source-profile tests.
- Re-run after deleting
  `tests/unit/emailOtpEcdsaBranchIsolation.guard.unit.test.ts` and moving
  central domain-brand ownership, passkey PRF persistence, wallet-subject
  vocabulary, and temporary diagnostic cleanup checks into
  `tests/scripts/check-email-otp-ecdsa-branch-isolation.mjs`:
  `node --check tests/scripts/check-email-otp-ecdsa-branch-isolation.mjs`
  passed; `pnpm -C tests run check:email-otp-ecdsa-branch-isolation` passed;
  `pnpm -C tests run check:refactor88-test-ledger:complete` reported
  `scope=442 ledger_existing=442 ledger_deleted=19 missing=0`; and
  `pnpm -C tests run test:source-guards` passed after `build:sdk-full` with
  572/572 source-profile tests after one transient WASM build rerun.
- Re-run after mounting local D1 Email Recovery prepare/respond routes through
  a structural prepare-only Router API option: `pnpm -C packages/sdk-server-ts run build`
  passed;
  `pnpm -C tests exec playwright test -c playwright.unit.config.ts ./unit/cloudflareD1ConsoleServices.unit.test.ts --reporter=line`
  passed 15/15; `pnpm -C tests run check:refactor88-test-ledger:complete`
  reported `scope=442 ledger_existing=442 ledger_deleted=19 missing=0`;
  `pnpm -C tests run test:source-guards` passed after `build:sdk-full` with
  572/572 source-profile tests; and `git diff --check` passed.
- Re-run after deleting `tests/unit/authSecretTerminology.guard.unit.test.ts`
  and moving the auth-neutral docs terminology check into
  `tests/scripts/check-auth-secret-terminology.mjs`:
  `node --check tests/scripts/check-auth-secret-terminology.mjs` passed;
  `pnpm -C tests run check:auth-secret-terminology` passed;
  `pnpm -C tests run check:refactor88-test-ledger:complete` reported
  `scope=441 ledger_existing=441 ledger_deleted=20 missing=0`; and
  `pnpm -C tests run test:source-guards` passed after `build:sdk-full` with
  571/571 source-profile tests.
- Re-run after deleting
  `tests/unit/legacySeamsWebFacadeNames.guard.unit.test.ts` and
  `tests/unit/webauthnOriginPolicy.guard.unit.test.ts`, moving their
  invariants into package-export coverage and
  `tests/scripts/check-webauthn-origin-policy.mjs`:
  `node --check` plus each focused `pnpm -C tests run check:*` command passed;
  `pnpm -C tests run check:refactor88-test-ledger:complete` reported
  `scope=439 ledger_existing=439 ledger_deleted=22 missing=0`; and
  `pnpm -C tests run test:source-guards` passed after `build:sdk-full` with
  568/568 source-profile tests.
- Re-run after deleting
  `tests/unit/thresholdEd25519PresignNonceLifecycle.guard.unit.test.ts`,
  moving its source assertions into
  `tests/scripts/check-threshold-ed25519-presign-nonce-lifecycle.mjs`, and
  moving Ed25519 wallet-session material readiness/state helpers from
  `flows/signNear/shared` into `session/warmCapabilities`:
  `node --check tests/scripts/check-threshold-ed25519-presign-nonce-lifecycle.mjs`
  passed; `pnpm -C tests run check:threshold-ed25519-presign-nonce-lifecycle`
  passed; the focused Ed25519 HSS material and signing-engine ownership guards
  passed 36/36; `pnpm -C tests run check:refactor88-test-ledger:complete`
  reported `scope=438 ledger_existing=438 ledger_deleted=23 missing=0`;
  `pnpm -C tests run test:source-guards` passed after `build:sdk-full` with
  566/566 source-profile tests; and `git diff --check` passed.
- Re-run after deleting `tests/unit/thresholdEcdsa.behavior.guard.unit.test.ts`
  and moving ECDSA HSS source-boundary assertions into
  `tests/scripts/check-threshold-ecdsa-hss-boundaries.mjs`:
  `node --check tests/scripts/check-threshold-ecdsa-hss-boundaries.mjs`
  passed; `pnpm -C tests run check:threshold-ecdsa-hss-boundaries` passed;
  `pnpm -C tests run check:refactor88-test-ledger:complete` reported
  `scope=437 ledger_existing=437 ledger_deleted=24 missing=0`;
  `pnpm -C tests run test:source-guards` passed after `build:sdk-full` with
  561/561 source-profile tests; and `git diff --check` passed.
- Re-run after deleting
  `tests/unit/routerAbServerWalletSessionClaimBoundary.guard.unit.test.ts` and
  moving Router A/B wallet-session claim-boundary assertions into
  `tests/scripts/check-router-ab-server-wallet-session-claim-boundaries.mjs`:
  `node --check
  tests/scripts/check-router-ab-server-wallet-session-claim-boundaries.mjs`
  passed; `pnpm -C tests run
  check:router-ab-server-wallet-session-claim-boundaries` passed;
  `pnpm -C tests run check:refactor88-test-ledger:complete` reported
  `scope=436 ledger_existing=436 ledger_deleted=25 missing=0`; and
  `pnpm -C tests run test:source-guards` passed after `build:sdk-full` with
  557/557 source-profile tests.
- Re-run after deleting
  `tests/unit/headlessGoogleEmailOtpFlowBoundaries.guard.unit.test.ts` and
  moving its source assertions into
  `tests/scripts/check-headless-google-email-otp-flow-boundaries.mjs`:
  `node --check
  tests/scripts/check-headless-google-email-otp-flow-boundaries.mjs` passed;
  `pnpm -C tests run check:headless-google-email-otp-flow-boundaries` passed;
  `pnpm -C tests exec playwright test -c playwright.unit.config.ts
  unit/googleEmailOtpWalletAuthFlow.unit.test.ts
  unit/googleEmailOtpWalletIframeHandles.unit.test.ts --reporter=line` passed
  37/37; `pnpm -C tests run check:refactor88-test-ledger:complete` reported
  `scope=435 ledger_existing=435 ledger_deleted=26 missing=0`; and
  `pnpm -C tests run test:source-guards` passed after `build:sdk-full` with
  551/551 source-profile tests.
- Re-run after deleting
  `tests/unit/emailOtpRegistrationBoundaries.guard.unit.test.ts` and moving
  its source assertions into
  `tests/scripts/check-email-otp-registration-boundaries.mjs`: `node --check
  tests/scripts/check-email-otp-registration-boundaries.mjs` passed; `pnpm -C
  tests run check:email-otp-registration-boundaries` passed; `pnpm -C tests
  exec playwright test -c playwright.unit.config.ts
  unit/googleEmailOtpWalletAuthFlow.unit.test.ts
  unit/googleEmailOtpWalletIframeHandles.unit.test.ts
  unit/emailOtpRegistrationRoute.unit.test.ts --reporter=line` passed 42/42;
  the intended contract source guard was refreshed to the current
  `EmailOtpRegistrationCoreSummary` and `EmailOtpUnlockCoreSummary` page
  result type names; `pnpm -C tests run check:refactor88-test-ledger:complete`
  reported `scope=434 ledger_existing=434 ledger_deleted=27 missing=0`; and
  `pnpm -C tests run test:source-guards` passed after `build:sdk-full` with
  543/543 source-profile tests.
- Re-run after deleting
  `tests/unit/accountSignerLifecycle.domain.guard.unit.test.ts` and moving its
  source assertions into
  `tests/scripts/check-account-signer-lifecycle-boundaries.mjs`: `node --check
  tests/scripts/check-account-signer-lifecycle-boundaries.mjs` passed; `pnpm
  -C tests run check:account-signer-lifecycle-boundaries` passed; and `pnpm
  -C tests run check:refactor88-test-ledger:complete` reported
  `scope=433 ledger_existing=433 ledger_deleted=28 missing=0`; `pnpm -C
  tests run test:source-guards` passed after `build:sdk-full` with 541/541
  source-profile tests.
- Re-run after deleting `tests/unit/walletScopedLookups.guard.unit.test.ts`,
  moving its D1 wallet-id parser behavior assertion into
  `tests/unit/domainIds.boundary.unit.test.ts`, and moving the remaining source
  assertions into `tests/scripts/check-wallet-scoped-lookup-boundaries.mjs`:
  `node --check tests/scripts/check-wallet-scoped-lookup-boundaries.mjs`
  passed; `pnpm -C tests run check:wallet-scoped-lookup-boundaries` passed;
  and `pnpm -C tests exec playwright test -c playwright.unit.config.ts
  unit/domainIds.boundary.unit.test.ts --reporter=line` passed 26/26.
- Full cleanup-batch re-run after the wallet-scoped guard deletion:
  `pnpm -C tests run check:refactor88-test-ledger:complete` reported
  `scope=432 ledger_existing=432 ledger_deleted=29 missing=0`; `git diff
  --check` passed; the Refactor 88 intended action-result discriminant guard
  was tightened to read only the top-level action-result switch instead of
  nested ECDSA target-profile switches; and `pnpm -C tests run
  test:source-guards` passed after `build:sdk-full` with 535/535
  source-profile tests.
- Re-run after deleting `tests/unit/emailOtpOperationSplit.guard.unit.test.ts`
  and moving its 17 source-shaped operation-split checks into
  `tests/scripts/check-email-otp-operation-split.mjs`: `node --check
  tests/scripts/check-email-otp-operation-split.mjs` passed; `pnpm -C tests
  run check:email-otp-operation-split` passed; and the script is wired into
  `pnpm -C tests run test:source-guards`.
- Full cleanup-batch re-run after the Email OTP operation-split guard
  deletion: `pnpm -C tests run check:refactor88-test-ledger:complete`
  reported `scope=431 ledger_existing=431 ledger_deleted=30 missing=0`; the
  intended action-result guard was refreshed to the current page summary type
  names; the registration timing guard was refreshed for the split Ed25519
  timing buckets; `git diff --check` passed; and `pnpm -C tests run
  test:source-guards` passed after `build:sdk-full` with 518/518
  source-profile tests.
- Re-run after deleting `tests/unit/exactLookupNoFallbackBoundaries.guard.unit.test.ts`
  and moving its exact lookup / no-fallback assertions into
  `tests/scripts/check-exact-lookup-no-fallback-boundaries.mjs`: `node --check
  tests/scripts/check-exact-lookup-no-fallback-boundaries.mjs` passed; `pnpm
  -C tests run check:exact-lookup-no-fallback-boundaries` passed; `pnpm -C
  tests run check:refactor88-test-ledger:complete` reported
  `scope=430 ledger_existing=430 ledger_deleted=31 missing=0`; `git diff
  --check` passed; and `pnpm -C tests run test:source-guards` passed after
  `build:sdk-full` with 508/508 source-profile tests.
- Re-run after deleting `tests/unit/keyMaterialBrandingBoundaries.guard.unit.test.ts`
  and moving its key-material branding / grant-lifecycle assertions into
  `tests/scripts/check-key-material-branding-boundaries.mjs`: `node --check
  tests/scripts/check-key-material-branding-boundaries.mjs` passed; `pnpm -C
  tests run check:key-material-branding-boundaries` passed; `pnpm -C tests
  run check:refactor88-test-ledger:complete` reported
  `scope=429 ledger_existing=429 ledger_deleted=32 missing=0`; `git diff
  --check` passed; the Email OTP registration source check was refreshed to
  the current D1 prepare/persist block shape; the intended action-result guard
  was refreshed to end the parser range at `parseEcdsaEnabledSnapshot`; and
  `pnpm -C tests run test:source-guards` passed after `build:sdk-full` with
  499/499 source-profile tests.
- Re-run after deleting `tests/unit/routeLifecycleDomainBoundaries.guard.unit.test.ts`
  and moving its route/lifecycle boundary assertions into
  `tests/scripts/check-route-lifecycle-domain-boundaries.mjs`: `node --check
  tests/scripts/check-route-lifecycle-domain-boundaries.mjs` passed; `pnpm
  -C tests run check:route-lifecycle-domain-boundaries` passed; `pnpm -C
  tests run check:refactor88-test-ledger:complete` reported
  `scope=428 ledger_existing=428 ledger_deleted=33 missing=0`; `git diff
  --check` passed; and `pnpm -C tests run test:source-guards` passed after
  `build:sdk-full` with 484/484 source-profile tests.
- Re-run after deleting `tests/unit/thresholdEd25519.nearSigningQueue.guard.unit.test.ts`
  and moving its threshold Ed25519 NEAR signing queue assertions into
  `tests/scripts/check-threshold-ed25519-near-signing-queue.mjs`: `node
  --check tests/scripts/check-threshold-ed25519-near-signing-queue.mjs`
  passed; `pnpm -C tests run check:threshold-ed25519-near-signing-queue`
  passed; `pnpm -C tests run check:refactor88-test-ledger:complete` reported
  `scope=427 ledger_existing=427 ledger_deleted=34 missing=0`; `git diff
  --check` passed; and `pnpm -C tests run test:source-guards` passed after
  `build:sdk-full` with 468/468 source-profile tests.
- Re-run after deleting `tests/unit/walletCapabilityBindings.sourceGuard.unit.test.ts`
  and moving its wallet capability binding assertions into
  `tests/scripts/check-wallet-capability-bindings-source-guard.mjs`: `node
  --check tests/scripts/check-wallet-capability-bindings-source-guard.mjs`
  passed; `pnpm -C tests run check:wallet-capability-bindings-source-guard`
  passed; `pnpm -C tests run check:refactor88-test-ledger:complete` reported
  `scope=426 ledger_existing=426 ledger_deleted=35 missing=0`; `git diff
  --check` passed; and `pnpm -C tests run test:source-guards` passed after
  `build:sdk-full` with 468/468 source-profile tests.
- Re-run after pruning stale wallet capability allowlist entries and adding
  stale-entry rejection to
  `tests/scripts/check-wallet-capability-bindings-source-guard.mjs`: `pnpm -C
  tests run check:wallet-capability-bindings-source-guard` passed with ten
  live documented allowlist entries remaining. Follow-up validation moved the
  `test:source-guards` `build:sdk-full` step before standalone scripts so
  ignored WASM declaration outputs exist before source checks inspect them,
  added a short WASM output-existence retry to `build-wasm.sh`, and removed the
  public signer-worker type entry's runtime import of generated NEAR signer
  JS by mirroring the generated worker enums locally. `pnpm -C packages/sdk-web
  exec tsc -p tsconfig.json --noEmit --pretty false` passed; `pnpm -C
  packages/sdk-web run build:sdk-full` passed; `pnpm -C tests run
  test:source-guards` passed with 408/408 source-profile tests; `pnpm -C tests
  run check:refactor88-test-ledger:complete` reported
  `scope=420 ledger_existing=420 ledger_deleted=44 missing=0`; and `git diff
  --check` passed.
- Re-run after moving permanent parser/builder/diagnostics wallet-capability
  boundaries into built-in checker exemptions: `pnpm -C tests run
  check:wallet-capability-bindings-source-guard` passed with six
  migration-owned JSON allowlist entries remaining.
- Re-run after deleting the retired wallet-capability JSON allowlist: `pnpm -C
  tests run check:wallet-capability-bindings-source-guard` passed; `pnpm -C
  packages/sdk-web type-check` passed after wallet-scoped ECDSA and Email OTP
  flow events moved to `walletId` payloads; `pnpm -C tests run
  check:refactor88-test-ledger:complete` reported
  `scope=413 ledger_existing=413 ledger_deleted=53 missing=0`; and `pnpm -C
  tests run test:source-guards` passed with all standalone checks and 190/190
  source-profile tests.
- Re-run after moving strict-router route literals out of
  `crates/router-ab-cloudflare/tests/source_guards.rs` into
  `crates/router-ab-cloudflare/tests/route_paths.rs`: `cargo fmt
  --manifest-path crates/router-ab-cloudflare/Cargo.toml` passed; `cargo test
  --manifest-path crates/router-ab-cloudflare/Cargo.toml --test route_paths`
  passed 1/1; `cargo test --manifest-path
  crates/router-ab-cloudflare/Cargo.toml --test source_guards` passed 38/38;
  and `git diff --check -- crates/router-ab-cloudflare/tests/route_paths.rs
  crates/router-ab-cloudflare/tests/source_guards.rs
  docs/refactor-89-clean-source-guards.md` passed.
- Re-run after splitting strict-router CORS checks out of the broad Cloudflare
  source guard into `crates/router-ab-cloudflare/tests/strict_router_cors_boundaries.rs`:
  `cargo fmt --manifest-path crates/router-ab-cloudflare/Cargo.toml` passed;
  `cargo test --manifest-path crates/router-ab-cloudflare/Cargo.toml --test
  strict_router_cors_boundaries` passed 2/2; `cargo test --manifest-path
  crates/router-ab-cloudflare/Cargo.toml --test source_guards` passed 36/36;
  and `cargo test --manifest-path crates/router-ab-cloudflare/Cargo.toml
  --test route_paths` passed 1/1.
- Re-run after splitting strict-router bearer-admission and parser-boundary
  checks into `crates/router-ab-cloudflare/tests/strict_router_route_boundaries.rs`:
  `cargo fmt --manifest-path crates/router-ab-cloudflare/Cargo.toml` passed;
  `cargo test --manifest-path crates/router-ab-cloudflare/Cargo.toml --test
  strict_router_route_boundaries` passed 3/3; and `cargo test
  --manifest-path crates/router-ab-cloudflare/Cargo.toml --test source_guards`
  passed 33/33.
- Re-run after moving the normal-signing replay-order and admission-candidate
  route checks into `crates/router-ab-cloudflare/tests/strict_router_route_boundaries.rs`:
  `cargo fmt --manifest-path crates/router-ab-cloudflare/Cargo.toml` passed;
  `cargo test --manifest-path crates/router-ab-cloudflare/Cargo.toml --test
  strict_router_route_boundaries` passed 5/5; and `cargo test
  --manifest-path crates/router-ab-cloudflare/Cargo.toml --test source_guards`
  passed 31/31.
- Re-run after moving Phase 3B mutation-proof ownership out of
  `tests/scripts/check-intended-behaviour-contract-boundaries.mjs` and into the
  dedicated mutation verifier: `node --check
  tests/scripts/check-intended-behaviour-contract-boundaries.mjs`, `node
  --check tests/scripts/check-intended-mutation-self-check.mjs`, `pnpm -C
  tests run check:intended-mutation-self-check:complete`, and `pnpm -C tests
  run check:intended-behaviour-contract-boundaries` passed.
- Re-run after moving retained-boundary audit ownership out of
  `tests/scripts/check-intended-behaviour-contract-boundaries.mjs` and into the
  Refactor 88 ledger verifier: `node --check
  tests/scripts/check-intended-behaviour-contract-boundaries.mjs`, `node
  --check tests/scripts/check-refactor88-test-ledger.mjs`, `pnpm -C tests run
  check:refactor88-test-ledger:complete`, and `pnpm -C tests run
  check:intended-behaviour-contract-boundaries` passed. The aggregate `pnpm -C
  tests run test:source-guards` command passed with the ledger verifier wired
  into the source profile and 190/190 Playwright source-profile tests green.
- Re-run after moving ECDSA-HSS activation/export assertions from
  `crates/router-ab-cloudflare/tests/source_guards.rs` into
  `crates/router-ab-cloudflare/tests/ecdsa_hss_activation_boundaries.rs`:
  `cargo fmt --manifest-path crates/router-ab-cloudflare/Cargo.toml` passed;
  `cargo test --manifest-path crates/router-ab-cloudflare/Cargo.toml --test
  ecdsa_hss_activation_boundaries` passed 8/8; and `cargo test
  --manifest-path crates/router-ab-cloudflare/Cargo.toml --test source_guards`
  passed 21/21.
- Re-run after moving ECDSA-HSS normal-signing/presignature assertions from
  `crates/router-ab-cloudflare/tests/source_guards.rs` into
  `crates/router-ab-cloudflare/tests/ecdsa_hss_normal_signing_boundaries.rs`:
  `cargo fmt --manifest-path crates/router-ab-cloudflare/Cargo.toml` passed;
  `cargo test --manifest-path crates/router-ab-cloudflare/Cargo.toml --test
  ecdsa_hss_normal_signing_boundaries` passed 8/8; and `cargo test
  --manifest-path crates/router-ab-cloudflare/Cargo.toml --test source_guards`
  passed 13/13.
- Re-run after moving normal-signing worker, strict private worker dispatch,
  and legacy-symbol assertions from
  `crates/router-ab-cloudflare/tests/source_guards.rs` into
  `crates/router-ab-cloudflare/tests/normal_signing_worker_boundaries.rs`:
  `cargo fmt --manifest-path crates/router-ab-cloudflare/Cargo.toml` passed;
  `cargo test --manifest-path crates/router-ab-cloudflare/Cargo.toml --test
  normal_signing_worker_boundaries` passed 10/10; and `cargo test
  --manifest-path crates/router-ab-cloudflare/Cargo.toml --test source_guards`
  passed 3/3.
- Re-run after deleting the `tests/unit/signingEngineArchitecture.*.guard.unit.test.ts`
  Playwright wrappers and `tests/unit/helpers/signingEngineArchitectureGuard.ts`
  helper, with their checks moved into
  `tests/scripts/check-signing-engine-architecture-boundaries.mjs`: `node
  --check tests/scripts/check-signing-engine-architecture-boundaries.mjs`
  passed; `pnpm -C tests run check:signing-engine-architecture-boundaries`
  passed; `pnpm -C tests run check:refactor88-test-ledger:complete` reported
  `scope=421 ledger_existing=421 ledger_deleted=40 missing=0`; `git diff
  --check` passed; and `pnpm -C tests run test:source-guards` passed after
  `build:sdk-full` with 431/431 source-profile tests.
- Stabilization re-run after retargeting stale Email OTP enrollment references
  to the current `prewarmedRegistrationMaterial` / worker-enrollment boundary:
  `node --check tests/scripts/check-cross-platform-boundaries.mjs` passed;
  `node tests/scripts/check-cross-platform-boundaries.mjs` passed; `node
  --check tests/scripts/check-email-otp-recovery-code-leakage.mjs` passed;
  `node tests/scripts/check-email-otp-recovery-code-leakage.mjs` passed;
  `pnpm -C tests exec playwright test -c playwright.source.config.ts
  unit/ed25519HssMaterialBoundaries.guard.unit.test.ts --reporter=line` passed
  26/26; `pnpm -C tests exec playwright test -c playwright.unit.config.ts
  unit/seamsWeb.emailOtp.unit.test.ts --reporter=line` passed 8/8; and
  `pnpm -C tests run test:source-guards` passed end-to-end after
  `build:sdk-full` with 408/408 source-profile tests. The Refactor 88 ledger
  completeness check reported `scope=421 ledger_existing=421 ledger_deleted=44 missing=0`
  after adding the retained D1 registration ECDSA wallet-key row.
- Current validation, July 5, 2026: `pnpm -C tests run test:source-guards`
  passes end-to-end after `build:sdk-full`, with all standalone source scripts
  passing and 190/190 Playwright source-profile tests green.
  `pnpm -C tests run check:refactor88-test-ledger:complete` reports
  `scope=407 ledger_existing=407 ledger_deleted=66 missing=0`.
- Re-run after narrowing D1 registration/add-signer source checks and deleting
  the broad Cloudflare Router A/B `source_guards.rs` file:
  `node --check tests/scripts/check-cloudflare-d1-runtime-boundaries.mjs`,
  `pnpm -C tests run check:cloudflare-d1-runtime-boundaries`,
  `cargo test --manifest-path crates/router-ab-cloudflare/Cargo.toml --test secret_material_boundaries`,
  the six focused Router A/B boundary tests
  (`route_paths`, `strict_router_cors_boundaries`,
  `strict_router_route_boundaries`, `ecdsa_hss_activation_boundaries`,
  `ecdsa_hss_normal_signing_boundaries`, and
  `normal_signing_worker_boundaries`),
  `pnpm -C tests run check:refactor88-test-ledger:complete`, and
  `git diff --check` all pass.

Remaining source-guard cleanup buckets:

- Current source profile is green; no failing guard buckets remain in
  `playwright.source.config.ts`.
- The former 82/83 refactor-numbered temporary guards now use stable filenames;
  their owner-plan cleanup gates remain active.
- Large temporary suites are split by invariant in Phase 0. Their rows now
  need replacement coverage, conversion to stable durable tests, or deletion as
  their owner-plan gates fire.
- Refactor 88 remote-CI enforcement and the retired setup/runtime absence window
  still gate deletion of `tests/scripts/check-intended-behaviour-contract-boundaries.mjs`.
  The Phase 3B mutation-proof shard has moved to the dedicated
  `check:intended-mutation-self-check:complete` verifier, and retained-boundary
  audit evidence has moved to `check:refactor88-test-ledger:complete`.
- `tests/scripts/check-refactor88-test-ledger.mjs` remains active until
  Refactor 88 closes. The Refactor 90 F3 Express route deletion has fired; the
  guard still covers the live Refactor 90-gated console route collapse and
  budget-to-grant-use cleanup rows.
