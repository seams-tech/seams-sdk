# Refactor 89 final local test receipt v1

Date: July 17, 2026 (JST)

Base commit: `186e55d99f0a1df0f0229b44e6ceaf3aec00f013`

This receipt records commands executed against the shared development
worktree. The worktree contained the Refactor 89 implementation changes, so
the base commit alone does not identify the tested tree. Release digests stay
owned by `phase-e-local-artifacts-v1.json`; this receipt provides reproducible
command and result evidence for the final local gate rerun.

## Host and toolchain

- architecture: `arm64`
- Rust: `rustc 1.96.0 (ac68faa20 2026-05-25)`
- Cargo: `cargo 1.96.0 (30a34c682 2026-05-25)`
- Node.js: `v24.18.0`
- pnpm: `10.28.2`

## Rust crypto, oracle, pool, and Router A/B routes

| Command | Direct result |
| --- | --- |
| `cargo test --locked --manifest-path crates/router-ab-ecdsa-presign/Cargo.toml` | passed: 44 runtime tests and 7 compile-fail doctests |
| `cargo test --locked --manifest-path crates/router-ab-ecdsa-online/Cargo.toml` | passed: 1 runtime test and 5 compile-fail doctests |
| `cargo test --locked --manifest-path crates/router-ab-ecdsa-pool/Cargo.toml` | passed: 8 runtime tests and 1 tombstone compile-fail doctest |
| `cargo test --locked --manifest-path crates/router-ab-ecdsa-near-oracle-tests/Cargo.toml` | passed: 20 integration tests, including the four-case semantic parity matrix, abort index, manifest/inventory guards, production boundaries, and release-Wasm constant-time scan |
| `cargo test --locked --manifest-path crates/router-ab-cloudflare/Cargo.toml` | passed: 332 tests, including 280 binding tests and all strict ECDSA activation, pool lifecycle, normal-signing, CORS, route, secret-material, and vector-adapter suites |
| `cargo test --locked --manifest-path crates/router-ab-dev/Cargo.toml` | passed: 77 tests, including Cloudflare parity, local HTTP worker profiles, durable storage, and route ownership |
| `node crates/router-ab-cloudflare/scripts/assert-release-ready.mjs` | passed: Router A/B release blockers clear |

The oracle result is semantic compatibility evidence within the pinned corpus.
It does not satisfy the independent construction-review gate.

## SDK, server, build, and boundary guards

| Command | Direct result |
| --- | --- |
| `pnpm -C packages/sdk-server-ts type-check` | passed |
| `pnpm -C packages/sdk-server-ts build` | passed, including TypeScript, Rolldown, and Wasm asset copy |
| `pnpm -C packages/sdk-web type-check` | passed |
| `pnpm -C packages/sdk-web build:prod` | passed after the missing pinned `wasm-bindgen` CLI was downloaded; the first sandboxed attempt failed only on blocked DNS/download access |
| `pnpm -C packages/sdk-web check:bundle-size` | passed after the completed build; all expected worker/Wasm outputs were present |
| `pnpm -C packages/sdk-web check:wasm-exports` | completed successfully as an informational generated-export audit |
| `node tests/scripts/check-ecdsa-client-worker-split.mjs` | passed: fixed worker ownership, deleted-symbol, dependency, artifact, and review-corpus digest checks |
| `node tests/scripts/check-signing-engine-ecdsa-identity-boundaries.mjs` | passed |
| `node tests/scripts/check-cross-platform-boundaries.mjs` | passed |
| `node tests/scripts/check-router-ab-ecdsa-derivation-boundaries.mjs` | passed after the negative deletion guard was classified as a guard surface |
| `node tests/scripts/check-intended-behaviour-contract-boundaries.mjs` | passed after the encrypted Client presign store browser suite received its retained audit row |

The production build emitted every current ECDSA role-specific Wasm package
and completed its runtime-entry, hosted-wallet asset, TypeScript, and bundling
checks. The generated-export report also enumerated ignored local `pkg` caches
for the deleted experimental `evm_transaction_codec` and `webauthn_p256`
crates. No corresponding file appeared in `packages/sdk-web/dist`.

## Registration package closure follow-up

The final registration optimization moved bootstrap preparation, finalization,
resolved Email OTP bootstrap, and role-local share opening into
`wasm/ecdsa_registration_client`. Explicit recovery/export remains in
`wasm/router_ab_ecdsa_derivation_client`. The production worker selects the
package by operation, so registration does not fetch or initialize the deferred
export Wasm.

| Command or check | Direct result |
| --- | --- |
| `cargo check --offline --locked --manifest-path wasm/ecdsa_registration_client/Cargo.toml` | passed |
| `wasm-pack build --locked --target web --out-dir pkg --out-name ecdsa_registration_client --release` | passed |
| `pnpm -C packages/sdk-web run build:prod` | passed, including TypeScript, production worker bundling, hosted static assets, and the renamed Wasm copies |
| `node tests/scripts/check-router-ab-ecdsa-derivation-boundaries.mjs` | passed, including registration-package dependency, export, and compressed-size ceilings |
| `node tests/scripts/check-ecdsa-client-worker-split.mjs` | passed |
| `node tests/scripts/check-ed25519-yao-near-signing-boundaries.mjs` | passed |
| `pnpm -C tests exec playwright test -c playwright.lite.config.ts ./unit/routerAbEcdsaRegistrationWaterfall.unit.test.ts --reporter=line` | passed: registration fetched `ecdsa_registration_client_bg.wasm` and made zero requests for the deferred export Wasm |
| stale-name and output search | passed: no source, generated package, or production artifact retained `router_ab_ecdsa_registration_client` |

The current production registration worker and Wasm total 264,754 raw bytes,
102,165 gzip-9 bytes, and 85,438 Brotli-11 bytes. The previous mixed dependency
path was approximately 250,506 gzip bytes, so first-registration ECDSA
cryptographic transfer falls by 148,341 bytes, or 59.2%.
The renamed registration package itself changes no cryptographic equation,
transcript, pool lifecycle, or normal-signing path. Separately changed
Cloudflare lifecycle files are tracked by the formal-closure blocker below.

## Focused browser and intended-behaviour evidence

The following command passed 75 of 75 Chromium tests:

```text
pnpm -C tests exec playwright test -c playwright.unit.config.ts \
  ./unit/ecdsaPresignMaterialStore.unit.test.ts \
  ./unit/thresholdEcdsa.presignDistributed.unit.test.ts \
  ./unit/thresholdEcdsa.persistedRecords.unit.test.ts \
  ./unit/thresholdEcdsa.presignPoolPolicy.unit.test.ts \
  ./unit/evmFamilyEcdsaIdentity.unit.test.ts \
  ./unit/routerAbEcdsaPoolHitWaterfall.unit.test.ts \
  --reporter=line
```

The result directly covers encrypted one-use Client persistence, destructive
recovery and exact-scope retirement, current persisted-record rejection,
cross-Wasm fixed-role presigning, SigningWorker pool fill, refill admission,
exact EVM-family identity, and the emitted online-only pool-hit waterfall with
zero presign fetches and zero browser Deriver calls.

The complete 11-contract passkey and Email OTP intended-behaviour suite was
not rerun. `phase-e-local-artifacts-v1.json` already records its July 17 pass,
and this final rerun changed only source-guard classification and test-ledger
bookkeeping. A fresh full run also requires the intended-services and Google
OIDC credential setup. The standalone intended-behaviour boundary guard passed
in this receipt.

## Failures inspected and resolved

1. The first SDK production build attempt reached the ECDSA packages, then the
   Ed25519 Yao build could not download its pinned `wasm-bindgen` CLI inside the
   network-restricted sandbox. The identical command passed with approved
   network access. No source fix was required.
2. The Router A/B vocabulary guard scanned the ECDSA deletion guard and treated
   its forbidden-symbol assertions as active vocabulary. The negative guard is
   now classified with the other guard-only surfaces. Both the vocabulary guard
   and deletion guard pass.
3. The intended-behaviour boundary guard found that
   `ecdsaPresignMaterialStore.unit.test.ts` used the retained browser bootstrap
   without a Refactor 88 audit row. The current six-test encrypted persistence
   suite now has an exact `keep` row. The boundary guard passes.

No lifecycle, cryptographic, persistence, request, or product behavior changed
during these resolutions. No obsolete-behavior fixture needed restoration.

## External and deployment-owned cases

These cases remain outside this local receipt:

- independently administered Cloudflare account and CI separation evidence;
- deployed ECDSA cold/warm latency, CPU, memory, cost, failure, and rollback
  measurements owned by `docs/router-a-b-deployment.md`;
- credential-dependent Redis/Upstash persistence cases; and
- deployed-browser route evidence requiring the configured external Router A/B
  endpoints.

The Ed25519 Yao Phase 13A decision and independent-operator resource import
remain owned by `docs/yaos-ab-deployment.md` and do not close an ECDSA local
checkbox.

## Checklist disposition

Every directly executable implementation checkbox is complete in
`docs/refactor-89-slimmer-near-ecdsa.md`. The registration-package behavior
passes its narrow review, while formal closure remains open because three
subsequently changed Cloudflare signing/pool lifecycle files no longer match
the approved source-tree manifest. Those files require a bounded review
refresh. Deployment-owned items remain open in their deployment plans.
