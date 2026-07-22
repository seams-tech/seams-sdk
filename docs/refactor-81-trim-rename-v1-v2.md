# Refactor 81: Trim And Rename V1/V2 Route Noise

Date created: June 26, 2026

Status: implemented.

Related plans:

- [refactor-77-near-implicit-accounts.md](./refactor-77-near-implicit-accounts.md)
- [refactor-78-wallet-capability-bindings.md](./refactor-78-wallet-capability-bindings.md)
- [refactor-79-exact-signing-lane.md](./refactor-79-exact-signing-lane.md)
- [refactor-80-switch-case.md](./refactor-80-switch-case.md)
- [router-ab/protocol.md](./router-ab/protocol.md)

## Goal

Make the active Router A/B codebase read as one current architecture.

HTTP route names, route constants, local-dev route mirrors, and route tests
should stop carrying `v1`/`v2` suffixes. Version suffixes remain only for durable
wire, cryptographic, storage, and hash-domain contracts where the version is
part of compatibility or canonical bytes.

Primary outcomes:

- active HTTP paths use one unversioned Router A/B namespace;
- route constants do not use `_V1` or `_V2` suffixes;
- route-specific local-dev and Cloudflare helpers do not encode route versions
  in their names;
- protocol/wire/storage types keep their existing version suffixes;
- source guards reject route-version churn from returning.

No legacy compatibility is required. Delete aliases and stale route names rather
than preserving adapters.

## Problem

The current code mixes several unrelated meanings under the same `v1`/`v2`
language:

- route namespace version, such as `/v2/router-ab/...` and `/v1/legacy/...`;
- protocol and canonical wire type versions, such as
  `RouterAbEcdsaDerivationEvmDigestSigningRequestV1`;
- storage record and Durable Object API versions;
- local-dev route mirror names;
- test fixture and source-guard names.

That makes active code harder to audit. A reader cannot tell whether `V2` means
"current route path", "new protocol format", "current storage shape", or
"historical compatibility".

The route layer should be boring. The protocol layer can remain explicit.

## Naming Rule

Use version suffixes only where the version changes durable meaning:

- canonical wire request/response structs;
- domain tags used in hashes, signatures, JWT claims, HPKE labels, and formal
  verification vectors;
- persisted records and compatibility boundary parsers;
- database/storage schemas;
- protocol helper functions whose name describes a canonical wire algorithm.

Remove version suffixes from route-level names:

- HTTP path constants;
- route family allowlists;
- route dispatch helpers;
- local-dev route constants;
- service-binding path constants;
- Durable Object HTTP operation paths;
- source guards about routes.

Examples:

```ts
// route constant: unversioned
export const ROUTER_AB_ECDSA_DERIVATION_NORMAL_SIGNING_PATH =
  '/router-ab/ecdsa-derivation/sign' as const;

// wire type: versioned
export type RouterAbEcdsaDerivationEvmDigestSigningRequestV1 = {
  // canonical protocol fields
};
```

```rust
// route constant: unversioned
pub const CLOUDFLARE_ROUTER_ECDSA_DERIVATION_SIGNING_PUBLIC_REQUEST_PATH: &str =
    "/router-ab/ecdsa-derivation/sign";

// protocol parser: versioned
parse_router_ab_ecdsa_derivation_evm_digest_signing_request_v1_json(...)
```

## Target Route Shape

Public Router routes:

| Current route | Target route |
| --- | --- |
| `/v1/legacy/split-derivation` | `/router-ab/split-derivation` |
| `/v2/router-ab/keyset` | `/router-ab/keyset` |
| `/.well-known/router-ab/keyset` | keep as canonical well-known alias |
| `/v2/router-ab/ed25519/sign/prepare` | `/router-ab/ed25519/sign/prepare` |
| `/v2/router-ab/ed25519/sign/presign-pool/prepare` | `/router-ab/ed25519/sign/presign-pool/prepare` |
| `/v2/router-ab/ed25519/sign` | `/router-ab/ed25519/sign` |
| `/router-ab/ecdsa-derivation/healthz` | `/router-ab/ecdsa-derivation/healthz` |
| `/router-ab/ecdsa-derivation/export/share` | `/router-ab/ecdsa-derivation/export/share` |
| `/v1/legacy/ecdsa/register` | `/router-ab/ecdsa-derivation/register` |
| `/v1/legacy/ecdsa/export` | `/router-ab/ecdsa-derivation/export` |
| `/v1/legacy/ecdsa/recover` | `/router-ab/ecdsa-derivation/recover` |
| `/v1/legacy/ecdsa/refresh` | `/router-ab/ecdsa-derivation/refresh` |
| `/v1/legacy/ecdsa/sign/prepare` | `/router-ab/ecdsa-derivation/sign/prepare` |
| `/v1/legacy/ecdsa/sign` | `/router-ab/ecdsa-derivation/sign` |
| `/router-ab/ecdsa-derivation/presignature-pool/fill/init` | `/router-ab/ecdsa-derivation/presignature-pool/fill/init` |
| `/router-ab/ecdsa-derivation/presignature-pool/fill/step` | `/router-ab/ecdsa-derivation/presignature-pool/fill/step` |
| `/session/signing-budget/status` | `/router-ab/wallet-budget/status` |
| `/router-ab/wallet-session/ed25519` | `/router-ab/wallet-session/ed25519` |

Private Cloudflare/local worker routes:

| Current route | Target route |
| --- | --- |
| `/router-ab/v1/router/wallet-budget/put-grant` | `/router-ab/router/wallet-budget/put-grant` |
| `/router-ab/v1/signer-a` | `/router-ab/signer-a` |
| `/router-ab/v1/signer-b` | `/router-ab/signer-b` |
| `/router-ab/v1/signer-a/peer` | `/router-ab/signer-a/peer` |
| `/router-ab/v1/signer-b/peer` | `/router-ab/signer-b/peer` |
| `/router-ab/v1/signer-a/ecdsa-derivation/*` | `/router-ab/signer-a/ecdsa-derivation/*` |
| `/router-ab/v1/signer-b/ecdsa-derivation/*` | `/router-ab/signer-b/ecdsa-derivation/*` |
| `/router-ab/v1/signing-worker/*` | `/router-ab/signing-worker/*` |

Durable Object internal call routes:

| Current route | Target route |
| --- | --- |
| `/router-ab/do/v1/*` | `/router-ab/do/*` |

Route strings must have no active `/v1/`, `/v2/`, `/router-ab/v1`,
`/router-ab/v2`, `/router-ab/do/v1`, or `/router-ab/do/v2` segments.

## Phase 0: Inventory And Classification

- [x] Inventory every active route literal and route constant:
  - [x] `crates/router-ab-cloudflare/src/paths.rs`
  - [x] `crates/router-ab-cloudflare/src/strict_worker/*`
  - [x] `crates/router-ab-cloudflare/src/durable_object/*`
  - [x] `crates/router-ab-dev/src/*`
  - [x] `packages/shared-ts/src/utils/routerAbEcdsaDerivation.ts`
  - [x] `packages/sdk-server-ts/src/router/**`
  - [x] `packages/sdk-server-ts/src/core/ThresholdService/routerAb/**`
  - [x] `packages/sdk-web/src/core/rpcClients/relayer/**`
  - [x] `packages/sdk-web/src/core/signingEngine/routerAb/**`
  - [x] `tests/**`
- [x] Classify each `V1`/`V2` symbol as one of:
  - [x] route-level naming to remove;
  - [x] protocol/wire naming to keep;
  - [x] storage/schema naming to keep;
  - [x] hash-domain/formal-vector naming to keep;
  - [x] historical docs only.
- [x] Write down any ambiguous cases before editing.

Acceptance:

- The inventory separates route names from protocol names.
- No route-level symbol is marked for compatibility preservation.

## Phase 1: Rename Active Route Paths

- [x] Change public Router paths from `/v1/legacy/...` and `/v2/router-ab/...` to
      `/router-ab/...`.
- [x] Change private service-binding paths from `/router-ab/v1/...` to
      `/router-ab/...`.
- [x] Change Durable Object paths from `/router-ab/do/v1/...` to
      `/router-ab/do/...`.
- [x] Keep `/.well-known/router-ab/keyset` as an explicit well-known alias.
- [x] Do not add legacy aliases for the old paths.
- [x] Update error messages that list expected routes.

Acceptance:

- Active route dispatch accepts only the target route shape.
- Old routes fail by absence, not through a compatibility branch.

## Phase 2: Remove Route Constant Version Suffixes

- [x] Rename Cloudflare path constants:
  - [x] `CLOUDFLARE_ROUTER_*_PATH_V2` -> `CLOUDFLARE_ROUTER_*_PATH`
  - [x] `CLOUDFLARE_SIGNER_*_PATH_V2` -> `CLOUDFLARE_SIGNER_*_PATH`
  - [x] `CLOUDFLARE_SIGNING_WORKER_*_PATH_V2` ->
        `CLOUDFLARE_SIGNING_WORKER_*_PATH`
  - [x] `CLOUDFLARE_DURABLE_OBJECT_API_VERSION` should be renamed or
        removed if it only describes route naming.
- [x] Rename shared TS ECDSA derivation path constants:
  - [x] `ROUTER_AB_ECDSA_DERIVATION_*_PATH_V2` -> `ROUTER_AB_ECDSA_DERIVATION_*_PATH`
- [x] Rename local-dev route mirrors:
  - [x] `LOCAL_ROUTER_*_PATH_V2` -> `LOCAL_ROUTER_*_PATH`
  - [x] `LOCAL_DERIVER_*_PATH_V2` -> `LOCAL_DERIVER_*_PATH`
  - [x] `LOCAL_SIGNING_WORKER_*_PATH_V2` -> `LOCAL_SIGNING_WORKER_*_PATH`
- [x] Rename TypeScript private route constants:
  - [x] `PRIVATE_ED25519_*_PATH_V2` -> `PRIVATE_ED25519_*_PATH`
  - [x] `PRIVATE_ECDSA_DERIVATION_*_PATH_V2` -> `PRIVATE_ECDSA_DERIVATION_*_PATH`

Acceptance:

- `rg 'PATH_V[0-9]'` finds no active route constants.
- Remaining versioned identifiers are protocol, storage, hash-domain, or
  historical fixtures.

## Phase 3: Update SDK And Server Callers

- [x] Update SDK web relayer clients:
  - [x] ECDSA bootstrap/export clients
  - [x] ECDSA normal signing prepare/finalize
  - [x] ECDSA presignature pool fill init/step
  - [x] Ed25519 normal signing prepare/finalize/refill
  - [x] wallet budget status reader
- [x] Update SDK server route definitions and route handlers:
  - [x] Express threshold ECDSA routes
  - [x] Cloudflare threshold ECDSA routes
  - [x] session/wallet budget routes
  - [x] route metadata and policy definitions
- [x] Update Cloudflare self-hosted signing-worker scripts and release checks.
- [x] Update local-dev worker topology and parity tests.

Acceptance:

- Browser SDK, server SDK, local-dev Router, and strict Cloudflare agree on one
  route namespace.
- No call site constructs the old route strings manually.

## Phase 4: Preserve Protocol Version Names

- [x] Keep canonical protocol and parser names such as:
  - [x] `RouterAbEcdsaDerivationEvmDigestSigningRequestV1`
  - [x] `RouterAbEd25519NormalSigningPrepareRequestV2`
  - [x] `parse_router_ab_ecdsa_derivation_*_v1_json`
  - [x] `parse_router_ab_ed25519_*_v2_json`
- [x] Keep hash-domain strings such as:
  - [x] `router-ab-protocol/.../v1`
  - [x] `router-ab-protocol/.../v2`
  - [x] HPKE/domain-separation labels
- [x] Keep storage record versions when they describe persisted shape.
- [x] Avoid broad mechanical renames that change canonical bytes or formal
      vectors.

Acceptance:

- Route tests change routes.
- Wire vector tests do not require vector regeneration because route names are
  transport concerns.

## Phase 5: Tests, Guards, And Fixtures

- [x] Update route fixtures in:
  - [x] `tests/unit/routerAbNormalSigningSdk.guard.unit.test.ts`
  - [x] `tests/unit/router.routeDefinitions.unit.test.ts`
  - [x] `tests/unit/refactor80SwitchCase.guard.unit.test.ts`
  - [x] relayer threshold ECDSA tests
  - [x] Cloudflare/local-dev Rust tests
- [x] Add a source guard rejecting active route-version strings:
  - [x] `/v1/legacy`
  - [x] `/v2/router-ab`
  - [x] `/router-ab/v1`
  - [x] `/router-ab/v2`
  - [x] `/router-ab/do/v1`
  - [x] `/router-ab/do/v2`
  - [x] `/session/signing-budget/status`
- [x] Add a source guard rejecting route constant suffixes:
  - [x] `PATH_V1`
  - [x] `PATH_V2`
  - [x] `REQUEST_PATH_V1`
  - [x] `REQUEST_PATH_V2`
- [x] Add allowlist comments only for:
  - [x] the guard file itself;
  - [x] historical audit/chat docs;
  - [x] protocol/domain strings unrelated to HTTP routes.

Acceptance:

- A new route with `v1` or `v2` in the path fails the guard.
- A new route constant with `_V1` or `_V2` fails the guard.
- Protocol type names remain accepted.

## Phase 6: Docs And Operator Surface

- [x] Update active docs:
  - [x] [router-ab/protocol.md](./router-ab/protocol.md)
  - [x] [router-ab/local-development.md](./router-ab/local-development.md)
  - [x] [router-ab/protocol.md](./router-ab/protocol.md)
  - [x] [refactor-70-server-budget.md](./refactor-70-server-budget.md)
  - [x] threshold ECDSA integration/signing docs
- [x] Update release/deploy scripts that probe routes.
- [x] Update Caddy/source-guard text that mentions route path splitting.
- [x] Leave historical audit/chats alone unless an active guard reads them.

Acceptance:

- Active docs show one route family.
- Historical records can still mention old routes as historical facts.

## Phase 7: Validation

Run targeted validation after implementation:

```text
cargo check --manifest-path crates/router-ab-cloudflare/Cargo.toml
cargo check --manifest-path crates/router-ab-cloudflare/Cargo.toml --features strict-worker-router-entrypoint
cargo check --manifest-path crates/router-ab-cloudflare/Cargo.toml --features strict-worker-signer-a-entrypoint
cargo check --manifest-path crates/router-ab-cloudflare/Cargo.toml --features strict-worker-signer-b-entrypoint
cargo check --manifest-path crates/router-ab-cloudflare/Cargo.toml --features strict-worker-signing-worker-entrypoint
cargo test --manifest-path crates/router-ab-cloudflare/Cargo.toml --test source_guards
cargo test --manifest-path crates/router-ab-dev/Cargo.toml --test cloudflare_parity
cargo test --manifest-path crates/router-ab-dev/Cargo.toml --test local_worker_env
pnpm -C packages/shared-ts exec tsc -p tsconfig.json --noEmit
pnpm -C packages/sdk-server-ts exec tsc -p tsconfig.json --noEmit
pnpm -C packages/sdk-web -s type-check
pnpm -C tests exec playwright test tests/unit/routerAbNormalSigningSdk.guard.unit.test.ts tests/unit/router.routeDefinitions.unit.test.ts tests/unit/refactor80SwitchCase.guard.unit.test.ts --reporter=line
git diff --check
```

Run broader relayer or e2e tests only if the implementation touches route
handler behavior beyond path names and constant names.

## Phase 8: Cloudflare Module Slimming

This phase is paired with the route rename because both changes remove naming
and structural noise from the Router A/B Cloudflare surface. Keep the slimming
work scoped. Do not collapse domain-state structs or protocol request/response
constructors unless the simplification makes invalid states harder to express.

### Best Cuts

- [x] [signing_worker/mod.rs](../crates/router-ab-cloudflare/src/signing_worker/mod.rs):
      14 manual `Debug` impl blocks print every field. Add `Debug` to derives
      and delete the impls. Expected reduction: about 120 lines.
- [x] [paths.rs](../crates/router-ab-cloudflare/src/paths.rs): 14 service URL
      functions repeat the same role check, internal host, and path pattern.
      Use one helper for signer-peer URLs and one helper for SigningWorker URLs.
      Expected reduction: about 160 lines.
- [x] [strict_worker/router.rs](../crates/router-ab-cloudflare/src/strict_worker/router.rs):
      route branches repeatedly read the body, parse JSON, build bearer
      credentials, call a handler, and wrap a CORS response. Add small boundary
      helpers such as `read_body`, `parse_json_body`, `json_cors_response`, and
      `bearer_credential`. Expected reduction: about 180 to 260 lines.
- [x] [strict_worker/signing_worker.rs](../crates/router-ab-cloudflare/src/strict_worker/signing_worker.rs):
      seven branches repeat `cloudflare_now_unix_ms_v1()` and handler
      construction. Pull `now_unix_ms` once for timed routes and switch on
      `request.path()`. Expected reduction: about 50 lines.
- [x] [strict_worker/cors.rs](../crates/router-ab-cloudflare/src/strict_worker/cors.rs):
      public-keyset CORS and normal-signing CORS are nearly the same function
      with different config/defaults. Use one `apply_cors(config)` helper.
      Expected reduction: about 40 lines.
- [x] [encoding.rs](../crates/router-ab-cloudflare/src/encoding.rs): fixed
      32/33/64-byte decoders repeat the same body. Use a const-generic
      `decode_base64url_fixed<const N: usize>` helper. Expected reduction:
      about 20 lines.
- [x] [hpke.rs](../crates/router-ab-cloudflare/src/hpke.rs): signer-envelope
      and server-output HPKE secret encode/decode helpers are prefix variants
      of the same operation. Share the prefix-aware helper. Expected reduction:
      about 35 lines.
- [x] [lib.rs](../crates/router-ab-cloudflare/src/lib.rs) and
      [durable_object/mod.rs](../crates/router-ab-cloudflare/src/durable_object/mod.rs):
      duplicated validation helpers should move to a tiny `validation.rs`.
      Expected reduction: about 35 lines.

### Bigger Cuts

- [x] [durable_object/handlers.rs](../crates/router-ab-cloudflare/src/durable_object/handlers.rs)
      and [durable_object/worker_storage.rs](../crates/router-ab-cloudflare/src/durable_object/worker_storage.rs):
      the Durable Object state machine exists twice, once for typed memory
      storage and once for real Worker storage. Start with smaller shared
      helpers for:
  - [x] idempotent put;
  - [x] take plus lookup validation;
  - [x] cleanup expired;
  - [x] wallet-budget record lookup and mutation setup.

      Avoid a full async storage abstraction in the first pass. Expected
      reduction: about 300 to 700 lines without destabilizing the crate.
- [x] [strict_worker/deriver.rs](../crates/router-ab-cloudflare/src/strict_worker/deriver.rs):
      registration/export/recovery/refresh branches repeat parse, role
      validation, preload, root metadata, and decrypt handler setup. Use the
      existing preload/root-metadata helpers to thin the four branch bodies.
      Expected reduction: about 120 lines.

### Mostly Keep

- [x] [auth.rs](../crates/router-ab-cloudflare/src/auth.rs): lean enough. Keep
      the constant-time compare because this is a security boundary.
- [x] [env.rs](../crates/router-ab-cloudflare/src/env.rs): forbidden env lists
      are ugly, but security-sensitive. Simplify only after adding table-driven
      tests for every role's allowed and forbidden bindings.
- [x] [router/mod.rs](../crates/router-ab-cloudflare/src/router/mod.rs): many
      admission-candidate shapes repeat, but they model domain state. Do not
      collapse aggressively right after Refactors 79 and 80. Use small
      validation helpers only.
- [x] [durable_object/mod.rs](../crates/router-ab-cloudflare/src/durable_object/mod.rs):
      large, but much of it is protocol surface. Split further by domain later.
      Do not macro away request/response constructors unless tests stay strong.

Recommended first implementation batch:

- [x] Debug derives;
- [x] fixed decoder helper;
- [x] HPKE secret helper;
- [x] CORS helper;
- [x] SigningWorker route `match`.

This first batch is low risk and should provide useful line reduction before
touching Durable Object behavior.

## Non-Goals

- Do not rename canonical protocol structs just because they have `V1` or `V2`.
- Do not regenerate wire vectors for a route-only rename.
- Do not add backward-compatible route aliases.
- Do not change storage schemas unless a route name is persisted as an
  authority key.
- Do not collapse protocol versions into route names.

## Completion Criteria

- [x] Active public routes use `/router-ab/...`.
- [x] Active private worker routes use `/router-ab/...`.
- [x] Active Durable Object routes use `/router-ab/do/...`.
- [x] No active route constant has a `V1` or `V2` suffix.
- [x] Source guards distinguish route naming from protocol version naming.
- [x] Targeted Rust, TypeScript, and Playwright checks pass.

## Implementation Notes

- Completed on June 26, 2026.
- Route rename covered Cloudflare, local-dev, shared TypeScript route constants,
  SDK server/web callers, tests, route guards, and active docs.
- First slimming batch completed: Debug derives, service URL helpers, fixed-size
  base64url decoder helper, shared CORS helper, HPKE secret helper,
  SigningWorker route `match`, and shared validation helpers.
- Final slimming batch completed: strict Router body/parse/credential/CORS
  response helpers, strict Deriver parse/preload/root-metadata helpers, and
  Durable Object idempotent-put/take/cleanup/wallet-budget helpers for both
  typed memory storage and real Worker storage.
- LOC snapshot for `crates/router-ab-cloudflare/src`, measured against `HEAD`
  and including untracked split modules: before 30,988 lines; after 30,838
  lines; net -150. The final slimming batch removed 192 lines from the interim
  31,030-line snapshot after the modular split.
- Validation passed on June 26, 2026:
  - `cargo check --manifest-path crates/router-ab-cloudflare/Cargo.toml`
  - `cargo check --manifest-path crates/router-ab-cloudflare/Cargo.toml --features strict-worker-router-entrypoint`
  - `cargo check --manifest-path crates/router-ab-cloudflare/Cargo.toml --features strict-worker-signer-a-entrypoint`
  - `cargo check --manifest-path crates/router-ab-cloudflare/Cargo.toml --features strict-worker-signer-b-entrypoint`
  - `cargo check --manifest-path crates/router-ab-cloudflare/Cargo.toml --features strict-worker-signing-worker-entrypoint`
  - `cargo test --manifest-path crates/router-ab-cloudflare/Cargo.toml --lib`
  - `cargo test --manifest-path crates/router-ab-cloudflare/Cargo.toml --test source_guards`
  - `cargo test --manifest-path crates/router-ab-dev/Cargo.toml --test cloudflare_parity`
  - `cargo test --manifest-path crates/router-ab-dev/Cargo.toml --test local_worker_env`
  - `cargo test --manifest-path crates/router-ab-dev/Cargo.toml --test local_worker_http`
  - `pnpm -C packages/shared-ts exec tsc -p tsconfig.json --noEmit`
  - `pnpm -C packages/sdk-server-ts exec tsc -p tsconfig.json --noEmit`
  - `pnpm -C packages/sdk-web -s type-check`
  - `pnpm -C tests exec playwright test tests/unit/routerAbNormalSigningSdk.guard.unit.test.ts tests/unit/router.routeDefinitions.unit.test.ts tests/unit/refactor80SwitchCase.guard.unit.test.ts --reporter=line`
  - `git diff --check`
