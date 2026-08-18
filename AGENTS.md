# seams-sdk — agent instructions

Single instruction file for all coding agents: Codex reads it natively; Claude Code
injects it via the SessionStart hook in `.claude/settings.json`. This repo deliberately
has no CLAUDE.md — do not create one. Keep this file lean: it is loaded into every
agent session. When working under `tests/`, also read `tests/AGENTS.md`.

## Repo shape (the non-obvious parts)

- Monorepo: Rust crates in `crates/`, TypeScript in `packages/` + `apps/`, wasm signers in `wasm/`.
- ALL TypeScript tests live in the top-level `tests/` workspace (`tests/unit/`,
  `tests/e2e/`, `tests/relayer/`, `tests/wallet-iframe/`, ...) — never co-located with
  sources in `packages/*`.
- Rust tests are per-crate under `crates/*/tests/`.

## Custody vocabulary (each term names exactly one thing)

`root` alone always names a secret derivation origin. The `Id`/`Version`/`Epoch`
suffixes name metadata *about* one, never key material — do not read `signingRootId`
as a key. A value whose name omits both is neither; check it before citing it in a
security claim.

- **wallet custody seed** — the one random secret per wallet. Every owner signing
  root derives from it in parallel; no signing root derives from another.
- **Ed25519 Yao Client root** / **ECDSA client root share** — the owner signing
  roots, seed-derived.
- **lane holder share** — per-lane material provisioned by Refactor 102, *not*
  seed-derived and never in a recovery set.
- **signingRootId / signingRootVersion** — identifiers inside the EVM-family key
  slot id, serialized in D1 rows and wire ids. Renaming them breaks stored records.
- **RootShareEpoch** — an epoch marker for durable ECDSA material.
- **custody ceremony** — a flow that derives owner roots *and* verifies the key
  manifest: registration and recovery re-establishment. These live in the
  `wallet_custody_ceremony` wasm module, which links both protocol crates.
  Adding a factor and unlocking are not ceremonies and stay in `near_signer`:
  opening an envelope authenticates the seed against its key manifest, so a
  reseal carries that claim forward without deriving anything.
- **two proofs, never one** — `VerifiedWalletKeyManifestDigestV1` says a seed
  was just proved to reproduce a key set (registration, recovery).
  `WalletCustodySeedFromSealedEnvelopeV1` says a seed came from an envelope
  authenticated to a wallet and manifest (factor addition). They are distinct
  types on purpose; do not add a conversion between them.
- **threshold** — the MPC protocol, never a KDF stage. A "threshold root" once
  existed as an Email OTP KDF intermediate; the collision caused a misdiagnosed
  vulnerability report, and the value has been deleted.

## Testing policy — read before "fixing" any failing test

Suites are not equally trustworthy, and each owns different invariants. Authority map,
with staleness risk under refactor:

1. **Intended-behaviour contracts** — own supported user-facing lifecycle behaviour
   (registration, unlock, signing, step-up, export).
   `tests/e2e/intended-behaviours/*.contract.test.ts`, run with `pnpm test:intended`.
   Spec: `docs/intended-behaviours.md` and the active `docs/refactor-NN-*.md`.
2. **Rust vector / anti-drift tests, and type fixtures** — vectors own explicit
   cryptographic, wire, and encoding invariants, self-validating against production
   encoders (e.g. `crates/router-ab-core/tests/normal_signing_vectors.rs`,
   `cargo yao-fv` checks); type fixtures (`tests/typecheck/*.typecheck.ts`) own
   compile-time constraints — invalid states must fail to compile.
3. **Unit tests built on shared factories** (`tests/unit/helpers/*.fixtures.ts`,
   `tests/helpers/`) — own focused component invariants: error paths, store semantics,
   edge cases the E2E suite never reaches. Low staleness risk; fixtures track the types.
4. **Unit tests with inline hand-written record literals, and source-guard scripts**
   (`tests/scripts/check-*.mjs`, `packages/wallet/scripts/checks/`) — highest staleness
   risk: they assert snapshots of past type shapes or source text and break on
   legitimate refactors.

Decision rules — classify before fixing:

- Before changing ANY code for a failing test, identify the invariant the test encodes,
  compare it against the current domain types (`packages/*/src`, `crates/*/src`) and the
  spec docs, and classify the failure as one of: `production_regression`,
  `valid_test_needs_update`, `obsolete_test_or_fixture`, or
  `environment_or_infrastructure_failure` (env-gated deps: Redis/Upstash, NEAR RPC,
  Safari, faucet). State the classification before repairing anything. Regression ⇒ fix
  the code. Obsolete ⇒ update the fixture through its shared factory, or delete
  tests/fixtures/mocks/helpers that encode retired behaviour — do not keep legacy code
  paths alive solely to keep a stale test green.
- Do not enter fixture-repair loops: after one failed repair attempt on a
  lower-authority test, stop and reassess whether the test is stale before changing
  anything else.
- Run the narrowest command that validates the change (a single test file beats a
  suite); run broad suites only for changes to shared behaviour, public APIs, schemas,
  persistence, auth, or crypto. Keep production fixes, valid test updates, and
  stale-test deletions in separate commits when practical.
- A green `pnpm test:intended` is evidence that a *lifecycle* claim is stale — it does
  not make every lower-tier failure stale. Vectors, type fixtures, and focused unit
  tests own invariants the E2E suite never exercises.
- Never change production behaviour solely to satisfy a stale inline fixture or source
  guard, and never widen or fork a domain type to make a hand-written fixture pass. A
  stale fixture's field shape is not documentation of the current schema.
- Never hand-edit generated fixtures or artifacts. Regenerate:
  - Router A/B normal-signing vectors:
    `UPDATE_ROUTER_AB_NORMAL_SIGNING_VECTORS=1 cargo test -p router-ab-core --test normal_signing_vectors`
  - Ed25519-Yao vectors/goldens: `cargo yao-fv all` (individual checks: `just ed25519-yao-fv-*`)
  - Rust→TS type bindings: `pnpm generate:signer-core-types`
  - Wallet-custody wire fixtures (Rust↔TS contract):
    `UPDATE_WALLET_CUSTODY_WIRE_FIXTURES=1 cargo test --test wire_fixtures` in
    `wasm/wallet_custody_ceremony` — regenerate only for an intended wire change on both sides
- An intentional behaviour change updates the spec doc and its contract test in the same
  change set.
- Complex domain-state records (session, auth/capability, signing, persistence) come
  only from the shared branch-specific factories — no inline `satisfies SomeRecord` /
  `: SomeRecord = {...}` literals for these. Simple value objects and request params may
  stay inline.
- If a source-guard script fails during a refactor, the guard itself may be stale: see
  `docs/refactor-88B-clean-source-guards.md` for whether to update or retire it. Do not
  contort correct code to satisfy an obsolete pattern, and prefer type fixtures, lint
  rules, or behavioural assertions over adding new source-text guards.

## Commands

- `pnpm test:intended` — authoritative lifecycle contracts (service prerequisites:
  `tests/README.md`)
- `pnpm test:unit` / `pnpm test:relayer` / `pnpm test:wallet-iframe` / `pnpm test:lit-components`
- `pnpm test:source-guards` — the source-guard chain
- `pnpm check` — lint + type-check + Rust lint + architecture boundary checks
- Rust: `cargo test -p <crate>`; formal verification: `pnpm check:formal-verification`
- Full suite documentation: `tests/README.md`
