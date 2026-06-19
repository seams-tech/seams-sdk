# Refactor 71: Wallet Session ID Naming Cleanup

Date created: June 17, 2026

Status: implementation-ready plan.

Primary source of truth:

- [refactor-68-wallet-session-v2.md](./refactor-68-wallet-session-v2.md)
- [router-a-b-single-session.md](./router-a-b-single-session.md)
- [router-A-B-signer-SPEC.md](./router-A-B-signer-SPEC.md)
- [router-a-b-cleanup.md](./router-a-b-cleanup.md)

## Goal

Make wallet-session and threshold-session identifiers readable at call sites
without collapsing separate authorization boundaries.

The current names make two different concepts look interchangeable:

```text
sessionId
walletSigningSessionId
```

The target names are:

```text
thresholdSessionId
signingGrantId
```

The refactor should make this distinction obvious everywhere:

- `thresholdSessionId` identifies the concrete threshold/MPC protocol session.
- `signingGrantId` identifies the user-approved signing allowance that carries
  TTL, remaining-use, and replay/idempotency budget.

## Non-Goals

- Do not merge the threshold session and signing grant into one id.
- Do not remove `walletId`, `rpId`, or `relayerKeyId`.
- Preserve app-session cookie support. Router A/B signing-capable Wallet
  Sessions use bearer JWT only.
- Do not add long-lived compatibility aliases in core logic.
- Do not change cryptographic protocol state, signer sets, budget semantics, or
  replay behavior.

## Naming Decisions

| Current name | New name | Meaning |
| --- | --- | --- |
| `sessionId` | `thresholdSessionId` | Concrete threshold/MPC session record and lifecycle state. |
| `walletSigningSessionId` | `signingGrantId` | User-approved signing allowance spent by threshold sessions. |
| `walletId` | `walletId` | Wallet/account resource being controlled. |
| `rpId` | `rpId` | WebAuthn relying-party boundary. |
| `relayerKeyId` | `relayerKeyId` | Relayer/server signing key identity. |

Avoid `walletSessionId` for either renamed field. The project already uses
Wallet Session as the client-facing credential concept, and `walletSessionId`
would blur the credential, threshold session, and signing grant layers.

Avoid `budgetId` as the primary public name. Budget is one enforcement property
of the grant. `signingGrantId` describes the authority the user approved.

## Target Domain Model

Boundary parsers should normalize raw request, JWT, worker, and persisted shapes
into precise internal objects:

```ts
type VerifiedWalletSession = {
  kind: 'verified_wallet_session';
  walletId: WalletId;
  thresholdSessionId: ThresholdSessionId;
  signingGrantId: SigningGrantId;
  rpId: RpId;
  relayerKeyId: RelayerKeyId;
  participantIds: readonly [number, number, ...number[]];
  expiresAtMs: number;
};
```

Core functions should accept this narrow object when they need wallet-session
authority. They should not accept loose `sessionId`, `walletSigningSessionId`,
`walletId`, `rpId`, and `relayerKeyId` strings independently unless the function
is itself a boundary parser or record builder.

## Current Behavior To Preserve

The existing server binds spendable budget by deriving a budget record from:

```text
walletSigningSessionId + curve + thresholdSessionId
```

After this refactor the same binding becomes:

```text
signingGrantId + curve + thresholdSessionId
```

The following rejection behavior must stay intact:

- a threshold session cannot spend a grant created for another threshold session
- a grant cannot be reused with a different signer set
- a grant cannot be reused across RP boundaries
- a grant cannot be reused across relayer key identities
- an old threshold-session JWT cannot refill exhausted signing budget
- cross-curve budget spending remains explicitly bound
- JWT `sub` and `walletId` must still match for threshold-session tokens

## Compatibility Rule

This is a breaking internal and SDK naming cleanup. Prefer direct renames.

Compatibility code is allowed only at persistence and request boundaries:

- persisted records may parse old fields into the new internal fields
- public request parsers may accept old field names only when the route version is
  still intentionally supported
- emitted responses, new records, core types, SDK types, and tests should use the
  new names only

Any old-field parser added during this refactor must have an explicit deletion
point in the same plan phase. Do not add helper paths that let old names leak
back into core logic.

## Route Version And Compatibility Decisions

Default policy: new active code emits only `thresholdSessionId` and
`signingGrantId`.

Route/version decisions before implementation:

- Router A/B signing-capable routes should be breaking and bearer-only. They
  should reject old threshold-session JWT claim shapes after the route boundary
  parser normalizes any intentionally supported transition input.
- Public request bodies that already carry a route version may accept old field
  names only in that route-version parser. The parser must immediately return a
  verified object with new names.
- New responses, SDK public types, new persisted records, and new docs must use
  new names only.
- IndexedDB and Durable Object readers may normalize old persisted field names
  during a bounded migration window. Writers must use new names only.
- Private SigningWorker routes should receive trusted normalized identity from
  the Router, not public Wallet Session claim parsing.

Temporary parser support must be documented with:

- exact route or storage record version
- old field names accepted
- normalized internal output type
- deletion phase
- tests proving old names do not leak past the boundary

## SessionId Allowlist

Plain `sessionId` remains valid only for identities that are not threshold/MPC
sessions.

Allowed `sessionId` meanings:

- app/browser auth session ids
- Email OTP worker session handles
- recovery execution sessions
- device-linking sessions
- request-correlation ids
- generic local map/store helper parameters when the helper is not
  threshold-session-specific
- third-party protocol fields that are explicitly named `sessionId`

Rename to `thresholdSessionId` when the value identifies:

- threshold-session JWT claims
- threshold/MPC route request or response fields
- Router A/B Wallet Session credentials
- threshold session policies
- threshold session store records
- signing budget status records
- Ed25519/ECDSA signing-session records
- threshold-specific test fixtures

Remove the field when it is an unused passthrough whose only purpose was to
carry an old threshold-session id through a derivation or worker boundary.

## Phase 1: Inventory And Ownership

- [ ] Inventory all `sessionId` usages in wallet-session, threshold-session,
      Router A/B, SDK, tests, docs, and fixtures.
- [ ] Classify each `sessionId` as one of:
      `thresholdSessionId`, app/browser session id, request id, ceremony id, or
      unrelated local variable.
- [ ] Inventory all `walletSigningSessionId` usages.
- [ ] Identify persisted field owners:
      `SessionStore`, `WalletSessionStore`, Cloudflare Durable Object records,
      sealed-refresh records, IndexedDB records, test fixtures, and docs.
- [ ] Identify public request/response contracts that currently expose
      `sessionId` or `walletSigningSessionId`.
- [ ] Decide whether each public wire contract receives a route/protocol version
      bump or a temporary request-boundary parser for old names.

## Phase 2: Add Branded Domain IDs

- [ ] Add `ThresholdSessionId` and `SigningGrantId` branded string types in the
      shared/server domain layer that already owns session-token parsing.
- [ ] Add boundary parsers:
      `parseThresholdSessionId(...)` and `parseSigningGrantId(...)`.
- [ ] Add builders for wallet-session claims and verified wallet-session objects.
- [ ] Replace broad object spreads in wallet-session claim construction with
      branch-specific builders.
- [ ] Add type fixtures rejecting raw strings where a verified wallet-session
      object is required.

## Phase 3: Rename Server Claims And Records

- [ ] Rename threshold-session JWT claim fields:
      `sessionId -> thresholdSessionId` and
      `walletSigningSessionId -> signingGrantId`.
- [ ] Update `parseThresholdEd25519SessionClaims` and
      `parseThresholdEcdsaSessionClaims` to return only new internal fields.
- [ ] Keep old claim field parsing only at the JWT boundary if existing route
      versions require it, then immediately normalize to the new internal type.
- [ ] Version Router A/B Wallet Session claims so signing-capable routes reject
      old threshold-session JWTs that lack Router A/B binding.
- [ ] Bind Router A/B Wallet Session claims to the SigningWorker identity,
      runtime scope, curve-specific public identity, and activation/keyset
      context required by the route.
- [ ] Update `signWalletSessionJwt` so newly minted tokens emit only
      `thresholdSessionId` and `signingGrantId`.
- [ ] Update server-side wallet budget binding to derive from
      `signingGrantId + curve + thresholdSessionId`.
- [ ] Update ECDSA and Ed25519 threshold session stores and record parsers.
- [ ] Update route handlers to consume a verified wallet-session object instead
      of independent loose strings.
- [ ] Reject `sessionKind: "cookie"` on Router A/B signing-capable issuance,
      bootstrap, HSS, key-identity, export, and normal-signing routes.

## Phase 4: Rename SDK And Browser Surfaces

- [ ] Rename SDK public result fields:
      `sessionId -> thresholdSessionId` and
      `walletSigningSessionId -> signingGrantId` where they refer to Wallet
      Session signing authority.
- [ ] Update sealed-refresh and warm-session persistence readers to normalize old
      records at the storage boundary.
- [ ] Update IndexedDB writers to persist new field names only.
- [ ] Update `walletSessionJwt` claim readers to expose the new names.
- [ ] Update Router A/B normal-signing request builders and status readers.
- [ ] Add source guards preventing `walletSigningSessionId` from returning in SDK
      public types after the refactor.

## Phase 5: Router A/B Cloudflare And Rust Contracts

- [ ] Rename strict Router verified Wallet Session fields where they represent
      threshold signing authority.
- [ ] Update normal-signing prepare/finalize admission candidates.
- [ ] Update ECDSA-HSS signing prepare/finalize request validation.
- [ ] Update Durable Object schemas only through explicit boundary parsers or
      versioned records.
- [ ] Keep private SigningWorker routes free of public Wallet Session parsing.
- [ ] Add Rust source guards proving public Router routes verify Wallet Session
      credentials before deriving trusted admission.

## Phase 6: Tests, Fixtures, And Docs

- [ ] Delete fixtures that encode old names as intended current behavior.
- [ ] Update tests that still verify valid behavior under the new names.
- [ ] Add targeted negative tests for:
      threshold session mismatch, signing grant mismatch, RP mismatch, relayer key
      mismatch, signer-set mismatch, and cross-curve grant reuse.
- [ ] Add TypeScript `@ts-expect-error` fixtures for invalid claim combinations.
- [ ] Update docs to describe the five trust axes with the new pair:
      `thresholdSessionId` and `signingGrantId`.
- [ ] Update examples and README snippets so no newly documented surface emits
      `walletSigningSessionId`.

## Phase 7: Cleanup

- [ ] Remove temporary parser support for old request fields after route/version
      cutover.
- [ ] Remove old helper names, type aliases, and test helpers.
- [ ] Remove docs references that present `sessionId` as the threshold session id.
- [ ] Run source guards for old names:
      `walletSigningSessionId`, `thresholdSessionAuthToken`, and ambiguous
      wallet-session `sessionId` public surfaces.
- [ ] Keep unrelated app-session, request-session, and browser-session names
      unchanged where `sessionId` is the correct local term.

## Validation Plan

Run the cheapest checks that cover the affected layer while implementing each
phase:

```sh
rtk rg "walletSigningSessionId|thresholdSessionId|signingGrantId"
rtk pnpm -C packages/sdk-server-ts type-check
rtk pnpm -C packages/sdk-web type-check
rtk pnpm -C tests test tests/unit/thresholdSessionClaims.unit.test.ts
rtk pnpm -C tests test tests/unit/sessionTokens.unit.test.ts
rtk pnpm -C tests test tests/unit/routerAbEd25519.walletSessionState.unit.test.ts
rtk pnpm -C tests test tests/unit/routerAbEcdsaHssNormalSigning.unit.test.ts
```

For Router A/B Rust changes:

```sh
rtk cargo test --manifest-path crates/router-ab-cloudflare/Cargo.toml --test source_guards
rtk cargo check --manifest-path crates/router-ab-cloudflare/Cargo.toml --features strict-worker-router-entrypoint
```

Run broader suites only when the rename crosses public route schemas,
persistence records, Cloudflare Durable Object schemas, or SDK public types.

## Phase Guard Expectations

After each implementation phase, add or update guards for the layer just
changed:

- Shared/domain phase: old branded type names and parsers cannot be imported by
  current code outside documented compatibility parsers.
- Server claim phase: new Wallet Session JWT issuers emit
  `thresholdSessionId` and `signingGrantId`; active signing routes do not read
  loose `sessionId` / `walletSigningSessionId` strings.
- Persistence phase: writers use new field names; readers normalize old names
  at the boundary; tests prove normalized records expose new internal fields.
- SDK public phase: exported public types and examples do not expose
  `walletSigningSessionId` for the signing grant.
- Worker/RPC phase: worker messages and route clients use new names unless the
  route version parser explicitly accepts old input.
- Cleanup phase: old names appear only in the allowlist, historical docs, or
  explicit compatibility-boundary tests.

## Acceptance Criteria

- Core wallet-session logic uses `thresholdSessionId` and `signingGrantId`.
- No core function requires callers to pass the five authority strings as an
  untyped bag.
- New JWTs, new persisted records, and new public SDK responses emit the new
  field names.
- Router A/B signing-capable routes reject cookie-mode session issuance and old
  threshold-session JWTs that lack SigningWorker / Router A/B binding.
- Old names appear only in intentionally supported request/persistence parsers or
  historical docs.
- Existing budget, expiry, signer-set, RP, relayer-key, and replay protections
  still have direct test coverage.
