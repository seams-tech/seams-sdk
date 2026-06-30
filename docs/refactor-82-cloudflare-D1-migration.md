# Cloudflare D1 Migration Plan

Date created: June 26, 2026
Updated: June 30, 2026

Status: execution checkpoint. Phases 1 through 5 are complete for the current
D1/DO staging scope. Phase 6 is the real staging deployment phase and has open
exit criteria. Phase 9 now tracks the ECDSA-HSS pool-fill Durable Object
ownership fix and is a staging blocker while ECDSA-HSS signing is enabled. This
plan moves the default Seams console and signer persistence path to Cloudflare D1
plus Durable Objects, while keeping a clean full-family Postgres escape hatch for
future scale or relational needs.

Refactor 82 is an execution plan, not a generic multi-database platform build.
The first deliverable is a D1/DO staging backend that can run sponsored gas,
prepaid billing, signer custody, dashboard reconciliation, local development,
tests, Time Travel bookmarks, and R2 restore drills without Docker Postgres.
Postgres stays as a typed escape-hatch contract until an explicit scale,
throughput, enterprise, or relational trigger requires implementation.

## Decision

Use Cloudflare D1 and Durable Objects as the first production backend family:

- D1 owns console tables, signer metadata, sealed signer ciphertext, billing
  records, sponsored gas records, reconciliation tables, and snapshot outbox
  tables.
- Durable Objects own signer coordination that needs per-entity serialized
  mutation or short-lived ceremony lifecycle ownership: registration
  ceremonies, session use counts, budget consumption, replay guards,
  presignature pools, ECDSA-HSS pool-fill live sessions, and signing-root
  coordination.
- Cloudflare Secrets Store is the hosted KEK source for signer share
  encryption. Wrangler secrets are allowed for local development. External KMS
  or HSM support is exposed through a narrow signer-only KEK provider adapter.
- Local development uses Wrangler/Miniflare D1 and local Durable Object storage
  by default.
- Postgres remains an adapter family behind the same domain-store ports. It is
  activated only as a complete backend family.

Key rule: no half-Postgres runtime. A tenant or deployment uses D1/DO for all
route-owned persistence, or Postgres for all route-owned persistence.

Authoritative Cloudflare references:

- [D1 local development](https://developers.cloudflare.com/d1/best-practices/local-development/)
- [D1 Worker binding API](https://developers.cloudflare.com/d1/worker-api/d1-database/)
- [D1 migrations](https://developers.cloudflare.com/d1/reference/migrations/)
- [D1 limits](https://developers.cloudflare.com/d1/platform/limits/)
- [D1 Time Travel](https://developers.cloudflare.com/d1/reference/time-travel/)
- [D1 data security](https://developers.cloudflare.com/d1/reference/data-security/)
- [Durable Object storage](https://developers.cloudflare.com/durable-objects/best-practices/access-durable-objects-storage/)
- [Durable Object rules](https://developers.cloudflare.com/durable-objects/best-practices/rules-of-durable-objects/)
- [Workers testing](https://developers.cloudflare.com/workers/testing/)
- [Hyperdrive Postgres connectivity](https://developers.cloudflare.com/hyperdrive/)

## Simplified Rule Set

- Build domain-store adapters, not a generic SQL compatibility layer.
- Implement D1/DO first.
- Keep Postgres as a documented full-family backend contract until a real
  trigger requires implementation.
- First staging uses static shared D1/DO route resolution. Dynamic tenant route
  registry, dedicated tenant D1 databases, and a live Postgres adapter are
  deferred.
- Keep Postgres work at the contract boundary for refactor 82: route union,
  domain-store ports, schema semantics, transaction semantics, migration
  playbook, and readiness bar.
- Resolve storage once per request from tenant identity.
- Pass domain stores into core logic. Core code never receives raw D1 bindings,
  Postgres clients, transaction handles, Durable Object stubs, or raw rows.
- Store JSON as `TEXT` in D1 and parse it at adapter boundaries.
- Validate request bodies, DB rows, Worker responses, and route records once at
  the boundary.
- Make invalid backend combinations unrepresentable with discriminated unions.
- Use atomic D1/SQLite writes for prepaid reservations and sponsored gas
  settlement.
- Stage on D1/DO from the start. There is no mixed staging mode.
- Cloudflare Worker-facing code imports D1/DO leaf modules directly. Mixed
  Postgres/D1 modules are allowed only on Node/Postgres paths.
- The shared sponsored execution recorder is D1-only for refactor 82 staging.
  A future Postgres implementation must enter through the full-family Postgres
  adapter contract, not through the Cloudflare D1 route path.
- Cloudflare cron helpers are D1-only for refactor 82 staging. Billing monthly
  finalization, runtime snapshot outbox dispatch, and webhook retry dispatch
  accept D1 bindings and call D1 runners directly.
- The Worker-facing `cloudflare-adaptor` barrel exports D1/DO adapters,
  Cloudflare route factories, and in-memory test helpers only. Postgres adapter
  exports stay on Node/Postgres entrypoints or direct module imports.

## Simplification Decisions

- First staging uses one shared `CONSOLE_DB`, one shared `SIGNER_DB`, one
  `THRESHOLD_STORE` Durable Object namespace, and one hosted signer KEK
  provider.
- Tenant route resolution is static for the first release. A persistent tenant
  route registry is deferred until the first dedicated D1 route or Postgres
  route is required.
- Dedicated tenant D1 databases are deferred. Shared D1 remains acceptable while
  storage, latency, and customer isolation triggers stay below the thresholds in
  this plan.
- The first staging environment starts empty on D1/DO or imports fixture data
  through D1/DO import tools. It does not run a live mixed Postgres/D1 request
  path.
- The Postgres adapter family is defined through ports, schema contracts,
  transaction semantics, and shared contract tests. A live implementation waits
  until a concrete scale or enterprise trigger appears.
- High-volume observability, cold archives, and bulky long-retention data go to
  R2, Analytics Engine, logs, or later warehouse storage. D1 keeps compact
  dashboard state and reconciliation records.
- Durable Objects are used where serialized mutation or short-lived signer
  ceremony ownership is the core property: registration ceremonies, signer
  budgets, replay guards, presignature pools, signing-session admission, and
  signing-root coordination.
- Cloudflare Secrets Store is the hosted signer KEK source. External KMS/HSM
  support stays behind the signer KEK provider interface.

## Phased First-Cut Plan

This ten-phase sequence is the authoritative execution path for refactor 82. The
remaining sections define the invariants and detailed ownership model for those
phases.

- [x] Phase 1: Inventory current Postgres coupling in `seams-console` and
      `seams-signer`.
- [x] Phase 2: Define D1 schemas and Durable Object ownership boundaries for the
      current staging baseline.
- [x] Phase 3 (closure): D1/DO adapters are implemented for the first staging
      scope; domain-store port proof, Durable Object contract coverage, and the
      high-risk D1 adapter matrix are recorded.
- [x] Phase 4 (closure): Wrangler/Miniflare D1 is the default local path and the
      full dashboard, signer, billing, sponsored EVM route-mount, and
      reconciliation workflow is proven without Docker Postgres.
- [x] Phase 5 (closure): staging-required D1/DO tests are migrated for the
      first-staging route surface; future signer auth-method coverage is deferred
      to future complete route slices.
- [ ] Phase 6 (staging deployment): apply staging D1 migrations, configure hosted
      signer KEKs, import fixtures, capture Time Travel bookmarks, and run staging
      smoke, reconciliation, signer route health, fixture-backed custody checks,
      and restore drills.
- [x] Phase 7: Delete legacy staging code, stale compatibility paths, temporary
      refactor scaffolding, and obsolete tests. This runs as a same-phase cleanup
      gate during implementation and now has a final tracked-plus-untracked count
      report with owners for the remaining positive blocks.
- [x] Phase 8: Replace hard-coded combined registration with a signer-set
      registration model. This removes the `ed25519_and_ecdsa` cross-product
      shape, makes D1 registration branch orchestration generic over requested
      signer capabilities, and splits the current D1 ceremony service by domain.
- [ ] Phase 9: Move `ThresholdEcdsaPresignSession` live ownership from the Router
      API Worker into a Durable Object. The Worker routes parse and authorize
      requests, while the DO owns the live WASM session across
      `/router-ab/ecdsa-hss/presignature-pool/fill/init` and `/fill/step`.
- [x] Phase 10: Move sponsored EVM spend pricing into Console D1. The schema,
      static-pricing adapter, D1 Router API pricing wiring, explicit setup seed,
      and Cloudflare D1 env-pricing guard are implemented; the full
      platform-admin pricing UI/API remains deferred.

Operating rule for Phases 3-10:

- [x] Each implementation phase includes a deletion pass before the phase is
      marked complete.
- [x] New D1/DO adapters replace the staging paths they supersede during the same
      phase unless a concrete staging blocker is recorded in the phase notes.
- [x] Compatibility code lives only at request and persistence boundaries, with a
      named deletion condition.
- [x] Source guards prevent old paths from returning and are reviewed for deletion
      once the D1/DO architecture is stable.
- [x] Phase completion records before/after line counts. Phase 7 records the final
      tracked-plus-untracked count and names owners for every remaining positive
      block.

Line-count cleanup baseline:

- [x] Checkpoint baseline recorded from
      `20af682856f1417abdab6ec39dc7793176d35bd0..HEAD`: 47,329 additions and
      4,358 deletions across all files.
- [x] Non-doc baseline recorded: 46,334 additions and 1,868 deletions after
      excluding docs and Markdown.
- [x] Docs/Markdown baseline recorded: 995 additions and 2,490 deletions.
- [x] Intent-allocation slice recorded before plan-doc update: 1,218 code
      additions and 236 code deletions across D1 Router API, shared intent parsing,
      `AuthService`, and unit tests. The same-phase deletion pass removed duplicate
      private signer-selection parsers and three disabled Cloudflare Router API bindings;
      the remaining positive delta is a Phase 7 cleanup target once the full
      ceremony path is proven.
- [x] Add-auth-method ceremony slice recorded before plan-doc update: 1,196 code
      additions and 2 code deletions across the D1 Router API auth service and unit
      tests. The same-slice deletion pass replaced the disabled D1 factory path for
      `startWalletAddAuthMethod` and `finalizeWalletAddAuthMethod`; the shared
      disabled-service scaffold still existed at that checkpoint and is now deleted
      in the final disabled-scaffold deletion pass below.
- [x] ECDSA add-signer start slice recorded before plan-doc update: 559 code
      additions and 1 code deletion across the D1 Router API auth service and unit
      tests. The same-slice deletion pass replaced the disabled D1 factory path for
      `startWalletAddSigner`; Ed25519 add-signer start/respond/finalize remained a
      named ceremony gap at that checkpoint, and the shared disabled-service
      scaffold is now deleted in the final disabled-scaffold deletion pass below.
- [x] ECDSA add-signer respond slice recorded before plan-doc update: 699 code
      additions and 0 code deletions across the D1 Router API auth service and unit
      tests. The same-slice deletion pass replaced the disabled D1 factory path for
      `respondWalletAddSignerHss`; ECDSA add-signer finalize and Ed25519
      add-signer start/respond/finalize remained named ceremony gaps at that
      checkpoint, and the shared disabled-service scaffold is now deleted in the
      final disabled-scaffold deletion pass below.
- [x] ECDSA add-signer finalize slice recorded before plan-doc update: 732 code
      additions and 320 code deletions across the D1 Router API auth service, D1 wallet
      store leaf, mixed wallet store, and unit tests. The same-slice deletion pass
      moved the D1 wallet store into a Worker-safe leaf module, deleted the old D1
      implementation from the mixed `WalletStore`, and replaced the disabled D1
      factory path for `finalizeWalletAddSigner`; Ed25519 add-signer
      start/respond/finalize remained a named ceremony gap at that checkpoint, and
      the shared disabled-service scaffold is now deleted in the final
      disabled-scaffold deletion pass below.
- [x] ECDSA wallet-registration start slice recorded before plan-doc update:
      682 code additions and 0 code deletions across the D1 Router API auth service and
      unit tests. The same-slice cleanup pass replaced the D1 factory fallback for
      `startWalletRegistration`; the shared disabled-service scaffold still existed
      as a blocker at that checkpoint and is now deleted in the final
      disabled-scaffold deletion pass below.
- [x] ECDSA wallet-registration respond slice recorded before plan-doc update:
      391 code additions and 0 code deletions across the D1 Router API auth service and
      unit tests. The same-slice cleanup pass replaced the D1 factory fallback for
      `respondWalletRegistrationHss`; the shared disabled-service scaffold still
      existed as a blocker at that checkpoint and is now deleted in the final
      disabled-scaffold deletion pass below.
- [x] ECDSA wallet-registration finalize slice recorded before plan-doc update:
      383 code additions and 0 code deletions across the D1 Router API auth service and
      unit tests. The same-slice cleanup pass replaced the D1 factory fallback for
      `finalizeWalletRegistration`; follow-up gaps moved into the replay and Email
      OTP enrollment finalize slices below, and the shared disabled-service
      scaffold still existed as a blocker at that checkpoint. It is now deleted in
      the final disabled-scaffold deletion pass below.
- [x] D1 wallet-registration finalize replay slice recorded before plan-doc
      update: 225 code additions and 7 code deletions across the D1 Router API auth
      service and unit tests. The same-slice cleanup pass deleted the explicit D1
      `finalizeWalletRegistration` idempotency-unsupported branch, added the D1
      Durable Object replay record parser, and covered replay after ceremony
      consumption; Email OTP enrollment-material persistence moved into the next
      completed slice.
- [x] D1 wallet-registration Email OTP enrollment finalize slice recorded before
      plan-doc update: 356 code additions and 7 code deletions across the D1 Router API
      auth service and unit tests. The same-slice cleanup pass deleted the explicit
      D1 `emailOtpEnrollment`/`emailOtpBackupAck` unsupported branch, requires
      enrollment material plus backup acknowledgement for Email OTP registration
      finalize, persists the wallet enrollment, recovery-wrapped enrollment escrows,
      and auth-state reset in D1, and verifies replay still works after ceremony
      consumption.
- [x] Cloudflare D1 signed-delegate scope cleanup slice recorded before
      plan-doc update: 39 code additions and 37 code deletions across the
      Cloudflare auth port, D1 service bundle, signed-delegate route typing,
      NEAR sponsorship adapter, and D1 console service tests. The same-slice
      cleanup pass deleted the D1 `signedDelegateRoute` bundle option, removed
      `executeSignedDelegate` from the D1 Cloudflare Router API auth port, removed the
      disabled D1 signed-delegate placeholder, and left NEAR signed delegates as an
      explicit opt-in route for non-D1 or future full-family adapter surfaces.
      Remaining disabled signer/recovery ceremony methods after this cleanup: 3.
- [x] Cloudflare D1 email-recovery scope cleanup slice recorded before
      plan-doc update: 145 code additions and 56 code deletions across the router-api
      route surface, Express and Cloudflare routers, Cloudflare email-recovery route
      typing, D1 smoke tests, and relayer tests. The same-slice cleanup pass made
      DKIM/TEE email recovery prepare, ECDSA respond, and ingress routes explicit
      opt-in routes, removed `prepareEmailRecovery` and `respondEmailRecoveryEcdsa`
      from the D1 Cloudflare Router API auth port, removed both disabled D1 placeholders,
      and proved the local D1 worker returns 404 for `/router-api/email-recovery/prepare`.
      Remaining disabled signer/recovery ceremony methods after this cleanup: 1.
- [x] Cloudflare D1 Ed25519 registration-prepare scope cleanup slice recorded
      before plan-doc update: raw Git count is 2,851 code additions and 2,752 code
      deletions because the already-present route-module move records
      `relayWalletRegistration.ts` as a delete plus `walletRegistrationRoutes.ts`
      as a new file. Rename-aware functional count is 127 additions and 28
      deletions across route-surface options, Express/Cloudflare route mounting, D1
      smoke tests, boundary fixtures, and Cloudflare auth-port cleanup. The
      same-slice cleanup pass made Ed25519 registration prepare explicit opt-in via
      `ed25519RegistrationPrepare: { authService }`. The later local-registration
      smoke pass reintroduced the D1 implementation for implicit NEAR account
      registration and changed the local D1 worker expectation from 404 to route
      validation. Sponsored named NEAR account creation remains a separate D1
      adapter task.
- [x] Cloudflare D1 Router API disabled-scaffold deletion pass recorded after all
      first-staging auth-port methods had concrete D1/DO implementations or explicit
      route-scope exclusions. The D1 factory now returns the concrete
      `CloudflareD1RouterApiAuthMetadataService` directly, TypeScript proves it
      satisfies `CloudflareRouterApiAuthService`, and
      `packages/sdk-server-ts/src/router/cloudflare/disabledRelayAuthService.ts`
      was deleted. Line count: `d1RouterApiAuthService.ts` dropped from 12,790 to
      12,722 lines and deleting `disabledRelayAuthService.ts` removed another 147
      lines, a net-negative 215-line cleanup.
- [x] Email OTP rate-limit D1 store split recorded: rate-limit SQL moved from
      `d1RouterApiAuthService.ts` into
      `packages/sdk-server-ts/src/router/cloudflare/d1EmailOtpRateLimitStore.ts`.
      The same-slice deletion pass removed the service-local
      `consumeEmailOtpRateLimit` and `consumeEmailOtpRateLimitKey` helpers, leaving
      the Router API service with orchestration-only calls to `emailOtpRateLimits`.
      Line count: `d1RouterApiAuthService.ts` dropped from 7,313 to 7,213 lines while
      `d1EmailOtpRateLimitStore.ts` added 122 lines, a +22-line split from the
      former local monolith shape.
- [x] Email OTP enrollment/auth-state D1 store split recorded: wallet-enrollment,
      auth-state, and canonical signer-wallet existence SQL moved from
      `d1RouterApiAuthService.ts` into
      `packages/sdk-server-ts/src/router/cloudflare/d1EmailOtpEnrollmentStore.ts`.
      The same-slice deletion pass removed the service-local
      `readEmailOtpWalletEnrollment`, `readEmailOtpWalletEnrollmentByProviderUserId`,
      `signerWalletExists`, `deleteEmailOtpWalletEnrollment`,
      `putEmailOtpWalletEnrollment`, `readEmailOtpAuthState`,
      `readEmailOtpAuthStateForEnrollment`, `putEmailOtpAuthStateForEnrollment`,
      `resetEmailOtpAuthStateForEnrollment`, and `resetEmailOtpFailureState`
      helpers. Line count: `d1RouterApiAuthService.ts` dropped from 7,213 to 6,970
      lines while `d1EmailOtpEnrollmentStore.ts` added 258 lines, a +15-line split
      from the former local monolith shape.
- [x] Email OTP recovery-escrow D1 store split recorded: recovery-wrapped
      enrollment escrow list/read/consume/upsert SQL moved from
      `d1RouterApiAuthService.ts` into
      `packages/sdk-server-ts/src/router/cloudflare/d1EmailOtpRecoveryEscrowStore.ts`.
      The same-slice deletion pass removed the service-local
      `listEmailOtpRecoveryEscrowsForEnrollment`, `readEmailOtpRecoveryEscrow`,
      `consumeEmailOtpRecoveryEscrow`, `putEmailOtpRecoveryEscrows`, and
      `putEmailOtpRecoveryEscrowStatement` helpers. Line count:
      `d1RouterApiAuthService.ts` dropped from 6,970 to 6,850 lines while
      `d1EmailOtpRecoveryEscrowStore.ts` added 165 lines, a +45-line split from
      the former local monolith shape.
- [x] Email OTP challenge/unlock D1 store split recorded: login/registration/device
      recovery challenge SQL and unlock-challenge SQL moved from
      `d1RouterApiAuthService.ts` into
      `packages/sdk-server-ts/src/router/cloudflare/d1EmailOtpChallengeStore.ts`.
      The same-slice deletion pass removed the service-local
      `pruneExpiredEmailOtpChallenges`, `readEmailOtpChallenge`,
      `findLatestActiveEmailOtpChallenge`, `countActiveEmailOtpChallenges`,
      `deleteOldestActiveEmailOtpChallenge`, `putEmailOtpChallenge`,
      `updateEmailOtpChallengeAttemptCount`, `putEmailOtpUnlockChallenge`, and
      `consumeEmailOtpUnlockChallenge` SQL helpers. The Router API service keeps only
      orchestration and now calls the D1 challenge store directly for pruning,
      active-limit overflow deletion, explicit challenge delete, challenge
      consume, and development outbox readback. The follow-up deletion pass removed
      the D1-only in-memory dev outbox Map, `readOutboxEntry`,
      `deleteOutboxEntry`, and the router-api `*AndOutbox` wrapper helpers. D1 local
      development uses `dev_d1_outbox`, and OTP readback is sourced from
      `signer_email_otp_challenges`. Current line count after the deletion pass:
      `d1RouterApiAuthService.ts` is 6,576 lines, `d1EmailOtpChallengeStore.ts` is
      319 lines, and `d1EmailOtpDeliveryRuntime.ts` is 61 lines.
- [x] NEAR public-key D1 store split recorded: tenant-scoped
      `signer_near_public_keys` listing moved from `d1RouterApiAuthService.ts` into
      `packages/sdk-server-ts/src/router/cloudflare/d1NearPublicKeyStore.ts`. The
      same-slice deletion pass removed the direct service-local NEAR public-key SQL
      from `listNearPublicKeysForUser`; the Router API service keeps only request
      validation and response projection. Line count: `d1RouterApiAuthService.ts`
      dropped from 6,596 to 6,586 lines while `d1NearPublicKeyStore.ts` added 36
      lines, a +26-line split from the former local monolith shape.
- [x] D1 identity store Worker-safe leaf split recorded: D1 identity-link and
      app-session-version persistence moved out of the mixed
      `core/IdentityStore.ts` module into
      `packages/sdk-server-ts/src/core/d1IdentityStore.ts`, and the Cloudflare D1
      router-api now imports that D1 leaf directly. The same-slice deletion pass removed
      the D1 schema/options/class/helpers from the mixed identity factory module;
      `core/IdentityStore.ts` is now 1,386 lines, `core/d1IdentityStore.ts` is
      634 lines, and `d1RouterApiAuthService.ts` is 6,587 lines. The Refactor 82
      runtime guard now walks dynamic `import()` calls so lazy Postgres imports
      cannot enter the Cloudflare runtime graph unnoticed.
- [x] Each remaining implementation commit either removes the staging path it
      supersedes or records the concrete blocker in this plan.
- [x] Phase 7 records the final before/after counts and explains any remaining
      positive non-doc line delta.

Definition of done for the first cut:

- [ ] Staging starts on D1/DO.
- [ ] No request path mixes D1/DO and Postgres.
- [ ] Sponsored EVM gas uses prepaid billing reservations and atomic D1
      settlement.
- [ ] Signer secrets are sealed before storage, with KEKs resolved through the
      signer-only KEK provider.
- [ ] The dashboard can reconcile sponsored gas, billing ledger evidence, runtime
      snapshots, and signer state from D1/DO.
- [ ] Local development uses Wrangler/Miniflare D1 and local Durable Object
      storage without Docker Postgres for staging-required flows.
- [ ] The Postgres escape hatch remains a documented full-family contract with
      a migration playbook and readiness bar.
- [ ] Legacy staging/runtime paths introduced or preserved during the migration
      are deleted, with a before/after line-count report.

Deferred until a concrete trigger:

- Live Postgres adapter implementation.
- Persistent tenant route registry.
- Dedicated tenant D1 databases.
- Threshold public-key metadata tables unless dashboard or reconciliation reads
  require them.
- Device linking, which remains refactor 84 scope while routes return 410.

## Current Baseline

Refactor 82 is a D1/DO-first staging migration. It does not add a dual-backend
runtime. The current codebase already has the important boundaries in place:

- `TenantStorageRoute` models D1/DO and Postgres as mutually exclusive backend
  families.
- Cloudflare Worker-facing routes use D1/DO leaf modules and are guarded by a
  runtime import scan that rejects Postgres storage, mixed console barrels, and
  the session-seal index barrel.
- Local Wrangler/Miniflare D1 is configured for `CONSOLE_DB`, `SIGNER_DB`, and
  `THRESHOLD_STORE`; `/readyz` verifies 40 console tables, 21 signer tables,
  and a Durable Object normal-signing admission operation.
- Console D1 adapters cover the first staging dashboard surface: org, project,
  environment, account/profile, team RBAC, policies, API keys, wallet index,
  approvals, key exports, audit, bootstrap tokens, billing, prepaid
  reservations, sponsorship spend caps, sponsored-call records, runtime
  snapshots, webhooks, compact observability, Stripe credit purchases, monthly
  usage statements, and billing finalization.
- Signer D1 adapters cover wallet metadata/auth methods, WebAuthn storage,
  identity links, app-session versions, recovery sessions/executions, NEAR
  public keys, email recovery preparations, Email OTP storage, Email OTP login
  challenge/grant/rate-limit flow, Email OTP device-recovery challenge/grant
  flow, Email OTP recovery-key consumption and failure-attempt reporting, Email
  OTP provider delivery, Email OTP registration enrollment verification, Email
  OTP unlock challenge/proof flow, and sealed signing-root secret shares.
- Cloudflare Router API auth service D1 methods cover recovery-session reads,
  recovery-session status transitions, recovery-execution upserts for the email
  recovery route, Email OTP device recovery, Email OTP recovery-key
  consumption, recovery-key failure reporting, recovery-code rotation, Email
  OTP provider delivery, Email OTP enrollment verification/persistence, wallet
  auth-method revocation, Email OTP add-auth-method start/finalize ceremonies,
  and generic OIDC JWT exchange. Email OTP server-seal apply/remove runs through
  the Worker-safe Shamir cipher boundary.
- Durable Objects cover registration ceremonies, signing admission, signing
  budgets, replay guards, ECDSA presignature pools, pool-fill CAS, and
  signing-root coordination where serialized mutation is the property. The D1
  Router API auth service constructs threshold signing through a Cloudflare
  Durable Object-only factory so Worker code does not import the mixed
  Postgres/Redis threshold factory.
- The signer KEK boundary supports Cloudflare Secrets Store, Wrangler secrets,
  and external KMS/HSM clients.

Remaining before D1 staging:

- Keep the first-staging Cloudflare Router API surface limited to implemented D1/DO
  methods. Future NEAR signed delegates, DKIM/TEE email recovery, Ed25519
  registration prepare, and device linking must land as complete
  route-plus-adapter slices.
- Keep device linking deferred to refactor 84 while the route returns 410.
- Keep threshold public-key metadata out of D1 unless a dashboard or
  reconciliation query requires it.
- Keep local Wrangler/Miniflare smoke coverage in sync with every required
  D1 table and Durable Object path.
- Add staging import, remote restore, Time Travel bookmark, and weekly R2 export
  drills. Local D1 backup/restore drill tooling is in place.
- Keep Postgres as a typed full-family escape hatch contract until a tenant or
  deployment actually needs it.

## Scope

### In Scope

- Console org, project, environment, RBAC, policy, approval, API key, wallet,
  settings, and audit storage.
- Production sponsored EVM gas payments with prepaid billing and dashboard
  reconciliation.
- Billing summaries, append-only ledger entries, reservations, settlement, and
  release flows.
- Runtime snapshot persistence and snapshot outbox dispatch.
- Signer metadata, wallet auth, WebAuthn, email OTP, sealed signer ciphertext,
  recovery records, identity indexes, and threshold public-key metadata only
  when dashboard or reconciliation reads require it.
- Signer coordination in Durable Objects.
- Local D1/DO development and D1 adapter tests.
- Future Postgres adapter contract, readiness bar, and D1-to-Postgres migration
  path.

### Out Of Scope For The First Cut

- A live Postgres adapter implementation.
- A tenant route registry database.
- Dedicated tenant D1 databases.
- Postgres RLS, advisory locks, partitions, JSONB operators, or row locks in
  core domain code.
- High-volume raw observability in D1.
- Storing plaintext signer shares, root shares, private keys, KEKs, or API
  secrets in D1, Durable Objects, R2 exports, or Postgres.

## Target Runtime Topology

First release topology:

- One shared `CONSOLE_DB` D1 database.
- One shared `SIGNER_DB` D1 database.
- One shared `THRESHOLD_STORE` Durable Object namespace.
- One signer KEK provider configured for hosted production.
- Local Wrangler/Miniflare bindings for the same D1/DO shape.

Wrangler shape:

```toml
[[d1_databases]]
binding = "CONSOLE_DB"
database_name = "seams-console"
database_id = "<remote-console-d1-database-id>"
preview_database_id = "seams-console-local"
migrations_dir = "migrations/d1-console"

[[d1_databases]]
binding = "SIGNER_DB"
database_name = "seams-signer"
database_id = "<remote-signer-d1-database-id>"
preview_database_id = "seams-signer-local"
migrations_dir = "migrations/d1-signer"

[[durable_objects.bindings]]
name = "THRESHOLD_STORE"
class_name = "ThresholdStoreDurableObject"

[[migrations]]
tag = "signer-do-v1"
new_sqlite_classes = ["ThresholdStoreDurableObject"]
```

Local commands:

```bash
pnpm --dir packages/sdk-server-ts run d1:local:prepare
pnpm --dir packages/sdk-server-ts run d1:local:dev
curl http://127.0.0.1:9090/readyz
curl http://127.0.0.1:9090/console/readyz
curl http://127.0.0.1:9090/router-api/healthz
```

The package scripts pin `wrangler.d1-local.toml` and
`.wrangler/state/seams-d1`, so local D1 and Durable Object state stays under
the SDK package and mirrors the production binding names: `CONSOLE_DB`,
`SIGNER_DB`, and `THRESHOLD_STORE`.

Inspection:

- Open local SQLite files under
  `packages/sdk-server-ts/.wrangler/state/seams-d1` in TablePlus with the
  SQLite driver.
- Treat TablePlus as read-only.
- Remote D1 has no TablePlus TCP endpoint. Use `wrangler d1 execute`,
  `wrangler d1 export`, Cloudflare dashboard tools, or a purpose-built admin
  route.

## Storage Route Type

The route type allows only two backend families:

```ts
type CloudflareD1DoTenantRoute = {
  kind: 'cloudflare_d1_do';
  namespace: NamespaceId;
  orgId: OrgId;
  routeVersion: RouteVersion;
  topology: 'shared' | 'dedicated_tenant';
  jurisdiction: TenantDataJurisdiction;
  console: ConsoleD1Target;
  signer: SignerD1DoTarget;
  postgres?: never;
};

type PostgresTenantRoute = {
  kind: 'postgres';
  namespace: NamespaceId;
  orgId: OrgId;
  routeVersion: RouteVersion;
  migrationReason: 'd1_size_limit' | 'd1_throughput_limit' | 'logical_database_required';
  console: ConsolePostgresTarget;
  signer: SignerPostgresTarget;
  cloudflare?: never;
};

type TenantStorageRoute = CloudflareD1DoTenantRoute | PostgresTenantRoute;
```

Rules:

- First release uses a static resolver that always returns
  `kind: 'cloudflare_d1_do'` with `topology: 'shared'`.
- The canonical route registry is deferred. Add a dedicated `TENANT_ROUTE_DB`
  only when the first dedicated D1 route or Postgres route is needed.
- Route registry rows, once introduced, are parsed at the request boundary into
  `TenantStorageRoute`.
- Route target combinations are checked at the type level and again when parsing
  untrusted registry rows.
- Route changes are versioned. Writes include the expected `routeVersion` and
  fail with `tenant_route_changed` when stale.

## Domain Store Ports

Core logic depends on these ports:

- `ConsoleTenantRecordStore`: org, project, environment, RBAC, policies,
  approvals, API keys, account settings, wallets, and audit events.
- `ConsoleBillingStore`: prepaid summaries, reservations, ledger entries,
  sponsored execution settlement, and reconciliation reads.
- `ConsoleRuntimeSnapshotStore`: snapshot writes, outbox enqueue, lease claim,
  dispatch acknowledgement, retry visibility, and dead-letter state.
- `SignerMetadataStore`: wallet auth, WebAuthn, email OTP, threshold key
  metadata, sealed share ciphertext, recovery records, and identity indexes.
- `SignerCoordinationStore`: signing-session counts, signing budgets, replay
  guards, presignature pools, pool-fill compare-and-swap, and signing-root
  coordination.
- `SigningRootKekResolver`: resolves KEK material from Cloudflare Secrets Store,
  Wrangler secrets, or external KMS/HSM clients.

Every port result is a narrow `Result`-style union. Idempotency conflicts,
insufficient balance, expired reservations, duplicate identity, exhausted
signing budget, corrupt persisted rows, missing custody authority, and stale
route versions are recoverable domain failures. Driver errors stay inside
adapters.

## Postgres Coupling Inventory

Current and former Postgres coupling is concentrated in:

- Former `packages/sdk-server-ts/src/console/**/postgres.ts` partial console
  adapters. These were deleted during Phase 7 because Refactor 82 keeps Postgres
  as a future full-family backend contract, not a live console-only backend.
- Former `packages/sdk-server-ts/src/console/shared/postgresTenantContext.ts`
  and `postgresNormalize.ts` shared helpers. These were deleted with the partial
  console Postgres adapters.
- Former `packages/sdk-server-ts/src/storage/postgres.ts` generic pool/read
  helper. This was deleted during Phase 7 so Postgres remains a typed future
  full-family route contract, not a partial public driver subpath.
- `packages/sdk-server-ts/src/core/**/*Store.ts`
- `packages/sdk-server-ts/src/core/ThresholdService/stores/*Store.ts`
- `packages/sdk-server-ts/src/router/routerAbNormalSigningAdmissionStore.ts`
- `packages/sdk-server-ts/src/threshold/session/signingSessionSeal/idempotencyBackends.ts`

### Console Table Ownership

| Area                           | Former Postgres tables / current D1 tables                                                                                                                                                                                                                                                                                                                                                        | Target owner                                                                       | Notes                                                                                                                                                                                                                                                                                                                                              |
| ------------------------------ | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Org/project/env                | Former `console_organizations`, `console_projects`, `console_environments`; current D1 `organizations`, `projects`, `environments`                                                                                                                                                                                                                                                                | `CONSOLE_DB` D1                                                                    | D1 adapter, append-only migration, local smoke coverage, and tenant-scoping contract test are in place.                                                                                                                                                                                                                                            |
| Account/profile                | Former `console_user_profiles`, `console_user_backup_emails`; current D1 `user_profiles`, `user_backup_emails`                                                                                                                                                                                                                                                                                    | `CONSOLE_DB` D1                                                                    | D1 adapter, append-only migration, local smoke coverage, and profile/organization contract test are in place.                                                                                                                                                                                                                                      |
| Team RBAC                      | Former `console_team_members`; current D1 `team_members`                                                                                                                                                                                                                                                                                                                                          | `CONSOLE_DB` D1                                                                    | D1 adapter, append-only migration, local smoke coverage, Cloudflare bundle wiring, and owner/member lifecycle contract test are in place. Add a `team_member_roles` side table only if indexed role lookup becomes necessary.                                                                                                                      |
| Approvals                      | Former `console_approvals`; current D1 `approvals`                                                                                                                                                                                                                                                                                                                                                | `CONSOLE_DB` D1                                                                    | D1 adapter, append-only migration, local smoke coverage, Cloudflare bundle wiring, tenant-scoping checks, MFA enforcement, duplicate-decision checks, and state-specific conditional transition tests are in place. Approval JSON is stored as `TEXT` and parsed at the adapter boundary.                                                          |
| Audit                          | Former `console_audit_events`, `console_audit_evidence`; current D1 `audit_events`, `audit_evidence`                                                                                                                                                                                                                                                                                              | `CONSOLE_DB` D1                                                                    | D1 adapter, append-only migration, local smoke coverage, Cloudflare bundle wiring, event/evidence filters, search, duplicate-id handling, and tenant-scoping contract test are in place. JSON is stored as `TEXT` and parsed at the adapter boundary.                                                                                              |
| Bootstrap tokens               | Former Postgres `console_bootstrap_tokens`; current D1 `bootstrap_tokens`                                                                                                                                                                                                                                                                                                                         | `CONSOLE_DB` D1                                                                    | D1 adapter, append-only migration, local smoke coverage, Cloudflare bundle wiring, tenant-scoped count/peek, and atomic conditional redemption contract test are in place.                                                                                                                                                                         |
| Policies                       | Former `console_policies`, `console_policy_versions`, `console_policy_assignments`; current D1 `policies`, `policy_versions`, `policy_assignments`                                                                                                                                                                                                                                                | `CONSOLE_DB` D1                                                                    | D1 adapter, append-only migration, local smoke coverage, Cloudflare bundle wiring, system-default uniqueness, publish-version history, and assignment-resolution contract test are in place. Policy JSON is stored as `TEXT`.                                                                                                                      |
| API keys                       | Former Postgres `console_api_keys`; current D1 `api_keys`                                                                                                                                                                                                                                                                                                                                         | `CONSOLE_DB` D1                                                                    | D1 adapter, append-only migration, local smoke coverage, Cloudflare bundle wiring, hashed lookup, secret-key auth, publishable-key auth, revoke/rotate/delete, anomaly flag, usage count, and tenant-scoping contract test are in place.                                                                                                           |
| Wallet index                   | Former `console_wallet_index`; current D1 `wallet_index`                                                                                                                                                                                                                                                                                                                                          | `CONSOLE_DB` D1                                                                    | D1 adapter, append-only migration, local smoke coverage, Cloudflare bundle wiring, tenant-scoped upsert/get/list/search, filter indexes, cursor pagination, and contract tests are in place. This is a queryable dashboard index only; signer ownership stays in `SIGNER_DB`/DO.                                                                   |
| Billing                        | Former `console_billing_*` and `console_invoice*` tables; current D1 `billing_accounts`, `billing_ledger_entries`, `billing_ledger_postings`, `billing_monthly_active_wallets`, `billing_credit_purchases`, `invoices`, `invoice_line_items`, `stripe_webhook_events`; later `usage_meter_events`, `usage_rollups_monthly` if per-event usage audit or rollup replay becomes necessary                 | `CONSOLE_DB` D1                                                                    | D1 billing account/ledger tables, Stripe credit purchases, receipt invoices, monthly usage statements, receipt/statement line items, webhook idempotency, monthly finalization runner, append-only migrations, local smoke coverage, Cloudflare bundle wiring, manual credit/debit support, and sponsored execution debit statements are in place. |
| Prepaid reservations           | Former `console_billing_prepaid_reservation_summaries`, `console_billing_prepaid_reservations`; current D1 `billing_prepaid_reservation_summaries`, `billing_prepaid_reservations`                                                                                                                                                                                                                 | `CONSOLE_DB` D1                                                                    | Trigger-backed D1 adapter, append-only migration, local smoke coverage, and contract tests are in place. Summary mutation and reservation lifecycle transitions remain SQLite-atomic.                                                                                                                                                              |
| Sponsored calls                | Former `console_sponsored_call_records`; current D1 `sponsored_call_records`                                                                                                                                                                                                                                                                                                                       | `CONSOLE_DB` D1                                                                    | D1 adapter, append-only migration, local smoke coverage, Cloudflare bundle wiring, idempotency test, and atomic sponsored gas settlement contract test are in place.                                                                                                                                                                               |
| Sponsorship spend caps         | Former `console_sponsorship_spend_cap_windows`, `console_sponsorship_spend_cap_reservations`; current D1 `sponsorship_spend_cap_windows`, `sponsorship_spend_cap_reservations`                                                                                                                                                                                                                    | `CONSOLE_DB` D1                                                                    | Trigger-backed D1 adapter, append-only migration, local smoke coverage, Cloudflare bundle wiring, source-event idempotency, tenant-scoped usage lookup, and reservation/settlement/release contract tests are in place. Window usage mutation stays SQLite-atomic inside reservation insert and lifecycle transition triggers.                     |
| Key exports                    | Former `console_key_exports`; current D1 `key_exports`                                                                                                                                                                                                                                                                                                                                            | `CONSOLE_DB` D1                                                                    | D1 adapter, append-only migration, local smoke coverage, Cloudflare bundle wiring, tenant-scoped list/create/approve, MFA enforcement, duplicate-approver checks, approval threshold transitions, and conditional approval update tests are in place. Approval and constraint JSON is stored as `TEXT` and parsed at the adapter boundary.         |
| Runtime snapshots              | Former `console_runtime_snapshots`, `console_runtime_snapshot_outbox`; current D1 `runtime_snapshots`, `runtime_snapshot_outbox`                                                                                                                                                                                                                                                                   | `CONSOLE_DB` D1                                                                    | D1 adapter, append-only migration, local smoke coverage, Cloudflare bundle wiring, snapshot upsert/get/list, claim-lease outbox dispatch, and lease-race contract test are in place.                                                                                                                                                               |
| Webhooks                       | Former `console_webhook_*` tables; current D1 `webhook_endpoints`, `webhook_endpoint_categories`, `webhook_deliveries`, `webhook_attempts`, `webhook_dead_letters`                                                                                                                                                                                                                               | `CONSOLE_DB` D1 plus webhook secret cipher                                         | D1 route-service adapter, retry-dispatch runner, append-only migrations, local smoke coverage, optional Cloudflare bundle wiring, endpoint CRUD, category side-table lookup, event dispatch, delivery/attempt/dead-letter pages, replay resolution, retry claim leases, and sealed signing-secret tests are in place.                              |
| Key export and webhook secrets | Former `console_key_exports` and `console_webhook_endpoints.signing_secret`; current D1 `key_exports` and `webhook_endpoints.signing_secret_ciphertext_b64u`                                                                                                                                                                                                                                      | `CONSOLE_DB` D1 plus secrets adapter                                               | Key exports store approval/constraint JSON only. Webhook D1 rows store sealed signing-secret ciphertext, KEK ID, and envelope version. Plaintext webhook signing secrets stay in process memory only during endpoint creation and request signing.                                                                                                 |
| Observability                  | Former `console_observability_*` tables; current D1 `observability_events`, `observability_event_dedup`, `observability_ingest_windows`, `observability_request_rollups_minute`                                                                                                                                                                                                                   | `CONSOLE_DB` D1 for compact dashboard state; R2/Analytics Engine for raw telemetry | D1 compact adapter, append-only migration, local smoke coverage, Cloudflare bundle wiring, incident-event dedupe/redaction, request-rollup ingestion, summary/event/timeseries/service reads, and tenant-scoping tests are in place. High-volume raw telemetry stays outside D1.                                                                   |

### Signer Table Ownership

| Area                               | Current Postgres tables                                                                                                                                                                                                                                | Target owner                                                | Notes                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                   |
| ---------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | ----------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| WebAuthn                           | `webauthn_authenticators`, `webauthn_credential_bindings`, `webauthn_challenges`                                                                                                                                                                       | `SIGNER_DB` D1                                              | D1 authenticator, credential-binding, login-challenge, and sync-challenge adapters, append-only migration, explicit `kind: 'd1'` factory selectors, local smoke coverage, tenant-scoping tests, and atomic challenge consumption tests are in place. Tenant/project/env scope is required.                                                                                                                                                                                                                                                                                                                                              |
| Registration                       | `wallet_registration_intents`, `wallet_registration_ceremonies`                                                                                                                                                                                        | Durable Object                                              | Already implemented through `CloudflareDurableObjectRegistrationCeremonyStore` with tests for one-time grant, preparation, ceremony, and finalize replay consumption. Keep these records out of D1 because they are short-lived ceremony coordination state, not dashboard-queryable metadata.                                                                                                                                                                                                                                                                                                                                          |
| Wallet metadata                    | `wallets`, `wallet_auth_methods`, `wallet_signers`                                                                                                                                                                                                     | `SIGNER_DB` D1                                              | D1 wallet and wallet-auth-method adapters, append-only migration, explicit `kind: 'd1'` factory selectors, tenant/project/env-scoped options, local smoke coverage, and tenant-scoping contract tests are in place. Keep wallet ID, org, project, and env required on wallet rows; keep RP ID required only on passkey/WebAuthn auth-method rows; keep chain identity required on ECDSA signer rows.                                                                                                                                                                                                                                    |
| Email OTP                          | `email_otp_challenges`, `email_otp_grants`, `email_otp_wallet_enrollments`, `email_otp_recovery_wrapped_enrollment_escrows`, `email_otp_auth_states`, `email_otp_unlock_challenges`, `email_otp_registration_attempts`, `signer_email_otp_rate_limits` | `SIGNER_DB` D1                                              | D1 adapters, append-only migrations, local smoke coverage, explicit `kind: 'd1'` factory selectors, tenant-scoped adapter tests, provider delivery hook, one-time grant/unlock consumption, login challenge issue/verify/grant flow, device-recovery challenge issue/verify/grant flow, recovery-key consumption, recovery-key failure-attempt reporting without grant consumption, unlock challenge/proof flow, fixed-window rate limiting, registration-attempt scope disambiguation, and expiry deletion coverage are in place. Challenge/grant expiry stays adapter-owned. JSON is stored as `TEXT` with normalized lookup columns. |
| Threshold public-key metadata      | Future signer key index tables if dashboard lookup needs them                                                                                                                                                                                          | `SIGNER_DB` D1                                              | Store public identifiers only: wallet ID, auth method, RP ID, signing-root ID/version, public key, chain address, status, and audit timestamps. The former `threshold_ed25519_keys` and `threshold_ecdsa_keys` Postgres key-store paths contained relayer signing shares, so they were deleted from the active Postgres bootstrap and cannot be used as D1 metadata substitutes.                                                                                                                                                                                                                                                        |
| Legacy threshold key-store records | Former Postgres tables `threshold_ed25519_keys`, `threshold_ecdsa_keys`                                                                                                                                                                                | Durable Object or retired behind sealed signing-root shares | These records are secret-bearing under the current TypeScript interfaces. The partial Postgres key-store backend has been deleted; production D1/DO staging must use sealed signing-root share storage or the existing Durable Object path until raw-share records are retired. Do not add raw-share D1 tables.                                                                                                                                                                                                                                                                                                                         |
| Sealed signing-root shares         | Former Postgres table `signing_root_secret_shares`; current D1 table `signer_signing_root_secret_shares`                                                                                                                                               | `SIGNER_DB` D1                                              | D1 stores ciphertext, KEK ID, envelope version, AAD digest, ciphertext digest, and audit marker. The partial Postgres signing-root secret store has been deleted; a future Postgres escape hatch must implement the full signer-family contract before selection.                                                                                                                                                                                                                                                                                                                                                                       |
| Recovery/identity                  | `email_recovery_preparations`, `signer_near_public_keys`, `identity_links`, `app_session_versions`, `recovery_sessions`, `recovery_executions`                                                                                                         | `SIGNER_DB` D1                                              | D1 identity-link, app-session-version, recovery-session, recovery-execution, NEAR public key, and email recovery preparation adapters, append-only migrations, explicit `kind: 'd1'` factory selectors, local smoke coverage, tenant-scoping tests, sole-identity move/unlink tests, app-session rotation tests, recovery-session expiry reads, recovery-execution status query tests, NEAR public key list/upsert tests, and email recovery preparation expiry/delete tests are in place.                                                                                                                                              |
| Device linking                     | `device_linking_sessions`                                                                                                                                                                                                                              | Future complete route slice                                 | Current route handlers return 410 and `AuthService` returns the unsupported result. Keep device linking out of refactor 82 staging scope until a future device-linking route slice re-enables the feature and defines its persistence contract. Refactor 84 is reserved for Ed25519 HSS payload trimming.                                                                                                                                                                                                                                                                                                                                 |
| Signing sessions                   | Former partial Postgres threshold session backends in `SessionStore.ts` and `WalletSessionStore.ts`; former table `threshold_ed25519_sessions`                                                                                                         | Durable Object                                              | Threshold session and wallet-session config types no longer expose `kind: "postgres"` or env-shaped `POSTGRES_URL`; raw explicit unknown store kinds fail at the store boundary. Session use counts and replay-sensitive mutation belong in DO methods. The old shared table bootstrap/reset references have been deleted.                                                                                                                                                                                                                                                                                                              |
| Budget and replay guards           | Former Postgres tables `threshold_wallet_session_consumptions`, `threshold_wallet_session_budget_reservations`, and `threshold_signing_session_seal_idempotency`                                                                                       | Durable Object                                              | The partial Postgres session-seal idempotency backend and wallet-session budget/replay backend have been deleted. Replace row locks and unique idempotency rows with DO methods that return the same result unions.                                                                                                                                                                                                                                                                                                                                                                                                                     |
| ECDSA presign                      | Former Postgres tables `threshold_ecdsa_presign_sessions`, `threshold_ecdsa_presignatures`                                                                                                                                                             | Durable Object                                              | The partial Postgres ECDSA presign backend has been deleted; threshold store config types no longer expose `kind: "postgres"` or env-shaped `POSTGRES_URL`. Active presign reservation and pool-fill coordination stays in Durable Objects, Redis, or in-memory test stores.                                                                                                                                                                                                                                                                                                                                                            |
| Normal signing admission           | Former Postgres tables `router_ab_normal_signing_quota_reservations`, `router_ab_normal_signing_project_policies`, `router_ab_normal_signing_abuse_records`                                                                                            | Durable Object                                              | The partial Postgres admission backend has been deleted from the public router facade and SDK exports. Quota reservation, project policy, and abuse decisions stay in `CloudflareDurableObjectRouterAbNormalSigningAdmissionStore`, with in-memory only for tests.                                                                                                                                                                                                                                                                                                                                                                      |

### Postgres Primitive Replacement Map

| Postgres primitive       | Current use                                                                                    | D1/DO replacement                                                                                                                      |
| ------------------------ | ---------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------- |
| Advisory migration locks | Schema setup in console and signer Postgres modules                                            | Wrangler D1 migrations plus serialized CI/deploy migration command. Runtime adapters do not take migration locks.                      |
| Row-level security       | Console tenant protection through Postgres policies                                            | Tenant route resolution plus required tenant columns in every primary key and query. Tests must prove cross-org reads and writes fail. |
| `JSONB` columns          | Policy payloads, webhook categories, audit evidence, signer records, session records           | Store JSON as `TEXT` and parse once at adapter boundaries. Add normalized side tables for indexed membership queries.                  |
| GIN indexes              | Webhook endpoint category lookup                                                               | `console_webhook_endpoint_categories` join table with `(namespace, org_id, category, endpoint_id)` index.                              |
| `FOR UPDATE`             | Billing, approvals, key exports, bootstrap tokens, spend caps, signer sessions, signer budgets | D1 conditional updates or Durable Object serialized methods. The target owner decides the primitive.                                   |
| `FOR UPDATE SKIP LOCKED` | Runtime snapshot outbox and ECDSA presignature reservation                                     | D1 claim leases for snapshot outbox; Durable Object reservation method for presignatures.                                              |
| Bigserial IDs            | Webhook attempts and similar append-only rows                                                  | Application-generated IDs or monotonic per-owner counters inside the owning Durable Object.                                            |
| Postgres partial indexes | Pending/unresolved and idempotency lookups                                                     | SQLite partial indexes where supported; otherwise explicit status columns in tenant-first indexes.                                     |

### Adapter Checklist

Before D1 staging, these D1/DO adapters must exist behind domain-store ports:

- [x] Console D1 remaining: none for the simplified first D1 staging scope.
- [x] Console D1 in place: org/project/env, account/profile, team RBAC, policies,
      wallet index, API keys, approvals, key exports, audit, bootstrap tokens,
      billing ledger sponsored settlement, prepaid reservations, sponsorship spend
      caps, sponsored calls, runtime snapshots, compact observability
      read/ingestion services, and the webhook route service.
- [x] Signer D1 remaining: none for the simplified first D1 staging scope.
      Threshold public-key metadata is deferred because the first-staging dashboard
      and reconciliation surface use wallet metadata, NEAR public-key metadata,
      signer rows, sealed shares, audit, billing, snapshots, and explicit ECDSA
      key-inventory diagnostics.
- [x] Signer D1 in place: WebAuthn, wallet metadata, wallet auth methods, identity
      links, app-session versions, recovery sessions, recovery executions, NEAR
      public keys, email recovery preparations, Email OTP login challenge/grant
      flow, Email OTP device-recovery challenge/grant flow, Email OTP recovery-key
      consumption, Email OTP recovery-key failure-attempt reporting, Email OTP
      provider delivery, Email OTP registration enrollment verification, Email OTP
      unlock challenge/proof flow, Email OTP rate limits, and sealed signing-root
      secret shares.
- [x] Durable Objects in place: registration intents, HSS preparations,
      registration ceremonies, add-signer/add-auth-method ceremonies, finalize
      replay records, signing-session use counts, wallet signing budgets,
      idempotency/replay guards, ECDSA presignature pools, ECDSA pool-fill
      sessions, normal-signing admission storage, and signing-root coordination.
- [x] Durable Objects remaining for staging: none for the simplified first D1
      staging scope. Local default wiring and contract coverage are recorded in the
      Phase 3 closure checks for signer admission, budget, replay, presignature,
      signing-root coordination, and session consumption.
- [x] Postgres escape hatch: refactor 82 keeps the route type, domain-store port
      contracts, schema semantics, transaction semantics, D1-to-Postgres migration
      playbook, and readiness bar in this document. Live Postgres migrations,
      adapters, and shared contract-test execution are required before any
      production tenant can select Postgres; they do not block first D1/DO staging.

## D1 Schema Rules

Every D1 table has explicit tenant columns. Console tables use
`(namespace, org_id, ...)`. Signer tables use the narrowest required identity,
usually `(namespace, org_id, project_id, env_id, ...)` for custody records and
wallet-specific keys for wallet auth records.

Baseline table shape:

```sql
CREATE TABLE projects (
  namespace TEXT NOT NULL,
  id TEXT NOT NULL,
  org_id TEXT NOT NULL,
  name TEXT NOT NULL,
  slug TEXT NOT NULL,
  status TEXT NOT NULL,
  created_at_ms INTEGER NOT NULL,
  updated_at_ms INTEGER NOT NULL,
  PRIMARY KEY (namespace, id)
);
```

D1 adapter rules:

- Bind `namespace` and `org_id` in every console query.
- Bind signer identity fields in every signer query.
- Keep indexes page-first and tenant-first.
- Keep row values under D1 row/blob/string limits.
- Keep raw observability and large archive data outside D1 from the start.
- Use `D1Database.batch()` or trigger-backed single statements for invariants
  that must roll back together.
- Cover every trigger-backed invariant with local SQLite and D1 integration
  tests.

## Atomic Billing Reservations

Billing reservations must be atomic in D1/SQLite. Double debit risk is
unacceptable.

Recommended D1 implementation:

- `billing_prepaid_reservation_summaries`
  - Primary key: `(namespace, org_id)`.
  - Tracks active reserved amount, active reservation count, and updated time.
- `billing_prepaid_reservations`
  - Primary key: `(namespace, org_id, reservation_id)`.
  - Unique idempotency/source key: `(namespace, org_id, source_event_id)`.
  - Stores amount, state, created time, expiry, settlement reference, and
    posted balance evidence.
- `billing_ledger_entries`
  - Append-only evidence for credits, reservations, settlement, release,
    expiry, and corrections.

Reserve operation:

1. Read the current billing account balance from `billing_accounts`.
2. Insert the reservation row with a unique source or idempotency key and the
   posted balance evidence.
3. In the same SQLite atomic unit, verify
   `reserved_minor + reserve_amount <= posted_balance_minor`.
4. Abort the insert with a domain error such as `prepaid_balance_insufficient`
   when funds are unavailable.
5. On duplicate source key, return the existing reservation result after parsing
   the stored row.

Implementation options:

- Preferred first cut: one `INSERT` guarded by SQLite triggers that create the
  summary row if needed, check balance, and mutate the summary atomically.
- Acceptable alternative: one `D1Database.batch()` with a conditional summary
  update and a reservation insert, with tests proving rollback and duplicate
  idempotency behavior.

Settle, release, and expire operations use state-specific conditional writes:

- `RESERVED -> SETTLED`
- `RESERVED -> RELEASED`
- `RESERVED -> EXPIRED`

Each transition updates the summary and writes ledger evidence in the same D1
atomic unit.

## Sponsored EVM Gas Payments

Simplified product scope:

- Production sponsored gas payments for EVM calls.
- Prepaid billing only.
- Dashboard reconciliation for sponsored executions, fee estimates, final fees,
  reservation IDs, ledger IDs, and settlement status.

Flow:

1. Authorize the API key and resolve tenant route.
2. Estimate sponsor cost and create a prepaid reservation.
3. Execute the EVM call.
4. Record the sponsored call result with an idempotency key.
5. Finalize settlement by atomically updating the sponsored call, reservation,
   billing summary, and ledger entry.
6. Reconcile dashboard views from sponsored call records plus billing ledger
   evidence.

D1 settlement invariant:

- A sponsored execution can settle only once.
- A reservation can settle only once.
- Sponsored-call records require an idempotency key.
- The ledger entry for settlement is unique by `(namespace, org_id, entry_type,
source_event_id)`, where `source_event_id` is derived from the reservation
  source event.
- Finalization runs as one D1 `D1Database.batch()` unit over the shared
  `CONSOLE_DB`: reservation lifecycle update, sponsored execution debit ledger
  insert, and sponsored-call record insert.

Recoverable states:

- `reserved`
- `executed_pending_settlement`
- `settled`
- `released`
- `failed_released`
- `reconciliation_required`

## Runtime Snapshot Outbox

Replace `FOR UPDATE SKIP LOCKED` with a D1 lease model.

Outbox columns:

- `namespace`
- `org_id`
- `event_id`
- `snapshot_id`
- `event_kind`
- `payload_json`
- `status`
- `attempt_count`
- `available_at_ms`
- `claimed_by`
- `claim_expires_at_ms`
- `last_error`
- `created_at_ms`
- `updated_at_ms`

Claiming approach:

1. Select a bounded page of visible rows where `status = 'pending'`,
   `available_at_ms <= now`, and the existing claim is empty or expired.
2. For each candidate, run conditional `UPDATE ... WHERE event_id = ? AND
(claimed_by IS NULL OR claim_expires_at_ms < ?)`.
3. Read back rows claimed by this worker and lease token.
4. Mark dispatched, retry, or dead-letter with state-specific conditional
   updates.

Cloudflare Queues or Workflows remain a later dispatch option. The first cut
keeps outbox semantics in D1 because it is the closest replacement for the
current snapshot outbox contract.

## Signer Persistence

D1 owns durable queryable signer state:

- wallets and wallet auth methods
- WebAuthn authenticators, bindings, and challenges
- email OTP challenges, grants, enrollments, recovery escrows, and auth state
- wallet signers and threshold public-key metadata when dashboard lookup needs it
- sealed signing-root secret shares
- identity links, app sessions, recovery sessions, and recovery executions

Device linking is deferred to refactor 84. Refactor 82 does not register
server-side link-device routes and does not keep unsupported `AuthService`
methods for that future feature, so it is not a staging persistence requirement.

Durable Objects own hot coordination state:

- registration intents, HSS preparations, ceremonies, and finalize replay
  records
- signing-session use-count consumption
- idempotency consumption guards
- normal-signing admission quotas, project policy decisions, and abuse decisions
- wallet signing budget reserve, commit, release, and validation
- ECDSA presignature put, reserve, take, and discard
- ECDSA pool-fill compare-and-swap advancement
- Ed25519 presign capacity and rate limiting
- signing-root status and replay guards

Durable Object names:

```text
threshold-store:namespace:{namespace}:wallet:{walletId}
threshold-store:namespace:{namespace}:signing-root:{signingRootId}:{signingRootVersion}
threshold-store:namespace:{namespace}:relayer-key:{relayerKeyId}
threshold-store:namespace:{namespace}:session:{sessionId}
threshold-store:namespace:{namespace}:admission:{authorityScope}
```

DO rules:

- Use one object per coordination atom.
- Persist before updating in-memory cache.
- Keep `blockConcurrencyWhile()` limited to constructor schema setup.
- Avoid external network I/O inside critical mutations.
- Use typed RPC methods for new callers.
- Keep import-only fetch surfaces behind migration admin boundaries and delete
  them before production cutover.

## Encrypted Signer Secrets

D1 may store encrypted signer ciphertext. D1 must never store plaintext signer
shares, root shares, private keys, KEKs, or API secrets.

The current threshold key-store records are secret-bearing:

- `ThresholdEd25519KeyRecord` contains `relayerSigningShareB64u`.
- `EcdsaHssRoleLocalKeyRecord` contains `relayerShare32B64u` and
  `relayerCaitSithInput.mappedPrivateShare32B64u`.

Production D1 staging must satisfy one of these readiness conditions before
using those flows:

- Replace the key-store secret fields with sealed signing-root share references
  and store ciphertext through `signer_signing_root_secret_shares`.
- Keep the existing Durable Object key-store path for short-lived coordination
  and add a deletion milestone for raw-share DO records after sealed-share
  persistence is the only production path.

Raw threshold share tables in D1 are outside the simplified plan.

Sealed share rows include:

- tenant identity fields
- signing root ID and version
- share ID
- sealed ciphertext
- optional external storage ID
- KEK ID
- envelope version
- AAD digest
- ciphertext digest
- rotation state
- last audit event ID
- created and updated timestamps

KEK provider shape:

```ts
type SignerKekProvider =
  | {
      kind: 'cloudflare_secrets_store';
      secretsByKekId: Readonly<Record<KekId, CloudflareSecretsStoreSecretBinding>>;
      encoding: SigningRootEncodedKekMaterialEncoding;
      workerSecretsByKekId?: never;
      externalKmsClient?: never;
    }
  | {
      kind: 'worker_secret';
      workerSecretsByKekId: Readonly<Record<KekId, string>>;
      encoding: SigningRootEncodedKekMaterialEncoding;
      secretsByKekId?: never;
      externalKmsClient?: never;
    }
  | {
      kind: 'external_kms';
      externalKmsClient: SigningRootExternalKmsKekClient;
      secretsByKekId?: never;
      workerSecretsByKekId?: never;
      encoding?: never;
    };
```

Rules:

- Core sealing code depends on `SigningRootKekResolver`.
- Hosted production uses Cloudflare Secrets Store.
- Local development may use Wrangler secrets.
- Enterprise custody can use an external KMS/HSM through a signer-only adapter.
- Console routes cannot access signer KEKs.
- Import tooling may handle plaintext only in process memory during a controlled
  migration. Plaintext cannot be logged, written to disk, returned in responses,
  or stored in D1/DO/R2/Postgres.

## Multi-Tenancy Decisions

First-release recommendation:

- Use shared D1 databases for all tenants.
- Add tenant route resolution now, backed by a static resolver.
- Defer the route registry until a tenant needs a dedicated D1 route or
  full-family Postgres route.
- Keep every table tenant-scoped.
- Keep raw observability, bulky snapshots, and long-retention archives out of
  shared D1.

D1 scaling thresholds:

- Alert at 7 GB.
- Prepare cold-data offload, dedicated tenant D1, or Postgres migration at 8 GB.
- Freeze new high-volume writes and execute the move before 9 GB.
- Treat 10 GB as a hard cap, since paid D1 databases are capped at 10 GB per
  database.

Scaling order:

1. Move raw and cold data out of D1.
2. Move a large enterprise tenant to dedicated `CONSOLE_DB` and `SIGNER_DB`
   bindings.
3. Move the tenant or deployment to the full-family Postgres adapter when the
   product needs one logical relational database above D1 limits.

Dedicated tenant D1 triggers:

- Contractual database-level isolation.
- Database-level restore/export/delete requirements.
- Tenant signer or console rows exceed 2 GB.
- One tenant consumes more than 30 percent of shared D1 storage.
- Shared D1 reaches 7 GB and one tenant is the largest contributor.
- Repeated hot-tenant latency or overload incidents.
- Customer-managed KMS/HSM or dedicated KEK lifecycle.

## Backup And Recovery

D1 reliability plan:

- Use D1 Time Travel as the primary short-term recovery layer for production D1
  databases on the production storage subsystem.
- Verify production storage support with `wrangler d1 info DB_NAME` before
  cutover.
- Capture `wrangler d1 time-travel info DB_NAME` bookmarks before migrations,
  imports, tenant moves, route switches, and destructive maintenance.
- Run `pnpm --dir packages/sdk-server-ts run d1:local:restore:drill` before
  staging imports or D1 migration changes. This local drill backs up the
  Miniflare console and signer SQLite databases, restores SQL dumps into fresh
  SQLite files, verifies `PRAGMA integrity_check`, validates the expected table
  counts, and writes an ignored manifest under
  `packages/sdk-server-ts/.wrangler/d1-local-restore-drills`.
- Keep weekly exports of `CONSOLE_DB` and `SIGNER_DB` in R2.
- Add weekly exports for `TENANT_ROUTE_DB` after the registry exists.
- Add weekly exports for every dedicated tenant D1.
- Retain weekly R2 exports for at least 12 weeks unless customer or compliance
  policy requires more.
- Run monthly staging restore drills from Time Travel and R2 exports.

Security notes:

- D1 encrypts data at rest and in transit.
- Signer shares remain application-encrypted before storage.
- R2 exports contain sensitive encrypted data and require restricted access.
- KEKs are never exported to D1, R2, or local SQLite files.
- Tenant deletion reports must account for Time Travel, export, and backup
  retention windows.

## Postgres Escape Hatch

Postgres is a future full-family backend adapter selected by
`TenantStorageRoute`. Partial backend splits are invalid. The first D1/DO
staging deploy does not require a live Postgres implementation.

Postgres adapter readiness bar before any production tenant can select
Postgres:

- Every required domain-store port has a Postgres implementation.
- Postgres migrations exist for console, billing, sponsored gas, runtime
  snapshots, signer metadata, signer coordination, and reconciliation data.
- Schemas mirror the D1 logical model: tenant keys, lifecycle columns,
  idempotency keys, uniqueness constraints, ciphertext fields, AAD fields,
  digest fields, and parse boundaries.
- Billing reserve, settle, release, and expiry operations run in one Postgres
  transaction and lock the summary and reservation rows they mutate.
- Sponsored settlement finalization runs in one transaction that updates the
  sponsored execution, reservation lifecycle, billing summary, and ledger entry.
- Snapshot outbox claiming may use `FOR UPDATE SKIP LOCKED` inside the adapter.
  It returns the same lease, retry, and dead-letter result unions as the D1
  adapter.
- Signer coordination uses transactions, row locks, and unique idempotency
  indexes to match Durable Object result contracts.
- Worker runtime access uses Hyperdrive. Node migration tooling may use a direct
  Postgres pool.
- Shared contract tests pass against D1/DO and Postgres.
- Export/import tooling has passed a tenant smoke test.

D1-to-Postgres migration path:

1. Provision Postgres and Hyperdrive.
2. Apply Postgres adapter migrations.
3. Capture D1 Time Travel bookmarks and write a migration manifest to R2.
4. Freeze tenant writes through the route layer.
5. Export all tenant-scoped D1 state and Durable Object durable coordination
   state.
6. Parse exports into internal domain types.
7. Import through Postgres adapters.
8. Run count, key-identity, signer sealed-share, billing-balance, sponsored gas,
   snapshot outbox, and dashboard smoke checks.
9. Switch the route to the `postgres` branch with a route version compare-and-set.
10. Reopen writes.
11. Keep source D1 read-only through the archive window, then delete rows in
    small batches.

## Phased Todo List

Goal: ship staging on D1/DO with the smallest backend surface that preserves
sponsored gas billing, dashboard reconciliation, signer custody, tenant
isolation, local development, recovery, and a full-family Postgres escape
hatch.

### Phase 1: Inventory Postgres Coupling

Status: complete for the current staging inventory. Keep the ownership matrix
current as adapters land.

Work:

- [x] Inventory `seams-console` Postgres services, SQL files, migrations, and
      tests.
- [x] Inventory `seams-signer` Postgres tables and runtime call sites.
- [x] Categorize each table as console D1, signer D1, signer Durable Object, raw
      archive, or deferred Postgres escape-hatch concern.
- [x] Record every `FOR UPDATE`, `SKIP LOCKED`, advisory lock, transaction,
      JSONB, partial-index, and RLS dependency needed for the current staging scope.

Exit criteria:

- [x] Every current Postgres table and SQL primitive has a target owner in this
      document.
- [x] Remaining unknowns are tracked as explicit open items before adapter work
      starts.

### Phase 2: Define D1 Schemas And Durable Object Ownership

Status: complete for the current D1/DO schema and Durable Object ownership
baseline. Reopen only if a remaining staging-required signer method needs a new
table, index, or Durable Object state key.

Work:

- [x] Add D1 migrations for the console and signer tables required by staging.
- [x] Add Durable Object storage schemas for signer coordination atoms.
- [x] Define lifecycle states, idempotency keys, tenant-first indexes, lease
      columns, and atomic D1/SQLite invariants.
- [x] Store JSON as `TEXT` and add side tables only for indexed membership
      queries.

Exit criteria:

- [x] Local Wrangler/Miniflare migrations apply cleanly for `CONSOLE_DB` and
      `SIGNER_DB`.
- [x] Every current staging-required table appears in the D1 smoke Worker.
- [x] Atomic billing, sponsored settlement, snapshot leases, and signer secret
      rows have focused schema tests for the implemented baseline.

### Phase 3: Add D1/DO Adapters Behind Domain Stores

Status: complete for the simplified first-staging scope. D1/DO adapters are
implemented behind domain-store ports, first-staging Durable Object behavior has
direct contract coverage, and the high-risk D1 adapter matrix is complete for the
current route surface. Reopen only when a future route slice adds a new
first-staging adapter, Durable Object behavior, or indexed signer metadata table.

Completed:

- [x] Console D1 adapters cover the first staging dashboard surface: orgs,
      projects, environments, account/profile state, team RBAC, policies, API keys,
      wallet index, approvals, key exports, audit, bootstrap tokens, billing,
      prepaid reservations, sponsorship spend caps, sponsored-call records, runtime
      snapshots, webhooks, compact observability, Stripe credit purchases, monthly
      usage statements, and billing finalization.
- [x] Sponsored gas settlement stays on the D1 atomic path for staging.
- [x] Signer D1 adapters cover wallet metadata/auth methods, WebAuthn storage,
      identity links, app-session versions, recovery sessions/executions, NEAR
      public keys, email recovery preparations, Email OTP storage, Email OTP login
      challenge/grant/rate-limit flow, Email OTP device-recovery challenge/grant
      flow, Email OTP recovery-key consumption and failure-attempt reporting, Email
      OTP provider delivery, Email OTP registration enrollment verification, Email
      OTP unlock challenge/proof flow, and sealed signing-root secret shares.
- [x] Cloudflare Router API auth service D1 methods cover recovery-session reads,
      recovery-session status transitions, recovery-execution upserts, Email OTP
      device recovery, Email OTP recovery-key consumption, recovery-key failure
      reporting, recovery-code rotation, Email OTP provider delivery, and Email OTP
      enrollment verification/persistence.
- [x] Cloudflare Router API auth service D1 methods can issue Email OTP enrollment
      challenges for wallet registration without requiring an existing enrollment.
- [x] Cloudflare Router API auth service D1 methods can verify Email OTP enrollment
      challenges, require an existing canonical signer wallet, persist enrollment
      material, and store the recovery-wrapped enrollment escrow set.
- [x] Cloudflare Router API auth service D1 methods can rate-limit, create, reuse,
      and restart Google Email OTP registration attempts during session exchange.
- [x] Cloudflare Router API auth service D1 methods verify generic OIDC JWT exchange
      tokens with Worker-safe JWKS caching, issuer/audience claim checks, and D1
      identity linking.
- [x] Cloudflare Router API auth service D1 methods apply and remove Email OTP
      server seals through configured Worker Shamir key material and fail closed
      when that material is absent.
- [x] Cloudflare Router API auth service D1 methods revoke wallet auth methods
      through the D1 wallet auth-method leaf store, bind app-session revoke policy
      to the requested wallet and target, and reject removal of the last active auth
      method.
- [x] Cloudflare Router API auth service D1 methods return explicit ECDSA key
      inventory diagnostics while threshold metadata storage remains deferred.
- [x] Durable Objects cover registration ceremonies, signing admission, signing
      budgets, replay guards, ECDSA presignature pools, pool-fill CAS, and
      signing-root coordination where serialized mutation is the required property.
- [x] Finish Ed25519 HSS ceremony persistence contract: durable server-owned
      finalize state in Durable Object storage, no process-local handles, and no
      client-carried server private state.
- [x] Cloudflare Router API auth service D1 methods auto-wire threshold signing from
      `THRESHOLD_STORE` through a Durable Object-only factory and expose the ECDSA
      HSS role-local bootstrap, existing-key proof verification, and export-share
      primitive methods.
- [x] Cloudflare Router API auth service D1 methods allocate wallet-registration,
      add-signer, and add-auth-method intents through the `THRESHOLD_STORE` Durable
      Object protocol, including server-allocated-wallet replay reservation and signer
      wallet collision checks.
- [x] Signer-selection request parsing for registration and add-signer intents
      lives in the shared boundary parser instead of duplicated private
      `AuthService` helpers.
- [x] Deleted the disabled Cloudflare Router API bindings for
      `createRegistrationIntent`, `createAddSignerIntent`, and
      `createAddAuthMethodIntent`.
- [x] Cloudflare Router API auth service D1 methods start and finalize Email OTP
      add-auth-method ceremonies through Durable Object intent and ceremony storage,
      consume registration Email OTP challenges, bind app-session policy to the
      exact intent/runtime scope, persist wallet auth-method rows in D1, and consume
      ceremonies exactly once.
- [x] Cloudflare Router API auth service D1 methods start, respond to, and finalize
      ECDSA-only wallet registration ceremonies through Durable Object intent and
      ceremony storage, consume registration Email OTP challenges, bind authority
      proofs to the exact registration intent/runtime scope, emit ECDSA role-local
      prepare state, persist responded ECDSA role-local bootstrap state, persist
      finalized wallet, active auth-method, ECDSA wallet signer rows, direct Email
      OTP enrollment material, recovery-wrapped enrollment escrows, and Email OTP
      auth-state reset rows in D1, and consume registration intents and finalize
      ceremonies exactly once.
- [x] Cloudflare Router API auth service D1 methods start, respond to, and finalize
      ECDSA add-signer ceremonies through Durable Object intent and ceremony
      storage, bind app-session policy to the exact signer selection/runtime scope,
      emit ECDSA role-local prepare state, persist responded ECDSA role-local
      bootstrap state, persist finalized ECDSA wallet signer rows in D1, and
      consume add-signer intents and finalize ceremonies exactly once.
- [x] The D1 Router API auth factory no longer starts from a disabled compatibility
      service and overrides methods. It returns the concrete D1 service directly,
      and the obsolete disabled scaffold was deleted after route-scope exclusions
      removed the last unsupported first-staging method from the D1 auth port.
- [x] The Cloudflare service-bundle router-api options are wired to the Durable Object
      normal-signing admission store.
- [x] The Cloudflare service-bundle router-api options are wired to D1-backed
      billing, prepaid reservations, sponsorship spend caps, sponsored-call records,
      API keys, bootstrap tokens, wallet indexes, runtime snapshots, and
      observability ingestion.
- [x] The KEK provider boundary stays narrow: Cloudflare Secrets Store for hosted
      production, Wrangler secrets for local development, external KMS/HSM for
      enterprise custody.
- [x] Cloudflare Worker-facing imports point at D1/DO leaf modules and the
      runtime import guard rejects Postgres storage, mixed console barrels, and
      session-seal barrels in Worker bundles.
- [x] Cloudflare cron stays on D1 runner inputs. Postgres cron belongs to a future
      full-family Postgres adapter surface, not the D1/DO staging Worker helper.
- [x] Cloudflare signer routes are typed against `CloudflareRouterApiAuthService`.
- [x] Signer metadata methods live in Worker-safe D1 leaf modules.
- [x] The D1 wallet auth-method store lives in a Worker-safe leaf module; the
      mixed Node/Postgres factory re-exports it without making Worker code import
      Postgres storage.
- [x] Local Wrangler router-api development passes `THRESHOLD_STORE` into the D1
      Router API auth service and lets router threshold routes auto-resolve from the
      service instead of forcing `threshold: null`.
- [x] WebAuthn login and sync verification run through the D1 Router API auth service,
      including one-time challenge consumption and atomic authenticator-counter
      updates.
- [x] Device linking remains deferred to refactor 84 while the feature remains
      disabled at the route and service layers.
- [x] Threshold public-key metadata D1 tables are deferred. This does not block
      first D1 staging unless dashboard or recovery flows require a public-key
      lookup before staging deploy.
- [x] NEAR signed delegates are excluded from the simplified first D1 staging
      scope. The Cloudflare D1 service bundle omits the `/signed-delegate` route,
      and signed-delegate execution is typed as a narrow opt-in route dependency
      outside `CloudflareRouterApiAuthService`.
- [x] DKIM/TEE email recovery prepare, ECDSA respond, and `/recover-email`
      ingress are excluded from the simplified first D1 staging scope. Non-D1
      route users must opt in with the structural `emailRecovery` route branch:
      `kind: 'prepare_and_execute'` carries `authService` plus
      `executionService`, while `kind: 'prepare_only'` carries only the auth
      service and omits the `/recover-email` route. The D1 local worker smoke
      test proves the recovery route is absent. Validation passed:
      `pnpm --dir packages/sdk-server-ts type-check`,
      `pnpm --dir tests exec playwright test -c playwright.unit.config.ts
unit/router.relayRouteSurface.unit.test.ts
unit/router.routeDefinitions.unit.test.ts --reporter=line`,
      `pnpm --dir tests exec playwright test -c playwright.relayer.config.ts
relayer/cloudflare-router.test.ts relayer/express-router.test.ts --grep
"recover-email" --reporter=line`,
      `pnpm --dir tests exec playwright test -c playwright.relayer.config.ts
relayer/email-recovery.prepare.test.ts --reporter=line`,
      `pnpm --dir packages/sdk-server-ts build`,
      `pnpm --dir tests exec playwright test -c playwright.unit.config.ts
unit/refactor82CloudflareD1Runtime.guard.unit.test.ts --reporter=line`, and
      `git diff --check`.
- [x] Ed25519 wallet-registration prepare is mounted for D1 through the structural
      `ed25519RegistrationPrepare: { authService }` route option. The D1 service
      supports implicit NEAR account registration for the current local
      `ed25519_and_ecdsa` registration flow; sponsored named NEAR account creation
      still needs a D1 relayer transaction adapter before it can be enabled.
- [x] Core orchestration receives domain-store ports instead of raw persistence
      bindings. `tests/unit/refactor82CloudflareD1Runtime.guard.unit.test.ts`
      now guards `AuthService`, `SessionService`, threshold signing orchestration,
      signing handlers, and Router A/B threshold orchestration against storage
      imports, raw D1 binding/statement types, raw Durable Object binding/stub
      types, tenant-route resolution, Cloudflare binding names, and raw database
      method calls.
- [x] Durable Object wallet-session use-count idempotency has direct first-staging
      contract coverage. `tests/unit/walletSessionBudgetReservation.store.unit.test.ts`
      now verifies the Cloudflare Durable Object store consumes one session
      idempotency key once under concurrent duplicate calls, preserves the consumed
      marker, and rejects a different idempotency key after the available budget is
      exhausted. The in-test Durable Object storage helper now serializes
      transactions, matching the staging-critical mutation property.
- [x] Console prepaid reservations have direct high-risk D1 coverage for atomic
      idempotency, lifecycle transitions, insufficient-balance rollback, and corrupt
      raw-row rejection. The D1 schema and migration now enforce non-empty tenant
      and reservation identity, positive requested amount, monotonic timestamps, and
      lifecycle-specific settlement/release invariants. The adapter parser now
      rejects corrupt rows instead of clamping invalid numeric fields into valid
      domain state.

Closure checks:

- [x] Keep the signer Email OTP D1 adapter slice covered by migration, local
      smoke, and contract tests as staging coverage expands.
- [x] Run a Durable Object staging-behavior audit across registration ceremonies,
      signing admission, signing budgets, replay guards, ECDSA presignature pools,
      pool-fill CAS, signing-root coordination, and session consumption. Add
      contract tests for any first-staging behavior without direct coverage.
- [x] Prove core logic receives domain-store ports only. Storage details must stay
      inside D1 adapters, Durable Object stubs/facades, request boundaries, or
      tenant-route resolution.
- [x] Confirm high-risk D1 adapters have direct tests for tenant scoping,
      idempotency, lifecycle transitions, and corrupt-row parsing. The required
      first-staging set is prepaid reservations, sponsored-call records, runtime
      snapshot outbox/leases, webhook delivery state, signer wallets/auth methods,
      sealed signer shares, identity/session/recovery rows, and Email OTP records.
      Evidence: the high-risk D1 adapter coverage matrix below records the direct
      tenant-scope, idempotency, lifecycle, lease, and corrupt-row checks.
- [x] Confirm route-owned staging persistence has no local Postgres dependency.
      Evidence: `tests/unit/refactor82CloudflareD1Runtime.guard.unit.test.ts`
      proves the Cloudflare runtime graph stays D1/DO-only at persistence
      boundaries and that sdk-server runtime Postgres adapters are absent.
      `tests/relayer/console-router.test.ts` proves the Cloudflare console router
      rejects a `PostgresTenantStorageRoute` with
      `tenant_storage_backend_not_supported_in_cloudflare_runtime`, before
      route-owned services can use tenant persistence.
- [x] Decide whether dashboard or recovery requires threshold public-key metadata
      before staging. Decision: first D1 staging does not require a new threshold
      public-key metadata table. The staging dashboard and reconciliation surface
      use wallet metadata, NEAR public-key metadata, signer rows, sealed shares,
      audit, billing, snapshots, and explicit ECDSA key-inventory diagnostics.
      Device recovery execution and dashboard key-inventory lookups that need a
      persisted threshold public-key index must land later as complete route slices
      with their own D1 schema, adapter, and tests.

Exit criteria:

- [x] Domain-store port proof is recorded with source-guard or type-check evidence.
- [x] High-risk adapter coverage matrix is complete for the first-staging scope.
- [x] Route-owned staging persistence no longer depends on local Postgres.
- [x] Threshold public-key metadata is either implemented or explicitly confirmed
      unnecessary for first staging.

Durable Object staging-behavior audit:

| Behavior                                                                                               | First-staging proof                                                                                                                                                                                                                                                                                           |
| ------------------------------------------------------------------------------------------------------ | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Registration ceremonies, intent consumption, finalize replay, and server-allocated wallet reservations | `tests/unit/registrationCeremonyStore.unit.test.ts` covers server-allocated-wallet reservation scope, Cloudflare Durable Object grant and ceremony single-use consumption, preparation scope matching, lifecycle branch parsing, and corrupt raw ceremony/replay rejection.                                   |
| Router A/B normal-signing admission                                                                    | `tests/unit/routerAbNormalSigningAdmissionStore.unit.test.ts` covers the Cloudflare Durable Object admission store and quota semantics; `tests/unit/cloudflareD1ConsoleServices.unit.test.ts` proves the D1 service bundle wires that DO-backed admission into router-api options and local `/readyz`.             |
| Wallet-session budget reservation and session consumption                                              | `tests/unit/walletSessionBudgetReservation.store.unit.test.ts` covers Cloudflare Durable Object reservation lifecycle semantics and `consumeUseCountOnce` duplicate idempotency under concurrent calls.                                                                                                       |
| Replay guards                                                                                          | `tests/relayer/threshold-ecdsa.durable-stores.test.ts` covers Cloudflare Durable Object export nonce reservation once under concurrency.                                                                                                                                                                      |
| ECDSA presignature pools                                                                               | `tests/relayer/threshold-ecdsa.durable-stores.test.ts` covers Cloudflare Durable Object presignature `reserve`, `reserveById`, and `consume` as single-use operations under concurrent calls.                                                                                                                 |
| Pool-fill CAS                                                                                          | `tests/relayer/threshold-ecdsa.durable-stores.test.ts` covers Cloudflare Durable Object `poolFillSessionStore` compare-and-swap transitions.                                                                                                                                                                  |
| Signing-root coordination                                                                              | `tests/unit/thresholdPrf.cloudflareWorkerSigningRoot.script.unit.test.ts` covers Cloudflare Durable Object signing-root protocol status storage, sealed-share materialization, and optional sealed-share listing cache. `tests/unit/signingRootSecretConfig.script.unit.test.ts` covers resolver composition. |

High-risk D1 adapter coverage matrix:

| Adapter surface                       | Tenant scope                                                                                                                                                                                                                    | Idempotency / one-time behavior                                                                                                                      | Lifecycle / lease behavior                                                                                                                                                      | Corrupt-row parsing or schema rejection                                                                                                                                                                                                                                                                                                          |
| ------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| Prepaid reservations                  | `tests/relayer/console-d1-adapters.test.ts` scopes reservation summaries and lookups by org context.                                                                                                                            | The trigger-atomic reservation test proves duplicate source-event reservation does not double debit.                                                 | The same test covers reserve, settle, release, insufficient-balance rollback, and stale transition rejection.                                                                   | `d1-console prepaid-reservation migration rejects corrupt raw records` rejects invalid source IDs, non-positive amounts, bad release math, reserved settlement data, and regressed timestamps.                                                                                                                                                   |
| Sponsored-call records                | `sponsored gas settlement writes reservation, billing, and call record in one D1 batch` scopes billing and sponsored ledgers by org context.                                                                                    | `sponsored call idempotency returns the original record` and the atomic settlement test prove duplicate idempotency keys replay the original record. | Atomic settlement tests cover settled reservations, duplicate settlement replay, conflict rejection, and stale reservation rejection without billing side effects.              | `d1-console sponsored-call migration rejects corrupt raw records` rejects empty idempotency keys, invalid JSON, negative estimates, zero timestamps, and regressed updates.                                                                                                                                                                      |
| Billing ledger and monthly usage rows | Billing and sponsored-gas tests scope accounts, ledger entries, postings, and monthly wallet usage by org context.                                                                                                              | Ledger idempotency keys, source-event indexes, and sponsored-gas settlement tests prove replay does not double-post.                                 | Billing finalization and sponsored-gas settlement tests cover purchase, debit, statement, and sponsored execution ledger lifecycle.                                             | `d1-console billing ledger migration rejects corrupt raw records` rejects empty tenant/ledger IDs, invalid months, empty optional refs, inverted credit/debit signs, zero manual adjustments, invalid postings, and invalid monthly-wallet rows.                                                                                                 |
| Runtime snapshot outbox/leases        | `runtime snapshot outbox claim lease prevents duplicate dispatch` runs dispatch for one org context.                                                                                                                            | The race harness proves a competing worker cannot dispatch the same event after another worker claims it.                                            | The same test covers claim lease behavior and post-dispatch non-reclaim.                                                                                                        | `d1-console runtime snapshot migration rejects corrupt raw outbox rows` rejects missing IDs, invalid JSON, invalid claim leases, dispatched rows without dispatch timestamps, and dead-letter rows without errors.                                                                                                                               |
| Webhook delivery state                | Webhook D1 adapter tests create/list/delete endpoints through org-scoped service contexts.                                                                                                                                      | Retry dispatch claims failed deliveries before sending, so a competing worker cannot send the same failed delivery.                                  | Webhook tests cover failed delivery, retry claim, success transition, replay, disabled endpoint behavior, and deletion.                                                         | `d1-console webhook migration rejects corrupt raw endpoint rows` rejects invalid tenant IDs, endpoint IDs, URLs, secret ciphertext, secret previews, timestamps, and unsupported categories.                                                                                                                                                     |
| Signer wallets/auth methods           | `signer wallet metadata and auth methods are scoped by tenant environment` proves wallet, signer, passkey, and Email OTP records are invisible in another env.                                                                  | WebAuthn challenge stores consume login and sync challenges exactly once.                                                                            | Wallet/auth-method tests cover active auth methods, signer rows, WebAuthn counter overwrite, and one-time challenge consumption.                                                | Signer wallet/auth-method migration tests reject raw identity mismatches and invalid branch rows.                                                                                                                                                                                                                                                |
| Sealed signer shares                  | `signer sealed shares are scoped by tenant, project, and environment` proves production shares are invisible from development env.                                                                                              | Share writes are keyed by signing root, version, and share ID.                                                                                       | The D1 store requires `kekId` for sealed share writes, and signing-root DO tests cover coordination state.                                                                      | `d1-signer sealed-share migration rejects corrupt raw custody rows` rejects invalid namespace, signing root ID, base64url ciphertext/AAD, storage ID, timestamps, and rotation timestamps.                                                                                                                                                       |
| Identity/session/recovery rows        | `signer identity links and app session versions are scoped in D1`, `signer recovery sessions and executions are scoped in D1`, and `signer email recovery preparations are scoped and expire in D1` prove env-scoped isolation. | Identity linking rejects already-linked subjects, app-session version ensure is idempotent, and version rotation changes authority.                  | Recovery session tests cover prepared state expiry; recovery execution tests cover pending/confirmed rows and pending sweeps.                                                   | `d1-signer identity and recovery migrations reject corrupt raw rows` rejects empty tenant/identity fields, mismatched JSON envelope identities, invalid session statuses, regressed timestamps, invalid recovery execution states, and mismatched email-recovery wallet bindings.                                                                |
| Email OTP records                     | `signer Email OTP stores are scoped and consume one-time records in D1` proves challenge, grant, enrollment, escrow, auth-state, unlock challenge, and registration-attempt rows are invisible across env scope.                | Grants and unlock challenges consume exactly once; challenge lookup/deletion and active-count queries are scoped.                                    | The same test covers active/expired challenge lifecycle, escrow active/consumed states, auth-state updates, registration attempt replacement, abandonment, and expiry deletion. | `tests/unit/emailOtp.records.unit.test.ts` rejects malformed Email OTP persisted records, and `d1-signer Email OTP migrations reject corrupt raw rows` rejects raw D1 rows with tenant gaps, invalid actions/statuses, JSON envelope mismatches, invalid escrow lifecycle fields, malformed registration offers, and invalid rate-limit windows. |

Phase 3 closure validation evidence:

- [x] `pnpm --dir tests exec playwright test -c playwright.relayer.config.ts
relayer/console-d1-adapters.test.ts --reporter=line` passed with 43 D1
      migration and adapter tests covering corrupt-row schema rejection, tenant
      scoping, idempotency, lifecycle transitions, webhook retry claims, runtime
      snapshot claim leases, billing ledger invariants, sponsored gas settlement,
      signer wallet/auth-method stores, signer identity/session/recovery raw-row
      rejection, Email OTP raw-row rejection, Email OTP adapter rows, and sealed
      shares.
- [x] `pnpm --dir tests exec playwright test -c playwright.unit.config.ts
unit/registrationCeremonyStore.unit.test.ts
unit/routerAbNormalSigningAdmissionStore.unit.test.ts
unit/walletSessionBudgetReservation.store.unit.test.ts
unit/thresholdPrf.cloudflareWorkerSigningRoot.script.unit.test.ts
unit/signingRootSecretConfig.script.unit.test.ts
unit/emailOtp.records.unit.test.ts --reporter=line` passed with 36 tests
      passed and 2 external-backend tests skipped after updating the
      signing-root resolver fixture to provide the required
      `ROUTER_AB_NORMAL_SIGNING_WORKER_ID`.
- [x] `pnpm --dir tests exec playwright test -c playwright.relayer.config.ts
relayer/threshold-ecdsa.durable-stores.test.ts --grep "Wallet Session
export replay guard|Cloudflare Durable Object" --reporter=line` passed with
      5 Durable Object tests covering export nonce replay guard, ECDSA
      presignature reserve/consume, reserve-by-id, and pool-fill CAS.
- [x] `pnpm --dir tests exec tsc -p tsconfig.playwright.json --noEmit` and
      `git diff --check` passed after the Phase 3 plan and stale fixture updates.

### Phase 4: Make Local Development D1/DO By Default

Status: complete for the first-staging local workflow. SDK package command path,
local D1/DO console Worker path, local sponsored-gas Router API path, Cloudflare signer
route service port, bundle smoke, representative signer passkey-options smoke,
and clean-state live Wrangler workflow smoke are complete. A developer can run
dashboard flows, signer flows, sponsored-gas billing, sponsored EVM route-mount,
and reconciliation locally without Docker Postgres.

Work:

- [x] Keep the default SDK local console and sponsored-gas Router API path on
      Wrangler/Miniflare D1 and local Durable Object storage for staging-required
      flows.
- [x] Use `pnpm --dir packages/sdk-server-ts run d1:local:prepare` for local
      migrations plus table smoke, and
      `pnpm --dir packages/sdk-server-ts run d1:local:dev` for Wrangler dev.
- [x] Use `GET /readyz` on the local Worker as the exact readiness gate. It must
      report `backend: "cloudflare_d1_do"`, 40 console tables, 21 signer tables,
      and a configured Durable Object admission reservation.
- [x] Use `/console/*` for real D1-backed console route development.
- [x] Use `/router-api/*` for sponsored-gas Router API smoke development, with local EVM
      execution configured through `SPONSORED_EVM_EXECUTORS_JSON` when needed.
- [x] Keep signer routes fail-closed while their D1/DO
      `CloudflareRouterApiAuthService` methods are incomplete.
- [x] Run representative signer smoke through Wrangler after the
      Cloudflare-safe signer AuthService slice lands.
- [x] Keep `apps/web-server` as the Node/Express legacy runner until it is replaced
      by the Cloudflare Worker app path. Do not add a D1-via-Express shim; local D1
      should go through Wrangler/Miniflare bindings.
- [x] Keep Docker Postgres available only for legacy tests and unfinished
      non-staging paths while those paths are removed from the default workflow.
- [x] Reset clean local state by deleting
      `packages/sdk-server-ts/.wrangler/state/seams-d1`; add a fixture seed/import
      command only after the staging fixture format is chosen.
- [x] Document read-only TablePlus inspection of local SQLite files under
      `packages/sdk-server-ts/.wrangler/state/seams-d1`.
- [x] Add automated local Worker workflow smoke coverage for dashboard readiness,
      signer passkey-options flow, idempotent support-credit billing, billing
      overview/activity, sponsored execution history, and reconciliation using
      migrated D1 console/signer schemas plus local Durable Object storage.
- [x] Document and run the live Wrangler/Miniflare workflow smoke sequence for
      dashboard flows, signer flows, sponsored-gas billing, sponsored EVM route
      mounting with `SPONSORED_EVM_EXECUTORS_JSON`, and reconciliation using only
      local D1, local Durable Object storage, and local secret/KMS configuration.
- [x] Run the full local workflow smoke from a clean
      `packages/sdk-server-ts/.wrangler/state/seams-d1` state and record the exact
      commands plus expected responses.
- [x] Verify the local workflow does not require Docker Postgres, `POSTGRES_URL`,
      `CONSOLE_POSTGRES_URL`, or Postgres migration scripts.
- [x] Phase 4 deletion pass: remove the duplicate sponsored-EVM Worker WASM
      initialization path and make `evmWorkerSignerWasm.ts` delegate to the shared
      `core/ThresholdService/ethSignerWasm.ts` runtime. The shared loader now
      tries a bundled Worker `.wasm` module before URL-fetch fallbacks, which lets
      Wrangler/workerd derive the local sponsor address and mount the sponsored
      route.

Exit criteria:

- [x] A developer can run the dashboard, signer flows, sponsored gas billing, and
      reconciliation locally without Docker Postgres.
- [x] The local command path mirrors Cloudflare bindings, D1 API behavior, and
      Durable Object storage behavior.
- [x] A representative sponsored-gas Router API smoke path runs through Wrangler
      without `POSTGRES_URL`, `CONSOLE_POSTGRES_URL`, or Docker Postgres.
- [x] A representative signer smoke path runs through Wrangler after the
      Cloudflare-safe signer AuthService slice lands.
- [x] Full local workflow smoke evidence is recorded for dashboard flows, signer
      flows, sponsored-gas billing, and reconciliation.

Validation evidence:

- [x] `pnpm --dir packages/sdk-server-ts run d1:local:prepare` passed with
      Wrangler `4.105.0`, applying local D1 migrations and confirming 40
      console tables plus 21 signer tables. Re-run on June 29, 2026: no pending
      local migrations, console smoke returned `table_count: 40`, and signer smoke
      returned `table_count: 21`.
- [x] `pnpm --dir packages/sdk-server-ts run d1:local:dev` starts the local
      Worker after `packages/sdk-server-ts/wrangler.d1-local.toml` enables
      `nodejs_compat`, with local `CONSOLE_DB`, `SIGNER_DB`, and `THRESHOLD_STORE`
      bindings.
- [x] `packages/sdk-server-ts` owns its local D1 CLI dependency through
      `wrangler@4.105.0`, and `pnpm --dir packages/sdk-server-ts run d1:local:dev`
      starts without the previous compatibility-date fallback warning.
- [x] `packages/sdk-server-ts/package.json` orders `types` before runtime export
      conditions, so Wrangler dev starts without unreachable-export-condition
      warnings.
- [x] Live local HTTP smoke returned `200` for `GET /readyz`, reporting
      `backend: "cloudflare_d1_do"`, 40 console tables, 21 signer tables, and a
      configured Durable Object admission reservation.
- [x] Live local HTTP smoke returned `200` for `GET /router-api/healthz` and
      `POST /router-api/auth/passkey/options`, proving the representative signer route
      runs through Wrangler/Miniflare and writes signer challenge state through the
      D1 route path.
- [x] `pnpm --dir tests exec playwright test -c playwright.unit.config.ts
unit/cloudflareD1ConsoleServices.unit.test.ts --grep "local D1 Worker runs
dashboard" --reporter=line` passed. The smoke applies the D1 console and
      signer migrations to temporary SQLite-backed D1 databases, calls the local
      Worker `/readyz` and `/console/readyz` paths, creates and replays an
      idempotent support credit, verifies billing overview/activity, creates a
      signer passkey-options challenge through `/router-api/auth/passkey/options`, and
      verifies sponsored execution history plus reconciliation read paths without
      Docker Postgres, `POSTGRES_URL`, `CONSOLE_POSTGRES_URL`, or Postgres
      migration scripts.
- [x] `packages/sdk-server-ts/wrangler.d1-local.toml` now includes a local-only
      deterministic `SPONSORED_EVM_EXECUTORS_JSON` entry. The key is documented as
      a dev smoke key and must never be funded.
- [x] Clean-state live local workflow smoke passed after deleting
      `packages/sdk-server-ts/.wrangler/state/seams-d1`, running
      `env -u POSTGRES_URL -u CONSOLE_POSTGRES_URL pnpm --dir packages/sdk-server-ts
run d1:local:prepare`, and starting `env -u POSTGRES_URL -u
CONSOLE_POSTGRES_URL pnpm --dir packages/sdk-server-ts run d1:local:dev`.
      HTTP smoke results: `GET /readyz` returned `200` with
      `backend: "cloudflare_d1_do"`, 40 console tables, 21 signer tables, and a
      Durable Object admission reservation; `GET /console/readyz` returned `200`;
      `POST /console/billing/adjustments/support-credit` returned `201`;
      replaying the same support credit returned `200` with `created: false`;
      `GET /console/billing/overview` returned a 5,000 minor-unit credit balance;
      `GET /console/billing/account/activity?limit=5` returned the credit entry;
      `POST /router-api/auth/passkey/options` returned `200`; `POST
/router-api/sponsorships/evm/call` returned `401` with
      `code: "publishable_key_missing"`, proving the sponsored EVM route mounted
      and reached the publishable-key auth gate; `GET
/console/billing/sponsored-executions` returned `200`; and `GET
/console/billing/sponsored-executions/reconciliation` returned `200` with
      zero reconciliation mismatches.

### Phase 5: Port Tests To D1/DO

Status: complete for the simplified first-staging route surface. Staging-required
D1/DO tests are migrated, the first-staging signer auth scope is frozen, and
future signer auth methods require their own complete route slices with D1/DO
coverage.

Work:

- [x] Move implemented staging-required persistence flows onto D1/DO adapter
      tests.
- [x] Add Playwright unit coverage for implemented Cloudflare D1 Router API auth
      service slices, including recovery-code rotation, generic OIDC JWT exchange,
      Email OTP server-seal transforms, wallet auth-method revocation, Durable
      Object threshold wiring, D1/DO wallet intent allocation, Email OTP
      add-auth-method start/finalize ceremonies, ECDSA add-signer start/respond/finalize
      ceremonies, and the Worker runtime import guard.
- [x] Keep pure unit fakes for core logic that does not depend on SQL behavior.
- [x] Cover every remaining duplicate idempotency, insufficient balance,
      settlement replay, lease races, tenant isolation, sealed-share parsing,
      budget exhaustion, and signing-root coordination.
- [x] Freeze the first-staging signer auth scope. Current scope covers the
      implemented passkey/WebAuthn, Email OTP, and ECDSA ceremony paths. Device
      linking, Ed25519 registration prepare, DKIM/TEE recovery execution, and
      threshold public-key metadata stay outside the first-staging blocker set
      and require future complete route slices.
- [x] Track future signer auth-method D1/DO coverage as route-slice work. This is
      a forward-looking test requirement and should not block first D1 staging
      after the first-staging scope is frozen.

Exit criteria:

- [x] `pnpm --dir packages/sdk-server-ts type-check` passes.
- [x] Local D1 adapter contract tests pass.
- [x] Local Wrangler/Miniflare smoke proves all required D1 tables exist.
- [x] Durable Object coordination tests pass for hot signer state.
- [x] First-staging signer auth scope is frozen, and deferred auth methods have
      named follow-up route slices.

Validation evidence:

- [x] `pnpm --dir tests exec playwright test -c playwright.relayer.config.ts
relayer/console-d1-adapters.test.ts --reporter=line` passed with 39 tests:
      all console and signer D1 migrations apply in order, constraint hardening
      rejects corrupt raw rows, and the D1 adapter contracts pass after removing
      the obsolete expectation that wallet metadata records carry `rpId`.
- [x] Added Cloudflare Durable Object export replay-guard coverage in
      `tests/relayer/threshold-ecdsa.durable-stores.test.ts`; this is a
      coverage-only Phase 5 addition with no superseded runtime path to delete in
      the same pass.
- [x] `pnpm --dir tests exec playwright test -c playwright.relayer.config.ts
relayer/threshold-ecdsa.durable-stores.test.ts --grep "Wallet Session export
replay guard|Cloudflare Durable Object" --reporter=line` passed with 5 tests
      passed.
- [x] `pnpm --dir tests exec playwright test -c playwright.unit.config.ts
unit/routerAbNormalSigningAdmissionStore.unit.test.ts
unit/walletSessionBudgetReservation.store.unit.test.ts
unit/thresholdPrf.cloudflareWorkerSigningRoot.script.unit.test.ts
unit/registrationCeremonyStore.unit.test.ts --reporter=line` passed with 29
      tests passed and 3 external-backend tests skipped.
- [x] `pnpm --dir tests exec playwright test -c playwright.unit.config.ts
unit/walletSessionBudgetReservation.store.unit.test.ts --reporter=line` passed
      after adding the Cloudflare Durable Object `consumeUseCountOnce` contract,
      with 11 tests passed and 2 external-backend tests skipped.
- [x] `pnpm --dir tests exec playwright test -c playwright.unit.config.ts
unit/refactor82CloudflareD1Runtime.guard.unit.test.ts --reporter=line` passed
      with 10 source-guard tests, including the core-orchestration domain-store
      port guard.
- [x] `pnpm --dir tests exec playwright test -c playwright.relayer.config.ts
relayer/console-d1-adapters.test.ts -g "prepaid-reservation migration|billing
reservations are trigger-atomic" --reporter=line` passed with 2 tests after
      prepaid reservation schema hardening and corrupt-row parser tightening.
- [x] `pnpm --dir tests exec playwright test -c playwright.relayer.config.ts
relayer/console-router.test.ts --grep "rejects Postgres tenant routes"
--reporter=line` passed, proving Cloudflare console routes reject Postgres tenant
      routes before route-owned persistence can run. `pnpm --dir tests exec
      playwright test -c playwright.unit.config.ts
      unit/refactor82CloudflareD1Runtime.guard.unit.test.ts --reporter=line`
      passed with 10 source-guard tests.
- [x] `pnpm --dir tests exec playwright test -c playwright.unit.config.ts
unit/cloudflareD1RouterApiAuthService.unit.test.ts --grep "reads signer metadata with
tenant scope" --reporter=line` passed, proving the D1 Router API auth service returns
      explicit ECDSA key-inventory diagnostics while threshold public-key metadata
      storage remains deferred. `pnpm --dir tests exec playwright test -c
      playwright.unit.config.ts unit/authService.ecdsaKeyIdentityInventory.unit.test.ts
      --reporter=line` passed after deleting the stale expectation that ECDSA
      threshold key metadata lookup receives `rpId`.
- [x] `pnpm --dir packages/sdk-web type-check` passes after updating Refactor 82
      D1/DO test fixtures to the current branded wallet/RP ID types, current
      D1 batch result shape, required registration-prepare route service branch,
      D1 observability ingestion metric contract, and sponsorship pricing quote
      contract.
- [x] `pnpm --dir tests exec playwright test -c playwright.unit.config.ts
unit/cloudflareD1RouterApiAuthService.unit.test.ts
unit/relayWalletRegistration.boundary.unit.test.ts
unit/cloudflareD1ConsoleServices.unit.test.ts --reporter=line` passed with 97
      tests.
- [x] `pnpm --dir tests exec playwright test -c playwright.relayer.config.ts
relayer/console-d1-adapters.test.ts --grep "observability adapter stores compact
D1 incident events and request rollups|webhook" --reporter=line` passed with 4
      focused D1 adapter tests.

### Phase 6: Deploy D1/DO Staging

Status: staging deployment. Phase 6 starts after Phase 3 boundary/coverage
closure, Phase 4 full local workflow proof, and Phase 5 first-staging test-scope
closure. This phase provisions and proves the real staging D1/DO data plane.

Work:

- [ ] Create or select the staging D1 console and signer databases and the staging
      Durable Object namespace using the approved Cloudflare account/project.
- [ ] Verify Ed25519 HSS ceremony persistence in staging: durable server-owned
      finalize state is stored in Durable Object storage, no process-local handles
      cross request boundaries, and no server private state is carried by client
      request/response payloads.
- [x] Add a credential-free staging Wrangler readiness gate that checks separate
      console and router-api Worker configs, rejects local Worker config, placeholder
      D1 IDs, missing/duplicate/unexpected profile D1 bindings, Postgres env
      tokens, signer/DO/KEK bindings on the console Worker, plaintext signer
      KEKs, plaintext sponsored-EVM executor config, plaintext session secrets,
      and missing hosted signer KEK Secrets Store bindings before remote
      migrations.
- [x] Add a credential-free staging deployment log/runbook generator that runs
      after the readiness gate and records the exact Wrangler command sequence,
      resource inventory, Time Travel bookmark files, fixture-import evidence,
      smoke results, R2 export/restore object keys, and sign-off checklist without
      storing secret values.
- [x] Add a resource inventory capture tool. It reuses readiness-clean console
      and router-api Wrangler profiles, records config-derived Worker names, D1
      database IDs, Durable Object bindings, Secrets Store metadata, required
      secret names, and remote D1/Worker JSON metadata without secret values.
- [x] Add a staging fixture-import tool for D1 SQL bundles. It reuses the
      readiness-clean console and router-api Wrangler profiles, validates data-only SQL,
      rejects schema DDL, rejects cross-domain console/signer table writes, writes
      fixture hashes to a manifest, and runs remote imports only through explicit
      `--mode remote`. Remote mode rejects failed Wrangler D1 import commands
      before writing a passing manifest.
- [x] Add a staging smoke evidence script for the actual unauthenticated staging
      readiness endpoints: `/console/readyz` on the console Worker, `/readyz`
      and `/healthz` on the router-api Worker, plus configured signer custody health
      routes `/router-ab/ed25519/healthz` and
      `/router-ab/ecdsa-hss/healthz`.
- [x] Add a Time Travel bookmark script for the console and signer D1 databases.
      It reuses readiness-clean staging configs, supports dry-run and remote
      modes, validates lower-snake purpose labels, writes console/signer bookmark
      JSON files, and records bookmark evidence in a manifest. Remote mode
      rejects failed Time Travel commands before trusting bookmark JSON evidence.
- [x] Add a hosted signer KEK metadata check. It reuses the readiness-clean router-api
      staging config, derives expected Cloudflare Secrets Store binding names,
      lists remote Secrets Store metadata, records only secret names/store IDs, and
      fails if a configured KEK secret name is absent.
- [x] Add a staging D1 migration apply tool. It reuses readiness-clean console
      and router-api Wrangler profiles, hashes local console/signer migration files,
      runs remote migration list/apply/list through explicit dry-run and remote
      modes, uses `CI=true` for noninteractive Wrangler apply, and writes command
      evidence to a manifest.
- [x] Add a read-only D1 reconciliation tool. It reuses readiness-clean staging
      configs, targets the selected staging tenant, validates dashboard billing
      balances, prepaid reservation summary totals, sponsored-EVM billing links,
      sponsored settlement amounts, and signer sealed-share KEK/lifecycle
      integrity, then writes mismatch evidence to a manifest.
- [x] Add a fixture-backed signer custody route drill. It calls only the
      production threshold route health endpoints and
      `/router-ab/ecdsa-hss/export/share`, reads the wallet-session JWT from an
      operator-selected environment variable, writes fixture hashes, and redacts
      wallet-session JWTs plus server export shares from evidence manifests.
- [x] Add a remote R2 export/restore drill script for the console and signer D1
      databases. It reuses readiness-clean staging configs, exports both D1
      databases, uploads the SQL exports to R2, downloads them into a restore
      workspace, creates timestamped restore-drill D1 databases, imports the
      downloaded SQL, runs `PRAGMA integrity_check`, and writes command/artifact
      evidence. Remote mode rejects failed export, upload, download, import, and
      integrity-check commands before writing a passing manifest.
- [x] Add a final Phase 6 evidence verifier. It reads the remote manifests from
      resource inventory, KEK metadata, migrations, Time Travel bookmarks,
      fixture import, staging smoke, reconciliation, signer custody, and R2
      restore drill; rejects dry-run manifests, failed commands, reconciliation
      mismatch rows, non-HTTPS remote Worker endpoint evidence, missing signer
      custody export-share evidence, missing missing-KEK fail-closed evidence,
      wrong endpoint paths/statuses, and incomplete restore artifacts; verifies
      the manifests share one staging environment, one console config, one router-api
      config, one tenant tuple, configured KEK secret-name evidence, and
      monotonic run ordering; then writes a compact verification summary.
- [x] Add a console-only D1 service-bundle factory for the staging dashboard
      Worker so console routes can be mounted with `CONSOLE_DB` only, without
      receiving signer metadata D1, Durable Object, or signer KEK bindings.
- [x] Add concrete Cloudflare staging Worker entrypoints:
      `src/router/cloudflare/d1ConsoleStagingWorker.ts` for console-only
      dashboard routes and `src/router/cloudflare/d1RouterApiStagingWorker.ts` for
      Router API/signer custody routes.
- [x] Re-run the current Refactor 82 runtime guard and staging-script static
      checks after the Router API rename and current worktree drift. Validation
      passed on June 29, 2026: `pnpm --dir tests exec playwright test -c
      playwright.unit.config.ts
      unit/refactor82CloudflareD1Runtime.guard.unit.test.ts --reporter=line`
      with 43 tests, and `node --check` for
      `packages/sdk-server-ts/scripts/d1-staging-*.mjs` plus
      `packages/sdk-server-ts/scripts/d1-local-backup-restore-drill.mjs`. This is
      pre-staging evidence only; the live Phase 6 tasks below stay open until the
      real staging Wrangler configs replace placeholder resource IDs and remote
      manifests are captured.
- [ ] Apply D1 migrations to staging.
- [ ] Configure the hosted signer KEK provider. Cloudflare Secrets Store is the
      default hosted provider; external KMS/HSM stays behind the signer-only KEK
      provider adapter.
- [x] Verify console routes cannot access signer KEKs through the static staging
      split: console-only D1 factory, console-only Wrangler profile, and source
      guard coverage.
- [ ] Import staging fixture data through D1/DO import tooling.
- [x] Add a local D1 backup/restore drill for console and signer databases.
- [ ] Capture D1 Time Travel bookmarks before imports and route changes.
- [ ] Run local smoke after the staging configs are copied from the templates and
      filled with real Cloudflare resource IDs and Wrangler secrets.
- [ ] Run staging smoke against deployed Worker bindings.
- [ ] Run dashboard reconciliation checks against staging data.
- [ ] Run sponsored-gas settlement and prepaid-billing reconciliation checks.
- [ ] Run fixture-backed signer custody checks, including encrypted secret
      read/write, KEK separation, and fail-closed missing-KEK behavior.
- [ ] Run remote R2 export/restore drills for console and signer D1 databases.
- [ ] Run the final evidence verifier and record staging resource IDs, migration
      versions, Time Travel bookmarks, R2 backup object keys, smoke results, and
      the verification summary in the deployment log.

Exit criteria:

- [ ] Staging starts on D1/DO.
- [ ] No request path mixes D1/DO and Postgres.
- [ ] Staging has Time Travel bookmarks captured before fixture import and before
      route traffic switch.
- [ ] Dashboard reconciliation, sponsored gas settlement, signer route health,
      fixture-backed custody checks, and restore drills pass before production
      planning begins.

Phase 6 staging-readiness decisions:

- The staging preflight command is `pnpm --dir packages/sdk-server-ts run
d1:staging:check`. It checks both
  `packages/sdk-server-ts/wrangler.d1-staging-console.toml` and
  `packages/sdk-server-ts/wrangler.d1-staging-router-api.toml`. Copy the matching
  `.example` files, keep the selected Worker entrypoints
  `src/router/cloudflare/d1ConsoleStagingWorker.ts` and
  `src/router/cloudflare/d1RouterApiStagingWorker.ts`, fill D1 database IDs,
  Cloudflare Secrets Store ID, relayer public key, and Wrangler secrets, then
  run the preflight before applying remote migrations.
- Console authentication is a separate console-session boundary. The console
  Worker verifies `console_session_v1` HMAC JWTs with
  `CONSOLE_SESSION_HMAC_SECRET`, then resolves dashboard roles from
  `CONSOLE_DB` Team RBAC plus explicit platform-admin email configuration. It
  leaves signer D1 app-session versions behind the Router API/signer Worker because
  the console Worker receives no `SIGNER_DB` binding.
- Hosted signer KEKs must use `SIGNING_ROOT_KEK_PROVIDER =
"cloudflare_secrets_store"` with `SIGNING_ROOT_KEK_IDS` mapped to
  `[[secrets_store_secrets]]` bindings. The Secrets Store binding name is the
  upper-snake version of the KEK id, for example
  `signing-root-kek-staging-r1` maps to `SIGNING_ROOT_KEK_STAGING_R1`.
  Sponsored-EVM executor config, Router API session HMAC secret, console session HMAC
  secret, and the account-id derivation secret must be declared under
  `[secrets].required`, never plaintext `[vars]`.
- The console/signer KEK isolation shape is selected. The console Worker receives
  `CONSOLE_DB` only and uses `createCloudflareD1ConsoleOnlyServiceBundle`.
  Router API signer-custody code receives `CONSOLE_DB`, `SIGNER_DB`,
  `THRESHOLD_STORE`, hosted signer KEKs, and Router API secrets. Console key-export
  routes create and approve metadata only; signer custody execution stays behind
  the Router API/signer profile.
- The live Phase 6 deployment log is generated only after static readiness passes:
  `pnpm --dir packages/sdk-server-ts run d1:staging:runbook -- --output
../../docs/deployment/refactor-82-staging-log.md --r2-bucket
<staging-r2-backup-bucket> --console-origin <https-console-staging-origin>
--router-api-origin <https-router-api-staging-origin>`. The generator fails closed if the
  console or Router API Wrangler profile fails the staging readiness gate, if the
  console/Router API origins are missing, non-HTTPS, or path-bearing, or if the R2
  bucket is missing or supplied as an object path. It then emits the verified
  Wrangler 4.105.0 command sequence for remote migrations, Time Travel bookmark
  capture, fixture import, Worker deploy, staging smoke, and R2 export/restore
  drills.
- Resource inventory capture uses
  `pnpm --dir packages/sdk-server-ts run d1:staging:resources`. Run `--mode
dry-run` first to record config-derived resource IDs and exact remote metadata
  commands, then `--mode remote` to record `wrangler d1 info --json` and
  `wrangler deployments status --json` output. Secrets Store evidence remains
  metadata-only; the inventory records secret names and binding names, never
  secret values.
- Staging D1 migration apply uses
  `pnpm --dir packages/sdk-server-ts run d1:staging:migrate`. The first run must
  be `--mode dry-run` to record the migration file hashes and exact Wrangler
  list/apply/list commands. The live run uses `--mode remote`; apply commands run
  with `CI=true` so Wrangler skips the interactive confirmation path while still
  taking its automatic D1 backup after apply.
- Time Travel bookmark capture uses
  `pnpm --dir packages/sdk-server-ts run d1:staging:bookmark`. For each purpose,
  run `--mode dry-run` first, then `--mode remote`: use
  `--purpose before_fixture_import` before fixture import and
  `--purpose before_route_switch` before route changes. The script captures console
  and signer D1 bookmarks with `wrangler d1 time-travel info`, writes bookmark JSON
  files under `.wrangler/d1-staging-bookmarks`, and records a manifest for the
  deployment log.
- Hosted signer KEK metadata checks use
  `pnpm --dir packages/sdk-server-ts run d1:staging:kek-check`. Run
  `--mode dry-run` first, then `--mode remote`. The script parses
  `SIGNING_ROOT_KEK_IDS` and `[[secrets_store_secrets]]` from the Router API
  staging config, lists remote Cloudflare Secrets Store metadata, and records only
  KEK ids, binding names, store IDs, secret names, and command status. Do not
  retrieve or record secret values in the Phase 6 deployment log.
- Staging D1 fixture import uses
  `pnpm --dir packages/sdk-server-ts run d1:staging:import-fixtures`. The first
  run must be `--mode dry-run` to produce the manifest and exact Wrangler import
  commands; the live run uses `--mode remote` after the pre-import Time Travel
  bookmarks are recorded. Fixture SQL is validated against table allowlists
  derived from the checked-in D1 migrations: console fixtures may touch only
  `migrations/d1-console` tables such as `organizations`, and signer fixtures may
  touch only `migrations/d1-signer` tables such as `wallets`. Durable Object
  fixture state must enter through a router-api Worker route or typed staging
  admin tool. Remote mode fails closed on the first nonzero Wrangler command
  status.
- Staging readiness smoke uses
  `pnpm --dir packages/sdk-server-ts run d1:staging:smoke`. Run `--mode dry-run`
  first, then `--mode remote`, with `--console-origin
  <https-console-staging-origin>` and `--router-api-origin
  <https-router-api-staging-origin>`. The console Worker does not expose a root `/readyz`;
  the canonical console readiness route is `/console/readyz`. The router-api Worker
  owns root `/readyz` and `/healthz`. The same smoke manifest also checks
  `/router-ab/ed25519/healthz` and `/router-ab/ecdsa-hss/healthz` and requires
  both signer custody routes to report `configured: true`. Remote smoke mode
  requires HTTPS console and Router API origins; HTTP origins are dry-run/local
  planning only.
- Read-only D1 reconciliation uses
  `pnpm --dir packages/sdk-server-ts run d1:staging:reconcile`. Run
  `--mode dry-run` first to record the exact remote D1 `SELECT` commands, then
  `--mode remote` after staging smoke passes. The script must return zero rows
  for every mismatch query before dashboard reconciliation and sponsored billing
  are considered clean. The signer checks verify persisted sealed-share KEK and
  lifecycle integrity only.
- Fixture-backed signer custody drills use
  `pnpm --dir packages/sdk-server-ts run d1:staging:signer-custody`. Run
  `--mode dry-run` first with `--router-api-origin` and `--export-share-fixture
./staging/fixtures/ecdsa-export-share.json`, plus
  `--missing-kek-fixture ./staging/fixtures/ecdsa-export-share-missing-kek.json`,
  `--missing-kek-wallet-session-jwt-env
SEAMS_STAGING_MISSING_KEK_WALLET_SESSION_JWT`,
  `--missing-kek-expected-status 503`, and
  `--missing-kek-expected-code missing_signing_root_kek`; then set
  `SEAMS_STAGING_ECDSA_WALLET_SESSION_JWT` to a fresh fixture wallet-session JWT
  and `SEAMS_STAGING_MISSING_KEK_WALLET_SESSION_JWT` to a fresh fixture
  wallet-session JWT for the staging variant that deliberately omits the selected
  KEK binding, then run `--mode remote` with the same arguments. The script
  checks the configured Ed25519 and ECDSA threshold health endpoints, posts the
  happy-path fixture body to `/router-ab/ecdsa-hss/export/share`, requires
  `ok: true` with `value.serverExportShare32B64u`, posts the missing-KEK fixture
  body to the same production route, requires the configured 503
  `ok: false` failure with code `missing_signing_root_kek`, and redacts JWTs plus server export shares from the
  manifest. Remote signer-custody mode requires an HTTPS Router API origin and an
  HTTPS request `Origin` header when `--origin` is provided. The final evidence
  verifier requires `ecdsa_export_share_missing_kek_fail_closed` in the signer
  custody manifest.
- Remote R2 restore drills use
  `pnpm --dir packages/sdk-server-ts run d1:staging:r2-restore-drill`. Run
  `--mode dry-run` first to record timestamped export paths, R2 object keys, and
  restore database names, then `--mode remote` to perform the D1 export, R2
  upload/download, restore database import, and integrity checks. The script
  writes its manifest under
  `packages/sdk-server-ts/.wrangler/d1-staging-r2-restore-drills`. Remote mode
  fails closed on the first nonzero Wrangler command status.
- Final Phase 6 evidence verification uses
  `pnpm --dir packages/sdk-server-ts run d1:staging:evidence`. Pass the remote
  manifest paths from resource inventory, KEK metadata, migrations, both Time
  Travel bookmark captures, fixture import, staging smoke, reconciliation, signer
  custody, and R2 restore drill. The verifier rejects dry-run manifests, failed
  commands, reconciliation mismatch rows, missing signer custody export-share
  evidence, missing missing-KEK fail-closed evidence, wrong custody endpoint
  paths/statuses, incomplete restore artifacts, mixed staging environments,
  mixed Wrangler config paths, tenant tuple drift, configured KEKs missing from
  Secrets Store evidence, and out-of-order run manifests, then writes
  `.wrangler/d1-staging-evidence/verification.json`.

Validation evidence:

- [x] Added `packages/sdk-server-ts/scripts/d1-staging-readiness-check.mjs`,
      `packages/sdk-server-ts/wrangler.d1-staging-console.toml.example`,
      `packages/sdk-server-ts/wrangler.d1-staging-router-api.toml.example`, and
      `pnpm --dir packages/sdk-server-ts run d1:staging:check`.
- [x] Gitignored the concrete staging Wrangler configs
      `packages/sdk-server-ts/wrangler.d1-staging-console.toml` and
      `packages/sdk-server-ts/wrangler.d1-staging-router-api.toml` while keeping
      the `.example` templates tracked. This lets Phase 6 operators copy and fill
      real Cloudflare resource IDs without accidentally adding environment
      configs to source control. The Refactor 82 guard now checks the ignore
      entries, and direct `git check-ignore -v` confirms both concrete paths are
      ignored.
- [x] Added `packages/sdk-server-ts/scripts/d1-staging-runbook.mjs`,
      `pnpm --dir packages/sdk-server-ts run d1:staging:runbook`, and
      `docs/deployment/refactor-82-staging-log.md` so Phase 6 has a
      credential-free deployment log, resource inventory, exact command runbook,
      and evidence checklist before live staging work starts. The runbook
      generator now rejects missing placeholder endpoints, non-HTTPS origins, and
      R2 object paths before writing the deployment log. Follow-up hardening made
      the signer-custody drill commands explicit about both JWT env bindings and
      the console request `Origin`, so operators do not depend on script defaults
      for the success export-share JWT or miss the cross-origin route behavior.
- [x] Added `packages/sdk-server-ts/scripts/d1-staging-resource-inventory.mjs`
      and `pnpm --dir packages/sdk-server-ts run d1:staging:resources` so Phase
      6 can capture config-derived resource IDs, remote D1 info JSON, Worker
      deployment status JSON, Durable Object binding metadata, and Secrets Store
      metadata without recording secret values. Remote inventory now rejects
      failed Wrangler metadata commands and empty Wrangler JSON output before
      writing a passing manifest. Validation passed: `pnpm --dir tests exec
      playwright test -c playwright.unit.config.ts
      unit/d1StagingResourceInventory.script.unit.test.ts --reporter=line` with
      6 tests, `node --check
      packages/sdk-server-ts/scripts/d1-staging-resource-inventory.mjs`, `pnpm
      --dir tests exec tsc -p tsconfig.playwright.json --noEmit`, and `git diff
      --check`.
- [x] Added `packages/sdk-server-ts/scripts/d1-staging-fixture-import.mjs` and
      `pnpm --dir packages/sdk-server-ts run d1:staging:import-fixtures` so Phase
      6 fixture import has a dry-run manifest, remote import mode, readiness
      gating, fixture hash recording, and data-only console/signer table checks.
- [x] Added `packages/sdk-server-ts/scripts/d1-staging-smoke.mjs` and
      `pnpm --dir packages/sdk-server-ts run d1:staging:smoke` so Phase 6 can
      capture readiness evidence from the real console and Router API staging
      endpoints after deploy, including threshold Ed25519 and ECDSA signer route
      health configured checks.
      Validation passed: `pnpm --dir tests exec playwright test -c
playwright.unit.config.ts unit/d1StagingSmoke.script.unit.test.ts
--reporter=line`; the full Phase 6 staging script cluster with 44 tests;
      `pnpm --dir tests exec tsc -p tsconfig.playwright.json --noEmit`; Node
      `--check` for `packages/sdk-server-ts/scripts/d1-staging-*.mjs`; `git diff
--check`; and a dry-run smoke CLI with console/router-api example origins.
- [x] Added `packages/sdk-server-ts/scripts/d1-staging-time-travel-bookmark.mjs`
      and `pnpm --dir packages/sdk-server-ts run d1:staging:bookmark` so Phase 6
      bookmark capture has dry-run planning, remote execution, readiness gating,
      lower-snake purpose validation, console/signer bookmark JSON files, and
      manifest evidence. Remote mode now parses bookmark artifact JSON before
      writing a passing manifest and rejects status-0 output that lacks a usable
      non-placeholder bookmark value. Deletion pass: the bookmark JSON collector
      now lives in the shared staging config helper and the duplicate
      final-verifier collector was removed. Validation passed: `pnpm --dir tests
      exec playwright test -c playwright.unit.config.ts
      unit/d1StagingTimeTravelBookmark.script.unit.test.ts
      unit/d1StagingEvidenceVerify.script.unit.test.ts --reporter=line` with 61
      tests, `node --check packages/sdk-server-ts/scripts/d1-staging-config.mjs`,
      `node --check
      packages/sdk-server-ts/scripts/d1-staging-time-travel-bookmark.mjs`, `node
      --check packages/sdk-server-ts/scripts/d1-staging-evidence-verify.mjs`,
      `pnpm --dir tests exec tsc -p tsconfig.playwright.json --noEmit`, and
      `git diff --check`.
- [x] Added `packages/sdk-server-ts/scripts/d1-staging-kek-check.mjs` and
      `pnpm --dir packages/sdk-server-ts run d1:staging:kek-check` so hosted
      signer KEK setup has dry-run planning, remote metadata verification,
      exact Secrets Store secret-name presence checks, failed remote-command
      rejection, and metadata-only manifests. The checker parses JSON-shaped and
      current Wrangler text/table output into explicit secret-name sets, so
      substring-only names cannot satisfy KEK readiness.
- [x] Added `packages/sdk-server-ts/scripts/d1-staging-migrate.mjs` and
      `pnpm --dir packages/sdk-server-ts run d1:staging:migrate` so remote D1
      migration application has dry-run planning, local migration hash evidence,
      readiness gating, noninteractive remote apply commands, and command
      manifests. Remote migration now rejects failed list/apply/list commands
      before writing a clean migration manifest.
- [x] Added `packages/sdk-server-ts/scripts/d1-staging-reconciliation.mjs` and
      `pnpm --dir packages/sdk-server-ts run d1:staging:reconcile` so dashboard
      billing reconciliation, sponsored-EVM prepaid billing linkage, settlement
      amount matching, and signer sealed-share metadata integrity have dry-run
      planning, remote read-only D1 checks, mismatch failure behavior, and
      failed remote-command rejection before writing clean command manifests.
      Remote reconciliation now also rejects empty Wrangler JSON output instead
      of treating it as zero mismatch rows. Validation passed: `pnpm --dir tests
      exec playwright test -c playwright.unit.config.ts
      unit/d1StagingResourceInventory.script.unit.test.ts
      unit/d1StagingReconciliation.script.unit.test.ts --reporter=line` with 13
      tests, `node --check
      packages/sdk-server-ts/scripts/d1-staging-resource-inventory.mjs`, `node
      --check packages/sdk-server-ts/scripts/d1-staging-reconciliation.mjs`,
      `pnpm --dir tests exec tsc -p tsconfig.playwright.json --noEmit`, and
      `git diff --check`.
- [x] Added `packages/sdk-server-ts/scripts/d1-staging-signer-custody.mjs` and
      `pnpm --dir packages/sdk-server-ts run d1:staging:signer-custody` so
      fixture-backed signer custody route drills have dry-run planning, remote
      route execution, JWT-from-env handling, production route allowlisting,
      configured threshold health checks, export-share presence assertions,
      HTTPS remote-origin validation, required missing-KEK fail-closed
      assertions, and redacted manifests.
      Validation passed: `pnpm --dir tests exec playwright test -c
playwright.unit.config.ts unit/d1StagingSignerCustody.script.unit.test.ts
--reporter=line`; the full Phase 6 staging script cluster with 48 tests;
      `pnpm --dir tests exec tsc -p tsconfig.playwright.json --noEmit`; Node
      `--check` for `packages/sdk-server-ts/scripts/d1-staging-*.mjs`; `git diff
--check`; and a dry-run signer-custody CLI with a temporary export-share
      fixture.
- [x] Aligned the SDK server staging README with the signer-custody runbook. The
      README now shows the success export-share fixture, the missing-KEK fixture,
      both wallet-session JWT env bindings, the console request `Origin`, and the
      expected `503` `missing_signing_root_kek` result required by final evidence
      verification. The README final-evidence command now also writes the same
      `.wrangler/d1-staging-evidence/verification.json` output path as the
      runbook. The Refactor 82 guard now checks that this README cannot drift
      back to default-JWT or success-only custody evidence. Validation passed:
      `pnpm --dir tests exec playwright test -c
      playwright.unit.config.ts unit/refactor82CloudflareD1Runtime.guard.unit.test.ts
      --reporter=line` with 46 tests passing, `pnpm --dir tests exec tsc -p
      tsconfig.playwright.json --noEmit`, and `git diff --check`.
- [x] Tightened final-evidence runbook coverage. The runbook test now asserts
      every required final evidence manifest flag: resource inventory, KEK check,
      migrations, both Time Travel bookmarks, fixture import, staging smoke,
      reconciliation, signer custody, and R2 restore drill. The SDK server README
      summary now names the same missing-KEK, custody endpoint, staging
      environment, configured KEK, and restore-artifact rejection classes as the
      verifier. Follow-up coverage now asserts that the generated command
      sequence runs the readiness preflight before resource inventory capture,
      and that resource inventory still runs before remote migrations. Validation
      passed: `pnpm --dir tests exec playwright test -c
      playwright.unit.config.ts unit/d1StagingRunbook.script.unit.test.ts
      --reporter=line` with 6 tests passing, `node --check
      packages/sdk-server-ts/scripts/d1-staging-runbook.mjs`, `pnpm --dir tests
      exec tsc -p tsconfig.playwright.json --noEmit`, and `git diff --check`.
- [x] Reconciled the Phase 6 fixture-import decision text with the implemented
      importer. The plan now describes migration-derived table allowlists from
      `migrations/d1-console` and `migrations/d1-signer`, matching
      `d1-staging-fixture-import.mjs`; it no longer describes obsolete
      `console_`/`signer_` prefix-only fixture scopes. The Refactor 82 guard now
      blocks that stale wording from returning. Validation passed: `pnpm --dir
      tests exec playwright test -c playwright.unit.config.ts
      unit/refactor82CloudflareD1Runtime.guard.unit.test.ts --reporter=line` with
      47 tests passing, `pnpm --dir tests exec tsc -p
      tsconfig.playwright.json --noEmit`, and `git diff --check`.
- [x] Aligned the SDK server staging README and Phase 6 decision text with the
      generated runbook's dry-run discipline for Phase 6 commands. Time Travel
      bookmarks, fixture import, KEK metadata checks, and staging smoke now show
      or describe dry-run commands before remote execution, so operators preview
      the exact command shape before mutating staging or trusting endpoint
      evidence. The Refactor 82 guard now checks these README snippets.
      Validation passed: `pnpm --dir tests exec playwright test -c
      playwright.unit.config.ts unit/refactor82CloudflareD1Runtime.guard.unit.test.ts
      --reporter=line` with 48 tests passing, `pnpm --dir tests exec tsc -p
      tsconfig.playwright.json --noEmit`, and `git diff --check`.
- [x] Hardened signer-custody evidence redaction before live staging. Response
      body field names are normalized before redaction, so camelCase and
      snake_case spellings of server export shares, private keys, signing shares,
      authorization headers, JWTs, and tokens are replaced with `<redacted>` in
      manifests. The signer-custody script test now returns multiple
      secret-shaped spellings from the fake export-share endpoint and proves none
      are persisted. Validation passed:
      `./node_modules/.bin/playwright test -c playwright.source.config.ts
unit/d1StagingSignerCustody.script.unit.test.ts --reporter=line` with 6
      tests, the full `unit/d1Staging*.script.unit.test.ts` cluster with 84
      tests, and `git diff --check`.
- [x] Hardened the final Phase 6 evidence verifier against unredacted
      signer-custody response bodies. The verifier now recursively scans
      `signer_custody.results[].body`, normalizes sensitive field names, accepts
      only `<redacted>` for server export shares, private keys, signing shares,
      authorization headers, JWTs, and tokens, and fails the run if a raw value
      appears in a remote manifest. Validation passed:
      `node --check packages/sdk-server-ts/scripts/d1-staging-evidence-verify.mjs`,
      `./node_modules/.bin/playwright test -c playwright.source.config.ts
unit/d1StagingEvidenceVerify.script.unit.test.ts --reporter=line` with 19
      tests, the full `unit/d1Staging*.script.unit.test.ts` cluster with 85
      tests, and `git diff --check`.
- [x] Hardened the final Phase 6 evidence verifier against mixed Router API origins.
      The verifier now derives the canonical Router API origin from
      `staging_smoke.checks.router_api_readyz.url`, requires the other router-api-owned
      smoke checks to share it, and requires every `signer_custody.results[].url`
      to use that same origin. This prevents combining a signer-custody manifest
      from another deployed router-api with otherwise valid staging evidence.
      Validation passed:
      `node --check packages/sdk-server-ts/scripts/d1-staging-evidence-verify.mjs`,
      `./node_modules/.bin/playwright test -c playwright.source.config.ts
unit/d1StagingEvidenceVerify.script.unit.test.ts --reporter=line` with 20
      tests, the full `unit/d1Staging*.script.unit.test.ts` cluster with 86
      tests, and `git diff --check`.
- [x] Hardened the final Phase 6 evidence verifier against shared console/router-api
      smoke origins. The verifier now requires `staging_smoke.checks.console_readyz`
      and `staging_smoke.checks.router_api_readyz` to come from distinct Worker
      origins, so the final evidence cannot prove both readiness checks against a
      single deployed Worker. Validation passed:
      `node --check packages/sdk-server-ts/scripts/d1-staging-evidence-verify.mjs`,
      `pnpm --dir tests exec playwright test -c playwright.unit.config.ts
      unit/d1StagingEvidenceVerify.script.unit.test.ts --reporter=line` with 54
      tests, and `git diff --check`.
- [x] Hardened the final Phase 6 evidence verifier against evidence IDs pointed
      at the wrong endpoint paths. Smoke evidence must now use the exact
      `/console/readyz`, `/readyz`, `/healthz`,
      `/router-ab/ed25519/healthz`, and `/router-ab/ecdsa-hss/healthz` paths.
      Signer-custody evidence must now use the exact threshold health paths and
      `/router-ab/ecdsa-hss/export/share`, with no query string or fragment.
      This prevents a manifest from proving a generic healthy route while
      claiming signer-custody or readiness evidence. Validation passed:
      `node --check packages/sdk-server-ts/scripts/d1-staging-evidence-verify.mjs`,
      `./node_modules/.bin/playwright test -c playwright.source.config.ts
unit/d1StagingEvidenceVerify.script.unit.test.ts --reporter=line` with 22
      tests, the full `unit/d1Staging*.script.unit.test.ts` cluster with 88
      tests, and `git diff --check`.
- [x] Hardened the final Phase 6 evidence verifier against HTTP status drift.
      Smoke evidence and required signer-custody evidence must now carry the
      exact status code produced by the staging scripts: 200 for console
      readiness, router-api readiness, router-api health, threshold health, and the ECDSA
      export-share success check. This prevents a manifest from passing with
      `ok: true` while hiding a non-200 response. Validation passed:
      `node --check packages/sdk-server-ts/scripts/d1-staging-evidence-verify.mjs`,
      `./node_modules/.bin/playwright test -c playwright.source.config.ts
unit/d1StagingEvidenceVerify.script.unit.test.ts --reporter=line` with 24
      tests, the full `unit/d1Staging*.script.unit.test.ts` cluster with 90
      tests, and `git diff --check`.
- [x] Hardened the final Phase 6 evidence verifier against pre-mutation evidence
      captured out of order. The verifier now includes resource inventory and
      hosted signer KEK metadata in the ordered evidence chain before remote D1
      migrations, so final staging evidence cannot pass if the supposedly
      pre-change resource/secret metadata was captured after mutations started.
      Validation passed: `pnpm --dir tests exec playwright test -c
      playwright.unit.config.ts unit/d1StagingEvidenceVerify.script.unit.test.ts
      --reporter=line` with 55 tests, `node --check
      packages/sdk-server-ts/scripts/d1-staging-evidence-verify.mjs`, `pnpm
      --dir tests exec tsc -p tsconfig.playwright.json --noEmit`, and `git diff
      --check`.
- [x] Made the missing-KEK signer-custody drill mandatory final evidence. The
      verifier now requires `ecdsa_export_share_missing_kek_fail_closed`, checks
      that it uses the production export-share route, requires a 4xx/5xx
      fail-closed status with `body.ok === false`, and still applies router-api-origin
      and redaction checks. The generated runbook now includes the missing-KEK
      fixture, JWT env var, expected status, and expected error-code flags in the
      required signer-custody commands. Validation passed:
      `node --check packages/sdk-server-ts/scripts/d1-staging-evidence-verify.mjs`,
      `node --check packages/sdk-server-ts/scripts/d1-staging-signer-custody.mjs`,
      `node --check packages/sdk-server-ts/scripts/d1-staging-runbook.mjs`,
      `./node_modules/.bin/playwright test -c playwright.source.config.ts
unit/d1StagingEvidenceVerify.script.unit.test.ts
unit/d1StagingSignerCustody.script.unit.test.ts
unit/d1StagingRunbook.script.unit.test.ts --reporter=line` with 39 tests,
      the full `unit/d1Staging*.script.unit.test.ts` cluster with 93 tests,
      `git diff --check`, and a direct trailing-whitespace scan over the touched
      tracked and untracked files. Follow-up validation cleanup added the test
      package's own `node_modules` to `tests/tsconfig.playwright.json`
      `typeRoots`, routed the `sonner` smoke-test import to the site app
      dependency, and removed VoiceID's direct `express-serve-static-core` type
      import in favor of the minimal Express request/response shape the adapter
      consumes. `pnpm --dir tests exec tsc -p tsconfig.playwright.json
--noEmit` now passes; `pnpm -C voiceId test` passes with 127 tests. `pnpm
-C voiceId type-check` still fails on broader SDK-server exact-optional and
      shared-alias errors outside this Phase 6 evidence slice.
- [x] Deleted remaining active Relay-era naming from the Router API staging
      surface. Runtime/test strings now say `Cloudflare D1 Router API auth
service`; VoiceID's current server adapter moved from
      `voiceId/server/src/sdkRelayExtension.ts` to
      `voiceId/server/src/sdkRouterApiExtension.ts`; the VoiceID route adapter
      type/function names now use `RouterApi`; and the stale-name guard now scans
      the active Router API source, VoiceID adapter, VoiceID README, and focused
      unit tests for the old names. Follow-up cleanup renamed the web-server
      startup log and local auth-meter variables from Relay-era names to Router
      API names. Follow-up cleanup renamed
      `tests/relayer/router-api-api-keys.test.ts` to
      `tests/relayer/router-api-keys.test.ts`, updated its fixture IDs, and added
      a guard for the old test filename. The guard now scans `apps/web-server/src`
      for the stale rename tokens. A later cleanup replaced the stale validation
      command in
      `docs/saas/billing-cleanup.md` that still pointed at deleted live-Postgres
      relayer suites and the removed Router API key test filename; the guard now
      rejects those obsolete validation paths in that doc. Follow-up cleanup
      replaced stale `Router API` wording in the active Router API options comment
      and self-hosted migration doc, and the stale-name guard now rejects
      `Router API key` / `Router API key` wording in active Router API surfaces.
      Follow-up cleanup renamed the signing-session-seal keygen output block from
      `Relay server / worker env` to `Router API / worker env` and extended the
      stale-name guard to scan `apps/web-server/scripts`, so active app scripts do
      not revive old Relay-era operator wording. Follow-up validation passed:
      `node --check
      apps/web-server/scripts/generate-signing-session-seal-keys.mjs`,
      `pnpm --dir tests exec playwright test -c playwright.unit.config.ts
      unit/refactor82CloudflareD1Runtime.guard.unit.test.ts --reporter=line`
      with 43 tests, `pnpm --dir tests exec tsc -p
      tsconfig.playwright.json --noEmit`, `git diff --check`, and a direct scan
      proving the old label remains only in the guard's forbidden-token list.
      Follow-up cleanup also replaced the active SDK web README example host
      `router-api-server.example.com` with `router-api.example.com` while preserving
      the public `relayer.url` config field. The stale-name guard now scans
      `packages/sdk-web/README.md` and rejects the old example host. Validation
      passed: `pnpm --dir tests exec playwright test -c
      playwright.unit.config.ts unit/refactor82CloudflareD1Runtime.guard.unit.test.ts
      --reporter=line` with 43 tests, `pnpm --dir tests exec tsc -p
      tsconfig.playwright.json --noEmit`, `git diff --check`, and a direct scan
      proving `router-api-server.example.com` remains only in the guard's
      forbidden-token list.
      Follow-up cleanup aligned the active BYO Auth docs with Router API
      terminology. `docs/auth-provider-integrations/{auth0,better-auth,google-oidc,okta,quickstarts-clerk-supabase-firebase}.md`
      now use `createRouterApiSession*` examples and `ROUTER_API_BASE_URL`;
      `docs/saas/bring-you-own-auth.md` now describes Router API session
      exchange/setup/webhooks while preserving the SDK's current `relayUrl`
      public option name. The stale-name guard now scans the auth-provider
      integration docs and rejects `createRelaySession`, `RELAY_BASE_URL`, and
      `router-api app sessions`. Validation passed: direct scans over those docs for
      `createRelaySession`, `RELAY_BASE_URL`, `router-api app sessions`, and
      standalone Relay/router-api wording; `pnpm --dir tests exec playwright test -c
      playwright.unit.config.ts unit/refactor82CloudflareD1Runtime.guard.unit.test.ts
      --reporter=line` with 43 tests; `pnpm --dir tests exec tsc -p
      tsconfig.playwright.json --noEmit`; and `git diff --check`.
      Follow-up cleanup aligned the active API-key plan and SDK-facing example
      comments: `docs/saas/api-keys.md` now names Router API for credential
      enforcement, broker redemption, bootstrap-token redemption, testing
      parity, and self-hosted deployment notes; the server-only curl example now
      uses `https://router-api.example.com`; and SDK comments in
      `packages/sdk-web/src/react/types.ts` and
      `packages/sdk-web/src/core/types/signer-worker.ts` now describe the Router
      API server while preserving current `relayer`/`relayerUrl` field names.
      The stale-name guard now scans the API-key doc and rejects
      `router-api.example.com` plus `relayer server`. Validation passed: focused
      stale scans over the API-key doc and touched SDK comments; `pnpm --dir
      tests exec playwright test -c playwright.unit.config.ts
      unit/refactor82CloudflareD1Runtime.guard.unit.test.ts --reporter=line`
      with 43 tests; `pnpm --dir tests exec tsc -p tsconfig.playwright.json
      --noEmit`; and `git diff --check`.
      Follow-up cleanup extended the same stale-host guard to the Rust
      `wasm/near_signer/src/types/signing.rs` threshold signer config comment,
      replacing the old `relayer server` / `https://router-api.example.com` example
      with Router API wording and `https://router-api.example.com`. Validation
      passed: focused scan for `router-api.example.com` and `relayer server` over the
      touched active surfaces, the Refactor 82 guard with 43 tests, and
      `git diff --check`.
      Follow-up cleanup removed stale Relay-era wording from active Router API
      runtime/operator surfaces. Router API bootstrap-grant, webhook, and signed
      delegate logs now use `[router-api][...]` tags; the signed-delegate
      sponsorship route tags now use `router-api][signed-delegate`; Router API
      route, publishable-key auth, Ed25519 registration, warm-session
      reconstruction, WebAuthn, and SDK session comments/messages now describe
      Router API. The stale-name guard now rejects the old log tags and exact
      phrases including `router-api usage-meter`, `router-api-issued sessions`,
      `prepared router-api state`, `router-api metadata`, `router-api verification`,
      `router-api publishable key auth`, `router-api app session mint`, `sent to the router-api`,
      `override Router API URL`, and `must use Router API surface`. Validation passed:
      focused stale scans over `packages/sdk-server-ts/src` and
      `packages/sdk-web/src`, `pnpm --dir tests exec playwright test -c
      playwright.unit.config.ts unit/refactor82CloudflareD1Runtime.guard.unit.test.ts
      --reporter=line` with 43 tests, `pnpm --dir tests exec tsc -p
      tsconfig.playwright.json --noEmit`, `pnpm --dir packages/sdk-server-ts
      type-check`, `pnpm --dir packages/sdk-web type-check`, and
      `git diff --check`.
      Follow-up cleanup removed the live `RELAY_API_KEY_AUTH_ENABLED` app-server
      flag. `apps/web-server/src/index.ts`, `apps/web-server/.env.example`, and
      `apps/web-server/README.md` now use `ROUTER_API_KEY_AUTH_ENABLED` only,
      with no fallback alias for the old env name. The stale-name guard now scans
      `apps/web-server/.env.example` and rejects `RELAY_API_KEY_AUTH_ENABLED`.
      Validation passed: hidden-file scan proving the old env var remains only in
      the guard deny-list, `pnpm --dir tests exec playwright test -c
      playwright.unit.config.ts unit/refactor82CloudflareD1Runtime.guard.unit.test.ts
      --reporter=line` with 43 tests, `pnpm --dir tests exec tsc -p
      tsconfig.playwright.json --noEmit`, `pnpm -s type-check:router-server`,
      and `git diff --check`.
      Validation passed:
      `pnpm --dir tests exec playwright test -c playwright.unit.config.ts
unit/refactor82CloudflareD1Runtime.guard.unit.test.ts
unit/cloudflareD1ConsoleServices.unit.test.ts
unit/cloudflareD1RouterApiAuthService.unit.test.ts --reporter=line` with
      58 tests, `pnpm -C voiceId test` with 127 tests, `pnpm --dir tests exec
tsc -p tsconfig.playwright.json --noEmit`, `git diff --check`, and focused
      stale-name scans.
- [x] Replaced stale gas-sponsorship prepaid-billing implementation notes that
      still pointed at the old simple-threshold-signer workspace, server-local
      Postgres adapters, Postgres settlement wording, and `examples/seams-site`
      dashboard paths. The doc now describes the current D1/SQLite atomic
      settlement path, current `packages/sdk-server-ts` console/router modules,
      and current `apps/seams-site` billing surfaces. The Refactor 82 guard now
      rejects those stale sponsorship/prepaid doc strings so the old Postgres
      settlement story cannot return. Validation passed:
      `pnpm --dir tests exec playwright test -c playwright.unit.config.ts
unit/refactor82CloudflareD1Runtime.guard.unit.test.ts --reporter=line` with 30
      tests, `pnpm --dir tests exec tsc -p tsconfig.playwright.json --noEmit`,
      `git diff --check`, plus a direct targeted `rg` scan for the stale absolute
      path, Postgres adapter paths, and Postgres settlement/index wording.
- [x] Replaced stale gas-and-signing policy doc links that still pointed at the
      old simple-threshold-signer workspace and `server/src` tree. The doc now
      links to the current `packages/sdk-server-ts/src` policy, gas-sponsorship,
      runtime snapshot, console-router, and EVM sponsorship modules. The Refactor
      82 guard now rejects old absolute workspace links plus `server/src` and
      `examples/seams-site` link targets in that doc. Validation passed:
      `pnpm --dir tests exec playwright test -c playwright.unit.config.ts
unit/refactor82CloudflareD1Runtime.guard.unit.test.ts --reporter=line` with 31
      tests, `pnpm --dir tests exec tsc -p tsconfig.playwright.json --noEmit`,
      `git diff --check`, plus a direct targeted `rg` scan for the stale absolute
      path and old link targets.
- [x] Replaced stale billing follow-up and canonical prepaid-billing doc wording
      that still described the active billing path as Postgres-backed. The current
      docs now use local relative links, describe ledger accounts/postings and
      projection rebuilds as backend-neutral current behavior, and keep D1 adapter
      validation as the remaining backend-specific work. The Refactor 82 guard now
      rejects old simple-threshold-signer absolute links and active
      `Postgres billing` wording in those two current billing docs. Validation
      passed: `pnpm --dir tests exec playwright test -c playwright.unit.config.ts
unit/refactor82CloudflareD1Runtime.guard.unit.test.ts --reporter=line` with 32
      tests, `pnpm --dir tests exec tsc -p tsconfig.playwright.json --noEmit`,
      `git diff --check`, plus a direct targeted `rg` scan for the stale absolute
      links and active Postgres billing phrases.
- [x] Consolidated the Refactor 82 guard's repeated current-doc stale-pattern
      scanners into one shared helper. Billing cleanup, current billing,
      gas-sponsorship prepaid, and gas-and-signing policy doc guards now share the
      same boundary scanner instead of each carrying its own read/loop body.
      Validation passed: `pnpm --dir tests exec playwright test -c
playwright.unit.config.ts unit/refactor82CloudflareD1Runtime.guard.unit.test.ts
--reporter=line` with 32 tests, `pnpm --dir tests exec tsc -p
tsconfig.playwright.json --noEmit`, and `git diff --check`.
- [x] Replaced stale policy-engine plan references that still described current
      policy storage as Postgres-backed and pointed at deleted
      `server/src/**/postgres.ts` paths. The doc now names D1 policy storage,
      current `packages/sdk-server-ts` policy/gas-sponsorship modules, current
      `apps/seams-site` dashboard paths, and local relative sponsorship-policy
      links. The Refactor 82 guard now rejects old absolute workspace links,
      `server/src` / `examples/seams-site` link targets, and active
      Postgres-policy-storage wording in that doc. Validation passed:
      `pnpm --dir tests exec playwright test -c playwright.unit.config.ts
unit/refactor82CloudflareD1Runtime.guard.unit.test.ts --reporter=line` with 33
      tests, `pnpm --dir tests exec tsc -p tsconfig.playwright.json --noEmit`,
      `git diff --check`, plus a direct targeted `rg` scan for the stale policy
      doc links and Postgres policy phrases.
- [x] Replaced stale sponsorship-policy plan links that still pointed at the old
      simple-threshold-signer workspace and `server/src` sponsorship modules. The
      plan now links to current `packages/sdk-server-ts` gas-sponsorship,
      runtime-snapshot, sponsored-call, delegate-action, and EVM sponsorship
      modules. The Refactor 82 guard now rejects old absolute workspace links and
      old `server/src` / `examples/seams-site` link targets in that doc.
      Validation passed: `pnpm --dir tests exec playwright test -c
playwright.unit.config.ts unit/refactor82CloudflareD1Runtime.guard.unit.test.ts
--reporter=line` with 34 tests, `pnpm --dir tests exec tsc -p
tsconfig.playwright.json --noEmit`, `git diff --check`, plus a direct targeted
      `rg` scan for the stale sponsorship-policy links.
- [x] Replaced stale billing-cleanup plan references that still used old
      `server/src` and `examples/seams-site` paths. The doc now names current
      `packages/sdk-server-ts` router/billing/onboarding/adaptor paths,
      `apps/seams-site` dashboard validation, and D1 schema cleanup wording. The
      existing billing-cleanup guard now also rejects old `server/src` and
      `examples/seams-site` references in that doc. Validation passed:
      `pnpm --dir tests exec playwright test -c playwright.unit.config.ts
unit/refactor82CloudflareD1Runtime.guard.unit.test.ts --reporter=line` with 34
      tests, `pnpm --dir tests exec tsc -p tsconfig.playwright.json --noEmit`,
      `git diff --check`, plus a direct targeted `rg` scan for stale
      billing-cleanup paths and old relayer suite names.
- [x] Replaced stale SaaS frontend doc paths that still used the old
      `examples/seams-site` tree. `policy-drafts.md` now points at the current
      dashboard draft utilities under `apps/seams-site/src/pages/dashboard/drafts`
      and the current site build command. `professionalize.md` now describes the
      current React app layout: top-level routes in `apps/seams-site/src/app/App.tsx`,
      page modules under `apps/seams-site/src/pages`, homepage sections under
      `apps/seams-site/src/pages/home/sections`, and shared navbar/footer modules.
      The Refactor 82 guard now rejects `examples/seams-site` and the removed
      VitePress config path in those active docs. Validation passed:
      `pnpm --dir tests exec playwright test -c playwright.unit.config.ts
unit/refactor82CloudflareD1Runtime.guard.unit.test.ts --reporter=line` with 41
      tests, `pnpm --dir tests exec tsc -p tsconfig.playwright.json --noEmit`,
      `git diff --check`, plus a direct targeted stale-path scan.
- [x] Replaced stale schema/topology documentation that still described the
      active dashboard backend as Postgres/RLS-based. `db-schema.md` now names
      `CONSOLE_DB`, `SIGNER_DB`, Durable Objects, Wrangler/Miniflare local D1,
      explicit tenant predicates, and D1 tenant-isolation tests. The dashboard
      backend plan now names current D1 table names for team RBAC, approvals,
      audit, and runtime snapshot outbox, and describes claim-lease dispatch
      instead of advisory locks. The account settings plan now names
      `organizations.created_by_user_id` and `team_members` as the current
      account organization directory indexes. The Refactor 82 guard now rejects
      the stale `console_*` table names, Postgres topology, RLS, DB-level tenant
      context, Postgres org/billing isolation, and advisory-lock wording in those
      active docs. Validation passed:
      `pnpm --dir tests exec playwright test -c playwright.unit.config.ts
unit/refactor82CloudflareD1Runtime.guard.unit.test.ts --reporter=line` with 41
      tests, `pnpm --dir tests exec tsc -p tsconfig.playwright.json --noEmit`,
      `git diff --check`, plus a direct targeted stale-topology scan.
- [x] Replaced stale onboarding and API-key validation labels that still described
      current coverage as Postgres/RLS-backed. `console-onboarding.md` now names
      route-policy checks plus D1 adapter predicates for tenant isolation, and
      the organization-first backend phase now names the D1-backed
      org/project/environment service. `api-keys.md` now names D1 persistence
      tests and D1/SQLite persistence coverage for tenant isolation, schema
      evolution, index-backed lookup, and bootstrap-token atomic redemption. The
      Refactor 82 guard now rejects `RLS` and `Postgres service` in the onboarding
      doc, plus `Postgres persistence tests` and `Postgres tests:` in the API-key
      doc. Validation passed:
      `pnpm --dir tests exec playwright test -c playwright.unit.config.ts
unit/refactor82CloudflareD1Runtime.guard.unit.test.ts --reporter=line` with 42
      tests, `pnpm --dir tests exec tsc -p tsconfig.playwright.json --noEmit`,
      `git diff --check`, plus a direct targeted stale-validation-label scan.
- [x] Replaced stale current-service labels that still described policy, key
      export, billing, and scheduled-worker coverage as Postgres-backed.
      `policy-engine.md` now names D1 console service wiring and shared
      in-memory/D1 policy evaluator coverage. The dashboard backend plan now
      names D1 job config warnings and D1 key-export service wiring. Billing
      cleanup docs now describe D1/current billing validation instead of
      Postgres-specific validation labels. The Refactor 82 guard now rejects
      `Postgres namespace split`, `in-memory and Postgres services`,
      `memory versus Postgres services`, `postgresUrl`, `in-memory + postgres
      service + router wiring`, `Postgres validation and cleanup`, and
      `Postgres tests no longer clean up` in those active docs. Validation
      passed:
      `pnpm --dir tests exec playwright test -c playwright.unit.config.ts
unit/refactor82CloudflareD1Runtime.guard.unit.test.ts --reporter=line` with 42
      tests, `pnpm --dir tests exec tsc -p tsconfig.playwright.json --noEmit`,
      `git diff --check`, plus a direct targeted stale-service-label scan.
- [x] Replaced stale router-api-server/example-router-api labels in current docs. The
      policy engine plan now describes `apps/web-server` Router API wiring and
      the local Router API stack. The dashboard backend plan now names local D1
      console wiring for audit/evidence seed data and describes removed
      `apps/web-server` Postgres automation directly. The Refactor 82 guard now
      rejects `example router-api`, `router-api-server demo`, and `active router-api-server
      Postgres automation` in those active docs. Validation passed:
      `pnpm --dir tests exec playwright test -c playwright.unit.config.ts
unit/refactor82CloudflareD1Runtime.guard.unit.test.ts --reporter=line` with 42
      tests, `pnpm --dir tests exec tsc -p tsconfig.playwright.json --noEmit`,
      `git diff --check`, plus a direct targeted router-api-label scan.
- [x] Added `packages/sdk-server-ts/scripts/d1-staging-r2-restore-drill.mjs` and
      `pnpm --dir packages/sdk-server-ts run d1:staging:r2-restore-drill` so Phase
      6 remote restore drills have dry-run planning, remote execution, R2 object
      key evidence, restore database names, command output capture, export
      artifact hashes, and integrity-check command evidence. Remote mode now
      parses `PRAGMA integrity_check` Wrangler JSON before writing a passing
      manifest, so status-0 corruption output fails in the drill script rather
      than waiting for final evidence verification. Deletion pass: the
      integrity-check JSON collector now lives in the shared staging config helper
      and the duplicate final-verifier collector was removed. Validation passed:
      `pnpm --dir tests exec playwright test -c playwright.unit.config.ts
      unit/d1StagingR2RestoreDrill.script.unit.test.ts
      unit/d1StagingEvidenceVerify.script.unit.test.ts --reporter=line` with 61
      tests, `node --check packages/sdk-server-ts/scripts/d1-staging-config.mjs`,
      `node --check
      packages/sdk-server-ts/scripts/d1-staging-r2-restore-drill.mjs`, `node
      --check packages/sdk-server-ts/scripts/d1-staging-evidence-verify.mjs`,
      `pnpm --dir tests exec tsc -p tsconfig.playwright.json --noEmit`, and
      `git diff --check`.
- [x] Added `packages/sdk-server-ts/scripts/d1-staging-evidence-verify.mjs` and
      `pnpm --dir packages/sdk-server-ts run d1:staging:evidence` so Phase 6 has
      a final manifest-level gate before production planning. The verifier checks
      every remote staging artifact family, proves the artifacts belong to one
      staging environment/config/tenant/run sequence, verifies configured KEK IDs
      appear in Secrets Store evidence, requires complete resource inventory,
      console/signer migration, fixture-import, Time Travel bookmark,
      reconciliation, smoke, signer-custody, and R2 restore artifact evidence,
      and writes a compact pass/fail summary without copying resource metadata or
      secret-adjacent response bodies. The same pass updated stale Phase 6 test
      fixtures from the old Router API staging entrypoint to
      `src/router/cloudflare/d1RouterApiStagingWorker.ts`, and aligned smoke evidence
      with the router-api-owned `router_api_readyz` and `router_api_healthz` check IDs. The
      verifier now requires remote smoke and signer-custody evidence URLs to be
      HTTPS. Follow-up Phase 6 hardening binds the final evidence bundle to the
      exact configured remote D1 databases: the resource inventory must include
      console and router-api D1 binding IDs, the console and router-api `CONSOLE_DB` IDs
      must match, and remote `wrangler d1 info` evidence must report the same
      console and signer database IDs as the selected Wrangler configs. Resource
      inventory evidence must now also prove the planned remote command list has
      every required check ID, has the same count as the check evidence, and each
      remote check command matches the planned command for that check ID. It now
      also proves the selected resource split: the console Worker cannot receive `SIGNER_DB`,
      `THRESHOLD_STORE`, or signer KEK Secrets Store bindings, while the router-api
      Worker must expose `THRESHOLD_STORE` and every configured signer KEK secret
      binding. The verifier also rejects substituted remote command evidence by
      requiring hosted signer KEK metadata checks, reconciliation checks,
      migration, Time Travel, fixture-import, and R2 restore-drill
      `executed.command` or check `command` values to match the planned command
      evidence exactly. Smoke and signer-custody HTTP evidence must now also
      bind observed response URLs and statuses to the planned endpoint/check
      entries for the same evidence IDs. Required evidence arrays now reject
      duplicate evidence IDs/logical names, so set-style required-ID checks cannot
      hide ambiguous repeated records. Migration command and execution evidence
      also rejects duplicate target/action pairs. R2
      restore-drill evidence must now include JSON `PRAGMA integrity_check`
      results for the advertised console and signer restore database names, and
      each restored database must report `integrity_check = ok`.
      Time Travel evidence must now bind console and signer bookmark evidence to
      the generated artifact paths and include concrete non-placeholder bookmark
      JSON for both D1 databases. R2 restore-drill artifact evidence must now
      include non-zero byte counts, SHA-256 digests, and matching export/restore
      hashes for both console and signer SQL artifacts, and duplicate artifact
      evidence paths are rejected so restore evidence is unambiguous. Signer-custody
      missing-KEK evidence must now prove the exact
      `missing_signing_root_kek` error code, so a generic 5xx failure cannot
      satisfy the fail-closed drill.
      Latest validation passed: `pnpm --dir tests exec playwright test -c
playwright.unit.config.ts unit/d1StagingEvidenceVerify.script.unit.test.ts
--reporter=line` with 53 tests; the full Phase 6 staging script/session cluster with 126 tests;
      `pnpm --dir tests exec tsc -p tsconfig.playwright.json --noEmit`;
      `node --check packages/sdk-server-ts/scripts/d1-staging-evidence-verify.mjs`;
      and `git diff --check`.
- [x] Added `packages/sdk-server-ts/src/router/cloudflare/d1ConsoleStagingWorker.ts`,
      `packages/sdk-server-ts/src/router/cloudflare/d1RouterApiStagingWorker.ts`,
      and `packages/sdk-server-ts/src/router/cloudflare/d1StagingSession.ts` so
      staging uses concrete Worker entrypoints, Worker-native HMAC session
      boundaries, hosted signer KEK env parsing, and router-api `/readyz` D1/DO
      checks.
- [x] Deleted the stale `d1RelayStagingWorker.ts` entrypoint name from the
      Phase 6 staging surface. The runtime guard now requires
      `d1RouterApiStagingWorker.ts`, rejects the old router-api file path, rejects the
      old `routerApier` typo path, and rejects the stale Relay-to-RouterApi rename
      symbols in active router docs, source, tests, SDK server staging scripts, and
      the checked-in Wrangler staging templates. Validation passed:
      `pnpm --dir tests exec playwright test -c playwright.unit.config.ts
unit/refactor82CloudflareD1Runtime.guard.unit.test.ts --reporter=line`; the
      full Phase 6 staging script/session cluster with 110 tests; `pnpm --dir
packages/sdk-server-ts type-check`; `pnpm --dir tests exec tsc -p
tsconfig.playwright.json --noEmit`; `node --check
packages/sdk-server-ts/scripts/d1-staging-readiness-check.mjs`;
      `pnpm --dir packages/sdk-server-ts build`; and `git diff --check`.
- [x] Re-mounted Ed25519 registration prepare on the D1 local and Router API
      staging Workers after adding a real D1 implicit-account implementation. The
      Refactor 82 runtime guard now requires structural
      `ed25519RegistrationPrepare` wiring and rejects the old enabled-flag form.
- [x] Added `createCloudflareD1ConsoleOnlyServiceBundle` and type fixtures that
      reject signer metadata D1, threshold Durable Object, and signer KEK
      bindings on console-only staging bundles.
- [x] Added `tests/unit/d1StagingReadiness.script.unit.test.ts` coverage for a
      valid console-only staging config, a valid Router API staging config, a valid
      router-api `env.staging` config, exact staging Worker entrypoint enforcement,
      extra and duplicate D1 binding rejection, placeholder template rejection,
      console-profile signer-binding rejection, and local development config
      rejection.
- [x] Added `tests/unit/d1StagingSession.unit.test.ts` coverage for Worker-native
      HMAC session signing/verification, audience rejection, console auth roles
      resolved from `CONSOLE_DB` Team RBAC, token role-escalation rejection, and
      Cloudflare Secrets Store signer KEK binding resolution.
- [x] Added `tests/unit/d1StagingRunbook.script.unit.test.ts` coverage that the
      runbook generator renders remote migration, Time Travel, R2 export/restore,
      smoke, and signer-custody evidence commands from readiness-clean configs,
      writes the deployment log, and rejects configs that fail the readiness gate.
- [x] Added `tests/unit/d1StagingResourceInventory.script.unit.test.ts` coverage
      that resource inventory records config-derived resource IDs, writes dry-run
      manifests without touching Cloudflare, records remote JSON metadata through
      a fake runner, rejects failed remote metadata commands, and rejects
      readiness-failing staging configs. Validation passed:
      `./node_modules/.bin/playwright test -c playwright.source.config.ts
unit/d1StagingResourceInventory.script.unit.test.ts --reporter=line` with 5
      tests, the source-only `unit/d1Staging*.script.unit.test.ts` cluster with
      79 tests, Node `--check` for every `d1-staging-*.mjs` script and the local
      D1 restore drill script, and `git diff --check`.
- [x] Consolidated duplicated staging Wrangler/TOML helper code into
      `packages/sdk-server-ts/scripts/d1-staging-config.mjs`. The Phase 6 script
      set now has one owner for environment-section selection, table parsing,
      string/array reads, placeholder detection, shell quoting, command execution,
      command failure formatting, command success enforcement, and repo-relative
      paths.
- [x] Added `tests/unit/d1StagingFixtureImport.script.unit.test.ts` coverage that
      fixture import builds a dry-run plan from readiness-clean configs, writes a
      manifest without touching Cloudflare, records remote command evidence
      through a fake runner, rejects failed remote D1 commands, rejects
      cross-domain fixture SQL, and rejects schema-changing fixture SQL.
- [x] Added `tests/unit/d1StagingSmoke.script.unit.test.ts` coverage that staging
      smoke targets the actual console and router-api readiness endpoints, writes
      remote evidence from mocked passing responses, rejects origins with paths,
      requires HTTPS origins in remote mode, and fails on unhealthy readiness
      responses.
- [x] Added `tests/unit/d1StagingTimeTravelBookmark.script.unit.test.ts` coverage
      that bookmark capture builds console/signer Time Travel commands, writes a
      dry-run manifest without executing commands, records bookmark JSON evidence
      in remote mode with a fake command runner, rejects failed remote bookmark
      commands, and rejects unsafe purpose names.
- [x] Added `tests/unit/d1StagingKekCheck.script.unit.test.ts` coverage that KEK
      checks derive expected Secrets Store metadata commands, write a dry-run
      manifest without listing remote secrets, record metadata-only remote
      presence from JSON-shaped and Wrangler text output, fail when required KEK
      secret metadata is absent, reject substring-only matches, and reject failed
      remote listing commands. Validation passed:
      `./node_modules/.bin/playwright test -c playwright.source.config.ts
unit/d1StagingKekCheck.script.unit.test.ts --reporter=line` with 7 tests,
      the source-only `unit/d1Staging*.script.unit.test.ts` cluster with 78
      tests, Node `--check` for every `d1-staging-*.mjs` script and the local D1
      restore drill script, and `git diff --check`.
- [x] Added `tests/unit/d1StagingMigrate.script.unit.test.ts` coverage that D1
      migration apply records migration hashes, renders noninteractive remote
      list/apply/list commands, writes dry-run manifests without touching
      Cloudflare, records remote command evidence through a fake runner, rejects
      failed remote migration commands, and rejects readiness-failing staging
      configs. Validation passed: `./node_modules/.bin/playwright test -c
playwright.source.config.ts unit/d1StagingMigrate.script.unit.test.ts
--reporter=line` with 5 tests, the source-only
      `unit/d1Staging*.script.unit.test.ts` cluster with 81 tests, Node
      `--check` for every `d1-staging-*.mjs` script and the local D1 restore
      drill script, and `git diff --check`.
- [x] Added `tests/unit/d1StagingReconciliation.script.unit.test.ts` coverage that
      D1 reconciliation builds read-only console/signer checks, writes dry-run
      manifests without touching Cloudflare, records zero-row remote evidence,
      fails when mismatch rows are returned, rejects failed remote D1 query
      commands, and rejects readiness-failing staging configs. Validation passed:
      `./node_modules/.bin/playwright test -c playwright.source.config.ts
unit/d1StagingReconciliation.script.unit.test.ts --reporter=line` with 6
      tests, the source-only `unit/d1Staging*.script.unit.test.ts` cluster with
      80 tests, Node `--check` for every `d1-staging-*.mjs` script and the local
      D1 restore drill script, and `git diff --check`.
- [x] Added `tests/unit/d1StagingR2RestoreDrill.script.unit.test.ts` coverage that
      the R2 restore drill builds timestamped export/upload/download/restore
      commands, writes a dry-run manifest without executing commands, records
      command and artifact evidence in remote mode with a fake command runner,
      rejects failed remote export commands, and rejects object paths passed as
      bucket names.
- [x] Revalidated the fail-closed Phase 6 staging script surface after
      centralizing command execution. Validation passed:
      `./node_modules/.bin/playwright test -c playwright.source.config.ts
unit/d1StagingFixtureImport.script.unit.test.ts
unit/d1StagingTimeTravelBookmark.script.unit.test.ts
unit/d1StagingR2RestoreDrill.script.unit.test.ts --reporter=line` with 16
      tests; the source-only `unit/d1Staging*.script.unit.test.ts` cluster with
      84 tests; Node `--check` for every `d1-staging-*.mjs` script and the local
      D1 restore drill script.
- [x] `pnpm --dir tests exec playwright test -c playwright.unit.config.ts
unit/d1StagingReadiness.script.unit.test.ts --reporter=line` passed with 7
      tests.
- [x] `pnpm --dir tests exec playwright test -c playwright.unit.config.ts
unit/d1StagingSession.unit.test.ts --reporter=line` passed with 6 tests.
- [x] `pnpm --dir tests exec playwright test -c playwright.unit.config.ts
unit/cloudflareD1ConsoleServices.unit.test.ts --grep "console-only|service
bundle wires|sponsored EVM" --reporter=line` passed with 4 tests.
- [x] `pnpm --dir tests exec playwright test -c playwright.unit.config.ts
unit/refactor82CloudflareD1Runtime.guard.unit.test.ts --reporter=line`
      passed with 13 source-guard tests.
- [x] `pnpm --dir packages/sdk-server-ts type-check`, `pnpm --dir tests exec
tsc -p tsconfig.playwright.json --noEmit`, and `git diff --check` passed.
- [x] `pnpm --dir packages/sdk-server-ts build` passed after adding the concrete
      console and router-api Cloudflare D1 staging Worker entrypoints.
- [x] Current credential-free Phase 6 pre-deploy validation passed:
      `node --check` for every `packages/sdk-server-ts/scripts/d1-staging-*.mjs`
      script and `packages/sdk-server-ts/scripts/d1-local-backup-restore-drill.mjs`,
      plus `pnpm --dir tests exec playwright test -c playwright.unit.config.ts
      unit/d1StagingEvidenceVerify.script.unit.test.ts
      unit/d1StagingFixtureImport.script.unit.test.ts
      unit/d1StagingKekCheck.script.unit.test.ts
      unit/d1StagingMigrate.script.unit.test.ts
      unit/d1StagingR2RestoreDrill.script.unit.test.ts
      unit/d1StagingReadiness.script.unit.test.ts
      unit/d1StagingReconciliation.script.unit.test.ts
      unit/d1StagingResourceInventory.script.unit.test.ts
      unit/d1StagingRunbook.script.unit.test.ts
      unit/d1StagingSession.unit.test.ts
      unit/d1StagingSignerCustody.script.unit.test.ts
      unit/d1StagingSmoke.script.unit.test.ts
      unit/d1StagingTimeTravelBookmark.script.unit.test.ts --reporter=line`, which
      passed with 126 staging script/session tests. The latest focused runbook
      validation passed with 6 tests, `node --check
      packages/sdk-server-ts/scripts/d1-staging-runbook.mjs`, `pnpm --dir tests
      exec tsc -p tsconfig.playwright.json --noEmit`, and `git diff --check`.
- [x] Hardened hosted signer missing-KEK behavior end to end. The signer KEK
      provider now raises a typed `missing_signing_root_kek` error for missing
      Cloudflare Secrets Store bindings, empty Cloudflare Secrets Store values,
      and missing Worker secrets. The signing-root share resolver preserves that
      code instead of collapsing it into `resolver_failed`, threshold route status
      mapping returns 503, and the Phase 6 runbook plus final evidence fixtures
      now require `--missing-kek-expected-status 503`. Validation passed:
      `pnpm --dir tests exec playwright test
      tests/unit/signingRootKekProvider.script.unit.test.ts
      tests/unit/signingRootShareResolver.script.unit.test.ts
      tests/unit/thresholdStatusCodes.unit.test.ts
      tests/unit/d1StagingRunbook.script.unit.test.ts
      tests/unit/d1StagingEvidenceVerify.script.unit.test.ts` with 66 tests;
      `pnpm --dir packages/sdk-server-ts type-check`;
      `pnpm --dir tests exec tsc -p tsconfig.playwright.json --noEmit`;
      `node --check packages/sdk-server-ts/scripts/d1-staging-runbook.mjs`;
      `node --check packages/sdk-server-ts/scripts/d1-staging-evidence-verify.mjs`;
      the full Phase 6 staging script/session/signing-root cluster with 155
      tests; and `git diff --check`.
- [ ] Live Phase 6 deployment remains open because only
      `wrangler.d1-staging-console.toml.example` and
      `wrangler.d1-staging-router-api.toml.example` exist in the workspace, and
      `docs/deployment/refactor-82-staging-log.md` is still the template log. Copy
      the templates to concrete `wrangler.d1-staging-*.toml` files, fill real
      Cloudflare resource IDs and secrets, then run the remote command sequence.
      The concrete staging config files are intentionally gitignored.

### Phase 7: Delete Legacy Migration Scaffolding

Status: complete for the current Refactor 82 cleanup/count closure. Phase 6
staging smoke and any post-MVP adapter slimming remain separate follow-up work.

Goal:

- [x] Make the D1/DO implementation the only Cloudflare staging/runtime path.
- [x] Bring Refactor 82 production-code growth down to net-neutral or record a
      concrete product reason for every remaining positive block.
- [x] Prefer deletion over abstraction. Add shared helpers only when they delete
      repeated code in the same cleanup slice.

Scope after the post-Refactor 82 integration fixes:

- [x] Treat the local D1/Router runtime fixes, D1 signer-set registration fixes,
      Ed25519 HSS durable-finalize fixes, NEAR Ed25519 signing readiness fixes,
      EVM/Tempo/ARC signing fixes, wallet unlock fixes, Router A/B validation
      hardening, and local WASM resolution fixes as product-correctness work, not
      automatic deletion targets.
- [x] Keep Phase 7 focused on Refactor 82 cleanup: stale Cloudflare staging/runtime
      scaffolding, duplicate D1/DO assembly paths, obsolete Postgres/default-runtime
      fixtures, superseded local-dev helpers, and untracked implementation files
      that either need to be staged as real Refactor 82 code or deleted.
- [x] Keep iframe overlay cleanup, visible wallet-ID activation binding, and the
      long-term `PasskeyRegistrationDraft` model in the Refactor 83 follow-up
      lane. Phase 7 may only touch those files when deleting obsolete Refactor 82
      scaffolding with focused tests.
- [x] Keep Ed25519 HSS payload-size trimming in Refactor 84. Phase 7 must preserve
      the durable finalize contract: `serverEvalFinalizeOutputB64u` is required at
      request boundaries, server finalize output is stored durably with the
      ceremony, and process-local staged-artifact handles cannot be required across
      requests.
- [x] Keep ECDSA role-local material identity slimming, capability subject
      hardening, `chainTarget` / `routerAbStateSessionId` trimming, and
      `clientVerifyingShareB64u` vocabulary cleanup in Refactor 85 Phase 0D/0E.
      Phase 7 should not reshape those public or worker-material contracts.
- [x] Route live ECDSA-HSS pool-fill session ownership cleanup to Phase 9. The
      interim Worker-level live-session caches are staging blockers, but Phase 7
      must not delete them before a Durable Object owner and fresh-Worker-handler
      tests replace them.
- [x] After Phase 9 lands, include deletion of
      `localRouterApiEcdsaPoolFillLiveSessionsCache`,
      `routerApiStagingEcdsaPoolFillLiveSessionsCache`, and Worker
      `ecdsaPoolFillLiveSessions` factory plumbing in the Phase 7 final count
      report.
- [x] Before deleting code touched by the post-82 integration fixes, name the
      owning follow-up plan or the exact Refactor 82 runtime path it supersedes,
      then run the smallest regression test that covers the fixed behavior.

Work:

- [x] Build a deletion inventory from `git diff --stat`, `git diff --name-only`,
      `rg "POSTGRES|Postgres|postgres|legacy|compat|TODO|temporary"`, and the
      Refactor 82 guard allowlist.
- [x] Record Phase 7 start counts with these slices:
      `git diff --shortstat 20af682856f1417abdab6ec39dc7793176d35bd0 --`,
      `git diff --shortstat 20af682856f1417abdab6ec39dc7793176d35bd0 --
':!docs/**' ':!**/*.md'`, and
      `git diff --shortstat 20af682856f1417abdab6ec39dc7793176d35bd0 --
'packages/sdk-server-ts/src/**' ':!**/*.typecheck.ts'`.
- [x] Build a top-growth inventory with `git diff --numstat` grouped by
      production path. Prioritize the largest positive files before touching small
      cosmetic debt.
- [x] Run the runtime-source slimming track against the current measured
      `packages/sdk-server-ts/src` growth. The June 29 checkpoint reports
      `52,329` runtime-source additions, `34,158` runtime-source deletions, and
      `18,171` net new runtime-source lines, with almost all growth under
      `packages/sdk-server-ts/src`.
      The June 30 tracked refresh after local D1/registration/signing integration
      fixes reports `55,766` runtime-source additions, `31,047` runtime-source
      deletions, and `24,719` net new runtime-source lines under
      `packages/sdk-server-ts/src` excluding `*.typecheck.ts`. Treat this as the
      active Phase 7 slimming baseline until the next cleanup slice records a newer
      count.
      - [x] Refresh the runtime-source count before each cleanup slice:
            `git diff --shortstat 20af682856f1417abdab6ec39dc7793176d35bd0 --
            'packages/sdk-server-ts/src/**' ':!**/*.typecheck.ts'`.
      - [x] Classify the top 20 runtime-growth files into four buckets:
            required product logic, duplicated adapter plumbing, test/local/staging
            support that can move out of runtime source, and obsolete migration
            scaffolding that should be deleted.
      - [x] Classify the June 30 post-82 integration files separately from
            migration scaffolding. Local D1 startup, D1 registration, signing
            readiness, unlock behavior, Router A/B validation, and explicit WASM
            loading fixes are retained unless a replacement path is already present.
      - [x] Classify Worker-level ECDSA-HSS pool-fill live-session cache code as a
            Phase 9 staging blocker, not generic Phase 7 bloat. Delete it only in
            the same slice that installs the Durable Object owner and proves fresh
            Worker handlers can advance the same pool-fill ceremony through DO
            routing.
      - [x] Classify the largest console D1 adapters first:
            `console/billing/d1.ts`, `console/webhooks/d1.ts`,
            `console/observability/d1.ts`, `console/orgProjectEnv/d1.ts`,
            `console/runtimeSnapshots/d1.ts`, `console/apiKeys/d1.ts`,
            `console/policies/d1.ts`, `console/teamRbac/d1.ts`, and
            `console/sponsorshipSpendCaps/d1.ts`. They are product-owned D1
            replacements for deleted Postgres adapters. Further tenant-scope,
            pagination, JSON-column, mutation-count, and lifecycle helper cleanup
            is post-MVP adapter slimming and should happen only when a helper
            removes more code in the same slice.
      - [x] Classify the D1 signer/auth record-service split:
            `d1RegistrationCeremonyRecords.ts`, `d1EmailOtpRecords.ts`,
            `d1EmailOtpRecoveryService.ts`, `d1WalletAuthMethodService.ts`,
            `d1GoogleEmailOtpSessionResolver.ts`, `d1OidcBoundary.ts`,
            `d1WebAuthnAuthService.ts`, and related `d1*Records.ts` files.
            They are product-owned D1/DO signer runtime boundaries. Merge
            record-only modules later only when the split adds indirection while
            still preserving the raw-D1-row parser boundary.
      - [x] Classify `d1LocalDevWorker.ts`, `d1ConsoleStagingWorker.ts`, and
            `d1RouterApiStagingWorker.ts`. They should assemble the production
            route factories with local/staging bindings and avoid carrying duplicate
            route tables, duplicate env parsing, or local-only service graphs in
            runtime source. Current Phase 7 closure finds no Worker-level
            ECDSA-HSS live-session cache in those runtime files.
      - [x] Classify the explicit local WASM/runtime support files for Refactor 82
            duplication. Module-local filesystem candidates and explicit D1-local
            WASM setup remain because local source execution and built package
            execution resolve from different places.
      - [x] Classify D1 schema source-of-truth work by environment. Migrations are
            the setup source for local, test, and staging. Any remaining runtime
            schema helpers are product-owned until the migration runner fully covers
            that request path; deletion moves to Phase 6 staging hardening or a
            focused post-MVP schema cleanup.
      - [x] Count every untracked runtime-source file before final Phase 7 counts
            and assign a current owner. Stage files that are real, fold small
            one-caller helpers into their owner, and delete obsolete prototypes in
            the normal commit flow; the count closure includes untracked text so it
            cannot hide production growth.
      - [x] Resolve untracked follow-up plan docs separately from implementation
            files. `docs/refactor-83-iframe-walletId.md`,
            `docs/refactor-84-trim-hss.md`, and Refactor 85 plan/spec docs are
            follow-up planning artifacts, not Phase 7 runtime bloat.
      - [x] Every runtime-slimming slice records before/after counts for
            `packages/sdk-server-ts/src` and must be net-negative unless it fixes a
            concrete Phase 6 staging blocker.
      - [x] Phase 7 exit target: reduce the tracked runtime-source delta from the
            June 30 `+24,719` net lines to below `+10,000`, or record a named
            product reason and owner for each remaining positive runtime block.
- [x] For every D1 adapter added in this refactor, name the exact old runtime path
      it replaces. Delete the old path in the same slice or add a dated blocker in
      this document.
- [x] Remove legacy staging/runtime code that exists only to keep the pre-D1
      workflow alive: stale Worker env fields, unused compatibility adapters,
      duplicate in-memory/Postgres-only request paths, temporary shims, and route
      wiring that cannot run in the D1/DO staging topology.
- [x] Remove disabled-capability route scaffolding. Unsupported D1-era route
      scopes should be absent from the route table or rejected by a tiny boundary
      parser, without service bundles, option unions, no-op adapters, or fixtures.
- [x] Revisit the Postgres escape hatch. Keep only a minimal typed contract when
      there is an active product requirement for a full-family backend. Delete the
      implementation, exports, docs, tests, and fixtures if there is no concrete
      trigger.
      Evidence: Postgres remains only as a future full-family route contract in
      `packages/sdk-server-ts/src/storage/tenantRoute.ts`, its type fixture, the
      migration playbook, package-export negative tests, and the Cloudflare console
      route rejection test for Postgres tenant routes. There are no
      `*postgres*` runtime files under `packages/sdk-server-ts/src`, no runtime
      `pg` imports, no `new Pool`, no `getPostgresPool`, no live
      `createPostgres*Service` factory, and no `postgresRecords` helpers. The
      Refactor 82 runtime guard now rejects those paths while preserving the typed
      `TenantStorageRoute` escape-hatch contract. Validation passed:
      `pnpm --dir tests exec tsc -p tsconfig.playwright.json --noEmit`,
      `pnpm --dir tests exec playwright test -c playwright.unit.config.ts
unit/refactor82CloudflareD1Runtime.guard.unit.test.ts --reporter=line`,
      direct `find packages/sdk-server-ts/src -iname '*postgres*'`, and direct
      stale-symbol scans for `pg` runtime imports and Postgres service factories.
- [x] Delete Cloudflare runtime imports of mixed console/signer barrels when a
      narrower D1 module exists.
- [x] Delete local-dev paths that still require Docker Postgres once Wrangler D1
      local development covers the same flow.
- [x] Delete or rewrite tests, fixtures, mocks, docs, and source guards that
      encode obsolete Postgres/default-runtime behavior. Keep compatibility coverage
      only at explicit request or persistence boundaries that are still intentional.
- [x] Collapse duplicate D1/local/dev helpers that were added during migration
      once the final Cloudflare Worker entrypoint is authoritative.
      Progress: `tests/unit/cloudflareD1RouterApiAuthService.unit.test.ts` now uses
      the shared SQLite-backed D1 harness from `tests/helpers/sqliteD1.ts` instead
      of carrying its own D1 database, prepared-statement, batch, SQL interpolation,
      and cleanup implementation. The Refactor 82 runtime guard now rejects local
      SQLite-D1 harness copies outside the shared helper. Follow-up cleanup also
      deleted the test-local signer migration file reader: router-api-auth tests now
      apply `listD1MigrationFiles('d1-signer')` through the shared
      `applyD1MigrationFiles` helper, so they run against the same ordered signer
      D1 migration set as the migration smoke suite. The guard now rejects local
      D1 migration applicators and hard-coded D1 migration paths outside the shared
      helper. Validation passed:
      `pnpm --dir tests exec tsc -p tsconfig.playwright.json --noEmit`,
      `pnpm --dir tests exec playwright test -c playwright.unit.config.ts
unit/refactor82CloudflareD1Runtime.guard.unit.test.ts --reporter=line`,
      `pnpm --dir tests exec playwright test -c playwright.unit.config.ts
unit/cloudflareD1RouterApiAuthService.unit.test.ts --reporter=line`, a direct
      stale-harness and stale-migration-helper scan under `tests`, and
      `git diff --check`. Completion check passed again with
      `pnpm --dir tests exec playwright test -c playwright.unit.config.ts
unit/refactor82CloudflareD1Runtime.guard.unit.test.ts --reporter=line`
      and a direct duplicate-helper scan that found the SQLite-backed D1 harness
      only in `tests/helpers/sqliteD1.ts`, and the D1 runtime helpers only in
      `packages/sdk-server-ts/src/storage/d1Sql.ts`.
- [x] Consolidate repeated D1 statement plumbing into tiny helpers only where the
      helper deletes repeated code immediately: `queryOne`, `queryMany`, `execute`,
      `parseJsonColumn`, `requireChangedOne`, and corrupt-row mapping are the
      expected helper ceiling.
      Evidence: repeated D1 row-query helpers, mutation-count helpers, D1 database
      resolver helpers, and JSON-column parsers are centralized in
      `packages/sdk-server-ts/src/storage/d1Sql.ts`. The latest cleanup deleted
      seven local `parseD1RecordJson` bodies from core D1-backed signer stores
      while keeping domain-specific record validation local to each store. The
      Refactor 82 runtime guard now rejects reintroduced local `parseD1RecordJson`,
      D1 mutation-count helpers, and D1 database resolver helpers outside the
      storage boundary. Validation passed: `pnpm --dir packages/sdk-server-ts
type-check`, `pnpm --dir tests exec tsc -p tsconfig.playwright.json
--noEmit`, `pnpm --dir tests exec playwright test -c
	playwright.unit.config.ts unit/refactor82CloudflareD1Runtime.guard.unit.test.ts
	--reporter=line`, the stale-helper scan, and `git diff --check`.
- [x] Remove redundant database-family prefixes from D1 object names. Because
      console and signer data now live in separate D1 databases, table/index/trigger
      identifiers should not carry `console_` or `signer_` prefixes. Keep only
      platform/internal names as-is: `_cf_METADATA`, `d1_migrations`, and
      `sqlite_sequence`.
      Scope: database object names only. Do not rename route IDs such as
      `console_projects_list`, source folders such as `console/`, public API names,
      or domain concepts such as signer/signing.
      Implementation checklist:
      - [x] Rename D1 migration SQL table, index, and trigger identifiers:
            `console_organizations` -> `organizations`,
            `console_projects` -> `projects`,
            `console_runtime_snapshots` -> `runtime_snapshots`,
            `signer_wallets` -> `wallets`,
            `signer_wallet_signers` -> `wallet_signers`,
            `signer_webauthn_challenges` -> `webauthn_challenges`, and the rest of
            the exact D1 object-name set.
      - [x] Update all D1 query strings and marker-table checks that reference the
            renamed objects.
      - [x] Update D1 smoke, backup/restore, staging, and fixture scripts.
      - [x] Update tests, fixtures, and source guards that assert D1 object names.
      - [x] Delete local D1 state and recreate it from migrations during manual
            testing.
      - [x] Avoid compatibility views, dual-name query paths, and legacy migration
            aliases.
      Evidence: an exact-token rewrite over the D1 object-name set updated
      migrations, D1 query strings, local/staging scripts, package smoke checks, and
      fixtures while excluding docs and route IDs. A strict scan for the original
      D1 object names found no exact hits outside docs. Local `.wrangler/state/seams-d1`
      was deleted and recreated from migrations. Validation passed:
      `pnpm --dir packages/sdk-server-ts type-check`,
      `pnpm --dir packages/sdk-server-ts run d1:local:prepare`,
      `pnpm --dir packages/sdk-server-ts run d1:local:restore:drill -- --skip-prepare`,
      `pnpm --dir tests exec tsc -p tsconfig.playwright.json --noEmit`,
      `pnpm --dir tests exec playwright test -c playwright.relayer.config.ts
      relayer/console-d1-adapters.test.ts --reporter=line`,
      `pnpm --dir tests exec playwright test -c playwright.unit.config.ts
      unit/refactor82CloudflareD1Runtime.guard.unit.test.ts --reporter=line`, and
      `git diff --check` for the touched files.
- [x] Push invariants into D1 schema where practical: `NOT NULL`, `UNIQUE`,
      deterministic primary keys, lifecycle-state checks, and foreign-key-like
      ownership columns should replace app-side duplicate guards when D1 can enforce
      them.
      Progress: sponsored-call records now enforce non-empty idempotency keys,
      valid JSON `details_json`, non-negative estimated and settled spend, positive
      timestamps, and monotonic `updated_at_ms >= created_at_ms` in both the runtime
      D1 schema helper and D1 console migrations. The migration smoke suite now
      directly inserts corrupt raw sponsored-call rows and proves D1 rejects them
      while still accepting a valid raw row. Validation passed:
      `pnpm --dir packages/sdk-server-ts type-check`,
      `pnpm --dir tests exec playwright test -c playwright.relayer.config.ts
relayer/console-d1-adapters.test.ts --grep
"D1 migration smoke|sponsored call idempotency" --reporter=line`,
      `pnpm --dir tests exec tsc -p tsconfig.playwright.json --noEmit`, and
      `git diff --check`.
      Progress: prepaid reservation rows now enforce non-empty tenant scope,
      reservation IDs, environment IDs, source-event IDs, positive requested
      amounts, non-negative accounting fields, positive monotonic timestamps, and
      lifecycle-specific release/settlement consistency in both the runtime D1
      schema helper, fresh `packages/sdk-server-ts/migrations/d1-console/0001_console_d1_initial.sql`,
      and upgrade migration
      `packages/sdk-server-ts/migrations/d1-console/0018_console_constraint_hardening.sql`.
      The D1 adapter parser now rejects corrupt reservation and summary rows rather
      than clamping numeric fields. The migration smoke suite directly inserts
      corrupt raw prepaid reservation rows, proves D1 rejects them while accepting a
      valid raw row, and the trigger-atomic reservation contract still proves
      duplicate source events and insufficient balance do not double-reserve.
      Validation passed: `pnpm --dir packages/sdk-server-ts type-check`,
      `pnpm --dir tests exec playwright test -c playwright.relayer.config.ts
relayer/console-d1-adapters.test.ts -g "prepaid-reservation migration|billing
reservations are trigger-atomic" --reporter=line`, and
      `pnpm --dir tests exec tsc -p tsconfig.playwright.json --noEmit`.
      Progress: console webhook endpoint rows now enforce non-empty tenant scope,
      endpoint IDs, HTTP(S) URLs, base64url-shaped sealed webhook signing-secret
      ciphertext, non-empty KEK/envelope/secret preview fields, positive secret
      versions, and positive monotonic timestamps. Webhook endpoint category rows
      now enforce non-empty scope plus the supported category enum. These checks
      live in the runtime D1 schema helper, fresh
      `packages/sdk-server-ts/migrations/d1-console/0015_console_webhooks.sql`,
      and upgrade migration
      `packages/sdk-server-ts/migrations/d1-console/0018_console_constraint_hardening.sql`.
      The migration smoke suite now inserts corrupt raw webhook endpoint/category
      rows, proves D1 rejects them while accepting valid raw rows, and verifies
      the upgrade migration preserves existing endpoint category rows. Validation
      passed: `pnpm --dir packages/sdk-server-ts type-check`, `pnpm --dir tests
exec playwright test -c playwright.relayer.config.ts
relayer/console-d1-adapters.test.ts --grep "D1 migration smoke|webhook"
--reporter=line`, `pnpm --dir tests exec tsc -p
tsconfig.playwright.json --noEmit`, and `git diff --check`.
      Deletion pass: the sponsored-call and webhook endpoint invariant upgrades
      were collapsed into the single
      `packages/sdk-server-ts/migrations/d1-console/0018_console_constraint_hardening.sql`
      migration, deleting the interim separate webhook endpoint constraint
      migration and keeping the console migration count at 18 files.
      Progress: sealed signing-root secret share rows now enforce non-empty
      tenant scope, non-empty signing-root IDs, base64url-shaped sealed shares,
      exact SHA-256 digest string lengths for AAD and ciphertext digests,
      non-empty optional storage/rotation references when present, positive
      creation timestamps, and monotonic update/rotation/retirement timestamps.
      These checks live in the runtime D1 schema helper, the fresh
      `packages/sdk-server-ts/migrations/d1-signer/0001_signer_d1_initial.sql`
      schema, and upgrade migration
      `packages/sdk-server-ts/migrations/d1-signer/0010_signer_constraint_hardening.sql`.
      The migration smoke suite now inserts corrupt raw custody rows and proves D1
      rejects them while accepting a valid raw sealed-share row. Validation passed:
      `pnpm --dir packages/sdk-server-ts type-check`, `pnpm --dir tests exec
playwright test -c playwright.relayer.config.ts
relayer/console-d1-adapters.test.ts --grep
"D1 migration smoke|signer sealed shares" --reporter=line`, `pnpm --dir
tests exec tsc -p tsconfig.playwright.json --noEmit`, and
      `git diff --check`.
      Progress: signer wallet auth-method rows now enforce branch-specific
      invariants in the runtime D1 schema helper, fresh signer metadata migration,
      and combined wallet metadata constraint migration
      `packages/sdk-server-ts/migrations/d1-signer/0010_signer_constraint_hardening.sql`.
      Passkey rows must carry RP ID, credential ID, public key, deterministic auth
      identifier, and deterministic `wallet_auth_method_id`, while Email OTP rows
      must carry no RP/passkey fields and must carry email hash, registration
      authority, deterministic auth identifier, and deterministic
      `wallet_auth_method_id`. The migration smoke suite now inserts corrupt raw
      signer auth-method rows and proves D1 rejects invalid branch combinations
      while accepting valid passkey and Email OTP rows. Validation passed:
      `pnpm --dir packages/sdk-server-ts type-check`,
      `pnpm --dir tests exec playwright test -c playwright.relayer.config.ts
relayer/console-d1-adapters.test.ts --grep
"D1 migration smoke|signer wallet metadata and auth methods"
--reporter=line`, `pnpm --dir tests exec tsc -p tsconfig.playwright.json
--noEmit`, and `git diff --check`.
      Progress: base signer wallet rows now enforce JSON identity in the runtime
      D1 schema helper, fresh signer metadata migration, and combined wallet
      metadata constraint migration
      `packages/sdk-server-ts/migrations/d1-signer/0010_signer_constraint_hardening.sql`.
      Wallet rows must carry `wallet_v1` JSON envelopes and the JSON `walletId`
      must match the indexed `wallet_id`. The migration smoke suite now inserts
      raw wallet rows with mismatched or missing JSON identity and proves D1 rejects
      them while accepting a valid wallet row. Validation passed:
      `pnpm --dir packages/sdk-server-ts type-check`,
      `pnpm --dir tests exec playwright test -c playwright.relayer.config.ts
relayer/console-d1-adapters.test.ts --grep
"D1 migration smoke|signer wallet metadata and auth methods"
--reporter=line`, `pnpm --dir tests exec tsc -p tsconfig.playwright.json
--noEmit`, and `git diff --check`.
      Progress: signer wallet signer rows now enforce branch-specific indexed
      identity in the runtime D1 schema helper, fresh signer metadata migration,
      and combined wallet metadata constraint migration
      `packages/sdk-server-ts/migrations/d1-signer/0010_signer_constraint_hardening.sql`.
      Ed25519 signer rows must carry no chain target, use the `ed25519:` signer ID
      prefix, and match the JSON `walletId`/`signerId` envelope. ECDSA signer rows
      must carry a non-empty chain target, use deterministic `ecdsa:${chainTargetKey}`
      signer IDs, and match JSON `walletId`/`signerId`/`chainTargetKey` envelope
      fields. The migration smoke suite now inserts corrupt raw signer rows and
      proves D1 rejects invalid branch combinations while accepting valid Ed25519
      and ECDSA signer rows. Validation passed:
      `pnpm --dir packages/sdk-server-ts type-check`,
      `pnpm --dir tests exec playwright test -c playwright.relayer.config.ts
relayer/console-d1-adapters.test.ts --grep
"D1 migration smoke|signer wallet metadata and auth methods"
--reporter=line`, `pnpm --dir tests exec tsc -p tsconfig.playwright.json
--noEmit`, and `git diff --check`.
      Deletion pass: the three interim signer wallet metadata upgrade migrations
      were collapsed into the combined
      `packages/sdk-server-ts/migrations/d1-signer/0010_signer_constraint_hardening.sql`
      migration. This deleted the separate signer auth-method, signer row, and
      wallet identity constraint migrations. Follow-up cleanup folded sealed
      signing-root secret share constraints into that same signer hardening
      migration and deleted the interim separate secret-share constraint migration,
      keeping the signer migration smoke expectation at 10 files.
      Progress: runtime snapshot and snapshot outbox rows now enforce non-empty
      scope/identity columns, JSON payload validity, positive timestamps,
      monotonic update and dispatch timestamps, and outbox lifecycle consistency
      for pending, claimed, dispatched, and dead-letter states. These checks live
      in the runtime D1 schema helper, fresh
      `packages/sdk-server-ts/migrations/d1-console/0001_console_d1_initial.sql`,
      and existing combined console constraint migration
      `packages/sdk-server-ts/migrations/d1-console/0018_console_constraint_hardening.sql`.
      The migration smoke suite now inserts corrupt raw runtime snapshot/outbox
      rows and proves D1 rejects missing IDs, invalid JSON, missing claim expiry,
      expired claims, dispatched rows without dispatch timestamps, and dead-letter
      rows without errors while accepting valid pending, dispatched, and
      dead-letter outbox rows. Validation passed:
      `pnpm --dir tests exec playwright test -c playwright.relayer.config.ts
relayer/console-d1-adapters.test.ts --grep "D1 migration smoke|runtime
snapshot" --reporter=line`, `pnpm --dir packages/sdk-server-ts
type-check`, `pnpm --dir tests exec tsc -p tsconfig.playwright.json
--noEmit`, and `git diff --check`.
      Deletion pass: the runtime snapshot/outbox upgrade was folded into
      `0018_console_constraint_hardening.sql` instead of adding a temporary
      follow-up migration, keeping the console migration count at 18 files.
      Progress: billing ledger D1 rows now enforce non-empty tenant and ledger
      identity columns, ledger entry type enums, entry-specific amount sign
      rules, USD-only currency, month format, non-empty optional reference fields,
      posting direction and positive amount rules, monthly active wallet identity
      checks, and positive timestamps. These checks live in the runtime billing D1
      schema helper, fresh
      `packages/sdk-server-ts/migrations/d1-console/0006_console_billing_ledger.sql`,
      and existing combined console constraint migration
      `packages/sdk-server-ts/migrations/d1-console/0018_console_constraint_hardening.sql`.
      The migration smoke suite now inserts corrupt raw billing ledger, posting,
      and monthly-active-wallet rows and proves D1 rejects inverted credit/debit
      signs, zero manual adjustments, invalid months, empty IDs, empty optional
      reference keys, and zero timestamps while accepting valid manual adjustment
      ledger rows, manual postings, and monthly wallet usage rows. Deletion pass:
      the upgrade was folded into `0018_console_constraint_hardening.sql` instead
      of adding a temporary follow-up migration, keeping the console migration
      count at 18 files.
      Progress: signer identity links, app-session versions, recovery sessions,
      recovery executions, and email recovery preparations now enforce non-empty
      tenant scope, JSON envelope versions, indexed identity columns matching JSON
      fields, allowed recovery statuses, monotonic timestamps, and email-recovery
      wallet-binding consistency at the D1 boundary. These checks live in the
      runtime D1 schema helpers, fresh signer migrations
      `packages/sdk-server-ts/migrations/d1-signer/0004_signer_identity.sql`,
      `packages/sdk-server-ts/migrations/d1-signer/0005_signer_recovery.sql`,
      `packages/sdk-server-ts/migrations/d1-signer/0007_signer_email_recovery_preparations.sql`,
      and existing combined signer constraint migration
      `packages/sdk-server-ts/migrations/d1-signer/0010_signer_constraint_hardening.sql`.
      The migration smoke suite now inserts corrupt raw identity, app-session,
      recovery-session, recovery-execution, and email-recovery-preparation rows and
      proves D1 rejects scope gaps, JSON identity mismatches, invalid statuses,
      timestamp regressions, and mismatched email-recovery wallet bindings while
      accepting one valid row per table. Deletion pass: the upgrade was folded into
      `0010_signer_constraint_hardening.sql` instead of adding another signer
      follow-up migration, keeping the signer migration count at 10 files.
      Progress: signer Email OTP challenges, grants, wallet enrollments,
      recovery-wrapped enrollment escrows, auth states, unlock challenges, Google
      Email OTP registration attempts, and rate-limit rows now enforce non-empty
      tenant scope, JSON envelope versions, indexed identity columns matching JSON
      fields, allowed action/operation/status enums, escrow lifecycle consistency,
      registration-offer array shape, monotonic timestamps, and positive
      rate-limit windows at the D1 boundary. These checks live in fresh signer
      migrations
      `packages/sdk-server-ts/migrations/d1-signer/0008_signer_email_otp.sql`,
      `packages/sdk-server-ts/migrations/d1-signer/0009_signer_email_otp_rate_limits.sql`,
      and existing combined signer constraint migration
      `packages/sdk-server-ts/migrations/d1-signer/0010_signer_constraint_hardening.sql`.
      The migration smoke suite now inserts corrupt raw Email OTP rows and proves
      D1 rejects scope gaps, invalid actions, JSON identity mismatches, invalid
      escrow lifecycle fields, malformed registration offer JSON, and invalid
      rate-limit windows while accepting one valid row per Email OTP table.
      Deletion pass: the upgrade was folded into
      `0010_signer_constraint_hardening.sql` instead of adding another signer
      follow-up migration, keeping the signer migration count at 10 files.
      Completion decision: the first-staging schema invariant matrix is complete.
      The current migration set has 18 console migrations, 10 signer migrations,
      and the combined hardening migrations
      `packages/sdk-server-ts/migrations/d1-console/0018_console_constraint_hardening.sql`
      plus
      `packages/sdk-server-ts/migrations/d1-signer/0010_signer_constraint_hardening.sql`.
      Invariants that require multi-row ordering, request authorization, secret
      access, or serialized signer mutation stay in adapters or Durable Object
      methods. Future signer auth methods must add their own schema checks as part
      of a complete route slice.
- [x] Run a split-identity cleanup inventory across the new D1 modules:
      `rg "isValidAccountId\\((walletId|userId|linkedWalletId|enrollment\\.walletId)"
packages/sdk-server-ts/src/router/cloudflare packages/sdk-server-ts/src/core`.
      Wallet identity must parse as wallet identity. NEAR-shaped hosted-account
      requirements need a branch-specific predicate.
- [x] Run an RP-scope cleanup inventory across generic wallet/NEAR paths:
      `rg "\\brpId\\b" packages/shared-ts/src/utils/registrationIntent.ts
packages/sdk-server-ts/src/core packages/sdk-server-ts/src/router/cloudflare`.
      RP ID should appear only in passkey/WebAuthn auth-method branches or in
      explicitly documented request-boundary compatibility code.
      Cleanup completed for NEAR public-key metadata, signing-root
      migration/context records, and live threshold Ed25519 session policy,
      wallet-session records, MPC/signing records, and presign scopes. Remaining
      RP references are intentionally branch-specific WebAuthn/passkey fields,
      JWT/token claims, route request boundaries, ROR/bootstrap policy, or
      historical Ed25519 key-material identity that needs its own key-store
      migration decision.
- [x] Record the final cleanup result in this document: files removed, net lines
      deleted, remaining intentional non-D1 code, and why each survivor still
      exists. The final Phase 7 snapshot counts tracked diff plus untracked text,
      so implementation files cannot disappear from the closure math merely because
      they have not been staged yet.

Adapter replacement ledger:

| D1/DO adapter family                                                                                                                                                                                                                                                               | Replaced or deleted runtime path                                                                                                                                                                                                             | Status   |
| ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | -------- |
| Console account D1 adapter: `packages/sdk-server-ts/src/console/account/d1.ts`                                                                                                                                                                                                     | Deleted `packages/sdk-server-ts/src/console/account/postgres.ts`                                                                                                                                                                             | Complete |
| Console API-key D1 adapter: `packages/sdk-server-ts/src/console/apiKeys/d1.ts`                                                                                                                                                                                                     | Deleted `packages/sdk-server-ts/src/console/apiKeys/postgres.ts`                                                                                                                                                                             | Complete |
| Console approvals D1 adapter: `packages/sdk-server-ts/src/console/approvals/d1.ts`                                                                                                                                                                                                 | Deleted `packages/sdk-server-ts/src/console/approvals/postgres.ts`                                                                                                                                                                           | Complete |
| Console audit D1 adapter: `packages/sdk-server-ts/src/console/audit/d1.ts`                                                                                                                                                                                                         | Deleted `packages/sdk-server-ts/src/console/audit/postgres.ts`                                                                                                                                                                               | Complete |
| Console billing D1 adapter: `packages/sdk-server-ts/src/console/billing/d1.ts`                                                                                                                                                                                                     | Deleted `packages/sdk-server-ts/src/console/billing/postgres.ts`                                                                                                                                                                             | Complete |
| Console prepaid-reservation D1 adapter: `packages/sdk-server-ts/src/console/billingPrepaidReservations/d1.ts`                                                                                                                                                                      | Deleted `packages/sdk-server-ts/src/console/billingPrepaidReservations/postgres.ts`                                                                                                                                                          | Complete |
| Console bootstrap-token D1 adapter: `packages/sdk-server-ts/src/console/bootstrapTokens/d1.ts`                                                                                                                                                                                     | Deleted `packages/sdk-server-ts/src/console/bootstrapTokens/postgres.ts`                                                                                                                                                                     | Complete |
| Console key-export D1 adapter: `packages/sdk-server-ts/src/console/keyExports/d1.ts`                                                                                                                                                                                               | Deleted `packages/sdk-server-ts/src/console/keyExports/postgres.ts`                                                                                                                                                                          | Complete |
| Console observability D1 adapter: `packages/sdk-server-ts/src/console/observability/d1.ts`                                                                                                                                                                                         | Deleted `packages/sdk-server-ts/src/console/observability/postgres.ts`, `incidentIngest.ts`, `queries.ts`, `retention.ts`, and `schema.ts`                                                                                                   | Complete |
| Console org/project/env D1 adapter: `packages/sdk-server-ts/src/console/orgProjectEnv/d1.ts`                                                                                                                                                                                       | Deleted `packages/sdk-server-ts/src/console/orgProjectEnv/postgres.ts`                                                                                                                                                                       | Complete |
| Console policy D1 adapter: `packages/sdk-server-ts/src/console/policies/d1.ts`                                                                                                                                                                                                     | Deleted `packages/sdk-server-ts/src/console/policies/postgres.ts`                                                                                                                                                                            | Complete |
| Console runtime-snapshot D1 adapter: `packages/sdk-server-ts/src/console/runtimeSnapshots/d1.ts`                                                                                                                                                                                   | Deleted `packages/sdk-server-ts/src/console/runtimeSnapshots/postgres.ts` and `runtimeSnapshots/retention.ts`                                                                                                                                | Complete |
| Console sponsored-call D1 adapter: `packages/sdk-server-ts/src/console/sponsoredCalls/d1.ts`                                                                                                                                                                                       | Deleted `packages/sdk-server-ts/src/console/sponsoredCalls/postgres.ts`                                                                                                                                                                      | Complete |
| Console sponsorship spend-cap D1 adapter: `packages/sdk-server-ts/src/console/sponsorshipSpendCaps/d1.ts`                                                                                                                                                                          | Deleted `packages/sdk-server-ts/src/console/sponsorshipSpendCaps/postgres.ts`                                                                                                                                                                | Complete |
| Console team-RBAC D1 adapter: `packages/sdk-server-ts/src/console/teamRbac/d1.ts`                                                                                                                                                                                                  | Deleted `packages/sdk-server-ts/src/console/teamRbac/postgres.ts`                                                                                                                                                                            | Complete |
| Console wallet-index D1 adapter: `packages/sdk-server-ts/src/console/wallets/d1.ts`                                                                                                                                                                                                | Deleted `packages/sdk-server-ts/src/console/wallets/postgres.ts`                                                                                                                                                                             | Complete |
| Console webhook D1 adapter: `packages/sdk-server-ts/src/console/webhooks/d1.ts`                                                                                                                                                                                                    | Deleted `packages/sdk-server-ts/src/console/webhooks/postgres.ts`                                                                                                                                                                            | Complete |
| Shared D1 SQL helpers: `packages/sdk-server-ts/src/storage/d1Sql.ts`                                                                                                                                                                                                               | Replaces the deleted generic Postgres helper `packages/sdk-server-ts/src/storage/postgres.ts` on the Cloudflare path                                                                                                                         | Complete |
| D1 wallet, wallet auth-method, and identity stores: `d1WalletStore.ts`, `d1WalletAuthMethodStore.ts`, and `d1IdentityStore.ts`                                                                                                                                                     | Replaces the deleted wallet/auth-method/identity blocks from `packages/sdk-server-ts/src/storage/postgres.ts`                                                                                                                                | Complete |
| D1 WebAuthn stores and auth service: `d1WebAuthnStore.ts`, `d1WebAuthnRecords.ts`, and `d1WebAuthnAuthService.ts`                                                                                                                                                                  | Replaces the deleted WebAuthn storage blocks from `packages/sdk-server-ts/src/storage/postgres.ts`                                                                                                                                           | Complete |
| D1 registration ceremony store and Durable Object owner: `d1RegistrationCeremonyStore.ts`, `d1RegistrationCeremonyRecords.ts`, and `d1RegistrationCeremonyDo.ts`                                                                                                                   | Replaces the deleted registration ceremony blocks from `packages/sdk-server-ts/src/storage/postgres.ts` and the deleted disabled D1 auth scaffold                                                                                            | Complete |
| D1 Email OTP record/store/service family: `d1EmailOtp*.ts` and `d1GoogleEmailOtp*.ts`                                                                                                                                                                                              | Replaces deleted `packages/sdk-server-ts/src/core/EmailOtpPostgresRecords.ts` and the deleted Email OTP blocks from `packages/sdk-server-ts/src/storage/postgres.ts`; provider/OIDC service leaves are first D1-only staging implementations | Complete |
| D1 session/recovery service family: `d1SessionStore.ts`, `d1SessionRecords.ts`, `d1SessionService.ts`, and `d1EmailOtpRecoveryService.ts`                                                                                                                                          | Replaces deleted recovery/session blocks from `packages/sdk-server-ts/src/storage/postgres.ts`; `/recover-email` execution remains outside first D1 staging scope                                                                            | Complete |
| D1 NEAR public-key and signing-root secret stores: `d1NearPublicKeyStore.ts` and `SigningRootSecretStore.d1.ts`                                                                                                                                                                    | Replaces deleted `ThresholdService/postgresRecords.ts` metadata helpers and deleted signing-root secret blocks from `packages/sdk-server-ts/src/storage/postgres.ts`                                                                         | Complete |
| D1 signing-session seal idempotency records: `signingSessionSeal/idempotencyRecords.ts`                                                                                                                                                                                            | Replaces deleted `packages/sdk-server-ts/src/threshold/session/signingSessionSeal/postgresRecords.ts`                                                                                                                                        | Complete |
| D1 Router API auth service leaves and boundary/config modules: `d1RouterApiAuthService.ts`, `d1RouterApiAuthBoundary.ts`, `d1RouterApiAuthConfig.ts`, `d1WalletAuthMethodService.ts`, `d1RegistrationIntentService.ts`, `d1WalletRegistrationService.ts`, `d1WalletAddSignerService.ts`, and `d1ThresholdSigningRuntime.ts` | Replace deleted `packages/sdk-server-ts/src/router/cloudflare/disabledRelayAuthService.ts`; unsupported route branches are absent or opt-in structural route dependencies                                                                    | Complete |
| Local D1 Worker: `packages/sdk-server-ts/src/router/cloudflare/d1LocalDevWorker.ts`                                                                                                                                                                                                | Replaces deleted local Docker Postgres scripts under `apps/web-server/scripts/postgres-*.mjs`, the deleted Docker compose file, and deleted live Postgres relayer runners                                                                    | Complete |
| Durable Object threshold and ceremony coordination: `packages/sdk-server-ts/src/router/cloudflare/durableObjects/thresholdStore.ts` plus D1 ceremony DO records                                                                                                                    | Replaces partial Postgres threshold session, wallet-session, presign, admission, budget, replay, and registration-finalization paths; future Postgres support must re-enter as the full-family adapter contract                              | Complete |

Phase 7 cleanup evidence:

- [x] Phase 7 start counts recorded after the first cleanup pass:
      `git diff --shortstat 20af682856f1417abdab6ec39dc7793176d35bd0 --`
      reports 261 files changed, 51,541 insertions, and 15,101 deletions.
      The non-doc slice reports 247 files changed, 48,540 insertions, and
      7,881 deletions. The `packages/sdk-server-ts/src` production slice,
      excluding typecheck fixtures, reports 134 files changed, 31,509 insertions,
      and 3,854 deletions.
- [x] Added the D1/DO adapter replacement ledger above. It names the deleted
      runtime path for each console D1 adapter and each signer/core D1 store
      family, using the current D1 adapter inventory, deleted `console/**/postgres.ts`
      files, and `git diff --name-status` over SDK server console, core, router,
      storage, and threshold paths. No runtime code changed in this documentation
      slice.
- [x] Consolidated duplicated Phase 6 staging-script test TOML fixtures into
      `tests/unit/helpers/d1StagingScriptFixtures.ts`. The cleanup deleted local
      console/router-api Wrangler profile copies from the readiness, runbook, resource
      inventory, KEK check, migration, fixture import, Time Travel bookmark,
      reconciliation, and R2 restore drill script tests. The same helper now also
      owns shared staging timestamp/origin constants, temporary JSON manifest
      paths, request URL extraction, and JSON response construction across the
      Phase 6 script tests where those values are shared fixtures. Current line
      count for the tracked config-test slice plus the shared helper is 725
      additions and 815 deletions, net -90 lines. Validation passed:
      `./node_modules/.bin/playwright test -c playwright.source.config.ts
unit/d1Staging*.script.unit.test.ts --reporter=line` with 84 tests, plus
      `git diff --check`.
- [x] Consolidated duplicated Phase 6 staging-script JSON manifest writing into
      `writeJsonManifest()` in `packages/sdk-server-ts/scripts/d1-staging-config.mjs`.
      The cleanup removed repeated manifest-directory creation and JSON formatting
      blocks from the fixture import, KEK metadata, migration, R2 restore drill,
      reconciliation, resource inventory, signer custody, smoke, Time Travel
      bookmark, and evidence verification scripts. The Refactor 82 guard now
      rejects reintroduced local manifest write blocks in those scripts.
      Validation passed: `node --check` on the shared helper plus all touched
      staging scripts, `pnpm --dir tests exec playwright test -c
      playwright.unit.config.ts` over the 12 Phase 6 staging script test files
      with 93 tests passing, the focused manifest-writer guard test, the evidence
      verifier test file with 26 tests passing, direct duplicate manifest-write
      scan, and `git diff --check`.
- [x] Consolidated duplicated Phase 6 staging-script common helpers into
      `packages/sdk-server-ts/scripts/d1-staging-config.mjs`: CLI argument
      parsing with shared string and boolean flag parsing, package-relative path
      formatting, manifest output path resolution, generated-at manifest
      stamping, dry-run/remote mode parsing, and readiness failure formatting,
      direct-invocation detection, ISO timestamp parsing, and compact ISO stamp
      formatting, Wrangler package command formatting, and staging readiness
      profile gating, CLI result printing, JSON endpoint execution, JSON record
      detection, staging origin validation, staging timeout validation,
      console/Router API staging config defaults, router-api-only staging config defaults,
      shared console/router-api option normalization, shared manifest CLI defaults,
      shared CLI exception formatting, and shared stamped manifest writing. The
      cleanup removed local helper bodies from staging migration, readiness,
      evidence verification, runbook, smoke, signer custody, fixture import,
      reconciliation, resource inventory, KEK metadata, R2 restore drill, and
      Time Travel bookmark scripts.
      The Refactor 82 guard now rejects reintroduced local copies of those helpers
      and raw Wrangler package command strings outside the shared config helper,
      local readiness collector wrappers outside the readiness-check module, and
      local result-printer functions plus local JSON endpoint plumbing outside the
      shared config helper, plus local origin and timeout validators outside the
      shared config helper, plus local `args.length` CLI parse loops outside the
      shared config helper, plus local staging Wrangler config defaults and
      console/Router API config path normalizers outside the shared config helper,
      plus local manifest CLI default blocks, local CLI exception formatting, and
      local stamped manifest output path assembly.
      Validation passed: `node --check` on all `d1-staging-*.mjs` scripts,
      `pnpm --dir tests exec playwright test -c playwright.unit.config.ts` over
      the 12 Phase 6 staging script test files with 93 tests passing, the focused
      ISO/stamp helper staging script subset with 59 tests passing, the focused
      `D1 staging scripts share` guard tests with 2 tests passing, and `pnpm --dir
      tests exec tsc -p tsconfig.playwright.json --noEmit`. A direct scan for
      local `print*Result` functions and staging JSON endpoint helper bodies
      outside `d1-staging-config.mjs`, plus local origin and timeout validators,
      plus local `args.length` parser loops, command runners, and runbook path
      resolvers, SHA-256 helper bodies, R2 bucket validators, and SQL quoting
      helpers, JSON record-shape helpers, and required package-path helpers
      returned no matches outside the shared helper. A follow-up scan for local
      staging Wrangler config defaults and repeated console/Router API config path
      normalization, local repeated manifest CLI defaults, and local CLI exception
      formatting plus local repeated stamped manifest path assembly also returned
      no matches outside the shared helper. The follow-up parser, command-runner,
      hash-helper, R2 bucket validation, SQL quoting, JSON record detection,
      required path resolution, runbook path-resolution, readiness,
      result-printing, JSON endpoint, origin, timeout, staging config default,
      console/router-api option-normalization, manifest-default, CLI-error, and
      stamped-manifest cleanup brought
      `packages/sdk-server-ts/scripts/d1-staging-*.mjs` to 4,913 total lines,
      down from the prior 4,995-line, 5,010-line, 5,033-line, 5,423-line,
      5,643-line, and 5,687-line Phase 7 helper checkpoints. The local D1
      backup/restore drill also reuses the shared
      package root, package-relative formatter, manifest writer, and string-value
      plus boolean argument parser helper, command runner, and SHA-256 file helper.
      The Refactor 82 guard now includes the local drill in the manifest-writer,
      CLI-helper, command-runner, and hash-helper duplication scans, and its
      current line count is 281 lines.
      Validation passed:
      `node --check` over all `d1-staging-*.mjs` scripts plus
      `d1-local-backup-restore-drill.mjs`, the runbook/R2 restore script tests
      with 11 tests passing, the 12 Phase 6 staging script test files with 93
      tests passing, the full Phase 6 staging script/session cluster with 99
      tests passing, the focused `D1 staging scripts share` guard tests with 2
      tests passing, the reconciliation script tests with 6 tests passing, the
      evidence verifier/fixture import/signer custody focused subset with 39 tests
      passing,
      the full Refactor 82 runtime guard with 28 tests passing,
      `pnpm --dir tests exec tsc -p
      tsconfig.playwright.json --noEmit`,
      `pnpm --dir packages/sdk-server-ts run d1:local:restore:drill --
      --skip-prepare`, and `git diff --check`.
      A later follow-up deleted the redundant `parseStringFlagArgs()` wrapper
      from `d1-staging-config.mjs`; staging scripts now import and call the single
      `parseFlagArgs()` helper directly. Current line count for
      `packages/sdk-server-ts/scripts/d1-staging-*.mjs` plus
      `d1-local-backup-restore-drill.mjs` is 6,108 lines after the wrapper
      deletion. Validation passed: `node --check` over all staging scripts plus
      the local backup/restore drill, the full 12-file Phase 6 staging script
      unit-test cluster with 121 tests passing, the focused Refactor 82 guard plus
      evidence/migration/resource-inventory script subset with 107 tests passing,
      `pnpm --dir tests exec tsc -p tsconfig.playwright.json --noEmit`, a direct
      source scan showing no remaining `parseStringFlagArgs`, and
      `git diff --check`.
- [x] Deleted repeated Phase 6 evidence-verifier test boilerplate from
      `tests/unit/d1StagingEvidenceVerify.script.unit.test.ts`. The cleanup added
      one fixture helper and one verifier-assertion helper, then removed repeated
      module loading, temp-manifest setup, and verification-call blocks from all
      53 evidence-verifier cases. A follow-up cleanup added manifest-record
      replacement/removal helpers, deleted the last full copied smoke and
      signer-custody result arrays, and removed one stale helper. A later cleanup
      replaced three single-purpose record-mutation helpers with one field-based
      helper, then collapsed the remaining single-use string replacement helpers
      into one manifest-string replacement helper, then deleted the redundant
      ID-only record replacement wrapper. The latest cleanup reused the
      field-based helper for the remaining inline manifest-record mutations.
      A later cleanup converted the repetitive rejection cases into a top-level
      mutation-case table while keeping every scenario as a named Playwright test.
      Coverage stayed intact while the untracked test file dropped from 1,930 to
      1,081 lines, an 849-line deletion. Validation passed:
      `pnpm --dir tests exec playwright test -c
      playwright.unit.config.ts unit/d1StagingEvidenceVerify.script.unit.test.ts
      --reporter=line` with 54 tests, `pnpm --dir tests exec tsc -p
      tsconfig.playwright.json --noEmit`, and `git diff --check`.
- [x] Deleted repeated Phase 6 staging-script command-runner result scaffolding
      across the migration, fixture-import, KEK-check, resource-inventory,
      Time Travel bookmark, reconciliation, and R2 restore-drill unit tests. The
      cleanup moved the shared command result type and constructor into
      `tests/unit/helpers/d1StagingScriptFixtures.ts`, then kept each script's
      branch-specific runner behavior local. The seven test files plus shared
      helper dropped from 1,621 to 1,487 lines, a net 134-line deletion after
      the helper grew by 25 lines. Validation passed:
      `pnpm --dir tests exec playwright test -c playwright.unit.config.ts
      unit/d1StagingResourceInventory.script.unit.test.ts
      unit/d1StagingFixtureImport.script.unit.test.ts
      unit/d1StagingReconciliation.script.unit.test.ts
      unit/d1StagingR2RestoreDrill.script.unit.test.ts
      unit/d1StagingMigrate.script.unit.test.ts
      unit/d1StagingSignerCustody.script.unit.test.ts
      unit/d1StagingKekCheck.script.unit.test.ts
      unit/d1StagingReadiness.script.unit.test.ts
      unit/d1StagingSmoke.script.unit.test.ts
      unit/d1StagingEvidenceVerify.script.unit.test.ts
      unit/d1StagingTimeTravelBookmark.script.unit.test.ts
      unit/d1StagingRunbook.script.unit.test.ts --reporter=line` with 121
      tests, `pnpm --dir tests exec tsc -p tsconfig.playwright.json --noEmit`,
      and `git diff --check`.
- [x] Deleted repeated Phase 6 staging-script module-loading boilerplate from all
      12 staging script unit tests. The shared fixture helper now owns the repo
      root, package root, package-relative path helper, and dynamic `.mjs` import
      wrapper. The local tests still keep script-specific module types and
      branch-specific fixtures, but no longer carry local `repoRoot`,
      `scriptPath`, `fileURLToPath`, or `pathToFileURL` setup. The 12 script
      tests plus shared helper dropped from the post-command-runner checkpoint of
      3,901 lines to 3,851 lines, a net 50-line deletion after the helper grew by
      15 lines. A follow-up cleanup deleted the remaining per-file `load*Module`
      wrappers and switched each file to one top-level module promise, bringing
      the same slice to 3,841 lines for a net 60-line deletion from that
      checkpoint. A second follow-up moved duplicated shell-token unquoting into
      the shared fixture helper for the R2 restore and Time Travel bookmark tests,
      bringing the same slice to 3,838 lines for a net 63-line deletion from that
      checkpoint. A third follow-up deleted pure `buildValidInputs()` wrappers
      from migration, resource inventory, reconciliation, R2 restore, and Time
      Travel bookmark tests by calling `writeValidD1StagingConfigFiles()` directly,
      bringing the same slice to 3,803 lines for a net 98-line deletion from that
      checkpoint. A fourth follow-up reused one read-only runbook config fixture
      across the runbook happy-path and endpoint-validation tests, bringing the
      same slice to 3,788 lines for a net 113-line deletion from that checkpoint.
      A fifth follow-up moved the repeated mis-scoped console staging config
      fixture into the shared helper and reused one read-only KEK Router API config
      path, bringing the same slice to 3,763 lines for a net 138-line deletion
      from that checkpoint.
      A sixth follow-up moved the duplicated successful command runner from the
      migration and fixture-import tests into the shared helper, bringing the same
      slice to 3,761 lines for a net 140-line deletion from that checkpoint.
      A seventh follow-up replaced three single-purpose evidence-verifier record
      mutation helpers with one field-based helper, bringing the same slice to
      3,735 lines for a net 166-line deletion from that checkpoint.
      An eighth follow-up collapsed the remaining single-use evidence-verifier
      string replacement helpers into one manifest-string replacement helper,
      bringing the same slice to 3,729 lines for a net 172-line deletion from
      that checkpoint.
      A ninth follow-up deleted the redundant evidence-verifier ID-only record
      replacement wrapper, bringing the same slice to 3,713 lines for a net
      188-line deletion from that checkpoint.
      A tenth follow-up reused the existing field-based helper for the remaining
      inline evidence-verifier manifest-record mutations, bringing the same slice
      to 3,710 lines for a net 191-line deletion from that checkpoint.
      An eleventh follow-up moved repeated JSON command-runner result construction
      into the shared fixture helper for the KEK-check, resource-inventory, and
      reconciliation tests, bringing the same slice to 3,704 lines for a net
      197-line deletion from that checkpoint.
      A twelfth follow-up moved repeated failed command-result construction into
      the shared fixture helper for migration, fixture-import, R2 restore, and
      Time Travel bookmark tests, bringing the same slice to 3,700 lines for a
      net 201-line deletion from that checkpoint.
      A thirteenth follow-up deleted the readiness test's pure temp-config wrapper
      and collapsed duplicate malformed D1 binding TOML fixture bodies, bringing
      the same slice to 3,693 lines for a net 208-line deletion from that
      checkpoint.
      A fourteenth follow-up replaced the repeated smoke endpoint
      `expect.objectContaining` blocks with one tuple assertion, bringing the same
      slice to 3,677 lines for a net 224-line deletion from that checkpoint.
      A fifteenth follow-up collapsed repeated signer-custody secret-redaction
      assertions into compact manifest regex checks, bringing the same slice to
      3,673 lines for a net 228-line deletion from that checkpoint.
      A sixteenth follow-up deleted the explicit inferred return type from the
      runbook option helper, bringing the same slice to 3,665 lines for a net
      236-line deletion from that checkpoint.
      A seventeenth follow-up replaced the fixed runbook-options builder with one
      read-only fixture object and explicit config-path overrides for the negative
      readiness case, bringing the same slice to 3,657 lines for a net 244-line
      deletion from that checkpoint.
      An eighteenth follow-up reused one R2 restore drill base input across the
      R2 restore tests and deleted explicit dry-run defaults, bringing the same
      slice to 3,648 lines for a net 253-line deletion from that checkpoint.
      A nineteenth follow-up reused base staging inputs across the migration,
      reconciliation, resource-inventory, and Time Travel bookmark tests and
      deleted repeated explicit dry-run defaults, bringing the same slice to
      3,623 lines for a net 278-line deletion from that checkpoint.
      A twentieth follow-up replaced the fixture-import input builder with one
      base fixture-import input, then reused base inputs in the KEK-check and
      smoke tests, bringing the same slice to 3,584 lines for a net 317-line
      deletion from that checkpoint.
      A twenty-first follow-up moved signer-custody export-share temp-file
      writing onto the shared staging temp-file helper and reused one local
      signer-custody input builder, bringing the same slice to 3,568 lines for a
      net 333-line deletion from that checkpoint.
      A twenty-second follow-up added one evidence-verifier manifest patch helper
      and used it for the resource-inventory, migration, fixture-import, and Time
      Travel bookmark mutation cluster, bringing the same slice to 3,541 lines
      for a net 360-line deletion from that checkpoint.
      A twenty-third follow-up reused the same patch helper for the smoke and
      signer-custody evidence-verifier mutation cluster, bringing the same slice
      to 3,521 lines for a net 380-line deletion from that checkpoint.
      A twenty-fourth follow-up reused the patch helper for the remaining
      reconciliation, R2 restore, mixed-evidence, and KEK-check verifier mutation
      cluster, then deleted the extra overwrite wrapper, bringing the same slice
      to 3,500 lines for a net 401-line deletion from that checkpoint.
      A twenty-fifth follow-up reused the shared staging temp-file helper in the
      runbook test and deleted local `os`/`path` temp-path imports, bringing the
      same slice to 3,499 lines for a net 402-line deletion from that checkpoint.
      A twenty-sixth follow-up added local evidence-verifier manifest-record and
      resource-worker patch helpers, then deleted repeated read/patch/write
      scaffolding from the evidence verifier cases, bringing the same slice to
      3,392 lines for a net 509-line deletion from that checkpoint.
      A twenty-seventh follow-up deleted the remaining single-use evidence
      verifier record/string mutation wrappers and removed `Promise.resolve`
      boilerplate from the signer-custody fetch fixture, bringing the same slice
      to 3,372 lines for a net 529-line deletion from that checkpoint.
      A twenty-eighth follow-up removed the duplicated env-scoped router-api TOML from
      the readiness test by deriving it from the shared Router API staging fixture and
      deleted the remaining smoke-test `Promise.resolve` fetch wrappers, bringing
      the same slice to 3,339 lines for a net 562-line deletion from that
      checkpoint.
      A twenty-ninth follow-up moved repeated manifest JSON reads to the shared
      staging script fixture helper, made dry-run manifest tests assert persisted
      evidence directly, and deleted two single-use readiness D1-binding wrapper
      helpers, bringing the same slice to 3,331 lines for a net 570-line deletion
      from that checkpoint.
      A thirtieth follow-up folded readiness success/failure assertions into the
      existing result-shape and error helpers, bringing the same slice to 3,323
      lines for a net 578-line deletion from that checkpoint.
      A thirty-first follow-up converted the evidence-verifier rejection tests
      from repeated per-test setup blocks to a top-level mutation-case table,
      bringing the same slice to 3,128 lines for a net 773-line deletion from
      that checkpoint.
      A thirty-second follow-up moved package-relative artifact writes for the
      R2 restore and Time Travel bookmark tests into the shared staging fixture
      helper, then deleted the local `fs`/`path`/package-root plumbing and direct
      JSON manifest reads from those two tests. The same slice is now 3,127 lines
      for a net 774-line deletion from that checkpoint.
      The signer-custody fixture helper stayed local because it creates
      per-scenario export-share files. Validation passed:
      `pnpm --dir tests exec playwright test -c playwright.unit.config.ts
      unit/d1StagingResourceInventory.script.unit.test.ts
      unit/d1StagingFixtureImport.script.unit.test.ts
      unit/d1StagingReconciliation.script.unit.test.ts
      unit/d1StagingR2RestoreDrill.script.unit.test.ts
      unit/d1StagingMigrate.script.unit.test.ts
      unit/d1StagingSignerCustody.script.unit.test.ts
      unit/d1StagingKekCheck.script.unit.test.ts
      unit/d1StagingReadiness.script.unit.test.ts
      unit/d1StagingSmoke.script.unit.test.ts
      unit/d1StagingEvidenceVerify.script.unit.test.ts
      unit/d1StagingTimeTravelBookmark.script.unit.test.ts
      unit/d1StagingRunbook.script.unit.test.ts --reporter=line` with 121
      tests, `pnpm --dir tests exec tsc -p tsconfig.playwright.json --noEmit`,
      a direct loader-boilerplate scan showing the URL/path loader only in
      `tests/unit/helpers/d1StagingScriptFixtures.ts`, a direct scan showing no
      local `load*Module` wrappers in the staging script tests, the focused R2
      restore plus Time Travel bookmark script tests with 10 tests passing after
      the shell-token cleanup, the focused migration/resource-inventory/
      reconciliation/R2-restore/Time Travel script tests with 26 tests passing
      after deleting pure config-input wrappers, the focused runbook script tests
      with 6 tests passing after reusing the shared runbook config fixture,
      the focused migration/reconciliation/resource-inventory/runbook/KEK script
      tests with 29 tests passing after the shared mis-scoped config fixture and
      KEK Router API config cleanup,
      the focused migration and fixture-import script tests with 11 tests passing
      after the shared successful command runner cleanup,
      the focused evidence verifier script test with 54 tests passing after the
      single-purpose record-mutation helper cleanup,
      the focused evidence verifier script test with 54 tests passing after the
      single-use string helper cleanup,
      the focused evidence verifier script test with 54 tests passing after the
      ID-only helper deletion,
      the focused evidence verifier script test with 54 tests passing after the
      inline manifest-record cleanup,
      the focused KEK-check/resource-inventory/reconciliation script tests with
      18 tests passing after the shared JSON command-result cleanup,
      the focused migration/fixture-import/R2-restore/Time Travel bookmark script
      tests with 21 tests passing after the shared failed command-result cleanup,
      the focused readiness script test with 9 tests passing after the readiness
      fixture cleanup,
      the focused smoke script test with 6 tests passing after the endpoint
      assertion cleanup,
      the focused signer-custody script test with 7 tests passing after the
      redaction-assertion cleanup,
      the focused runbook script test with 6 tests passing after the option-helper
      return-type cleanup,
      the focused runbook script test with 6 tests passing after the fixed-options
      fixture cleanup,
      the focused R2 restore drill script test with 5 tests passing after the
      shared R2 input cleanup,
      the focused migration/reconciliation/resource-inventory/Time Travel bookmark
      script tests with 21 tests passing after the shared base-input cleanup,
      the focused fixture-import/KEK-check/smoke script tests with 19 tests
      passing after the fixture and route-health base-input cleanup,
      the focused signer-custody script test with 7 tests passing after the
      shared temp-file and signer-custody input cleanup,
      the focused evidence verifier script test with 54 tests passing after the
      manifest patch-helper cleanup,
      the focused evidence verifier script test with 54 tests passing after the
      smoke and signer-custody patch-helper cleanup,
      the focused evidence verifier script test with 54 tests passing after the
      final verifier mutation patch-helper cleanup,
      the focused runbook script test with 6 tests passing after the shared
      temp-file output-path cleanup,
      the focused evidence verifier script test with 54 tests passing after the
      manifest-record and resource-worker patch-helper cleanup,
      the focused evidence verifier plus signer-custody script tests with 61
      tests passing after the final verifier mutation and signer-custody fetch
      cleanup,
      the focused smoke script test with 6 tests passing after the async fetch
      cleanup,
      the focused readiness script test with 9 tests passing after the env-scoped
      TOML fixture cleanup,
      the focused fixture-import, KEK-check, migration, resource-inventory,
      reconciliation, signer-custody, smoke, and readiness script tests with 51
      tests passing after the shared manifest-read and readiness-wrapper cleanup,
      the focused readiness script test with 9 tests passing after the readiness
      assertion cleanup,
      the focused evidence verifier script test with 54 tests and the full
      12-file Phase 6 staging script test cluster with 121 tests passing after
      the mutation-case cleanup,
      the focused R2 restore plus Time Travel bookmark script tests with 10 tests
      passing after the shared package-file writer cleanup,
      `pnpm --dir tests exec tsc -p tsconfig.playwright.json --noEmit`, and
      `git diff --check`.
- [x] Removed the passkey-only RP ID assumption from Ed25519 registration
      finalize. D1 wallet registration and the older `AuthService` registration
      path now pass the Ed25519 authority-scope key into HSS finalize/keygen
      instead of requiring a WebAuthn RP ID for Email OTP registration. The same
      cleanup deleted the now-unused D1 `d1RegistrationIntentPasskeyRpId`
      helper, the unused `registrationIntentRpId` wrapper, dead D1 wallet
      registration imports, one unused local helper, and one unused constant.
      `d1WalletRegistrationService.ts` dropped from 1,334 to 1,301 lines. The
      Refactor 82 guard now rejects the removed D1 helper, the removed
      `AuthService` wrapper, and the exact passkey-only RP ID error string in
      active registration code.
      Validation passed: `pnpm --dir packages/sdk-server-ts type-check`,
      `pnpm --dir tests exec playwright test -c playwright.unit.config.ts
      unit/cloudflareD1RouterApiAuthService.unit.test.ts
      unit/relayWalletRegistration.intentModes.unit.test.ts --reporter=line`
      with 37 tests, `pnpm --dir tests exec tsc -p
      tsconfig.playwright.json --noEmit`, and `git diff --check`.
- [x] Fixed ECDSA finalize key-handle allowlist semantics across the D1
      wallet-registration service, the D1 add-signer service, and the older
      `AuthService` path. A non-empty `expectedKeyHandles` list now accepts any
      matching handle instead of rejecting the first non-matching entry. Existing
      success tests now put an unexpected handle before the real handle, covering
      combined D1 registration, ECDSA-only D1 registration, D1 ECDSA add-signer,
      generic combined registration, generic ECDSA-only registration, and generic
      ECDSA add-signer. Validation passed: `pnpm --dir packages/sdk-server-ts
      type-check`, `pnpm --dir tests exec playwright test -c
      playwright.unit.config.ts unit/cloudflareD1RouterApiAuthService.unit.test.ts
      --grep "combined Ed25519 and ECDSA registration|ECDSA add-signer"
      --reporter=line` with 3 tests, `pnpm --dir tests exec playwright test
      -c playwright.unit.config.ts unit/cloudflareD1RouterApiAuthService.unit.test.ts
      --grep "ECDSA wallet registration" --reporter=line` with 3 tests,
      `pnpm --dir tests exec playwright test -c playwright.unit.config.ts
      unit/registrationIntentAllocation.unit.test.ts --grep
      "combined|ECDSA-only|add-signer" --reporter=line` with 8 tests,
      `pnpm --dir tests exec playwright test -c playwright.unit.config.ts
      unit/refactor82CloudflareD1Runtime.guard.unit.test.ts --reporter=line`
      with 43 tests, `pnpm --dir tests exec tsc -p
      tsconfig.playwright.json --noEmit`, an `rg` scan for the stale all-equal
      key-handle predicate, and `git diff --check`.
- [x] Replaced the stale staging fixture-import prefix rule with a D1
      migration-derived table allowlist. Console fixtures now validate against
      actual console D1 tables such as `organizations`, while signer fixtures
      validate against actual signer D1 tables such as `wallets`; cross-domain
      fixture writes still fail before any remote command runs. Validation passed:
      `node --check packages/sdk-server-ts/scripts/d1-staging-fixture-import.mjs`,
      `pnpm --dir tests exec playwright test -c playwright.unit.config.ts
      unit/d1StagingFixtureImport.script.unit.test.ts --reporter=line` with 6
      tests passing, and the full 12-file Phase 6 staging script cluster with 93
      tests passing.
- [x] Removed stale router API rename references from VoiceID integration docs.
      `voiceId/README.md` and the VoiceID planning docs now describe
      `RouterApiOptions`, `RouterApiModule`,
      `createVoiceIdRouterApiRouteExtension`, and
      `createVoiceIdRouterApiModule` instead of the removed `RelayRouter*` and
      `createVoiceIdRelay*` public names. The Refactor 82 stale-name guard now
      scans those VoiceID docs so the old names cannot return outside the guard's
      forbidden-token list. Validation passed: direct stale-name `rg` scan across
      `packages`, `tests`, `apps`, `voiceId`, and `docs` excluding the guard file
      and this plan found no matches; `pnpm --dir tests exec playwright test -c
playwright.unit.config.ts
unit/refactor82CloudflareD1Runtime.guard.unit.test.ts --reporter=line`
      passed with 16 tests.
- [x] Removed the last stale Router API rename references from active handoff docs.
      `docs/deployment/infra.md` now points at
      `d1RouterApiStagingWorker.ts`, and `docs/chats/chat-6-voiceId.md` now lists
      `sdkRouterApiExtension.ts`. The stale-name guard now scans both docs.
      Validation passed: `pnpm --dir tests exec playwright test -c
playwright.unit.config.ts
unit/refactor82CloudflareD1Runtime.guard.unit.test.ts --grep "stale staging and
relayer names" --reporter=line`, direct stale-name `rg` scan excluding the guard
      and this plan, and `git diff --check`.
- [x] Deleted optional live-Postgres console-router suites from
      `tests/relayer/console-router.test.ts`. The file still keeps the small
      Cloudflare runtime rejection test for Postgres tenant routes, which is the
      intentional request-boundary escape-hatch contract. Removed the live
      Postgres console service imports and direct Postgres seed helper from that
      test file. Slice diff: 59 insertions and 2,668 deletions in
      `tests/relayer/console-router.test.ts`.
- [x] Deleted optional live-Postgres console sponsored-call history and prepaid
      reservation suites from
      `tests/relayer/console-sponsored-calls.history.test.ts` and
      `tests/relayer/console-billing-prepaid-reservations.test.ts`. Current
      coverage for those files stays on in-memory router behavior and D1 adapter
      contract tests; the future Postgres backend remains a full-family contract.
      Slice diff: 1 insertion and 292 deletions across the two test files.
- [x] Deleted optional live-Postgres threshold durable-store branches from
      `tests/relayer/threshold-ecdsa.durable-stores.test.ts`. Current coverage in
      that mixed suite stays on in-memory and Cloudflare Durable Object behavior;
      dedicated Postgres adapter coverage remains the place for the future
      full-family escape hatch. Slice diff: 32 insertions and 223 deletions in
      `tests/relayer/threshold-ecdsa.durable-stores.test.ts`.
- [x] Deleted the optional live-Postgres wallet-session budget reservation
      contract from `tests/unit/walletSessionBudgetReservation.store.unit.test.ts`.
      The mixed unit suite now covers in-memory and Cloudflare Durable Object
      contracts locally, with Redis and Upstash remaining explicit external
      backend contracts. Slice diff: 20 deletions.
- [x] Deleted the optional live-Postgres sponsorship spend-cap branch from
      `tests/relayer/console-sponsorship-spend-caps.test.ts`. The mixed relayer
      suite keeps the in-memory service behavior, and D1 spend-cap behavior remains
      covered in `tests/relayer/console-d1-adapters.test.ts`. Slice diff:
      1 insertion and 131 deletions.
- [x] Deleted the disabled server-side link-device route scaffold. Removed the
      Cloudflare and Express link-device route modules, their Router API route-table
      definitions, their router registrations, the `AuthService` unsupported
      methods, the relayer route-stub test, and the source guard that protected
      the old `410` behavior. Browser-side link-device UI stubs remain outside the
      server route surface until refactor 84 provides the real feature. Targeted
      deletions include the two route files, 5 public route definitions, the
      83-line relayer test, and the obsolete core service methods.
- [x] Deleted disabled delegation route status placeholders from
      `packages/sdk-server-ts/src/router/delegation`. The static
      `enabled: false` agent-lane, delegated-signing, and linked-device lane
      exports had no importers and only preserved a disabled route surface. Slice
      diff: 30 deletions across 4 files. Validation passed: no dangling
      delegation references, `pnpm --dir packages/sdk-server-ts type-check`,
      `pnpm -s type-check:router-server`, and `git diff --check`.
- [x] Removed generic cron enable flags from the Cloudflare scheduled handler.
      `createCloudflareCron` now accepts only structural job options: providing
      `billingMonthlyFinalization`, `runtimeSnapshotOutbox`, or
      `webhookRetryDispatch` opts the job into the scheduled handler, and
      `cronExpressions` remains the per-job schedule filter. The cleanup also
      deleted the unused service argument from the factory and removed test-only
      `enabled: true` scaffolding. Slice diff: 13 insertions and 59 deletions
      across `packages/sdk-server-ts/src/router/cloudflare/cron.ts` and
      `tests/relayer/cloudflare-cron.test.ts`. Validation passed:
      `pnpm --dir packages/sdk-server-ts type-check`,
      `pnpm --dir tests exec playwright test -c playwright.relayer.config.ts
relayer/cloudflare-cron.test.ts --reporter=line`, stale scan for cron
      `enabled` patterns, and `git diff --check`.
- [x] Consolidated repeated D1 console query helpers. `storage/d1Sql.ts` now owns
      the shared `D1Row`, `queryD1One`, and `queryD1All` helpers, and the console
      D1 adapters for account, team RBAC, billing, prepaid reservations, runtime
      snapshots, sponsored calls, sponsorship spend caps, org/project/env, and
      policies no longer carry local copies of the same `queryOne`/`queryAll`
      statement plumbing. Selected-file tracked diff is 161 insertions and 257
      deletions across the helper and ten adapter files; the global Refactor 82
      aggregate dropped by another 126 added lines because these D1 adapters are
      new relative to the baseline. Validation passed:
      `pnpm --dir packages/sdk-server-ts type-check`,
      `pnpm --dir tests exec playwright test -c playwright.relayer.config.ts
relayer/console-d1-adapters.test.ts --reporter=line`, stale scan for
      remaining local `queryOne`/`queryAll` helpers in console D1 adapters, and
      `git diff --check`. Follow-up cleanup removed the remaining local
      `queryRows`/`queryFirstRow` copies from the observability and webhook D1
      adapters; those files now import `queryD1All`/`queryD1One` from
      `storage/d1Sql.ts`. The two-file follow-up diff was 26 insertions and 60
      deletions, and the stale scan for local `queryRows`, `queryFirstRow`,
      `queryAll`, and `queryOne` helpers in console D1 adapters is clean.
- [x] Consolidated repeated D1 mutation-count helpers. `storage/d1Sql.ts` now owns
      `d1ChangedRows`, and console D1 adapters no longer carry local
      `runChanges` or `d1Changes` copies. The combined D1 SQL helper cleanup now
      reports a selected-file tracked diff of 154 insertions and 282 deletions
      across the helper and 13 adapter files. Validation passed:
      `pnpm --dir packages/sdk-server-ts type-check`,
      `pnpm --dir tests exec playwright test -c playwright.relayer.config.ts
relayer/console-d1-adapters.test.ts --reporter=line`, stale scan for
      local D1 change-count helpers in console D1 adapters, and `git diff --check`.
      Follow-up cleanup moved the remaining core `d1Changes`/`toD1Changes`
      helpers from `EmailOtpStores.ts` and `d1IdentityStore.ts` onto the same
      shared helper, while preserving the `rows_written` fallback for D1 mocks.
      The current stale scan for local D1 change-count helper definitions under
      `packages/sdk-server-ts/src` is clean. Validation passed:
      `pnpm --dir packages/sdk-server-ts type-check`,
      `pnpm --dir tests exec playwright test -c playwright.unit.config.ts
unit/cloudflareD1RouterApiAuthService.unit.test.ts --reporter=line`, and
      `git diff --check`.
- [x] Consolidated repeated D1 database/config resolver helpers. `storage/d1Sql.ts`
      now owns `isD1DatabaseLike` and `resolveD1DatabaseFromConfig`, replacing the
      identical local copies in wallet, wallet auth-method, identity, Email OTP,
      NEAR public-key, WebAuthn, recovery-session, recovery-execution, and email
      recovery preparation stores. The stale scan for local
      `isD1DatabaseLike`/`resolveD1DatabaseFromConfig` definitions now finds only
      the shared helper in `storage/d1Sql.ts`. Validation passed:
      `pnpm --dir packages/sdk-server-ts type-check`,
      `pnpm --dir tests exec playwright test -c playwright.unit.config.ts
unit/cloudflareD1RouterApiAuthService.unit.test.ts
unit/walletAuthMethodStore.unit.test.ts
unit/walletScopedLookups.guard.unit.test.ts --reporter=line`, and
      `git diff --check`.
- [x] Consolidated repeated D1 JSON-column parser helpers. `storage/d1Sql.ts` now
      owns `parseD1JsonColumn`, `parseD1JsonArrayColumn`, and
      `parseD1JsonObjectColumn`. The wallet metadata store, wallet auth-method
      store, console API keys, approvals, audit, bootstrap tokens, key exports,
      observability, policies, runtime snapshots, and team RBAC adapters now use
      those helpers instead of local `JSON.parse` wrappers while keeping their
      record-specific domain parsers. Remaining direct D1 JSON parsing is scoped
      to route request boundaries, cursors, webhooks, WebAuthn record parsing, or
      local-dev request parsing. Validation passed:
      `pnpm --dir packages/sdk-server-ts type-check`,
      `pnpm --dir tests exec playwright test -c playwright.relayer.config.ts
relayer/console-d1-adapters.test.ts --reporter=line`,
      `pnpm --dir tests exec playwright test -c playwright.unit.config.ts
unit/walletAuthMethodStore.unit.test.ts
unit/walletScopedLookups.guard.unit.test.ts --reporter=line`, and
      `git diff --check`.
- [x] Renamed shared threshold persisted-record parsers from
      `ThresholdService/postgresRecords.ts` to
      `ThresholdService/persistedRecords.ts`. Current D1 and shared threshold
      stores now import backend-neutral persisted parsers, and the Ed25519,
      ECDSA, and signing-root parser tests were renamed from `*.postgresRecords`
      to `*.persistedRecords`. The Ed25519 fixtures now include split wallet and
      hosted NEAR identity fields required by the current parser.
- [x] Deleted the partial Postgres NEAR public-key metadata backend from
      `packages/sdk-server-ts/src/core/NearPublicKeyStore.ts` and removed the
      unused `near_public_keys` table from the shared Postgres schema bootstrap.
      The signer metadata factory now rejects Postgres selection until the
      full-family Postgres escape hatch exists, while D1 `signer_near_public_keys`
      remains covered by the tenant-scoped D1 contract test.
- [x] Converted `tests/relayer/sponsored-evm-call.test.ts` from optional
      Postgres-era sponsorship storage to local SQLite-backed D1 services. The
      route suite now wires D1 billing, prepaid reservations, and sponsored-call
      records against one temporary database and namespace, so the test exercises
      atomic D1 settlement for prepaid sponsored gas. The same pass extracted the
      reusable SQLite-D1 harness into `tests/helpers/sqliteD1.ts` and removed the
      duplicate embedded harness from `tests/relayer/console-d1-adapters.test.ts`.
      Shared settlement quoting now releases `rpc_rejected` and no-reference
      `broadcast_failed` reservations before pricing finalization, preserving the
      no-debit invariant for calls that never broadcast. Tracked slice diff:
      405 insertions and 365 deletions across `prepaidBalance.ts`,
      `sponsored-evm-call.test.ts`, and `console-d1-adapters.test.ts`; the new
      shared helper is 320 lines and replaces duplicated D1 test plumbing.
- [x] Deleted the optional live-Postgres console tenant-isolation relayer suite
      from `tests/relayer/console-tenant-isolation.postgres.test.ts`. The future
      Postgres backend remains a full-family escape hatch with contract tests only
      after that adapter family is production-ready. The same pass reduced
      `tests/relayer/console-observability.ingestion.test.ts` to backend-neutral
      observability envelope and redaction tests, deleting its optional live
      Postgres ingestion/query block, and removed the deleted tenant-isolation file
      from `tests/scripts/run-relayer-console-postgres.mjs`. Slice diff:
      1 insertion and 2,481 deletions across the three files.
- [x] Deleted optional live-Postgres relayer suites for bootstrap tokens, legacy
      policy-id migration, and webhooks:
      `tests/relayer/bootstrap-tokens.postgres.test.ts`,
      `tests/relayer/console-policy-id.postgres.test.ts`, and
      `tests/relayer/console-webhooks.postgres.test.ts`. Current D1 coverage for
      those domains lives in `tests/relayer/console-d1-adapters.test.ts`, and
      Cloudflare route behavior remains covered in `tests/relayer/console-router.test.ts`.
      Slice diff: 1,118 deletions.
- [x] Deleted the remaining optional live-Postgres relayer suites from
      `tests/relayer/console-billing.postgres.test.ts` and
      `tests/relayer/console-config-modules.postgres.test.ts`. Removed the now-dead
      `tests/scripts/run-relayer-console-postgres.mjs` runner, the
      `test:relayer:console-postgres` package script, and the CI step that invoked
      it. Current D1 coverage for the deleted billing/config domains lives in
      `tests/relayer/console-d1-adapters.test.ts`; Cloudflare request behavior
      remains covered in `tests/relayer/console-router.test.ts`. Slice diff:
      11 insertions and 2,182 deletions across the two suites, runner, package
      script, and CI workflow.
- [x] Deleted the partial Postgres signing-session seal idempotency backend. The
      session-seal idempotency resolver now supports in-memory, Upstash Redis REST,
      and Redis TCP only; the D1/DO staging path no longer accepts
      `SIGNING_SESSION_SEAL_IDEMPOTENCY_POSTGRES_URL` or
      `SIGNING_SESSION_SEAL_IDEMPOTENCY_POSTGRES_NAMESPACE`. The shared parser moved
      from `signingSessionSeal/postgresRecords.ts` to backend-neutral
      `signingSessionSeal/idempotencyRecords.ts`, and the last
      `POSTGRES_URL`-gated relayer test was deleted from
      `tests/relayer/signing-session-seal-router.test.ts`. Slice diff:
      71 insertions and 408 deletions across the backend, config, parser, relayer
      test, parser unit test, and guards. Follow-up cleanup removed the stale
      Postgres idempotency kind and `SIGNING_SESSION_SEAL_IDEMPOTENCY_POSTGRES_*`
      examples from `apps/web-server/.env.example`, matching the current
      in-memory/Redis-only resolver.
      A further guard review removed the redundant `idempotencyKind: "postgres"`
      assertion from `tests/relayer/signing-session-seal-router.test.ts`; the same
      test already proves unsupported kinds fail closed, and active config no longer
      names Postgres as a selectable kind. The same cleanup renamed the remaining
      backend-neutral row parser error in
      `packages/sdk-server-ts/src/router/routerAbNormalSigningAdmissionCore.ts`
      from a Postgres-specific message to `Storage row must be an object`.
- [x] Deleted disabled sponsored EVM route placeholders from the Node runner and
      Cloudflare D1 local route surface. The Node web-server no longer mounts
      `sponsoredEvmCall` with `config: null` or logs a disabled sponsored EVM
      endpoint; it still fails startup if old Node sponsored execution env is
      provided. The Cloudflare D1 service bundle now exposes `sponsoredEvmCall`
      only when a real executor config exists, the local D1 worker returns 404 for
      `/router-api/sponsorships/evm/call` without executor config, and
      `RouterApiOptions.sponsoredEvmCall.config` is non-nullable so a mounted
      sponsored gas route represents an executable capability. The follow-up
      deletion removed the obsolete `sponsored_evm_call_disabled` response branch
      from the shared router-api handler and the matching demo-site error mapping;
      mounted sponsored EVM routes now fail with concrete route/auth/runtime/chain
      misconfiguration errors. A follow-up boundary cleanup removed the request-time
      `publishable_key_auth_unavailable` branch: mounted sponsored EVM routes now
      carry a ready `publishableKeyAuth` adapter, and the legacy Express helper
      validates `ConsoleApiKeyService.authenticatePublishableKey` at route
      registration through the shared adapter constructor. Validation passed:
      `pnpm --dir packages/sdk-server-ts type-check`, `pnpm -C apps/web-server
exec tsc --noEmit`, `pnpm --dir apps/seams-site run typecheck`,
      `unit/cloudflareD1ConsoleServices.unit.test.ts`,
      `unit/router.sponsoredEvmCallCloudflare.unit.test.ts`,
      `unit/router.relayRouteSurface.unit.test.ts`,
      `relayer/sponsored-evm-call.test.ts`.
- [x] Deleted the internal Signing-session seal route `enabled` compatibility
      flag. `SigningSessionSealRoutesOptions` now represents a mounted capability
      only: provided means the route exists, omitted means it does not. A follow-up
      cleanup also removed `enabled` from `CreateSigningSessionSealOptionsInput`,
      so the SDK helper always returns concrete route options when called. The
      cleanup removed `enabled` from the route option type and constructor,
      simplified Cloudflare/Express transports and route-surface generation,
      removed enabled flags from route-surface tests, and added type fixtures
      rejecting the old `signingSessionSeal.enabled` route shape and helper input.
      Validation passed: `pnpm --dir packages/sdk-server-ts type-check`,
      `unit/router.relayRouteSurface.unit.test.ts`,
      `unit/router.routeDefinitions.unit.test.ts`,
      `relayer/signing-session-seal-router.test.ts`, and
      `relayer/health-wellknown.test.ts`. Stale-symbol scans confirm the only
      remaining `signingSessionSeal.enabled` object is the negative type fixture;
      A later local-dev cleanup removed `SIGNING_SESSION_SEAL_ENABLED` from the
      Node web-server runner and docs as well. The Node example now mounts the
      optional signing-session seal routes when all required key-material values are
      present and omits them when the key material is absent; partial key material
      remains a startup configuration error. Focused validation passed:
      `pnpm -C apps/web-server exec tsc --noEmit`, `pnpm --dir
packages/sdk-server-ts type-check`, focused route-surface and web-server
      console-config guard tests, focused signing-session seal relayer tests, and a
      stale-symbol scan proving `SIGNING_SESSION_SEAL_ENABLED` has no source or doc
      references outside this historical plan note.
- [x] Deleted the partial Postgres registration-finalization transaction branch
      from `packages/sdk-server-ts/src/core/AuthService.ts`. Wallet registration,
      add-signer, and add-auth-method finalization now consume ceremonies through
      the domain-store path only; the future Postgres escape hatch must arrive as
      a full-family adapter instead of an embedded core transaction branch. The
      same pass deleted the unused
      `putGoogleEmailOtpRegistrationAttemptWithExecutor` helper and
      `PgQueryExecutor` import from `packages/sdk-server-ts/src/core/EmailOtpStores.ts`
      and updated the Google SSO Email OTP registration guard to assert the single
      store-backed finalization path. Slice diff before this doc update: 36
      insertions and 458 deletions across `AuthService.ts`, `EmailOtpStores.ts`,
      and `tests/unit/refactor58OtpRegistrationSlim.guard.unit.test.ts`.
- [x] Deleted the partial Postgres wallet identity and wallet auth-method stores
      from `packages/sdk-server-ts/src/core/WalletStore.ts` and
      `packages/sdk-server-ts/src/core/WalletAuthMethodStore.ts`. D1 and DO
      remain the staging-capable persistent paths. The same pass removed the
      `wallets`, `wallet_signers`, and `wallet_auth_methods` bootstrap blocks
      from `packages/sdk-server-ts/src/storage/postgres.ts` and deleted the
      public executor exports from `packages/sdk-server-ts/src/index.ts`.
      Selected-path tracked diff from the Refactor 82 baseline is 291 insertions
      and 703 deletions across the modified wallet/auth-method/index/Postgres
      schema files. The later selector cleanup below removed the temporary
      Postgres-shaped rejection fixtures and branches.
- [x] Deleted the partial Postgres WebAuthn store family from
      `packages/sdk-server-ts/src/core/WebAuthnAuthenticatorStore.ts`,
      `packages/sdk-server-ts/src/core/WebAuthnCredentialBindingStore.ts`,
      `packages/sdk-server-ts/src/core/WebAuthnLoginChallengeStore.ts`, and
      `packages/sdk-server-ts/src/core/WebAuthnSyncChallengeStore.ts`. The same pass
      removed the WebAuthn executor exports from `packages/sdk-server-ts/src/index.ts`
      and deleted the old unprefixed `webauthn_authenticators`,
      `webauthn_credential_bindings`, and `webauthn_challenges` bootstrap blocks
      from `packages/sdk-server-ts/src/storage/postgres.ts`. Store/index diff:
      24 insertions and 472 deletions. The later selector cleanup below removed
      the temporary Postgres-shaped rejection fixture and branches.
- [x] Deleted the partial Postgres recovery store family from
      `packages/sdk-server-ts/src/core/RecoverySessionStore.ts`,
      `packages/sdk-server-ts/src/core/RecoveryExecutionStore.ts`, and
      `packages/sdk-server-ts/src/core/EmailRecoveryPreparationStore.ts`. The same
      pass removed the old
      `email_recovery_preparations`, `recovery_sessions`, and
      `recovery_executions` bootstrap blocks from
      `packages/sdk-server-ts/src/storage/postgres.ts`. Store/schema tracked diff:
      18 insertions and 707 deletions across the modified production files; the
      later selector cleanup below removed the temporary Postgres-shaped rejection
      fixture and branches.
- [x] Deleted the partial Postgres identity store from
      `packages/sdk-server-ts/src/core/IdentityStore.ts`. The same pass removed the exported identity executor
      helper from `packages/sdk-server-ts/src/index.ts` and deleted the old
      `identity_links` and `app_session_versions` bootstrap blocks from
      `packages/sdk-server-ts/src/storage/postgres.ts`. Selected production tracked
      diff from the Refactor 82 baseline is 21 insertions and 1,414 deletions across
      the modified identity/index/Postgres schema files. The later selector cleanup
      below removed the temporary Postgres-shaped rejection fixture and branch.
- [x] Deleted the partial Postgres registration ceremony store from
      `packages/sdk-server-ts/src/core/RegistrationCeremonyStore.ts`. Cloudflare
      Durable Object remains the durable staging path. The same pass removed the old
      `wallet_registration_intents` and `wallet_registration_ceremonies` bootstrap
      blocks from `packages/sdk-server-ts/src/storage/postgres.ts`. Selected-file
      tracked diff from the Refactor 82 baseline is 167 insertions and 1,172
      deletions across the ceremony store, shared Postgres schema, and focused
      ceremony store tests. The later selector cleanup below removed the temporary
      Postgres-shaped rejection fixture and branch.
- [x] Deleted the partial Postgres signing-root secret store from
      `packages/sdk-server-ts/src/core/ThresholdService/stores/SigningRootSecretStore.ts`.
      The threshold service barrel no longer exports `PostgresSigningRootSecretStore`,
      and the old unprefixed `signing_root_secret_shares` bootstrap/reset references
      are gone from the shared Postgres schema and local reset runbook. D1
      `signer_signing_root_secret_shares` remains the sealed-share staging table; a
      future Postgres escape hatch must implement the full signer-family backend
      before it can be selected.
- [x] Deleted the partial Postgres threshold key-store backend from
      `packages/sdk-server-ts/src/core/ThresholdService/stores/KeyStore.ts`. The
      first deletion pass removed the old `threshold_ed25519_keys` and
      `threshold_ecdsa_keys` bootstrap/reset references plus the obsolete
      `tests/unit/thresholdEcdsa.postgresKeyStoreBackfill.unit.test.ts` suite.
      The later threshold config cleanup below removed the temporary
      Postgres-shaped selection surface.
- [x] Deleted the partial Postgres threshold session-store backend from
      `packages/sdk-server-ts/src/core/ThresholdService/stores/SessionStore.ts`.
      The first deletion pass kept existing in-memory presign/session behavior
      covered while removing the partial Postgres backend. The later threshold
      config cleanup below removed the temporary Postgres-shaped selection surface.
- [x] Deleted the partial Postgres wallet-session backend from
      `packages/sdk-server-ts/src/core/ThresholdService/stores/WalletSessionStore.ts`.
      The first deletion pass removed the `threshold_ed25519_sessions`,
      `threshold_wallet_session_consumptions`, and
      `threshold_wallet_session_budget_reservations` bootstrap/reset references.
      The obsolete wallet-session malformed-row assertions were removed before
      the suite was retired by the ECDSA presign deletion pass. The later threshold
      config cleanup below removed the temporary Postgres-shaped selection surface.
- [x] Deleted the partial Postgres ECDSA presign backend from
      `packages/sdk-server-ts/src/core/ThresholdService/stores/EcdsaSigningStore.ts`.
      The first deletion pass removed the `threshold_ecdsa_presign_sessions` and
      `threshold_ecdsa_presignatures` bootstrap/reset references and deleted
      the obsolete `tests/unit/thresholdPostgresMalformedCleanup.unit.test.ts`
      suite that only exercised the removed backend. The later threshold config
      cleanup below removed the temporary Postgres-shaped selection surface.
- [x] Deleted stale threshold partial-Postgres selection guards and tests.
      `ThresholdStoreConfig` no longer includes `kind: "postgres"` and
      `ThresholdStoreEnvInput` no longer includes `POSTGRES_URL`. The key-store,
      session-store, wallet-session, and ECDSA presign factories share one
      raw-boundary unknown-kind guard instead of carrying Postgres-specific
      rejection branches. The same pass removed obsolete runtime-rejection tests
      from the threshold persisted-record, presign, and wallet budget suites and
      added `ThresholdStoreConfig.typecheck.ts` fixtures proving Postgres-shaped
      threshold config is rejected at compile time. Selected slice diff from
      `HEAD`: 241 insertions and 3,103 deletions in tracked core/test files, plus
      59 new helper/type-fixture lines. Validation passed: `pnpm --dir
packages/sdk-server-ts type-check`, `pnpm -s type-check:router-server`,
      the focused threshold store/D1 runtime Playwright unit slice, stale
      threshold Postgres scans excluding typecheck fixtures, and `git diff --check`.
- [x] Deleted stale signer metadata and Email OTP partial-Postgres selector guards
      and tests. Wallet, wallet auth-method, WebAuthn, recovery, identity,
      NEAR-public-key, registration ceremony, and Email OTP factories no longer
      carry Postgres-specific rejection branches; explicit unrecognized store kinds
      fail as unknown kinds, while D1/DO, Redis/Upstash, and in-memory selections
      that are still valid keep their existing behavior. The same pass removed
      obsolete runtime-rejection fixtures from the focused wallet/auth-method,
      WebAuthn, recovery, identity, NEAR public-key, registration ceremony, and
      Email OTP tests. Selected slice diff from `HEAD`: 173 insertions and 3,990
      deletions across tracked core/test files. Validation passed: `pnpm --dir
packages/sdk-server-ts type-check`, `pnpm -s type-check:router-server`, the
      focused Email OTP/wallet-auth-method/registration-ceremony/D1 runtime
      Playwright unit slice, source-level stale partial-Postgres scans, and
      `git diff --check`.
- [x] Deleted the partial Postgres normal-signing admission backend from
      `packages/sdk-server-ts/src/router/routerAbNormalSigningAdmissionStore.ts`.
      The facade and public SDK exports now expose only Durable Object and
      in-memory admission stores. A type fixture rejects the old
      `PostgresRouterAbNormalSigningAdmissionStoreOptions` export so quota,
      project-policy, and abuse admission cannot silently reintroduce a partial
      Postgres hot path.
- [x] Deleted the unused shared Postgres schema initializer and the remaining
      generic `packages/sdk-server-ts/src/storage/postgres.ts` public helper.
      Removed the last `AuthService` warmup call that created shared Postgres
      tables. Future Postgres support now lives only in the full-family
      `TenantStorageRoute` adapter contract and migration playbook. The stale
      local Postgres reset runbook and SQL file were deleted, and deployment docs
      now describe D1/DO/R2 as the staging data plane.
- [x] Deleted stale Node router-api-server signer/split Postgres scaffolding. Root
      `router:server` now starts the local Wrangler/Miniflare D1 Worker by
      default, the Express example no longer wires signer/threshold Postgres,
      normal-signing admission Postgres, or session-seal Postgres idempotency,
      and the removed signer/split migration scripts plus their unit/script
      helpers are gone. Console Postgres remains explicit console-only boundary
      code. Selected slice diff: 44 insertions and 1,578 deletions.
- [x] Deleted the remaining Router A/B local-dev Postgres seed scripts:
      `crates/router-ab-dev/scripts/seed-ecdsa-wallet-session.mjs` and
      `crates/router-ab-dev/scripts/seed-ed25519-key-store.mjs`. These scripts
      wrote directly to the removed partial Postgres threshold key-store and
      wallet-session tables and had no package-script or source references after
      local development moved to SQLite/D1/DO seed tooling. Added a Refactor 82
      guard that scans `crates/router-ab-dev/scripts` for `POSTGRES_URL`,
      `threshold_ed25519_keys`, and the removed wallet-session Postgres tables.
      Slice diff: 125 insertions and 557 deletions across the guard and the two
      deleted scripts. Validation passed: `pnpm --dir tests exec playwright test
-c playwright.unit.config.ts
unit/refactor82CloudflareD1Runtime.guard.unit.test.ts --reporter=line`,
      stale scans for the deleted script names outside this plan and for Postgres
      seed tokens under `crates/router-ab-dev/scripts`, and the app/package/crate/test
      `POSTGRES_URL` inventory now finds only negative tests, type fixtures, and
      the guard itself.
- [x] Deleted the Router A/B local persistence seed planner's Postgres SQL
      dialect branch. `LocalPersistenceSqlDialectV1` is gone, seed plans and
      execution receipts no longer carry a one-value dialect field, and
      `local_persistence_seed_sql_plan_v1` now produces SQLite statements for the
      local D1-compatible dev harness only. Removed the obsolete Postgres
      placeholder assertions, the SQLite-executor rejection test for Postgres
      plans, and the redundant `dialect: "sqlite"` JSON field from
      `dev_seed_router_ab_sqlite`. Validation passed:
      `cargo test --manifest-path crates/router-ab-core/Cargo.toml --test local
local_persistence`,
      `cargo test --manifest-path crates/router-ab-dev/Cargo.toml --test
sqlite_seed`, `cargo fmt --manifest-path crates/router-ab-core/Cargo.toml`,
      `cargo fmt --manifest-path crates/router-ab-dev/Cargo.toml`, and stale scans
      for `LocalPersistenceSqlDialectV1`, `Postgres`, `postgres`, and `dialect`
      under `crates/router-ab-core` and `crates/router-ab-dev`.
- [x] Rewrote stale SaaS architecture notes that still described live Postgres
      validation, Postgres-backed console isolation, or atomic Postgres sponsored
      settlement as current work. The current docs now point billing,
      prepaid-reservation, dashboard-backend, account-settings, gas-sponsorship,
      and wallet-session budget validation at local SQLite-D1, staging D1, D1
      tenant-scope tests, Durable Objects, Redis, and Upstash where those backends
      still exist. Targeted doc cleanup diff: 74 insertions and 91 deletions
      across `docs/saas/billing-2.md`, `docs/saas/prepaid-billing.md`,
      `docs/saas/gas-sponsorship-prepaid-balances.md`,
      `docs/saas/dashboard-backend-implementation-plan.md`,
      `docs/saas/account-settings.md`, and `docs/refactor-70-server-budget.md`.
      Validation passed: stale scans for `Postgres-backed`, `atomic Postgres`,
      `live Postgres`, `real Postgres`, `Postgres suites`,
      `*_POSTGRES_URL`, and `Postgres variants` under those docs return no
      matches, and `git diff --check` passes.
- [x] Tightened the account-settings plan around the current D1 account adapter.
      `docs/saas/account-settings.md` now points at
      `packages/sdk-server-ts/src/console/account`, names the D1 account tables
      `organizations`, `user_profiles`, and `user_backup_emails`, and lists
      `d1.ts` as the backend module instead of the deleted Postgres adapter.
      The Refactor 82 guard rejects the old `server/src/console/account` path,
      `postgres.ts`, `account Postgres slice`, and stale `console_*` account table
      names in that doc. Validation passed:
      `pnpm --dir tests exec playwright test -c playwright.unit.config.ts
unit/refactor82CloudflareD1Runtime.guard.unit.test.ts --reporter=line` with 35
      tests, `pnpm --dir tests exec tsc -p tsconfig.playwright.json --noEmit`,
      targeted stale scan for those account-settings patterns, and
      `git diff --check`.
- [x] Rewrote the active observability architecture and event-surfacing docs to
      the D1-era module layout. `docs/saas/observability-events-3.md` and
      `docs/saas/observability-events-4.md` now point at
      `packages/sdk-server-ts/src`, `apps/seams-site`, the D1 observability
      migration, `d1.ts`, `policy.ts`, `requestRollups.ts`, `redaction.ts`, and
      shared router hooks instead of deleted `server/src`,
      `examples/seams-site`, `postgres.ts`, and `console_observability_*`
      names. The Refactor 82 guard now blocks those stale observability doc
      references. Observability-doc slice diff: 83 insertions and 82 deletions.
      Validation passed:
      `pnpm --dir tests exec playwright test -c playwright.unit.config.ts
unit/refactor82CloudflareD1Runtime.guard.unit.test.ts --reporter=line` with 36
      tests, `pnpm --dir tests exec tsc -p tsconfig.playwright.json --noEmit`,
      targeted stale scan for the observability-doc patterns, and
      `git diff --check`.
- [x] Rewrote `docs/saas/generalized-gas-sponsorship.md` links to the current
      sponsorship, policy, dashboard, and app-server modules. The doc now points
      at `packages/sdk-server-ts/src`, `apps/seams-site`, `apps/web-server`, and
      current Cloudflare route filenames
      `router/cloudflare/routes/sponsoredEvmCall.ts` and
      `router/cloudflare/routes/signedDelegate.ts`. The Refactor 82 guard now
      rejects the old `simple-threshold-signer` workspace, old `server/src`,
      `examples/seams-site`, `examples/router-api-server`, deleted Router API route
      filenames, broken chained replacements, and deleted `postgres.ts` adapter
      references in that doc. Generalized sponsorship doc slice diff: 44
      insertions and 44 deletions. Validation passed:
      `pnpm --dir tests exec playwright test -c playwright.unit.config.ts
unit/refactor82CloudflareD1Runtime.guard.unit.test.ts --reporter=line` with 37
      tests, `pnpm --dir tests exec tsc -p tsconfig.playwright.json --noEmit`,
      targeted stale scan for the generalized sponsorship doc patterns, markdown
      absolute-link existence check for that doc, and `git diff --check`.
- [x] Rewrote active schema and dashboard backend docs away from Postgres/RLS
      tenant language. `docs/saas/db-schema.md` and
      `docs/saas/dashboard-backend-implementation-plan.md` now name the current
      D1 account tables (`organizations`, `user_profiles`, `user_backup_emails`)
      and describe tenant isolation as explicit `namespace` / `org_id` scoping,
      D1 schema constraints, and D1 service-level tenant-isolation tests. The
      Refactor 82 guard now rejects the old account table names plus
      `app.console_*`, transaction-scoped Postgres wiring, RLS enforcement,
      Force-RLS billing wording, and DB-level Postgres policy-test wording in
      those docs. Schema/dashboard doc slice diff: 45 insertions and 45
      deletions. Validation passed:
      `pnpm --dir tests exec playwright test -c playwright.unit.config.ts
unit/refactor82CloudflareD1Runtime.guard.unit.test.ts --reporter=line` with 38
      tests, `pnpm --dir tests exec tsc -p tsconfig.playwright.json --noEmit`,
      targeted stale scan for the schema/dashboard patterns, and
      `git diff --check`.
- [x] Rewrote policy ID and dashboard backend policy docs to current D1 policy
      table names. `docs/saas/policyId.md` now defines `policyId` against
      `policies.id` and describes the removed gas sponsorship config model
      without naming the deleted `console_gas_sponsorship_configs` table. The
      dashboard backend plan now names `policies`, `policy_versions`, and
      `policy_assignments`. The Refactor 82 guard now rejects the old
      console-prefixed policy table names in those docs. Policy-table doc slice
      diff: 49 insertions and 50 deletions across the docs, plus focused guard
      coverage. Validation passed:
      `pnpm --dir tests exec playwright test -c playwright.unit.config.ts
unit/refactor82CloudflareD1Runtime.guard.unit.test.ts --reporter=line` with 39
      tests, `pnpm --dir tests exec tsc -p tsconfig.playwright.json --noEmit`,
      targeted stale scan for the policy table-name patterns, and
      `git diff --check`.
- [x] Rewrote active billing and sponsorship docs to current D1 billing table
      names. `docs/saas/billing-2.md` and `docs/saas/prepaid-billing.md` now use
      `billing_accounts`, `billing_ledger_entries`, `billing_ledger_postings`,
      `invoices`, `invoice_line_items`, and ledger/invoice-derived activity
      views. `docs/saas/gas-sponsorship-prepaid-balances.md` now uses
      `sponsored_call_records`. The Refactor 82 guard now rejects the old
      console-prefixed billing and sponsored-call table names in those active docs.
      Billing/sponsorship table-name doc slice diff: 168 insertions and 159
      deletions across the docs, plus focused guard coverage. Validation passed:
      `pnpm --dir tests exec playwright test -c playwright.unit.config.ts
unit/refactor82CloudflareD1Runtime.guard.unit.test.ts --reporter=line` with 39
      tests, `pnpm --dir tests exec tsc -p tsconfig.playwright.json --noEmit`,
      targeted stale scan for the billing/sponsorship table-name patterns, and
      `git diff --check`.
- [x] Deleted legacy threshold-session parser compatibility exports from
      `packages/sdk-server-ts/src/core/ThresholdService/validation.ts`. The
      obsolete `parseThresholdEd25519SessionClaims`,
      `parseThresholdEcdsaSessionClaims`, and `LegacyThreshold*SessionClaims`
      types were only supporting historical acceptance tests; active Router A/B
      route/service code already uses the strict Router A/B Wallet Session
      parsers and still rejects old threshold-session JWT kinds. The cleanup
      removed the historical acceptance assertions from
      `tests/unit/thresholdSessionClaims.unit.test.ts`, removed the guard
      allowlist for `validation.ts`, and updated the Router A/B issuer guard to
      assert the current claim-builder functions. Slice diff before this plan
      update: 10 insertions and 118 deletions across the parser and two unit
      guard files. Validation passed: `pnpm --dir packages/sdk-server-ts
type-check`, `pnpm --dir tests exec playwright test -c
playwright.unit.config.ts unit/thresholdSessionClaims.unit.test.ts
unit/routerAbServerWalletSessionClaimBoundary.guard.unit.test.ts
--reporter=line`, and a production source scan for the deleted parser and
      legacy type names returned no matches.
- [x] Deleted the app-server raw Postgres demo wallet seed path. Demo console
      wallet seeding now writes through `ConsoleWalletService.upsertWallet` for
      every app-server backend and skips existing wallet rows, preserving the old
      seed-once behavior at the service boundary. `apps/web-server/src/index.ts`
      no longer imports `pg` or opens a raw `Pool`. Current tracked app-server
      diff from `HEAD`: 50 insertions and 103 deletions.
- [x] Deleted the active `apps/web-server` console Postgres runtime path. The
      Node example now wires console state through in-memory services only,
      rejects configured Node sponsored-EVM execution with a Cloudflare D1/DO
      handoff error, and no longer exposes Postgres console backend selection.
      Removed the web-server Postgres Docker compose file, Postgres up/down/migrate
      scripts, package scripts, config fields, and README/env-example instructions.
      The future Postgres escape hatch remains at SDK adapter/contract boundaries,
      not in the active Node staging runner. Selected slice diff from `HEAD`:
      139 insertions and 1,064 deletions across web-server source, docs, scripts,
      package config, and the focused config test.
- [x] Deleted the stale `createPostgresConsoleBillingService` import from
      `tests/relayer/console-billing.service.test.ts`. That file now exercises
      only in-memory billing behavior; D1 billing, prepaid reservation, Stripe
      idempotency, monthly statement, and sponsored settlement behavior remain in
      `tests/relayer/console-d1-adapters.test.ts`. Slice diff: 1 deletion.
- [x] Deleted the partial console-only Postgres adapter family. Removed
      `packages/sdk-server-ts/src/console/**/postgres.ts`, the Postgres-only
      observability/query/retention helper modules, the runtime-snapshot Postgres
      retention helper, and the shared console Postgres tenant/normalization
      helpers. Console barrels and the Express router barrel now export D1 and
      in-memory console services only; the package smoke test asserts that Express
      and Cloudflare router barrels do not expose partial console Postgres service
      factories. Postgres remains only as a future full-family backend contract in
      `TenantStorageRoute`, schema semantics, and the migration playbook. Focused
      slice diff before this plan update:
      271 insertions and 18,540 deletions across console/router/app-server source,
      the package smoke test, the D1 runtime guard, and the stale dashboard backend
      note. The same pass removed the obsolete `authService.initStorage()` startup
      warmup from the Node app-server example.
- [x] Validation passed: `pnpm --dir packages/sdk-server-ts type-check`,
      `pnpm -s type-check:router-server`, `pnpm -C apps/web-server exec tsc
--noEmit`, and `pnpm --dir tests exec playwright test -c
playwright.unit.config.ts unit/refactor51bPackageInstallSmoke.unit.test.ts
unit/refactor82CloudflareD1Runtime.guard.unit.test.ts --reporter=line`.
      Stale scans find no console Postgres implementation files and no remaining
      `createPostgresConsole*`, `ensureConsole*Postgres`, `runPostgresConsole*`,
      or `PostgresConsole*` source symbols outside the tenant-route type fixture,
      package smoke absence assertions, and historical Refactor 82 notes.
- [x] Split console authentication out of the broad console router module into
      `packages/sdk-server-ts/src/router/consoleAuth.ts` and repointed
      Cloudflare and Express runtime imports at that leaf. `router/console.ts`
      still owns `ConsoleRouterOptions` and re-exports the auth surface for public
      API continuity, while Worker runtime code now imports
      `authenticateConsoleRequest`, `hasConsoleRole`, `ConsoleAuthClaims`,
      `ConsoleAuthAdapter`, and `HeaderRecord` from `consoleAuth`. The same pass
      moved internal auth imports in route-policy, observability, platform billing,
      app-session console auth, Cloudflare local D1 dev, and both console routers
      off the broad module. The stale runtime-import scan
      `rg -n -P "^import(?!\\s+type).*from ['\\\"]\\.\\./console['\\\"]"
packages/sdk-server-ts/src/router/cloudflare
packages/sdk-server-ts/src/router/express --glob '*.ts'` now returns no
      matches. Type-only `ConsoleRouterOptions` imports remain intentional because
      the router option shape is the current request-boundary contract, and they
      are erased from Worker runtime output. The validation run also exposed a
      stale webhook delivery-order assertion that depended on same-millisecond
      ordering; the test now verifies the delivered event set and keeps
      observability ingestion as the chronological balance-transition assertion.
      Validation passed: `pnpm --dir packages/sdk-server-ts type-check`,
      `pnpm -s type-check:router-server`, `pnpm --dir tests exec tsc -p
tsconfig.playwright.json --noEmit`, `pnpm --dir tests exec playwright test
-c playwright.relayer.config.ts relayer/console-router.test.ts
--reporter=line`, the stale runtime-import scan above, and
      `git diff --check`.
- [x] Removed generic wallet-as-NEAR validation from the AuthService D1-era
      identity paths. WebAuthn login, Email OTP unlock, OIDC linked-wallet
      resolution, Google Email OTP enrollment lookup, and hosted Google Email OTP
      cleanup now boundary-parse wallet identity with the wallet parser. Hosted
      relayer-wallet branches use the branch-specific
      `isHostedHmacReadableRelayerWalletId` predicate, and the generic
      `isRelayerSubaccount` helper was deleted. The split-identity scan now only
      returns the intentional `hostedAccountIds.ts` internals that parse hosted
      NEAR-shaped relayer wallet IDs. `walletScopedLookups.guard.unit.test.ts`
      now fails on reintroduced direct `isValidAccountId(...)` calls for
      `walletId`, `userId`, `linkedWalletId`, or `enrollment.walletId` in
      `AuthService.ts`; the hosted-account privacy fixture was updated to include
      the current runtime-policy scope rather than stale resumable-attempt
      behavior. Validation passed:
      `pnpm --dir packages/sdk-server-ts type-check`,
      `pnpm --dir tests exec tsc -p tsconfig.playwright.json --noEmit`,
      `pnpm --dir tests exec playwright test -c playwright.unit.config.ts
unit/walletScopedLookups.guard.unit.test.ts
unit/authService.hostedAccountPrivacy.unit.test.ts --reporter=line`,
      `pnpm --dir tests exec playwright test -c playwright.relayer.config.ts
relayer/email-otp.authservice.test.ts --reporter=line`, the
      split-identity scan, and `git diff --check`.
- [x] Removed root passkey fields from NEAR public-key metadata. Core
      `NearPublicKeyRecord`, Cloudflare D1 `NearPublicKeyRecord`, AuthService
      record creation, and the Cloudflare D1 list response now use
      `authBinding: { kind: 'passkey', rpId, credentialIdB64u }` instead of
      root `rpId`/`credentialIdB64u`. The record parsers reject stale root fields,
      and `walletScopedLookups.guard.unit.test.ts` now fails if the root fields
      return to either NEAR public-key record type or if the Cloudflare list
      response flattens them again. At the time of this cleanup, the remaining
      RP-scope inventory was threshold Ed25519 session policy plus signing-root
      migration/context records; the later signing-root cleanup below narrows the
      remaining work to live threshold Ed25519 session policy. Validation passed:
      `pnpm --dir packages/sdk-server-ts type-check`,
      `pnpm --dir tests exec tsc -p tsconfig.playwright.json --noEmit`,
      `pnpm --dir tests exec playwright test -c playwright.unit.config.ts
unit/walletScopedLookups.guard.unit.test.ts --grep "D1 auth and recovery
boundaries" --reporter=line`,
      `pnpm --dir tests exec playwright test -c playwright.unit.config.ts
unit/cloudflareD1RouterApiAuthService.unit.test.ts --grep "reads signer
metadata with tenant scope" --reporter=line`,
      `pnpm --dir tests exec playwright test -c playwright.relayer.config.ts
relayer/console-d1-adapters.test.ts --grep "signer NEAR public key
metadata is scoped in D1" --reporter=line`, and `git diff --check`.
- [x] Removed root `rpId` from signing-root migration/context records.
      `SigningRootRecord`, migration bundles, wallet inventory entries, Durable
      Object wire records, and signing-root status responses now carry
      `authorityScope: { kind: 'passkey_rp', rpId }`. The parser rejects stale
      root `rpId` on records and migration bundles; the typecheck fixture rejects
      direct root `rpId` construction for records, bundles, and wallet inventory
      entries. Self-host and Durable Object signing-root fixtures now import the
      new authority-scope shape. Remaining RP-scope cleanup is narrowed to live
      threshold Ed25519 session policy and presign/session records. Validation
      passed: `pnpm --dir packages/sdk-server-ts type-check`,
      `pnpm --dir tests exec tsc -p tsconfig.playwright.json --noEmit`,
      `pnpm --dir tests exec playwright test -c playwright.unit.config.ts
unit/signingRootRecords.script.unit.test.ts
unit/thresholdPrf.cloudflareWorkerSigningRoot.script.unit.test.ts
--reporter=line`, `pnpm --dir tests exec playwright test -c
playwright.unit.config.ts unit/cloudflareSelfHostedSigningWorker.script.unit.test.ts
--grep "signing-root|self-host Cloudflare signing router" --reporter=line`,
      the signing-root stale root-`rpId` scan, and `git diff --check`.
- [x] Removed root `rpId` from live threshold Ed25519 session and presign state.
      `Ed25519SessionPolicy`, Ed25519 wallet-session records, Ed25519 MPC/signing
      records, Router A/B Ed25519 presign records, and presign expected scopes now
      use `authorityScope: { kind: 'passkey_rp', rpId }`. The route parser rejects
      stale root `sessionPolicy.rpId`, persisted-record parsers reject stale root
      `rpId`, and `thresholdEd25519AuthorityScope.typecheck.ts` rejects direct
      root `rpId` construction for the changed domain objects. The web
      `buildEd25519SessionPolicy` builder now validates its passkey RP input and
      emits the authority-scope shape. Validation passed: `pnpm --dir
packages/sdk-server-ts type-check`, `pnpm --dir packages/sdk-web type-check`,
      `pnpm --dir tests exec tsc -p tsconfig.playwright.json --noEmit`, and
      `pnpm --dir tests exec playwright test -c playwright.unit.config.ts
unit/thresholdEd25519.sessionPolicyDigest.unit.test.ts
unit/thresholdEd25519.presignStore.unit.test.ts
unit/signingSessionSeal.sessionPolicy.unit.test.ts
unit/walletSessionBudgetReservation.store.unit.test.ts --reporter=line`.
- [x] Removed root `rpId` from threshold Ed25519 key-store records.
      `ThresholdEd25519KeyRecord`, its persisted-record parser, Durable Object
      key-store reads, in-memory/Redis key stores, registration material replay,
      HSS registration finalization, Router A/B SigningWorker material lookup, and
      relayer-share repair now use `authorityScope: { kind: 'passkey_rp', rpId }`
      for the passkey authority branch. Request bodies and wallet-session JWT
      claims still carry passkey `rpId` at the route/auth boundary, then normalize
      before comparing with persisted key identity. The parser rejects stale root
      `rpId` key records, and `thresholdEd25519AuthorityScope.typecheck.ts`
      rejects direct root `rpId` construction for key-store records. Validation
      passed: `pnpm --dir packages/sdk-server-ts type-check`,
      `pnpm --dir tests exec tsc -p tsconfig.playwright.json --noEmit`, `pnpm
--dir tests exec playwright test -c playwright.unit.config.ts
unit/thresholdEcdsa.persistedRecords.unit.test.ts
unit/thresholdEd25519.persistedRecords.unit.test.ts
unit/thresholdEd25519.presignStore.unit.test.ts
unit/walletScopedLookups.guard.unit.test.ts
unit/registrationIntentDigest.unit.test.ts --reporter=line`, the D1
      `isValidAccountId` scan, the threshold key-store stale-root scan, and
      `git diff --check`.
- [x] Validation passed: `pnpm --dir tests exec playwright test -c
playwright.relayer.config.ts relayer/console-billing.service.test.ts
--reporter=line`, `pnpm --dir tests exec playwright test -c
playwright.unit.config.ts unit/walletScopedLookups.guard.unit.test.ts
unit/registrationIntentDigest.unit.test.ts
unit/refactor82CloudflareD1Runtime.guard.unit.test.ts --reporter=line`,
      stale scans for `createPostgresConsoleBillingService` in the billing service
      test and direct `isValidAccountId` usage in production Cloudflare `d1*.ts`
      modules.
- [x] Validation passed: `pnpm --dir packages/sdk-web type-check`,
      `pnpm --dir packages/sdk-server-ts type-check`, and
      `pnpm --dir tests exec playwright test -c playwright.relayer.config.ts
relayer/console-router.test.ts --grep "GET /console/webhooks rejects
Postgres tenant routes|GET /console/healthz works|cloudflare POST
/console/projects auto-provisions" --reporter=line`.
- [x] Validation passed: `pnpm --dir packages/sdk-web type-check`,
      `pnpm --dir packages/sdk-server-ts type-check`, and
      `pnpm --dir tests exec playwright test -c playwright.relayer.config.ts
relayer/console-sponsored-calls.history.test.ts
relayer/console-billing-prepaid-reservations.test.ts --reporter=line`.
- [x] Validation passed: `pnpm --dir packages/sdk-web type-check`,
      `pnpm --dir packages/sdk-server-ts type-check`, `pnpm --dir tests exec
playwright test -c playwright.relayer.config.ts
relayer/threshold-ecdsa.durable-stores.test.ts --reporter=line`, and
      `git diff --check`.
- [x] Validation passed: `pnpm --dir packages/sdk-server-ts type-check`,
      `pnpm --dir tests exec playwright test -c playwright.unit.config.ts
unit/walletSessionBudgetReservation.store.unit.test.ts --reporter=line`,
      and `git diff --check`.
- [x] Validation passed: `pnpm --dir packages/sdk-server-ts type-check`,
      `pnpm --dir tests exec playwright test -c playwright.relayer.config.ts
relayer/console-sponsorship-spend-caps.test.ts --reporter=line`, and
      `git diff --check`.
- [x] Validation passed: `pnpm --dir packages/sdk-server-ts type-check`,
      `pnpm --dir packages/sdk-web type-check`,
      `pnpm --dir tests exec playwright test -c playwright.relayer.config.ts
relayer/sponsored-evm-call.test.ts --reporter=line`,
      `pnpm --dir tests exec playwright test -c playwright.relayer.config.ts
relayer/console-d1-adapters.test.ts --grep "sponsored gas settlement writes
reservation|sponsored gas settlement rejects stale" --reporter=line`, and
      `git diff --check`.
- [x] Validation passed: `pnpm --dir packages/sdk-server-ts type-check`,
      `pnpm --dir packages/sdk-web type-check`,
      `pnpm --dir tests exec playwright test -c playwright.relayer.config.ts
relayer/console-observability.ingestion.test.ts --reporter=line`, and
      `git diff --check`.
- [x] Validation passed: `pnpm --dir packages/sdk-server-ts type-check`,
      `pnpm --dir packages/sdk-web type-check`,
      `pnpm --dir tests exec playwright test -c playwright.relayer.config.ts
relayer/console-d1-adapters.test.ts --grep "bootstrap token
adapter|webhook adapter stores|webhook D1 retry dispatch|policy adapter
bootstraps" --reporter=line`, and `git diff --check`.
- [x] Validation passed: `pnpm --dir packages/sdk-server-ts type-check`,
      `pnpm --dir packages/sdk-web type-check`, `node -e
"JSON.parse(require('fs').readFileSync('tests/package.json','utf8'));
console.log('tests/package.json ok')"`, `pnpm --dir tests exec playwright
test -c playwright.relayer.config.ts relayer/console-d1-adapters.test.ts
--grep "key export adapter|policy adapter bootstraps|billing reservations
are trigger-atomic|billing credit purchases settle|billing monthly
finalization|runtime snapshot outbox claim lease" --reporter=line`, and
      `git diff --check`.
- [x] Validation passed: `pnpm --dir packages/sdk-server-ts type-check`,
      `pnpm --dir packages/sdk-web type-check`,
      `pnpm --dir tests exec playwright test -c playwright.relayer.config.ts
relayer/signing-session-seal-router.test.ts --grep "idempotency env
resolver" --reporter=line`, `pnpm --dir tests exec playwright test -c
playwright.unit.config.ts unit/signingSessionSeal.idempotencyRecords.unit.test.ts
unit/refactor82CloudflareD1Runtime.guard.unit.test.ts
unit/refactor76BrandedKeys.guard.unit.test.ts --reporter=line`, and
      `git diff --check`.
- [x] Validation passed: `pnpm --dir packages/sdk-server-ts type-check`,
      `pnpm --dir tests exec playwright test -c playwright.unit.config.ts
unit/refactor58OtpRegistrationSlim.guard.unit.test.ts
unit/emailOtpRecoveryWrappedEnrollmentEscrowStore.unit.test.ts
--reporter=line`, `rg -n
"putGoogleEmailOtpRegistrationAttemptWithExecutor|PgQueryExecutor|postgresRegistrationPersistenceConfig|writeRegistrationPersistenceWithExecutor|writeAddAuthMethodPersistenceWithExecutor|writeEmailOtpRegistrationEnrollmentWithExecutor|persistGoogleEmailOtpRegistrationActivationWithExecutor|Postgres finalization requires|getPostgresPool\\("
packages/sdk-server-ts/src/core/AuthService.ts
packages/sdk-server-ts/src/core/EmailOtpStores.ts
tests/unit/refactor58OtpRegistrationSlim.guard.unit.test.ts`, and
      `git diff --check`.
- [x] Validation passed: `pnpm --dir packages/sdk-server-ts type-check`,
      `pnpm --dir tests exec playwright test -c playwright.unit.config.ts
unit/walletStore.unit.test.ts unit/walletAuthMethodStore.unit.test.ts
unit/refactor82CloudflareD1Runtime.guard.unit.test.ts --reporter=line`,
      `pnpm --dir tests exec playwright test -c playwright.relayer.config.ts
relayer/console-d1-adapters.test.ts --grep "signer wallet metadata and auth
methods are scoped by tenant environment" --reporter=line`, and the stale
      wallet Postgres symbol/schema inventories returned no matches.
- [x] Validation passed: `pnpm --dir packages/sdk-server-ts type-check`,
      `pnpm --dir tests exec playwright test -c playwright.unit.config.ts
unit/webauthnStoreFactories.unit.test.ts
unit/refactor82CloudflareD1Runtime.guard.unit.test.ts --reporter=line`,
      `pnpm --dir tests exec playwright test -c playwright.unit.config.ts
unit/cloudflareD1RouterApiAuthService.unit.test.ts --grep "reads signer metadata
with tenant scope" --reporter=line`, and the stale WebAuthn Postgres
      symbol/schema inventories returned no matches.
- [x] Validation passed: `pnpm --dir packages/sdk-server-ts type-check`,
      `pnpm --dir tests exec playwright test -c playwright.unit.config.ts
unit/recoveryStoreFactories.unit.test.ts unit/recoverySessionStore.unit.test.ts
unit/recoveryExecutionStore.unit.test.ts
unit/refactor82CloudflareD1Runtime.guard.unit.test.ts --reporter=line`,
      `pnpm --dir tests exec playwright test -c playwright.unit.config.ts
unit/cloudflareD1RouterApiAuthService.unit.test.ts --grep "tracks recovery
sessions and executions" --reporter=line`, and the stale recovery Postgres
      symbol/schema inventories returned no matches.
- [x] Validation passed: `pnpm --dir packages/sdk-server-ts type-check`,
      `pnpm --dir tests exec playwright test -c playwright.unit.config.ts
unit/identityStore.unit.test.ts --reporter=line`, `git diff --check`, and
      the stale identity Postgres helper/table inventories returned no matches.
- [x] Validation passed: `pnpm --dir packages/sdk-server-ts type-check`,
      `pnpm --dir tests exec playwright test -c playwright.unit.config.ts
unit/registrationCeremonyStore.unit.test.ts --reporter=line`, `pnpm --dir
tests exec playwright test -c playwright.unit.config.ts
unit/refactor82CloudflareD1Runtime.guard.unit.test.ts --reporter=line`,
      `git diff --check`, and the stale registration ceremony Postgres
      helper/table inventories returned no matches.
- [x] Validation passed after renaming the web-server demo JWT issuer from
      `router-api-worker-demo` to `router-api-worker-demo` without a compatibility
      alias: `pnpm --dir tests exec playwright test -c
playwright.unit.config.ts unit/refactor82CloudflareD1Runtime.guard.unit.test.ts
--reporter=line`, `pnpm --dir tests exec tsc -p tsconfig.playwright.json
--noEmit`, `pnpm -s type-check:router-server`, focused
      `router-api-worker-demo|router-api-worker-demo` inventory, and
      `git diff --check`.
- [x] Validation passed after renaming test-only default origins from
      `router-api-server.localhost` to `router-api.localhost` and adding the old
      origin to the stale-name guard. Follow-up cleanup renamed the internal
      Router API mock option/base/log scope away from `relayUrl`, `relayBase`,
      and `Router API mock` wording in the test setup helpers, with no compatibility
      alias because those helpers have no external callers. Validation passed:
      `pnpm --dir tests exec playwright test -c
playwright.unit.config.ts unit/refactor82CloudflareD1Runtime.guard.unit.test.ts
--reporter=line`, `pnpm --dir tests exec tsc -p tsconfig.playwright.json
--noEmit`, `pnpm --dir tests exec playwright test -c
playwright.unit.config.ts unit/seamsWeb.setTheme.unit.test.ts
unit/seamsWeb.namespacedSigningSurface.unit.test.ts
unit/useAccountInput.clearPrefill.unit.test.ts
unit/passkeyAuthMenu.accountAvailability.unit.test.ts --reporter=line`, focused
      `router-api-server.localhost|router-api.localhost` inventory, focused
      Router API mock stale-token inventory, and
      `git diff --check`.
- [x] Deleted unused duplicate test setup mock modules
      `tests/setup/intercepts.ts` and `tests/setup/route-mocks.ts` after proving
      the current test graph has no imports or symbol references to either file.
      This removed 612 lines of dead setup scaffolding and replaced the stale
      README pointer with a guard that fails if either file returns. Validation
      passed: `pnpm --dir tests exec playwright test -c
playwright.unit.config.ts unit/refactor82CloudflareD1Runtime.guard.unit.test.ts
--reporter=line`, `pnpm --dir tests exec tsc -p tsconfig.playwright.json
--noEmit`, explicit deleted-file/no-reference inventory, and
      `git diff --check`.
- [x] Renamed Phase 6 resource-inventory deployment evidence from
      `relay_worker_deployment_status`/`relay_worker` to
      `router_api_worker_deployment_status`/`router_api_worker`. This keeps the
      staging evidence IDs aligned with the Router API worker rename while
      leaving the broader `routerApiConfigPath` and `routerApiWorker` manifest fields
      for the full staging-manifest contract rename below. The source guard now
      rejects the old evidence IDs and target labels. Validation passed:
      `pnpm --dir tests exec playwright test -c playwright.unit.config.ts
unit/d1StagingEvidenceVerify.script.unit.test.ts
unit/d1StagingResourceInventory.script.unit.test.ts
unit/refactor82CloudflareD1Runtime.guard.unit.test.ts --reporter=line`,
      `pnpm --dir tests exec tsc -p tsconfig.playwright.json --noEmit`,
      focused stale evidence-ID inventory, and `git diff --check`.
- [x] Completed the broader Phase 6 Router API staging-manifest contract rename.
      The staging scripts now use `routerApiConfigPath`, `--router-api-config`,
      `routerApiOrigin`, `--router-api-origin`, `routerApiWorker`,
      `router_api_readyz`, and `router_api_healthz` throughout the generated
      manifests, runbook, evidence verifier, README, and deployment docs. The old
      `wrangler.d1-staging-relay.toml.example` template path was replaced with
      `packages/sdk-server-ts/wrangler.d1-staging-router-api.toml.example`, the
      guard rejects the old staging CLI/config symbols, and no compatibility
      aliases were added. Validation passed: `node --check
packages/sdk-server-ts/scripts/d1-staging-readiness-check.mjs`, `pnpm --dir
tests exec playwright test -c playwright.unit.config.ts
unit/d1StagingResourceInventory.script.unit.test.ts
unit/d1StagingEvidenceVerify.script.unit.test.ts
unit/d1StagingReadiness.script.unit.test.ts
unit/d1StagingRunbook.script.unit.test.ts
unit/d1StagingSmoke.script.unit.test.ts
unit/d1StagingSignerCustody.script.unit.test.ts
unit/d1StagingKekCheck.script.unit.test.ts
unit/d1StagingMigrate.script.unit.test.ts
unit/d1StagingFixtureImport.script.unit.test.ts
unit/d1StagingTimeTravelBookmark.script.unit.test.ts
unit/d1StagingReconciliation.script.unit.test.ts
unit/d1StagingR2RestoreDrill.script.unit.test.ts
unit/d1StagingSession.unit.test.ts
unit/refactor82CloudflareD1Runtime.guard.unit.test.ts --reporter=line` with
      170 tests passing, `pnpm --dir tests exec tsc -p
tsconfig.playwright.json --noEmit`, `pnpm -s type-check:router-server`, focused
      stale staging-token inventories, and `git diff --check`.
- [x] Removed remaining active public-config Relay-era process wording from the
      web-server env example, web-server README, server package README, deployment
      infra doc, and SDK web comments. Current prose now describes the hosted
      process as Router API while preserving `RELAYER_*` and `relayUrl` where
      those are still real public/domain names. The guard now rejects the stale
      local issuer defaults and process comments (`JWT_ISSUER=relay-server`,
      `JWT_ISSUER=relay`, `dev-relay-jwt-secret`, `The relay verifies`, and the
      old local relay-process wording). Validation passed: `pnpm --dir tests exec
playwright test -c playwright.unit.config.ts
unit/refactor82CloudflareD1Runtime.guard.unit.test.ts --reporter=line` with 43
      tests passing, focused stale public-config wording inventory, and
      `git diff --check`.
- [x] Tightened the server package README session integration surface from a
      broad "compatible adapter" phrase to the concrete `SessionService` router
      contract. The Refactor 82 guard now rejects the stale wording across active
      Router API text paths. Validation passed: `pnpm --dir tests exec playwright
test -c playwright.unit.config.ts
unit/refactor82CloudflareD1Runtime.guard.unit.test.ts --reporter=line` with 43
      tests passing, a focused stale compatibility wording scan, and
      `git diff --check`.
- [x] Removed stale "legacy prefix" wording from the active server default-config
      comments. The default remains unchanged; the comment now describes the
      current published threshold keyspace prefix. The Refactor 82 guard now scans
      `packages/sdk-server-ts/src/core/defaultConfigsServer.ts` for the old phrase.
      Validation passed: `pnpm --dir tests exec playwright test -c
playwright.unit.config.ts unit/refactor82CloudflareD1Runtime.guard.unit.test.ts
--reporter=line` with 43 tests passing, a focused stale-prefix scan, and
      `git diff --check`.
- [x] Removed stale "legacy `code_source`" wording from the server-side contract
      error formatter. The error now states the accepted Outlayer
      `request_execution` field and rejects `code_source` directly. The Refactor
      82 guard now rejects the old phrase in active source. Validation passed:
      `pnpm --dir tests exec playwright test -c playwright.unit.config.ts
unit/refactor82CloudflareD1Runtime.guard.unit.test.ts --reporter=line` with 43
      tests passing, a focused stale phrase scan, and `git diff --check`.
- [x] Tightened the threshold Durable Object config comment from "compatible with
      the SDK's threshold store protocol" to "implementing the SDK's threshold
      store protocol." The Refactor 82 guard now rejects the old phrase in active
      source. Validation passed: `pnpm --dir tests exec playwright test -c
playwright.unit.config.ts unit/refactor82CloudflareD1Runtime.guard.unit.test.ts
--reporter=line` with 43 tests passing, a focused stale phrase scan, and
      `git diff --check`.
- [x] Replaced stale compatibility-test wording in the email encryption boundary
      with "Outlayer interoperability tests." This keeps the deterministic AAD
      warning while avoiding compatibility-path language in active server source.
      The Refactor 82 guard now rejects the old phrase. Validation passed:
      `pnpm --dir tests exec playwright test -c playwright.unit.config.ts
unit/refactor82CloudflareD1Runtime.guard.unit.test.ts --reporter=line` with 43
      tests passing, a focused phrase scan, and `git diff --check`.
- [x] Renamed the email encryption test file from the old compat filename to
      `emailEncryptionOutlayerInteroperability.test.ts`, updated its test labels
      and skip messages, and added a guard that rejects the old file path and
      stale labels. Validation passed: `pnpm --dir tests exec playwright test -c
playwright.unit.config.ts unit/refactor82CloudflareD1Runtime.guard.unit.test.ts
--reporter=line` with 43 tests passing,
      `pnpm --dir tests exec tsc -p tsconfig.playwright.json --noEmit`, a direct
      old-path absence check, a focused stale filename/text scan, and
      `git diff --check`. The renamed email encryption Playwright file was
      discovered by `pnpm --dir tests exec playwright test -c
playwright.unit.config.ts unit/emailEncryptionOutlayerInteroperability.test.ts
--reporter=line`; its 3 cases still skip through the pre-existing unavailable
      helper path in this environment.
- [x] Deleted the ambient Express type shim at
      `packages/sdk-server-ts/src/router/express-shim.d.ts`. The package now uses
      the declared `@types/express` dependency through an explicit TypeScript path
      for `express`, and `createConsoleRouter.ts` stores request-scoped console
      auth claims in a `WeakMap<Request, ConsoleAuthClaims>` instead of mutating
      the request object through a broad record cast. The Refactor 82 guard now
      rejects the old shim path. Validation passed:
      `pnpm --dir packages/sdk-server-ts exec tsc -p tsconfig.json --noEmit
--pretty false`, `pnpm --dir packages/sdk-server-ts exec tsc -p
tsconfig.build.json --pretty false`, `pnpm --dir tests exec playwright test -c
playwright.unit.config.ts unit/refactor82CloudflareD1Runtime.guard.unit.test.ts
--reporter=line` with 43 tests passing, a direct old-path absence check, and
      `git diff --check`.
- [x] Deleted stale "scaffolding" comments from the current Threshold Ed25519
      Express routes and threshold signing service factory. The Refactor 82 guard
      now rejects `scaffolding` wording in `packages/sdk-server-ts/src`
      production source so current runtime code is not described as temporary
      migration scaffolding. Validation passed: `pnpm --dir tests exec playwright
      test -c playwright.unit.config.ts
      unit/refactor82CloudflareD1Runtime.guard.unit.test.ts --reporter=line`
      with 45 tests passing, `pnpm --dir tests exec tsc -p
      tsconfig.playwright.json --noEmit`, a direct `rg "scaffolding"
      packages/sdk-server-ts/src` scan, and `git diff --check`.

Exit criteria:

- [x] `rg "POSTGRES_URL|CONSOLE_POSTGRES_URL|BILLING_POSTGRES_URL"` finds only
      negative tests, type fixtures, and source guards.
      Evidence: outside this Refactor 82 plan, the exact env-token inventory now
      returns only `tests/unit/refactor82CloudflareD1Runtime.guard.unit.test.ts`,
      `tests/unit/webServer.consoleConfig.unit.test.ts`, and
      `packages/sdk-server-ts/src/core/ThresholdService/stores/ThresholdStoreConfig.typecheck.ts`.
      There are no app, package, crate, local-dev script, or architecture-doc
      references to those runtime env keys.
- [x] Cloudflare runtime and staging-required code paths have no legacy fallback
      branches.
      Evidence: the stale-name guard now scans `packages/sdk-server-ts/src`,
      `packages/sdk-web/src`, `tests`, `packages/sdk-server-ts/src/README.md`,
      `packages/sdk-server-ts/README.md`, `apps/web-server/README.md`,
      `docs/registrations-top-up.md`,
      `docs/refactor-85-modular-auth-capabilities-SPEC.md`,
      `docs/saas/bring-you-own-auth.md`,
      `packages/sdk-server-ts/scripts`, `apps/web-server/src`, and the Wrangler
      staging templates for
      the old Router API staging Worker filename, the `routerApier` typo path, and the
      stale Relay-to-RouterApi route-surface names. A narrowed runtime scan for
      legacy/compatibility/fallback terminology across Cloudflare runtime,
      staging-required router files, storage, and console D1 paths finds only the
      intentional webhook terminal `no-op` branch in
      `packages/sdk-server-ts/src/console/webhooks/shared.ts`. Validation passed:
      `pnpm --dir tests exec playwright test -c playwright.unit.config.ts
unit/refactor82CloudflareD1Runtime.guard.unit.test.ts --reporter=line`; the
      full Phase 6 staging script/session cluster with 110 tests; `pnpm --dir
packages/sdk-server-ts type-check`; `pnpm --dir tests exec tsc -p
tsconfig.playwright.json --noEmit`; and `git diff --check`.
      Follow-up stale-name cleanup after the RouterApi rename updated the sample
      app README, the registration top-up plan, and the Refactor 85 spec; the
      source-only guard passed with 16 tests, `git diff --check` passed, and the
      repository-wide stale-token inventory now returns only the guard's
      forbidden-token declarations.
- [x] No Cloudflare runtime request path carries an `enabled`, `unavailable`, or
      disabled-service option for legacy behavior.
      Evidence: `tests/unit/refactor82CloudflareD1Runtime.guard.unit.test.ts`
      scans runtime router source, excluding typecheck fixtures, for the old
      `emailRecovery: { enabled: true }`, `ed25519RegistrationPrepare:
{ enabled: true }`, and `signingSessionSeal: { enabled: true }` route
      capability shapes. The old shapes survive only in
      `packages/sdk-server-ts/src/router/relayRouteOptions.typecheck.ts` as
      `@ts-expect-error` fixtures. The remaining `unavailable` strings are
      runtime capability, crypto, or request-source result codes rather than
      legacy disabled-service route options.
- [x] No generic wallet/session/auth D1 path validates wallet identity with NEAR
      account validators. Evidence: `unit/walletScopedLookups.guard.unit.test.ts`
      scans every production Cloudflare `d1*.ts` module for direct
      `isValidAccountId` usage and proves `parseD1BoundaryWalletIdResult` accepts
      generic non-NEAR wallet IDs such as `wallet:alice` while rejecting
      whitespace/control-character IDs.
- [x] The Refactor 82 guard allowlist is smaller after cleanup, and any remaining
      allowlist entry has an owner and deletion condition.
      Evidence: the Refactor 82 Cloudflare runtime guard no longer uses an
      allowlist. It walks static imports, exports, and dynamic imports, then
      rejects forbidden runtime dependencies and env tokens directly.
- [x] The final cleanup pass records why the working tree remains net-positive
      after deleting legacy staging/runtime paths.
- [x] Final Phase 7 counts are recorded for all files, non-doc files, and
      `packages/sdk-server-ts/src` production files. Any remaining positive
      production delta has a named product reason and follow-up owner.

### Phase 8: Signer-Set Registration Model

Status: complete. Functional closure is validated, the service-split line-count
checkpoint is recorded, and the remaining positive count cleanup is explicitly
owned by the final Phase 7 deletion/count pass.

Trigger:

- Local D1 registration exposed that the current registration model treats
  combined NEAR Ed25519 plus EVM-family ECDSA provisioning as a special two-signer
  case. The D1 backend now has a real combined ceremony implementation, but the
  public request shape and D1 ceremony state still encode today's exact signer
  pair. That will not scale to future signer families or wallet capabilities.

Goal:

- [x] Replace `signerSelection: { mode: 'ed25519_and_ecdsa', ... }` with a
      signer/capability set request shape.
- [x] Make D1 wallet registration orchestration work over a validated set of
      requested signer branches, instead of the hard-coded
      `combined_registration` branch.
- [x] Split the current D1 ceremony implementation so wallet registration,
      NEAR Ed25519, and EVM-family ECDSA have separate owners.
- [x] Add a D1-specific combined finalize test before marking this phase done.
- [x] Keep local and staging request compatibility only at explicit boundary
      parsers while the SDK and demo app are updated. Delete the old internal
      mode paths in the same phase.

Current progress:

- [x] Added the shared signer-set boundary parser:
      `normalizeRegistrationSignerPlan()` accepts the new
      `kind: 'signer_set'` request shape and converts legacy
      `ed25519_only`, `ecdsa_only`, and `ed25519_and_ecdsa` request shapes
      into the same branch-keyed `RegistrationSignerPlan`.
- [x] Added stable branch keys for the shared plan contract:
      `near_ed25519:slot:<slot>` and deterministic
      `evm_family_ecdsa:<chain-target-key>` keys.
- [x] Kept the new `near_ed25519` signer-set request shape free of Ed25519
      protocol key-purpose/version fields; the shared parser injects the current
      `near_tx` and `threshold-ed25519-hss-v1` defaults into the parsed plan.
- [x] Added duplicate rejection at the shared parser boundary for duplicate
      NEAR Ed25519 signer slots and duplicate EVM-family ECDSA chain targets.
- [x] Added type fixtures rejecting malformed signer-set branch combinations
      and parsed plan branches missing stable branch identity.
- [x] Wired the shared signer-set plan into
      `walletRegistrationRoutes.ts` for registration-intent, prepare, and start
      request parsing. The route now deletes its duplicate registration signer
      parser and keeps legacy request compatibility at the route boundary while
      durable intent writers store current signer-set state.
- [x] Widened `CreateRegistrationIntentRequest.signerSelection` to accept the new
      signer-set request shape. AuthService and the D1 registration-intent service
      now normalize to `RegistrationSignerPlan` and persist
      `kind: 'signer_set'` intent state.
- [x] Wired D1 registration-intent persistence parsing through
      `normalizeRegistrationSignerPlan()` so stored signer-set-shaped intents are
      accepted and stored legacy-mode rows are upgraded to signer-set state at the
      D1 record boundary during the transition.
- [x] Validation for the signer-set boundary slice passed:
      `pnpm --dir tests exec tsc -p tsconfig.playwright.json --noEmit`,
      `pnpm --dir packages/shared-ts type-check`,
      `pnpm --dir packages/sdk-server-ts type-check`, focused Playwright unit
      tests for registration signer normalization, wallet-registration intent
      modes, and D1 registration-intent storage, plus `git diff --check`.
- [x] Added `signer_set_registration` ceremony state with branch-specific
      `near_ed25519_prepared`, `near_ed25519_responded`,
      `evm_family_ecdsa_prepared`, and `evm_family_ecdsa_responded` records.
      Each branch carries a stable `branchKey`.
- [x] Moved the D1 combined Ed25519 plus EVM-family ECDSA registration
      start/respond/finalize path to `signer_set_registration`. The D1 record
      parser converts old persisted `combined_registration` records to the new
      branch-set state at the persistence boundary.
- [x] Validation for the D1 signer-set ceremony-state slice passed:
      `pnpm --dir tests exec tsc -p tsconfig.playwright.json --noEmit`,
      `pnpm --dir packages/shared-ts type-check`,
      `pnpm --dir packages/sdk-server-ts type-check`, focused Playwright unit
      tests for registration signer normalization, wallet-registration intent
      modes, D1 registration-intent storage, and combined D1 registration
      start/respond, plus `git diff --check`.
- [x] Added focused combined D1 finalize coverage: a single branch-set ceremony
      now starts, responds, finalizes, writes both Ed25519 and EVM-family ECDSA
      signer records, clears the Durable Object ceremony, and keeps Email OTP
      registration authority data RP-free.
- [x] Added a narrow source guard preventing `combined_registration` from being
      reintroduced anywhere in the Cloudflare D1 runtime tree. Core legacy
      references remain open until the SDK/public request callers move fully to
      signer-set terminology.
- [x] Moved SDK wallet-registration intent RPC requests to signer-set wire
      payloads. The SDK registration state machine can still use the normalized
      legacy mode internally during this transition, but
      `createWalletRegistrationIntent()` now sends `kind: 'signer_set'` for
      combined, Ed25519-only, and ECDSA-only registration requests. Focused SDK
      wrapper tests assert the outgoing wire body and keep the mocked route
      boundary aligned with the server by normalizing signer-set requests back to
      durable intent state.
- [x] Exported signer-set request types from the SDK root and React public
      barrels:
      `RegistrationSignerSetSelection`, `RegistrationSignerRequest`,
      `RegistrationNearEd25519SignerRequest`, and
      `RegistrationEvmFamilyEcdsaSignerRequest`. The SDK registration intent type
      fixture imports them through the public entrypoint and validates the new
      `kind: 'signer_set'` shape.
- [x] Wired signer-set terminology through the SDK public registration boundary
      and wallet-iframe message boundary. `RegistrationCapability.registerWallet`
      and `registerWithEmailOtp` now accept `RegistrationSignerSetSelection`,
      `PM_REGISTER_WALLET` posts `kind: 'signer_set'` payloads, and the iframe host
      plus in-process public API bridges pass signer-set payloads through the
      current registration state machine without converting back to legacy mode
      state.
- [x] Deleted the duplicate inline signer-set converter from
      `walletRegistration.ts`. The SDK now shares
      `registrationSignerSetRequestSelection()` for outbound router-api and iframe
      wire payloads, and uses the shared registration signer-plan parser for the
      temporary inbound conversion to legacy internal mode state.
- [x] Moved SDK public/demo registration request construction to signer-set
      shapes directly. `buildNearWalletRegistrationSignerSetSelection()` now
      returns `kind: 'signer_set'`, omits legacy Ed25519 key-purpose/version
      request fields, and replaces the old near-registration helper. NEAR
      registration, EVM-only registration, iframe registration, passkey
      registration, and Google Email OTP registration now construct signer-set
      request payloads directly.
- [x] Moved registration timing summaries off legacy signer modes. Emitted
      `registration_timing_summary_v1` payloads now report
      `signerSet: { kind: 'signer_set', branches: [...] }` with
      `near_ed25519` and `evm_family_ecdsa` branch labels. The current precompute
      planner still uses local `signerMode` state as a scoped internal
      transition detail.
- [x] Added a public/demo registration request-construction source guard. The
      guard scans the converted SDK public builders, wallet iframe entrypoint,
      public type fixture, and demo app source for legacy
      `ed25519_only`/`ecdsa_only`/`ed25519_and_ecdsa` registration construction,
      `combined_registration`, and the deleted
      `buildNearWalletRegistrationSignerSelection` builder name.
- [x] Closed the signer-set type-fixture gap for branch identity. Shared
      `@ts-expect-error` fixtures now prove NEAR Ed25519 signer requests require
      account-provisioning identity, EVM-family ECDSA signer requests require
      chain-target identity, signer-set requests reject legacy mode fields, and
      parsed signer-plan branches require a stable `branchKey`. Duplicate branch
      identities remain a parser/runtime invariant and are covered by the duplicate
      branch rejection test.
- [x] Moved the D1 wallet-registration service start/respond/finalize decision
      path off direct legacy registration modes. Shared signer-plan helpers now
      derive `near_ed25519` and `evm_family_ecdsa` branches from the current
      boundary-normalized selection, and `d1WalletRegistrationService.ts` uses branch
      presence for Ed25519 preparation, ECDSA preparation, HSS response
      requirements, and finalize input validation. Later cleanup removed the
      remaining durable legacy-mode conversions from `AuthService` and route-owned
      registration-intent writers.
- [x] Moved the D1 registration-intent wallet-allocation gate off direct legacy
      registration modes. `d1RegistrationIntentService.ts` now uses the normalized
      signer plan to find a `near_ed25519` branch and applies implicit-account,
      sponsored-named-account, or generic server-allocated/provided wallet
      allocation from branch presence. The remaining legacy conversion in that
      module is the explicit boundary conversion used to build the current
      persisted `RegistrationIntentV1` shape.
- [x] Strengthened the Cloudflare D1 runtime source guard. The Refactor 82 guard
      now rejects `ed25519_only`, `ecdsa_only`, `ed25519_and_ecdsa`, and
      `combined_registration` anywhere in the Cloudflare D1 runtime graph, so the
      D1 registration-intent and D1 ceremony paths cannot regress to legacy mode
      branching while the shared compatibility parser remains at the boundary.
- [x] Moved the D1 single-branch Ed25519-only and ECDSA-only wallet-registration
      start/respond/finalize paths onto `signer_set_registration`. The D1
      service now requires signer-set state for wallet-registration HSS
      respond/finalize, and the obsolete standalone
      `buildD1EcdsaRegistrationRespondedCeremony()` helper was deleted in the
      same cleanup pass.
- [x] Validation for the single-branch signer-set D1 service slice passed:
      `pnpm --dir packages/sdk-server-ts type-check`,
      `pnpm --dir tests exec tsc -p tsconfig.playwright.json --noEmit`,
      focused Playwright unit tests for ECDSA-only start/respond/finalize,
      Ed25519-only start/respond, and combined start/respond, plus
      `git diff --check`.
- [x] Moved D1 add-signer start/respond/finalize orchestration out of
      `d1WalletRegistrationService.ts` into `d1WalletAddSignerService.ts`. The new
      service owns add-signer intent consumption, existing-auth verification,
      ECDSA HSS response/finalize, wallet signer writes, and ceremony cleanup.
      It reuses `buildD1EvmFamilyEcdsaRegistrationPrepare()` for the add-signer
      prepare payload instead of duplicating EVM-family key ID derivation.
      old `d1EcdsaCeremonyService.ts` module was then renamed to
      `d1WalletRegistrationService.ts`; the wallet-registration service is 1,333
      lines and the new add-signer service is 375 lines.
- [x] Added a source guard proving `d1RouterApiAuthService.ts` delegates D1
      add-signer routes to `d1WalletAddSignerService.ts` and
      `d1WalletRegistrationService.ts` does not own add-signer route methods.
- [x] Moved durable registration-intent state off the legacy signer-mode
      conversion. `RegistrationIntentV1` now accepts signer-set selections,
      generic AuthService and D1 intent allocation write `kind: 'signer_set'`,
      D1 persisted rows parse to signer-set state, and SDK-web normalizes the
      durable union once at its internal registration boundary.
- [x] Added a source guard proving durable registration-intent writers do not call
      `legacyRegistrationSignerSelectionFromPlan()`.
- [x] Moved generic wallet-registration routes off legacy signer-mode intent
      normalization. `walletRegistrationRoutes.ts` now accepts signer-set
      request bodies and rejects legacy mode-shaped registration requests at the
      request boundary.
- [x] Extended the durable intent source guard to cover
      `walletRegistrationRoutes.ts`, so the route parser cannot convert normalized
      signer plans back to legacy durable intent state.
- [x] Narrowed SDK public registration surfaces to signer-set inputs only.
      `RegistrationCapability.registerWallet`, `registerWithEmailOtp`,
      `PM_REGISTER_WALLET`, and the SDK root/React public barrels no longer expose
      legacy registration signer-mode types.
- [x] Added a public type-surface source guard proving SDK public registration
      signatures and iframe messages do not reintroduce the legacy registration
      signer-selection type.
- [x] Moved SDK registration orchestration off legacy signer modes. The browser
      registration operation derives a shared signer plan from
      `RegistrationSignerSetSelection`, threads branch-specific Ed25519/ECDSA
      plan records through precompute/start/respond/finalize, and no longer
      converts signer-set requests back to `RegistrationSignerSelection`.
- [x] Deleted the SDK RPC legacy request converter. `registrationSignerSetRequest`
      is signer-set-only, and SDK public/NEAR/EVM/Google Email OTP registration
      adapters now pass signer-set wire requests directly.
- [x] Renamed the stale SDK registration helper module and parser test from
      signer-selection terminology to signer-set terminology:
      `registrationSignerSet.ts` and `registrationSignerSetNormalization.unit.test.ts`
      now own those surfaces, and the Refactor 82 guard rejects the old helper
      filename from returning.
- [x] Wire remaining demo app registration requests to signer-set terminology
      after the public SDK and iframe request boundaries.
- [x] Deleted the legacy mode API and parser compatibility after call sites
      stopped depending on it. `RegistrationIntentV1`, route bodies, D1 auth
      service tests, SDK orchestration tests, relayer fixtures, wallet-iframe
      fixtures, and e2e registration fixtures now use signer-set request state.

Target request shape:

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

Internal model:

- [x] Parse raw wallet-registration route request bodies once into a
      `RegistrationSignerPlan`.
- [x] Reject duplicate signer identities at the boundary. For example, two
      `near_ed25519` entries with the same slot, or two `evm_family_ecdsa`
      entries targeting the same wallet key/signing root, are invalid.
- [x] Reject unsupported signer kinds at the boundary with a typed error.
- [x] Preserve branch-specific types after parsing. Core code must not inspect
      raw `kind` strings from request bodies.
- [x] Give every signer branch a stable internal key, such as
      `near_ed25519:slot:1` or `evm_family_ecdsa:<walletKeyId>`, so Durable
      Object state can store branch progress without order dependence.

D1 ceremony state:

- [x] Replace `StoredCombinedRegistrationState` with a generic branch-set state,
      for example:

```ts
type StoredWalletRegistrationSignerSetState = {
  kind: 'signer_set_registration';
  branches: readonly StoredWalletRegistrationSignerBranch[];
};
```

- [x] Model each branch as its own discriminated union:
      `near_ed25519_prepared`, `near_ed25519_responded`,
      `evm_family_ecdsa_prepared`, and `evm_family_ecdsa_responded`.
- [x] Keep branch identity inside each branch record. Do not infer branch meaning
      from array order.
- [x] Delete `combined_registration` after the signer-set state is live. If a
      persistence compatibility parser is needed during local development, keep it
      in the D1 record parser only and remove it before Phase 8 completion.

Service/module split:

- [x] Rename or split
      `packages/sdk-server-ts/src/router/cloudflare/d1EcdsaCeremonyService.ts`.
      The old mixed file was renamed to
      `packages/sdk-server-ts/src/router/cloudflare/d1WalletRegistrationService.ts`
      after NEAR Ed25519 branch helpers, EVM-family ECDSA prepare helpers, and
      add-signer route orchestration were split out.
- [x] Extract the EVM-family ECDSA wallet-registration branch prepare helper into
      `packages/sdk-server-ts/src/router/cloudflare/d1EvmFamilyEcdsaRegistrationBranch.ts`.
      The mixed ceremony service imports the branch helper and no longer defines
      the wallet-registration ECDSA prepare builder inline.
- [x] Extract the NEAR Ed25519 wallet-registration branch mechanics into
      `packages/sdk-server-ts/src/router/cloudflare/d1NearEd25519RegistrationBranch.ts`.
      The mixed ceremony service imports branch-specific signing-root, authority
      scope, HSS prepare/respond, signer-record, and session-policy helpers instead
      of defining those mechanics inline.
- [x] Extract D1 wallet add-signer route orchestration into
      `packages/sdk-server-ts/src/router/cloudflare/d1WalletAddSignerService.ts`.
      The top-level D1 auth service delegates add-signer start/respond/finalize to
      the dedicated service, and the mixed ceremony service no longer owns
      add-signer route methods.
- [x] Rename the remaining D1 wallet-registration owner to
      `d1WalletRegistrationService.ts` and delete the misleading
      `d1EcdsaCeremonyService.ts` module path.
- [x] Target modules:
      `d1WalletRegistrationService.ts` for registration orchestration,
      `d1NearEd25519RegistrationBranch.ts` for NEAR Ed25519 branch
      prepare/respond/finalize helpers,
      `d1EvmFamilyEcdsaRegistrationBranch.ts` for ECDSA branch
      prepare/respond/finalize helpers, and a small shared record module for
      branch-state parsing/building.
- [x] Keep add-signer flows separate from wallet-registration branch orchestration
      unless the helper removes real duplication without broadening inputs.
- [x] Avoid a generic abstraction over HSS protocols. Use a tiny branch interface
      only if it deletes repeated registration orchestration code and preserves
      branch-specific input/output types.

Frontend and SDK updates:

- [x] Update default frontend registration to send:

```ts
signerSelection: {
  kind: 'signer_set',
  signers: [
    { kind: 'near_ed25519', ... },
    { kind: 'evm_family_ecdsa', ... },
  ],
}
```

- [x] Update SDK public types, iframe messages, wallet-registration RPC client
      request payloads, and type fixtures to use signer-set terminology at
      request/message boundaries.
- [x] Update remaining public demo app surfaces to stop constructing legacy
      `ed25519_only`, `ecdsa_only`, and `ed25519_and_ecdsa` registration
      requests.
- [x] Update registration timing events to stop reporting legacy
      `ed25519_only`, `ecdsa_only`, and `ed25519_and_ecdsa` modes.
- [x] Export signer-set request types from SDK public barrels and add public
      type fixtures for the new request shape.
- [x] Remove `ed25519_only`, `ecdsa_only`, and `ed25519_and_ecdsa` from core
      registration logic. If the public boundary temporarily accepts old mode
      shapes, convert them once to `signer_set` and add a deletion checkbox in
      this phase.
- [x] Keep `server_allocated` wallet naming. The server allocates the wallet ID;
      signer material remains MPC/HSS generated.

Tests and guards:

- [x] Add D1 tests for prepare/start/respond/finalize of a two-signer set.
- [x] Add a D1-specific combined finalize test before marking Phase 8 done.
- [x] Update ECDSA-only D1 start/respond/finalize tests to assert the same
      branch-set state machinery as combined registration.
- [x] Add D1 tests for Ed25519-only signer sets using the same branch-set state
      machinery.
- [x] Add a duplicate branch rejection test.
- [x] Add source guards rejecting new production references to
      `ed25519_and_ecdsa`, `ed25519_only`, `ecdsa_only`, and
      `combined_registration` outside boundary parser fixtures while the
      transition is active.
- [x] Add the D1 runtime source guard slice: Cloudflare D1 runtime cannot
      reference `ed25519_and_ecdsa`, `ed25519_only`, `ecdsa_only`, or
      `combined_registration`.
- [x] Add the generic `AuthService` source guard slice: wallet-registration core
      orchestration cannot reference `ed25519_and_ecdsa`, `ed25519_only`, or
      `ecdsa_only`.
- [x] Add the production combined-state source guard slice: production
      TypeScript/TSX under `apps/seams-site/src`, `packages/shared-ts/src`,
      `packages/sdk-server-ts/src`, and `packages/sdk-web/src` cannot reference
      `combined_registration`.
- [x] Add the public/demo request-construction source guard slice: converted SDK
      public builders, wallet iframe, public fixture, and demo app source cannot
      construct legacy registration signer modes.
- [x] Add the public type-surface source guard slice: SDK root exports, React
      exports, public registration capability types, and iframe registration
      messages cannot expose `RegistrationSignerSelection`.
- [x] Add the durable intent writer source guard slice: AuthService, D1
      registration-intent allocation, and D1 registration-intent parsing cannot
      convert normalized signer plans back to legacy durable intent state.
- [x] Add type fixtures that prevent direct construction of malformed signer-set
      plans and branch records missing identity. Duplicate branch records are a
      parser/runtime invariant covered by the duplicate branch rejection test.
- [x] Record the service-split line-count checkpoint and assign the remaining
      positive line-count cleanup to the final Phase 7 deletion/count pass.

Exit criteria:

- [x] Local D1 registration provisions both NEAR Ed25519 and EVM-family ECDSA
      signers from the signer-set request shape.
- [x] The D1 backend has no core dependency on the two-signer cross-product mode.
- [x] D1 combined finalize is covered by a targeted unit test.
- [x] `pnpm --dir packages/sdk-server-ts type-check`,
      `pnpm --dir packages/sdk-web type-check`, focused D1 registration tests,
      registration intent allocation tests, and `git diff --check` pass.

Phase 8 SDK public/iframe boundary validation evidence:

- [x] `pnpm --dir tests exec tsc -p tsconfig.playwright.json --noEmit` passed
      after widening public and iframe registration request types.
- [x] `W3A_TEST_FRONTEND_URL=http://127.0.0.1:3799 pnpm --dir tests exec
playwright test -c playwright.unit.config.ts
unit/registrationSignerSetNormalization.unit.test.ts
--reporter=line` passed with 9 tests, including the SDK boundary
      conversion test for signer-set wire shape and internal mode normalization.
- [x] Browser iframe runtime assertion is added in
      `tests/unit/seamsWeb.passkeyIframe.flowEvents.unit.test.ts` and now has
      reproducible validation after rebuilding `packages/sdk-web/dist/esm`. The
      assertion expects `PM_REGISTER_WALLET` to receive `kind: 'signer_set'` with
      `near_ed25519` and `evm_family_ecdsa` signer branches.
- [x] `pnpm --dir packages/sdk-web run build:sdk` passed; the previous
      `TS2688: Cannot find type definition file for '@playwright/test'` blocker is
      no longer present in the current workspace.
- [x] `pnpm --dir packages/sdk-web run build:rolldown` passed; the previous
      Rolldown CSS bundling blocker is no longer present in the current workspace.
- [x] `W3A_TEST_FRONTEND_URL=http://127.0.0.1:3799 pnpm --dir tests exec
      playwright test -c playwright.unit.config.ts
      unit/seamsWeb.passkeyIframe.flowEvents.unit.test.ts --reporter=line`
      passed with 1 browser iframe flow-event test.

Phase 8 public/demo request-construction cleanup validation evidence:

- [x] `pnpm --dir tests exec tsc -p tsconfig.playwright.json --noEmit` passed
      after the public/demo builders started constructing signer-set request
      payloads directly.
- [x] `W3A_TEST_FRONTEND_URL=http://127.0.0.1:3799 pnpm --dir tests exec
playwright test -c playwright.unit.config.ts
unit/passkeyRegistrationRollback.guard.unit.test.ts --reporter=line`
      passed after the guard moved from the deleted
      `registerPasskeyWithAuthenticatorOptions` function to the current
      `SeamsWeb.registerPasskeyDomain` path and checked
      `buildNearWalletRegistrationSignerSetSelection`.
- [x] `rg "buildNearWalletRegistrationSignerSelection|mode: 'ed25519_only'|mode:
'ecdsa_only'|mode: 'ed25519_and_ecdsa'"` over `apps`,
      SDK NEAR/EVM public registration builders, iframe registration,
      `SeamsWeb.ts`, Google Email OTP registration, and
      `publicInputs.typecheck.ts` returned no matches.

Phase 8 registration timing terminology validation evidence:

- [x] `pnpm --dir tests exec tsc -p tsconfig.playwright.json --noEmit` passed
      after timing summary payloads moved from `signerMode` to `signerSet`.
- [x] `W3A_TEST_FRONTEND_URL=http://127.0.0.1:3799 pnpm --dir tests exec
playwright test -c playwright.unit.config.ts
unit/addWalletSigner.orchestration.unit.test.ts --grep "near.registerNearWallet wraps combined registration for configured ECDSA targets"
--reporter=line` passed. The captured timing summary emitted
      `signerSet: { kind: 'signer_set', branches: ['near_ed25519',
  'evm_family_ecdsa'] }`.
- [x] Source scan confirmed `registration_timing_summary_v1` payloads now use
      `signerSet`. Remaining `signerMode` references in registration code are
      limited to the internal precompute planner.

Phase 8 public/demo request-construction guard evidence:

- [x] `pnpm --dir tests exec playwright test -c playwright.unit.config.ts
unit/refactor82CloudflareD1Runtime.guard.unit.test.ts --grep "public/demo registration request construction"
--reporter=line` passed after adding the signer-set terminology guard.
- [x] `pnpm --dir tests exec tsc -p tsconfig.playwright.json --noEmit` passed
      after the guard helper was added.

Phase 8 SDK signer-set filename cleanup validation evidence:

- [x] `pnpm --dir tests exec playwright test -c playwright.unit.config.ts
unit/refactor82CloudflareD1Runtime.guard.unit.test.ts --grep "SDK registration
helper files use signer-set filenames|public/demo registration request
construction|public registration type surfaces" --reporter=line` passed with 3
      guard tests after adding the stale-filename guard.
- [x] `pnpm --dir tests exec playwright test -c playwright.unit.config.ts
unit/registrationSignerSetNormalization.unit.test.ts --reporter=line` passed
      with 9 signer-set normalization tests under the renamed test filename.
- [x] `pnpm --dir packages/sdk-web run type-check` and `pnpm --dir tests exec
      tsc -p tsconfig.playwright.json --noEmit` passed after the helper/test
      rename.
- [x] `pnpm --dir packages/sdk-web run build:sdk` passed after the source
      filename changed and emitted the new `registrationSignerSet` SDK output.
- [x] `git diff --check` passed for the touched signer-set cleanup slice, and
      `find packages/sdk-web/src tests -name '*SignerSelection*' -o -name
      '*signerSelection*'` returned no stale helper/test filenames.

Phase 8 signer-set type-fixture validation evidence:

- [x] `pnpm --dir packages/shared-ts type-check` passed after adding missing
      branch-identity `@ts-expect-error` fixtures.
- [x] `pnpm --dir tests exec tsc -p tsconfig.playwright.json --noEmit` passed
      after the shared type fixtures were updated.

Phase 8 D1 wallet-registration branch-plan validation evidence:

- [x] `pnpm --dir packages/shared-ts type-check` passed after adding exported
      signer-plan branch helper functions.
- [x] `pnpm --dir packages/sdk-server-ts type-check` passed after moving
      `d1WalletRegistrationService.ts` wallet-registration decisions to branch-plan
      helpers.
- [x] `pnpm --dir tests exec playwright test -c playwright.unit.config.ts
unit/cloudflareD1RouterApiAuthService.unit.test.ts --grep "starts ECDSA wallet registration|starts and responds to combined Ed25519 and ECDSA registration|starts and responds to Ed25519-only signer-set registration|responds to ECDSA wallet registration|finalizes ECDSA wallet registration"
--reporter=line` passed with 5 focused D1 wallet-registration tests.
- [x] `pnpm --dir tests exec tsc -p tsconfig.playwright.json --noEmit` passed
      after the branch-plan service update.
- [x] Source scan over
      `packages/sdk-server-ts/src/router/cloudflare/d1WalletRegistrationService.ts`
      shows no remaining `ed25519_only`, `ecdsa_only`, `ed25519_and_ecdsa`, or
      `combined_registration` wallet-registration mode references. Remaining
      `signerSelection.mode` references in that file are add-signer
      `mode: 'ecdsa'` checks, which use a different domain type.

Phase 8 D1 registration-intent allocation gate validation evidence:

- [x] `pnpm --dir packages/sdk-server-ts type-check` passed after changing D1
      registration-intent wallet allocation to use signer-plan branch presence.
- [x] `pnpm --dir packages/shared-ts type-check` passed after the allocation gate
      reused the exported signer-plan helper.
- [x] `pnpm --dir tests exec playwright test -c playwright.unit.config.ts
unit/cloudflareD1RouterApiAuthService.unit.test.ts
unit/registrationSignerSetNormalization.unit.test.ts
unit/relayWalletRegistration.intentModes.unit.test.ts --grep "stores wallet registration intents|creates registration intents from signer-set request input|accepts signer-set registration intent input|creates an implicit Ed25519 registration intent with a server-allocated wallet ID"
--reporter=line` passed with 4 focused registration-intent tests.
- [x] Source scan over
      `packages/sdk-server-ts/src/router/cloudflare/d1RegistrationIntentService.ts`
      shows no remaining direct legacy registration-mode checks or legacy
      plan-to-intent conversion.
- [x] `pnpm --dir tests exec tsc -p tsconfig.playwright.json --noEmit` passed
      after the allocation gate update.

Phase 8 durable registration-intent state validation evidence:

- [x] `pnpm --dir packages/shared-ts type-check` passed after widening
      `RegistrationIntentV1.signerSelection` to include signer-set state and adding
      type fixtures for signer-set registration intents.
- [x] `pnpm --dir packages/sdk-server-ts type-check` passed after generic
      AuthService and the D1 registration-intent service switched from
      `legacyRegistrationSignerSelectionFromPlan()` to
      `registrationSignerSetSelectionFromPlan()`.
- [x] `pnpm --dir packages/sdk-web type-check` and `pnpm --dir tests exec tsc -p
      tsconfig.playwright.json --noEmit` passed after SDK-web normalized durable
      signer-set intents once at its internal registration boundary.
- [x] `pnpm --dir tests exec playwright test -c playwright.unit.config.ts
      unit/registrationSignerSetNormalization.unit.test.ts --reporter=line`
      passed with 9 tests and now asserts service-created registration intents use
      `kind: 'signer_set'`.
- [x] `pnpm --dir tests exec playwright test -c playwright.unit.config.ts
      unit/registrationIntentAllocation.unit.test.ts --reporter=line` passed with
      29 generic registration-intent and add-signer tests.
- [x] `pnpm --dir tests exec playwright test -c playwright.unit.config.ts
      unit/cloudflareD1RouterApiAuthService.unit.test.ts --reporter=line` passed
      with 30 D1 Router API auth service tests.
- [x] `pnpm --dir tests exec playwright test -c playwright.unit.config.ts
      unit/refactor82CloudflareD1Runtime.guard.unit.test.ts --reporter=line`
      passed with 24 source-guard tests, including the new durable intent writer
      guard.
- [x] `pnpm --dir tests exec playwright test -c playwright.unit.config.ts
      unit/relayWalletRegistration.boundary.unit.test.ts --reporter=line` passed
      with 64 route-boundary tests after fixture digests moved to signer-set
      intent state.
- [x] `pnpm --dir tests exec playwright test -c playwright.unit.config.ts
      unit/relayWalletRegistration.intentModes.unit.test.ts --reporter=line`
      passed with 7 route intent-mode tests after legacy request bodies started
      returning signer-set intents.
- [x] `pnpm --dir packages/sdk-web type-check` and `pnpm --dir tests exec tsc -p
      tsconfig.playwright.json --noEmit` passed after public SDK registration
      surfaces narrowed to signer-set only.
- [x] `pnpm --dir packages/sdk-web type-check` and `pnpm --dir tests exec tsc -p
      tsconfig.playwright.json --noEmit` passed after SDK registration
      orchestration and RPC request helpers stopped accepting
      `RegistrationSignerSelection`.
- [x] `pnpm --dir tests exec playwright test -c playwright.unit.config.ts
      unit/registrationSignerSetNormalization.unit.test.ts --reporter=line`
      passed with 9 signer-selection parser/RPC-boundary tests.
- [x] `pnpm --dir tests exec playwright test -c playwright.unit.config.ts
      unit/googleEmailOtpWalletAuthFlow.unit.test.ts --reporter=line` passed
      with 23 Google Email OTP registration/login flow tests after the precompute
      fixture and explicit-target assertions moved to signer-set scope.
- [x] `pnpm --dir tests exec playwright test -c playwright.unit.config.ts
      unit/refactor82CloudflareD1Runtime.guard.unit.test.ts --reporter=line`
      passed with 25 source-guard tests after SDK RPC legacy conversion was
      deleted.

Phase 8 D1 runtime legacy-registration source-guard evidence:

- [x] `pnpm --dir tests exec playwright test -c playwright.unit.config.ts
    unit/refactor82CloudflareD1Runtime.guard.unit.test.ts --grep "legacy registration modes"
    --reporter=line` passed after expanding the D1 runtime guard from
      `combined_registration` to all legacy wallet-registration mode literals.

Phase 8 generic AuthService branch-plan validation evidence:

- [x] `pnpm --dir packages/sdk-server-ts type-check` passed after moving
      generic wallet-registration allocation, prepare, start, respond, and
      finalize control flow off `ed25519_only`, `ecdsa_only`, and
      `ed25519_and_ecdsa`.
- [x] `pnpm --dir packages/shared-ts type-check` passed after the shared
      request-boundary parser restored precise branch-mixing errors for legacy
      Ed25519 account fields and sponsored-account fields inside implicit
      provisioning.
- [x] `pnpm --dir tests exec playwright test -c playwright.unit.config.ts
unit/relayWalletRegistration.intentModes.unit.test.ts
unit/relayWalletRegistration.boundary.unit.test.ts
unit/registrationSignerSetNormalization.unit.test.ts --reporter=line`
      passed with 80 focused registration route and normalization tests.
- [x] `pnpm --dir tests exec playwright test -c playwright.unit.config.ts
unit/refactor82CloudflareD1Runtime.guard.unit.test.ts --grep "AuthService wallet registration|legacy registration modes"
--reporter=line` passed after adding the `AuthService` legacy-mode guard.
- [x] `rg -n "ed25519_and_ecdsa|ed25519_only|ecdsa_only"
packages/sdk-server-ts/src/core/AuthService.ts` returned no matches.
- [x] `pnpm --dir tests exec tsc -p tsconfig.playwright.json --noEmit` and
      `git diff --check` passed after the generic `AuthService` branch-plan
      cleanup.

Phase 8 legacy registration-mode API deletion evidence:

- [x] `rg -n
      "RegistrationSignerSelection|legacyRegistrationSignerSelectionFromPlan|normalizeRegistrationSignerSelection|mode:
      'ed25519_only'|mode: 'ecdsa_only'|mode: 'ed25519_and_ecdsa'|
      ed25519_and_ecdsa|ecdsa_only|ed25519_only"
      packages/shared-ts/src packages/sdk-server-ts/src tests/relayer
      tests/e2e/cancel_overlay_specs.test.ts
      tests/wallet-iframe/router.cancellationProgress.test.ts
      tests/unit/addWalletSigner.orchestration.unit.test.ts
      tests/unit/cloudflareD1RouterApiAuthService.unit.test.ts
      tests/unit/registrationIntentDigest.unit.test.ts
      tests/unit/registrationCeremonyStore.unit.test.ts
      tests/unit/relayWalletRegistration.boundary.unit.test.ts
      tests/unit/relayWalletRegistration.intentModes.unit.test.ts`
      returned no matches after deleting the shared legacy registration-mode API
      and moving active registration fixtures to signer-set requests.
      This scan is intentionally scoped to registration request construction,
      durable ceremony state, shared intent parsing, and server route fixtures.
      Remaining `ed25519_only`, `ecdsa_only`, and `ed25519_and_ecdsa` references
      in SDK login/unlock-selection code are the current threshold warm-session
      unlock vocabulary, not the deleted registration signer-mode API.
- [x] `pnpm --dir tests exec playwright test -c playwright.unit.config.ts
      unit/registrationIntentDigest.unit.test.ts
      unit/registrationCeremonyStore.unit.test.ts
      unit/relayWalletRegistration.boundary.unit.test.ts
      unit/relayWalletRegistration.intentModes.unit.test.ts --reporter=line`
      passed with 87 focused shared/server registration tests.
- [x] `pnpm --dir tests exec playwright test -c playwright.unit.config.ts
      unit/addWalletSigner.orchestration.unit.test.ts --reporter=line` passed
      with 11 SDK registration orchestration tests.
- [x] `pnpm --dir tests exec playwright test -c playwright.unit.config.ts
      unit/cloudflareD1RouterApiAuthService.unit.test.ts --reporter=line`
      passed with 30 D1 auth service tests.
- [x] `pnpm --dir tests exec playwright test -c playwright.unit.config.ts
      unit/refactor82CloudflareD1Runtime.guard.unit.test.ts --reporter=line`
      passed with 25 source-guard tests, including the legacy registration-mode
      guards.
- [x] `USE_RELAY_SERVER=0 pnpm --dir tests exec playwright test
      wallet-iframe/router.cancellationProgress.test.ts --reporter=line` passed.
- [x] `pnpm --dir tests exec playwright test
      e2e/cancel_overlay_specs.test.ts --reporter=line` passed.
- [x] `pnpm --dir packages/shared-ts type-check`,
      `pnpm --dir packages/sdk-server-ts type-check`,
      `pnpm --dir packages/sdk-web type-check`,
      `pnpm --dir tests exec tsc -p tsconfig.playwright.json --noEmit`, and
      `git diff --check` passed after the deletion pass.
- [x] Added explicit `express` and `@types/express` dev dependencies to the test
      package, refreshed the lockfile with `pnpm install --lockfile-only
      --ignore-scripts`, and updated stale OIDC dev-cleanup wallet fixtures to the
      hosted relayer account shape enforced by `hostedAccountIds.ts`.
- [x] `pnpm --dir tests exec playwright test -c playwright.relayer.config.ts
      relayer/bootstrap-grants.test.ts relayer/oidc-exchange.authservice.test.ts
      relayer/router-api-keys.test.ts relayer/console-api-key-kinds.test.ts
      --reporter=line` passed with 66 relayer tests.

Phase 8 signer-set ceremony-state deletion evidence:

- [x] `StoredCombinedRegistrationState` was deleted from
      `packages/sdk-server-ts/src/core/RegistrationCeremonyStore.ts`. The generic
      `StoredWalletRegistrationSignerState` union now uses
      `StoredWalletRegistrationSignerSetState` for multi-branch registration
      progress.
- [x] Generic `AuthService` combined wallet registration now writes
      `signer_set_registration` with `near_ed25519_*` and
      `evm_family_ecdsa_*` branch records, then responds/finalizes through the
      shared branch finder and replacement helpers.
- [x] D1 wallet registration now imports the shared branch builder/finder/
      replacement helpers from `RegistrationCeremonyStore.ts`; the duplicate
      helper block in `d1EcdsaCeremonyService.ts` was deleted as the same-slice
      cleanup pass.
- [x] `pnpm --dir packages/sdk-server-ts type-check` and
      `pnpm --dir packages/shared-ts type-check` passed after deleting the
      combined-state type.
- [x] `pnpm --dir tests exec playwright test -c playwright.unit.config.ts
unit/relayWalletRegistration.boundary.unit.test.ts
unit/relayWalletRegistration.intentModes.unit.test.ts
unit/registrationCeremonyStore.unit.test.ts --reporter=line` passed with 79
      focused generic registration and store tests.
- [x] `pnpm --dir tests exec playwright test -c playwright.unit.config.ts
unit/cloudflareD1RouterApiAuthService.unit.test.ts --grep "starts ECDSA wallet registration|starts and responds to combined Ed25519 and ECDSA registration|starts and responds to Ed25519-only signer-set registration|responds to ECDSA wallet registration|finalizes ECDSA wallet registration"
--reporter=line` passed with 5 focused D1 registration lifecycle tests.
- [x] `pnpm --dir tests exec playwright test -c playwright.unit.config.ts
unit/refactor82CloudflareD1Runtime.guard.unit.test.ts --grep "combined registration state|legacy registration modes|AuthService wallet registration"
--reporter=line` passed after adding the production combined-state guard.
- [x] `rg -n "combined_registration|StoredCombinedRegistrationState"
packages/sdk-server-ts/src packages/shared-ts/src -g '*.{ts,tsx}'` returned no
      matches.
- [x] `pnpm --dir tests exec tsc -p tsconfig.playwright.json --noEmit` and
      `git diff --check` passed after the signer-set ceremony-state deletion.

Phase 8 registration branch split evidence:

- [x] Added
      `packages/sdk-server-ts/src/router/cloudflare/d1EvmFamilyEcdsaRegistrationBranch.ts`
      with `buildD1EvmFamilyEcdsaRegistrationPrepare`. The module is 79 lines and
      owns EVM-family wallet-key derivation, threshold key IDs, signing grant IDs,
      and the branch-specific prepare payload.
- [x] Added
      `packages/sdk-server-ts/src/router/cloudflare/d1NearEd25519RegistrationBranch.ts`
      with the NEAR Ed25519 registration signing-root, signing-key ID,
      authority-scope, HSS prepare/respond, wallet-signer-record, bootstrap-session,
      and session-policy helpers. The module is 445 lines.
- [x] Deleted the inline wallet-registration ECDSA prepare builder from
      `packages/sdk-server-ts/src/router/cloudflare/d1WalletRegistrationService.ts`.
      Also deleted the inline NEAR Ed25519 HSS branch helpers from that mixed
      service. The later add-signer extraction and module rename deleted the old
      `d1EcdsaCeremonyService.ts` path; `d1WalletRegistrationService.ts` is 1,333
      lines and add-signer route orchestration no longer lives there.
- [x] Added
      `packages/sdk-server-ts/src/router/cloudflare/d1WalletAddSignerService.ts`
      for D1 add-signer start/respond/finalize. The module is 375 lines, reuses
      `buildD1EvmFamilyEcdsaRegistrationPrepare()` for EVM-family add-signer
      prepare payload construction, and owns add-signer ceremony cleanup plus
      wallet signer writes.
- [x] Added a source guard proving the mixed ceremony service imports
      `d1EvmFamilyEcdsaRegistrationBranch.ts` and does not define an inline
      `buildD1*EcdsaRegistrationPrepare` function.
      The guard also proves the mixed ceremony service imports
      `d1NearEd25519RegistrationBranch.ts` and does not define the NEAR Ed25519
      HSS prepare/respond helpers inline.
      It now also proves `d1RouterApiAuthService.ts` delegates add-signer routes
      to `d1WalletAddSignerService.ts` and the mixed ceremony service does not own
      add-signer route methods.
      The guard now reads the wallet-registration service module and the old
      `d1EcdsaCeremonyService.ts` path is deleted.
- [x] Threaded Ed25519 HSS persisted `serverState` through D1 registration
      preparations, ceremony branches, respond transitions, and finalize requests.
      Test threshold fakes now return D1-parseable persisted server-state payloads
      instead of relying on process-local ceremony state.
- [x] Validation passed: `pnpm --dir packages/sdk-server-ts type-check`;
      `pnpm --dir tests exec playwright test -c playwright.unit.config.ts
unit/cloudflareD1RouterApiAuthService.unit.test.ts --grep "starts ECDSA wallet registration|starts and responds to combined Ed25519 and ECDSA registration|starts and responds to Ed25519-only signer-set registration|responds to ECDSA wallet registration|finalizes ECDSA wallet registration"
--reporter=line` with 5 focused D1 lifecycle tests;
      `pnpm --dir tests exec playwright test -c playwright.unit.config.ts
unit/refactor82CloudflareD1Runtime.guard.unit.test.ts --grep "NEAR Ed25519|EVM-family ECDSA registration branch prepare|combined registration state|legacy registration modes|AuthService wallet registration"
--reporter=line` with 5 guard tests; `pnpm --dir tests exec playwright test -c
playwright.unit.config.ts unit/refactor82CloudflareD1Runtime.guard.unit.test.ts
--grep "wallet add-signer|NEAR Ed25519|EVM-family ECDSA registration branch
prepare|combined registration state|legacy registration modes|AuthService wallet
registration" --reporter=line` with 6 guard tests; `pnpm --dir tests exec
playwright test -c playwright.unit.config.ts
unit/cloudflareD1RouterApiAuthService.unit.test.ts --grep "starts ECDSA
add-signer|responds to and finalizes ECDSA add-signer" --reporter=line` with 2
focused add-signer lifecycle tests; `pnpm --dir tests exec tsc -p
tsconfig.playwright.json --noEmit`; and `git diff --check`.
- [x] Current focused signer-set registration validation passed:
      `pnpm --dir tests exec playwright test -c playwright.unit.config.ts
      unit/cloudflareD1RouterApiAuthService.unit.test.ts --grep "starts and
      responds to combined Ed25519 and ECDSA registration ceremonies|finalizes
      ECDSA wallet registration ceremonies|starts and responds to Ed25519-only
      signer-set registration|starts ECDSA wallet registration ceremonies"
      --reporter=line` passed with 4 D1 registration tests, and
      `pnpm --dir tests exec playwright test -c playwright.unit.config.ts
      unit/refactor82CloudflareD1Runtime.guard.unit.test.ts --grep "NEAR
      Ed25519|EVM-family ECDSA registration branch prepare|combined registration
      state|legacy registration modes|AuthService wallet registration|D1 wallet
      add-signer" --reporter=line` passed with 6 guard tests. The first attempt
      ran both Playwright commands in parallel and failed to start one web server
      because port 5180 was already in use; the command passed when rerun alone.
- [x] Current SDK iframe/build validation passed:
      `pnpm --dir packages/sdk-web run build:sdk`,
      `pnpm --dir packages/sdk-web run build:rolldown`, and
      `W3A_TEST_FRONTEND_URL=http://127.0.0.1:3799 pnpm --dir tests exec
      playwright test -c playwright.unit.config.ts
      unit/seamsWeb.passkeyIframe.flowEvents.unit.test.ts --reporter=line`.
      The browser iframe test passed with 1 flow-event test and proves the built
      `PM_REGISTER_WALLET` path carries signer-set branches.
- [x] Service-split line-count checkpoint recorded, with final count cleanup owned
      by Phase 7. The old `d1EcdsaCeremonyService.ts` module is 831 lines at
      `HEAD`. Current split modules are 1,333 lines in
      `d1WalletRegistrationService.ts`, 445 in
      `d1NearEd25519RegistrationBranch.ts`, 79 in
      `d1EvmFamilyEcdsaRegistrationBranch.ts`, and 375 in
      `d1WalletAddSignerService.ts`. The split improves ownership, but it is not
      net-neutral once untracked files are counted, so Phase 7 still owns the final
      deletion/count pass.

### Phase 9: Durable Object-Owned ECDSA-HSS Pool-Fill Sessions

Status: implemented for the current D1/DO staging path, pending local Tempo/ARC
smoke confirmation. TTL alarm polish remains tracked below; the live WASM state
no longer belongs to the Router API Worker.

Trigger:

- Local D1/DO testing exposed that
  `/router-ab/ecdsa-hss/presignature-pool/fill/init` creates a live
  `ThresholdEcdsaPresignSession` WASM object and
  `/router-ab/ecdsa-hss/presignature-pool/fill/step` must advance the same live
  object.
- The current interim fix keeps a request-independent module-global live session
  store in the Router API Worker. That can avoid the immediate Cloudflare
  request-I/O error locally, but it is still the wrong owner: Workers are
  opportunistic isolates, cannot be routed to as stateful actors, and must not
  retain cryptographic ceremony state as architecture.
- Persisting the WASM internals into D1 is also the wrong shape. D1 should store
  metadata, audit state, completed presignatures, and durable coordination
  records. The live HSS pool-fill object is short-lived actor state.

Goal:

- [x] Move live `ThresholdEcdsaPresignSession` ownership into a dedicated Durable
      Object path.
- [x] Keep Router API Worker routes as thin boundaries: parse request bodies,
      validate wallet/session authority, derive the DO routing key, call the DO,
      and return the typed response.
- [x] Keep D1 out of live WASM session ownership. D1 may persist final
      presignatures and durable metadata only.
- [x] Delete the interim Worker-level ECDSA pool-fill live-session cache after the
      DO path is live.

Target ownership:

- Router API Worker:
  - [x] Parses `/router-ab/ecdsa-hss/presignature-pool/fill/init` and
        `/fill/step` bodies through the existing route validators.
  - [x] Verifies wallet-session claims and project/runtime scope.
  - [x] Derives a stable live-session DO object id from the pool-fill session id
        after validating tenant/runtime scope and ECDSA signer identity from the
        durable session record. Chain target is operation identity and must not be
        used as live ECDSA key-material authority.
  - [x] Forwards typed commands to the DO. It keeps no
        `ThresholdEcdsaPresignSession`, WASM handle, request-scoped I/O object, or
        module-global crypto session cache.
- ECDSA pool-fill Durable Object:
  - [x] Owns the live `ThresholdEcdsaPresignSession` instances in memory for the
        lifetime of each pool-fill ceremony.
  - [ ] Stores durable metadata in DO storage: tenant/runtime scope, ECDSA signer
        identity, threshold session id, pool-fill session id, stage, expiry,
        replay/idempotency keys, and audit markers.
  - [x] Advances init/step with serialized live-session mutation inside the DO.
  - [x] Writes completed presignatures into the existing presignature pool owner
        or the existing pool persistence interface.
  - [x] Clears live session state on completion, cancellation, failure, and
        observed expiry.

State and failure semantics:

- [x] The DO returns a typed stale-session result such as
      `stale_pool_fill_session` when the live WASM session has been evicted,
      expired, or was never initialized in that DO instance.
- [x] The SDK treats stale pool-fill state as a retryable precomputation miss and
      restarts `/fill/init`; it must not consume signing budget or present this as
      a user-auth failure.
- [x] Completed presignature writes remain idempotent. Duplicate step retries must
      return the same committed result or a typed replay result.
- [ ] Pool-fill live sessions have short TTLs and DO alarms/cleanup for expired
      metadata. Current staging behavior uses short session TTLs, explicit
      completion/failure cleanup, and stale-session retry; add alarms when we need
      proactive cleanup beyond DO storage expiration.

Implementation inventory:

- [x] `packages/sdk-server-ts/src/core/ThresholdService/routerAb/ecdsaHssPoolFillHandlers.ts`
      moves live-session creation/advancement behind a DO command surface. Keep
      pure parsing/result helpers if they still remove real duplication.
- [x] `packages/sdk-server-ts/src/core/ThresholdService/ThresholdSigningService.ts`
      stops accepting `ecdsaPoolFillLiveSessions` from Cloudflare Worker
      factories.
- [x] `packages/sdk-server-ts/src/core/ThresholdService/createCloudflareDurableObjectThresholdSigningService.ts`
      stops threading Worker-owned ECDSA pool-fill live stores.
- [x] `packages/sdk-server-ts/src/router/cloudflare/d1ThresholdSigningRuntime.ts`,
      `d1RouterApiAuthConfig.ts`, and `d1RouterApiAuthService.ts` stop accepting
      or passing `ecdsaPoolFillLiveSessions`.
- [x] `packages/sdk-server-ts/src/router/cloudflare/d1LocalDevWorker.ts` deletes
      `localRouterApiEcdsaPoolFillLiveSessionsCache`.
- [x] `packages/sdk-server-ts/src/router/cloudflare/d1RouterApiStagingWorker.ts`
      deletes `routerApiStagingEcdsaPoolFillLiveSessionsCache`.
- [x] `packages/sdk-server-ts/src/router/cloudflare/durableObjects/thresholdStore.ts`
      owns the live session map and live create/step/delete commands. Durable
      metadata and completed-presignature writes continue through the existing
      DO-backed pool-fill session and presignature pool stores.
- [x] Wrangler and local-dev bindings route ECDSA pool-fill commands to the DO
      owner through `THRESHOLD_STORE` or a narrower explicitly named namespace.
      Prefer reusing `THRESHOLD_STORE` if it preserves clear object ownership.

Guards and tests:

- [ ] Add a focused unit/integration test where `/fill/init` and `/fill/step` run
      through fresh Router API Worker handler instances and still share live state
      through the DO.
- [x] Add a stale-session test proving a missing live DO session returns the typed
      stale result and the SDK retries by starting a new init.
- [x] Add an idempotency test proving duplicate step/final writes do not create
      duplicate presignatures.
- [x] Update `tests/unit/refactor82CloudflareD1Runtime.guard.unit.test.ts` so
      Router API Worker source rejects:
      `localRouterApiEcdsaPoolFillLiveSessionsCache`,
      `routerApiStagingEcdsaPoolFillLiveSessionsCache`,
      `ecdsaPoolFillLiveSessions` in Worker factory options, and any direct
      `createRouterAbEcdsaHssPoolFillLiveSessionStore()` call outside the DO
      owner or test fixtures.
- [x] Add a source guard that rejects D1 persistence of serialized
      `ThresholdEcdsaPresignSession` internals.

Exit criteria:

- [ ] ECDSA-HSS Tempo and ARC signing can fill a presignature pool locally through
      Wrangler/Miniflare D1 plus Durable Objects with fresh Worker handlers per
      request.
- [x] Router API Worker code has no live ECDSA-HSS pool-fill session cache.
- [x] D1 stores no live WASM session internals.
- [x] The typed stale-session path is covered and user-facing retry behavior is
      clear.
- [x] `pnpm --dir packages/sdk-server-ts type-check` passes.
- [x] Focused Refactor 82 runtime guard passes.
- [x] `git diff --check` passes.

### Phase 10: Console-Owned Sponsored Spend Pricing

Status: implemented for the D1 runtime MVP. Frontend EVM flows do not use gas
sponsorship; clients are expected to fund their EVM accounts. This phase keeps
the D1 backend model coherent and makes signer/backend assembly compile without
env-pricing hacks. Runtime EVM signing does not depend on sponsorship pricing.

Trigger:

- Local D1 testing exposed `Sponsored spend pricing is not configured on this
  server` from `/sponsorships/evm/call`, but that route is outside the current
  frontend EVM signing requirement.
- Sponsored spend pricing is business policy. It belongs in the Console D1
  policy database with platform-admin write access, while executor private keys
  and RPC endpoints remain deployment secrets/configuration.
- Request-time backfill or env-var fallback would let runtime traffic silently
  mint pricing policy. That is an accounting and sponsorship-control risk.

Goal:

- [x] Add the minimal Console D1 schema for static EVM gas pricing.
- [x] Add the smallest D1 adapter that implements
      `SponsorshipSpendPricingService` for `evm_static_gas_v1`.
- [x] Wire the D1 Router API to that adapter only where sponsorship routes are
      explicitly mounted, so backend assembly compiles without env-pricing
      services.
- [x] Keep estimate/finalize version-locked through the existing
      `pricingVersion` field.
- [x] Delete D1 Router API env-var pricing configuration and any request-time
      pricing backfill path.
- [x] Keep normal frontend EVM signing on client-funded accounts. Enable the
      Tempo testnet demo drip button through `/sponsorships/evm/call` so demo
      wallets can receive Tempo fee tokens without manually funding testnet gas.
- [x] Defer platform-admin UI, live pricing, CoinGecko pricing, generalized
      sponsorship configuration, and broad billing product work.

Target data model:

- [x] Add `sponsorship_pricing_rules` to Console D1 with one supported model:
      `evm_static_gas_v1`.
- [x] Required selector fields: `namespace`, `org_id`, `project_id`,
      `environment_id`, `policy_id`, `chain_family`, `chain_id`, `intent_kind`,
      and `executor_kind`.
- [x] Required model fields: `estimate_fee_per_gas_wei`,
      `minor_per_wei_numerator`, `minor_per_wei_denominator`,
      `min_spend_minor`, and `rounding_mode`.
- [x] Required lifecycle fields: `pricing_version`, `status`,
      `effective_from_ms`, `effective_until_ms`, `created_by`, `created_at_ms`,
      and `updated_at_ms`.
- [x] Enforce one active rule per selector with a D1 unique index. Use `policy_id`
      as an empty string for environment-level pricing in the MVP.
- [x] Keep secrets out of pricing rows. Executor private keys, RPC URLs, and
      sponsor wallet material remain in secret/config boundaries.

Runtime integration:

- [x] Add `ConsoleSponsorshipPricingService` as the smallest adapter that
      implements `SponsorshipSpendPricingService`.
- [x] Wire `createCloudflareD1ConsoleServiceBundle()` into Router API
      sponsorship options so `/sponsorships/evm/call` reads pricing from
      `CONSOLE_DB`.
- [x] Estimate uses the active `evm_static_gas_v1` row:
      `estimate_fee_per_gas_wei * requested_gas_limit * minor_per_wei`, rounded
      up and clamped to `min_spend_minor`.
- [x] Finalize loads the exact `estimatedPricingVersion` row and computes:
      `fee_amount_wei * minor_per_wei`, rounded up and clamped to
      `min_spend_minor`.
- [x] Missing active pricing, missing exact finalize version, retired exact
      finalize version, malformed fee units, or unsupported chain family return a
      typed fail-closed pricing error.
- [x] Keep local `pnpm router` behavior deterministic: normal EVM signing works
      without pricing; sponsored-call routes either have an explicit seeded static
      pricing row or fail closed with a typed configuration error.

MVP seed/admin surface:

- [x] Add an explicit setup helper for Tempo testnet static pricing and call it
      when a publishable key enables the Tempo onboarding policy for an
      environment. This is setup code, not request-time fallback.
- [x] No HTTP write path is needed for compile/test harnesses. The MVP uses an
      explicit setup helper; a future HTTP write path must be platform-admin-only
      and limited to create/retire for the static model.
- [x] Defer dashboard UI and broad pricing-management APIs.

Cleanup inventory:

- [x] Remove `SPONSORED_*PRICING*` env-var parsing from Cloudflare D1 Router API
      runtime wiring.
- [x] Keep generic pricing fixtures outside the Cloudflare D1 runtime; the D1
      runtime guard rejects env-pricing reads under Cloudflare Worker sources.
- [x] Update local setup docs so EVM signing instructions say accounts must be
      client-funded. Add the explicit platform-admin pricing seed step only under
      optional sponsorship-route testing.
- [x] Update frontend/demo code so EVM account funding is presented as a client
      funding prerequisite. Do not route normal EVM signing through
      `/sponsorships/evm/call`.
- [x] Update `/readyz` or local smoke checks to report missing sponsorship pricing
      only when sponsored EVM execution is explicitly enabled. Missing pricing
      must not make normal EVM signer readiness fail.
- [x] Add a Refactor 82 guard that rejects env-pricing reads in
      `packages/sdk-server-ts/src/router/cloudflare/**` and request-time
      pricing backfill helpers.

Tests and validation:

- [x] D1 migration smoke proves the pricing table, indexes, and constraints.
- [x] Service tests prove static EVM gas estimate/finalize math, active-rule
      selection by selector, exact-version finalize, and fail-closed behavior for
      no active rule.
- [x] Reservation tests prove estimate stores `pricingVersion` and finalize uses
      that exact version.
- [x] Seed/setup tests prove local static Tempo pricing can be installed once for
      optional sponsorship-route testing.
- [x] HTTP write-path authorization tests are not applicable because no HTTP
      write path was added.
- [x] Type-check proves D1 Router API assembly no longer needs env-pricing
      services.
- [x] Frontend or route-surface tests prove normal Tempo/ARC signing does not call
      `/sponsorships/evm/call`.

Exit criteria:

- [x] D1 Router API compiles and assembles sponsorship dependencies from Console
      D1 pricing, with no env-pricing service required.
- [x] Normal EVM signing works without any sponsorship pricing row.
- [x] Missing Console D1 pricing fails closed with a typed configuration error.
      only for explicitly sponsored-call routes.
- [x] Pricing rows are created only through migration/setup tooling or
      platform-admin-only APIs.
- [x] No request path can create, infer, or backfill sponsored spend pricing.
- [x] Focused disabled-route/static-schema sponsorship MVP tests pass.
- [x] Refactor 82 runtime guard passes.
- [x] `pnpm --dir packages/sdk-server-ts type-check` passes.
- [x] `git diff --check` passes.

## Validation

Minimum checks before first D1 staging deploy:

- [x] `pnpm --dir packages/sdk-server-ts type-check`
- [x] D1 schema smoke tests for every migration.
- [x] Billing reservation atomic duplicate and insufficient-balance tests.
- [x] Sponsored settlement idempotency and replay tests.
- [x] Snapshot outbox lease claim tests.
- [x] Tenant scoping tests that prove cross-org reads and writes fail.
- [x] Signer sealed-share parser tests.
- [x] Durable Object coordination tests for normal-signing admission, budgets,
      replay guards, presignature pools, signing-root coordination, and session
      consumption.
- [ ] Durable Object-owned ECDSA-HSS pool-fill tests proving fresh Router API
      Worker handlers can run init/step through the DO owner without Worker-local
      live session caches.
- [ ] Console-owned sponsored spend pricing tests proving D1-backed pricing
      selection, version-locked settlement, platform-admin mutation control, and
      fail-closed missing-rule behavior.
- [x] Local D1 backup/restore drill:

```bash
pnpm --dir packages/sdk-server-ts run d1:local:restore:drill
```

Validation evidence: the drill passed on June 27, 2026. It ran local D1
prepare, backed up and restored `seams-console` and `seams-signer`, verified
`PRAGMA integrity_check = ok`, and confirmed 40 console tables with 18 applied
migrations plus 21 signer tables with 10 applied migrations. Re-run on June 29,
2026: `pnpm --dir packages/sdk-server-ts run d1:local:restore:drill` passed and
wrote `.wrangler/d1-local-restore-drills/2026-06-28T23-20-08-539Z/manifest.json`.

- [x] Local Wrangler D1/DO smoke:

```bash
pnpm --dir packages/sdk-server-ts run d1:local:prepare
pnpm --dir packages/sdk-server-ts run d1:local:dev
curl http://127.0.0.1:9090/readyz
curl http://127.0.0.1:9090/console/readyz
curl http://127.0.0.1:9090/router-api/healthz
```

The local `/readyz` response must confirm `cloudflare_d1_do`, 40 console
tables, 21 signer tables, `CONSOLE_DB`, `SIGNER_DB`, `THRESHOLD_STORE`, and a
successful Durable Object normal-signing admission reservation.

Validation evidence: `pnpm --dir packages/sdk-server-ts run d1:local:prepare`
passed under Wrangler `4.105.0`, `pnpm --dir packages/sdk-server-ts run
d1:local:dev` started with local D1/DO bindings and no compatibility-date
fallback warning, and live local HTTP smoke returned `200` for `GET /readyz`,
`GET /console/readyz`, and `GET /router-api/healthz`.

## Immediate Phase Tracker

Proceed in this order:

- [x] Phase 1: Inventory only remaining Postgres coupling that is still on a
      staging-required console, signer, sponsored gas, billing, or reconciliation
      request path.
- [x] Phase 2: Freeze D1 schemas and Durable Object ownership boundaries for
      those paths.
- [x] Phase 3 (closure): record domain-store port proof, finish any missing
      Durable Object contract tests, complete the high-risk adapter coverage
      matrix, and decide whether threshold public-key metadata is needed before
      staging.
- [x] Phase 4 (closure): prove dashboard flows, signer flows, sponsored-gas
      billing, and reconciliation locally through Wrangler/Miniflare D1 and local
      Durable Object storage without Docker Postgres.
- [x] Phase 5 (closure): freeze the first-staging signer auth scope, confirm
      deferred signer auth methods are future route slices, and keep pure core
      tests on fakes where SQL or Durable Object semantics are irrelevant.
- [ ] Phase 6 (staging deployment): fill the staging Wrangler config, run the
      static readiness gate, apply staging D1 migrations, configure the hosted
      signer KEK provider, verify console routes cannot access signer KEKs, import
      staging fixtures, capture Time Travel bookmarks, run staging smoke,
      dashboard reconciliation, sponsored-gas billing, signer route health,
      fixture-backed custody checks, and remote R2 export/restore drills.
- [x] Phase 7: Delete legacy migration scaffolding, stale compatibility paths,
      obsolete tests, and temporary guards during cleanup slices. Final count
      closure now records tracked plus untracked text and names the owner for each
      remaining positive block. Post-82 iframe, HSS payload-trim, and ECDSA
      material-identity follow-ups stay in their own plans, and Phase 9
      Worker-level ECDSA-HSS pool-fill cache deletion is included after the Durable
      Object owner landed.
- [x] Phase 8: Functional signer-set and D1 branch-set ceremony closure is
      validated. The service-split count checkpoint is recorded, and the remaining
      positive count cleanup is rolled into the final Phase 7 deletion/count pass.
- [ ] Phase 9: Move ECDSA-HSS pool-fill live `ThresholdEcdsaPresignSession`
      ownership into a Durable Object, delete the interim Worker-level live
      session cache, and prove fresh Worker handlers can advance the same pool-fill
      ceremony through DO routing.
- [x] Phase 10: Move sponsored EVM spend pricing into Console D1. The schema,
      static-pricing adapter, D1 Router API pricing wiring, explicit setup seed,
      and Cloudflare D1 env-pricing guard are implemented; the full
      platform-admin pricing UI/API remains deferred.

## Audit Findings

Track auditor findings here until they are fixed, validated, and marked off.
Each fix should remove the obsolete shape rather than adding compatibility
branches, except at explicit request or persistence boundaries.

- [x] P2: Phase 7 line counts were misleading when they reported only tracked
      files.
      Fix: record tracked counts and tracked-plus-untracked working-tree counts
      separately. Treat tracked-only counts as cleanup evidence, and make the final
      closure count include untracked text so unstaged implementation files still
      count as production growth.
      Evidence: the Phase 7 cleanup entry records tracked and
      tracked-plus-untracked counts separately. The final June 30 snapshot records
      118,475 tracked additions and 72,918 tracked deletions, plus 6,516 untracked
      text lines across 18 files. It also records the non-doc and
      `packages/sdk-server-ts/src` slices, including the 1,497 untracked lines under
      `packages/sdk-server-ts/src`.
- [x] P3: Refactor 82 status text was inconsistent about Phase 6.
      Fix: the status header, phased first-cut plan, Phase 6 section, and
      immediate tracker now all say Phase 6 is the staging deployment phase with
      open exit criteria.
- [x] P3: Phase 3-5 status text blurred implementation work with closure work.
      Fix: Phase 3 now tracks adapter boundary proof, missing Durable Object
      contract tests, high-risk adapter coverage, local Postgres dependency
      closure, and the threshold public-key metadata decision. Phase 4 now tracks
      full local workflow proof without Docker Postgres. Phase 5 now tracks the
      first-staging signer auth scope freeze and defers future auth-method coverage
      to future route slices. Phase 6 now carries the real staging deployment
      checklist: staging D1 migrations, signer KEK provider setup, KEK separation
      verification, fixture import, Time Travel bookmarks, staging smoke,
      dashboard reconciliation, sponsored-gas billing, signer route health,
      fixture-backed custody checks, and remote R2 export/restore drills.
- [x] P1: `rpId` leaked into generic registration/add-signer/add-auth-method
      intent state and D1 wallet registration flow control.
      Fix: make intent authority branch-specific. Passkey/WebAuthn branches carry
      `WebAuthnRpId`; Email OTP, OIDC, ECDSA signer, and wallet-only branches do
      not carry `rpId` at the root. Parse route bodies into the exact branch at the
      Cloudflare/Express boundary before core logic sees the intent.
      Evidence: fixed in `packages/shared-ts/src/utils/registrationIntent.ts`,
      `packages/sdk-server-ts/src/router/cloudflare/d1RouterApiAuthService.ts`,
      `packages/sdk-server-ts/src/router/walletRegistrationRoutes.ts`,
      `packages/sdk-server-ts/src/core/AuthService.ts`, and SDK-web registration
      request builders. Type fixtures now reject root `rpId` on registration,
      add-signer, and add-auth-method intents. D1 Router API unit tests assert passkey,
      Email OTP, ECDSA registration, ECDSA add-signer, and Email OTP add-auth
      intents do not carry root `rpId` while passkey branches keep their RP scope.
      Validation passed: `pnpm --dir packages/shared-ts type-check`,
      `pnpm --dir packages/sdk-server-ts type-check`,
      `unit/cloudflareD1RouterApiAuthService.unit.test.ts`,
      `unit/registrationIntentAllocation.unit.test.ts`, and
      `unit/addWalletSigner.orchestration.unit.test.ts`.
- [x] P2: `NearAccountOwnershipProofMessageV1` still carried root `rpId`.
      Fix: remove `rpId` from the NEAR ownership proof message shape and parser.
      NEAR account ownership proves control of the NEAR account/public key for
      the wallet; WebAuthn RP scope belongs only to passkey auth branches.
      Evidence: fixed in `packages/shared-ts/src/utils/registrationIntent.ts`
      and `packages/sdk-server-ts/src/core/AuthService.ts`. Type fixtures now
      accept NEAR ownership proofs without `rpId` and reject adding `rpId` to the
      proof message. The runtime normalizer rejects stale raw proof payloads that
      still include `message.rpId`. Registration allocation tests build proof
      messages without RP scope. Validation passed: `pnpm --dir packages/shared-ts
type-check`, `pnpm --dir packages/sdk-server-ts type-check`,
      `unit/registrationIntentAllocation.unit.test.ts` focused on NEAR account
      ownership, and `unit/registrationIntentDigest.unit.test.ts`.
- [x] P1: D1 wallet persistence must reject RP-scoped wallet identity.
      Fix: remove `rp_id` from wallet rows, migrations, indexes, and wallet record
      types before D1 staging deploy. Store `rpId` only on passkey/WebAuthn
      auth-method, credential, challenge, or session records where it is part of
      authentication authority.
      Evidence: fixed in `packages/sdk-server-ts/src/core/WalletStore.ts`,
      `packages/sdk-server-ts/src/core/d1WalletStore.ts`,
      `packages/sdk-server-ts/migrations/d1-signer/0002_signer_wallet_metadata.sql`.
      Wallet identity and Ed25519 signer metadata reject `rpId` through
      `packages/sdk-server-ts/src/core/WalletStore.typecheck.ts`, and D1 migration
      smoke asserts `signer_wallets` has no RP column while auth-method rows keep
      their passkey RP column. Remaining `rp_id` columns are passkey/WebAuthn
      auth-method, bootstrap-token, recovery, or session authority rows. Validation passed: `pnpm --dir packages/sdk-server-ts
type-check`, `unit/cloudflareD1RouterApiAuthService.unit.test.ts`,
      `unit/registrationIntentAllocation.unit.test.ts`,
      `unit/registrationCeremonyStore.unit.test.ts`, and
      `unit/addWalletSigner.orchestration.unit.test.ts`.
- [x] P2: Wallet persistence and ceremony parsers branded raw strings with
      `as WalletId`.
      Fix: parse wallet identity with `parseWalletId()` at persistence/request
      boundaries and reject corrupt rows before core logic sees branded wallet
      state. Do not use `as WalletId` in wallet persistence/parser code.
      Evidence: fixed in `packages/sdk-server-ts/src/core/d1WalletStore.ts`,
      `packages/sdk-server-ts/src/core/WalletStore.ts`,
      `packages/sdk-server-ts/src/core/RegistrationCeremonyStore.ts`, and
      `packages/sdk-server-ts/src/core/AuthService.ts`. `parseWalletId()` now
      rejects embedded whitespace and control characters after boundary trimming,
      so corrupt persistence rows such as `alice testnet` cannot enter core wallet
      state. The wallet-scope guard now rejects `as WalletId` across
      `packages/sdk-server-ts/src/core` and production Cloudflare D1 parser/store
      modules. Validation passed:
      `pnpm --dir packages/sdk-server-ts type-check`, `pnpm --dir tests exec
playwright test -c playwright.unit.config.ts
unit/walletScopedLookups.guard.unit.test.ts
unit/registrationCeremonyStore.unit.test.ts
unit/walletAuthMethodStore.unit.test.ts --reporter=line`, and a direct
      `rg "as WalletId"` scan over the cited files.
      Follow-up Phase 7 boundary cleanup also deleted the self-hosted Cloudflare
      signing worker's local `HssWalletId` raw-string brand. The verify-wallet
      route now parses `subjectId` through `parseWalletId()` before calling the
      threshold signing-root verifier, and the focused self-hosted worker guard
      rejects reintroducing `HssWalletId`. Validation passed:
      `pnpm --dir tests exec playwright test -c playwright.unit.config.ts
      unit/cloudflareSelfHostedSigningWorker.script.unit.test.ts --reporter=line`
      with 6 tests, `pnpm --dir packages/sdk-server-ts type-check`,
      `pnpm --dir tests exec playwright test -c playwright.unit.config.ts
      unit/refactor82CloudflareD1Runtime.guard.unit.test.ts --reporter=line`
      with 43 tests, `pnpm --dir tests exec tsc -p
      tsconfig.playwright.json --noEmit`, `git diff --check`, and a direct scan
      proving `HssWalletId` remains only in the self-hosted worker source guard.
- [x] P1: D1 auth and recovery paths treated generic wallet IDs as NEAR account
      IDs.
      Fix: parse wallet identity at D1 boundaries with the wallet parser/brand.
      Apply `isValidAccountId` only inside the hosted NEAR relayer-account branch,
      where the value is explicitly a hosted relayer account ID.
      Evidence: fixed in
      `packages/sdk-server-ts/src/router/cloudflare/d1WebAuthnAuthService.ts`,
      `packages/sdk-server-ts/src/router/cloudflare/d1EmailOtpRecoveryService.ts`,
      `packages/sdk-server-ts/src/router/cloudflare/d1GoogleEmailOtpSessionResolver.ts`,
      `packages/sdk-server-ts/src/router/cloudflare/d1IdentityService.ts`, and
      the D1-era identity paths still owned by
      `packages/sdk-server-ts/src/core/AuthService.ts`.
      Latest cleanup also routes Email OTP recovery status, grant consumption,
      recovery-key consumption/failure, recovery-key rotation, and Google
      registration-attempt completion through `parseD1BoundaryWalletIdResult`
      before D1 recovery/auth logic sees a wallet ID. WebAuthn login, Email OTP
      unlock, OIDC linked-wallet resolution, Google Email OTP enrollment lookup,
      and hosted Google Email OTP cleanup now parse generic wallet identity with
      the wallet parser at the boundary, and the shared D1 boundary parser returns
      a branded `WalletId` rather than widening wallet identity back to `string`.
      The hosted Google Email OTP branch uses
      `parseHostedHmacReadableRelayerWalletId` and
      `isHostedHmacReadableRelayerWalletId`, branded branch-specific predicates
      for hosted NEAR-shaped relayer wallet IDs. Production Cloudflare `d1*.ts`
      modules no longer call `isValidAccountId` directly. AuthService keeps
      `isValidAccountId` only for the NEAR account creation request and the
      hosted-account parser internals. Validation passed:
      `pnpm --dir packages/sdk-server-ts type-check`,
      `pnpm --dir tests exec tsc -p tsconfig.playwright.json --noEmit`,
      `pnpm --dir tests exec playwright test -c playwright.unit.config.ts
unit/walletScopedLookups.guard.unit.test.ts
unit/authService.hostedAccountPrivacy.unit.test.ts --reporter=line`,
      `pnpm --dir tests exec playwright test -c playwright.relayer.config.ts
relayer/email-otp.authservice.test.ts --reporter=line`,
      `pnpm --dir tests exec playwright test -c playwright.unit.config.ts
unit/registrationIntentDigest.unit.test.ts --reporter=line`,
      `pnpm --dir packages/shared-ts type-check`,
      `pnpm --dir packages/sdk-web type-check`, and `git diff --check`.
- [x] P2: Server-allocated wallet ID reservations must be wallet-scoped.
      Fix: reserve server-allocated wallet IDs by tenant/runtime scope plus `walletId`, or
      by an explicit branch-specific authority scope. Do not use WebAuthn `rpId` as
      the universal wallet-name reservation namespace.
      Evidence: fixed in `packages/sdk-server-ts/src/core/RegistrationCeremonyStore.ts`,
      `packages/sdk-server-ts/src/core/AuthService.ts`, and the D1 registration
      ceremony Durable Object path. The D1/DO path reserves
      `server-allocated-wallet-reservation:{walletId}` inside the tenant-scoped
      registration ceremony DO prefix; it does not accept or persist `rpId` for
      server-allocated wallet reservation. Unit tests reject duplicate reservation by
      wallet ID and allow a distinct server-allocated wallet ID in the same tenant.
      Validation passed:
      `unit/registrationCeremonyStore.unit.test.ts`,
      `unit/cloudflareD1RouterApiAuthService.unit.test.ts`, and
      `unit/registrationIntentAllocation.unit.test.ts`.
- [x] P2: Sponsored reservation settlement must prove the lifecycle transition
      matched before writing settlement/release records.
      Fix: make the D1 settlement/release mutation return a definitive
      `settled | duplicate | missing | invalid_state` result from one atomic path,
      and insert sponsored-call or ledger records only from the successful
      transition branch.
      Evidence: fixed in `packages/sdk-server-ts/src/router/sponsorshipExecution.ts`,
      `packages/sdk-server-ts/src/console/billing/d1.ts`,
      `packages/sdk-server-ts/src/console/sponsoredCalls/d1.ts`, and
      `tests/relayer/console-d1-adapters.test.ts`. Reservation settlement/release
      remains one D1 batch; the reservation transition runs first, later ledger and
      sponsored-call inserts are guarded by SQLite `changes() = 1`, and the route
      converts stale or already-final reservations to `invalid_state` unless the
      original sponsored-call idempotency key already has a record. Validation
      passed: `pnpm --dir packages/sdk-server-ts type-check` and
      `pnpm --dir tests exec playwright test -c playwright.relayer.config.ts
relayer/console-d1-adapters.test.ts --grep "sponsored gas settlement|sponsored
call idempotency" --reporter=line`.
- [x] P2: Sponsored-call idempotency is route-enforced but still nullable in
      lower-level types/schema.
      Fix: make the idempotency key required in service input, D1 schema, and
      migrations. Remove nullable storage and compatibility fallbacks before
      staging.
      Evidence: fixed in `packages/sdk-server-ts/src/console/sponsoredCalls/types.ts`,
      `packages/sdk-server-ts/src/console/sponsoredCalls/service.ts`,
      `packages/sdk-server-ts/src/console/sponsoredCalls/d1.ts`,
      `packages/sdk-server-ts/migrations/d1-console/0001_console_d1_initial.sql`,
      and
      `packages/sdk-server-ts/migrations/d1-console/0018_console_constraint_hardening.sql`.
      The service request and record types now require `idempotencyKey`, adapters
      reject missing keys, fresh D1 schema uses `idempotency_key NOT NULL`, and
      the D1 migration rebuilds the table with a non-partial unique index.
      Validation passed: `pnpm --dir packages/sdk-server-ts type-check`,
      `pnpm --dir tests exec playwright test -c playwright.relayer.config.ts
relayer/console-d1-adapters.test.ts --grep "sponsored gas settlement|sponsored
call idempotency" --reporter=line`, `git diff --check`, and a SQLite smoke
      applying `0001_console_d1_initial.sql` plus
      `0018_console_constraint_hardening.sql`.
- [x] P2: The new D1 Router API auth service is a large monolith.
      Fix: split by route family and domain boundary after the D1 behavior is
      stable: registration ceremonies, WebAuthn, Email OTP/OIDC, ECDSA ceremonies,
      wallet auth methods, threshold/session storage, and shared boundary parsers.
      Keep core domain inputs exact and avoid adding wrapper abstractions that only
      move the same broad state around.
      Progress: shared raw-record boundary parsing moved to
      `packages/sdk-server-ts/src/router/cloudflare/d1RouterApiAuthBoundary.ts`, and
      registration-ceremony Durable Object config/transport moved to
      `packages/sdk-server-ts/src/router/cloudflare/d1RegistrationCeremonyDo.ts`.
      Persisted registration/add-signer/add-auth-method ceremony record parsers
      moved to
      `packages/sdk-server-ts/src/router/cloudflare/d1RegistrationCeremonyRecords.ts`.
      The DO-backed registration ceremony store moved to
      `packages/sdk-server-ts/src/router/cloudflare/d1RegistrationCeremonyStore.ts`.
      This deleted the local boundary, parser, DO transport, and DO store copies
      from `d1RouterApiAuthService.ts`. Parser extraction line count:
      `d1RouterApiAuthService.ts` dropped from 14,345 to 13,462 lines while the new
      parser module added 950 lines, a near-neutral +67-line split. Store extraction
      line count: `d1RouterApiAuthService.ts` dropped from 13,462 to 13,128 lines while
      the new store module added 356 lines, a near-neutral +22-line split.
      Wallet-auth revoke request parsing and WebAuthn authentication credential
      parsing moved to
      `packages/sdk-server-ts/src/router/cloudflare/d1WalletAuthMethodBoundary.ts`,
      and persisted WebAuthn authenticator, binding, login-challenge, and
      sync-challenge parsing moved to
      `packages/sdk-server-ts/src/router/cloudflare/d1WebAuthnRecords.ts`.
      The same pass moved integer normalization helpers into
      `packages/sdk-server-ts/src/router/cloudflare/d1RouterApiAuthBoundary.ts`.
      The revoke-auth-method request contract is now branch-specific: passkey
      targets and WebAuthn assertion auth carry `rpId`; Email OTP targets and
      app-session Email OTP revoke requests reject root `rpId`, and Email OTP
      revoke responses do not return `rpId`.
      The D1 Router API factory now returns the concrete D1 auth service directly, and
      the obsolete disabled scaffold was deleted.
      WebAuthn/wallet-auth extraction line count: `d1RouterApiAuthService.ts` dropped
      from 13,128 to 12,790 lines while the two new modules plus boundary helper
      growth added 429 lines, a near-neutral +91-line split. Remaining split
      targets: Email OTP/OIDC, wallet auth method orchestration, ECDSA ceremonies,
      and threshold/session storage. Validation passed: `pnpm --dir
packages/shared-ts type-check`, `pnpm --dir packages/sdk-server-ts
type-check`, `pnpm --dir tests exec playwright test -c
playwright.unit.config.ts unit/cloudflareD1RouterApiAuthService.unit.test.ts
unit/registrationIntentAllocation.unit.test.ts
unit/registrationCeremonyStore.unit.test.ts --reporter=line`, `pnpm --dir
tests exec playwright test -c playwright.unit.config.ts
unit/cloudflareD1RouterApiAuthService.unit.test.ts
unit/registrationCeremonyStore.unit.test.ts --reporter=line`, and `git diff
--check`. Factory cleanup line count:
      `d1RouterApiAuthService.ts` dropped from 12,790 to 12,722 lines and deleting
      `disabledRelayAuthService.ts` removed another 147 lines, a net-negative
      215-line cleanup. Validation passed: `pnpm --dir packages/sdk-server-ts
type-check`, `pnpm --dir tests exec playwright test -c
playwright.unit.config.ts unit/cloudflareD1RouterApiAuthService.unit.test.ts
unit/refactor82CloudflareD1Runtime.guard.unit.test.ts --reporter=line`, and
      `git diff --check`. Persisted Email OTP wallet enrollment, auth-state,
      challenge, grant, unlock-challenge, and recovery-escrow row parsers/builders
      moved to
      `packages/sdk-server-ts/src/router/cloudflare/d1EmailOtpRecords.ts`; shared
      JSON/base64url boundary helpers moved to
      `packages/sdk-server-ts/src/router/cloudflare/d1RouterApiAuthBoundary.ts`. The
      same pass deleted the duplicate local Email OTP record helpers from
      `d1RouterApiAuthService.ts`. Email OTP record extraction line count:
      `d1RouterApiAuthService.ts` dropped from 12,722 to 12,071 lines while the new
      Email OTP record module plus boundary helper growth total 740 lines, a
      near-neutral +58-line split from the former local monolith shape. Validation
      passed: `pnpm --dir packages/shared-ts type-check`, `pnpm --dir
packages/sdk-server-ts type-check`, `pnpm --dir tests exec playwright test -c
playwright.unit.config.ts unit/cloudflareD1RouterApiAuthService.unit.test.ts
--grep "Email OTP|Google Email OTP|recovery-key|recovery keys|server
seal|unlock|server-allocated wallet" --reporter=line`, `pnpm --dir tests exec
playwright test -c playwright.unit.config.ts
unit/cloudflareD1RouterApiAuthService.unit.test.ts --grep "stores wallet
registration intents" --reporter=line`, `pnpm --dir tests exec playwright
test -c playwright.unit.config.ts
unit/refactor82CloudflareD1Runtime.guard.unit.test.ts --reporter=line`, and
      `git diff --check`. Google Email OTP registration-attempt row parsing,
      runtime-scope matching, offer response shaping, and attempt lifecycle record
      builders moved to
      `packages/sdk-server-ts/src/router/cloudflare/d1GoogleEmailOtpRegistrationRecords.ts`.
      The same pass deleted the duplicate local Google registration-attempt record
      helpers from `d1RouterApiAuthService.ts`. Google registration-attempt extraction
      line count: `d1RouterApiAuthService.ts` dropped from 12,071 to 11,447 lines while
      the new leaf module added 658 lines, a near-neutral +34-line split from the
      former local monolith shape. Remaining split targets: Email OTP/OIDC
      orchestration, wallet auth method orchestration, ECDSA ceremonies, and
      threshold/session storage. Validation passed: `pnpm --dir packages/sdk-server-ts
type-check`, `pnpm --dir tests exec playwright test -c
playwright.unit.config.ts unit/cloudflareD1RouterApiAuthService.unit.test.ts
--grep "Google Email OTP registration attempts|rate-limits Google Email OTP
registration attempts|ECDSA wallet registration ceremonies" --reporter=line`,
      and `git diff --check`. App-session row helpers plus recovery-session and
      recovery-execution D1 row parsing/status builders moved to
      `packages/sdk-server-ts/src/router/cloudflare/d1SessionRecords.ts`. The same
      pass deleted the duplicate local app-session/recovery record helpers from
      `d1RouterApiAuthService.ts`. Session/recovery record extraction line count:
      `d1RouterApiAuthService.ts` dropped from 11,447 to 11,222 lines while the new
      leaf module added 248 lines, a near-neutral +23-line split from the former
      local monolith shape. Remaining split targets: Email OTP/OIDC orchestration,
      wallet auth method orchestration, ECDSA ceremonies, and threshold signing
      storage. Validation passed: `pnpm --dir packages/sdk-server-ts type-check`,
      `pnpm --dir tests exec playwright test -c playwright.unit.config.ts
unit/cloudflareD1RouterApiAuthService.unit.test.ts --grep "recovery session|recovery
execution|app session|Email OTP recovery-key|recovery-key" --reporter=line`,
      and `git diff --check`. ECDSA ceremony bootstrap comparison, HSS bootstrap
      request shaping, responded-ceremony builders, finalized wallet-key material
      builders, wallet record builders, and ECDSA selection comparison helpers
      moved into
      `packages/sdk-server-ts/src/router/cloudflare/d1RegistrationCeremonyRecords.ts`.
      The same pass deleted the duplicate local ECDSA helper block from
      `d1RouterApiAuthService.ts`. ECDSA ceremony helper extraction line count:
      `d1RouterApiAuthService.ts` dropped from 11,222 to 10,957 lines while the
      ceremony record module grew from 950 to 1,338 lines, a +123-line split that
      also replaces the old loose missing-field scan with a typed complete-bootstrap
      boundary check. Remaining split targets: Email OTP/OIDC orchestration, wallet
      auth method orchestration, and threshold signing storage. Validation passed:
      `pnpm --dir packages/sdk-server-ts type-check`, `pnpm --dir tests exec
playwright test -c playwright.unit.config.ts
unit/cloudflareD1RouterApiAuthService.unit.test.ts --grep "ECDSA wallet
registration ceremonies|ECDSA add-signer ceremonies" --reporter=line`, and
      `git diff --check`. WebAuthn request-boundary helpers for
      base64url/base64 decoding, clientDataJSON parsing, RP-origin checks, and
      credential ID extraction moved to
      `packages/sdk-server-ts/src/router/cloudflare/d1WalletAuthMethodBoundary.ts`
      beside the existing WebAuthn authentication credential parser. Wallet
      auth-method record builders for active/revoked records and registration
      finalize responses moved to the same boundary module. The same pass deleted
      the duplicate local helpers from `d1RouterApiAuthService.ts`. Wallet-auth boundary
      helper extraction line count: `d1RouterApiAuthService.ts` dropped from 10,957 to
      10,783 lines while the wallet-auth boundary module grew from 212 to 419
      lines, a near-neutral +33-line split from the former local monolith shape.
      Remaining split targets: Email OTP/OIDC orchestration, wallet auth method
      orchestration, and threshold signing storage. Validation passed: `pnpm --dir
packages/sdk-server-ts type-check`, `pnpm --dir tests exec playwright test -c
playwright.unit.config.ts unit/cloudflareD1RouterApiAuthService.unit.test.ts
--grep "stores D1 Router API auth records|revokes wallet auth methods|adds Email
OTP wallet auth methods" --reporter=line`, `pnpm --dir tests exec playwright
test -c playwright.unit.config.ts unit/cloudflareD1RouterApiAuthService.unit.test.ts
--grep "reads signer metadata" --reporter=line`, and `git diff --check`.
      Email OTP challenge binding checks, attempt-count updates, recovery escrow
      active/revoked/consumed transitions, recovery challenge redaction, recovery
      escrow active counts, and auth-state patch builders moved to
      `packages/sdk-server-ts/src/router/cloudflare/d1EmailOtpRecords.ts`. The same
      pass deleted the duplicate local record-transition helpers from
      `d1RouterApiAuthService.ts`. Email OTP record-transition extraction line count:
      `d1RouterApiAuthService.ts` dropped from 10,783 to 10,474 lines while the Email
      OTP record module grew from 694 to 1,016 lines, a near-neutral +13-line split
      from the former local monolith shape. Remaining split targets: Email OTP/OIDC
      orchestration, wallet auth method orchestration, and threshold signing
      storage. Validation passed: `pnpm --dir packages/sdk-server-ts type-check`,
      `pnpm --dir tests exec playwright test -c playwright.unit.config.ts
unit/cloudflareD1RouterApiAuthService.unit.test.ts --grep "Email OTP|recovery-key|recovery
keys|unlock|registration Email OTP|device recovery" --reporter=line`, and
      `git diff --check`. OIDC exchange config normalization, issuer matching,
      JWT audience parsing, cache-control max-age parsing, Google JWKS parsing, and
      generic OIDC JWKS parsing moved to
      `packages/sdk-server-ts/src/router/cloudflare/d1OidcBoundary.ts`. The local
      D1 dev Worker now imports OIDC config types from that boundary module instead
      of from the Router API service. The same pass deleted the duplicate local OIDC
      helpers from `d1RouterApiAuthService.ts`. OIDC boundary extraction line count:
      `d1RouterApiAuthService.ts` dropped from 10,474 to 10,320 lines while the new
      OIDC boundary module added 196 lines, a +42-line split from the former local
      monolith shape. Remaining split targets: Email OTP/OIDC orchestration, wallet
      auth method orchestration, and threshold signing storage. Validation passed:
      `pnpm --dir packages/sdk-server-ts type-check`, `pnpm --dir tests exec
playwright test -c playwright.unit.config.ts
unit/cloudflareD1RouterApiAuthService.unit.test.ts --grep "Google OIDC|generic
OIDC exchange" --reporter=line`, and `git diff --check`.
      WebAuthn sync wallet-binding shaping and NEAR public-key row parsing moved to
      `packages/sdk-server-ts/src/router/cloudflare/d1WebAuthnRecords.ts`. The same
      pass deleted the duplicate local helpers from `d1RouterApiAuthService.ts` after the
      extraction had landed. WebAuthn/Near helper extraction line count:
      `d1RouterApiAuthService.ts` dropped from 10,320 to 10,261 lines while
      `d1WebAuthnRecords.ts` grew from 193 to 254 lines, a near-neutral +2-line
      split from the former local monolith shape. Remaining split targets: Email
      OTP/OIDC orchestration, wallet auth method orchestration, and threshold
      signing storage. Validation passed: `pnpm --dir packages/sdk-server-ts
type-check`, `pnpm --dir tests exec playwright test -c
playwright.unit.config.ts unit/cloudflareD1RouterApiAuthService.unit.test.ts
--grep "stores wallet registration intents|starts ECDSA wallet registration|adds
Email OTP wallet auth methods" --reporter=line` passed with 3 tests,
      `pnpm --dir tests exec playwright test -c playwright.unit.config.ts
unit/cloudflareD1RouterApiAuthService.unit.test.ts --grep "starts ECDSA add-signer
ceremonies" --reporter=line`, and `git diff --check`.
      Identity-link row typing, identity record building, stale Google Email OTP
      identity mapping, wallet-subject collision checks, and link-conflict result
      builders moved to
      `packages/sdk-server-ts/src/router/cloudflare/d1IdentityRecords.ts`. Generic
      D1 count and mutation-change parsing moved to
      `packages/sdk-server-ts/src/router/cloudflare/d1RouterApiAuthBoundary.ts` so the
      identity module only owns identity behavior. The same pass deleted the
      duplicate local helpers from `d1RouterApiAuthService.ts`. Identity boundary
      extraction line count: `d1RouterApiAuthService.ts` dropped from 10,261 to 10,184
      lines, the new identity module added 88 lines, and `d1RouterApiAuthBoundary.ts`
      grew from 46 to 63 lines, a +28-line split from the former local monolith
      shape. Remaining split targets: Email OTP/OIDC orchestration, wallet auth
      method orchestration, and threshold signing storage. Validation passed:
      `pnpm --dir packages/sdk-server-ts type-check`, `pnpm --dir tests exec
playwright test -c playwright.unit.config.ts
unit/cloudflareD1RouterApiAuthService.unit.test.ts --grep "reads signer
metadata|Google Email OTP|Google OIDC|generic OIDC exchange" --reporter=line`,
      and `git diff --check`.
      RS256 JWT segment parsing, JWT signature verification, and boolean JWT claim
      parsing moved to `packages/sdk-server-ts/src/router/cloudflare/d1OidcBoundary.ts`
      beside the existing JWKS and OIDC issuer normalization code. Generic
      `Uint8Array` to `ArrayBuffer` conversion moved to
      `packages/sdk-server-ts/src/router/cloudflare/d1RouterApiAuthBoundary.ts` so the
      Router API service and OIDC verifier share one byte-boundary helper. The same pass
      deleted the duplicate local JWT helper block from `d1RouterApiAuthService.ts`.
      RS256/OIDC extraction line count: `d1RouterApiAuthService.ts` dropped from 10,184
      to 10,035 lines, `d1OidcBoundary.ts` grew from 196 to 347 lines, and
      `d1RouterApiAuthBoundary.ts` grew from 63 to 69 lines, a near-neutral +8-line
      split from the former local monolith shape. Remaining split targets: Email
      OTP/OIDC orchestration, wallet auth method orchestration, and threshold
      signing storage. Validation passed: `pnpm --dir packages/sdk-server-ts
type-check`, `pnpm --dir tests exec playwright test -c
playwright.unit.config.ts unit/cloudflareD1RouterApiAuthService.unit.test.ts
--grep "Google OIDC|generic OIDC exchange" --reporter=line`, and
      `git diff --check`.
      Email OTP recovery-key rotation escrow validation and active escrow record
      construction moved to
      `packages/sdk-server-ts/src/router/cloudflare/d1EmailOtpRecords.ts` beside the
      existing Email OTP recovery escrow parsers. The same pass deleted the duplicate
      service-local rotation helper block from `d1RouterApiAuthService.ts`; the router-api
      service now passes its portable SHA-256 boundary helper into the Email OTP
      record builder. Recovery-rotation extraction line count:
      `d1RouterApiAuthService.ts` dropped from 10,035 to 9,909 lines while
      `d1EmailOtpRecords.ts` grew from 1,016 to 1,166 lines, a +24-line split from
      the former local monolith shape. Remaining split targets: Email OTP/OIDC
      orchestration, wallet auth method orchestration, and threshold signing
      storage. Validation passed: `pnpm --dir packages/sdk-server-ts type-check`,
      `pnpm --dir tests exec playwright test -c playwright.unit.config.ts
unit/cloudflareD1RouterApiAuthService.unit.test.ts --grep "rotates Email OTP
recovery keys|rejects stale Email OTP recovery-key rotation|rejects invalid
Email OTP recovery-key rotation" --reporter=line`, and `git diff --check`.
      Registration/add-signer/add-auth intent construction, server-allocated wallet ID
      allocation, runtime-scope inference from signing roots, and intent-policy
      matchers moved to
      `packages/sdk-server-ts/src/router/cloudflare/d1RegistrationCeremonyRecords.ts`
      beside the D1 ceremony record parsers. The same pass deleted the duplicate
      service-local ceremony helper block from `d1RouterApiAuthService.ts`; the router-api
      service now imports those domain helpers from the ceremony records module.
      Ceremony-helper extraction line count: `d1RouterApiAuthService.ts` dropped from
      9,909 to 9,758 lines while `d1RegistrationCeremonyRecords.ts` grew from 1,338
      to 1,504 lines, a +15-line split from the former local monolith shape.
      Remaining split targets: Email OTP/OIDC orchestration, wallet auth method
      orchestration, and threshold signing storage. Validation passed: `pnpm --dir
packages/sdk-server-ts type-check`, `pnpm --dir tests exec playwright test -c
playwright.unit.config.ts unit/cloudflareD1RouterApiAuthService.unit.test.ts
--grep "stores wallet registration intents|starts ECDSA wallet
registration|starts ECDSA add-signer ceremonies|adds Email OTP wallet auth
methods" --reporter=line`, and `git diff --check`.
      Email OTP enrollment-material boundary validation and recovery-wrapped escrow
      set validation moved to
      `packages/sdk-server-ts/src/router/cloudflare/d1EmailOtpRecords.ts`. The same
      pass deleted the duplicate private validation methods from
      `d1RouterApiAuthService.ts`; the Router API service now injects its portable SHA-256
      and secp256k1 public-key validators into the Email OTP boundary helper while
      keeping D1 reads/writes in the service-owned persistence methods.
      Enrollment-material extraction line count: `d1RouterApiAuthService.ts` dropped
      from 9,758 to 9,537 lines while `d1EmailOtpRecords.ts` grew from 1,166 to
      1,415 lines, a +28-line split from the former local monolith shape.
      Remaining split targets: Email OTP/OIDC orchestration, wallet auth method
      orchestration, and threshold signing storage. Validation passed: `pnpm --dir
packages/sdk-server-ts type-check`, `pnpm --dir tests exec playwright test -c
playwright.unit.config.ts unit/cloudflareD1RouterApiAuthService.unit.test.ts
--grep "finalizes ECDSA wallet registration ceremonies|verifies registration
Email OTP enrollment" --reporter=line`, and `git diff --check`.
      Email OTP utility and rate-limit boundary helpers moved to
      `packages/sdk-server-ts/src/router/cloudflare/d1EmailOtpRecords.ts`: masked
      email hints, numeric OTP generation, unlock TTL clamping, fixed-size
      base64url decoding, constant-work byte comparison, rate-limit key shaping,
      and rate-limit failure shaping. The same pass deleted the duplicate
      service-local helper block and D1 rate-limit row/scope types from
      `d1RouterApiAuthService.ts`. Utility/rate-limit extraction line count:
      `d1RouterApiAuthService.ts` dropped from 9,537 to 9,441 lines while
      `d1EmailOtpRecords.ts` grew from 1,415 to 1,524 lines, a +13-line split from
      the former local monolith shape. Remaining split targets: Email OTP/OIDC
      orchestration, wallet auth method orchestration, and threshold signing
      storage. Validation passed: `pnpm --dir packages/sdk-server-ts type-check`,
      `pnpm --dir tests exec playwright test -c playwright.unit.config.ts
unit/cloudflareD1RouterApiAuthService.unit.test.ts --grep "delivers Email OTP
through configured provider|fails closed when Email OTP provider is
missing|rate-limits Google Email OTP registration attempts|enforces Email OTP
challenge rate limits|verifies Email OTP unlock proofs once" --reporter=line`,
      and `git diff --check`.
      Google OIDC `id_token` claim validation moved to
      `packages/sdk-server-ts/src/router/cloudflare/d1OidcBoundary.ts`. The same
      pass deleted the duplicate private `validateGoogleIdTokenClaims` method and
      local failure type from `d1RouterApiAuthService.ts`, keeping JWT parsing and
      claim normalization at the OIDC boundary while the service retains JWKS cache,
      signature verification orchestration, and identity linking. OIDC boundary
      extraction line count: `d1RouterApiAuthService.ts` dropped from 9,441 to 9,327
      lines while `d1OidcBoundary.ts` grew from 347 to 457 lines, a net -4-line
      split from the former local monolith shape. The same validation pass fixed the
      SDK browser build import from `@noble/hashes/sha2` to
      `@noble/hashes/sha2.js`, restoring the built Vite plugin required by the
      Playwright unit web server. Remaining split targets: Email OTP/OIDC
      orchestration, wallet auth method orchestration, and threshold signing
      storage. Validation passed: `pnpm --dir packages/sdk-server-ts type-check`,
      `pnpm -C packages/sdk-web run build:sdk`, and `pnpm --dir tests exec
playwright test -c playwright.unit.config.ts
unit/cloudflareD1RouterApiAuthService.unit.test.ts --grep "verifies Google OIDC
tokens and links identity" --reporter=line`.
      Generic OIDC JWT exchange issuer/audience/subject/profile claim parsing and
      post-signature temporal claim validation moved to
      `packages/sdk-server-ts/src/router/cloudflare/d1OidcBoundary.ts`. The router-api
      service now keeps only OIDC exchange orchestration: parse JWT, fetch the
      issuer JWKS, verify the RS256 signature, then link the normalized identity
      subject. OIDC boundary extraction line count: `d1RouterApiAuthService.ts` dropped
      from 9,327 to 9,218 lines while `d1OidcBoundary.ts` grew from 457 to 631
      lines, a +65-line split from the former local monolith shape. Remaining split
      targets: Email OTP/OIDC orchestration, wallet auth method orchestration, and
      threshold signing storage. Validation passed: `pnpm --dir
packages/sdk-server-ts type-check` and `pnpm --dir tests exec playwright test
-c playwright.unit.config.ts unit/cloudflareD1RouterApiAuthService.unit.test.ts
--grep "verifies generic OIDC exchange tokens|verifies Google OIDC tokens"
--reporter=line`.
      D1 Router API auth option normalization, Email OTP delivery provider public types,
      Email OTP runtime rate-limit defaults, and Email OTP server-seal config
      parsing moved to `packages/sdk-server-ts/src/router/cloudflare/d1RouterApiAuthConfig.ts`.
      The service keeps the existing public type re-exports, plus the normalized
      options object it consumes at construction time. Config boundary split line
      count: `d1RouterApiAuthService.ts` dropped from 9,218 to 8,804 lines while
      `d1RouterApiAuthConfig.ts` added 444 lines, a near-neutral +30-line split from the
      former local monolith shape. Remaining split targets: Email OTP/OIDC
      orchestration, wallet auth method orchestration, and threshold signing
      storage. Validation passed: `pnpm --dir packages/sdk-server-ts type-check`
      and `pnpm --dir tests exec playwright test -c playwright.unit.config.ts
unit/cloudflareD1RouterApiAuthService.unit.test.ts --grep "delivers Email OTP
through configured provider|fails closed when Email OTP provider is
missing|applies and removes Email OTP server seals|verifies generic OIDC
exchange tokens|verifies Google OIDC tokens" --reporter=line`.
      Google and generic OIDC JWKS cache/fetch state moved to
      `packages/sdk-server-ts/src/router/cloudflare/d1OidcBoundary.ts` through
      `CloudflareD1OidcJwksCache`. The Router API service now asks the boundary cache
      for Google and issuer JWKS sets instead of owning cache maps, in-flight fetch
      promises, HTTP response parsing, and cache-control handling. JWKS boundary
      split line count: `d1RouterApiAuthService.ts` dropped from 8,804 to 8,719 lines
      while `d1OidcBoundary.ts` grew from 631 to 724 lines, a near-neutral +8-line
      split from the former local monolith shape. Remaining split targets: Email
      OTP/OIDC orchestration, wallet auth method orchestration, and threshold
      signing storage. Validation passed: `pnpm --dir packages/sdk-server-ts
type-check` and `pnpm --dir tests exec playwright test -c
playwright.unit.config.ts unit/cloudflareD1RouterApiAuthService.unit.test.ts
--grep "verifies generic OIDC exchange tokens|verifies Google OIDC tokens"
--reporter=line`.
      Email OTP dev outbox and delivery side effects moved to
      `packages/sdk-server-ts/src/router/cloudflare/d1EmailOtpDeliveryRuntime.ts`.
      The Router API service now owns challenge orchestration through the D1 challenge
      store and calls the delivery runtime for provider delivery or local
      development logging. Development OTP readback comes from D1 challenge rows.
      Delivery runtime split line count: `d1RouterApiAuthService.ts` dropped from 8,719
      to 8,624 lines while `d1EmailOtpDeliveryRuntime.ts` added 142 lines, a
      +47-line split from the former local monolith shape. Remaining split targets:
      Email OTP/OIDC orchestration, wallet auth method orchestration, and threshold
      signing storage. Validation passed: `pnpm --dir packages/sdk-server-ts
type-check` and `pnpm --dir tests exec playwright test -c
playwright.unit.config.ts unit/cloudflareD1RouterApiAuthService.unit.test.ts
--grep "Email OTP wallet auth methods|issues and verifies login Email OTP
challenges|issues registration Email OTP challenges|verifies registration
Email OTP enrollment|delivers Email OTP through configured provider|fails
      closed when Email OTP provider is missing|issues and verifies device recovery
      Email OTP challenges|enforces Email OTP challenge rate limits|verifies Email
      OTP unlock proofs once" --reporter=line`.
      Follow-up deletion pass: D1 removed the `memory` delivery mode in favor of
      `dev_d1_outbox`, deleted the runtime `memoryOutbox` Map,
      `readOutboxEntry`, `deleteOutboxEntry`, and the router-api
      `pruneExpiredEmailOtpChallengeOutboxEntries`,
      `enforceEmailOtpActiveChallengeOutboxLimit`,
      `deleteEmailOtpChallengeAndOutbox`, and
      `consumeEmailOtpChallengeAndOutbox` helpers. Current line count:
      `d1EmailOtpDeliveryRuntime.ts` is 61 lines and
      `d1RouterApiAuthService.ts` is 6,576 lines. Validation passed:
      `pnpm --dir packages/sdk-server-ts type-check`, `pnpm --dir
      packages/sdk-server-ts build`, `pnpm --dir tests exec playwright test -c
      playwright.unit.config.ts unit/cloudflareD1RouterApiAuthService.unit.test.ts
      --grep "starts ECDSA wallet registration ceremonies through Durable
      Objects|responds to ECDSA wallet registration ceremonies through Durable
      Objects|finalizes ECDSA wallet registration ceremonies through Durable
      Objects|adds Email OTP wallet auth methods|issues and verifies login Email
      OTP challenges|issues registration Email OTP challenges|verifies
      registration Email OTP enrollment|issues and verifies device recovery Email
      OTP challenges|enforces Email OTP challenge rate limits" --reporter=line`,
      `pnpm --dir tests exec playwright test -c playwright.unit.config.ts
      unit/refactor82CloudflareD1Runtime.guard.unit.test.ts --reporter=line`, and
      `git diff --check`.
      Email OTP server-seal cipher creation moved to
      `packages/sdk-server-ts/src/router/cloudflare/d1EmailOtpServerSealRuntime.ts`.
      The Router API service now calls the seal runtime for apply/remove operations and
      no longer imports the Shamir cipher adapter or owns the seal-cipher result
      union. Server-seal runtime split line count: `d1RouterApiAuthService.ts` dropped
      from 8,624 to 8,579 lines while `d1EmailOtpServerSealRuntime.ts` added 56
      lines, a near-neutral +11-line split from the former local monolith shape.
      Remaining split targets: Email OTP/OIDC orchestration, wallet auth method
      orchestration, and threshold signing storage. Validation passed: `pnpm --dir
packages/sdk-server-ts type-check` and `pnpm --dir tests exec playwright test
-c playwright.unit.config.ts unit/cloudflareD1RouterApiAuthService.unit.test.ts
--grep "applies and removes Email OTP server seals|fails closed when Email OTP
server seal is unconfigured" --reporter=line`.
      Threshold-signing lazy resolution moved to
      `packages/sdk-server-ts/src/router/cloudflare/d1ThresholdSigningRuntime.ts`.
      The Router API service keeps the public `getThresholdSigningService()` method, but
      no longer owns the cached threshold-service field, initialized flag, Durable
      Object threshold factory call, or unsupported NEAR fallback stubs. Threshold
      runtime split line count: `d1RouterApiAuthService.ts` dropped from 8,579 to 8,559
      lines while `d1ThresholdSigningRuntime.ts` added 53 lines, a +33-line split
      from the former local monolith shape. Remaining split targets: Email OTP/OIDC
      orchestration and wallet auth method orchestration. Validation passed:
      `pnpm --dir packages/sdk-server-ts type-check` and `pnpm --dir tests exec
playwright test -c playwright.unit.config.ts
unit/cloudflareD1RouterApiAuthService.unit.test.ts --grep "wires threshold
signing from Durable Object config|responds to ECDSA wallet registration
ceremonies through Durable Objects|responds to and finalizes ECDSA add-signer
ceremonies through Durable Objects" --reporter=line`.
      D1 recovery-session, recovery-execution, and app-session-version SQL
      persistence moved to
      `packages/sdk-server-ts/src/router/cloudflare/d1SessionStore.ts`. The router-api
      service now validates request/domain inputs and delegates tenant-scoped D1
      record round-tripping to the session store, deleting the old private SQL
      helpers from the monolith in the same pass. Session store split line count:
      `d1RouterApiAuthService.ts` dropped from 8,559 to 8,340 lines while
      `d1SessionStore.ts` added 248 lines, a near-neutral +29-line split from the
      former local monolith shape. Remaining split targets: Email OTP/OIDC
      orchestration and wallet auth method orchestration. Validation passed:
      `pnpm --dir packages/sdk-server-ts type-check`, `pnpm --dir tests exec
playwright test -c playwright.unit.config.ts
unit/cloudflareD1RouterApiAuthService.unit.test.ts --grep "reads signer metadata
with tenant scope|tracks recovery sessions and executions" --reporter=line`,
      and `pnpm --dir tests exec playwright test -c playwright.relayer.config.ts
relayer/cloudflare-router.test.ts relayer/express-router.test.ts --grep
"recover-email" --reporter=line`.
      Wallet auth-method revoke policy validation, WebAuthn authorization lookup,
      and target-record resolution moved to
      `packages/sdk-server-ts/src/router/cloudflare/d1WalletAuthMethodBoundary.ts`.
      The Router API service now keeps the high-level revoke workflow while the
      branch-specific passkey/Email OTP revoke boundary owns target equality,
      app-session policy errors, WebAuthn authorization credential lookup, and
      hashed Email OTP target lookup. The same pass deleted the old private
      `findWalletAuthMethodRecordForRevokeTarget` helper from
      `d1RouterApiAuthService.ts` and updated a legacy route-boundary fixture that still
      put `rpId` at the root of an Email OTP revoke request. Revoke-boundary split
      line count: `d1RouterApiAuthService.ts` dropped from 8,340 to 8,284 lines while
      `d1WalletAuthMethodBoundary.ts` grew from 419 to 513 lines, a +38-line split
      from the former local monolith shape. Remaining split targets: Email OTP/OIDC
      orchestration and wallet auth method orchestration beyond revoke. Validation
      passed: `pnpm --dir packages/sdk-server-ts type-check`, `pnpm --dir tests
exec playwright test -c playwright.unit.config.ts
unit/cloudflareD1RouterApiAuthService.unit.test.ts --grep "revokes wallet auth
methods" --reporter=line`, `pnpm --dir tests exec playwright test -c
playwright.unit.config.ts unit/relayWalletRegistration.boundary.unit.test.ts
--grep "auth-method revoke" --reporter=line`, and `pnpm --dir tests exec
playwright test -c playwright.unit.config.ts
unit/registrationIntentAllocation.unit.test.ts --grep "revokes one auth
method|rejects revoking the last active auth method" --reporter=line`.
      Existing-auth resolution for add-signer and add-auth-method ceremonies moved
      to `packages/sdk-server-ts/src/router/cloudflare/d1WalletAuthMethodBoundary.ts`.
      The boundary now owns app-session policy wallet/method/selection/runtime-scope
      checks and WebAuthn authorization credential lookup for those wallet
      auth-method orchestration paths. The same pass deleted the duplicate private
      `resolveAddSignerExistingAuth` and `resolveAddAuthMethodExistingAuth` methods
      from `d1RouterApiAuthService.ts`. Add-signer/add-auth authorization split line
      count: `d1RouterApiAuthService.ts` dropped from 8,284 to 8,118 lines while
      `d1WalletAuthMethodBoundary.ts` grew from 513 to 706 lines, a +27-line split
      from the former local monolith shape. Remaining split target: Email OTP/OIDC
      orchestration, plus any smaller wallet auth-method authority helpers that
      still prove worth extracting during Phase 7. Validation passed: `pnpm --dir
packages/sdk-server-ts type-check`, `pnpm --dir tests exec playwright test -c
playwright.unit.config.ts unit/registrationIntentAllocation.unit.test.ts
--grep "starts and finalizes passkey add-auth-method|starts and finalizes
Email OTP add-auth-method|runs Ed25519 add-signer|runs ECDSA add-signer|rejects
add-auth-method when the wallet has no active auth methods" --reporter=line`,
      and `pnpm --dir tests exec playwright test -c playwright.unit.config.ts
unit/cloudflareD1RouterApiAuthService.unit.test.ts --grep "adds Email OTP wallet
auth methods|starts ECDSA add-signer ceremonies|responds to and finalizes
ECDSA add-signer ceremonies" --reporter=line`.
      Identity-link persistence now delegates from the Cloudflare D1 Router API service to
      the shared `D1IdentityStore` instead of keeping duplicate service-local SQL
      helpers. The shared D1 adapter now preserves the router-api's atomic conditional
      semantics for identity moves and last-identity unlink protection through
      single-statement `UPDATE`/`DELETE` guards, plus final-read verification for
      conflict races. The same pass deleted the private `readIdentity*`,
      `deleteIdentitySubjectLinkForDevCleanup`, and `moveIdentityIfAllowed` helper
      block from `d1RouterApiAuthService.ts`. Identity persistence cleanup line count:
      `d1RouterApiAuthService.ts` dropped from 8,118 to 7,886 lines while
      `IdentityStore.ts` grew from 1,895 to 1,968 lines, a net-negative 159-line
      cleanup. Remaining split target: Email OTP/OIDC orchestration. Validation
      passed: `pnpm --dir packages/sdk-server-ts type-check`, `pnpm --dir tests
exec playwright test -c playwright.relayer.config.ts
relayer/console-d1-adapters.test.ts --grep "signer identity links"
--reporter=line`, `pnpm --dir tests exec playwright test -c
playwright.relayer.config.ts relayer/oidc-exchange.authservice.test.ts
--grep "identity mapping|Google Email OTP registration|Google Email OTP
login|dev cleanup" --reporter=line`, `pnpm --dir tests exec playwright test
      -c playwright.unit.config.ts unit/cloudflareD1RouterApiAuthService.unit.test.ts
      --grep "Google OIDC|generic OIDC exchange|Google Email OTP" --reporter=line`,
      and `git diff --check`.
      Google Email OTP registration-attempt D1 persistence moved to
      `packages/sdk-server-ts/src/router/cloudflare/d1GoogleEmailOtpRegistrationAttemptStore.ts`.
      The store now owns tenant-scoped cleanup, create/read/write/delete, live
      wallet-offer collision checks, started-attempt refresh, malformed-row
      cleanup, replacement abandonment, and runtime-org write validation. The router-api
      service keeps wallet derivation, enrollment discovery, stale mapping
      decisions, and identity-link finalization. The same pass deleted the
      service-local `cleanupGoogleEmailOtpRegistrationAttempts`,
      `createGoogleEmailOtpRegistrationAttempt`,
      `findStartedGoogleEmailOtpRegistrationAttempt`,
      `abandonStartedGoogleEmailOtpRegistrationAttemptsExceptAppSession`,
      `hasLiveStartedGoogleEmailOtpWalletAttempt`,
      `readGoogleEmailOtpRegistrationAttempt`,
      `putGoogleEmailOtpRegistrationAttempt`, and
      `deleteGoogleEmailOtpRegistrationAttempt` helpers from
      `d1RouterApiAuthService.ts`. Registration-attempt store split line count:
      `d1RouterApiAuthService.ts` dropped from 7,886 to 7,612 lines while
      `d1GoogleEmailOtpRegistrationAttemptStore.ts` added 307 lines, a +33-line
      split from the former local monolith shape. Remaining split target: broader
      Email OTP/OIDC orchestration. Validation passed: `pnpm --dir
      packages/sdk-server-ts type-check`, `pnpm --dir tests exec playwright test
      -c playwright.unit.config.ts unit/cloudflareD1RouterApiAuthService.unit.test.ts
      --grep "Google Email OTP registration attempts|rate-limits Google Email OTP
      registration attempts|verifies Google OIDC|generic OIDC exchange"
      --reporter=line`, `pnpm --dir tests exec playwright test -c
      playwright.relayer.config.ts relayer/oidc-exchange.authservice.test.ts
      --grep "identity mapping|Google Email OTP registration|Google Email OTP
      login|dev cleanup" --reporter=line`, and `git diff --check`.
      Google Email OTP session resolution moved to
      `packages/sdk-server-ts/src/router/cloudflare/d1GoogleEmailOtpSessionResolver.ts`.
      The resolver now owns login/registration branching, stale mapping repair,
      HMAC-readable account derivation, registration-offer allocation, registration
      attempt completion, and development cleanup for Google Email OTP wallet
      mappings. The Router API service keeps only route/service method delegation and
      shared store ownership. The same pass deleted
      `resolveGoogleEmailOtpLoginSession`,
      `resolveGoogleEmailOtpRegistrationSession`,
      `createFreshGoogleEmailOtpRegistrationAttempt`,
      `deriveHostedGoogleEmailOtpWalletId`,
      `getGoogleEmailOtpEnrollmentBySubject`,
      `repairGoogleEmailOtpWalletLink`,
      `isGoogleEmailOtpEnrollmentLookupMiss`,
      `isRelayerSubaccount`, and
      `isHostedHmacReadableRelayerSubaccount` from `d1RouterApiAuthService.ts`.
      Session-resolver split line count: `d1RouterApiAuthService.ts` dropped from
      6,576 to 6,059 lines while `d1GoogleEmailOtpSessionResolver.ts` added 661
      lines, a +144-line split from the former local monolith shape. Remaining
      split target: non-Google Email OTP challenge/enrollment/recovery
      orchestration and any non-store helper cleanup candidates. Validation passed:
      `pnpm --dir packages/sdk-server-ts type-check`, `pnpm --dir
      packages/sdk-server-ts build`, `pnpm --dir tests exec playwright test -c
      playwright.unit.config.ts unit/cloudflareD1RouterApiAuthService.unit.test.ts
      --grep "Google Email OTP registration attempts|rate-limits Google Email OTP
      registration attempts|verifies Google OIDC|generic OIDC exchange"
      --reporter=line`, `pnpm --dir tests exec playwright test -c
      playwright.relayer.config.ts relayer/oidc-exchange.authservice.test.ts
      --grep "identity mapping|Google Email OTP registration|Google Email OTP
      login|dev cleanup" --reporter=line`, `pnpm --dir tests exec playwright
      test -c playwright.unit.config.ts
      unit/refactor82CloudflareD1Runtime.guard.unit.test.ts --reporter=line`, and
      `git diff --check`.
      WebAuthn D1 persistence moved to
      `packages/sdk-server-ts/src/router/cloudflare/d1WebAuthnStore.ts`. The store
      now owns tenant-scoped WebAuthn challenge write/consume, authenticator
      read/write/counter update, credential-binding lookup, and parsed binding-row
      listing. The Router API service keeps WebAuthn option construction,
      SimpleWebAuthn verification, origin/RP validation, identity linking, and
      response shaping. The same pass deleted the service-local
      `writeWebAuthnChallenge`, `consumeWebAuthnLoginChallenge`,
      `consumeWebAuthnSyncChallenge`, `consumeWebAuthnChallenge`,
      `readWebAuthnAuthenticator`, `writeWebAuthnAuthenticator`,
      `updateWebAuthnAuthenticatorCounter`, `readWebAuthnBindingByCredential`,
      `readWebAuthnAuthenticatorRows`, and `readWebAuthnBindingRows` helpers from
      `d1RouterApiAuthService.ts`. WebAuthn store split line count:
      `d1RouterApiAuthService.ts` dropped from 7,612 to 7,386 lines while
      `d1WebAuthnStore.ts` added 268 lines, a +42-line split from the former local
      monolith shape. Remaining split target: broader Email OTP/OIDC
      orchestration. Validation passed: `pnpm --dir packages/sdk-server-ts
      type-check`, `pnpm --dir tests exec playwright test -c
      playwright.unit.config.ts unit/cloudflareD1RouterApiAuthService.unit.test.ts
      --grep "reads signer metadata with tenant scope" --reporter=line`,
      `pnpm --dir tests exec playwright test -c playwright.unit.config.ts
      unit/registrationIntentAllocation.unit.test.ts --grep "starts and finalizes
      passkey add-auth-method" --reporter=line`, `pnpm --dir tests exec
      playwright test -c playwright.unit.config.ts
      unit/cloudflareD1RouterApiAuthService.unit.test.ts --grep "stores D1 Router API auth
      records|adds Email OTP wallet auth methods" --reporter=line`, and `git diff
      --check`.
      Email OTP grant D1 persistence moved to
      `packages/sdk-server-ts/src/router/cloudflare/d1EmailOtpGrantStore.ts`. The
      store now owns tenant-scoped grant insert, consume, read, and delete
      operations. The Router API service keeps challenge verification, grant binding
      checks, recovery failure reporting, and recovery-key consumption behavior.
      The same pass deleted the service-local `putEmailOtpGrant`,
      `consumeEmailOtpGrantRecord`, `readEmailOtpGrantRecord`, and
      `deleteEmailOtpGrantRecord` helpers from `d1RouterApiAuthService.ts`. Grant
      store split line count: `d1RouterApiAuthService.ts` dropped from 7,386 to 7,313
      lines while `d1EmailOtpGrantStore.ts` added 86 lines, a +13-line split from
      the former local monolith shape. Remaining split target: broader Email
      OTP/OIDC orchestration and remaining Email OTP challenge/enrollment/recovery
      persistence. Validation passed: `pnpm --dir packages/sdk-server-ts
      type-check`, `pnpm --dir tests exec playwright test -c
      playwright.unit.config.ts unit/cloudflareD1RouterApiAuthService.unit.test.ts
      --grep "reads signer metadata with tenant scope" --reporter=line`, `pnpm
      --dir tests exec playwright test -c playwright.unit.config.ts
      unit/cloudflareD1RouterApiAuthService.unit.test.ts --grep "issues and verifies
      device recovery Email OTP challenges" --reporter=line`, and `git diff
      --check`.
      Email OTP rate-limit D1 persistence moved to
      `packages/sdk-server-ts/src/router/cloudflare/d1EmailOtpRateLimitStore.ts`.
      The store now owns tenant-scoped fixed-window key derivation and atomic
      `INSERT ... ON CONFLICT ... WHERE ... RETURNING` consumption for challenge,
      verify, grant, recovery-key-attempt, and Google registration-attempt
      scopes. The Router API service keeps action-specific validation, Email OTP
      challenge/recovery orchestration, and rate-limit response propagation. The
      same pass deleted the service-local `consumeEmailOtpRateLimit` and
      `consumeEmailOtpRateLimitKey` helpers from `d1RouterApiAuthService.ts`.
      Rate-limit store split line count: `d1RouterApiAuthService.ts` dropped from
      7,313 to 7,213 lines while `d1EmailOtpRateLimitStore.ts` added 122 lines, a
      +22-line split from the former local monolith shape. Remaining split target:
      broader Email OTP/OIDC orchestration and remaining Email OTP
      challenge/enrollment/recovery persistence. Validation passed: `pnpm --dir
      packages/sdk-server-ts type-check`, `pnpm --dir tests exec playwright test
      -c playwright.unit.config.ts unit/cloudflareD1RouterApiAuthService.unit.test.ts
      --grep "rate-limits Google Email OTP registration attempts|enforces Email
      OTP challenge rate limits|issues and verifies device recovery Email OTP
      challenges" --reporter=line`, and `git diff --check`.
      Email OTP enrollment/auth-state D1 persistence moved to
      `packages/sdk-server-ts/src/router/cloudflare/d1EmailOtpEnrollmentStore.ts`.
      The store now owns tenant-scoped wallet enrollment read/write/delete,
      provider-user enrollment lookup, signer-wallet existence checks, auth-state
      read/write, enrollment-bound auth-state validation, auth-state reset, and
      failure-state reset. The Router API service keeps registration/add-auth/login
      orchestration, invalid-attempt challenge handling, recovery-key rotation
      policy, and response shaping. The same pass deleted the service-local
      `readEmailOtpWalletEnrollment`, `readEmailOtpWalletEnrollmentByProviderUserId`,
      `signerWalletExists`, `deleteEmailOtpWalletEnrollment`,
      `putEmailOtpWalletEnrollment`, `readEmailOtpAuthState`,
      `readEmailOtpAuthStateForEnrollment`, `putEmailOtpAuthStateForEnrollment`,
      `resetEmailOtpAuthStateForEnrollment`, and `resetEmailOtpFailureState`
      helpers from `d1RouterApiAuthService.ts`. Enrollment/auth-state store split line
      count: `d1RouterApiAuthService.ts` dropped from 7,213 to 6,970 lines while
      `d1EmailOtpEnrollmentStore.ts` added 258 lines, a +15-line split from the
      former local monolith shape. Remaining split target: broader Email OTP/OIDC
      orchestration and remaining Email OTP challenge/recovery persistence.
      Validation passed: `pnpm --dir packages/sdk-server-ts type-check`, `pnpm
      --dir tests exec playwright test -c playwright.unit.config.ts
      unit/cloudflareD1RouterApiAuthService.unit.test.ts --grep "adds Email OTP wallet
      auth methods|issues and verifies login Email OTP challenges|issues
      registration Email OTP challenges|verifies registration Email OTP
      enrollment|issues and verifies device recovery Email OTP challenges|rotates
      Email OTP recovery keys after fresh auth|starts, reuses, and restarts Google
      Email OTP registration attempts" --reporter=line`, and `git diff --check`.
      Email OTP recovery escrow D1 persistence moved to
      `packages/sdk-server-ts/src/router/cloudflare/d1EmailOtpRecoveryEscrowStore.ts`.
      The store now owns tenant-scoped recovery-wrapped enrollment escrow listing,
      single recovery-key lookup, active-key consumption, and batched
      active/consumed/revoked escrow upserts. The Router API service keeps recovery-key
      binding checks, rotation policy, active-code count enforcement, and response
      shaping. The same pass deleted the service-local
      `listEmailOtpRecoveryEscrowsForEnrollment`, `readEmailOtpRecoveryEscrow`,
      `consumeEmailOtpRecoveryEscrow`, `putEmailOtpRecoveryEscrows`, and
      `putEmailOtpRecoveryEscrowStatement` helpers from `d1RouterApiAuthService.ts`.
      Recovery-escrow store split line count: `d1RouterApiAuthService.ts` dropped from
      6,970 to 6,850 lines while `d1EmailOtpRecoveryEscrowStore.ts` added 165
      lines, a +45-line split from the former local monolith shape. Remaining
      split target: broader Email OTP/OIDC orchestration and remaining Email OTP
      challenge/unlock persistence. Validation passed: `pnpm --dir
      packages/sdk-server-ts type-check`, `pnpm --dir tests exec playwright test
      -c playwright.unit.config.ts unit/cloudflareD1RouterApiAuthService.unit.test.ts
      --grep "verifies registration Email OTP enrollment|issues and verifies
      device recovery Email OTP challenges|rotates Email OTP recovery keys after
      fresh auth|rejects stale Email OTP recovery-key rotation|rejects invalid
      Email OTP recovery-key rotation payloads|adds Email OTP wallet auth methods"
      --reporter=line`, and `git diff --check`.
      Email OTP challenge/unlock D1 persistence moved to
      `packages/sdk-server-ts/src/router/cloudflare/d1EmailOtpChallengeStore.ts`.
      The store now owns tenant-scoped login, registration, and device-recovery
      challenge read/write/consume/delete, expired challenge pruning, active
      challenge overflow deletion, attempt-count updates, and unlock-challenge
      write/consume. The Router API service keeps OTP generation, delivery-runtime
      dispatch, D1 challenge-row dev outbox reads, binding checks,
      invalid-attempt policy, active-limit response behavior, and response
      shaping. The same pass deleted the
      service-local `pruneExpiredEmailOtpChallenges`, `readEmailOtpChallenge`,
      `findLatestActiveEmailOtpChallenge`, `countActiveEmailOtpChallenges`,
      `deleteOldestActiveEmailOtpChallenge`, `putEmailOtpChallenge`,
      `updateEmailOtpChallengeAttemptCount`, `putEmailOtpUnlockChallenge`, and
      `consumeEmailOtpUnlockChallenge` SQL helpers from `d1RouterApiAuthService.ts`.
      A follow-up deletion pass removed the D1 dev outbox's in-memory Map and
      wrapper cleanup hooks, so pruning, overflow deletion, explicit delete, and
      consume now use D1 store methods directly.
      Challenge/unlock store split line count: `d1RouterApiAuthService.ts` dropped from
      6,850 to 6,596 lines while `d1EmailOtpChallengeStore.ts` added 319 lines, a
      +65-line split from the former local monolith shape. Remaining split target:
      broader Email OTP/OIDC orchestration and non-Email-OTP persistence cleanup
      candidates. Validation passed: `pnpm --dir packages/sdk-server-ts
      type-check`, `pnpm --dir tests exec playwright test -c
      playwright.unit.config.ts unit/cloudflareD1RouterApiAuthService.unit.test.ts
      --grep "issues and verifies login Email OTP challenges|issues registration
      Email OTP challenges|verifies registration Email OTP enrollment|issues and
      verifies device recovery Email OTP challenges|enforces Email OTP challenge
      rate limits|verifies Email OTP unlock proofs once|delivers Email OTP through
      configured provider|fails closed when Email OTP provider is missing"
      --reporter=line`, and `git diff --check`.
      NEAR public-key D1 listing moved to
      `packages/sdk-server-ts/src/router/cloudflare/d1NearPublicKeyStore.ts`. The
      store now owns tenant-scoped `signer_near_public_keys` reads and row parsing
      while the Router API service keeps request validation and public response
      projection. The same pass deleted the direct service-local NEAR public-key SQL
      from `listNearPublicKeysForUser`. NEAR public-key store split line count:
      `d1RouterApiAuthService.ts` dropped from 6,596 to 6,586 lines while
      `d1NearPublicKeyStore.ts` added 36 lines, a +26-line split from the former
      local monolith shape. Remaining split target: broader Email OTP/OIDC
      orchestration and any remaining non-store helper cleanup candidates.
      Validation passed: `pnpm --dir packages/sdk-server-ts type-check`, `pnpm
      --dir tests exec playwright test -c playwright.unit.config.ts
      unit/cloudflareD1RouterApiAuthService.unit.test.ts --grep "reads signer metadata
      with tenant scope" --reporter=line`, and `git diff --check`.
      D1 identity persistence moved to
      `packages/sdk-server-ts/src/core/d1IdentityStore.ts` and
      `d1RouterApiAuthService.ts` now imports the D1 leaf instead of the mixed
      `core/IdentityStore.ts` module. The mixed factory still re-exports the D1
      adapter for public API compatibility, but Cloudflare runtime no longer walks
      through the module that owns Postgres construction. The same pass deleted the
      D1 schema/options/class/helper block from `core/IdentityStore.ts` and
      strengthened the Refactor 82 runtime guard to follow dynamic `import()`
      dependencies. Validation passed: `pnpm --dir packages/sdk-server-ts
      type-check`, `pnpm --dir tests exec playwright test -c playwright.unit.config.ts
      unit/refactor82CloudflareD1Runtime.guard.unit.test.ts --reporter=line`, and
      `pnpm --dir tests exec playwright test -c playwright.unit.config.ts
      unit/cloudflareD1RouterApiAuthService.unit.test.ts --grep "verifies Google OIDC
      tokens and links identity|starts, reuses, and restarts Google Email OTP
      registration attempts|rotates Email OTP recovery keys after fresh auth|issues
      and verifies login Email OTP challenges|adds Email OTP wallet auth methods"
      --reporter=line`, and `pnpm --dir packages/sdk-server-ts build`.
      Email OTP registration-enrollment finalization moved to
      `packages/sdk-server-ts/src/router/cloudflare/d1EmailOtpRegistrationEnrollmentFinalizer.ts`.
      The finalizer now owns wallet-registration finalize enrollment material
      validation, backup-ack binding, provider-enrollment moves, recovery-wrapped
      escrow upserts, active escrow count verification, auth-state reset, and the
      standalone verified-enrollment persistence path that completes Google Email
      OTP registration attempts. The same pass deleted the duplicate
      `emailOtpEnrollmentPersistenceForRegistrationFinalize`,
      `buildEmailOtpRegistrationEnrollmentPersistence`,
      `persistEmailOtpRegistrationEnrollment`, and
      `completeGoogleEmailOtpRegistrationAttempt` helpers from
      `d1RouterApiAuthService.ts`. Registration-enrollment finalizer split line count:
      `d1RouterApiAuthService.ts` dropped from 6,059 to 5,686 lines while the new
      finalizer module added 394 lines, a near-neutral +21-line split from the
      former local monolith shape. Remaining split target: non-registration Email
      OTP challenge/recovery orchestration and any small non-store helper cleanup
      candidates. Validation passed: `pnpm --dir packages/sdk-server-ts
      type-check`, `pnpm --dir tests exec playwright test -c
      playwright.unit.config.ts unit/cloudflareD1RouterApiAuthService.unit.test.ts
      --grep "finalizes ECDSA wallet registration ceremonies|verifies
      registration Email OTP enrollment|starts, reuses, and restarts Google Email
      OTP registration attempts" --reporter=line`, `pnpm --dir tests exec
      playwright test -c playwright.relayer.config.ts
      relayer/oidc-exchange.authservice.test.ts --grep "identity mapping|Google
      Email OTP registration|completed Google Email OTP registration|dev cleanup"
      --reporter=line`, `pnpm --dir packages/sdk-server-ts build`, `pnpm --dir
      tests exec playwright test -c playwright.unit.config.ts
      unit/refactor82CloudflareD1Runtime.guard.unit.test.ts --reporter=line`, and
      `git diff --check`.
      Email OTP challenge verification moved to
      `packages/sdk-server-ts/src/router/cloudflare/d1EmailOtpChallengeVerifier.ts`.
      The verifier now owns existing-login/device-recovery challenge verification,
      registration challenge verification, verify-scope rate-limit consumption,
      challenge binding checks, OTP lockout enforcement, invalid-attempt auth-state
      updates, attempt-count updates, exhausted-challenge deletion, and successful
      challenge consumption. The Router API service keeps route response shaping,
      grant issuance, device-recovery response shaping, and authority construction.
      The same pass deleted the private `verifyEmailOtpExistingChallengeCode`,
      `verifyEmailOtpRegistrationChallengeCode`, `recordEmailOtpInvalidAttempt`,
      and `recordEmailOtpInvalidRegistrationAttempt` helpers from
      `d1RouterApiAuthService.ts`. Challenge-verifier split line count:
      `d1RouterApiAuthService.ts` dropped from 5,686 to 5,294 lines while the new
      verifier module added 470 lines, a +78-line split from the former local
      monolith shape. Remaining split target: Email OTP challenge issuance,
      grant/recovery-key consumption, and any small non-store helper cleanup
      candidates. Validation passed: `pnpm --dir packages/sdk-server-ts
      type-check`, `pnpm --dir tests exec playwright test -c
      playwright.unit.config.ts unit/cloudflareD1RouterApiAuthService.unit.test.ts
      --grep "issues and verifies login Email OTP challenges|issues registration
      Email OTP challenges|verifies registration Email OTP enrollment|issues and
      verifies device recovery Email OTP challenges|enforces Email OTP challenge
      rate limits|adds Email OTP wallet auth methods" --reporter=line`,
      `pnpm --dir packages/sdk-server-ts build`, `pnpm --dir tests exec
      playwright test -c playwright.unit.config.ts
      unit/refactor82CloudflareD1Runtime.guard.unit.test.ts --reporter=line`, and
      `git diff --check`.
      Email OTP challenge issuance moved to
      `packages/sdk-server-ts/src/router/cloudflare/d1EmailOtpChallengeIssuer.ts`.
      The issuer now owns challenge request validation, registration/login/device
      recovery purpose checks, active-enrollment lookup for non-registration
      challenges, issue-scope rate-limit consumption, active challenge reuse,
      active challenge overflow cleanup, OTP generation, D1 challenge persistence,
      delivery dispatch, and delivery-failure rollback. The Router API service keeps
      public response shaping for login, registration enrollment, and device
      recovery challenge routes. The same pass deleted the private
      `createEmailOtpChallengeWithAction` helper and the service-local
      `EmailOtpChallengeIssue*` types from `d1RouterApiAuthService.ts`.
      Challenge-issuer split line count: `d1RouterApiAuthService.ts` dropped from
      5,294 to 5,067 lines while the new issuer module added 327 lines, a +100-line
      split from the former local monolith shape. Remaining split targets:
      grant/recovery-key handling and any small non-store helper cleanup
      candidates. Validation passed: `pnpm --dir packages/sdk-server-ts
      type-check`, `pnpm --dir tests exec playwright test -c
      playwright.unit.config.ts unit/cloudflareD1RouterApiAuthService.unit.test.ts
      --grep "issues and verifies login Email OTP challenges|issues registration
      Email OTP challenges|verifies registration Email OTP enrollment|issues and
      verifies device recovery Email OTP challenges|enforces Email OTP challenge
      rate limits|delivers Email OTP through configured provider|fails closed when
      Email OTP provider is missing" --reporter=line`, `pnpm --dir
      packages/sdk-server-ts build`, `pnpm --dir tests exec playwright test -c
      playwright.unit.config.ts unit/refactor82CloudflareD1Runtime.guard.unit.test.ts
      --reporter=line`, and `git diff --check`.
      Email OTP recovery and grant handling moved to
      `packages/sdk-server-ts/src/router/cloudflare/d1EmailOtpRecoveryService.ts`.
      The recovery service now owns recovery-code status reads, device-recovery
      OTP verification response assembly, recovery consume-grant issuance, unlock
      challenge creation, unlock-proof verification, atomic login-grant
      consumption, atomic recovery-key consumption, recovery-key rotation, and
      recovery-key failure-attempt reporting. The Router API service keeps only the
      public `CloudflareRouterApiAuthService` method surface and delegates the D1
      implementation to the recovery service. The same pass deleted the
      service-local `emailOtpRecoveryNotEnrolledStatus`,
      `emailOtpGrantInvalidOrExpired`,
      `emailOtpRecoveryConsumeGrantInvalidOrExpired`, and
      `emailOtpRecoveryGrantBindingMismatch` helpers from `d1RouterApiAuthService.ts`,
      plus the old method-local recovery validation, grant binding, unlock proof,
      and recovery-rotation bodies. Recovery-service split line count:
      `d1RouterApiAuthService.ts` dropped from 5,067 to 4,329 lines while the new
      recovery module added 1,152 lines, a +414-line split from the former local
      monolith shape. Remaining split target: small non-store helper cleanup and
      broader wallet/OIDC orchestration still tracked by this phase. Validation
      passed: `pnpm --dir packages/sdk-server-ts type-check`, `pnpm --dir tests
      exec playwright test -c playwright.unit.config.ts
      unit/cloudflareD1RouterApiAuthService.unit.test.ts --grep "issues and verifies
      login Email OTP challenges|rotates Email OTP recovery keys after fresh
      auth|rejects stale Email OTP recovery-key rotation|rejects invalid Email OTP
      recovery-key rotation payloads|issues and verifies device recovery Email OTP
      challenges|enforces Email OTP challenge rate limits|verifies Email OTP
      unlock proofs once|verifies registration Email OTP enrollment"
      --reporter=line`, `pnpm --dir packages/sdk-server-ts build`, `pnpm --dir
      tests exec playwright test -c playwright.unit.config.ts
      unit/refactor82CloudflareD1Runtime.guard.unit.test.ts --reporter=line`, and
      `git diff --check`.
      Google and generic OIDC verification orchestration moved to
      `packages/sdk-server-ts/src/router/cloudflare/d1OidcVerificationService.ts`.
      The verifier now owns Google OIDC public config shaping, Google `id_token`
      verification, generic OIDC exchange JWT verification, JWKS cache use,
      WebCrypto signature verification calls, temporal claim enforcement, and
      identity-link reconciliation for verified provider subjects. The router-api
      service keeps only the public `CloudflareRouterApiAuthService` method surface
      and delegates the D1 implementation to the verifier. The same pass deleted
      the service-local OIDC JWKS cache property and the method-local
      `verifyGoogleLogin` / `verifyOidcJwtExchange` orchestration bodies from
      `d1RouterApiAuthService.ts`. OIDC-verifier split line count:
      `d1RouterApiAuthService.ts` dropped from 4,329 to 4,137 lines while the new
      verifier module added 268 lines, a +76-line split from the former local
      monolith shape. Remaining split target: wallet auth method orchestration,
      ECDSA ceremony orchestration, and threshold/session storage cleanup.
      Validation passed: `pnpm --dir packages/sdk-server-ts type-check`, `pnpm
      --dir tests exec playwright test -c playwright.unit.config.ts
      unit/cloudflareD1RouterApiAuthService.unit.test.ts --grep "verifies Google OIDC
      tokens and links identity|verifies generic OIDC exchange tokens"
      --reporter=line`, `pnpm --dir tests exec playwright test -c
      playwright.relayer.config.ts relayer/oidc-exchange.authservice.test.ts
      --reporter=line`, `pnpm --dir packages/sdk-server-ts build`, `pnpm --dir
      tests exec playwright test -c playwright.unit.config.ts
      unit/refactor82CloudflareD1Runtime.guard.unit.test.ts --reporter=line`, and
      `git diff --check`.
      App-session, recovery-session, and recovery-execution orchestration moved
      to `packages/sdk-server-ts/src/router/cloudflare/d1SessionService.ts`.
      The session service now owns app-session creation, rotation, validation,
      recovery-session reads/status updates, and recovery-execution upserts over
      the D1 session store. The Router API service keeps only the public
      `CloudflareRouterApiAuthService` method surface and delegates the D1
      implementation to the session service. The same pass deleted the method-local
      app-session validation, recovery-session mutation, metadata patch validation,
      and recovery-execution record construction bodies from
      `d1RouterApiAuthService.ts`. Session-service split line count:
      `d1RouterApiAuthService.ts` dropped from 4,137 to 3,995 lines while the new
      session module added 232 lines, a +90-line split from the former local
      monolith shape. Remaining split target: wallet auth method orchestration,
      ECDSA ceremony orchestration, and threshold signing storage cleanup.
      Validation passed: `pnpm --dir packages/sdk-server-ts type-check`, `pnpm
      --dir tests exec playwright test -c playwright.unit.config.ts
      unit/cloudflareD1RouterApiAuthService.unit.test.ts --grep "tracks recovery
      sessions and executions" --reporter=line`, `pnpm --dir tests exec
      playwright test -c playwright.unit.config.ts
      unit/cloudflareD1RouterApiAuthService.unit.test.ts --grep "reads signer
      metadata" --reporter=line`, `pnpm --dir tests exec playwright test -c
      playwright.relayer.config.ts relayer/oidc-exchange.authservice.test.ts
      --grep "returns invalid_session_version for stale app session version"
      --reporter=line`, `pnpm --dir packages/sdk-server-ts build`, `pnpm --dir
      tests exec playwright test -c playwright.unit.config.ts
      unit/refactor82CloudflareD1Runtime.guard.unit.test.ts --reporter=line`, and
      `git diff --check`.
      WebAuthn login, authenticator listing, sync-account option construction,
      authentication assertion verification, login verification, and sync-account
      verification moved to
      `packages/sdk-server-ts/src/router/cloudflare/d1WebAuthnAuthService.ts`.
      The Router API service keeps the public `CloudflareRouterApiAuthService` methods and
      delegates WebAuthn login/sync behavior to the focused service. The same pass
      deleted the duplicate method bodies, login/sync challenge TTL helper,
      boundary wallet-id parser, authenticator sorter, WebAuthn login/sync record
      imports, and authentication-assertion-only helpers from
      `d1RouterApiAuthService.ts`; passkey registration verification remains in the
      router-api because it still shares the registration ceremony flow. WebAuthn auth
      split line count: `d1RouterApiAuthService.ts` dropped from 3,995 to 3,428 lines
      while the new WebAuthn auth module is 694 lines, a +127-line split from the
      former local monolith shape and a 567-line router-api deletion in this pass.
      Remaining split target: wallet auth method orchestration, ECDSA ceremony
      orchestration, and threshold signing storage cleanup. Validation passed:
      `pnpm --dir packages/sdk-server-ts type-check`, `pnpm --dir tests exec
      playwright test -c playwright.unit.config.ts
      unit/cloudflareD1RouterApiAuthService.unit.test.ts --grep
      "WebAuthn|authenticator|sync account|reads signer metadata" --reporter=line`,
      `pnpm --dir packages/sdk-server-ts build`, `pnpm --dir tests exec
      playwright test -c playwright.unit.config.ts
      unit/refactor82CloudflareD1Runtime.guard.unit.test.ts --reporter=line`, and
      `git diff --check`.
      Wallet auth-method orchestration moved to
      `packages/sdk-server-ts/src/router/cloudflare/d1WalletAuthMethodService.ts`.
      The focused service now owns add-signer/add-auth existing-authorization
      resolution, passkey and Email OTP authority verification, duplicate
      authority detection, wallet auth-method persistence, and revoke policy
      execution. The same pass deleted the corresponding private helper block,
      stale SimpleWebAuthn helper imports, wallet-auth boundary imports, and local
      Email OTP hash helper from `d1RouterApiAuthService.ts`; the router-api keeps the
      public `CloudflareRouterApiAuthService` methods and delegates to the focused
      service. Wallet auth-method orchestration split line count:
      `d1RouterApiAuthService.ts` dropped from 3,428 to 2,725 lines while the new
      wallet auth-method module is 763 lines, a +60-line split from the former
      local monolith shape and a 703-line router-api deletion in this pass. Remaining
      split targets: ECDSA ceremony orchestration and threshold signing storage
      cleanup. Validation passed: `pnpm --dir packages/sdk-server-ts type-check`,
      `pnpm --dir tests exec playwright test -c playwright.relayer.config.ts
      ./relayer/cloudflare-router.test.ts --grep "recover-email"
      --reporter=line`, `pnpm --dir tests exec playwright test -c
      playwright.relayer.config.ts ./relayer/express-router.test.ts --grep
      "recover-email" --reporter=line`, `pnpm --dir tests exec playwright test
      -c playwright.relayer.config.ts ./relayer/email-recovery.prepare.test.ts
      --reporter=line`, `pnpm --dir tests exec playwright test -c
      playwright.unit.config.ts
      unit/router.relayRouteSurface.unit.test.ts
      unit/refactor82CloudflareD1Runtime.guard.unit.test.ts --reporter=line`,
      `pnpm --dir tests exec playwright test -c playwright.unit.config.ts
      unit/cloudflareD1RouterApiAuthService.unit.test.ts --grep
      "registration|add-auth|revoke|auth method|WebAuthn|Email OTP|signer
      metadata|add signer" --reporter=line`,
      `pnpm --dir packages/sdk-server-ts build`, and `git diff --check`.
      D1 wallet-registration orchestration moved to
      `packages/sdk-server-ts/src/router/cloudflare/d1WalletRegistrationService.ts`,
      and D1 add-signer orchestration moved to
      `packages/sdk-server-ts/src/router/cloudflare/d1WalletAddSignerService.ts`.
      The router-api keeps the public `CloudflareRouterApiAuthService` methods and
      delegates those method families to the focused services. The same pass deleted the
      copied ceremony method bodies, stale ECDSA helper imports, local ECDSA helper
      imports, and the registration signing-session-use constant from
      `d1RouterApiAuthService.ts`. ECDSA ceremony split line count:
      `d1RouterApiAuthService.ts` dropped from 2,725 to 2,025 lines while the new
      ECDSA ceremony module is 831 lines, a +131-line split from the former local
      monolith shape and a 700-line router-api deletion in this pass. Remaining split
      target: threshold signing storage cleanup. Validation passed: `pnpm --dir
      packages/sdk-server-ts type-check`, `pnpm --dir tests exec playwright test
      -c playwright.unit.config.ts unit/cloudflareD1RouterApiAuthService.unit.test.ts
      --grep "ECDSA wallet registration|wallet registration ceremonies|add-signer
      ceremonies|finalizes ECDSA|responds to ECDSA|starts ECDSA|add signer"
      --reporter=line`, `pnpm --dir packages/sdk-server-ts build`, `pnpm --dir
      tests exec playwright test -c playwright.unit.config.ts
      unit/refactor82CloudflareD1Runtime.guard.unit.test.ts --reporter=line`, and
      `git diff --check`.
      Threshold signing facade cleanup moved D1 relayer metadata, D1 empty ECDSA
      key-inventory responses, HSS bootstrap forwarding, client-root-proof
      forwarding, and export-share forwarding into
      `packages/sdk-server-ts/src/router/cloudflare/d1ThresholdSigningRuntime.ts`.
      The router-api keeps the public `CloudflareRouterApiAuthService` methods and delegates
      the threshold-facing methods to the runtime. The same pass deleted the local
      relayer default constants, empty-inventory helpers, and direct threshold
      service forwarding bodies from `d1RouterApiAuthService.ts`. Threshold facade
      cleanup line count: `d1RouterApiAuthService.ts` dropped from 2,025 to 1,959 lines
      while `d1ThresholdSigningRuntime.ts` is now 208 lines after taking ownership
      of the runtime facade. Remaining split target: review whether any thin public
      router-api delegations should stay in the route-facing auth port or move behind a
      narrower threshold route service during Phase 7. Validation passed:
      `pnpm --dir packages/sdk-server-ts type-check`, `pnpm --dir tests exec
      playwright test -c playwright.unit.config.ts
      unit/cloudflareD1RouterApiAuthService.unit.test.ts --grep
      "threshold|key facts|relayer|signer metadata" --reporter=line`, `pnpm --dir
      packages/sdk-server-ts build`, `pnpm --dir tests exec playwright test -c
      playwright.unit.config.ts unit/refactor82CloudflareD1Runtime.guard.unit.test.ts
      --reporter=line`, and `git diff --check`.
      Registration-intent allocation moved to
      `packages/sdk-server-ts/src/router/cloudflare/d1RegistrationIntentService.ts`.
      The focused service now owns wallet ID allocation, server-allocated-wallet
      collision checks, registration/add-signer/add-auth-method intent building,
      grant issuance, digest computation, and Durable Object intent persistence.
      The router-api keeps the public `CloudflareRouterApiAuthService` methods and delegates
      intent creation to the focused service. The deletion pass removed the stale
      router-api-local wallet allocation helpers, old registration-intent imports, and
      duplicate allocation type aliases. Registration-intent split line count:
      `d1RouterApiAuthService.ts` dropped from 1,959 to 1,693 lines while the new
      registration-intent module is 324 lines, a +58-line split from the former
      local monolith shape and a 266-line router-api deletion across the combined
      extraction. Remaining split target: review any thin public router-api delegations
      during Phase 7. Validation passed: `pnpm --dir packages/sdk-server-ts
      type-check`, `pnpm --dir tests exec playwright test -c
      playwright.unit.config.ts unit/cloudflareD1RouterApiAuthService.unit.test.ts
      unit/registrationIntentAllocation.unit.test.ts --grep "stores wallet
      registration intents|registration intent|add-signer intent|add-auth-method
      intent|server-allocated wallet" --reporter=line`, `pnpm --dir packages/sdk-server-ts
      build`, `pnpm --dir tests exec playwright test -c playwright.unit.config.ts
      unit/refactor82CloudflareD1Runtime.guard.unit.test.ts --reporter=line`, and
      `git diff --check`.
      Add-auth-method ceremony start/finalize moved into
      `packages/sdk-server-ts/src/router/cloudflare/d1WalletAuthMethodService.ts`.
      The wallet-auth service now owns add-auth-method grant consumption, digest
      verification, existing-auth resolution, authority verification, ceremony DO
      persistence, duplicate-authority checks, and final auth-method persistence.
      The router-api keeps only the public `CloudflareRouterApiAuthService` methods and
      delegates add-auth-method start/finalize to the focused service. The deletion
      pass removed the router-api-local add-auth ceremony bodies and their stale intent
      imports. Add-auth-method ceremony split line count: `d1RouterApiAuthService.ts`
      dropped from 1,693 to 1,561 lines while `d1WalletAuthMethodService.ts`
      grew from 763 to 921 lines, a +26-line split from the former local monolith
      shape and a 132-line router-api deletion in this pass. Remaining split target:
      review thin public router-api delegations and small Email OTP response-shaping
      bodies during Phase 7. Validation passed: `pnpm --dir packages/sdk-server-ts
      type-check`, `pnpm --dir tests exec playwright test -c
      playwright.unit.config.ts unit/cloudflareD1RouterApiAuthService.unit.test.ts
      unit/registrationIntentAllocation.unit.test.ts --grep "add-auth-method|adds
      Email OTP wallet auth methods|wallet auth methods" --reporter=line`,
      `pnpm --dir packages/sdk-server-ts build`, `pnpm --dir tests exec
      playwright test -c playwright.unit.config.ts
      unit/refactor82CloudflareD1Runtime.guard.unit.test.ts --reporter=line`, and
      `git diff --check`.
      Email OTP challenge-facing orchestration moved to
      `packages/sdk-server-ts/src/router/cloudflare/d1EmailOtpChallengeService.ts`.
      The focused service now owns login, registration-enrollment, and
      device-recovery challenge creation; enrollment and login challenge
      verification; registration finalization through the Email OTP finalizer; and
      development outbox reads. The router-api keeps the public
      `CloudflareRouterApiAuthService` methods and delegates those six methods to the
      focused service. The same pass deleted the corresponding method bodies,
      stale challenge imports, local email masking, and grant-record helpers from
      `d1RouterApiAuthService.ts`. Email OTP challenge-service split line count:
      `d1RouterApiAuthService.ts` dropped from 1,478 to 1,196 lines while the new
      challenge service added 429 lines, a +147-line split from the former local
      monolith shape and a 282-line router-api deletion in this pass. Remaining split
      target: review thin public router-api delegations during Phase 7. Validation
      passed: `pnpm --dir packages/sdk-server-ts build`, `pnpm --dir tests exec
      playwright test -c playwright.unit.config.ts
      unit/cloudflareD1RouterApiAuthService.unit.test.ts
      unit/registrationIntentAllocation.unit.test.ts --grep "Near account
      ownership|existing-account Ed25519|Email OTP challenge|Email OTP
      enrollment|Google Email OTP|WebAuthn login" --reporter=line`, `pnpm --dir
      tests exec playwright test -c playwright.unit.config.ts
      unit/refactor82CloudflareD1Runtime.guard.unit.test.ts --reporter=line`, and
      `git diff --check`.
      Relay facade type-alias scaffolding was collapsed into generic
      `RelayInput` and `RelayResult` helpers. The cleanup deleted the one-off
      per-method input/result alias block without changing the route-facing
      `CloudflareRouterApiAuthService` contract. Facade cleanup line count:
      `d1RouterApiAuthService.ts` dropped from 1,196 to 932 lines, a net-negative
      264-line cleanup. Validation passed: `pnpm --dir packages/sdk-server-ts
      type-check`.
      Email OTP enrollment reads and strong-auth state moved from the router-api facade
      into `packages/sdk-server-ts/src/router/cloudflare/d1EmailOtpRecoveryService.ts`,
      which already owns the D1 enrollment/auth-state stores and recovery flows.
      The same cleanup removed the recovery service's callback into the router-api and
      collapsed duplicated local D1 wallet parsers into
      `packages/sdk-server-ts/src/router/cloudflare/d1RouterApiAuthBoundary.ts`.
      The D1 boundary parser rejects missing, whitespace-bearing, and control-byte
      wallet IDs without treating wallet IDs as NEAR account IDs. Facade cleanup
      line count: `d1RouterApiAuthService.ts` dropped from 932 to 868 lines, a tracked
      64-line router-api deletion and a 64-line non-doc tracked diff reduction in this
      pass. Validation passed: `pnpm --dir packages/sdk-server-ts type-check`,
      `pnpm --dir tests exec playwright test -c playwright.unit.config.ts
      unit/cloudflareD1RouterApiAuthService.unit.test.ts --grep "reads signer
      metadata with tenant scope|rotates Email OTP recovery keys|verifies Email
      OTP unlock proofs once" --reporter=line`, `pnpm --dir tests exec
      playwright test -c playwright.relayer.config.ts
      relayer/email-otp.authservice.test.ts --grep "Email OTP enrollment reads
      require tenant scope|Email OTP strong-auth gate flips" --reporter=line`,
      `pnpm --dir tests exec playwright test -c playwright.unit.config.ts
      unit/refactor82CloudflareD1Runtime.guard.unit.test.ts --reporter=line`, and
      `git diff --check`.
      Deleted the stale `CloudflareD1RouterApiAuthService.getThresholdRelayerAccount`
      facade method. The threshold runtime still keeps its internal helper, but
      no route or test caller uses the router-api facade method. Facade cleanup line
      count: `d1RouterApiAuthService.ts` dropped from 868 to 861 lines, a 7-line
      router-api deletion. Validation passed: `rg -n "getThresholdRelayerAccount"
      packages/sdk-server-ts/src tests apps`, `pnpm --dir packages/sdk-server-ts
      type-check`, and `git diff --check`.
      Email OTP server-seal apply/remove operations moved from the router-api facade
      into `packages/sdk-server-ts/src/router/cloudflare/d1EmailOtpServerSealRuntime.ts`.
      The router-api now delegates both public methods to the focused runtime, and the
      runtime's cipher creation is a private implementation detail. Facade cleanup
      line count: `d1RouterApiAuthService.ts` dropped from 861 to 801 lines, a 60-line
      router-api deletion. Validation passed: `pnpm --dir packages/sdk-server-ts
      type-check`, `pnpm --dir tests exec playwright test -c
      playwright.unit.config.ts unit/cloudflareD1RouterApiAuthService.unit.test.ts
      --grep "server seal" --reporter=line`, and `git diff --check`.
      Google Email OTP registration-attempt rate-limit parsing moved from the
      router-api facade into
      `packages/sdk-server-ts/src/router/cloudflare/d1GoogleEmailOtpSessionResolver.ts`,
      which already owns Google Email OTP session identity parsing and
      registration-attempt lifecycle decisions. Facade cleanup line count:
      `d1RouterApiAuthService.ts` dropped from 801 to 751 lines, a 50-line router-api
      deletion. Validation passed: `pnpm --dir packages/sdk-server-ts
      type-check`, `pnpm --dir tests exec playwright test -c
      playwright.unit.config.ts unit/cloudflareD1RouterApiAuthService.unit.test.ts
      --grep "rate-limits Google Email OTP registration attempts|Google Email OTP
      registration attempts" --reporter=line`, and `git diff --check`.
      NEAR public-key route response shaping moved from the router-api facade into
      `packages/sdk-server-ts/src/router/cloudflare/d1NearPublicKeyStore.ts`, while
      the Cloudflare runtime continues to avoid the mixed core NEAR key store that
      also imports Postgres fallback code. Facade cleanup line count:
      `d1RouterApiAuthService.ts` dropped from 751 to 723 lines, a 28-line router-api
      deletion. Validation passed: `pnpm --dir packages/sdk-server-ts type-check`,
      `pnpm --dir tests exec playwright test -c playwright.unit.config.ts
      unit/cloudflareD1RouterApiAuthService.unit.test.ts --grep "reads signer metadata
      with tenant scope" --reporter=line`, and `git diff --check`.
      Portable SHA-256 runtime plumbing moved from the router-api facade into
      `packages/sdk-server-ts/src/router/cloudflare/d1RouterApiAuthBoundary.ts`, next to
      the `toArrayBufferCopy` utility it depends on. Facade cleanup line count:
      `d1RouterApiAuthService.ts` dropped from 723 to 711 lines, a 12-line router-api
      deletion. Validation passed: `pnpm --dir packages/sdk-server-ts type-check`,
      `pnpm --dir tests exec playwright test -c playwright.unit.config.ts
      unit/cloudflareD1RouterApiAuthService.unit.test.ts --grep "reads signer metadata
      with tenant scope|add-auth-method|Email OTP recovery keys|unlock proofs"
      --reporter=line`, and `git diff --check`.
      Facade return-type cleanup removed stale concrete response and threshold
      type imports from `d1RouterApiAuthService.ts`, using the existing `RelayResult`
      helper for all route-facing method annotations instead. Facade cleanup line
      count: `d1RouterApiAuthService.ts` dropped from 706 to 689 lines, a 17-line
      router-api deletion. Validation passed: `pnpm --dir packages/sdk-server-ts
      type-check` and `git diff --check`.
      Final facade cleanup removed the old `emailRecovery = null` property from
      `d1RouterApiAuthService.ts` and removed `emailRecovery` from the
      `CloudflareRouterApiAuthService` port. Cloudflare email ingress now owns a
      narrow `CloudflareEmailRecoveryService` shape, while router-api fetch routing uses
      structural `opts.emailRecovery` branches. Current `d1RouterApiAuthService.ts`
      is 688 lines and contains only constructor composition, thin public
      delegations, lazy D1 store construction, and tenant-scoped D1 statement
      binding. Validation passed: `pnpm --dir packages/sdk-server-ts type-check`,
      `pnpm --dir tests exec playwright test -c playwright.unit.config.ts
      unit/cloudflareD1RouterApiAuthService.unit.test.ts
      unit/refactor82CloudflareD1Runtime.guard.unit.test.ts --reporter=line`, and
      `git diff --check`.
      Recovery ingress cleanup centralized the duplicated `/recover-email`
      execution tracking flow in `recoveryExecutionTracking.ts` and removed the
      Cloudflare/Express route-local pending/submitted/failed mutation helpers.
      The transport route files now own route parsing, async transport scheduling,
      and response shape; session verification, execution records, and
      success/failure session transitions live at the shared recovery tracking
      boundary. Slice diff for the three touched files: 411 additions and 323
      deletions, with `recoverEmail.ts` route files reduced to 87 Cloudflare lines
      and 93 Express lines. Validation passed: `pnpm --dir
      packages/sdk-server-ts type-check`, `pnpm --dir tests exec tsc -p
      tsconfig.playwright.json --noEmit`, `pnpm --dir tests exec playwright test
      -c playwright.relayer.config.ts relayer/cloudflare-router.test.ts
      relayer/express-router.test.ts --grep "recover-email" --reporter=line`,
      route inline-callback scan, and `git diff --check`.
      Follow-up public-surface cleanup removed the recovery tracking re-export
      block from `packages/sdk-server-ts/src/index.ts` and made low-level recovery
      mutation helpers module-private. `resolveTrackedNearRecoveryExecution`
      remains exported only from its implementation file for the focused unit
      test. Validation passed: `pnpm --dir packages/sdk-server-ts type-check`,
      `pnpm --dir tests exec tsc -p tsconfig.playwright.json --noEmit`,
      `pnpm --dir tests exec playwright test -c playwright.unit.config.ts
      unit/recoveryExecutionTracking.unit.test.ts
      unit/refactor51bPackageExports.unit.test.ts --reporter=line`, the focused
      `/recover-email` relayer tests, the recovery tracking export scan, and
      `git diff --check`.
- [x] P2: Net production code growth is still too high for the migration.
      Fix: Phase 7 must record before/after line counts and perform a deletion pass
      against temporary D1 scaffolding, duplicate adapters, obsolete Postgres paths,
      compatibility tests, source guards, and route shims. The cleanup pass should
      materially reduce the positive delta before the refactor is complete.
      Earlier count snapshot including untracked files at this cleanup checkpoint:
      tracked diff was 328 files, 9,898 additions, and 65,387 deletions; untracked
      files added 24,754 lines. Combined all files were 34,652 additions and
      65,387 deletions, net -30,735. Combined non-doc files were 27,158 additions
      and 59,897 deletions, net -32,739.
      The immediate code-growth warning is resolved; Phase 7 cleanup/count closure
      is now recorded, and Phase 6 owns remaining staging validation.
      Latest evidence: the Email OTP partial Postgres store implementation was
      deleted from `packages/sdk-server-ts/src/core/EmailOtpStores.ts`; store
      factories now reject partial Postgres selection and require the future
      full-family Postgres backend instead. The same pass deleted the skipped
      Email OTP Postgres durable-store test block and added focused coverage for
      the explicit rejection. Slice diff: 30 additions and 1,248 deletions across
      `EmailOtpStores.ts`, `tests/relayer/email-otp.authservice.test.ts`, and
      `tests/unit/emailOtpRecoveryWrappedEnrollmentEscrowStore.unit.test.ts`.
      Follow-up cleanup renamed the still-current row parser/test from
      `EmailOtpPostgresRecords` and `emailOtp.postgresRecords.unit.test.ts` to
      backend-neutral `EmailOtpRecords` and `emailOtp.records.unit.test.ts`.
      Because the worktree is unstaged, Git currently reports that rename as
      tracked deletions plus untracked backend-neutral replacements.
      Phase 7 cleanup then deleted optional live-Postgres console-router suites
      from `tests/relayer/console-router.test.ts`, while keeping the Cloudflare
      runtime test that rejects Postgres tenant routes at the request boundary.
      That slice removed 2,668 lines and added 59 lines in the router test file.
      The next cleanup deleted optional live-Postgres sponsored-call history and
      prepaid reservation suites, removing another 292 lines while keeping current
      in-memory router and D1 adapter coverage. The next cleanup deleted optional
      live-Postgres threshold durable-store branches from
      `tests/relayer/threshold-ecdsa.durable-stores.test.ts`, removing 223 lines
      and adding 32 lines while keeping in-memory and Cloudflare Durable Object
      coverage in that mixed suite. The next cleanup deleted the optional
      live-Postgres wallet-session budget reservation unit contract, removing 20
      lines while keeping in-memory and Cloudflare Durable Object reservation
      coverage. The next cleanup deleted the optional live-Postgres sponsorship
      spend-cap branch, removing 131 lines and adding 1 line while D1 spend-cap
      behavior remains covered in the D1 adapter suite. The next cleanup converted
      the sponsored EVM route suite to local SQLite-backed D1 billing,
      prepaid-reservation, and sponsored-call services, extracted the shared
      SQLite-D1 test harness, and fixed shared prepaid settlement quoting so
      no-broadcast sponsored attempts release reservations without billing debits.
      That tracked slice added 405 lines and deleted 365 lines across the shared
      settlement helper and relayer suites; the new shared D1 helper is 320 lines.
      The next cleanup deleted the optional live-Postgres console tenant-isolation
      relayer suite, reduced the observability ingestion relayer suite to
      backend-neutral builder/redaction coverage, and removed the deleted suite
      from the Postgres runner. That slice added 1 line and deleted 2,481 lines
      across the three test/runner files. The next cleanup deleted optional
      live-Postgres bootstrap-token, legacy policy-id migration, and webhook
      relayer suites, removing another 1,118 lines while retaining current D1
      adapter and Cloudflare route coverage for those domains. The next cleanup
      deleted the remaining live-Postgres console billing/config relayer suites,
      deleted their now-dead runner, and removed the package/CI wiring for that
      runner. That slice added 11 lines and deleted 2,182 lines while retaining
      current D1 adapter and Cloudflare route coverage for billing, key export,
      policy, runtime snapshot, and related config domains.
      The next cleanup deleted the partial Postgres signing-session seal
      idempotency backend and renamed the shared session-seal idempotency parser
      away from `postgresRecords`, removing another 408 lines and adding 71 lines
      across production code, tests, and guards. Session-seal idempotency now uses
      in-memory, Upstash Redis REST, or Redis TCP; Postgres remains only a
      full-family future backend concern.
      The next cleanup deleted the partial Postgres registration-finalization
      transaction branch embedded in `AuthService`, so wallet registration,
      add-signer, and add-auth-method finalization all use the domain-store path
      while Postgres remains a future full-family adapter concern. The same pass
      deleted the unused Google Email OTP registration-attempt executor helper
      from `EmailOtpStores` and updated the registration ordering guard. Slice
      diff before this doc update: 36 insertions and 458 deletions across core
      service/store code and the guard.
      The next cleanup deleted disabled server-side link-device scaffolding:
      Cloudflare and Express route modules, Router API route-table entries, router
      registrations, unsupported `AuthService` methods, the relayer route-stub
      test, and the guard that required the old `410` behavior. The SDK browser
      link-device stub remains separate from the server route surface until
      refactor 84 implements the feature.
      The next cleanup renamed the shared threshold parser/test family from
      `ThresholdService/postgresRecords.ts` and `*.postgresRecords.unit.test.ts`
      to backend-neutral `ThresholdService/persistedRecords.ts` and
      `*.persistedRecords.unit.test.ts`. Current D1 signing-root stores and shared
      threshold stores no longer import a Postgres-branded parser module, and the
      Ed25519 parser fixtures now prove split wallet/hosted-NEAR identity fields
      are required. Validation passed: `pnpm --dir packages/sdk-server-ts
type-check` and `pnpm --dir tests exec playwright test -c
playwright.unit.config.ts unit/thresholdEd25519.persistedRecords.unit.test.ts
unit/thresholdEcdsa.persistedRecords.unit.test.ts
unit/signingRootSecretShare.persistedRecords.unit.test.ts --reporter=line`.
      The next cleanup deleted the partial Postgres NEAR public-key metadata
      backend and the unused `near_public_keys` Postgres schema bootstrap block.
      `createNearPublicKeyStore` now rejects Postgres selection until a full-family
      backend exists, while D1 `signer_near_public_keys` behavior remains covered.
      Validation passed: `pnpm --dir packages/sdk-server-ts type-check`, `pnpm
--dir tests exec playwright test -c playwright.unit.config.ts
unit/nearPublicKeyStore.unit.test.ts
unit/refactor82CloudflareD1Runtime.guard.unit.test.ts --reporter=line`, and
      `pnpm --dir tests exec playwright test -c playwright.relayer.config.ts
relayer/console-d1-adapters.test.ts --grep "signer NEAR public key metadata
is scoped in D1" --reporter=line`.
      The next cleanup deleted the partial Postgres wallet identity and wallet
      auth-method stores and removed the old wallet Postgres schema bootstrap
      blocks. Wallet store factories now reject `kind: "postgres"` and
      env-shaped `POSTGRES_URL` until a full-family backend exists, while D1/DO
      remain the staging persistent paths. Validation passed: `pnpm --dir
packages/sdk-server-ts type-check`, the focused wallet store unit tests, the
      D1 wallet metadata/auth-method tenant-scoping relayer test, and stale symbol
      inventories.
      The next cleanup deleted the partial Postgres WebAuthn store family:
      authenticator, credential binding, login challenge, and sync challenge
      stores. The factories now reject partial Postgres selection, the old
      WebAuthn executor exports are gone, and the unprefixed WebAuthn Postgres
      bootstrap blocks were removed from the shared schema. Store/index diff:
      24 insertions and 472 deletions, with a 109-line rejection fixture.
      Validation passed: `pnpm --dir packages/sdk-server-ts type-check`, the
      focused WebAuthn factory rejection test, the D1 runtime guard, and the D1
      router-api auth signer metadata tenant-scope test that exercises WebAuthn login
      and sync storage.
      The next cleanup deleted the partial Postgres recovery store family:
      recovery sessions, recovery executions, and Email Recovery preparations. The
      factories now reject partial Postgres selection, and the old
      `email_recovery_preparations`, `recovery_sessions`, and `recovery_executions`
      bootstrap blocks are gone from the shared Postgres schema. Store/schema
      tracked diff: 18 insertions and 707 deletions across production files, plus
      an 83-line focused factory rejection fixture. Validation passed: `pnpm --dir
packages/sdk-server-ts type-check`, the focused recovery factory/session/
      execution tests, the D1 runtime guard, the D1 Router API auth recovery smoke, and
      stale recovery Postgres symbol/schema inventories.
      The next cleanup deleted the partial Postgres identity store and its exported
      executor helper. `createIdentityStore` now rejects partial Postgres selection,
      and the old `identity_links` plus `app_session_versions` bootstrap blocks are
      gone from the shared Postgres schema. Selected production tracked diff from
      the Refactor 82 baseline is 21 insertions and 1,414 deletions across the
      modified identity/index/schema files, plus a 31-line focused factory
      rejection fixture. Validation passed: `pnpm --dir packages/sdk-server-ts
type-check`, the focused identity factory test, `git diff --check`, and stale
      identity Postgres helper/table inventories.
      The next cleanup deleted the partial Postgres registration ceremony store.
      `createRegistrationCeremonyStore` now rejects partial Postgres selection, and
      the old `wallet_registration_intents` plus `wallet_registration_ceremonies`
      bootstrap blocks are gone from the shared Postgres schema. Selected tracked
      diff from the Refactor 82 baseline is 167 insertions and 1,172 deletions
      across the ceremony store, schema, and test files. Validation passed: `pnpm
--dir packages/sdk-server-ts type-check`, the focused registration ceremony
      suite, the D1 runtime guard, `git diff --check`, and stale ceremony Postgres
      helper/table inventories.
      The next cleanup deleted the partial Postgres signing-root secret store and
      removed the old unprefixed `signing_root_secret_shares` bootstrap/reset
      references. The D1 signer table `signer_signing_root_secret_shares` remains the
      sealed-share staging owner. Validation passed: `pnpm --dir packages/sdk-server-ts
type-check`, the focused wallet-scope/registration-intent/signing-root/refactor82
      guard tests, `git diff --check`, and an exact stale-symbol inventory for
      `PostgresSigningRootSecretStore` plus the old unprefixed table name.
      The next cleanup deleted the partial Postgres threshold key-store backend:
      the Ed25519 and ECDSA key-store factories now reject partial Postgres
      selection, the old `threshold_ed25519_keys` and `threshold_ecdsa_keys`
      bootstrap/reset references are gone from the active schema/runbook, and the
      Postgres key-store backfill test was deleted. Validation passed: `pnpm --dir
  packages/sdk-server-ts type-check`, the focused threshold persisted-record/D1
      runtime guard tests, `git diff --check`, and stale key-store symbol/table
      inventories.
      The next cleanup deleted the partial Postgres threshold session-store
      backend. The Ed25519 and ECDSA session-store factories now reject explicit
      `kind: "postgres"` and env-shaped `POSTGRES_URL` selection until the
      full-family Postgres backend exists, while Durable Object/Redis/in-memory
      paths remain the only active selections. Focused validation passed:
      `pnpm --dir packages/sdk-server-ts type-check`, `pnpm --dir tests exec
  playwright test -c playwright.unit.config.ts
  unit/thresholdEd25519.presignStore.unit.test.ts
      unit/walletScopedLookups.guard.unit.test.ts
  unit/registrationIntentDigest.unit.test.ts
  unit/refactor82CloudflareD1Runtime.guard.unit.test.ts --reporter=line`,
      and `git diff --check`.
      The next cleanup deleted the partial Postgres wallet-session backend and
      its table bootstrap/reset references. The Ed25519 wallet-session, ECDSA
      wallet-session, and wallet signing-budget factories now reject partial
      Postgres selection until the full-family backend exists. Focused validation
      passed: `pnpm --dir packages/sdk-server-ts type-check`, `pnpm --dir tests
    exec playwright test -c playwright.unit.config.ts
    unit/walletSessionBudgetReservation.store.unit.test.ts
    unit/thresholdEcdsa.persistedRecords.unit.test.ts
    unit/refactor82CloudflareD1Runtime.guard.unit.test.ts --reporter=line`,
      and `git diff --check`.
      The next cleanup deleted the partial Postgres ECDSA presign backend,
      its active Postgres schema bootstrap, its local reset references, and the
      obsolete malformed-cleanup test suite. `createThresholdEcdsaSigningStores`
      now rejects explicit and env-shaped Postgres selection until a
      full-family backend exists. Focused validation passed:
      `pnpm --dir packages/sdk-server-ts type-check`, `pnpm --dir tests exec
    playwright test -c playwright.unit.config.ts
    unit/thresholdEcdsa.persistedRecords.unit.test.ts
    unit/refactor82CloudflareD1Runtime.guard.unit.test.ts
        unit/walletScopedLookups.guard.unit.test.ts
    unit/walletSessionBudgetReservation.store.unit.test.ts --reporter=line`,
      `pnpm --dir tests exec playwright test -c playwright.relayer.config.ts
      relayer/threshold-ecdsa.durable-stores.test.ts --reporter=line`, and
      `git diff --check`.
      The next cleanup deleted the partial Postgres normal-signing admission
      backend and removed its SDK/Express exports. The facade now exposes
      Durable Object and in-memory admission stores only, with a type fixture
      rejecting the old Postgres options export. Focused validation passed:
      `pnpm --dir packages/sdk-server-ts type-check`, `pnpm --dir tests exec
      playwright test -c playwright.unit.config.ts
      unit/routerAbNormalSigningAdmissionStore.unit.test.ts
      unit/refactor82CloudflareD1Runtime.guard.unit.test.ts --reporter=line`,
      and `git diff --check`.
      The next cleanup deleted the unused shared Postgres schema initializer,
      the stale `AuthService` startup schema warmup, and the obsolete local
      Postgres reset runbook. Deployment docs describe D1/DO/R2 as the
      staging data plane. Focused
      validation passed: `pnpm --dir packages/sdk-server-ts type-check`,
      `pnpm --dir packages/shared-ts type-check`, `pnpm --dir tests exec
      playwright test -c playwright.unit.config.ts
          unit/walletScopedLookups.guard.unit.test.ts
      unit/registrationIntentDigest.unit.test.ts
      unit/refactor82CloudflareD1Runtime.guard.unit.test.ts
      unit/routerAbNormalSigningAdmissionStore.unit.test.ts
      unit/thresholdEcdsa.persistedRecords.unit.test.ts
      unit/walletSessionBudgetReservation.store.unit.test.ts --reporter=line`,
      `git diff --check`, and stale-symbol scans for
      `ensurePostgresSchema`, `getPostgresUrlFromConfig`,
      `storageInitPromise`, `initStorage(`, `threshold-postgres-reset`, and
      direct D1 `isValidAccountId` usage outside `hostedAccountIds.ts`.
      The next cleanup deleted the generic `storage/postgres.ts` helper,
      removed the public `@seams/sdk-server/storage/postgres` package
      subpath, removed the Rolldown entry and TypeScript aliases, dropped
      direct `pg` and `@types/pg` workspace dependencies, and deleted the
      orphaned `postgresReadHelpers` unit test. Postgres now remains only
      in `TenantStorageRoute` as the future full-family backend contract
      and in negative package-export tests. Focused validation passed:
      `pnpm install --lockfile-only --ignore-scripts`, package manifest
      JSON parsing, stale scans for `@seams/sdk-server/storage/postgres`,
      `parsePostgresRow`, and `getPostgresPool`, plus `git diff --check`.
      A follow-up guard cleanup also renamed the core login unlock request
      type away from iframe-specific vocabulary and branded the tenant
      storage resolver `orgId` boundary with `parseOrgId`, keeping raw
      console auth claims outside the route contract.
      The next cleanup deleted stale router-api-server signer/split Postgres
      scaffolding: root `router:server` now runs local D1/DO through
      Wrangler/Miniflare by default, the Express example no longer wires
      signer/threshold Postgres, normal-signing admission Postgres, or
      session-seal Postgres idempotency, and the removed signer/split
      migration scripts plus their unit/script helpers are gone. Console
      Postgres remains an explicit console-only boundary. Selected slice
      diff: 44 insertions and 1,578 deletions across app scripts, docs,
      package scripts, and focused tests. Focused validation passed:
      `pnpm -s type-check:router-server`, `pnpm --dir packages/sdk-server-ts
          type-check`, `pnpm --dir tests exec playwright test -c
      playwright.unit.config.ts unit/webServer.consoleConfig.unit.test.ts
      unit/refactor82CloudflareD1Runtime.guard.unit.test.ts
      unit/routerAbNormalSigningAdmissionStore.unit.test.ts --reporter=line`,
      stale-symbol scans for removed signer/split Postgres commands and
      env knobs, and `git diff --check`.
      The next cleanup deleted the app-server raw Postgres demo wallet seed
      path. Demo console wallet seeding now writes through the existing
      `ConsoleWalletService.upsertWallet` port for every app-server
      backend and skips existing rows at that boundary. `apps/web-server/src/index.ts`
      no longer imports `pg` or opens a raw `Pool`; the current tracked
      app-server diff is 50 insertions and 103 deletions. Focused
      validation passed: `pnpm -s type-check:router-server`, stale scans
      for `seedDemoConsoleWalletsInPostgres`, `new Pool`, and
      `from 'pg'` in `apps/web-server/src/index.ts`, focused
      wallet-scope/registration-intent guard tests, and `git diff --check`.
      The next cleanup deleted the active `apps/web-server` console Postgres
      runtime path. The Node runner now wires console state through in-memory
      services only, rejects configured Node sponsored-EVM execution with a
      Cloudflare D1/DO handoff error, and no longer exposes
      `CONSOLE_POSTGRES_URL` backend selection. Removed the web-server Postgres
      Docker compose file, Postgres up/down/migrate scripts, package scripts,
      config fields, and README/env-example instructions. Selected slice diff
      from `HEAD`: 139 insertions and 1,064 deletions. Focused validation passed:
      `pnpm -s type-check:router-server`,
      `unit/webServer.consoleConfig.unit.test.ts`, and stale scans for the
      deleted web-server Postgres commands/runtime symbols. The only
      `CONSOLE_POSTGRES_*` web-server hit is the focused unit test proving those
      legacy env keys are ignored by the memory-only runner. Follow-up Phase 7
      guard hardening now checks the exact deleted `apps/web-server`
      `docker-compose.postgres.yml` and `scripts/postgres-*.mjs` paths, plus
      `apps/web-server/package.json` scripts, so the removed local Postgres
      helper tooling cannot be reintroduced without failing the Refactor 82
      runtime guard. Validation passed: `pnpm --dir tests exec playwright test -c
      playwright.unit.config.ts unit/refactor82CloudflareD1Runtime.guard.unit.test.ts
      --reporter=line` with 43 tests, `pnpm --dir tests exec tsc -p
      tsconfig.playwright.json --noEmit`, and `git diff --check`.
      The next cleanup renamed the Playwright Router API test-server harness away
      from stale router-api-server terminology and moved the default provision cache
      off the deleted `examples/router-api-server` path into
      `tests/playwright-report/router-api-provision-cache.json`. The Refactor 82
      guard now rejects the old harness script filenames, package-script name,
      removed examples path, and stale harness log labels so the E2E bootstrap
      path cannot silently drift back to the old server naming or filesystem
      layout. Validation passed: `node --check` for the three test-server harness
      scripts, `pnpm --dir tests exec playwright test -c
      playwright.unit.config.ts unit/refactor82CloudflareD1Runtime.guard.unit.test.ts
      --reporter=line` with 43 tests, `pnpm --dir tests exec tsc -p
      tsconfig.playwright.json --noEmit`, stale harness-name scans, and
      `git diff --check`.
      The next cleanup removed the remaining active Node web-server
      `router-api-server` labels from the app package name, console config helper,
      startup logs, Bun helper, and focused console-config unit test filename.
      `apps/web-server/package.json` is now the private `web-server` app package,
      `resolveWebServerConsoleConfig` is the current config boundary, and the
      Refactor 82 guard rejects the old helper names, package name, log prefix,
      console-config test filename, Stripe billing-provider test filename, and
      stale web-server test labels. A follow-up removed the last active
      sdk-server core `router-api-server types` comment and guards that exact phrase.
      A later test-harness cleanup renamed the internal Router API proxy helper
      to `installRouterApiProxyShim`, moved its option names to
      `routerApiOrigin`/`routerApiUpstream`, and changed its log scope to
      `router-api-proxy` while preserving the existing test hostname and
      `RELAY_PORT` env knob. Proxy-shim validation passed: focused Refactor 82
      guard with 43 tests, `pnpm --dir tests exec tsc -p
      tsconfig.playwright.json --noEmit`, stale proxy-name scans, and
      `git diff --check`. The registration-flow benchmark Playwright config
      `--list` check could not run because `@playwright/test` is not resolvable
      from the non-package benchmark config directory. Follow-up test-utility
      cleanup aligned the browser-context Router API setup preset, failure mock,
      registration mock, setup intercept message, and setup README with the
      current Router API naming. The Refactor 82 guard now rejects those old
      test utility names and labels while continuing to allow the existing
      `relayServerUrl`, `RELAY_PORT`, and test hostname compatibility knobs.
      Validation passed: `pnpm -s
      type-check:router-server`, `pnpm --dir tests exec playwright test -c
      playwright.unit.config.ts unit/webServer.consoleConfig.unit.test.ts
      unit/webServer.stripeBillingProvider.unit.test.ts
      unit/refactor82CloudflareD1Runtime.guard.unit.test.ts --reporter=line`
      with 49 tests, `pnpm --dir tests exec tsc -p tsconfig.playwright.json
      --noEmit`, `pnpm --dir packages/sdk-server-ts type-check`, a focused
      Refactor 82 guard rerun with 43 tests, stale web-server naming scans, and
      `git diff --check`.
      The next cleanup finished the remaining console-router fixture rewrite:
      gas sponsorship request bodies now use the current `evm_call`/
      `allowedCalls`/`spendCap` schema, runtime snapshots assert
      `gasSponsorship.resolvedPolicies`, billing adjustment read-after-write tests
      use the required billing read role, Stripe checkout reconciliation expects
      `billing.balance.recovered`, and the Postgres tenant route fixture uses a
      parsed branded `OrgId`. This deletes stale test behavior instead of
      preserving compatibility with obsolete request and snapshot shapes.
      Validation passed: `pnpm --dir tests exec playwright test -c
playwright.relayer.config.ts relayer/console-router.test.ts
--reporter=line` with 209 tests passing, `pnpm --dir packages/sdk-web
type-check`, and `git diff --check`.
      The next cleanup removed the last route-surface wording that described
      optional routes as enabled/disabled flags and added a runtime source guard
      that rejects the old `enabled: true` capability shapes outside typecheck
      fixtures. Validation passed: `pnpm --dir packages/sdk-server-ts
type-check`, `pnpm --dir tests exec playwright test -c
playwright.unit.config.ts unit/refactor82CloudflareD1Runtime.guard.unit.test.ts
unit/router.relayRouteSurface.unit.test.ts
unit/router.routeDefinitions.unit.test.ts --reporter=line` with 19 tests
      passing, and `git diff --check`.
      The next cleanup deleted the legacy Router A/B
      `email_otp_registration` Ed25519 HSS rejection helper and all three
      Cloudflare/Express route branches that called it. Current HSS request
      shape is now owned by `thresholdEd25519RequestValidation.ts`, and
      `unit/refactor80SwitchCase.guard.unit.test.ts` asserts the helper and
      custom rejection string stay absent. Slice diff:
      16 additions and 90 deletions across the two Ed25519 route handlers and
      the guard test. Validation passed: `pnpm --dir packages/sdk-server-ts
type-check` and `pnpm --dir tests exec playwright test -c
playwright.unit.config.ts unit/refactor80SwitchCase.guard.unit.test.ts
unit/walletScopedLookups.guard.unit.test.ts
unit/registrationIntentDigest.unit.test.ts --reporter=line` with 29 tests
      passing.
      Follow-up test cleanup deleted the stale Express and Cloudflare dispatch
      tests that asserted the removed legacy `email_otp_registration` HSS
      finalize rejection string and `finalizeForRegistration` shim. The remaining
      legacy threshold-session JWT test now sends a current valid HSS prepare body,
      so it still proves the claim-boundary rejection instead of depending on an
      obsolete malformed request. Slice diff:
      8 additions and 85 deletions in
      `tests/relayer/threshold-ed25519.scheme-dispatch.test.ts`. Validation
      passed: `pnpm --dir tests exec playwright test -c
playwright.relayer.config.ts relayer/threshold-ed25519.scheme-dispatch.test.ts
--reporter=line` with 11 tests passing, `pnpm --dir tests exec playwright
test -c playwright.unit.config.ts unit/refactor80SwitchCase.guard.unit.test.ts
--reporter=line` with 16 tests passing, and `git diff --check`.
      A second cleanup in the same dispatch file deleted the duplicated legacy
      threshold-session route assertions and their helper, leaving
      `unit/thresholdSessionClaims.unit.test.ts` and
      `unit/routerAbServerWalletSessionClaimBoundary.guard.unit.test.ts` as the
      authoritative parser/validator/source-guard coverage for old claim kinds.
      Slice diff: 170 deletions in
      `tests/relayer/threshold-ed25519.scheme-dispatch.test.ts`. Validation
      passed: `pnpm --dir tests exec playwright test -c
playwright.relayer.config.ts relayer/threshold-ed25519.scheme-dispatch.test.ts
--reporter=line` with 9 tests passing, `pnpm --dir tests exec playwright
test -c playwright.unit.config.ts unit/thresholdSessionClaims.unit.test.ts
unit/routerAbServerWalletSessionClaimBoundary.guard.unit.test.ts
--reporter=line` with 11 tests passing, and `git diff --check`.
      The next cleanup replaced stale threshold-session JWT fixture strings in
      active E2E and relayer test scaffolding with current Router A/B Wallet
      Session kinds. `tests/e2e/thresholdEd25519.testUtils.ts` now emits
      `router_ab_ed25519_wallet_session_v1` and
      `router_ab_ecdsa_hss_wallet_session_v1` claims, the sealed-refresh harness
      recognizes those current kinds, wallet-budget stale-session tests use
      expired current ECDSA Wallet Session claims, and Email OTP app-session
      route tests reject current wallet-session auth instead of obsolete
      `threshold_ecdsa_session_v1` fixtures. Validation passed:
      `pnpm --dir tests exec playwright test -c playwright.relayer.config.ts
relayer/cloudflare-router.test.ts relayer/express-router.test.ts
relayer/email-otp.bootstrap-integration.test.ts -g
"wallet-budget/status: stale|app-session routes reject wallet-session"
--reporter=line` with 3 tests passing, `pnpm --dir tests exec tsc -p
tsconfig.playwright.json --noEmit`, the focused D1 wallet/ownership guard
      tests, `pnpm --dir packages/sdk-server-ts type-check`,
      `pnpm --dir packages/shared-ts type-check`, and `git diff --check`.
      Final Phase 7 cleanup/count closure on June 30, 2026:
      `git diff --shortstat 20af682856f1417abdab6ec39dc7793176d35bd0 --`
      reports 908 tracked files changed, 118,475 insertions, and 72,918
      deletions, net `+45,557`. The non-doc tracked slice reports 838 files
      changed, 105,979 insertions, and 67,038 deletions, net `+38,941`. The
      `packages/sdk-server-ts/src` tracked slice reports 313 files changed,
      57,970 insertions, and 31,568 deletions, net `+26,402`; excluding
      typecheck fixtures, it reports 296 files changed, 56,428 insertions, and
      31,527 deletions, net `+24,901`.

      Current untracked text adds 6,516 lines across 18 files, including 2,324
      non-doc lines and 1,497 lines under `packages/sdk-server-ts/src`. The
      production-only untracked `packages/sdk-server-ts/src` slice, excluding
      typecheck fixtures, is also 1,497 lines. The final tracked-plus-untracked
      working-tree count is therefore 124,991 additions and 72,918 deletions
      across all text files, net `+52,073`; 108,303 additions and 67,038
      deletions for non-doc text, net `+41,265`; 59,467 additions and 31,568
      deletions for all `packages/sdk-server-ts/src` text, net `+27,899`; and
      57,925 additions and 31,527 deletions for production-only
      `packages/sdk-server-ts/src`, net `+26,398`.

      The remaining positive production blocks have explicit owners:
      D1 console adapters (`console/**/d1.ts`) are required product runtime
      replacements for the deleted Postgres adapters; D1 Router API auth,
      registration, Email OTP, WebAuthn, recovery, wallet, threshold, and
      ceremony modules are the D1/DO signer runtime and replace deleted partial
      Postgres or disabled-service branches; staging scripts and migrations are
      Phase 6 deployment evidence; `sponsorshipPricing/d1.ts` is Phase 10 static
      pricing MVP work; `ecdsaHssPoolFillLiveSession.ts` is Phase 9 Durable
      Object-owned live HSS state; `nearImplicitAccountFunding.ts` and
      `nearSignerWasmRuntime.ts` are post-82 local runtime/signing support; Refactor
      83/84/85 plan/spec docs and Seams v9 image assets are outside Refactor 82
      runtime growth.

      Remaining intentional non-D1 code is restricted to named boundaries:
      `storage/tenantRoute.ts` keeps the future full-family Postgres route
      contract while Cloudflare runtimes reject it, Redis/in-memory threshold
      stores remain for non-Cloudflare and test runtimes, and the
      `InMemoryRouterAbEcdsaHssPoolFillLiveSessionOwner` is now used as
      Durable Object actor memory rather than Router API Worker module state.
      The Cloudflare runtime inventory finds no active Postgres env/runtime
      references except the focused type fixture proving D1 adapters reject
      Postgres routes, and `localRouterApiEcdsaPoolFillLiveSessionsCache`,
      `routerApiStagingEcdsaPoolFillLiveSessionsCache`, and Worker
      `ecdsaPoolFillLiveSessions` factory plumbing are absent from runtime source.

- [x] P3: Tenant storage route resolver semantics need one final consistency
      check against the plan.
      Fix: either return the planned explicit D1/Postgres/in-memory route union at
      the boundary, or simplify the plan and implementation to D1-only staging with
      no hidden fallback route. Keep any non-D1 backend outside Cloudflare runtime
      wiring.
      Evidence: chose the explicit D1/Postgres route union at the generic resolver
      boundary while keeping Cloudflare runtime D1/DO-only. Fixed in
      `packages/sdk-server-ts/src/storage/tenantRoute.ts`,
      `packages/sdk-server-ts/src/router/cloudflare/createCloudflareConsoleRouter.ts`,
      `packages/sdk-server-ts/src/storage/tenantRoute.typecheck.ts`, and
      `tests/relayer/console-router.test.ts`. `TenantStorageRouteResolver` now
      returns `TenantStorageRoute`, route types still reject mixed console/signer
      backends, and the Cloudflare console router rejects Postgres routes with
      `tenant_storage_backend_not_supported_in_cloudflare_runtime`. Validation
      passed: `pnpm --dir packages/sdk-server-ts type-check`,
      `pnpm --dir tests exec playwright test -c playwright.relayer.config.ts
relayer/console-router.test.ts --grep "rejects Postgres tenant routes"
--reporter=line`, and `git diff --check`.
- [x] P3: Cloudflare Worker environment types and docs must remain free of
      stale Postgres cron/runtime fields.
      Fix: run the Phase 7 `POSTGRES|Postgres|postgres|legacy|compat|temporary`
      inventory and delete any remaining Cloudflare-runtime references that do not
      have an active, documented owner and deletion condition.
      Evidence: the Cloudflare runtime inventory now finds no Postgres runtime/env
      references except the intentional `d1ConsoleServices.typecheck.ts` fixture
      proving D1 adapters reject Postgres routes. The Refactor 82 runtime guard in
      `tests/unit/refactor82CloudflareD1Runtime.guard.unit.test.ts` blocks
      Cloudflare runtime imports of Postgres storage, mixed console barrels, console
      Postgres adapters, and the Postgres env-token family (`POSTGRES_URL`,
      `CONSOLE_POSTGRES_URL`, migration URLs, billing/outbox/webhook cron
      fallbacks, and signing-session seal Postgres idempotency variables). The
      same guard now blocks old route-capability `enabled: true` flags in runtime
      router source, while keeping those old shapes only as `@ts-expect-error`
      fixtures in `relayRouteOptions.typecheck.ts`.
      The next cleanup deleted the obsolete split-domain Postgres smoke job from
      `.github/workflows/ci.yml` and removed the unused Postgres service/env from
      the threshold core CI job. The guard now scans the CI workflow for removed
      Postgres smoke jobs, `postgres:setup:split`, `postgres:down`, Postgres env
      tokens, and Postgres service containers. Slice diff: 167 insertions and 57
      deletions across the guard and CI workflow, with 54 CI lines deleted.
      The next cleanup removed stale `pg` compiler scaffolding from
      `packages/sdk-server-ts/tsconfig.json`; direct `pg` and `@types/pg`
      package dependencies had already been deleted. The runtime guard now scans
      the SDK server TypeScript config so `pg` ambient types and path aliases do
      not return while Postgres remains a future full-family contract.
      The next cleanup deleted Router A/B local-dev Postgres SQL dialect support:
      `LocalPersistenceSqlDialectV1`, Postgres placeholder generation, the
      Postgres seed-plan test branch, and the SQLite executor's Postgres-plan
      rejection test are gone. Local persistence seed plans now produce SQLite
      statements for the D1-compatible dev harness only.
      Validation passed: `pnpm --dir tests exec playwright test -c
playwright.unit.config.ts unit/refactor82CloudflareD1Runtime.guard.unit.test.ts
unit/router.relayRouteSurface.unit.test.ts unit/router.routeDefinitions.unit.test.ts
--reporter=line`, `pnpm --dir packages/sdk-server-ts type-check`,
      `pnpm --dir tests exec tsc -p tsconfig.playwright.json --noEmit`,
      `cargo test --manifest-path crates/router-ab-core/Cargo.toml --test local
local_persistence`,
      `cargo test --manifest-path crates/router-ab-dev/Cargo.toml --test
sqlite_seed`, stale `pg` package/config scans, stale Router A/B local
      Postgres/dialect scans, and `git diff --check`.

Execution rule: no half-Postgres staging. If D1/DO is the target, staging starts
life on D1/DO.
