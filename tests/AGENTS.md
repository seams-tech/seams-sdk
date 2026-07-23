# tests/ — agent instructions (detail)

Root `AGENTS.md` has the short policy. This file is the operational detail for work under
`tests/`.

## Suite map

- `e2e/intended-behaviours/*.contract.test.ts` (`pnpm test:intended`) — the normative
  lifecycle oracle for registration, unlock, signing, step-up, and export. Spec:
  `docs/intended-behaviours.md`. The generic Playwright config deliberately excludes
  these; lifecycle assertions run only under the intended runner.
- `unit/` (`pnpm test:unit`) — fast regression coverage. Trustworthy only insofar as its
  fixtures come from the shared factories below.
- `relayer/`, `wallet-iframe/`, `lit-components/`, `yaos-local/` — integration surfaces
  (`pnpm test:relayer`, etc.).
- `scripts/check-*.mjs` (`pnpm test:source-guards`) — literal source-text guards, governed
  by `docs/refactor-88B-clean-source-guards.md`.

Do not add lifecycle coverage as broad mocked unit tests (refactor-88 rule), and do not
use `setupBasicPasskeyTest` as a lifecycle oracle.

## Fixture rules — factories only

Build domain records exclusively through the shared factories. When a domain type changes,
update the factory once; tests override only the fields they exercise.

- `unit/helpers/signingSessionRecord.fixtures.ts` — ThresholdEd25519/Ecdsa session
  records, warm/wallet sessions (constructed via the real `upsert*` production paths)
- `helpers/ed25519YaoCapabilityFixtures.ts` — Ed25519-Yao capability records (via the real
  parse/build production functions)
- `unit/helpers/ecdsaBootstrap.fixtures.ts`, `unit/helpers/ecdsaChainTarget.fixtures.ts`
- `unit/helpers/accountAuth.fixtures.ts`, `unit/helpers/availableSigningLanes.fixtures.ts`,
  `unit/helpers/cloudflareD1RouterApiAuthService.fixtures.ts`,
  `unit/helpers/warmSessionTestServices.fixtures.ts`,
  `unit/helpers/warmSessionUiConfirm.fixtures.ts`
- `relayer/signingBudgetStatus.fixtures.ts`, `helpers/signingBudgetStatus.ts`
- Cross-suite utilities: `helpers/routerAbSigningRuntimeTestUtils.ts`,
  `helpers/thresholdEcdsaClientBootstrap.ts`, `helpers/emailOtpDerivation.ts`,
  `helpers/sqliteD1.ts`

Rules:

- Complex domain-state records (session, auth/capability, signing, persistence) come
  only from the factories — no inline `satisfies SomeRecord` / typed object literals for
  these. Simple value objects, request params, and small DTOs may stay inline.
- If no factory covers the type, add a branch-specific builder in `unit/helpers/`
  (prefer constructing through the production parser/builder — those cannot drift
  silently), then use it. Builders produce valid current-domain objects and expose only
  meaningful variations — no universal mega-factory with broad optional fields; keep
  passkey/email-OTP and ECDSA/Ed25519 branches separate. Deliberately-invalid records
  (rejection-path tests) are built as factory output plus a visible corrupting override
  at the call site.
- Do not copy record shapes from other tests; they may predate the current types.

## Stale-test triage (a test fails after a refactor)

Classify before fixing: identify the invariant, then its authority — only then decide
test-fix vs code-fix.

1. What does the failing test own? Lifecycle behaviour (intended contract), a
   crypto/wire invariant (vector test), a component invariant (factory-based unit test),
   or a snapshot of an old type shape / source text (inline fixture, source guard)?
2. Is that invariant still intended? Check the current domain types and
   `docs/intended-behaviours.md` / the active `docs/refactor-NN-*.md`. For lifecycle
   claims, a green `pnpm test:intended` supports staleness; for other invariant classes
   it proves nothing — the E2E suite never exercises them. Classify the failure:
   `production_regression`, `valid_test_needs_update`, `obsolete_test_or_fixture`, or
   `environment_or_infrastructure_failure` (Redis/Upstash, NEAR RPC, Safari, faucet 429
   gate several suites — don't touch fixtures or code for those). State the
   classification before repairing.
3. Invariant still intended ⇒ real regression: fix the code, not the test. If one
   repair attempt on a lower-authority test fails, stop and reassess staleness before
   changing more code.
4. Invariant obsolete ⇒ stale test: update the fixture in its shared factory (list
   above), or delete the test/fixture/mock/helper if it encodes retired behaviour.
   Never copy the old shape back into product code, and never change production
   behaviour solely to satisfy a stale fixture.
5. Source-guard failure (`scripts/check-*.mjs`): decide guard-vs-code with
   `docs/refactor-88B-clean-source-guards.md`. Guards assert literal source patterns and
   can themselves be stale; retirement is gated on intended-contract coverage.
