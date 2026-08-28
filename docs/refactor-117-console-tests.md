# Refactor 117 — High-Impact Console Operating Tests

Status: planned.

Date created: August 28, 2026

## Goal

Replace the Console's intercepted-API browser suite with a small set of real
operating-path tests. Each replacement test runs the Console application
through Caddy against the local Cloudflare worker and fresh D1 databases.

Refactor 117 is complete when five browser tests provide vertical coverage
across routing, session claims, onboarding, organization and project setup, API
keys, policy governance, runtime snapshots, audit, webhooks, billing, invoices,
and persistence.

The refactor deletes 50 mocked browser tests and approximately 11,745 lines:

| File                                                       | Tests | Lines |
| ---------------------------------------------------------- | ----: | ----: |
| `tests/e2e/dashboard.consoleConfigPages.apiWiring.test.ts` |    43 | 9,894 |
| `tests/e2e/dashboard.billing.console.apiWiring.test.ts`    |     5 | 1,503 |
| `tests/e2e/dashboard.webhooks.apiWiring.test.ts`           |     2 |   348 |

The replacement suite contains no `page.route()` or `route.fulfill()` calls.
Test setup may call real Console APIs to provision prerequisites. Product
actions and asserted outcomes pass through production request parsing, routing,
services, and D1 persistence.

## Why This Refactor Is Necessary

The existing files are named E2E tests, while their Console API responses are
large hand-written fixtures. They prove that React components can render the
fixture shapes and issue selected requests. They do not prove that:

- Caddy mounts `apps/seams-console` at `/dashboard/*` and `/platform/*`;
- the frontend and deployed Console API agree on response shapes;
- session claims select the correct organization, project, and environment;
- mutations survive a reload;
- webhook signatures reach an external receiver;
- delivery failure and replay traverse the real service and D1 state;
- checkout reconciliation posts one balanced ledger credit; or
- policy publication reaches runtime snapshots and audit history.

The current generic Playwright runner demonstrates the gap. It starts
`apps/seams-site`, then the Console tests navigate to `/dashboard/*`. The
marketing application renders its Page Not Found view. Negative assertions can
still pass on that missing page. This is an
`environment_or_infrastructure_failure` in the test harness and evidence that
the suite cannot gate the Console operating path.

Large fixtures also duplicate server response types, seed irrelevant fields,
and turn routine UI changes into broad test edits. The highest-value Console
properties sit at boundaries between modules. Refactor 117 tests those
boundaries directly.

## Decisions

### Five browser tests are the Console E2E authority

The Console browser authority consists of exactly five operating paths:

1. Console route and data smoke;
2. new owner setup;
3. policy governance;
4. webhook failure and recovery; and
5. billing funding and documents.

Each test owns one business outcome. Intermediate pages are checkpoints within
that outcome. A sixth browser test requires a distinct user-facing operating
path that cannot be demonstrated inside the five existing journeys.

### Real local services are required

The browser suite uses:

- Caddy for the public `/dashboard/*`, `/platform/*`, and
  `/dashboard-static/*` routing contract;
- `apps/seams-console` for the frontend;
- the local Cloudflare worker for `/console/*`;
- fresh `seams-console` and `seams-signer` D1 databases;
- the existing local Console auth boundary;
- the existing synthetic paid-checkout provider; and
- a test-owned HTTP receiver for real webhook dispatch.

The suite uses no external network service. Stripe protocol parsing and signing
remain covered at their backend boundary. The Console billing journey uses the
production billing service with its existing local provider adapter.

### Durable outcomes are the assertions

A successful click is insufficient evidence. Every mutation must be confirmed
through at least one durable or external observation:

- reload and read the D1-backed resource;
- read the resource through a second Console page or API;
- inspect the published runtime snapshot;
- follow the resulting audit event;
- verify a webhook at an external HTTP receiver; or
- confirm ledger, activity, and billing-document projections agree.

### Lower suites retain precise boundary ownership

Refactor 117 preserves focused tests for:

- D1 migrations, adapters, atomic transitions, and tenant isolation;
- RBAC and malformed-request rejection;
- Stripe signature verification, refunds, disputes, and idempotency;
- ledger balance and reservation invariants;
- webhook HMAC construction, cursor parsing, retry claims, and secret sealing;
- runtime snapshot encoding and persistence; and
- pure UI state with meaningful behavior that is expensive to reproduce in a
  browser operating path.

An in-memory or route test is a later deletion candidate only when one of the
five real-D1 journeys proves the same positive outcome and the lower test owns
no additional boundary invariant.

## Test Authority After Refactor 117

| Invariant                                                      | Authority                         |
| -------------------------------------------------------------- | --------------------------------- |
| Console application mounts and routes correctly                | Console route smoke               |
| Browser and Console API integrate through real response shapes | Five Console operating paths      |
| Supported owner workflows survive reload                       | Relevant Console operating path   |
| D1 schema, persistence, isolation, and atomicity               | D1 integration tests              |
| Role and permission rejection matrix                           | Router and service boundary tests |
| Request parsing and validation errors                          | Router and request-parser tests   |
| Stripe signature and event-envelope correctness                | Billing boundary tests            |
| Billing ledger and refund/dispute accounting                   | D1 billing tests                  |
| Webhook HMAC algorithm and pagination semantics                | Webhook boundary tests            |
| Real webhook transport, failure visibility, and replay         | Webhook operating path            |
| Exact UI copy, CSS classes, and request implementation details | No test authority                 |

## Harness

### Dedicated Playwright configuration

Add `tests/playwright.console.config.ts` with:

- `testMatch: ['**/e2e/console/**/*.operating.test.ts']`;
- Chromium only;
- one worker;
- zero retries;
- `trace: 'retain-on-failure'`;
- `screenshot: 'only-on-failure'`;
- `video: 'retain-on-failure'`;
- an expectation timeout suitable for local D1 and Vite; and
- one managed `webServer` command.

Add one command at the tests workspace and repository root:

```text
pnpm test:console
```

Local development and CI run the same command. Do not add separate scripts that
select different test files or service compositions.

### Service startup

Extend `tests/scripts/start-intended-services.mjs` to start
`apps/seams-console` beside the existing Caddy, site, router, migrations, and
seed operations. Use the same deployment origins already passed to the site:

```text
VITE_SITE_ORIGIN=http://localhost:4001
VITE_CONSOLE_BASE_URL=https://localhost:4101
VITE_RELAYER_URL=https://localhost:4101
VITE_WALLET_ORIGIN=https://localhost:4002
```

The managed readiness server becomes ready only after all of these checks pass:

- Router `/healthz`;
- Router `/readyz`;
- Console `/console/readyz`;
- public `/dashboard/login` returns the Console application; and
- one authenticated `/dashboard/overview` navigation can load its initial
  Console requests.

Starting the Console from the existing service manager is the smallest direct
change. A separate orchestration framework or duplicate local stack is outside
this refactor.

### Authentication

Use the existing local `X-Console-*` auth boundary. A Console test fixture
creates a Playwright context with required headers:

```text
X-Console-User-Id
X-Console-Org-Id
X-Console-Project-Id
X-Console-Environment-Id
```

The local worker converts those boundary values into precise session claims.
Browser tests do not forge a session response or install hand-written claims in
storage.

Google OIDC, GitHub OAuth, HMAC session issuance, cookie security, and session
revocation retain focused boundary coverage. Provider login is outside the
Console operating suite because it introduces external identity availability
without increasing Console workflow coverage.

### Tenant isolation

Each operating test receives a deterministic, unique organization ID matching
the production parser. Project, environment, policy, API-key, webhook, billing,
and audit records remain scoped to that organization.

Prerequisite tenants are created through the real onboarding APIs. The new
owner journey performs those same actions through the UI. Tests never write raw
D1 rows from their bodies.

The service manager resets the local D1 state once per run. Unique tenants make
the five tests independent of execution order and make retained failure state
easy to inspect.

### Shared fixture responsibilities

Keep the fixture small. It may own only:

- deterministic tenant identity;
- authenticated API request context;
- prerequisite onboarding through public APIs;
- browser `pageerror`, `requestfailed`, and `/console` 5xx collection;
- webhook receiver lifecycle; and
- concise failure diagnostics.

It must not expose response builders, fixture payload overrides, page-specific
selectors, or direct database mutation.

## Operating Path 1 — Console Route and Data Smoke

### Outcome

A seeded owner can open the mounted Console and visit every visible enabled
destination without a route failure, browser exception, failed Console request,
or Console 5xx response.

### Flow

1. Open `/dashboard` with an authenticated, completed tenant.
2. Confirm routing settles on `/dashboard/overview`.
3. Confirm the main Dashboard workspace and selected tenant context render.
4. Discover enabled sidebar links from the rendered navigation.
5. Visit each visible destination through its link.
6. Confirm the public URL, main page landmark, and absence of an error state.
7. Visit `/platform/billing` through a platform-support context.
8. Assert the collected browser and Console request diagnostics are empty.

### Coverage

- Caddy Console rewrites;
- Vite base path and assets;
- Dashboard route resolution;
- session bootstrap;
- organization/project/environment context;
- sidebar navigation;
- all visible page module imports;
- initial real API reads; and
- broad protection against blank pages and marketing-site fallthrough.

The test does not assert every heading or card. One stable landmark per page and
clean request diagnostics are sufficient.

## Operating Path 2 — New Owner Setup

### Outcome

A new owner creates an operable project and a reveal-once publishable API key.
The resulting state survives reload.

### Flow

1. Open `/dashboard` with a valid session for an organization that has no
   persisted profile.
2. Confirm routing enters the focused onboarding flow and dashboard navigation
   is withheld until setup completes.
3. Enter the organization name and submit.
4. Create the first project and development environment.
5. Confirm onboarding completes and dashboard navigation becomes available.
6. Open API keys and create a publishable key scoped to the new environment.
7. Capture the full reveal-once secret and verify its prefix.
8. Reload the page.
9. Confirm the key remains listed, its environment scope remains correct, and
   the full secret is no longer available.
10. Read the organization, project, environment, and key through authenticated
    Console APIs and verify the same identities.

### Coverage

- empty-account routing;
- onboarding navigation lock;
- organization/project/environment creation;
- selected context propagation;
- API-key creation and reveal-once behavior;
- D1 persistence; and
- reload behavior.

## Operating Path 3 — Policy Governance

### Outcome

An owner creates and publishes a policy. The effective runtime snapshot and
audit history identify the published policy.

### Flow

1. Provision a completed tenant through real onboarding APIs.
2. Open Policy Engine and create one policy with a meaningful chain/action
   constraint.
3. Simulate one allowed and one rejected request through the UI.
4. Complete the supported approval and publication actions.
5. Confirm the UI reports the published version.
6. Read the latest runtime snapshot and verify the policy identity, version,
   scope, and effective rule.
7. Open Audit, find the publication event, and follow its policy deep link.
8. Confirm the deep link selects the published policy.

### Coverage

- policy authoring;
- simulation;
- approval and publication;
- runtime snapshot publication;
- audit emission;
- audit search and deep linking; and
- cross-page URL state.

The test uses one policy shape. Parser, rule, role, and scope matrices remain in
focused lower suites.

## Operating Path 4 — Webhook Failure and Recovery

### Outcome

A Console-created webhook receives an authentic signed event, exposes a failed
delivery, and succeeds after replay.

### Flow

1. Start a test-owned HTTP receiver on an ephemeral local port.
2. Provision a completed tenant.
3. Open Webhooks and create an active endpoint for the event category emitted
   by the chosen trigger.
4. Capture the reveal-once `whsec_` signing secret.
5. Trigger a real Console event through a supported API mutation.
6. Have the receiver independently verify:
   - endpoint ID;
   - event ID;
   - event type;
   - timestamp;
   - JSON body; and
   - HMAC-SHA256 over `timestamp.body` using Node crypto.
7. Return HTTP 500 for the first request.
8. Refresh Webhooks and confirm the failed delivery, attempt metadata, and
   dead-letter state.
9. Replay the delivery through the UI.
10. Return HTTP 200 and confirm the delivery becomes successful.
11. Reload and verify the endpoint and recovered delivery remain visible.

### Coverage

- endpoint creation;
- secret reveal-once handling;
- sealed-secret readback inside the service;
- category matching;
- real HTTP transport;
- independently verified signing;
- delivery and attempt persistence;
- failure/dead-letter presentation;
- replay; and
- reload persistence.

The receiver is an external observer. It does not replace or intercept any
Console request.

## Operating Path 5 — Billing Funding and Documents

### Outcome

An owner funds a zero-balance account through checkout. Reconciliation creates
one durable credit and one billing document, and repeated reconciliation does
not duplicate the ledger posting.

### Flow

1. Provision a completed tenant with zero prepaid balance.
2. Open `/dashboard/billing/account` and confirm the zero balance and blocked
   or unfunded readiness state.
3. Select the `$25` credit pack and start checkout.
4. Follow the existing synthetic provider's paid success URL.
5. Let the account page reconcile the checkout session.
6. Confirm the balance is `$25.00`, account activity contains the purchase, and
   readiness reflects the funded state.
7. Open Invoices and select the generated purchase receipt.
8. Confirm receipt amount, line items, and activity.
9. Download the PDF and verify a successful PDF response with a non-empty body.
10. Reconcile the same checkout session a second time through the real API.
11. Reload the account and verify the balance remains `$25.00` and only one
    purchase credit exists.

### Coverage

- billing overview;
- credit-pack selection;
- checkout-session creation;
- browser redirect and success query parameters;
- checkout reconciliation;
- ledger idempotency;
- account activity;
- live-environment readiness;
- billing-document list and detail; and
- PDF export.

Raw Stripe webhook signature parsing, refunds, disputes, manual adjustments,
and accounting edge cases remain lower-suite invariants.

## Assertions and Selectors

Use accessible roles, labels, and stable domain identifiers. CSS class names are
not Console E2E selectors.

Prefer assertions such as:

- URL settled on the domain route;
- named main region is visible;
- resource ID or stable user-supplied name is present;
- durable state agrees after reload;
- response status and content type are correct;
- no browser/page/request diagnostics were collected; and
- an external receiver observed the expected signed event.

Avoid assertions for:

- exact explanatory copy;
- element ordering without a product requirement;
- incidental request counts;
- absence of unrelated API calls;
- CSS class names;
- complete JSON response shapes; and
- every option in a filter or dropdown.

## Deletion and Consolidation

### Mocked browser suite

After all five replacement tests pass, classify the three intercepted-API files
as `obsolete_test_or_fixture` and delete them in one dedicated commit. Delete
their inline response builders, route scaffolds, mock record arrays, and
mock-only assertions with the files.

Do not retain individual tests for query serialization, copy, role-specific
element counts, mocked network failures, or stale response shapes. A behavior
survives only when it has authority in the new operating paths or a precise
lower-level boundary suite.

### Backend suite

Perform a second deletion audit after the browser cutover:

1. map each remaining positive router/service test to the invariant it owns;
2. identify cases that duplicate a real-D1 operating outcome;
3. retain negative parsing, RBAC, isolation, atomicity, cryptographic, and
   financial cases;
4. delete exact happy-path duplicates and their exclusive fixtures; and
5. run the narrowest owning suite after each deletion group.

Keep backend-test cleanup in a separate commit from browser replacement and
mock-suite deletion. This makes obsolete-test removal reviewable and prevents a
green E2E path from hiding lost boundary coverage.

## CI Gate

Add `pnpm test:console` as a required pull-request and merge-queue job in
`.github/workflows/validate-repository.yml`.

The job must:

1. install workspace dependencies;
2. install Chromium;
3. prepare the Rust/WASM artifacts required by the local worker;
4. start the managed local stack through the Playwright configuration;
5. run the five Console operating paths with one worker and zero retries; and
6. retain traces, screenshots, video, and Playwright results for seven days on
   failure while keeping managed-service output in the CI job log.

A retry can hide shared-state leakage and race conditions. Fix the cause of a
failure before considering retries.

The implemented gate uploads Playwright failure evidence from
`tests/test-results` for seven days. Managed-service output remains in the CI
job log.

CI should run this gate when Console frontend, Console backend, Console shared
types, D1 migrations, Caddy routing, the Console harness, or the five tests
change. Start with a normal required job. Add path filtering only after the
unfiltered job is stable and the dependency list is proven complete.

## Phases

### Phase 1 — Make the real Console runnable under Playwright

- [x] Start `apps/seams-console` from the existing managed local service stack.
- [x] Add Console frontend and `/console/readyz` readiness checks.
- [x] Add `tests/playwright.console.config.ts`.
- [x] Add the root and tests-workspace `test:console` command.
- [x] Add the authenticated tenant and diagnostic fixture.
- [x] Prove `/dashboard/webhooks` and `/dashboard/billing/account` render the
      Console application through Caddy.

Phase 1 is complete when the harness catches a wrong application mount before
any product assertion runs.

### Phase 2 — Establish broad routing and setup coverage

- [x] Add Console route and data smoke.
- [x] Add new owner setup.
- [x] Confirm independent tenants and execution-order independence.

### Phase 3 — Establish governance coverage

- [x] Add policy creation and simulation.
- [x] Complete the supported approval/publication path.
- [x] Verify runtime snapshot and audit deep link.

### Phase 4 — Establish external webhook evidence

- [x] Add the ephemeral HTTP receiver.
- [x] Verify webhook HMAC independently.
- [x] Demonstrate HTTP 500, persisted failure, UI replay, and HTTP 200 recovery.

### Phase 5 — Establish financial operating evidence

- [x] Add zero-balance tenant setup through real APIs.
- [x] Demonstrate checkout creation, redirect, and reconciliation.
- [x] Verify ledger, activity, receipt, PDF, readiness, and idempotency.

### Phase 6 — Cut over and delete

- [x] Run the five tests successfully three consecutive times with fresh tenant
      state on the isolated local stack.
- [x] Add the required CI gate.
- [x] Delete the three mocked browser files and their exclusive helpers.
- [x] Update `tests/README.md` and the root testing documentation.
- [ ] Audit exact backend happy-path duplication in a separate commit.

## Acceptance Criteria

Refactor 117 is complete when:

- exactly five Console browser operating tests are collected;
- no Console browser test calls `page.route()` or `route.fulfill()`;
- `pnpm test:console` starts a fresh stack and passes from a clean checkout;
- every test uses a unique tenant and passes independently of order;
- every mutation is verified through durable or external evidence;
- the route smoke fails when `/dashboard/*` resolves to the marketing app;
- webhook evidence includes independently verified HMAC and real HTTP
  failure/replay;
- billing evidence includes checkout, reconciliation, one ledger credit,
  receipt, PDF, reload, and duplicate reconciliation;
- policy evidence includes publication, runtime snapshot, audit event, and deep
  link;
- the three mocked browser files are deleted;
- lower suites still cover D1, RBAC, validation, cryptographic, and financial
  edge invariants; and
- CI runs the same `pnpm test:console` command used locally with zero retries.

## Non-Goals

Refactor 117 does not:

- test Google or GitHub provider availability;
- call live Stripe;
- create screenshot baselines for visual regression;
- exhaustively exercise every role, filter, parser branch, billing event, or
  webhook cursor in the browser;
- preserve mocked Console response fixtures for compatibility;
- add a generic E2E framework for unrelated products; or
- make browser tests the authority for D1 atomicity, RBAC matrices,
  cryptographic algorithms, or financial accounting edge cases.

## Simplicity Check

The smallest effective design uses the local runtime already present in the
repository, starts the missing Console frontend, and adds five tests with one
small fixture. It adds no alternate backend, fixture schema, response factory,
record/replay layer, visual snapshot system, or external test account.

The expected net result is roughly 11,745 deleted mock-test lines, a compact
operating suite, and stronger evidence for the user-visible Console than the
current 50 browser tests provide.
