# Refactor 103: Lean Console Organization, Billing, And Email Plan

Date created: July 20, 2026

Last reconciled: July 21, 2026

Status: Planned

## Goal

Finish the dashboard and console model with the smallest coherent feature set:

1. Organization membership follows the GitHub ownership model.
2. Administrators have a small set of configurable organization permissions.
3. Members receive viewer or editor access to selected projects.
4. Invitations remain pending until accepted.
5. Billing is prepaid pay-as-you-go with working refunds.
6. Essential transactional email is durable and retried.
7. Console code depends on the public wallet SDK through a small, stable API boundary.
8. The wallet SDK and private cloud platform finish as two independent repositories.

This plan replaces conflicting organization, role, billing, refund, and notification claims in `docs/saas/` as each phase lands.

## Repository Boundary

The repository is partially modular today. Package dependency direction is healthy: the private console packages depend on the public SDK packages, and the SDK packages do not import the console packages. The boundary is still too porous for a clean repository split:

- `packages/sdk-server-ts` contains console roles, authentication, route definitions, and console-aware tenant storage types.
- `packages/console-server-ts` imports many `@seams/sdk-server/internal/*` modules.
- `apps/seams-site` builds the dashboard, marketing site, wallet demos, and SDK examples as one frontend.
- `apps/web-server` and the hosted Cloudflare gateway compose the public signer with private console services.

The self-hosted signing worker already proves the intended open-source core. It uses public SDK exports and excludes the hosted console, billing, webhooks, sponsorship, and policy-management implementation.

### Target Two-SDK, Two-Repository Model

The open-source `seams-wallet-sdk` repository owns:

- `packages/sdk-web`
- `packages/sdk-server-ts`
- SDK-only shared utilities and required Rust/Wasm crates
- signer storage migrations
- `examples/self-host-cloudflare-worker`
- SDK documentation, examples, tests, and release workflows
- generic signer-side policy enforcement contracts and safe local defaults

The private `seams-cloud` repository owns:

- `packages/console-shared-ts`
- `packages/console-server-ts`
- the whole `apps/seams-site` application
- `apps/web-server`
- organization, membership, project administration, billing, refunds, email, webhooks, sponsorship, observability, and audit features
- policy authoring, persistence, compilation, and hosted policy adapters
- console migrations, console tests, and hosted deployment workflows

Moving the whole site to the private repository is the lean frontend split. The public repository keeps SDK documentation and self-host examples; carving marketing pages into another application is deferred.

Each repository has its own workspace manifest, lockfile, versioning, CI, release process, issue tracker, and access controls. The public repository produces the versioned `@seams/sdk` and `@seams/sdk-server` packages. The private repository produces its internal console packages and deployable cloud applications.

### Dependency Rules

- Dependency direction is private cloud to public SDK only.
- The public SDK contains no console roles, console routes, billing, organization membership, or dashboard implementation.
- The private repository imports supported SDK package exports. It never imports `@seams/sdk-server/internal/*`.
- Add one narrow public server extension surface for the hosted gateway. Promote only the contracts the private composition actually needs.
- Keep signer-side cryptographic, session, recovery, and admission invariants open source. The private policy system supplies typed decisions or signed runtime snapshots through the public extension contract.
- A self-hosted operator can use safe local defaults or implement the public policy provider.
- Published package artifacts are the integration boundary. `seams-cloud` pins released versions of `@seams/sdk` and `@seams/sdk-server`.
- Cross-repository builds do not use workspace links, source-path imports, Git submodules, copied source, or shared unpublished packages.

Clean the boundary in the current monorepo first, then perform the physical extraction as the final phase. This avoids maintaining compatibility paths or duplicating code during the cutover.

### Minimal-Change Split Strategy

The split is primarily a source-movement, package-release, and CI task. Keep the wallet SDK's public API, signer runtime, cryptography, session and recovery behavior, signer schemas, and self-host worker behavior unchanged.

The required SDK source changes are limited to:

1. Move console authentication, console principals, and console route definitions into `packages/console-server-ts`.
2. Move the combined console-and-signer tenant composition into the private repository, leaving the public SDK storage model signer-only.
3. Add one supported `@seams/sdk-server/cloud-host` entrypoint that exports the existing signer composition primitives required by `seams-cloud`.
4. Replace private `@seams/sdk-server/internal/*` imports with that supported entrypoint, then remove the wildcard internal package export.

The `cloud-host` entrypoint is a curated export surface over existing SDK primitives. This phase does not redesign those primitives or change their runtime behavior.

Split constraints:

- Do not rename the public SDK packages during extraction.
- Do not combine organization, billing, email, or policy feature changes with repository movement.
- Do not change signer database schemas or self-host deployment behavior.
- Pin an exact public SDK release in `seams-cloud` for the first independent build.
- Keep the original monorepo private and read-only until both new repositories pass staging deployment checks.
- Scan the complete public repository history for private source and secrets before changing its visibility.

## Product Model

### Hierarchy

```text
Organization
├── owners, administrators, and members
├── billing account
└── projects
    └── environments
```

“Team” remains a dashboard label for organization membership. It is not a separate persisted aggregate between organization and project.

The organization is the owner, member roster, payer, and billing boundary. A customer that needs a different owner set, roster, or billing account creates another organization.

Owners and administrators can access all projects. Members receive explicit project access.

### GitHub-Style Ownership

- An organization has one or more owners.
- All owners are equal. There is no primary owner.
- Owners have full organization, project, member, and billing access.
- Owners can invite a new user as an owner.
- Owners can promote any active member or administrator to owner.
- Owners can change another owner's role when at least one owner remains.
- An owner cannot change their own role.
- An owner can leave the organization only when another owner remains.
- The dashboard recommends at least two owners.
- Every owner change requires recent authentication, audit logging, and email notification.
- Billing contacts are separate from ownership.

This follows GitHub's continuity model: [organizations can have multiple owners and GitHub recommends at least two](https://docs.github.com/en/organizations/managing-peoples-access-to-your-organization-with-roles/maintaining-ownership-continuity-for-your-organization). Ownership handoff adds the successor first and then removes the former owner, matching [GitHub's documented transfer flow](https://docs.github.com/en/organizations/managing-organization-settings/transferring-organization-ownership).

### Roles And Permissions

Keep the role system small.

#### Owner

Owners always have full access. Their authority is implied by the `OWNER` membership role and cannot be reduced through permission toggles.

#### Administrator

Owners choose from these administrator permissions:

```ts
type AdminPermission =
  | "members.manage"
  | "projects.manage"
  | "billing.view"
  | "billing.manage";
```

Rules:

- `members.manage` can invite, suspend, reactivate, and remove members.
- `members.manage` cannot change owners, administrators, or administrator permissions.
- `projects.manage` can create and update projects and environments.
- Administrators can read projects even without `projects.manage`.
- `billing.view` can view balance, purchases, usage, refunds, and billing documents.
- `billing.manage` can create top-up checkouts and update billing contacts. It implies `billing.view`.
- Only owners can create administrators or change administrator permissions.

#### Member

Members receive access per project:

```ts
type ProjectAccessLevel = "viewer" | "editor";
```

- `viewer` can read project and environment configuration, usage, and observability.
- `editor` includes viewer access and can perform normal project operations.
- Existing approval, step-up authentication, and key-export controls still apply to sensitive operations.
- Members cannot access organization billing or membership administration.

Custom roles and fine-grained per-page permission toggles are deferred.

### Membership Lifecycle

Use one closed membership model:

```ts
type OrganizationMembership =
  | {
      kind: "active";
      role: "OWNER" | "ADMIN" | "MEMBER";
    }
  | {
      kind: "suspended";
      role: "ADMIN" | "MEMBER";
      suspendedAt: IsoTimestamp;
    }
  | {
      kind: "removed";
      role: "ADMIN" | "MEMBER";
      removedAt: IsoTimestamp;
    };
```

An owner must become an administrator before suspension or removal. Removed memberships remain as audit records.

### Invitation Lifecycle

An invitation is not a membership.

```ts
type OrganizationInvitation =
  | { kind: "pending"; expiresAt: IsoTimestamp }
  | { kind: "accepted"; membershipId: OrganizationMembershipId }
  | { kind: "declined"; declinedAt: IsoTimestamp }
  | { kind: "revoked"; revokedAt: IsoTimestamp }
  | { kind: "expired"; expiredAt: IsoTimestamp };
```

Rules:

- Owners can invite owners, administrators, or members.
- Administrators with `members.manage` can invite members.
- Administrator invitations include their administrator permissions.
- Member invitations include their initial project assignments.
- The invitee becomes a member only after acceptance.
- Acceptance requires an authenticated account with the invited verified email.
- Invitations expire after seven days.
- Resend rotates the token and extends expiry.
- The database stores only the token hash.

## Current Gaps

### Organization And Permissions

- `team_members.roles_json` can represent zero or several owners without enforcing a minimum.
- Removal code protects the last owner in some paths, while invite and role-update paths use different rules.
- The dashboard permission vocabulary differs from route authorization roles.
- Administrator-management permissions shown in the UI are not consistently enforced.
- Most authenticated members can read project resources without project assignment.
- Invitations create active memberships immediately.

### Billing

- The current product is one-time prepaid credit with usage deductions.
- There is no subscription implementation.
- Usage pricing is pay-as-you-go and funding is prepaid.
- Some billing events use balanced postings; purchases, other usage paths, and adjustments do not all follow the same ledger rule.
- Balance reads rely on a mutable cached field.
- Stripe webhook handling does not verify the raw `Stripe-Signature` request.
- Refund states exist in types, while refund creation, persistence, provider calls, and customer history are missing.
- Live Stripe can be combined with in-memory billing state in the local web server.

### Email

- Console transactional email has no provider, templates, outbox, retries, or delivery records.
- Authentication OTP email is a separate SDK feature.

### Repository Boundary

- The public server package defines the private console route surface and legacy console roles.
- The public tenant-storage route combines console and signer storage targets.
- The private console server relies on the public package's broad `internal/*` export.
- Dashboard and non-dashboard pages share one Vite application and deployment artifact.
- Current source guards reject direct package imports in selected signer files, while allowing console concepts implemented inside the signer package.

## Target Persistence

### Organization Tables

Use:

- `organization_memberships`
- `organization_admin_permissions`
- `organization_invitations`
- `project_member_access`
- `organization_owner_events`

Add these fields to `organizations`:

- `owner_anchor_membership_id`
- `owner_set_version`
- `authorization_version`

The owner anchor is an internal database invariant. It points to any active owner and grants no additional authority.

Persistence rules:

- `organization_memberships.role` is `OWNER`, `ADMIN`, or `MEMBER`.
- `OWNER` is valid only for an active membership.
- Every organization row references an active owner membership in the same organization.
- Several active memberships can use the `OWNER` role.
- Changing the anchor and demoting its former owner occurs in one transaction.
- Demoting, removing, or leaving as the last owner fails.
- Owner-set mutations compare and increment `owner_set_version`.
- Any membership or permission mutation increments `authorization_version`.
- Owner memberships cannot have administrator permission rows.
- Project access references a member and project in the same organization.

### Minimal Database Enforcement

Use a required owner-anchor composite foreign key and `PRAGMA defer_foreign_keys = on` while creating or changing the circular organization-membership relationship. [D1 supports deferring foreign-key checks until transaction completion](https://developers.cloudflare.com/d1/sql-api/foreign-keys/).

Add focused migration tests and a readiness query for ownerless organizations. There is one persistence path and no runtime fallback.

## API And Authorization

### Session Context

Application-session claims carry identity and lookup data:

```ts
type ConsoleSessionClaims = {
  accountUserId: AccountUserId;
  organizationId: OrganizationId;
  membershipId: OrganizationMembershipId;
  authorizationVersion: number;
};
```

Do not store role arrays in session claims. Load the current membership, administrator permissions, and project access at the console boundary. Reject stale authorization versions and refresh the session.

### Routes

Replace the current member and ownership routes with:

- `GET /console/organization/memberships`
- `GET /console/organization/invitations`
- `POST /console/organization/invitations`
- `POST /console/organization/invitations/:invitationId/resend`
- `DELETE /console/organization/invitations/:invitationId`
- `POST /console/account/invitations/:invitationId/accept`
- `POST /console/account/invitations/:invitationId/decline`
- `PATCH /console/organization/memberships/:membershipId/admin-permissions`
- `POST /console/organization/memberships/:membershipId/change-role`
- `POST /console/organization/memberships/:membershipId/suspend`
- `POST /console/organization/memberships/:membershipId/reactivate`
- `DELETE /console/organization/memberships/:membershipId`
- `PUT /console/organization/projects/:projectId/members/:membershipId`
- `DELETE /console/organization/projects/:projectId/members/:membershipId`
- `POST /console/organization/leave`

Route policy:

| Route family | Required access |
| --- | --- |
| Owner and administrator changes | Owner |
| Member management | Owner or administrator with `members.manage` |
| Project creation and settings | Owner or administrator with `projects.manage` |
| Project reads and operations | Owner, administrator, or assigned member access |
| Billing reads | Owner or administrator with `billing.view` |
| Billing changes and top-ups | Owner or administrator with `billing.manage` |
| Refund administration | Internal support authorization |
| Stripe webhook | Valid Stripe signature |

Express and Cloudflare adapters must use the same policy evaluator.

## Billing

### Supported Model

Ship one billing model:

- USD
- prepaid credit
- one-time Stripe Checkout top-ups
- metered pay-as-you-go usage
- partial and full refunds

Subscriptions, recurring plans, postpaid billing, stored payment methods, automatic top-ups, and multi-currency are deferred.

### Ledger

Keep the existing ledger direction and finish it:

- Every purchase, usage debit, support adjustment, refund, and dispute writes one immutable journal entry.
- Every journal entry has balanced postings.
- The balance projection is rebuilt from postings.
- Remove direct balance mutation as a source of truth.
- Keep a cached projection only when it records the last applied journal sequence and passes reconstruction tests.

Required financial events:

| Event | Credit effect |
| --- | --- |
| Stripe top-up settled | Increase prepaid credit |
| Usage | Decrease prepaid credit |
| Support credit | Increase prepaid credit |
| Authorized adjustment | Increase or decrease prepaid credit |
| Refund succeeded | Decrease prepaid credit |
| Dispute opened | Decrease prepaid credit and block when necessary |
| Dispute won | Restore prepaid credit |

Corporate accounting, Stripe payout reconciliation, tax, and revenue-recognition work are deferred.

### Stripe Boundary

- Create pending purchases before calling Stripe.
- Use the purchase ID as the idempotency key.
- Accept a configured credit pack, not an arbitrary amount.
- Construct success and cancellation URLs from the configured console origin.
- Verify the raw request body with `Stripe-Signature`.
- Store processed Stripe event IDs.
- Treat event replay as successful and side-effect free.
- Live Stripe requires durable D1 billing repositories.
- Mock providers are explicit test dependencies.

Handle:

- checkout completion and expiry
- refund creation and updates
- charge refunds
- dispute creation and closure

### Refunds

Add `billing_refunds` with:

- refund ID
- organization ID
- purchase ID
- amount
- reason
- status
- Stripe refund ID
- requester
- timestamps
- journal entry ID after success

Status is a closed union:

```ts
type BillingRefundStatus =
  | "requested"
  | "provider_pending"
  | "succeeded"
  | "failed"
  | "canceled";
```

Rules:

- Only internal support authorization can initiate a refund.
- Customers with billing read access can view refund status.
- Refund amount cannot exceed the unrefunded purchase amount.
- A console-initiated refund cannot exceed unused prepaid credit.
- Persist the request before calling Stripe.
- Use the refund ID as the Stripe idempotency key.
- Write the refund ledger entry only after provider success.
- Import refunds initiated directly in Stripe from verified webhook events.
- An external refund that exceeds remaining credit creates a negative balance and blocks billable usage.
- A support credit is never represented as a cash refund.

The first release needs refund history in the existing billing UI. A customer self-service refund form is deferred.

## Transactional Email

Implement only essential console email:

- organization invitation
- owner added or removed
- membership suspended or removed
- top-up receipt
- refund succeeded or failed
- low-balance warning

### Delivery

Add:

- `console_email_outbox`
- `console_email_deliveries`

Flow:

1. Commit the domain change and outbox item in the same transaction.
2. A scheduled worker claims pending items with a lease.
3. Render a versioned text and HTML template.
4. Send through one `ConsoleEmailProvider` adapter.
5. Retry transient failures with bounded backoff.
6. Record success or final failure.

Development uses an explicit capture provider. Production requires a configured live provider. Invitation token material is encrypted in the outbox and erased after provider acceptance, invitation acceptance, revocation, or expiry.

Notification preferences, marketing email, bounce-management UI, notification centers, and security-event email beyond the list above are deferred.

## Migration

This is a breaking development-stage cutover.

### Membership Migration

1. Report ownerless organizations and repair them explicitly.
2. Preserve every existing owner as `OWNER`.
3. Choose the earliest-created owner as the authority-neutral anchor.
4. Map `admin` to `ADMIN`.
5. Map `admin_manage_members` to `members.manage`.
6. Map project/administration write permissions to `projects.manage`.
7. Map `billing_read` to `billing.view`.
8. Map `billing_write` to `billing.manage`.
9. Give current members viewer or editor access to their existing projects based on their current read/write permissions.
10. Reject unknown roles.
11. Cut routes and sessions to the new model.
12. Drop `team_members`, role JSON parsers, and legacy route-role logic.

No runtime dual reads or dual writes.

### Billing Migration

1. Convert each existing purchase, usage event, and adjustment to balanced postings.
2. Rebuild organization balances from postings.
3. Stop when any reconstructed balance differs from the expected balance.
4. Cut all billing reads and writes to the ledger projection.
5. Remove the balance mutation trigger and incomplete posting paths.

Record a D1 Time Travel bookmark before shared-environment migration.

## Implementation Phases

### Phase 1: Organization Ownership And Invitations

- [ ] Add precise membership, invitation, administrator-permission, and project-access types.
- [ ] Add the organization schema migration.
- [ ] Implement owner invite, promotion, demotion, leave, and last-owner protection.
- [ ] Implement pending invitation acceptance, decline, resend, expiry, and revocation.
- [ ] Implement administrator permissions.
- [ ] Implement member project access.
- [ ] Increment authorization version on every access change.
- [ ] Add owner and membership audit events.

Likely files:

- `packages/console-server-ts/src/teamRbac/`
- `packages/console-server-ts/src/account/`
- `packages/console-server-ts/src/orgProjectEnv/`
- `packages/console-server-ts/migrations/d1-console/`

Exit:

- Every organization has at least one owner.
- Multiple owners work.
- An invitation is never an active membership.

### Phase 2: Route And Dashboard Cutover

- [ ] Move console authentication, principals, route definitions, and route policies from `packages/sdk-server-ts` to `packages/console-server-ts`.
- [ ] Make the public SDK route definition and tenant-storage models signer-only.
- [ ] Add the `@seams/sdk-server/cloud-host` entrypoint with only the existing primitives required by the hosted gateway.
- [ ] Replace console imports of `@seams/sdk-server/internal/*` with supported public exports.
- [ ] Replace route roles with the lean policy matrix.
- [ ] Add one shared policy evaluator for Express and Cloudflare.
- [ ] Add authorization-version refresh.
- [ ] Replace member and ownership routes.
- [ ] Update Team and Account Settings pages.
- [ ] Show all owners and recommend a second owner.
- [ ] Add project viewer/editor assignment.
- [ ] Delete current role checkboxes and transfer-owner UI.

Likely files:

- `packages/console-server-ts/src/router/consoleRouteDefinitions.ts`
- `packages/console-server-ts/src/router/consoleRoutePolicy.ts`
- the public SDK route, storage, and package-export files being reduced to signer concerns
- Express and Cloudflare console routers
- `apps/seams-site/src/pages/dashboard/routes/team-members/`
- `apps/seams-site/src/pages/dashboard/routes/account-settings/`
- `apps/seams-site/src/pages/dashboard/consoleSession.tsx`

Exit:

- UI and server use the same four administrator permissions.
- Members can access only assigned projects.
- The last owner cannot be removed through any route.

### Phase 3: Billing And Refunds

- [ ] Route every financial event through balanced postings.
- [ ] Rebuild balances from the ledger.
- [ ] Verify raw Stripe webhook signatures.
- [ ] Add durable Stripe event idempotency.
- [ ] Add full and partial refund persistence and provider calls.
- [ ] Add minimal dispute balance handling.
- [ ] Show refunds in billing history.
- [ ] Remove live-Stripe/in-memory-billing wiring.
- [ ] Remove direct balance mutation.

Likely files:

- `packages/console-server-ts/src/billing/`
- `packages/console-server-ts/migrations/d1-console/`
- `apps/web-server/src/stripeBillingProvider.ts`
- `apps/web-server/src/index.ts`
- dashboard billing pages

Exit:

- Every displayed balance reconstructs from postings.
- Refunds are provider-backed, idempotent, and customer-visible.
- Live Stripe uses durable billing state.

### Phase 4: Essential Email

- [ ] Add the email outbox and delivery tables.
- [ ] Write outbox records in the relevant domain transactions.
- [ ] Add the six required template families.
- [ ] Add development capture and live provider adapters.
- [ ] Add the lease, retry, and final-failure worker.
- [ ] Redact and erase invitation secrets.

Exit:

- Invitations and required financial notifications survive process failure.
- Failed email is visible and retryable.

### Phase 5: Delete Legacy Paths And Validate

- [ ] Delete `team_members`, role JSON, and legacy role aliases.
- [ ] Delete old ownership-transfer code and tests.
- [ ] Delete incomplete refund state paths.
- [ ] Delete direct balance mutation and non-posting writers.
- [ ] Delete tests and fixtures that preserve obsolete behavior.
- [ ] Remove the public SDK `internal/*` wildcard export after all private consumers use supported exports.
- [ ] Strengthen the boundary guard to reject console concepts anywhere in public SDK source and package artifacts.
- [ ] Add a standalone build that installs the packed public SDK into the self-host example.
- [ ] Update affected `docs/saas/` documents.
- [ ] Update the D1 local smoke table list.

Exit:

- Repository search finds no legacy console role model or old ownership-transfer path.
- Public package tarballs contain no console, billing, organization-membership, or dashboard implementation.
- The private packages build without workspace links, source imports, or `@seams/sdk-server/internal/*`.
- The self-host example builds from packed public packages alone.
- Targeted tests and package builds pass.

### Phase 6: Split The Repositories

#### 6.1 Prepare Independent Builds

- [ ] Define an explicit path allowlist for each repository, including required root configuration and shared Rust/Wasm code.
- [ ] Build and pack `@seams/sdk` and `@seams/sdk-server` from the public path set.
- [ ] Build the private path set against those packed packages with workspace links disabled.
- [ ] Fix only missing package exports, configuration, and asset ownership exposed by this test.

#### 6.2 Extract The Repositories

- [ ] Create `seams-wallet-sdk` from the public path allowlist while preserving relevant history.
- [ ] Create private `seams-cloud` from the private path allowlist while preserving relevant history.
- [ ] Give each repository its own workspace manifest, lockfile, CI, release configuration, ownership, and access controls.
- [ ] Move console migrations, tests, hosted deployment workflows, secrets, and operational runbooks to `seams-cloud`.
- [ ] Keep SDK documentation, SDK tests, signer migrations, and the self-host example in `seams-wallet-sdk`.
- [ ] Remove paths and workflows owned by the other repository.

#### 6.3 Publish And Connect

- [ ] Publish the first independent `@seams/sdk` and `@seams/sdk-server` release from `seams-wallet-sdk`.
- [ ] Replace `workspace:*` SDK dependencies in `seams-cloud` with that exact released version.
- [ ] Generate and commit the independent lockfiles.
- [ ] Build and deploy the hosted console and gateway from `seams-cloud` to staging.

#### 6.4 Verify And Cut Over

- [ ] Scan the full `seams-wallet-sdk` tree and Git history for private implementation, secrets, private environment names, and private deployment configuration.
- [ ] Inspect public package tarballs and generated source maps for console implementation.
- [ ] Run SDK, signer, and self-host tests in `seams-wallet-sdk`.
- [ ] Run console, billing, policy, email, and hosted gateway tests in `seams-cloud`.
- [ ] Promote the staging deployment, make `seams-wallet-sdk` public, and retain the former monorepo as a private read-only archive.

Exit:

- Both repositories clone, install, build, and test independently.
- `seams-wallet-sdk` can build and run the self-host example without access to `seams-cloud`.
- `seams-cloud` builds from released public SDK packages without filesystem or Git access to `seams-wallet-sdk`.
- Hosted console and gateway deployments run exclusively from `seams-cloud`.
- Existing wallet SDK consumers require no API or behavior migration for the repository split.

## Targeted Tests

### Ownership And Access

- organization creation creates its first owner
- multiple owners are allowed
- concurrent owner demotions cannot remove the last owner
- an owner cannot change their own role
- an owner can leave only when another owner exists
- owner invitation becomes ownership only after acceptance
- administrators cannot manage owners or other administrators
- administrator permissions are enforced
- project viewers cannot write
- members cannot access unassigned projects
- stale sessions cannot retain removed access

### Invitations

- token replay fails
- expired and revoked invitations cannot be accepted
- resend invalidates the old token
- verified email must match
- concurrent accept and revoke allow one terminal state

### Billing And Stripe

- every journal entry balances
- balance reconstruction matches the projection
- Stripe signatures reject changed or stale payloads
- provider event replay creates no duplicate effect
- partial refunds cannot exceed the purchase remainder
- console refunds cannot exceed unused credit
- refund webhook and reconciliation finalize once
- external over-credit refunds block billable usage
- live Stripe refuses in-memory billing state

### Email

- domain mutation and outbox write commit together
- concurrent workers do not deliver the same item twice
- transient failures retry
- final failures are recorded
- invitation tokens do not appear in logs or delivery records

## Validation

During implementation, run the narrow tests for the touched phase. The final cutover runs:

```bash
pnpm -C packages/console-server-ts type-check
pnpm -C packages/sdk-server-ts type-check
pnpm -C apps/seams-site typecheck
pnpm -C packages/console-server-ts d1:local:migrate:console

pnpm -C tests exec playwright test \
  -c playwright.relayer.config.ts \
  ./relayer/console-router.test.ts \
  ./relayer/console-d1-adapters.test.ts \
  ./relayer/console-billing.service.test.ts \
  ./relayer/console-app-session-auth.test.ts \
  --reporter=line

pnpm -C tests exec playwright test \
  ./e2e/dashboard.consoleConfigPages.apiWiring.test.ts \
  ./e2e/dashboard.billing.console.apiWiring.test.ts \
  --reporter=line

pnpm -C packages/console-server-ts build
pnpm -C packages/sdk-server-ts build
pnpm -C apps/seams-site build
```

## Explicitly Deferred

- subscriptions and recurring plans
- postpaid invoicing
- automatic top-ups
- stored payment methods
- multi-currency and tax calculation
- customer-defined roles
- fine-grained page-level capabilities
- nested team aggregates
- cross-organization project sharing
- customer self-service refund requests
- dispute evidence management
- notification preferences and notification center
- broad security-event email
- marketing email
- corporate general-ledger and payout reconciliation

## Definition Of Done

- Organizations have one or more equal owners.
- The dashboard recommends two owners.
- Ownership handoff adds the successor before the former owner leaves.
- Owners, administrators, and members have one consistent authorization model.
- Members see only assigned projects.
- Invitations require acceptance.
- Billing is clearly prepaid pay-as-you-go.
- Every financial event uses balanced postings.
- Full and partial refunds work through Stripe and appear in billing history.
- Essential transactional email is durable and retried.
- Legacy roles, owner-transfer code, direct balance mutation, and obsolete fixtures are deleted.
- Console code depends only on supported public SDK exports.
- The public SDK and self-host example build without private console packages.
- `seams-wallet-sdk` and `seams-cloud` exist as separate repositories with independent builds and release lifecycles.
