# Account Settings Implementation Plan

Date updated: March 10, 2026

## Objective

Implement a first-class Account Settings experience in dashboard with a hard cutover from the current Team Members modal handoff.

Target outcomes:

- Topbar `Account Settings` opens a dedicated page at `/dashboard/account-settings`.
- Page lives in the `Administration` sidebar group.
- Page supports:
  - account profile editing (username, primary email, backup emails),
  - user-created organizations list with create/open/edit/delete actions,
  - organization owner transfer to another admin.

## Product Decision (Locked)

- Create a dedicated `/dashboard/account-settings` page.
- Remove the legacy `Account Settings -> /dashboard/team-members + self-edit modal` behavior.
- Keep topbar account menu focused on three actions only:
  - `Account Settings`
  - `Toggle Theme`
  - `Sign out`

## Current State Snapshot (March 10, 2026)

- Dashboard topbar account menu is action-oriented and now routes `Account Settings` directly to `/dashboard/account-settings`.
- Dashboard sidebar includes `Account settings` in the `Administration` group.
- Legacy `Account Settings -> /dashboard/team-members + self-edit modal` behavior has been removed.
- `/dashboard/account-settings` is the one dashboard route exempt from the onboarding redirect; all other non-onboarding routes still redirect until the active org completes onboarding.
- Backend now has a dedicated `server/src/console/account` module:
  - `GET/PATCH /console/account/profile`
  - `GET/POST /console/account/organizations`
  - `PATCH /console/account/organizations/:orgId`
  - `DELETE /console/account/organizations/:orgId`
  - `POST /console/account/organizations/:orgId/transfer-owner`
  - `POST /console/account/organizations/:orgId/switch-context`
- Account profile persistence now exists for display name, primary email, and backup emails.
- `console_organizations` now includes `created_by_user_id`, and the account Postgres slice maintains `console_user_profiles` plus `console_user_backup_emails`.
- Organization creation from account settings reuses the existing onboarding organization bootstrap path rather than forking org/owner initialization logic.
- Console auth/session carries `orgId` plus scoped `projectId` and `environmentId` claims when available, and account-driven org switching refreshes all three together.

## Scope

In scope:

- Dashboard route + UI for Account Settings.
- New account backend slice (`/console/account/*`) for profile and organization directory operations.
- Organization creation and owner transfer workflow from Account Settings, reusing the existing onboarding org bootstrap path/service rather than duplicating it.
- Session/org/project/environment context handling plus onboarding-gate behavior required to open organizations from account page.

Out of scope (this plan):

- Rebuilding the full Billing page inside Account Settings.
- Legacy compatibility path for old account modal intent (remove during cutover).

## Target UX

`/dashboard/account-settings` sections:

1. **Profile**
   - Username/display name
   - Primary email (if editable by provider policy)
   - Backup emails list (add/remove/verify state if supported)
2. **My Organizations**
   - Organizations created by current user
   - Create organization action
   - Per-organization actions:
     - open/switch into org dashboard context,
     - edit organization name,
     - delete organization when it is empty,
     - transfer owner to another admin

Navigation:

- Add `Account settings` sidebar item in the `Administration` group.
- Topbar `Account Settings` action always routes to `/dashboard/account-settings`.
- `/dashboard/account-settings` remains reachable even when the current org is not fully onboarded; it is the one dashboard route exempt from the onboarding redirect so users can manage profile and organizations before completing setup.
- `Open organization` switches org context first, then routes to `/dashboard/onboarding` if the target org is not fully onboarded, otherwise routes to the default dashboard entry for that org.

## Backend Contracts (Proposed)

New `/console/account/*` endpoints:

- `GET /console/account/profile`
- `PATCH /console/account/profile`
- `GET /console/account/organizations`
- `POST /console/account/organizations`
- `PATCH /console/account/organizations/:orgId`
- `DELETE /console/account/organizations/:orgId`
- `POST /console/account/organizations/:orgId/transfer-owner`
- `POST /console/account/organizations/:orgId/switch-context`

Notes:

- Keep existing `/console/billing/*` as billing source of truth.
- `switch-context` should rotate/refresh app session context to the selected org (no client-side fake context).
- `switch-context` must refresh `orgId`, `projectId`, and `environmentId` claims together so the client never carries project/environment scope from the previous org.
- If the target org has no active default project/environment yet, `switch-context` should clear those claims and let the dashboard route decision fall back to onboarding for org-scoped navigation.
- Organization creation should extract or share the existing onboarding organization bootstrap implementation so onboarding and account settings stay on one canonical path for org creation + initial owner bootstrap + audit behavior.
- Organization deletion should stay owner-only and only succeed when the target org is not the active org, has no other non-removed members, and has no wallets.
- Owner transfer should be transactional:
  - validate actor is current owner in target org,
  - validate target member has admin eligibility,
  - apply owner role transfer with last-owner safety preserved.

## Data Model Changes (Proposed)

Additions:

- `console_user_profiles`
  - `user_id` (pk), `display_name`, `primary_email`, timestamps
- `console_user_backup_emails`
  - `user_id`, `email`, `status`, timestamps, unique `(user_id, lower(email))`
- Add `created_by_user_id` to `console_organizations`
  - required for authoritative “organizations created by user” list

Recommended access index:

- `console_org_user_index` (or equivalent join view/table)
  - maps `user_id <-> org_id` for fast account-scoped org directory queries.
  - can be derived from active memberships, but keep explicit index if query/load requires it.

## Breaking Change and Cleanup Policy

- Remove `accountSettingsIntents` modal trigger flow once page cutover is complete.
- Remove any legacy topbar selection semantics for account action items.
- Do not keep dual implementations after cutover; page route becomes the only account settings path.

## Implementation Status (March 10, 2026)

Shipped:

- Dedicated dashboard route, sidebar entry, and topbar cutover are implemented.
- Dedicated account backend slice is implemented for profile, backup emails, organization directory, org create/rename/delete, owner transfer, and context switching.
- Account page UI is implemented for profile editing, backup emails, and organization management, including owner-only delete actions for empty non-current orgs.
- Account org creation reuses onboarding bootstrap, and org rename/owner transfer emit audit events.
- Context switching now refreshes `orgId`, `projectId`, and `environmentId` together and routes to onboarding for incomplete target orgs.
- Focused relayer parity coverage exists for Express and Cloudflare account routes, including OIDC primary-email read-only enforcement, forbidden owner transfer, and org-directory visibility checks.
- Browser-level account-settings API wiring has been extended for create/rename/transfer/open flows and read-only-email UX, but the dashboard Playwright harness is still blocked before the dashboard shell renders.

Remaining next steps:

- Get the dashboard account-settings Playwright cases green once the existing dashboard shell/bootstrap blocker is resolved.
- Add any still-missing service-level validation coverage and optional Postgres-backed account-query coverage if we want persistence-level guarantees beyond current route tests.
- Verify downstream `/console/*` behavior after context switch in the real browser path once the dashboard harness is healthy.

## Phased TODO List

### Phase 1: Route and Navigation Cutover

- [x] Add dashboard route `/dashboard/account-settings` with new page component.
- [x] Add sidebar item `Account settings` in the `Administration` group.
- [x] Update topbar `Account Settings` action to route to `/dashboard/account-settings`.
- [x] Exempt `/dashboard/account-settings` from the onboarding redirect while keeping the rest of the onboarding gate intact.
- [x] Delete `requestOpenSelfMemberSettings` handoff from dashboard topbar select handler.
- [x] Remove obsolete account settings intent helpers if no longer referenced.
- [x] Add/update API-wiring e2e test for topbar->account-settings navigation.

Exit criteria:

- Account Settings action never routes to team-members modal flow.

### Phase 2: Account Profile Backend + UI

- [x] Create `server/src/console/account` module (`types.ts`, `requests.ts`, `service.ts`, `postgres.ts`, `errors.ts`, `index.ts`).
- [x] Implement profile endpoints (`GET/PATCH /console/account/profile`) in Express + Cloudflare console routers.
- [x] Add profile form UI and optimistic/safe-save states on account settings page.
- [x] Add validation and permission rules for editable fields.
- [ ] Add focused parser/service validation coverage; route parity tests (Express + Cloudflare) are already in place.

Exit criteria:

- Profile fields can be read/updated end-to-end with deterministic validation behavior.

### Phase 3: Backup Email Management

- [x] Implement backup email persistence and CRUD endpoints under `/console/account/profile`.
- [x] Add backup email UI list with add/remove flows and clear error states.
- [x] Define provider-boundary rules (for example: primary email may be read-only for OIDC-managed identities).
- [x] Add route coverage for backup email validation and duplicate handling.

Exit criteria:

- User can manage backup emails without touching team-members pages.

### Phase 4: Organization Directory + Creation

- [x] Add `created_by_user_id` migration for `console_organizations`.
- [x] Reuse the existing onboarding organization bootstrap path as the canonical org-creation path for account settings.
- [x] Implement `GET/POST /console/account/organizations` for “organizations created by me” on top of that shared org-creation path.
- [x] Implement account page organizations list and create organization form.
- [x] Preserve current owner bootstrap and audit behavior when account settings creates an organization.
- [ ] Add Postgres-backed tenant-safe query coverage and finish browser verification for org-creation wiring once the dashboard harness is green.

Exit criteria:

- User can create multiple organizations and see them in account settings.

### Phase 5: Organization Editing + Owner Transfer

- [x] Implement `PATCH /console/account/organizations/:orgId` (rename).
- [x] Implement `DELETE /console/account/organizations/:orgId` for empty-org deletion.
- [x] Implement `POST /console/account/organizations/:orgId/transfer-owner`.
- [x] Add UI actions for rename and transfer owner in org row/details panel.
- [x] Add UI action for owner-only org deletion with empty-org guardrails.
- [x] Reuse existing Team RBAC role semantics; enforce last-owner safety.
- [x] Emit audit events for rename and owner transfer.
- [ ] Finish browser verification for successful transfer and delete flows once the dashboard harness is green; relayer parity coverage now includes successful and blocked delete cases.

Exit criteria:

- Organization rename and owner transfer are fully auditable and role-safe.

### Phase 6: Org Context Switching + Hard Cleanup

- [x] Implement `POST /console/account/organizations/:orgId/switch-context` to refresh active `orgId`/`projectId`/`environmentId` claim context for the target org.
- [x] Wire “Open organization” action from account settings list.
- [x] Clear persisted project/environment selections from the previous org during switch and rehydrate them from the target org session/onboarding state.
- [x] Route switched users to onboarding for incomplete orgs and to the default dashboard route for complete orgs.
- [ ] Verify downstream `/console/*` routes behave correctly after context switch in the real browser path once the dashboard harness is green.
- [x] Remove dead legacy code paths and obsolete tests tied to team-members modal account settings.
- [ ] Update docs:
  - [x] `docs/saas/dashboard-backend-implementation-plan.md` (new account module status)
  - [x] `docs/saas/db-schema.md` (new account/profile/org-created-by fields)

Exit criteria:

- Multi-org account flow works with one canonical context-switch path and no legacy account-settings code.

## Test Plan

- Frontend:
  - e2e API wiring for account menu navigation, account profile updates, organization management, and theme-safe rendering.
- Backend:
  - parser/service unit tests for account module.
  - Express + Cloudflare route parity tests for all `/console/account/*` endpoints.
- Regression:
  - existing team-members/billing flows still pass in current org context after switch-context operations.

## Acceptance Criteria

- `Account Settings` always opens `/dashboard/account-settings`.
- `/dashboard/account-settings` remains accessible even when the active org is still onboarding.
- Account page supports profile editing + backup emails.
- Account page lists organizations created by current user and supports create/rename/transfer owner.
- Account page supports owner-only deletion for empty non-current orgs and blocks deletion when other members or wallets exist.
- User can switch active org context from account settings without leaking stale project/environment scope from the previous org.
- Opening an incomplete org from account settings routes to onboarding; opening a complete org routes to the default dashboard entry.
- No legacy modal-intent account settings path remains in dashboard code.
