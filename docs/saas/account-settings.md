# Account Settings

Date updated: July 26, 2026

## Objective

Keep personal account settings and organization switching in one dashboard page at
`/dashboard/account-settings`. Organization ownership and member administration live
in the Team page under the shared organization-access model.

## Product Model

- A user profile is independent from organization membership.
- The organization directory lists organizations where the user has an active
  membership.
- An organization has one or more equal owners. The dashboard recommends two.
- Ownership handoff invites or promotes the successor to owner first. The former
  owner can then change role or leave while another owner remains.
- There is no ownership-transfer endpoint or primary-owner field.
- `created_by_user_id` remains organization provenance. It does not grant access.

## Account Routes

- `GET /console/account/profile`
- `PATCH /console/account/profile`
- `GET /console/account/organizations`
- `POST /console/account/organizations`
- `PATCH /console/account/organizations/:orgId`
- `DELETE /console/account/organizations/:orgId`
- `POST /console/account/organizations/:orgId/switch-context`

Ownership and membership changes use:

- `GET /console/organization/memberships`
- `GET/POST /console/organization/invitations`
- `POST /console/organization/memberships/:membershipId/change-role`
- `POST /console/organization/leave`

## Dashboard Behavior

The page contains:

1. Profile display name, primary email, and backup emails.
2. Organizations where the user has an active membership.
3. Create, open, rename, and eligible delete actions.

Opening an organization refreshes the server-issued organization, project, environment,
membership, role, permission, project-access, and authorization-version claims
together. An incomplete organization opens onboarding; a complete organization opens
the dashboard.

The page remains reachable while onboarding is incomplete. The topbar Account Settings
action always routes to this page.

## Authorization

- Active membership is required to list or open an organization.
- Owners can rename an organization.
- Administrators with `projects.manage` can rename an organization.
- Organization deletion is owner-only and requires a non-current organization with no
  other current members and no wallets.
- Organization creation uses the onboarding bootstrap service, which creates the first
  owner and owner-anchor invariant in the same flow.
- Session refresh rejects stale authorization versions after access changes.

## Persistence

- `user_profiles`
- `user_backup_emails`
- `organizations.created_by_user_id`
- `organization_memberships`
- `organization_admin_permissions`
- `project_member_access`

Organization directory queries join active memberships. They do not infer access from
`created_by_user_id`.

## Implementation Status

- The dedicated route, sidebar entry, and topbar navigation are implemented.
- Profile and backup-email persistence and UI are implemented.
- Organization create, list, rename, delete, open, and context switching are
  implemented for Express and Cloudflare.
- Organization creation shares the onboarding owner-bootstrap path.
- The legacy transfer-owner route and UI are removed.
- Focused route tests cover organization visibility, context refresh, deletion
  guardrails, and the absence of the retired transfer route.

## Validation

- Account directory returns only organizations with active membership.
- Switching organizations cannot retain project or environment scope from the previous
  organization.
- Ownership changes preserve at least one owner.
- A user with removed or suspended membership cannot reopen the organization.
- OIDC-managed primary email remains read-only.
