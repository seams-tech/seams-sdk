export type ConsoleRouteMethod = 'DELETE' | 'GET' | 'PATCH' | 'POST' | 'PUT';

export type ConsoleRouteRequirement =
  | 'authenticated'
  | 'owner'
  | 'members.read'
  | 'members.manage'
  | 'projects.manage'
  | 'projects.list'
  | 'project.view'
  | 'project.edit'
  | 'billing.view'
  | 'billing.manage'
  | 'platform.support';

export interface ConsoleRouteDefinition {
  readonly id: string;
  readonly surface: 'console';
  readonly method: ConsoleRouteMethod;
  readonly path: string;
  readonly auth: {
    readonly plane: 'console';
    readonly requirement: ConsoleRouteRequirement;
  };
  readonly metering: { readonly kind: 'none' };
  readonly summary: string;
}

type ConsoleRouteTuple = readonly [id: string, method: ConsoleRouteMethod, path: string];

const AUTHENTICATED_ROUTES: readonly ConsoleRouteTuple[] = [
  ['console_session_get', 'GET', '/console/session'],
  ['console_account_profile_get', 'GET', '/console/account/profile'],
  ['console_account_profile_patch', 'PATCH', '/console/account/profile'],
  ['console_account_organizations_list', 'GET', '/console/account/organizations'],
  ['console_account_organizations_create', 'POST', '/console/account/organizations'],
  ['console_org_get', 'GET', '/console/org'],
  [
    'console_account_organizations_switch_context',
    'POST',
    '/console/account/organizations/:orgId/switch-context',
  ],
  [
    'console_account_invitations_accept',
    'POST',
    '/console/account/invitations/:invitationId/accept',
  ],
  [
    'console_account_invitations_decline',
    'POST',
    '/console/account/invitations/:invitationId/decline',
  ],
  ['console_organization_leave', 'POST', '/console/organization/leave'],
  ['console_onboarding_state_get', 'GET', '/console/onboarding/state'],
  ['console_onboarding_organization_create', 'POST', '/console/onboarding/organization'],
];

const OWNER_ROUTES: readonly ConsoleRouteTuple[] = [
  ['console_account_organizations_delete', 'DELETE', '/console/account/organizations/:orgId'],
  [
    'console_organization_membership_change_role',
    'POST',
    '/console/organization/memberships/:membershipId/change-role',
  ],
  [
    'console_organization_membership_admin_permissions',
    'PATCH',
    '/console/organization/memberships/:membershipId/admin-permissions',
  ],
  ['console_enterprise_isolation_trigger', 'POST', '/console/isolation/trigger'],
];

const MEMBERS_READ_ROUTES: readonly ConsoleRouteTuple[] = [
  ['console_organization_memberships_list', 'GET', '/console/organization/memberships'],
  ['console_organization_invitations_list', 'GET', '/console/organization/invitations'],
];

const MEMBERS_MANAGE_ROUTES: readonly ConsoleRouteTuple[] = [
  ['console_organization_invitations_create', 'POST', '/console/organization/invitations'],
  [
    'console_organization_invitations_resend',
    'POST',
    '/console/organization/invitations/:invitationId/resend',
  ],
  [
    'console_organization_invitations_revoke',
    'DELETE',
    '/console/organization/invitations/:invitationId',
  ],
  [
    'console_organization_membership_suspend',
    'POST',
    '/console/organization/memberships/:membershipId/suspend',
  ],
  [
    'console_organization_membership_reactivate',
    'POST',
    '/console/organization/memberships/:membershipId/reactivate',
  ],
  [
    'console_organization_membership_remove',
    'DELETE',
    '/console/organization/memberships/:membershipId',
  ],
];

const PROJECTS_MANAGE_ROUTES: readonly ConsoleRouteTuple[] = [
  ['console_account_organizations_update', 'PATCH', '/console/account/organizations/:orgId'],
  ['console_onboarding_project_create', 'POST', '/console/onboarding/project'],
  ['console_projects_create', 'POST', '/console/projects'],
  ['console_projects_update', 'PATCH', '/console/projects/:id'],
  ['console_projects_archive', 'POST', '/console/projects/:id/archive'],
  ['console_environments_create', 'POST', '/console/environments'],
  ['console_environments_update', 'PATCH', '/console/environments/:id'],
  ['console_environments_archive', 'POST', '/console/environments/:id/archive'],
  ['console_tenant_root_create', 'POST', '/console/tenant-root/creation'],
  [
    'console_organization_project_member_access_set',
    'PUT',
    '/console/organization/projects/:projectId/members/:membershipId',
  ],
  [
    'console_organization_project_member_access_remove',
    'DELETE',
    '/console/organization/projects/:projectId/members/:membershipId',
  ],
];

const PROJECT_VIEW_ROUTES: readonly ConsoleRouteTuple[] = [
  ['console_environments_list', 'GET', '/console/environments'],
  ['console_approvals_list', 'GET', '/console/approvals'],
  ['console_approvals_get', 'GET', '/console/approvals/:id'],
  ['console_audit_events_list', 'GET', '/console/audit/events'],
  ['console_audit_evidence_list', 'GET', '/console/audit/evidence'],
  ['console_audit_exports_list', 'GET', '/console/audit/exports'],
  ['console_audit_exports_get', 'GET', '/console/audit/exports/:id'],
  ['console_isolation_status_get', 'GET', '/console/isolation/status'],
  ['console_wallets_list', 'GET', '/console/wallets'],
  ['console_wallets_search', 'GET', '/console/wallets/search'],
  ['console_wallets_get', 'GET', '/console/wallets/:id'],
  ['console_wallet_balances_refresh', 'POST', '/console/wallets/balances/refresh'],
  ['console_policies_list', 'GET', '/console/policies'],
  ['console_policy_versions_list', 'GET', '/console/policies/:id/versions'],
  ['console_policy_assignments_list', 'GET', '/console/policies/assignments'],
  ['console_policies_simulate', 'POST', '/console/policies/:id/simulate'],
  ['console_observability_summary_get', 'GET', '/console/observability/summary'],
  ['console_observability_events_list', 'GET', '/console/observability/events'],
  ['console_observability_timeseries_get', 'GET', '/console/observability/timeseries'],
  ['console_observability_services_list', 'GET', '/console/observability/services'],
  ['console_policy_coverage_get', 'GET', '/console/policy/coverage'],
  ['console_gas_readiness_get', 'GET', '/console/gas/readiness'],
  ['console_export_governance_get', 'GET', '/console/export/governance'],
  ['console_webhooks_list', 'GET', '/console/webhooks'],
  ['console_webhooks_deliveries_list', 'GET', '/console/webhooks/:id/deliveries'],
  ['console_webhooks_attempts_list', 'GET', '/console/webhooks/:id/attempts'],
  ['console_webhooks_dead_letters_list', 'GET', '/console/webhooks/:id/dead-letters'],
  ['console_key_exports_list', 'GET', '/console/key-exports'],
  ['console_runtime_snapshots_list', 'GET', '/console/runtime-snapshots'],
  ['console_runtime_snapshots_latest_get', 'GET', '/console/runtime-snapshots/latest'],
  ['console_api_keys_list', 'GET', '/console/api-keys'],
];

const PROJECT_LIST_ROUTES: readonly ConsoleRouteTuple[] = [
  ['console_projects_list', 'GET', '/console/projects'],
];

const PROJECT_EDIT_ROUTES: readonly ConsoleRouteTuple[] = [
  ['console_approvals_create', 'POST', '/console/approvals'],
  ['console_approvals_approve', 'POST', '/console/approvals/:id/approve'],
  ['console_approvals_reject', 'POST', '/console/approvals/:id/reject'],
  ['console_audit_exports_create', 'POST', '/console/audit/exports'],
  ['console_policies_create', 'POST', '/console/policies'],
  ['console_policy_assignments_upsert', 'PUT', '/console/policies/assignments'],
  ['console_policy_assignments_delete', 'DELETE', '/console/policies/assignments/:id'],
  ['console_policies_update', 'PATCH', '/console/policies/:id'],
  ['console_policies_delete', 'DELETE', '/console/policies/:id'],
  ['console_policies_publish', 'POST', '/console/policies/:id/publish'],
  ['console_webhooks_create', 'POST', '/console/webhooks'],
  ['console_webhooks_update', 'PATCH', '/console/webhooks/:id'],
  ['console_webhooks_delete', 'DELETE', '/console/webhooks/:id'],
  ['console_webhooks_replay', 'POST', '/console/webhooks/:id/replay'],
  ['console_webhooks_rotate_secret', 'POST', '/console/webhooks/:id/rotate-secret'],
  ['console_key_exports_create', 'POST', '/console/key-exports'],
  ['console_key_exports_approve', 'POST', '/console/key-exports/:id/approve'],
  ['console_runtime_snapshots_publish', 'POST', '/console/runtime-snapshots/publish'],
  [
    'console_runtime_snapshots_publish_current',
    'POST',
    '/console/runtime-snapshots/publish-current',
  ],
  ['console_api_keys_create', 'POST', '/console/api-keys'],
  ['console_api_keys_revoke', 'DELETE', '/console/api-keys/:id'],
  ['console_api_keys_purge', 'DELETE', '/console/api-keys/:id/purge'],
  ['console_api_keys_update', 'PATCH', '/console/api-keys/:id'],
  ['console_api_keys_rotate', 'POST', '/console/api-keys/:id/rotate'],
];

const BILLING_VIEW_ROUTES: readonly ConsoleRouteTuple[] = [
  ['console_billing_overview_get', 'GET', '/console/billing/overview'],
  ['console_billing_account_activity_get', 'GET', '/console/billing/account/activity'],
  ['console_billing_sponsored_executions_get', 'GET', '/console/billing/sponsored-executions'],
  [
    'console_billing_sponsored_executions_reconciliation_get',
    'GET',
    '/console/billing/sponsored-executions/reconciliation',
  ],
  ['console_billing_invoices_list', 'GET', '/console/billing/invoices'],
  ['console_billing_invoices_get', 'GET', '/console/billing/invoices/:id'],
  ['console_billing_invoices_pdf_get', 'GET', '/console/billing/invoices/:id/pdf'],
  ['console_billing_invoices_activity_get', 'GET', '/console/billing/invoices/:id/activity'],
  ['console_billing_invoices_line_items_get', 'GET', '/console/billing/invoices/:id/line-items'],
  [
    'console_billing_usage_monthly_active_wallets',
    'GET',
    '/console/billing/usage/monthly-active-wallets',
  ],
  ['console_billing_refunds_list', 'GET', '/console/billing/refunds'],
];

const BILLING_MANAGE_ROUTES: readonly ConsoleRouteTuple[] = [
  [
    'console_billing_stripe_checkout_session_create',
    'POST',
    '/console/billing/stripe/checkout-session',
  ],
  [
    'console_billing_stripe_checkout_session_reconcile',
    'POST',
    '/console/billing/stripe/checkout-session/reconcile',
  ],
];

const PLATFORM_SUPPORT_ROUTES: readonly ConsoleRouteTuple[] = [
  ['console_onboarding_telemetry_get', 'GET', '/console/onboarding/telemetry'],
  ['console_ops_cockpit_summary_get', 'GET', '/console/ops-cockpit/summary'],
  ['console_platform_billing_search_get', 'GET', '/console/platform/billing/search'],
  ['console_platform_billing_account_get', 'GET', '/console/platform/billing/account'],
  ['console_billing_usage_events_record', 'POST', '/console/billing/usage/events'],
  ['console_billing_invoices_generate', 'POST', '/console/billing/invoices/generate'],
  [
    'console_billing_adjustments_support_credit',
    'POST',
    '/console/billing/adjustments/support-credit',
  ],
  ['console_billing_adjustments_admin_debit', 'POST', '/console/billing/adjustments/admin-debit'],
  [
    'console_platform_billing_adjustments_support_credit',
    'POST',
    '/console/platform/billing/adjustments/support-credit',
  ],
  [
    'console_platform_billing_adjustments_admin_debit',
    'POST',
    '/console/platform/billing/adjustments/admin-debit',
  ],
  ['console_platform_billing_refunds_create', 'POST', '/console/platform/billing/refunds'],
  [
    'console_platform_billing_refunds_reconcile',
    'POST',
    '/console/platform/billing/refunds/reconcile',
  ],
];

function routeSummary(id: string): string {
  return id
    .replace(/^console_/u, '')
    .split('_')
    .join(' ');
}

function appendRoutes(
  output: ConsoleRouteDefinition[],
  requirement: ConsoleRouteRequirement,
  tuples: readonly ConsoleRouteTuple[],
): void {
  for (const [id, method, path] of tuples) {
    output.push(
      Object.freeze({
        id,
        surface: 'console',
        method,
        path,
        auth: Object.freeze({ plane: 'console', requirement }),
        metering: Object.freeze({ kind: 'none' }),
        summary: routeSummary(id),
      }),
    );
  }
}

export function createConsoleRouteDefinitions(): readonly ConsoleRouteDefinition[] {
  const definitions: ConsoleRouteDefinition[] = [];
  appendRoutes(definitions, 'authenticated', AUTHENTICATED_ROUTES);
  appendRoutes(definitions, 'owner', OWNER_ROUTES);
  appendRoutes(definitions, 'members.read', MEMBERS_READ_ROUTES);
  appendRoutes(definitions, 'members.manage', MEMBERS_MANAGE_ROUTES);
  appendRoutes(definitions, 'projects.manage', PROJECTS_MANAGE_ROUTES);
  appendRoutes(definitions, 'projects.list', PROJECT_LIST_ROUTES);
  appendRoutes(definitions, 'project.view', PROJECT_VIEW_ROUTES);
  appendRoutes(definitions, 'project.edit', PROJECT_EDIT_ROUTES);
  appendRoutes(definitions, 'billing.view', BILLING_VIEW_ROUTES);
  appendRoutes(definitions, 'billing.manage', BILLING_MANAGE_ROUTES);
  appendRoutes(definitions, 'platform.support', PLATFORM_SUPPORT_ROUTES);
  return Object.freeze(definitions);
}

function matchesPathPattern(pattern: string, pathname: string): boolean {
  const patternSegments = pattern.split('/').filter(Boolean);
  const pathnameSegments = pathname.split('/').filter(Boolean);
  if (patternSegments.length !== pathnameSegments.length) return false;
  for (let index = 0; index < patternSegments.length; index += 1) {
    const patternSegment = patternSegments[index];
    const pathnameSegment = pathnameSegments[index];
    if (!patternSegment || !pathnameSegment) return false;
    if (!patternSegment.startsWith(':') && patternSegment !== pathnameSegment) return false;
  }
  return true;
}

export function findConsoleRouteDefinitionForRequest(
  definitions: readonly ConsoleRouteDefinition[],
  method: string,
  pathname: string,
): ConsoleRouteDefinition | null {
  const normalizedMethod = method.trim().toUpperCase();
  const normalizedPathname = pathname.trim();
  for (const definition of definitions) {
    if (definition.method !== normalizedMethod) continue;
    if (matchesPathPattern(definition.path, normalizedPathname)) return definition;
  }
  return null;
}
