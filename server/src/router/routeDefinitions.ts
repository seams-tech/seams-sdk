import { DEFAULT_SPONSORED_EVM_CALL_ROUTE } from '../sponsorship/evmRelay';
import {
  buildPrfSessionSealApplyPath,
  buildPrfSessionSealRemovePath,
  resolvePrfSessionSealBasePath,
} from '../threshold/session/prfSessionSeal';
import {
  API_CREDENTIAL_ROUTE_SCOPES,
  API_CREDENTIAL_TYPES,
  PUBLIC_PROOF_TYPES,
  type RouteAuthPolicy,
} from './routeAuthPolicy';
import {
  ROUTE_SERVICE_KEYS,
  type RouteMethod,
  type RouteServiceKey,
} from './routeExecutionContext';
import type { RouteMeteringPolicy } from './routeMeteringPolicy';

export interface RouteDefinition {
  id: string;
  surface: 'console' | 'relay';
  method: RouteMethod;
  path: string;
  aliases?: readonly string[];
  auth: RouteAuthPolicy;
  metering: RouteMeteringPolicy;
  requiredServices?: readonly RouteServiceKey[];
  summary: string;
}

export interface RelayRouteDefinitionOptions {
  enableHealthz?: boolean;
  enablePrfSessionSeal?: boolean;
  enableReadyz?: boolean;
  enableSponsoredEvmCall?: boolean;
  prfSessionSealBasePath?: string;
  sessionStatePath?: string;
  signedDelegatePath?: string;
  sponsoredEvmCallPath?: string;
}

const CONSOLE_CONFIG_MUTATION_ROLES: NonNullable<
  Extract<RouteAuthPolicy, { plane: 'console' }>['roles']
> = ['owner', 'admin', 'security_admin'];
const CONSOLE_ORG_PROJECT_ENV_MUTATION_ROLES: NonNullable<
  Extract<RouteAuthPolicy, { plane: 'console' }>['roles']
> = ['owner', 'admin'];
const CONSOLE_BILLING_OPERATOR_ROLES: NonNullable<
  Extract<RouteAuthPolicy, { plane: 'console' }>['roles']
> = ['admin', 'ops'];
const CONSOLE_TEAM_RBAC_MUTATION_ROLES: NonNullable<
  Extract<RouteAuthPolicy, { plane: 'console' }>['roles']
> = ['owner', 'admin'];
const CONSOLE_APPROVAL_MUTATION_ROLES: NonNullable<
  Extract<RouteAuthPolicy, { plane: 'console' }>['roles']
> = ['owner', 'admin', 'security_admin'];
const CONSOLE_POLICY_MUTATION_ROLES: NonNullable<
  Extract<RouteAuthPolicy, { plane: 'console' }>['roles']
> = ['owner', 'admin', 'security_admin'];
const CONSOLE_KEY_EXPORT_REQUEST_ROLES: NonNullable<
  Extract<RouteAuthPolicy, { plane: 'console' }>['roles']
> = ['owner', 'admin', 'security_admin'];
const CONSOLE_KEY_EXPORT_APPROVAL_ROLES: NonNullable<
  Extract<RouteAuthPolicy, { plane: 'console' }>['roles']
> = ['admin'];
const CONSOLE_API_KEY_MUTATION_ROLES: NonNullable<
  Extract<RouteAuthPolicy, { plane: 'console' }>['roles']
> = ['owner', 'admin', 'security_admin'];
const CONSOLE_ENTERPRISE_ISOLATION_MUTATION_ROLES: NonNullable<
  Extract<RouteAuthPolicy, { plane: 'console' }>['roles']
> = ['owner', 'admin'];
const CONSOLE_INVOICE_GENERATION_ROLES: NonNullable<
  Extract<RouteAuthPolicy, { plane: 'console' }>['roles']
> = ['admin', 'ops'];
const CONSOLE_PLATFORM_BILLING_ADJUSTMENT_ROLES: NonNullable<
  Extract<RouteAuthPolicy, { plane: 'console' }>['roles']
> = ['platform_admin'];
const CONSOLE_ONBOARDING_TELEMETRY_READ_ROLES: NonNullable<
  Extract<RouteAuthPolicy, { plane: 'console' }>['roles']
> = ['admin', 'ops'];
const CONSOLE_OPS_COCKPIT_READ_ROLES: NonNullable<
  Extract<RouteAuthPolicy, { plane: 'console' }>['roles']
> = ['owner', 'admin', 'security_admin', 'ops'];
const CONSOLE_AUDIT_READ_ROLES: NonNullable<
  Extract<RouteAuthPolicy, { plane: 'console' }>['roles']
> = ['owner', 'admin', 'security_admin', 'ops'];
const CONSOLE_WALLET_READ_ROLES: NonNullable<
  Extract<RouteAuthPolicy, { plane: 'console' }>['roles']
> = ['owner', 'admin', 'security_admin', 'ops', 'support'];
const CONSOLE_BILLING_READ_ROLES: NonNullable<
  Extract<RouteAuthPolicy, { plane: 'console' }>['roles']
> = ['owner', 'admin', 'billing_admin', 'ops'];
const CONSOLE_OBSERVABILITY_READ_ROLES: NonNullable<
  Extract<RouteAuthPolicy, { plane: 'console' }>['roles']
> = ['owner', 'admin', 'security_admin', 'ops', 'support'];
const API_CREDENTIAL_TYPE_SET = new Set<string>(API_CREDENTIAL_TYPES);
const API_CREDENTIAL_ROUTE_SCOPE_SET = new Set<string>(API_CREDENTIAL_ROUTE_SCOPES);
const PUBLIC_PROOF_TYPE_SET = new Set<string>(PUBLIC_PROOF_TYPES);
const ROUTE_SERVICE_KEY_SET = new Set<string>(ROUTE_SERVICE_KEYS);

function normalizeAliases(
  path: string,
  aliases: readonly string[] | undefined,
): readonly string[] | undefined {
  if (!aliases || aliases.length === 0) return undefined;
  const seen = new Set<string>();
  const next: string[] = [];
  for (const alias of aliases) {
    const value = String(alias || '').trim();
    if (!value || value === path || seen.has(value)) continue;
    seen.add(value);
    next.push(value);
  }
  return next.length > 0 ? next : undefined;
}

function normalizeRequiredServices(
  id: string,
  requiredServices: readonly RouteServiceKey[] | undefined,
): readonly RouteServiceKey[] | undefined {
  if (!requiredServices || requiredServices.length === 0) return undefined;
  const seen = new Set<string>();
  const next: RouteServiceKey[] = [];
  for (const requiredService of requiredServices) {
    const value = String(requiredService || '').trim();
    if (!value) {
      throw new Error(`route definition requiredServices must contain non-empty values for ${id}`);
    }
    if (!ROUTE_SERVICE_KEY_SET.has(value)) {
      throw new Error(
        `route definition requiredServices contains unknown service ${value} for ${id}`,
      );
    }
    if (seen.has(value)) continue;
    seen.add(value);
    next.push(value as RouteServiceKey);
  }
  return next.length > 0 ? next : undefined;
}

function normalizeAuthPolicy(id: string, auth: RouteAuthPolicy): RouteAuthPolicy {
  switch (auth.plane) {
    case 'api_credentials': {
      const seenCredentials = new Set<string>();
      const credentials = auth.credentials
        .map((credential) => String(credential || '').trim())
        .filter(Boolean)
        .filter((credential) => {
          if (!API_CREDENTIAL_TYPE_SET.has(credential)) {
            throw new Error(
              `route definition api_credentials auth contains unknown credential ${credential} for ${id}`,
            );
          }
          if (seenCredentials.has(credential)) return false;
          seenCredentials.add(credential);
          return true;
        }) as Extract<RouteAuthPolicy, { plane: 'api_credentials' }>['credentials'];
      if (credentials.length === 0) {
        throw new Error(
          `route definition api_credentials auth must declare at least one credential for ${id}`,
        );
      }

      let scopes: Extract<RouteAuthPolicy, { plane: 'api_credentials' }>['scopes'] | undefined;
      if (auth.scopes && auth.scopes.length > 0) {
        const seenScopes = new Set<string>();
        scopes = auth.scopes
          .map((scope) => String(scope || '').trim())
          .filter(Boolean)
          .filter((scope) => {
            if (!API_CREDENTIAL_ROUTE_SCOPE_SET.has(scope)) {
              throw new Error(
                `route definition api_credentials auth contains unknown scope ${scope} for ${id}`,
              );
            }
            if (seenScopes.has(scope)) return false;
            seenScopes.add(scope);
            return true;
          }) as Extract<RouteAuthPolicy, { plane: 'api_credentials' }>['scopes'];
        if (!scopes || scopes.length === 0) scopes = undefined;
      }

      return {
        ...auth,
        credentials,
        ...(scopes ? { scopes } : {}),
      };
    }
    case 'public': {
      const rationale = String(auth.rationale || '').trim();
      if (!rationale) {
        throw new Error(`route definition public auth rationale is required for ${id}`);
      }
      const proof = auth.proof ? String(auth.proof || '').trim() : '';
      if (proof && !PUBLIC_PROOF_TYPE_SET.has(proof)) {
        throw new Error(`route definition public auth contains unknown proof ${proof} for ${id}`);
      }
      return {
        ...auth,
        rationale,
        ...(proof
          ? { proof: proof as Extract<RouteAuthPolicy, { plane: 'public' }>['proof'] }
          : {}),
      };
    }
    default:
      return auth;
  }
}

export function defineRoute(definition: RouteDefinition): RouteDefinition {
  const id = String(definition.id || '').trim();
  const path = String(definition.path || '').trim();
  const summary = String(definition.summary || '').trim();
  if (!id) throw new Error('route definition id is required');
  if (!path) throw new Error(`route definition path is required for ${id}`);
  if (!path.startsWith('/')) throw new Error(`route definition path must start with / for ${id}`);
  if (!summary) throw new Error(`route definition summary is required for ${id}`);
  const aliases = normalizeAliases(path, definition.aliases);
  return Object.freeze({
    ...definition,
    auth: normalizeAuthPolicy(id, definition.auth),
    id,
    path,
    aliases,
    summary,
    requiredServices: normalizeRequiredServices(id, definition.requiredServices),
  });
}

export function findRouteDefinitionById(
  definitions: readonly RouteDefinition[],
  id: string,
): RouteDefinition | null {
  const normalizedId = String(id || '').trim();
  if (!normalizedId) return null;
  for (const definition of definitions) {
    if (definition.id === normalizedId) return definition;
  }
  return null;
}

function matchesPathPattern(pattern: string, pathname: string): boolean {
  const normalizedPattern = String(pattern || '').trim();
  const normalizedPathname = String(pathname || '').trim();
  if (!normalizedPattern || !normalizedPathname) return false;
  if (normalizedPattern === normalizedPathname) return true;

  const patternSegments = normalizedPattern.split('/').filter(Boolean);
  const pathnameSegments = normalizedPathname.split('/').filter(Boolean);
  if (patternSegments.length !== pathnameSegments.length) return false;

  for (let index = 0; index < patternSegments.length; index += 1) {
    const patternSegment = patternSegments[index];
    const pathnameSegment = pathnameSegments[index];
    if (!patternSegment || !pathnameSegment) return false;
    if (patternSegment.startsWith(':')) continue;
    if (patternSegment !== pathnameSegment) return false;
  }
  return true;
}

export function matchesRouteDefinitionRequest(
  route: RouteDefinition,
  method: string,
  pathname: string,
): boolean {
  const normalizedMethod = String(method || '')
    .trim()
    .toUpperCase();
  if (route.method !== normalizedMethod) return false;
  if (matchesPathPattern(route.path, pathname)) return true;
  for (const alias of route.aliases || []) {
    if (matchesPathPattern(alias, pathname)) return true;
  }
  return false;
}

export function findRouteDefinitionForRequest(
  definitions: readonly RouteDefinition[],
  method: string,
  pathname: string,
): RouteDefinition | null {
  for (const definition of definitions) {
    if (matchesRouteDefinitionRequest(definition, method, pathname)) return definition;
  }
  return null;
}

function publicRoute(
  id: string,
  method: RouteMethod,
  path: string,
  summary: string,
  proof: RouteAuthPolicy & { plane: 'public' },
  requiredServices?: readonly RouteServiceKey[],
  metering: RouteMeteringPolicy = { kind: 'none' },
  aliases?: readonly string[],
): RouteDefinition {
  return defineRoute({
    id,
    surface: 'relay',
    method,
    path,
    aliases,
    auth: proof,
    metering,
    requiredServices,
    summary,
  });
}

function userSessionRoute(
  id: string,
  method: RouteMethod,
  path: string,
  summary: string,
  requiredServices?: readonly RouteServiceKey[],
  aliases?: readonly string[],
): RouteDefinition {
  return defineRoute({
    id,
    surface: 'relay',
    method,
    path,
    aliases,
    auth: { plane: 'user_session' },
    metering: { kind: 'none' },
    requiredServices,
    summary,
  });
}

function thresholdSessionRoute(
  id: string,
  method: RouteMethod,
  path: string,
  summary: string,
  scheme: 'any' | 'ecdsa' | 'ed25519',
  requiredServices?: readonly RouteServiceKey[],
): RouteDefinition {
  return defineRoute({
    id,
    surface: 'relay',
    method,
    path,
    auth: { plane: 'threshold_session', scheme },
    metering: { kind: 'none' },
    requiredServices,
    summary,
  });
}

function apiCredentialRoute(
  id: string,
  method: RouteMethod,
  path: string,
  summary: string,
  auth: Extract<RouteAuthPolicy, { plane: 'api_credentials' }>,
  metering: RouteMeteringPolicy,
  requiredServices?: readonly RouteServiceKey[],
): RouteDefinition {
  return defineRoute({
    id,
    surface: 'relay',
    method,
    path,
    auth,
    metering,
    requiredServices,
    summary,
  });
}

function consoleRoute(
  id: string,
  method: RouteMethod,
  path: string,
  summary: string,
  options: {
    aliases?: readonly string[];
    forbiddenMessage?: string;
    requiredServices?: readonly RouteServiceKey[];
    roles?: Extract<RouteAuthPolicy, { plane: 'console' }>['roles'];
  } = {},
): RouteDefinition {
  return defineRoute({
    id,
    surface: 'console',
    method,
    path,
    aliases: options.aliases,
    auth: {
      plane: 'console',
      ...(options.roles && options.roles.length > 0 ? { roles: [...options.roles] } : {}),
      ...(options.forbiddenMessage ? { forbiddenMessage: options.forbiddenMessage } : {}),
    },
    metering: { kind: 'none' },
    requiredServices: options.requiredServices,
    summary,
  });
}

export function createConsoleRouteDefinitions(): RouteDefinition[] {
  return [
    consoleRoute('console_session_get', 'GET', '/console/session', 'Read console session'),
    consoleRoute(
      'console_account_profile_get',
      'GET',
      '/console/account/profile',
      'Read account profile',
      {
        requiredServices: ['account'],
      },
    ),
    consoleRoute(
      'console_account_profile_patch',
      'PATCH',
      '/console/account/profile',
      'Update account profile',
      {
        requiredServices: ['account'],
      },
    ),
    consoleRoute(
      'console_account_organizations_list',
      'GET',
      '/console/account/organizations',
      'List account organizations',
      {
        requiredServices: ['account'],
      },
    ),
    consoleRoute(
      'console_account_organizations_create',
      'POST',
      '/console/account/organizations',
      'Create account organization',
      {
        requiredServices: ['account'],
      },
    ),
    consoleRoute(
      'console_account_organizations_update',
      'PATCH',
      '/console/account/organizations/:orgId',
      'Update account organization',
      {
        requiredServices: ['account'],
      },
    ),
    consoleRoute(
      'console_account_organizations_delete',
      'DELETE',
      '/console/account/organizations/:orgId',
      'Delete account organization',
      {
        requiredServices: ['account'],
      },
    ),
    consoleRoute(
      'console_account_organizations_transfer_owner',
      'POST',
      '/console/account/organizations/:orgId/transfer-owner',
      'Transfer account organization owner',
      {
        requiredServices: ['account'],
      },
    ),
    consoleRoute(
      'console_account_organizations_switch_context',
      'POST',
      '/console/account/organizations/:orgId/switch-context',
      'Switch account organization context',
      {
        requiredServices: ['account', 'session'],
      },
    ),
    consoleRoute(
      'console_onboarding_state_get',
      'GET',
      '/console/onboarding/state',
      'Read onboarding state',
      {
        requiredServices: ['onboarding'],
      },
    ),
    consoleRoute(
      'console_onboarding_telemetry_get',
      'GET',
      '/console/onboarding/telemetry',
      'Read onboarding telemetry',
      {
        roles: CONSOLE_ONBOARDING_TELEMETRY_READ_ROLES,
        forbiddenMessage: 'Only admin or ops can view onboarding telemetry',
        requiredServices: ['onboarding'],
      },
    ),
    consoleRoute(
      'console_ops_cockpit_summary_get',
      'GET',
      '/console/ops-cockpit/summary',
      'Read ops cockpit summary',
      {
        roles: CONSOLE_OPS_COCKPIT_READ_ROLES,
        forbiddenMessage: 'Only owner, admin, security_admin, or ops can view ops cockpit',
      },
    ),
    consoleRoute('console_org_get', 'GET', '/console/org', 'Read organization', {
      requiredServices: ['orgProjectEnv'],
    }),
    consoleRoute('console_projects_list', 'GET', '/console/projects', 'List projects', {
      requiredServices: ['orgProjectEnv'],
    }),
    consoleRoute('console_environments_list', 'GET', '/console/environments', 'List environments', {
      requiredServices: ['orgProjectEnv'],
    }),
    consoleRoute('console_members_list', 'GET', '/console/members', 'List team members', {
      requiredServices: ['teamRbac'],
    }),
    consoleRoute('console_approvals_list', 'GET', '/console/approvals', 'List approval requests', {
      requiredServices: ['approvals'],
    }),
    consoleRoute('console_approvals_get', 'GET', '/console/approvals/:id', 'Get approval request', {
      requiredServices: ['approvals'],
    }),
    consoleRoute('console_audit_events_list', 'GET', '/console/audit/events', 'List audit events', {
      roles: CONSOLE_AUDIT_READ_ROLES,
      forbiddenMessage: 'Only owner, admin, security_admin, or ops can view audit events',
      requiredServices: ['audit'],
    }),
    consoleRoute(
      'console_audit_evidence_list',
      'GET',
      '/console/audit/evidence',
      'List audit evidence',
      {
        roles: CONSOLE_AUDIT_READ_ROLES,
        forbiddenMessage: 'Only owner, admin, security_admin, or ops can view audit evidence',
        requiredServices: ['audit'],
      },
    ),
    consoleRoute(
      'console_audit_exports_list',
      'GET',
      '/console/audit/exports',
      'List audit exports',
      {
        roles: CONSOLE_AUDIT_READ_ROLES,
        forbiddenMessage: 'Only owner, admin, security_admin, or ops can view audit exports',
        requiredServices: ['auditExports'],
      },
    ),
    consoleRoute(
      'console_audit_exports_get',
      'GET',
      '/console/audit/exports/:id',
      'Get audit export',
      {
        roles: CONSOLE_AUDIT_READ_ROLES,
        forbiddenMessage: 'Only owner, admin, security_admin, or ops can view audit exports',
        requiredServices: ['auditExports'],
      },
    ),
    consoleRoute(
      'console_isolation_status_get',
      'GET',
      '/console/isolation/status',
      'Read enterprise isolation status',
      {
        requiredServices: ['enterpriseIsolation'],
      },
    ),
    consoleRoute('console_wallets_list', 'GET', '/console/wallets', 'List wallets', {
      roles: CONSOLE_WALLET_READ_ROLES,
      forbiddenMessage: 'Only owner, admin, security_admin, ops, or support can view wallets',
      requiredServices: ['wallets'],
    }),
    consoleRoute('console_wallets_search', 'GET', '/console/wallets/search', 'Search wallets', {
      roles: CONSOLE_WALLET_READ_ROLES,
      forbiddenMessage: 'Only owner, admin, security_admin, ops, or support can view wallets',
      requiredServices: ['wallets'],
    }),
    consoleRoute('console_wallets_get', 'GET', '/console/wallets/:id', 'Get wallet', {
      roles: CONSOLE_WALLET_READ_ROLES,
      forbiddenMessage: 'Only owner, admin, security_admin, ops, or support can view wallets',
      requiredServices: ['wallets'],
    }),
    consoleRoute('console_policies_list', 'GET', '/console/policies', 'List policies', {
      requiredServices: ['policies'],
    }),
    consoleRoute(
      'console_policy_versions_list',
      'GET',
      '/console/policies/:id/versions',
      'List policy versions',
      {
        requiredServices: ['policies'],
      },
    ),
    consoleRoute(
      'console_policy_assignments_list',
      'GET',
      '/console/policies/assignments',
      'List policy assignments',
      {
        requiredServices: ['policies'],
      },
    ),
    consoleRoute(
      'console_policies_simulate',
      'POST',
      '/console/policies/:id/simulate',
      'Simulate policy',
      {
        requiredServices: ['policies'],
      },
    ),
    consoleRoute(
      'console_observability_summary_get',
      'GET',
      '/console/observability/summary',
      'Read observability summary',
      {
        roles: CONSOLE_OBSERVABILITY_READ_ROLES,
        forbiddenMessage:
          'Only owner, admin, security_admin, ops, or support can view observability',
        requiredServices: ['observability'],
      },
    ),
    consoleRoute(
      'console_observability_events_list',
      'GET',
      '/console/observability/events',
      'List observability events',
      {
        roles: CONSOLE_OBSERVABILITY_READ_ROLES,
        forbiddenMessage:
          'Only owner, admin, security_admin, ops, or support can view observability',
        requiredServices: ['observability'],
      },
    ),
    consoleRoute(
      'console_observability_timeseries_get',
      'GET',
      '/console/observability/timeseries',
      'Read observability timeseries',
      {
        roles: CONSOLE_OBSERVABILITY_READ_ROLES,
        forbiddenMessage:
          'Only owner, admin, security_admin, ops, or support can view observability',
        requiredServices: ['observability'],
      },
    ),
    consoleRoute(
      'console_observability_services_list',
      'GET',
      '/console/observability/services',
      'List observability services',
      {
        roles: CONSOLE_OBSERVABILITY_READ_ROLES,
        forbiddenMessage:
          'Only owner, admin, security_admin, ops, or support can view observability',
        requiredServices: ['observability'],
      },
    ),
    consoleRoute(
      'console_policy_coverage_get',
      'GET',
      '/console/policy/coverage',
      'Read policy coverage',
    ),
    consoleRoute(
      'console_gas_readiness_get',
      'GET',
      '/console/gas/readiness',
      'Read gas readiness',
    ),
    consoleRoute(
      'console_export_governance_get',
      'GET',
      '/console/export/governance',
      'Read export governance',
      {
        requiredServices: ['keyExports'],
      },
    ),
    consoleRoute(
      'console_billing_overview_get',
      'GET',
      '/console/billing/overview',
      'Read billing overview',
      {
        roles: CONSOLE_BILLING_READ_ROLES,
        forbiddenMessage: 'Only owner, admin, billing_admin, or ops can view billing',
        requiredServices: ['billing'],
      },
    ),
    consoleRoute(
      'console_billing_account_activity_get',
      'GET',
      '/console/billing/account/activity',
      'Read billing account activity',
      {
        roles: CONSOLE_BILLING_READ_ROLES,
        forbiddenMessage: 'Only owner, admin, billing_admin, or ops can view billing',
        requiredServices: ['billing'],
      },
    ),
    consoleRoute(
      'console_billing_sponsored_executions_get',
      'GET',
      '/console/billing/sponsored-executions',
      'Read sponsored execution history',
      {
        roles: CONSOLE_BILLING_READ_ROLES,
        forbiddenMessage: 'Only owner, admin, billing_admin, or ops can view billing',
        requiredServices: ['sponsoredCalls'],
      },
    ),
    consoleRoute(
      'console_billing_sponsored_executions_reconciliation_get',
      'GET',
      '/console/billing/sponsored-executions/reconciliation',
      'Read sponsored execution reconciliation',
      {
        roles: CONSOLE_BILLING_READ_ROLES,
        forbiddenMessage: 'Only owner, admin, billing_admin, or ops can view billing',
        requiredServices: ['billing', 'sponsoredCalls'],
      },
    ),
    consoleRoute(
      'console_platform_billing_search_get',
      'GET',
      '/console/platform/billing/search',
      'Search platform billing targets',
      {
        roles: CONSOLE_PLATFORM_BILLING_ADJUSTMENT_ROLES,
        forbiddenMessage: 'Only platform_admin can access platform billing',
        requiredServices: ['orgProjectEnv'],
      },
    ),
    consoleRoute(
      'console_platform_billing_account_get',
      'GET',
      '/console/platform/billing/account',
      'Read platform billing account lookup',
      {
        roles: CONSOLE_PLATFORM_BILLING_ADJUSTMENT_ROLES,
        forbiddenMessage: 'Only platform_admin can access platform billing',
        requiredServices: ['billing', 'orgProjectEnv'],
      },
    ),
    consoleRoute(
      'console_billing_invoices_list',
      'GET',
      '/console/billing/invoices',
      'List billing invoices',
      {
        roles: CONSOLE_BILLING_READ_ROLES,
        forbiddenMessage: 'Only owner, admin, billing_admin, or ops can view billing',
        requiredServices: ['billing'],
      },
    ),
    consoleRoute(
      'console_billing_invoices_get',
      'GET',
      '/console/billing/invoices/:id',
      'Get billing invoice',
      {
        roles: CONSOLE_BILLING_READ_ROLES,
        forbiddenMessage: 'Only owner, admin, billing_admin, or ops can view billing',
        requiredServices: ['billing'],
      },
    ),
    consoleRoute(
      'console_billing_invoices_pdf_get',
      'GET',
      '/console/billing/invoices/:id/pdf',
      'Get billing invoice PDF',
      {
        roles: CONSOLE_BILLING_READ_ROLES,
        forbiddenMessage: 'Only owner, admin, billing_admin, or ops can view billing',
        requiredServices: ['billing'],
      },
    ),
    consoleRoute(
      'console_billing_invoices_activity_get',
      'GET',
      '/console/billing/invoices/:id/activity',
      'Get billing invoice activity',
      {
        roles: CONSOLE_BILLING_READ_ROLES,
        forbiddenMessage: 'Only owner, admin, billing_admin, or ops can view billing',
        requiredServices: ['billing'],
      },
    ),
    consoleRoute(
      'console_billing_invoices_line_items_get',
      'GET',
      '/console/billing/invoices/:id/line-items',
      'Get billing invoice line items',
      {
        roles: CONSOLE_BILLING_READ_ROLES,
        forbiddenMessage: 'Only owner, admin, billing_admin, or ops can view billing',
        requiredServices: ['billing'],
      },
    ),
    consoleRoute(
      'console_billing_stripe_checkout_session_create',
      'POST',
      '/console/billing/stripe/checkout-session',
      'Create Stripe checkout session',
      {
        requiredServices: ['billing'],
      },
    ),
    consoleRoute(
      'console_billing_stripe_checkout_session_reconcile',
      'POST',
      '/console/billing/stripe/checkout-session/reconcile',
      'Reconcile Stripe checkout session',
      {
        requiredServices: ['billing'],
      },
    ),
    consoleRoute(
      'console_onboarding_organization_create',
      'POST',
      '/console/onboarding/organization',
      'Create onboarding organization',
      {
        roles: CONSOLE_ORG_PROJECT_ENV_MUTATION_ROLES,
        forbiddenMessage: 'Only admin or owner can mutate projects and environments',
        requiredServices: ['onboarding'],
      },
    ),
    consoleRoute(
      'console_onboarding_project_create',
      'POST',
      '/console/onboarding/project',
      'Create onboarding project',
      {
        roles: CONSOLE_ORG_PROJECT_ENV_MUTATION_ROLES,
        forbiddenMessage: 'Only admin or owner can mutate projects and environments',
        requiredServices: ['onboarding'],
      },
    ),
    consoleRoute('console_projects_create', 'POST', '/console/projects', 'Create project', {
      roles: CONSOLE_ORG_PROJECT_ENV_MUTATION_ROLES,
      forbiddenMessage: 'Only admin or owner can mutate projects and environments',
      requiredServices: ['orgProjectEnv'],
    }),
    consoleRoute('console_projects_update', 'PATCH', '/console/projects/:id', 'Update project', {
      roles: CONSOLE_ORG_PROJECT_ENV_MUTATION_ROLES,
      forbiddenMessage: 'Only admin or owner can mutate projects and environments',
      requiredServices: ['orgProjectEnv'],
    }),
    consoleRoute(
      'console_projects_archive',
      'POST',
      '/console/projects/:id/archive',
      'Archive project',
      {
        roles: CONSOLE_ORG_PROJECT_ENV_MUTATION_ROLES,
        forbiddenMessage: 'Only admin or owner can mutate projects and environments',
        requiredServices: ['orgProjectEnv'],
      },
    ),
    consoleRoute(
      'console_environments_create',
      'POST',
      '/console/environments',
      'Create environment',
      {
        roles: CONSOLE_ORG_PROJECT_ENV_MUTATION_ROLES,
        forbiddenMessage: 'Only admin or owner can mutate projects and environments',
        requiredServices: ['orgProjectEnv'],
      },
    ),
    consoleRoute(
      'console_environments_update',
      'PATCH',
      '/console/environments/:id',
      'Update environment',
      {
        roles: CONSOLE_ORG_PROJECT_ENV_MUTATION_ROLES,
        forbiddenMessage: 'Only admin or owner can mutate projects and environments',
        requiredServices: ['orgProjectEnv'],
      },
    ),
    consoleRoute(
      'console_environments_archive',
      'POST',
      '/console/environments/:id/archive',
      'Archive environment',
      {
        roles: CONSOLE_ORG_PROJECT_ENV_MUTATION_ROLES,
        forbiddenMessage: 'Only admin or owner can mutate projects and environments',
        requiredServices: ['orgProjectEnv'],
      },
    ),
    consoleRoute(
      'console_members_invite',
      'POST',
      '/console/members/invite',
      'Invite team member',
      {
        roles: CONSOLE_TEAM_RBAC_MUTATION_ROLES,
        forbiddenMessage: 'Only admin or owner can mutate org member roles',
        requiredServices: ['teamRbac'],
      },
    ),
    consoleRoute(
      'console_members_update_roles',
      'PATCH',
      '/console/members/:id/roles',
      'Update team member roles',
      {
        roles: CONSOLE_TEAM_RBAC_MUTATION_ROLES,
        forbiddenMessage: 'Only admin or owner can mutate org member roles',
        requiredServices: ['teamRbac'],
      },
    ),
    consoleRoute('console_members_remove', 'DELETE', '/console/members/:id', 'Remove team member', {
      roles: CONSOLE_TEAM_RBAC_MUTATION_ROLES,
      forbiddenMessage: 'Only admin or owner can mutate org member roles',
      requiredServices: ['teamRbac'],
    }),
    consoleRoute(
      'console_approvals_create',
      'POST',
      '/console/approvals',
      'Create approval request',
      {
        roles: CONSOLE_APPROVAL_MUTATION_ROLES,
        forbiddenMessage: 'Only owner, admin, or security_admin can mutate approval queue requests',
        requiredServices: ['approvals'],
      },
    ),
    consoleRoute(
      'console_approvals_approve',
      'POST',
      '/console/approvals/:id/approve',
      'Approve approval request',
      {
        roles: CONSOLE_APPROVAL_MUTATION_ROLES,
        forbiddenMessage: 'Only owner, admin, or security_admin can mutate approval queue requests',
        requiredServices: ['approvals'],
      },
    ),
    consoleRoute(
      'console_approvals_reject',
      'POST',
      '/console/approvals/:id/reject',
      'Reject approval request',
      {
        roles: CONSOLE_APPROVAL_MUTATION_ROLES,
        forbiddenMessage: 'Only owner, admin, or security_admin can mutate approval queue requests',
        requiredServices: ['approvals'],
      },
    ),
    consoleRoute(
      'console_audit_exports_create',
      'POST',
      '/console/audit/exports',
      'Create audit export',
      {
        roles: CONSOLE_ENTERPRISE_ISOLATION_MUTATION_ROLES,
        forbiddenMessage: 'Only owner or admin can create audit exports',
        requiredServices: ['auditExports'],
      },
    ),
    consoleRoute(
      'console_enterprise_isolation_trigger',
      'POST',
      '/console/isolation/trigger',
      'Trigger enterprise isolation',
      {
        roles: CONSOLE_ENTERPRISE_ISOLATION_MUTATION_ROLES,
        forbiddenMessage: 'Only owner or admin can trigger enterprise isolation',
        requiredServices: ['enterpriseIsolation'],
      },
    ),
    consoleRoute('console_policies_create', 'POST', '/console/policies', 'Create policy', {
      roles: CONSOLE_POLICY_MUTATION_ROLES,
      forbiddenMessage: 'Only owner, admin, or security_admin can mutate policies',
      requiredServices: ['policies'],
    }),
    consoleRoute(
      'console_policy_assignments_upsert',
      'PUT',
      '/console/policies/assignments',
      'Upsert policy assignment',
      {
        roles: CONSOLE_POLICY_MUTATION_ROLES,
        forbiddenMessage: 'Only owner, admin, or security_admin can mutate policies',
        requiredServices: ['policies'],
      },
    ),
    consoleRoute(
      'console_policy_assignments_delete',
      'DELETE',
      '/console/policies/assignments/:id',
      'Delete policy assignment',
      {
        roles: CONSOLE_POLICY_MUTATION_ROLES,
        forbiddenMessage: 'Only owner, admin, or security_admin can mutate policies',
        requiredServices: ['policies'],
      },
    ),
    consoleRoute('console_policies_update', 'PATCH', '/console/policies/:id', 'Update policy', {
      roles: CONSOLE_POLICY_MUTATION_ROLES,
      forbiddenMessage: 'Only owner, admin, or security_admin can mutate policies',
      requiredServices: ['policies'],
    }),
    consoleRoute('console_policies_delete', 'DELETE', '/console/policies/:id', 'Delete policy', {
      roles: CONSOLE_POLICY_MUTATION_ROLES,
      forbiddenMessage: 'Only owner, admin, or security_admin can mutate policies',
      requiredServices: ['policies'],
    }),
    consoleRoute(
      'console_policies_publish',
      'POST',
      '/console/policies/:id/publish',
      'Publish policy',
      {
        roles: CONSOLE_POLICY_MUTATION_ROLES,
        forbiddenMessage: 'Only owner, admin, or security_admin can mutate policies',
        requiredServices: ['policies'],
      },
    ),
    consoleRoute('console_webhooks_list', 'GET', '/console/webhooks', 'List webhook endpoints', {
      requiredServices: ['webhooks'],
    }),
    consoleRoute(
      'console_webhooks_create',
      'POST',
      '/console/webhooks',
      'Create webhook endpoint',
      {
        roles: CONSOLE_CONFIG_MUTATION_ROLES,
        forbiddenMessage: 'Only owner, admin, or security_admin can mutate console configuration',
        requiredServices: ['webhooks'],
      },
    ),
    consoleRoute(
      'console_webhooks_update',
      'PATCH',
      '/console/webhooks/:id',
      'Update webhook endpoint',
      {
        roles: CONSOLE_CONFIG_MUTATION_ROLES,
        forbiddenMessage: 'Only owner, admin, or security_admin can mutate console configuration',
        requiredServices: ['webhooks'],
      },
    ),
    consoleRoute(
      'console_webhooks_delete',
      'DELETE',
      '/console/webhooks/:id',
      'Delete webhook endpoint',
      {
        roles: CONSOLE_CONFIG_MUTATION_ROLES,
        forbiddenMessage: 'Only owner, admin, or security_admin can mutate console configuration',
        requiredServices: ['webhooks'],
      },
    ),
    consoleRoute(
      'console_webhooks_deliveries_list',
      'GET',
      '/console/webhooks/:id/deliveries',
      'List webhook deliveries',
      {
        requiredServices: ['webhooks'],
      },
    ),
    consoleRoute(
      'console_webhooks_attempts_list',
      'GET',
      '/console/webhooks/:id/attempts',
      'List webhook delivery attempts',
      {
        requiredServices: ['webhooks'],
      },
    ),
    consoleRoute(
      'console_webhooks_dead_letters_list',
      'GET',
      '/console/webhooks/:id/dead-letters',
      'List webhook dead letters',
      {
        requiredServices: ['webhooks'],
      },
    ),
    consoleRoute(
      'console_webhooks_replay',
      'POST',
      '/console/webhooks/:id/replay',
      'Replay webhook delivery',
      {
        roles: CONSOLE_CONFIG_MUTATION_ROLES,
        forbiddenMessage: 'Only owner, admin, or security_admin can mutate console configuration',
        requiredServices: ['webhooks'],
      },
    ),
    consoleRoute(
      'console_billing_usage_monthly_active_wallets',
      'GET',
      '/console/billing/usage/monthly-active-wallets',
      'Read monthly active wallet usage',
      {
        roles: CONSOLE_BILLING_READ_ROLES,
        forbiddenMessage: 'Only owner, admin, billing_admin, or ops can view billing',
        requiredServices: ['billing'],
      },
    ),
    consoleRoute(
      'console_billing_usage_events_record',
      'POST',
      '/console/billing/usage/events',
      'Record billing usage event',
      {
        roles: CONSOLE_BILLING_OPERATOR_ROLES,
        forbiddenMessage: 'Only admin or ops can record billing usage events',
        requiredServices: ['billing'],
      },
    ),
    consoleRoute(
      'console_billing_invoices_generate',
      'POST',
      '/console/billing/invoices/generate',
      'Generate monthly invoice',
      {
        roles: CONSOLE_INVOICE_GENERATION_ROLES,
        forbiddenMessage: 'Only admin or ops can generate monthly invoices',
        requiredServices: ['billing'],
      },
    ),
    consoleRoute(
      'console_billing_adjustments_support_credit',
      'POST',
      '/console/billing/adjustments/support-credit',
      'Append support credit adjustment',
      {
        roles: CONSOLE_PLATFORM_BILLING_ADJUSTMENT_ROLES,
        forbiddenMessage: 'Only platform_admin can append manual billing adjustments',
        requiredServices: ['billing'],
      },
    ),
    consoleRoute(
      'console_billing_adjustments_admin_debit',
      'POST',
      '/console/billing/adjustments/admin-debit',
      'Append admin debit adjustment',
      {
        roles: CONSOLE_PLATFORM_BILLING_ADJUSTMENT_ROLES,
        forbiddenMessage: 'Only platform_admin can append manual billing adjustments',
        requiredServices: ['billing'],
      },
    ),
    consoleRoute(
      'console_platform_billing_adjustments_support_credit',
      'POST',
      '/console/platform/billing/adjustments/support-credit',
      'Append platform support credit adjustment',
      {
        roles: CONSOLE_PLATFORM_BILLING_ADJUSTMENT_ROLES,
        forbiddenMessage: 'Only platform_admin can append manual billing adjustments',
        requiredServices: ['billing', 'orgProjectEnv'],
      },
    ),
    consoleRoute(
      'console_platform_billing_adjustments_admin_debit',
      'POST',
      '/console/platform/billing/adjustments/admin-debit',
      'Append platform admin debit adjustment',
      {
        roles: CONSOLE_PLATFORM_BILLING_ADJUSTMENT_ROLES,
        forbiddenMessage: 'Only platform_admin can append manual billing adjustments',
        requiredServices: ['billing', 'orgProjectEnv'],
      },
    ),
    consoleRoute(
      'console_key_exports_list',
      'GET',
      '/console/key-exports',
      'List key export requests',
      {
        requiredServices: ['keyExports'],
      },
    ),
    consoleRoute(
      'console_key_exports_create',
      'POST',
      '/console/key-exports',
      'Create key export request',
      {
        roles: CONSOLE_KEY_EXPORT_REQUEST_ROLES,
        forbiddenMessage: 'Only owner, admin, or security_admin can request key exports',
        requiredServices: ['keyExports'],
      },
    ),
    consoleRoute(
      'console_key_exports_approve',
      'POST',
      '/console/key-exports/:id/approve',
      'Approve key export request',
      {
        roles: CONSOLE_KEY_EXPORT_APPROVAL_ROLES,
        forbiddenMessage: 'Only admin can approve key export requests',
        requiredServices: ['keyExports'],
      },
    ),
    consoleRoute(
      'console_smart_wallets_list',
      'GET',
      '/console/smart-wallets',
      'List smart-wallet configurations',
      {
        requiredServices: ['smartWallets'],
      },
    ),
    consoleRoute(
      'console_smart_wallets_create',
      'POST',
      '/console/smart-wallets',
      'Create smart-wallet configuration',
      {
        roles: CONSOLE_CONFIG_MUTATION_ROLES,
        forbiddenMessage: 'Only owner, admin, or security_admin can mutate console configuration',
        requiredServices: ['smartWallets'],
      },
    ),
    consoleRoute(
      'console_smart_wallets_update',
      'PATCH',
      '/console/smart-wallets/:id',
      'Update smart-wallet configuration',
      {
        roles: CONSOLE_CONFIG_MUTATION_ROLES,
        forbiddenMessage: 'Only owner, admin, or security_admin can mutate console configuration',
        requiredServices: ['smartWallets'],
      },
    ),
    consoleRoute(
      'console_runtime_snapshots_list',
      'GET',
      '/console/runtime-snapshots',
      'List runtime snapshots',
      {
        requiredServices: ['runtimeSnapshots'],
      },
    ),
    consoleRoute(
      'console_runtime_snapshots_latest_get',
      'GET',
      '/console/runtime-snapshots/latest',
      'Get latest runtime snapshot',
      {
        requiredServices: ['runtimeSnapshots'],
      },
    ),
    consoleRoute(
      'console_runtime_snapshots_publish',
      'POST',
      '/console/runtime-snapshots/publish',
      'Publish runtime snapshot',
      {
        roles: CONSOLE_CONFIG_MUTATION_ROLES,
        forbiddenMessage: 'Only owner, admin, or security_admin can mutate console configuration',
        requiredServices: ['runtimeSnapshots'],
      },
    ),
    consoleRoute(
      'console_runtime_snapshots_publish_current',
      'POST',
      '/console/runtime-snapshots/publish-current',
      'Publish current runtime snapshot',
      {
        roles: CONSOLE_CONFIG_MUTATION_ROLES,
        forbiddenMessage: 'Only owner, admin, or security_admin can mutate console configuration',
        requiredServices: ['runtimeSnapshots'],
      },
    ),
    consoleRoute('console_api_keys_list', 'GET', '/console/api-keys', 'List API keys', {
      requiredServices: ['apiKeys'],
    }),
    consoleRoute('console_api_keys_create', 'POST', '/console/api-keys', 'Create API key', {
      roles: CONSOLE_API_KEY_MUTATION_ROLES,
      forbiddenMessage: 'Only owner, admin, or security_admin can mutate API keys',
      requiredServices: ['apiKeys'],
    }),
    consoleRoute('console_api_keys_revoke', 'DELETE', '/console/api-keys/:id', 'Revoke API key', {
      roles: CONSOLE_API_KEY_MUTATION_ROLES,
      forbiddenMessage: 'Only owner, admin, or security_admin can mutate API keys',
      requiredServices: ['apiKeys'],
    }),
    consoleRoute(
      'console_api_keys_purge',
      'DELETE',
      '/console/api-keys/:id/purge',
      'Purge API key',
      {
        roles: CONSOLE_API_KEY_MUTATION_ROLES,
        forbiddenMessage: 'Only owner, admin, or security_admin can mutate API keys',
        requiredServices: ['apiKeys'],
      },
    ),
    consoleRoute('console_api_keys_update', 'PATCH', '/console/api-keys/:id', 'Update API key', {
      roles: CONSOLE_API_KEY_MUTATION_ROLES,
      forbiddenMessage: 'Only owner, admin, or security_admin can mutate API keys',
      requiredServices: ['apiKeys'],
    }),
    consoleRoute(
      'console_api_keys_rotate',
      'POST',
      '/console/api-keys/:id/rotate',
      'Rotate API key',
      {
        roles: CONSOLE_API_KEY_MUTATION_ROLES,
        forbiddenMessage: 'Only owner, admin, or security_admin can mutate API keys',
        requiredServices: ['apiKeys'],
      },
    ),
  ];
}

export function createRelayRouteDefinitions(
  options: RelayRouteDefinitionOptions = {},
): RouteDefinition[] {
  const sessionStatePath = String(options.sessionStatePath || '').trim() || '/session/state';
  const sessionStateAliases =
    sessionStatePath === '/session/state' ? undefined : ['/session/state'];
  const signedDelegatePath = String(options.signedDelegatePath || '').trim();
  const sponsoredEvmCallPath =
    String(options.sponsoredEvmCallPath || '').trim() || DEFAULT_SPONSORED_EVM_CALL_ROUTE;
  const prfBasePath = resolvePrfSessionSealBasePath(options.prfSessionSealBasePath);
  const definitions: RouteDefinition[] = [];

  if (options.enableHealthz) {
    definitions.push(
      publicRoute(
        'relay_healthz',
        'GET',
        '/healthz',
        'Relay health probe',
        { plane: 'public', rationale: 'Health probes are intentionally public diagnostics.' },
        ['authService'],
      ),
    );
  }
  if (options.enableReadyz) {
    definitions.push(
      publicRoute(
        'relay_readyz',
        'GET',
        '/readyz',
        'Relay readiness probe',
        { plane: 'public', rationale: 'Readiness probes are intentionally public diagnostics.' },
        ['authService'],
      ),
    );
  }

  definitions.push(
    publicRoute(
      'relay_well_known_webauthn',
      'GET',
      '/.well-known/webauthn',
      'Related Origin Requests manifest',
      { plane: 'public', rationale: 'Well-known discovery endpoints are intentionally public.' },
      ['authService'],
      { kind: 'none' },
      ['/.well-known/webauthn/'],
    ),
    apiCredentialRoute(
      'registration_bootstrap_grants',
      'POST',
      '/v1/registration/bootstrap-grants',
      'Issue managed registration bootstrap grants',
      {
        plane: 'api_credentials',
        credentials: ['publishable_key'],
        environmentBinding: 'required',
        originBinding: 'required',
      },
      { kind: 'none' },
      ['bootstrapGrantBroker'],
    ),
    apiCredentialRoute(
      'registration_bootstrap',
      'POST',
      '/registration/bootstrap',
      'Create and register a user account',
      {
        plane: 'api_credentials',
        credentials: ['secret_key', 'bootstrap_token'],
        scopes: ['accounts.create'],
        environmentBinding: 'required',
      },
      { kind: 'event', action: 'wallet_created' },
      ['authService'],
    ),
    apiCredentialRoute(
      'registration_threshold_ed25519_hss_prepare',
      'POST',
      '/registration/threshold-ed25519/hss/prepare',
      'Prepare threshold Ed25519 HSS relay ceremony during registration bootstrap',
      {
        plane: 'api_credentials',
        credentials: ['secret_key', 'bootstrap_token'],
        scopes: ['accounts.create'],
        environmentBinding: 'required',
      },
      { kind: 'none' },
      ['authService'],
    ),
    apiCredentialRoute(
      'registration_threshold_ed25519_hss_respond',
      'POST',
      '/registration/threshold-ed25519/hss/respond',
      'Respond to threshold Ed25519 HSS client request during registration bootstrap',
      {
        plane: 'api_credentials',
        credentials: ['secret_key', 'bootstrap_token'],
        scopes: ['accounts.create'],
        environmentBinding: 'required',
      },
      { kind: 'none' },
      ['authService'],
    ),
    apiCredentialRoute(
      'registration_threshold_ed25519_hss_finalize',
      'POST',
      '/registration/threshold-ed25519/hss/finalize',
      'Finalize threshold Ed25519 HSS server ceremony during registration bootstrap',
      {
        plane: 'api_credentials',
        credentials: ['secret_key', 'bootstrap_token'],
        scopes: ['accounts.create'],
        environmentBinding: 'required',
      },
      { kind: 'none' },
      ['authService'],
    ),
    apiCredentialRoute(
      'api_wallets_list',
      'GET',
      '/v1/wallets',
      'List wallets for the authenticated API credential environment',
      {
        plane: 'api_credentials',
        credentials: ['secret_key'],
        scopes: ['wallets.read'],
      },
      { kind: 'none' },
      ['apiKeyAuth', 'wallets'],
    ),
    apiCredentialRoute(
      'api_wallets_search',
      'GET',
      '/v1/wallets/search',
      'Search wallets for the authenticated API credential environment',
      {
        plane: 'api_credentials',
        credentials: ['secret_key'],
        scopes: ['wallets.read'],
      },
      { kind: 'none' },
      ['apiKeyAuth', 'wallets'],
    ),
    apiCredentialRoute(
      'api_wallets_get',
      'GET',
      '/v1/wallets/:id',
      'Get a wallet for the authenticated API credential environment',
      {
        plane: 'api_credentials',
        credentials: ['secret_key'],
        scopes: ['wallets.read'],
      },
      { kind: 'none' },
      ['apiKeyAuth', 'wallets'],
    ),
    publicRoute(
      'auth_provider_action',
      'POST',
      '/auth/:provider/:action',
      'Start or verify provider login',
      {
        plane: 'public',
        proof: 'challenge_exchange',
        rationale:
          'Provider login bootstrap and verification are intentionally public challenge-based routes.',
      },
      ['authService'],
    ),
    publicRoute(
      'sync_account_options',
      'POST',
      '/sync-account/options',
      'Create sync-account challenge options',
      {
        plane: 'public',
        proof: 'webauthn',
        rationale:
          'Sync-account flows are public because they are challenge-driven WebAuthn entrypoints.',
      },
      ['authService'],
    ),
    publicRoute(
      'sync_account_verify',
      'POST',
      '/sync-account/verify',
      'Verify sync-account response',
      {
        plane: 'public',
        proof: 'webauthn',
        rationale: 'Sync-account verification is public because the WebAuthn proof is the gate.',
      },
      ['authService'],
    ),
    publicRoute(
      'link_device_session_get',
      'GET',
      '/link-device/session/:sessionId',
      'Read link-device session state',
      {
        plane: 'public',
        rationale:
          'Link-device routes are intentionally public for now and rely on opaque session identifiers.',
      },
      ['authService'],
    ),
    publicRoute(
      'link_device_session_create',
      'POST',
      '/link-device/session',
      'Create link-device session',
      {
        plane: 'public',
        rationale:
          'Link-device routes are intentionally public for now and rely on opaque session identifiers.',
      },
      ['authService'],
    ),
    publicRoute(
      'link_device_session_claim',
      'POST',
      '/link-device/session/claim',
      'Claim link-device session',
      {
        plane: 'public',
        rationale:
          'Link-device routes are intentionally public for now and rely on opaque session identifiers.',
      },
      ['authService'],
    ),
    publicRoute(
      'link_device_prepare',
      'POST',
      '/link-device/prepare',
      'Prepare link-device flow',
      {
        plane: 'public',
        rationale:
          'Link-device routes are intentionally public for now and rely on opaque session identifiers.',
      },
      ['authService'],
    ),
    publicRoute(
      'smart_account_deployment_manifest',
      'POST',
      '/smart-account/deployment/manifest',
      'Read canonical smart-account deployment manifest',
      {
        plane: 'public',
        rationale:
          'Smart-account deployment manifests are relay-public routes gated by threshold session authorization.',
      },
      ['authService', 'session'],
    ),
    publicRoute(
      'smart_account_deployment_observe',
      'POST',
      '/smart-account/deployment/observe',
      'Report canonical smart-account deployment observation',
      {
        plane: 'public',
        rationale:
          'Smart-account deployment observations are relay-public routes gated by threshold session authorization.',
      },
      ['authService', 'session'],
    ),
    publicRoute(
      'email_recovery_prepare',
      'POST',
      '/email-recovery/prepare',
      'Prepare email recovery flow',
      {
        plane: 'public',
        proof: 'recovery_proof',
        rationale: 'Email recovery preparation is a public recovery bootstrap route.',
      },
      ['authService'],
    ),
    publicRoute(
      'threshold_ed25519_healthz',
      'GET',
      '/threshold-ed25519/healthz',
      'Threshold Ed25519 health probe',
      {
        plane: 'public',
        rationale: 'Threshold health probes are intentionally public diagnostics.',
      },
      ['threshold'],
    ),
    publicRoute(
      'threshold_ed25519_session',
      'POST',
      '/threshold-ed25519/session',
      'Issue threshold Ed25519 session',
      {
        plane: 'public',
        proof: 'webauthn',
        rationale:
          'Threshold session bootstrap is intentionally public because session issuance validates proof payloads.',
      },
      ['threshold', 'session'],
    ),
    thresholdSessionRoute(
      'threshold_ed25519_authorize',
      'POST',
      '/threshold-ed25519/authorize',
      'Authorize threshold Ed25519 signing session',
      'ed25519',
      ['threshold', 'session'],
    ),
    thresholdSessionRoute(
      'threshold_ed25519_hss_prepare',
      'POST',
      '/threshold-ed25519/hss/prepare',
      'Prepare threshold Ed25519 HSS relay ceremony step',
      'ed25519',
      ['threshold', 'session'],
    ),
    thresholdSessionRoute(
      'threshold_ed25519_hss_respond',
      'POST',
      '/threshold-ed25519/hss/respond',
      'Respond to threshold Ed25519 HSS client request',
      'ed25519',
      ['threshold', 'session'],
    ),
    thresholdSessionRoute(
      'threshold_ed25519_hss_finalize',
      'POST',
      '/threshold-ed25519/hss/finalize',
      'Finalize threshold Ed25519 HSS server ceremony step',
      'ed25519',
      ['threshold', 'session'],
    ),
    publicRoute(
      'threshold_ed25519_sign_init',
      'POST',
      '/threshold-ed25519/sign/init',
      'Begin threshold Ed25519 signing continuation',
      {
        plane: 'public',
        proof: 'threshold_protocol_state',
        rationale:
          'Low-level threshold continuations are intentionally auth-free and rely on protocol state plus share possession.',
      },
      ['threshold'],
    ),
    publicRoute(
      'threshold_ed25519_sign_finalize',
      'POST',
      '/threshold-ed25519/sign/finalize',
      'Finalize threshold Ed25519 signing continuation',
      {
        plane: 'public',
        proof: 'threshold_protocol_state',
        rationale:
          'Low-level threshold continuations are intentionally auth-free and rely on protocol state plus share possession.',
      },
      ['threshold'],
    ),
    publicRoute(
      'threshold_ed25519_internal_cosign_init',
      'POST',
      '/threshold-ed25519/internal/cosign/init',
      'Begin threshold Ed25519 cosign continuation',
      {
        plane: 'public',
        proof: 'threshold_protocol_state',
        rationale:
          'Current cosign continuation routes remain public and are gated by threshold protocol state, not route auth.',
      },
      ['threshold'],
    ),
    publicRoute(
      'threshold_ed25519_internal_cosign_finalize',
      'POST',
      '/threshold-ed25519/internal/cosign/finalize',
      'Finalize threshold Ed25519 cosign continuation',
      {
        plane: 'public',
        proof: 'threshold_protocol_state',
        rationale:
          'Current cosign continuation routes remain public and are gated by threshold protocol state, not route auth.',
      },
      ['threshold'],
    ),
    publicRoute(
      'threshold_ecdsa_healthz',
      'GET',
      '/threshold-ecdsa/healthz',
      'Threshold ECDSA health probe',
      {
        plane: 'public',
        rationale: 'Threshold health probes are intentionally public diagnostics.',
      },
      ['threshold'],
    ),
    publicRoute(
      'threshold_ecdsa_hss_prepare',
      'POST',
      '/threshold-ecdsa/hss/prepare',
      'Prepare staged threshold ECDSA HSS bootstrap ceremony',
      {
        plane: 'public',
        proof: 'webauthn',
        rationale:
          'Staged ecdsa-hss bootstrap remains public because proof validation happens inside the threshold bootstrap flow.',
      },
      ['threshold'],
    ),
    publicRoute(
      'threshold_ecdsa_hss_respond',
      'POST',
      '/threshold-ecdsa/hss/respond',
      'Continue staged threshold ECDSA HSS bootstrap ceremony',
      {
        plane: 'public',
        proof: 'threshold_protocol_state',
        rationale:
          'Staged ecdsa-hss respond remains public because it is gated by protocol state rather than route auth.',
      },
      ['threshold'],
    ),
    publicRoute(
      'threshold_ecdsa_hss_finalize',
      'POST',
      '/threshold-ecdsa/hss/finalize',
      'Finalize staged threshold ECDSA HSS bootstrap ceremony',
      {
        plane: 'public',
        proof: 'threshold_protocol_state',
        rationale:
          'Staged ecdsa-hss finalize remains public because it is gated by protocol state rather than route auth.',
      },
      ['threshold'],
    ),
    thresholdSessionRoute(
      'threshold_ecdsa_authorize',
      'POST',
      '/threshold-ecdsa/authorize',
      'Authorize threshold ECDSA signing session',
      'ecdsa',
      ['threshold', 'session'],
    ),
    thresholdSessionRoute(
      'threshold_ecdsa_presign_init',
      'POST',
      '/threshold-ecdsa/presign/init',
      'Begin threshold ECDSA presign session',
      'ecdsa',
      ['threshold', 'session'],
    ),
    thresholdSessionRoute(
      'threshold_ecdsa_presign_step',
      'POST',
      '/threshold-ecdsa/presign/step',
      'Continue threshold ECDSA presign session',
      'ecdsa',
      ['threshold', 'session'],
    ),
    publicRoute(
      'threshold_ecdsa_sign_init',
      'POST',
      '/threshold-ecdsa/sign/init',
      'Begin threshold ECDSA signing continuation',
      {
        plane: 'public',
        proof: 'threshold_protocol_state',
        rationale:
          'Low-level threshold continuations are intentionally auth-free and rely on protocol state plus share possession.',
      },
      ['threshold'],
    ),
    publicRoute(
      'threshold_ecdsa_sign_finalize',
      'POST',
      '/threshold-ecdsa/sign/finalize',
      'Finalize threshold ECDSA signing continuation',
      {
        plane: 'public',
        proof: 'threshold_protocol_state',
        rationale:
          'Low-level threshold continuations are intentionally auth-free and rely on protocol state plus share possession.',
      },
      ['threshold'],
    ),
    publicRoute(
      'threshold_ecdsa_internal_cosign_init',
      'POST',
      '/threshold-ecdsa/internal/cosign/init',
      'Begin threshold ECDSA cosign continuation',
      {
        plane: 'public',
        proof: 'threshold_protocol_state',
        rationale:
          'Current cosign continuation routes remain public and are gated by threshold protocol state, not route auth.',
      },
      ['threshold'],
    ),
    publicRoute(
      'threshold_ecdsa_internal_cosign_finalize',
      'POST',
      '/threshold-ecdsa/internal/cosign/finalize',
      'Finalize threshold ECDSA cosign continuation',
      {
        plane: 'public',
        proof: 'threshold_protocol_state',
        rationale:
          'Current cosign continuation routes remain public and are gated by threshold protocol state, not route auth.',
      },
      ['threshold'],
    ),
    userSessionRoute(
      'webauthn_authenticators',
      'GET',
      '/webauthn/authenticators',
      'List registered WebAuthn authenticators',
      ['authService', 'session'],
    ),
    userSessionRoute(
      'near_public_keys',
      'GET',
      '/near/public-keys',
      'List NEAR public keys for current session',
      ['authService', 'session'],
    ),
    userSessionRoute(
      'session_state',
      'GET',
      sessionStatePath,
      'Read current session state',
      ['session'],
      sessionStateAliases,
    ),
    publicRoute(
      'session_exchange',
      'POST',
      '/session/exchange',
      'Exchange external assertion for app session',
      {
        plane: 'public',
        proof: 'challenge_exchange',
        rationale:
          'Session exchange is intentionally public because OIDC JWTs or passkey assertions are the gate.',
      },
      ['authService', 'session'],
    ),
    userSessionRoute('session_revoke', 'POST', '/session/revoke', 'Revoke current app session', [
      'authService',
      'session',
    ]),
    userSessionRoute('session_refresh', 'POST', '/session/refresh', 'Refresh current app session', [
      'authService',
      'session',
    ]),
    publicRoute(
      'wallet_unlock_challenge',
      'POST',
      '/wallet/unlock/challenge',
      'Create wallet unlock challenge',
      {
        plane: 'public',
        proof: 'challenge_exchange',
        rationale: 'Wallet unlock challenge issuance is intentionally public.',
      },
      ['authService'],
    ),
    publicRoute(
      'wallet_unlock_verify',
      'POST',
      '/wallet/unlock/verify',
      'Verify wallet unlock challenge',
      {
        plane: 'public',
        proof: 'challenge_exchange',
        rationale:
          'Wallet unlock verification is intentionally public because the challenge proof is the gate.',
      },
      ['authService'],
    ),
    userSessionRoute(
      'wallet_email_otp_registration_challenge',
      'POST',
      '/wallet/email-otp/registration/challenge',
      'Create Email OTP registration challenge for the current app session',
      ['authService', 'session'],
    ),
    userSessionRoute(
      'wallet_email_otp_registration_seal',
      'POST',
      '/wallet/email-otp/registration/seal',
      'Apply the Email OTP server seal for a new registration blob',
      ['authService', 'session'],
    ),
    userSessionRoute(
      'wallet_email_otp_registration_finalize',
      'POST',
      '/wallet/email-otp/registration/finalize',
      'Finalize Email OTP registration challenge for the current app session',
      ['authService', 'session'],
    ),
    userSessionRoute(
      'wallet_email_otp_login_challenge',
      'POST',
      '/wallet/email-otp/login/challenge',
      'Create Email OTP login challenge for the current app session',
      ['authService', 'session'],
    ),
    userSessionRoute(
      'wallet_email_otp_login_verify',
      'POST',
      '/wallet/email-otp/login/verify',
      'Verify Email OTP login challenge for the current app session',
      ['authService', 'session'],
    ),
    userSessionRoute(
      'wallet_email_otp_unseal',
      'POST',
      '/wallet/email-otp/unseal',
      'Remove the server Shamir seal after Email OTP authorization',
      ['authService', 'session'],
    ),
    publicRoute(
      'wallet_email_otp_dev_cleanup_google_registration',
      'POST',
      '/wallet/email-otp/dev/cleanup-google-registration',
      'Clean stale Google Email OTP registration state in local development',
      {
        plane: 'public',
        proof: 'signed_payload',
        rationale:
          'This development-only cleanup path verifies a Google id token before touching stale local registration state.',
      },
      ['authService'],
    ),
    userSessionRoute('wallet_state', 'GET', '/wallet/state', 'Read wallet state', [
      'authService',
      'session',
    ]),
    userSessionRoute('wallet_lock', 'POST', '/wallet/lock', 'Lock wallet', [
      'authService',
      'session',
    ]),
    publicRoute(
      'recover_email',
      'POST',
      '/recover-email',
      'Process email recovery ingress',
      {
        plane: 'public',
        rationale:
          'Recover-email remains auth-free for now and should be revisited if it starts incurring billable execution cost.',
      },
      ['authService'],
    ),
    userSessionRoute('auth_identities', 'GET', '/auth/identities', 'List linked identities', [
      'authService',
      'session',
    ]),
    userSessionRoute('auth_link', 'POST', '/auth/link', 'Link an additional identity', [
      'authService',
      'session',
    ]),
    userSessionRoute('auth_unlink', 'POST', '/auth/unlink', 'Unlink an identity', [
      'authService',
      'session',
    ]),
  );

  if (options.enableSponsoredEvmCall) {
    definitions.push(
      apiCredentialRoute(
        'sponsored_evm_call',
        'POST',
        sponsoredEvmCallPath,
        'Execute a sponsored EVM call',
        {
          plane: 'api_credentials',
          credentials: ['publishable_key'],
          environmentBinding: 'required',
          originBinding: 'required',
        },
        { kind: 'gas', ledger: 'evm' },
        ['relaySponsoredEvmCall'],
      ),
    );
  }

  if (options.enablePrfSessionSeal) {
    definitions.push(
      userSessionRoute(
        'prf_session_seal_apply_server_seal',
        'POST',
        buildPrfSessionSealApplyPath(prfBasePath),
        'Apply PRF session server seal',
        ['prfSessionSeal', 'session'],
      ),
      userSessionRoute(
        'prf_session_seal_remove_server_seal',
        'POST',
        buildPrfSessionSealRemovePath(prfBasePath),
        'Remove PRF session server seal',
        ['prfSessionSeal', 'session'],
      ),
    );
  }

  if (signedDelegatePath) {
    definitions.push(
      apiCredentialRoute(
        'signed_delegate',
        'POST',
        signedDelegatePath,
        'Execute signed NEAR delegate',
        {
          plane: 'api_credentials',
          credentials: ['publishable_key'],
          environmentBinding: 'required',
          originBinding: 'required',
        },
        { kind: 'gas', ledger: 'near_delegate' },
        ['authService', 'publishableKeyAuth', 'billing', 'runtimeSnapshots', 'sponsoredCalls'],
      ),
    );
  }

  return definitions;
}
