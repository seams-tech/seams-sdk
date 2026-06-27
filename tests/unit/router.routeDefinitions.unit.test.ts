import { expect, test } from '@playwright/test';
import { applyRouteMetering } from '../../packages/sdk-server-ts/src/router/applyRouteMetering';
import { authorizeConsoleRouteRequest } from '../../packages/sdk-server-ts/src/router/consoleRoutePolicy';
import { registerCloudflareRoute } from '../../packages/sdk-server-ts/src/router/cloudflare/registerCloudflareRoute';
import { enforceRoutePolicy } from '../../packages/sdk-server-ts/src/router/enforceRoutePolicy';
import { registerExpressRoute } from '../../packages/sdk-server-ts/src/router/express/registerExpressRoute';
import { API_CREDENTIAL_ROUTE_SCOPES } from '../../packages/sdk-server-ts/src/router/routeAuthPolicy';
import { ROUTE_SERVICE_KEYS } from '../../packages/sdk-server-ts/src/router/routeExecutionContext';
import {
  createConsoleRouteDefinitions,
  createRelayRouteDefinitions,
  defineRoute,
  findRouteDefinitionForRequest,
  type RouteDefinition,
} from '../../packages/sdk-server-ts/src/router/routeDefinitions';
import {
  ROUTER_AB_ECDSA_HSS_BOOTSTRAP_PATH,
  ROUTER_AB_ECDSA_HSS_EXPORT_SHARE_PATH,
  ROUTER_AB_ECDSA_HSS_HEALTH_PATH,
} from '@shared/utils/routerAbEcdsaHss';
import { WALLET_SESSION_SEAL_BASE_PATH } from '@shared/utils/signingSessionSeal';

const THRESHOLD_CONTINUATION_ROUTE_IDS = [
  'threshold_ed25519_sign_init',
  'threshold_ed25519_sign_finalize',
  'threshold_ed25519_internal_cosign_init',
  'threshold_ed25519_internal_cosign_finalize',
  'threshold_ecdsa_sign_init',
  'threshold_ecdsa_sign_finalize',
  'threshold_ecdsa_internal_cosign_init',
  'threshold_ecdsa_internal_cosign_finalize',
] as const;

const ALLOWLISTED_PUBLIC_RELAY_ROUTE_IDS = [
  'relay_healthz',
  'relay_readyz',
  'relay_well_known_webauthn',
  'relay_router_ab_public_keyset',
  'auth_provider_action',
  'sync_account_options',
  'sync_account_verify',
  'link_device_session_get',
  'link_device_session_create',
  'link_device_session_claim',
  'link_device_prepare',
  'link_device_ecdsa_respond',
  'email_recovery_prepare',
  'email_recovery_ecdsa_respond',
  'router_ab_ed25519_healthz',
  'router_ab_ed25519_wallet_session',
  'router_ab_ecdsa_hss_healthz',
  'session_exchange',
  'wallet_unlock_challenge',
  'wallet_unlock_verify',
  'wallet_registration_prepare',
  'wallet_registration_start',
  'wallet_registration_hss_respond',
  'wallet_registration_finalize',
  'wallet_add_signer_start',
  'wallet_add_signer_hss_respond',
  'wallet_add_signer_finalize',
  'wallet_add_auth_method_start',
  'wallet_add_auth_method_finalize',
  'wallet_revoke_auth_method',
  'wallet_email_otp_dev_cleanup_google_registration',
  'recover_email',
] as const;

const ALLOWLISTED_PROOFLESS_PUBLIC_RELAY_ROUTE_IDS = [
  'relay_healthz',
  'relay_readyz',
  'relay_well_known_webauthn',
  'relay_router_ab_public_keyset',
  'link_device_session_get',
  'link_device_session_create',
  'link_device_session_claim',
  'link_device_prepare',
  'link_device_ecdsa_respond',
  'router_ab_ed25519_healthz',
  'router_ab_ecdsa_hss_healthz',
  'recover_email',
] as const;

test.describe('route definition scaffolding', () => {
  test('relay route ids are unique and core policies are encoded', async () => {
    const routes = createRelayRouteDefinitions({
      enableEmailRecovery: true,
      enableHealthz: true,
      enableSigningSessionSeal: true,
      enableReadyz: true,
      enableSponsoredEvmCall: true,
      signingSessionSealBasePath: WALLET_SESSION_SEAL_BASE_PATH,
      sessionStatePath: '/session/state',
      signedDelegatePath: '/signed-delegate',
      sponsoredEvmCallPath: '/sponsorships/evm/call',
    });

    const ids = routes.map((route) => route.id);
    expect(new Set(ids).size).toBe(ids.length);

    expect(routes.find((route) => route.id === 'registration_bootstrap')).toBeUndefined();
    expect(
      routes.find((route) => route.id === 'registration_threshold_ed25519_hss_prepare'),
    ).toBeUndefined();
    expect(
      routes.find((route) => route.id === 'registration_threshold_ed25519_hss_respond'),
    ).toBeUndefined();
    expect(
      routes.find((route) => route.id === 'registration_threshold_ed25519_hss_finalize'),
    ).toBeUndefined();

    const walletRegistrationIntent = routes.find(
      (route) => route.id === 'wallet_registration_intent',
    );
    expect(walletRegistrationIntent).toBeTruthy();
    expect(walletRegistrationIntent?.auth).toMatchObject({
      plane: 'api_credentials',
      credentials: ['secret_key', 'bootstrap_token'],
      scopes: ['accounts.create'],
    });
    expect(walletRegistrationIntent?.metering).toEqual({ kind: 'none' });

    const walletAddAuthMethodIntent = routes.find(
      (route) => route.id === 'wallet_add_auth_method_intent',
    );
    expect(walletAddAuthMethodIntent).toBeTruthy();
    expect(walletAddAuthMethodIntent?.auth).toMatchObject({
      plane: 'api_credentials',
      credentials: ['secret_key', 'bootstrap_token'],
      scopes: ['wallets.auth_methods.create'],
    });
    expect(walletAddAuthMethodIntent?.metering).toEqual({ kind: 'none' });

    const walletRevokeAuthMethod = routes.find((route) => route.id === 'wallet_revoke_auth_method');
    expect(walletRevokeAuthMethod).toBeTruthy();
    expect(walletRevokeAuthMethod?.auth).toMatchObject({
      plane: 'public',
      proof: 'challenge_exchange',
    });
    expect(walletRevokeAuthMethod?.metering).toEqual({ kind: 'none' });

    const apiWalletList = routes.find((route) => route.id === 'api_wallets_list');
    expect(apiWalletList).toBeTruthy();
    expect(apiWalletList?.auth).toMatchObject({
      plane: 'api_credentials',
      credentials: ['secret_key'],
      scopes: ['wallets.read'],
    });
    expect(apiWalletList?.metering).toEqual({ kind: 'none' });

    const apiWalletRoute = findRouteDefinitionForRequest(routes, 'GET', '/v1/wallets/wlt_123');
    expect(apiWalletRoute?.id).toBe('api_wallets_get');

    const signedDelegate = routes.find((route) => route.id === 'signed_delegate');
    expect(signedDelegate).toBeTruthy();
    expect(signedDelegate?.auth).toMatchObject({
      plane: 'api_credentials',
      credentials: ['publishable_key'],
    });
    expect(signedDelegate?.metering).toEqual({ kind: 'gas', ledger: 'near_delegate' });

    expect(routes.find((route) => route.id === 'threshold_ecdsa_sign_init')).toBeUndefined();

    const sessionState = routes.find((route) => route.id === 'session_state');
    expect(sessionState).toBeTruthy();
    expect(sessionState?.path).toBe('/session/state');
    expect(sessionState?.aliases).toBeUndefined();

    const routePaths = routes.map((route) => route.path);
    expect(routePaths).toContain(ROUTER_AB_ECDSA_HSS_BOOTSTRAP_PATH);
    expect(routePaths).toContain(ROUTER_AB_ECDSA_HSS_EXPORT_SHARE_PATH);
    expect(routePaths).toContain(ROUTER_AB_ECDSA_HSS_HEALTH_PATH);
    expect(routePaths).not.toContain('/threshold-ed25519/session');
    expect(routePaths).not.toContain('/threshold-ed25519/internal/cosign/init');
    expect(routePaths).not.toContain('/threshold-ed25519/internal/cosign/finalize');
    expect(routePaths).not.toContain('/threshold-ecdsa/hss/bootstrap');
    expect(routePaths).not.toContain('/threshold-ecdsa/hss/export/share');
    expect(routePaths).not.toContain('/threshold-ecdsa/internal/cosign/init');
    expect(routePaths).not.toContain('/threshold-ecdsa/internal/cosign/finalize');
    expect(routePaths).not.toContain('/threshold-ecdsa/hss/prepare');
    expect(routePaths).not.toContain('/threshold-ecdsa/hss/respond');
    expect(routePaths).not.toContain('/threshold-ecdsa/hss/finalize');

    const wellKnown = routes.find((route) => route.id === 'relay_well_known_webauthn');
    expect(wellKnown?.aliases).toEqual(['/.well-known/webauthn/']);

    const prfApply = routes.find((route) => route.id === 'signing_session_seal_apply_server_seal');
    expect(prfApply?.path).toBe(`${WALLET_SESSION_SEAL_BASE_PATH}/apply-server-seal`);

    const apiCredentialRoutes = routes.filter((route) => route.auth.plane === 'api_credentials');
    expect(apiCredentialRoutes.length).toBeGreaterThan(0);
    for (const route of apiCredentialRoutes) {
      const auth = route.auth as Extract<RouteDefinition['auth'], { plane: 'api_credentials' }>;
      expect(auth.credentials.length).toBeGreaterThan(0);
      expect(new Set(auth.credentials).size).toBe(auth.credentials.length);
      for (const scope of auth.scopes || []) {
        expect(API_CREDENTIAL_ROUTE_SCOPES).toContain(scope);
      }
    }

    const usedApiCredentialScopes = new Set(
      apiCredentialRoutes.flatMap((route) =>
        route.auth.plane === 'api_credentials' ? route.auth.scopes || [] : [],
      ),
    );
    for (const scope of API_CREDENTIAL_ROUTE_SCOPES) {
      expect(usedApiCredentialScopes.has(scope)).toBe(true);
    }

    const publicRoutes = routes.filter((route) => route.auth.plane === 'public');
    expect(publicRoutes.length).toBeGreaterThan(0);
    for (const route of publicRoutes) {
      const auth = route.auth as Extract<RouteDefinition['auth'], { plane: 'public' }>;
      const rationale = auth.rationale.trim();
      expect(rationale.length).toBeGreaterThan(0);
      expect(Boolean(auth.proof) || rationale.length > 0).toBe(true);
    }

    const continuationRoutes = routes.filter((route) =>
      THRESHOLD_CONTINUATION_ROUTE_IDS.includes(
        route.id as (typeof THRESHOLD_CONTINUATION_ROUTE_IDS)[number],
      ),
    );
    expect(continuationRoutes).toEqual([]);

    const publicRouteIds = publicRoutes.map((route) => route.id).sort();
    expect(publicRouteIds).toEqual([...ALLOWLISTED_PUBLIC_RELAY_ROUTE_IDS].sort());

    const prooflessPublicRoutes = publicRoutes.filter(
      (route) => route.auth.plane === 'public' && !route.auth.proof,
    );
    expect(prooflessPublicRoutes.map((route) => route.id).sort()).toEqual(
      [...ALLOWLISTED_PROOFLESS_PUBLIC_RELAY_ROUTE_IDS].sort(),
    );
    for (const route of prooflessPublicRoutes) {
      expect(route.metering).toEqual({ kind: 'none' });
    }

    for (const route of routes) {
      if (route.auth.plane === 'api_credentials') continue;
      expect(
        'scopes' in route.auth,
        `non-api_credentials route references scopes: ${route.id}`,
      ).toBe(false);
    }

    const declaredServices = new Set(ROUTE_SERVICE_KEYS);
    for (const route of routes) {
      for (const service of route.requiredServices || []) {
        expect(declaredServices.has(service)).toBe(true);
      }
    }
  });

  test('defineRoute rejects invalid definitions', async () => {
    expect(() =>
      defineRoute({
        id: '',
        surface: 'relay',
        method: 'GET',
        path: '/ok',
        auth: { plane: 'public', rationale: 'test' },
        metering: { kind: 'none' },
        summary: 'broken',
      }),
    ).toThrow(/id is required/);

    expect(() =>
      defineRoute({
        id: 'broken',
        surface: 'relay',
        method: 'GET',
        path: 'not-slash-prefixed',
        auth: { plane: 'public', rationale: 'test' },
        metering: { kind: 'none' },
        summary: 'broken',
      }),
    ).toThrow(/must start with \//);

    expect(() =>
      defineRoute({
        id: 'broken_api_credentials',
        surface: 'relay',
        method: 'POST',
        path: '/broken-api-credentials',
        auth: { plane: 'api_credentials', credentials: [] },
        metering: { kind: 'none' },
        summary: 'broken api credentials',
      }),
    ).toThrow(/at least one credential/);

    expect(() =>
      defineRoute({
        id: 'broken_public',
        surface: 'relay',
        method: 'POST',
        path: '/broken-public',
        auth: { plane: 'public', rationale: '   ' },
        metering: { kind: 'none' },
        summary: 'broken public',
      }),
    ).toThrow(/rationale is required/);

    expect(() =>
      defineRoute({
        id: 'broken_services',
        surface: 'relay',
        method: 'POST',
        path: '/broken-services',
        auth: { plane: 'public', rationale: 'test' },
        metering: { kind: 'none' },
        requiredServices: ['not_real' as never],
        summary: 'broken services',
      }),
    ).toThrow(/unknown service/);
  });

  test('console route definitions encode targeted RBAC and path matching', async () => {
    const routes = createConsoleRouteDefinitions();
    const ids = routes.map((route) => route.id);
    expect(new Set(ids).size).toBe(ids.length);
    expect(routes.every((route) => route.auth.plane === 'console')).toBe(true);
    expect(routes.every((route) => route.metering.kind === 'none')).toBe(true);

    const onboardingOrganizationCreate = routes.find(
      (route) => route.id === 'console_onboarding_organization_create',
    );
    expect(onboardingOrganizationCreate?.auth).toMatchObject({
      plane: 'console',
      roles: ['owner', 'admin'],
    });

    const onboardingTelemetry = routes.find(
      (route) => route.id === 'console_onboarding_telemetry_get',
    );
    expect(onboardingTelemetry?.auth).toMatchObject({
      plane: 'console',
      roles: ['admin', 'ops'],
    });

    const accountSwitchContext = routes.find(
      (route) => route.id === 'console_account_organizations_switch_context',
    );
    expect(accountSwitchContext?.auth).toMatchObject({
      plane: 'console',
    });

    const opsCockpitSummary = routes.find(
      (route) => route.id === 'console_ops_cockpit_summary_get',
    );
    expect(opsCockpitSummary?.auth).toMatchObject({
      plane: 'console',
      roles: ['owner', 'admin', 'security_admin', 'ops'],
    });

    const auditEvents = routes.find((route) => route.id === 'console_audit_events_list');
    expect(auditEvents?.auth).toMatchObject({
      plane: 'console',
      roles: ['owner', 'admin', 'security_admin', 'ops'],
    });

    const walletsList = routes.find((route) => route.id === 'console_wallets_list');
    expect(walletsList?.auth).toMatchObject({
      plane: 'console',
      roles: ['owner', 'admin', 'security_admin', 'ops', 'support'],
    });

    const projectArchive = routes.find((route) => route.id === 'console_projects_archive');
    expect(projectArchive?.auth).toMatchObject({
      plane: 'console',
      roles: ['owner', 'admin'],
    });

    const teamMemberInvite = routes.find((route) => route.id === 'console_members_invite');
    expect(teamMemberInvite?.auth).toMatchObject({
      plane: 'console',
      roles: ['owner', 'admin'],
    });

    const approvalReject = routes.find((route) => route.id === 'console_approvals_reject');
    expect(approvalReject?.auth).toMatchObject({
      plane: 'console',
      roles: ['owner', 'admin', 'security_admin'],
    });

    const auditExportCreate = routes.find((route) => route.id === 'console_audit_exports_create');
    expect(auditExportCreate?.auth).toMatchObject({
      plane: 'console',
      roles: ['owner', 'admin'],
    });

    const policyPublish = routes.find((route) => route.id === 'console_policies_publish');
    expect(policyPublish?.auth).toMatchObject({
      plane: 'console',
      roles: ['owner', 'admin', 'security_admin'],
    });

    const observabilitySummary = routes.find(
      (route) => route.id === 'console_observability_summary_get',
    );
    expect(observabilitySummary?.auth).toMatchObject({
      plane: 'console',
      roles: ['owner', 'admin', 'security_admin', 'ops', 'support'],
    });

    const invoiceGenerate = routes.find(
      (route) => route.id === 'console_billing_invoices_generate',
    );
    expect(invoiceGenerate?.auth).toMatchObject({
      plane: 'console',
      roles: ['admin', 'ops'],
    });

    const billingOverview = routes.find((route) => route.id === 'console_billing_overview_get');
    expect(billingOverview?.auth).toMatchObject({
      plane: 'console',
      roles: ['owner', 'admin', 'billing_admin', 'ops'],
    });

    const supportCredit = routes.find(
      (route) => route.id === 'console_billing_adjustments_support_credit',
    );
    expect(supportCredit?.auth).toMatchObject({
      plane: 'console',
      roles: ['platform_admin'],
    });

    const webhookCreate = routes.find((route) => route.id === 'console_webhooks_create');
    expect(webhookCreate?.auth).toMatchObject({
      plane: 'console',
      roles: ['owner', 'admin', 'security_admin'],
    });
    expect(webhookCreate?.metering).toEqual({ kind: 'none' });

    const billingUsageEvents = routes.find(
      (route) => route.id === 'console_billing_usage_events_record',
    );
    expect(billingUsageEvents?.auth).toMatchObject({
      plane: 'console',
      roles: ['admin', 'ops'],
    });

    const keyExportCreate = routes.find((route) => route.id === 'console_key_exports_create');
    expect(keyExportCreate?.auth).toMatchObject({
      plane: 'console',
      roles: ['owner', 'admin', 'security_admin'],
    });

    const keyExportApprove = routes.find((route) => route.id === 'console_key_exports_approve');
    expect(keyExportApprove?.auth).toMatchObject({
      plane: 'console',
      roles: ['admin'],
    });

    const apiKeyRotate = routes.find((route) => route.id === 'console_api_keys_rotate');
    expect(apiKeyRotate?.auth).toMatchObject({
      plane: 'console',
      roles: ['owner', 'admin', 'security_admin'],
    });

    const publishCurrentSnapshot = routes.find(
      (route) => route.id === 'console_runtime_snapshots_publish_current',
    );
    expect(publishCurrentSnapshot?.auth).toMatchObject({
      plane: 'console',
      roles: ['owner', 'admin', 'security_admin'],
    });

    const replayRoute = findRouteDefinitionForRequest(
      routes,
      'POST',
      '/console/webhooks/wh_123/replay',
    );
    expect(replayRoute?.id).toBe('console_webhooks_replay');

    const keyExportApproveRoute = findRouteDefinitionForRequest(
      routes,
      'POST',
      '/console/key-exports/ke_123/approve',
    );
    expect(keyExportApproveRoute?.id).toBe('console_key_exports_approve');

    const apiKeyRotateRoute = findRouteDefinitionForRequest(
      routes,
      'POST',
      '/console/api-keys/ak_123/rotate',
    );
    expect(apiKeyRotateRoute?.id).toBe('console_api_keys_rotate');

    const environmentArchiveRoute = findRouteDefinitionForRequest(
      routes,
      'POST',
      '/console/environments/env_123/archive',
    );
    expect(environmentArchiveRoute?.id).toBe('console_environments_archive');

    const teamMemberRolesRoute = findRouteDefinitionForRequest(
      routes,
      'PATCH',
      '/console/members/mbr_123/roles',
    );
    expect(teamMemberRolesRoute?.id).toBe('console_members_update_roles');

    const approvalApproveRoute = findRouteDefinitionForRequest(
      routes,
      'POST',
      '/console/approvals/apr_123/approve',
    );
    expect(approvalApproveRoute?.id).toBe('console_approvals_approve');

    const auditExportCreateRoute = findRouteDefinitionForRequest(
      routes,
      'POST',
      '/console/audit/exports',
    );
    expect(auditExportCreateRoute?.id).toBe('console_audit_exports_create');

    const policyAssignmentDeleteRoute = findRouteDefinitionForRequest(
      routes,
      'DELETE',
      '/console/policies/assignments/asg_123',
    );
    expect(policyAssignmentDeleteRoute?.id).toBe('console_policy_assignments_delete');

    const policyPublishRoute = findRouteDefinitionForRequest(
      routes,
      'POST',
      '/console/policies/pol_123/publish',
    );
    expect(policyPublishRoute?.id).toBe('console_policies_publish');

    const sessionRoute = findRouteDefinitionForRequest(routes, 'GET', '/console/session');
    expect(sessionRoute?.id).toBe('console_session_get');

    const accountProfileRoute = findRouteDefinitionForRequest(
      routes,
      'PATCH',
      '/console/account/profile',
    );
    expect(accountProfileRoute?.id).toBe('console_account_profile_patch');

    const switchContextRoute = findRouteDefinitionForRequest(
      routes,
      'POST',
      '/console/account/organizations/org_123/switch-context',
    );
    expect(switchContextRoute?.id).toBe('console_account_organizations_switch_context');

    const observabilityServicesRoute = findRouteDefinitionForRequest(
      routes,
      'GET',
      '/console/observability/services',
    );
    expect(observabilityServicesRoute?.id).toBe('console_observability_services_list');

    const walletRoute = findRouteDefinitionForRequest(routes, 'GET', '/console/wallets/wlt_123');
    expect(walletRoute?.id).toBe('console_wallets_get');

    const invoicePdfRoute = findRouteDefinitionForRequest(
      routes,
      'GET',
      '/console/billing/invoices/inv_123/pdf',
    );
    expect(invoicePdfRoute?.id).toBe('console_billing_invoices_pdf_get');

    const policySimulateRoute = findRouteDefinitionForRequest(
      routes,
      'POST',
      '/console/policies/pol_123/simulate',
    );
    expect(policySimulateRoute?.id).toBe('console_policies_simulate');

    const checkoutSessionRoute = findRouteDefinitionForRequest(
      routes,
      'POST',
      '/console/billing/stripe/checkout-session',
    );
    expect(checkoutSessionRoute?.id).toBe('console_billing_stripe_checkout_session_create');

    const checkoutReconcileRoute = findRouteDefinitionForRequest(
      routes,
      'POST',
      '/console/billing/stripe/checkout-session/reconcile',
    );
    expect(checkoutReconcileRoute?.id).toBe('console_billing_stripe_checkout_session_reconcile');

    const supportCreditRoute = findRouteDefinitionForRequest(
      routes,
      'POST',
      '/console/billing/adjustments/support-credit',
    );
    expect(supportCreditRoute?.id).toBe('console_billing_adjustments_support_credit');

    const denied = authorizeConsoleRouteRequest({
      claims: {
        userId: 'user_console_route_definitions',
        orgId: 'org_console_route_definitions',
        roles: ['developer'],
      },
      definitions: routes,
      method: 'POST',
      pathname: '/console/webhooks',
    });
    expect(denied.ok).toBe(false);
    if (!denied.ok) {
      expect(denied.status).toBe(403);
      expect(denied.body).toMatchObject({ code: 'forbidden' });
    }
  });

  test('enforceRoutePolicy allows public routes and blocks unresolved api credential routes', async () => {
    const publicRoute: RouteDefinition = defineRoute({
      id: 'public_route',
      surface: 'relay',
      method: 'POST',
      path: '/public-route',
      auth: { plane: 'public', rationale: 'Public for smoke test' },
      metering: { kind: 'none' },
      summary: 'public route',
    });
    const apiCredentialRoute: RouteDefinition = defineRoute({
      id: 'api_credential_route',
      surface: 'relay',
      method: 'POST',
      path: '/api-credential-route',
      auth: { plane: 'api_credentials', credentials: ['secret_key'], scopes: ['accounts.create'] },
      metering: { kind: 'event', action: 'wallet_created' },
      summary: 'api credential route',
    });

    const publicResult = await enforceRoutePolicy({
      route: publicRoute,
      headers: {},
      logger: {
        debug() {},
        error() {},
        info() {},
        warn() {},
      },
      request: { body: {}, headers: {} },
    });
    expect(publicResult.ok).toBe(true);
    if (publicResult.ok) {
      expect(publicResult.context.principal).toEqual({ kind: 'public' });
    }

    const apiCredentialResult = await enforceRoutePolicy({
      route: apiCredentialRoute,
      headers: {},
      logger: {
        debug() {},
        error() {},
        info() {},
        warn() {},
      },
      request: { body: {}, headers: {} },
    });
    expect(apiCredentialResult.ok).toBe(false);
    if (!apiCredentialResult.ok) {
      expect(apiCredentialResult.body).toMatchObject({
        code: 'route_auth_not_configured',
      });
    }
  });

  test('applyRouteMetering dispatches event and gas policies', async () => {
    const calls: string[] = [];
    const eventRoute = defineRoute({
      id: 'event_route',
      surface: 'relay',
      method: 'POST',
      path: '/event-route',
      auth: { plane: 'public', rationale: 'test' },
      metering: { kind: 'event', action: 'wallet_created' },
      summary: 'event route',
    });
    const gasRoute = defineRoute({
      id: 'gas_route',
      surface: 'relay',
      method: 'POST',
      path: '/gas-route',
      auth: { plane: 'public', rationale: 'test' },
      metering: { kind: 'gas', ledger: 'near_delegate' },
      summary: 'gas route',
    });

    const context = {
      headers: {},
      logger: { debug() {}, error() {}, info() {}, warn() {} },
      principal: { kind: 'public' as const },
      services: {},
    };

    await applyRouteMetering({
      route: eventRoute,
      context,
      response: { status: 200, body: { ok: true } },
      handlers: {
        event: async ({ action }) => {
          calls.push(`event:${action}`);
        },
        gas: async ({ ledger }) => {
          calls.push(`gas:${ledger}`);
        },
      },
    });

    await applyRouteMetering({
      route: gasRoute,
      context,
      response: { status: 200, body: { ok: true } },
      handlers: {
        event: async ({ action }) => {
          calls.push(`event:${action}`);
        },
        gas: async ({ ledger }) => {
          calls.push(`gas:${ledger}`);
        },
      },
    });

    expect(calls).toEqual(['event:wallet_created', 'gas:near_delegate']);
  });

  test('transport wrappers match paths and methods', async () => {
    const route = defineRoute({
      id: 'wrapper_route',
      surface: 'relay',
      method: 'GET',
      path: '/wrapper',
      aliases: ['/wrapper/'],
      auth: { plane: 'public', rationale: 'test' },
      metering: { kind: 'none' },
      summary: 'wrapper route',
    });

    const cloudflareHandler = registerCloudflareRoute(route, async ({ route: matchedRoute }) => {
      return new Response(JSON.stringify({ id: matchedRoute.id }), { status: 200 });
    });

    const miss = await cloudflareHandler({ method: 'POST', pathname: '/wrapper' });
    expect(miss).toBeNull();
    const hit = await cloudflareHandler({ method: 'GET', pathname: '/wrapper/' });
    expect(hit?.status).toBe(200);

    const registered: Array<{ method: string; path: string }> = [];
    const fakeRouter = {
      delete(path: string) {
        registered.push({ method: 'DELETE', path });
      },
      get(path: string) {
        registered.push({ method: 'GET', path });
      },
      patch(path: string) {
        registered.push({ method: 'PATCH', path });
      },
      post(path: string) {
        registered.push({ method: 'POST', path });
      },
      put(path: string) {
        registered.push({ method: 'PUT', path });
      },
    };

    registerExpressRoute({
      router: fakeRouter as any,
      route,
      context: {},
      handler: async () => {},
    });

    expect(registered).toEqual([
      { method: 'GET', path: '/wrapper' },
      { method: 'GET', path: '/wrapper/' },
    ]);
  });
});
