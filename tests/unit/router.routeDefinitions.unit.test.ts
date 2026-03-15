import { expect, test } from '@playwright/test';
import { applyRouteMetering } from '../../server/src/router/applyRouteMetering';
import { authorizeConsoleRouteRequest } from '../../server/src/router/consoleRoutePolicy';
import { registerCloudflareRoute } from '../../server/src/router/cloudflare/registerCloudflareRoute';
import { enforceRoutePolicy } from '../../server/src/router/enforceRoutePolicy';
import { registerExpressRoute } from '../../server/src/router/express/registerExpressRoute';
import { MACHINE_ROUTE_SCOPES } from '../../server/src/router/routeAuthPolicy';
import { ROUTE_SERVICE_KEYS } from '../../server/src/router/routeExecutionContext';
import {
  createConsoleRouteDefinitions,
  createRelayRouteDefinitions,
  defineRoute,
  findRouteDefinitionForRequest,
  type RouteDefinition,
} from '../../server/src/router/routeDefinitions';

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
  'auth_provider_action',
  'sync_account_options',
  'sync_account_verify',
  'link_device_session_get',
  'link_device_session_create',
  'link_device_session_claim',
  'link_device_prepare',
  'email_recovery_prepare',
  'threshold_ed25519_healthz',
  'threshold_ed25519_keygen',
  'threshold_ed25519_session',
  'threshold_ed25519_sign_init',
  'threshold_ed25519_sign_finalize',
  'threshold_ed25519_internal_cosign_init',
  'threshold_ed25519_internal_cosign_finalize',
  'threshold_ecdsa_healthz',
  'threshold_ecdsa_bootstrap',
  'threshold_ecdsa_sign_init',
  'threshold_ecdsa_sign_finalize',
  'threshold_ecdsa_internal_cosign_init',
  'threshold_ecdsa_internal_cosign_finalize',
  'session_exchange',
  'wallet_unlock_challenge',
  'wallet_unlock_verify',
  'recover_email',
] as const;

const ALLOWLISTED_PROOFLESS_PUBLIC_RELAY_ROUTE_IDS = [
  'relay_healthz',
  'relay_readyz',
  'relay_well_known_webauthn',
  'link_device_session_get',
  'link_device_session_create',
  'link_device_session_claim',
  'link_device_prepare',
  'threshold_ed25519_healthz',
  'threshold_ecdsa_healthz',
  'recover_email',
] as const;

test.describe('route definition scaffolding', () => {
  test('relay route ids are unique and core policies are encoded', async () => {
    const routes = createRelayRouteDefinitions({
      enableHealthz: true,
      enablePrfSessionSeal: true,
      enableReadyz: true,
      enableSponsoredEvmCall: true,
      prfSessionSealBasePath: '/threshold-ecdsa/prf-seal',
      sessionStatePath: '/session/state',
      signedDelegatePath: '/signed-delegate',
      sponsoredEvmCallPath: '/sponsorships/evm/call',
    });

    const ids = routes.map((route) => route.id);
    expect(new Set(ids).size).toBe(ids.length);

    const registrationBootstrap = routes.find((route) => route.id === 'registration_bootstrap');
    expect(registrationBootstrap).toBeTruthy();
    expect(registrationBootstrap?.auth).toMatchObject({
      plane: 'machine',
      credentials: ['secret_key', 'bootstrap_token'],
      scopes: ['accounts.create'],
    });
    expect(registrationBootstrap?.metering).toEqual({ kind: 'event', action: 'wallet_created' });

    const machineWalletList = routes.find((route) => route.id === 'machine_wallets_list');
    expect(machineWalletList).toBeTruthy();
    expect(machineWalletList?.auth).toMatchObject({
      plane: 'machine',
      credentials: ['secret_key'],
      scopes: ['wallets.read'],
    });
    expect(machineWalletList?.metering).toEqual({ kind: 'none' });

    const machineWalletRoute = findRouteDefinitionForRequest(routes, 'GET', '/v1/wallets/wlt_123');
    expect(machineWalletRoute?.id).toBe('machine_wallets_get');

    const signedDelegate = routes.find((route) => route.id === 'signed_delegate');
    expect(signedDelegate).toBeTruthy();
    expect(signedDelegate?.auth).toMatchObject({
      plane: 'machine',
      credentials: ['publishable_key'],
    });
    expect(signedDelegate?.metering).toEqual({ kind: 'gas', ledger: 'near_delegate' });

    const thresholdSignInit = routes.find((route) => route.id === 'threshold_ecdsa_sign_init');
    expect(thresholdSignInit).toBeTruthy();
    expect(thresholdSignInit?.auth).toMatchObject({
      plane: 'public',
      proof: 'threshold_protocol_state',
    });
    expect(thresholdSignInit?.metering).toEqual({ kind: 'none' });

    const sessionState = routes.find((route) => route.id === 'session_state');
    expect(sessionState).toBeTruthy();
    expect(sessionState?.path).toBe('/session/state');
    expect(sessionState?.aliases).toBeUndefined();

    const wellKnown = routes.find((route) => route.id === 'relay_well_known_webauthn');
    expect(wellKnown?.aliases).toEqual(['/.well-known/webauthn/']);

    const prfApply = routes.find((route) => route.id === 'prf_session_seal_apply_server_seal');
    expect(prfApply?.path).toBe('/threshold-ecdsa/prf-seal/apply-server-seal');

    const machineRoutes = routes.filter((route) => route.auth.plane === 'machine');
    expect(machineRoutes.length).toBeGreaterThan(0);
    for (const route of machineRoutes) {
      expect(route.auth.credentials.length).toBeGreaterThan(0);
      expect(new Set(route.auth.credentials).size).toBe(route.auth.credentials.length);
      for (const scope of route.auth.scopes || []) {
        expect(MACHINE_ROUTE_SCOPES).toContain(scope);
      }
    }

    const usedMachineScopes = new Set(
      machineRoutes.flatMap((route) => (route.auth.plane === 'machine' ? route.auth.scopes || [] : [])),
    );
    for (const scope of MACHINE_ROUTE_SCOPES) {
      expect(usedMachineScopes.has(scope)).toBe(true);
    }

    const publicRoutes = routes.filter((route) => route.auth.plane === 'public');
    expect(publicRoutes.length).toBeGreaterThan(0);
    for (const route of publicRoutes) {
      const rationale = route.auth.rationale.trim();
      expect(rationale.length).toBeGreaterThan(0);
      expect(Boolean(route.auth.proof) || rationale.length > 0).toBe(true);
    }

    const continuationRoutes = routes.filter((route) =>
      THRESHOLD_CONTINUATION_ROUTE_IDS.includes(route.id as (typeof THRESHOLD_CONTINUATION_ROUTE_IDS)[number]),
    );
    expect(continuationRoutes.map((route) => route.id).sort()).toEqual(
      [...THRESHOLD_CONTINUATION_ROUTE_IDS].sort(),
    );
    for (const route of continuationRoutes) {
      expect(route.auth.plane).toBe('public');
      if (route.auth.plane === 'public') {
        expect(route.auth.proof).toBe('threshold_protocol_state');
      }
      expect(route.metering).toEqual({ kind: 'none' });
      expect('scopes' in route.auth).toBe(false);
    }

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
      if (route.auth.plane === 'machine') continue;
      expect('scopes' in route.auth, `non-machine route references scopes: ${route.id}`).toBe(false);
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
        id: 'broken_machine',
        surface: 'relay',
        method: 'POST',
        path: '/broken-machine',
        auth: { plane: 'machine', credentials: [] },
        metering: { kind: 'none' },
        summary: 'broken machine',
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

    const billingOverview = routes.find(
      (route) => route.id === 'console_billing_overview_get',
    );
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

    const smartWalletCreate = routes.find((route) => route.id === 'console_smart_wallets_create');
    expect(smartWalletCreate?.auth).toMatchObject({
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

  test('enforceRoutePolicy allows public routes and blocks unresolved machine routes', async () => {
    const publicRoute: RouteDefinition = defineRoute({
      id: 'public_route',
      surface: 'relay',
      method: 'POST',
      path: '/public-route',
      auth: { plane: 'public', rationale: 'Public for smoke test' },
      metering: { kind: 'none' },
      summary: 'public route',
    });
    const machineRoute: RouteDefinition = defineRoute({
      id: 'machine_route',
      surface: 'relay',
      method: 'POST',
      path: '/machine-route',
      auth: { plane: 'machine', credentials: ['secret_key'], scopes: ['accounts.create'] },
      metering: { kind: 'event', action: 'wallet_created' },
      summary: 'machine route',
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

    const machineResult = await enforceRoutePolicy({
      route: machineRoute,
      headers: {},
      logger: {
        debug() {},
        error() {},
        info() {},
        warn() {},
      },
      request: { body: {}, headers: {} },
    });
    expect(machineResult.ok).toBe(false);
    if (!machineResult.ok) {
      expect(machineResult.body).toMatchObject({
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
