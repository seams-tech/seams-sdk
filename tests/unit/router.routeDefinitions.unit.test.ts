import { expect, test } from '@playwright/test';
import { applyRouteMetering } from '../../packages/wallet-server/src/router/framework/applyRouteMetering';
import { enforceRoutePolicy } from '../../packages/wallet-server/src/router/framework/enforceRoutePolicy';
import { API_CREDENTIAL_ROUTE_SCOPES } from '../../packages/wallet-server/src/router/framework/routeAuthPolicy';
import { ROUTE_SERVICE_KEYS } from '../../packages/wallet-server/src/router/framework/routeExecutionContext';
import {
  createRouterApiRouteDefinitions,
  defineRoute,
  type RouteDefinition,
} from '../../packages/wallet-server/src/router/framework/routeDefinitions';
import {
  ROUTER_AB_ECDSA_DERIVATION_EXPORT_PATH,
  ROUTER_AB_ECDSA_DERIVATION_HEALTH_PATH,
} from '@shared/utils/routerAbEcdsaDerivation';
import { WALLET_SESSION_SEAL_BASE_PATH } from '@shared/utils/signingSessionSeal';

const ALLOWLISTED_PUBLIC_RELAY_ROUTE_IDS = [
  'router_api_healthz',
  'router_api_readyz',
  'relay_well_known_webauthn',
  'relay_router_ab_public_keyset',
  'auth_provider_action',
  'sync_account_options',
  'sync_account_verify',
  'router_ab_ed25519_healthz',
  'router_ab_ed25519_wallet_session',
  'router_ab_ecdsa_derivation_healthz',
  'session_exchange',
  'wallet_unlock_challenge',
  'wallet_unlock_verify',
  'wallet_registration_respond',
  'wallet_registration_activate',
  'wallet_registration_near_provisioning',
  'wallet_add_signer_start',
  'wallet_add_signer_ecdsa_derivation_respond',
  'wallet_add_signer_ecdsa_activation',
  'wallet_add_signer_finalize',
  'wallet_add_auth_method_start',
  'wallet_add_auth_method_finalize',
  'wallet_revoke_auth_method',
  'wallet_email_otp_dev_cleanup_google_registration',
] as const;

const ALLOWLISTED_PROOFLESS_PUBLIC_RELAY_ROUTE_IDS = [
  'router_api_healthz',
  'router_api_readyz',
  'relay_well_known_webauthn',
  'relay_router_ab_public_keyset',
  'router_ab_ed25519_healthz',
  'router_ab_ecdsa_derivation_healthz',
] as const;

test.describe('route definition scaffolding', () => {
  test('Router API route ids are unique and core policies are encoded', async () => {
    const routes = createRouterApiRouteDefinitions({
      enableHealthz: true,
      enableSigningSessionSeal: true,
      enableReadyz: true,
      signingSessionSealBasePath: WALLET_SESSION_SEAL_BASE_PATH,
      sessionStatePath: '/session/state',
    });

    const ids = routes.map((route) => route.id);
    expect(new Set(ids).size).toBe(ids.length);

    const walletRegistrationSetup = routes.find(
      (route) => route.id === 'wallet_registration_setup',
    );
    expect(walletRegistrationSetup).toBeTruthy();
    expect(walletRegistrationSetup?.auth).toMatchObject({
      plane: 'api_credentials',
      credentials: ['publishable_key'],
      scopes: ['accounts.create'],
    });
    expect(walletRegistrationSetup?.metering).toEqual({ kind: 'none' });

    const walletAddAuthMethodIntent = routes.find(
      (route) => route.id === 'wallet_add_auth_method_intent',
    );
    expect(walletAddAuthMethodIntent).toBeTruthy();
    expect(walletAddAuthMethodIntent?.auth).toMatchObject({
      plane: 'api_credentials',
      credentials: ['publishable_key'],
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

    const sessionState = routes.find((route) => route.id === 'session_state');
    expect(sessionState).toBeTruthy();
    expect(sessionState?.path).toBe('/session/state');
    expect(sessionState?.aliases).toBeUndefined();

    const routePaths = routes.map((route) => route.path);
    expect(routePaths).toContain(ROUTER_AB_ECDSA_DERIVATION_EXPORT_PATH);
    expect(routePaths).toContain(ROUTER_AB_ECDSA_DERIVATION_HEALTH_PATH);

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

    const publicRoutes = routes.filter((route) => route.auth.plane === 'public');
    expect(publicRoutes.length).toBeGreaterThan(0);
    for (const route of publicRoutes) {
      const auth = route.auth as Extract<RouteDefinition['auth'], { plane: 'public' }>;
      const rationale = auth.rationale.trim();
      expect(rationale.length).toBeGreaterThan(0);
      expect(Boolean(auth.proof) || rationale.length > 0).toBe(true);
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
});
