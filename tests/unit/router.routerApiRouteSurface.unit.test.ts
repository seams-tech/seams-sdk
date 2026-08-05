import { expect, test } from '@playwright/test';
import type { RouterApiServiceBag } from '../../packages/sdk-server-ts/src/router/framework/authServicePort';
import { createCloudflareRouter } from '../../packages/sdk-server-ts/src/router/cloudflare/runtime/createCloudflareRouter';
import {
  createRouterAbEd25519YaoProductRegistrationCompositionFromPortsV1,
  createRouterApiRouter,
  type RouterAbEd25519YaoProductRegistrationPortsV1,
} from '@seams/sdk-server/router/express';
import { createRouterApiModule } from '../../packages/sdk-server-ts/src/router/framework/modules';
import type {
  RouterApiCloudflareRouteExtensionInput,
  RouterApiRouteExtension,
} from '../../packages/sdk-server-ts/src/router/framework/routeExtensions';
import { defineRoute } from '../../packages/sdk-server-ts/src/router/framework/routeDefinitions';
import { getRouterApiRouteSurface } from '../../packages/sdk-server-ts/src/router/framework/routerApiRouteSurface';
import {
  parseRouterAbPublicKeysetV2,
  ROUTER_AB_PUBLIC_KEYSET_VERSION_V2,
} from '@shared/utils/routerAbPublicKeyset';
import { ROUTER_AB_TRACE_ID_HEADER_V1 } from '@shared/utils/routerAbTraceContext';
import { callCf } from '../relayer/helpers';

function makeUnexpectedRouterApiServiceValue(path: string): unknown {
  const target = function unexpectedRouterApiServiceCall(): never {
    throw new Error(`Unexpected RouterApiServiceBag fixture call: ${path}`);
  };
  return new Proxy(target, {
    get(_target, property) {
      if (property === 'then') return undefined;
      return makeUnexpectedRouterApiServiceValue(`${path}.${String(property)}`);
    },
    apply() {
      throw new Error(`Unexpected RouterApiServiceBag fixture call: ${path}`);
    },
  });
}

function makeRouterApiServiceBagFixture(): RouterApiServiceBag {
  const target = {
    thresholdRuntime: {
      getRouterAbNormalSigningRuntime() {
        return undefined;
      },
      getRouterAbEcdsaBootstrapExportRuntime() {
        return undefined;
      },
      getRouterAbEcdsaPresignRuntime() {
        return undefined;
      },
    },
  };
  return new Proxy(target, {
    get(target, property, receiver) {
      if (property in target) return Reflect.get(target, property, receiver);
      if (property === 'then') return undefined;
      return makeUnexpectedRouterApiServiceValue(`RouterApiServiceBag.${String(property)}`);
    },
  }) as RouterApiServiceBag;
}

function makeUnusedYaoHostPort<T extends object>(name: string): T {
  return makeUnexpectedRouterApiServiceValue(name) as T;
}

function makeNodeYaoProductPorts(): RouterAbEd25519YaoProductRegistrationPortsV1 {
  return {
    signingWorkerId: 'node-signing-worker-1',
    registrationService: makeUnusedYaoHostPort('registrationService'),
    authorization: makeUnusedYaoHostPort('authorization'),
    recoveryService: makeUnusedYaoHostPort('recoveryService'),
    capabilities: makeUnusedYaoHostPort('capabilities'),
    recoveryAuthorization: makeUnusedYaoHostPort('recoveryAuthorization'),
    exportService: makeUnusedYaoHostPort('exportService'),
    exportAuthorization: makeUnusedYaoHostPort('exportAuthorization'),
    session: makeUnusedYaoHostPort('session'),
  };
}

const ROUTER_AB_PUBLIC_KEYSET = parseRouterAbPublicKeysetV2({
  keyset_version: ROUTER_AB_PUBLIC_KEYSET_VERSION_V2,
  signer_envelope_hpke: {
    current: {
      deriver_a: {
        role: 'signer_a',
        key_epoch: 'epoch-a',
        public_key: 'x25519:1111111111111111111111111111111111111111111111111111111111111111',
      },
      deriver_b: {
        role: 'signer_b',
        key_epoch: 'epoch-b',
        public_key: 'x25519:2222222222222222222222222222222222222222222222222222222222222222',
      },
    },
  },
  signer_peer_verifying_keys: {
    deriver_a: {
      role: 'signer_a',
      verifying_key_hex: '5afa80b305e72e02615ed1f580144a40a42a71dfcac175809ceb5d79e740d015',
    },
    deriver_b: {
      role: 'signer_b',
      verifying_key_hex: '0c700dd63695221e508f3164b528f190bed63a4437d38e882308f9a57acc1bc3',
    },
  },
  signing_worker_server_output_hpke: {
    key_epoch: 'epoch-server',
    public_key: 'x25519:3333333333333333333333333333333333333333333333333333333333333333',
  },
});

function handleHostedRouteExtension(input: RouterApiCloudflareRouteExtensionInput): Response {
  return new Response(JSON.stringify({ routeId: input.route.id }), {
    headers: { 'Content-Type': 'application/json' },
  });
}

function makeHostedRouteExtension(
  extensionId: string,
  routeId: string,
  path: string,
): RouterApiRouteExtension {
  return {
    kind: 'cloudflare_route_extension',
    id: extensionId,
    routes: [testExtensionRoute(routeId, 'POST', path)],
    handleCloudflareRoute: handleHostedRouteExtension,
  };
}

function makeHostedRouteExtensions(input: {
  readonly signedDelegateRoute: string;
  readonly sponsoredEvmRoute: string;
}): readonly RouterApiRouteExtension[] {
  return [
    makeHostedRouteExtension(
      'hosted-signed-delegate',
      'signed_delegate',
      input.signedDelegateRoute,
    ),
    makeHostedRouteExtension(
      'hosted-sponsored-evm-call',
      'sponsored_evm_call',
      input.sponsoredEvmRoute,
    ),
  ];
}

function canonicalRouteKeys(
  input: { method: string; path: string; aliases?: readonly string[] }[],
): string[] {
  return input.flatMap((route) => {
    const keys = [`${route.method} ${route.path}`];
    for (const alias of route.aliases || []) {
      keys.push(`${route.method} ${alias}`);
    }
    return keys;
  });
}

function materializeRoutePath(path: string): string {
  return path.replace(/:([A-Za-z0-9_]+)/g, (_match, name: string) => {
    const normalized = String(name || '').toLowerCase();
    if (normalized === 'provider') return 'passkey';
    if (normalized === 'action') return 'options';
    if (normalized.includes('id')) return 'test_id';
    return `test_${normalized}`;
  });
}

function testExtensionRoute(id: string, method: 'GET' | 'POST', path: string) {
  return defineRoute({
    id,
    surface: 'relay',
    method,
    path,
    auth: {
      plane: 'public',
      proof: 'intent_grant',
      rationale: 'Test extension route exercises generic module registration.',
    },
    metering: { kind: 'none' },
    summary: `Test extension route ${id}`,
  });
}

const EMAIL_RECOVERY_EXECUTION_SERVICE = {
  async requestEmailRecovery() {
    return { success: true };
  },
};

test.describe('Router API route surface wiring', () => {
  test('Express public entrypoint composes the canonical Ed25519 Yao module and envelope', async () => {
    const composition = createRouterAbEd25519YaoProductRegistrationCompositionFromPortsV1(
      makeNodeYaoProductPorts(),
    );
    const surface = getRouterApiRouteSurface(
      createRouterApiRouter(makeRouterApiServiceBagFixture(), {
        modules: [composition.module],
      }),
    );
    const routeIds = new Set((surface?.routeDefinitions || []).map((route) => route.id));
    expect(
      [
        'router_ab_ed25519_yao_registration_admit',
        'router_ab_ed25519_yao_registration_execute',
        'router_ab_ed25519_yao_warm_recovery_bootstrap',
        'router_ab_ed25519_yao_recovery_admit',
        'router_ab_ed25519_yao_recovery_execute',
        'router_ab_ed25519_yao_recovery_activate',
        'router_ab_ed25519_yao_export_admit',
        'router_ab_ed25519_yao_export_execute',
      ].filter((routeId) => !routeIds.has(routeId)),
    ).toEqual([]);

    const registration = composition.module.routeExtensions[0];
    const route = registration?.routes[0];
    if (!registration || !route) throw new Error('missing Node Ed25519 Yao registration route');
    const response = await registration.handleCloudflareRoute({
      request: new Request(`https://node.example.test${route.path}`, { method: 'GET' }),
      route,
      pathname: route.path,
      method: 'GET',
      logger: makeUnusedYaoHostPort('logger'),
    });
    expect(response.status).toBe(405);
    await expect(response.json()).resolves.toEqual({
      ok: false,
      code: 'method_not_allowed',
      message: 'Method not allowed',
    });
  });

  test('Express adapter route surface matches canonical fetch router surface', async () => {
    const service = makeRouterApiServiceBagFixture();
    const options = {
      healthz: true,
      readyz: true,
      signingSessionSeal: {
        basePath: '/threshold/custom-signing-session',
        service: {} as any,
      },
      sessionRoutes: { state: '/session/me' },
      routeExtensions: makeHostedRouteExtensions({
        signedDelegateRoute: '/delegate/submit',
        sponsoredEvmRoute: '/gas/relay',
      }),
    };

    const expressSurface = getRouterApiRouteSurface(createRouterApiRouter(service, options));
    const fetchSurface = getRouterApiRouteSurface(createCloudflareRouter(service, options));
    expect(expressSurface).toBeTruthy();
    expect(fetchSurface).toBeTruthy();
    expect(expressSurface?.mePath).toBe('/session/me');
    expect(expressSurface?.signedDelegatePath).toBe('/delegate/submit');

    const actualKeys = new Set(canonicalRouteKeys(expressSurface?.routeDefinitions || []));
    const expectedKeys = new Set(canonicalRouteKeys(fetchSurface?.routeDefinitions || []));

    expect([...expectedKeys].filter((key) => !actualKeys.has(key))).toEqual([]);
    expect([...actualKeys].filter((key) => !expectedKeys.has(key))).toEqual([]);
  });

  test('conditional Router API route families are only attached when enabled', async () => {
    const service = makeRouterApiServiceBagFixture();
    const router = createRouterApiRouter(service, {});
    const surface = getRouterApiRouteSurface(router);
    const ids = new Set((surface?.routeDefinitions || []).map((route) => route.id));

    expect(ids.has('router_api_healthz')).toBe(false);
    expect(ids.has('router_api_readyz')).toBe(false);
    expect(ids.has('signed_delegate')).toBe(false);
    expect(ids.has('sponsored_evm_call')).toBe(false);
    expect(ids.has('signing_session_seal_apply_server_seal')).toBe(false);
    expect(ids.has('signing_session_seal_remove_server_seal')).toBe(false);
  });

  test('email recovery route surface separates prepare-only and executable ingress branches', async () => {
    const service = makeRouterApiServiceBagFixture();
    const prepareOnlySurface = getRouterApiRouteSurface(
      createRouterApiRouter(service, {
        emailRecovery: {
          kind: 'prepare_only',
          authService: service,
        },
      }),
    );
    const prepareOnlyIds = new Set(
      (prepareOnlySurface?.routeDefinitions || []).map((route) => route.id),
    );

    expect(prepareOnlyIds.has('email_recovery_prepare')).toBe(true);
    expect(prepareOnlyIds.has('recover_email')).toBe(false);

    const executableSurface = getRouterApiRouteSurface(
      createRouterApiRouter(service, {
        emailRecovery: {
          kind: 'prepare_and_execute',
          authService: service,
          executionService: EMAIL_RECOVERY_EXECUTION_SERVICE,
        },
      }),
    );
    const executableIds = new Set(
      (executableSurface?.routeDefinitions || []).map((route) => route.id),
    );

    expect(executableIds.has('email_recovery_prepare')).toBe(true);
    expect(executableIds.has('recover_email')).toBe(true);
  });

  test('cloudflare and express attach the same configured Router API route surface', async () => {
    const service = makeRouterApiServiceBagFixture();
    const options = {
      healthz: true,
      signingSessionSeal: {
        basePath: '/threshold/custom-signing-session',
        service: {} as any,
      },
      readyz: true,
      sessionRoutes: { state: '/session/me' },
      routeExtensions: makeHostedRouteExtensions({
        signedDelegateRoute: '/delegate/submit',
        sponsoredEvmRoute: '/gas/relay',
      }),
    };

    const expressSurface = getRouterApiRouteSurface(createRouterApiRouter(service, options));
    const cloudflareSurface = getRouterApiRouteSurface(createCloudflareRouter(service, options));

    expect(cloudflareSurface).toEqual(expressSurface);
  });

  test('cloudflare handler recognizes every seeded Router API route definition', async () => {
    const service = makeRouterApiServiceBagFixture();
    const handler = createCloudflareRouter(service, {
      corsOrigins: ['https://example.localhost'],
      healthz: true,
      readyz: true,
      routerAbPublicKeyset: ROUTER_AB_PUBLIC_KEYSET,
      signingSessionSeal: {
        basePath: '/threshold/custom-signing-session',
        service: {} as any,
      },
      sessionRoutes: { state: '/session/me' },
      routeExtensions: makeHostedRouteExtensions({
        signedDelegateRoute: '/delegate/submit',
        sponsoredEvmRoute: '/gas/relay',
      }),
    });
    const surface = getRouterApiRouteSurface(handler);
    expect(surface).toBeTruthy();

    for (const route of surface?.routeDefinitions || []) {
      const response = await callCf(handler, {
        method: route.method,
        path: materializeRoutePath(route.path),
        origin: 'https://example.localhost',
        ...(route.method === 'POST' ? { body: {} } : {}),
      });
      expect(response.status, `${route.method} ${route.path}`).not.toBe(404);
    }
  });

  test('cloudflare registration preflight allows the trace correlation header', async () => {
    const origin = 'https://sign.seams.sh';
    const handler = createCloudflareRouter(makeRouterApiServiceBagFixture(), {
      corsOrigins: [origin],
    });

    const response = await callCf(handler, {
      method: 'OPTIONS',
      path: '/wallets/register/setup',
      origin,
      headers: {
        'Access-Control-Request-Headers': `content-type,${ROUTER_AB_TRACE_ID_HEADER_V1}`,
        'Access-Control-Request-Method': 'POST',
      },
    });

    expect(response.status).toBe(204);
    expect(response.headers.get('Access-Control-Allow-Origin')).toBe(origin);
    const allowedHeaders = new Set(
      (response.headers.get('Access-Control-Allow-Headers') || '')
        .split(',')
        .map((header) => header.trim().toLowerCase()),
    );
    expect(allowedHeaders.has(ROUTER_AB_TRACE_ID_HEADER_V1)).toBe(true);
  });

  test('route extensions are surfaced and mounted by supported transport', async () => {
    const service = makeRouterApiServiceBagFixture();
    const cloudflareRoute = testExtensionRoute(
      'test_evidence_cloudflare',
      'POST',
      '/test/evidence',
    );
    const capabilitiesRoute = testExtensionRoute('test_capabilities', 'GET', '/test/capabilities');
    const extensions: RouterApiRouteExtension[] = [
      {
        kind: 'cloudflare_route_extension',
        id: 'test-evidence-cloudflare',
        routes: [cloudflareRoute],
        handleCloudflareRoute: ({ route }) =>
          new Response(JSON.stringify({ routeId: route.id, runtime: 'cloudflare' }), {
            headers: { 'Content-Type': 'application/json' },
          }),
      },
      {
        kind: 'cloudflare_route_extension',
        id: 'test-capabilities',
        routes: [capabilitiesRoute],
        handleCloudflareRoute: ({ route }) =>
          new Response(JSON.stringify({ routeId: route.id, runtime: 'cloudflare' }), {
            headers: { 'Content-Type': 'application/json' },
          }),
      },
    ];

    const cloudflareHandler = createCloudflareRouter(service, { routeExtensions: extensions });
    const cloudflareSurface = getRouterApiRouteSurface(cloudflareHandler);
    const cloudflareIds = new Set(
      (cloudflareSurface?.routeDefinitions || []).map((route) => route.id),
    );
    expect(cloudflareIds.has('test_evidence_cloudflare')).toBe(true);
    expect(cloudflareIds.has('test_capabilities')).toBe(true);

    const evidenceResponse = await callCf(cloudflareHandler, {
      method: 'POST',
      path: '/test/evidence',
      body: {},
    });
    expect(evidenceResponse.status).toBe(200);
    expect(evidenceResponse.json).toEqual({
      routeId: 'test_evidence_cloudflare',
      runtime: 'cloudflare',
    });

    const expressRouter = createRouterApiRouter(service, { routeExtensions: extensions });
    const expressSurface = getRouterApiRouteSurface(expressRouter);
    const expressIds = new Set((expressSurface?.routeDefinitions || []).map((route) => route.id));
    expect(expressIds.has('test_evidence_cloudflare')).toBe(true);
    expect(expressIds.has('test_capabilities')).toBe(true);
  });

  test('route extensions cannot shadow existing Router API routes', async () => {
    const service = makeRouterApiServiceBagFixture();
    const extension: RouterApiRouteExtension = {
      kind: 'cloudflare_route_extension',
      id: 'conflicting-extension',
      routes: [testExtensionRoute('conflicting_session_state', 'GET', '/session/state')],
      handleCloudflareRoute: () => new Response(null, { status: 204 }),
    };

    expect(() => createCloudflareRouter(service, { routeExtensions: [extension] })).toThrow(
      /duplicate Router API route definition path GET \/session\/state/,
    );
  });

  test('Router API modules reject duplicate module ids', async () => {
    const service = makeRouterApiServiceBagFixture();
    const route = testExtensionRoute('test_duplicate_module_route', 'GET', '/test/dupe');
    const extension: RouterApiRouteExtension = {
      kind: 'cloudflare_route_extension',
      id: 'duplicate-module-extension',
      routes: [route],
      handleCloudflareRoute: () => new Response(null, { status: 204 }),
    };
    const first = createRouterApiModule({ id: 'test-module', routeExtensions: [extension] });
    const second = createRouterApiModule({ id: 'test-module', routeExtensions: [extension] });

    expect(() => createCloudflareRouter(service, { modules: [first, second] })).toThrow(
      /duplicate Router API module id test-module/,
    );
  });
});
