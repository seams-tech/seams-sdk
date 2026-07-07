import { expect, test } from '@playwright/test';
import { createInMemoryConsoleApiKeyService } from '../../packages/console-server-ts/src/apiKeys';
import { createInMemoryConsoleRuntimeSnapshotService } from '../../packages/console-server-ts/src/runtimeSnapshots';
import { createInMemoryConsoleSponsoredCallService } from '../../packages/console-server-ts/src/sponsoredCalls';
import type { RouterApiServiceBag } from '../../packages/sdk-server-ts/src/router/authServicePort';
import { createCloudflareRouter } from '../../packages/sdk-server-ts/src/router/cloudflare/createCloudflareRouter';
import { createRouterApiRouter } from '../../packages/sdk-server-ts/src/router/express-adaptor';
import {
  createRouterApiModule,
  type RouterApiModule,
} from '../../packages/sdk-server-ts/src/router/modules';
import { createRouterApiPublishableKeyAuthAdapter } from '../../packages/console-server-ts/src/router/routerApiKeyAuth';
import { createConsoleRouterApiRouteExtensions } from '../../packages/console-server-ts/src/router/routeExtensions';
import type { RouterApiRouteExtension } from '../../packages/sdk-server-ts/src/router/routeExtensions';
import { defineRoute } from '../../packages/sdk-server-ts/src/router/routeDefinitions';
import { getRouterApiRouteSurface } from '../../packages/sdk-server-ts/src/router/routerApiRouteSurface';
import {
  parseRouterAbPublicKeysetV2,
  ROUTER_AB_PUBLIC_KEYSET_VERSION_V2,
} from '@shared/utils/routerAbPublicKeyset';
import {
  createDefaultVoiceIdService,
  createVoiceIdRouterApiModule,
  createVoiceIdServerCapability,
} from '../../voiceId/server/src/index';
import { callCf } from '../relayer/helpers';

type CloudflareRouterApiHandler = ReturnType<typeof createCloudflareRouter>;

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
      getThresholdSigningService() {
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

function makeSponsoredEvmExecutorConfig() {
  return {
    executorsByChain: new Map([
      [
        42_431,
        {
          chainId: 42_431,
          rpcUrl: 'https://rpc.example.test',
          sponsorAddress: '0x2222222222222222222222222222222222222222' as const,
          sponsorPrivateKeyHex:
            '0x1111111111111111111111111111111111111111111111111111111111111111' as const,
          maxPriorityFeePerGasFloor: 2_000_000_000n,
          maxFeePerGasFloor: 40_000_000_000n,
        },
      ],
    ]),
  };
}

function makeTestPublishableKeyAuth() {
  return createRouterApiPublishableKeyAuthAdapter(createInMemoryConsoleApiKeyService());
}

function makeSponsoredEvmRouteExtensions(route: string): readonly RouterApiRouteExtension[] {
  return createConsoleRouterApiRouteExtensions({
    sponsoredEvmCall: {
      route,
      publishableKeyAuth: makeTestPublishableKeyAuth(),
      billing: {} as any,
      ledger: createInMemoryConsoleSponsoredCallService(),
      runtimeSnapshots: createInMemoryConsoleRuntimeSnapshotService(),
      config: makeSponsoredEvmExecutorConfig(),
      observabilityIngestion: null,
      prepaidReservations: null,
      pricing: null,
      spendCaps: null,
    },
  });
}

function makeSignedDelegateRouteOptions(route: string, authService: unknown) {
  return {
    route,
    authService: authService as any,
    billing: {} as any,
    ledger: createInMemoryConsoleSponsoredCallService(),
    runtimeSnapshots: createInMemoryConsoleRuntimeSnapshotService(),
    publishableKeyAuth: makeTestPublishableKeyAuth(),
    observabilityIngestion: null,
    prepaidReservations: null,
    pricing: null,
    spendCaps: null,
    webhooks: null,
  };
}

function makeManagedSponsorshipRouteExtensions(input: {
  readonly signedDelegateRoute: string;
  readonly sponsoredEvmRoute: string;
  readonly authService: unknown;
}): readonly RouterApiRouteExtension[] {
  return createConsoleRouterApiRouteExtensions({
    signedDelegate: makeSignedDelegateRouteOptions(input.signedDelegateRoute, input.authService),
    sponsoredEvmCall: {
      route: input.sponsoredEvmRoute,
      publishableKeyAuth: makeTestPublishableKeyAuth(),
      billing: {} as any,
      ledger: createInMemoryConsoleSponsoredCallService(),
      runtimeSnapshots: createInMemoryConsoleRuntimeSnapshotService(),
      config: makeSponsoredEvmExecutorConfig(),
      observabilityIngestion: null,
      prepaidReservations: null,
      pricing: null,
      spendCaps: null,
    },
  });
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

function voiceIdTestRoute(id: string, method: 'GET' | 'POST', path: string) {
  return defineRoute({
    id,
    surface: 'relay',
    method,
    path,
    auth: {
      plane: 'public',
      proof: 'intent_grant',
      rationale: 'VoiceID extension routes exchange caller-held owner-presence evidence.',
    },
    metering: { kind: 'none' },
    summary: `VoiceID test route ${id}`,
  });
}

async function callCfFormData(
  handler: CloudflareRouterApiHandler,
  path: string,
  form: FormData,
): Promise<{
  status: number;
  headers: Headers;
  json: Record<string, unknown> | null;
  text: string;
}> {
  const response = await handler(
    new Request(new URL(path, 'https://relay.test').toString(), {
      method: 'POST',
      body: form,
    }),
  );
  return await readResponse(response);
}

async function readResponse(response: globalThis.Response): Promise<{
  status: number;
  headers: Headers;
  json: Record<string, unknown> | null;
  text: string;
}> {
  const text = await response.text();
  let json: Record<string, unknown> | null = null;
  try {
    const parsed: unknown = text ? JSON.parse(text) : null;
    if (parsed && typeof parsed === 'object' && !Array.isArray(parsed)) {
      json = parsed as Record<string, unknown>;
    }
  } catch {
    json = null;
  }
  return { status: response.status, headers: response.headers, json, text };
}

function okValue<TValue>(body: Record<string, unknown> | null): TValue {
  expect(body?.kind).toBe('ok');
  const value = body?.value;
  expect(value).toBeTruthy();
  return value as TValue;
}

const VOICE_ID_TEST_INTENT_DIGEST = 'A'.repeat(43);

const EMAIL_RECOVERY_EXECUTION_SERVICE = {
  async requestEmailRecovery() {
    return { success: true };
  },
};

function voiceIdIntentBindingBody(): Record<string, unknown> {
  return {
    intentDigest: VOICE_ID_TEST_INTENT_DIGEST,
    intentExpiresAt: '2099-01-01T00:00:00.000Z',
    intentNonce: 'nonce_123456',
  };
}

function voiceIdOwnerPresenceAuthorizationBody(verificationId: string): Record<string, unknown> {
  return {
    verificationId,
    intentDigest: VOICE_ID_TEST_INTENT_DIGEST,
    useCase: 'wallet_mpc_signing',
    policyVersion: 'voiceid-wallet-policy-v1',
    audio: {
      kind: 'audio_liveness_signals_v1',
      promptOpenedAt: '2026-06-13T00:00:00.000Z',
      speechStartedAt: '2026-06-13T00:00:00.600Z',
      speechEndedAt: '2026-06-13T00:00:01.900Z',
      captureSource: {
        kind: 'trusted_microphone',
        deviceId: 'sdk-router-surface-test-mic',
      },
      replayRisk: { kind: 'low' },
    },
    context: {
      kind: 'local_device_context_v1',
      deviceId: 'sdk-router-surface-device',
      sidecarId: 'sdk-router-surface-sidecar',
      captureStartedAt: '2026-06-13T00:00:00.000Z',
      evaluatedAt: '2026-06-13T00:00:02.200Z',
      localPolicyVersion: 'voiceid-liveness-policy-v1',
    },
  };
}

function voiceIdSampleForm(input: {
  fields: Record<string, unknown>;
  speakerLabel: string;
}): FormData {
  const bytes = new Uint8Array([1, 2, 3]);
  const form = new FormData();
  form.set('audio', new Blob([bytes], { type: 'audio/webm' }));
  form.set(
    'metadata',
    JSON.stringify({
      mimeType: 'audio/webm',
      durationMs: 1500,
      sampleRate: { kind: 'unknown' },
      channelCount: { kind: 'unknown' },
      byteLength: bytes.byteLength,
      capturedAt: '2026-06-13T00:00:00.000Z',
      recorder: 'router-module-test',
      fixtureBehavior: { kind: 'speaker_label', speakerLabel: input.speakerLabel },
    }),
  );
  form.set('fields', JSON.stringify(input.fields));
  return form;
}

test.describe('Router API route surface wiring', () => {
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
      routeExtensions: makeManagedSponsorshipRouteExtensions({
        signedDelegateRoute: '/delegate/submit',
        sponsoredEvmRoute: '/gas/relay',
        authService: service,
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
    expect(prepareOnlyIds.has('email_recovery_ecdsa_respond')).toBe(true);
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
    expect(executableIds.has('email_recovery_ecdsa_respond')).toBe(true);
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
      routeExtensions: makeManagedSponsorshipRouteExtensions({
        signedDelegateRoute: '/delegate/submit',
        sponsoredEvmRoute: '/gas/relay',
        authService: service,
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
      routeExtensions: makeManagedSponsorshipRouteExtensions({
        signedDelegateRoute: '/delegate/submit',
        sponsoredEvmRoute: '/gas/relay',
        authService: service,
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

  test('route extensions are surfaced and mounted by supported transport', async () => {
    const service = makeRouterApiServiceBagFixture();
    const cloudflareRoute = voiceIdTestRoute(
      'voiceid_owner_presence_cloudflare',
      'POST',
      '/voiceid/owner-presence',
    );
    const capabilitiesRoute = voiceIdTestRoute('voiceid_capabilities', 'GET', '/voiceid/capabilities');
    const extensions: RouterApiRouteExtension[] = [
      {
        kind: 'cloudflare_route_extension',
        id: 'voiceid-cloudflare',
        routes: [cloudflareRoute],
        handleCloudflareRoute: ({ route }) =>
          new Response(JSON.stringify({ routeId: route.id, runtime: 'cloudflare' }), {
            headers: { 'Content-Type': 'application/json' },
          }),
      },
      {
        kind: 'cloudflare_route_extension',
        id: 'voiceid-capabilities',
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
    expect(cloudflareIds.has('voiceid_owner_presence_cloudflare')).toBe(true);
    expect(cloudflareIds.has('voiceid_capabilities')).toBe(true);

    const ownerPresenceResponse = await callCf(cloudflareHandler, {
      method: 'POST',
      path: '/voiceid/owner-presence',
      body: {},
    });
    expect(ownerPresenceResponse.status).toBe(200);
    expect(ownerPresenceResponse.json).toEqual({
      routeId: 'voiceid_owner_presence_cloudflare',
      runtime: 'cloudflare',
    });

    const expressRouter = createRouterApiRouter(service, { routeExtensions: extensions });
    const expressSurface = getRouterApiRouteSurface(expressRouter);
    const expressIds = new Set((expressSurface?.routeDefinitions || []).map((route) => route.id));
    expect(expressIds.has('voiceid_owner_presence_cloudflare')).toBe(true);
    expect(expressIds.has('voiceid_capabilities')).toBe(true);
  });

  test('console Router API route extensions own managed registration and wallet API routes', async () => {
    const service = makeRouterApiServiceBagFixture();
    const extensions = createConsoleRouterApiRouteExtensions({
      apiKeyAuth: {} as any,
      bootstrapGrantBroker: {} as any,
      wallets: {} as any,
    });
    const cloudflareSurface = getRouterApiRouteSurface(
      createCloudflareRouter(service, { routeExtensions: extensions }),
    );
    const routes = cloudflareSurface?.routeDefinitions || [];

    const bootstrapGrant = routes.find((route) => route.id === 'registration_bootstrap_grants');
    expect(bootstrapGrant).toBeTruthy();
    expect(bootstrapGrant?.auth).toMatchObject({
      plane: 'api_credentials',
      credentials: ['publishable_key'],
    });

    const apiWalletList = routes.find((route) => route.id === 'api_wallets_list');
    expect(apiWalletList).toBeTruthy();
    expect(apiWalletList?.auth).toMatchObject({
      plane: 'api_credentials',
      credentials: ['secret_key'],
      scopes: ['wallets.read'],
    });
    expect(apiWalletList?.metering).toEqual({ kind: 'none' });

    const apiWalletRoute = routes.find((route) => route.id === 'api_wallets_get');
    expect(apiWalletRoute?.path).toBe('/v1/wallets/:id');
  });

  test('route extensions cannot shadow existing Router API routes', async () => {
    const service = makeRouterApiServiceBagFixture();
    const extension: RouterApiRouteExtension = {
      kind: 'cloudflare_route_extension',
      id: 'conflicting-extension',
      routes: [voiceIdTestRoute('conflicting_session_state', 'GET', '/session/state')],
      handleCloudflareRoute: () => new Response(null, { status: 204 }),
    };

    expect(() => createCloudflareRouter(service, { routeExtensions: [extension] })).toThrow(
      /duplicate Router API route definition path GET \/session\/state/,
    );
  });

  test('Router API routers run without optional VoiceID module registered', async () => {
    const service = makeRouterApiServiceBagFixture();

    const cloudflareHandler = createCloudflareRouter(service, {});
    const cloudflareSurface = getRouterApiRouteSurface(cloudflareHandler);
    const cloudflareIds = new Set(
      (cloudflareSurface?.routeDefinitions || []).map((route) => route.id),
    );
    expect(cloudflareIds.has('voice_id_health')).toBe(false);

    const missingVoiceIdResponse = await callCf(cloudflareHandler, {
      method: 'GET',
      path: '/voice-id/health',
    });
    expect(missingVoiceIdResponse.status).toBe(404);

    const expressRouter = createRouterApiRouter(service, {});
    const expressSurface = getRouterApiRouteSurface(expressRouter);
    const expressIds = new Set((expressSurface?.routeDefinitions || []).map((route) => route.id));
    expect(expressIds.has('voice_id_health')).toBe(false);
  });

  test('Router API modules register VoiceID routes across Cloudflare and Express', async () => {
    const service = makeRouterApiServiceBagFixture();
    const voiceIdModule: RouterApiModule = createVoiceIdRouterApiModule(
      createVoiceIdServerCapability({
        kind: 'service',
        service: createDefaultVoiceIdService({ verifierMode: 'fake' }),
      }),
    );

    const cloudflareHandler = createCloudflareRouter(service, { modules: [voiceIdModule] });
    const cloudflareSurface = getRouterApiRouteSurface(cloudflareHandler);
    const cloudflareIds = new Set(
      (cloudflareSurface?.routeDefinitions || []).map((route) => route.id),
    );
    expect(cloudflareIds.has('voice_id_health')).toBe(true);
    expect(cloudflareIds.has('voice_id_verification_sample')).toBe(true);
    expect(cloudflareIds.has('voice_id_owner_presence_authorize')).toBe(true);

    const healthResponse = await callCf(cloudflareHandler, {
      method: 'GET',
      path: '/voice-id/health',
    });
    expect(healthResponse.status).toBe(200);
    expect(healthResponse.json?.kind).toBe('ok');
    expect(healthResponse.json?.service).toBe('voice-id-api');

    const enrollmentStart = okValue<{ record: { enrollmentId: string } }>(
      (
        await callCf(cloudflareHandler, {
          method: 'POST',
          path: '/voice-id/enrollment/start',
          body: {
            userId: 'owner',
            phrase: 'Walking on clouds',
          },
        })
      ).json,
    );

    for (let attemptNumber = 1; attemptNumber <= 3; attemptNumber += 1) {
      const sample = await callCfFormData(
        cloudflareHandler,
        '/voice-id/enrollment/sample',
        voiceIdSampleForm({
          fields: {
            userId: 'owner',
            enrollmentId: enrollmentStart.record.enrollmentId,
            expectedPhrase: 'Walking on clouds',
            spokenPhrase: 'Walking on clouds',
            attemptNumber,
          },
          speakerLabel: 'owner',
        }),
      );
      expect(sample.status).toBe(200);
      expect(sample.json?.kind).toBe('ok');
    }

    const finalized = okValue<{ state: string }>(
      (
        await callCf(cloudflareHandler, {
          method: 'POST',
          path: '/voice-id/enrollment/finalize',
          body: {
            userId: 'owner',
            enrollmentId: enrollmentStart.record.enrollmentId,
          },
        })
      ).json,
    );
    expect(finalized.state).toBe('enrolled');

    const verificationStart = okValue<{ record: { verificationId: string } }>(
      (
        await callCf(cloudflareHandler, {
          method: 'POST',
          path: '/voice-id/verification/start',
          body: {
            userId: 'owner',
            enrollmentId: enrollmentStart.record.enrollmentId,
            phrase: 'Walking on clouds',
            ...voiceIdIntentBindingBody(),
          },
        })
      ).json,
    );

    const verificationSample = await callCfFormData(
      cloudflareHandler,
      '/voice-id/verification/sample',
      voiceIdSampleForm({
        fields: {
          userId: 'owner',
          enrollmentId: enrollmentStart.record.enrollmentId,
          verificationId: verificationStart.record.verificationId,
          expectedPhrase: 'Walking on clouds',
          spokenPhrase: 'Walking on clouds',
          attemptNumber: 1,
        },
        speakerLabel: 'owner',
      }),
    );
    const verificationResult = okValue<{ kind: string }>(verificationSample.json);
    expect(verificationResult.kind).toBe('accepted');

    const ownerPresence = okValue<{
      ownerPresence: { kind: string; intentDigest: string };
      decision: { kind: string; evidence?: { intentDigest: string } };
    }>(
      (
        await callCf(cloudflareHandler, {
          method: 'POST',
          path: '/voice-id/owner-presence/authorize',
          body: voiceIdOwnerPresenceAuthorizationBody(verificationStart.record.verificationId),
        })
      ).json,
    );
    expect(ownerPresence.ownerPresence.kind).toBe('accepted');
    expect(ownerPresence.ownerPresence.intentDigest).toBe(VOICE_ID_TEST_INTENT_DIGEST);
    expect(ownerPresence.decision.kind).toBe('accepted');
    expect(ownerPresence.decision.evidence?.intentDigest).toBe(VOICE_ID_TEST_INTENT_DIGEST);

    const expressRouter = createRouterApiRouter(service, { modules: [voiceIdModule] });
    const expressSurface = getRouterApiRouteSurface(expressRouter);
    const expressIds = new Set((expressSurface?.routeDefinitions || []).map((route) => route.id));
    expect(expressIds.has('voice_id_health')).toBe(true);
    expect(expressIds.has('voice_id_verification_sample')).toBe(true);
    expect(expressIds.has('voice_id_owner_presence_authorize')).toBe(true);
  });

  test('Router API modules reject duplicate module ids', async () => {
    const service = makeRouterApiServiceBagFixture();
    const route = voiceIdTestRoute('voiceid_duplicate_module_route', 'GET', '/voiceid/dupe');
    const extension: RouterApiRouteExtension = {
      kind: 'cloudflare_route_extension',
      id: 'duplicate-module-extension',
      routes: [route],
      handleCloudflareRoute: () => new Response(null, { status: 204 }),
    };
    const first = createRouterApiModule({ id: 'voiceid', routeExtensions: [extension] });
    const second = createRouterApiModule({ id: 'voiceid', routeExtensions: [extension] });

    expect(() => createCloudflareRouter(service, { modules: [first, second] })).toThrow(
      /duplicate Router API module id voiceid/,
    );
  });
});
