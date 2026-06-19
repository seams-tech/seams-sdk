import { expect, test } from '@playwright/test';
import type { Request as ExpressRequest, Response as ExpressResponse } from 'express';
import { createInMemoryConsoleApiKeyService } from '../../packages/sdk-server-ts/src/console/apiKeys';
import { createInMemoryConsoleRuntimeSnapshotService } from '../../packages/sdk-server-ts/src/console/runtimeSnapshots';
import { createInMemoryConsoleSponsoredCallService } from '../../packages/sdk-server-ts/src/console/sponsoredCalls';
import { createCloudflareRouter } from '../../packages/sdk-server-ts/src/router/cloudflare/createCloudflareRouter';
import { createRelayRouter } from '../../packages/sdk-server-ts/src/router/express/createRelayRouter';
import {
  createRelayRouterModule,
  type RelayRouterModule,
} from '../../packages/sdk-server-ts/src/router/modules';
import type { RelayRouteExtension } from '../../packages/sdk-server-ts/src/router/routeExtensions';
import { defineRoute } from '../../packages/sdk-server-ts/src/router/routeDefinitions';
import { getRelayRouteSurface } from '../../packages/sdk-server-ts/src/router/relayRouteSurface';
import {
  parseRouterAbPublicKeysetV2,
  ROUTER_AB_PUBLIC_KEYSET_VERSION_V2,
} from '@shared/utils/routerAbPublicKeyset';
import {
  createDefaultVoiceIdService,
  createVoiceIdRelayRouterModule,
  createVoiceIdServerCapability,
} from '../../voiceId/server/src/index';
import { callCf } from '../relayer/helpers';
import { makeFakeAuthService } from '../relayer/helpers';

type ExpressRouteEntry = {
  method: string;
  path: string;
};

type CloudflareRelayHandler = ReturnType<typeof createCloudflareRouter>;

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

function listExpressRoutes(router: unknown): ExpressRouteEntry[] {
  const entries: ExpressRouteEntry[] = [];

  const visitStack = (stack: unknown): void => {
    if (!Array.isArray(stack)) return;
    for (const layer of stack) {
      if (!layer || typeof layer !== 'object') continue;
      const route = (layer as { route?: { path?: unknown; methods?: Record<string, boolean> } })
        .route;
      if (route && typeof route.path === 'string' && route.methods) {
        for (const [method, enabled] of Object.entries(route.methods)) {
          if (!enabled) continue;
          entries.push({ method: method.toUpperCase(), path: route.path });
        }
      }
      const nested = (layer as { handle?: { stack?: unknown } }).handle?.stack;
      if (nested) visitStack(nested);
    }
  };

  visitStack((router as { stack?: unknown })?.stack);
  return entries;
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
  handler: CloudflareRelayHandler,
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

test.describe('relay route surface wiring', () => {
  test('attached route surface matches registered express routes', async () => {
    const service = makeFakeAuthService();
    const router = createRelayRouter(service, {
      healthz: true,
      readyz: true,
      signingSessionSeal: {
        enabled: true,
        basePath: '/threshold/custom-signing-session',
        service: {} as any,
      },
      sessionRoutes: { state: '/session/me' },
      signedDelegate: { route: '/delegate/submit' },
      sponsoredEvmCall: {
        route: '/gas/relay',
        apiKeys: {} as any,
        billing: {} as any,
        ledger: {} as any,
        runtimeSnapshots: {} as any,
        config: null,
      },
    });

    const surface = getRelayRouteSurface(router);
    expect(surface).toBeTruthy();
    expect(surface?.mePath).toBe('/session/me');
    expect(surface?.signedDelegatePath).toBe('/delegate/submit');

    const actualKeys = new Set(
      listExpressRoutes(router)
        .filter((entry) => entry.method !== 'HEAD' && entry.method !== 'OPTIONS')
        .map((entry) => `${entry.method} ${entry.path}`),
    );
    const expectedKeys = new Set(
      canonicalRouteKeys(
        (surface?.routeDefinitions || []).map((route) => ({
          method: route.method,
          path: route.path,
          aliases: route.aliases,
        })),
      ),
    );

    expect([...expectedKeys].filter((key) => !actualKeys.has(key))).toEqual([]);
    expect([...actualKeys].filter((key) => !expectedKeys.has(key))).toEqual([]);
  });

  test('conditional relay route families are only attached when enabled', async () => {
    const service = makeFakeAuthService();
    const router = createRelayRouter(service, {});
    const surface = getRelayRouteSurface(router);
    const ids = new Set((surface?.routeDefinitions || []).map((route) => route.id));

    expect(ids.has('relay_healthz')).toBe(false);
    expect(ids.has('relay_readyz')).toBe(false);
    expect(ids.has('signed_delegate')).toBe(false);
    expect(ids.has('sponsored_evm_call')).toBe(false);
    expect(ids.has('signing_session_seal_apply_server_seal')).toBe(false);
    expect(ids.has('signing_session_seal_remove_server_seal')).toBe(false);
  });

  test('cloudflare and express attach the same configured relay route surface', async () => {
    const service = makeFakeAuthService();
    const options = {
      healthz: true,
      signingSessionSeal: {
        enabled: true,
        basePath: '/threshold/custom-signing-session',
        service: {} as any,
      },
      readyz: true,
      sessionRoutes: { state: '/session/me' },
      signedDelegate: { route: '/delegate/submit' },
      sponsoredEvmCall: {
        route: '/gas/relay',
        apiKeys: {} as any,
        billing: {} as any,
        ledger: {} as any,
        runtimeSnapshots: {} as any,
        config: null,
      },
    };

    const expressSurface = getRelayRouteSurface(createRelayRouter(service, options));
    const cloudflareSurface = getRelayRouteSurface(createCloudflareRouter(service, options));

    expect(cloudflareSurface).toEqual(expressSurface);
  });

  test('cloudflare handler recognizes every seeded relay route definition', async () => {
    const service = makeFakeAuthService();
    const apiKeys = createInMemoryConsoleApiKeyService();
    const runtimeSnapshots = createInMemoryConsoleRuntimeSnapshotService();
    const ledger = createInMemoryConsoleSponsoredCallService();
    const handler = createCloudflareRouter(service, {
      corsOrigins: ['https://example.localhost'],
      healthz: true,
      readyz: true,
      routerAbPublicKeyset: ROUTER_AB_PUBLIC_KEYSET,
      signingSessionSeal: {
        enabled: true,
        basePath: '/threshold/custom-signing-session',
        service: {} as any,
      },
      sessionRoutes: { state: '/session/me' },
      signedDelegate: { route: '/delegate/submit' },
      sponsoredEvmCall: {
        route: '/gas/relay',
        apiKeys,
        billing: {
          async recordUsageEvent() {
            return {
              accepted: true,
              counted: true,
              monthUtc: '2026-03',
              monthlyActiveWallets: 1,
            };
          },
          async recordSponsoredExecutionDebit() {
            return {
              accepted: true,
              debitAppliedMinor: 0,
              creditBalanceMinor: 0,
              monthUtc: '2026-03',
              statementId: 'inv_202603_001',
            };
          },
        } as any,
        ledger,
        runtimeSnapshots,
        config: {
          executorsByChain: new Map([
            [
              42_431,
              {
                chainId: 42_431,
                rpcUrl: 'https://rpc.example.test',
                sponsorAddress: '0x2222222222222222222222222222222222222222',
                sponsorPrivateKeyHex:
                  '0x1111111111111111111111111111111111111111111111111111111111111111',
                maxPriorityFeePerGasFloor: 2_000_000_000n,
                maxFeePerGasFloor: 40_000_000_000n,
              },
            ],
          ]),
        },
      },
    });
    const surface = getRelayRouteSurface(handler);
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
    const service = makeFakeAuthService();
    const cloudflareRoute = voiceIdTestRoute(
      'voiceid_owner_presence_cloudflare',
      'POST',
      '/voiceid/owner-presence',
    );
    const expressRoute = voiceIdTestRoute(
      'voiceid_owner_presence_express',
      'GET',
      '/voiceid/express-owner-presence',
    );
    const universalRoute = voiceIdTestRoute('voiceid_capabilities', 'GET', '/voiceid/capabilities');
    const extensions: RelayRouteExtension[] = [
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
        kind: 'express_route_extension',
        id: 'voiceid-express',
        routes: [expressRoute],
        registerExpressRoutes: ({ router, routes }) => {
          for (const route of routes) {
            router.get(route.path, (_req: ExpressRequest, res: ExpressResponse) => {
              res.json({ routeId: route.id, runtime: 'express' });
            });
          }
        },
      },
      {
        kind: 'universal_route_extension',
        id: 'voiceid-universal',
        routes: [universalRoute],
        handleCloudflareRoute: ({ route }) =>
          new Response(JSON.stringify({ routeId: route.id, runtime: 'cloudflare' }), {
            headers: { 'Content-Type': 'application/json' },
          }),
        registerExpressRoutes: ({ router, routes }) => {
          for (const route of routes) {
            router.get(route.path, (_req: ExpressRequest, res: ExpressResponse) => {
              res.json({ routeId: route.id, runtime: 'express' });
            });
          }
        },
      },
    ];

    const cloudflareHandler = createCloudflareRouter(service, { routeExtensions: extensions });
    const cloudflareSurface = getRelayRouteSurface(cloudflareHandler);
    const cloudflareIds = new Set(
      (cloudflareSurface?.routeDefinitions || []).map((route) => route.id),
    );
    expect(cloudflareIds.has('voiceid_owner_presence_cloudflare')).toBe(true);
    expect(cloudflareIds.has('voiceid_owner_presence_express')).toBe(false);
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

    const expressRouter = createRelayRouter(service, { routeExtensions: extensions });
    const expressSurface = getRelayRouteSurface(expressRouter);
    const expressIds = new Set((expressSurface?.routeDefinitions || []).map((route) => route.id));
    expect(expressIds.has('voiceid_owner_presence_cloudflare')).toBe(false);
    expect(expressIds.has('voiceid_owner_presence_express')).toBe(true);
    expect(expressIds.has('voiceid_capabilities')).toBe(true);

    const expressKeys = new Set(
      listExpressRoutes(expressRouter).map((entry) => `${entry.method} ${entry.path}`),
    );
    expect(expressKeys.has('GET /voiceid/express-owner-presence')).toBe(true);
    expect(expressKeys.has('GET /voiceid/capabilities')).toBe(true);
    expect(expressKeys.has('POST /voiceid/owner-presence')).toBe(false);
  });

  test('route extensions cannot shadow existing relay routes', async () => {
    const service = makeFakeAuthService();
    const extension: RelayRouteExtension = {
      kind: 'cloudflare_route_extension',
      id: 'conflicting-extension',
      routes: [voiceIdTestRoute('conflicting_session_state', 'GET', '/session/state')],
      handleCloudflareRoute: () => new Response(null, { status: 204 }),
    };

    expect(() => createCloudflareRouter(service, { routeExtensions: [extension] })).toThrow(
      /duplicate relay route definition path GET \/session\/state/,
    );
  });

  test('relay routers run without optional VoiceID module registered', async () => {
    const service = makeFakeAuthService();

    const cloudflareHandler = createCloudflareRouter(service, {});
    const cloudflareSurface = getRelayRouteSurface(cloudflareHandler);
    const cloudflareIds = new Set(
      (cloudflareSurface?.routeDefinitions || []).map((route) => route.id),
    );
    expect(cloudflareIds.has('voice_id_health')).toBe(false);

    const missingVoiceIdResponse = await callCf(cloudflareHandler, {
      method: 'GET',
      path: '/voice-id/health',
    });
    expect(missingVoiceIdResponse.status).toBe(404);

    const expressRouter = createRelayRouter(service, {});
    const expressSurface = getRelayRouteSurface(expressRouter);
    const expressIds = new Set((expressSurface?.routeDefinitions || []).map((route) => route.id));
    expect(expressIds.has('voice_id_health')).toBe(false);

    const expressKeys = new Set(
      listExpressRoutes(expressRouter).map((entry) => `${entry.method} ${entry.path}`),
    );
    expect(expressKeys.has('GET /voice-id/health')).toBe(false);
  });

  test('relay modules register VoiceID routes across Cloudflare and Express', async () => {
    const service = makeFakeAuthService();
    const voiceIdModule: RelayRouterModule = createVoiceIdRelayRouterModule(
      createVoiceIdServerCapability({
        kind: 'service',
        service: createDefaultVoiceIdService({ verifierMode: 'fake' }),
      }),
    );

    const cloudflareHandler = createCloudflareRouter(service, { modules: [voiceIdModule] });
    const cloudflareSurface = getRelayRouteSurface(cloudflareHandler);
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

    const expressRouter = createRelayRouter(service, { modules: [voiceIdModule] });
    const expressSurface = getRelayRouteSurface(expressRouter);
    const expressIds = new Set((expressSurface?.routeDefinitions || []).map((route) => route.id));
    expect(expressIds.has('voice_id_health')).toBe(true);
    expect(expressIds.has('voice_id_verification_sample')).toBe(true);
    expect(expressIds.has('voice_id_owner_presence_authorize')).toBe(true);

    const expressKeys = new Set(
      listExpressRoutes(expressRouter).map((entry) => `${entry.method} ${entry.path}`),
    );
    expect(expressKeys.has('GET /voice-id/health')).toBe(true);
    expect(expressKeys.has('POST /voice-id/verification/sample')).toBe(true);
    expect(expressKeys.has('POST /voice-id/owner-presence/authorize')).toBe(true);
  });

  test('relay modules reject duplicate module ids', async () => {
    const service = makeFakeAuthService();
    const route = voiceIdTestRoute('voiceid_duplicate_module_route', 'GET', '/voiceid/dupe');
    const extension: RelayRouteExtension = {
      kind: 'cloudflare_route_extension',
      id: 'duplicate-module-extension',
      routes: [route],
      handleCloudflareRoute: () => new Response(null, { status: 204 }),
    };
    const first = createRelayRouterModule({ id: 'voiceid', routeExtensions: [extension] });
    const second = createRelayRouterModule({ id: 'voiceid', routeExtensions: [extension] });

    expect(() => createCloudflareRouter(service, { modules: [first, second] })).toThrow(
      /duplicate relay router module id voiceid/,
    );
  });
});
