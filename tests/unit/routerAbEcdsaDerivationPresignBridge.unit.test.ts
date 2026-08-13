import { expect, test } from '@playwright/test';
import {
  parseCloudflareSigningWorkerEcdsaDerivationPresignaturePoolPutReceiptV1,
  parseCloudflareSigningWorkerEcdsaDerivationPresignaturePoolPutRequestV1,
  parseRouterAbEcdsaDerivationNormalSigningScopeV1,
  type CloudflareSigningWorkerEcdsaDerivationPresignaturePoolPutReceiptV1Wire,
  type CloudflareSigningWorkerEcdsaDerivationPresignaturePoolPutRequestV1Wire,
  type RouterAbEcdsaDerivationNormalSigningScopeV1,
} from '@shared/utils/routerAbEcdsaDerivation';
import {
  buildRouterAbEcdsaDerivationPresignaturePoolPutRequest,
  CLOUDFLARE_SIGNING_WORKER_ECDSA_DERIVATION_PRESIGNATURE_POOL_PUT_PATH,
  CLOUDFLARE_SIGNING_WORKER_ECDSA_PRESIGN_SESSION_INIT_PATH,
  CLOUDFLARE_SIGNING_WORKER_ECDSA_PRESIGN_SESSION_STEP_PATH,
  putRouterAbEcdsaDerivationPresignaturePoolFill,
  ROUTER_AB_INTERNAL_SERVICE_AUTH_HEADER_V1,
  startRouterAbEcdsaPresignSession,
  stepRouterAbEcdsaPresignSession,
} from '@server/core/ThresholdService/routerAb/ecdsaDerivationPresignBridge';
import { parseRouterAbNormalSigningRuntimeConfig } from '@server/core/routerAbSigning/RouterAbNormalSigningRuntime';
import { RouterAbEcdsaDerivationPoolFillHandlers } from '@server/core/ThresholdService/routerAb/ecdsaDerivationPoolFillHandlers';
import { routerAbMpcMaterialActivationRefToWire } from '@shared/utils/routerAbNormalSigningIdentity';
import { buildMpcMaterialActivationRefFixture } from './helpers/ecdsaMaterialRef.fixtures';

function b64u(byte: number, length: number): string {
  return Buffer.from(new Uint8Array(length).fill(byte)).toString('base64url');
}

const materialActivation = routerAbMpcMaterialActivationRefToWire(
  buildMpcMaterialActivationRefFixture('presign-bridge'),
);

const scope: RouterAbEcdsaDerivationNormalSigningScopeV1 = {
  wallet_id: 'wallet-1',
  ecdsa_threshold_key_id: 'ecdsa-key-1',
  signing_root_id: 'project-1:env-1',
  signing_root_version: 'root-v1',
  context: {
    application_binding_digest_b64u: 'BwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwc',
  },
  public_identity: {
    context_binding_b64u: b64u(1, 32),
    derivation_client_share_public_key33_b64u: b64u(2, 33),
    server_public_key33_b64u: b64u(3, 33),
    threshold_public_key33_b64u: b64u(2, 33),
    ethereum_address20_b64u: b64u(5, 20),
    client_share_retry_counter: 0,
    server_share_retry_counter: 1,
  },
  material_activation: materialActivation,
  signing_worker: {
    server_id: 'signing-worker-1',
    key_epoch: 'worker-epoch-1',
    recipient_encryption_key:
      'x25519:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
  },
  activation_epoch: 'activation-1',
};

const presignature = {
  serverKeyId: 'server-key-1',
  presignatureId: 'presig-client-selected',
  bigRB64u: b64u(2, 33),
  kShareB64u: b64u(7, 32),
  sigmaShareB64u: b64u(8, 32),
  createdAtMs: 1_800_000_000_000,
};

function digest(byte: number): { bytes: number[] } {
  return { bytes: Array.from(new Uint8Array(32).fill(byte)) };
}

const hostedSigningWorkerFetch: typeof fetch = async () => Response.json({ ok: true });

type StatelessPresignScenario = {
  readonly requests: Array<{ url: string; body: Record<string, unknown> }>;
};

let statelessPresignScenario: StatelessPresignScenario | null = null;

function requireStatelessPresignScenario(): StatelessPresignScenario {
  if (!statelessPresignScenario) throw new Error('stateless presign scenario is not active');
  return statelessPresignScenario;
}

async function statelessPresignFetch(input: RequestInfo | URL, init?: RequestInit) {
  const scenario = requireStatelessPresignScenario();
  const url = String(input);
  const body = JSON.parse(String(init?.body || '{}')) as Record<string, unknown>;
  scenario.requests.push({ url, body });
  if (url.endsWith(CLOUDFLARE_SIGNING_WORKER_ECDSA_PRESIGN_SESSION_INIT_PATH)) {
    return Response.json({
      kind: 'continue',
      presign_session_id: body.presign_session_id,
      stage: 'triples',
      event: 'none',
      outgoing_messages_b64u: [],
    });
  }
  return Response.json({
    kind: 'complete',
    presign_session_id: body.presign_session_id,
    server_presignature_id: 'presignature-private-do-1',
    server_big_r33_b64u: b64u(2, 33),
  });
}

async function readyPresignRuntime(): Promise<void> {}

function fixturePresignSessionId(expiresAtMs: number): string {
  return `ecdsa-presign-v2:${expiresAtMs}:fixture`;
}

function request(): CloudflareSigningWorkerEcdsaDerivationPresignaturePoolPutRequestV1Wire {
  return buildRouterAbEcdsaDerivationPresignaturePoolPutRequest({
    scope,
    presignature,
    expiresAtMs: 1_800_000_060_000,
  });
}

function receipt(
  req: CloudflareSigningWorkerEcdsaDerivationPresignaturePoolPutRequestV1Wire,
  stored: boolean,
): CloudflareSigningWorkerEcdsaDerivationPresignaturePoolPutReceiptV1Wire {
  return {
    active_signing_worker_state: {
      account_id: scope.wallet_id,
      material_activation: materialActivation,
      account_public_key: scope.public_identity.threshold_public_key33_b64u,
      signing_worker: scope.signing_worker,
      activation_transcript_digest: digest(9),
      activation_digest: digest(10),
      signing_worker_material_handle: 'material-1',
      activated_at_ms: 1_800_000_000_100,
    },
    server_presignature_id: req.server_presignature_id,
    server_big_r33_b64u: req.server_big_r33_b64u,
    stored,
  };
}

test.describe('Router A/B ECDSA derivation presign bridge', () => {
  test('keeps presign coordination exclusively in the SigningWorker session route', async () => {
    const expiresAtMs = Date.now() + 60_000;
    const requests: Array<{ url: string; body: Record<string, unknown> }> = [];
    statelessPresignScenario = { requests };
    const handlers = new RouterAbEcdsaDerivationPoolFillHandlers({
      nodeRole: 'coordinator',
      participantIds2p: [1, 2],
      ensureReady: readyPresignRuntime,
      createPoolFillSessionId: fixturePresignSessionId,
      signingWorkerTransport: {
        signingWorkerBaseUrl: 'http://signing-worker.internal',
        auth: { kind: 'internal_service_auth_secret', secret: 'test-secret' },
        fetchImpl: statelessPresignFetch,
      },
    });
    const claims = {
      walletId: scope.wallet_id,
      relayerKeyId: 'relayer-key-1',
      keyHandle: 'key-handle-1',
      runtimePolicyScope: {
        orgId: 'org-1',
        projectId: 'project-1',
        envId: 'env-1',
        signingRootVersion: 'root-v1',
      },
      participantIds: [1, 2],
      thresholdExpiresAtMs: expiresAtMs + 10_000,
      routerAbEcdsaDerivationNormalSigning: {
        kind: 'router_ab_ecdsa_derivation_normal_signing_v1' as const,
        scope,
      },
    };

    const initialized = await handlers.routerAbEcdsaDerivationPresignaturePoolFillInit({
      claims,
      request: {
        keyHandle: claims.keyHandle,
        count: 1,
        poolFill: {
          kind: 'router_ab_ecdsa_derivation_signing_worker_pool',
          scope,
          expiresAtMs,
        },
      },
    });
    if (!initialized.ok) throw new Error(`${initialized.code}: ${initialized.message}`);
    expect(initialized).toMatchObject({
      ok: true,
      presignSessionId: `ecdsa-presign-v2:${expiresAtMs}:fixture`,
      stage: 'triples',
    });
    if (!initialized.presignSessionId) {
      throw new Error('expected initialized presign session');
    }

    const completed = await handlers.routerAbEcdsaDerivationPresignaturePoolFillStep({
      claims,
      request: {
        presignSessionId: initialized.presignSessionId,
        stage: 'presign',
        outgoingMessagesB64u: [],
      },
    });
    expect(completed).toMatchObject({
      ok: true,
      stage: 'done',
      event: 'presign_done',
      presignatureId: 'presignature-private-do-1',
    });
    expect(requests).toHaveLength(2);
    expect(requests[0]?.body.expires_at_ms).toBe(expiresAtMs);
    expect(requests[1]?.body.expires_at_ms).toBe(expiresAtMs);
    statelessPresignScenario = null;
  });

  test('preserves the hosted SigningWorker service-binding transport', () => {
    const config = parseRouterAbNormalSigningRuntimeConfig({
      ROUTER_AB_NORMAL_SIGNING_WORKER_ID: 'signing-worker-1',
      ROUTER_AB_SIGNING_WORKER_URL: 'https://signing-worker.router-ab.internal',
      ROUTER_AB_INTERNAL_SERVICE_AUTH_SECRET: 'test-secret',
      routerAbSigningWorkerFetch: hostedSigningWorkerFetch,
    });
    expect(config.signingWorkerTransport.kind).toBe('configured');
    if (config.signingWorkerTransport.kind !== 'configured') {
      throw new Error('expected configured SigningWorker transport');
    }
    expect(config.signingWorkerTransport.fetchImpl).toBe(hostedSigningWorkerFetch);
  });

  test('relays presign init and step through the SigningWorker without server shares', async () => {
    const requests: Array<{ url: string; body: Record<string, unknown> }> = [];
    const fetchImpl: typeof fetch = async (input, init) => {
      const url = String(input);
      requests.push({
        url,
        body: JSON.parse(String(init?.body || '{}')) as Record<string, unknown>,
      });
      if (url.endsWith(CLOUDFLARE_SIGNING_WORKER_ECDSA_PRESIGN_SESSION_INIT_PATH)) {
        return new Response(
          JSON.stringify({
            kind: 'continue',
            presign_session_id: 'presign-session-1',
            stage: 'triples',
            event: 'none',
            outgoing_messages_b64u: [b64u(9, 4)],
          }),
          { status: 200 },
        );
      }
      return new Response(
        JSON.stringify({
          kind: 'complete',
          presign_session_id: 'presign-session-1',
          server_presignature_id: 'presig-public-1',
          server_big_r33_b64u: b64u(2, 33),
        }),
        { status: 200 },
      );
    };

    const started = await startRouterAbEcdsaPresignSession({
      signingWorkerBaseUrl: 'http://127.0.0.1:9103',
      scope,
      presignSessionId: 'presign-session-1',
      expiresAtMs: 1_800_000_060_000,
      auth: { kind: 'internal_service_auth_secret', secret: 'test-secret' },
      fetchImpl,
    });
    expect(started).toMatchObject({
      ok: true,
      value: { kind: 'continue', presignSessionId: 'presign-session-1', stage: 'triples' },
    });

    const stepped = await stepRouterAbEcdsaPresignSession({
      signingWorkerBaseUrl: 'http://127.0.0.1:9103',
      scope,
      presignSessionId: 'presign-session-1',
      requestedStage: 'presign',
      outgoingMessagesB64u: [b64u(10, 4)],
      expiresAtMs: 1_800_000_060_000,
      auth: { kind: 'internal_service_auth_secret', secret: 'test-secret' },
      fetchImpl,
    });
    expect(stepped).toMatchObject({
      ok: true,
      value: {
        kind: 'complete',
        presignSessionId: 'presign-session-1',
        serverPresignatureId: 'presig-public-1',
      },
    });
    expect(requests[0]?.url).toContain(CLOUDFLARE_SIGNING_WORKER_ECDSA_PRESIGN_SESSION_INIT_PATH);
    expect(requests[0]?.body).not.toHaveProperty('relayer_share32_b64u');
    expect(requests[1]?.url).toContain(CLOUDFLARE_SIGNING_WORKER_ECDSA_PRESIGN_SESSION_STEP_PATH);
    expect(requests[1]?.body).not.toHaveProperty('server_k_share32_b64u');
    expect(requests[1]?.body).not.toHaveProperty('server_sigma_share32_b64u');
  });

  test('maps a completed threshold ECDSA server presignature into the strict Worker pool-fill wire shape', () => {
    const poolFillRequest = request();

    expect(poolFillRequest).toEqual({
      scope,
      server_presignature_id: 'presig-client-selected',
      server_big_r33_b64u: presignature.bigRB64u,
      server_k_share32_b64u: presignature.kShareB64u,
      server_sigma_share32_b64u: presignature.sigmaShareB64u,
      expires_at_ms: 1_800_000_060_000,
    });
    expect(
      parseCloudflareSigningWorkerEcdsaDerivationPresignaturePoolPutRequestV1(poolFillRequest),
    ).toEqual(poolFillRequest);
  });

  test('requires the active Worker receipt to name material activation explicitly', () => {
    const validReceipt = receipt(request(), true);
    const parsed =
      parseCloudflareSigningWorkerEcdsaDerivationPresignaturePoolPutReceiptV1(validReceipt);
    expect(parsed.active_signing_worker_state.material_activation).toEqual(materialActivation);

    const activationIdOnlyState = {
      ...validReceipt,
      active_signing_worker_state: {
        ...validReceipt.active_signing_worker_state,
        material_activation_id: materialActivation.activation_id,
      },
    };
    delete (activationIdOnlyState.active_signing_worker_state as { material_activation?: unknown })
      .material_activation;
    expect(() =>
      parseCloudflareSigningWorkerEcdsaDerivationPresignaturePoolPutReceiptV1(
        activationIdOnlyState,
      ),
    ).toThrow(
      'receipt.active_signing_worker_state.material_activation_id is not a supported field',
    );
  });

  test('rejects loose Router A/B scope shapes before private pool-fill construction', () => {
    expect(() =>
      parseRouterAbEcdsaDerivationNormalSigningScopeV1({
        ...scope,
        public_identity: {
          ...scope.public_identity,
          threshold_public_key33_b64u: b64u(9, 32),
        },
      }),
    ).toThrow('scope.public_identity.threshold_public_key33_b64u must decode to 33 bytes');

    expect(() =>
      parseRouterAbEcdsaDerivationNormalSigningScopeV1({
        ...scope,
        context: {
          ...scope.context,
          key_scope: 'evm-family',
        },
      }),
    ).toThrow('scope.context.key_scope is not a supported field');

    expect(() =>
      parseRouterAbEcdsaDerivationNormalSigningScopeV1({
        ...scope,
        legacy_v1: true,
      }),
    ).toThrow('scope.legacy_v1 is not a supported field');

    expect(() =>
      parseRouterAbEcdsaDerivationNormalSigningScopeV1({
        ...scope,
        activation_epoch: 1,
      }),
    ).toThrow('scope.activation_epoch must be a string');
  });

  test('rejects malformed server share material and exact legacy compatibility fields', () => {
    expect(() =>
      buildRouterAbEcdsaDerivationPresignaturePoolPutRequest({
        scope,
        presignature: {
          ...presignature,
          kShareB64u: b64u(10, 31),
        },
        expiresAtMs: 1_800_000_060_000,
      }),
    ).toThrow('presignature.kShareB64u must decode to 32 bytes');

    expect(() =>
      parseCloudflareSigningWorkerEcdsaDerivationPresignaturePoolPutRequestV1({
        scope,
        server_presignature_id: presignature.presignatureId,
        server_big_r33_b64u: presignature.bigRB64u,
        server_k_share32_b64u: presignature.kShareB64u,
        server_sigma_share32_b64u: presignature.sigmaShareB64u,
        expires_at_ms: 1_800_000_060_000,
        relayerKeyId: presignature.serverKeyId,
      }),
    ).toThrow('poolFillRequest.relayerKeyId is not a supported field');

    expect(() =>
      buildRouterAbEcdsaDerivationPresignaturePoolPutRequest({
        scope,
        presignature: {
          // @ts-expect-error legacy relayer naming must stay outside the new Router A/B boundary.
          relayerKeyId: presignature.serverKeyId,
          presignatureId: presignature.presignatureId,
          bigRB64u: presignature.bigRB64u,
          kShareB64u: presignature.kShareB64u,
          sigmaShareB64u: presignature.sigmaShareB64u,
          createdAtMs: presignature.createdAtMs,
        },
        expiresAtMs: 1_800_000_060_000,
      }),
    ).toThrow('presignature.relayerKeyId is not a supported field');
  });

  test('posts the private pool-fill request to the strict SigningWorker path', async () => {
    const poolFillRequest = request();
    const calls: Array<{ url: string; init: RequestInit }> = [];
    const fetchImpl = (async (url: RequestInfo | URL, init?: RequestInit) => {
      calls.push({ url: String(url), init: init || {} });
      return new Response(JSON.stringify(receipt(poolFillRequest, true)), {
        status: 200,
        headers: { 'content-type': 'application/json' },
      });
    }) as typeof fetch;

    const result = await putRouterAbEcdsaDerivationPresignaturePoolFill({
      signingWorkerBaseUrl: 'https://signing-worker.example/base/',
      request: poolFillRequest,
      auth: { kind: 'internal_service_auth_secret', secret: 'private-route-token' },
      fetchImpl,
    });

    if (!result.ok) throw new Error(`expected pool-fill success, got ${result.code}`);
    expect(result.status).toBe(200);
    expect(calls).toHaveLength(1);
    expect(calls[0].url).toBe(
      `https://signing-worker.example/base${CLOUDFLARE_SIGNING_WORKER_ECDSA_DERIVATION_PRESIGNATURE_POOL_PUT_PATH}`,
    );
    expect(calls[0].init.method).toBe('POST');
    expect(calls[0].init.headers).toEqual({
      'content-type': 'application/json',
      [ROUTER_AB_INTERNAL_SERVICE_AUTH_HEADER_V1]: 'private-route-token',
    });
    expect(JSON.parse(String(calls[0].init.body))).toEqual(poolFillRequest);
  });

  test('returns an explicit duplicate result when the private route receipt is not stored', async () => {
    const poolFillRequest = request();
    const fetchImpl = (async () =>
      new Response(JSON.stringify(receipt(poolFillRequest, false)), {
        status: 200,
        headers: { 'content-type': 'application/json' },
      })) as typeof fetch;

    await expect(
      putRouterAbEcdsaDerivationPresignaturePoolFill({
        signingWorkerBaseUrl: 'https://signing-worker.example',
        request: poolFillRequest,
        auth: { kind: 'internal_service_auth_secret', secret: 'private-route-token' },
        fetchImpl,
      }),
    ).resolves.toEqual({
      ok: false,
      code: 'already_exists',
      message: 'Router A/B ECDSA derivation presignature already exists in the SigningWorker pool',
      status: 200,
      receipt: receipt(poolFillRequest, false),
    });
  });

  test('reports the private pool-fill target when the SigningWorker fetch fails', async () => {
    const poolFillRequest = request();
    const fetchImpl = (async () => {
      throw new Error('fetch failed');
    }) as typeof fetch;

    await expect(
      putRouterAbEcdsaDerivationPresignaturePoolFill({
        signingWorkerBaseUrl: 'http://127.0.0.1:9103',
        request: poolFillRequest,
        auth: { kind: 'internal_service_auth_secret', secret: 'private-route-token' },
        fetchImpl,
      }),
    ).resolves.toMatchObject({
      ok: false,
      code: 'network_error',
      message:
        'pool-fill request to http://127.0.0.1:9103/router-ab/signing-worker/ecdsa-derivation/presignature-pool/put failed: fetch failed',
    });
  });

  test('rejects private route receipts that do not match the pool-fill request', async () => {
    const poolFillRequest = request();
    const drifted = {
      ...receipt(poolFillRequest, true),
      server_presignature_id: 'other-presig',
    };
    const fetchImpl = (async () =>
      new Response(JSON.stringify(drifted), {
        status: 200,
        headers: { 'content-type': 'application/json' },
      })) as typeof fetch;

    await expect(
      putRouterAbEcdsaDerivationPresignaturePoolFill({
        signingWorkerBaseUrl: 'https://signing-worker.example',
        request: poolFillRequest,
        auth: { kind: 'internal_service_auth_secret', secret: 'private-route-token' },
        fetchImpl,
      }),
    ).resolves.toMatchObject({
      ok: false,
      code: 'invalid_response',
      status: 200,
      message: 'receipt.server_presignature_id does not match pool-fill request',
    });
  });
});
