import { expect, test } from '@playwright/test';
import {
  parseCloudflareSigningWorkerEcdsaHssPresignaturePoolPutRequestV1,
  parseRouterAbEcdsaHssNormalSigningScopeV1,
  type CloudflareSigningWorkerEcdsaHssPresignaturePoolPutReceiptV1Wire,
  type CloudflareSigningWorkerEcdsaHssPresignaturePoolPutRequestV1Wire,
  type RouterAbEcdsaHssNormalSigningScopeV1,
} from '@shared/utils/routerAbEcdsaHss';
import {
  buildRouterAbEcdsaHssPresignaturePoolPutRequest,
  CLOUDFLARE_SIGNING_WORKER_ECDSA_HSS_PRESIGNATURE_POOL_PUT_PATH,
  putRouterAbEcdsaHssPresignaturePoolFill,
  ROUTER_AB_INTERNAL_SERVICE_AUTH_HEADER_V1,
} from '@server/core/ThresholdService/routerAb/ecdsaHssPresignBridge';

function b64u(byte: number, length: number): string {
  return Buffer.from(new Uint8Array(length).fill(byte)).toString('base64url');
}

const scope: RouterAbEcdsaHssNormalSigningScopeV1 = {
  wallet_key_id: 'wallet-key-localhost',
  wallet_id: 'wallet-1',
  ecdsa_threshold_key_id: 'ecdsa-key-1',
  signing_root_id: 'root-1',
  signing_root_version: 'root-v1',
  context: {
    application_binding_digest_b64u: 'BwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwc',
  },
  public_identity: {
    context_binding_b64u: b64u(1, 32),
    client_public_key33_b64u: b64u(2, 33),
    server_public_key33_b64u: b64u(3, 33),
    threshold_public_key33_b64u: b64u(4, 33),
    ethereum_address20_b64u: b64u(5, 20),
    client_share_retry_counter: 0,
    server_share_retry_counter: 1,
  },
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
  bigRB64u: b64u(6, 33),
  kShareB64u: b64u(7, 32),
  sigmaShareB64u: b64u(8, 32),
  createdAtMs: 1_800_000_000_000,
};

function digest(byte: number): { bytes: number[] } {
  return { bytes: Array.from(new Uint8Array(32).fill(byte)) };
}

function request(): CloudflareSigningWorkerEcdsaHssPresignaturePoolPutRequestV1Wire {
  return buildRouterAbEcdsaHssPresignaturePoolPutRequest({
    scope,
    presignature,
    expiresAtMs: 1_800_000_060_000,
  });
}

function receipt(
  req: CloudflareSigningWorkerEcdsaHssPresignaturePoolPutRequestV1Wire,
  stored: boolean,
): CloudflareSigningWorkerEcdsaHssPresignaturePoolPutReceiptV1Wire {
  return {
    active_signing_worker_state: {
      account_id: scope.wallet_id,
      session_id: 'session-1',
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

test.describe('Router A/B ECDSA-HSS presign bridge', () => {
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
      parseCloudflareSigningWorkerEcdsaHssPresignaturePoolPutRequestV1(poolFillRequest),
    ).toEqual(poolFillRequest);
  });

  test('rejects loose Router A/B scope shapes before private pool-fill construction', () => {
    expect(() =>
      parseRouterAbEcdsaHssNormalSigningScopeV1({
        ...scope,
        public_identity: {
          ...scope.public_identity,
          threshold_public_key33_b64u: b64u(9, 32),
        },
      }),
    ).toThrow('scope.public_identity.threshold_public_key33_b64u must decode to 33 bytes');

    expect(() =>
      parseRouterAbEcdsaHssNormalSigningScopeV1({
        ...scope,
        context: {
          ...scope.context,
          key_scope: 'evm-family',
        },
      }),
    ).toThrow('scope.context.key_scope is not a supported field');

    expect(() =>
      parseRouterAbEcdsaHssNormalSigningScopeV1({
        ...scope,
        legacy_v1: true,
      }),
    ).toThrow('scope.legacy_v1 is not a supported field');

    expect(() =>
      parseRouterAbEcdsaHssNormalSigningScopeV1({
        ...scope,
        activation_epoch: 1,
      }),
    ).toThrow('scope.activation_epoch must be a string');
  });

  test('rejects malformed server share material and exact legacy compatibility fields', () => {
    expect(() =>
      buildRouterAbEcdsaHssPresignaturePoolPutRequest({
        scope,
        presignature: {
          ...presignature,
          kShareB64u: b64u(10, 31),
        },
        expiresAtMs: 1_800_000_060_000,
      }),
    ).toThrow('presignature.kShareB64u must decode to 32 bytes');

    expect(() =>
      parseCloudflareSigningWorkerEcdsaHssPresignaturePoolPutRequestV1({
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
      buildRouterAbEcdsaHssPresignaturePoolPutRequest({
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

    const result = await putRouterAbEcdsaHssPresignaturePoolFill({
      signingWorkerBaseUrl: 'https://signing-worker.example/base/',
      request: poolFillRequest,
      auth: { kind: 'internal_service_auth_token', token: 'private-route-token' },
      fetchImpl,
    });

    if (!result.ok) throw new Error(`expected pool-fill success, got ${result.code}`);
    expect(result.status).toBe(200);
    expect(calls).toHaveLength(1);
    expect(calls[0].url).toBe(
      `https://signing-worker.example/base${CLOUDFLARE_SIGNING_WORKER_ECDSA_HSS_PRESIGNATURE_POOL_PUT_PATH}`,
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
      putRouterAbEcdsaHssPresignaturePoolFill({
        signingWorkerBaseUrl: 'https://signing-worker.example',
        request: poolFillRequest,
        auth: { kind: 'internal_service_auth_token', token: 'private-route-token' },
        fetchImpl,
      }),
    ).resolves.toEqual({
      ok: false,
      code: 'already_exists',
      message: 'Router A/B ECDSA-HSS presignature already exists in the SigningWorker pool',
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
      putRouterAbEcdsaHssPresignaturePoolFill({
        signingWorkerBaseUrl: 'http://127.0.0.1:9093',
        request: poolFillRequest,
        auth: { kind: 'internal_service_auth_token', token: 'private-route-token' },
        fetchImpl,
      }),
    ).resolves.toMatchObject({
      ok: false,
      code: 'network_error',
      message:
        'pool-fill request to http://127.0.0.1:9093/router-ab/signing-worker/ecdsa-hss/presignature-pool/put failed: fetch failed',
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
      putRouterAbEcdsaHssPresignaturePoolFill({
        signingWorkerBaseUrl: 'https://signing-worker.example',
        request: poolFillRequest,
        auth: { kind: 'internal_service_auth_token', token: 'private-route-token' },
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
