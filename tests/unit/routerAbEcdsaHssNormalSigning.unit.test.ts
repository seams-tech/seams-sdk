import { expect, test } from '@playwright/test';
import {
  buildRouterAbEcdsaHssEvmDigestSigningFinalizeRequestV1,
  buildRouterAbEcdsaHssEvmDigestSigningRequestV1,
  parseRouterAbEcdsaHssEvmDigestSigningResponseForRequestV1,
  parseRouterAbEcdsaHssEvmDigestSigningPrepareResponseForRequestV1,
  parseRouterAbEcdsaHssEvmDigestSigningRequestV1,
  routerAbEcdsaHssContextBindingB64uV1,
  routerAbEcdsaHssEvmDigestSigningFinalizeRequestDigestV1,
  routerAbEcdsaHssEvmDigestSigningRequestDigestV1,
  type RouterAbEcdsaHssEvmDigestSigningFinalizeRequestV1Wire,
  type RouterAbEcdsaHssEvmDigestSigningPrepareResponseV1Wire,
  type RouterAbEcdsaHssEvmDigestSigningRequestV1Wire,
  type RouterAbEcdsaHssEvmDigestSigningResponseV1Wire,
  type RouterAbEcdsaHssNormalSigningScopeV1,
} from '@shared/utils/routerAbEcdsaHss';
import {
  finalizeRouterAbEcdsaHssEvmDigestSigningV1,
  prepareRouterAbEcdsaHssEvmDigestSigningV1,
} from '@/core/rpcClients/relayer/routerAbNormalSigning';

function b64u(byte: number, length: number): string {
  return Buffer.from(new Uint8Array(length).fill(byte)).toString('base64url');
}

function hexB64u(hex: string): string {
  return Buffer.from(hex, 'hex').toString('base64url');
}

function digest(byte: number): { bytes: number[] } {
  return { bytes: Array.from(new Uint8Array(32).fill(byte)) };
}

const ecdsaClientPublicKey33B64u = hexB64u(
  '0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798',
);
const ecdsaServerPublicKey33B64u = hexB64u(
  '02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5',
);
const ecdsaThresholdPublicKey33B64u = hexB64u(
  '02f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9',
);
const ecdsaServerBigR33B64u = hexB64u(
  '03f28773c2d975288bc7d1d205c3748651b075fbc6610e58cddeeddf8f19405aa8',
);

const stableContext = {
  wallet_id: 'wallet-1',
  rp_id: 'localhost',
  key_scope: 'evm-family',
  ecdsa_threshold_key_id: 'ecdsa-key-1',
  signing_root_id: 'root-1',
  signing_root_version: 'root-v1',
  key_purpose: 'evm-signing',
  key_version: 'v1',
} as const;

let scope: RouterAbEcdsaHssNormalSigningScopeV1;

async function buildScope(): Promise<RouterAbEcdsaHssNormalSigningScopeV1> {
  return {
    context: stableContext,
    public_identity: {
      context_binding_b64u: await routerAbEcdsaHssContextBindingB64uV1(stableContext),
      client_public_key33_b64u: ecdsaClientPublicKey33B64u,
      server_public_key33_b64u: ecdsaServerPublicKey33B64u,
      threshold_public_key33_b64u: ecdsaThresholdPublicKey33B64u,
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
}

function prepareRequest() {
  return buildRouterAbEcdsaHssEvmDigestSigningRequestV1({
    scope,
    requestId: 'ecdsa-sign-request-1',
    clientPresignatureId: 'presig-client-selected',
    expiresAtMs: 1_900_000_000_000,
    signingDigest32: new Uint8Array(32).fill(11),
  });
}

async function prepareResponse(
  request: RouterAbEcdsaHssEvmDigestSigningRequestV1Wire = prepareRequest(),
): Promise<RouterAbEcdsaHssEvmDigestSigningPrepareResponseV1Wire> {
  return {
    scope,
    request_id: request.request_id,
    budget_reservation_id: 'ecdsa-sign-budget-reservation-1',
    request_digest: await routerAbEcdsaHssEvmDigestSigningRequestDigestV1(request),
    signing_digest: digest(11),
    server_presignature_id: request.client_presignature_id,
    server_big_r33_b64u: ecdsaServerBigR33B64u,
    rerandomization_entropy32_b64u: b64u(14, 32),
    signature_scheme: 'ecdsa_secp256k1_recoverable_v1',
    prepared_at_ms: 1_800_000_000_000,
    expires_at_ms: request.expires_at_ms,
  };
}

async function signingResponse(
  request: RouterAbEcdsaHssEvmDigestSigningFinalizeRequestV1Wire,
): Promise<RouterAbEcdsaHssEvmDigestSigningResponseV1Wire> {
  return {
    scope,
    request_id: request.request_id,
    request_digest: await routerAbEcdsaHssEvmDigestSigningFinalizeRequestDigestV1(request),
    signing_digest: digest(11),
    signature_scheme: 'ecdsa_secp256k1_recoverable_v1',
    signature65_b64u: b64u(16, 65),
  };
}

test.describe('Router A/B ECDSA-HSS normal-signing boundary', () => {
  test.beforeAll(async () => {
    scope = await buildScope();
  });

  test('builds strict prepare and finalize requests', () => {
    const request = prepareRequest();
    expect(request).toEqual({
      scope,
      request_id: 'ecdsa-sign-request-1',
      client_presignature_id: 'presig-client-selected',
      expires_at_ms: 1_900_000_000_000,
      signing_digest_b64u: b64u(11, 32),
    });

    const finalizeRequest = buildRouterAbEcdsaHssEvmDigestSigningFinalizeRequestV1({
      scope,
      requestId: request.request_id,
      budgetReservationId: 'ecdsa-sign-budget-reservation-1',
      expiresAtMs: request.expires_at_ms,
      signingDigest32: new Uint8Array(32).fill(11),
      serverPresignatureId: request.client_presignature_id,
      clientSignatureShare32: new Uint8Array(32).fill(17),
    });

    expect(finalizeRequest).toEqual({
      scope,
      request_id: request.request_id,
      budget_reservation_id: 'ecdsa-sign-budget-reservation-1',
      expires_at_ms: request.expires_at_ms,
      signing_digest_b64u: b64u(11, 32),
      server_presignature_id: 'presig-client-selected',
      client_signature_share32_b64u: b64u(17, 32),
    });
  });

  test('rejects request digests when scope context binding does not match context', async () => {
    const mismatchedScope: RouterAbEcdsaHssNormalSigningScopeV1 = {
      context: scope.context,
      public_identity: {
        context_binding_b64u: b64u(99, 32),
        client_public_key33_b64u: scope.public_identity.client_public_key33_b64u,
        server_public_key33_b64u: scope.public_identity.server_public_key33_b64u,
        threshold_public_key33_b64u: scope.public_identity.threshold_public_key33_b64u,
        ethereum_address20_b64u: scope.public_identity.ethereum_address20_b64u,
        client_share_retry_counter: scope.public_identity.client_share_retry_counter,
        server_share_retry_counter: scope.public_identity.server_share_retry_counter,
      },
      signing_worker: scope.signing_worker,
      activation_epoch: scope.activation_epoch,
    };
    const request = buildRouterAbEcdsaHssEvmDigestSigningRequestV1({
      scope: mismatchedScope,
      requestId: 'ecdsa-sign-request-context-mismatch',
      clientPresignatureId: 'presig-client-selected',
      expiresAtMs: 1_900_000_000_000,
      signingDigest32: new Uint8Array(32).fill(11),
    });

    await expect(routerAbEcdsaHssEvmDigestSigningRequestDigestV1(request)).rejects.toThrow(
      /context_binding_b64u does not match scope.context/,
    );
  });

  test('rejects legacy threshold-session fields and mismatched prepare responses', async () => {
    const request = prepareRequest();
    expect(() =>
      parseRouterAbEcdsaHssEvmDigestSigningRequestV1({
        ...request,
        mpcSessionId: 'legacy-session',
      }),
    ).toThrow('ecdsaSigningRequest.mpcSessionId is not a supported field');

    await expect(
      parseRouterAbEcdsaHssEvmDigestSigningPrepareResponseForRequestV1(request, {
        ...(await prepareResponse(request)),
        server_presignature_id: 'other-presig',
      }),
    ).rejects.toThrow('ecdsaPrepareResponse.server_presignature_id does not match request');

    await expect(
      parseRouterAbEcdsaHssEvmDigestSigningPrepareResponseForRequestV1(request, {
        ...(await prepareResponse(request)),
        request_digest: digest(99),
      }),
    ).rejects.toThrow('ecdsaPrepareResponse.request_digest does not match request');

    await expect(
      parseRouterAbEcdsaHssEvmDigestSigningPrepareResponseForRequestV1(request, {
        ...(await prepareResponse(request)),
        signature_scheme: 'ecdsa_hss_v1',
      }),
    ).rejects.toThrow(
      'ecdsaPrepareResponse.signature_scheme must be ecdsa_secp256k1_recoverable_v1',
    );
  });

  test('rejects mismatched finalize response request digests', async () => {
    const request = prepareRequest();
    const finalizeRequest = buildRouterAbEcdsaHssEvmDigestSigningFinalizeRequestV1({
      scope,
      requestId: request.request_id,
      budgetReservationId: 'ecdsa-sign-budget-reservation-1',
      expiresAtMs: request.expires_at_ms,
      signingDigest32: new Uint8Array(32).fill(11),
      serverPresignatureId: request.client_presignature_id,
      clientSignatureShare32: new Uint8Array(32).fill(17),
    });

    await expect(
      parseRouterAbEcdsaHssEvmDigestSigningResponseForRequestV1(finalizeRequest, {
        ...(await signingResponse(finalizeRequest)),
        request_digest: digest(99),
      }),
    ).rejects.toThrow('ecdsaSigningResponse.request_digest does not match request');
  });

  test('posts prepare and finalize requests through Wallet Session bearer auth', async () => {
    const request = prepareRequest();
    const preparedResponse = await prepareResponse(request);
    const finalizeRequest = buildRouterAbEcdsaHssEvmDigestSigningFinalizeRequestV1({
      scope,
      requestId: request.request_id,
      budgetReservationId: 'ecdsa-sign-budget-reservation-1',
      expiresAtMs: request.expires_at_ms,
      signingDigest32: new Uint8Array(32).fill(11),
      serverPresignatureId: preparedResponse.server_presignature_id,
      clientSignatureShare32: new Uint8Array(32).fill(17),
    });
    const signedResponse = await signingResponse(finalizeRequest);
    const calls: Array<{ url: string; init: RequestInit }> = [];
    const originalFetch = globalThis.fetch;
    globalThis.fetch = (async (url: RequestInfo | URL, init?: RequestInit) => {
      calls.push({ url: String(url), init: init || {} });
      if (String(url).endsWith('/v1/hss/ecdsa/sign/prepare')) {
        return new Response(JSON.stringify(preparedResponse), {
          status: 200,
          headers: { 'content-type': 'application/json' },
        });
      }
      return new Response(JSON.stringify(signedResponse), {
        status: 200,
        headers: { 'content-type': 'application/json' },
      });
    }) as typeof fetch;
    try {
      await expect(
        prepareRouterAbEcdsaHssEvmDigestSigningV1({
          relayServerUrl: 'https://router.example/base/',
          credential: { kind: 'jwt', walletSessionJwt: 'wallet-session-jwt' },
          request,
        }),
      ).resolves.toEqual(preparedResponse);

      await expect(
        finalizeRouterAbEcdsaHssEvmDigestSigningV1({
          relayServerUrl: 'https://router.example/base/',
          credential: { kind: 'jwt', walletSessionJwt: 'wallet-session-jwt' },
          request: finalizeRequest,
        }),
      ).resolves.toEqual(signedResponse);
    } finally {
      globalThis.fetch = originalFetch;
    }

    expect(calls.map((call) => call.url)).toEqual([
      'https://router.example/base/v1/hss/ecdsa/sign/prepare',
      'https://router.example/base/v1/hss/ecdsa/sign',
    ]);
    expect(calls[0].init.credentials).toBe('omit');
    expect(calls[0].init.headers).toEqual({
      'Content-Type': 'application/json',
      Authorization: 'Bearer wallet-session-jwt',
    });
    expect(JSON.parse(String(calls[0].init.body))).toEqual(request);
    expect(JSON.parse(String(calls[1].init.body))).toEqual(finalizeRequest);
  });
});
