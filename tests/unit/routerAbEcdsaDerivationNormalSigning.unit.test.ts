import { expect, test } from '@playwright/test';
import {
  buildRouterAbEcdsaDerivationEvmDigestSigningBudgetedFinalizeRequestV1,
  buildRouterAbEcdsaDerivationEvmDigestSigningRequestV1,
  parseRouterAbEcdsaDerivationEvmDigestSigningResponseForCoreRequestV1,
  parseRouterAbEcdsaDerivationEvmDigestSigningPrepareResponseForRequestV1,
  parseRouterAbEcdsaDerivationEvmDigestSigningRequestV1,
  routerAbEcdsaDerivationContextBindingB64uV1,
  routerAbEcdsaDerivationEvmDigestSigningFinalizeCoreRequestDigestV1,
  routerAbEcdsaDerivationEvmDigestSigningFinalizeCoreRequestFromBudgetedV1,
  routerAbEcdsaDerivationEvmDigestSigningRequestDigestV1,
  routerAbEcdsaRerandomizationClientCommitmentV1,
  type RouterAbEcdsaDerivationEvmDigestSigningBudgetedFinalizeRequestV1Wire,
  type RouterAbEcdsaDerivationEvmDigestSigningPrepareResponseV1Wire,
  type RouterAbEcdsaDerivationEvmDigestSigningRequestV1Wire,
  type RouterAbEcdsaDerivationEvmDigestSigningResponseV1Wire,
  type RouterAbEcdsaDerivationNormalSigningScopeV1,
} from '@shared/utils/routerAbEcdsaDerivation';
import {
  finalizeRouterAbEcdsaDerivationEvmDigestSigningV1,
  prepareRouterAbEcdsaDerivationEvmDigestSigningV1,
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
const clientRerandomizationCommitment32 = new Uint8Array(32).fill(12);
const clientRerandomizationContribution32 = new Uint8Array(32).fill(13);

const stableContext = {
  application_binding_digest_b64u: 'BwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwc',
} as const;

let scope: RouterAbEcdsaDerivationNormalSigningScopeV1;

async function buildScope(): Promise<RouterAbEcdsaDerivationNormalSigningScopeV1> {
  return {
    wallet_key_id: 'wallet-key-localhost',
    wallet_id: 'wallet-1',
    ecdsa_threshold_key_id: 'ecdsa-key-1',
    signing_root_id: 'root-1',
    signing_root_version: 'root-v1',
    context: stableContext,
    public_identity: {
      context_binding_b64u: await routerAbEcdsaDerivationContextBindingB64uV1(stableContext),
      derivation_client_share_public_key33_b64u: ecdsaClientPublicKey33B64u,
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
  return buildRouterAbEcdsaDerivationEvmDigestSigningRequestV1({
    scope,
    requestId: 'ecdsa-sign-request-1',
    clientPresignatureId: 'presig-client-selected',
    expiresAtMs: 1_900_000_000_000,
    signingDigest32: new Uint8Array(32).fill(11),
    clientRerandomizationCommitment32,
  });
}

async function prepareResponse(
  request: RouterAbEcdsaDerivationEvmDigestSigningRequestV1Wire = prepareRequest(),
): Promise<RouterAbEcdsaDerivationEvmDigestSigningPrepareResponseV1Wire> {
  return {
    scope,
    request_id: request.request_id,
    budget_reservation_id: 'ecdsa-sign-budget-reservation-1',
    budget_operation_id: 'ecdsa-sign-budget-operation-1',
    budget_status: {
      committed_remaining_uses: 3,
      reserved_uses: 1,
      available_uses: 2,
    },
    request_digest: await routerAbEcdsaDerivationEvmDigestSigningRequestDigestV1(request),
    signing_digest: digest(11),
    server_presignature_id: request.client_presignature_id,
    server_big_r33_b64u: ecdsaServerBigR33B64u,
    signing_worker_rerandomization_contribution32_b64u: b64u(14, 32),
    signature_scheme: 'ecdsa_secp256k1_recoverable_v1',
    prepared_at_ms: 1_800_000_000_000,
    expires_at_ms: request.expires_at_ms,
  };
}

async function signingResponse(
  request: RouterAbEcdsaDerivationEvmDigestSigningBudgetedFinalizeRequestV1Wire,
): Promise<RouterAbEcdsaDerivationEvmDigestSigningResponseV1Wire> {
  const coreRequest = routerAbEcdsaDerivationEvmDigestSigningFinalizeCoreRequestFromBudgetedV1(
    request,
  );
  return {
    scope,
    request_id: request.request_id,
    request_digest: await routerAbEcdsaDerivationEvmDigestSigningFinalizeCoreRequestDigestV1(
      coreRequest,
    ),
    signing_digest: digest(11),
    signature_scheme: 'ecdsa_secp256k1_recoverable_v1',
    signature65_b64u: b64u(16, 65),
  };
}

test.describe('Router A/B ECDSA derivation normal-signing boundary', () => {
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
      client_rerandomization_commitment32_b64u: b64u(12, 32),
    });

    const finalizeRequest = buildRouterAbEcdsaDerivationEvmDigestSigningBudgetedFinalizeRequestV1({
      scope,
      requestId: request.request_id,
      budgetReservationId: 'ecdsa-sign-budget-reservation-1',
      budgetOperationId: 'ecdsa-sign-budget-operation-1',
      expiresAtMs: request.expires_at_ms,
      signingDigest32: new Uint8Array(32).fill(11),
      serverPresignatureId: request.client_presignature_id,
      clientSignatureShare32: new Uint8Array(32).fill(17),
      clientRerandomizationContribution32,
    });

    expect(finalizeRequest).toEqual({
      scope,
      request_id: request.request_id,
      budget_reservation_id: 'ecdsa-sign-budget-reservation-1',
      budget_operation_id: 'ecdsa-sign-budget-operation-1',
      expires_at_ms: request.expires_at_ms,
      signing_digest_b64u: b64u(11, 32),
      server_presignature_id: 'presig-client-selected',
      client_signature_share32_b64u: b64u(17, 32),
      client_rerandomization_contribution32_b64u: b64u(13, 32),
    });
  });

  test('matches the Rust client rerandomization commitment vector', async () => {
    const commitment = await routerAbEcdsaRerandomizationClientCommitmentV1(
      new Uint8Array(32).fill(0x44),
    );
    expect(Buffer.from(commitment).toString('base64url')).toBe(
      'S9FX5zM9m3vAn8E1xDn0YqbRjAG_nibOaiphjxKGhmw',
    );
  });

  test('rejects request digests when scope context binding does not match context', async () => {
    const mismatchedScope: RouterAbEcdsaDerivationNormalSigningScopeV1 = {
      ...scope,
      public_identity: {
        context_binding_b64u: b64u(99, 32),
        derivation_client_share_public_key33_b64u: scope.public_identity.derivation_client_share_public_key33_b64u,
        server_public_key33_b64u: scope.public_identity.server_public_key33_b64u,
        threshold_public_key33_b64u: scope.public_identity.threshold_public_key33_b64u,
        ethereum_address20_b64u: scope.public_identity.ethereum_address20_b64u,
        client_share_retry_counter: scope.public_identity.client_share_retry_counter,
        server_share_retry_counter: scope.public_identity.server_share_retry_counter,
      },
    };
    const request = buildRouterAbEcdsaDerivationEvmDigestSigningRequestV1({
      scope: mismatchedScope,
      requestId: 'ecdsa-sign-request-context-mismatch',
      clientPresignatureId: 'presig-client-selected',
      expiresAtMs: 1_900_000_000_000,
      signingDigest32: new Uint8Array(32).fill(11),
      clientRerandomizationCommitment32,
    });

    await expect(routerAbEcdsaDerivationEvmDigestSigningRequestDigestV1(request)).rejects.toThrow(
      /context_binding_b64u does not match scope.context/,
    );
  });

  test('rejects legacy threshold-session fields and mismatched prepare responses', async () => {
    const request = prepareRequest();
    expect(() =>
      parseRouterAbEcdsaDerivationEvmDigestSigningRequestV1({
        ...request,
        mpcSessionId: 'legacy-session',
      }),
    ).toThrow('ecdsaSigningRequest.mpcSessionId is not a supported field');

    await expect(
      parseRouterAbEcdsaDerivationEvmDigestSigningPrepareResponseForRequestV1(request, {
        ...(await prepareResponse(request)),
        server_presignature_id: 'other-presig',
      }),
    ).rejects.toThrow('ecdsaPrepareResponse.server_presignature_id does not match request');

    await expect(
      parseRouterAbEcdsaDerivationEvmDigestSigningPrepareResponseForRequestV1(request, {
        ...(await prepareResponse(request)),
        request_digest: digest(99),
      }),
    ).rejects.toThrow('ecdsaPrepareResponse.request_digest does not match request');

    await expect(
      parseRouterAbEcdsaDerivationEvmDigestSigningPrepareResponseForRequestV1(request, {
        ...(await prepareResponse(request)),
        signature_scheme: 'ecdsa_derivation_v1',
      }),
    ).rejects.toThrow(
      'ecdsaPrepareResponse.signature_scheme must be ecdsa_secp256k1_recoverable_v1',
    );
  });

  test('rejects mismatched finalize response request digests', async () => {
    const request = prepareRequest();
    const finalizeRequest = buildRouterAbEcdsaDerivationEvmDigestSigningBudgetedFinalizeRequestV1({
      scope,
      requestId: request.request_id,
      budgetReservationId: 'ecdsa-sign-budget-reservation-1',
      budgetOperationId: 'ecdsa-sign-budget-operation-1',
      expiresAtMs: request.expires_at_ms,
      signingDigest32: new Uint8Array(32).fill(11),
      serverPresignatureId: request.client_presignature_id,
      clientSignatureShare32: new Uint8Array(32).fill(17),
      clientRerandomizationContribution32,
    });

    await expect(
      parseRouterAbEcdsaDerivationEvmDigestSigningResponseForCoreRequestV1(
        routerAbEcdsaDerivationEvmDigestSigningFinalizeCoreRequestFromBudgetedV1(finalizeRequest),
        {
          ...(await signingResponse(finalizeRequest)),
          request_digest: digest(99),
        },
      ),
    ).rejects.toThrow('ecdsaSigningResponse.request_digest does not match request');
  });

  test('posts prepare and finalize requests through Wallet Session bearer auth', async () => {
    const request = prepareRequest();
    const preparedResponse = await prepareResponse(request);
    const finalizeRequest = buildRouterAbEcdsaDerivationEvmDigestSigningBudgetedFinalizeRequestV1({
      scope,
      requestId: request.request_id,
      budgetReservationId: 'ecdsa-sign-budget-reservation-1',
      budgetOperationId: preparedResponse.budget_operation_id,
      expiresAtMs: request.expires_at_ms,
      signingDigest32: new Uint8Array(32).fill(11),
      serverPresignatureId: preparedResponse.server_presignature_id,
      clientSignatureShare32: new Uint8Array(32).fill(17),
      clientRerandomizationContribution32,
    });
    const signedResponse = await signingResponse(finalizeRequest);
    const calls: Array<{ url: string; init: RequestInit }> = [];
    const originalFetch = globalThis.fetch;
    globalThis.fetch = (async (url: RequestInfo | URL, init?: RequestInit) => {
      calls.push({ url: String(url), init: init || {} });
      if (String(url).endsWith('/router-ab/ecdsa-derivation/sign/prepare')) {
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
        prepareRouterAbEcdsaDerivationEvmDigestSigningV1({
          relayServerUrl: 'https://router.example/base/',
          credential: { kind: 'jwt', walletSessionJwt: 'wallet-session-jwt' },
          request,
        }),
      ).resolves.toEqual(preparedResponse);

      await expect(
        finalizeRouterAbEcdsaDerivationEvmDigestSigningV1({
          relayServerUrl: 'https://router.example/base/',
          credential: { kind: 'jwt', walletSessionJwt: 'wallet-session-jwt' },
          request: finalizeRequest,
        }),
      ).resolves.toEqual(signedResponse);
    } finally {
      globalThis.fetch = originalFetch;
    }

    expect(calls.map((call) => call.url)).toEqual([
      'https://router.example/base/router-ab/ecdsa-derivation/sign/prepare',
      'https://router.example/base/router-ab/ecdsa-derivation/sign',
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
