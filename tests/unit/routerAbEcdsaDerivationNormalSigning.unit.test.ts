import { expect, test } from '@playwright/test';
import {
  buildRouterAbEcdsaDerivationEvmDigestSigningFinalizeRequestV1,
  buildRouterAbEcdsaDerivationEvmDigestSigningRequestV1,
  parseRouterAbEcdsaDerivationEvmDigestSigningResponseForCoreRequestV1,
  parseRouterAbEcdsaDerivationEvmDigestSigningPrepareResponseForRequestV1,
  parseRouterAbEcdsaDerivationEvmDigestSigningRequestV1,
  routerAbEcdsaDerivationContextBindingB64uV1,
  routerAbEcdsaDerivationEvmDigestSigningFinalizeCoreRequestDigestV1,
  routerAbEcdsaDerivationEvmDigestSigningRequestDigestV1,
  routerAbEcdsaRerandomizationClientCommitmentV1,
  type RouterAbEcdsaDerivationEvmDigestSigningFinalizeRequestV1Wire,
  type RouterAbEcdsaDerivationEvmDigestSigningPrepareResponseV1Wire,
  type RouterAbEcdsaDerivationEvmDigestSigningRequestV1Wire,
  type RouterAbEcdsaDerivationEvmDigestSigningResponseV1Wire,
  type RouterAbEcdsaDerivationNormalSigningScopeV1,
} from '@shared/utils/routerAbEcdsaDerivation';
import {
  finalizeRouterAbEcdsaDerivationEvmDigestSigningV1,
  prepareRouterAbEcdsaDerivationEvmDigestSigningV1,
} from '@/core/rpcClients/relayer/routerAbNormalSigning';
import type { WorkerOperationContext } from '@/core/signingEngine/workerManager/executeWorkerOperation';
import {
  clearAllRouterAbEcdsaDerivationClientPresignatures,
  signRouterAbEcdsaDerivationDigestWithPool,
  signRouterAbEcdsaDerivationDigestWithPoolHit,
  type RouterAbEcdsaDerivationClientSigningMaterialSource,
} from '@/core/signingEngine/routerAb/ecdsaDerivation/presignaturePool';

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

const operationId = 'ecdsa-operation-1';
const operationDigests = {
  lane_digest_b64u: b64u(10, 32),
  intent_digest_b64u: b64u(11, 32),
  display_digest_b64u: b64u(12, 32),
};
const authorization = {
  kind: 'reusable_wallet_session' as const,
  wallet_session_id: 'wallet-session-1',
};
const materialActivation = {
  kind: 'mpc_material_activation_ref' as const,
  activation_id: 'activation-1',
  capability: 'capability-1',
  material_owner: 'wallet-1',
  key_binding: 'key-binding-1',
  lifecycle_binding: 'lifecycle-binding-1',
  signing_worker: 'signing-worker-1',
};

async function buildScope(): Promise<RouterAbEcdsaDerivationNormalSigningScopeV1> {
  return {
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
    material_activation: materialActivation,
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
    operationId,
    operationDigests,
    authorization,
    materialActivation,
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
  request: RouterAbEcdsaDerivationEvmDigestSigningFinalizeRequestV1Wire,
): Promise<RouterAbEcdsaDerivationEvmDigestSigningResponseV1Wire> {
  const coreRequest = request;
  return {
    scope,
    request_id: request.request_id,
    request_digest:
      await routerAbEcdsaDerivationEvmDigestSigningFinalizeCoreRequestDigestV1(coreRequest),
    signing_digest: digest(11),
    signature_scheme: 'ecdsa_secp256k1_recoverable_v1',
    signature65_b64u: b64u(16, 65),
  };
}

type ClientPresignatureRefFixture = {
  presignatureId: string;
  materialHandle: string;
  bigR33: Uint8Array;
  createdAtMs: number;
  expiresAtMs: number;
};

type ClientSigningMaterialFixtureOverrides = {
  listAvailableClientPresignatures?: () => Promise<ClientPresignatureRefFixture[]>;
  reserveClientPresignature?: () => Promise<void>;
  destroyClientPresignature?: (input: { materialHandle: string }) => Promise<void>;
};

function createDeferred<T>(): {
  promise: Promise<T>;
  resolve: (value: T) => void;
} {
  let resolvePromise: (value: T) => void = () => {};
  const promise = new Promise<T>((resolve) => {
    resolvePromise = resolve;
  });
  return { promise, resolve: resolvePromise };
}

function buildClientPresignatureRefFixture(): ClientPresignatureRefFixture {
  return {
    presignatureId: 'fixture-client-presignature',
    materialHandle: 'fixture-client-material',
    bigR33: Uint8Array.from(Buffer.from(ecdsaServerBigR33B64u, 'base64url')),
    createdAtMs: Date.now(),
    expiresAtMs: Date.now() + 30_000,
  };
}

function buildClientSigningMaterialFixture(
  overrides: ClientSigningMaterialFixtureOverrides = {},
): RouterAbEcdsaDerivationClientSigningMaterialSource {
  const listAvailableClientPresignatures =
    overrides.listAvailableClientPresignatures ??
    (async () => [buildClientPresignatureRefFixture()]);
  const reserveClientPresignature = overrides.reserveClientPresignature ?? (async () => {});
  const destroyClientPresignature =
    overrides.destroyClientPresignature ?? (async (_input: { materialHandle: string }) => {});
  return {
    kind: 'router_ab_ecdsa_derivation_client_signing_material_source_v1',
    initClientPresignSession: async () => {
      throw new Error('fixture must not initialize a client presignature session');
    },
    stepClientPresignSession: async () => {
      throw new Error('fixture must not step a client presignature session');
    },
    abortClientPresignSession: async () => {},
    admitClientPresignature: async () => {},
    destroyClientPresignature,
    reserveClientPresignature,
    commitClientPresignature: async () => {},
    listAvailableClientPresignatures,
    retireClientPresignaturePool: async () => 0,
    computeSignatureShareFromPresignatureHandle: async () => new Uint8Array(32),
  };
}

function validationWorkerContext(): WorkerOperationContext {
  return {
    requestWorkerOperation: async (args: {
      kind: string;
      request: { type: string; payload?: Record<string, unknown> };
    }) => {
      if (args.kind !== 'evmCrypto' || args.request.type !== 'validateSecp256k1PublicKey33') {
        throw new Error(`Unexpected worker request: ${args.kind}/${args.request.type}`);
      }
      return args.request.payload?.publicKey33 as ArrayBuffer;
    },
  } as WorkerOperationContext;
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
      operation_id: operationId,
      operation_digests: operationDigests,
      authorization,
      material_activation: materialActivation,
      client_presignature_id: 'presig-client-selected',
      expires_at_ms: 1_900_000_000_000,
      signing_digest_b64u: b64u(11, 32),
      client_rerandomization_commitment32_b64u: b64u(12, 32),
    });

    const finalizeRequest = buildRouterAbEcdsaDerivationEvmDigestSigningFinalizeRequestV1({
      scope,
      requestId: request.request_id,
      operationId,
      operationDigests,
      authorization,
      materialActivation,
      expiresAtMs: request.expires_at_ms,
      signingDigest32: new Uint8Array(32).fill(11),
      serverPresignatureId: request.client_presignature_id,
      clientSignatureShare32: new Uint8Array(32).fill(17),
      clientRerandomizationContribution32,
    });

    expect(finalizeRequest).toEqual({
      scope,
      request_id: request.request_id,
      operation_id: operationId,
      operation_digests: operationDigests,
      authorization,
      material_activation: materialActivation,
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
        derivation_client_share_public_key33_b64u:
          scope.public_identity.derivation_client_share_public_key33_b64u,
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
      operationId,
      operationDigests,
      authorization,
      materialActivation,
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
    const finalizeRequest = buildRouterAbEcdsaDerivationEvmDigestSigningFinalizeRequestV1({
      scope,
      requestId: request.request_id,
      operationId,
      operationDigests,
      authorization,
      materialActivation,
      expiresAtMs: request.expires_at_ms,
      signingDigest32: new Uint8Array(32).fill(11),
      serverPresignatureId: request.client_presignature_id,
      clientSignatureShare32: new Uint8Array(32).fill(17),
      clientRerandomizationContribution32,
    });

    await expect(
      parseRouterAbEcdsaDerivationEvmDigestSigningResponseForCoreRequestV1(finalizeRequest, {
        ...(await signingResponse(finalizeRequest)),
        request_digest: digest(99),
      }),
    ).rejects.toThrow('ecdsaSigningResponse.request_digest does not match request');
  });

  test('posts prepare and finalize requests through Wallet Session bearer auth', async () => {
    const request = prepareRequest();
    const preparedResponse = await prepareResponse(request);
    const finalizeRequest = buildRouterAbEcdsaDerivationEvmDigestSigningFinalizeRequestV1({
      scope,
      requestId: request.request_id,
      operationId,
      operationDigests,
      authorization,
      materialActivation,
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
          credential: { kind: 'wallet_session_jwt', walletSessionJwt: 'wallet-session-jwt' },
          request,
        }),
      ).resolves.toEqual(preparedResponse);

      await expect(
        finalizeRouterAbEcdsaDerivationEvmDigestSigningV1({
          relayServerUrl: 'https://router.example/base/',
          credential: { kind: 'wallet_session_jwt', walletSessionJwt: 'wallet-session-jwt' },
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

  test('classifies a stale server pool record as pool-entry expiry', async () => {
    clearAllRouterAbEcdsaDerivationClientPresignatures();
    const destroyedHandles: string[] = [];
    const clientSigningMaterial: RouterAbEcdsaDerivationClientSigningMaterialSource = {
      kind: 'router_ab_ecdsa_derivation_client_signing_material_source_v1',
      initClientPresignSession: async () => {
        throw new Error('stale-pool test must not refill the client presignature');
      },
      stepClientPresignSession: async () => {
        throw new Error('stale-pool test must not refill the client presignature');
      },
      abortClientPresignSession: async () => {},
      admitClientPresignature: async () => {},
      destroyClientPresignature: async ({ materialHandle }) => {
        destroyedHandles.push(materialHandle);
      },
      reserveClientPresignature: async () => {},
      commitClientPresignature: async () => {},
      listAvailableClientPresignatures: async () => [
        {
          presignatureId: 'stale-local-presignature',
          materialHandle: 'stale-local-material',
          bigR33: Uint8Array.from(
            Buffer.from(
              '03f28773c2d975288bc7d1d205c3748651b075fbc6610e58cddeeddf8f19405aa8',
              'hex',
            ),
          ),
          createdAtMs: Date.now() - 1_000,
          expiresAtMs: Date.now() + 30_000,
        },
      ],
      retireClientPresignaturePool: async () => 0,
      computeSignatureShareFromPresignatureHandle: async () => new Uint8Array(32),
    };
    const workerCtx = {
      requestWorkerOperation: async (args: {
        kind: string;
        request: { type: string; payload?: Record<string, unknown> };
      }) => {
        if (args.kind !== 'evmCrypto' || args.request.type !== 'validateSecp256k1PublicKey33') {
          throw new Error(
            `Unexpected stale-pool worker request: ${args.kind}/${args.request.type}`,
          );
        }
        return args.request.payload?.publicKey33 as ArrayBuffer;
      },
    } as WorkerOperationContext;
    const originalFetch = globalThis.fetch;
    globalThis.fetch = async () =>
      new Response('InvalidLocalServiceConfig: presignature material is expired', { status: 500 });
    try {
      const result = await signRouterAbEcdsaDerivationDigestWithPoolHit({
        relayerUrl: 'https://router.example',
        scope,
        operationId,
        operationDigests,
        materialActivation,
        credential: { kind: 'wallet_session_jwt', walletSessionJwt: 'wallet-session-jwt' },
        signingDigest32: new Uint8Array(32).fill(11),
        clientSigningMaterial,
        expiresAtMs: Date.now() + 30_000,
        workerCtx,
        authorization,
      });

      expect(result).toMatchObject({ ok: false, code: 'pool_entry_expired' });
      expect(destroyedHandles).toEqual(['stale-local-material']);
    } finally {
      globalThis.fetch = originalFetch;
      clearAllRouterAbEcdsaDerivationClientPresignatures();
    }
  });

  test('does not hydrate a presignature returned after the worker pool was cleared', async () => {
    clearAllRouterAbEcdsaDerivationClientPresignatures();
    const listStarted = createDeferred<void>();
    const listResult = createDeferred<ClientPresignatureRefFixture[]>();
    const clientSigningMaterial = buildClientSigningMaterialFixture({
      listAvailableClientPresignatures: async () => {
        listStarted.resolve();
        return await listResult.promise;
      },
    });
    let fetchCalls = 0;
    const originalFetch = globalThis.fetch;
    globalThis.fetch = async () => {
      fetchCalls += 1;
      throw new Error('stale presignature must not reach server prepare');
    };
    try {
      const signing = signRouterAbEcdsaDerivationDigestWithPoolHit({
        relayerUrl: 'https://router.example',
        scope,
        operationId,
        operationDigests,
        materialActivation,
        credential: { kind: 'wallet_session_jwt', walletSessionJwt: 'wallet-session-jwt' },
        signingDigest32: new Uint8Array(32).fill(11),
        clientSigningMaterial,
        expiresAtMs: Date.now() + 30_000,
        workerCtx: validationWorkerContext(),
        authorization,
      });
      await listStarted.promise;
      clearAllRouterAbEcdsaDerivationClientPresignatures();
      listResult.resolve([buildClientPresignatureRefFixture()]);

      await expect(signing).resolves.toMatchObject({ ok: false, code: 'pool_empty' });
      expect(fetchCalls).toBe(0);
    } finally {
      globalThis.fetch = originalFetch;
      clearAllRouterAbEcdsaDerivationClientPresignatures();
    }
  });

  test('invalidates a selected handle before prepare when the worker pool resets', async () => {
    clearAllRouterAbEcdsaDerivationClientPresignatures();
    const destroyedHandles: string[] = [];
    const clientSigningMaterial = buildClientSigningMaterialFixture({
      reserveClientPresignature: async () => {
        clearAllRouterAbEcdsaDerivationClientPresignatures();
      },
      destroyClientPresignature: async ({ materialHandle }) => {
        destroyedHandles.push(materialHandle);
      },
    });
    let fetchCalls = 0;
    const originalFetch = globalThis.fetch;
    globalThis.fetch = async () => {
      fetchCalls += 1;
      throw new Error('reset presignature must not reach server prepare');
    };
    try {
      const result = await signRouterAbEcdsaDerivationDigestWithPoolHit({
        relayerUrl: 'https://router.example',
        scope,
        operationId,
        operationDigests,
        materialActivation,
        credential: { kind: 'wallet_session_jwt', walletSessionJwt: 'wallet-session-jwt' },
        signingDigest32: new Uint8Array(32).fill(11),
        clientSigningMaterial,
        expiresAtMs: Date.now() + 30_000,
        workerCtx: validationWorkerContext(),
        authorization,
      });

      expect(result).toMatchObject({ ok: false, code: 'pool_entry_unavailable' });
      expect(fetchCalls).toBe(0);
      expect(destroyedHandles).toEqual(['fixture-client-material']);
    } finally {
      globalThis.fetch = originalFetch;
      clearAllRouterAbEcdsaDerivationClientPresignatures();
    }
  });

  test('does not retry unavailable client material after prepare claims the operation', async () => {
    clearAllRouterAbEcdsaDerivationClientPresignatures();
    const clientSigningMaterial: RouterAbEcdsaDerivationClientSigningMaterialSource = {
      kind: 'router_ab_ecdsa_derivation_client_signing_material_source_v1',
      initClientPresignSession: async () => {
        throw new Error('post-prepare failure must not refill');
      },
      stepClientPresignSession: async () => {
        throw new Error('post-prepare failure must not refill');
      },
      abortClientPresignSession: async () => {},
      admitClientPresignature: async () => {},
      destroyClientPresignature: async () => {},
      reserveClientPresignature: async () => {},
      commitClientPresignature: async () => {
        throw new Error('Opaque ECDSA presign material is unknown');
      },
      listAvailableClientPresignatures: async () => [
        {
          presignatureId: 'claimed-operation-presignature',
          materialHandle: 'claimed-operation-material',
          bigR33: Uint8Array.from(Buffer.from(ecdsaServerBigR33B64u, 'base64url')),
          createdAtMs: Date.now(),
          expiresAtMs: Date.now() + 30_000,
        },
      ],
      retireClientPresignaturePool: async () => 0,
      computeSignatureShareFromPresignatureHandle: async () => {
        throw new Error('post-prepare failure must not compute a signature share');
      },
    };
    const workerCtx = {
      requestWorkerOperation: async (args: {
        kind: string;
        request: { type: string; payload?: Record<string, unknown> };
      }) => {
        if (args.kind !== 'evmCrypto' || args.request.type !== 'validateSecp256k1PublicKey33') {
          throw new Error(`Unexpected worker request: ${args.kind}/${args.request.type}`);
        }
        return args.request.payload?.publicKey33 as ArrayBuffer;
      },
    } as WorkerOperationContext;
    let prepareCalls = 0;
    const originalFetch = globalThis.fetch;
    globalThis.fetch = (async (_url: RequestInfo | URL, init?: RequestInit) => {
      prepareCalls += 1;
      const request = JSON.parse(
        String(init?.body || ''),
      ) as RouterAbEcdsaDerivationEvmDigestSigningRequestV1Wire;
      return new Response(JSON.stringify(await prepareResponse(request)), {
        status: 200,
        headers: { 'content-type': 'application/json' },
      });
    }) as typeof fetch;
    try {
      const result = await signRouterAbEcdsaDerivationDigestWithPool({
        relayerUrl: 'https://router.example',
        scope,
        operationId,
        operationDigests,
        materialActivation,
        credential: { kind: 'wallet_session_jwt', walletSessionJwt: 'wallet-session-jwt' },
        signingDigest32: new Uint8Array(32).fill(11),
        clientSigningMaterial,
        expiresAtMs: Date.now() + 30_000,
        workerCtx,
        authorization,
      });

      expect(result).toMatchObject({
        ok: false,
        code: 'router_ab_sign_failed',
        message: 'Opaque ECDSA presign material is unknown',
      });
      expect(prepareCalls).toBe(1);
    } finally {
      globalThis.fetch = originalFetch;
      clearAllRouterAbEcdsaDerivationClientPresignatures();
    }
  });
});
