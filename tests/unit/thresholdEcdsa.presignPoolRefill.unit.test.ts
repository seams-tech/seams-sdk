import { expect, test } from '@playwright/test';
import { base64UrlEncode } from '@shared/utils/encoders';
import type { WorkerOperationContext } from '@/core/signingEngine/workerManager/executeWorkerOperation';
import {
  abortRouterAbEcdsaHssClientPresignSession,
  computeRouterAbEcdsaHssClientSignatureShareFromPresignatureHandle,
  initRouterAbEcdsaHssClientPresignSessionFromAdditiveShare,
  stepRouterAbEcdsaHssClientPresignSession,
} from '@/core/signingEngine/routerAb/ecdsaHss/clientSigningMaterialBoundary';
import {
  clearAllRouterAbEcdsaHssClientPresignatures,
  clearRouterAbEcdsaHssClientPresignaturesForLane,
  getRouterAbEcdsaHssClientPresignaturePoolDepth,
  refillRouterAbEcdsaHssClientPresignaturePool,
  scheduleRouterAbEcdsaHssClientPresignaturePoolRefill,
  signRouterAbEcdsaHssDigestWithPool,
} from '@/core/signingEngine/routerAb/ecdsaHss/presignaturePool';
import {
  ROUTER_AB_ECDSA_HSS_PRESIGNATURE_POOL_FILL_INIT_PATH,
  ROUTER_AB_ECDSA_HSS_PRESIGNATURE_POOL_FILL_STEP_PATH,
  routerAbEcdsaHssContextBindingB64uV1,
  routerAbEcdsaHssEvmDigestSigningFinalizeCoreRequestDigestV1,
  routerAbEcdsaHssEvmDigestSigningFinalizeCoreRequestFromBudgetedV1,
  routerAbEcdsaHssEvmDigestSigningRequestDigestV1,
  type RouterAbEcdsaHssEvmDigestSigningBudgetedFinalizeRequestV1Wire,
  type RouterAbEcdsaHssEvmDigestSigningRequestV1Wire,
  type RouterAbEcdsaHssNormalSigningScopeV1,
} from '@shared/utils/routerAbEcdsaHss';
import {
  parseEcdsaClientVerifyingShareB64u,
  parseEcdsaKeyHandle,
  parseEcdsaThresholdKeyId,
} from '@/core/signingEngine/session/keyMaterialBrands';

const RELAYER_URL = 'https://relay.example';
const ECDSA_KEY_HANDLE = parseEcdsaKeyHandle('ehss-key-presign-test');
const ECDSA_THRESHOLD_KEY_ID = parseEcdsaThresholdKeyId('ecdsa-hss-test-key-1');
const RP_ID = 'example.localhost';
const PARTICIPANT_IDS = [1, 2];

const CLIENT_SIGNING_SHARE_32 = new Uint8Array(32).fill(7);
const CLIENT_VERIFYING_SHARE_33 = (() => {
  const out = new Uint8Array(33).fill(9);
  out[0] = 2;
  return out;
})();
const GROUP_PUBLIC_KEY_33 = (() => {
  const out = new Uint8Array(33).fill(11);
  out[0] = 3;
  return out;
})();
const PRESIGN_BIG_R_33 = (() => {
  const out = new Uint8Array(33).fill(13);
  out[0] = 2;
  return out;
})();
const DIGEST_32 = new Uint8Array(32).fill(23);
const ENTROPY_32 = new Uint8Array(32).fill(29);
const CLIENT_SIGNATURE_SHARE_32 = new Uint8Array(32).fill(31);
const SIGNATURE_65 = (() => {
  const out = new Uint8Array(65).fill(37);
  out[64] = 1;
  return out;
})();
// Backend bridge field only. Public identity is ecdsaThresholdKeyId/group key/address.
const BACKEND_CLIENT_VERIFYING_SHARE_B64U = parseEcdsaClientVerifyingShareB64u(
  base64UrlEncode(CLIENT_VERIFYING_SHARE_33),
);
const GROUP_PUBLIC_KEY_B64U = base64UrlEncode(GROUP_PUBLIC_KEY_33);
const PRESIGN_BIG_R_B64U = base64UrlEncode(PRESIGN_BIG_R_33);
const SIGNATURE_65_B64U = base64UrlEncode(SIGNATURE_65);
const ENTROPY_B64U = base64UrlEncode(ENTROPY_32);
const WALLET_SESSION_CREDENTIAL = { kind: 'jwt' as const, walletSessionJwt: 'wallet-session-jwt' };
const ROUTER_AB_ECDSA_HSS_CONTEXT = {
  application_binding_digest_b64u: 'BwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwc',
} as const;
let ROUTER_AB_ECDSA_HSS_SCOPE: RouterAbEcdsaHssNormalSigningScopeV1;
type ClientPresignInitInput = Omit<
  Parameters<typeof initRouterAbEcdsaHssClientPresignSessionFromAdditiveShare>[0],
  'clientSigningShare32'
>;

async function buildRouterAbEcdsaHssScope(): Promise<RouterAbEcdsaHssNormalSigningScopeV1> {
  return {
    wallet_key_id: RP_ID,
    wallet_id: 'alice.testnet',
    ecdsa_threshold_key_id: ECDSA_THRESHOLD_KEY_ID,
    signing_root_id: 'proj_local:dev',
    signing_root_version: 'default',
    context: ROUTER_AB_ECDSA_HSS_CONTEXT,
    public_identity: {
      context_binding_b64u: await routerAbEcdsaHssContextBindingB64uV1(
        ROUTER_AB_ECDSA_HSS_CONTEXT,
      ),
      client_public_key33_b64u: BACKEND_CLIENT_VERIFYING_SHARE_B64U,
      server_public_key33_b64u: GROUP_PUBLIC_KEY_B64U,
      threshold_public_key33_b64u: GROUP_PUBLIC_KEY_B64U,
      ethereum_address20_b64u: base64UrlEncode(new Uint8Array(20).fill(43)),
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

type ThresholdFetchCounters = {
  presignInit: number;
  presignStep: number;
  routerPrepare: number;
  routerFinalize: number;
  presignInitBodies: Array<Record<string, unknown>>;
  presignInitPaths: string[];
  presignStepPaths: string[];
};

function routerAbPoolFill(
  expiresAtMs = Date.now() + 60_000,
  scope: RouterAbEcdsaHssNormalSigningScopeV1 = ROUTER_AB_ECDSA_HSS_SCOPE,
) {
  return {
    kind: 'router_ab_ecdsa_hss_signing_worker_pool' as const,
    scope,
    expiresAtMs,
  };
}

function makeWorkerCtx(args: {
  clientSigningShare32: Uint8Array;
  clientVerifyingShare33: Uint8Array;
  presignBigR33: Uint8Array;
  clientSignatureShare32: Uint8Array;
}): WorkerOperationContext {
  let presignatureHandleCounter = 0;
  const activePresignatureHandles = new Set<string>();
  return {
    requestWorkerOperation: async ({ request }) => {
      const type = String((request as { type?: string })?.type || '');
      const payload = (request as { payload?: Record<string, unknown> })?.payload || {};
      if (type === 'validateSecp256k1PublicKey33') {
        return new Uint8Array(payload.publicKey33 as ArrayBuffer).slice().buffer as any;
      }
      if (type === 'mapAdditiveShareToThresholdSignaturesShare2p') {
        const additiveShare32 = new Uint8Array(payload.additiveShare32 as ArrayBuffer);
        const expectedShare32 = args.clientSigningShare32;
        const matches =
          additiveShare32.length === expectedShare32.length &&
          additiveShare32.every((value, index) => value === expectedShare32[index]);
        if (!matches) {
          throw new Error('client signing share mismatch');
        }
        return additiveShare32.slice().buffer as any;
      }
      if (type === 'thresholdEcdsaPresignSessionInit') {
        const presignatureHandle = `fixture-presignature-handle-${++presignatureHandleCounter}`;
        activePresignatureHandles.add(presignatureHandle);
        return {
          stage: 'done',
          event: 'presign_done',
          outgoingMessages: [],
          presignatureHandle,
          presignatureBigR33: args.presignBigR33.slice().buffer,
        } as any;
      }
      if (type === 'thresholdEcdsaPresignSessionStep') {
        return { stage: 'done', event: 'none', outgoingMessages: [] } as any;
      }
      if (type === 'thresholdEcdsaPresignSessionAbort') {
        return {
          kind: 'threshold_ecdsa_presign_session_aborted',
          sessionId: String(payload.sessionId || ''),
        } as any;
      }
      if (type === 'thresholdEcdsaComputeSignatureShareFromPresignatureHandle') {
        const materialHandle = String(payload.materialHandle || '');
        if (!activePresignatureHandles.delete(materialHandle)) {
          throw new Error('unknown presignature handle');
        }
        const expectedBigR33 = new Uint8Array(payload.expectedPresignBigR33 as ArrayBuffer);
        const matches =
          expectedBigR33.length === args.presignBigR33.length &&
          expectedBigR33.every((value, index) => value === args.presignBigR33[index]);
        if (!matches) {
          throw new Error('presignature bigR mismatch');
        }
        return args.clientSignatureShare32.slice().buffer as any;
      }
      throw new Error(`Unexpected worker operation in test: ${type}`);
    },
  };
}

function installThresholdEcdsaFetchMock(args?: {
  failPresignInitAfter?: number;
  presignInitDelayMs?: number;
}): {
  counters: ThresholdFetchCounters;
  restore: () => void;
} {
  const counters: ThresholdFetchCounters = {
    presignInit: 0,
    presignStep: 0,
    routerPrepare: 0,
    routerFinalize: 0,
    presignInitBodies: [],
    presignInitPaths: [],
    presignStepPaths: [],
  };
  const originalFetch = globalThis.fetch;
  const failPresignInitAfter = Number(args?.failPresignInitAfter ?? Infinity);
  const presignInitDelayMs = Number(args?.presignInitDelayMs ?? 0);

  (globalThis as { fetch: typeof fetch }).fetch = (async (input, init) => {
    const urlRaw =
      typeof input === 'string' ? input : input instanceof URL ? input.toString() : input.url;
    const path = new URL(urlRaw).pathname;
    const method = String(init?.method || 'GET').toUpperCase();
    if (method !== 'POST') {
      return new Response(JSON.stringify({ ok: false, code: 'invalid_method' }), {
        status: 405,
        headers: { 'Content-Type': 'application/json' },
      });
    }

    if (path.endsWith(ROUTER_AB_ECDSA_HSS_PRESIGNATURE_POOL_FILL_INIT_PATH)) {
      counters.presignInit += 1;
      counters.presignInitPaths.push(path);
      counters.presignInitBodies.push(JSON.parse(String(init?.body || '{}')));
      if (presignInitDelayMs > 0) {
        await new Promise((resolve) => setTimeout(resolve, presignInitDelayMs));
      }
      if (counters.presignInit > failPresignInitAfter) {
        return new Response(
          JSON.stringify({
            ok: false,
            code: 'forced_presign_init_failure',
            message: 'forced failure',
          }),
          {
            status: 500,
            headers: { 'Content-Type': 'application/json' },
          },
        );
      }
      return new Response(
        JSON.stringify({
          ok: true,
          presignSessionId: `presign-session-${counters.presignInit}`,
          stage: 'triples',
          outgoingMessagesB64u: [],
        }),
        {
          status: 200,
          headers: { 'Content-Type': 'application/json' },
        },
      );
    }

    if (path.endsWith(ROUTER_AB_ECDSA_HSS_PRESIGNATURE_POOL_FILL_STEP_PATH)) {
      counters.presignStep += 1;
      counters.presignStepPaths.push(path);
      return new Response(
        JSON.stringify({
          ok: true,
          stage: 'done',
          event: 'presign_done',
          outgoingMessagesB64u: [],
          presignatureId: `presig-${counters.presignStep}`,
          bigRB64u: PRESIGN_BIG_R_B64U,
        }),
        {
          status: 200,
          headers: { 'Content-Type': 'application/json' },
        },
      );
    }

    if (path.endsWith('/router-ab/ecdsa-hss/sign/prepare')) {
      counters.routerPrepare += 1;
      const body = JSON.parse(String(init?.body || '{}')) as RouterAbEcdsaHssEvmDigestSigningRequestV1Wire;
      return new Response(
        JSON.stringify({
          scope: body.scope,
          request_id: body.request_id,
          budget_reservation_id: `ecdsa-sign-budget-reservation-${counters.routerPrepare}`,
          budget_operation_id: `ecdsa-sign-budget-operation-${counters.routerPrepare}`,
          budget_status: {
            committed_remaining_uses: 3,
            reserved_uses: 1,
            available_uses: 2,
          },
          request_digest: await routerAbEcdsaHssEvmDigestSigningRequestDigestV1(body),
          signing_digest: { bytes: Array.from(DIGEST_32) },
          server_presignature_id: body.client_presignature_id,
          server_big_r33_b64u: PRESIGN_BIG_R_B64U,
          rerandomization_entropy32_b64u: ENTROPY_B64U,
          signature_scheme: 'ecdsa_secp256k1_recoverable_v1',
          prepared_at_ms: Date.now(),
          expires_at_ms: body.expires_at_ms,
        }),
        {
          status: 200,
          headers: { 'Content-Type': 'application/json' },
        },
      );
    }

    if (path.endsWith('/router-ab/ecdsa-hss/sign')) {
      counters.routerFinalize += 1;
      const body = JSON.parse(
        String(init?.body || '{}'),
      ) as RouterAbEcdsaHssEvmDigestSigningBudgetedFinalizeRequestV1Wire;
      const coreRequest = routerAbEcdsaHssEvmDigestSigningFinalizeCoreRequestFromBudgetedV1(
        body,
      );
      return new Response(
        JSON.stringify({
          scope: body.scope,
          request_id: body.request_id,
          request_digest: await routerAbEcdsaHssEvmDigestSigningFinalizeCoreRequestDigestV1(
            coreRequest,
          ),
          signing_digest: { bytes: Array.from(DIGEST_32) },
          signature_scheme: 'ecdsa_secp256k1_recoverable_v1',
          signature65_b64u: SIGNATURE_65_B64U,
        }),
        {
          status: 200,
          headers: { 'Content-Type': 'application/json' },
        },
      );
    }

    return new Response(
      JSON.stringify({
        ok: false,
        code: 'unexpected_route',
        message: path,
      }),
      {
        status: 404,
        headers: { 'Content-Type': 'application/json' },
      },
    );
  }) as typeof fetch;

  return {
    counters,
    restore: () => {
      (globalThis as { fetch: typeof fetch }).fetch = originalFetch;
    },
  };
}

async function waitForPredicate(predicate: () => boolean, timeoutMs = 1_000): Promise<void> {
  const startedAt = Date.now();
  while (Date.now() - startedAt < timeoutMs) {
    if (predicate()) return;
    await new Promise((resolve) => setTimeout(resolve, 10));
  }
  throw new Error('Timed out waiting for predicate');
}

function expectZeroedBytes(bytes: Uint8Array): void {
  expect(Array.from(bytes).every((value) => value === 0)).toBe(true);
}

function clientSigningMaterial(bytes: Uint8Array = CLIENT_SIGNING_SHARE_32) {
  return {
    kind: 'router_ab_ecdsa_hss_client_signing_material_source_v1' as const,
    initClientPresignSession: async (input: ClientPresignInitInput) =>
      await initRouterAbEcdsaHssClientPresignSessionFromAdditiveShare({
        clientSigningShare32: bytes.slice(),
        ...input,
      }),
    stepClientPresignSession: async (input: Parameters<typeof stepRouterAbEcdsaHssClientPresignSession>[0]) =>
      await stepRouterAbEcdsaHssClientPresignSession(input),
    abortClientPresignSession: async (input: Parameters<typeof abortRouterAbEcdsaHssClientPresignSession>[0]) =>
      await abortRouterAbEcdsaHssClientPresignSession(input),
    computeSignatureShareFromPresignatureHandle: async (
      input: Parameters<typeof computeRouterAbEcdsaHssClientSignatureShareFromPresignatureHandle>[0],
    ) => await computeRouterAbEcdsaHssClientSignatureShareFromPresignatureHandle(input),
  };
}

function ownedClientSigningMaterial(bytes: Uint8Array) {
  return {
    kind: 'router_ab_ecdsa_hss_client_signing_material_source_v1' as const,
    initClientPresignSession: async (input: ClientPresignInitInput) =>
      await initRouterAbEcdsaHssClientPresignSessionFromAdditiveShare({
        clientSigningShare32: bytes,
        ...input,
      }),
    stepClientPresignSession: async (input: Parameters<typeof stepRouterAbEcdsaHssClientPresignSession>[0]) =>
      await stepRouterAbEcdsaHssClientPresignSession(input),
    abortClientPresignSession: async (input: Parameters<typeof abortRouterAbEcdsaHssClientPresignSession>[0]) =>
      await abortRouterAbEcdsaHssClientPresignSession(input),
    computeSignatureShareFromPresignatureHandle: async (
      input: Parameters<typeof computeRouterAbEcdsaHssClientSignatureShareFromPresignatureHandle>[0],
    ) => await computeRouterAbEcdsaHssClientSignatureShareFromPresignatureHandle(input),
  };
}

test.describe('Router A/B ECDSA-HSS presignature pool refill behavior', () => {
  test.beforeAll(async () => {
    ROUTER_AB_ECDSA_HSS_SCOPE = await buildRouterAbEcdsaHssScope();
  });

  test.beforeEach(async () => {
    clearAllRouterAbEcdsaHssClientPresignatures();
  });

  test('Router A/B second sign consumes pooled presignature without inline presign in steady state', async () => {
    const workerCtx = makeWorkerCtx({
      clientSigningShare32: CLIENT_SIGNING_SHARE_32.slice(),
      clientVerifyingShare33: CLIENT_VERIFYING_SHARE_33,
      presignBigR33: PRESIGN_BIG_R_33,
      clientSignatureShare32: CLIENT_SIGNATURE_SHARE_32,
    });
    const fetchMock = installThresholdEcdsaFetchMock();

    try {
      const refillInput = {
        relayerUrl: RELAYER_URL,
        ecdsaThresholdKeyId: ECDSA_THRESHOLD_KEY_ID,
        keyHandle: ECDSA_KEY_HANDLE,
        clientVerifyingShareB64u: BACKEND_CLIENT_VERIFYING_SHARE_B64U,
        participantIds: PARTICIPANT_IDS,
        clientSigningMaterial: clientSigningMaterial(),
        thresholdEcdsaPublicKeyB64u: GROUP_PUBLIC_KEY_B64U,
        credential: WALLET_SESSION_CREDENTIAL,
        routerAbEcdsaHssPoolFill: routerAbPoolFill(),
        workerCtx,
      };

      const refill1 = await refillRouterAbEcdsaHssClientPresignaturePool(refillInput);
      const refill2 = await refillRouterAbEcdsaHssClientPresignaturePool({
        ...refillInput,
        clientSigningMaterial: clientSigningMaterial(),
      });
      expect(refill1.ok).toBe(true);
      expect(refill2.ok).toBe(true);
      expect(
        getRouterAbEcdsaHssClientPresignaturePoolDepth({
          relayerUrl: RELAYER_URL,
          scope: ROUTER_AB_ECDSA_HSS_SCOPE,
          participantIds: PARTICIPANT_IDS,
        }),
      ).toBe(2);

      const signArgsBase = {
        relayerUrl: RELAYER_URL,
        scope: ROUTER_AB_ECDSA_HSS_SCOPE,
        credential: WALLET_SESSION_CREDENTIAL,
        keyHandle: ECDSA_KEY_HANDLE,
        signingDigest32: DIGEST_32,
        participantIds: PARTICIPANT_IDS,
        workerCtx,
      };
      const signed1 = await signRouterAbEcdsaHssDigestWithPool({
        ...signArgsBase,
        clientSigningMaterial: clientSigningMaterial(),
      });
      const signed2 = await signRouterAbEcdsaHssDigestWithPool({
        ...signArgsBase,
        clientSigningMaterial: clientSigningMaterial(),
      });

      expect(signed1.ok).toBe(true);
      expect(signed2.ok).toBe(true);
      expect(fetchMock.counters.presignInit).toBe(2);
      expect(fetchMock.counters.presignStep).toBe(2);
      expect(fetchMock.counters.routerPrepare).toBe(2);
      expect(fetchMock.counters.routerFinalize).toBe(2);
    } finally {
      fetchMock.restore();
    }
  });

  test('Router A/B pool-fill refill sends the SigningWorker pool destination at presign init', async () => {
    const workerCtx = makeWorkerCtx({
      clientSigningShare32: CLIENT_SIGNING_SHARE_32.slice(),
      clientVerifyingShare33: CLIENT_VERIFYING_SHARE_33,
      presignBigR33: PRESIGN_BIG_R_33,
      clientSignatureShare32: CLIENT_SIGNATURE_SHARE_32,
    });
    const fetchMock = installThresholdEcdsaFetchMock();
    const expiresAtMs = Date.now() + 60_000;

    try {
      const refill = await refillRouterAbEcdsaHssClientPresignaturePool({
        relayerUrl: RELAYER_URL,
        ecdsaThresholdKeyId: ECDSA_THRESHOLD_KEY_ID,
        keyHandle: ECDSA_KEY_HANDLE,
        clientVerifyingShareB64u: BACKEND_CLIENT_VERIFYING_SHARE_B64U,
        participantIds: PARTICIPANT_IDS,
        clientSigningMaterial: clientSigningMaterial(),
        thresholdEcdsaPublicKeyB64u: GROUP_PUBLIC_KEY_B64U,
        credential: WALLET_SESSION_CREDENTIAL,
        routerAbEcdsaHssPoolFill: {
          kind: 'router_ab_ecdsa_hss_signing_worker_pool',
          scope: ROUTER_AB_ECDSA_HSS_SCOPE,
          expiresAtMs,
        },
        workerCtx,
      });

      expect(refill.ok).toBe(true);
      expect(fetchMock.counters.presignInitBodies).toHaveLength(1);
      expect(fetchMock.counters.presignInitPaths).toEqual([
        ROUTER_AB_ECDSA_HSS_PRESIGNATURE_POOL_FILL_INIT_PATH,
      ]);
      expect(fetchMock.counters.presignStepPaths).toEqual([
        ROUTER_AB_ECDSA_HSS_PRESIGNATURE_POOL_FILL_STEP_PATH,
      ]);
      expect(fetchMock.counters.presignInitBodies[0]).toMatchObject({
        keyHandle: ECDSA_KEY_HANDLE,
        count: 1,
        requestTag: 'background_presign_pool_refill',
        poolFill: {
          kind: 'router_ab_ecdsa_hss_signing_worker_pool',
          scope: ROUTER_AB_ECDSA_HSS_SCOPE,
          expiresAtMs,
        },
      });
    } finally {
      fetchMock.restore();
    }
  });

  test('browser pool key is bound to ECDSA-HSS active signing scope', async () => {
    const workerCtx = makeWorkerCtx({
      clientSigningShare32: CLIENT_SIGNING_SHARE_32.slice(),
      clientVerifyingShare33: CLIENT_VERIFYING_SHARE_33,
      presignBigR33: PRESIGN_BIG_R_33,
      clientSignatureShare32: CLIENT_SIGNATURE_SHARE_32,
    });
    const fetchMock = installThresholdEcdsaFetchMock();
    const nextActivationScope: RouterAbEcdsaHssNormalSigningScopeV1 = {
      ...ROUTER_AB_ECDSA_HSS_SCOPE,
      activation_epoch: 'activation-2',
    };

    try {
      const refill = await refillRouterAbEcdsaHssClientPresignaturePool({
        relayerUrl: RELAYER_URL,
        ecdsaThresholdKeyId: ECDSA_THRESHOLD_KEY_ID,
        keyHandle: ECDSA_KEY_HANDLE,
        clientVerifyingShareB64u: BACKEND_CLIENT_VERIFYING_SHARE_B64U,
        participantIds: PARTICIPANT_IDS,
        clientSigningMaterial: clientSigningMaterial(),
        thresholdEcdsaPublicKeyB64u: GROUP_PUBLIC_KEY_B64U,
        credential: WALLET_SESSION_CREDENTIAL,
        routerAbEcdsaHssPoolFill: routerAbPoolFill(Date.now() + 60_000),
        workerCtx,
      });
      expect(refill.ok).toBe(true);
      expect(
        getRouterAbEcdsaHssClientPresignaturePoolDepth({
          relayerUrl: RELAYER_URL,
          scope: ROUTER_AB_ECDSA_HSS_SCOPE,
          participantIds: PARTICIPANT_IDS,
        }),
      ).toBe(1);
      expect(
        getRouterAbEcdsaHssClientPresignaturePoolDepth({
          relayerUrl: RELAYER_URL,
          scope: nextActivationScope,
          participantIds: PARTICIPANT_IDS,
        }),
      ).toBe(0);

      const signed = await signRouterAbEcdsaHssDigestWithPool({
        relayerUrl: RELAYER_URL,
        scope: nextActivationScope,
        credential: WALLET_SESSION_CREDENTIAL,
        keyHandle: ECDSA_KEY_HANDLE,
        signingDigest32: DIGEST_32,
        clientSigningMaterial: clientSigningMaterial(),
        participantIds: PARTICIPANT_IDS,
        workerCtx,
      });
      expect(signed.ok).toBe(true);
      expect(fetchMock.counters.presignInit).toBe(2);
      expect(fetchMock.counters.presignStep).toBe(2);
      expect(
        getRouterAbEcdsaHssClientPresignaturePoolDepth({
          relayerUrl: RELAYER_URL,
          scope: ROUTER_AB_ECDSA_HSS_SCOPE,
          participantIds: PARTICIPANT_IDS,
        }),
      ).toBe(1);
      expect(
        getRouterAbEcdsaHssClientPresignaturePoolDepth({
          relayerUrl: RELAYER_URL,
          scope: nextActivationScope,
          participantIds: PARTICIPANT_IDS,
        }),
      ).toBe(0);
    } finally {
      fetchMock.restore();
    }
  });

  test('Router A/B cold pool miss refills then signs through Router prepare/finalize', async () => {
    const workerCtx = makeWorkerCtx({
      clientSigningShare32: CLIENT_SIGNING_SHARE_32.slice(),
      clientVerifyingShare33: CLIENT_VERIFYING_SHARE_33,
      presignBigR33: PRESIGN_BIG_R_33,
      clientSignatureShare32: CLIENT_SIGNATURE_SHARE_32,
    });
    const fetchMock = installThresholdEcdsaFetchMock();

    try {
      const signed = await signRouterAbEcdsaHssDigestWithPool({
        relayerUrl: RELAYER_URL,
        scope: ROUTER_AB_ECDSA_HSS_SCOPE,
        credential: WALLET_SESSION_CREDENTIAL,
        keyHandle: ECDSA_KEY_HANDLE,
        signingDigest32: DIGEST_32,
        clientSigningMaterial: clientSigningMaterial(),
        participantIds: PARTICIPANT_IDS,
        workerCtx,
      });

      expect(signed.ok).toBe(true);
      expect(fetchMock.counters.presignInit).toBe(1);
      expect(fetchMock.counters.presignStep).toBe(1);
      expect(fetchMock.counters.presignInitPaths).toEqual([
        ROUTER_AB_ECDSA_HSS_PRESIGNATURE_POOL_FILL_INIT_PATH,
      ]);
      expect(fetchMock.counters.presignStepPaths).toEqual([
        ROUTER_AB_ECDSA_HSS_PRESIGNATURE_POOL_FILL_STEP_PATH,
      ]);
      expect(fetchMock.counters.routerPrepare).toBe(1);
      expect(fetchMock.counters.routerFinalize).toBe(1);
      expect(fetchMock.counters.presignInitBodies[0]?.poolFill).toMatchObject({
        kind: 'router_ab_ecdsa_hss_signing_worker_pool',
        scope: ROUTER_AB_ECDSA_HSS_SCOPE,
      });
    } finally {
      fetchMock.restore();
    }
  });

  test('lane-scoped clear drops pooled presignatures immediately', async () => {
    const workerCtx = makeWorkerCtx({
      clientSigningShare32: CLIENT_SIGNING_SHARE_32.slice(),
      clientVerifyingShare33: CLIENT_VERIFYING_SHARE_33,
      presignBigR33: PRESIGN_BIG_R_33,
      clientSignatureShare32: CLIENT_SIGNATURE_SHARE_32,
    });
    const fetchMock = installThresholdEcdsaFetchMock();

    try {
      const refill = await refillRouterAbEcdsaHssClientPresignaturePool({
        relayerUrl: RELAYER_URL,
        ecdsaThresholdKeyId: ECDSA_THRESHOLD_KEY_ID,
        keyHandle: ECDSA_KEY_HANDLE,
        clientVerifyingShareB64u: BACKEND_CLIENT_VERIFYING_SHARE_B64U,
        participantIds: PARTICIPANT_IDS,
        clientSigningMaterial: clientSigningMaterial(),
        thresholdEcdsaPublicKeyB64u: GROUP_PUBLIC_KEY_B64U,
        credential: WALLET_SESSION_CREDENTIAL,
        routerAbEcdsaHssPoolFill: routerAbPoolFill(),
        workerCtx,
      });
      expect(refill.ok).toBe(true);
      expect(
        getRouterAbEcdsaHssClientPresignaturePoolDepth({
          relayerUrl: RELAYER_URL,
          scope: ROUTER_AB_ECDSA_HSS_SCOPE,
          participantIds: PARTICIPANT_IDS,
        }),
      ).toBe(1);

      clearRouterAbEcdsaHssClientPresignaturesForLane({
        relayerUrl: RELAYER_URL,
        scope: ROUTER_AB_ECDSA_HSS_SCOPE,
        participantIds: PARTICIPANT_IDS,
      });

      expect(
        getRouterAbEcdsaHssClientPresignaturePoolDepth({
          relayerUrl: RELAYER_URL,
          scope: ROUTER_AB_ECDSA_HSS_SCOPE,
          participantIds: PARTICIPANT_IDS,
        }),
      ).toBe(0);
    } finally {
      fetchMock.restore();
    }
  });

  test('lane-scoped clear prevents an in-flight refill from repopulating the pool', async () => {
    const workerCtx = makeWorkerCtx({
      clientSigningShare32: CLIENT_SIGNING_SHARE_32.slice(),
      clientVerifyingShare33: CLIENT_VERIFYING_SHARE_33,
      presignBigR33: PRESIGN_BIG_R_33,
      clientSignatureShare32: CLIENT_SIGNATURE_SHARE_32,
    });
    const fetchMock = installThresholdEcdsaFetchMock({ presignInitDelayMs: 50 });

    try {
      const scheduled = scheduleRouterAbEcdsaHssClientPresignaturePoolRefill({
        relayerUrl: RELAYER_URL,
        ecdsaThresholdKeyId: ECDSA_THRESHOLD_KEY_ID,
        keyHandle: ECDSA_KEY_HANDLE,
        clientVerifyingShareB64u: BACKEND_CLIENT_VERIFYING_SHARE_B64U,
        participantIds: PARTICIPANT_IDS,
        clientSigningMaterial: clientSigningMaterial(),
        thresholdEcdsaPublicKeyB64u: GROUP_PUBLIC_KEY_B64U,
        credential: WALLET_SESSION_CREDENTIAL,
        routerAbEcdsaHssPoolFill: routerAbPoolFill(),
        workerCtx,
        poolPolicy: {
          enabled: true,
          targetDepth: 1,
          lowWatermark: 0,
          maxRefillInFlight: 1,
          refillAttemptTimeoutMs: 250,
        },
      });
      expect(scheduled.scheduled).toBe(true);

      clearRouterAbEcdsaHssClientPresignaturesForLane({
        relayerUrl: RELAYER_URL,
        scope: ROUTER_AB_ECDSA_HSS_SCOPE,
        participantIds: PARTICIPANT_IDS,
      });

      await waitForPredicate(() => fetchMock.counters.presignInit > 0);
      await new Promise((resolve) => setTimeout(resolve, 100));

      expect(
        getRouterAbEcdsaHssClientPresignaturePoolDepth({
          relayerUrl: RELAYER_URL,
          scope: ROUTER_AB_ECDSA_HSS_SCOPE,
          participantIds: PARTICIPANT_IDS,
        }),
      ).toBe(0);
    } finally {
      fetchMock.restore();
    }
  });

  test('direct refill zeroizes its owned client signing share after completion', async () => {
    const workerCtx = makeWorkerCtx({
      clientSigningShare32: CLIENT_SIGNING_SHARE_32,
      clientVerifyingShare33: CLIENT_VERIFYING_SHARE_33,
      presignBigR33: PRESIGN_BIG_R_33,
      clientSignatureShare32: CLIENT_SIGNATURE_SHARE_32,
    });
    const fetchMock = installThresholdEcdsaFetchMock();
    const ownedClientSigningShare32 = CLIENT_SIGNING_SHARE_32.slice();

    try {
      const refill = await refillRouterAbEcdsaHssClientPresignaturePool({
        relayerUrl: RELAYER_URL,
        ecdsaThresholdKeyId: ECDSA_THRESHOLD_KEY_ID,
        keyHandle: ECDSA_KEY_HANDLE,
        clientVerifyingShareB64u: BACKEND_CLIENT_VERIFYING_SHARE_B64U,
        participantIds: PARTICIPANT_IDS,
        clientSigningMaterial: ownedClientSigningMaterial(ownedClientSigningShare32),
        thresholdEcdsaPublicKeyB64u: GROUP_PUBLIC_KEY_B64U,
        credential: WALLET_SESSION_CREDENTIAL,
        routerAbEcdsaHssPoolFill: routerAbPoolFill(),
        workerCtx,
      });
      expect(refill.ok).toBe(true);
      expectZeroedBytes(ownedClientSigningShare32);
    } finally {
      fetchMock.restore();
    }
  });

  test('scheduled refill zeroizes its owned client signing share after invalidation', async () => {
    const workerCtx = makeWorkerCtx({
      clientSigningShare32: CLIENT_SIGNING_SHARE_32,
      clientVerifyingShare33: CLIENT_VERIFYING_SHARE_33,
      presignBigR33: PRESIGN_BIG_R_33,
      clientSignatureShare32: CLIENT_SIGNATURE_SHARE_32,
    });
    const fetchMock = installThresholdEcdsaFetchMock({ presignInitDelayMs: 50 });
    const ownedClientSigningShare32 = CLIENT_SIGNING_SHARE_32.slice();

    try {
      const scheduled = scheduleRouterAbEcdsaHssClientPresignaturePoolRefill({
        relayerUrl: RELAYER_URL,
        ecdsaThresholdKeyId: ECDSA_THRESHOLD_KEY_ID,
        keyHandle: ECDSA_KEY_HANDLE,
        clientVerifyingShareB64u: BACKEND_CLIENT_VERIFYING_SHARE_B64U,
        participantIds: PARTICIPANT_IDS,
        clientSigningMaterial: ownedClientSigningMaterial(ownedClientSigningShare32),
        thresholdEcdsaPublicKeyB64u: GROUP_PUBLIC_KEY_B64U,
        credential: WALLET_SESSION_CREDENTIAL,
        routerAbEcdsaHssPoolFill: routerAbPoolFill(),
        workerCtx,
        poolPolicy: {
          enabled: true,
          targetDepth: 1,
          lowWatermark: 0,
          maxRefillInFlight: 1,
          refillAttemptTimeoutMs: 250,
        },
      });
      expect(scheduled.scheduled).toBe(true);

      clearRouterAbEcdsaHssClientPresignaturesForLane({
        relayerUrl: RELAYER_URL,
        scope: ROUTER_AB_ECDSA_HSS_SCOPE,
        participantIds: PARTICIPANT_IDS,
      });

      await waitForPredicate(() => fetchMock.counters.presignInit > 0);
      await waitForPredicate(() =>
        Array.from(ownedClientSigningShare32).every((value) => value === 0),
      );
      expectZeroedBytes(ownedClientSigningShare32);
    } finally {
      fetchMock.restore();
    }
  });

  test('foreground sign zeroizes its owned client signing share after completion', async () => {
    const workerCtx = makeWorkerCtx({
      clientSigningShare32: CLIENT_SIGNING_SHARE_32,
      clientVerifyingShare33: CLIENT_VERIFYING_SHARE_33,
      presignBigR33: PRESIGN_BIG_R_33,
      clientSignatureShare32: CLIENT_SIGNATURE_SHARE_32,
    });
    const fetchMock = installThresholdEcdsaFetchMock();
    const ownedClientSigningShare32 = CLIENT_SIGNING_SHARE_32.slice();

    try {
      const signed = await signRouterAbEcdsaHssDigestWithPool({
        relayerUrl: RELAYER_URL,
        scope: ROUTER_AB_ECDSA_HSS_SCOPE,
        credential: WALLET_SESSION_CREDENTIAL,
        keyHandle: ECDSA_KEY_HANDLE,
        signingDigest32: DIGEST_32,
        clientSigningMaterial: ownedClientSigningMaterial(ownedClientSigningShare32),
        participantIds: PARTICIPANT_IDS,
        workerCtx,
      });
      expect(signed.ok).toBe(true);
      expectZeroedBytes(ownedClientSigningShare32);
    } finally {
      fetchMock.restore();
    }
  });

  test('foreground sign rejects reuse of a zeroized stale client signing share buffer', async () => {
    const workerCtx = makeWorkerCtx({
      clientSigningShare32: CLIENT_SIGNING_SHARE_32,
      clientVerifyingShare33: CLIENT_VERIFYING_SHARE_33,
      presignBigR33: PRESIGN_BIG_R_33,
      clientSignatureShare32: CLIENT_SIGNATURE_SHARE_32,
    });
    const fetchMock = installThresholdEcdsaFetchMock();
    const ownedClientSigningShare32 = CLIENT_SIGNING_SHARE_32.slice();

    try {
      const first = await signRouterAbEcdsaHssDigestWithPool({
        relayerUrl: RELAYER_URL,
        scope: ROUTER_AB_ECDSA_HSS_SCOPE,
        credential: WALLET_SESSION_CREDENTIAL,
        keyHandle: ECDSA_KEY_HANDLE,
        signingDigest32: DIGEST_32,
        clientSigningMaterial: ownedClientSigningMaterial(ownedClientSigningShare32),
        participantIds: PARTICIPANT_IDS,
        workerCtx,
      });
      expect(first.ok).toBe(true);
      expectZeroedBytes(ownedClientSigningShare32);

      const second = await signRouterAbEcdsaHssDigestWithPool({
        relayerUrl: RELAYER_URL,
        scope: ROUTER_AB_ECDSA_HSS_SCOPE,
        credential: WALLET_SESSION_CREDENTIAL,
        keyHandle: ECDSA_KEY_HANDLE,
        signingDigest32: DIGEST_32,
        clientSigningMaterial: ownedClientSigningMaterial(ownedClientSigningShare32),
        participantIds: PARTICIPANT_IDS,
        workerCtx,
      });
      expect(second.ok).toBe(false);
      if (second.ok) {
        throw new Error('expected stale zeroized client signing share reuse to fail');
      }
      expect(second.message).toContain('client signing share mismatch');
      expectZeroedBytes(ownedClientSigningShare32);
    } finally {
      fetchMock.restore();
    }
  });

  test('foreground sign reuses in-flight refill result instead of starting duplicate presign handshake', async () => {
    const workerCtx = makeWorkerCtx({
      clientSigningShare32: CLIENT_SIGNING_SHARE_32.slice(),
      clientVerifyingShare33: CLIENT_VERIFYING_SHARE_33,
      presignBigR33: PRESIGN_BIG_R_33,
      clientSignatureShare32: CLIENT_SIGNATURE_SHARE_32,
    });
    const fetchMock = installThresholdEcdsaFetchMock({
      presignInitDelayMs: 120,
    });

    try {
      const scheduled = scheduleRouterAbEcdsaHssClientPresignaturePoolRefill({
        relayerUrl: RELAYER_URL,
        ecdsaThresholdKeyId: ECDSA_THRESHOLD_KEY_ID,
        keyHandle: ECDSA_KEY_HANDLE,
        clientVerifyingShareB64u: BACKEND_CLIENT_VERIFYING_SHARE_B64U,
        participantIds: PARTICIPANT_IDS,
        clientSigningMaterial: clientSigningMaterial(),
        thresholdEcdsaPublicKeyB64u: GROUP_PUBLIC_KEY_B64U,
        credential: WALLET_SESSION_CREDENTIAL,
        routerAbEcdsaHssPoolFill: routerAbPoolFill(),
        workerCtx,
        poolPolicy: {
          enabled: true,
          targetDepth: 1,
          lowWatermark: 0,
          maxRefillInFlight: 1,
          refillAttemptTimeoutMs: 2_000,
        },
      });
      expect(scheduled.scheduled).toBe(true);

      const signed = await signRouterAbEcdsaHssDigestWithPool({
        relayerUrl: RELAYER_URL,
        scope: ROUTER_AB_ECDSA_HSS_SCOPE,
        credential: WALLET_SESSION_CREDENTIAL,
        keyHandle: ECDSA_KEY_HANDLE,
        signingDigest32: DIGEST_32,
        clientSigningMaterial: clientSigningMaterial(),
        participantIds: PARTICIPANT_IDS,
        workerCtx,
      });

      expect(signed.ok).toBe(true);
      expect(fetchMock.counters.presignInit).toBe(1);
      expect(fetchMock.counters.presignStep).toBe(1);
      expect(fetchMock.counters.routerPrepare).toBe(1);
      expect(fetchMock.counters.routerFinalize).toBe(1);
    } finally {
      fetchMock.restore();
    }
  });
});
