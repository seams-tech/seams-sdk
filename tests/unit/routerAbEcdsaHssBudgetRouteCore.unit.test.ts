import { expect, test } from '@playwright/test';
import type {
  RouterAbNormalSigningBudgetFinalizeInput,
  RouterAbNormalSigningBudgetReleaseInput,
  RouterAbNormalSigningBudgetReservationInput,
} from '../../packages/sdk-server-ts/src/core/routerAbSigning/RouterAbNormalSigningRuntime';
import {
  deriveRouterAbEcdsaHssBudgetRequestDigest,
  deriveRouterAbEcdsaHssBudgetOperationId,
  handleRouterAbEcdsaHssNormalSigningRouteCore,
  ROUTER_AB_ECDSA_HSS_PRIVATE_SIGNING_PATHS,
  type RouterAbNormalSigningAdmissionAdapter,
} from '../../packages/sdk-server-ts/src/router/routerAbPrivateSigningWorker';
import type { SessionAdapter } from '../../packages/sdk-server-ts/src/router/routerApi';
import {
  buildRouterAbEcdsaHssEvmDigestSigningBudgetedFinalizeRequestV1,
  buildRouterAbEcdsaHssEvmDigestSigningRequestV1,
  ROUTER_AB_ECDSA_HSS_KEY_SCOPE_V1,
  ROUTER_AB_ECDSA_HSS_NORMAL_SIGNING_STATE_KIND_V1,
  routerAbEcdsaHssActiveStateSessionId,
  routerAbEcdsaHssContextBindingB64uV1,
  type RouterAbEcdsaHssEvmDigestSigningBudgetedFinalizeRequestV1Wire,
  type RouterAbEcdsaHssEvmDigestSigningRequestV1Wire,
  type RouterAbEcdsaHssNormalSigningScopeV1,
} from '@shared/utils/routerAbEcdsaHss';
import { ROUTER_AB_ECDSA_HSS_WALLET_SESSION_JWT_KIND } from '@shared/utils/sessionTokens';
import { deriveEvmFamilySigningKeySlotId } from '@shared/signing-lanes';

type EcdsaRouteInput = Parameters<typeof handleRouterAbEcdsaHssNormalSigningRouteCore>[0];
type EcdsaNormalSigningRuntime = NonNullable<EcdsaRouteInput['runtime']>;

const signingGrantId = 'signing-grant-ecdsa-1';
const walletId = 'alice.testnet';
const rpId = 'localhost';
const keyHandle = 'ehss-key-1';
const relayerKeyId = 'ehss-relayer-1';
const signingWorkerId = 'signing-worker-1';
const expiresAtMs = Date.now() + 60_000;
const signingRootId = 'root-1';
const signingRootVersion = 'root-v1';
const evmFamilySigningKeySlotId = deriveEvmFamilySigningKeySlotId({
  walletId,
  signingRootId,
  signingRootVersion,
});

let scope: RouterAbEcdsaHssNormalSigningScopeV1;
let thresholdSessionId: string;

type EcdsaBudgetRouteHarness = {
  runtime: EcdsaNormalSigningRuntime;
  commitCalls: RouterAbNormalSigningBudgetFinalizeInput[];
  releaseCalls: Array<
    RouterAbNormalSigningBudgetReleaseInput | RouterAbNormalSigningBudgetFinalizeInput
  >;
  reserveCalls: RouterAbNormalSigningBudgetReservationInput[];
  validateCalls: RouterAbNormalSigningBudgetFinalizeInput[];
};

function b64u(byte: number, length: number): string {
  return Buffer.from(new Uint8Array(length).fill(byte)).toString('base64url');
}

function hexB64u(hex: string): string {
  return Buffer.from(hex, 'hex').toString('base64url');
}

function budgetFailure(): {
  ok: false;
  status: number;
  code: string;
  message: string;
} {
  return {
    ok: false,
    status: 409,
    code: 'wallet_budget_exhausted',
    message: 'Wallet Session signature budget is exhausted',
  };
}

async function buildScope(): Promise<RouterAbEcdsaHssNormalSigningScopeV1> {
  const context = {
    application_binding_digest_b64u: 'BwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwc',
  } as const;
  return {
    wallet_key_id: evmFamilySigningKeySlotId,
    wallet_id: walletId,
    ecdsa_threshold_key_id: 'ecdsa-key-1',
    signing_root_id: signingRootId,
    signing_root_version: signingRootVersion,
    context,
    public_identity: {
      context_binding_b64u: await routerAbEcdsaHssContextBindingB64uV1(context),
      client_public_key33_b64u: hexB64u(
        '0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798',
      ),
      server_public_key33_b64u: hexB64u(
        '02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5',
      ),
      threshold_public_key33_b64u: hexB64u(
        '02f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9',
      ),
      ethereum_address20_b64u: b64u(5, 20),
      client_share_retry_counter: 0,
      server_share_retry_counter: 1,
    },
    signing_worker: {
      server_id: signingWorkerId,
      key_epoch: 'worker-epoch-1',
      recipient_encryption_key:
        'x25519:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
    },
    activation_epoch: 'activation-1',
  };
}

function walletSessionClaims(): Record<string, unknown> {
  return {
    sub: walletId,
    walletId,
    kind: ROUTER_AB_ECDSA_HSS_WALLET_SESSION_JWT_KIND,
    thresholdSessionId,
    signingGrantId,
    keyScope: ROUTER_AB_ECDSA_HSS_KEY_SCOPE_V1,
    keyHandle,
    relayerKeyId,
    evmFamilySigningKeySlotId,
    rpId,
    runtimePolicyScope: {
      orgId: 'org-1',
      projectId: 'project-1',
      envId: 'env-1',
      signingRootVersion: 'root-v1',
    },
    thresholdExpiresAtMs: expiresAtMs,
    participantIds: [1, 2],
    routerAbEcdsaHssNormalSigning: {
      kind: ROUTER_AB_ECDSA_HSS_NORMAL_SIGNING_STATE_KIND_V1,
      scope,
    },
  };
}

function sessionAdapter(): SessionAdapter {
  return {
    async signJwt() {
      return 'unused.jwt';
    },
    async parse() {
      return { ok: true, claims: walletSessionClaims() };
    },
    buildSetCookie() {
      return 'unused-cookie';
    },
    buildClearCookie() {
      return 'unused-clear-cookie';
    },
    async refresh() {
      return { ok: false };
    },
  };
}

function allowAllAdmissionAdapter(): RouterAbNormalSigningAdmissionAdapter {
  return {
    async evaluate() {
      return { ok: true };
    },
  };
}

function prepareBody(): RouterAbEcdsaHssEvmDigestSigningRequestV1Wire {
  return buildRouterAbEcdsaHssEvmDigestSigningRequestV1({
    scope,
    requestId: 'ecdsa-sign-request-1',
    clientPresignatureId: 'presig-client-selected',
    expiresAtMs,
    signingDigest32: new Uint8Array(32).fill(11),
  });
}

function finalizeBody(args: {
  budgetOperationId: string;
}): RouterAbEcdsaHssEvmDigestSigningBudgetedFinalizeRequestV1Wire {
  return buildRouterAbEcdsaHssEvmDigestSigningBudgetedFinalizeRequestV1({
    scope,
    requestId: 'ecdsa-sign-request-1',
    budgetReservationId: 'budget-reservation-ecdsa-1',
    budgetOperationId: args.budgetOperationId,
    expiresAtMs,
    signingDigest32: new Uint8Array(32).fill(11),
    serverPresignatureId: 'presig-client-selected',
    clientSignatureShare32: new Uint8Array(32).fill(17),
  });
}

async function ecdsaBudgetRequestDigest(
  body:
    | RouterAbEcdsaHssEvmDigestSigningRequestV1Wire
    | RouterAbEcdsaHssEvmDigestSigningBudgetedFinalizeRequestV1Wire,
): Promise<string> {
  return deriveRouterAbEcdsaHssBudgetRequestDigest({
    body,
    signingWorkerId,
    thresholdSessionId,
  });
}

function createNormalSigningRuntime(args?: {
  commitBudget?: 'ok' | 'exhausted';
  reserveBudget?: 'ok' | 'exhausted';
  validateBudget?: 'ok' | 'exhausted';
}): EcdsaBudgetRouteHarness {
  const commitCalls: RouterAbNormalSigningBudgetFinalizeInput[] = [];
  const releaseCalls: Array<
    RouterAbNormalSigningBudgetReleaseInput | RouterAbNormalSigningBudgetFinalizeInput
  > = [];
  const reserveCalls: RouterAbNormalSigningBudgetReservationInput[] = [];
  const validateCalls: RouterAbNormalSigningBudgetFinalizeInput[] = [];
  const runtime: EcdsaNormalSigningRuntime = {
    getSigningWorkerPrivateTransport() {
      return {
        kind: 'configured',
        signingWorkerBaseUrl: 'https://signing-worker.internal',
        auth: { kind: 'internal_service_auth_secret', secret: 'internal-token' },
      };
    },
    async reservePrepareReplay() {
      return { ok: true };
    },
    async reserveBudget(input) {
      reserveCalls.push(input);
      if (args?.reserveBudget === 'exhausted') return budgetFailure();
      return {
        ok: true,
        reservationId: 'budget-reservation-ecdsa-1',
        remainingUses: 3,
        reservedUses: 1,
        availableUses: 2,
      };
    },
    async commitBudget(input) {
      commitCalls.push(input);
      if (args?.commitBudget === 'exhausted') return budgetFailure();
      return { ok: true, remainingUses: 2 };
    },
    async validateBudget(input) {
      validateCalls.push(input);
      if (args?.validateBudget === 'exhausted') return budgetFailure();
      return { ok: true, remainingUses: 3 };
    },
    async releaseBudget(input) {
      releaseCalls.push(input);
      return {
        ok: true,
        released: true,
        remainingUses: 3,
        reservedUses: 0,
        availableUses: 3,
      };
    },
    async releaseBudgetForIdentity(input) {
      releaseCalls.push(input);
      return {
        ok: true,
        released: true,
        remainingUses: 3,
        reservedUses: 0,
        availableUses: 3,
      };
    },
  };
  return { runtime, commitCalls, releaseCalls, reserveCalls, validateCalls };
}

async function callEcdsaRouteCore(input: {
  body:
    | RouterAbEcdsaHssEvmDigestSigningRequestV1Wire
    | RouterAbEcdsaHssEvmDigestSigningBudgetedFinalizeRequestV1Wire;
  privatePath: EcdsaRouteInput['privatePath'];
  phase: EcdsaRouteInput['phase'];
  runtime: EcdsaNormalSigningRuntime;
}): Promise<Awaited<ReturnType<typeof handleRouterAbEcdsaHssNormalSigningRouteCore>>> {
  return await handleRouterAbEcdsaHssNormalSigningRouteCore({
    body: input.body as unknown as Record<string, unknown>,
    rawBody: input.body,
    headers: { authorization: 'Bearer wallet-session.jwt' },
    session: sessionAdapter(),
    runtime: input.runtime,
    admissionAdapter: allowAllAdmissionAdapter(),
    privatePath: input.privatePath,
    phase: input.phase,
  });
}

test.describe('Router A/B ECDSA-HSS route-core budget gates', () => {
  test.beforeAll(async () => {
    scope = await buildScope();
    thresholdSessionId = routerAbEcdsaHssActiveStateSessionId({
      kind: ROUTER_AB_ECDSA_HSS_NORMAL_SIGNING_STATE_KIND_V1,
      scope,
    });
  });

  test('budget request digest is stable across prepare and finalize for the same signature operation', async () => {
    const prepare = prepareBody();
    const budgetOperationId = await deriveRouterAbEcdsaHssBudgetOperationId({
      body: prepare,
      signingWorkerId,
      thresholdSessionId,
    });
    const finalize = finalizeBody({ budgetOperationId });
    const changedDigestPrepare = buildRouterAbEcdsaHssEvmDigestSigningRequestV1({
      scope,
      requestId: 'ecdsa-sign-request-1',
      clientPresignatureId: 'presig-client-selected',
      expiresAtMs,
      signingDigest32: new Uint8Array(32).fill(12),
    });

    expect(await ecdsaBudgetRequestDigest(prepare)).toBe(await ecdsaBudgetRequestDigest(finalize));
    expect(await ecdsaBudgetRequestDigest(changedDigestPrepare)).not.toBe(
      await ecdsaBudgetRequestDigest(prepare),
    );
    expect(await ecdsaBudgetRequestDigest(prepare)).not.toBe(prepare.signing_digest_b64u);
  });

  test('prepare rejects missing admission adapter before private SigningWorker forwarding', async () => {
    const harness = createNormalSigningRuntime();
    const body = prepareBody();
    const fetchCalls: string[] = [];
    const originalFetch = globalThis.fetch;
    globalThis.fetch = async (url) => {
      fetchCalls.push(String(url));
      return new Response(JSON.stringify({ ok: true }), { status: 200 });
    };

    try {
      const result = await handleRouterAbEcdsaHssNormalSigningRouteCore({
        body: body as unknown as Record<string, unknown>,
        rawBody: body,
        headers: { authorization: 'Bearer wallet-session.jwt' },
        session: sessionAdapter(),
        runtime: harness.runtime,
        admissionAdapter: null,
        privatePath: ROUTER_AB_ECDSA_HSS_PRIVATE_SIGNING_PATHS.prepare,
        phase: 'prepare',
      });

      expect(result).toEqual({
        status: 501,
        body: {
          ok: false,
          code: 'not_configured',
          message: 'Router A/B normal-signing admission adapter is not configured',
        },
      });
      expect(fetchCalls).toEqual([]);
      expect(harness.reserveCalls).toEqual([]);
      expect(harness.commitCalls).toEqual([]);
    } finally {
      globalThis.fetch = originalFetch;
    }
  });

  test('prepare rejects exhausted budget before private SigningWorker forwarding', async () => {
    const harness = createNormalSigningRuntime({ reserveBudget: 'exhausted' });
    const body = prepareBody();
    const expectedRequestDigest = await ecdsaBudgetRequestDigest(body);
    const expectedOperationId = await deriveRouterAbEcdsaHssBudgetOperationId({
      body,
      signingWorkerId,
      thresholdSessionId,
    });
    const fetchCalls: string[] = [];
    const originalFetch = globalThis.fetch;
    globalThis.fetch = async (url) => {
      fetchCalls.push(String(url));
      return new Response(JSON.stringify({ ok: true }), { status: 200 });
    };

    try {
      const result = await callEcdsaRouteCore({
        body,
        privatePath: ROUTER_AB_ECDSA_HSS_PRIVATE_SIGNING_PATHS.prepare,
        phase: 'prepare',
        runtime: harness.runtime,
      });

      expect(result).toEqual({
        status: 409,
        body: {
          ok: false,
          code: 'wallet_budget_exhausted',
          message: 'Wallet Session signature budget is exhausted',
        },
      });
      expect(expectedRequestDigest).not.toBe(body.signing_digest_b64u);
      expect(expectedOperationId).not.toBe(body.request_id);
      expect(fetchCalls).toEqual([]);
      expect(harness.reserveCalls).toEqual([
        {
          curve: 'ecdsa',
          thresholdSessionId,
          signingGrantId,
          signingWorkerId,
          operationId: expectedOperationId,
          requestDigest: expectedRequestDigest,
          signatureUses: 1,
          expiresAtMs,
        },
      ]);
    } finally {
      globalThis.fetch = originalFetch;
    }
  });

  test('finalize rejects invalid reservation before private SigningWorker forwarding', async () => {
    const harness = createNormalSigningRuntime({ validateBudget: 'exhausted' });
    const prepare = prepareBody();
    const budgetOperationId = await deriveRouterAbEcdsaHssBudgetOperationId({
      body: prepare,
      signingWorkerId,
      thresholdSessionId,
    });
    const body = finalizeBody({ budgetOperationId });
    const expectedRequestDigest = await ecdsaBudgetRequestDigest(body);
    const fetchCalls: string[] = [];
    const originalFetch = globalThis.fetch;
    globalThis.fetch = async (url) => {
      fetchCalls.push(String(url));
      return new Response(JSON.stringify({ ok: true }), { status: 200 });
    };

    try {
      const result = await callEcdsaRouteCore({
        body,
        privatePath: ROUTER_AB_ECDSA_HSS_PRIVATE_SIGNING_PATHS.finalize,
        phase: 'finalize',
        runtime: harness.runtime,
      });

      expect(result).toEqual({
        status: 409,
        body: {
          ok: false,
          code: 'wallet_budget_exhausted',
          message: 'Wallet Session signature budget is exhausted',
        },
      });
      expect(fetchCalls).toEqual([]);
      expect(harness.validateCalls).toEqual([
        {
          curve: 'ecdsa',
          thresholdSessionId,
          signingGrantId,
          reservationId: body.budget_reservation_id,
          signingWorkerId,
          operationId: budgetOperationId,
          requestDigest: expectedRequestDigest,
        },
      ]);
      expect(harness.commitCalls).toEqual([]);
      expect(harness.releaseCalls).toEqual([
        {
          curve: 'ecdsa',
          thresholdSessionId,
          signingGrantId,
          reservationId: body.budget_reservation_id,
          signingWorkerId,
          operationId: budgetOperationId,
          requestDigest: expectedRequestDigest,
        },
      ]);
    } finally {
      globalThis.fetch = originalFetch;
    }
  });

  test('finalize rejects a transport request id masquerading as the budget operation id', async () => {
    const harness = createNormalSigningRuntime();
    const body = finalizeBody({ budgetOperationId: 'ecdsa-sign-request-1' });
    const expectedOperationId = await deriveRouterAbEcdsaHssBudgetOperationId({
      body,
      signingWorkerId,
      thresholdSessionId,
    });
    const fetchCalls: string[] = [];
    const originalFetch = globalThis.fetch;
    globalThis.fetch = async (url) => {
      fetchCalls.push(String(url));
      return new Response(JSON.stringify({ ok: true }), { status: 200 });
    };

    try {
      const result = await callEcdsaRouteCore({
        body,
        privatePath: ROUTER_AB_ECDSA_HSS_PRIVATE_SIGNING_PATHS.finalize,
        phase: 'finalize',
        runtime: harness.runtime,
      });

      expect(expectedOperationId).toMatch(/^router-ab-ecdsa-hss:/);
      expect(expectedOperationId).not.toBe(body.request_id);
      expect(result).toEqual({
        status: 409,
        body: {
          ok: false,
          code: 'wallet_budget_reservation_mismatch',
          message: 'Router A/B ECDSA-HSS budget operation identity mismatch',
        },
      });
      expect(fetchCalls).toEqual([]);
      expect(harness.validateCalls).toEqual([]);
      expect(harness.commitCalls).toEqual([]);
      expect(harness.releaseCalls).toEqual([]);
    } finally {
      globalThis.fetch = originalFetch;
    }
  });

  test('finalize private-worker failure releases a validated reservation', async () => {
    const harness = createNormalSigningRuntime();
    const prepare = prepareBody();
    const budgetOperationId = await deriveRouterAbEcdsaHssBudgetOperationId({
      body: prepare,
      signingWorkerId,
      thresholdSessionId,
    });
    const body = finalizeBody({ budgetOperationId });
    const fetchCalls: string[] = [];
    const forwardedBodies: unknown[] = [];
    const originalFetch = globalThis.fetch;
    globalThis.fetch = async (url, init) => {
      fetchCalls.push(String(url));
      forwardedBodies.push(JSON.parse(String(init?.body || '{}')));
      return new Response('private worker failed', { status: 502 });
    };

    try {
      const result = await callEcdsaRouteCore({
        body,
        privatePath: ROUTER_AB_ECDSA_HSS_PRIVATE_SIGNING_PATHS.finalize,
        phase: 'finalize',
        runtime: harness.runtime,
      });

      expect(result).toEqual({
        status: 502,
        body: {
          ok: false,
          code: 'signing_worker_error',
          message: 'private worker failed',
        },
      });
      expect(fetchCalls).toEqual([
        'https://signing-worker.internal/router-ab/signing-worker/ecdsa-hss/sign',
      ]);
      expect(forwardedBodies).toHaveLength(1);
      expect(forwardedBodies[0]).toMatchObject({
        request: {
          request_id: body.request_id,
          server_presignature_id: body.server_presignature_id,
        },
      });
      expect(JSON.stringify(forwardedBodies[0])).not.toContain('budget_reservation_id');
      expect(JSON.stringify(forwardedBodies[0])).not.toContain('budget_operation_id');
      expect(harness.validateCalls).toHaveLength(1);
      expect(harness.commitCalls).toEqual([]);
      expect(harness.releaseCalls).toEqual([
        {
          curve: 'ecdsa',
          phase: 'finalize',
          thresholdSessionId,
          signingGrantId,
          reservationId: body.budget_reservation_id,
        },
      ]);
    } finally {
      globalThis.fetch = originalFetch;
    }
  });
});
