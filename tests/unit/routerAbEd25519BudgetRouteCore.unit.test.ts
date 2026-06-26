import { expect, test } from '@playwright/test';
import {
  handleRouterAbEd25519NormalSigningRouteCore,
  ROUTER_AB_ED25519_PRIVATE_SIGNING_PATHS,
  type RouterAbNormalSigningAdmissionAdapter,
} from '../../packages/sdk-server-ts/src/router/routerAbPrivateSigningWorker';
import type { SessionAdapter } from '../../packages/sdk-server-ts/src/router/relay';
import type {
  RouterAbNormalSigningBudgetCommitInput,
  RouterAbNormalSigningBudgetReleaseInput,
  RouterAbNormalSigningBudgetReservationInput,
  RouterAbNormalSigningBudgetValidateInput,
} from '../../packages/sdk-server-ts/src/core/ThresholdService/ThresholdSigningService';
import { ROUTER_AB_ED25519_WALLET_SESSION_JWT_KIND } from '@shared/utils/sessionTokens';
import { ROUTER_AB_ED25519_NORMAL_SIGNING_STATE_KIND } from '@shared/utils/signingSessionSeal';

type Ed25519RouteInput = Parameters<typeof handleRouterAbEd25519NormalSigningRouteCore>[0];
type Ed25519ThresholdService = NonNullable<ReturnType<Ed25519RouteInput['getThreshold']>>;

const thresholdSessionId = 'threshold-ed25519-session-1';
const signingGrantId = 'signing-grant-1';
const walletId = 'alice.test.near';
const signingWorkerId = 'local-signing-worker';
const expiresAtMs = Date.now() + 60_000;
const budgetDigestPattern = /^[A-Za-z0-9_-]{43}$/;

type BudgetRouteHarness = {
  service: Ed25519ThresholdService;
  commitCalls: RouterAbNormalSigningBudgetCommitInput[];
  releaseCalls: RouterAbNormalSigningBudgetReleaseInput[];
  reserveCalls: RouterAbNormalSigningBudgetReservationInput[];
  validateCalls: RouterAbNormalSigningBudgetValidateInput[];
};

function walletSessionClaims(): Record<string, unknown> {
  return {
    sub: walletId,
    walletId,
    kind: ROUTER_AB_ED25519_WALLET_SESSION_JWT_KIND,
    thresholdSessionId,
    signingGrantId,
    relayerKeyId: 'near-relayer-key-1',
    rpId: 'localhost',
    runtimePolicyScope: {
      orgId: 'org-1',
      projectId: 'project-1',
      envId: 'env-1',
      signingRootVersion: 'root-v1',
    },
    thresholdExpiresAtMs: expiresAtMs,
    participantIds: [1, 2],
    routerAbNormalSigning: {
      kind: ROUTER_AB_ED25519_NORMAL_SIGNING_STATE_KIND,
      signingWorkerId,
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

function routerAbScope(requestId: string): Record<string, unknown> {
  return {
    request_id: requestId,
    account_id: walletId,
    session_id: thresholdSessionId,
    signing_worker_id: signingWorkerId,
  };
}

function presignPoolFinalizeBody(): Record<string, unknown> {
  return {
    scope: routerAbScope('presign-finalize-request-1'),
    expires_at_ms: expiresAtMs,
    intent: {
      kind: 'near_transaction_v1',
      operation_id: 'operation-1',
    },
    signing_payload: {
      kind: 'near_unsigned_transaction_borsh_v1',
      unsigned_transaction_borsh_b64u: 'AQID',
      expected_signing_digest_b64u: 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',
    },
    pool_binding: {
      server_round1_handle: 'server-round1-handle-1',
      pool_entry_binding_digest: { bytes: Array.from(new Uint8Array(32).fill(7)) },
    },
  };
}

function prepareBody(): Record<string, unknown> {
  return {
    scope: routerAbScope('prepare-request-1'),
    expires_at_ms: expiresAtMs,
    intent: {
      operation_id: 'operation-1',
    },
    signing_payload: {
      kind: 'near_unsigned_transaction_borsh_v1',
      unsigned_transaction_borsh_b64u: 'AQID',
      expected_signing_digest_b64u: 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',
    },
  };
}

function prepareBodyForExpiry(expiresAtValueMs: number): Record<string, unknown> {
  const body = prepareBody();
  body.expires_at_ms = expiresAtValueMs;
  return body;
}

function finalizeBody(): Record<string, unknown> {
  return {
    scope: routerAbScope('prepare-request-1'),
    expires_at_ms: expiresAtMs,
    budget_reservation_id: 'budget-reservation-1',
    budget_operation_id: 'operation-1',
    prepare_binding: {
      server_round1_handle: 'server-round1-handle-1',
      round1_binding_digest: { bytes: Array.from(new Uint8Array(32).fill(6)) },
      intent_digest: { bytes: Array.from(new Uint8Array(32).fill(5)) },
      signing_payload_digest: {
        bytes: Array.from(Buffer.from('AbtCmiEEvKTXVsYJeTBQLryqUuVoUjxQWTbN6PWNzf8', 'base64url')),
      },
    },
    protocol: {
      kind: 'ed25519_two_party_frost_finalize_v1',
      client_commitments: { hiding: 'client-hiding', binding: 'client-binding' },
      server_commitments: { hiding: 'server-hiding', binding: 'server-binding' },
      client_verifying_share_b64u: 'client-verifier',
      server_verifying_share_b64u: 'server-verifier',
      client_signature_share_b64u: 'client-sig-share',
    },
  };
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

function createThresholdService(args?: {
  commitBudget?: 'ok' | 'exhausted';
  reserveBudget?: 'ok' | 'exhausted';
  validateBudget?: 'ok' | 'exhausted';
}): BudgetRouteHarness {
  const commitCalls: RouterAbNormalSigningBudgetCommitInput[] = [];
  const releaseCalls: RouterAbNormalSigningBudgetReleaseInput[] = [];
  const reserveCalls: RouterAbNormalSigningBudgetReservationInput[] = [];
  const validateCalls: RouterAbNormalSigningBudgetValidateInput[] = [];
  const service: Ed25519ThresholdService = {
    getRouterAbSigningWorkerPrivateHttpConfig() {
      return {
        signingWorkerBaseUrl: 'https://signing-worker.internal',
        auth: { kind: 'internal_service_auth_token', token: 'internal-token' },
      };
    },
    async resolveRouterAbEd25519SigningWorkerPrivateMaterial() {
      return {
        ok: true,
        material: {
          kind: 'router_ab_ed25519_signing_worker_material_v1',
          account_public_key: 'ed25519-public-key-1',
          x_server_base_b64u: 'server-base-share-1',
          signing_worker_material_handle: 'worker-material-handle-1',
          activated_at_ms: 1_800_000_000_000,
        },
      };
    },
    async reserveRouterAbNormalSigningPrepareReplay() {
      return { ok: true };
    },
    async reserveRouterAbNormalSigningBudget(input) {
      reserveCalls.push(input);
      if (args?.reserveBudget === 'exhausted') return budgetFailure();
      return {
        ok: true,
        reservationId: 'budget-reservation-1',
        remainingUses: 3,
        reservedUses: 1,
        availableUses: 2,
      };
    },
    async commitRouterAbNormalSigningBudget(input) {
      commitCalls.push(input);
      if (args?.commitBudget === 'exhausted') return budgetFailure();
      return { ok: true, remainingUses: 2 };
    },
    async validateRouterAbNormalSigningBudget(input) {
      validateCalls.push(input);
      if (args?.validateBudget === 'exhausted') return budgetFailure();
      return { ok: true, remainingUses: 3 };
    },
    async releaseRouterAbNormalSigningBudget(input) {
      releaseCalls.push(input);
      return {
        ok: true,
        released: true,
        remainingUses: 3,
        reservedUses: 0,
        availableUses: 3,
      };
    },
    async releaseRouterAbNormalSigningBudgetForIdentity(input) {
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
  return { service, commitCalls, releaseCalls, reserveCalls, validateCalls };
}

async function callEd25519RouteCore(input: {
  body: Record<string, unknown>;
  privatePath: Ed25519RouteInput['privatePath'];
  phase: Ed25519RouteInput['phase'];
  service: Ed25519ThresholdService;
}): Promise<Awaited<ReturnType<typeof handleRouterAbEd25519NormalSigningRouteCore>>> {
  return await handleRouterAbEd25519NormalSigningRouteCore({
    body: input.body,
    rawBody: input.body,
    headers: { authorization: 'Bearer wallet-session.jwt' },
    session: sessionAdapter(),
    getThreshold: () => input.service,
    admissionAdapter: allowAllAdmissionAdapter(),
    privatePath: input.privatePath,
    phase: input.phase,
  });
}

async function okRouterAbEd25519SigningWorkerFetch(
  url: Parameters<typeof fetch>[0],
  _init?: Parameters<typeof fetch>[1],
): Promise<Response> {
  const path = String(url).endsWith('/sign/prepare')
    ? ROUTER_AB_ED25519_PRIVATE_SIGNING_PATHS.prepare
    : ROUTER_AB_ED25519_PRIVATE_SIGNING_PATHS.finalize;
  return new Response(JSON.stringify({ ok: true, privatePath: path }), { status: 200 });
}

test.describe('Router A/B Ed25519 route-core budget gates', () => {
  test('prepare rejects missing admission adapter before private SigningWorker forwarding', async () => {
    const harness = createThresholdService();
    const fetchCalls: string[] = [];
    const originalFetch = globalThis.fetch;
    globalThis.fetch = async (url) => {
      fetchCalls.push(String(url));
      return new Response(JSON.stringify({ ok: true }), { status: 200 });
    };

    try {
      const result = await handleRouterAbEd25519NormalSigningRouteCore({
        body: prepareBody(),
        rawBody: prepareBody(),
        headers: { authorization: 'Bearer wallet-session.jwt' },
        session: sessionAdapter(),
        getThreshold: () => harness.service,
        admissionAdapter: null,
        privatePath: ROUTER_AB_ED25519_PRIVATE_SIGNING_PATHS.prepare,
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

  test('presign-pool finalize rejects exhausted budget before private SigningWorker forwarding', async () => {
    const harness = createThresholdService({ reserveBudget: 'exhausted' });
    const fetchCalls: string[] = [];
    const originalFetch = globalThis.fetch;
    globalThis.fetch = async (url) => {
      fetchCalls.push(String(url));
      return new Response(JSON.stringify({ ok: true }), { status: 200 });
    };

    try {
      const result = await callEd25519RouteCore({
        body: presignPoolFinalizeBody(),
        privatePath: ROUTER_AB_ED25519_PRIVATE_SIGNING_PATHS.finalize,
        phase: 'finalize',
        service: harness.service,
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
      expect(harness.reserveCalls).toEqual([
        {
          curve: 'ed25519',
          phase: 'finalize',
          thresholdSessionId,
          signingGrantId,
          signingWorkerId,
          operationId: 'operation-1',
          requestDigest: expect.stringMatching(budgetDigestPattern),
          signatureUses: 1,
          expiresAtMs,
        },
      ]);
      expect(harness.commitCalls).toEqual([]);
    } finally {
      globalThis.fetch = originalFetch;
    }
  });

  test('presign-pool finalize commits canonical budget identity before private SigningWorker forwarding', async () => {
    const harness = createThresholdService();
    const fetchCalls: string[] = [];
    const originalFetch = globalThis.fetch;
    globalThis.fetch = async (url) => {
      fetchCalls.push(String(url));
      return new Response(JSON.stringify({ ok: true, signature_scheme: 'ed25519_v1' }), {
        status: 200,
      });
    };

    try {
      const result = await callEd25519RouteCore({
        body: presignPoolFinalizeBody(),
        privatePath: ROUTER_AB_ED25519_PRIVATE_SIGNING_PATHS.finalize,
        phase: 'finalize',
        service: harness.service,
      });

      expect(result.status).toBe(200);
      expect(fetchCalls).toEqual([
        'https://signing-worker.internal/router-ab/signing-worker/sign/presign-pool',
      ]);
      expect(harness.reserveCalls).toEqual([
        {
          curve: 'ed25519',
          phase: 'finalize',
          thresholdSessionId,
          signingGrantId,
          signingWorkerId,
          operationId: 'operation-1',
          requestDigest: expect.stringMatching(budgetDigestPattern),
          signatureUses: 1,
          expiresAtMs,
        },
      ]);
      expect(harness.commitCalls).toEqual([
        {
          curve: 'ed25519',
          phase: 'finalize',
          thresholdSessionId,
          signingGrantId,
          reservationId: 'budget-reservation-1',
          signingWorkerId,
          operationId: 'operation-1',
          requestDigest: expect.stringMatching(budgetDigestPattern),
        },
      ]);
    } finally {
      globalThis.fetch = originalFetch;
    }
  });

  test('normal prepare rejects exhausted server budget before private SigningWorker forwarding', async () => {
    const harness = createThresholdService({ reserveBudget: 'exhausted' });
    const fetchCalls: string[] = [];
    const originalFetch = globalThis.fetch;
    globalThis.fetch = async (url) => {
      fetchCalls.push(String(url));
      return new Response(JSON.stringify({ ok: true }), { status: 200 });
    };

    try {
      const result = await callEd25519RouteCore({
        body: prepareBody(),
        privatePath: ROUTER_AB_ED25519_PRIVATE_SIGNING_PATHS.prepare,
        phase: 'prepare',
        service: harness.service,
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
      expect(harness.reserveCalls).toEqual([
        {
          curve: 'ed25519',
          phase: 'prepare',
          thresholdSessionId,
          signingGrantId,
          signingWorkerId,
          operationId: 'operation-1',
          requestDigest: expect.stringMatching(budgetDigestPattern),
          signatureUses: 1,
          expiresAtMs,
        },
      ]);
    } finally {
      globalThis.fetch = originalFetch;
    }
  });

  test('prepare private-worker failure releases the reservation as prepare phase', async () => {
    const harness = createThresholdService();
    const fetchCalls: string[] = [];
    const originalFetch = globalThis.fetch;
    globalThis.fetch = async (url) => {
      fetchCalls.push(String(url));
      return new Response('private worker failed', { status: 502 });
    };

    try {
      const result = await callEd25519RouteCore({
        body: prepareBody(),
        privatePath: ROUTER_AB_ED25519_PRIVATE_SIGNING_PATHS.prepare,
        phase: 'prepare',
        service: harness.service,
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
        'https://signing-worker.internal/router-ab/signing-worker/sign/prepare',
      ]);
      expect(harness.reserveCalls).toHaveLength(1);
      expect(harness.releaseCalls).toEqual([
        {
          curve: 'ed25519',
          phase: 'prepare',
          thresholdSessionId,
          signingGrantId,
          reservationId: 'budget-reservation-1',
        },
      ]);
    } finally {
      globalThis.fetch = originalFetch;
    }
  });

  test('normal prepare and finalize share the same canonical budget request digest', async () => {
    const harness = createThresholdService();
    const originalFetch = globalThis.fetch;
    globalThis.fetch = okRouterAbEd25519SigningWorkerFetch;

    try {
      const prepared = await callEd25519RouteCore({
        body: prepareBody(),
        privatePath: ROUTER_AB_ED25519_PRIVATE_SIGNING_PATHS.prepare,
        phase: 'prepare',
        service: harness.service,
      });
      expect(prepared.status).toBe(200);

      const finalized = await callEd25519RouteCore({
        body: finalizeBody(),
        privatePath: ROUTER_AB_ED25519_PRIVATE_SIGNING_PATHS.finalize,
        phase: 'finalize',
        service: harness.service,
      });
      expect(finalized.status).toBe(200);
      expect(harness.reserveCalls).toHaveLength(1);
      expect(harness.validateCalls).toHaveLength(1);
      expect(harness.reserveCalls[0]?.requestDigest).toEqual(
        expect.stringMatching(budgetDigestPattern),
      );
      expect(harness.validateCalls[0]?.requestDigest).toBe(harness.reserveCalls[0]?.requestDigest);
    } finally {
      globalThis.fetch = originalFetch;
    }
  });

  test('normal prepare budget digest changes when request expiry changes', async () => {
    const harness = createThresholdService();
    const originalFetch = globalThis.fetch;
    globalThis.fetch = okRouterAbEd25519SigningWorkerFetch;

    try {
      await callEd25519RouteCore({
        body: prepareBodyForExpiry(expiresAtMs),
        privatePath: ROUTER_AB_ED25519_PRIVATE_SIGNING_PATHS.prepare,
        phase: 'prepare',
        service: harness.service,
      });
      await callEd25519RouteCore({
        body: prepareBodyForExpiry(expiresAtMs - 1),
        privatePath: ROUTER_AB_ED25519_PRIVATE_SIGNING_PATHS.prepare,
        phase: 'prepare',
        service: harness.service,
      });
      expect(harness.reserveCalls).toHaveLength(2);
      expect(harness.reserveCalls[0]?.requestDigest).toEqual(
        expect.stringMatching(budgetDigestPattern),
      );
      expect(harness.reserveCalls[1]?.requestDigest).toEqual(
        expect.stringMatching(budgetDigestPattern),
      );
      expect(harness.reserveCalls[0]?.requestDigest).not.toBe(
        harness.reserveCalls[1]?.requestDigest,
      );
    } finally {
      globalThis.fetch = originalFetch;
    }
  });

  test('finalize private-worker failure releases the reservation without committing budget', async () => {
    const harness = createThresholdService();
    const fetchCalls: string[] = [];
    const originalFetch = globalThis.fetch;
    globalThis.fetch = async (url) => {
      fetchCalls.push(String(url));
      return new Response('private worker failed', { status: 502 });
    };

    try {
      const result = await callEd25519RouteCore({
        body: finalizeBody(),
        privatePath: ROUTER_AB_ED25519_PRIVATE_SIGNING_PATHS.finalize,
        phase: 'finalize',
        service: harness.service,
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
        'https://signing-worker.internal/router-ab/signing-worker/sign',
      ]);
      expect(harness.validateCalls).toEqual([
        {
          curve: 'ed25519',
          phase: 'finalize',
          thresholdSessionId,
          signingGrantId,
          reservationId: 'budget-reservation-1',
          signingWorkerId,
          operationId: 'operation-1',
          requestDigest: expect.stringMatching(budgetDigestPattern),
        },
      ]);
      expect(harness.commitCalls).toEqual([]);
      expect(harness.releaseCalls).toEqual([
        {
          curve: 'ed25519',
          phase: 'finalize',
          thresholdSessionId,
          signingGrantId,
          reservationId: 'budget-reservation-1',
        },
      ]);
    } finally {
      globalThis.fetch = originalFetch;
    }
  });

  test('normal finalize rejects invalid reservation before private SigningWorker forwarding', async () => {
    const harness = createThresholdService({ validateBudget: 'exhausted' });
    const fetchCalls: string[] = [];
    const originalFetch = globalThis.fetch;
    globalThis.fetch = async (url) => {
      fetchCalls.push(String(url));
      return new Response(JSON.stringify({ ok: true }), { status: 200 });
    };

    try {
      const result = await callEd25519RouteCore({
        body: finalizeBody(),
        privatePath: ROUTER_AB_ED25519_PRIVATE_SIGNING_PATHS.finalize,
        phase: 'finalize',
        service: harness.service,
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
          curve: 'ed25519',
          phase: 'finalize',
          thresholdSessionId,
          signingGrantId,
          reservationId: 'budget-reservation-1',
          signingWorkerId,
          operationId: 'operation-1',
          requestDigest: expect.stringMatching(budgetDigestPattern),
        },
      ]);
      expect(harness.commitCalls).toEqual([]);
      expect(harness.releaseCalls).toEqual([
        {
          curve: 'ed25519',
          phase: 'finalize',
          thresholdSessionId,
          signingGrantId,
          reservationId: 'budget-reservation-1',
          signingWorkerId,
          operationId: 'operation-1',
          requestDigest: expect.stringMatching(budgetDigestPattern),
        },
      ]);
    } finally {
      globalThis.fetch = originalFetch;
    }
  });
});
