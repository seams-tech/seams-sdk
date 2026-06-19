import { expect, test } from '@playwright/test';
import {
  handleRouterAbEd25519NormalSigningRouteCore,
  ROUTER_AB_ED25519_PRIVATE_SIGNING_PATHS,
} from '../../packages/sdk-server-ts/src/router/routerAbPrivateSigningWorker';
import type { SessionAdapter } from '../../packages/sdk-server-ts/src/router/relay';
import type {
  RouterAbNormalSigningBudgetConsumeInput,
  RouterAbNormalSigningBudgetReleaseInput,
  RouterAbNormalSigningBudgetReservationInput,
} from '../../packages/sdk-server-ts/src/core/ThresholdService/ThresholdSigningService';
import { ROUTER_AB_ED25519_WALLET_SESSION_JWT_KIND } from '@shared/utils/sessionTokens';
import { ROUTER_AB_ED25519_NORMAL_SIGNING_STATE_KIND } from '@shared/utils/signingSessionSeal';

type Ed25519RouteInput = Parameters<typeof handleRouterAbEd25519NormalSigningRouteCore>[0];
type Ed25519ThresholdService = NonNullable<ReturnType<Ed25519RouteInput['getThreshold']>>;

const thresholdSessionId = 'threshold-ed25519-session-1';
const walletSigningSessionId = 'wallet-signing-session-1';
const walletId = 'alice.test.near';
const signingWorkerId = 'local-signing-worker';
const expiresAtMs = Date.now() + 60_000;

type BudgetRouteHarness = {
  service: Ed25519ThresholdService;
  consumeCalls: RouterAbNormalSigningBudgetConsumeInput[];
  releaseCalls: RouterAbNormalSigningBudgetReleaseInput[];
  reserveCalls: RouterAbNormalSigningBudgetReservationInput[];
};

function walletSessionClaims(): Record<string, unknown> {
  return {
    sub: walletId,
    walletId,
    kind: ROUTER_AB_ED25519_WALLET_SESSION_JWT_KIND,
    sessionId: thresholdSessionId,
    walletSigningSessionId,
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
    pool_binding: {
      server_round1_handle: 'server-round1-handle-1',
      binding_digest: { bytes: Array.from(new Uint8Array(32).fill(7)) },
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

function createThresholdService(args?: { consumeBudget?: 'ok' | 'exhausted' }): BudgetRouteHarness {
  const consumeCalls: RouterAbNormalSigningBudgetConsumeInput[] = [];
  const releaseCalls: RouterAbNormalSigningBudgetReleaseInput[] = [];
  const reserveCalls: RouterAbNormalSigningBudgetReservationInput[] = [];
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
    async consumeRouterAbNormalSigningBudget(input) {
      consumeCalls.push(input);
      if (args?.consumeBudget === 'exhausted') return budgetFailure();
      return { ok: true, remainingUses: 2 };
    },
    async reserveRouterAbNormalSigningBudget(input) {
      reserveCalls.push(input);
      return {
        ok: true,
        reservationId: 'budget-reservation-1',
        remainingUses: 3,
        reservedUses: 1,
        availableUses: 2,
      };
    },
    async commitRouterAbNormalSigningBudget() {
      return { ok: true, remainingUses: 2 };
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
  };
  return { service, consumeCalls, releaseCalls, reserveCalls };
}

async function callEd25519RouteCore(
  input: {
    body: Record<string, unknown>;
    privatePath: Ed25519RouteInput['privatePath'];
    phase: Ed25519RouteInput['phase'];
    service: Ed25519ThresholdService;
  },
): Promise<Awaited<ReturnType<typeof handleRouterAbEd25519NormalSigningRouteCore>>> {
  return await handleRouterAbEd25519NormalSigningRouteCore({
    body: input.body,
    rawBody: input.body,
    headers: { authorization: 'Bearer wallet-session.jwt' },
    session: sessionAdapter(),
    getThreshold: () => input.service,
    admissionAdapter: null,
    privatePath: input.privatePath,
    phase: input.phase,
  });
}

test.describe('Router A/B Ed25519 route-core budget gates', () => {
  test('presign-pool finalize rejects exhausted budget before private SigningWorker forwarding', async () => {
    const harness = createThresholdService({ consumeBudget: 'exhausted' });
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
      expect(harness.consumeCalls).toEqual([
        {
          curve: 'ed25519',
          phase: 'finalize',
          sessionId: thresholdSessionId,
          walletSigningSessionId,
          requestId: 'presign-finalize-request-1',
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
        'https://signing-worker.internal/router-ab/v1/signing-worker/sign/prepare',
      ]);
      expect(harness.reserveCalls).toHaveLength(1);
      expect(harness.releaseCalls).toEqual([
        {
          curve: 'ed25519',
          phase: 'prepare',
          sessionId: thresholdSessionId,
          walletSigningSessionId,
          reservationId: 'budget-reservation-1',
        },
      ]);
    } finally {
      globalThis.fetch = originalFetch;
    }
  });
});
