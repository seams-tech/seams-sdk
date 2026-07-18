import { expect, test } from '@playwright/test';
import { readFileSync } from 'node:fs';
import {
  buildRouterAbEd25519PrivateSigningWorkerBody,
  handleRouterAbEd25519NormalSigningRouteCore,
  ROUTER_AB_ED25519_PRIVATE_SIGNING_PATHS,
  type RouterAbNormalSigningAdmissionAdapter,
} from '../../packages/sdk-server-ts/src/router/routerAbPrivateSigningWorker';
import type { SessionAdapter } from '../../packages/sdk-server-ts/src/router/routerApi';
import type {
  RouterAbNormalSigningBudgetFinalizeInput,
  RouterAbNormalSigningBudgetReleaseInput,
  RouterAbNormalSigningBudgetReservationInput,
} from '../../packages/sdk-server-ts/src/core/routerAbSigning/RouterAbNormalSigningRuntime';
import { parseRouterAbEd25519WalletSessionClaims } from '../../packages/sdk-server-ts/src/core/ThresholdService/validation';
import { ROUTER_AB_ED25519_WALLET_SESSION_JWT_KIND } from '@shared/utils/sessionTokens';
import { ROUTER_AB_ED25519_NORMAL_SIGNING_STATE_KIND } from '@shared/utils/signingSessionSeal';

type Ed25519RouteInput = Parameters<typeof handleRouterAbEd25519NormalSigningRouteCore>[0];
type Ed25519NormalSigningRuntime = NonNullable<Ed25519RouteInput['runtime']>;

const normalSigningVectors = JSON.parse(
  readFileSync(
    new URL(
      '../../crates/router-ab-core/fixtures/protocol/normal-signing/normal-signing-vectors-v2.json',
      import.meta.url,
    ),
    'utf8',
  ),
) as {
  cases: Array<{
    case_id: string;
    prepare_request_json: Record<string, unknown>;
    intent_digest_b64u: string;
    signing_payload_digest_b64u: string;
    admitted_signing_digest_b64u: string;
    round1_binding_digest_b64u: string;
  }>;
};

const thresholdSessionId = 'threshold-ed25519-session-1';
const signingGrantId = 'signing-grant-1';
const walletId = 'alice.test.near';
const signingWorkerId = 'local-signing-worker';
const expiresAtMs = Date.now() + 60_000;
const budgetDigestPattern = /^[A-Za-z0-9_-]{43}$/;

type BudgetRouteHarness = {
  runtime: Ed25519NormalSigningRuntime;
  commitCalls: RouterAbNormalSigningBudgetFinalizeInput[];
  releaseCalls: Array<
    RouterAbNormalSigningBudgetReleaseInput | RouterAbNormalSigningBudgetFinalizeInput
  >;
  reserveCalls: RouterAbNormalSigningBudgetReservationInput[];
  validateCalls: RouterAbNormalSigningBudgetFinalizeInput[];
};

function walletSessionClaims(): Record<string, unknown> {
  return {
    sub: walletId,
    walletId,
    nearAccountId: walletId,
    nearEd25519SigningKeyId: 'near-ed25519-key-1',
    kind: ROUTER_AB_ED25519_WALLET_SESSION_JWT_KIND,
    thresholdSessionId,
    signingGrantId,
    relayerKeyId: 'near-relayer-key-1',
    authority: {
      walletId,
      factor: { kind: 'passkey', credentialIdB64u: 'credential-1' },
      verifier: { kind: 'webauthn', rpId: 'localhost' },
      bindingId: 'passkey:localhost:credential-1',
    },
    authorityScope: { kind: 'passkey_rp', rpId: 'localhost' },
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

function parsedWalletSessionClaims() {
  const parsed = parseRouterAbEd25519WalletSessionClaims(walletSessionClaims());
  if (!parsed) throw new Error('wallet session claims fixture is invalid');
  return parsed;
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

function prepareBody(): Record<string, unknown> {
  return {
    scope: routerAbScope('prepare-request-1'),
    expires_at_ms: expiresAtMs,
    intent: {
      kind: 'near_transaction_v1',
      operation_id: 'operation-1',
      operation_fingerprint: 'operation-fingerprint-1',
      near_account_id: walletId,
      near_network_id: 'testnet',
      transactions: [
        {
          receiver_id: 'contract.testnet',
          action_fingerprint: 'action-fingerprint-1',
        },
      ],
      unsigned_transaction_borsh_b64u: 'AQID',
    },
    signing_payload: {
      kind: 'near_unsigned_transaction_borsh_v1',
      unsigned_transaction_borsh_b64u: 'AQID',
      expected_signing_digest_b64u: 'A5BYxvLAy0ksUzsKTRTvd8wPeKvMztUofYShogEc-4E',
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
        bytes: Array.from(Buffer.from('PYo-Uu3D3rEWSPO7bJM8XSbkpWuMuVPK7f6MpsCfUrE', 'base64url')),
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

function createNormalSigningRuntime(args?: {
  commitBudget?: 'ok' | 'exhausted';
  reserveBudget?: 'ok' | 'exhausted';
  validateBudget?: 'ok' | 'exhausted';
}): BudgetRouteHarness {
  const commitCalls: RouterAbNormalSigningBudgetFinalizeInput[] = [];
  const releaseCalls: Array<
    RouterAbNormalSigningBudgetReleaseInput | RouterAbNormalSigningBudgetFinalizeInput
  > = [];
  const reserveCalls: RouterAbNormalSigningBudgetReservationInput[] = [];
  const validateCalls: RouterAbNormalSigningBudgetFinalizeInput[] = [];
  const runtime: Ed25519NormalSigningRuntime = {
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
        reservationId: 'budget-reservation-1',
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

async function callEd25519RouteCore(input: {
  body: Record<string, unknown>;
  privatePath: Ed25519RouteInput['privatePath'];
  phase: Ed25519RouteInput['phase'];
  runtime: Ed25519NormalSigningRuntime;
}): Promise<Awaited<ReturnType<typeof handleRouterAbEd25519NormalSigningRouteCore>>> {
  return await handleRouterAbEd25519NormalSigningRouteCore({
    body: input.body,
    rawBody: input.body,
    headers: { authorization: 'Bearer wallet-session.jwt' },
    session: sessionAdapter(),
    runtime: input.runtime,
    admissionAdapter: allowAllAdmissionAdapter(),
    privatePath: input.privatePath,
    phase: input.phase,
  });
}

async function okRouterAbEd25519SigningWorkerFetch(
  url: Parameters<typeof fetch>[0],
  init?: Parameters<typeof fetch>[1],
): Promise<Response> {
  const privateBody = JSON.parse(String(init?.body)) as Record<string, unknown>;
  expect(Object.hasOwn(privateBody, 'server_material')).toBe(false);
  const path = String(url).endsWith('/sign/prepare')
    ? ROUTER_AB_ED25519_PRIVATE_SIGNING_PATHS.prepare
    : ROUTER_AB_ED25519_PRIVATE_SIGNING_PATHS.finalize;
  if (path === ROUTER_AB_ED25519_PRIVATE_SIGNING_PATHS.prepare) {
    expect(privateBody.scope).toEqual(routerAbScope('prepare-request-1'));
    expect(privateBody.admission_candidate).toMatchObject({
      account_id: walletId,
      subject_id: walletId,
      threshold_session_id: thresholdSessionId,
      signing_worker_id: signingWorkerId,
      request_id: 'prepare-request-1',
      expires_at_ms: expiresAtMs,
    });
    expect(privateBody.trusted_admission).toMatchObject({
      metadata: {
        org_id: 'org-1',
        project_id: 'project-1',
        environment: 'env-1',
        account_id: walletId,
        trusted_source_digest: {
          bytes: Array.from(
            Buffer.from('zV9QyP4XJjcW9OEwvRRDDMyxGcdOmL7Uf9hB0oQD-PM', 'base64url'),
          ),
        },
      },
      decision: {
        kind: 'accepted',
        request_id: 'prepare-request-1',
      },
    });
  } else {
    expect(privateBody.request).toMatchObject({
      scope: routerAbScope('prepare-request-1'),
      expires_at_ms: expiresAtMs,
    });
    expect(privateBody).not.toHaveProperty('kind');
  }
  return new Response(JSON.stringify({ ok: true, privatePath: path }), { status: 200 });
}

function digestB64u(value: unknown): string {
  const record = value as { bytes?: unknown };
  if (!Array.isArray(record.bytes)) throw new Error('digest bytes are missing');
  return Buffer.from(record.bytes).toString('base64url');
}

test.describe('Router A/B Ed25519 route-core budget gates', () => {
  test('private prepare admission matches the committed Rust protocol vectors', async () => {
    for (const vector of normalSigningVectors.cases) {
      const privateBody = await buildRouterAbEd25519PrivateSigningWorkerBody({
        phase: 'prepare',
        body: vector.prepare_request_json,
        claims: parsedWalletSessionClaims(),
        headers: { origin: 'https://localhost' },
      });
      if (!('admission_candidate' in privateBody)) {
        throw new Error(`${vector.case_id} did not produce a prepare admission`);
      }
      expect(digestB64u(privateBody.admission_candidate.intent_digest)).toBe(
        vector.intent_digest_b64u,
      );
      expect(digestB64u(privateBody.admission_candidate.signing_payload_digest)).toBe(
        vector.signing_payload_digest_b64u,
      );
      expect(digestB64u(privateBody.admission_candidate.admitted_signing_digest)).toBe(
        vector.admitted_signing_digest_b64u,
      );
      expect(digestB64u(privateBody.admission_candidate.round1_binding_digest)).toBe(
        vector.round1_binding_digest_b64u,
      );
    }
  });

  test('prepare rejects missing admission adapter before private SigningWorker forwarding', async () => {
    const harness = createNormalSigningRuntime();
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
        runtime: harness.runtime,
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

  test('normal prepare rejects exhausted server budget before private SigningWorker forwarding', async () => {
    const harness = createNormalSigningRuntime({ reserveBudget: 'exhausted' });
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
      expect(harness.reserveCalls).toEqual([
        {
          curve: 'ed25519',
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
    const harness = createNormalSigningRuntime();
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
    const harness = createNormalSigningRuntime();
    const originalFetch = globalThis.fetch;
    globalThis.fetch = okRouterAbEd25519SigningWorkerFetch;

    try {
      const prepared = await callEd25519RouteCore({
        body: prepareBody(),
        privatePath: ROUTER_AB_ED25519_PRIVATE_SIGNING_PATHS.prepare,
        phase: 'prepare',
        runtime: harness.runtime,
      });
      expect(prepared.status).toBe(200);

      const finalized = await callEd25519RouteCore({
        body: finalizeBody(),
        privatePath: ROUTER_AB_ED25519_PRIVATE_SIGNING_PATHS.finalize,
        phase: 'finalize',
        runtime: harness.runtime,
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
    const harness = createNormalSigningRuntime();
    const originalFetch = globalThis.fetch;
    globalThis.fetch = okRouterAbEd25519SigningWorkerFetch;

    try {
      await callEd25519RouteCore({
        body: prepareBodyForExpiry(expiresAtMs),
        privatePath: ROUTER_AB_ED25519_PRIVATE_SIGNING_PATHS.prepare,
        phase: 'prepare',
        runtime: harness.runtime,
      });
      await callEd25519RouteCore({
        body: prepareBodyForExpiry(expiresAtMs - 1),
        privatePath: ROUTER_AB_ED25519_PRIVATE_SIGNING_PATHS.prepare,
        phase: 'prepare',
        runtime: harness.runtime,
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
    const harness = createNormalSigningRuntime();
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
      expect(fetchCalls).toEqual(['https://signing-worker.internal/router-ab/signing-worker/sign']);
      expect(harness.validateCalls).toEqual([
        {
          curve: 'ed25519',
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
    const harness = createNormalSigningRuntime({ validateBudget: 'exhausted' });
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
          curve: 'ed25519',
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
