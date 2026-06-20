import { expect, test } from '@playwright/test';
import { createRelayRouter } from '@server/router/express-adaptor';
import type {
  RouterAbNormalSigningAdmissionAdapter,
  RouterAbNormalSigningAdmissionInput,
  ThresholdSigningAdapter,
} from '@server/router/express-adaptor';
import { deriveRouterAbEcdsaHssBudgetOperationId } from '@server/router/routerAbPrivateSigningWorker';
import {
  ROUTER_AB_ED25519_NORMAL_SIGNING_PATH_V2,
  ROUTER_AB_ED25519_NORMAL_SIGNING_PRESIGN_POOL_PREPARE_PATH_V2,
  ROUTER_AB_ED25519_NORMAL_SIGNING_PREPARE_PATH_V2,
  ROUTER_AB_ED25519_NORMAL_SIGNING_STATE_KIND,
} from '@shared/utils/signingSessionSeal';
import {
  buildRouterAbEcdsaHssEvmDigestSigningFinalizeRequestV1,
  buildRouterAbEcdsaHssEvmDigestSigningRequestV1,
  routerAbEcdsaHssContextBindingB64uV1,
  ROUTER_AB_ECDSA_HSS_KEY_SCOPE_V1,
  ROUTER_AB_ECDSA_HSS_NORMAL_SIGNING_PATH_V1,
  ROUTER_AB_ECDSA_HSS_NORMAL_SIGNING_PREPARE_PATH_V1,
  ROUTER_AB_ECDSA_HSS_NORMAL_SIGNING_STATE_KIND_V1,
} from '@shared/utils/routerAbEcdsaHss';
import {
  ROUTER_AB_ECDSA_HSS_WALLET_SESSION_JWT_KIND,
  ROUTER_AB_ED25519_WALLET_SESSION_JWT_KIND,
} from '@shared/utils/sessionTokens';
import { base64UrlEncode } from '@shared/utils/encoders';
import { fetchJson, makeFakeAuthService, makeSessionAdapter, startExpressRouter } from './helpers';

type LegacyThresholdSessionKind = 'threshold_ed25519_session_v1' | 'threshold_ecdsa_session_v2';

type RouterAbBudgetConsumeCall = {
  curve: 'ed25519' | 'ecdsa-hss';
  phase: 'finalize';
  thresholdSessionId: string;
  signingGrantId: string;
  operationId: string;
};

const ROUTER_AB_TEST_EXPIRES_AT_MS = Date.now() + 60 * 60 * 1000;

const NORMAL_SIGNING_ROUTES = [
  {
    label: 'Ed25519 prepare',
    path: ROUTER_AB_ED25519_NORMAL_SIGNING_PREPARE_PATH_V2,
    message: 'Missing or invalid Wallet Session JWT',
    legacyKind: 'threshold_ed25519_session_v1',
    legacyMessage: 'Invalid Router A/B Wallet Session claims',
  },
  {
    label: 'Ed25519 presign-pool prepare',
    path: ROUTER_AB_ED25519_NORMAL_SIGNING_PRESIGN_POOL_PREPARE_PATH_V2,
    message: 'Missing or invalid Wallet Session JWT',
    legacyKind: 'threshold_ed25519_session_v1',
    legacyMessage: 'Invalid Router A/B Wallet Session claims',
  },
  {
    label: 'Ed25519 finalize',
    path: ROUTER_AB_ED25519_NORMAL_SIGNING_PATH_V2,
    message: 'Missing or invalid Wallet Session JWT',
    legacyKind: 'threshold_ed25519_session_v1',
    legacyMessage: 'Invalid Router A/B Wallet Session claims',
  },
  {
    label: 'ECDSA-HSS prepare',
    path: ROUTER_AB_ECDSA_HSS_NORMAL_SIGNING_PREPARE_PATH_V1,
    message: 'Missing or invalid Wallet Session token',
    legacyKind: 'threshold_ecdsa_session_v2',
    legacyMessage: 'Invalid Wallet Session token claims',
  },
  {
    label: 'ECDSA-HSS finalize',
    path: ROUTER_AB_ECDSA_HSS_NORMAL_SIGNING_PATH_V1,
    message: 'Missing or invalid Wallet Session token',
    legacyKind: 'threshold_ecdsa_session_v2',
    legacyMessage: 'Invalid Wallet Session token claims',
  },
] as const;

const ED25519_NORMAL_SIGNING_ROUTES = NORMAL_SIGNING_ROUTES.filter((route) =>
  route.label.startsWith('Ed25519'),
);
const ECDSA_HSS_NORMAL_SIGNING_ROUTES = NORMAL_SIGNING_ROUTES.filter((route) =>
  route.label.startsWith('ECDSA-HSS'),
);

function b64u(bytes: number[]): string {
  return base64UrlEncode(Uint8Array.from(bytes));
}

const ROUTER_AB_ED25519_CLAIMS = {
  kind: ROUTER_AB_ED25519_WALLET_SESSION_JWT_KIND,
  sub: 'alice.testnet',
  walletId: 'alice.testnet',
  thresholdSessionId: 'threshold-session-1',
  signingGrantId: 'signing-grant-1',
  relayerKeyId: 'relayer-key-1',
  rpId: 'example.localhost',
  thresholdExpiresAtMs: ROUTER_AB_TEST_EXPIRES_AT_MS,
  participantIds: [1, 2],
  runtimePolicyScope: {
    orgId: 'org',
    projectId: 'proj',
    envId: 'dev',
    signingRootVersion: 'default',
  },
  routerAbNormalSigning: {
    kind: ROUTER_AB_ED25519_NORMAL_SIGNING_STATE_KIND,
    signingWorkerId: 'signing-worker-a',
  },
} as const;

const ECDSA_HSS_SCOPE = {
  context: {
    wallet_id: 'alice.testnet',
    rp_id: 'example.localhost',
    key_scope: ROUTER_AB_ECDSA_HSS_KEY_SCOPE_V1,
    ecdsa_threshold_key_id: 'ehss-key-test',
    signing_root_id: 'signing-root',
    signing_root_version: 'default',
    key_purpose: 'normal-signing',
    key_version: 'v1',
  },
  public_identity: {
    context_binding_b64u: b64u(Array.from({ length: 32 }, (_, index) => index + 1)),
    client_public_key33_b64u: b64u([0x02, ...Array.from({ length: 32 }, () => 1)]),
    server_public_key33_b64u: b64u([0x03, ...Array.from({ length: 32 }, () => 2)]),
    threshold_public_key33_b64u: b64u([0x02, ...Array.from({ length: 32 }, () => 3)]),
    ethereum_address20_b64u: b64u(Array.from({ length: 20 }, () => 4)),
    client_share_retry_counter: 0,
    server_share_retry_counter: 0,
  },
  signing_worker: {
    server_id: 'signing-worker-1',
    key_epoch: 'epoch-1',
    recipient_encryption_key: 'x25519:signing-worker-recipient-key',
  },
  activation_epoch: 'activation-epoch-1',
} as const;

const ROUTER_AB_ECDSA_HSS_CLAIMS = {
  kind: ROUTER_AB_ECDSA_HSS_WALLET_SESSION_JWT_KIND,
  sub: 'alice.testnet',
  walletId: 'alice.testnet',
  thresholdSessionId: 'threshold-ecdsa-session-1',
  signingGrantId: 'signing-grant-ecdsa-1',
  keyScope: 'evm-family',
  keyHandle: ECDSA_HSS_SCOPE.context.ecdsa_threshold_key_id,
  relayerKeyId: 'relayer-key-1',
  rpId: ECDSA_HSS_SCOPE.context.rp_id,
  thresholdExpiresAtMs: ROUTER_AB_TEST_EXPIRES_AT_MS,
  participantIds: [1, 2],
  runtimePolicyScope: {
    orgId: 'org',
    projectId: 'proj',
    envId: 'dev',
    signingRootVersion: ECDSA_HSS_SCOPE.context.signing_root_version,
  },
  routerAbEcdsaHssNormalSigning: {
    kind: ROUTER_AB_ECDSA_HSS_NORMAL_SIGNING_STATE_KIND_V1,
    scope: ECDSA_HSS_SCOPE,
  },
} as const;

function legacyThresholdClaims(kind: LegacyThresholdSessionKind): Record<string, unknown> {
  const claims = {
    kind,
    sub: 'alice.testnet',
    walletId: 'alice.testnet',
    thresholdSessionId: 'threshold-session-1',
    signingGrantId: 'signing-grant-1',
    relayerKeyId: 'relayer-key-1',
    rpId: 'example.localhost',
    thresholdExpiresAtMs: ROUTER_AB_TEST_EXPIRES_AT_MS,
    participantIds: [1, 2],
  };
  if (kind === 'threshold_ed25519_session_v1') return claims;
  return {
    ...claims,
    keyScope: 'evm-family',
    keyHandle: 'ehss-key-test',
  };
}

async function allowRouterAbNormalSigningAdmission(
  _input: RouterAbNormalSigningAdmissionInput,
): Promise<{ ok: true }> {
  return { ok: true };
}

const ALLOW_ROUTER_AB_NORMAL_SIGNING_ADMISSION: RouterAbNormalSigningAdmissionAdapter = {
  evaluate: allowRouterAbNormalSigningAdmission,
};

async function withAuthBoundaryRouter<T>(
  parseSession: ReturnType<typeof makeSessionAdapter>['parse'],
  run: (input: { baseUrl: string; getThresholdServiceReadCount: () => number }) => Promise<T>,
): Promise<T> {
  let thresholdServiceReads = 0;
  const thresholdOption: ThresholdSigningAdapter = {
    getSchemeModule: () => null,
  };
  const service = makeFakeAuthService({
    getThresholdSigningService: () => {
      thresholdServiceReads += 1;
      return null;
    },
  });
  const router = createRelayRouter(service, {
    session: makeSessionAdapter({ parse: parseSession }),
    threshold: thresholdOption,
    routerAbNormalSigningAdmission: ALLOW_ROUTER_AB_NORMAL_SIGNING_ADMISSION,
  });
  const srv = await startExpressRouter(router);
  try {
    return await run({
      baseUrl: srv.baseUrl,
      getThresholdServiceReadCount: () => thresholdServiceReads,
    });
  } finally {
    await srv.close();
  }
}

async function withReplayProtectedNormalSigningRouter<T>(
  parseSession: ReturnType<typeof makeSessionAdapter>['parse'],
  run: (input: {
    baseUrl: string;
    forwardedCalls: () => number;
    forwardedUrls: () => readonly string[];
  }) => Promise<T>,
): Promise<T> {
  const reserved = new Set<string>();
  let forwardedCalls = 0;
  const forwardedUrls: string[] = [];
  const originalFetch = globalThis.fetch;
  globalThis.fetch = (async (url: RequestInfo | URL, init?: RequestInit) => {
    const href = String(url);
    if (href.startsWith('http://127.0.0.1:')) {
      return originalFetch(url, init);
    }
    forwardedCalls += 1;
    forwardedUrls.push(href);
    return new Response(JSON.stringify({ ok: true }), {
      status: 200,
      headers: { 'content-type': 'application/json' },
    });
  }) as typeof fetch;

  const thresholdOption: ThresholdSigningAdapter = {
    getSchemeModule: () => null,
  };
  const thresholdService = {
    getRouterAbSigningWorkerPrivateHttpConfig: () => ({
      signingWorkerBaseUrl: 'https://signing-worker.internal',
      auth: { kind: 'internal_service_auth_token', token: 'internal-service-token' },
    }),
    resolveRouterAbEd25519SigningWorkerPrivateMaterial: async () => ({
      ok: true as const,
      material: {
        kind: 'router_ab_ed25519_signing_worker_material_v1',
        account_public_key: 'ed25519:relayer-key-1',
        x_server_base_b64u: b64u(Array.from({ length: 32 }, () => 9)),
        signing_worker_material_handle: 'ed25519-hss/relayer-key-1/threshold-session-1',
        activated_at_ms: 1_800_000_000_000,
      },
    }),
    reserveRouterAbNormalSigningPrepareReplay: async (input: {
      curve: 'ed25519' | 'ecdsa-hss';
      phase: 'prepare' | 'presign-pool-prepare';
      thresholdSessionId: string;
      requestId: string;
    }) => {
      const key = `${input.curve}:${input.phase}:${input.thresholdSessionId}:${input.requestId}`;
      if (reserved.has(key)) {
        return {
          ok: false as const,
          status: 400,
          code: 'one_use_replay_rejected',
          message: 'Router A/B normal-signing prepare request id already used',
        };
      }
      reserved.add(key);
      return { ok: true as const };
    },
    consumeRouterAbNormalSigningBudget: async () => ({
      ok: true as const,
      remainingUses: 2,
    }),
    reserveRouterAbNormalSigningBudget: async (input: { operationId: string }) => ({
      ok: true as const,
      reservationId: `${input.operationId}-budget-reservation`,
      remainingUses: 3,
      reservedUses: 1,
      availableUses: 2,
    }),
    commitRouterAbNormalSigningBudget: async () => ({
      ok: true as const,
      remainingUses: 2,
    }),
    validateRouterAbNormalSigningBudget: async () => ({
      ok: true as const,
      remainingUses: 3,
    }),
    releaseRouterAbNormalSigningBudget: async () => ({
      ok: true as const,
      released: true,
      remainingUses: 3,
      reservedUses: 0,
      availableUses: 3,
    }),
  };
  const service = makeFakeAuthService({
    getThresholdSigningService: () => thresholdService as any,
  });
  const router = createRelayRouter(service, {
    session: makeSessionAdapter({ parse: parseSession }),
    threshold: thresholdOption,
    routerAbNormalSigningAdmission: ALLOW_ROUTER_AB_NORMAL_SIGNING_ADMISSION,
  });
  const srv = await startExpressRouter(router);
  try {
    return await run({
      baseUrl: srv.baseUrl,
      forwardedCalls: () => forwardedCalls,
      forwardedUrls: () => [...forwardedUrls],
    });
  } finally {
    await srv.close();
    globalThis.fetch = originalFetch;
  }
}

async function withAdmissionGuardedNormalSigningRouter<T>(
  parseSession: ReturnType<typeof makeSessionAdapter>['parse'],
  admissionAdapter: RouterAbNormalSigningAdmissionAdapter,
  run: (input: {
    baseUrl: string;
    forwardedCalls: () => number;
    privateSigningWorkerReads: () => number;
    budgetConsumes: () => number;
  }) => Promise<T>,
): Promise<T> {
  let forwardedCalls = 0;
  let signingWorkerConfigReads = 0;
  let ed25519MaterialReads = 0;
  let budgetConsumes = 0;
  const originalFetch = globalThis.fetch;
  globalThis.fetch = (async (url: RequestInfo | URL, init?: RequestInit) => {
    const href = String(url);
    if (href.startsWith('http://127.0.0.1:')) {
      return originalFetch(url, init);
    }
    forwardedCalls += 1;
    return new Response(JSON.stringify({ ok: true }), {
      status: 200,
      headers: { 'content-type': 'application/json' },
    });
  }) as typeof fetch;

  const thresholdOption: ThresholdSigningAdapter = {
    getSchemeModule: () => null,
  };
  const thresholdService = {
    getRouterAbSigningWorkerPrivateHttpConfig: () => {
      signingWorkerConfigReads += 1;
      return {
        signingWorkerBaseUrl: 'https://signing-worker.internal',
        auth: { kind: 'internal_service_auth_token', token: 'internal-service-token' },
      };
    },
    resolveRouterAbEd25519SigningWorkerPrivateMaterial: async () => {
      ed25519MaterialReads += 1;
      return {
        ok: true as const,
        material: {
          kind: 'router_ab_ed25519_signing_worker_material_v1',
          account_public_key: 'ed25519:relayer-key-1',
          x_server_base_b64u: b64u(Array.from({ length: 32 }, () => 9)),
          signing_worker_material_handle: 'ed25519-hss/relayer-key-1/threshold-session-1',
          activated_at_ms: 1_800_000_000_000,
        },
      };
    },
    reserveRouterAbNormalSigningPrepareReplay: async () => ({ ok: true as const }),
    consumeRouterAbNormalSigningBudget: async () => {
      budgetConsumes += 1;
      return { ok: true as const, remainingUses: 2 };
    },
    reserveRouterAbNormalSigningBudget: async (input: { operationId: string }) => ({
      ok: true as const,
      reservationId: `${input.operationId}-budget-reservation`,
      remainingUses: 3,
      reservedUses: 1,
      availableUses: 2,
    }),
    commitRouterAbNormalSigningBudget: async () => {
      budgetConsumes += 1;
      return { ok: true as const, remainingUses: 2 };
    },
    validateRouterAbNormalSigningBudget: async () => ({
      ok: true as const,
      remainingUses: 3,
    }),
    releaseRouterAbNormalSigningBudget: async () => ({
      ok: true as const,
      released: true,
      remainingUses: 3,
      reservedUses: 0,
      availableUses: 3,
    }),
  };
  const service = makeFakeAuthService({
    getThresholdSigningService: () => thresholdService as any,
  });
  const router = createRelayRouter(service, {
    session: makeSessionAdapter({ parse: parseSession }),
    threshold: thresholdOption,
    routerAbNormalSigningAdmission: admissionAdapter,
  });
  const srv = await startExpressRouter(router);
  try {
    return await run({
      baseUrl: srv.baseUrl,
      forwardedCalls: () => forwardedCalls,
      privateSigningWorkerReads: () => signingWorkerConfigReads + ed25519MaterialReads,
      budgetConsumes: () => budgetConsumes,
    });
  } finally {
    await srv.close();
    globalThis.fetch = originalFetch;
  }
}

async function withBudgetedNormalSigningRouter<T>(
  parseSession: ReturnType<typeof makeSessionAdapter>['parse'],
  validateRouterAbNormalSigningBudget: (
    input: RouterAbBudgetConsumeCall,
  ) => Promise<
    | { ok: true; remainingUses: number }
    | { ok: false; status: number; code: string; message: string }
  >,
  run: (input: {
    baseUrl: string;
    forwardedCalls: () => number;
    forwardedUrls: () => readonly string[];
  }) => Promise<T>,
): Promise<T> {
  let forwardedCalls = 0;
  const forwardedUrls: string[] = [];
  const originalFetch = globalThis.fetch;
  globalThis.fetch = (async (url: RequestInfo | URL, init?: RequestInit) => {
    const href = String(url);
    if (href.startsWith('http://127.0.0.1:')) {
      return originalFetch(url, init);
    }
    forwardedCalls += 1;
    forwardedUrls.push(href);
    return new Response(JSON.stringify({ ok: true }), {
      status: 200,
      headers: { 'content-type': 'application/json' },
    });
  }) as typeof fetch;

  const thresholdOption: ThresholdSigningAdapter = {
    getSchemeModule: () => null,
  };
  const thresholdService = {
    getRouterAbSigningWorkerPrivateHttpConfig: () => ({
      signingWorkerBaseUrl: 'https://signing-worker.internal',
      auth: { kind: 'internal_service_auth_token', token: 'internal-service-token' },
    }),
    resolveRouterAbEd25519SigningWorkerPrivateMaterial: async () => ({
      ok: true as const,
      material: {
        kind: 'router_ab_ed25519_signing_worker_material_v1',
        account_public_key: 'ed25519:relayer-key-1',
        x_server_base_b64u: b64u(Array.from({ length: 32 }, () => 9)),
        signing_worker_material_handle: 'ed25519-hss/relayer-key-1/threshold-session-1',
        activated_at_ms: 1_800_000_000_000,
      },
    }),
    reserveRouterAbNormalSigningPrepareReplay: async () => ({ ok: true as const }),
    reserveRouterAbNormalSigningBudget: async (input: { operationId: string }) => ({
      ok: true as const,
      reservationId: `${input.operationId}-budget-reservation`,
      remainingUses: 3,
      reservedUses: 1,
      availableUses: 2,
    }),
    commitRouterAbNormalSigningBudget: async (input: {
      curve: 'ed25519' | 'ecdsa-hss';
      phase: 'finalize';
      thresholdSessionId: string;
      signingGrantId: string;
      operationId: string;
    }) => ({ ok: true as const, remainingUses: 2 }),
    validateRouterAbNormalSigningBudget: async (input: {
      curve: 'ed25519' | 'ecdsa-hss';
      phase: 'finalize';
      thresholdSessionId: string;
      signingGrantId: string;
      operationId: string;
    }) =>
      validateRouterAbNormalSigningBudget({
        curve: input.curve,
        phase: input.phase,
        thresholdSessionId: input.thresholdSessionId,
        signingGrantId: input.signingGrantId,
        operationId: input.operationId,
      }),
    releaseRouterAbNormalSigningBudget: async () => ({
      ok: true as const,
      released: true,
      remainingUses: 3,
      reservedUses: 0,
      availableUses: 3,
    }),
  };
  const service = makeFakeAuthService({
    getThresholdSigningService: () => thresholdService as any,
  });
  const router = createRelayRouter(service, {
    session: makeSessionAdapter({ parse: parseSession }),
    threshold: thresholdOption,
    routerAbNormalSigningAdmission: ALLOW_ROUTER_AB_NORMAL_SIGNING_ADMISSION,
  });
  const srv = await startExpressRouter(router);
  try {
    return await run({
      baseUrl: srv.baseUrl,
      forwardedCalls: () => forwardedCalls,
      forwardedUrls: () => [...forwardedUrls],
    });
  } finally {
    await srv.close();
    globalThis.fetch = originalFetch;
  }
}

function ed25519NormalSigningBody(
  requestId: string,
  extra: Record<string, unknown> = {},
): Record<string, unknown> {
  const operationId = `${requestId}-operation`;
  return {
    scope: {
      request_id: requestId,
      account_id: ROUTER_AB_ED25519_CLAIMS.walletId,
      session_id: ROUTER_AB_ED25519_CLAIMS.thresholdSessionId,
      signing_worker_id: ROUTER_AB_ED25519_CLAIMS.routerAbNormalSigning.signingWorkerId,
    },
    expires_at_ms: ROUTER_AB_ED25519_CLAIMS.thresholdExpiresAtMs,
    budget_reservation_id: `${requestId}-budget-reservation`,
    budget_operation_id: operationId,
    intent: {
      kind: 'near_transaction_v1',
      operation_id: operationId,
      operation_fingerprint: `${requestId}-fingerprint`,
      near_account_id: ROUTER_AB_ED25519_CLAIMS.walletId,
      near_network_id: 'testnet',
      transactions: [
        {
          receiver_id: 'receiver.testnet',
          action_fingerprint: `${requestId}-action`,
        },
      ],
      unsigned_transaction_borsh_b64u: b64u([1, 2, 3]),
    },
    signing_payload: {
      kind: 'near_unsigned_transaction_borsh_v1',
      unsigned_transaction_borsh_b64u: b64u([1, 2, 3]),
      expected_signing_digest_b64u: b64u(Array.from({ length: 32 }, (_, index) => index)),
    },
    prepare_binding: {
      server_round1_handle: `${requestId}-server-round-1`,
      round1_binding_digest: { bytes: Array.from({ length: 32 }, (_, index) => index + 1) },
      intent_digest: { bytes: Array.from({ length: 32 }, (_, index) => index + 2) },
      signing_payload_digest: { bytes: Array.from({ length: 32 }, (_, index) => index + 3) },
    },
    ...extra,
  };
}

function bearerToken(headers: Record<string, string | string[] | undefined>): string {
  const header = headers.authorization || headers.Authorization;
  const value = Array.isArray(header) ? header[0] : header;
  const match = String(value || '').match(/^Bearer\s+(.+)$/i);
  return String(match?.[1] || '').trim();
}

function parseSessionFromClaimsByToken(
  claimsByToken: Map<string, Record<string, unknown>>,
): ReturnType<typeof makeSessionAdapter>['parse'] {
  return async (headers) => {
    const claims = claimsByToken.get(bearerToken(headers));
    return claims ? { ok: true as const, claims } : { ok: false as const };
  };
}

async function ecdsaFinalizeBudgetCase(input: {
  label: string;
  token: string;
  thresholdSessionId: string;
  signingGrantId: string;
  requestId: string;
  keyHandle: string;
  signingRootId: string;
  signingRootVersion: string;
}): Promise<{
  label: string;
  token: string;
  path: string;
  body: Record<string, unknown>;
  claims: Record<string, unknown>;
  privatePath: string;
  budget: RouterAbBudgetConsumeCall;
}> {
  const context = {
    ...ECDSA_HSS_SCOPE.context,
    ecdsa_threshold_key_id: input.keyHandle,
    signing_root_id: input.signingRootId,
    signing_root_version: input.signingRootVersion,
  };
  const scope = {
    ...ECDSA_HSS_SCOPE,
    context,
    public_identity: {
      ...ECDSA_HSS_SCOPE.public_identity,
      context_binding_b64u: await routerAbEcdsaHssContextBindingB64uV1(context),
    },
  };
  const operationIdentityBody = buildRouterAbEcdsaHssEvmDigestSigningRequestV1({
    scope,
    requestId: input.requestId,
    clientPresignatureId: `${input.requestId}-server-presignature`,
    expiresAtMs: ROUTER_AB_ECDSA_HSS_CLAIMS.thresholdExpiresAtMs,
    signingDigest32: Uint8Array.from({ length: 32 }, (_, index) => index + 1),
  });
  const operationId = await deriveRouterAbEcdsaHssBudgetOperationId({
    body: operationIdentityBody,
    signingWorkerId: scope.signing_worker.server_id,
    thresholdSessionId: input.thresholdSessionId,
  });
  const body = buildRouterAbEcdsaHssEvmDigestSigningFinalizeRequestV1({
    scope,
    requestId: input.requestId,
    budgetReservationId: `${input.requestId}-budget-reservation`,
    budgetOperationId: operationId,
    expiresAtMs: ROUTER_AB_ECDSA_HSS_CLAIMS.thresholdExpiresAtMs,
    signingDigest32: Uint8Array.from({ length: 32 }, (_, index) => index + 1),
    serverPresignatureId: `${input.requestId}-server-presignature`,
    clientSignatureShare32: Uint8Array.from({ length: 32 }, (_, index) => 255 - index),
  });
  const claims = {
    ...ROUTER_AB_ECDSA_HSS_CLAIMS,
    thresholdSessionId: input.thresholdSessionId,
    signingGrantId: input.signingGrantId,
    keyHandle: input.keyHandle,
    runtimePolicyScope: {
      ...ROUTER_AB_ECDSA_HSS_CLAIMS.runtimePolicyScope,
      signingRootVersion: input.signingRootVersion,
    },
    routerAbEcdsaHssNormalSigning: {
      kind: ROUTER_AB_ECDSA_HSS_NORMAL_SIGNING_STATE_KIND_V1,
      scope,
    },
  };
  return {
    label: input.label,
    token: input.token,
    path: ROUTER_AB_ECDSA_HSS_NORMAL_SIGNING_PATH_V1,
    body,
    claims,
    privatePath: '/router-ab/v1/signing-worker/ecdsa-hss/sign',
    budget: {
      curve: 'ecdsa-hss',
      phase: 'finalize',
      thresholdSessionId: input.thresholdSessionId,
      signingGrantId: input.signingGrantId,
      operationId,
    },
  };
}

async function routerAbBudgetFinalizationCases(): Promise<
  Array<{
    label: string;
    token: string;
    path: string;
    body: Record<string, unknown>;
    claims: Record<string, unknown>;
    privatePath: string;
    budget: RouterAbBudgetConsumeCall;
  }>
> {
  const ed25519RequestId = 'router-ab-ed25519-budget-finalize';
  const ed25519Case = {
    label: 'Ed25519 final signing',
    token: 'router-ab-budget-ed25519',
    path: ROUTER_AB_ED25519_NORMAL_SIGNING_PATH_V2,
    body: ed25519NormalSigningBody(ed25519RequestId),
    claims: ROUTER_AB_ED25519_CLAIMS,
    privatePath: '/router-ab/v1/signing-worker/sign',
    budget: {
      curve: 'ed25519' as const,
      phase: 'finalize' as const,
      thresholdSessionId: ROUTER_AB_ED25519_CLAIMS.thresholdSessionId,
      signingGrantId: ROUTER_AB_ED25519_CLAIMS.signingGrantId,
      operationId: `${ed25519RequestId}-operation`,
    },
  };
  const ecdsaEvmCase = await ecdsaFinalizeBudgetCase({
    label: 'ECDSA EVM final signing',
    token: 'router-ab-budget-ecdsa-evm',
    thresholdSessionId: 'threshold-ecdsa-session-evm-budget',
    signingGrantId: 'signing-grant-ecdsa-evm-budget',
    requestId: 'router-ab-ecdsa-evm-budget-finalize',
    keyHandle: 'ehss-key-budget-evm',
    signingRootId: 'evm-signing-root',
    signingRootVersion: 'evm-root-v1',
  });
  const tempoCase = await ecdsaFinalizeBudgetCase({
    label: 'ECDSA Tempo final signing',
    token: 'router-ab-budget-ecdsa-tempo',
    thresholdSessionId: 'threshold-ecdsa-session-tempo-budget',
    signingGrantId: 'signing-grant-ecdsa-tempo-budget',
    requestId: 'router-ab-ecdsa-tempo-budget-finalize',
    keyHandle: 'ehss-key-budget-tempo',
    signingRootId: 'tempo-signing-root',
    signingRootVersion: 'tempo-root-v1',
  });
  return [ed25519Case, ecdsaEvmCase, tempoCase];
}

test.describe('Router A/B normal signing auth boundary', () => {
  test('rejects missing Wallet Session bearer auth before private SigningWorker forwarding', async () => {
    await withAuthBoundaryRouter(
      async () => ({ ok: false as const }),
      async (srv) => {
        for (const route of NORMAL_SIGNING_ROUTES) {
          const res = await fetchJson(`${srv.baseUrl}${route.path}`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: '{}',
          });

          expect(res.status, route.label).toBe(401);
          expect(res.json, route.label).toMatchObject({
            ok: false,
            code: 'unauthorized',
            message: route.message,
          });
        }

        expect(srv.getThresholdServiceReadCount()).toBe(0);
      },
    );
  });

  test('rejects cookie sessionKind before Wallet Session parsing', async () => {
    for (const route of NORMAL_SIGNING_ROUTES) {
      await withAuthBoundaryRouter(
        async () => {
          throw new Error('cookie-mode Router A/B normal signing must not parse auth');
        },
        async (srv) => {
          const res = await fetchJson(`${srv.baseUrl}${route.path}`, {
            method: 'POST',
            headers: {
              Authorization: 'Bearer router-ab-wallet-session',
              'Content-Type': 'application/json',
            },
            body: JSON.stringify({ sessionKind: 'cookie' }),
          });

          expect(res.status, route.label).toBe(400);
          expect(res.json, route.label).toMatchObject({
            ok: false,
            code: 'invalid_body',
            message: route.label.startsWith('Ed25519')
              ? 'Router A/B Ed25519 normal-signing requires sessionKind=jwt'
              : 'Router A/B ECDSA-HSS normal-signing requires sessionKind=jwt',
          });
          expect(srv.getThresholdServiceReadCount(), route.label).toBe(0);
        },
      );
    }
  });

  test('rejects legacy threshold-session bearer claims before private SigningWorker forwarding', async () => {
    for (const route of NORMAL_SIGNING_ROUTES) {
      await withAuthBoundaryRouter(
        async () => ({ ok: true as const, claims: legacyThresholdClaims(route.legacyKind) }),
        async (srv) => {
          const res = await fetchJson(`${srv.baseUrl}${route.path}`, {
            method: 'POST',
            headers: {
              Authorization: 'Bearer legacy-threshold-session',
              'Content-Type': 'application/json',
            },
            body: '{}',
          });

          expect(res.status, route.label).toBe(401);
          expect(res.json, route.label).toMatchObject({
            ok: false,
            code: 'unauthorized',
            message: route.legacyMessage,
          });
          expect(srv.getThresholdServiceReadCount(), route.label).toBe(0);
        },
      );
    }
  });

  test('rejects Ed25519 scope drift before private SigningWorker forwarding', async () => {
    for (const route of ED25519_NORMAL_SIGNING_ROUTES) {
      await withAuthBoundaryRouter(
        async () => ({ ok: true as const, claims: ROUTER_AB_ED25519_CLAIMS }),
        async (srv) => {
          const res = await fetchJson(`${srv.baseUrl}${route.path}`, {
            method: 'POST',
            headers: {
              Authorization: 'Bearer router-ab-ed25519-wallet-session',
              'Content-Type': 'application/json',
            },
            body: JSON.stringify({
              scope: {
                request_id: `router-ab-ed25519-scope-drift-${route.path}`,
                account_id: 'mallory.testnet',
                session_id: ROUTER_AB_ED25519_CLAIMS.thresholdSessionId,
                signing_worker_id: ROUTER_AB_ED25519_CLAIMS.routerAbNormalSigning.signingWorkerId,
              },
              expires_at_ms: ROUTER_AB_ED25519_CLAIMS.thresholdExpiresAtMs,
            }),
          });

          expect(res.status, route.label).toBe(403);
          expect(res.json, route.label).toMatchObject({
            ok: false,
            code: 'forbidden',
            message: 'Router A/B Ed25519 normal-signing scope does not match Wallet Session claims',
          });
          expect(srv.getThresholdServiceReadCount(), route.label).toBe(0);
        },
      );
    }
  });

  test('rejects Ed25519 cross-session scope drift before private SigningWorker forwarding', async () => {
    for (const route of ED25519_NORMAL_SIGNING_ROUTES) {
      await withAuthBoundaryRouter(
        async () => ({ ok: true as const, claims: ROUTER_AB_ED25519_CLAIMS }),
        async (srv) => {
          const res = await fetchJson(`${srv.baseUrl}${route.path}`, {
            method: 'POST',
            headers: {
              Authorization: 'Bearer router-ab-ed25519-wallet-session',
              'Content-Type': 'application/json',
            },
            body: JSON.stringify({
              scope: {
                request_id: `router-ab-ed25519-cross-session-${route.path}`,
                account_id: ROUTER_AB_ED25519_CLAIMS.walletId,
                session_id: 'other-threshold-session',
                signing_worker_id: ROUTER_AB_ED25519_CLAIMS.routerAbNormalSigning.signingWorkerId,
              },
              expires_at_ms: ROUTER_AB_ED25519_CLAIMS.thresholdExpiresAtMs,
            }),
          });

          expect(res.status, route.label).toBe(403);
          expect(res.json, route.label).toMatchObject({
            ok: false,
            code: 'forbidden',
            message: 'Router A/B Ed25519 normal-signing scope does not match Wallet Session claims',
          });
          expect(srv.getThresholdServiceReadCount(), route.label).toBe(0);
        },
      );
    }
  });

  test('rejects ECDSA-HSS cross-session canonical scope drift before private SigningWorker forwarding', async () => {
    const driftedScope = {
      ...ECDSA_HSS_SCOPE,
      activation_epoch: 'different-activation-epoch',
    };
    for (const route of ECDSA_HSS_NORMAL_SIGNING_ROUTES) {
      const body =
        route.path === ROUTER_AB_ECDSA_HSS_NORMAL_SIGNING_PREPARE_PATH_V1
          ? buildRouterAbEcdsaHssEvmDigestSigningRequestV1({
              scope: driftedScope,
              requestId: 'router-ab-ecdsa-hss-scope-drift-prepare',
              clientPresignatureId: 'client-presignature-scope-drift',
              expiresAtMs: ROUTER_AB_ECDSA_HSS_CLAIMS.thresholdExpiresAtMs,
              signingDigest32: Uint8Array.from({ length: 32 }, (_, index) => index + 1),
            })
          : buildRouterAbEcdsaHssEvmDigestSigningFinalizeRequestV1({
              scope: driftedScope,
              requestId: 'router-ab-ecdsa-hss-scope-drift-finalize',
              budgetReservationId: 'router-ab-ecdsa-hss-scope-drift-budget-reservation',
              budgetOperationId: 'router-ab-ecdsa-hss-scope-drift-budget-operation',
              expiresAtMs: ROUTER_AB_ECDSA_HSS_CLAIMS.thresholdExpiresAtMs,
              signingDigest32: Uint8Array.from({ length: 32 }, (_, index) => index + 1),
              serverPresignatureId: 'server-presignature-scope-drift',
              clientSignatureShare32: Uint8Array.from({ length: 32 }, (_, index) => 255 - index),
            });

      await withAuthBoundaryRouter(
        async () => ({ ok: true as const, claims: ROUTER_AB_ECDSA_HSS_CLAIMS }),
        async (srv) => {
          const res = await fetchJson(`${srv.baseUrl}${route.path}`, {
            method: 'POST',
            headers: {
              Authorization: 'Bearer router-ab-ecdsa-hss-wallet-session',
              'Content-Type': 'application/json',
            },
            body: JSON.stringify(body),
          });

          expect(res.status, route.label).toBe(403);
          expect(res.json, route.label).toMatchObject({
            ok: false,
            code: 'forbidden',
            message:
              'Router A/B ECDSA-HSS normal-signing scope does not match Wallet Session claims',
          });
          expect(srv.getThresholdServiceReadCount(), route.label).toBe(0);
        },
      );
    }
  });

  test('rejects expired normal-signing requests before private SigningWorker forwarding', async () => {
    for (const route of ED25519_NORMAL_SIGNING_ROUTES) {
      await withAuthBoundaryRouter(
        async () => ({ ok: true as const, claims: ROUTER_AB_ED25519_CLAIMS }),
        async (srv) => {
          const res = await fetchJson(`${srv.baseUrl}${route.path}`, {
            method: 'POST',
            headers: {
              Authorization: 'Bearer router-ab-ed25519-wallet-session',
              'Content-Type': 'application/json',
            },
            body: JSON.stringify({
              scope: {
                request_id: `router-ab-ed25519-expired-${route.path}`,
                account_id: ROUTER_AB_ED25519_CLAIMS.walletId,
                session_id: ROUTER_AB_ED25519_CLAIMS.thresholdSessionId,
                signing_worker_id: ROUTER_AB_ED25519_CLAIMS.routerAbNormalSigning.signingWorkerId,
              },
              expires_at_ms: 1,
            }),
          });

          expect(res.status, route.label).toBe(408);
          expect(res.json, route.label).toMatchObject({
            ok: false,
            code: 'expired_request',
            message: 'Router A/B Ed25519 normal-signing request is expired',
          });
          expect(srv.getThresholdServiceReadCount(), route.label).toBe(0);
        },
      );
    }

    for (const route of ECDSA_HSS_NORMAL_SIGNING_ROUTES) {
      const body =
        route.path === ROUTER_AB_ECDSA_HSS_NORMAL_SIGNING_PREPARE_PATH_V1
          ? buildRouterAbEcdsaHssEvmDigestSigningRequestV1({
              scope: ECDSA_HSS_SCOPE,
              requestId: 'router-ab-ecdsa-hss-expired-prepare',
              clientPresignatureId: 'client-presignature-expired',
              expiresAtMs: 1,
              signingDigest32: Uint8Array.from({ length: 32 }, (_, index) => index + 1),
            })
          : buildRouterAbEcdsaHssEvmDigestSigningFinalizeRequestV1({
              scope: ECDSA_HSS_SCOPE,
              requestId: 'router-ab-ecdsa-hss-expired-finalize',
              budgetReservationId: 'router-ab-ecdsa-hss-expired-budget-reservation',
              budgetOperationId: 'router-ab-ecdsa-hss-expired-budget-operation',
              expiresAtMs: 1,
              signingDigest32: Uint8Array.from({ length: 32 }, (_, index) => index + 1),
              serverPresignatureId: 'server-presignature-expired',
              clientSignatureShare32: Uint8Array.from({ length: 32 }, (_, index) => 255 - index),
            });

      await withAuthBoundaryRouter(
        async () => ({ ok: true as const, claims: ROUTER_AB_ECDSA_HSS_CLAIMS }),
        async (srv) => {
          const res = await fetchJson(`${srv.baseUrl}${route.path}`, {
            method: 'POST',
            headers: {
              Authorization: 'Bearer router-ab-ecdsa-hss-wallet-session',
              'Content-Type': 'application/json',
            },
            body: JSON.stringify(body),
          });

          expect(res.status, route.label).toBe(408);
          expect(res.json, route.label).toMatchObject({
            ok: false,
            code: 'expired_request',
            message: 'Router A/B ECDSA-HSS normal-signing request is expired',
          });
          expect(srv.getThresholdServiceReadCount(), route.label).toBe(0);
        },
      );
    }
  });

  test('forwards successful Ed25519 normal-signing routes to exact private worker paths', async () => {
    const cases = [
      {
        path: ROUTER_AB_ED25519_NORMAL_SIGNING_PREPARE_PATH_V2,
        body: ed25519NormalSigningBody('router-ab-ed25519-private-prepare'),
        privatePath: '/router-ab/v1/signing-worker/sign/prepare',
        budgetStatus: {
          committed_remaining_uses: 3,
          reserved_uses: 1,
          available_uses: 2,
        },
      },
      {
        path: ROUTER_AB_ED25519_NORMAL_SIGNING_PRESIGN_POOL_PREPARE_PATH_V2,
        body: ed25519NormalSigningBody('router-ab-ed25519-private-presign-pool-prepare', {
          generation: 1,
          client_offers: [],
        }),
        privatePath: '/router-ab/v1/signing-worker/sign/presign-pool/prepare',
      },
      {
        path: ROUTER_AB_ED25519_NORMAL_SIGNING_PATH_V2,
        body: ed25519NormalSigningBody('router-ab-ed25519-private-finalize'),
        privatePath: '/router-ab/v1/signing-worker/sign',
      },
      {
        path: ROUTER_AB_ED25519_NORMAL_SIGNING_PATH_V2,
        body: ed25519NormalSigningBody('router-ab-ed25519-private-pool-finalize', {
          pool_binding: {
            server_round1_handle: 'router-ab-ed25519-private-pool-finalize-server-round-1',
            pool_entry_binding_digest: {
              bytes: Array.from({ length: 32 }, (_, index) => index + 7),
            },
          },
        }),
        privatePath: '/router-ab/v1/signing-worker/sign/presign-pool',
      },
    ];

    await withReplayProtectedNormalSigningRouter(
      async () => ({ ok: true as const, claims: ROUTER_AB_ED25519_CLAIMS }),
      async (srv) => {
        for (const route of cases) {
          const res = await fetchJson(`${srv.baseUrl}${route.path}`, {
            method: 'POST',
            headers: {
              Authorization: 'Bearer router-ab-ed25519-wallet-session',
              'Content-Type': 'application/json',
            },
            body: JSON.stringify(route.body),
          });
          expect(res.status, route.privatePath).toBe(200);
          if ('budgetStatus' in route) {
            expect(res.json, route.privatePath).toMatchObject({
              budget_reservation_id:
                'router-ab-ed25519-private-prepare-operation-budget-reservation',
              budget_operation_id: 'router-ab-ed25519-private-prepare-operation',
              budget_status: route.budgetStatus,
            });
          }
        }

        expect(srv.forwardedUrls()).toEqual(
          cases.map((route) => `https://signing-worker.internal${route.privatePath}`),
        );
      },
    );
  });

  test('consumes server Wallet Session budget before Router A/B final signing', async () => {
    const cases = await routerAbBudgetFinalizationCases();
    const claimsByToken = new Map(cases.map((testCase) => [testCase.token, testCase.claims]));
    const budgetConsumes: RouterAbBudgetConsumeCall[] = [];

    await withBudgetedNormalSigningRouter(
      parseSessionFromClaimsByToken(claimsByToken),
      async (input) => {
        budgetConsumes.push({ ...input });
        return { ok: true as const, remainingUses: 2 };
      },
      async (srv) => {
        for (const testCase of cases) {
          const res = await fetchJson(`${srv.baseUrl}${testCase.path}`, {
            method: 'POST',
            headers: {
              Authorization: `Bearer ${testCase.token}`,
              'Content-Type': 'application/json',
            },
            body: JSON.stringify(testCase.body),
          });

          expect(res.status, testCase.label).toBe(200);
        }

        expect(budgetConsumes).toEqual(cases.map((testCase) => testCase.budget));
        expect(srv.forwardedUrls()).toEqual(
          cases.map((testCase) => `https://signing-worker.internal${testCase.privatePath}`),
        );
      },
    );
  });

  test('rejects exhausted server Wallet Session budget before Router A/B final signing', async () => {
    const cases = await routerAbBudgetFinalizationCases();
    const claimsByToken = new Map(cases.map((testCase) => [testCase.token, testCase.claims]));
    const budgetConsumes: RouterAbBudgetConsumeCall[] = [];

    await withBudgetedNormalSigningRouter(
      parseSessionFromClaimsByToken(claimsByToken),
      async (input) => {
        budgetConsumes.push({ ...input });
        return {
          ok: false as const,
          status: 409,
          code: 'exhausted',
          message: 'signing grant exhausted',
        };
      },
      async (srv) => {
        for (const testCase of cases) {
          const res = await fetchJson(`${srv.baseUrl}${testCase.path}`, {
            method: 'POST',
            headers: {
              Authorization: `Bearer ${testCase.token}`,
              'Content-Type': 'application/json',
            },
            body: JSON.stringify(testCase.body),
          });

          expect(res.status, testCase.label).toBe(409);
          expect(res.json, testCase.label).toMatchObject({
            ok: false,
            code: 'exhausted',
            message: 'signing grant exhausted',
          });
        }

        expect(budgetConsumes).toEqual(cases.map((testCase) => testCase.budget));
        expect(srv.forwardedCalls()).toBe(0);
      },
    );
  });

  test('dedupes Router A/B final signing budget retries by operation identity', async () => {
    const cases = await routerAbBudgetFinalizationCases();
    const claimsByToken = new Map(cases.map((testCase) => [testCase.token, testCase.claims]));
    const remainingBySession = new Map(
      cases.map((testCase) => [testCase.budget.thresholdSessionId, 1]),
    );
    const consumedKeys = new Set<string>();

    await withBudgetedNormalSigningRouter(
      parseSessionFromClaimsByToken(claimsByToken),
      async (input) => {
        const key = [
          input.curve,
          input.phase,
          input.thresholdSessionId,
          input.signingGrantId,
          input.operationId,
        ].join(':');
        if (!consumedKeys.has(key)) {
          const remaining = remainingBySession.get(input.thresholdSessionId) ?? 0;
          if (remaining <= 0) {
            return {
              ok: false as const,
              status: 409,
              code: 'exhausted',
              message: 'signing grant exhausted',
            };
          }
          remainingBySession.set(input.thresholdSessionId, remaining - 1);
          consumedKeys.add(key);
        }
        return {
          ok: true as const,
          remainingUses: remainingBySession.get(input.thresholdSessionId) ?? 0,
        };
      },
      async (srv) => {
        for (const testCase of cases) {
          for (const attempt of [1, 2]) {
            const res = await fetchJson(`${srv.baseUrl}${testCase.path}`, {
              method: 'POST',
              headers: {
                Authorization: `Bearer ${testCase.token}`,
                'Content-Type': 'application/json',
              },
              body: JSON.stringify(testCase.body),
            });

            expect(res.status, `${testCase.label} attempt ${attempt}`).toBe(200);
          }
        }

        expect(consumedKeys.size).toBe(cases.length);
        expect(srv.forwardedCalls()).toBe(cases.length * 2);
      },
    );
  });

  test('rejects replayed prepare request ids before a second SigningWorker forward', async () => {
    const ed25519Body = ed25519NormalSigningBody('router-ab-ed25519-replay-shared-id');
    const ed25519PresignPoolBody = ed25519NormalSigningBody('router-ab-ed25519-replay-shared-id', {
      generation: 1,
      client_offers: [],
    });
    await withReplayProtectedNormalSigningRouter(
      async () => ({ ok: true as const, claims: ROUTER_AB_ED25519_CLAIMS }),
      async (srv) => {
        const first = await fetchJson(
          `${srv.baseUrl}${ROUTER_AB_ED25519_NORMAL_SIGNING_PREPARE_PATH_V2}`,
          {
            method: 'POST',
            headers: {
              Authorization: 'Bearer router-ab-ed25519-wallet-session',
              'Content-Type': 'application/json',
            },
            body: JSON.stringify(ed25519Body),
          },
        );
        const replay = await fetchJson(
          `${srv.baseUrl}${ROUTER_AB_ED25519_NORMAL_SIGNING_PREPARE_PATH_V2}`,
          {
            method: 'POST',
            headers: {
              Authorization: 'Bearer router-ab-ed25519-wallet-session',
              'Content-Type': 'application/json',
            },
            body: JSON.stringify(ed25519Body),
          },
        );

        expect(first.status).toBe(200);
        expect(first.json).toMatchObject({
          budget_reservation_id: 'router-ab-ed25519-replay-shared-id-operation-budget-reservation',
          budget_operation_id: 'router-ab-ed25519-replay-shared-id-operation',
          budget_status: {
            committed_remaining_uses: 3,
            reserved_uses: 1,
            available_uses: 2,
          },
        });
        expect(replay.status).toBe(400);
        expect(replay.json).toMatchObject({
          ok: false,
          code: 'one_use_replay_rejected',
          message: 'Router A/B normal-signing prepare request id already used',
        });

        const presignPoolFirst = await fetchJson(
          `${srv.baseUrl}${ROUTER_AB_ED25519_NORMAL_SIGNING_PRESIGN_POOL_PREPARE_PATH_V2}`,
          {
            method: 'POST',
            headers: {
              Authorization: 'Bearer router-ab-ed25519-wallet-session',
              'Content-Type': 'application/json',
            },
            body: JSON.stringify(ed25519PresignPoolBody),
          },
        );
        const presignPoolReplay = await fetchJson(
          `${srv.baseUrl}${ROUTER_AB_ED25519_NORMAL_SIGNING_PRESIGN_POOL_PREPARE_PATH_V2}`,
          {
            method: 'POST',
            headers: {
              Authorization: 'Bearer router-ab-ed25519-wallet-session',
              'Content-Type': 'application/json',
            },
            body: JSON.stringify(ed25519PresignPoolBody),
          },
        );

        expect(presignPoolFirst.status).toBe(200);
        expect(presignPoolReplay.status).toBe(400);
        expect(presignPoolReplay.json).toMatchObject({
          ok: false,
          code: 'one_use_replay_rejected',
          message: 'Router A/B normal-signing prepare request id already used',
        });
        expect(srv.forwardedCalls()).toBe(2);
      },
    );

    const ecdsaReplayScope = {
      ...ECDSA_HSS_SCOPE,
      public_identity: {
        ...ECDSA_HSS_SCOPE.public_identity,
        context_binding_b64u: await routerAbEcdsaHssContextBindingB64uV1(ECDSA_HSS_SCOPE.context),
      },
    };
    const ecdsaReplayClaims = {
      ...ROUTER_AB_ECDSA_HSS_CLAIMS,
      routerAbEcdsaHssNormalSigning: {
        ...ROUTER_AB_ECDSA_HSS_CLAIMS.routerAbEcdsaHssNormalSigning,
        scope: ecdsaReplayScope,
      },
    };
    const ecdsaBody = buildRouterAbEcdsaHssEvmDigestSigningRequestV1({
      scope: ecdsaReplayScope,
      requestId: 'router-ab-ecdsa-hss-replay-prepare',
      clientPresignatureId: 'client-presignature-replay',
      expiresAtMs: ROUTER_AB_ECDSA_HSS_CLAIMS.thresholdExpiresAtMs,
      signingDigest32: Uint8Array.from({ length: 32 }, (_, index) => index + 1),
    });
    const ecdsaBudgetOperationId = await deriveRouterAbEcdsaHssBudgetOperationId({
      body: ecdsaBody,
      signingWorkerId: ecdsaReplayScope.signing_worker.server_id,
      thresholdSessionId: ROUTER_AB_ECDSA_HSS_CLAIMS.thresholdSessionId,
    });
    await withReplayProtectedNormalSigningRouter(
      async () => ({ ok: true as const, claims: ecdsaReplayClaims }),
      async (srv) => {
        const first = await fetchJson(
          `${srv.baseUrl}${ROUTER_AB_ECDSA_HSS_NORMAL_SIGNING_PREPARE_PATH_V1}`,
          {
            method: 'POST',
            headers: {
              Authorization: 'Bearer router-ab-ecdsa-hss-wallet-session',
              'Content-Type': 'application/json',
            },
            body: JSON.stringify(ecdsaBody),
          },
        );
        const replay = await fetchJson(
          `${srv.baseUrl}${ROUTER_AB_ECDSA_HSS_NORMAL_SIGNING_PREPARE_PATH_V1}`,
          {
            method: 'POST',
            headers: {
              Authorization: 'Bearer router-ab-ecdsa-hss-wallet-session',
              'Content-Type': 'application/json',
            },
            body: JSON.stringify(ecdsaBody),
          },
        );

        expect(first.status).toBe(200);
        expect(first.json).toMatchObject({
          budget_reservation_id: `${ecdsaBudgetOperationId}-budget-reservation`,
          budget_operation_id: ecdsaBudgetOperationId,
          budget_status: {
            committed_remaining_uses: 3,
            reserved_uses: 1,
            available_uses: 2,
          },
        });
        expect(first.json?.budget_operation_id).not.toBe(ecdsaBody.request_id);
        expect(replay.status).toBe(400);
        expect(replay.json).toMatchObject({
          ok: false,
          code: 'one_use_replay_rejected',
          message: 'Router A/B normal-signing prepare request id already used',
        });
        expect(srv.forwardedCalls()).toBe(1);
      },
    );
  });

  test('rejects quota and abuse admission before private SigningWorker forwarding', async () => {
    const ecdsaScope = {
      ...ECDSA_HSS_SCOPE,
      public_identity: {
        ...ECDSA_HSS_SCOPE.public_identity,
        context_binding_b64u: await routerAbEcdsaHssContextBindingB64uV1(ECDSA_HSS_SCOPE.context),
      },
    };
    const ecdsaClaims = {
      ...ROUTER_AB_ECDSA_HSS_CLAIMS,
      routerAbEcdsaHssNormalSigning: {
        ...ROUTER_AB_ECDSA_HSS_CLAIMS.routerAbEcdsaHssNormalSigning,
        scope: ecdsaScope,
      },
    };
    const testCases = [
      {
        label: 'Ed25519 prepare quota',
        path: ROUTER_AB_ED25519_NORMAL_SIGNING_PREPARE_PATH_V2,
        claims: ROUTER_AB_ED25519_CLAIMS,
        body: {
          scope: {
            request_id: 'router-ab-ed25519-quota-prepare',
            account_id: ROUTER_AB_ED25519_CLAIMS.walletId,
            session_id: ROUTER_AB_ED25519_CLAIMS.thresholdSessionId,
            signing_worker_id: ROUTER_AB_ED25519_CLAIMS.routerAbNormalSigning.signingWorkerId,
          },
          expires_at_ms: ROUTER_AB_ED25519_CLAIMS.thresholdExpiresAtMs,
        },
        expectedAdmission: {
          curve: 'ed25519',
          phase: 'prepare',
          requestId: 'router-ab-ed25519-quota-prepare',
          signingWorkerId: ROUTER_AB_ED25519_CLAIMS.routerAbNormalSigning.signingWorkerId,
          runtimePolicyScope: ROUTER_AB_ED25519_CLAIMS.runtimePolicyScope,
        },
        failure: {
          ok: false as const,
          status: 429 as const,
          code: 'quota_saturated' as const,
          message: 'Router A/B normal-signing quota is saturated',
        },
      },
      {
        label: 'Ed25519 finalize abuse',
        path: ROUTER_AB_ED25519_NORMAL_SIGNING_PATH_V2,
        claims: ROUTER_AB_ED25519_CLAIMS,
        body: {
          scope: {
            request_id: 'router-ab-ed25519-abuse-finalize',
            account_id: ROUTER_AB_ED25519_CLAIMS.walletId,
            session_id: ROUTER_AB_ED25519_CLAIMS.thresholdSessionId,
            signing_worker_id: ROUTER_AB_ED25519_CLAIMS.routerAbNormalSigning.signingWorkerId,
          },
          expires_at_ms: ROUTER_AB_ED25519_CLAIMS.thresholdExpiresAtMs,
        },
        expectedAdmission: {
          curve: 'ed25519',
          phase: 'finalize',
          requestId: 'router-ab-ed25519-abuse-finalize',
          signingWorkerId: ROUTER_AB_ED25519_CLAIMS.routerAbNormalSigning.signingWorkerId,
          runtimePolicyScope: ROUTER_AB_ED25519_CLAIMS.runtimePolicyScope,
        },
        failure: {
          ok: false as const,
          status: 403 as const,
          code: 'abuse_rejected' as const,
          message: 'Router A/B normal-signing abuse policy rejected the request',
        },
      },
      {
        label: 'ECDSA-HSS prepare quota',
        path: ROUTER_AB_ECDSA_HSS_NORMAL_SIGNING_PREPARE_PATH_V1,
        claims: ecdsaClaims,
        body: buildRouterAbEcdsaHssEvmDigestSigningRequestV1({
          scope: ecdsaScope,
          requestId: 'router-ab-ecdsa-hss-quota-prepare',
          clientPresignatureId: 'client-presignature-quota',
          expiresAtMs: ROUTER_AB_ECDSA_HSS_CLAIMS.thresholdExpiresAtMs,
          signingDigest32: Uint8Array.from({ length: 32 }, (_, index) => index + 1),
        }),
        expectedAdmission: {
          curve: 'ecdsa-hss',
          phase: 'prepare',
          requestId: 'router-ab-ecdsa-hss-quota-prepare',
          signingWorkerId: ECDSA_HSS_SCOPE.signing_worker.server_id,
          keyHandle: ROUTER_AB_ECDSA_HSS_CLAIMS.keyHandle,
          runtimePolicyScope: ROUTER_AB_ECDSA_HSS_CLAIMS.runtimePolicyScope,
        },
        failure: {
          ok: false as const,
          status: 429 as const,
          code: 'quota_saturated' as const,
          message: 'Router A/B normal-signing quota is saturated',
        },
      },
      {
        label: 'ECDSA-HSS finalize abuse',
        path: ROUTER_AB_ECDSA_HSS_NORMAL_SIGNING_PATH_V1,
        claims: ecdsaClaims,
        body: buildRouterAbEcdsaHssEvmDigestSigningFinalizeRequestV1({
          scope: ecdsaScope,
          requestId: 'router-ab-ecdsa-hss-abuse-finalize',
          budgetReservationId: 'router-ab-ecdsa-hss-abuse-budget-reservation',
          budgetOperationId: 'router-ab-ecdsa-hss-abuse-budget-operation',
          expiresAtMs: ROUTER_AB_ECDSA_HSS_CLAIMS.thresholdExpiresAtMs,
          signingDigest32: Uint8Array.from({ length: 32 }, (_, index) => index + 1),
          serverPresignatureId: 'server-presignature-abuse',
          clientSignatureShare32: Uint8Array.from({ length: 32 }, (_, index) => 255 - index),
        }),
        expectedAdmission: {
          curve: 'ecdsa-hss',
          phase: 'finalize',
          requestId: 'router-ab-ecdsa-hss-abuse-finalize',
          signingWorkerId: ECDSA_HSS_SCOPE.signing_worker.server_id,
          keyHandle: ROUTER_AB_ECDSA_HSS_CLAIMS.keyHandle,
          runtimePolicyScope: ROUTER_AB_ECDSA_HSS_CLAIMS.runtimePolicyScope,
        },
        failure: {
          ok: false as const,
          status: 403 as const,
          code: 'abuse_rejected' as const,
          message: 'Router A/B normal-signing abuse policy rejected the request',
        },
      },
    ] as const;

    for (const testCase of testCases) {
      const admissionInputs: RouterAbNormalSigningAdmissionInput[] = [];
      await withAdmissionGuardedNormalSigningRouter(
        async () => ({ ok: true as const, claims: testCase.claims }),
        {
          evaluate: async (input) => {
            admissionInputs.push(input);
            return testCase.failure;
          },
        },
        async (srv) => {
          const res = await fetchJson(`${srv.baseUrl}${testCase.path}`, {
            method: 'POST',
            headers: {
              Authorization: 'Bearer router-ab-wallet-session',
              'Content-Type': 'application/json',
            },
            body: JSON.stringify(testCase.body),
          });

          expect(res.status, testCase.label).toBe(testCase.failure.status);
          expect(res.json, testCase.label).toMatchObject({
            ok: false,
            code: testCase.failure.code,
            message: testCase.failure.message,
          });
          expect(admissionInputs, testCase.label).toHaveLength(1);
          expect(admissionInputs[0], testCase.label).toMatchObject(testCase.expectedAdmission);
          expect(srv.privateSigningWorkerReads(), testCase.label).toBe(0);
          expect(srv.budgetConsumes(), testCase.label).toBe(0);
          expect(srv.forwardedCalls(), testCase.label).toBe(0);
        },
      );
    }
  });
});
