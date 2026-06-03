import { expect, test } from '@playwright/test';
import { createCloudflareRouter } from '@server/router/cloudflare-adaptor';
import { createRelayRouter } from '@server/router/express-adaptor';
import { signerBoundWalletSigningBudgetSessionId } from '@server/core/ThresholdService/walletSigningBudget';
import { THRESHOLD_ED25519_FROST_2P_V1_SCHEME_ID } from '@server/core/ThresholdService/schemes/schemeIds';
import type { ThresholdEd25519PresignRecord } from '@server/core/ThresholdService/stores/SessionStore';
import type { ThresholdEd25519PresignRefillRequest } from '@server/core/types';
import type { ThresholdEd25519SessionClaims } from '@server/core/ThresholdService/validation';
import {
  createThresholdSigningServiceForUnitTests,
  deriveThresholdEd25519VerifyingShareForUnitTests,
} from '../helpers/thresholdEd25519TestUtils';
import {
  callCf,
  fetchJson,
  makeFakeAuthService,
  makeSessionAdapter,
  startExpressRouter,
} from '../relayer/helpers';

const SESSION_ID = 'threshold-session-refill';
const WALLET_SIGNING_SESSION_ID = 'wallet-signing-session-refill';
const WALLET_ID = 'alice.testnet';
const RP_ID = 'wallet.example.test';
const RELAYER_KEY_ID = 'relayer-ed25519-refill';
const SIGNER_PUBLIC_KEY = 'ed25519:refill-signer-public-key';
const RELAYER_SIGNING_SHARE_B64U = 'BwAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA';
const CLIENT_VERIFYING_SHARE_B64U = deriveThresholdEd25519VerifyingShareForUnitTests({
  signingShareB64u: 'BQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',
});
const WALLET_BUDGET_SESSION_ID = signerBoundWalletSigningBudgetSessionId({
  walletSigningSessionId: WALLET_SIGNING_SESSION_ID,
  curve: 'ed25519',
  thresholdSessionId: SESSION_ID,
});

const runtimePolicyScope = {
  orgId: 'org-refill',
  projectId: 'project-refill',
  envId: 'test',
  signingRootVersion: 'root-v1',
};

function claims(input?: {
  sessionId?: string;
  walletSigningSessionId?: string;
}): ThresholdEd25519SessionClaims {
  return {
    sub: WALLET_ID,
    walletId: WALLET_ID,
    kind: 'threshold_ed25519_session_v1',
    sessionId: input?.sessionId ?? SESSION_ID,
    walletSigningSessionId: input?.walletSigningSessionId ?? WALLET_SIGNING_SESSION_ID,
    relayerKeyId: RELAYER_KEY_ID,
    rpId: RP_ID,
    runtimePolicyScope,
    thresholdExpiresAtMs: Date.now() + 60_000,
    participantIds: [1, 2],
  };
}

function refillRequest(input?: {
  nearAccountId?: string;
  count?: number;
}): ThresholdEd25519PresignRefillRequest {
  const count = input?.count ?? 1;
  return {
    kind: 'threshold_ed25519_presign_refill_v1',
    relayerKeyId: RELAYER_KEY_ID,
    nearAccountId: input?.nearAccountId || WALLET_ID,
    nearNetworkId: 'testnet',
    expectedSignerPublicKey: SIGNER_PUBLIC_KEY,
    participantIds: [1, 2],
    clientPresigns: Array.from({ length: count }, (_, index) => ({
      clientPresignId: `client-presign-${index + 1}`,
      clientVerifyingShareB64u: CLIENT_VERIFYING_SHARE_B64U,
      clientCommitments: {
        hiding: `client-hiding-${index + 1}`,
        binding: `client-binding-${index + 1}`,
      },
    })),
    requestTag: 'background_presign_pool_refill',
  };
}

function storedPresignRecord(index: number): ThresholdEd25519PresignRecord {
  return {
    kind: 'threshold_ed25519_presign_record_v1',
    expiresAtMs: Date.now() + 60_000,
    thresholdSessionId: SESSION_ID,
    walletSigningSessionId: WALLET_SIGNING_SESSION_ID,
    relayerKeyId: RELAYER_KEY_ID,
    nearAccountId: WALLET_ID,
    nearNetworkId: 'testnet',
    signerPublicKey: SIGNER_PUBLIC_KEY,
    rpcPolicyId: 'ed25519-presign-finalize',
    rpId: RP_ID,
    runtimePolicyScope,
    protocolVersion: 'ed25519_frost_2p_presign_v1',
    participantIds: [1, 2],
    groupPublicKey: SIGNER_PUBLIC_KEY,
    clientVerifyingShareB64u: CLIENT_VERIFYING_SHARE_B64U,
    clientCommitments: {
      hiding: `stored-client-hiding-${index}`,
      binding: `stored-client-binding-${index}`,
    },
    relayerCommitments: {
      hiding: `stored-relayer-hiding-${index}`,
      binding: `stored-relayer-binding-${index}`,
    },
    relayerVerifyingShareB64u: 'stored-relayer-verifying-share',
    relayerNoncesB64u: `stored-relayer-nonces-${index}`,
  };
}

async function seedBudget(
  authSessionStore: ReturnType<
    typeof createThresholdSigningServiceForUnitTests
  >['authSessionStore'],
  remainingUses: number,
): Promise<void> {
  await authSessionStore.putSession(
    WALLET_BUDGET_SESSION_ID,
    {
      expiresAtMs: Date.now() + 60_000,
      relayerKeyId: 'wallet-signing-budget',
      userId: WALLET_ID,
      rpId: RP_ID,
      participantIds: [1, 2],
      walletBudgetBinding: { curve: 'ed25519', thresholdSessionId: SESSION_ID },
    },
    { ttlMs: 60_000, remainingUses },
  );
}

function createService(input?: {
  logger?: Parameters<typeof createThresholdSigningServiceForUnitTests>[0]['logger'];
}) {
  return createThresholdSigningServiceForUnitTests({
    ...(input?.logger ? { logger: input.logger } : {}),
    keyRecord: {
      publicKey: SIGNER_PUBLIC_KEY,
      relayerSigningShareB64u: RELAYER_SIGNING_SHARE_B64U,
      keyVersion: 'v1',
      recoveryExportCapable: true,
    },
    accessKeysOnChain: [SIGNER_PUBLIC_KEY],
  });
}

function getEd25519Scheme(svc: ReturnType<typeof createService>['svc']) {
  const scheme = svc.getSchemeModule(THRESHOLD_ED25519_FROST_2P_V1_SCHEME_ID);
  if (!scheme || scheme.schemeId !== THRESHOLD_ED25519_FROST_2P_V1_SCHEME_ID) {
    throw new Error('missing Ed25519 scheme');
  }
  return scheme;
}

test.describe('threshold Ed25519 presign refill', () => {
  test('service stores refill presigns without decrementing wallet budget', async () => {
    const { svc, sessionStore, authSessionStore } = createService();
    await seedBudget(authSessionStore, 1);

    const result = await getEd25519Scheme(svc).presign.refill({
      claims: claims(),
      request: refillRequest({ count: 2 }),
    });

    expect(result).toMatchObject({
      ok: true,
      kind: 'threshold_ed25519_presign_refill_response_v1',
      rejectedClientPresignIds: [],
    });
    expect(result.ok && result.accepted).toHaveLength(2);
    if (!result.ok) throw new Error('expected refill success');
    const first = result.accepted[0];
    await expect(
      sessionStore.takePresignForFinalize(first.presignId, {
        thresholdSessionId: SESSION_ID,
        walletSigningSessionId: WALLET_SIGNING_SESSION_ID,
        relayerKeyId: RELAYER_KEY_ID,
        nearAccountId: WALLET_ID,
        nearNetworkId: 'testnet',
        signerPublicKey: SIGNER_PUBLIC_KEY,
        rpcPolicyId: 'ed25519-presign-finalize',
        rpId: RP_ID,
        runtimePolicyScope,
        participantIds: [1, 2],
        groupPublicKey: SIGNER_PUBLIC_KEY,
      }),
    ).resolves.toMatchObject({ ok: true });
    await expect(
      authSessionStore.getSessionStatus(WALLET_BUDGET_SESSION_ID),
    ).resolves.toMatchObject({
      remainingUses: 1,
    });
  });

  test('wrong account scope rejects before storing presigns', async () => {
    const { svc } = createService();

    await expect(
      getEd25519Scheme(svc).presign.refill({
        claims: claims(),
        request: refillRequest({ nearAccountId: 'mallory.testnet' }),
      }),
    ).resolves.toMatchObject({
      ok: false,
      code: 'wrong_scope',
    });
  });

  test('wrong relayer and participant scope reject before storing presigns', async () => {
    const { svc } = createService();
    const scheme = getEd25519Scheme(svc);

    await expect(
      scheme.presign.refill({
        claims: claims(),
        request: { ...refillRequest(), relayerKeyId: 'other-relayer-key' },
      }),
    ).resolves.toMatchObject({
      ok: false,
      code: 'unauthorized',
    });

    await expect(
      scheme.presign.refill({
        claims: claims(),
        request: { ...refillRequest(), participantIds: [1, 3] },
      }),
    ).resolves.toMatchObject({
      ok: false,
      code: 'wrong_scope',
    });
  });

  test('wallet-session rate limit rejects a second full refill before capacity', async () => {
    const { svc } = createService();
    const scheme = getEd25519Scheme(svc);

    await expect(
      scheme.presign.refill({
        claims: claims(),
        request: refillRequest({ count: 8 }),
      }),
    ).resolves.toMatchObject({
      ok: true,
      accepted: expect.arrayContaining([
        expect.objectContaining({ clientPresignId: 'client-presign-1' }),
      ]),
    });

    await expect(
      scheme.presign.refill({
        claims: claims(),
        request: refillRequest({ count: 1 }),
      }),
    ).resolves.toMatchObject({
      ok: false,
      code: 'rate_limited',
    });
  });

  test('account relayer rate limit spans threshold sessions', async () => {
    const { svc } = createService();
    const scheme = getEd25519Scheme(svc);

    for (let index = 1; index <= 3; index += 1) {
      await expect(
        scheme.presign.refill({
          claims: claims({
            sessionId: `threshold-session-refill-account-${index}`,
            walletSigningSessionId: `wallet-signing-session-refill-account-${index}`,
          }),
          request: refillRequest({ count: 8 }),
        }),
      ).resolves.toMatchObject({
        ok: true,
        accepted: expect.arrayContaining([
          expect.objectContaining({ clientPresignId: 'client-presign-1' }),
        ]),
      });
    }

    await expect(
      scheme.presign.refill({
        claims: claims({
          sessionId: 'threshold-session-refill-account-4',
          walletSigningSessionId: 'wallet-signing-session-refill-account-4',
        }),
        request: refillRequest({ count: 1 }),
      }),
    ).resolves.toMatchObject({
      ok: false,
      code: 'rate_limited',
    });
  });

  test('emits redacted refill metrics for accepted and rate-limited offers', async () => {
    const logs: unknown[][] = [];
    const { svc } = createService({
      logger: {
        info: (...args: unknown[]) => logs.push(args),
      },
    });
    const scheme = getEd25519Scheme(svc);

    await expect(
      scheme.presign.refill({
        claims: claims(),
        request: refillRequest({ count: 2 }),
      }),
    ).resolves.toMatchObject({ ok: true });

    await expect(
      scheme.presign.refill({
        claims: claims(),
        request: refillRequest({ count: 8 }),
      }),
    ).resolves.toMatchObject({ ok: false, code: 'rate_limited' });

    const metricLogs = logs.filter((entry) => entry[0] === '[threshold-ed25519-presign-metrics]');
    expect(metricLogs).toEqual([
      [
        '[threshold-ed25519-presign-metrics]',
        expect.objectContaining({
          metric: 'ed25519_presign_refill_result',
          offeredCount: 2,
          acceptedOfferCount: 2,
          rejectedOfferCount: 0,
          rateLimitRejected: false,
        }),
      ],
      [
        '[threshold-ed25519-presign-metrics]',
        expect.objectContaining({
          metric: 'ed25519_presign_refill_rejected',
          offeredCount: 8,
          acceptedOfferCount: 0,
          rejectedOfferCount: 8,
          rateLimitRejected: true,
          code: 'rate_limited',
        }),
      ],
    ]);
    const serialized = JSON.stringify(metricLogs);
    expect(serialized).not.toContain(RELAYER_SIGNING_SHARE_B64U);
    expect(serialized).not.toContain(CLIENT_VERIFYING_SHARE_B64U);
    expect(serialized).not.toContain('client-hiding-1');
    expect(serialized).not.toContain('client-binding-1');
  });

  test('capacity preflight rejects before creating relayer nonce material', async () => {
    const { svc, sessionStore } = createThresholdSigningServiceForUnitTests({
      keyRecord: {
        publicKey: SIGNER_PUBLIC_KEY,
        relayerSigningShareB64u: 'invalid-relayer-signing-share',
        relayerVerifyingShareB64u: 'invalid-relayer-verifying-share',
        keyVersion: 'v1',
        recoveryExportCapable: true,
      },
      accessKeysOnChain: [SIGNER_PUBLIC_KEY],
    });
    for (let index = 0; index < 8; index += 1) {
      await sessionStore.putPresign(
        `stored-presign-${index + 1}`,
        storedPresignRecord(index + 1),
        60_000,
      );
    }

    await expect(
      getEd25519Scheme(svc).presign.refill({
        claims: claims(),
        request: refillRequest({ count: 1 }),
      }),
    ).resolves.toMatchObject({
      ok: false,
      code: 'capacity_exceeded',
    });
  });

  test('express refill route succeeds through threshold-session auth', async () => {
    const { svc } = createService();
    const session = makeSessionAdapter({
      parse: async () => ({ ok: true as const, claims: claims() }),
    });
    const router = createRelayRouter(makeFakeAuthService(), { threshold: svc, session });
    const server = await startExpressRouter(router);

    try {
      const res = await fetchJson(`${server.baseUrl}/threshold-ed25519/presign/refill`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', Authorization: 'Bearer refill-test' },
        body: JSON.stringify(refillRequest()),
      });

      expect(res.status, res.text).toBe(200);
      expect(res.json).toMatchObject({
        ok: true,
        kind: 'threshold_ed25519_presign_refill_response_v1',
        accepted: [expect.objectContaining({ clientPresignId: 'client-presign-1' })],
        rejectedClientPresignIds: [],
      });
    } finally {
      await server.close();
    }
  });

  test('cloudflare refill route succeeds through threshold-session auth', async () => {
    const { svc } = createService();
    const session = makeSessionAdapter({
      parse: async () => ({ ok: true as const, claims: claims() }),
    });
    const handler = createCloudflareRouter(makeFakeAuthService(), { threshold: svc, session });

    const res = await callCf(handler, {
      method: 'POST',
      path: '/threshold-ed25519/presign/refill',
      headers: { Authorization: 'Bearer refill-test' },
      body: refillRequest(),
    });

    expect(res.status, res.text).toBe(200);
    expect(res.json).toMatchObject({
      ok: true,
      kind: 'threshold_ed25519_presign_refill_response_v1',
      accepted: [expect.objectContaining({ clientPresignId: 'client-presign-1' })],
      rejectedClientPresignIds: [],
    });
  });

  test('cloudflare refill route rate limits by deployment origin across fresh sessions', async () => {
    const { svc } = createService();
    let parseCount = 0;
    const session = makeSessionAdapter({
      parse: async () => {
        parseCount += 1;
        return {
          ok: true as const,
          claims: claims({
            sessionId: `threshold-session-origin-${parseCount}`,
            walletSigningSessionId: `wallet-signing-session-origin-${parseCount}`,
          }),
        };
      },
    });
    const handler = createCloudflareRouter(makeFakeAuthService(), { threshold: svc, session });

    for (let index = 1; index <= 2; index += 1) {
      const res = await callCf(handler, {
        method: 'POST',
        path: '/threshold-ed25519/presign/refill',
        origin: 'https://wallet.example.test',
        headers: { Authorization: 'Bearer refill-test' },
        body: refillRequest({ count: 8 }),
      });

      expect(res.status, res.text).toBe(200);
      expect(res.json).toMatchObject({ ok: true });
    }

    const limited = await callCf(handler, {
      method: 'POST',
      path: '/threshold-ed25519/presign/refill',
      origin: 'https://wallet.example.test',
      headers: { Authorization: 'Bearer refill-test' },
      body: refillRequest({ count: 1 }),
    });

    expect(limited.status, limited.text).toBe(429);
    expect(limited.json).toMatchObject({
      ok: false,
      code: 'rate_limited',
    });
  });

  test('express refill route rejects malformed client commitments at the boundary', async () => {
    const { svc } = createService();
    const session = makeSessionAdapter({
      parse: async () => ({ ok: true as const, claims: claims() }),
    });
    const router = createRelayRouter(makeFakeAuthService(), { threshold: svc, session });
    const server = await startExpressRouter(router);

    try {
      const body = refillRequest();
      const malformed = {
        ...body,
        clientPresigns: [
          {
            clientPresignId: 'client-presign-malformed',
            clientVerifyingShareB64u: CLIENT_VERIFYING_SHARE_B64U,
            clientCommitments: { hiding: 'client-hiding' },
          },
        ],
      };
      const res = await fetchJson(`${server.baseUrl}/threshold-ed25519/presign/refill`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', Authorization: 'Bearer refill-test' },
        body: JSON.stringify(malformed),
      });

      expect(res.status, res.text).toBe(400);
      expect(res.json).toMatchObject({ ok: false, code: 'invalid_body' });
    } finally {
      await server.close();
    }
  });
});
