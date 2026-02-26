import { expect, test } from '@playwright/test';
import { base64UrlEncode } from '@shared/utils/encoders';
import type { WorkerOperationContext } from '@/core/signingEngine/workerManager/executeWorkerOperation';
import {
  clearAllThresholdEcdsaClientPresignatures,
  getThresholdEcdsaClientPresignaturePoolDepth,
  refillThresholdEcdsaClientPresignaturePool,
  scheduleThresholdEcdsaClientPresignaturePoolRefill,
  signThresholdEcdsaDigestWithPool,
} from '@/core/signingEngine/orchestration/walletOrigin/thresholdEcdsaCoordinator';
import { Secp256k1Engine } from '@/core/signingEngine/signers/algorithms/secp256k1';
import {
  clearAllCachedEcdsaAuthSessions,
  makeEcdsaAuthSessionCacheKey,
  putCachedEcdsaAuthSession,
} from '@/core/signingEngine/threshold/session/ecdsaAuthSession';

const RELAYER_URL = 'https://relay.example';
const RELAYER_KEY_ID = 'rk-1';
const USER_ID = 'alice.testnet';
const RP_ID = 'example.localhost';
const PARTICIPANT_IDS = [1, 2];
const SESSION_ID = 'session-1';

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
const PRESIGN_K_SHARE_32 = new Uint8Array(32).fill(17);
const PRESIGN_SIGMA_SHARE_32 = new Uint8Array(32).fill(19);
const DIGEST_32 = new Uint8Array(32).fill(23);
const ENTROPY_32 = new Uint8Array(32).fill(29);
const CLIENT_SIGNATURE_SHARE_32 = new Uint8Array(32).fill(31);
const SIGNATURE_65 = (() => {
  const out = new Uint8Array(65).fill(37);
  out[64] = 1;
  return out;
})();
const PRF_FIRST_B64U = base64UrlEncode(new Uint8Array(32).fill(41));

const CLIENT_VERIFYING_SHARE_B64U = base64UrlEncode(CLIENT_VERIFYING_SHARE_33);
const GROUP_PUBLIC_KEY_B64U = base64UrlEncode(GROUP_PUBLIC_KEY_33);
const PRESIGN_BIG_R_B64U = base64UrlEncode(PRESIGN_BIG_R_33);
const SIGNATURE_65_B64U = base64UrlEncode(SIGNATURE_65);
const ENTROPY_B64U = base64UrlEncode(ENTROPY_32);

type ThresholdFetchCounters = {
  authorize: number;
  presignInit: number;
  presignStep: number;
  signInit: number;
  signFinalize: number;
};

function concatBytes(parts: Uint8Array[]): Uint8Array {
  const total = parts.reduce((sum, entry) => sum + entry.length, 0);
  const out = new Uint8Array(total);
  let offset = 0;
  for (const entry of parts) {
    out.set(entry, offset);
    offset += entry.length;
  }
  return out;
}

function makeWorkerCtx(args: {
  clientSigningShare32: Uint8Array;
  clientVerifyingShare33: Uint8Array;
  presignature97: Uint8Array;
  clientSignatureShare32: Uint8Array;
}): WorkerOperationContext {
  return {
    requestWorkerOperation: async ({ request }) => {
      const type = String((request as { type?: string })?.type || '');
      const payload = (request as { payload?: Record<string, unknown> })?.payload || {};
      if (type === 'deriveThresholdSecp256k1ClientShare') {
        return {
          clientSigningShare32: args.clientSigningShare32.slice().buffer,
          clientVerifyingShare33: args.clientVerifyingShare33.slice().buffer,
        } as any;
      }
      if (type === 'validateSecp256k1PublicKey33') {
        return new Uint8Array(payload.publicKey33 as ArrayBuffer).slice().buffer as any;
      }
      if (type === 'mapAdditiveShareToThresholdSignaturesShare2p') {
        return new Uint8Array(payload.additiveShare32 as ArrayBuffer).slice().buffer as any;
      }
      if (type === 'thresholdEcdsaPresignSessionInit') {
        return {
          stage: 'done',
          event: 'presign_done',
          outgoingMessages: [],
          presignature97: args.presignature97.slice().buffer,
        } as any;
      }
      if (type === 'thresholdEcdsaPresignSessionStep') {
        return { stage: 'done', event: 'none', outgoingMessages: [] } as any;
      }
      if (type === 'thresholdEcdsaPresignSessionAbort') {
        return { ok: true } as any;
      }
      if (type === 'thresholdEcdsaComputeSignatureShare') {
        return args.clientSignatureShare32.slice().buffer as any;
      }
      throw new Error(`Unexpected worker operation in test: ${type}`);
    },
  };
}

function installThresholdEcdsaFetchMock(args?: {
  failPresignInitAfter?: number;
  includeAuthorizePolicyHint?: boolean;
  presignInitDelayMs?: number;
}): {
  counters: ThresholdFetchCounters;
  restore: () => void;
} {
  const counters: ThresholdFetchCounters = {
    authorize: 0,
    presignInit: 0,
    presignStep: 0,
    signInit: 0,
    signFinalize: 0,
  };
  const originalFetch = globalThis.fetch;
  const failPresignInitAfter = Number(args?.failPresignInitAfter ?? Infinity);
  const includeAuthorizePolicyHint = args?.includeAuthorizePolicyHint === true;
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

    if (path.endsWith('/threshold-ecdsa/authorize')) {
      counters.authorize += 1;
      return new Response(
        JSON.stringify({
          ok: true,
          mpcSessionId: `mpc-${counters.authorize}`,
          expiresAt: new Date(Date.now() + 60_000).toISOString(),
          ...(includeAuthorizePolicyHint
            ? {
                presignPoolPolicy: {
                  enabled: true,
                  targetDepth: 2,
                  lowWatermark: 1,
                  maxRefillInFlight: 2,
                  refillAttemptTimeoutMs: 30_000,
                },
              }
            : {}),
        }),
        {
          status: 200,
          headers: { 'Content-Type': 'application/json' },
        },
      );
    }

    if (path.endsWith('/threshold-ecdsa/presign/init')) {
      counters.presignInit += 1;
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

    if (path.endsWith('/threshold-ecdsa/presign/step')) {
      counters.presignStep += 1;
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

    if (path.endsWith('/threshold-ecdsa/sign/init')) {
      counters.signInit += 1;
      return new Response(
        JSON.stringify({
          ok: true,
          signingSessionId: `signing-session-${counters.signInit}`,
          relayerRound1: {
            entropyB64u: ENTROPY_B64U,
            bigRB64u: PRESIGN_BIG_R_B64U,
          },
        }),
        {
          status: 200,
          headers: { 'Content-Type': 'application/json' },
        },
      );
    }

    if (path.endsWith('/threshold-ecdsa/sign/finalize')) {
      counters.signFinalize += 1;
      return new Response(
        JSON.stringify({
          ok: true,
          relayerRound2: {
            signature65B64u: SIGNATURE_65_B64U,
            rB64u: base64UrlEncode(new Uint8Array(32).fill(43)),
            sB64u: base64UrlEncode(new Uint8Array(32).fill(47)),
            recId: 1,
          },
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

test.describe('threshold ECDSA presign pool refill behavior', () => {
  test.beforeEach(async () => {
    clearAllThresholdEcdsaClientPresignatures();
    clearAllCachedEcdsaAuthSessions();
  });

  test('second sign consumes pooled presignature without inline presign in steady state', async () => {
    const presignature97 = concatBytes([
      PRESIGN_BIG_R_33,
      PRESIGN_K_SHARE_32,
      PRESIGN_SIGMA_SHARE_32,
    ]);
    const workerCtx = makeWorkerCtx({
      clientSigningShare32: CLIENT_SIGNING_SHARE_32,
      clientVerifyingShare33: CLIENT_VERIFYING_SHARE_33,
      presignature97,
      clientSignatureShare32: CLIENT_SIGNATURE_SHARE_32,
    });
    const fetchMock = installThresholdEcdsaFetchMock();

    try {
      const refillInput = {
        relayerUrl: RELAYER_URL,
        relayerKeyId: RELAYER_KEY_ID,
        clientVerifyingShareB64u: CLIENT_VERIFYING_SHARE_B64U,
        participantIds: PARTICIPANT_IDS,
        clientSigningShare32: CLIENT_SIGNING_SHARE_32,
        groupPublicKeyB64u: GROUP_PUBLIC_KEY_B64U,
        sessionKind: 'cookie' as const,
        workerCtx,
      };

      const refill1 = await refillThresholdEcdsaClientPresignaturePool(refillInput);
      const refill2 = await refillThresholdEcdsaClientPresignaturePool(refillInput);
      expect(refill1.ok).toBe(true);
      expect(refill2.ok).toBe(true);
      expect(
        getThresholdEcdsaClientPresignaturePoolDepth({
          relayerUrl: RELAYER_URL,
          relayerKeyId: RELAYER_KEY_ID,
          clientVerifyingShareB64u: CLIENT_VERIFYING_SHARE_B64U,
          participantIds: PARTICIPANT_IDS,
        }),
      ).toBe(2);

      const signArgsBase = {
        relayerUrl: RELAYER_URL,
        relayerKeyId: RELAYER_KEY_ID,
        clientVerifyingShareB64u: CLIENT_VERIFYING_SHARE_B64U,
        signingDigest32: DIGEST_32,
        clientSigningShare32: CLIENT_SIGNING_SHARE_32,
        participantIds: PARTICIPANT_IDS,
        groupPublicKeyB64u: GROUP_PUBLIC_KEY_B64U,
        sessionKind: 'cookie' as const,
        workerCtx,
      };
      const signed1 = await signThresholdEcdsaDigestWithPool({
        ...signArgsBase,
        mpcSessionId: 'mpc-1',
      });
      const signed2 = await signThresholdEcdsaDigestWithPool({
        ...signArgsBase,
        mpcSessionId: 'mpc-2',
      });

      expect(signed1.ok).toBe(true);
      expect(signed2.ok).toBe(true);
      expect(fetchMock.counters.presignInit).toBe(2);
      expect(fetchMock.counters.presignStep).toBe(2);
      expect(fetchMock.counters.signInit).toBe(2);
      expect(fetchMock.counters.signFinalize).toBe(2);
    } finally {
      fetchMock.restore();
    }
  });

  test('commit-start refill skips cold-start empty pool to avoid duplicate inline presign', async () => {
    const presignature97 = concatBytes([
      PRESIGN_BIG_R_33,
      PRESIGN_K_SHARE_32,
      PRESIGN_SIGMA_SHARE_32,
    ]);
    const workerCtx = makeWorkerCtx({
      clientSigningShare32: CLIENT_SIGNING_SHARE_32,
      clientVerifyingShare33: CLIENT_VERIFYING_SHARE_33,
      presignature97,
      clientSignatureShare32: CLIENT_SIGNATURE_SHARE_32,
    });
    const fetchMock = installThresholdEcdsaFetchMock();

    try {
      const cacheKey = makeEcdsaAuthSessionCacheKey({
        userId: USER_ID,
        rpId: RP_ID,
        relayerUrl: RELAYER_URL,
        relayerKeyId: RELAYER_KEY_ID,
        participantIds: PARTICIPANT_IDS,
      });
      putCachedEcdsaAuthSession(cacheKey, {
        sessionKind: 'cookie',
        policy: {
          version: 'threshold_session_v1',
          userId: USER_ID,
          rpId: RP_ID,
          relayerKeyId: RELAYER_KEY_ID,
          sessionId: SESSION_ID,
          participantIds: PARTICIPANT_IDS,
          ttlMs: 60_000,
          remainingUses: 10,
        },
        policyJson: '{}',
        sessionPolicyDigest32: 'digest',
        expiresAtMs: Date.now() + 60_000,
      });

      const refillEvents: Array<{
        trigger: 'commit_start' | 'post_sign_success';
        result: { scheduled: boolean; reason: string };
      }> = [];

      const engine = new Secp256k1Engine({
        getRpId: () => RP_ID,
        workerCtx,
        thresholdEcdsaPresignPoolPolicy: {
          enabled: true,
          targetDepth: 1,
          lowWatermark: 0,
          maxRefillInFlight: 1,
          refillAttemptTimeoutMs: 250,
        },
        dispenseThresholdEcdsaPrfFirstForSession: async () => ({
          ok: true,
          prfFirstB64u: PRF_FIRST_B64U,
          remainingUses: 9,
          expiresAtMs: Date.now() + 60_000,
        }),
        onThresholdEcdsaPresignRefillScheduled: (event) => {
          refillEvents.push({
            trigger: event.trigger,
            result: {
              scheduled: event.result.scheduled,
              reason: event.result.reason,
            },
          });
        },
      });

      const signed = await engine.sign(
        {
          kind: 'digest',
          algorithm: 'secp256k1',
          digest32: DIGEST_32,
          label: 'evm',
        },
        {
          type: 'threshold-ecdsa-secp256k1',
          userId: USER_ID,
          relayerUrl: RELAYER_URL,
          relayerKeyId: RELAYER_KEY_ID,
          clientVerifyingShareB64u: CLIENT_VERIFYING_SHARE_B64U,
          participantIds: PARTICIPANT_IDS,
          groupPublicKeyB64u: GROUP_PUBLIC_KEY_B64U,
          thresholdSessionKind: 'cookie',
          thresholdSessionId: SESSION_ID,
        },
      );

      expect(signed.length).toBe(65);
      expect(refillEvents.length).toBe(2);
      expect(refillEvents[0]!.trigger).toBe('commit_start');
      expect(refillEvents[0]!.result.scheduled).toBe(false);
      expect(refillEvents[0]!.result.reason).toBe('cold_start_pool_empty');

      await waitForPredicate(() => fetchMock.counters.presignInit === 2, 1_000);
      expect(fetchMock.counters.presignInit).toBe(2);
      expect(fetchMock.counters.signInit).toBe(1);
      expect(fetchMock.counters.signFinalize).toBe(1);
    } finally {
      fetchMock.restore();
    }
  });

  test('background refill failures are non-fatal to active sign', async () => {
    const presignature97 = concatBytes([
      PRESIGN_BIG_R_33,
      PRESIGN_K_SHARE_32,
      PRESIGN_SIGMA_SHARE_32,
    ]);
    const workerCtx = makeWorkerCtx({
      clientSigningShare32: CLIENT_SIGNING_SHARE_32,
      clientVerifyingShare33: CLIENT_VERIFYING_SHARE_33,
      presignature97,
      clientSignatureShare32: CLIENT_SIGNATURE_SHARE_32,
    });
    const fetchMock = installThresholdEcdsaFetchMock({
      failPresignInitAfter: 1,
      includeAuthorizePolicyHint: true,
    });

    try {
      const warmed = await refillThresholdEcdsaClientPresignaturePool({
        relayerUrl: RELAYER_URL,
        relayerKeyId: RELAYER_KEY_ID,
        clientVerifyingShareB64u: CLIENT_VERIFYING_SHARE_B64U,
        participantIds: PARTICIPANT_IDS,
        clientSigningShare32: CLIENT_SIGNING_SHARE_32,
        groupPublicKeyB64u: GROUP_PUBLIC_KEY_B64U,
        sessionKind: 'cookie',
        workerCtx,
      });
      expect(warmed.ok).toBe(true);

      const cacheKey = makeEcdsaAuthSessionCacheKey({
        userId: USER_ID,
        rpId: RP_ID,
        relayerUrl: RELAYER_URL,
        relayerKeyId: RELAYER_KEY_ID,
        participantIds: PARTICIPANT_IDS,
      });
      putCachedEcdsaAuthSession(cacheKey, {
        sessionKind: 'cookie',
        policy: {
          version: 'threshold_session_v1',
          userId: USER_ID,
          rpId: RP_ID,
          relayerKeyId: RELAYER_KEY_ID,
          sessionId: SESSION_ID,
          participantIds: PARTICIPANT_IDS,
          ttlMs: 60_000,
          remainingUses: 10,
        },
        policyJson: '{}',
        sessionPolicyDigest32: 'digest',
        expiresAtMs: Date.now() + 60_000,
      });

      const refillEvents: Array<{
        trigger: 'commit_start' | 'post_sign_success';
        result: { scheduled: boolean; reason: string };
      }> = [];
      const engine = new Secp256k1Engine({
        getRpId: () => RP_ID,
        workerCtx,
        thresholdEcdsaPresignPoolPolicy: {
          enabled: true,
          targetDepth: 2,
          lowWatermark: 1,
          maxRefillInFlight: 2,
          refillAttemptTimeoutMs: 500,
        },
        dispenseThresholdEcdsaPrfFirstForSession: async () => ({
          ok: true,
          prfFirstB64u: PRF_FIRST_B64U,
          remainingUses: 9,
          expiresAtMs: Date.now() + 60_000,
        }),
        onThresholdEcdsaPresignRefillScheduled: (event) => {
          refillEvents.push({
            trigger: event.trigger,
            result: {
              scheduled: event.result.scheduled,
              reason: event.result.reason,
            },
          });
        },
      });

      const signed = await engine.sign(
        {
          kind: 'digest',
          algorithm: 'secp256k1',
          digest32: DIGEST_32,
          label: 'evm',
        },
        {
          type: 'threshold-ecdsa-secp256k1',
          userId: USER_ID,
          relayerUrl: RELAYER_URL,
          relayerKeyId: RELAYER_KEY_ID,
          clientVerifyingShareB64u: CLIENT_VERIFYING_SHARE_B64U,
          participantIds: PARTICIPANT_IDS,
          groupPublicKeyB64u: GROUP_PUBLIC_KEY_B64U,
          thresholdSessionKind: 'cookie',
          thresholdSessionId: SESSION_ID,
        },
      );

      expect(signed.length).toBe(65);
      expect(fetchMock.counters.signInit).toBe(1);
      expect(fetchMock.counters.signFinalize).toBe(1);
      expect(refillEvents.length).toBe(2);
      expect(refillEvents[0]!.trigger).toBe('commit_start');
      expect(refillEvents[0]!.result.scheduled).toBe(true);

      await waitForPredicate(() => fetchMock.counters.presignInit >= 2, 1_000);
      expect(fetchMock.counters.presignInit).toBeGreaterThanOrEqual(2);
      expect(fetchMock.counters.signInit).toBe(1);
      expect(fetchMock.counters.signFinalize).toBe(1);
    } finally {
      fetchMock.restore();
    }
  });

  test('foreground sign reuses in-flight refill result instead of starting duplicate presign handshake', async () => {
    const presignature97 = concatBytes([
      PRESIGN_BIG_R_33,
      PRESIGN_K_SHARE_32,
      PRESIGN_SIGMA_SHARE_32,
    ]);
    const workerCtx = makeWorkerCtx({
      clientSigningShare32: CLIENT_SIGNING_SHARE_32,
      clientVerifyingShare33: CLIENT_VERIFYING_SHARE_33,
      presignature97,
      clientSignatureShare32: CLIENT_SIGNATURE_SHARE_32,
    });
    const fetchMock = installThresholdEcdsaFetchMock({
      presignInitDelayMs: 120,
    });

    try {
      const scheduled = scheduleThresholdEcdsaClientPresignaturePoolRefill({
        relayerUrl: RELAYER_URL,
        relayerKeyId: RELAYER_KEY_ID,
        clientVerifyingShareB64u: CLIENT_VERIFYING_SHARE_B64U,
        participantIds: PARTICIPANT_IDS,
        clientSigningShare32: CLIENT_SIGNING_SHARE_32,
        groupPublicKeyB64u: GROUP_PUBLIC_KEY_B64U,
        sessionKind: 'cookie',
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

      const signed = await signThresholdEcdsaDigestWithPool({
        relayerUrl: RELAYER_URL,
        relayerKeyId: RELAYER_KEY_ID,
        clientVerifyingShareB64u: CLIENT_VERIFYING_SHARE_B64U,
        mpcSessionId: 'mpc-foreground-reuse',
        signingDigest32: DIGEST_32,
        clientSigningShare32: CLIENT_SIGNING_SHARE_32,
        participantIds: PARTICIPANT_IDS,
        groupPublicKeyB64u: GROUP_PUBLIC_KEY_B64U,
        sessionKind: 'cookie',
        workerCtx,
      });

      expect(signed.ok).toBe(true);
      expect(fetchMock.counters.presignInit).toBe(1);
      expect(fetchMock.counters.presignStep).toBe(1);
      expect(fetchMock.counters.signInit).toBe(1);
      expect(fetchMock.counters.signFinalize).toBe(1);
    } finally {
      fetchMock.restore();
    }
  });
});
