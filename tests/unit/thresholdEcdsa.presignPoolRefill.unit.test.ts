import { expect, test } from '@playwright/test';
import { base64UrlEncode } from '@shared/utils/encoders';
import type { WorkerOperationContext } from '@/core/signingEngine/workerManager/executeWorkerOperation';
import {
  clearAllThresholdEcdsaClientPresignatures,
  clearThresholdEcdsaClientPresignaturesForLane,
  getThresholdEcdsaClientPresignaturePoolDepth,
  refillThresholdEcdsaClientPresignaturePool,
  scheduleThresholdEcdsaClientPresignaturePoolRefill,
  signThresholdEcdsaDigestWithPool,
} from '@/core/signingEngine/threshold/ecdsa/presignPool';
import {
  buildReadySecp256k1SigningMaterialFromKeyRef,
  Secp256k1Engine,
} from '@/core/signingEngine/flows/signEvmFamily/signers/secp256k1';
import type {
  SignRequest,
  ThresholdEcdsaSecp256k1KeyRef,
} from '@/core/signingEngine/interfaces/signing';
import {
  thresholdEcdsaChainTargetFromChainFamily,
  toWalletId,
} from '@/core/signingEngine/interfaces/ecdsaChainTarget';

const RELAYER_URL = 'https://relay.example';
const ECDSA_KEY_HANDLE = 'ehss-key-presign-test';
const ECDSA_THRESHOLD_KEY_ID = 'ecdsa-hss-test-key-1';
const BACKEND_RELAYER_KEY_ID = 'rk-1';
const USER_ID = 'alice.testnet';
const USER_SUBJECT_ID = toWalletId(USER_ID);
const EVM_CHAIN_TARGET = thresholdEcdsaChainTargetFromChainFamily({
  chain: 'evm',
  chainId: 5042002,
  networkSlug: 'arc-testnet',
});
const RP_ID = 'example.localhost';
const PARTICIPANT_IDS = [1, 2];
const ETHEREUM_ADDRESS = `0x${'11'.repeat(20)}`;
const SESSION_ID = 'session-1';
const WALLET_SIGNING_SESSION_ID = 'wallet-session-1';

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
// Backend bridge field only. Public identity is ecdsaThresholdKeyId/group key/address.
const BACKEND_CLIENT_VERIFYING_SHARE_B64U = base64UrlEncode(CLIENT_VERIFYING_SHARE_33);
const BACKEND_CLIENT_ADDITIVE_SHARE_32_B64U = base64UrlEncode(CLIENT_SIGNING_SHARE_32);
const GROUP_PUBLIC_KEY_B64U = base64UrlEncode(GROUP_PUBLIC_KEY_33);
const PRESIGN_BIG_R_B64U = base64UrlEncode(PRESIGN_BIG_R_33);
const SIGNATURE_65_B64U = base64UrlEncode(SIGNATURE_65);
const ENTROPY_B64U = base64UrlEncode(ENTROPY_32);

function makeDigestSignRequest(): Extract<SignRequest, { kind: 'digest' }> & {
  algorithm: 'secp256k1';
} {
  return {
    kind: 'digest',
    algorithm: 'secp256k1',
    digest32: DIGEST_32,
    label: 'evm',
  };
}

function makeThresholdEcdsaKeyRef(
  overrides: Partial<ThresholdEcdsaSecp256k1KeyRef> = {},
): ThresholdEcdsaSecp256k1KeyRef {
  const base: ThresholdEcdsaSecp256k1KeyRef = {
    type: 'threshold-ecdsa-secp256k1',
    userId: USER_ID,
    chainTarget: EVM_CHAIN_TARGET,
    relayerUrl: RELAYER_URL,
    keyHandle: ECDSA_KEY_HANDLE,
    ecdsaThresholdKeyId: ECDSA_THRESHOLD_KEY_ID,
    signingRootId: 'proj_local:dev',
    backendBinding: {
      relayerKeyId: BACKEND_RELAYER_KEY_ID,
      clientVerifyingShareB64u: BACKEND_CLIENT_VERIFYING_SHARE_B64U,
      clientAdditiveShare32B64u: BACKEND_CLIENT_ADDITIVE_SHARE_32_B64U,
    },
    participantIds: PARTICIPANT_IDS,
    thresholdEcdsaPublicKeyB64u: GROUP_PUBLIC_KEY_B64U,
    ethereumAddress: ETHEREUM_ADDRESS,
    thresholdSessionKind: 'cookie',
    thresholdSessionId: SESSION_ID,
    walletSigningSessionId: WALLET_SIGNING_SESSION_ID,
  };
  return {
    ...base,
    ...overrides,
    backendBinding: {
      ...base.backendBinding!,
      ...(overrides.backendBinding || {}),
    },
  };
}

async function makeReadySecp256k1Material(
  overrides: Partial<ThresholdEcdsaSecp256k1KeyRef> = {},
) {
  return await buildReadySecp256k1SigningMaterialFromKeyRef({
    keyRef: makeThresholdEcdsaKeyRef(overrides),
    requestLabel: 'evm',
    rpId: RP_ID,
  });
}

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

function expectZeroedBytes(bytes: Uint8Array): void {
  expect(Array.from(bytes).every((value) => value === 0)).toBe(true);
}

test.describe('threshold ECDSA presign pool refill behavior', () => {
  test.beforeEach(async () => {
    clearAllThresholdEcdsaClientPresignatures();
  });

  test('second sign consumes pooled presignature without inline presign in steady state', async () => {
    const presignature97 = concatBytes([
      PRESIGN_BIG_R_33,
      PRESIGN_K_SHARE_32,
      PRESIGN_SIGMA_SHARE_32,
    ]);
    const workerCtx = makeWorkerCtx({
      clientSigningShare32: CLIENT_SIGNING_SHARE_32.slice(),
      clientVerifyingShare33: CLIENT_VERIFYING_SHARE_33,
      presignature97,
      clientSignatureShare32: CLIENT_SIGNATURE_SHARE_32,
    });
    const fetchMock = installThresholdEcdsaFetchMock();

    try {
      const refillInput = {
        relayerUrl: RELAYER_URL,
        ecdsaThresholdKeyId: ECDSA_THRESHOLD_KEY_ID,
        keyHandle: ECDSA_KEY_HANDLE,
        relayerKeyId: BACKEND_RELAYER_KEY_ID,
        clientVerifyingShareB64u: BACKEND_CLIENT_VERIFYING_SHARE_B64U,
        participantIds: PARTICIPANT_IDS,
        clientSigningShare32: CLIENT_SIGNING_SHARE_32.slice(),
        thresholdEcdsaPublicKeyB64u: GROUP_PUBLIC_KEY_B64U,
        sessionKind: 'cookie' as const,
        workerCtx,
      };

      const refill1 = await refillThresholdEcdsaClientPresignaturePool(refillInput);
      const refill2 = await refillThresholdEcdsaClientPresignaturePool({
        ...refillInput,
        clientSigningShare32: CLIENT_SIGNING_SHARE_32.slice(),
      });
      expect(refill1.ok).toBe(true);
      expect(refill2.ok).toBe(true);
      expect(
        getThresholdEcdsaClientPresignaturePoolDepth({
          relayerUrl: RELAYER_URL,
          ecdsaThresholdKeyId: ECDSA_THRESHOLD_KEY_ID,
          participantIds: PARTICIPANT_IDS,
        }),
      ).toBe(2);

      const signArgsBase = {
        relayerUrl: RELAYER_URL,
        ecdsaThresholdKeyId: ECDSA_THRESHOLD_KEY_ID,
        keyHandle: ECDSA_KEY_HANDLE,
        relayerKeyId: BACKEND_RELAYER_KEY_ID,
        clientVerifyingShareB64u: BACKEND_CLIENT_VERIFYING_SHARE_B64U,
        signingDigest32: DIGEST_32,
        participantIds: PARTICIPANT_IDS,
        thresholdEcdsaPublicKeyB64u: GROUP_PUBLIC_KEY_B64U,
        sessionKind: 'cookie' as const,
        workerCtx,
      };
      const signed1 = await signThresholdEcdsaDigestWithPool({
        ...signArgsBase,
        mpcSessionId: 'mpc-1',
        clientSigningShare32: CLIENT_SIGNING_SHARE_32.slice(),
      });
      const signed2 = await signThresholdEcdsaDigestWithPool({
        ...signArgsBase,
        mpcSessionId: 'mpc-2',
        clientSigningShare32: CLIENT_SIGNING_SHARE_32.slice(),
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

  test('lane-scoped clear drops pooled presignatures immediately', async () => {
    const presignature97 = concatBytes([
      PRESIGN_BIG_R_33,
      PRESIGN_K_SHARE_32,
      PRESIGN_SIGMA_SHARE_32,
    ]);
    const workerCtx = makeWorkerCtx({
      clientSigningShare32: CLIENT_SIGNING_SHARE_32.slice(),
      clientVerifyingShare33: CLIENT_VERIFYING_SHARE_33,
      presignature97,
      clientSignatureShare32: CLIENT_SIGNATURE_SHARE_32,
    });
    const fetchMock = installThresholdEcdsaFetchMock();

    try {
      const refill = await refillThresholdEcdsaClientPresignaturePool({
        relayerUrl: RELAYER_URL,
        ecdsaThresholdKeyId: ECDSA_THRESHOLD_KEY_ID,
        keyHandle: ECDSA_KEY_HANDLE,
        relayerKeyId: BACKEND_RELAYER_KEY_ID,
        clientVerifyingShareB64u: BACKEND_CLIENT_VERIFYING_SHARE_B64U,
        participantIds: PARTICIPANT_IDS,
        clientSigningShare32: CLIENT_SIGNING_SHARE_32.slice(),
        thresholdEcdsaPublicKeyB64u: GROUP_PUBLIC_KEY_B64U,
        sessionKind: 'cookie',
        workerCtx,
      });
      expect(refill.ok).toBe(true);
      expect(
        getThresholdEcdsaClientPresignaturePoolDepth({
          relayerUrl: RELAYER_URL,
          ecdsaThresholdKeyId: ECDSA_THRESHOLD_KEY_ID,
          participantIds: PARTICIPANT_IDS,
        }),
      ).toBe(1);

      clearThresholdEcdsaClientPresignaturesForLane({
        relayerUrl: RELAYER_URL,
        ecdsaThresholdKeyId: ECDSA_THRESHOLD_KEY_ID,
        participantIds: PARTICIPANT_IDS,
      });

      expect(
        getThresholdEcdsaClientPresignaturePoolDepth({
          relayerUrl: RELAYER_URL,
          ecdsaThresholdKeyId: ECDSA_THRESHOLD_KEY_ID,
          participantIds: PARTICIPANT_IDS,
        }),
      ).toBe(0);
    } finally {
      fetchMock.restore();
    }
  });

  test('lane-scoped clear prevents an in-flight refill from repopulating the pool', async () => {
    const presignature97 = concatBytes([
      PRESIGN_BIG_R_33,
      PRESIGN_K_SHARE_32,
      PRESIGN_SIGMA_SHARE_32,
    ]);
    const workerCtx = makeWorkerCtx({
      clientSigningShare32: CLIENT_SIGNING_SHARE_32.slice(),
      clientVerifyingShare33: CLIENT_VERIFYING_SHARE_33,
      presignature97,
      clientSignatureShare32: CLIENT_SIGNATURE_SHARE_32,
    });
    const fetchMock = installThresholdEcdsaFetchMock({ presignInitDelayMs: 50 });

    try {
      const scheduled = scheduleThresholdEcdsaClientPresignaturePoolRefill({
        relayerUrl: RELAYER_URL,
        ecdsaThresholdKeyId: ECDSA_THRESHOLD_KEY_ID,
        keyHandle: ECDSA_KEY_HANDLE,
        relayerKeyId: BACKEND_RELAYER_KEY_ID,
        clientVerifyingShareB64u: BACKEND_CLIENT_VERIFYING_SHARE_B64U,
        participantIds: PARTICIPANT_IDS,
        clientSigningShare32: CLIENT_SIGNING_SHARE_32.slice(),
        thresholdEcdsaPublicKeyB64u: GROUP_PUBLIC_KEY_B64U,
        sessionKind: 'cookie',
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

      clearThresholdEcdsaClientPresignaturesForLane({
        relayerUrl: RELAYER_URL,
        ecdsaThresholdKeyId: ECDSA_THRESHOLD_KEY_ID,
        participantIds: PARTICIPANT_IDS,
      });

      await waitForPredicate(() => fetchMock.counters.presignInit > 0);
      await new Promise((resolve) => setTimeout(resolve, 100));

      expect(
        getThresholdEcdsaClientPresignaturePoolDepth({
          relayerUrl: RELAYER_URL,
          ecdsaThresholdKeyId: ECDSA_THRESHOLD_KEY_ID,
          participantIds: PARTICIPANT_IDS,
        }),
      ).toBe(0);
    } finally {
      fetchMock.restore();
    }
  });

  test('direct refill zeroizes its owned client signing share after completion', async () => {
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
    const ownedClientSigningShare32 = CLIENT_SIGNING_SHARE_32.slice();

    try {
      const refill = await refillThresholdEcdsaClientPresignaturePool({
        relayerUrl: RELAYER_URL,
        ecdsaThresholdKeyId: ECDSA_THRESHOLD_KEY_ID,
        keyHandle: ECDSA_KEY_HANDLE,
        relayerKeyId: BACKEND_RELAYER_KEY_ID,
        clientVerifyingShareB64u: BACKEND_CLIENT_VERIFYING_SHARE_B64U,
        participantIds: PARTICIPANT_IDS,
        clientSigningShare32: ownedClientSigningShare32,
        thresholdEcdsaPublicKeyB64u: GROUP_PUBLIC_KEY_B64U,
        sessionKind: 'cookie',
        workerCtx,
      });
      expect(refill.ok).toBe(true);
      expectZeroedBytes(ownedClientSigningShare32);
    } finally {
      fetchMock.restore();
    }
  });

  test('scheduled refill zeroizes its owned client signing share after invalidation', async () => {
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
    const fetchMock = installThresholdEcdsaFetchMock({ presignInitDelayMs: 50 });
    const ownedClientSigningShare32 = CLIENT_SIGNING_SHARE_32.slice();

    try {
      const scheduled = scheduleThresholdEcdsaClientPresignaturePoolRefill({
        relayerUrl: RELAYER_URL,
        ecdsaThresholdKeyId: ECDSA_THRESHOLD_KEY_ID,
        keyHandle: ECDSA_KEY_HANDLE,
        relayerKeyId: BACKEND_RELAYER_KEY_ID,
        clientVerifyingShareB64u: BACKEND_CLIENT_VERIFYING_SHARE_B64U,
        participantIds: PARTICIPANT_IDS,
        clientSigningShare32: ownedClientSigningShare32,
        thresholdEcdsaPublicKeyB64u: GROUP_PUBLIC_KEY_B64U,
        sessionKind: 'cookie',
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

      clearThresholdEcdsaClientPresignaturesForLane({
        relayerUrl: RELAYER_URL,
        ecdsaThresholdKeyId: ECDSA_THRESHOLD_KEY_ID,
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
    const ownedClientSigningShare32 = CLIENT_SIGNING_SHARE_32.slice();

    try {
      const signed = await signThresholdEcdsaDigestWithPool({
        relayerUrl: RELAYER_URL,
        ecdsaThresholdKeyId: ECDSA_THRESHOLD_KEY_ID,
        keyHandle: ECDSA_KEY_HANDLE,
        relayerKeyId: BACKEND_RELAYER_KEY_ID,
        clientVerifyingShareB64u: BACKEND_CLIENT_VERIFYING_SHARE_B64U,
        mpcSessionId: 'mpc-owned-share-zeroize',
        signingDigest32: DIGEST_32,
        clientSigningShare32: ownedClientSigningShare32,
        participantIds: PARTICIPANT_IDS,
        thresholdEcdsaPublicKeyB64u: GROUP_PUBLIC_KEY_B64U,
        sessionKind: 'cookie',
        workerCtx,
      });
      expect(signed.ok).toBe(true);
      expectZeroedBytes(ownedClientSigningShare32);
    } finally {
      fetchMock.restore();
    }
  });

  test('foreground sign rejects reuse of a zeroized stale client signing share buffer', async () => {
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
    const ownedClientSigningShare32 = CLIENT_SIGNING_SHARE_32.slice();

    try {
      const first = await signThresholdEcdsaDigestWithPool({
        relayerUrl: RELAYER_URL,
        ecdsaThresholdKeyId: ECDSA_THRESHOLD_KEY_ID,
        keyHandle: ECDSA_KEY_HANDLE,
        relayerKeyId: BACKEND_RELAYER_KEY_ID,
        clientVerifyingShareB64u: BACKEND_CLIENT_VERIFYING_SHARE_B64U,
        mpcSessionId: 'mpc-stale-share-first',
        signingDigest32: DIGEST_32,
        clientSigningShare32: ownedClientSigningShare32,
        participantIds: PARTICIPANT_IDS,
        thresholdEcdsaPublicKeyB64u: GROUP_PUBLIC_KEY_B64U,
        sessionKind: 'cookie',
        workerCtx,
      });
      expect(first.ok).toBe(true);
      expectZeroedBytes(ownedClientSigningShare32);

      const second = await signThresholdEcdsaDigestWithPool({
        relayerUrl: RELAYER_URL,
        ecdsaThresholdKeyId: ECDSA_THRESHOLD_KEY_ID,
        keyHandle: ECDSA_KEY_HANDLE,
        relayerKeyId: BACKEND_RELAYER_KEY_ID,
        clientVerifyingShareB64u: BACKEND_CLIENT_VERIFYING_SHARE_B64U,
        mpcSessionId: 'mpc-stale-share-second',
        signingDigest32: DIGEST_32,
        clientSigningShare32: ownedClientSigningShare32,
        participantIds: PARTICIPANT_IDS,
        thresholdEcdsaPublicKeyB64u: GROUP_PUBLIC_KEY_B64U,
        sessionKind: 'cookie',
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

  test('commit-start refill skips cold-start empty pool to avoid duplicate inline presign', async () => {
    const presignature97 = concatBytes([
      PRESIGN_BIG_R_33,
      PRESIGN_K_SHARE_32,
      PRESIGN_SIGMA_SHARE_32,
    ]);
    const workerCtx = makeWorkerCtx({
      clientSigningShare32: CLIENT_SIGNING_SHARE_32.slice(),
      clientVerifyingShare33: CLIENT_VERIFYING_SHARE_33,
      presignature97,
      clientSignatureShare32: CLIENT_SIGNATURE_SHARE_32,
    });
    const fetchMock = installThresholdEcdsaFetchMock();

    try {
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

      const signed = await engine.signReady(
        makeDigestSignRequest(),
        await makeReadySecp256k1Material(),
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
      clientSigningShare32: CLIENT_SIGNING_SHARE_32.slice(),
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
        ecdsaThresholdKeyId: ECDSA_THRESHOLD_KEY_ID,
        keyHandle: ECDSA_KEY_HANDLE,
        relayerKeyId: BACKEND_RELAYER_KEY_ID,
        clientVerifyingShareB64u: BACKEND_CLIENT_VERIFYING_SHARE_B64U,
        participantIds: PARTICIPANT_IDS,
        clientSigningShare32: CLIENT_SIGNING_SHARE_32.slice(),
        thresholdEcdsaPublicKeyB64u: GROUP_PUBLIC_KEY_B64U,
        sessionKind: 'cookie',
        workerCtx,
      });
      expect(warmed.ok).toBe(true);

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

      const signed = await engine.signReady(
        makeDigestSignRequest(),
        await makeReadySecp256k1Material(),
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
      clientSigningShare32: CLIENT_SIGNING_SHARE_32.slice(),
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
        ecdsaThresholdKeyId: ECDSA_THRESHOLD_KEY_ID,
        keyHandle: ECDSA_KEY_HANDLE,
        relayerKeyId: BACKEND_RELAYER_KEY_ID,
        clientVerifyingShareB64u: BACKEND_CLIENT_VERIFYING_SHARE_B64U,
        participantIds: PARTICIPANT_IDS,
        clientSigningShare32: CLIENT_SIGNING_SHARE_32.slice(),
        thresholdEcdsaPublicKeyB64u: GROUP_PUBLIC_KEY_B64U,
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
        ecdsaThresholdKeyId: ECDSA_THRESHOLD_KEY_ID,
        keyHandle: ECDSA_KEY_HANDLE,
        relayerKeyId: BACKEND_RELAYER_KEY_ID,
        clientVerifyingShareB64u: BACKEND_CLIENT_VERIFYING_SHARE_B64U,
        mpcSessionId: 'mpc-foreground-reuse',
        signingDigest32: DIGEST_32,
        clientSigningShare32: CLIENT_SIGNING_SHARE_32.slice(),
        participantIds: PARTICIPANT_IDS,
        thresholdEcdsaPublicKeyB64u: GROUP_PUBLIC_KEY_B64U,
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

  test('jwt keyRef fallback signs successfully when canonical ECDSA session record is unavailable', async () => {
    const presignature97 = concatBytes([
      PRESIGN_BIG_R_33,
      PRESIGN_K_SHARE_32,
      PRESIGN_SIGMA_SHARE_32,
    ]);
    const workerCtx = makeWorkerCtx({
      clientSigningShare32: CLIENT_SIGNING_SHARE_32.slice(),
      clientVerifyingShare33: CLIENT_VERIFYING_SHARE_33,
      presignature97,
      clientSignatureShare32: CLIENT_SIGNATURE_SHARE_32,
    });
    const fetchMock = installThresholdEcdsaFetchMock();

    try {
      const thresholdSessionAuthToken = 'jwt-refresh-self-heal';
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
      });

      const signed = await engine.signReady(
        makeDigestSignRequest(),
        await makeReadySecp256k1Material({
          thresholdSessionKind: 'jwt',
          thresholdSessionAuthToken,
        }),
      );

      expect(signed.length).toBe(65);
      expect(fetchMock.counters.authorize).toBe(1);
    } finally {
      fetchMock.restore();
    }
  });
});
