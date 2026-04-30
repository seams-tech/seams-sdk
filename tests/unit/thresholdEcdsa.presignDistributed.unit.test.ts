import { test, expect } from '@playwright/test';
import { createHash, hkdfSync } from 'node:crypto';
import { secp256k1 } from '@noble/curves/secp256k1.js';
import { bytesToNumberBE, numberToBytesBE } from '../../shared/src/utils/bigint';
import { alphabetizeStringify, sha256BytesUtf8 } from '../../shared/src/utils/digests';
import { base64UrlDecode, base64UrlEncode } from '../../shared/src/utils/encoders';
import { mapAdditiveShareToThresholdSignaturesShare2p } from '../../shared/src/threshold/secp256k1Ecdsa2pShareMapping';
import { SECP256K1_ORDER } from '../../shared/src/threshold/secp256k1';
import { THRESHOLD_SECP256K1_ECDSA_2P_V1_SCHEME_ID } from '../../server/src/core/ThresholdService/schemes/schemeIds';
import { ThresholdEcdsaSigningHandlers } from '../../server/src/core/ThresholdService/ecdsaSigningHandlers';
import {
  InMemoryThresholdEcdsaPresignSessionStore,
  InMemoryThresholdEcdsaPresignaturePool,
  InMemoryThresholdEcdsaSigningSessionStore,
} from '../../server/src/core/ThresholdService/stores/EcdsaSigningStore';
import { ThresholdEcdsaPresignSession } from '../../wasm/eth_signer/pkg/eth_signer.js';

const TEST_RELAYER_SHARE_SEED_B64U = Buffer.from(new Uint8Array(32).fill(9)).toString('base64url');
const TEST_THRESHOLD_EXPIRES_IN_MS = 10 * 60_000;
const TEST_RUNTIME_SCOPE = { orgId: 'org-alpha', projectId: 'project-alpha', envId: 'env-alpha' } as const;
const TEST_SIGNING_ROOT_ID = `${TEST_RUNTIME_SCOPE.projectId}:${TEST_RUNTIME_SCOPE.envId}`;

function toUint8Array(value: ArrayBuffer | ArrayBufferView): Uint8Array {
  if (value instanceof Uint8Array) return value;
  if (value instanceof ArrayBuffer) return new Uint8Array(value);
  return new Uint8Array(value.buffer, value.byteOffset, value.byteLength);
}

function sha256Bytes(input: Uint8Array): Uint8Array {
  return new Uint8Array(createHash('sha256').update(input).digest());
}

function deriveFixtureRelayerSecp256k1SigningShare32(input: {
  relayerShareSeedB64u: string;
  relayerKeyId: string;
}): Uint8Array {
  const relayerShareSeedBytes = base64UrlDecode(input.relayerShareSeedB64u);
  const relayerShareSaltV1 = new TextEncoder().encode(
    'seams/test/threshold-secp256k1-ecdsa/fixture-relayer-share:v1',
  );
  const relayerShareInfo = new TextEncoder().encode(input.relayerKeyId);
  const okm64 = toUint8Array(
    hkdfSync('sha256', relayerShareSeedBytes, relayerShareSaltV1, relayerShareInfo, 64),
  );
  const reduced = (bytesToNumberBE(okm64) % (SECP256K1_ORDER - 1n)) + 1n;
  return numberToBytesBE(reduced, 32);
}

function randomSecpSecretKey32(): Uint8Array {
  const utils = (secp256k1 as any)?.utils;
  if (typeof utils?.randomPrivateKey === 'function') return utils.randomPrivateKey();
  if (typeof utils?.randomSecretKey === 'function') return utils.randomSecretKey();
  throw new Error('secp256k1 random secret key generator is unavailable');
}

function bytesToHex(input: Uint8Array): string {
  return Array.from(input, (byte) => byte.toString(16).padStart(2, '0')).join('');
}

function sumSecpPublicKeysCompressed(
  aCompressed33: Uint8Array,
  bCompressed33: Uint8Array,
): Uint8Array {
  const pointCtor = ((secp256k1 as any).ProjectivePoint || (secp256k1 as any).Point) as
    | { fromHex: (hex: string | Uint8Array) => any }
    | undefined;
  if (!pointCtor || typeof pointCtor.fromHex !== 'function') {
    throw new Error('secp256k1 point constructor is unavailable');
  }
  const point = pointCtor
    .fromHex(bytesToHex(aCompressed33))
    .add(pointCtor.fromHex(bytesToHex(bCompressed33)));
  if (typeof point.toRawBytes === 'function') return point.toRawBytes(true);
  return point.toBytes(true);
}

function buildIntegratedKeyRecord(input: {
  ecdsaThresholdKeyId: string;
  userId: string;
  rpId: string;
  participantIds: number[];
  relayerKeyId: string;
  clientVerifyingShareB64u: string;
}) {
  const clientVerifyingShare33 = base64UrlDecode(input.clientVerifyingShareB64u);
  const relayerSigningShare32 = deriveFixtureRelayerSecp256k1SigningShare32({
    relayerShareSeedB64u: TEST_RELAYER_SHARE_SEED_B64U,
    relayerKeyId: input.relayerKeyId,
  });
  const relayerVerifyingShare33 = secp256k1.getPublicKey(relayerSigningShare32, true);
  const groupPublicKey33 = sumSecpPublicKeysCompressed(
    clientVerifyingShare33,
    relayerVerifyingShare33,
  );
  const nowMs = Date.now();
  return {
    version: 'threshold_ecdsa_hss_key_v1' as const,
    ecdsaThresholdKeyId: input.ecdsaThresholdKeyId,
    userId: input.userId,
    rpId: input.rpId,
    schemeId: THRESHOLD_SECP256K1_ECDSA_2P_V1_SCHEME_ID,
    clientVerifyingShareB64u: input.clientVerifyingShareB64u,
    thresholdEcdsaPublicKeyB64u: base64UrlEncode(groupPublicKey33),
    ethereumAddress: `0x${'11'.repeat(20)}`,
    signingRootId: TEST_SIGNING_ROOT_ID,
    walletKeyVersion: 'v1',
    derivationVersion: 1,
    participantIds: input.participantIds,
    relayerKeyId: input.relayerKeyId,
    relayerVerifyingShareB64u: base64UrlEncode(relayerVerifyingShare33),
    relayerRootShare32B64u: base64UrlEncode(relayerSigningShare32),
    relayerBackendInputB64u: base64UrlEncode(relayerSigningShare32),
    createdAtMs: nowMs,
    updatedAtMs: nowMs,
  };
}

function pollSession(session: ThresholdEcdsaPresignSession): {
  stage: 'triples' | 'triples_done' | 'presign' | 'done';
  event: 'none' | 'triples_done' | 'presign_done';
  outgoingMessages: Uint8Array[];
} {
  const raw = session.poll() as { stage?: unknown; event?: unknown; outgoing?: unknown };
  const stage =
    raw?.stage === 'triples_done'
      ? 'triples_done'
      : raw?.stage === 'presign'
        ? 'presign'
        : raw?.stage === 'done'
          ? 'done'
          : 'triples';
  const event =
    raw?.event === 'triples_done'
      ? 'triples_done'
      : raw?.event === 'presign_done'
        ? 'presign_done'
        : 'none';
  const outgoingMessages = Array.isArray(raw?.outgoing)
    ? raw.outgoing.map((entry) => {
        if (entry instanceof Uint8Array) return entry;
        if (entry instanceof ArrayBuffer) return new Uint8Array(entry);
        if (ArrayBuffer.isView(entry as any)) {
          const view = entry as ArrayBufferView;
          return new Uint8Array(view.buffer, view.byteOffset, view.byteLength);
        }
        throw new Error('Unexpected presign outgoing message type');
      })
    : [];
  return { stage, event, outgoingMessages };
}

test.describe('threshold-ecdsa presign distributed session store', () => {
  test('completes one presign session on a single coordinator instance', async () => {
    const userId = 'distributed-user';
    const rpId = 'example.localhost';
    const participantIds = [1, 2];
    const clientParticipantId = 1;
    const relayerParticipantId = 2;
    const thresholdExpiresAtMs = Date.now() + TEST_THRESHOLD_EXPIRES_IN_MS;

    const clientSigningShare32 = randomSecpSecretKey32();
    const clientVerifyingShare33 = secp256k1.getPublicKey(clientSigningShare32, true);
    const clientVerifyingShareB64u = base64UrlEncode(clientVerifyingShare33);

    const relayerKeyIdDigest32 = await sha256BytesUtf8(
      alphabetizeStringify({
        version: 'threshold_secp256k1_key_id_v1',
        schemeId: THRESHOLD_SECP256K1_ECDSA_2P_V1_SCHEME_ID,
        userId,
        rpId,
        clientVerifyingShareB64u,
      }),
    );
    const relayerKeyId = `secp-${base64UrlEncode(relayerKeyIdDigest32)}`;
    const ecdsaThresholdKeyId = `ecdsa-hss-${base64UrlEncode(relayerKeyIdDigest32)}`;
    const integratedKeyRecord = buildIntegratedKeyRecord({
      ecdsaThresholdKeyId,
      userId,
      rpId,
      participantIds,
      relayerKeyId,
      clientVerifyingShareB64u,
    });

    const relayerSigningShare32 = deriveFixtureRelayerSecp256k1SigningShare32({
      relayerShareSeedB64u: TEST_RELAYER_SHARE_SEED_B64U,
      relayerKeyId,
    });
    const relayerVerifyingShare33 = secp256k1.getPublicKey(relayerSigningShare32, true);
    const groupPublicKey33 = sumSecpPublicKeysCompressed(
      clientVerifyingShare33,
      relayerVerifyingShare33,
    );

    const sharedPresignSessionStore = new InMemoryThresholdEcdsaPresignSessionStore();
    const sharedPresignaturePool = new InMemoryThresholdEcdsaPresignaturePool();
    const sharedSigningSessionStore = new InMemoryThresholdEcdsaSigningSessionStore();

    const fakeSessionStore = {
      putMpcSession: async () => {},
      takeMpcSession: async () => null,
      putSigningSession: async () => {},
      takeSigningSession: async () => null,
      putCoordinatorSigningSession: async () => {},
      takeCoordinatorSigningSession: async () => null,
    } as const;

    let presignIdCounter = 0;
    const makeLogger = () => ({
      debug: () => {},
      info: () => {},
      warn: () => {},
      error: () => {},
    });
    const makeHandler = () =>
      new ThresholdEcdsaSigningHandlers({
        logger: makeLogger() as any,
        nodeRole: 'coordinator',
        participantIds2p: participantIds,
        clientParticipantId,
        relayerParticipantId,
        sessionStore: fakeSessionStore as any,
        signingSessionStore: sharedSigningSessionStore,
        presignSessionStore: sharedPresignSessionStore,
        presignaturePool: sharedPresignaturePool,
        resolveIntegratedKeyRecord: async ({ ecdsaThresholdKeyId: requested }) =>
          requested === ecdsaThresholdKeyId ? integratedKeyRecord : null,
        ensureReady: async () => {},
        createSigningSessionId: () => `sign-${Date.now()}-${Math.random().toString(16).slice(2)}`,
        createPresignSessionId: () => `presign-${++presignIdCounter}`,
      });

    const handlerA = makeHandler();

    const claims = {
      sub: userId,
      rpId,
      relayerKeyId,
      participantIds,
      thresholdExpiresAtMs,
      runtimePolicyScope: TEST_RUNTIME_SCOPE,
    };

    const init = await handlerA.ecdsaPresignInit({
      claims: claims as any,
      request: { ecdsaThresholdKeyId, count: 1 },
    });
    expect(init.ok, JSON.stringify(init)).toBe(true);
    const presignSessionId = String(init.presignSessionId || '');
    expect(presignSessionId).toBeTruthy();

    const localClientThresholdShare32 = mapAdditiveShareToThresholdSignaturesShare2p({
      additiveShare32: clientSigningShare32,
      participantId: clientParticipantId,
    });
    const localSession = new ThresholdEcdsaPresignSession(
      new Uint32Array(participantIds),
      clientParticipantId,
      2,
      localClientThresholdShare32,
      groupPublicKey33,
    );

    let stageForServer: 'triples' | 'presign' = 'triples';
    let pendingClientOutgoing = pollSession(localSession).outgoingMessages;
    let pendingServerOutgoing = (init.outgoingMessagesB64u || []).map((msg) =>
      base64UrlDecode(msg),
    );
    let localPresignature97: Uint8Array | null = null;
    let serverPresignatureId = '';
    let serverBigRB64u = '';
    let serverDone = false;

    const MAX_STEPS = 64;
    for (let i = 0; i < MAX_STEPS; i += 1) {
      if (pendingServerOutgoing.length > 0 && !localPresignature97) {
        if (stageForServer === 'presign' && localSession.stage() === 'triples_done') {
          localSession.start_presign();
        }
        for (const msg of pendingServerOutgoing) {
          localSession.message(relayerParticipantId, msg);
        }
        pendingServerOutgoing = [];
        const polled = pollSession(localSession);
        pendingClientOutgoing.push(...polled.outgoingMessages);
        if (
          polled.stage === 'triples_done' ||
          polled.stage === 'presign' ||
          polled.stage === 'done'
        ) {
          stageForServer = 'presign';
        }
        if (polled.event === 'presign_done') {
          localPresignature97 = localSession.take_presignature_97();
        }
      }

      if (!serverDone) {
        const step = await handlerA.ecdsaPresignStep({
          claims: claims as any,
          request: {
            presignSessionId,
            stage: stageForServer,
            outgoingMessagesB64u: pendingClientOutgoing.map((msg) => base64UrlEncode(msg)),
          },
        });
        expect(step.ok, JSON.stringify(step)).toBe(true);
        pendingClientOutgoing = [];
        pendingServerOutgoing = (step.outgoingMessagesB64u || []).map((msg) =>
          base64UrlDecode(msg),
        );
        if (step.event === 'triples_done' || step.stage === 'presign') {
          stageForServer = 'presign';
        }
        if (step.event === 'presign_done') {
          serverDone = true;
          serverPresignatureId = String(step.presignatureId || '');
          serverBigRB64u = String(step.bigRB64u || '');
        }
      }

      if (serverDone && localPresignature97) break;
    }

    expect(serverDone).toBe(true);
    expect(localPresignature97).not.toBeNull();
    const localBigR33 = localPresignature97!.slice(0, 33);
    const expectedPresignatureId = `presig-${base64UrlEncode(sha256Bytes(localBigR33))}`;
    expect(serverPresignatureId).toBe(expectedPresignatureId);
    expect(serverBigRB64u).toBe(base64UrlEncode(localBigR33));

    const reserved = await sharedPresignaturePool.reserve(relayerKeyId);
    expect(reserved?.presignatureId).toBe(serverPresignatureId);
    expect(reserved?.bigRB64u).toBe(serverBigRB64u);
  });

  test('returns retriable stale_session_state on cross-instance cache miss', async () => {
    const userId = 'strict-no-replay-user';
    const rpId = 'example.localhost';
    const participantIds = [1, 2];
    const clientParticipantId = 1;
    const relayerParticipantId = 2;
    const thresholdExpiresAtMs = Date.now() + TEST_THRESHOLD_EXPIRES_IN_MS;

    const clientSigningShare32 = randomSecpSecretKey32();
    const clientVerifyingShare33 = secp256k1.getPublicKey(clientSigningShare32, true);
    const clientVerifyingShareB64u = base64UrlEncode(clientVerifyingShare33);

    const relayerKeyIdDigest32 = await sha256BytesUtf8(
      alphabetizeStringify({
        version: 'threshold_secp256k1_key_id_v1',
        schemeId: THRESHOLD_SECP256K1_ECDSA_2P_V1_SCHEME_ID,
        userId,
        rpId,
        clientVerifyingShareB64u,
      }),
    );
    const relayerKeyId = `secp-${base64UrlEncode(relayerKeyIdDigest32)}`;
    const ecdsaThresholdKeyId = `ecdsa-hss-${base64UrlEncode(relayerKeyIdDigest32)}`;
    const integratedKeyRecord = buildIntegratedKeyRecord({
      ecdsaThresholdKeyId,
      userId,
      rpId,
      participantIds,
      relayerKeyId,
      clientVerifyingShareB64u,
    });

    const sharedPresignSessionStore = new InMemoryThresholdEcdsaPresignSessionStore();
    const sharedPresignaturePool = new InMemoryThresholdEcdsaPresignaturePool();
    const sharedSigningSessionStore = new InMemoryThresholdEcdsaSigningSessionStore();

    const fakeSessionStore = {
      putMpcSession: async () => {},
      takeMpcSession: async () => null,
      putSigningSession: async () => {},
      takeSigningSession: async () => null,
      putCoordinatorSigningSession: async () => {},
      takeCoordinatorSigningSession: async () => null,
    } as const;

    let presignIdCounter = 0;
    const makeHandler = () =>
      new ThresholdEcdsaSigningHandlers({
        logger: {
          debug: () => {},
          info: () => {},
          warn: () => {},
          error: () => {},
        } as any,
        nodeRole: 'coordinator',
        participantIds2p: participantIds,
        clientParticipantId,
        relayerParticipantId,
        sessionStore: fakeSessionStore as any,
        signingSessionStore: sharedSigningSessionStore,
        presignSessionStore: sharedPresignSessionStore,
        presignaturePool: sharedPresignaturePool,
        resolveIntegratedKeyRecord: async ({ ecdsaThresholdKeyId: requested }) =>
          requested === ecdsaThresholdKeyId ? integratedKeyRecord : null,
        ensureReady: async () => {},
        createSigningSessionId: () => `sign-${Date.now()}-${Math.random().toString(16).slice(2)}`,
        createPresignSessionId: () => `presign-cache-miss-${++presignIdCounter}`,
      });

    const handlerA = makeHandler();
    const handlerB = makeHandler();
    const claims = {
      sub: userId,
      rpId,
      relayerKeyId,
      participantIds,
      thresholdExpiresAtMs,
      runtimePolicyScope: TEST_RUNTIME_SCOPE,
    };

    const init = await handlerA.ecdsaPresignInit({
      claims: claims as any,
      request: { ecdsaThresholdKeyId, count: 1 },
    });
    expect(init.ok, JSON.stringify(init)).toBe(true);
    const presignSessionId = String(init.presignSessionId || '');
    expect(presignSessionId).toBeTruthy();

    const step = await handlerB.ecdsaPresignStep({
      claims: claims as any,
      request: {
        presignSessionId,
        stage: 'triples',
        outgoingMessagesB64u: [],
      },
    });
    expect(step.ok).toBe(false);
    expect(step.code).toBe('stale_session_state');
    expect(String(step.message || '')).toContain('/threshold-ecdsa/presign/init');
    expect(await sharedPresignSessionStore.getSession(presignSessionId)).toBeNull();
  });

  test('forwards cross-instance presign step to owner coordinator', async () => {
    const userId = 'owner-forward-user';
    const rpId = 'example.localhost';
    const participantIds = [1, 2];
    const clientParticipantId = 1;
    const relayerParticipantId = 2;
    const thresholdExpiresAtMs = Date.now() + TEST_THRESHOLD_EXPIRES_IN_MS;

    const clientSigningShare32 = randomSecpSecretKey32();
    const clientVerifyingShare33 = secp256k1.getPublicKey(clientSigningShare32, true);
    const clientVerifyingShareB64u = base64UrlEncode(clientVerifyingShare33);

    const relayerKeyIdDigest32 = await sha256BytesUtf8(
      alphabetizeStringify({
        version: 'threshold_secp256k1_key_id_v1',
        schemeId: THRESHOLD_SECP256K1_ECDSA_2P_V1_SCHEME_ID,
        userId,
        rpId,
        clientVerifyingShareB64u,
      }),
    );
    const relayerKeyId = `secp-${base64UrlEncode(relayerKeyIdDigest32)}`;
    const ecdsaThresholdKeyId = `ecdsa-hss-${base64UrlEncode(relayerKeyIdDigest32)}`;
    const integratedKeyRecord = buildIntegratedKeyRecord({
      ecdsaThresholdKeyId,
      userId,
      rpId,
      participantIds,
      relayerKeyId,
      clientVerifyingShareB64u,
    });

    const sharedPresignSessionStore = new InMemoryThresholdEcdsaPresignSessionStore();
    const sharedPresignaturePool = new InMemoryThresholdEcdsaPresignaturePool();
    const sharedSigningSessionStore = new InMemoryThresholdEcdsaSigningSessionStore();

    const fakeSessionStore = {
      putMpcSession: async () => {},
      takeMpcSession: async () => null,
      putSigningSession: async () => {},
      takeSigningSession: async () => null,
      putCoordinatorSigningSession: async () => {},
      takeCoordinatorSigningSession: async () => null,
    } as const;

    let presignIdCounter = 0;
    const makeHandler = (input: {
      instanceId: string;
      peers?: Array<{ instanceId: string; relayerUrl: string }>;
    }) =>
      new ThresholdEcdsaSigningHandlers({
        logger: {
          debug: () => {},
          info: () => {},
          warn: () => {},
          error: () => {},
        } as any,
        nodeRole: 'coordinator',
        participantIds2p: participantIds,
        clientParticipantId,
        relayerParticipantId,
        coordinatorInstanceId: input.instanceId,
        coordinatorPeers: input.peers,
        sessionStore: fakeSessionStore as any,
        signingSessionStore: sharedSigningSessionStore,
        presignSessionStore: sharedPresignSessionStore,
        presignaturePool: sharedPresignaturePool,
        resolveIntegratedKeyRecord: async ({ ecdsaThresholdKeyId: requested }) =>
          requested === ecdsaThresholdKeyId ? integratedKeyRecord : null,
        ensureReady: async () => {},
        createSigningSessionId: () => `sign-${Date.now()}-${Math.random().toString(16).slice(2)}`,
        createPresignSessionId: () => `presign-forward-${++presignIdCounter}`,
      });

    const handlerA = makeHandler({ instanceId: 'coordinator-a' });
    const handlerB = makeHandler({
      instanceId: 'coordinator-b',
      peers: [{ instanceId: 'coordinator-a', relayerUrl: 'https://relay-a.internal' }],
    });
    const claims = {
      sub: userId,
      rpId,
      relayerKeyId,
      participantIds,
      thresholdExpiresAtMs,
      runtimePolicyScope: TEST_RUNTIME_SCOPE,
    };

    const init = await handlerA.ecdsaPresignInit({
      claims: claims as any,
      request: { ecdsaThresholdKeyId, count: 1 },
    });
    expect(init.ok, JSON.stringify(init)).toBe(true);
    const presignSessionId = String(init.presignSessionId || '');
    expect(presignSessionId).toBeTruthy();

    const originalFetch = globalThis.fetch;
    let forwardedCount = 0;
    globalThis.fetch = (async (url: RequestInfo | URL, init?: RequestInit): Promise<Response> => {
      forwardedCount += 1;
      expect(String(url)).toBe('https://relay-a.internal/threshold-ecdsa/presign/step');
      const headers = new Headers(init?.headers);
      const payload = JSON.parse(String(init?.body || '{}'));
      const result = await handlerA.ecdsaPresignStep({
        claims: claims as any,
        request: payload,
        transport: {
          authorizationHeader: headers.get('authorization') || undefined,
          cookieHeader: headers.get('cookie') || undefined,
          forwardedHop: Number(headers.get('x-threshold-ecdsa-presign-forward-hop') || 0),
        },
      });
      return new Response(JSON.stringify(result), {
        status: result.ok ? 200 : 409,
        headers: { 'content-type': 'application/json' },
      });
    }) as typeof fetch;

    try {
      const step = await handlerB.ecdsaPresignStep({
        claims: claims as any,
        request: {
          presignSessionId,
          stage: 'triples',
          outgoingMessagesB64u: [],
        },
        transport: {
          authorizationHeader: 'Bearer session-token',
        },
      });
      expect(step.ok, JSON.stringify(step)).toBe(true);
      expect(forwardedCount).toBe(1);
      expect(await sharedPresignSessionStore.getSession(presignSessionId)).not.toBeNull();
    } finally {
      globalThis.fetch = originalFetch;
    }
  });

  test('returns stale_session_state when forwarding lacks session auth headers', async () => {
    const userId = 'owner-forward-no-auth-user';
    const rpId = 'example.localhost';
    const participantIds = [1, 2];
    const clientParticipantId = 1;
    const relayerParticipantId = 2;
    const thresholdExpiresAtMs = Date.now() + TEST_THRESHOLD_EXPIRES_IN_MS;

    const clientSigningShare32 = randomSecpSecretKey32();
    const clientVerifyingShare33 = secp256k1.getPublicKey(clientSigningShare32, true);
    const clientVerifyingShareB64u = base64UrlEncode(clientVerifyingShare33);

    const relayerKeyIdDigest32 = await sha256BytesUtf8(
      alphabetizeStringify({
        version: 'threshold_secp256k1_key_id_v1',
        schemeId: THRESHOLD_SECP256K1_ECDSA_2P_V1_SCHEME_ID,
        userId,
        rpId,
        clientVerifyingShareB64u,
      }),
    );
    const relayerKeyId = `secp-${base64UrlEncode(relayerKeyIdDigest32)}`;
    const ecdsaThresholdKeyId = `ecdsa-hss-${base64UrlEncode(relayerKeyIdDigest32)}`;
    const integratedKeyRecord = buildIntegratedKeyRecord({
      ecdsaThresholdKeyId,
      userId,
      rpId,
      participantIds,
      relayerKeyId,
      clientVerifyingShareB64u,
    });

    const sharedPresignSessionStore = new InMemoryThresholdEcdsaPresignSessionStore();
    const sharedPresignaturePool = new InMemoryThresholdEcdsaPresignaturePool();
    const sharedSigningSessionStore = new InMemoryThresholdEcdsaSigningSessionStore();

    const fakeSessionStore = {
      putMpcSession: async () => {},
      takeMpcSession: async () => null,
      putSigningSession: async () => {},
      takeSigningSession: async () => null,
      putCoordinatorSigningSession: async () => {},
      takeCoordinatorSigningSession: async () => null,
    } as const;

    let presignIdCounter = 0;
    const makeHandler = (input: {
      instanceId: string;
      peers?: Array<{ instanceId: string; relayerUrl: string }>;
    }) =>
      new ThresholdEcdsaSigningHandlers({
        logger: {
          debug: () => {},
          info: () => {},
          warn: () => {},
          error: () => {},
        } as any,
        nodeRole: 'coordinator',
        participantIds2p: participantIds,
        clientParticipantId,
        relayerParticipantId,
        coordinatorInstanceId: input.instanceId,
        coordinatorPeers: input.peers,
        sessionStore: fakeSessionStore as any,
        signingSessionStore: sharedSigningSessionStore,
        presignSessionStore: sharedPresignSessionStore,
        presignaturePool: sharedPresignaturePool,
        resolveIntegratedKeyRecord: async ({ ecdsaThresholdKeyId: requested }) =>
          requested === ecdsaThresholdKeyId ? integratedKeyRecord : null,
        ensureReady: async () => {},
        createSigningSessionId: () => `sign-${Date.now()}-${Math.random().toString(16).slice(2)}`,
        createPresignSessionId: () => `presign-forward-no-auth-${++presignIdCounter}`,
      });

    const handlerA = makeHandler({ instanceId: 'coordinator-a' });
    const handlerB = makeHandler({
      instanceId: 'coordinator-b',
      peers: [{ instanceId: 'coordinator-a', relayerUrl: 'https://relay-a.internal' }],
    });
    const claims = {
      sub: userId,
      rpId,
      relayerKeyId,
      participantIds,
      thresholdExpiresAtMs,
      runtimePolicyScope: TEST_RUNTIME_SCOPE,
    };

    const init = await handlerA.ecdsaPresignInit({
      claims: claims as any,
      request: { ecdsaThresholdKeyId, count: 1 },
    });
    expect(init.ok, JSON.stringify(init)).toBe(true);
    const presignSessionId = String(init.presignSessionId || '');
    expect(presignSessionId).toBeTruthy();

    const step = await handlerB.ecdsaPresignStep({
      claims: claims as any,
      request: {
        presignSessionId,
        stage: 'triples',
        outgoingMessagesB64u: [],
      },
      transport: {},
    });
    expect(step.ok).toBe(false);
    expect(step.code).toBe('stale_session_state');
    expect(String(step.message || '')).toContain('missing session auth');

    const persisted = await sharedPresignSessionStore.getSession(presignSessionId);
    expect(persisted).not.toBeNull();
    expect(Number(persisted?.version || 0)).toBe(1);
  });

  test('keeps scope validation precedence over cache miss', async () => {
    const userId = 'strict-scope-user';
    const rpId = 'example.localhost';
    const participantIds = [1, 2];
    const clientParticipantId = 1;
    const relayerParticipantId = 2;
    const thresholdExpiresAtMs = Date.now() + TEST_THRESHOLD_EXPIRES_IN_MS;

    const clientSigningShare32 = randomSecpSecretKey32();
    const clientVerifyingShare33 = secp256k1.getPublicKey(clientSigningShare32, true);
    const clientVerifyingShareB64u = base64UrlEncode(clientVerifyingShare33);

    const relayerKeyIdDigest32 = await sha256BytesUtf8(
      alphabetizeStringify({
        version: 'threshold_secp256k1_key_id_v1',
        schemeId: THRESHOLD_SECP256K1_ECDSA_2P_V1_SCHEME_ID,
        userId,
        rpId,
        clientVerifyingShareB64u,
      }),
    );
    const relayerKeyId = `secp-${base64UrlEncode(relayerKeyIdDigest32)}`;
    const ecdsaThresholdKeyId = `ecdsa-hss-${base64UrlEncode(relayerKeyIdDigest32)}`;
    const integratedKeyRecord = buildIntegratedKeyRecord({
      ecdsaThresholdKeyId,
      userId,
      rpId,
      participantIds,
      relayerKeyId,
      clientVerifyingShareB64u,
    });

    const sharedPresignSessionStore = new InMemoryThresholdEcdsaPresignSessionStore();
    const sharedPresignaturePool = new InMemoryThresholdEcdsaPresignaturePool();
    const sharedSigningSessionStore = new InMemoryThresholdEcdsaSigningSessionStore();

    const fakeSessionStore = {
      putMpcSession: async () => {},
      takeMpcSession: async () => null,
      putSigningSession: async () => {},
      takeSigningSession: async () => null,
      putCoordinatorSigningSession: async () => {},
      takeCoordinatorSigningSession: async () => null,
    } as const;

    let presignIdCounter = 0;
    const makeHandler = () =>
      new ThresholdEcdsaSigningHandlers({
        logger: {
          debug: () => {},
          info: () => {},
          warn: () => {},
          error: () => {},
        } as any,
        nodeRole: 'coordinator',
        participantIds2p: participantIds,
        clientParticipantId,
        relayerParticipantId,
        sessionStore: fakeSessionStore as any,
        signingSessionStore: sharedSigningSessionStore,
        presignSessionStore: sharedPresignSessionStore,
        presignaturePool: sharedPresignaturePool,
        resolveIntegratedKeyRecord: async ({ ecdsaThresholdKeyId: requested }) =>
          requested === ecdsaThresholdKeyId ? integratedKeyRecord : null,
        ensureReady: async () => {},
        createSigningSessionId: () => `sign-${Date.now()}-${Math.random().toString(16).slice(2)}`,
        createPresignSessionId: () => `presign-scope-${++presignIdCounter}`,
      });

    const handlerA = makeHandler();
    const handlerB = makeHandler();
    const validClaims = {
      sub: userId,
      rpId,
      relayerKeyId,
      participantIds,
      thresholdExpiresAtMs,
      runtimePolicyScope: TEST_RUNTIME_SCOPE,
    };

    const init = await handlerA.ecdsaPresignInit({
      claims: validClaims as any,
      request: { ecdsaThresholdKeyId, count: 1 },
    });
    expect(init.ok, JSON.stringify(init)).toBe(true);
    const presignSessionId = String(init.presignSessionId || '');
    expect(presignSessionId).toBeTruthy();

    const wrongScopeClaims = {
      ...validClaims,
      sub: 'different-user',
    };
    const step = await handlerB.ecdsaPresignStep({
      claims: wrongScopeClaims as any,
      request: {
        presignSessionId,
        stage: 'triples',
        outgoingMessagesB64u: [],
      },
    });
    expect(step.ok).toBe(false);
    expect(step.code).toBe('unauthorized');
    expect(String(step.message || '')).toContain('does not match threshold session scope');
    expect(await sharedPresignSessionStore.getSession(presignSessionId)).toBeNull();
  });

  test('rejects stage regression once presign stage has started', async () => {
    const userId = 'stage-regression-user';
    const rpId = 'example.localhost';
    const participantIds = [1, 2];
    const clientParticipantId = 1;
    const relayerParticipantId = 2;
    const thresholdExpiresAtMs = Date.now() + TEST_THRESHOLD_EXPIRES_IN_MS;

    const clientSigningShare32 = randomSecpSecretKey32();
    const clientVerifyingShare33 = secp256k1.getPublicKey(clientSigningShare32, true);
    const clientVerifyingShareB64u = base64UrlEncode(clientVerifyingShare33);

    const relayerKeyIdDigest32 = await sha256BytesUtf8(
      alphabetizeStringify({
        version: 'threshold_secp256k1_key_id_v1',
        schemeId: THRESHOLD_SECP256K1_ECDSA_2P_V1_SCHEME_ID,
        userId,
        rpId,
        clientVerifyingShareB64u,
      }),
    );
    const relayerKeyId = `secp-${base64UrlEncode(relayerKeyIdDigest32)}`;
    const ecdsaThresholdKeyId = `ecdsa-hss-${base64UrlEncode(relayerKeyIdDigest32)}`;
    const integratedKeyRecord = buildIntegratedKeyRecord({
      ecdsaThresholdKeyId,
      userId,
      rpId,
      participantIds,
      relayerKeyId,
      clientVerifyingShareB64u,
    });

    const relayerSigningShare32 = deriveFixtureRelayerSecp256k1SigningShare32({
      relayerShareSeedB64u: TEST_RELAYER_SHARE_SEED_B64U,
      relayerKeyId,
    });
    const relayerVerifyingShare33 = secp256k1.getPublicKey(relayerSigningShare32, true);
    const groupPublicKey33 = sumSecpPublicKeysCompressed(
      clientVerifyingShare33,
      relayerVerifyingShare33,
    );

    const sharedPresignSessionStore = new InMemoryThresholdEcdsaPresignSessionStore();
    const sharedPresignaturePool = new InMemoryThresholdEcdsaPresignaturePool();
    const sharedSigningSessionStore = new InMemoryThresholdEcdsaSigningSessionStore();

    const fakeSessionStore = {
      putMpcSession: async () => {},
      takeMpcSession: async () => null,
      putSigningSession: async () => {},
      takeSigningSession: async () => null,
      putCoordinatorSigningSession: async () => {},
      takeCoordinatorSigningSession: async () => null,
    } as const;

    let presignIdCounter = 0;
    const handler = new ThresholdEcdsaSigningHandlers({
      logger: {
        debug: () => {},
        info: () => {},
        warn: () => {},
        error: () => {},
      } as any,
      nodeRole: 'coordinator',
      participantIds2p: participantIds,
      clientParticipantId,
      relayerParticipantId,
      sessionStore: fakeSessionStore as any,
      signingSessionStore: sharedSigningSessionStore,
      presignSessionStore: sharedPresignSessionStore,
      presignaturePool: sharedPresignaturePool,
      resolveIntegratedKeyRecord: async ({ ecdsaThresholdKeyId: requested }) =>
        requested === ecdsaThresholdKeyId ? integratedKeyRecord : null,
      ensureReady: async () => {},
      createSigningSessionId: () => `sign-${Date.now()}-${Math.random().toString(16).slice(2)}`,
      createPresignSessionId: () => `presign-stage-regression-${++presignIdCounter}`,
    });

    const claims = {
      sub: userId,
      rpId,
      relayerKeyId,
      participantIds,
      thresholdExpiresAtMs,
      runtimePolicyScope: TEST_RUNTIME_SCOPE,
    };

    const init = await handler.ecdsaPresignInit({
      claims: claims as any,
      request: { ecdsaThresholdKeyId, count: 1 },
    });
    expect(init.ok, JSON.stringify(init)).toBe(true);
    const presignSessionId = String(init.presignSessionId || '');
    expect(presignSessionId).toBeTruthy();

    const localClientThresholdShare32 = mapAdditiveShareToThresholdSignaturesShare2p({
      additiveShare32: clientSigningShare32,
      participantId: clientParticipantId,
    });
    const localSession = new ThresholdEcdsaPresignSession(
      new Uint32Array(participantIds),
      clientParticipantId,
      2,
      localClientThresholdShare32,
      groupPublicKey33,
    );

    let stageForServer: 'triples' | 'presign' = 'triples';
    let pendingClientOutgoing = pollSession(localSession).outgoingMessages;
    let pendingServerOutgoing = (init.outgoingMessagesB64u || []).map((msg) =>
      base64UrlDecode(msg),
    );
    let reachedServerPresignStage = false;

    const MAX_STEPS = 64;
    for (let i = 0; i < MAX_STEPS; i += 1) {
      if (pendingServerOutgoing.length > 0) {
        if (stageForServer === 'presign' && localSession.stage() === 'triples_done') {
          localSession.start_presign();
        }
        for (const msg of pendingServerOutgoing) {
          localSession.message(relayerParticipantId, msg);
        }
        pendingServerOutgoing = [];
        const polled = pollSession(localSession);
        pendingClientOutgoing.push(...polled.outgoingMessages);
        if (
          polled.stage === 'triples_done' ||
          polled.stage === 'presign' ||
          polled.stage === 'done'
        ) {
          stageForServer = 'presign';
        }
      }

      const step = await handler.ecdsaPresignStep({
        claims: claims as any,
        request: {
          presignSessionId,
          stage: stageForServer,
          outgoingMessagesB64u: pendingClientOutgoing.map((msg) => base64UrlEncode(msg)),
        },
      });
      expect(step.ok, JSON.stringify(step)).toBe(true);
      pendingClientOutgoing = [];
      pendingServerOutgoing = (step.outgoingMessagesB64u || []).map((msg) => base64UrlDecode(msg));
      if (step.stage === 'presign' && step.event !== 'presign_done') {
        reachedServerPresignStage = true;
        break;
      }
      if (step.event === 'triples_done' || step.stage === 'presign') {
        stageForServer = 'presign';
      }
      if (step.event === 'presign_done' || step.stage === 'done') {
        break;
      }
    }

    expect(reachedServerPresignStage).toBe(true);

    const regressed = await handler.ecdsaPresignStep({
      claims: claims as any,
      request: {
        presignSessionId,
        stage: 'triples',
        outgoingMessagesB64u: [],
      },
    });
    expect(regressed.ok).toBe(false);
    expect(regressed.code).toBe('invalid_body');
    expect(String(regressed.message || '')).toContain('stage regression is not allowed');
  });

  test('sign/init honors client-selected presignature and preserves other pool items', async () => {
    const relayerKeyId = 'secp-test-relayer-key';
    const ecdsaThresholdKeyId = 'ecdsa-hss-test-signinit-select';
    const userId = 'user-select';
    const rpId = 'example.localhost';
    const participantIds = [1, 2];
    const clientSigningShare32 = randomSecpSecretKey32();
    const clientVerifyingShareB64u = base64UrlEncode(
      secp256k1.getPublicKey(clientSigningShare32, true),
    );
    const digest32 = new Uint8Array(32).fill(7);
    const signingDigestB64u = base64UrlEncode(digest32);
    const mpcSessionId = 'mpc-signinit-select';
    const integratedKeyRecord = buildIntegratedKeyRecord({
      ecdsaThresholdKeyId,
      userId,
      rpId,
      participantIds,
      relayerKeyId,
      clientVerifyingShareB64u,
    });

    const firstRecord = {
      relayerKeyId,
      presignatureId: 'ps-first',
      bigRB64u: base64UrlEncode(new Uint8Array(33).fill(11)),
      kShareB64u: base64UrlEncode(new Uint8Array(32).fill(12)),
      sigmaShareB64u: base64UrlEncode(new Uint8Array(32).fill(13)),
      createdAtMs: Date.now() - 2,
    };
    const secondRecord = {
      relayerKeyId,
      presignatureId: 'ps-second',
      bigRB64u: base64UrlEncode(new Uint8Array(33).fill(21)),
      kShareB64u: base64UrlEncode(new Uint8Array(32).fill(22)),
      sigmaShareB64u: base64UrlEncode(new Uint8Array(32).fill(23)),
      createdAtMs: Date.now() - 1,
    };

    const sharedPresignaturePool = new InMemoryThresholdEcdsaPresignaturePool();
    await sharedPresignaturePool.put(firstRecord as any);
    await sharedPresignaturePool.put(secondRecord as any);

    const sharedSigningSessionStore = new InMemoryThresholdEcdsaSigningSessionStore();
    const sharedPresignSessionStore = new InMemoryThresholdEcdsaPresignSessionStore();

    const mpcSessions = new Map<string, unknown>([
      [
        mpcSessionId,
        {
          expiresAtMs: Date.now() + 120_000,
          relayerKeyId,
          ecdsaThresholdKeyId,
          purpose: 'test-sign-init-select',
          intentDigestB64u: signingDigestB64u,
          signingDigestB64u,
          userId,
          rpId,
          clientVerifyingShareB64u,
          participantIds,
          signingRootId: TEST_SIGNING_ROOT_ID,
          walletKeyVersion: 'v1',
          derivationVersion: 1,
        },
      ],
    ]);

    const fakeSessionStore = {
      putMpcSession: async () => {},
      takeMpcSession: async (id: string) => {
        const rec = mpcSessions.get(id) || null;
        mpcSessions.delete(id);
        return rec as any;
      },
      putSigningSession: async () => {},
      takeSigningSession: async () => null,
      putCoordinatorSigningSession: async () => {},
      takeCoordinatorSigningSession: async () => null,
    } as const;

    const handler = new ThresholdEcdsaSigningHandlers({
      logger: console as any,
      nodeRole: 'coordinator',
      participantIds2p: [1, 2],
      clientParticipantId: 1,
      relayerParticipantId: 2,
      sessionStore: fakeSessionStore as any,
      signingSessionStore: sharedSigningSessionStore,
      presignSessionStore: sharedPresignSessionStore,
      presignaturePool: sharedPresignaturePool,
      resolveIntegratedKeyRecord: async ({ ecdsaThresholdKeyId: requested }) =>
        requested === ecdsaThresholdKeyId ? integratedKeyRecord : null,
      ensureReady: async () => {},
      createSigningSessionId: () => `sign-${Date.now()}-${Math.random().toString(16).slice(2)}`,
      createPresignSessionId: () => `presign-${Date.now()}-${Math.random().toString(16).slice(2)}`,
    });

    const signInit = await handler.ecdsaSignInit({
      mpcSessionId,
      relayerKeyId,
      signingDigestB64u,
      clientRound1: { presignatureId: secondRecord.presignatureId },
    });
    expect(signInit.ok, JSON.stringify(signInit)).toBe(true);
    expect(signInit.relayerRound1?.presignatureId).toBe(secondRecord.presignatureId);
    expect(signInit.relayerRound1?.bigRB64u).toBe(secondRecord.bigRB64u);

    const selectedReserved = await sharedPresignaturePool.consume(
      relayerKeyId,
      secondRecord.presignatureId,
    );
    expect(selectedReserved?.presignatureId).toBe(secondRecord.presignatureId);

    const remaining = await sharedPresignaturePool.reserve(relayerKeyId);
    expect(remaining?.presignatureId).toBe(firstRecord.presignatureId);
  });
});
