import { test, expect } from '@playwright/test';
import { createHash, hkdfSync } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { secp256k1 } from '@noble/curves/secp256k1.js';
import { bytesToNumberBE, numberToBytesBE } from '../../shared/src/utils/bigint';
import { alphabetizeStringify, sha256BytesUtf8 } from '../../shared/src/utils/digests';
import { base64UrlDecode, base64UrlEncode } from '../../shared/src/utils/encoders';
import { SECP256K1_ORDER } from '../../shared/src/threshold/secp256k1';
import { THRESHOLD_SECP256K1_ECDSA_2P_V1_SCHEME_ID } from '../../server/src/core/ThresholdService/schemes/schemeIds';
import { ThresholdEcdsaSigningHandlers } from '../../server/src/core/ThresholdService/ecdsaSigningHandlers';
import {
  InMemoryThresholdEcdsaPresignSessionStore,
  InMemoryThresholdEcdsaPresignaturePool,
  InMemoryThresholdEcdsaSigningSessionStore,
} from '../../server/src/core/ThresholdService/stores/EcdsaSigningStore';
import {
  ThresholdEcdsaPresignSession,
  initSync as initEthSignerWasmSync,
  map_additive_share_to_threshold_signatures_share_2p,
} from '../../wasm/eth_signer/pkg/eth_signer.js';

const ETH_SIGNER_WASM_URL = new URL(
  '../../wasm/eth_signer/pkg/eth_signer_bg.wasm',
  import.meta.url,
);
const TEST_RELAYER_SHARE_SEED_B64U = Buffer.from(new Uint8Array(32).fill(9)).toString('base64url');
const TEST_THRESHOLD_EXPIRES_IN_MS = 10 * 60_000;
const TEST_RUNTIME_SCOPE = {
  orgId: 'org-alpha',
  projectId: 'project-alpha',
  envId: 'env-alpha',
  signingRootVersion: 'root-v1',
} as const;
const TEST_SIGNING_ROOT_ID = `${TEST_RUNTIME_SCOPE.projectId}:${TEST_RUNTIME_SCOPE.envId}`;
const TEST_ECDSA_PRESIGN_POOL_KEY_VERSION = 'v2';
const TEST_ECDSA_ROLE_LOCAL_WALLET_KEY_VERSION = 'v1';
const TEST_ECDSA_ROLE_LOCAL_DERIVATION_VERSION = 1;
const TEST_ECDSA_CHAIN_TARGET = {
  kind: 'evm',
  namespace: 'eip155',
  chainId: 11155111,
  networkSlug: 'sepolia',
} as const;

let ethSignerWasmInitialized = false;

function ensureEthSignerWasm(): void {
  if (ethSignerWasmInitialized) return;
  initEthSignerWasmSync({ module: readFileSync(ETH_SIGNER_WASM_URL) });
  ethSignerWasmInitialized = true;
}

test.beforeAll(() => {
  ensureEthSignerWasm();
});

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

function mapAdditiveShareToThresholdSignaturesShare2p(args: {
  additiveShare32: Uint8Array;
  participantId: number;
}): Uint8Array {
  return map_additive_share_to_threshold_signatures_share_2p(
    args.additiveShare32,
    args.participantId,
  );
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

function buildRoleLocalKeyRecord(input: {
  ecdsaThresholdKeyId: string;
  keyHandle?: string;
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
  const relayerMappedPrivateShare32 = mapAdditiveShareToThresholdSignaturesShare2p({
    additiveShare32: relayerSigningShare32,
    participantId: 2,
  });
  const nowMs = Date.now();
  return {
    version: 'threshold_ecdsa_hss_role_local_v2' as const,
    ecdsaThresholdKeyId: input.ecdsaThresholdKeyId,
    keyHandle: input.keyHandle || `ehss-key-${input.ecdsaThresholdKeyId}`,
    walletId: input.userId,
    rpId: input.rpId,
    signingRootId: TEST_SIGNING_ROOT_ID,
    signingRootVersion: TEST_RUNTIME_SCOPE.signingRootVersion,
    keyScope: 'evm-family' as const,
    relayerKeyId: input.relayerKeyId,
    contextBinding32B64u: base64UrlEncode(new Uint8Array(32).fill(3)),
    relayerShare32B64u: base64UrlEncode(relayerSigningShare32),
    relayerPublicKey33B64u: base64UrlEncode(relayerVerifyingShare33),
    clientPublicKey33B64u: input.clientVerifyingShareB64u,
    groupPublicKey33B64u: base64UrlEncode(groupPublicKey33),
    ethereumAddress: `0x${'11'.repeat(20)}`,
    relayerCaitSithInput: {
      participantId: 2 as const,
      mappedPrivateShare32B64u: base64UrlEncode(relayerMappedPrivateShare32),
      verifyingShare33B64u: base64UrlEncode(relayerVerifyingShare33),
    },
    publicTranscriptDigest32B64u: base64UrlEncode(new Uint8Array(32).fill(4)),
    createdAtMs: nowMs,
    updatedAtMs: nowMs,
  };
}

function presignPoolKeyPart(value: string | number, fieldName: string): string {
  const normalized = typeof value === 'number' ? String(value) : value.trim();
  if (!normalized) throw new Error(`${fieldName} is required for test presign pool key`);
  return encodeURIComponent(normalized);
}

function presignPoolKeyForRoleLocalKey(
  roleLocalKey: ReturnType<typeof buildRoleLocalKeyRecord>,
): string {
  return [
    TEST_ECDSA_PRESIGN_POOL_KEY_VERSION,
    `keyHandle=${presignPoolKeyPart(roleLocalKey.keyHandle, 'keyHandle')}`,
    `ecdsaThresholdKeyId=${presignPoolKeyPart(
      roleLocalKey.ecdsaThresholdKeyId,
      'ecdsaThresholdKeyId',
    )}`,
    `relayerKeyId=${presignPoolKeyPart(roleLocalKey.relayerKeyId, 'relayerKeyId')}`,
    `signingRootId=${presignPoolKeyPart(roleLocalKey.signingRootId, 'signingRootId')}`,
    `signingRootVersion=${presignPoolKeyPart(
      roleLocalKey.signingRootVersion || 'default',
      'signingRootVersion',
    )}`,
    `walletKeyVersion=${presignPoolKeyPart(
      TEST_ECDSA_ROLE_LOCAL_WALLET_KEY_VERSION,
      'walletKeyVersion',
    )}`,
    `derivationVersion=${presignPoolKeyPart(
      TEST_ECDSA_ROLE_LOCAL_DERIVATION_VERSION,
      'derivationVersion',
    )}`,
    `groupPublicKey=${presignPoolKeyPart(
      roleLocalKey.groupPublicKey33B64u,
      'groupPublicKey',
    )}`,
  ].join('|');
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
    const keyHandle = `ehss-key-${base64UrlEncode(relayerKeyIdDigest32)}`;
    const roleLocalKeyRecord = {
      ...buildRoleLocalKeyRecord({
        ecdsaThresholdKeyId,
        userId,
        rpId,
        participantIds,
        relayerKeyId,
        clientVerifyingShareB64u,
      }),
      keyHandle,
    };

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
        resolveRoleLocalKeyRecord: async (selector) => {
          switch (selector.kind) {
            case 'key_handle':
              return selector.keyHandle === keyHandle ? roleLocalKeyRecord : null;
          }
        },
        ensureReady: async () => {},
        createSigningSessionId: () => `sign-${Date.now()}-${Math.random().toString(16).slice(2)}`,
        createPresignSessionId: () => `presign-${++presignIdCounter}`,
      });

    const handlerA = makeHandler();

    const claims = {
      walletId: userId,
      rpId,
      relayerKeyId,
      keyHandle,
      ecdsaThresholdKeyId,
      participantIds,
      thresholdExpiresAtMs,
      runtimePolicyScope: TEST_RUNTIME_SCOPE,
    };

    const init = await handlerA.ecdsaPresignInit({
      claims: claims as any,
      request: { keyHandle: roleLocalKeyRecord.keyHandle, count: 1 },
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

    const reserved = await sharedPresignaturePool.reserve(
      presignPoolKeyForRoleLocalKey(roleLocalKeyRecord),
    );
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
    const roleLocalKeyRecord = buildRoleLocalKeyRecord({
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
        resolveRoleLocalKeyRecord: async ({ keyHandle: requested }) =>
          requested === roleLocalKeyRecord.keyHandle ? roleLocalKeyRecord : null,
        ensureReady: async () => {},
        createSigningSessionId: () => `sign-${Date.now()}-${Math.random().toString(16).slice(2)}`,
        createPresignSessionId: () => `presign-cache-miss-${++presignIdCounter}`,
      });

    const handlerA = makeHandler();
    const handlerB = makeHandler();
    const claims = {
      walletId: userId,
      rpId,
      relayerKeyId,
      keyHandle: roleLocalKeyRecord.keyHandle,
      ecdsaThresholdKeyId,
      participantIds,
      thresholdExpiresAtMs,
      runtimePolicyScope: TEST_RUNTIME_SCOPE,
    };

    const init = await handlerA.ecdsaPresignInit({
      claims: claims as any,
      request: { keyHandle: roleLocalKeyRecord.keyHandle, count: 1 },
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
    const roleLocalKeyRecord = buildRoleLocalKeyRecord({
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
        resolveRoleLocalKeyRecord: async ({ keyHandle: requested }) =>
          requested === roleLocalKeyRecord.keyHandle ? roleLocalKeyRecord : null,
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
      walletId: userId,
      rpId,
      relayerKeyId,
      keyHandle: roleLocalKeyRecord.keyHandle,
      ecdsaThresholdKeyId,
      participantIds,
      thresholdExpiresAtMs,
      runtimePolicyScope: TEST_RUNTIME_SCOPE,
    };

    const init = await handlerA.ecdsaPresignInit({
      claims: claims as any,
      request: { keyHandle: roleLocalKeyRecord.keyHandle, count: 1 },
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
    const roleLocalKeyRecord = buildRoleLocalKeyRecord({
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
        resolveRoleLocalKeyRecord: async ({ keyHandle: requested }) =>
          requested === roleLocalKeyRecord.keyHandle ? roleLocalKeyRecord : null,
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
      walletId: userId,
      rpId,
      relayerKeyId,
      keyHandle: roleLocalKeyRecord.keyHandle,
      ecdsaThresholdKeyId,
      participantIds,
      thresholdExpiresAtMs,
      runtimePolicyScope: TEST_RUNTIME_SCOPE,
    };

    const init = await handlerA.ecdsaPresignInit({
      claims: claims as any,
      request: { keyHandle: roleLocalKeyRecord.keyHandle, count: 1 },
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
    const roleLocalKeyRecord = buildRoleLocalKeyRecord({
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
        resolveRoleLocalKeyRecord: async ({ keyHandle: requested }) =>
          requested === roleLocalKeyRecord.keyHandle ? roleLocalKeyRecord : null,
        ensureReady: async () => {},
        createSigningSessionId: () => `sign-${Date.now()}-${Math.random().toString(16).slice(2)}`,
        createPresignSessionId: () => `presign-scope-${++presignIdCounter}`,
      });

    const handlerA = makeHandler();
    const handlerB = makeHandler();
    const validClaims = {
      walletId: userId,
      rpId,
      relayerKeyId,
      keyHandle: roleLocalKeyRecord.keyHandle,
      ecdsaThresholdKeyId,
      participantIds,
      thresholdExpiresAtMs,
      runtimePolicyScope: TEST_RUNTIME_SCOPE,
    };

    const init = await handlerA.ecdsaPresignInit({
      claims: validClaims as any,
      request: { keyHandle: roleLocalKeyRecord.keyHandle, count: 1 },
    });
    expect(init.ok, JSON.stringify(init)).toBe(true);
    const presignSessionId = String(init.presignSessionId || '');
    expect(presignSessionId).toBeTruthy();

    const wrongScopeClaims = {
      ...validClaims,
      walletId: 'different-user',
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

  test('burns presign session on relayer key mismatch', async () => {
    const userId = 'relayer-mismatch-user';
    const rpId = 'example.localhost';
    const participantIds = [1, 2];
    const clientParticipantId = 1;
    const relayerParticipantId = 2;
    const thresholdExpiresAtMs = Date.now() + TEST_THRESHOLD_EXPIRES_IN_MS;

    const clientSigningShare32 = randomSecpSecretKey32();
    const clientVerifyingShareB64u = base64UrlEncode(
      secp256k1.getPublicKey(clientSigningShare32, true),
    );
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
    const roleLocalKeyRecord = buildRoleLocalKeyRecord({
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
    } as const;
    let presignIdCounter = 0;
    const handler = new ThresholdEcdsaSigningHandlers({
      logger: { debug: () => {}, info: () => {}, warn: () => {}, error: () => {} } as any,
      nodeRole: 'coordinator',
      participantIds2p: participantIds,
      clientParticipantId,
      relayerParticipantId,
      sessionStore: fakeSessionStore as any,
      signingSessionStore: sharedSigningSessionStore,
      presignSessionStore: sharedPresignSessionStore,
      presignaturePool: sharedPresignaturePool,
      resolveRoleLocalKeyRecord: async ({ keyHandle: requested }) =>
        requested === roleLocalKeyRecord.keyHandle ? roleLocalKeyRecord : null,
      ensureReady: async () => {},
      createSigningSessionId: () => `sign-${Date.now()}-${Math.random().toString(16).slice(2)}`,
      createPresignSessionId: () => `presign-relayer-mismatch-${++presignIdCounter}`,
    });
    const claims = {
      walletId: userId,
      rpId,
      relayerKeyId,
      keyHandle: roleLocalKeyRecord.keyHandle,
      ecdsaThresholdKeyId,
      participantIds,
      thresholdExpiresAtMs,
      runtimePolicyScope: TEST_RUNTIME_SCOPE,
    };

    const init = await handler.ecdsaPresignInit({
      claims: claims as any,
      request: { keyHandle: roleLocalKeyRecord.keyHandle, count: 1 },
    });
    expect(init.ok, JSON.stringify(init)).toBe(true);
    const presignSessionId = String(init.presignSessionId || '');
    expect(presignSessionId).toBeTruthy();

    const step = await handler.ecdsaPresignStep({
      claims: { ...claims, relayerKeyId: 'different-relayer-key' } as any,
      request: { presignSessionId, stage: 'triples', outgoingMessagesB64u: [] },
    });
    expect(step.ok).toBe(false);
    expect(step.code).toBe('unauthorized');
    expect(String(step.message || '')).toContain('does not match threshold session scope');
    expect(await sharedPresignSessionStore.getSession(presignSessionId)).toBeNull();
  });

  test('burns presign session after malformed protocol message', async () => {
    const userId = 'malformed-protocol-user';
    const rpId = 'example.localhost';
    const participantIds = [1, 2];
    const clientParticipantId = 1;
    const relayerParticipantId = 2;
    const thresholdExpiresAtMs = Date.now() + TEST_THRESHOLD_EXPIRES_IN_MS;

    const clientSigningShare32 = randomSecpSecretKey32();
    const clientVerifyingShareB64u = base64UrlEncode(
      secp256k1.getPublicKey(clientSigningShare32, true),
    );
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
    const roleLocalKeyRecord = buildRoleLocalKeyRecord({
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
    const handler = new ThresholdEcdsaSigningHandlers({
      logger: { debug: () => {}, info: () => {}, warn: () => {}, error: () => {} } as any,
      nodeRole: 'coordinator',
      participantIds2p: participantIds,
      clientParticipantId,
      relayerParticipantId,
      sessionStore: { putMpcSession: async () => {}, takeMpcSession: async () => null } as any,
      signingSessionStore: sharedSigningSessionStore,
      presignSessionStore: sharedPresignSessionStore,
      presignaturePool: sharedPresignaturePool,
      resolveRoleLocalKeyRecord: async ({ keyHandle: requested }) =>
        requested === roleLocalKeyRecord.keyHandle ? roleLocalKeyRecord : null,
      ensureReady: async () => {},
      createSigningSessionId: () => `sign-${Date.now()}-${Math.random().toString(16).slice(2)}`,
      createPresignSessionId: () => `presign-malformed-${Date.now()}`,
    });
    const claims = {
      walletId: userId,
      rpId,
      relayerKeyId,
      keyHandle: roleLocalKeyRecord.keyHandle,
      ecdsaThresholdKeyId,
      participantIds,
      thresholdExpiresAtMs,
      runtimePolicyScope: TEST_RUNTIME_SCOPE,
    };
    const init = await handler.ecdsaPresignInit({
      claims: claims as any,
      request: { keyHandle: roleLocalKeyRecord.keyHandle, count: 1 },
    });
    expect(init.ok, JSON.stringify(init)).toBe(true);
    const presignSessionId = String(init.presignSessionId || '');
    expect(presignSessionId).toBeTruthy();

    const step = await handler.ecdsaPresignStep({
      claims: claims as any,
      request: {
        presignSessionId,
        stage: 'triples',
        outgoingMessagesB64u: ['#'],
      },
    });
    expect(step.ok).toBe(false);
    expect(step.code).toBe('invalid_body');
    expect(String(step.message || '')).toContain('invalid base64url');
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
    const roleLocalKeyRecord = buildRoleLocalKeyRecord({
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
      resolveRoleLocalKeyRecord: async ({ keyHandle: requested }) =>
        requested === roleLocalKeyRecord.keyHandle ? roleLocalKeyRecord : null,
      ensureReady: async () => {},
      createSigningSessionId: () => `sign-${Date.now()}-${Math.random().toString(16).slice(2)}`,
      createPresignSessionId: () => `presign-stage-regression-${++presignIdCounter}`,
    });

    const claims = {
      walletId: userId,
      rpId,
      relayerKeyId,
      keyHandle: roleLocalKeyRecord.keyHandle,
      ecdsaThresholdKeyId,
      participantIds,
      thresholdExpiresAtMs,
      runtimePolicyScope: TEST_RUNTIME_SCOPE,
    };

    const init = await handler.ecdsaPresignInit({
      claims: claims as any,
      request: { keyHandle: roleLocalKeyRecord.keyHandle, count: 1 },
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
    const roleLocalKeyRecord = buildRoleLocalKeyRecord({
      ecdsaThresholdKeyId,
      userId,
      rpId,
      participantIds,
      relayerKeyId,
      clientVerifyingShareB64u,
    });
    const presignPoolKey = presignPoolKeyForRoleLocalKey(roleLocalKeyRecord);

    const firstRecord = {
      relayerKeyId: presignPoolKey,
      presignatureId: 'ps-first',
      bigRB64u: base64UrlEncode(new Uint8Array(33).fill(11)),
      kShareB64u: base64UrlEncode(new Uint8Array(32).fill(12)),
      sigmaShareB64u: base64UrlEncode(new Uint8Array(32).fill(13)),
      createdAtMs: Date.now() - 2,
    };
    const secondRecord = {
      relayerKeyId: presignPoolKey,
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
          keyHandle: roleLocalKeyRecord.keyHandle,
          purpose: 'test-sign-init-select',
          intentDigestB64u: signingDigestB64u,
          signingDigestB64u,
          walletSessionUserId: userId,
          rpId,
          clientVerifyingShareB64u,
          participantIds,
          signingRootId: TEST_SIGNING_ROOT_ID,
          signingRootVersion: TEST_RUNTIME_SCOPE.signingRootVersion,
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
      resolveRoleLocalKeyRecord: async ({ keyHandle: requested }) =>
        requested === roleLocalKeyRecord.keyHandle ? roleLocalKeyRecord : null,
      ensureReady: async () => {},
      createSigningSessionId: () => `sign-${Date.now()}-${Math.random().toString(16).slice(2)}`,
      createPresignSessionId: () => `presign-${Date.now()}-${Math.random().toString(16).slice(2)}`,
    });

    const relayerMismatchMpcSessionId = 'mpc-signinit-relayer-mismatch';
    mpcSessions.set(relayerMismatchMpcSessionId, {
      ...(mpcSessions.get(mpcSessionId) as Record<string, unknown>),
      purpose: 'test-sign-init-relayer-mismatch',
    });
    const relayerMismatch = await handler.ecdsaSignInit({
      mpcSessionId: relayerMismatchMpcSessionId,
      relayerKeyId: `${relayerKeyId}:rotated`,
      signingDigestB64u,
      clientRound1: { presignatureId: secondRecord.presignatureId },
    });
    expect(relayerMismatch).toMatchObject({
      ok: false,
      code: 'unauthorized',
    });
    expect(String(relayerMismatch.message || '')).toContain(
      'relayerKeyId does not match mpcSessionId scope',
    );

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
      presignPoolKey,
      secondRecord.presignatureId,
    );
    expect(selectedReserved?.presignatureId).toBe(secondRecord.presignatureId);

    const remaining = await sharedPresignaturePool.reserve(presignPoolKey);
    expect(remaining?.presignatureId).toBe(firstRecord.presignatureId);
  });

  test('sign/init cannot consume presignature from key-only namespace with same key handle', async () => {
    const relayerKeyId = 'shared-relayer-key';
    const sharedKeyHandle = 'ehss-shared-key-handle';
    const rpId = 'example.localhost';
    const participantIds = [1, 2];
    const digest32 = new Uint8Array(32).fill(31);
    const signingDigestB64u = base64UrlEncode(digest32);
    const clientShareA32 = randomSecpSecretKey32();
    const clientShareB32 = randomSecpSecretKey32();
    const clientVerifyingShareAB64u = base64UrlEncode(secp256k1.getPublicKey(clientShareA32, true));
    const clientVerifyingShareBB64u = base64UrlEncode(secp256k1.getPublicKey(clientShareB32, true));
    const keyA = buildRoleLocalKeyRecord({
      ecdsaThresholdKeyId: 'ecdsa-hss-key-a',
      keyHandle: sharedKeyHandle,
      userId: 'user-a',
      rpId,
      participantIds,
      relayerKeyId,
      clientVerifyingShareB64u: clientVerifyingShareAB64u,
    });
    const keyB = buildRoleLocalKeyRecord({
      ecdsaThresholdKeyId: 'ecdsa-hss-key-b',
      keyHandle: sharedKeyHandle,
      userId: 'user-b',
      rpId,
      participantIds,
      relayerKeyId,
      clientVerifyingShareB64u: clientVerifyingShareBB64u,
    });
    expect(presignPoolKeyForRoleLocalKey(keyA)).not.toBe(presignPoolKeyForRoleLocalKey(keyB));

    const sharedPresignaturePool = new InMemoryThresholdEcdsaPresignaturePool();
    await sharedPresignaturePool.put({
      relayerKeyId: `keyHandle:${sharedKeyHandle}`,
      presignatureId: 'ps-key-a',
      bigRB64u: base64UrlEncode(new Uint8Array(33).fill(41)),
      kShareB64u: base64UrlEncode(new Uint8Array(32).fill(42)),
      sigmaShareB64u: base64UrlEncode(new Uint8Array(32).fill(43)),
      createdAtMs: Date.now(),
    });

    const mpcSessionId = 'mpc-cross-key';
    const mpcSessions = new Map<string, any>([
      [
        mpcSessionId,
        {
          expiresAtMs: Date.now() + 120_000,
          relayerKeyId,
          ecdsaThresholdKeyId: keyB.ecdsaThresholdKeyId,
          keyHandle: keyB.keyHandle,
          purpose: 'test-cross-key',
          intentDigestB64u: signingDigestB64u,
          signingDigestB64u,
          walletSessionUserId: keyB.walletId,
          rpId,
          clientVerifyingShareB64u: keyB.clientPublicKey33B64u,
          participantIds,
          signingRootId: TEST_SIGNING_ROOT_ID,
          signingRootVersion: TEST_RUNTIME_SCOPE.signingRootVersion,
          walletKeyVersion: 'v1',
          derivationVersion: 1,
        },
      ],
    ]);
    let restoredMpcSession = false;
    const handler = new ThresholdEcdsaSigningHandlers({
      logger: { debug: () => {}, info: () => {}, warn: () => {}, error: () => {} } as any,
      nodeRole: 'coordinator',
      participantIds2p: participantIds,
      clientParticipantId: 1,
      relayerParticipantId: 2,
      sessionStore: {
        takeMpcSession: async (id: string) => {
          const record = mpcSessions.get(id) || null;
          mpcSessions.delete(id);
          return record;
        },
        putMpcSession: async (id: string, record: any) => {
          restoredMpcSession = true;
          mpcSessions.set(id, record);
        },
      },
      signingSessionStore: new InMemoryThresholdEcdsaSigningSessionStore(),
      presignSessionStore: new InMemoryThresholdEcdsaPresignSessionStore(),
      presignaturePool: sharedPresignaturePool,
      resolveRoleLocalKeyRecord: async ({ keyHandle: requested }) => {
        if (requested === keyB.keyHandle) return keyB;
        return null;
      },
      ensureReady: async () => {},
      createSigningSessionId: () => `sign-${Date.now()}-${Math.random().toString(16).slice(2)}`,
      createPresignSessionId: () => `presign-${Date.now()}-${Math.random().toString(16).slice(2)}`,
    });

    const signInit = await handler.ecdsaSignInit({
      mpcSessionId,
      relayerKeyId,
      signingDigestB64u,
      clientRound1: { presignatureId: 'ps-key-a' },
    });
    expect(signInit.ok).toBe(false);
    expect(signInit.code).toBe('pool_empty');
    expect(restoredMpcSession).toBe(true);
    expect(mpcSessions.has(mpcSessionId)).toBe(true);

    const stillAvailableForKeyA = await sharedPresignaturePool.reserve(
      `keyHandle:${sharedKeyHandle}`,
    );
    expect(stillAvailableForKeyA?.presignatureId).toBe('ps-key-a');
  });
});
