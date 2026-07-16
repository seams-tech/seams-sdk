import { test, expect } from '@playwright/test';
import { createHash, hkdfSync } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { secp256k1 } from '@noble/curves/secp256k1.js';
import { bytesToNumberBE, numberToBytesBE } from '../../packages/shared-ts/src/utils/bigint';
import { alphabetizeStringify, sha256BytesUtf8 } from '../../packages/shared-ts/src/utils/digests';
import { base64UrlDecode, base64UrlEncode } from '../../packages/shared-ts/src/utils/encoders';
import {
  parseCloudflareSigningWorkerEcdsaDerivationPresignaturePoolPutRequestV1,
  type RouterAbEcdsaDerivationNormalSigningScopeV1,
} from '../../packages/shared-ts/src/utils/routerAbEcdsaDerivation';
import { SECP256K1_ORDER } from '../../packages/shared-ts/src/threshold/secp256k1';
import { deriveEvmFamilySigningKeySlotId } from '../../packages/shared-ts/src/signing-lanes';
import { RouterAbEcdsaDerivationPoolFillHandlers } from '../../packages/sdk-server-ts/src/core/ThresholdService/routerAb/ecdsaDerivationPoolFillHandlers';
import {
  CLOUDFLARE_SIGNING_WORKER_ECDSA_DERIVATION_PRESIGNATURE_POOL_PUT_PATH,
  ROUTER_AB_INTERNAL_SERVICE_AUTH_HEADER_V1,
} from '../../packages/sdk-server-ts/src/core/ThresholdService/routerAb/ecdsaDerivationPresignBridge';
import {
  InMemoryRouterAbEcdsaDerivationPoolFillSessionStore,
  InMemoryRouterAbEcdsaDerivationPresignaturePool,
} from '../../packages/sdk-server-ts/src/core/ThresholdService/stores/EcdsaSigningStore';

import { initSync as initRouterAbEcdsaSigningWorkerWasmSync } from '../../wasm/router_ab_ecdsa_signing_worker/pkg/router_ab_ecdsa_signing_worker.js';
import {
  ClientPresignSession,
  initSync as initRouterAbEcdsaPresignClientWasmSync,
} from '../../wasm/router_ab_ecdsa_presign_client/pkg/router_ab_ecdsa_presign_client.js';

const THRESHOLD_SECP256K1_ECDSA_2P_V1_SCHEME_ID = 'threshold-secp256k1-ecdsa-2p-v1';
const ROUTER_AB_ECDSA_SIGNING_WORKER_WASM_URL = new URL(
  '../../wasm/router_ab_ecdsa_signing_worker/pkg/router_ab_ecdsa_signing_worker_bg.wasm',
  import.meta.url,
);
const ROUTER_AB_ECDSA_PRESIGN_CLIENT_WASM_URL = new URL(
  '../../wasm/router_ab_ecdsa_presign_client/pkg/router_ab_ecdsa_presign_client_bg.wasm',
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

function testEvmFamilySigningKeySlotId(walletId: string): string {
  return String(
    deriveEvmFamilySigningKeySlotId({
      walletId,
      signingRootId: TEST_SIGNING_ROOT_ID,
      signingRootVersion: TEST_RUNTIME_SCOPE.signingRootVersion,
    }),
  );
}

let routerAbEcdsaSigningWorkerWasmInitialized = false;
let routerAbEcdsaPresignClientWasmInitialized = false;

function ensureRouterAbEcdsaSigningWorkerWasm(): void {
  if (routerAbEcdsaSigningWorkerWasmInitialized) return;
  initRouterAbEcdsaSigningWorkerWasmSync({
    module: readFileSync(ROUTER_AB_ECDSA_SIGNING_WORKER_WASM_URL),
  });
  routerAbEcdsaSigningWorkerWasmInitialized = true;
}

function ensureRouterAbEcdsaPresignClientWasm(): void {
  if (routerAbEcdsaPresignClientWasmInitialized) return;
  initRouterAbEcdsaPresignClientWasmSync({
    module: readFileSync(ROUTER_AB_ECDSA_PRESIGN_CLIENT_WASM_URL),
  });
  routerAbEcdsaPresignClientWasmInitialized = true;
}

test.beforeAll(() => {
  ensureRouterAbEcdsaSigningWorkerWasm();
  ensureRouterAbEcdsaPresignClientWasm();
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

function mapSigningWorkerAdditiveShare2p(additiveShare32: Uint8Array): Uint8Array {
  const additiveShare = bytesToNumberBE(additiveShare32);
  const inverseNegativeTwo = (SECP256K1_ORDER - (SECP256K1_ORDER + 1n) / 2n) % SECP256K1_ORDER;
  return numberToBytesBE((additiveShare * inverseNegativeTwo) % SECP256K1_ORDER, 32);
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
  evmFamilySigningKeySlotId: string;
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
  const relayerMappedPrivateShare32 = mapSigningWorkerAdditiveShare2p(relayerSigningShare32);
  const nowMs = Date.now();
  return {
    version: 'threshold_ecdsa_derivation_role_local_v2' as const,
    ecdsaThresholdKeyId: input.ecdsaThresholdKeyId,
    keyHandle: input.keyHandle || `ederivation-key-${input.ecdsaThresholdKeyId}`,
    walletId: input.userId,
    evmFamilySigningKeySlotId: input.evmFamilySigningKeySlotId,
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

function b64uFromHex(hex: string): string {
  const normalized = hex.startsWith('0x') ? hex.slice(2) : hex;
  return Buffer.from(normalized, 'hex').toString('base64url');
}

function buildRouterAbEcdsaDerivationScope(
  roleLocalKey: ReturnType<typeof buildRoleLocalKeyRecord>,
): RouterAbEcdsaDerivationNormalSigningScopeV1 {
  return {
    wallet_key_id: roleLocalKey.evmFamilySigningKeySlotId,
    wallet_id: roleLocalKey.walletId,
    ecdsa_threshold_key_id: roleLocalKey.ecdsaThresholdKeyId,
    signing_root_id: roleLocalKey.signingRootId,
    signing_root_version: roleLocalKey.signingRootVersion || 'default',
    context: {
      application_binding_digest_b64u: 'BwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwc',
    },
    public_identity: {
      context_binding_b64u: roleLocalKey.contextBinding32B64u,
      derivation_client_share_public_key33_b64u: roleLocalKey.clientPublicKey33B64u,
      server_public_key33_b64u: roleLocalKey.relayerPublicKey33B64u,
      threshold_public_key33_b64u: roleLocalKey.groupPublicKey33B64u,
      ethereum_address20_b64u: b64uFromHex(roleLocalKey.ethereumAddress),
      client_share_retry_counter: 0,
      server_share_retry_counter: 0,
    },
    signing_worker: {
      server_id: 'signing-worker-a',
      key_epoch: 'epoch-1',
      recipient_encryption_key: 'recipient-key',
    },
    activation_epoch: 'activation-1',
  };
}

function buildRouterAbEcdsaDerivationPoolFill(
  roleLocalKey: ReturnType<typeof buildRoleLocalKeyRecord>,
  expiresAtMs = Date.now() + 60_000,
) {
  return {
    kind: 'router_ab_ecdsa_derivation_signing_worker_pool' as const,
    scope: buildRouterAbEcdsaDerivationScope(roleLocalKey),
    expiresAtMs,
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
    `groupPublicKey=${presignPoolKeyPart(roleLocalKey.groupPublicKey33B64u, 'groupPublicKey')}`,
  ].join('|');
}

type TestEcdsaMpcSessionRecord = Record<string, unknown> & { expiresAtMs: number };

function createEmptyEcdsaMpcSessionStore() {
  return {
    readMpcSession: async () => null,
    claimMpcSession: async () => ({ ok: false, code: 'not_found' as const }),
  };
}

function createMapEcdsaMpcSessionStore(
  sessions: Map<string, TestEcdsaMpcSessionRecord>,
  counters?: { claim?: number },
) {
  return {
    readMpcSession: async (id: string) => {
      const record = sessions.get(id) || null;
      return record ? { record, version: JSON.stringify(record) } : null;
    },
    claimMpcSession: async (id: string, version: string) => {
      counters && (counters.claim = (counters.claim || 0) + 1);
      const record = sessions.get(id) || null;
      if (!record) return { ok: false, code: 'not_found' as const };
      if (Date.now() > record.expiresAtMs) {
        sessions.delete(id);
        return { ok: false, code: 'expired' as const };
      }
      if (JSON.stringify(record) !== version) {
        return { ok: false, code: 'version_mismatch' as const };
      }
      sessions.delete(id);
      return { ok: true, record };
    },
  };
}

type PresignSession = {
  poll(): unknown;
};

function pollSession(session: PresignSession): {
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

test.describe('Router A/B ECDSA derivation pool-fill distributed session store', () => {
  test('rejects live presign init requests without Router A/B poolFill', async () => {
    const handler = new RouterAbEcdsaDerivationPoolFillHandlers({
      logger: { debug: () => {}, info: () => {}, warn: () => {}, error: () => {} } as any,
      nodeRole: 'coordinator',
      participantIds2p: [1, 2],
      clientParticipantId: 1,
      relayerParticipantId: 2,
      sessionStore: createEmptyEcdsaMpcSessionStore() as any,
      poolFillSessionStore: new InMemoryRouterAbEcdsaDerivationPoolFillSessionStore(),
      presignaturePool: new InMemoryRouterAbEcdsaDerivationPresignaturePool(),
      resolveRoleLocalKeyRecord: async () => null,
      ensureReady: async () => {},
      createPoolFillSessionId: () => 'unused-missing-pool-fill-test',
    });

    const result = await handler.routerAbEcdsaDerivationPresignaturePoolFillInit({
      claims: {} as any,
      request: { keyHandle: 'role-local-key', count: 1 } as any,
    });

    expect(result).toMatchObject({
      ok: false,
      code: 'invalid_body',
    });
    expect(String(result.message || '')).toContain('poolFill is required');
  });

  test('completes a cross-WASM client and SigningWorker presign handshake', async () => {
    const userId = 'distributed-user';
    const walletKeyId = testEvmFamilySigningKeySlotId(userId);
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
        evmFamilySigningKeySlotId: walletKeyId,
        clientVerifyingShareB64u,
      }),
    );
    const relayerKeyId = `secp-${base64UrlEncode(relayerKeyIdDigest32)}`;
    const ecdsaThresholdKeyId = `ecdsa-derivation-${base64UrlEncode(relayerKeyIdDigest32)}`;
    const keyHandle = `ederivation-key-${base64UrlEncode(relayerKeyIdDigest32)}`;
    const roleLocalKeyRecord = {
      ...buildRoleLocalKeyRecord({
        ecdsaThresholdKeyId,
        userId,
        evmFamilySigningKeySlotId: walletKeyId,
        participantIds,
        relayerKeyId,
        clientVerifyingShareB64u,
      }),
      keyHandle,
    };
    const poolFill = buildRouterAbEcdsaDerivationPoolFill(roleLocalKeyRecord);
    const poolFillRequests: Array<
      ReturnType<typeof parseCloudflareSigningWorkerEcdsaDerivationPresignaturePoolPutRequestV1>
    > = [];

    const relayerSigningShare32 = deriveFixtureRelayerSecp256k1SigningShare32({
      relayerShareSeedB64u: TEST_RELAYER_SHARE_SEED_B64U,
      relayerKeyId,
    });
    const relayerVerifyingShare33 = secp256k1.getPublicKey(relayerSigningShare32, true);
    const groupPublicKey33 = sumSecpPublicKeysCompressed(
      clientVerifyingShare33,
      relayerVerifyingShare33,
    );

    const sharedPresignSessionStore = new InMemoryRouterAbEcdsaDerivationPoolFillSessionStore();
    const sharedPresignaturePool = new InMemoryRouterAbEcdsaDerivationPresignaturePool();

    const fakeSessionStore = createEmptyEcdsaMpcSessionStore();
    const fetchImpl: typeof fetch = async (_url, init) => {
      const request = parseCloudflareSigningWorkerEcdsaDerivationPresignaturePoolPutRequestV1(
        JSON.parse(String(init?.body || '')),
      );
      poolFillRequests.push(request);
      return new Response(
        JSON.stringify({
          active_signing_worker_state: {
            account_id: poolFill.scope.wallet_id,
            session_id: 'router-ab-session-1',
            account_public_key: poolFill.scope.public_identity.threshold_public_key33_b64u,
            signing_worker: poolFill.scope.signing_worker,
            activation_transcript_digest: { bytes: new Array(32).fill(1) },
            activation_digest: { bytes: new Array(32).fill(2) },
            signing_worker_material_handle: 'signing-worker-material-1',
            activated_at_ms: Date.now(),
          },
          server_presignature_id: request.server_presignature_id,
          server_big_r33_b64u: request.server_big_r33_b64u,
          stored: true,
        }),
        { status: 200, headers: { 'content-type': 'application/json' } },
      );
    };

    let presignIdCounter = 0;
    const makeLogger = () => ({
      debug: () => {},
      info: () => {},
      warn: () => {},
      error: () => {},
    });
    const makeHandler = () =>
      new RouterAbEcdsaDerivationPoolFillHandlers({
        logger: makeLogger() as any,
        nodeRole: 'coordinator',
        participantIds2p: participantIds,
        clientParticipantId,
        relayerParticipantId,
        sessionStore: fakeSessionStore as any,
        poolFillSessionStore: sharedPresignSessionStore,
        presignaturePool: sharedPresignaturePool,
        resolveRoleLocalKeyRecord: async (requestedKeyHandle) =>
          requestedKeyHandle === keyHandle ? roleLocalKeyRecord : null,
        ensureReady: async () => {},
        createPoolFillSessionId: () => `presign-${++presignIdCounter}`,
        routerAbEcdsaDerivationPoolFill: {
          signingWorkerBaseUrl: 'https://signing-worker.internal',
          auth: {
            kind: 'internal_service_auth_secret',
            secret: 'signing-worker-private',
          },
          fetchImpl,
        },
      });

    const handlerA = makeHandler();

    const claims = {
      walletId: userId,
      evmFamilySigningKeySlotId: walletKeyId,
      relayerKeyId,
      keyHandle,
      ecdsaThresholdKeyId,
      participantIds,
      thresholdExpiresAtMs,
      runtimePolicyScope: TEST_RUNTIME_SCOPE,
    };

    const init = await handlerA.routerAbEcdsaDerivationPresignaturePoolFillInit({
      claims,
      request: { keyHandle: roleLocalKeyRecord.keyHandle, count: 1, poolFill },
    });
    expect(init.ok, JSON.stringify(init)).toBe(true);
    const presignSessionId = String(init.presignSessionId || '');
    expect(presignSessionId).toBeTruthy();

    const localSession = new ClientPresignSession(
      clientSigningShare32,
      groupPublicKey33,
      presignSessionId,
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
          localSession.message(msg);
        }
        pendingServerOutgoing = [];
        const polled = pollSession(localSession);
        pendingClientOutgoing.push(...polled.outgoingMessages);
        if (polled.event === 'presign_done') {
          localPresignature97 = localSession.take_presignature_97();
        }
      }

      if (!serverDone) {
        const step = await handlerA.routerAbEcdsaDerivationPresignaturePoolFillStep({
          claims,
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

    expect(poolFillRequests).toHaveLength(1);
    expect(poolFillRequests[0]).toMatchObject({
      server_presignature_id: serverPresignatureId,
      server_big_r33_b64u: serverBigRB64u,
      scope: poolFill.scope,
      expires_at_ms: poolFill.expiresAtMs,
    });
  });

  test('fills Router A/B ECDSA derivation SigningWorker pool on presign completion', async () => {
    const userId = 'router-ab-ecdsa-derivation-presign-user';
    const walletKeyId = testEvmFamilySigningKeySlotId(userId);
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
        evmFamilySigningKeySlotId: walletKeyId,
        clientVerifyingShareB64u,
      }),
    );
    const relayerKeyId = `secp-${base64UrlEncode(relayerKeyIdDigest32)}`;
    const ecdsaThresholdKeyId = `ecdsa-derivation-${base64UrlEncode(relayerKeyIdDigest32)}`;
    const keyHandle = `ederivation-key-${base64UrlEncode(relayerKeyIdDigest32)}`;
    const roleLocalKeyRecord = {
      ...buildRoleLocalKeyRecord({
        ecdsaThresholdKeyId,
        userId,
        evmFamilySigningKeySlotId: walletKeyId,
        participantIds,
        relayerKeyId,
        clientVerifyingShareB64u,
      }),
      keyHandle,
    };
    const scope = buildRouterAbEcdsaDerivationScope(roleLocalKeyRecord);
    const poolFillExpiresAtMs = Date.now() + 60_000;

    const relayerSigningShare32 = deriveFixtureRelayerSecp256k1SigningShare32({
      relayerShareSeedB64u: TEST_RELAYER_SHARE_SEED_B64U,
      relayerKeyId,
    });
    const relayerVerifyingShare33 = secp256k1.getPublicKey(relayerSigningShare32, true);
    const groupPublicKey33 = sumSecpPublicKeysCompressed(
      clientVerifyingShare33,
      relayerVerifyingShare33,
    );

    const sharedPresignSessionStore = new InMemoryRouterAbEcdsaDerivationPoolFillSessionStore();
    const sharedPresignaturePool = new InMemoryRouterAbEcdsaDerivationPresignaturePool();
    const fakeSessionStore = createEmptyEcdsaMpcSessionStore();
    const poolFillRequests: Array<
      ReturnType<typeof parseCloudflareSigningWorkerEcdsaDerivationPresignaturePoolPutRequestV1>
    > = [];
    const fetchImpl: typeof fetch = async (url, init) => {
      expect(String(url)).toBe(
        `https://signing-worker.internal${CLOUDFLARE_SIGNING_WORKER_ECDSA_DERIVATION_PRESIGNATURE_POOL_PUT_PATH}`,
      );
      const headers = new Headers(init?.headers);
      expect(headers.get(ROUTER_AB_INTERNAL_SERVICE_AUTH_HEADER_V1)).toBe('signing-worker-private');
      expect(headers.get('content-type')).toBe('application/json');
      const request = parseCloudflareSigningWorkerEcdsaDerivationPresignaturePoolPutRequestV1(
        JSON.parse(String(init?.body || '')),
      );
      poolFillRequests.push(request);
      return new Response(
        JSON.stringify({
          active_signing_worker_state: {
            account_id: scope.wallet_id,
            session_id: 'router-ab-session-1',
            account_public_key: scope.public_identity.threshold_public_key33_b64u,
            signing_worker: scope.signing_worker,
            activation_transcript_digest: { bytes: new Array(32).fill(1) },
            activation_digest: { bytes: new Array(32).fill(2) },
            signing_worker_material_handle: 'signing-worker-material-1',
            activated_at_ms: Date.now(),
          },
          server_presignature_id: request.server_presignature_id,
          server_big_r33_b64u: request.server_big_r33_b64u,
          stored: true,
        }),
        {
          status: 200,
          headers: { 'content-type': 'application/json' },
        },
      );
    };

    let presignIdCounter = 0;
    const handler = new RouterAbEcdsaDerivationPoolFillHandlers({
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
      poolFillSessionStore: sharedPresignSessionStore,
      presignaturePool: sharedPresignaturePool,
      resolveRoleLocalKeyRecord: async (requestedKeyHandle) =>
        requestedKeyHandle === keyHandle ? roleLocalKeyRecord : null,
      ensureReady: async () => {},
      createPoolFillSessionId: () => `router-ab-presign-${++presignIdCounter}`,
      routerAbEcdsaDerivationPoolFill: {
        signingWorkerBaseUrl: 'https://signing-worker.internal',
        auth: {
          kind: 'internal_service_auth_secret',
          secret: 'signing-worker-private',
        },
        fetchImpl,
      },
    });
    const claims = {
      walletId: userId,
      evmFamilySigningKeySlotId: walletKeyId,
      relayerKeyId,
      keyHandle,
      ecdsaThresholdKeyId,
      participantIds,
      thresholdExpiresAtMs,
      runtimePolicyScope: TEST_RUNTIME_SCOPE,
    };

    const init = await handler.routerAbEcdsaDerivationPresignaturePoolFillInit({
      claims,
      request: {
        keyHandle: roleLocalKeyRecord.keyHandle,
        count: 1,
        poolFill: {
          kind: 'router_ab_ecdsa_derivation_signing_worker_pool',
          scope,
          expiresAtMs: poolFillExpiresAtMs,
        },
      },
    });
    expect(init.ok, JSON.stringify(init)).toBe(true);
    const presignSessionId = String(init.presignSessionId || '');
    expect(presignSessionId).toBeTruthy();
    await expect(sharedPresignSessionStore.getSession(presignSessionId)).resolves.toMatchObject({
      poolFill: {
        kind: 'router_ab_ecdsa_derivation_signing_worker_pool',
        routerAbEcdsaDerivation: {
          scope,
          expiresAtMs: poolFillExpiresAtMs,
        },
      },
    });

    const localSession = new ClientPresignSession(
      clientSigningShare32,
      groupPublicKey33,
      presignSessionId,
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
          localSession.message(msg);
        }
        pendingServerOutgoing = [];
        const polled = pollSession(localSession);
        pendingClientOutgoing.push(...polled.outgoingMessages);
        if (polled.event === 'presign_done') {
          localPresignature97 = localSession.take_presignature_97();
        }
      }

      if (!serverDone) {
        const step = await handler.routerAbEcdsaDerivationPresignaturePoolFillStep({
          claims,
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
    expect(poolFillRequests).toHaveLength(1);
    expect(poolFillRequests[0]).toMatchObject({
      scope,
      server_presignature_id: serverPresignatureId,
      server_big_r33_b64u: serverBigRB64u,
      expires_at_ms: poolFillExpiresAtMs,
    });
    expect(
      await sharedPresignaturePool.reserve(presignPoolKeyForRoleLocalKey(roleLocalKeyRecord)),
    ).toBeNull();
  });

  test('returns retriable stale_session_state on cross-instance cache miss', async () => {
    const userId = 'strict-no-replay-user';
    const walletKeyId = testEvmFamilySigningKeySlotId(userId);
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
        evmFamilySigningKeySlotId: walletKeyId,
        clientVerifyingShareB64u,
      }),
    );
    const relayerKeyId = `secp-${base64UrlEncode(relayerKeyIdDigest32)}`;
    const ecdsaThresholdKeyId = `ecdsa-derivation-${base64UrlEncode(relayerKeyIdDigest32)}`;
    const roleLocalKeyRecord = buildRoleLocalKeyRecord({
      ecdsaThresholdKeyId,
      userId,
      evmFamilySigningKeySlotId: walletKeyId,
      participantIds,
      relayerKeyId,
      clientVerifyingShareB64u,
    });

    const sharedPresignSessionStore = new InMemoryRouterAbEcdsaDerivationPoolFillSessionStore();
    const sharedPresignaturePool = new InMemoryRouterAbEcdsaDerivationPresignaturePool();

    const fakeSessionStore = createEmptyEcdsaMpcSessionStore();

    let presignIdCounter = 0;
    const makeHandler = () =>
      new RouterAbEcdsaDerivationPoolFillHandlers({
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
        poolFillSessionStore: sharedPresignSessionStore,
        presignaturePool: sharedPresignaturePool,
        resolveRoleLocalKeyRecord: async (requestedKeyHandle) =>
          requestedKeyHandle === roleLocalKeyRecord.keyHandle ? roleLocalKeyRecord : null,
        ensureReady: async () => {},
        createPoolFillSessionId: () => `presign-cache-miss-${++presignIdCounter}`,
      });

    const handlerA = makeHandler();
    const handlerB = makeHandler();
    const claims = {
      walletId: userId,
      evmFamilySigningKeySlotId: walletKeyId,
      relayerKeyId,
      keyHandle: roleLocalKeyRecord.keyHandle,
      ecdsaThresholdKeyId,
      participantIds,
      thresholdExpiresAtMs,
      runtimePolicyScope: TEST_RUNTIME_SCOPE,
    };

    const init = await handlerA.routerAbEcdsaDerivationPresignaturePoolFillInit({
      claims,
      request: {
        keyHandle: roleLocalKeyRecord.keyHandle,
        count: 1,
        poolFill: buildRouterAbEcdsaDerivationPoolFill(roleLocalKeyRecord),
      },
    });
    expect(init.ok, JSON.stringify(init)).toBe(true);
    const presignSessionId = String(init.presignSessionId || '');
    expect(presignSessionId).toBeTruthy();

    const step = await handlerB.routerAbEcdsaDerivationPresignaturePoolFillStep({
      claims,
      request: {
        presignSessionId,
        stage: 'triples',
        outgoingMessagesB64u: [],
      },
    });
    expect(step.ok).toBe(false);
    expect(step.code).toBe('stale_session_state');
    expect(String(step.message || '')).toContain('cache_miss');
    expect(await sharedPresignSessionStore.getSession(presignSessionId)).toBeNull();
  });

  test('forwards cross-instance presign step to owner coordinator', async () => {
    const userId = 'owner-forward-user';
    const walletKeyId = testEvmFamilySigningKeySlotId(userId);
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
        evmFamilySigningKeySlotId: walletKeyId,
        clientVerifyingShareB64u,
      }),
    );
    const relayerKeyId = `secp-${base64UrlEncode(relayerKeyIdDigest32)}`;
    const ecdsaThresholdKeyId = `ecdsa-derivation-${base64UrlEncode(relayerKeyIdDigest32)}`;
    const roleLocalKeyRecord = buildRoleLocalKeyRecord({
      ecdsaThresholdKeyId,
      userId,
      evmFamilySigningKeySlotId: walletKeyId,
      participantIds,
      relayerKeyId,
      clientVerifyingShareB64u,
    });

    const sharedPresignSessionStore = new InMemoryRouterAbEcdsaDerivationPoolFillSessionStore();
    const sharedPresignaturePool = new InMemoryRouterAbEcdsaDerivationPresignaturePool();

    const fakeSessionStore = createEmptyEcdsaMpcSessionStore();

    let presignIdCounter = 0;
    const makeHandler = (input: {
      instanceId: string;
      peers?: Array<{ instanceId: string; relayerUrl: string }>;
    }) =>
      new RouterAbEcdsaDerivationPoolFillHandlers({
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
        poolFillSessionStore: sharedPresignSessionStore,
        presignaturePool: sharedPresignaturePool,
        resolveRoleLocalKeyRecord: async (requestedKeyHandle) =>
          requestedKeyHandle === roleLocalKeyRecord.keyHandle ? roleLocalKeyRecord : null,
        ensureReady: async () => {},
        createPoolFillSessionId: () => `presign-forward-${++presignIdCounter}`,
      });

    const handlerA = makeHandler({ instanceId: 'coordinator-a' });
    const handlerB = makeHandler({
      instanceId: 'coordinator-b',
      peers: [{ instanceId: 'coordinator-a', relayerUrl: 'https://relay-a.internal' }],
    });
    const claims = {
      walletId: userId,
      evmFamilySigningKeySlotId: walletKeyId,
      relayerKeyId,
      keyHandle: roleLocalKeyRecord.keyHandle,
      ecdsaThresholdKeyId,
      participantIds,
      thresholdExpiresAtMs,
      runtimePolicyScope: TEST_RUNTIME_SCOPE,
    };

    const init = await handlerA.routerAbEcdsaDerivationPresignaturePoolFillInit({
      claims,
      request: {
        keyHandle: roleLocalKeyRecord.keyHandle,
        count: 1,
        poolFill: buildRouterAbEcdsaDerivationPoolFill(roleLocalKeyRecord),
      },
    });
    expect(init.ok, JSON.stringify(init)).toBe(true);
    const presignSessionId = String(init.presignSessionId || '');
    expect(presignSessionId).toBeTruthy();

    const originalFetch = globalThis.fetch;
    let forwardedCount = 0;
    globalThis.fetch = (async (url: RequestInfo | URL, init?: RequestInit): Promise<Response> => {
      forwardedCount += 1;
      expect(String(url)).toBe(
        'https://relay-a.internal/router-ab/ecdsa-derivation/presignature-pool/fill/step',
      );
      const headers = new Headers(init?.headers);
      const payload = JSON.parse(String(init?.body || '{}'));
      const result = await handlerA.routerAbEcdsaDerivationPresignaturePoolFillStep({
        claims,
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
      const step = await handlerB.routerAbEcdsaDerivationPresignaturePoolFillStep({
        claims,
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
    const walletKeyId = testEvmFamilySigningKeySlotId(userId);
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
        evmFamilySigningKeySlotId: walletKeyId,
        clientVerifyingShareB64u,
      }),
    );
    const relayerKeyId = `secp-${base64UrlEncode(relayerKeyIdDigest32)}`;
    const ecdsaThresholdKeyId = `ecdsa-derivation-${base64UrlEncode(relayerKeyIdDigest32)}`;
    const roleLocalKeyRecord = buildRoleLocalKeyRecord({
      ecdsaThresholdKeyId,
      userId,
      evmFamilySigningKeySlotId: walletKeyId,
      participantIds,
      relayerKeyId,
      clientVerifyingShareB64u,
    });

    const sharedPresignSessionStore = new InMemoryRouterAbEcdsaDerivationPoolFillSessionStore();
    const sharedPresignaturePool = new InMemoryRouterAbEcdsaDerivationPresignaturePool();

    const fakeSessionStore = createEmptyEcdsaMpcSessionStore();

    let presignIdCounter = 0;
    const makeHandler = (input: {
      instanceId: string;
      peers?: Array<{ instanceId: string; relayerUrl: string }>;
    }) =>
      new RouterAbEcdsaDerivationPoolFillHandlers({
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
        poolFillSessionStore: sharedPresignSessionStore,
        presignaturePool: sharedPresignaturePool,
        resolveRoleLocalKeyRecord: async (requestedKeyHandle) =>
          requestedKeyHandle === roleLocalKeyRecord.keyHandle ? roleLocalKeyRecord : null,
        ensureReady: async () => {},
        createPoolFillSessionId: () => `presign-forward-no-auth-${++presignIdCounter}`,
      });

    const handlerA = makeHandler({ instanceId: 'coordinator-a' });
    const handlerB = makeHandler({
      instanceId: 'coordinator-b',
      peers: [{ instanceId: 'coordinator-a', relayerUrl: 'https://relay-a.internal' }],
    });
    const claims = {
      walletId: userId,
      evmFamilySigningKeySlotId: walletKeyId,
      relayerKeyId,
      keyHandle: roleLocalKeyRecord.keyHandle,
      ecdsaThresholdKeyId,
      participantIds,
      thresholdExpiresAtMs,
      runtimePolicyScope: TEST_RUNTIME_SCOPE,
    };

    const init = await handlerA.routerAbEcdsaDerivationPresignaturePoolFillInit({
      claims,
      request: {
        keyHandle: roleLocalKeyRecord.keyHandle,
        count: 1,
        poolFill: buildRouterAbEcdsaDerivationPoolFill(roleLocalKeyRecord),
      },
    });
    expect(init.ok, JSON.stringify(init)).toBe(true);
    const presignSessionId = String(init.presignSessionId || '');
    expect(presignSessionId).toBeTruthy();

    const step = await handlerB.routerAbEcdsaDerivationPresignaturePoolFillStep({
      claims,
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
    const walletKeyId = testEvmFamilySigningKeySlotId(userId);
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
        evmFamilySigningKeySlotId: walletKeyId,
        clientVerifyingShareB64u,
      }),
    );
    const relayerKeyId = `secp-${base64UrlEncode(relayerKeyIdDigest32)}`;
    const ecdsaThresholdKeyId = `ecdsa-derivation-${base64UrlEncode(relayerKeyIdDigest32)}`;
    const roleLocalKeyRecord = buildRoleLocalKeyRecord({
      ecdsaThresholdKeyId,
      userId,
      evmFamilySigningKeySlotId: walletKeyId,
      participantIds,
      relayerKeyId,
      clientVerifyingShareB64u,
    });

    const sharedPresignSessionStore = new InMemoryRouterAbEcdsaDerivationPoolFillSessionStore();
    const sharedPresignaturePool = new InMemoryRouterAbEcdsaDerivationPresignaturePool();

    const fakeSessionStore = createEmptyEcdsaMpcSessionStore();

    let presignIdCounter = 0;
    const makeHandler = () =>
      new RouterAbEcdsaDerivationPoolFillHandlers({
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
        poolFillSessionStore: sharedPresignSessionStore,
        presignaturePool: sharedPresignaturePool,
        resolveRoleLocalKeyRecord: async (requestedKeyHandle) =>
          requestedKeyHandle === roleLocalKeyRecord.keyHandle ? roleLocalKeyRecord : null,
        ensureReady: async () => {},
        createPoolFillSessionId: () => `presign-scope-${++presignIdCounter}`,
      });

    const handlerA = makeHandler();
    const handlerB = makeHandler();
    const validClaims = {
      walletId: userId,
      evmFamilySigningKeySlotId: walletKeyId,
      relayerKeyId,
      keyHandle: roleLocalKeyRecord.keyHandle,
      ecdsaThresholdKeyId,
      participantIds,
      thresholdExpiresAtMs,
      runtimePolicyScope: TEST_RUNTIME_SCOPE,
    };

    const init = await handlerA.routerAbEcdsaDerivationPresignaturePoolFillInit({
      claims: validClaims,
      request: {
        keyHandle: roleLocalKeyRecord.keyHandle,
        count: 1,
        poolFill: buildRouterAbEcdsaDerivationPoolFill(roleLocalKeyRecord),
      },
    });
    expect(init.ok, JSON.stringify(init)).toBe(true);
    const presignSessionId = String(init.presignSessionId || '');
    expect(presignSessionId).toBeTruthy();

    const wrongScopeClaims = {
      ...validClaims,
      walletId: 'different-user',
    };
    const step = await handlerB.routerAbEcdsaDerivationPresignaturePoolFillStep({
      claims: wrongScopeClaims,
      request: {
        presignSessionId,
        stage: 'triples',
        outgoingMessagesB64u: [],
      },
    });
    expect(step.ok).toBe(false);
    expect(step.code).toBe('unauthorized');
    expect(String(step.message || '')).toContain('does not match Wallet Session scope');
    expect(await sharedPresignSessionStore.getSession(presignSessionId)).toBeNull();
  });

  test('burns presign session on relayer key mismatch', async () => {
    const userId = 'relayer-mismatch-user';
    const walletKeyId = testEvmFamilySigningKeySlotId(userId);
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
        evmFamilySigningKeySlotId: walletKeyId,
        clientVerifyingShareB64u,
      }),
    );
    const relayerKeyId = `secp-${base64UrlEncode(relayerKeyIdDigest32)}`;
    const ecdsaThresholdKeyId = `ecdsa-derivation-${base64UrlEncode(relayerKeyIdDigest32)}`;
    const roleLocalKeyRecord = buildRoleLocalKeyRecord({
      ecdsaThresholdKeyId,
      userId,
      evmFamilySigningKeySlotId: walletKeyId,
      participantIds,
      relayerKeyId,
      clientVerifyingShareB64u,
    });

    const sharedPresignSessionStore = new InMemoryRouterAbEcdsaDerivationPoolFillSessionStore();
    const sharedPresignaturePool = new InMemoryRouterAbEcdsaDerivationPresignaturePool();
    const fakeSessionStore = createEmptyEcdsaMpcSessionStore();
    let presignIdCounter = 0;
    const handler = new RouterAbEcdsaDerivationPoolFillHandlers({
      logger: { debug: () => {}, info: () => {}, warn: () => {}, error: () => {} } as any,
      nodeRole: 'coordinator',
      participantIds2p: participantIds,
      clientParticipantId,
      relayerParticipantId,
      sessionStore: fakeSessionStore as any,
      poolFillSessionStore: sharedPresignSessionStore,
      presignaturePool: sharedPresignaturePool,
      resolveRoleLocalKeyRecord: async (requestedKeyHandle) =>
        requestedKeyHandle === roleLocalKeyRecord.keyHandle ? roleLocalKeyRecord : null,
      ensureReady: async () => {},
      createPoolFillSessionId: () => `presign-relayer-mismatch-${++presignIdCounter}`,
    });
    const claims = {
      walletId: userId,
      evmFamilySigningKeySlotId: walletKeyId,
      relayerKeyId,
      keyHandle: roleLocalKeyRecord.keyHandle,
      ecdsaThresholdKeyId,
      participantIds,
      thresholdExpiresAtMs,
      runtimePolicyScope: TEST_RUNTIME_SCOPE,
    };

    const init = await handler.routerAbEcdsaDerivationPresignaturePoolFillInit({
      claims,
      request: {
        keyHandle: roleLocalKeyRecord.keyHandle,
        count: 1,
        poolFill: buildRouterAbEcdsaDerivationPoolFill(roleLocalKeyRecord),
      },
    });
    expect(init.ok, JSON.stringify(init)).toBe(true);
    const presignSessionId = String(init.presignSessionId || '');
    expect(presignSessionId).toBeTruthy();

    const step = await handler.routerAbEcdsaDerivationPresignaturePoolFillStep({
      claims: { ...claims, relayerKeyId: 'different-relayer-key' } as any,
      request: { presignSessionId, stage: 'triples', outgoingMessagesB64u: [] },
    });
    expect(step.ok).toBe(false);
    expect(step.code).toBe('unauthorized');
    expect(String(step.message || '')).toContain('does not match Wallet Session scope');
    expect(await sharedPresignSessionStore.getSession(presignSessionId)).toBeNull();
  });

  test('burns presign session after malformed protocol message', async () => {
    const userId = 'malformed-protocol-user';
    const walletKeyId = testEvmFamilySigningKeySlotId(userId);
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
        walletKeyId,
        clientVerifyingShareB64u,
      }),
    );
    const relayerKeyId = `secp-${base64UrlEncode(relayerKeyIdDigest32)}`;
    const ecdsaThresholdKeyId = `ecdsa-derivation-${base64UrlEncode(relayerKeyIdDigest32)}`;
    const roleLocalKeyRecord = buildRoleLocalKeyRecord({
      ecdsaThresholdKeyId,
      userId,
      evmFamilySigningKeySlotId: walletKeyId,
      participantIds,
      relayerKeyId,
      clientVerifyingShareB64u,
    });

    const sharedPresignSessionStore = new InMemoryRouterAbEcdsaDerivationPoolFillSessionStore();
    const sharedPresignaturePool = new InMemoryRouterAbEcdsaDerivationPresignaturePool();
    const securityEvents: unknown[] = [];
    const handler = new RouterAbEcdsaDerivationPoolFillHandlers({
      logger: {
        debug: () => {},
        info: () => {},
        warn: (...args: unknown[]) => securityEvents.push(args),
        error: () => {},
      } as any,
      nodeRole: 'coordinator',
      participantIds2p: participantIds,
      clientParticipantId,
      relayerParticipantId,
      sessionStore: createEmptyEcdsaMpcSessionStore() as any,
      poolFillSessionStore: sharedPresignSessionStore,
      presignaturePool: sharedPresignaturePool,
      resolveRoleLocalKeyRecord: async (requestedKeyHandle) =>
        requestedKeyHandle === roleLocalKeyRecord.keyHandle ? roleLocalKeyRecord : null,
      ensureReady: async () => {},
      createPoolFillSessionId: () => `presign-malformed-${Date.now()}`,
    });
    const claims = {
      walletId: userId,
      evmFamilySigningKeySlotId: walletKeyId,
      relayerKeyId,
      keyHandle: roleLocalKeyRecord.keyHandle,
      ecdsaThresholdKeyId,
      participantIds,
      thresholdExpiresAtMs,
      runtimePolicyScope: TEST_RUNTIME_SCOPE,
    };
    const init = await handler.routerAbEcdsaDerivationPresignaturePoolFillInit({
      claims,
      request: {
        keyHandle: roleLocalKeyRecord.keyHandle,
        count: 1,
        poolFill: buildRouterAbEcdsaDerivationPoolFill(roleLocalKeyRecord),
      },
    });
    expect(init.ok, JSON.stringify(init)).toBe(true);
    const presignSessionId = String(init.presignSessionId || '');
    expect(presignSessionId).toBeTruthy();

    const step = await handler.routerAbEcdsaDerivationPresignaturePoolFillStep({
      claims,
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
    expect(JSON.stringify(securityEvents)).toContain('presign_protocol_rejected');

    const replay = await handler.routerAbEcdsaDerivationPresignaturePoolFillStep({
      claims,
      request: {
        presignSessionId,
        stage: 'triples',
        outgoingMessagesB64u: [],
      },
    });
    expect(replay.ok).toBe(false);
    expect(replay.code).toBe('unauthorized');
    expect(JSON.stringify(securityEvents)).toContain('presign_session_replay_or_missing');
  });

  test('rejects stage regression once presign stage has started', async () => {
    const userId = 'stage-regression-user';
    const walletKeyId = testEvmFamilySigningKeySlotId(userId);
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
        walletKeyId,
        clientVerifyingShareB64u,
      }),
    );
    const relayerKeyId = `secp-${base64UrlEncode(relayerKeyIdDigest32)}`;
    const ecdsaThresholdKeyId = `ecdsa-derivation-${base64UrlEncode(relayerKeyIdDigest32)}`;
    const roleLocalKeyRecord = buildRoleLocalKeyRecord({
      ecdsaThresholdKeyId,
      userId,
      evmFamilySigningKeySlotId: walletKeyId,
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

    const sharedPresignSessionStore = new InMemoryRouterAbEcdsaDerivationPoolFillSessionStore();
    const sharedPresignaturePool = new InMemoryRouterAbEcdsaDerivationPresignaturePool();

    const fakeSessionStore = createEmptyEcdsaMpcSessionStore();

    let presignIdCounter = 0;
    const handler = new RouterAbEcdsaDerivationPoolFillHandlers({
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
      poolFillSessionStore: sharedPresignSessionStore,
      presignaturePool: sharedPresignaturePool,
      resolveRoleLocalKeyRecord: async (requestedKeyHandle) =>
        requestedKeyHandle === roleLocalKeyRecord.keyHandle ? roleLocalKeyRecord : null,
      ensureReady: async () => {},
      createPoolFillSessionId: () => `presign-stage-regression-${++presignIdCounter}`,
    });

    const claims = {
      walletId: userId,
      evmFamilySigningKeySlotId: walletKeyId,
      relayerKeyId,
      keyHandle: roleLocalKeyRecord.keyHandle,
      ecdsaThresholdKeyId,
      participantIds,
      thresholdExpiresAtMs,
      runtimePolicyScope: TEST_RUNTIME_SCOPE,
    };

    const init = await handler.routerAbEcdsaDerivationPresignaturePoolFillInit({
      claims,
      request: {
        keyHandle: roleLocalKeyRecord.keyHandle,
        count: 1,
        poolFill: buildRouterAbEcdsaDerivationPoolFill(roleLocalKeyRecord),
      },
    });
    expect(init.ok, JSON.stringify(init)).toBe(true);
    const presignSessionId = String(init.presignSessionId || '');
    expect(presignSessionId).toBeTruthy();

    const localSession = new ClientPresignSession(
      clientSigningShare32,
      groupPublicKey33,
      presignSessionId,
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
          localSession.message(msg);
        }
        pendingServerOutgoing = [];
        const polled = pollSession(localSession);
        pendingClientOutgoing.push(...polled.outgoingMessages);
      }

      const step = await handler.routerAbEcdsaDerivationPresignaturePoolFillStep({
        claims,
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

    const regressed = await handler.routerAbEcdsaDerivationPresignaturePoolFillStep({
      claims,
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
});
