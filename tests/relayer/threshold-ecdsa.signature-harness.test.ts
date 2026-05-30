import { test, expect } from '@playwright/test';
import { readFileSync } from 'node:fs';
import { secp256k1 } from '@noble/curves/secp256k1.js';
import { base64UrlDecode, base64UrlEncode } from '@shared/utils/encoders';
import { alphabetizeStringify, sha256BytesUtf8 } from '@shared/utils/digests';
import {
  computeEcdsaHssRoleLocalRelayerKeyId,
  computeEcdsaHssRoleLocalThresholdKeyId,
} from '@shared/threshold/ecdsaHssRoleLocalBootstrap';
import { createRelayRouter } from '@server/router/express-adaptor';
import { AuthService } from '@server/core/AuthService';
import { createThresholdSigningService } from '@server/core/ThresholdService';
import type { ThresholdStoreConfigInput } from '@server/core/types';
import { makeSessionAdapter, fetchJson, startExpressRouter } from './helpers';
import {
  createFixtureSigningRootShareResolverForUnitTests,
} from '../helpers/thresholdEd25519TestUtils';
import {
  ThresholdEcdsaPresignSession,
  threshold_ecdsa_compute_signature_share,
} from '../../wasm/eth_signer/pkg/eth_signer.js';
import {
  initSync as initHssClientSignerWasmSync,
  threshold_ecdsa_hss_role_local_client_bootstrap,
  threshold_ecdsa_hss_role_local_export_artifact,
} from '../../wasm/hss_client_signer/pkg/hss_client_signer.js';

const HSS_CLIENT_SIGNER_WASM_URL = new URL(
  '../../wasm/hss_client_signer/pkg/hss_client_signer_bg.wasm',
  import.meta.url,
);
const TEST_RUNTIME_SCOPE = {
  orgId: 'org_threshold_ecdsa_signature_harness',
  projectId: 'proj_threshold_ecdsa_signature_harness',
  envId: 'env_threshold_ecdsa_signature_harness',
  signingRootVersion: 'v1',
} as const;
const TEST_SIGNING_ROOT_ID = `${TEST_RUNTIME_SCOPE.projectId}:${TEST_RUNTIME_SCOPE.envId}`;
const KEY_PURPOSE = 'evm-signing';
const KEY_VERSION = 'v1';
const EXPORT_CONFIRMATION_DIGEST_VERSION =
  'ecdsa-hss:role-local:product-export-confirmation:v2';
const EXPORT_AUTHORIZATION_DIGEST_VERSION =
  'ecdsa-hss:role-local:product-export-authorization:v2';
let hssClientSignerWasmInitialized = false;

function ensureHssClientSignerWasm(): void {
  if (hssClientSignerWasmInitialized) return;
  initHssClientSignerWasmSync({ module: readFileSync(HSS_CLIENT_SIGNER_WASM_URL) });
  hssClientSignerWasmInitialized = true;
}

function makeAuthServiceForThreshold(thresholdStore?: ThresholdStoreConfigInput | null): {
  service: AuthService;
  threshold: ReturnType<typeof createThresholdSigningService>;
} {
  const service = new AuthService({
    relayerAccount: 'relayer.testnet',
    relayerPrivateKey: 'ed25519:dummy',
    nearRpcUrl: 'https://rpc.testnet.near.org',
    networkId: 'testnet',
    accountInitialBalance: '1',
    createAccountAndRegisterGas: '1',
    logger: null,
  });

  (
    service as unknown as {
      verifyWebAuthnAuthenticationLite: (
        req: unknown,
      ) => Promise<{ success: boolean; verified: boolean }>;
    }
  ).verifyWebAuthnAuthenticationLite = async (_req: unknown) => ({ success: true, verified: true });

  const providedConfig = (thresholdStore || {}) as Partial<ThresholdStoreConfigInput>;
  const needsFixtureSigningRootResolver = !(
    providedConfig.signingRootShareResolver ||
    providedConfig.signingRootSecretResolverAdapters ||
    providedConfig.signingRootSecretStore ||
    providedConfig.signingRootSecretDecryptAdapter ||
    providedConfig.signingRootSecretShareKekResolver
  );
  const thresholdConfigDefaults: ThresholdStoreConfigInput = {
    kind: 'in-memory',
    THRESHOLD_NODE_ROLE: 'coordinator',
    ...(needsFixtureSigningRootResolver
      ? { signingRootShareResolver: createFixtureSigningRootShareResolverForUnitTests() }
      : {}),
  };
  const thresholdConfig: ThresholdStoreConfigInput = thresholdStore
    ? {
        ...thresholdConfigDefaults,
        ...thresholdStore,
      }
    : thresholdConfigDefaults;

  const threshold = createThresholdSigningService({
    authService: service,
    thresholdStore: thresholdConfig,
    logger: null,
  });
  service.setThresholdSigningService(threshold);

  return { service, threshold };
}

function makeJwtSessionAdapter(): ReturnType<typeof makeSessionAdapter> {
  const tokens = new Map<string, Record<string, unknown>>();
  return makeSessionAdapter({
    signJwt: async (sub: string, extra?: Record<string, unknown>) => {
      const token = `testjwt-${Date.now()}-${Math.random().toString(16).slice(2)}`;
      tokens.set(token, { sub, ...(extra || {}) });
      return token;
    },
    parse: async (headers: Record<string, string | string[] | undefined>) => {
      const authHeaderRaw = headers.authorization ?? headers.Authorization;
      const authHeader = Array.isArray(authHeaderRaw) ? authHeaderRaw[0] : authHeaderRaw;
      const token =
        typeof authHeader === 'string' ? authHeader.replace(/^Bearer\s+/i, '').trim() : '';
      const claims = token ? tokens.get(token) : undefined;
      return claims ? { ok: true as const, claims } : { ok: false as const };
    },
  });
}

function fakeWebAuthnAuthentication(): Record<string, unknown> {
  return {
    id: 'test',
    rawId: 'test',
    type: 'public-key',
    authenticatorAttachment: null,
    response: {
      clientDataJSON: 'test',
      authenticatorData: 'test',
      signature: 'test',
      userHandle: null,
    },
    clientExtensionResults: null,
  };
}

async function stagedBootstrapThresholdEcdsa(args: {
  baseUrl: string;
  session: ReturnType<typeof makeJwtSessionAdapter>;
  userId: string;
  rpId: string;
  clientRootShare32B64u: string;
  sessionId: string;
  participantIds: number[];
  ttlMs?: number;
  remainingUses?: number;
}) {
  const signingRootId = TEST_SIGNING_ROOT_ID;
  const signingRootVersion = TEST_RUNTIME_SCOPE.signingRootVersion;
  const ecdsaThresholdKeyId = await computeEcdsaHssRoleLocalThresholdKeyId({
    walletId: args.userId,
    rpId: args.rpId,
    signingRootId,
    signingRootVersion,
  });
  const relayerKeyId = await computeEcdsaHssRoleLocalRelayerKeyId({
    walletId: args.userId,
    rpId: args.rpId,
  });
  const walletSigningSessionId = `${args.sessionId}:wallet-signing`;
  const ttlMs = args.ttlMs ?? 60_000;
  const remainingUses = args.remainingUses ?? 3;

  ensureHssClientSignerWasm();
  const clientBootstrap = threshold_ecdsa_hss_role_local_client_bootstrap({
    walletId: args.userId,
    rpId: args.rpId,
    ecdsaThresholdKeyId,
    signingRootId,
    signingRootVersion,
    keyPurpose: KEY_PURPOSE,
    keyVersion: KEY_VERSION,
    clientRootShare32B64u: args.clientRootShare32B64u,
  }) as {
    contextBinding32B64u: string;
    clientPublicKey33B64u: string;
    clientShareRetryCounter: number;
    mappedPrivateShare32B64u: string;
    verifyingShare33B64u: string;
  };

  const bootstrap = await fetchJson(`${args.baseUrl}/threshold-ecdsa/hss/bootstrap`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      formatVersion: 'ecdsa-hss-role-local',
      walletId: args.userId,
      rpId: args.rpId,
      ecdsaThresholdKeyId,
      signingRootId,
      signingRootVersion,
      keyScope: 'evm-family',
      relayerKeyId,
      clientPublicKey33B64u: clientBootstrap.clientPublicKey33B64u,
      clientShareRetryCounter: clientBootstrap.clientShareRetryCounter,
      contextBinding32B64u: clientBootstrap.contextBinding32B64u,
      requestId: `bootstrap-request-${Date.now()}`,
      sessionId: args.sessionId,
      walletSigningSessionId,
      ttlMs,
      remainingUses,
      participantIds: args.participantIds,
      passkeyBootstrapAuthorization: {
        kind: 'passkey_bootstrap',
        webauthn_authentication: fakeWebAuthnAuthentication(),
        runtimePolicyScope: TEST_RUNTIME_SCOPE,
      },
    }),
  });

  if (bootstrap.status !== 200 || bootstrap.json?.ok !== true) return bootstrap;
  const value = (bootstrap.json.value || {}) as Record<string, unknown>;
  const jwt = await args.session.signJwt(args.userId, {
    kind: 'threshold_ecdsa_session_v2',
    walletId: args.userId,
    sessionId: String(value.sessionId || args.sessionId),
    walletSigningSessionId: String(value.walletSigningSessionId || walletSigningSessionId),
    keyScope: 'evm-family',
    keyHandle: String(value.keyHandle || ''),
    relayerKeyId: String(value.relayerKeyId || relayerKeyId),
    rpId: args.rpId,
    thresholdExpiresAtMs: Number(value.expiresAtMs || Date.now() + ttlMs),
    participantIds: Array.isArray(value.participantIds) ? value.participantIds : args.participantIds,
    runtimePolicyScope: TEST_RUNTIME_SCOPE,
  });

  return {
    ...bootstrap,
    json: {
      ok: true,
      ...value,
      jwt,
      clientVerifyingShareB64u: clientBootstrap.verifyingShare33B64u,
      clientBootstrap,
    },
  };
}

async function stagedExplicitExportThresholdEcdsa(args: {
  baseUrl: string;
  userId: string;
  rpId: string;
  ecdsaThresholdKeyId: string;
  clientRootShare32B64u: string;
  jwt: string;
  bootstrapJson: Record<string, unknown>;
}) {
  const exportRequest = await buildRoleLocalExportShareRequest(args);
  const publicIdentity = args.bootstrapJson.publicIdentity as Record<string, unknown>;
  const clientBootstrap = args.bootstrapJson.clientBootstrap as {
    clientShareRetryCounter: number;
  };
  const exportedShare = await fetchJson(`${args.baseUrl}/threshold-ecdsa/hss/export/share`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      Authorization: `Bearer ${args.jwt}`,
    },
    body: JSON.stringify(exportRequest),
  });

  if (exportedShare.status !== 200 || exportedShare.json?.ok !== true) return exportedShare;
  const exportValue = (exportedShare.json.value || {}) as Record<string, unknown>;
  const artifact = threshold_ecdsa_hss_role_local_export_artifact({
    walletId: args.userId,
    rpId: args.rpId,
    ecdsaThresholdKeyId: args.ecdsaThresholdKeyId,
    signingRootId: String(args.bootstrapJson.signingRootId || TEST_SIGNING_ROOT_ID),
    signingRootVersion: String(
      args.bootstrapJson.signingRootVersion || TEST_RUNTIME_SCOPE.signingRootVersion,
    ),
    keyPurpose: KEY_PURPOSE,
    keyVersion: KEY_VERSION,
    clientRootShare32B64u: args.clientRootShare32B64u,
    serverExportShare32B64u: String(exportValue.serverExportShare32B64u || ''),
    contextBinding32B64u: String(args.bootstrapJson.contextBinding32B64u || ''),
    clientPublicKey33B64u: String(publicIdentity.hssClientSharePublicKey33B64u || ''),
    relayerPublicKey33B64u: String(publicIdentity.relayerPublicKey33B64u || ''),
    groupPublicKey33B64u: String(publicIdentity.groupPublicKey33B64u || ''),
    ethereumAddress: String(publicIdentity.ethereumAddress || ''),
    clientShareRetryCounter: Number(clientBootstrap.clientShareRetryCounter || 0),
  }) as {
    publicKeyHex: string;
    privateKeyHex: string;
    ethereumAddress: string;
  };

  return {
    ...exportedShare,
    json: {
      ok: true,
      privateKeyHex: artifact.privateKeyHex,
      canonicalPublicKeyHex: artifact.publicKeyHex,
      canonicalEthereumAddress: artifact.ethereumAddress,
    },
  };
}

async function buildRoleLocalExportShareRequest(args: {
  userId: string;
  rpId: string;
  ecdsaThresholdKeyId: string;
  bootstrapJson: Record<string, unknown>;
}) {
  const keyHandle = String(args.bootstrapJson.keyHandle || '');
  const relayerKeyId = String(args.bootstrapJson.relayerKeyId || '');
  const signingRootId = String(args.bootstrapJson.signingRootId || TEST_SIGNING_ROOT_ID);
  const signingRootVersion = String(
    args.bootstrapJson.signingRootVersion || TEST_RUNTIME_SCOPE.signingRootVersion,
  );
  const contextBinding32B64u = String(args.bootstrapJson.contextBinding32B64u || '');
  const publicIdentity = args.bootstrapJson.publicIdentity as Record<string, unknown>;
  const issuedAtUnixMs = Date.now();
  const expiresAtUnixMs = issuedAtUnixMs + 60_000;
  const exportRequestNonce32B64u = base64UrlEncode(randomSecpSecretKey32());
  const requestWithoutDigests = {
    formatVersion: 'ecdsa-hss-role-local-export',
    walletId: args.userId,
    rpId: args.rpId,
    ecdsaThresholdKeyId: args.ecdsaThresholdKeyId,
    relayerKeyId,
    contextBinding32B64u,
    publicIdentity,
    clientDeviceId: 'signature-harness-device',
    clientSessionId: 'signature-harness-client-session',
    exportRequestNonce32B64u,
    issuedAtUnixMs,
    expiresAtUnixMs,
  };
  const confirmationDigest32B64u = await digestB64u({
    version: EXPORT_CONFIRMATION_DIGEST_VERSION,
    walletId: args.userId,
    rpId: args.rpId,
    ecdsaThresholdKeyId: args.ecdsaThresholdKeyId,
    relayerKeyId,
    contextBinding32B64u,
    publicIdentity,
    clientDeviceId: requestWithoutDigests.clientDeviceId,
    clientSessionId: requestWithoutDigests.clientSessionId,
    exportRequestNonce32B64u,
    issuedAtUnixMs,
    expiresAtUnixMs,
  });
  return {
    ...requestWithoutDigests,
    confirmationDigest32B64u,
    authorizationDigest32B64u: await digestB64u({
      version: EXPORT_AUTHORIZATION_DIGEST_VERSION,
      operation: 'explicit_key_export',
      keyHandle,
      walletId: args.userId,
      rpId: args.rpId,
      ecdsaThresholdKeyId: args.ecdsaThresholdKeyId,
      relayerKeyId,
      signingRootId,
      signingRootVersion,
      contextBinding32B64u,
      publicIdentity,
      exportRequestNonce32B64u,
      confirmationDigest32B64u,
      issuedAtUnixMs,
      expiresAtUnixMs,
      clientDeviceId: requestWithoutDigests.clientDeviceId,
      clientSessionId: requestWithoutDigests.clientSessionId,
      thresholdSessionId: String(args.bootstrapJson.sessionId || ''),
      walletSigningSessionId: String(args.bootstrapJson.walletSigningSessionId || ''),
      thresholdExpiresAtMs: Number(args.bootstrapJson.expiresAtMs || 0),
      participantIds: args.bootstrapJson.participantIds,
    }),
  };
}

async function digestB64u(value: unknown): Promise<string> {
  return base64UrlEncode(await sha256BytesUtf8(alphabetizeStringify(value)));
}

async function mintAppSessionJwt(args: {
  service: ReturnType<typeof makeAuthServiceForThreshold>['service'];
  session: ReturnType<typeof makeJwtSessionAdapter>;
  userId: string;
}): Promise<string> {
  const version = await args.service.getOrCreateAppSessionVersion({ userId: args.userId });
  expect(version.ok).toBe(true);
  expect(String(version.ok ? version.appSessionVersion : '')).toBeTruthy();
  return await args.session.signJwt(args.userId, {
    kind: 'app_session_v1',
    appSessionVersion: version.ok ? version.appSessionVersion : '',
  });
}

function randomSecpSecretKey32(): Uint8Array {
  const utils = (secp256k1 as any)?.utils;
  if (typeof utils?.randomPrivateKey === 'function') return utils.randomPrivateKey();
  if (typeof utils?.randomSecretKey === 'function') return utils.randomSecretKey();
  throw new Error('secp256k1 random secret key generator is unavailable');
}

function recoverSecpPublicKeyCompressed(args: {
  signature64: Uint8Array;
  recoveryId: number;
  digest32: Uint8Array;
}): Uint8Array {
  const signatureCtor = (secp256k1 as any)?.Signature;
  if (!signatureCtor) throw new Error('secp256k1.Signature is unavailable');

  const signature =
    typeof signatureCtor.fromCompact === 'function'
      ? signatureCtor.fromCompact(args.signature64)
      : signatureCtor.fromBytes(args.signature64);

  const recoveredPoint = signature
    .addRecoveryBit(args.recoveryId & 1)
    .recoverPublicKey(args.digest32);

  if (typeof recoveredPoint.toRawBytes === 'function') return recoveredPoint.toRawBytes(true);
  return recoveredPoint.toBytes(true);
}

function expectNoCanonicalExportMaterial(json: Record<string, unknown> | null): void {
  expect(json).not.toBeNull();
  expect('canonicalSecp256k1KeyB64u' in (json || {})).toBe(false);
  expect('canonical_x32_b64u' in (json || {})).toBe(false);
  expect('privateKeyHex' in (json || {})).toBe(false);
  expect('exportPrivateKeyHex' in (json || {})).toBe(false);
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

test.describe('threshold-ecdsa harness signature verification', () => {
  test.describe.configure({ timeout: 120_000 });

  test('signs a known digest and verifies the signature against the group key', async () => {
    const { service, threshold } = makeAuthServiceForThreshold();
    const session = makeJwtSessionAdapter();
    const router = createRelayRouter(service, { threshold, session });
    const srv = await startExpressRouter(router);

    try {
      const userId = 'bob.testnet';
      const rpId = 'example.localhost';
      const participantIds = [1, 2];
      const clientParticipantId = 1;
      const relayerParticipantId = 2;
      const digest32 = Uint8Array.from(Array.from({ length: 32 }, (_, i) => i + 1));
      const clientRootShare32 = randomSecpSecretKey32();
      const clientRootShare32B64u = base64UrlEncode(clientRootShare32);
      const sessionId = `sess-${Date.now()}`;
      const bootstrap = await stagedBootstrapThresholdEcdsa({
        baseUrl: srv.baseUrl,
        session,
        userId,
        rpId,
        clientRootShare32B64u,
        sessionId,
        participantIds,
      });
      expect(bootstrap.status, bootstrap.text).toBe(200);
      expect(bootstrap.json?.ok, bootstrap.text).toBe(true);
      expectNoCanonicalExportMaterial(bootstrap.json);

      const ecdsaThresholdKeyId = String(bootstrap.json?.ecdsaThresholdKeyId || '');
      const keyHandle = String(bootstrap.json?.keyHandle || '');
      const relayerKeyId = String(bootstrap.json?.relayerKeyId || '');
      const thresholdEcdsaPublicKeyB64u = String(bootstrap.json?.thresholdEcdsaPublicKeyB64u || '');
      const clientVerifyingShareB64u = String(bootstrap.json?.clientVerifyingShareB64u || '');
      expect(ecdsaThresholdKeyId).toBeTruthy();
      expect(keyHandle).toBeTruthy();
      expect(relayerKeyId).toBeTruthy();
      expect(thresholdEcdsaPublicKeyB64u).toBeTruthy();
      // Backend bridge consistency check only. Product identity is ecdsaThresholdKeyId/group key/address.
      expect(clientVerifyingShareB64u).toBeTruthy();

      const jwt = String(bootstrap.json?.jwt || '');
      expect(jwt).toBeTruthy();

      const clientBootstrap = bootstrap.json?.clientBootstrap as {
        mappedPrivateShare32B64u: string;
        verifyingShare33B64u: string;
      };
      expect(clientBootstrap.verifyingShare33B64u).toBe(clientVerifyingShareB64u);

      const authorized = await fetchJson(`${srv.baseUrl}/threshold-ecdsa/authorize`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${jwt}`,
        },
        body: JSON.stringify({
          keyHandle,
          purpose: 'test:known_digest',
          signing_digest_32: Array.from(digest32),
        }),
      });
      expect(authorized.status, authorized.text).toBe(200);
      expect(authorized.json?.ok, authorized.text).toBe(true);
      expectNoCanonicalExportMaterial(authorized.json);
      const mpcSessionId = String(authorized.json?.mpcSessionId || '');
      expect(mpcSessionId).toBeTruthy();

      const presignInit = await fetchJson(`${srv.baseUrl}/threshold-ecdsa/presign/init`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${jwt}`,
        },
        body: JSON.stringify({
          keyHandle,
          count: 1,
        }),
      });
      expect(presignInit.status, presignInit.text).toBe(200);
      expect(presignInit.json?.ok, presignInit.text).toBe(true);
      expectNoCanonicalExportMaterial(presignInit.json);

      const presignSessionId = String(presignInit.json?.presignSessionId || '');
      expect(presignSessionId).toBeTruthy();

      const groupPublicKey33 = base64UrlDecode(thresholdEcdsaPublicKeyB64u);
      const clientThresholdSigningShare32 = base64UrlDecode(
        clientBootstrap.mappedPrivateShare32B64u,
      );
      const localPresignSession = new ThresholdEcdsaPresignSession(
        new Uint32Array(participantIds),
        clientParticipantId,
        2,
        clientThresholdSigningShare32,
        groupPublicKey33,
      );

      let stageForServer: 'triples' | 'presign' = 'triples';
      let pendingClientOutgoing = pollSession(localPresignSession).outgoingMessages;
      let pendingServerOutgoing = (
        Array.isArray(presignInit.json?.outgoingMessagesB64u)
          ? presignInit.json!.outgoingMessagesB64u
          : []
      ).map((entry) => base64UrlDecode(String(entry || '')));
      let localPresignature97: Uint8Array | null = null;
      let serverPresignatureId = '';
      let serverBigRB64u = '';
      let serverDone = false;

      const MAX_HANDSHAKE_STEPS = 64;
      for (let i = 0; i < MAX_HANDSHAKE_STEPS; i += 1) {
        if (pendingServerOutgoing.length > 0 && !localPresignature97) {
          if (stageForServer === 'presign' && localPresignSession.stage() === 'triples_done') {
            localPresignSession.start_presign();
          }
          for (const msg of pendingServerOutgoing) {
            localPresignSession.message(relayerParticipantId, msg);
          }
          pendingServerOutgoing = [];
          const polled = pollSession(localPresignSession);
          pendingClientOutgoing.push(...polled.outgoingMessages);
          if (
            polled.stage === 'triples_done' ||
            polled.stage === 'presign' ||
            polled.stage === 'done'
          ) {
            stageForServer = 'presign';
          }
          if (polled.event === 'presign_done') {
            localPresignature97 = localPresignSession.take_presignature_97();
          }
        }

        if (!serverDone) {
          const presignStep = await fetchJson(`${srv.baseUrl}/threshold-ecdsa/presign/step`, {
            method: 'POST',
            headers: {
              'Content-Type': 'application/json',
              Authorization: `Bearer ${jwt}`,
            },
            body: JSON.stringify({
              presignSessionId,
              stage: stageForServer,
              outgoingMessagesB64u: pendingClientOutgoing.map((entry) => base64UrlEncode(entry)),
            }),
          });
          expect(presignStep.status, presignStep.text).toBe(200);
          expect(presignStep.json?.ok, presignStep.text).toBe(true);
          expectNoCanonicalExportMaterial(presignStep.json);
          pendingClientOutgoing = [];

          pendingServerOutgoing = (
            Array.isArray(presignStep.json?.outgoingMessagesB64u)
              ? presignStep.json!.outgoingMessagesB64u
              : []
          ).map((entry) => base64UrlDecode(String(entry || '')));
          const stepStage = String(presignStep.json?.stage || '');
          if (stepStage === 'presign' || stepStage === 'done') {
            stageForServer = 'presign';
          }
          if (String(presignStep.json?.event || '') === 'presign_done') {
            serverPresignatureId = String(presignStep.json?.presignatureId || '');
            serverBigRB64u = String(presignStep.json?.bigRB64u || '');
            serverDone = true;
          }
        }

        if (localPresignature97 && serverPresignatureId && serverBigRB64u) {
          break;
        }

        if (
          !pendingServerOutgoing.length &&
          !pendingClientOutgoing.length &&
          !localPresignature97
        ) {
          if (stageForServer === 'presign' && localPresignSession.stage() === 'triples_done') {
            localPresignSession.start_presign();
          }
          const polled = pollSession(localPresignSession);
          pendingClientOutgoing.push(...polled.outgoingMessages);
          if (
            polled.stage === 'triples_done' ||
            polled.stage === 'presign' ||
            polled.stage === 'done'
          ) {
            stageForServer = 'presign';
          }
          if (polled.event === 'presign_done') {
            localPresignature97 = localPresignSession.take_presignature_97();
          }
        }
      }

      expect(localPresignature97).toBeTruthy();
      expect(serverPresignatureId).toBeTruthy();
      expect(serverBigRB64u).toBeTruthy();

      const bigR33 = localPresignature97!.slice(0, 33);
      const kShare32 = localPresignature97!.slice(33, 65);
      const sigmaShare32 = localPresignature97!.slice(65, 97);
      expect(base64UrlEncode(bigR33)).toBe(serverBigRB64u);

      const signInit = await fetchJson(`${srv.baseUrl}/threshold-ecdsa/sign/init`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          mpcSessionId,
          relayerKeyId,
          signingDigestB64u: base64UrlEncode(digest32),
          clientRound1: { presignatureId: serverPresignatureId },
        }),
      });
      expect(signInit.status, signInit.text).toBe(200);
      expect(signInit.json?.ok, signInit.text).toBe(true);
      expectNoCanonicalExportMaterial(signInit.json);

      const signingSessionId = String(signInit.json?.signingSessionId || '');
      const entropyB64u = String(
        (signInit.json?.relayerRound1 as Record<string, unknown> | undefined)?.entropyB64u || '',
      );
      const bigREchoB64u = String(
        (signInit.json?.relayerRound1 as Record<string, unknown> | undefined)?.bigRB64u || '',
      );
      expect(signingSessionId).toBeTruthy();
      expect(entropyB64u).toBeTruthy();
      if (bigREchoB64u) expect(bigREchoB64u).toBe(serverBigRB64u);

      const clientSignatureShare32 = threshold_ecdsa_compute_signature_share(
        new Uint32Array(participantIds),
        clientParticipantId,
        groupPublicKey33,
        bigR33,
        kShare32,
        sigmaShare32,
        digest32,
        base64UrlDecode(entropyB64u),
      );
      expect(clientSignatureShare32.length).toBe(32);

      const finalized = await fetchJson(`${srv.baseUrl}/threshold-ecdsa/sign/finalize`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          signingSessionId,
          clientRound2: { clientSignatureShareB64u: base64UrlEncode(clientSignatureShare32) },
        }),
      });
      expect(finalized.status, finalized.text).toBe(200);
      expect(finalized.json?.ok, finalized.text).toBe(true);
      expectNoCanonicalExportMaterial(finalized.json);

      const signature65B64u = String(
        (finalized.json?.relayerRound2 as Record<string, unknown> | undefined)?.signature65B64u ||
          '',
      );
      expect(signature65B64u).toBeTruthy();

      const signature65 = base64UrlDecode(signature65B64u);
      expect(signature65.length).toBe(65);
      const signature64 = signature65.slice(0, 64);
      const recId = signature65[64]!;

      const verified = secp256k1.verify(signature64, digest32, groupPublicKey33, {
        lowS: true,
        prehash: false,
      });

      const recovered = recoverSecpPublicKeyCompressed({
        signature64,
        recoveryId: recId,
        digest32,
      });
      expect(verified).toBe(true);
      expect(base64UrlEncode(recovered)).toBe(thresholdEcdsaPublicKeyB64u);
    } finally {
      await srv.close();
    }
  });

  test('bootstrap endpoint keygens and mints session in a single relay call', async () => {
    const { service, threshold } = makeAuthServiceForThreshold();
    const session = makeJwtSessionAdapter();
    const router = createRelayRouter(service, { threshold, session });
    const srv = await startExpressRouter(router);

    try {
      const userId = 'bootstrap-bob.testnet';
      const rpId = 'example.localhost';
      const participantIds = [1, 2];
      const digest32 = Uint8Array.from(Array.from({ length: 32 }, (_, i) => i + 11));
      const clientRootShare32B64u = base64UrlEncode(randomSecpSecretKey32());
      const sessionId = `sess-${Date.now()}`;

      const bootstrap = await stagedBootstrapThresholdEcdsa({
        baseUrl: srv.baseUrl,
        session,
        userId,
        rpId,
        clientRootShare32B64u,
        sessionId,
        participantIds,
      });
      expect(bootstrap.status, bootstrap.text).toBe(200);
      expect(bootstrap.json?.ok, bootstrap.text).toBe(true);

      const ecdsaThresholdKeyId = String(bootstrap.json?.ecdsaThresholdKeyId || '');
      const keyHandle = String(bootstrap.json?.keyHandle || '');
      const relayerKeyId = String(bootstrap.json?.relayerKeyId || '');
      const thresholdEcdsaPublicKeyB64u = String(bootstrap.json?.thresholdEcdsaPublicKeyB64u || '');
      const jwt = String(bootstrap.json?.jwt || '');
      const returnedSessionId = String(bootstrap.json?.sessionId || '');
      expect(ecdsaThresholdKeyId).toBeTruthy();
      expect(keyHandle).toBeTruthy();
      expect(relayerKeyId).toBeTruthy();
      expect(thresholdEcdsaPublicKeyB64u).toBeTruthy();
      expect(jwt).toBeTruthy();
      expect(returnedSessionId).toBe(sessionId);

      const authorized = await fetchJson(`${srv.baseUrl}/threshold-ecdsa/authorize`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${jwt}`,
        },
        body: JSON.stringify({
          keyHandle,
          purpose: 'test:bootstrap_authorize',
          signing_digest_32: Array.from(digest32),
        }),
      });
      expect(authorized.status, authorized.text).toBe(200);
      expect(authorized.json?.ok, authorized.text).toBe(true);
      expect(String(authorized.json?.mpcSessionId || '')).toBeTruthy();
    } finally {
      await srv.close();
    }
  });

  test('authorize returns configured presign pool policy hint', async () => {
    const { service, threshold } = makeAuthServiceForThreshold({
      THRESHOLD_ECDSA_PRESIGN_POOL_HINT_ENABLED: 'true',
      THRESHOLD_ECDSA_PRESIGN_POOL_HINT_TARGET_DEPTH: '3',
      THRESHOLD_ECDSA_PRESIGN_POOL_HINT_LOW_WATERMARK: '1',
      THRESHOLD_ECDSA_PRESIGN_POOL_HINT_MAX_REFILL_IN_FLIGHT: '4',
      THRESHOLD_ECDSA_PRESIGN_POOL_HINT_REFILL_ATTEMPT_TIMEOUT_MS: '45000',
    });
    const session = makeJwtSessionAdapter();
    const router = createRelayRouter(service, { threshold, session });
    const srv = await startExpressRouter(router);

    try {
      const userId = 'hint-bob.testnet';
      const rpId = 'example.localhost';
      const participantIds = [1, 2];
      const digest32 = Uint8Array.from(Array.from({ length: 32 }, (_, i) => i + 19));
      const clientRootShare32B64u = base64UrlEncode(randomSecpSecretKey32());
      const sessionId = `sess-${Date.now()}`;

      const bootstrap = await stagedBootstrapThresholdEcdsa({
        baseUrl: srv.baseUrl,
        session,
        userId,
        rpId,
        clientRootShare32B64u,
        sessionId,
        participantIds,
      });
      expect(bootstrap.status, bootstrap.text).toBe(200);
      expect(bootstrap.json?.ok, bootstrap.text).toBe(true);
      const ecdsaThresholdKeyId = String(bootstrap.json?.ecdsaThresholdKeyId || '');
      const keyHandle = String(bootstrap.json?.keyHandle || '');
      const relayerKeyId = String(bootstrap.json?.relayerKeyId || '');
      const jwt = String(bootstrap.json?.jwt || '');
      expect(ecdsaThresholdKeyId).toBeTruthy();
      expect(keyHandle).toBeTruthy();
      expect(relayerKeyId).toBeTruthy();
      expect(jwt).toBeTruthy();

      const authorized = await fetchJson(`${srv.baseUrl}/threshold-ecdsa/authorize`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${jwt}`,
        },
        body: JSON.stringify({
          keyHandle,
          purpose: 'test:presign_policy_hint',
          signing_digest_32: Array.from(digest32),
        }),
      });
      expect(authorized.status, authorized.text).toBe(200);
      expect(authorized.json?.ok, authorized.text).toBe(true);
      expect(authorized.json?.presignPoolPolicy).toEqual({
        enabled: true,
        targetDepth: 3,
        lowWatermark: 1,
        maxRefillInFlight: 4,
        refillAttemptTimeoutMs: 45_000,
      });
    } finally {
      await srv.close();
    }
  });

  test('forwards presign step over HTTP to owner coordinator with session auth', async () => {
    const sharedSession = makeJwtSessionAdapter();
    const a = makeAuthServiceForThreshold({
      THRESHOLD_NODE_ROLE: 'coordinator',
      THRESHOLD_COORDINATOR_INSTANCE_ID: 'coordinator-a',
      THRESHOLD_COORDINATOR_PEERS: '[]',
    });
    const routerA = createRelayRouter(a.service, {
      threshold: a.threshold,
      session: sharedSession,
    });
    const srvA = await startExpressRouter(routerA);

    const b = makeAuthServiceForThreshold({
      THRESHOLD_NODE_ROLE: 'coordinator',
      THRESHOLD_COORDINATOR_INSTANCE_ID: 'coordinator-b',
      THRESHOLD_COORDINATOR_PEERS: JSON.stringify([
        { instanceId: 'coordinator-a', relayerUrl: srvA.baseUrl },
      ]),
    });
    const routerB = createRelayRouter(b.service, {
      threshold: b.threshold,
      session: sharedSession,
    });
    const srvB = await startExpressRouter(routerB);

    try {
      const handlerA = (a.threshold as any).ecdsaSigningHandlers as {
        presignSessionStore: {
          getSession: (id: string) => Promise<{ version?: number } | null>;
        };
        livePresignSessionById: Map<string, unknown>;
      };
      const handlerB = (b.threshold as any).ecdsaSigningHandlers as {
        presignSessionStore: unknown;
        livePresignSessionById: Map<string, unknown>;
      };

      // Simulate a shared durable presign-session store across coordinator instances.
      handlerB.presignSessionStore = handlerA.presignSessionStore;

      const userId = 'forwarding-bob.testnet';
      const rpId = 'example.localhost';
      const participantIds = [1, 2];
      const clientRootShare32B64u = base64UrlEncode(randomSecpSecretKey32());
      const sessionId = `sess-${Date.now()}`;

      const bootstrap = await stagedBootstrapThresholdEcdsa({
        baseUrl: srvA.baseUrl,
        session: sharedSession,
        userId,
        rpId,
        clientRootShare32B64u,
        sessionId,
        participantIds,
      });
      expect(bootstrap.status, bootstrap.text).toBe(200);
      expect(bootstrap.json?.ok, bootstrap.text).toBe(true);

      const ecdsaThresholdKeyId = String(bootstrap.json?.ecdsaThresholdKeyId || '');
      const keyHandle = String(bootstrap.json?.keyHandle || '');
      const relayerKeyId = String(bootstrap.json?.relayerKeyId || '');
      const jwt = String(bootstrap.json?.jwt || '');
      expect(ecdsaThresholdKeyId).toBeTruthy();
      expect(keyHandle).toBeTruthy();
      expect(relayerKeyId).toBeTruthy();
      expect(jwt).toBeTruthy();

      const presignInit = await fetchJson(`${srvA.baseUrl}/threshold-ecdsa/presign/init`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${jwt}`,
        },
        body: JSON.stringify({
          keyHandle,
          count: 1,
        }),
      });
      expect(presignInit.status, presignInit.text).toBe(200);
      expect(presignInit.json?.ok, presignInit.text).toBe(true);
      const presignSessionId = String(presignInit.json?.presignSessionId || '');
      expect(presignSessionId).toBeTruthy();

      // Call non-owner coordinator. It must forward over real HTTP to coordinator-a.
      const forwardedStep = await fetchJson(`${srvB.baseUrl}/threshold-ecdsa/presign/step`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${jwt}`,
        },
        body: JSON.stringify({
          presignSessionId,
          stage: 'triples',
          outgoingMessagesB64u: [],
        }),
      });
      expect(forwardedStep.status, forwardedStep.text).toBe(200);
      expect(forwardedStep.json?.ok, forwardedStep.text).toBe(true);

      const persisted = await handlerA.presignSessionStore.getSession(presignSessionId);
      expect(persisted).not.toBeNull();
      expect(Number(persisted?.version || 0)).toBeGreaterThan(1);

      expect(handlerB.livePresignSessionById.has(presignSessionId)).toBe(false);
      expect(handlerA.livePresignSessionById.has(presignSessionId)).toBe(true);
    } finally {
      await srvB.close();
      await srvA.close();
    }
  });

  test('exports the canonical ECDSA key for the same staged threshold identity', async () => {
    const { service, threshold } = makeAuthServiceForThreshold();
    const session = makeJwtSessionAdapter();
    const router = createRelayRouter(service, { threshold, session });
    const srv = await startExpressRouter(router);

    try {
      const userId = 'exporter.testnet';
      const rpId = 'example.localhost';
      const participantIds = [1, 2];
      const clientRootShare32 = randomSecpSecretKey32();
      const clientRootShare32B64u = base64UrlEncode(clientRootShare32);
      const bootstrap = await stagedBootstrapThresholdEcdsa({
        baseUrl: srv.baseUrl,
        session,
        userId,
        rpId,
        clientRootShare32B64u,
        sessionId: `sess-${Date.now()}`,
        participantIds,
      });
      expect(bootstrap.status, bootstrap.text).toBe(200);
      expect(bootstrap.json?.ok, bootstrap.text).toBe(true);
      expectNoCanonicalExportMaterial(bootstrap.json);

      const ecdsaThresholdKeyId = String(bootstrap.json?.ecdsaThresholdKeyId || '');
      const jwt = String(bootstrap.json?.jwt || '');
      const thresholdEcdsaPublicKeyB64u = String(bootstrap.json?.thresholdEcdsaPublicKeyB64u || '');
      const ethereumAddress = String(bootstrap.json?.ethereumAddress || '');
      expect(ecdsaThresholdKeyId).toBeTruthy();
      expect(jwt).toBeTruthy();
      expect(thresholdEcdsaPublicKeyB64u).toBeTruthy();
      expect(ethereumAddress).toBeTruthy();

      const exported = await stagedExplicitExportThresholdEcdsa({
        baseUrl: srv.baseUrl,
        userId,
        rpId,
        ecdsaThresholdKeyId,
        clientRootShare32B64u,
        jwt,
        bootstrapJson: bootstrap.json || {},
      });
      expect(exported.status, exported.text).toBe(200);
      expect(exported.json?.ok, exported.text).toBe(true);
      expect(String(exported.json?.privateKeyHex || '')).toMatch(/^0x[0-9a-f]{64}$/);
      expect(String(exported.json?.canonicalPublicKeyHex || '')).toBe(
        `0x${Buffer.from(base64UrlDecode(thresholdEcdsaPublicKeyB64u)).toString('hex')}`,
      );
      expect(String(exported.json?.canonicalEthereumAddress || '')).toBe(ethereumAddress);
      expect('jwt' in (exported.json || {})).toBe(false);
      expect('sessionId' in (exported.json || {})).toBe(false);
    } finally {
      await srv.close();
    }
  });

  test('export/share rejects app-session JWTs at the threshold-session boundary', async () => {
    const { service, threshold } = makeAuthServiceForThreshold();
    const session = makeJwtSessionAdapter();
    const router = createRelayRouter(service, { threshold, session });
    const srv = await startExpressRouter(router);

    try {
      const userId = 'explicit-export-app-session.testnet';
      const rpId = 'example.localhost';
      const participantIds = [1, 2];
      const clientRootShare32B64u = base64UrlEncode(randomSecpSecretKey32());
      const bootstrap = await stagedBootstrapThresholdEcdsa({
        baseUrl: srv.baseUrl,
        session,
        userId,
        rpId,
        clientRootShare32B64u,
        sessionId: `sess-${Date.now()}`,
        participantIds,
      });
      expect(bootstrap.status, bootstrap.text).toBe(200);
      expect(bootstrap.json?.ok, bootstrap.text).toBe(true);
      const ecdsaThresholdKeyId = String(bootstrap.json?.ecdsaThresholdKeyId || '');
      expect(ecdsaThresholdKeyId).toBeTruthy();

      const appSessionJwt = await mintAppSessionJwt({
        service,
        session,
        userId,
      });
      const request = await buildRoleLocalExportShareRequest({
        userId,
        rpId,
        ecdsaThresholdKeyId,
        bootstrapJson: bootstrap.json || {},
      });

      const exportedShare = await fetchJson(`${srv.baseUrl}/threshold-ecdsa/hss/export/share`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${appSessionJwt}`,
        },
        body: JSON.stringify(request),
      });
      expect(exportedShare.status, exportedShare.text).toBe(401);
      expect(exportedShare.json?.code).toBe('unauthorized');
      expect(exportedShare.json?.message).toBe('Invalid threshold session token claims');
    } finally {
      await srv.close();
    }
  });

  test('export/share rejects request userId outside threshold-session wallet scope', async () => {
    const { service, threshold } = makeAuthServiceForThreshold();
    const session = makeJwtSessionAdapter();
    const router = createRelayRouter(service, { threshold, session });
    const srv = await startExpressRouter(router);

    try {
      const userId = 'explicit-export-wallet-scope.testnet';
      const rpId = 'example.localhost';
      const participantIds = [1, 2];
      const clientRootShare32B64u = base64UrlEncode(randomSecpSecretKey32());
      const bootstrap = await stagedBootstrapThresholdEcdsa({
        baseUrl: srv.baseUrl,
        session,
        userId,
        rpId,
        clientRootShare32B64u,
        sessionId: `sess-${Date.now()}`,
        participantIds,
      });
      expect(bootstrap.status, bootstrap.text).toBe(200);
      expect(bootstrap.json?.ok, bootstrap.text).toBe(true);
      const ecdsaThresholdKeyId = String(bootstrap.json?.ecdsaThresholdKeyId || '');
      const jwt = String(bootstrap.json?.jwt || '');
      expect(ecdsaThresholdKeyId).toBeTruthy();
      expect(jwt).toBeTruthy();
      const request = await buildRoleLocalExportShareRequest({
        userId,
        rpId,
        ecdsaThresholdKeyId,
        bootstrapJson: bootstrap.json || {},
      });

      const exportedShare = await fetchJson(`${srv.baseUrl}/threshold-ecdsa/hss/export/share`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${jwt}`,
        },
        body: JSON.stringify({
          ...request,
          walletId: 'google:117142622123955425762',
        }),
      });
      expect(exportedShare.status, exportedShare.text).toBe(400);
      expect(exportedShare.json?.code).toBe('identity_mismatch');
      expect(exportedShare.json?.message).toBe('walletId mismatch');
    } finally {
      await srv.close();
    }
  });

  test('role-local bootstrap provisions ECDSA once, then later bootstrap/export reuse persisted key material', async () => {
    const { service, threshold } = makeAuthServiceForThreshold();
    const session = makeJwtSessionAdapter();
    const router = createRelayRouter(service, { threshold, session });
    const srv = await startExpressRouter(router);

    try {
      const userId = 'deferred-bootstrap.testnet';
      const rpId = 'example.localhost';
      const participantIds = [1, 2];
      const clientRootShare32B64u = base64UrlEncode(randomSecpSecretKey32());

      const firstBootstrap = await stagedBootstrapThresholdEcdsa({
        baseUrl: srv.baseUrl,
        session,
        userId,
        rpId,
        clientRootShare32B64u,
        sessionId: `ecdsa-first-${Date.now()}`,
        participantIds,
      });
      expect(firstBootstrap.status, firstBootstrap.text).toBe(200);
      expect(firstBootstrap.json?.ok, firstBootstrap.text).toBe(true);
      expectNoCanonicalExportMaterial(firstBootstrap.json);

      const ecdsaThresholdKeyId = String(firstBootstrap.json?.ecdsaThresholdKeyId || '');
      const keyHandle = String(firstBootstrap.json?.keyHandle || '');
      const relayerKeyId = String(firstBootstrap.json?.relayerKeyId || '');
      const thresholdEcdsaPublicKeyB64u = String(
        firstBootstrap.json?.thresholdEcdsaPublicKeyB64u || '',
      );
      const ethereumAddress = String(firstBootstrap.json?.ethereumAddress || '');
      const ecdsaJwt = String(firstBootstrap.json?.jwt || '');
      expect(ecdsaThresholdKeyId).toBeTruthy();
      expect(keyHandle).toBeTruthy();
      expect(relayerKeyId).toBeTruthy();
      expect(thresholdEcdsaPublicKeyB64u).toBeTruthy();
      expect(ethereumAddress).toBeTruthy();
      expect(ecdsaJwt).toBeTruthy();

      const firstPresignInit = await fetchJson(`${srv.baseUrl}/threshold-ecdsa/presign/init`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${ecdsaJwt}`,
        },
        body: JSON.stringify({
          keyHandle,
          count: 1,
        }),
      });
      expect(firstPresignInit.status, firstPresignInit.text).toBe(200);
      expect(firstPresignInit.json?.ok, firstPresignInit.text).toBe(true);
      expect(String(firstPresignInit.json?.presignSessionId || '')).toBeTruthy();

      (threshold as any).secp256k1MasterSecretB64u = '';

      const resumedBootstrap = await stagedBootstrapThresholdEcdsa({
        baseUrl: srv.baseUrl,
        session,
        userId,
        rpId,
        clientRootShare32B64u,
        sessionId: `ecdsa-second-${Date.now()}`,
        participantIds,
      });
      expect(resumedBootstrap.status, resumedBootstrap.text).toBe(200);
      expect(resumedBootstrap.json?.ok, resumedBootstrap.text).toBe(true);
      expectNoCanonicalExportMaterial(resumedBootstrap.json);
      expect(String(resumedBootstrap.json?.ecdsaThresholdKeyId || '')).toBe(ecdsaThresholdKeyId);
      expect(String(resumedBootstrap.json?.keyHandle || '')).toBe(keyHandle);
      expect(String(resumedBootstrap.json?.thresholdEcdsaPublicKeyB64u || '')).toBe(
        thresholdEcdsaPublicKeyB64u,
      );
      expect(String(resumedBootstrap.json?.ethereumAddress || '')).toBe(ethereumAddress);

      const resumedJwt = String(resumedBootstrap.json?.jwt || '');
      expect(resumedJwt).toBeTruthy();

      const exported = await stagedExplicitExportThresholdEcdsa({
        baseUrl: srv.baseUrl,
        userId,
        rpId,
        ecdsaThresholdKeyId,
        clientRootShare32B64u,
        jwt: resumedJwt,
        bootstrapJson: resumedBootstrap.json || {},
      });
      expect(exported.status, exported.text).toBe(200);
      expect(exported.json?.ok, exported.text).toBe(true);
      expect(String(exported.json?.privateKeyHex || '')).toMatch(/^0x[0-9a-f]{64}$/);
      expect(String(exported.json?.canonicalPublicKeyHex || '')).toBe(
        `0x${Buffer.from(base64UrlDecode(thresholdEcdsaPublicKeyB64u)).toString('hex')}`,
      );
      expect(String(exported.json?.canonicalEthereumAddress || '')).toBe(ethereumAddress);
    } finally {
      await srv.close();
    }
  });

  test('returns stale_session_state after owner restart and recovers via new presign init', async () => {
    const sharedSession = makeJwtSessionAdapter();
    const a = makeAuthServiceForThreshold({
      THRESHOLD_NODE_ROLE: 'coordinator',
      THRESHOLD_COORDINATOR_INSTANCE_ID: 'coordinator-a',
      THRESHOLD_COORDINATOR_PEERS: '[]',
    });
    const routerA = createRelayRouter(a.service, {
      threshold: a.threshold,
      session: sharedSession,
    });
    const srvA = await startExpressRouter(routerA);

    const b = makeAuthServiceForThreshold({
      THRESHOLD_NODE_ROLE: 'coordinator',
      THRESHOLD_COORDINATOR_INSTANCE_ID: 'coordinator-b',
      THRESHOLD_COORDINATOR_PEERS: JSON.stringify([
        { instanceId: 'coordinator-a', relayerUrl: srvA.baseUrl },
      ]),
    });
    const routerB = createRelayRouter(b.service, {
      threshold: b.threshold,
      session: sharedSession,
    });
    const srvB = await startExpressRouter(routerB);

    try {
      const handlerA = (a.threshold as any).ecdsaSigningHandlers as {
        presignSessionStore: {
          getSession: (id: string) => Promise<{ version?: number } | null>;
        };
        livePresignSessionById: Map<string, unknown>;
      };
      const thresholdA = a.threshold as any;
      const thresholdB = b.threshold as any;
      const handlerB = thresholdB.ecdsaSigningHandlers as {
        presignSessionStore: unknown;
      };
      handlerB.presignSessionStore = handlerA.presignSessionStore;
      thresholdB.ecdsaKeyStore = thresholdA.ecdsaKeyStore;

      const userId = 'forwarding-owner-restart.testnet';
      const rpId = 'example.localhost';
      const participantIds = [1, 2];
      const clientRootShare32B64u = base64UrlEncode(randomSecpSecretKey32());
      const sessionId = `sess-${Date.now()}`;

      const bootstrap = await stagedBootstrapThresholdEcdsa({
        baseUrl: srvA.baseUrl,
        session: sharedSession,
        userId,
        rpId,
        clientRootShare32B64u,
        sessionId,
        participantIds,
        remainingUses: 10,
      });
      expect(bootstrap.status, bootstrap.text).toBe(200);
      expect(bootstrap.json?.ok, bootstrap.text).toBe(true);

      const ecdsaThresholdKeyId = String(bootstrap.json?.ecdsaThresholdKeyId || '');
      const keyHandle = String(bootstrap.json?.keyHandle || '');
      const relayerKeyId = String(bootstrap.json?.relayerKeyId || '');
      const jwt = String(bootstrap.json?.jwt || '');
      expect(ecdsaThresholdKeyId).toBeTruthy();
      expect(keyHandle).toBeTruthy();
      expect(relayerKeyId).toBeTruthy();
      expect(jwt).toBeTruthy();

      const presignInitA = await fetchJson(`${srvA.baseUrl}/threshold-ecdsa/presign/init`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${jwt}`,
        },
        body: JSON.stringify({
          keyHandle,
          count: 1,
        }),
      });
      expect(presignInitA.status, presignInitA.text).toBe(200);
      expect(presignInitA.json?.ok, presignInitA.text).toBe(true);
      const staleSessionId = String(presignInitA.json?.presignSessionId || '');
      expect(staleSessionId).toBeTruthy();

      // Simulate owner restart by dropping live presign sessions while keeping durable records.
      handlerA.livePresignSessionById.clear();

      const staleStep = await fetchJson(`${srvB.baseUrl}/threshold-ecdsa/presign/step`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${jwt}`,
        },
        body: JSON.stringify({
          presignSessionId: staleSessionId,
          stage: 'triples',
          outgoingMessagesB64u: [],
        }),
      });
      expect(staleStep.status, staleStep.text).toBe(409);
      expect(staleStep.json?.ok).toBe(false);
      expect(String(staleStep.json?.code || '')).toBe('stale_session_state');
      expect(String(staleStep.json?.message || '')).toContain('/threshold-ecdsa/presign/init');

      const stalePersisted = await handlerA.presignSessionStore.getSession(staleSessionId);
      expect(stalePersisted).toBeNull();

      // Client recovers by creating a fresh presign session.
      const recoveredInit = await fetchJson(`${srvB.baseUrl}/threshold-ecdsa/presign/init`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${jwt}`,
        },
        body: JSON.stringify({
          keyHandle,
          count: 1,
        }),
      });
      expect(recoveredInit.status, recoveredInit.text).toBe(200);
      expect(recoveredInit.json?.ok, recoveredInit.text).toBe(true);
      const recoveredSessionId = String(recoveredInit.json?.presignSessionId || '');
      expect(recoveredSessionId).toBeTruthy();
      expect(recoveredSessionId).not.toBe(staleSessionId);

      const recoveredStep = await fetchJson(`${srvB.baseUrl}/threshold-ecdsa/presign/step`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${jwt}`,
        },
        body: JSON.stringify({
          presignSessionId: recoveredSessionId,
          stage: 'triples',
          outgoingMessagesB64u: [],
        }),
      });
      expect(recoveredStep.status, recoveredStep.text).toBe(200);
      expect(recoveredStep.json?.ok, recoveredStep.text).toBe(true);
    } finally {
      await srvB.close();
      await srvA.close();
    }
  });

  test('returns stale_session_state when owner coordinator peer mapping is missing', async () => {
    const sharedSession = makeJwtSessionAdapter();
    const a = makeAuthServiceForThreshold({
      THRESHOLD_NODE_ROLE: 'coordinator',
      THRESHOLD_COORDINATOR_INSTANCE_ID: 'coordinator-a',
      THRESHOLD_COORDINATOR_PEERS: '[]',
    });
    const routerA = createRelayRouter(a.service, {
      threshold: a.threshold,
      session: sharedSession,
    });
    const srvA = await startExpressRouter(routerA);

    const b = makeAuthServiceForThreshold({
      THRESHOLD_NODE_ROLE: 'coordinator',
      THRESHOLD_COORDINATOR_INSTANCE_ID: 'coordinator-b',
      THRESHOLD_COORDINATOR_PEERS: '[]',
    });
    const routerB = createRelayRouter(b.service, {
      threshold: b.threshold,
      session: sharedSession,
    });
    const srvB = await startExpressRouter(routerB);

    try {
      const handlerA = (a.threshold as any).ecdsaSigningHandlers as {
        presignSessionStore: {
          getSession: (id: string) => Promise<{ version?: number } | null>;
        };
      };
      const handlerB = (b.threshold as any).ecdsaSigningHandlers as {
        presignSessionStore: unknown;
      };
      handlerB.presignSessionStore = handlerA.presignSessionStore;

      const userId = 'forwarding-peer-missing.testnet';
      const rpId = 'example.localhost';
      const participantIds = [1, 2];
      const clientRootShare32B64u = base64UrlEncode(randomSecpSecretKey32());
      const sessionId = `sess-${Date.now()}`;

      const bootstrap = await stagedBootstrapThresholdEcdsa({
        baseUrl: srvA.baseUrl,
        session: sharedSession,
        userId,
        rpId,
        clientRootShare32B64u,
        sessionId,
        participantIds,
      });
      expect(bootstrap.status, bootstrap.text).toBe(200);
      expect(bootstrap.json?.ok, bootstrap.text).toBe(true);

      const ecdsaThresholdKeyId = String(bootstrap.json?.ecdsaThresholdKeyId || '');
      const keyHandle = String(bootstrap.json?.keyHandle || '');
      const relayerKeyId = String(bootstrap.json?.relayerKeyId || '');
      const jwt = String(bootstrap.json?.jwt || '');
      expect(ecdsaThresholdKeyId).toBeTruthy();
      expect(keyHandle).toBeTruthy();
      expect(relayerKeyId).toBeTruthy();
      expect(jwt).toBeTruthy();

      const presignInit = await fetchJson(`${srvA.baseUrl}/threshold-ecdsa/presign/init`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${jwt}`,
        },
        body: JSON.stringify({
          keyHandle,
          count: 1,
        }),
      });
      expect(presignInit.status, presignInit.text).toBe(200);
      expect(presignInit.json?.ok, presignInit.text).toBe(true);
      const presignSessionId = String(presignInit.json?.presignSessionId || '');
      expect(presignSessionId).toBeTruthy();

      const step = await fetchJson(`${srvB.baseUrl}/threshold-ecdsa/presign/step`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${jwt}`,
        },
        body: JSON.stringify({
          presignSessionId,
          stage: 'triples',
          outgoingMessagesB64u: [],
        }),
      });
      expect(step.status, step.text).toBe(409);
      expect(step.json?.ok).toBe(false);
      expect(String(step.json?.code || '')).toBe('stale_session_state');
      expect(String(step.json?.message || '')).toContain('owner unavailable');

      // Owner coordinator's durable presign session remains available for retry.
      const persisted = await handlerA.presignSessionStore.getSession(presignSessionId);
      expect(persisted).not.toBeNull();
      expect(Number(persisted?.version || 0)).toBe(1);
    } finally {
      await srvB.close();
      await srvA.close();
    }
  });

  test('ignores untrusted forwarded hop header from client and still forwards to owner', async () => {
    const sharedSession = makeJwtSessionAdapter();
    const a = makeAuthServiceForThreshold({
      THRESHOLD_NODE_ROLE: 'coordinator',
      THRESHOLD_COORDINATOR_INSTANCE_ID: 'coordinator-a',
      THRESHOLD_COORDINATOR_PEERS: '[]',
    });
    const routerA = createRelayRouter(a.service, {
      threshold: a.threshold,
      session: sharedSession,
    });
    const srvA = await startExpressRouter(routerA);

    const b = makeAuthServiceForThreshold({
      THRESHOLD_NODE_ROLE: 'coordinator',
      THRESHOLD_COORDINATOR_INSTANCE_ID: 'coordinator-b',
      THRESHOLD_COORDINATOR_PEERS: JSON.stringify([
        { instanceId: 'coordinator-a', relayerUrl: srvA.baseUrl },
      ]),
    });
    const routerB = createRelayRouter(b.service, {
      threshold: b.threshold,
      session: sharedSession,
    });
    const srvB = await startExpressRouter(routerB);

    try {
      const handlerA = (a.threshold as any).ecdsaSigningHandlers as {
        presignSessionStore: {
          getSession: (id: string) => Promise<{ version?: number } | null>;
        };
      };
      const handlerB = (b.threshold as any).ecdsaSigningHandlers as {
        presignSessionStore: unknown;
      };
      handlerB.presignSessionStore = handlerA.presignSessionStore;

      const userId = 'forwarding-untrusted-hop.testnet';
      const rpId = 'example.localhost';
      const participantIds = [1, 2];
      const clientRootShare32B64u = base64UrlEncode(randomSecpSecretKey32());
      const sessionId = `sess-${Date.now()}`;

      const bootstrap = await stagedBootstrapThresholdEcdsa({
        baseUrl: srvA.baseUrl,
        session: sharedSession,
        userId,
        rpId,
        clientRootShare32B64u,
        sessionId,
        participantIds,
      });
      expect(bootstrap.status, bootstrap.text).toBe(200);
      expect(bootstrap.json?.ok, bootstrap.text).toBe(true);

      const ecdsaThresholdKeyId = String(bootstrap.json?.ecdsaThresholdKeyId || '');
      const keyHandle = String(bootstrap.json?.keyHandle || '');
      const relayerKeyId = String(bootstrap.json?.relayerKeyId || '');
      const jwt = String(bootstrap.json?.jwt || '');
      expect(ecdsaThresholdKeyId).toBeTruthy();
      expect(keyHandle).toBeTruthy();
      expect(relayerKeyId).toBeTruthy();
      expect(jwt).toBeTruthy();

      const presignInit = await fetchJson(`${srvA.baseUrl}/threshold-ecdsa/presign/init`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${jwt}`,
        },
        body: JSON.stringify({
          keyHandle,
          count: 1,
        }),
      });
      expect(presignInit.status, presignInit.text).toBe(200);
      expect(presignInit.json?.ok, presignInit.text).toBe(true);
      const presignSessionId = String(presignInit.json?.presignSessionId || '');
      expect(presignSessionId).toBeTruthy();

      const step = await fetchJson(`${srvB.baseUrl}/threshold-ecdsa/presign/step`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${jwt}`,
          'x-threshold-ecdsa-presign-forward-hop': '99',
        },
        body: JSON.stringify({
          presignSessionId,
          stage: 'triples',
          outgoingMessagesB64u: [],
        }),
      });
      expect(step.status, step.text).toBe(200);
      expect(step.json?.ok, step.text).toBe(true);

      const persisted = await handlerA.presignSessionStore.getSession(presignSessionId);
      expect(persisted).not.toBeNull();
      expect(Number(persisted?.version || 0)).toBeGreaterThan(1);
    } finally {
      await srvB.close();
      await srvA.close();
    }
  });
});
