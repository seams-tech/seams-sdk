import { test, expect } from '@playwright/test';
import { readFileSync } from 'node:fs';
import { secp256k1 } from '@noble/curves/secp256k1.js';
import { base64UrlDecode, base64UrlEncode } from '@shared/utils/encoders';
import { alphabetizeStringify, sha256BytesUtf8 } from '@shared/utils/digests';
import {
  computeEcdsaHssRoleLocalRelayerKeyId,
  computeEcdsaHssRoleLocalThresholdKeyId,
} from '@shared/threshold/ecdsaHssRoleLocalBootstrap';
import type { RouterAbEcdsaHssNormalSigningScopeV1 } from '@shared/utils/routerAbEcdsaHss';
import { ROUTER_AB_ECDSA_HSS_WALLET_SESSION_JWT_KIND } from '@shared/utils/sessionTokens';
import {
  ROUTER_AB_PUBLIC_KEYSET_VERSION_V2,
  type RouterAbPublicKeysetV2,
} from '@shared/utils/routerAbPublicKeyset';
import { createRelayRouter } from '@server/router/express-adaptor';
import { AuthService } from '@server/core/AuthService';
import { createThresholdSigningService } from '@server/core/ThresholdService';
import type { ThresholdStoreConfigInput } from '@server/core/types';
import { makeSessionAdapter, fetchJson, startExpressRouter } from './helpers';
import { createFixtureSigningRootShareResolverForUnitTests } from '../helpers/thresholdEd25519TestUtils';
import {
  build_ecdsa_role_local_export_artifact_v1,
  initSync as initHssClientSignerWasmSync,
  open_ecdsa_role_local_signing_share_v1,
  threshold_ecdsa_hss_role_local_finalize_client_bootstrap,
} from '../../wasm/hss_client_signer/pkg/hss_client_signer.js';
import { prepareResolvedEmailOtpRootEcdsaClientBootstrapForTest } from '../helpers/thresholdEcdsaClientBootstrap';

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
const TEST_ECDSA_CHAIN_TARGET = {
  kind: 'evm',
  namespace: 'eip155',
  chainId: 1,
  networkSlug: 'ethereum',
} as const;
const EXPORT_CONFIRMATION_DIGEST_VERSION = 'ecdsa-hss:role-local:product-export-confirmation:v2';
const EXPORT_AUTHORIZATION_DIGEST_VERSION = 'ecdsa-hss:role-local:product-export-authorization:v2';
const TEST_ROUTER_AB_PUBLIC_KEYSET = {
  keyset_version: ROUTER_AB_PUBLIC_KEYSET_VERSION_V2,
  signer_envelope_hpke: {
    current: {
      deriver_a: {
        role: 'signer_a',
        key_epoch: 'epoch-a',
        public_key: `x25519:${'11'.repeat(32)}`,
      },
      deriver_b: {
        role: 'signer_b',
        key_epoch: 'epoch-b',
        public_key: `x25519:${'22'.repeat(32)}`,
      },
    },
  },
  signer_peer_verifying_keys: {
    deriver_a: { role: 'signer_a', verifying_key_hex: 'aa'.repeat(32) },
    deriver_b: { role: 'signer_b', verifying_key_hex: 'bb'.repeat(32) },
  },
  signing_worker_server_output_hpke: {
    key_epoch: 'signing-worker-output-epoch',
    public_key: `x25519:${'33'.repeat(32)}`,
  },
} satisfies RouterAbPublicKeysetV2;
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
    providedConfig.signingRootShareResolverAdapters ||
    providedConfig.signingRootSharePolicy ||
    providedConfig.signingRootShareStore ||
    providedConfig.signingRootShareDecryptAdapter
  );
  const thresholdConfigDefaults: ThresholdStoreConfigInput = {
    kind: 'in-memory',
    THRESHOLD_NODE_ROLE: 'coordinator',
    ROUTER_AB_NORMAL_SIGNING_WORKER_ID: 'unit-signing-worker',
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

function hssJsonHeaders(rpId: string, jwt?: string): Record<string, string> {
  return {
    'Content-Type': 'application/json',
    Origin: `https://${rpId}`,
    ...(jwt ? { Authorization: `Bearer ${jwt}` } : {}),
  };
}

function hexAddress20ToB64u(address: string): string {
  const normalized = address.trim().replace(/^0x/i, '');
  if (!/^[0-9a-fA-F]{40}$/.test(normalized)) {
    throw new Error('Expected a 20-byte ECDSA-HSS Ethereum address in bootstrap response');
  }
  return Buffer.from(normalized, 'hex').toString('base64url');
}

function buildRouterAbEcdsaHssPoolFillFromBootstrap(bootstrapJson: Record<string, unknown>) {
  const publicIdentity = (bootstrapJson.publicIdentity || {}) as Record<string, unknown>;
  const clientBootstrap = (bootstrapJson.clientBootstrap || {}) as Record<string, unknown>;
  const sessionExpiresAtMs = Number(bootstrapJson.expiresAtMs || Date.now() + 60_000);
  const expiresAtMs = Math.max(1, Math.min(sessionExpiresAtMs - 1, Date.now() + 30_000));
  const scope: RouterAbEcdsaHssNormalSigningScopeV1 = {
    context: {
      wallet_id: String(bootstrapJson.walletId || ''),
      rp_id: String(bootstrapJson.rpId || ''),
      key_scope: 'evm-family',
      ecdsa_threshold_key_id: String(bootstrapJson.ecdsaThresholdKeyId || ''),
      signing_root_id: String(bootstrapJson.signingRootId || TEST_SIGNING_ROOT_ID),
      signing_root_version: String(
        bootstrapJson.signingRootVersion || TEST_RUNTIME_SCOPE.signingRootVersion || 'default',
      ),
      key_purpose: 'normal-signing',
      key_version: 'v1',
    },
    public_identity: {
      context_binding_b64u: String(
        bootstrapJson.contextBinding32B64u || clientBootstrap.contextBinding32B64u || '',
      ),
      client_public_key33_b64u: String(
        bootstrapJson.clientVerifyingShareB64u ||
          publicIdentity.hssClientSharePublicKey33B64u ||
          clientBootstrap.hssClientSharePublicKey33B64u ||
          '',
      ),
      server_public_key33_b64u: String(publicIdentity.relayerPublicKey33B64u || ''),
      threshold_public_key33_b64u: String(
        bootstrapJson.thresholdEcdsaPublicKeyB64u || publicIdentity.groupPublicKey33B64u || '',
      ),
      ethereum_address20_b64u: hexAddress20ToB64u(
        String(bootstrapJson.ethereumAddress || publicIdentity.ethereumAddress || ''),
      ),
      client_share_retry_counter: Number(clientBootstrap.clientShareRetryCounter || 0),
      server_share_retry_counter: Number(publicIdentity.serverShareRetryCounter || 0),
    },
    signing_worker: {
      server_id: 'signing-worker-a',
      key_epoch: 'epoch-1',
      recipient_encryption_key: 'recipient-key',
    },
    activation_epoch: 'activation-1',
  };
  return {
    kind: 'router_ab_ecdsa_hss_signing_worker_pool' as const,
    scope,
    expiresAtMs,
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
  const signingGrantId = `${args.sessionId}:wallet-signing`;
  const ttlMs = args.ttlMs ?? 60_000;
  const remainingUses = args.remainingUses ?? 3;

  ensureHssClientSignerWasm();
  const preparedClientBootstrap = prepareResolvedEmailOtpRootEcdsaClientBootstrapForTest({
    context: {
      walletId: args.userId,
      rpId: args.rpId,
      chainTarget: TEST_ECDSA_CHAIN_TARGET,
      ecdsaThresholdKeyId,
      signingRootId,
      signingRootVersion,
    },
    clientRootShare32B64u: args.clientRootShare32B64u,
  });

  const bootstrap = await fetchJson(`${args.baseUrl}/v1/hss/ecdsa/bootstrap`, {
    method: 'POST',
    headers: hssJsonHeaders(args.rpId),
    body: JSON.stringify({
      formatVersion: 'ecdsa-hss-role-local',
      walletId: args.userId,
      rpId: args.rpId,
      ecdsaThresholdKeyId,
      signingRootId,
      signingRootVersion,
      keyScope: 'evm-family',
      relayerKeyId,
      hssClientSharePublicKey33B64u: preparedClientBootstrap.hssClientSharePublicKey33B64u,
      clientShareRetryCounter: preparedClientBootstrap.clientShareRetryCounter,
      contextBinding32B64u: preparedClientBootstrap.contextBinding32B64u,
      requestId: `bootstrap-request-${Date.now()}`,
      sessionId: args.sessionId,
      signingGrantId,
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
  const publicIdentity = value.publicIdentity as Record<string, unknown>;
  const readyClientBootstrap = threshold_ecdsa_hss_role_local_finalize_client_bootstrap({
    pendingStateBlobB64u: preparedClientBootstrap.pendingStateBlobB64u,
    relayerKeyId: String(value.relayerKeyId || relayerKeyId),
    relayerPublicKey33B64u: String(publicIdentity.relayerPublicKey33B64u || ''),
    groupPublicKey33B64u: String(publicIdentity.groupPublicKey33B64u || ''),
    ethereumAddress: String(publicIdentity.ethereumAddress || ''),
  }) as {
    stateBlobB64u: string;
    clientVerifyingShareB64u: string;
    clientShareRetryCounter: number;
  };
  const openedClientSigningShare = open_ecdsa_role_local_signing_share_v1({
    stateBlobB64u: readyClientBootstrap.stateBlobB64u,
  }) as {
    signingShare32B64u: string;
  };
  const clientBootstrap = {
    ...preparedClientBootstrap,
    ...readyClientBootstrap,
    clientAdditiveShare32B64u: openedClientSigningShare.signingShare32B64u,
  };
  const jwt = await args.session.signJwt(args.userId, {
    kind: ROUTER_AB_ECDSA_HSS_WALLET_SESSION_JWT_KIND,
    walletId: args.userId,
    sessionId: String(value.sessionId || args.sessionId),
    signingGrantId: String(value.signingGrantId || signingGrantId),
    keyScope: 'evm-family',
    keyHandle: String(value.keyHandle || ''),
    relayerKeyId: String(value.relayerKeyId || relayerKeyId),
    rpId: args.rpId,
    thresholdExpiresAtMs: Number(value.expiresAtMs || Date.now() + ttlMs),
    participantIds: Array.isArray(value.participantIds)
      ? value.participantIds
      : args.participantIds,
    runtimePolicyScope: TEST_RUNTIME_SCOPE,
    routerAbEcdsaHssNormalSigning: {
      kind: 'router_ab_ecdsa_hss_normal_signing_v1',
      scope: {
        context: {
          wallet_id: args.userId,
          rp_id: args.rpId,
          key_scope: 'evm-family',
          ecdsa_threshold_key_id: ecdsaThresholdKeyId,
          signing_root_id: signingRootId,
          signing_root_version: signingRootVersion,
          key_purpose: 'evm-signing',
          key_version: 'v1',
        },
        public_identity: {
          context_binding_b64u: preparedClientBootstrap.contextBinding32B64u,
          client_public_key33_b64u: preparedClientBootstrap.hssClientSharePublicKey33B64u,
          server_public_key33_b64u: String(publicIdentity.relayerPublicKey33B64u || ''),
          threshold_public_key33_b64u: String(publicIdentity.groupPublicKey33B64u || ''),
          ethereum_address20_b64u: hexAddress20ToB64u(
            String(publicIdentity.ethereumAddress || ''),
          ),
          client_share_retry_counter: Number(preparedClientBootstrap.clientShareRetryCounter || 0),
          server_share_retry_counter: Number(value.relayerShareRetryCounter || 0),
        },
        signing_worker: {
          server_id: 'signing-worker-test',
          key_epoch: 'signing-worker-output-epoch',
          recipient_encryption_key: `x25519:${'33'.repeat(32)}`,
        },
        activation_epoch: String(value.sessionId || args.sessionId),
      },
    },
  });

  return {
    ...bootstrap,
    json: {
      ok: true,
      ...value,
      jwt,
      clientVerifyingShareB64u: clientBootstrap.clientVerifyingShareB64u,
      clientBootstrap,
    },
  };
}

async function stagedExplicitExportThresholdEcdsa(args: {
  baseUrl: string;
  userId: string;
  rpId: string;
  ecdsaThresholdKeyId: string;
  jwt: string;
  bootstrapJson: Record<string, unknown>;
}) {
  const exportRequest = await buildRoleLocalExportShareRequest(args);
  const publicIdentity = args.bootstrapJson.publicIdentity as Record<string, unknown>;
  const clientBootstrap = args.bootstrapJson.clientBootstrap as {
    stateBlobB64u: string;
    contextBinding32B64u: string;
    hssClientSharePublicKey33B64u: string;
    clientShareRetryCounter: number;
  };
  const exportedShare = await fetchJson(`${args.baseUrl}/v1/hss/ecdsa/export/share`, {
    method: 'POST',
    headers: hssJsonHeaders(args.rpId, args.jwt),
    body: JSON.stringify(exportRequest),
  });

  if (exportedShare.status !== 200 || exportedShare.json?.ok !== true) return exportedShare;
  const exportValue = (exportedShare.json.value || {}) as Record<string, unknown>;
  const signingRootId = String(args.bootstrapJson.signingRootId || TEST_SIGNING_ROOT_ID);
  const signingRootVersion = String(
    args.bootstrapJson.signingRootVersion || TEST_RUNTIME_SCOPE.signingRootVersion,
  );
  const artifact = JSON.parse(
    build_ecdsa_role_local_export_artifact_v1(
      JSON.stringify({
        kind: 'build_ecdsa_role_local_export_artifact_v1',
        algorithm: 'ecdsa_hss_secp256k1_role_local_v1',
        stateBlob: {
          kind: 'ecdsa_role_local_state_blob_v1',
          curve: 'secp256k1',
          encoding: 'base64url',
          producer: 'signer_core',
          stateBlobB64u: String(clientBootstrap.stateBlobB64u || ''),
        },
        publicFacts: {
          walletId: args.userId,
          rpId: args.rpId,
          chainTarget: TEST_ECDSA_CHAIN_TARGET,
          keyHandle: String(args.bootstrapJson.keyHandle || ''),
          ecdsaThresholdKeyId: args.ecdsaThresholdKeyId,
          signingRootId,
          signingRootVersion,
          clientParticipantId: 1,
          relayerParticipantId: 2,
          participantIds: Array.isArray(args.bootstrapJson.participantIds)
            ? args.bootstrapJson.participantIds
            : [1, 2],
          contextBinding32B64u: String(
            args.bootstrapJson.contextBinding32B64u || clientBootstrap.contextBinding32B64u || '',
          ),
          hssClientSharePublicKey33B64u: String(
            publicIdentity.hssClientSharePublicKey33B64u ||
              clientBootstrap.hssClientSharePublicKey33B64u ||
              '',
          ),
          relayerPublicKey33B64u: String(publicIdentity.relayerPublicKey33B64u || ''),
          groupPublicKey33B64u: String(publicIdentity.groupPublicKey33B64u || ''),
          ethereumAddress: String(publicIdentity.ethereumAddress || ''),
        },
        authorization: {
          kind: 'passkey_export_authorized',
          walletId: args.userId,
          rpId: args.rpId,
          credentialIdB64u: base64UrlEncode(new Uint8Array([1])),
        },
        serverExportShare32B64u: String(exportValue.serverExportShare32B64u || ''),
      }),
    ),
  ) as {
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
      signingGrantId: String(args.bootstrapJson.signingGrantId || ''),
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

function expectNoCanonicalExportMaterial(json: Record<string, unknown> | null): void {
  expect(json).not.toBeNull();
  expect('canonicalSecp256k1KeyB64u' in (json || {})).toBe(false);
  expect('canonical_x32_b64u' in (json || {})).toBe(false);
  expect('privateKeyHex' in (json || {})).toBe(false);
  expect('exportPrivateKeyHex' in (json || {})).toBe(false);
}

test.describe('threshold-ecdsa harness signature verification', () => {
  test.describe.configure({ timeout: 120_000 });

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
      routerAbPublicKeyset: TEST_ROUTER_AB_PUBLIC_KEYSET,
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
      routerAbPublicKeyset: TEST_ROUTER_AB_PUBLIC_KEYSET,
    });
    const srvB = await startExpressRouter(routerB);

    try {
      const handlerA = (a.threshold as any).routerAbEcdsaHssPoolFillHandlers as {
        poolFillSessionStore: {
          getSession: (id: string) => Promise<{ version?: number } | null>;
        };
        livePresignSessionById: Map<string, unknown>;
      };
      const handlerB = (b.threshold as any).routerAbEcdsaHssPoolFillHandlers as {
        poolFillSessionStore: unknown;
        livePresignSessionById: Map<string, unknown>;
      };

      // Simulate a shared durable presign-session store across coordinator instances.
      handlerB.poolFillSessionStore = handlerA.poolFillSessionStore;

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

      const presignInit = await fetchJson(`${srvA.baseUrl}/v1/hss/ecdsa/presignature-pool/fill/init`, {
        method: 'POST',
        headers: hssJsonHeaders(rpId, jwt),
        body: JSON.stringify({
          keyHandle,
          count: 1,
          poolFill: buildRouterAbEcdsaHssPoolFillFromBootstrap(bootstrap.json || {}),
        }),
      });
      expect(presignInit.status, presignInit.text).toBe(200);
      expect(presignInit.json?.ok, presignInit.text).toBe(true);
      const presignSessionId = String(presignInit.json?.presignSessionId || '');
      expect(presignSessionId).toBeTruthy();

      // Call non-owner coordinator. It must forward over real HTTP to coordinator-a.
      const forwardedStep = await fetchJson(`${srvB.baseUrl}/v1/hss/ecdsa/presignature-pool/fill/step`, {
        method: 'POST',
        headers: hssJsonHeaders(rpId, jwt),
        body: JSON.stringify({
          presignSessionId,
          stage: 'triples',
          outgoingMessagesB64u: [],
        }),
      });
      expect(forwardedStep.status, forwardedStep.text).toBe(200);
      expect(forwardedStep.json?.ok, forwardedStep.text).toBe(true);

      const persisted = await handlerA.poolFillSessionStore.getSession(presignSessionId);
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
    const router = createRelayRouter(service, {
      threshold,
      session,
      routerAbPublicKeyset: TEST_ROUTER_AB_PUBLIC_KEYSET,
    });
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

  test('export/share rejects app-session JWTs at the Wallet Session boundary', async () => {
    const { service, threshold } = makeAuthServiceForThreshold();
    const session = makeJwtSessionAdapter();
    const router = createRelayRouter(service, {
      threshold,
      session,
      routerAbPublicKeyset: TEST_ROUTER_AB_PUBLIC_KEYSET,
    });
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

      const exportedShare = await fetchJson(`${srv.baseUrl}/v1/hss/ecdsa/export/share`, {
        method: 'POST',
        headers: hssJsonHeaders(rpId, appSessionJwt),
        body: JSON.stringify(request),
      });
      expect(exportedShare.status, exportedShare.text).toBe(401);
      expect(exportedShare.json?.code).toBe('unauthorized');
      expect(exportedShare.json?.message).toBe('Invalid Wallet Session token claims');
    } finally {
      await srv.close();
    }
  });

  test('export/share rejects request userId outside Wallet Session wallet scope', async () => {
    const { service, threshold } = makeAuthServiceForThreshold();
    const session = makeJwtSessionAdapter();
    const router = createRelayRouter(service, {
      threshold,
      session,
      routerAbPublicKeyset: TEST_ROUTER_AB_PUBLIC_KEYSET,
    });
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

      const exportedShare = await fetchJson(`${srv.baseUrl}/v1/hss/ecdsa/export/share`, {
        method: 'POST',
        headers: hssJsonHeaders(rpId, jwt),
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
    const router = createRelayRouter(service, {
      threshold,
      session,
      routerAbPublicKeyset: TEST_ROUTER_AB_PUBLIC_KEYSET,
    });
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

      const firstPresignInit = await fetchJson(`${srv.baseUrl}/v1/hss/ecdsa/presignature-pool/fill/init`, {
        method: 'POST',
        headers: hssJsonHeaders(rpId, ecdsaJwt),
        body: JSON.stringify({
          keyHandle,
          count: 1,
          poolFill: buildRouterAbEcdsaHssPoolFillFromBootstrap(firstBootstrap.json || {}),
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
      routerAbPublicKeyset: TEST_ROUTER_AB_PUBLIC_KEYSET,
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
      routerAbPublicKeyset: TEST_ROUTER_AB_PUBLIC_KEYSET,
    });
    const srvB = await startExpressRouter(routerB);

    try {
      const handlerA = (a.threshold as any).routerAbEcdsaHssPoolFillHandlers as {
        poolFillSessionStore: {
          getSession: (id: string) => Promise<{ version?: number } | null>;
        };
        livePresignSessionById: Map<string, unknown>;
      };
      const thresholdA = a.threshold as any;
      const thresholdB = b.threshold as any;
      const handlerB = thresholdB.routerAbEcdsaHssPoolFillHandlers as {
        poolFillSessionStore: unknown;
      };
      handlerB.poolFillSessionStore = handlerA.poolFillSessionStore;
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

      const presignInitA = await fetchJson(`${srvA.baseUrl}/v1/hss/ecdsa/presignature-pool/fill/init`, {
        method: 'POST',
        headers: hssJsonHeaders(rpId, jwt),
        body: JSON.stringify({
          keyHandle,
          count: 1,
          poolFill: buildRouterAbEcdsaHssPoolFillFromBootstrap(bootstrap.json || {}),
        }),
      });
      expect(presignInitA.status, presignInitA.text).toBe(200);
      expect(presignInitA.json?.ok, presignInitA.text).toBe(true);
      const staleSessionId = String(presignInitA.json?.presignSessionId || '');
      expect(staleSessionId).toBeTruthy();

      // Simulate owner restart by dropping live presign sessions while keeping durable records.
      handlerA.livePresignSessionById.clear();

      const staleStep = await fetchJson(`${srvB.baseUrl}/v1/hss/ecdsa/presignature-pool/fill/step`, {
        method: 'POST',
        headers: hssJsonHeaders(rpId, jwt),
        body: JSON.stringify({
          presignSessionId: staleSessionId,
          stage: 'triples',
          outgoingMessagesB64u: [],
        }),
      });
      expect(staleStep.status, staleStep.text).toBe(409);
      expect(staleStep.json?.ok).toBe(false);
      expect(String(staleStep.json?.code || '')).toBe('stale_session_state');
      expect(String(staleStep.json?.message || '')).toContain('/v1/hss/ecdsa/presignature-pool/fill/init');

      const stalePersisted = await handlerA.poolFillSessionStore.getSession(staleSessionId);
      expect(stalePersisted).toBeNull();

      // Client recovers by creating a fresh presign session.
      const recoveredInit = await fetchJson(`${srvB.baseUrl}/v1/hss/ecdsa/presignature-pool/fill/init`, {
        method: 'POST',
        headers: hssJsonHeaders(rpId, jwt),
        body: JSON.stringify({
          keyHandle,
          count: 1,
          poolFill: buildRouterAbEcdsaHssPoolFillFromBootstrap(bootstrap.json || {}),
        }),
      });
      expect(recoveredInit.status, recoveredInit.text).toBe(200);
      expect(recoveredInit.json?.ok, recoveredInit.text).toBe(true);
      const recoveredSessionId = String(recoveredInit.json?.presignSessionId || '');
      expect(recoveredSessionId).toBeTruthy();
      expect(recoveredSessionId).not.toBe(staleSessionId);

      const recoveredStep = await fetchJson(`${srvB.baseUrl}/v1/hss/ecdsa/presignature-pool/fill/step`, {
        method: 'POST',
        headers: hssJsonHeaders(rpId, jwt),
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
      routerAbPublicKeyset: TEST_ROUTER_AB_PUBLIC_KEYSET,
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
      routerAbPublicKeyset: TEST_ROUTER_AB_PUBLIC_KEYSET,
    });
    const srvB = await startExpressRouter(routerB);

    try {
      const handlerA = (a.threshold as any).routerAbEcdsaHssPoolFillHandlers as {
        poolFillSessionStore: {
          getSession: (id: string) => Promise<{ version?: number } | null>;
        };
      };
      const handlerB = (b.threshold as any).routerAbEcdsaHssPoolFillHandlers as {
        poolFillSessionStore: unknown;
      };
      handlerB.poolFillSessionStore = handlerA.poolFillSessionStore;

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

      const presignInit = await fetchJson(`${srvA.baseUrl}/v1/hss/ecdsa/presignature-pool/fill/init`, {
        method: 'POST',
        headers: hssJsonHeaders(rpId, jwt),
        body: JSON.stringify({
          keyHandle,
          count: 1,
          poolFill: buildRouterAbEcdsaHssPoolFillFromBootstrap(bootstrap.json || {}),
        }),
      });
      expect(presignInit.status, presignInit.text).toBe(200);
      expect(presignInit.json?.ok, presignInit.text).toBe(true);
      const presignSessionId = String(presignInit.json?.presignSessionId || '');
      expect(presignSessionId).toBeTruthy();

      const step = await fetchJson(`${srvB.baseUrl}/v1/hss/ecdsa/presignature-pool/fill/step`, {
        method: 'POST',
        headers: hssJsonHeaders(rpId, jwt),
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
      const persisted = await handlerA.poolFillSessionStore.getSession(presignSessionId);
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
      routerAbPublicKeyset: TEST_ROUTER_AB_PUBLIC_KEYSET,
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
      routerAbPublicKeyset: TEST_ROUTER_AB_PUBLIC_KEYSET,
    });
    const srvB = await startExpressRouter(routerB);

    try {
      const handlerA = (a.threshold as any).routerAbEcdsaHssPoolFillHandlers as {
        poolFillSessionStore: {
          getSession: (id: string) => Promise<{ version?: number } | null>;
        };
      };
      const handlerB = (b.threshold as any).routerAbEcdsaHssPoolFillHandlers as {
        poolFillSessionStore: unknown;
      };
      handlerB.poolFillSessionStore = handlerA.poolFillSessionStore;

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

      const presignInit = await fetchJson(`${srvA.baseUrl}/v1/hss/ecdsa/presignature-pool/fill/init`, {
        method: 'POST',
        headers: hssJsonHeaders(rpId, jwt),
        body: JSON.stringify({
          keyHandle,
          count: 1,
          poolFill: buildRouterAbEcdsaHssPoolFillFromBootstrap(bootstrap.json || {}),
        }),
      });
      expect(presignInit.status, presignInit.text).toBe(200);
      expect(presignInit.json?.ok, presignInit.text).toBe(true);
      const presignSessionId = String(presignInit.json?.presignSessionId || '');
      expect(presignSessionId).toBeTruthy();

      const step = await fetchJson(`${srvB.baseUrl}/v1/hss/ecdsa/presignature-pool/fill/step`, {
        method: 'POST',
        headers: {
          ...hssJsonHeaders(rpId, jwt),
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

      const persisted = await handlerA.poolFillSessionStore.getSession(presignSessionId);
      expect(persisted).not.toBeNull();
      expect(Number(persisted?.version || 0)).toBeGreaterThan(1);
    } finally {
      await srvB.close();
      await srvA.close();
    }
  });
});
