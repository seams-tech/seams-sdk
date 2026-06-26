import { expect, test } from '@playwright/test';
import { base64UrlEncode } from '@shared/utils/base64';
import { ROUTER_AB_ECDSA_HSS_WALLET_SESSION_JWT_KIND } from '@shared/utils/sessionTokens';
import {
  toWalletId,
  type ThresholdEcdsaChainTarget,
} from '../../packages/sdk-web/src/core/signingEngine/interfaces/ecdsaChainTarget';
import {
  buildEcdsaRoleLocalEmailOtpAuthMethod,
  buildEcdsaRoleLocalPasskeyAuthMethod,
  buildEcdsaRoleLocalPublicFacts,
  buildEcdsaRoleLocalReadyRecord,
} from '../../packages/sdk-web/src/core/platform';
import {
  buildVerifiedEcdsaPublicFacts,
  buildEvmFamilyEcdsaKeyIdentityFromRecord,
  toEvmFamilyEcdsaKeyHandle,
  toRpId,
  toThresholdOwnerAddress,
  toVerifiedEcdsaPublicFactsFromRecord,
} from '../../packages/sdk-web/src/core/signingEngine/session/identity/evmFamilyEcdsaIdentity';
import { SigningSessionIds } from '../../packages/sdk-web/src/core/signingEngine/session/operationState/types';
import {
  buildEvmFamilyEcdsaSignerBinding,
  exactEcdsaSigningLaneIdentity,
} from '../../packages/sdk-web/src/core/signingEngine/session/identity/exactSigningLaneIdentity';
import {
  deriveThresholdEcdsaRuntimeLaneKey,
  type ThresholdEcdsaSessionRecord,
} from '../../packages/sdk-web/src/core/signingEngine/session/persistence/records';
import type {
  ThresholdEcdsaEmailOtpAuthContext,
  ThresholdEcdsaSessionStoreSource,
} from '../../packages/sdk-web/src/core/signingEngine/session/identity/laneIdentity';
import {
  resolveEcdsaExportMaterialForLane,
  resolveFreshEmailOtpEcdsaExportMaterialForLane,
  type EcdsaExportSessionStoreDeps,
  type ExactEcdsaExportLane,
} from '../../packages/sdk-web/src/core/signingEngine/flows/recovery/ecdsaExportMaterial';
import { exportThresholdEcdsaKeyWithFreshEmailOtpRouteAuth } from '../../packages/sdk-web/src/core/signingEngine/flows/recovery/ecdsaExportFlow';
import type { ThresholdEcdsaCanonicalExportArtifact } from '../../packages/sdk-web/src/core/signingEngine/interfaces/signing';
import type { RouterAbEcdsaHssNormalSigningStateV1 } from '../../packages/shared-ts/src/utils/routerAbEcdsaHss';
import { markRouterAbEcdsaHssWorkerMaterialRuntimeValidated } from '../../packages/sdk-web/src/core/signingEngine/session/routerAbSigningWalletSession';

const WALLET_ID = toWalletId('alice.testnet');
const RP_ID = 'localhost';
const WALLET_KEY_ID = 'wallet-key-export';
const OWNER_ADDRESS = '0x1111111111111111111111111111111111111111';
const PUBLIC_KEY_B64U = 'AgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA';
const PASSKEY_EXPORT_CREDENTIAL_ID_B64U = 'export-passkey-credential';
const HSS_CLIENT_PUBLIC_KEY_B64U = base64UrlEncode(Uint8Array.from([2, ...Array(32).fill(1)]));
const RELAYER_PUBLIC_KEY_B64U = base64UrlEncode(Uint8Array.from([3, ...Array(32).fill(2)]));
const CONTEXT_BINDING_32_B64U = base64UrlEncode(new Uint8Array(32).fill(5));
const APPLICATION_BINDING_DIGEST_B64U = base64UrlEncode(new Uint8Array(32).fill(7));
const READY_STATE_BLOB_B64U = base64UrlEncode(new Uint8Array(96).fill(6));

const EVM_TARGET: ThresholdEcdsaChainTarget = {
  kind: 'evm',
  namespace: 'eip155',
  chainId: 5042002,
  networkSlug: 'arc-testnet',
};

function ethereumAddress20B64u(address: string): string {
  return Buffer.from(address.replace(/^0x/i, ''), 'hex').toString('base64url');
}

function unsignedJwt(payload: Record<string, unknown>): string {
  const header = Buffer.from(JSON.stringify({ alg: 'none', typ: 'JWT' })).toString('base64url');
  const body = Buffer.from(JSON.stringify(payload)).toString('base64url');
  return `${header}.${body}.sig`;
}

function thresholdEcdsaSessionJwtFixture(args: {
  thresholdSessionId: string;
  signingGrantId: string;
  keyHandle: string;
}): string {
  return unsignedJwt({
    kind: ROUTER_AB_ECDSA_HSS_WALLET_SESSION_JWT_KIND,
    sub: WALLET_ID,
    walletId: WALLET_ID,
    keyHandle: args.keyHandle,
    keyScope: 'evm-family',
    chainTarget: EVM_TARGET,
    thresholdSessionId: args.thresholdSessionId,
    signingGrantId: args.signingGrantId,
    exp: Math.floor(Date.now() / 1000) + 3600,
  });
}

function makeRouterAbEcdsaHssNormalSigningState(record: {
  walletId: ThresholdEcdsaSessionRecord['walletId'];
  ecdsaThresholdKeyId: ThresholdEcdsaSessionRecord['ecdsaThresholdKeyId'];
  signingRootId: ThresholdEcdsaSessionRecord['signingRootId'];
  signingRootVersion?: ThresholdEcdsaSessionRecord['signingRootVersion'];
}): RouterAbEcdsaHssNormalSigningStateV1 {
  return {
    kind: 'router_ab_ecdsa_hss_normal_signing_v1',
    scope: {
      wallet_key_id: WALLET_KEY_ID,
      wallet_id: String(record.walletId),
      ecdsa_threshold_key_id: String(record.ecdsaThresholdKeyId),
      signing_root_id: String(record.signingRootId),
      signing_root_version: String(record.signingRootVersion || 'default'),
      context: {
        application_binding_digest_b64u: 'BwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwc',
      },
      public_identity: {
        context_binding_b64u: CONTEXT_BINDING_32_B64U,
        client_public_key33_b64u: HSS_CLIENT_PUBLIC_KEY_B64U,
        server_public_key33_b64u: RELAYER_PUBLIC_KEY_B64U,
        threshold_public_key33_b64u: PUBLIC_KEY_B64U,
        ethereum_address20_b64u: ethereumAddress20B64u(OWNER_ADDRESS),
        client_share_retry_counter: 0,
        server_share_retry_counter: 0,
      },
      signing_worker: {
        server_id: 'signing-worker-1',
        key_epoch: 'worker-epoch-1',
        recipient_encryption_key:
          'x25519:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
      },
      activation_epoch: 'activation-1',
    },
  };
}

function makeVerifiedPublicFacts(keyHandle: string) {
  return buildVerifiedEcdsaPublicFacts({
    keyHandle: toEvmFamilyEcdsaKeyHandle(keyHandle),
    publicKeyB64u: PUBLIC_KEY_B64U,
    participantIds: [1, 2],
    thresholdOwnerAddress: OWNER_ADDRESS,
  });
}

function runtimeValidatedExportRecord<T extends ThresholdEcdsaSessionRecord>(record: T): T {
  if (record.thresholdSessionKind !== 'jwt') return record;
  if (!markRouterAbEcdsaHssWorkerMaterialRuntimeValidated(record)) {
    throw new Error('export fixture record failed Router A/B ECDSA runtime validation');
  }
  return record;
}

type EmailOtpEcdsaSessionRecord = Extract<ThresholdEcdsaSessionRecord, { source: 'email_otp' }>;
type PasskeyEcdsaSessionRecord = Exclude<ThresholdEcdsaSessionRecord, { source: 'email_otp' }>;
type EmailOtpExportRecordFixtureInput = {
  ecdsaThresholdKeyId?: EmailOtpEcdsaSessionRecord['ecdsaThresholdKeyId'];
  walletSessionJwt?: EmailOtpEcdsaSessionRecord['walletSessionJwt'];
  thresholdSessionKind?: EmailOtpEcdsaSessionRecord['thresholdSessionKind'];
  thresholdSessionId?: EmailOtpEcdsaSessionRecord['thresholdSessionId'];
  signingGrantId?: EmailOtpEcdsaSessionRecord['signingGrantId'];
  thresholdEcdsaPublicKeyB64u?: EmailOtpEcdsaSessionRecord['thresholdEcdsaPublicKeyB64u'];
};

function makeReadyRecordForExport(record: {
  walletId: ThresholdEcdsaSessionRecord['walletId'];
  chainTarget: ThresholdEcdsaSessionRecord['chainTarget'];
  keyHandle: ThresholdEcdsaSessionRecord['keyHandle'];
  ecdsaThresholdKeyId: ThresholdEcdsaSessionRecord['ecdsaThresholdKeyId'];
  signingRootId: ThresholdEcdsaSessionRecord['signingRootId'];
  signingRootVersion?: ThresholdEcdsaSessionRecord['signingRootVersion'];
  source: ThresholdEcdsaSessionStoreSource;
  emailOtpAuthContext?: ThresholdEcdsaEmailOtpAuthContext;
}) {
  const authMethod =
    record.source === 'email_otp'
      ? buildEcdsaRoleLocalEmailOtpAuthMethod({
          authSubjectId: record.emailOtpAuthContext?.authSubjectId,
        })
      : buildEcdsaRoleLocalPasskeyAuthMethod({
          credentialIdB64u: PASSKEY_EXPORT_CREDENTIAL_ID_B64U,
          rpId: RP_ID,
        });
  return buildEcdsaRoleLocalReadyRecord({
    stateBlob: {
      kind: 'ecdsa_role_local_state_blob_v1',
      curve: 'secp256k1',
      encoding: 'base64url',
      producer: 'signer_core',
      stateBlobB64u: READY_STATE_BLOB_B64U,
    },
    publicFacts: buildEcdsaRoleLocalPublicFacts({
      walletId: record.walletId,
      walletKeyId: WALLET_KEY_ID,
      chainTarget: record.chainTarget,
      keyHandle: record.keyHandle,
      ecdsaThresholdKeyId: record.ecdsaThresholdKeyId,
      signingRootId: record.signingRootId,
      signingRootVersion: String(record.signingRootVersion || 'default'),
      applicationBindingDigestB64u: APPLICATION_BINDING_DIGEST_B64U,
      clientParticipantId: 1,
      relayerParticipantId: 2,
      participantIds: [1, 2],
      hssClientSharePublicKey33B64u: HSS_CLIENT_PUBLIC_KEY_B64U,
      relayerPublicKey33B64u: RELAYER_PUBLIC_KEY_B64U,
      groupPublicKey33B64u: PUBLIC_KEY_B64U,
      ethereumAddress: OWNER_ADDRESS,
      contextBinding32B64u: CONTEXT_BINDING_32_B64U,
    }),
    authMethod,
  });
}

function makeRecord(input: EmailOtpExportRecordFixtureInput = {}): EmailOtpEcdsaSessionRecord {
  const emailOtpAuthContext = {
    policy: 'per_operation',
    retention: 'single_use',
    reason: 'sign',
    authMethod: 'email_otp',
    authSubjectId: 'google:alice',
  } satisfies ThresholdEcdsaEmailOtpAuthContext;
  const thresholdEcdsaPublicKeyB64u =
    'thresholdEcdsaPublicKeyB64u' in input
      ? input.thresholdEcdsaPublicKeyB64u
      : PUBLIC_KEY_B64U;
  const thresholdSessionId = input.thresholdSessionId ?? 'threshold-session-1';
  const signingGrantId = input.signingGrantId ?? 'signing-grant-1';
  const keyHandle = toEvmFamilyEcdsaKeyHandle('key-handle-export');
  const walletSessionJwt =
    'walletSessionJwt' in input
      ? input.walletSessionJwt
      : thresholdEcdsaSessionJwtFixture({
          thresholdSessionId,
          signingGrantId,
          keyHandle,
        });
  const record = {
    walletId: WALLET_ID,
    chainTarget: EVM_TARGET,
    relayerUrl: 'https://relay.localhost',
    ecdsaThresholdKeyId: input.ecdsaThresholdKeyId ?? 'ehss-export-key',
    signingRootId: 'project-export:env-export',
    signingRootVersion: 'default',
    relayerKeyId: 'relayer-key',
    clientVerifyingShareB64u: HSS_CLIENT_PUBLIC_KEY_B64U,
    relayerVerifyingShareB64u: RELAYER_PUBLIC_KEY_B64U,
    clientAdditiveShareHandle: {
      kind: 'email_otp_worker_session' as const,
      sessionId: 'email-otp-worker-session-1',
    },
    participantIds: [1, 2],
    thresholdSessionKind: input.thresholdSessionKind ?? 'jwt',
    thresholdSessionId,
    signingGrantId,
    walletSessionJwt,
    expiresAtMs: 1_900_000_000_000,
    remainingUses: 1,
    thresholdEcdsaPublicKeyB64u,
    verifiedPublicFacts: makeVerifiedPublicFacts(keyHandle),
    ethereumAddress: OWNER_ADDRESS,
    emailOtpAuthContext,
    runtimePolicyScope: {
      orgId: 'org-export',
      projectId: 'project-export',
      envId: 'env-export',
      signingRootVersion: 'default',
    },
    updatedAtMs: 1_800_000_000_000,
    source: 'email_otp' as const,
    keyHandle,
    walletKeyId: RP_ID,
  };
  return runtimeValidatedExportRecord({
    ...record,
    routerAbEcdsaHssNormalSigning: makeRouterAbEcdsaHssNormalSigningState(record),
    ecdsaRoleLocalReadyRecord: makeReadyRecordForExport(record),
  });
}

function makePasskeyRecord(): PasskeyEcdsaSessionRecord {
  const thresholdSessionId = 'threshold-session-1';
  const signingGrantId = 'signing-grant-1';
  const keyHandle = toEvmFamilyEcdsaKeyHandle('key-handle-export');
  const record = {
    walletId: WALLET_ID,
    chainTarget: EVM_TARGET,
    relayerUrl: 'https://relay.localhost',
    ecdsaThresholdKeyId: 'ehss-export-key',
    signingRootId: 'project-export:env-export',
    signingRootVersion: 'default',
    relayerKeyId: 'relayer-key',
    clientVerifyingShareB64u: HSS_CLIENT_PUBLIC_KEY_B64U,
    relayerVerifyingShareB64u: RELAYER_PUBLIC_KEY_B64U,
    participantIds: [1, 2],
    thresholdSessionKind: 'jwt' as const,
    thresholdSessionId,
    signingGrantId,
    walletSessionJwt: thresholdEcdsaSessionJwtFixture({
      thresholdSessionId,
      signingGrantId,
      keyHandle,
    }),
    expiresAtMs: 1_900_000_000_000,
    remainingUses: 1,
    thresholdEcdsaPublicKeyB64u: PUBLIC_KEY_B64U,
    verifiedPublicFacts: makeVerifiedPublicFacts(keyHandle),
    ethereumAddress: OWNER_ADDRESS,
    runtimePolicyScope: {
      orgId: 'org-export',
      projectId: 'project-export',
      envId: 'env-export',
      signingRootVersion: 'default',
    },
    updatedAtMs: 1_800_000_000_000,
    source: 'registration' as const,
    keyHandle,
    walletKeyId: RP_ID,
  };
  return runtimeValidatedExportRecord({
    ...record,
    routerAbEcdsaHssNormalSigning: makeRouterAbEcdsaHssNormalSigningState(record),
    ecdsaRoleLocalReadyRecord: makeReadyRecordForExport(record),
  });
}

async function exactExportLane(record: ThresholdEcdsaSessionRecord): Promise<ExactEcdsaExportLane> {
  const key = buildEvmFamilyEcdsaKeyIdentityFromRecord({ record, walletKeyId: WALLET_KEY_ID });
  const publicFacts = await toVerifiedEcdsaPublicFactsFromRecord({ record });
  return {
    curve: 'ecdsa',
    laneIdentity: exactEcdsaSigningLaneIdentity({
      signer: buildEvmFamilyEcdsaSignerBinding({
        walletId: record.walletId,
        chainTarget: record.chainTarget,
        keyHandle: publicFacts.keyHandle,
        key,
      }),
        auth:
          record.source === 'email_otp'
          ? { kind: 'email_otp', providerSubjectId: record.emailOtpAuthContext?.authSubjectId || 'google:export' }
          : {
              kind: 'passkey',
              rpId: toRpId(RP_ID),
              credentialIdB64u: PASSKEY_EXPORT_CREDENTIAL_ID_B64U,
            },
      signingGrantId: record.signingGrantId,
      thresholdSessionId: record.thresholdSessionId,
    }),
    key,
    publicFacts,
    session: {
      chainTarget: record.chainTarget,
      authMethod: record.source === 'email_otp' ? 'email_otp' : 'passkey',
      signingGrantId: SigningSessionIds.signingGrant(record.signingGrantId),
      thresholdSessionId: SigningSessionIds.thresholdEcdsaSession(record.thresholdSessionId),
      state: 'ready',
      source: 'runtime_session_record',
    },
  };
}

function depsForRecord(
  record: ThresholdEcdsaSessionRecord,
  cachedExportArtifact?: ThresholdEcdsaCanonicalExportArtifact,
): EcdsaExportSessionStoreDeps {
  const laneKey = deriveThresholdEcdsaRuntimeLaneKey(record);
  return {
    recordsByLane: new Map([[laneKey, record]]),
    exportArtifactsByLane: cachedExportArtifact
      ? new Map([[laneKey, cachedExportArtifact]])
      : new Map(),
  };
}

test.describe('ECDSA export material', () => {
  test('ready export material composes signer material with verified public facts', async () => {
    const record = makePasskeyRecord();
    const material = await resolveEcdsaExportMaterialForLane(
      depsForRecord(record),
      await exactExportLane(record),
    );

    expect(material.kind).toBe('ready_threshold_ecdsa_export_material');
    if (material.kind !== 'ready_threshold_ecdsa_export_material') {
      throw new Error(`expected ready threshold export material, got ${material.kind}`);
    }
    expect(material.record).toBe(record);
    expect(material.signerSession.kind).toBe('ready_ecdsa_signer_session');
    expect(material.signerSession.session.thresholdSessionId).toBe(record.thresholdSessionId);
    expect(material.cachedExportArtifact).toBeNull();
    expect(material.publicFacts.kind).toBe('verified_ecdsa_public_facts');
    expect(material.publicFacts.publicKeyB64u).toBe(PUBLIC_KEY_B64U);
    expect(material.publicFacts.participantIds.map(Number)).toEqual([1, 2]);
    expect(material.publicFacts.thresholdOwnerAddress).toBe(OWNER_ADDRESS);
    expect('ecdsaThresholdKeyId' in material.publicFacts).toBe(false);
    expect('participantIds' in material).toBe(false);
    expect('keyRef' in material).toBe(false);
    expect('readyMaterial' in material).toBe(false);
  });

  test('ready export material uses cached artifact from ready material provenance', async () => {
    const record = makePasskeyRecord();
    const cachedExportArtifact: ThresholdEcdsaCanonicalExportArtifact = {
      artifactKind: 'ecdsa-hss-secp256k1-export',
      chainTarget: EVM_TARGET,
      signingRootId: String(record.signingRootId || 'project:dev'),
      signingRootVersion: String(record.signingRootVersion || 'default'),
      publicKeyHex: '02'.padEnd(66, '0'),
      privateKeyHex: '11'.repeat(32),
      ethereumAddress: OWNER_ADDRESS,
    };
    const material = await resolveEcdsaExportMaterialForLane(
      depsForRecord(record, cachedExportArtifact),
      await exactExportLane(record),
    );

    expect(material.kind).toBe('ready_threshold_ecdsa_export_material');
    if (material.kind !== 'ready_threshold_ecdsa_export_material') {
      throw new Error(`expected ready threshold export material, got ${material.kind}`);
    }
    expect(material.cachedExportArtifact).toEqual(cachedExportArtifact);
  });

  test('fresh Email OTP export material uses route auth when runtime auth is available', async () => {
    const record = makeRecord();
    const material = await resolveFreshEmailOtpEcdsaExportMaterialForLane(
      depsForRecord(record),
      await exactExportLane(record),
    );

    expect(material.kind).toBe('fresh_email_otp_route_auth_ready');
    if (material.kind !== 'fresh_email_otp_route_auth_ready') {
      throw new Error(`expected route-auth-ready fresh material, got ${material.kind}`);
    }
    expect(material.publicFacts.kind).toBe('verified_ecdsa_public_facts');
    expect(material.publicFacts.publicKeyB64u).toBe(PUBLIC_KEY_B64U);
    expect(material.publicFacts.participantIds.map(Number)).toEqual([1, 2]);
    expect(material.publicFacts.thresholdOwnerAddress).toBe(OWNER_ADDRESS);
    expect(material.authLane.kind).toBe('signing_session');
    if (material.authLane.kind !== 'signing_session') {
      throw new Error(`expected signing-session auth lane, got ${material.authLane.kind}`);
    }
    expect(material.authLane.thresholdSessionId).toBe(record.thresholdSessionId);
    expect(material.runtimePolicyScope.orgId).toBe('org-export');
    expect('publicKey' in material).toBe(false);
    expect('participantIds' in material).toBe(false);
  });

  test('fresh Email OTP route-auth export requests challenge with signing-session lane', async () => {
    const record = makeRecord();
    const exportLane = await exactExportLane(record);
    const material = await resolveFreshEmailOtpEcdsaExportMaterialForLane(
      depsForRecord(record),
      exportLane,
    );
    expect(material.kind).toBe('fresh_email_otp_route_auth_ready');
    if (material.kind !== 'fresh_email_otp_route_auth_ready') {
      throw new Error(`expected route-auth-ready fresh material, got ${material.kind}`);
    }
    const { authLane } = material;
    const challengeRequests: unknown[] = [];
    const exportRequests: unknown[] = [];
    const confirmationRequests: unknown[] = [];
    const exportOrder: string[] = [];

    await exportThresholdEcdsaKeyWithFreshEmailOtpRouteAuth(
      {
        sessionStore: depsForRecord(record),
        touchConfirm: {
          requestUserConfirmation: async (request) => {
            confirmationRequests.push(request);
            if (request.type === 'showSecurePrivateKeyUi') {
              exportOrder.push('viewer-loading');
            }
            return {
              confirmed: true,
              requestId: 'export-confirmation-1',
              otpCode: '123456',
              emailOtpChallengeId: 'export-challenge-1',
            };
          },
        },
        emailOtp: {
          requestExportChallenge: async (request) => {
            challengeRequests.push(request);
            return { challengeId: 'export-challenge-1' };
          },
          exportEcdsaKeyWithFreshEmailOtpLane: async () => {
            throw new Error('unexpected fresh-lane export');
          },
          exportEcdsaKeyWithAuthorization: async (request) => {
            exportOrder.push('material-export');
            exportRequests.push(request);
            return {
              publicKeyHex: '02',
              privateKeyHex: '01',
              ethereumAddress: OWNER_ADDRESS,
            };
          },
        },
        warmSessionPolicy: {
          getWarmSession: async () => ({
            capabilities: {
              ecdsa: {
                evm: { record: null },
                tempo: { record: null },
              },
            },
          }),
          resolveExactEcdsaRecord: () => ({ kind: 'not_found' }),
        },
        getSignerWorkerContext: () => {
          throw new Error('unexpected worker context read');
        },
      },
      {
        walletId: String(WALLET_ID),
        exportLane,
        material,
        options: {},
        flowId: 'flow-export-route-auth',
      },
    );

    expect(challengeRequests).toHaveLength(1);
    expect(challengeRequests[0]).toMatchObject({
      kind: 'wallet_session_challenge',
      authLane,
    });
    expect(exportRequests).toHaveLength(1);
    expect(exportRequests[0]).toMatchObject({
      authLane,
      challengeId: 'export-challenge-1',
      otpCode: '123456',
    });
    expect(exportOrder).toEqual(['viewer-loading', 'material-export']);
    expect(confirmationRequests).toContainEqual(
      expect.objectContaining({
        type: 'showSecurePrivateKeyUi',
        payload: expect.objectContaining({
          loading: true,
          viewerSessionId: expect.any(String),
        }),
      }),
    );
  });

  test('fresh Email OTP export material can challenge from exact no-route-auth runtime records', async () => {
    const record = makeRecord({
      walletSessionJwt: undefined,
      thresholdSessionKind: 'cookie',
    });
    const material = await resolveFreshEmailOtpEcdsaExportMaterialForLane(
      depsForRecord(record),
      await exactExportLane(record),
    );

    expect(material.kind).toBe('fresh_email_otp_needs_challenge');
    if (material.kind !== 'fresh_email_otp_needs_challenge') {
      throw new Error(`expected needs-challenge fresh material, got ${material.kind}`);
    }
    expect(material.authSubjectMode).toBe('explicit_auth_subject');
    if (material.authSubjectMode !== 'explicit_auth_subject') {
      throw new Error(`expected explicit auth subject, got ${material.authSubjectMode}`);
    }
    expect(material.authSubjectId).toBe('google:alice');
    expect(material.runtimePolicyScope.projectId).toBe('project-export');
  });

  test('fresh Email OTP export material rejects missing verified public key facts', async () => {
    const record = makeRecord({
      ecdsaThresholdKeyId: 'ehss-export-key-missing-public-key',
      thresholdEcdsaPublicKeyB64u: undefined,
      thresholdSessionId: 'threshold-session-2',
      signingGrantId: 'signing-grant-2',
    });
    const selectedLane = await exactExportLane(
      makeRecord({
        ecdsaThresholdKeyId: record.ecdsaThresholdKeyId,
        thresholdSessionId: record.thresholdSessionId,
        signingGrantId: record.signingGrantId,
      }),
    );

    await expect(
      resolveFreshEmailOtpEcdsaExportMaterialForLane(depsForRecord(record), selectedLane),
    ).rejects.toThrow(/thresholdEcdsaPublicKeyB64u is required/);
  });

  test('ready export material rejects lane public facts that do not match stored record', async () => {
    const record = makePasskeyRecord();
    const lane = await exactExportLane(record);
    const mismatchedLane: ExactEcdsaExportLane = {
      ...lane,
      publicFacts: {
        ...lane.publicFacts,
        thresholdOwnerAddress: toThresholdOwnerAddress(
          '0x2222222222222222222222222222222222222222',
        ),
      },
    };

    await expect(
      resolveEcdsaExportMaterialForLane(depsForRecord(record), mismatchedLane),
    ).rejects.toThrow(/ready export lane public facts mismatch: thresholdOwnerAddress/);
  });

  test('fresh Email OTP export material rejects lane public facts that do not match resolved material', async () => {
    const record = makeRecord();
    const lane = await exactExportLane(record);
    const mismatchedLane: ExactEcdsaExportLane = {
      ...lane,
      publicFacts: {
        ...lane.publicFacts,
        thresholdOwnerAddress: toThresholdOwnerAddress(
          '0x2222222222222222222222222222222222222222',
        ),
      },
    };

    await expect(
      resolveFreshEmailOtpEcdsaExportMaterialForLane(depsForRecord(record), mismatchedLane),
    ).rejects.toThrow(/fresh Email OTP export lane public facts mismatch: thresholdOwnerAddress/);
  });
});
