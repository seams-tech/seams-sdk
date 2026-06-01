import { expect, test } from '@playwright/test';
import { base64UrlEncode } from '@shared/utils/base64';
import { toAccountId } from '../../client/src/core/types/accountIds';
import type { ThresholdEcdsaChainTarget } from '../../client/src/core/signingEngine/interfaces/ecdsaChainTarget';
import {
  buildEcdsaRoleLocalEmailOtpAuthMethod,
  buildEcdsaRoleLocalPasskeyAuthMethod,
  buildEcdsaRoleLocalPublicFacts,
  buildEcdsaRoleLocalReadyRecord,
} from '../../client/src/core/platform';
import {
  buildEvmFamilyEcdsaKeyIdentityFromRecord,
  toEvmFamilyEcdsaKeyHandle,
  toThresholdOwnerAddress,
  toVerifiedEcdsaPublicFactsFromRecord,
} from '../../client/src/core/signingEngine/session/identity/evmFamilyEcdsaIdentity';
import { SigningSessionIds } from '../../client/src/core/signingEngine/session/operationState/types';
import {
  deriveThresholdEcdsaRuntimeLaneKey,
  type ThresholdEcdsaSessionRecord,
} from '../../client/src/core/signingEngine/session/persistence/records';
import type {
  ThresholdEcdsaEmailOtpAuthContext,
  ThresholdEcdsaSessionStoreSource,
} from '../../client/src/core/signingEngine/session/identity/laneIdentity';
import {
  resolveEcdsaExportMaterialForLane,
  resolveFreshEmailOtpEcdsaExportMaterialForLane,
  type EcdsaExportSessionStoreDeps,
  type ExactEcdsaExportLane,
  type FreshEmailOtpEcdsaExportMaterialRouteAuthReady,
} from '../../client/src/core/signingEngine/flows/recovery/ecdsaExportMaterial';
import { exportThresholdEcdsaKeyWithFreshEmailOtpRouteAuth } from '../../client/src/core/signingEngine/flows/recovery/ecdsaExportFlow';
import type { ThresholdEcdsaCanonicalExportArtifact } from '../../client/src/core/signingEngine/interfaces/signing';
import { toAuthorizingWalletSigningSessionId } from '../../client/src/core/signingEngine/stepUpConfirmation/otpPrompt/authLane';

const WALLET_ID = toAccountId('alice.testnet');
const RP_ID = 'localhost';
const OWNER_ADDRESS = '0x1111111111111111111111111111111111111111';
const PUBLIC_KEY_B64U = 'AgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA';
const PASSKEY_EXPORT_CREDENTIAL_ID_B64U = 'export-passkey-credential';
const HSS_CLIENT_PUBLIC_KEY_B64U = base64UrlEncode(Uint8Array.from([2, ...Array(32).fill(1)]));
const RELAYER_PUBLIC_KEY_B64U = base64UrlEncode(Uint8Array.from([3, ...Array(32).fill(2)]));
const CONTEXT_BINDING_32_B64U = base64UrlEncode(new Uint8Array(32).fill(5));
const READY_STATE_BLOB_B64U = base64UrlEncode(new Uint8Array(96).fill(6));

const EVM_TARGET: ThresholdEcdsaChainTarget = {
  kind: 'evm',
  namespace: 'eip155',
  chainId: 5042002,
  networkSlug: 'arc-testnet',
};
type EmailOtpEcdsaSessionRecord = Extract<ThresholdEcdsaSessionRecord, { source: 'email_otp' }>;
type PasskeyEcdsaSessionRecord = Exclude<ThresholdEcdsaSessionRecord, { source: 'email_otp' }>;

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
      rpId: RP_ID,
      chainTarget: record.chainTarget,
      keyHandle: record.keyHandle,
      ecdsaThresholdKeyId: record.ecdsaThresholdKeyId,
      signingRootId: record.signingRootId,
      signingRootVersion: String(record.signingRootVersion || 'default'),
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

function makeRecord(
  overrides: Partial<EmailOtpEcdsaSessionRecord> = {},
): EmailOtpEcdsaSessionRecord {
  const emailOtpAuthContext =
    overrides.emailOtpAuthContext ??
    ({
      policy: 'per_operation',
      retention: 'single_use',
      reason: 'sign',
      authMethod: 'email_otp',
      authSubjectId: 'google:alice',
    } satisfies ThresholdEcdsaEmailOtpAuthContext);
  const record = {
    walletId: WALLET_ID,
    chainTarget: EVM_TARGET,
    relayerUrl: 'https://relay.localhost',
    ecdsaThresholdKeyId: 'ehss-export-key',
    signingRootId: 'project-export:env-export',
    signingRootVersion: 'default',
    relayerKeyId: 'relayer-key',
    clientVerifyingShareB64u: 'client-verifying-share',
    clientAdditiveShareHandle: {
      kind: 'email_otp_worker_session' as const,
      sessionId: 'email-otp-worker-session-1',
    },
    participantIds: [1, 2],
    thresholdSessionKind: 'jwt' as const,
    thresholdSessionId: 'threshold-session-1',
    walletSigningSessionId: 'wallet-signing-session-1',
    thresholdSessionAuthToken: 'threshold-auth-token',
    expiresAtMs: 1_900_000_000_000,
    remainingUses: 1,
    thresholdEcdsaPublicKeyB64u: PUBLIC_KEY_B64U,
    ethereumAddress: OWNER_ADDRESS,
    emailOtpAuthContext,
    runtimePolicyScope: {
      orgId: 'org-export',
      projectId: 'project-export',
      envId: 'env-export',
      signingRootVersion: 'default',
    },
    updatedAtMs: 1_800_000_000_000,
    ...overrides,
    source: 'email_otp' as const,
    keyHandle: overrides.keyHandle ?? toEvmFamilyEcdsaKeyHandle('key-handle-export'),
    authMetadata: overrides.authMetadata ?? { rpId: RP_ID },
  };
  return {
    ...record,
    ecdsaRoleLocalReadyRecord:
      overrides.ecdsaRoleLocalReadyRecord ?? makeReadyRecordForExport(record),
  };
}

function makePasskeyRecord(
  overrides: Partial<PasskeyEcdsaSessionRecord> = {},
): PasskeyEcdsaSessionRecord {
  const record = {
    walletId: WALLET_ID,
    chainTarget: EVM_TARGET,
    relayerUrl: 'https://relay.localhost',
    ecdsaThresholdKeyId: overrides.ecdsaThresholdKeyId ?? 'ehss-export-key',
    signingRootId: overrides.signingRootId ?? 'project-export:env-export',
    signingRootVersion: overrides.signingRootVersion ?? 'default',
    relayerKeyId: overrides.relayerKeyId ?? 'relayer-key',
    clientVerifyingShareB64u: overrides.clientVerifyingShareB64u ?? 'client-verifying-share',
    participantIds: overrides.participantIds ?? [1, 2],
    thresholdSessionKind: overrides.thresholdSessionKind ?? 'jwt',
    thresholdSessionId: overrides.thresholdSessionId ?? 'threshold-session-1',
    walletSigningSessionId: overrides.walletSigningSessionId ?? 'wallet-signing-session-1',
    thresholdSessionAuthToken: overrides.thresholdSessionAuthToken ?? 'threshold-auth-token',
    expiresAtMs: overrides.expiresAtMs ?? 1_900_000_000_000,
    remainingUses: overrides.remainingUses ?? 1,
    thresholdEcdsaPublicKeyB64u: overrides.thresholdEcdsaPublicKeyB64u ?? PUBLIC_KEY_B64U,
    ethereumAddress: overrides.ethereumAddress ?? OWNER_ADDRESS,
    runtimePolicyScope: overrides.runtimePolicyScope ?? {
      orgId: 'org-export',
      projectId: 'project-export',
      envId: 'env-export',
      signingRootVersion: 'default',
    },
    updatedAtMs: overrides.updatedAtMs ?? 1_800_000_000_000,
    source: 'registration' as const,
    keyHandle: overrides.keyHandle ?? toEvmFamilyEcdsaKeyHandle('key-handle-export'),
    authMetadata: overrides.authMetadata ?? { rpId: RP_ID },
  };
  return {
    ...record,
    ecdsaRoleLocalReadyRecord:
      overrides.ecdsaRoleLocalReadyRecord ?? makeReadyRecordForExport(record),
  };
}

async function exactExportLane(record: ThresholdEcdsaSessionRecord): Promise<ExactEcdsaExportLane> {
  return {
    curve: 'ecdsa',
    key: buildEvmFamilyEcdsaKeyIdentityFromRecord({ record, rpId: RP_ID }),
    publicFacts: await toVerifiedEcdsaPublicFactsFromRecord({ record }),
    session: {
      chainTarget: record.chainTarget,
      authMethod: record.source === 'email_otp' ? 'email_otp' : 'passkey',
      walletSigningSessionId: SigningSessionIds.walletSigningSession(record.walletSigningSessionId),
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
      RP_ID,
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
      RP_ID,
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
    const publicFacts = await toVerifiedEcdsaPublicFactsFromRecord({ record });
    const authLane = {
      kind: 'signing_session' as const,
      jwt: record.thresholdSessionAuthToken || 'threshold-auth-token',
      thresholdSessionId: record.thresholdSessionId,
      authorizingWalletSigningSessionId: toAuthorizingWalletSigningSessionId(
        record.walletSigningSessionId,
      ),
      curve: 'ecdsa' as const,
      chainTarget: record.chainTarget,
    };
    const material: FreshEmailOtpEcdsaExportMaterialRouteAuthReady = {
      kind: 'fresh_email_otp_route_auth_ready',
      chainTarget: record.chainTarget,
      publicFacts,
      runtimePolicyScope: record.runtimePolicyScope!,
      record,
      authLane,
    };
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
        getRpId: () => RP_ID,
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
          resolveExactEcdsaRecord: () => null,
        },
        getSignerWorkerContext: () => {
          throw new Error('unexpected worker context read');
        },
      },
      {
        walletSessionUserId: String(WALLET_ID),
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

  test('fresh Email OTP export material needs challenge when route auth is absent', async () => {
    const record = makeRecord({
      thresholdSessionAuthToken: undefined,
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
    expect(material.authSubjectId).toBe('google:alice');
  });

  test('fresh Email OTP export material rejects missing verified public key facts', async () => {
    const record = makeRecord({
      ecdsaThresholdKeyId: 'ehss-export-key-missing-public-key',
      thresholdEcdsaPublicKeyB64u: undefined,
      thresholdSessionId: 'threshold-session-2',
      walletSigningSessionId: 'wallet-signing-session-2',
    });
    const selectedLane = await exactExportLane(
      makeRecord({
        ecdsaThresholdKeyId: record.ecdsaThresholdKeyId,
        thresholdSessionId: record.thresholdSessionId,
        walletSigningSessionId: record.walletSigningSessionId,
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
      resolveEcdsaExportMaterialForLane(depsForRecord(record), mismatchedLane, RP_ID),
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
