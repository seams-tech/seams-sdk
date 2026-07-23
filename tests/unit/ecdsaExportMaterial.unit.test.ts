import { expect, test } from '@playwright/test';
import { base64UrlEncode } from '@shared/utils/base64';
import {
  toWalletId,
  type ThresholdEcdsaChainTarget,
} from '../../packages/sdk-web/src/core/signingEngine/interfaces/ecdsaChainTarget';
import {
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
import {
  buildEmailOtpAuthContextForWalletAuthMethod,
  emailOtpAuthContextProviderUserId,
} from '../../packages/sdk-web/src/core/signingEngine/session/identity/laneIdentity';
import {
  makeEmailOtpEcdsaSessionRecord,
  makePasskeyEcdsaSessionRecord,
  type EmailOtpEcdsaSessionRecord,
  type PasskeyEcdsaSessionRecord,
} from './helpers/ecdsaSessionRecordVariants.fixtures';
import {
  resolveEcdsaExportMaterialForLane,
  resolveFreshEmailOtpEcdsaExportMaterialForLane,
  type EcdsaExportSessionStoreDeps,
  type EmailOtpEcdsaPublicReauthExportAuthority,
  type ExactEcdsaExportLane,
} from '../../packages/sdk-web/src/core/signingEngine/flows/recovery/ecdsaExportMaterial';
import { buildEcdsaDerivationExportAuthorizationDigestInput } from '../../packages/sdk-web/src/core/signingEngine/flows/recovery/ecdsaDerivationExport';
import { exportThresholdEcdsaKeyWithFreshEmailOtpRouteAuth } from '../../packages/sdk-web/src/core/signingEngine/flows/recovery/ecdsaExportFlow';
import {
  exportEcdsaKeyWithDurableAuthorization,
  exportEcdsaKeyWithPublicReauthAuthorization,
} from '../../packages/sdk-web/src/core/signingEngine/session/emailOtp/exportRecovery';
import { buildEmailOtpSigningSessionRoutePlan } from '../../packages/sdk-web/src/core/signingEngine/session/emailOtp/routePlan';
import { resolveEmailOtpEcdsaSigningSessionAuthorityFromRecord } from '../../packages/sdk-web/src/core/signingEngine/session/emailOtp/ecdsaSigningSessionAuthority';
import type { ThresholdEcdsaCanonicalExportArtifact } from '../../packages/sdk-web/src/core/signingEngine/interfaces/signing';

const WALLET_ID = toWalletId('alice.testnet');
const RP_ID = 'localhost';
const SIGNING_ROOT_ID = 'project-export:env-export';
const SIGNING_ROOT_VERSION = 'default';
const EMAIL_OTP_EMAIL_HASH_HEX = 'email-hash-export';
const OWNER_ADDRESS = '0x1111111111111111111111111111111111111111';
const PUBLIC_KEY_B64U = 'AgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA';
const PASSKEY_EXPORT_CREDENTIAL_ID_B64U = 'export-passkey-credential';
const ECDSA_DERIVATION_CLIENT_PUBLIC_KEY_B64U = base64UrlEncode(
  Uint8Array.from([2, ...Array(32).fill(1)]),
);
const RELAYER_PUBLIC_KEY_B64U = base64UrlEncode(Uint8Array.from([3, ...Array(32).fill(2)]));
const CONTEXT_BINDING_32_B64U = base64UrlEncode(new Uint8Array(32).fill(5));

const EVM_TARGET: ThresholdEcdsaChainTarget = {
  kind: 'evm',
  namespace: 'eip155',
  chainId: 5042002,
  networkSlug: 'arc-testnet',
};

type EmailOtpExportRecordFixtureInput = {
  ecdsaThresholdKeyId?: EmailOtpEcdsaSessionRecord['ecdsaThresholdKeyId'];
  walletSessionJwt?: EmailOtpEcdsaSessionRecord['walletSessionJwt'];
  thresholdSessionId?: EmailOtpEcdsaSessionRecord['thresholdSessionId'];
  signingGrantId?: EmailOtpEcdsaSessionRecord['signingGrantId'];
  thresholdEcdsaPublicKeyB64u?: EmailOtpEcdsaSessionRecord['thresholdEcdsaPublicKeyB64u'];
};
type PasskeyExportRecordFixtureInput = {
  expiresAtMs?: PasskeyEcdsaSessionRecord['expiresAtMs'];
  walletSessionJwt?: PasskeyEcdsaSessionRecord['walletSessionJwt'];
  thresholdExpiresAtMs?: number;
  participantIds?: readonly number[];
};

/** Export-flow scenario axes shared by both branch wrappers below. */
const EXPORT_SCENARIO = {
  signingRootId: SIGNING_ROOT_ID,
  signingRootVersion: SIGNING_ROOT_VERSION,
  runtimePolicyScope: {
    orgId: 'org-export',
    projectId: 'project-export',
    envId: 'env-export',
    signingRootVersion: 'default',
  },
  ecdsaThresholdKeyId: 'ederivation-export-key',
  participantIds: [1, 2],
  remainingUses: 1,
  relayerVerifyingShareB64u: RELAYER_PUBLIC_KEY_B64U,
  runtimeValidated: true,
} as const;

function makeRecord(input: EmailOtpExportRecordFixtureInput = {}): EmailOtpEcdsaSessionRecord {
  return makeEmailOtpEcdsaSessionRecord({
    ...EXPORT_SCENARIO,
    participantIds: [...EXPORT_SCENARIO.participantIds],
    keyHandle: toEvmFamilyEcdsaKeyHandle('key-handle-export'),
    ecdsaThresholdKeyId: input.ecdsaThresholdKeyId ?? EXPORT_SCENARIO.ecdsaThresholdKeyId,
    thresholdSessionId: input.thresholdSessionId ?? 'threshold-session-1',
    signingGrantId: input.signingGrantId ?? 'signing-grant-1',
    clientAdditiveShareSessionId: 'email-otp-worker-session-1',
    emailOtpAuthContext: buildEmailOtpAuthContextForWalletAuthMethod({
      policy: 'per_operation',
      walletId: WALLET_ID,
      emailHashHex: EMAIL_OTP_EMAIL_HASH_HEX,
      provider: 'google',
      providerUserId: 'google:alice',
      // 'retention' became required; per-operation contexts are single-use, which
      // is the same pending single-use variant the omitted field produced.
      retention: 'single_use',
    }),
    ...('walletSessionJwt' in input ? { walletSessionJwt: input.walletSessionJwt } : {}),
    ...('thresholdEcdsaPublicKeyB64u' in input
      ? { thresholdEcdsaPublicKeyB64u: input.thresholdEcdsaPublicKeyB64u }
      : {}),
  });
}

function makePasskeyRecord(input: PasskeyExportRecordFixtureInput = {}): PasskeyEcdsaSessionRecord {
  const thresholdSessionId = 'threshold-session-1';
  const expiresAtMs = input.expiresAtMs ?? 1_900_000_000_000;
  return makePasskeyEcdsaSessionRecord({
    ...EXPORT_SCENARIO,
    participantIds: [...(input.participantIds ?? EXPORT_SCENARIO.participantIds)],
    keyHandle: toEvmFamilyEcdsaKeyHandle('key-handle-export'),
    passkeyCredentialIdB64u: PASSKEY_EXPORT_CREDENTIAL_ID_B64U,
    thresholdSessionId,
    signingGrantId: 'signing-grant-1',
    source: 'registration',
    expiresAtMs,
    jwtThresholdExpiresAtMs: input.thresholdExpiresAtMs ?? expiresAtMs,
    roleLocalDurableMaterialRef: `role-local:ecdsa-export:${thresholdSessionId}`,
    bindLiveRoleLocalWorkerMaterial: true,
    ...('walletSessionJwt' in input ? { walletSessionJwt: input.walletSessionJwt } : {}),
  });
}

async function exactExportLane(record: ThresholdEcdsaSessionRecord): Promise<ExactEcdsaExportLane> {
  const key = buildEvmFamilyEcdsaKeyIdentityFromRecord({ record });
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
          ? {
              kind: 'email_otp',
              providerSubjectId: record.emailOtpAuthContext
                ? emailOtpAuthContextProviderUserId(record.emailOtpAuthContext)
                : 'google:export',
            }
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
      material: { kind: 'loaded_worker_material' },
    },
  };
}

function emailOtpPublicReauthAuthority(
  record: EmailOtpEcdsaSessionRecord,
): EmailOtpEcdsaPublicReauthExportAuthority {
  const { signingRootVersion, runtimePolicyScope, routerAbEcdsaDerivationNormalSigning } = record;
  if (
    signingRootVersion === undefined ||
    runtimePolicyScope === undefined ||
    routerAbEcdsaDerivationNormalSigning === undefined
  ) {
    throw new Error('expected a fully-populated Email OTP export record fixture');
  }
  return {
    source: 'email_otp',
    provider: 'google',
    providerSubjectId: emailOtpAuthContextProviderUserId(record.emailOtpAuthContext),
    emailHashHex: EMAIL_OTP_EMAIL_HASH_HEX,
    chainTarget: record.chainTarget,
    signingRootId: record.signingRootId,
    signingRootVersion,
    evmFamilySigningKeySlotId: record.evmFamilySigningKeySlotId,
    keyHandle: record.keyHandle,
    ecdsaThresholdKeyId: record.ecdsaThresholdKeyId,
    ethereumAddress: record.ethereumAddress,
    relayerKeyId: record.relayerKeyId,
    thresholdEcdsaPublicKeyB64u: String(record.thresholdEcdsaPublicKeyB64u),
    participantIds: [...record.participantIds],
    runtimePolicyScope,
    routerAbEcdsaDerivationNormalSigning,
    relayerUrl: record.relayerUrl,
    publicCapability: record.ecdsaRoleLocalPublicFacts.publicCapability,
    roleLocalDurableMaterialRef: `role-local:ecdsa-export:${record.thresholdSessionId}`,
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
    expect(material.signerSession.kind).toBe('ready_ecdsa_signer_session');
    expect(material.signerSession.session.thresholdSessionId).toBe(record.thresholdSessionId);
    expect(material.cachedExportArtifact).toBeNull();
    expect(material.authMethod).toBe('passkey');
    expect(material.publicFacts.kind).toBe('verified_ecdsa_public_facts');
    expect(material.publicFacts.publicKeyB64u).toBe(PUBLIC_KEY_B64U);
    expect(material.publicFacts.participantIds.map(Number)).toEqual([1, 2]);
    expect(material.publicFacts.thresholdOwnerAddress).toBe(OWNER_ADDRESS);
    expect('ecdsaThresholdKeyId' in material.publicFacts).toBe(false);
    expect('participantIds' in material).toBe(false);
    expect('keyRef' in material).toBe(false);
    expect('readyMaterial' in material).toBe(false);
    expect('record' in material).toBe(false);
    expect(material.committedLane.authority.factor.kind).toBe('passkey');
    expect(material.committedLane.source).toBe(record.source);
    expect(material.committedLane.record).toBe(record);
    expect(material.committedLane.authLane).toBeUndefined();
    expect(material.committedLane.walletSessionAuthority.kind).toBe(
      'ecdsa_wallet_session_authority',
    );
    expect(material.committedLane.walletSessionAuthority.walletSessionJwt).toBe(
      record.walletSessionJwt,
    );
    expect(material.committedLane.walletSessionAuthority.signingGrantId).toBe(
      record.signingGrantId,
    );
  });

  test('passkey DERIVATION export authorization uses Wallet Session JWT policy claims', async () => {
    const jwtThresholdExpiresAtMs = 1_900_000_600_000;
    const record = makePasskeyRecord({
      expiresAtMs: 1_900_000_100_000,
      thresholdExpiresAtMs: jwtThresholdExpiresAtMs,
      participantIds: [1, 2],
    });
    const material = await resolveEcdsaExportMaterialForLane(
      depsForRecord(record),
      await exactExportLane(record),
    );

    expect(material.kind).toBe('ready_threshold_ecdsa_export_material');
    if (material.kind !== 'ready_threshold_ecdsa_export_material') {
      throw new Error(`expected ready threshold export material, got ${material.kind}`);
    }
    const walletSessionAuthority = material.committedLane.walletSessionAuthority;
    expect(walletSessionAuthority.kind).toBe('ecdsa_wallet_session_authority');
    if (walletSessionAuthority.kind !== 'ecdsa_wallet_session_authority') {
      throw new Error('expected Wallet Session JWT authority');
    }
    const digestInput = buildEcdsaDerivationExportAuthorizationDigestInput({
      ecdsaThresholdKeyId: String(record.ecdsaThresholdKeyId),
      signingRootId: String(record.signingRootId),
      signingRootVersion: String(record.signingRootVersion),
      contextBinding32B64u: CONTEXT_BINDING_32_B64U,
      publicIdentity: {
        derivationClientSharePublicKey33B64u: ECDSA_DERIVATION_CLIENT_PUBLIC_KEY_B64U,
        relayerPublicKey33B64u: RELAYER_PUBLIC_KEY_B64U,
        groupPublicKey33B64u: PUBLIC_KEY_B64U,
        ethereumAddress: OWNER_ADDRESS,
      },
      exportRequestNonce32B64u: base64UrlEncode(new Uint8Array(32).fill(9)),
      confirmationDigest32B64u: base64UrlEncode(new Uint8Array(32).fill(10)),
      issuedAtUnixMs: 1_800_000_000_000,
      expiresAtUnixMs: 1_800_000_060_000,
      walletSessionAuthority,
    });

    expect(digestInput.thresholdExpiresAtMs).toBe(jwtThresholdExpiresAtMs);
    expect(digestInput.thresholdExpiresAtMs).not.toBe(record.expiresAtMs);
    expect(digestInput.participantIds).toEqual([1, 2]);
  });

  test('ready Email OTP export material carries committed lane authority', async () => {
    const record = makeRecord();
    const material = await resolveEcdsaExportMaterialForLane(
      depsForRecord(record),
      await exactExportLane(record),
    );

    expect(material.kind).toBe('ready_threshold_ecdsa_export_material');
    if (material.kind !== 'ready_threshold_ecdsa_export_material') {
      throw new Error(`expected ready threshold export material, got ${material.kind}`);
    }
    expect(material.authMethod).toBe('email_otp');
    if (material.authMethod !== 'email_otp') {
      throw new Error(`expected Email OTP export material, got ${material.authMethod}`);
    }
    expect(material.committedLane.authority.factor.kind).toBe('email_otp');
    expect(material.committedLane.source).toBe('record_backed');
    expect(material.committedLane.record).toBe(record);
    expect(material.committedLane.authLane.kind).toBe('signing_session');
    expect(material.committedLane.walletSessionAuthority.walletSessionJwt).toBe(
      record.walletSessionJwt,
    );
    expect(material.committedLane.walletSessionAuthority.signingGrantId).toBe(
      record.signingGrantId,
    );
  });

  test('ready export material uses cached artifact from ready material provenance', async () => {
    const record = makePasskeyRecord();
    const cachedExportArtifact: ThresholdEcdsaCanonicalExportArtifact = {
      artifactKind: 'ecdsa-derivation-secp256k1-export',
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

  test('expired passkey export material exposes only the bootstrap context needed after approval', async () => {
    // Factory output plus a visible corrupting override (expired lane).
    const record = {
      ...makePasskeyRecord(),
      expiresAtMs: 1,
    };
    const material = await resolveEcdsaExportMaterialForLane(
      depsForRecord(record),
      await exactExportLane(record),
    );

    expect(material.kind).toBe('fresh_passkey_needs_authorization');
    if (material.kind !== 'fresh_passkey_needs_authorization') {
      throw new Error(`expected fresh passkey export material, got ${material.kind}`);
    }
    expect(material.bootstrap).toEqual({
      source: 'registration',
      relayerUrl: record.relayerUrl,
      relayerKeyId: record.relayerKeyId,
      ecdsaThresholdKeyId: record.ecdsaThresholdKeyId,
      evmFamilySigningKeySlotId: record.evmFamilySigningKeySlotId,
      signingRootId: record.signingRootId,
      signingRootVersion: record.signingRootVersion,
      participantIds: record.participantIds,
    });
    expect('record' in material).toBe(false);
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
    expect(material.authorization.kind).toBe('record_backed');
    if (material.authorization.kind !== 'record_backed') {
      throw new Error(`expected record-backed authorization, got ${material.authorization.kind}`);
    }
    const committedLane = material.authorization.committedLane;
    expect(committedLane.authLane.kind).toBe('signing_session');
    if (committedLane.authLane.kind !== 'signing_session') {
      throw new Error(`expected signing-session auth lane, got ${committedLane.authLane.kind}`);
    }
    expect(committedLane.authLane.thresholdSessionId).toBe(record.thresholdSessionId);
    expect(committedLane.record).toBe(record);
    expect(material.runtimePolicyScope.orgId).toBe('org-export');
    expect('publicKey' in material).toBe(false);
    expect('participantIds' in material).toBe(false);
    expect('record' in material).toBe(false);
    expect('authLane' in material).toBe(false);
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
    if (material.authorization.kind !== 'record_backed') {
      throw new Error(`expected record-backed authorization, got ${material.authorization.kind}`);
    }
    const { authLane } = material.authorization.committedLane;
    const challengeRequests: unknown[] = [];
    const exportRequests: unknown[] = [];
    const confirmationRequests: unknown[] = [];
    const exportOrder: string[] = [];

    await exportThresholdEcdsaKeyWithFreshEmailOtpRouteAuth(
      {
        sessionStore: depsForRecord(record),
        touchConfirm: {
          initialize: async () => {
            throw new Error('unexpected UI confirm bridge initialize');
          },
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
          requestPublicReauthExportChallenge: async () => {
            throw new Error('unexpected public-reauth export challenge');
          },
          exportEcdsaKeyWithDurableAuthorization: async () => {
            throw new Error('unexpected durable-authority export');
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
          exportEcdsaKeyWithPublicReauthAuthorization: async () => {
            throw new Error('unexpected public-reauth export');
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
        provisionPasskeyEcdsaExplicitExportSession: async () => {
          throw new Error('unexpected passkey explicit-export provision');
        },
        resolvePasskeyEcdsaExportRouteAuth: async () => {
          throw new Error('unexpected passkey export route auth resolution');
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
      challengeId: 'export-challenge-1',
      otpCode: '123456',
      committedLane: expect.objectContaining({
        authLane,
      }),
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

  test('durable Email OTP ECDSA export bootstraps from exact signing-session authority', async () => {
    const record = makeRecord();
    const authorityResolution = resolveEmailOtpEcdsaSigningSessionAuthorityFromRecord(record);
    if (authorityResolution.kind !== 'ready') {
      throw new Error(`expected signing-session authority, got ${authorityResolution.kind}`);
    }
    const runtimePolicyScope = record.runtimePolicyScope;
    if (!runtimePolicyScope) throw new Error('expected runtime policy scope');
    const publicFacts = await toVerifiedEcdsaPublicFactsFromRecord({ record });
    let loginRequest: unknown = null;
    await expect(
      exportEcdsaKeyWithDurableAuthorization(
        {
          requireRelayUrl: () => record.relayerUrl,
          buildSigningSessionRoutePlan: buildEmailOtpSigningSessionRoutePlan,
          getSignerWorkerContext: () => {
            throw new Error('unexpected worker context read');
          },
        },
        {
          walletSession: {
            walletId: record.walletId,
            walletSessionUserId: String(record.walletId),
          },
          chainTarget: record.chainTarget,
          challengeId: 'durable-export-challenge',
          otpCode: '123456',
          publicFacts,
          runtimePolicyScope,
          signingSessionAuthority: authorityResolution.authority,
          prepareEcdsaExportCapability: async (request) => {
            loginRequest = request;
            throw new Error('stop after durable export preparation request');
          },
        },
      ),
    ).rejects.toThrow('stop after durable export preparation request');

    expect(loginRequest).toMatchObject({
      challengeId: 'durable-export-challenge',
      otpCode: '123456',
      operation: 'export_key',
      routePlan: {
        routeFamily: 'signing_session',
        authLane: authorityResolution.authority.authLane,
      },
      providerIdentity: {
        kind: 'explicit_provider_user',
        providerUserId: 'google:alice',
      },
    });
  });

  test('page-refresh Email OTP export uses the durable public reauth authority after session retirement', async () => {
    const record = makeRecord();
    const activeLane = await exactExportLane(record);
    const publicReauthAuthority = emailOtpPublicReauthAuthority(record);
    const exportLane: ExactEcdsaExportLane = {
      curve: 'ecdsa',
      laneIdentity: activeLane.laneIdentity,
      key: activeLane.key,
      publicFacts: activeLane.publicFacts,
      session: {
        chainTarget: record.chainTarget,
        authMethod: 'email_otp',
        signingGrantId: SigningSessionIds.signingGrant(record.signingGrantId),
        thresholdSessionId: SigningSessionIds.thresholdEcdsaSession(record.thresholdSessionId),
        state: 'exhausted',
        source: 'durable_sealed_record',
        material: { kind: 'material_pending', reason: 'email_otp_route_auth' },
        publicReauthAuthority,
      },
    };
    const material = await resolveFreshEmailOtpEcdsaExportMaterialForLane(
      {
        recordsByLane: new Map(),
        exportArtifactsByLane: new Map(),
      },
      exportLane,
    );

    expect(material.authorization).toEqual({
      kind: 'public_reauth_authority_backed',
      publicReauthAuthority,
    });
    expect(material.publicFacts).toEqual(activeLane.publicFacts);
    expect(material.runtimePolicyScope).toEqual(record.runtimePolicyScope);
  });

  test('public reauth ECDSA export provisions its artifact through an app-session export route', async () => {
    const record = makeRecord();
    const publicReauthAuthority = emailOtpPublicReauthAuthority(record);
    let loginRequest: unknown = null;
    await expect(
      exportEcdsaKeyWithPublicReauthAuthorization(
        {
          requireRelayUrl: () => record.relayerUrl,
          getSignerWorkerContext: () => {
            throw new Error('unexpected worker context read');
          },
        },
        {
          walletSession: {
            walletId: record.walletId,
            walletSessionUserId: String(record.walletId),
          },
          chainTarget: record.chainTarget,
          challengeId: 'public-reauth-export-challenge',
          otpCode: '123456',
          appSessionJwt: 'app-session-jwt',
          publicReauthAuthority,
          prepareEcdsaExportCapability: async (request) => {
            loginRequest = request;
            throw new Error('stop after public reauth export preparation request');
          },
        },
      ),
    ).rejects.toThrow('stop after public reauth export preparation request');

    expect(loginRequest).toMatchObject({
      challengeId: 'public-reauth-export-challenge',
      otpCode: '123456',
      operation: 'export_key',
      routePlan: {
        routeFamily: 'login',
        authLane: { kind: 'app_session', jwt: 'app-session-jwt' },
      },
      keyHandle: record.keyHandle,
      providerIdentity: {
        kind: 'explicit_provider_user',
        providerUserId: 'google:alice',
      },
    });
  });

  test('fresh Email OTP export material rejects missing verified public key facts', async () => {
    const record = makeRecord({
      ecdsaThresholdKeyId: 'ederivation-export-key-missing-public-key',
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
