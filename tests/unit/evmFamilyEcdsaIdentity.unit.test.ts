import { expect, test } from '@playwright/test';
import { base64UrlEncode } from '@shared/utils/base64';
import { deriveThresholdEcdsaKeyHandle } from '@shared/utils/thresholdEcdsaKeyHandle';
import { deriveEvmFamilySigningKeySlotId } from '@shared/signing-lanes';
import type { ThresholdEcdsaSecp256k1KeyRef } from '../../packages/sdk-web/src/core/signingEngine/interfaces/signing';
import {
  buildEmailOtpEcdsaAuthBinding,
  buildEvmFamilyEcdsaKeyIdentityFromKeyRef,
  buildEvmFamilyEcdsaKeyIdentityFromRecord,
  buildPasskeyEcdsaAuthBinding,
  buildVerifiedEcdsaPublicFacts,
  buildKnownReadyThresholdEcdsaSessionPolicy,
  buildReadyEcdsaSignerSession,
  buildResolvedEvmFamilyEcdsaKey,
  buildThresholdEcdsaSecp256k1KeyRefFromSessionRecord,
  buildEcdsaWalletSessionTransportAuth,
  deriveEvmFamilyEcdsaKeyHandle,
  deriveEvmFamilyKeyFingerprint,
  deriveEvmFamilyKeyFingerprintFromPublicFacts,
  resolveThresholdSigningRootBindingFromRecord,
  toEvmFamilyEcdsaKeyHandle,
  toRpId,
  toReadyEcdsaSignerSessionFromReadyMaterial,
  toVerifiedEcdsaPublicFactsFromDurableRecord,
  toVerifiedEcdsaPublicFactsFromKeyRef,
  toVerifiedEcdsaPublicFactsFromReadyMaterial,
  toVerifiedEcdsaPublicFactsFromRecord,
} from '../../packages/sdk-web/src/core/signingEngine/session/identity/evmFamilyEcdsaIdentity';
import {
  parseEcdsaClientVerifyingPublicKey33B64u,
  parseEcdsaKeyHandle,
  parseEcdsaRelayerKeyId,
  parseEcdsaRoleLocalBindingDigest,
  parseEcdsaRoleLocalMaterialHandle,
  parseEcdsaRoleLocalWorkerHandle,
  parseEcdsaThresholdKeyId,
} from '../../packages/sdk-web/src/core/signingEngine/session/keyMaterialBrands';
import { buildEcdsaRoleLocalSigningMaterialHandle } from '../../packages/sdk-web/src/core/signingEngine/session/identity/ecdsaDerivationSigningMaterialHandle';
import {
  toWalletId,
  type ThresholdEcdsaChainTarget,
} from '../../packages/sdk-web/src/core/signingEngine/interfaces/ecdsaChainTarget';
import {
  clearStoredThresholdEcdsaSessionRecordByThresholdSessionIdForTarget,
  clearStoredThresholdEcdsaSessionRecordsForWalletKeyHandle,
  clearAllThresholdEcdsaSessionRecords,
  deriveThresholdEcdsaRuntimeLaneKey,
  getThresholdEcdsaSessionRecordByKey,
  getStoredThresholdEcdsaSessionRecordByThresholdSessionIdForTarget,
  listStoredThresholdEcdsaSessionRecordsForWallet,
  commitCurrentThresholdEcdsaSession,
  thresholdEcdsaSessionRecordReadModel,
  upsertThresholdEcdsaSessionFact,
  type ThresholdEcdsaSessionRecord,
} from '../../packages/sdk-web/src/core/signingEngine/session/persistence/records';
import { selectedEcdsaLane } from '../../packages/sdk-web/src/core/signingEngine/session/identity/laneIdentity';
import {
  makeEcdsaRoleLocalReadyRecordFixture as makeRoleLocalReadyRecord,
  makeEmailOtpEcdsaSessionRecord as makeEmailOtpRecord,
  makePasskeyEcdsaSessionRecord as makeRecord,
  makeRouterAbEcdsaDerivationNormalSigningStateFixture as makeRouterAbEcdsaDerivationNormalSigningState,
} from './helpers/ecdsaSessionRecordVariants.fixtures';
import { makeThresholdEcdsaSessionStoreDeps } from './helpers/thresholdEcdsaSessionStoreDeps.fixtures';
import {
  clearRouterAbEcdsaDerivationWorkerMaterialRuntimeValidation,
  markRouterAbEcdsaDerivationWorkerMaterialRuntimeValidated,
} from '../../packages/sdk-web/src/core/signingEngine/session/routerAbSigningWalletSession';

const WALLET_ID = toWalletId('alice.testnet');
const OTHER_WALLET_ID = toWalletId('bob.testnet');
const OWNER_ADDRESS = '0x1111111111111111111111111111111111111111';
const OTHER_OWNER_ADDRESS = '0x2222222222222222222222222222222222222222';
const RP_ID = 'localhost';
const PASSKEY_CREDENTIAL_ID = 'credential-passkey';
const VALID_PUBLIC_KEY_B64U = 'AgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA';
const RUNTIME_POLICY_SCOPE = {
  orgId: 'org-test',
  projectId: 'project',
  envId: 'dev',
  signingRootVersion: 'default',
};
const DEFAULT_SIGNING_ROOT_ID = `${RUNTIME_POLICY_SCOPE.projectId}:${RUNTIME_POLICY_SCOPE.envId}`;
const DEFAULT_SIGNING_ROOT_VERSION = RUNTIME_POLICY_SCOPE.signingRootVersion;

function plannedWalletKeyId(input: {
  walletId?: typeof WALLET_ID;
  signingRootId?: string;
  signingRootVersion?: string;
}) {
  return deriveEvmFamilySigningKeySlotId({
    walletId: input.walletId ?? WALLET_ID,
    signingRootId: input.signingRootId ?? DEFAULT_SIGNING_ROOT_ID,
    signingRootVersion: input.signingRootVersion ?? DEFAULT_SIGNING_ROOT_VERSION,
  });
}

const WALLET_KEY_ID = plannedWalletKeyId({});
type KeyRefFixtureInput = {
  backendBinding?: ThresholdEcdsaSecp256k1KeyRef['backendBinding'];
  participantIds?: ThresholdEcdsaSecp256k1KeyRef['participantIds'];
  thresholdEcdsaPublicKeyB64u?: ThresholdEcdsaSecp256k1KeyRef['thresholdEcdsaPublicKeyB64u'];
  ethereumAddress?: ThresholdEcdsaSecp256k1KeyRef['ethereumAddress'];
  routerAbEcdsaDerivationNormalSigning?: ThresholdEcdsaSecp256k1KeyRef['routerAbEcdsaDerivationNormalSigning'];
  thresholdSessionKind?: ThresholdEcdsaSecp256k1KeyRef['thresholdSessionKind'];
  walletSessionJwt?: ThresholdEcdsaSecp256k1KeyRef['walletSessionJwt'];
};

const EVM_TARGET: ThresholdEcdsaChainTarget = {
  kind: 'evm',
  namespace: 'eip155',
  chainId: 5042002,
  networkSlug: 'arc-testnet',
};

const TEMPO_TARGET: ThresholdEcdsaChainTarget = {
  kind: 'tempo',
  chainId: 42431,
  networkSlug: 'tempo-moderato',
};

function makeRuntimePolicyScopeForSigningRoot(input: {
  signingRootId: string;
  signingRootVersion?: string;
}): typeof RUNTIME_POLICY_SCOPE {
  const [projectId, envId] = input.signingRootId.split(':');
  if (!projectId || !envId) {
    throw new Error('test signingRootId must use project:env form');
  }
  return {
    ...RUNTIME_POLICY_SCOPE,
    projectId,
    envId,
    signingRootVersion: input.signingRootVersion ?? RUNTIME_POLICY_SCOPE.signingRootVersion,
  };
}

function makeKeyRef(input: KeyRefFixtureInput = {}): ThresholdEcdsaSecp256k1KeyRef {
  const record = makeRecord({ bindLiveRoleLocalWorkerMaterial: true });
  const recordKeyRef = buildThresholdEcdsaSecp256k1KeyRefFromSessionRecord({ record });
  if (recordKeyRef.backendBinding?.materialKind !== 'role_local_worker_handle') {
    throw new Error('expected live role-local backend binding');
  }
  return {
    type: 'threshold-ecdsa-secp256k1',
    userId: WALLET_ID,
    chainTarget: EVM_TARGET,
    relayerUrl: 'https://relay.localhost',
    keyHandle: toEvmFamilyEcdsaKeyHandle('key-handle-shared'),
    ecdsaThresholdKeyId: parseEcdsaThresholdKeyId('ederivation-shared-key'),
    thresholdSessionId: 'threshold-session-1',
    signingGrantId: 'signing-grant-1',
    backendBinding:
      'backendBinding' in input
        ? input.backendBinding
        : recordKeyRef.backendBinding,
    participantIds: input.participantIds ?? [1, 2],
    thresholdEcdsaPublicKeyB64u:
      'thresholdEcdsaPublicKeyB64u' in input
        ? input.thresholdEcdsaPublicKeyB64u
        : VALID_PUBLIC_KEY_B64U,
    ethereumAddress: input.ethereumAddress ?? OWNER_ADDRESS,
    routerAbEcdsaDerivationNormalSigning:
      'routerAbEcdsaDerivationNormalSigning' in input
        ? input.routerAbEcdsaDerivationNormalSigning
        : makeRouterAbEcdsaDerivationNormalSigningState({
            ethereumAddress: input.ethereumAddress ?? OWNER_ADDRESS,
            thresholdPublicKey33B64u:
              'thresholdEcdsaPublicKeyB64u' in input
                ? input.thresholdEcdsaPublicKeyB64u || VALID_PUBLIC_KEY_B64U
                : VALID_PUBLIC_KEY_B64U,
          }),
    thresholdSessionKind: input.thresholdSessionKind ?? 'jwt',
    walletSessionJwt: 'walletSessionJwt' in input ? input.walletSessionJwt : 'threshold-auth-token',
  };
}

const DEFAULT_MATERIAL_ACTIVATION = makeRecord().materialActivation;

function resetEcdsaIdentityTestState(): void {
  clearAllThresholdEcdsaSessionRecords(makeThresholdEcdsaSessionStoreDeps());
  clearRouterAbEcdsaDerivationWorkerMaterialRuntimeValidation();
}

test.describe('EVM-family ECDSA identity', () => {
  test.beforeEach(resetEcdsaIdentityTestState);
  test.afterEach(resetEcdsaIdentityTestState);

  test('derives one shared fingerprint across Tempo and Arc/EVM session lanes', () => {
    const evmKey = buildEvmFamilyEcdsaKeyIdentityFromRecord({
      record: makeRecord({
        chainTarget: EVM_TARGET,
        thresholdSessionId: 'threshold-session-evm',
        signingGrantId: 'wallet-session-evm',
      }),
    });
    const tempoKey = buildEvmFamilyEcdsaKeyIdentityFromRecord({
      record: makeRecord({
        chainTarget: TEMPO_TARGET,
        thresholdSessionId: 'threshold-session-tempo',
        signingGrantId: 'wallet-session-tempo',
      }),
    });

    expect(evmKey.ecdsaThresholdKeyId).toBe(tempoKey.ecdsaThresholdKeyId);
    expect(evmKey.thresholdOwnerAddress).toBe(tempoKey.thresholdOwnerAddress);
    expect(deriveEvmFamilyKeyFingerprint(evmKey)).toBe(deriveEvmFamilyKeyFingerprint(tempoKey));
  });

  test('normalizes participant order before fingerprinting shared key identity', () => {
    const recordKey = buildEvmFamilyEcdsaKeyIdentityFromRecord({
      record: makeRecord({ participantIds: [2, 1] }),
    });
    const keyRefKey = buildEvmFamilyEcdsaKeyIdentityFromKeyRef({
      keyRef: makeKeyRef({ participantIds: [1, 2] }),
      runtimePolicyScope: RUNTIME_POLICY_SCOPE,
    });

    expect(recordKey.participantIds.map(Number)).toEqual([1, 2]);
    expect(deriveEvmFamilyKeyFingerprint(recordKey)).toBe(deriveEvmFamilyKeyFingerprint(keyRefKey));
  });

  test('derives public-facts fingerprint without session or chain identity', async () => {
    const publicFacts = await toVerifiedEcdsaPublicFactsFromRecord({
      record: makeRecord(),
    });
    const evmFingerprint = deriveEvmFamilyKeyFingerprintFromPublicFacts({
      walletId: WALLET_ID,
      publicFacts,
    });
    const tempoFingerprint = deriveEvmFamilyKeyFingerprintFromPublicFacts({
      walletId: WALLET_ID,
      publicFacts,
    });
    const ownerDriftFingerprint = deriveEvmFamilyKeyFingerprintFromPublicFacts({
      walletId: WALLET_ID,
      publicFacts: buildVerifiedEcdsaPublicFacts({
        keyHandle: publicFacts.keyHandle,
        publicKeyB64u: publicFacts.publicKeyB64u,
        participantIds: publicFacts.participantIds,
        thresholdOwnerAddress: OTHER_OWNER_ADDRESS,
      }),
    });

    expect(evmFingerprint).toBe(tempoFingerprint);
    expect(ownerDriftFingerprint).not.toBe(evmFingerprint);
  });

  test('derives a deterministic key handle with normalized signing root version', async () => {
    const explicitDefault = await deriveEvmFamilyEcdsaKeyHandle({
      ecdsaThresholdKeyId: 'ederivation-shared-key',
      signingRootId: 'project:dev',
      signingRootVersion: 'default',
    });
    const implicitDefault = await deriveEvmFamilyEcdsaKeyHandle({
      ecdsaThresholdKeyId: 'ederivation-shared-key',
      signingRootId: 'project:dev',
      signingRootVersion: '',
    });
    const sharedUtilityHandle = await deriveThresholdEcdsaKeyHandle({
      ecdsaThresholdKeyId: 'ederivation-shared-key',
      signingRootId: 'project:dev',
      signingRootVersion: 'default',
    });

    expect(explicitDefault).toBe(implicitDefault);
    expect(explicitDefault).toBe(sharedUtilityHandle);
    expect(explicitDefault).toMatch(/^ederivation-key-/);
  });

  test('builds verified public facts from runtime records and key refs', async () => {
    const recordFacts = await toVerifiedEcdsaPublicFactsFromRecord({
      record: makeRecord(),
    });
    const keyRefFacts = await toVerifiedEcdsaPublicFactsFromKeyRef({
      keyRef: makeKeyRef(),
    });

    expect(recordFacts).toEqual(keyRefFacts);
    expect(recordFacts.kind).toBe('verified_ecdsa_public_facts');
    expect(recordFacts.publicKeyB64u).toBe(VALID_PUBLIC_KEY_B64U);
    expect(recordFacts.participantIds.map(Number)).toEqual([1, 2]);
    expect(recordFacts.thresholdOwnerAddress).toBe(OWNER_ADDRESS);
    expect('ecdsaThresholdKeyId' in recordFacts).toBe(false);
    expect('subjectId' in recordFacts).toBe(false);
    expect('rpId' in recordFacts).toBe(false);
  });

  test('builds resolved ECDSA key facade with branch-specific auth bindings', async () => {
    const publicFacts = await toVerifiedEcdsaPublicFactsFromRecord({
      record: makeRecord(),
    });
    const passkeyKey = buildResolvedEvmFamilyEcdsaKey({
      walletId: WALLET_ID,
      publicFacts,
      authBinding: buildPasskeyEcdsaAuthBinding({
        rpId: RP_ID,
        credentialIdB64u: PASSKEY_CREDENTIAL_ID,
      }),
    });
    const emailOtpKey = buildResolvedEvmFamilyEcdsaKey({
      walletId: WALLET_ID,
      publicFacts,
      authBinding: buildEmailOtpEcdsaAuthBinding({
        authSubjectId: 'google:alice',
        providerId: 'google',
      }),
    });

    expect(passkeyKey.kind).toBe('resolved_evm_family_ecdsa_key');
    expect(passkeyKey.publicFacts).toBe(publicFacts);
    expect(passkeyKey.authBinding.kind).toBe('passkey_ecdsa_auth_binding');
    expect(passkeyKey.authBinding.rpId).toBe(RP_ID);
    expect('providerId' in passkeyKey.authBinding).toBe(false);
    expect(emailOtpKey.authBinding.kind).toBe('email_otp_ecdsa_auth_binding');
    expect(emailOtpKey.authBinding.authSubjectId).toBe('google:alice');
    expect(emailOtpKey.authBinding.providerId).toBe('google');
    expect('rpId' in emailOtpKey.authBinding).toBe(false);
    expect('key' in passkeyKey).toBe(false);
    expect('signingRootId' in passkeyKey).toBe(false);
  });

  test('rejects incomplete resolved ECDSA auth bindings', () => {
    expect(() =>
      buildPasskeyEcdsaAuthBinding({ rpId: '', credentialIdB64u: PASSKEY_CREDENTIAL_ID }),
    ).toThrow(/rpId is required/);
    expect(() => buildPasskeyEcdsaAuthBinding({ rpId: RP_ID, credentialIdB64u: '' })).toThrow(
      /credentialIdB64u is required/,
    );
    expect(() =>
      buildEmailOtpEcdsaAuthBinding({ authSubjectId: '', providerId: 'google' }),
    ).toThrow(/authSubjectId is required/);
    expect(() =>
      buildEmailOtpEcdsaAuthBinding({ authSubjectId: 'google:alice', providerId: '' }),
    ).toThrow(/providerId is required/);
  });

  test('builds ready signer session material with transport auth and worker handle', async () => {
    const keyRef = makeKeyRef();
    const publicFacts = await toVerifiedEcdsaPublicFactsFromKeyRef({ keyRef });
    const signerSession = buildReadyEcdsaSignerSession({
      keyRef,
      materialActivation: DEFAULT_MATERIAL_ACTIVATION,
      publicFacts,
      sessionPolicy: buildKnownReadyThresholdEcdsaSessionPolicy({
        remainingUses: 1,
        expiresAtMs: 1_900_000_000_000,
      }),
      walletSessionJwt: 'wallet-session-jwt',
    });

    expect(signerSession.kind).toBe('ready_ecdsa_signer_session');
    expect(signerSession.publicFacts).toBe(publicFacts);
    expect(signerSession.session.policy).toEqual({
      kind: 'known_threshold_ecdsa_session_policy',
      remainingUses: 1,
      expiresAtMs: 1_900_000_000_000,
    });
    expect(signerSession.routerAbEcdsaDerivationNormalSigning.credential).toEqual({
      kind: 'jwt',
      walletSessionJwt: 'wallet-session-jwt',
    });
    expect(signerSession.transport.relayerKeyId).toBe('relayer-key');
    expect(signerSession.clientShare.kind).toBe('role_local_worker_share');
    if (signerSession.clientShare.kind !== 'role_local_worker_share') {
      throw new Error('expected role-local worker material');
    }
    expect(signerSession.clientShare.handle.materialHandle).toContain(
      'router-ab-ecdsa-role-local:',
    );
    expect('keyRef' in signerSession).toBe(false);
    expect('walletSessionJwt' in signerSession).toBe(false);
  });

  test('builds role-local worker material handles from material identity only', () => {
    const base = {
      keyHandle: parseEcdsaKeyHandle('key-handle-shared'),
      clientVerifyingPublicKey33B64u:
        parseEcdsaClientVerifyingPublicKey33B64u(VALID_PUBLIC_KEY_B64U),
      ecdsaThresholdKeyId: parseEcdsaThresholdKeyId('ederivation-shared-key'),
      participantIds: [1, 2] as const,
      relayerKeyId: parseEcdsaRelayerKeyId('relayer-key'),
    };

    const evmHandle = buildEcdsaRoleLocalSigningMaterialHandle(base);
    const tempoHandle = buildEcdsaRoleLocalSigningMaterialHandle(base);

    expect(evmHandle.bindingDigest).toBe(tempoHandle.bindingDigest);
    expect(evmHandle.materialHandle).toBe(tempoHandle.materialHandle);
    expect(evmHandle.materialHandle).toContain(
      'router-ab-ecdsa-role-local:key-handle-shared:ederivation-shared-key:',
    );

    const otherThresholdKeyHandle = buildEcdsaRoleLocalSigningMaterialHandle({
      ...base,
      ecdsaThresholdKeyId: parseEcdsaThresholdKeyId('ederivation-other-key'),
    });
    expect(otherThresholdKeyHandle.bindingDigest).not.toBe(evmHandle.bindingDigest);
    expect(otherThresholdKeyHandle.materialHandle).not.toBe(evmHandle.materialHandle);
  });

  test('validates role-local client verifying public keys as compressed 33-byte values', () => {
    const wrongLength = new Uint8Array(32);
    const uncompressedPrefix = new Uint8Array(33);
    uncompressedPrefix[0] = 0x04;

    expect(parseEcdsaClientVerifyingPublicKey33B64u(VALID_PUBLIC_KEY_B64U)).toBe(
      VALID_PUBLIC_KEY_B64U,
    );
    expect(() => parseEcdsaClientVerifyingPublicKey33B64u(base64UrlEncode(wrongLength))).toThrow(
      /canonical base64url for 33 bytes/,
    );
    expect(() =>
      parseEcdsaClientVerifyingPublicKey33B64u(base64UrlEncode(uncompressedPrefix)),
    ).toThrow(/compressed secp256k1/);
    expect(() => parseEcdsaClientVerifyingPublicKey33B64u(`${VALID_PUBLIC_KEY_B64U}=`)).toThrow(
      /unpadded base64url/,
    );
  });

  test('builds ready signer session material from a persisted role-local blob as a worker handle', async () => {
    const readyRecord = makeRoleLocalReadyRecord();
    const keyRef = makeKeyRef({
      backendBinding: {
        materialKind: 'role_local_ready_state_blob',
        relayerKeyId: 'relayer-key',
        clientVerifyingShareB64u: VALID_PUBLIC_KEY_B64U,
        stateBlob: readyRecord.stateBlob,
        ecdsaRoleLocalReadyRecord: readyRecord,
      },
    });
    const publicFacts = await toVerifiedEcdsaPublicFactsFromKeyRef({ keyRef });
    const signerSession = buildReadyEcdsaSignerSession({
      keyRef,
      materialActivation: DEFAULT_MATERIAL_ACTIVATION,
      publicFacts,
      sessionPolicy: buildKnownReadyThresholdEcdsaSessionPolicy({
        remainingUses: 1,
        expiresAtMs: 1_900_000_000_000,
      }),
      walletSessionJwt: 'wallet-session-jwt',
    });

    expect(signerSession.clientShare.kind).toBe('role_local_worker_share');
    if (signerSession.clientShare.kind !== 'role_local_worker_share') {
      throw new Error('expected role-local worker material');
    }
    expect(signerSession.clientShare.handle.bindingDigest).toContain(
      'router_ab_ecdsa_role_local_signing_material_binding_v2',
    );
  });

  test('rebuilds key refs from session facts without claiming durable material ownership', () => {
    const record = makeRecord();
    const keyRef = buildThresholdEcdsaSecp256k1KeyRefFromSessionRecord({ record });

    expect(keyRef.backendBinding?.materialKind).toBe('role_local_durable_public_anchor');
    expect(keyRef.walletSessionJwt).toBeUndefined();
    if (keyRef.backendBinding?.materialKind !== 'role_local_durable_public_anchor') {
      throw new Error('expected durable public anchor backend binding');
    }
    expect(keyRef.backendBinding.publicFacts).toStrictEqual(record.ecdsaRoleLocalPublicFacts);
  });

  test('builds key refs with canonical role-local public facts', () => {
    const record = makeRecord();
    const keyRef = buildThresholdEcdsaSecp256k1KeyRefFromSessionRecord({ record });
    expect(keyRef.backendBinding?.materialKind).toBe('role_local_durable_public_anchor');
    if (keyRef.backendBinding?.materialKind !== 'role_local_durable_public_anchor') {
      throw new Error('expected durable public anchor backend binding');
    }
    expect(keyRef.backendBinding.publicFacts.derivationClientSharePublicKey33B64u).toBe(
      VALID_PUBLIC_KEY_B64U,
    );
  });

  test('builds Email OTP worker share handles with exact lane identity', async () => {
    const emailOtpRecord = makeEmailOtpRecord();
    const emailOtpReadyRecord = makeRoleLocalReadyRecord({
      authMethod: emailOtpRecord.ecdsaRoleLocalAuthMethod,
    });
    const keyRef = makeKeyRef({
      thresholdSessionKind: 'jwt',
      walletSessionJwt: 'threshold-auth-token',
      backendBinding: {
        materialKind: 'email_otp_worker_handle',
        relayerKeyId: 'relayer-key',
        clientVerifyingShareB64u: VALID_PUBLIC_KEY_B64U,
        clientAdditiveShareHandle: {
          kind: 'email_otp_worker_session',
          sessionId: 'email-otp-worker-share-1',
        },
        ecdsaRoleLocalReadyRecord: emailOtpReadyRecord,
      },
    });
    const publicFacts = await toVerifiedEcdsaPublicFactsFromKeyRef({ keyRef });
    const signerSession = buildReadyEcdsaSignerSession({
      keyRef,
      materialActivation: emailOtpRecord.materialActivation,
      publicFacts,
      sessionPolicy: buildKnownReadyThresholdEcdsaSessionPolicy({
        remainingUses: 1,
        expiresAtMs: 1_900_000_000_000,
      }),
      walletSessionJwt: 'wallet-session-jwt',
    });

    expect(signerSession.routerAbEcdsaDerivationNormalSigning.credential).toEqual({
      kind: 'jwt',
      walletSessionJwt: 'wallet-session-jwt',
    });
    expect(signerSession.clientShare.kind).toBe('email_otp_worker_share');
    if (signerSession.clientShare.kind !== 'email_otp_worker_share') {
      throw new Error('expected Email OTP worker share');
    }
    expect(signerSession.clientShare.handle.sessionId).toBe('email-otp-worker-share-1');
    expect(signerSession.clientShare.handle.laneIdentity).toEqual({
      kind: 'email_otp_worker_share_lane_identity',
      keyHandle: publicFacts.keyHandle,
      chainTarget: EVM_TARGET,
      signingGrantId: 'signing-grant-1',
      thresholdSessionId: 'threshold-session-1',
    });
  });

  test('rejects incomplete ready signer session material', async () => {
    const keyRef = makeKeyRef({
      backendBinding: {
        materialKind: 'metadata_only',
        relayerKeyId: 'relayer-key',
        clientVerifyingShareB64u: VALID_PUBLIC_KEY_B64U,
      },
    });
    const publicFacts = await toVerifiedEcdsaPublicFactsFromKeyRef({ keyRef });

    expect(() =>
      buildEcdsaWalletSessionTransportAuth({
        kind: 'wallet_session_jwt',
      } as unknown as Parameters<typeof buildEcdsaWalletSessionTransportAuth>[0]),
    ).toThrow(/walletSessionJwt is required/);
    expect(() =>
      buildReadyEcdsaSignerSession({
        keyRef,
        materialActivation: DEFAULT_MATERIAL_ACTIVATION,
        publicFacts,
        sessionPolicy: buildKnownReadyThresholdEcdsaSessionPolicy({
          remainingUses: 1,
          expiresAtMs: 1_900_000_000_000,
        }),
        walletSessionJwt: 'wallet-session-jwt',
      }),
    ).toThrow(/requires signing material/);
  });

  test('builds verified public facts from durable sealed record metadata', async () => {
    const facts = await toVerifiedEcdsaPublicFactsFromDurableRecord({
      record: {
        ecdsaRestore: {
          keyHandle: toEvmFamilyEcdsaKeyHandle('key-handle-shared'),
          thresholdEcdsaPublicKeyB64u: VALID_PUBLIC_KEY_B64U,
          participantIds: [2, 1],
          ethereumAddress: OWNER_ADDRESS,
        },
      },
    });

    expect(facts.publicKeyB64u).toBe(VALID_PUBLIC_KEY_B64U);
    expect(facts.participantIds.map(Number)).toEqual([1, 2]);
    expect(facts.thresholdOwnerAddress).toBe(OWNER_ADDRESS);
  });

  test('rejects public facts without a verified compressed public key', async () => {
    await expect(
      toVerifiedEcdsaPublicFactsFromRecord({
        record: makeRecord({ thresholdEcdsaPublicKeyB64u: undefined }),
      }),
    ).rejects.toThrow(/thresholdEcdsaPublicKeyB64u is required/);

    await expect(
      toVerifiedEcdsaPublicFactsFromKeyRef({
        keyRef: makeKeyRef({ thresholdEcdsaPublicKeyB64u: 'AQ' }),
      }),
    ).rejects.toThrow(/thresholdEcdsaPublicKeyB64u must decode to 33 bytes/);
  });

  test('changes the shared fingerprint when stable EVM-family key fields change', () => {
    const baseKey = buildEvmFamilyEcdsaKeyIdentityFromRecord({
      record: makeRecord(),
    });
    const baseFingerprint = deriveEvmFamilyKeyFingerprint(baseKey);
    const variants = [
      buildEvmFamilyEcdsaKeyIdentityFromRecord({
        record: makeRecord({ walletId: OTHER_WALLET_ID }),
      }),
      buildEvmFamilyEcdsaKeyIdentityFromRecord({
        record: makeRecord({
          signingRootId: 'project:other',
          runtimePolicyScope: makeRuntimePolicyScopeForSigningRoot({
            signingRootId: 'project:other',
          }),
        }),
      }),
      buildEvmFamilyEcdsaKeyIdentityFromRecord({
        record: makeRecord({ signingRootVersion: 'v2' }),
      }),
      buildEvmFamilyEcdsaKeyIdentityFromRecord({
        record: makeRecord({ participantIds: [1, 2, 3] }),
      }),
      buildEvmFamilyEcdsaKeyIdentityFromRecord({
        record: makeRecord({ ecdsaThresholdKeyId: 'ederivation-other-key' }),
      }),
      buildEvmFamilyEcdsaKeyIdentityFromRecord({
        record: makeRecord({ ethereumAddress: OTHER_OWNER_ADDRESS }),
      }),
    ];

    for (const variant of variants) {
      expect(deriveEvmFamilyKeyFingerprint(variant)).not.toBe(baseFingerprint);
    }
  });

  test('uses explicit ECDSA signing-root binding before runtime policy metadata', () => {
    const record = makeRecord({
      signingRootId: 'project:dev',
      signingRootVersion: 'default',
      runtimePolicyScope: makeRuntimePolicyScopeForSigningRoot({
        signingRootId: 'other-project:prod',
        signingRootVersion: 'v2',
      }),
    });

    const binding = resolveThresholdSigningRootBindingFromRecord({ record });
    const key = buildEvmFamilyEcdsaKeyIdentityFromRecord({ record });

    expect(binding.signingRootId).toBe('project:dev');
    expect(binding.signingRootVersion).toBe('default');
    expect(key.signingRootId).toBe('project:dev');
    expect(key.signingRootVersion).toBe('default');
    expect(key.ecdsaThresholdKeyId).toBe('ederivation-shared-key');
  });

  test('record builder rejects persisted owner address when trusted key-ref owner disagrees', () => {
    expect(() =>
      buildEvmFamilyEcdsaKeyIdentityFromRecord({
        record: makeRecord({ ethereumAddress: OTHER_OWNER_ADDRESS }),
        trustedOwnerAddress: OWNER_ADDRESS,
      }),
    ).toThrow(/persisted owner address mismatches trusted EVM-family key material/);
  });

  test('key-ref builder rejects owner address when trusted key material disagrees', () => {
    expect(() =>
      buildEvmFamilyEcdsaKeyIdentityFromKeyRef({
        keyRef: makeKeyRef({ ethereumAddress: OTHER_OWNER_ADDRESS }),
        runtimePolicyScope: RUNTIME_POLICY_SCOPE,
        trustedOwnerAddress: OWNER_ADDRESS,
      }),
    ).toThrow(/key ref owner address mismatches trusted EVM-family key material/);
  });

  test('normalizes persisted ECDSA reads into shared key identity plus concrete lane', () => {
    const readModel = thresholdEcdsaSessionRecordReadModel(
      makeRecord({
        participantIds: [2, 1],
        ethereumAddress: '0xAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',
      }),
    );

    expect('evmFamilySigningKeySlotId' in readModel.key).toBe(false);
    expect(readModel.lane.materialActivation.activationId).toBeDefined();
    expect('rpId' in readModel.key).toBe(false);
    expect(readModel.key.keyScope).toBe('evm-family');
    expect(readModel.key.participantIds.map(Number)).toEqual([1, 2]);
    expect(readModel.key.thresholdOwnerAddress).toBe('0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa');
    expect(readModel.lane.key).toBe(readModel.key);
    expect(readModel.lane.chainTarget).toEqual(EVM_TARGET);
    expect(readModel.lane.thresholdSessionId).toBe('threshold-session-1');
    expect(readModel.lane.signingGrantId).toBe('signing-grant-1');
  });

  test('fact writes preserve same-authority Email OTP ECDSA target facts until current-session commit', () => {
    clearAllThresholdEcdsaSessionRecords(makeThresholdEcdsaSessionStoreDeps());
    const deps = makeThresholdEcdsaSessionStoreDeps({ now: () => 1_800_000_000_000 });
    upsertThresholdEcdsaSessionFact(
      deps,
      makeEmailOtpRecord({
        chainTarget: TEMPO_TARGET,
        thresholdSessionId: 'threshold-session-email-otp-old',
        signingGrantId: 'signing-grant-email-otp-old',
      }),
    );
    upsertThresholdEcdsaSessionFact(
      deps,
      makeEmailOtpRecord({
        chainTarget: TEMPO_TARGET,
        thresholdSessionId: 'threshold-session-email-otp-current',
        signingGrantId: 'signing-grant-email-otp-current',
      }),
    );

    const records = listStoredThresholdEcdsaSessionRecordsForWallet(WALLET_ID);

    expect(records).toHaveLength(2);
    expect(records.map((record) => record.thresholdSessionId).sort()).toEqual([
      'threshold-session-email-otp-current',
      'threshold-session-email-otp-old',
    ]);
    expect(deps.recordsByLane.size).toBe(2);
  });

  test('current-session commit retires superseded Email OTP ECDSA records for the same authority and key', () => {
    clearAllThresholdEcdsaSessionRecords(makeThresholdEcdsaSessionStoreDeps());
    const deps = makeThresholdEcdsaSessionStoreDeps({ now: () => 1_800_000_000_000 });
    upsertThresholdEcdsaSessionFact(
      deps,
      makeEmailOtpRecord({
        chainTarget: TEMPO_TARGET,
        thresholdSessionId: 'threshold-session-email-otp-old',
        signingGrantId: 'signing-grant-email-otp-old',
      }),
    );
    const currentRecord = {
      ...makeEmailOtpRecord({
        chainTarget: TEMPO_TARGET,
        thresholdSessionId: 'threshold-session-email-otp-current',
        signingGrantId: 'signing-grant-email-otp-current',
      }),
      expiresAtMs: 1_900_000_001_000,
      updatedAtMs: 1_800_000_001_000,
    };
    const commit = commitCurrentThresholdEcdsaSession({
      deps,
      record: currentRecord,
    });
    const records = listStoredThresholdEcdsaSessionRecordsForWallet(WALLET_ID);

    expect(commit).toMatchObject({
      kind: 'committed_current',
      retired: [{ thresholdSessionId: 'threshold-session-email-otp-old' }],
    });
    expect(records).toHaveLength(1);
    expect(records[0]?.chainTarget).toEqual(TEMPO_TARGET);
    expect(records[0]?.thresholdSessionId).toBe('threshold-session-email-otp-current');
    expect(deps.recordsByLane.size).toBe(1);
  });

  test('restored older Email OTP ECDSA fact does not retire a newer current session', () => {
    clearAllThresholdEcdsaSessionRecords(makeThresholdEcdsaSessionStoreDeps());
    const deps = makeThresholdEcdsaSessionStoreDeps({ now: () => 1_800_000_000_000 });
    const restoredRecord = {
      ...makeEmailOtpRecord({
        chainTarget: TEMPO_TARGET,
        thresholdSessionId: 'threshold-session-email-otp-generation-1',
        signingGrantId: 'signing-grant-email-otp-generation-1',
      }),
      expiresAtMs: 1_900_000_001_000,
      updatedAtMs: 1_800_000_001_000,
    };
    const currentRecord = {
      ...makeEmailOtpRecord({
        chainTarget: TEMPO_TARGET,
        thresholdSessionId: 'threshold-session-email-otp-generation-2',
        signingGrantId: 'signing-grant-email-otp-generation-2',
      }),
      expiresAtMs: 1_900_000_002_000,
      updatedAtMs: 1_800_000_002_000,
    };
    const currentCommit = commitCurrentThresholdEcdsaSession({
      deps,
      record: currentRecord,
    });
    upsertThresholdEcdsaSessionFact(deps, restoredRecord);

    const records = listStoredThresholdEcdsaSessionRecordsForWallet(WALLET_ID);

    expect(currentCommit.kind).toBe('committed_current');
    expect(records.map((record) => record.thresholdSessionId).sort()).toEqual([
      'threshold-session-email-otp-generation-1',
      'threshold-session-email-otp-generation-2',
    ]);
  });

  test('stale Email OTP ECDSA current-session commit is ignored while newer current session remains', () => {
    clearAllThresholdEcdsaSessionRecords(makeThresholdEcdsaSessionStoreDeps());
    const deps = makeThresholdEcdsaSessionStoreDeps({ now: () => 1_800_000_000_000 });
    const currentRecord = {
      ...makeEmailOtpRecord({
        chainTarget: TEMPO_TARGET,
        thresholdSessionId: 'threshold-session-email-otp-generation-2',
        signingGrantId: 'signing-grant-email-otp-generation-2',
      }),
      expiresAtMs: 1_900_000_002_000,
      updatedAtMs: 1_800_000_002_000,
    };
    const staleRecord = {
      ...makeEmailOtpRecord({
        chainTarget: TEMPO_TARGET,
        thresholdSessionId: 'threshold-session-email-otp-generation-1',
        signingGrantId: 'signing-grant-email-otp-generation-1',
      }),
      expiresAtMs: 1_900_000_001_000,
      updatedAtMs: 1_800_000_001_000,
    };
    commitCurrentThresholdEcdsaSession({
      deps,
      record: currentRecord,
    });
    const staleCommit = commitCurrentThresholdEcdsaSession({
      deps,
      record: staleRecord,
    });
    const records = listStoredThresholdEcdsaSessionRecordsForWallet(WALLET_ID);

    expect(staleCommit).toMatchObject({
      kind: 'stale_commit_ignored',
      incoming: { thresholdSessionId: 'threshold-session-email-otp-generation-1' },
      current: { thresholdSessionId: 'threshold-session-email-otp-generation-2' },
    });
    expect(records.map((record) => record.thresholdSessionId)).toEqual([
      'threshold-session-email-otp-generation-2',
    ]);
  });

  test('equal-generation Email OTP ECDSA conflict leaves the current store unchanged', () => {
    clearAllThresholdEcdsaSessionRecords(makeThresholdEcdsaSessionStoreDeps());
    const deps = makeThresholdEcdsaSessionStoreDeps({ now: () => 1_800_000_000_000 });
    const firstRecord = {
      ...makeEmailOtpRecord({
        chainTarget: TEMPO_TARGET,
        thresholdSessionId: 'threshold-session-email-otp-generation-a',
        signingGrantId: 'signing-grant-email-otp-generation-a',
      }),
      expiresAtMs: 1_900_000_002_000,
      updatedAtMs: 1_800_000_002_000,
    };
    const secondRecord = {
      ...makeEmailOtpRecord({
        chainTarget: TEMPO_TARGET,
        thresholdSessionId: 'threshold-session-email-otp-generation-b',
        signingGrantId: 'signing-grant-email-otp-generation-b',
      }),
      expiresAtMs: 1_900_000_002_000,
      updatedAtMs: 1_800_000_002_000,
    };
    commitCurrentThresholdEcdsaSession({
      deps,
      record: firstRecord,
    });
    const secondCommit = commitCurrentThresholdEcdsaSession({
      deps,
      record: secondRecord,
    });
    const records = listStoredThresholdEcdsaSessionRecordsForWallet(WALLET_ID);

    expect(secondCommit).toMatchObject({
      kind: 'same_generation_distinct_session',
      incoming: { thresholdSessionId: 'threshold-session-email-otp-generation-b' },
      existing: { thresholdSessionId: 'threshold-session-email-otp-generation-a' },
    });
    expect(records.map((record) => record.thresholdSessionId)).toEqual([
      'threshold-session-email-otp-generation-a',
    ]);
  });

  test('clears only the targeted runtime session lane for a threshold session id + chain target', () => {
    clearAllThresholdEcdsaSessionRecords(makeThresholdEcdsaSessionStoreDeps());
    const deps = makeThresholdEcdsaSessionStoreDeps({ now: () => 1_800_000_000_000 });
    upsertThresholdEcdsaSessionFact(
      deps,
      makeRecord({
        chainTarget: EVM_TARGET,
        thresholdSessionId: 'threshold-session-clear-target',
        signingGrantId: 'wallet-session-clear-target-evm',
      }),
    );
    upsertThresholdEcdsaSessionFact(
      deps,
      makeRecord({
        chainTarget: TEMPO_TARGET,
        thresholdSessionId: 'threshold-session-clear-target',
        signingGrantId: 'wallet-session-clear-target-tempo',
      }),
    );

    const removed = clearStoredThresholdEcdsaSessionRecordByThresholdSessionIdForTarget({
      thresholdSessionId: 'threshold-session-clear-target',
      chainTarget: EVM_TARGET,
    });
    const cleared = getStoredThresholdEcdsaSessionRecordByThresholdSessionIdForTarget({
      thresholdSessionId: 'threshold-session-clear-target',
      chainTarget: EVM_TARGET,
    });
    const retained = getStoredThresholdEcdsaSessionRecordByThresholdSessionIdForTarget({
      thresholdSessionId: 'threshold-session-clear-target',
      chainTarget: TEMPO_TARGET,
    });

    expect(removed).toBe(1);
    expect(cleared).toBeNull();
    expect(retained?.chainTarget).toEqual(TEMPO_TARGET);
    expect(retained?.thresholdSessionId).toBe('threshold-session-clear-target');
  });

  test('clears all runtime lanes for a wallet key handle', () => {
    clearAllThresholdEcdsaSessionRecords(makeThresholdEcdsaSessionStoreDeps());
    const deps = makeThresholdEcdsaSessionStoreDeps({ now: () => 1_800_000_000_000 });
    const sharedKeyHandle = toEvmFamilyEcdsaKeyHandle('key-handle-clear-shared');
    upsertThresholdEcdsaSessionFact(
      deps,
      makeEmailOtpRecord({
        keyHandle: sharedKeyHandle,
        thresholdSessionId: 'threshold-session-clear-shared-a',
        signingGrantId: 'wallet-session-clear-shared-a',
      }),
    );
    upsertThresholdEcdsaSessionFact(
      deps,
      makeEmailOtpRecord({
        keyHandle: sharedKeyHandle,
        chainTarget: TEMPO_TARGET,
        thresholdSessionId: 'threshold-session-clear-shared-b',
        signingGrantId: 'wallet-session-clear-shared-b',
      }),
    );
    upsertThresholdEcdsaSessionFact(
      deps,
      makeEmailOtpRecord({
        keyHandle: toEvmFamilyEcdsaKeyHandle('key-handle-clear-other'),
        thresholdSessionId: 'threshold-session-clear-other',
        signingGrantId: 'wallet-session-clear-other',
      }),
    );

    const removed = clearStoredThresholdEcdsaSessionRecordsForWalletKeyHandle({
      walletId: WALLET_ID,
      keyHandle: sharedKeyHandle,
    });
    const records = listStoredThresholdEcdsaSessionRecordsForWallet(WALLET_ID);

    expect(removed).toBe(2);
    expect(records).toHaveLength(1);
    expect(String(records[0]?.keyHandle)).toBe('key-handle-clear-other');
  });

  test('runtime ECDSA upsert rejects records missing canonical verified public facts', () => {
    const deps = makeThresholdEcdsaSessionStoreDeps({ now: () => 1_800_000_000_000 });
    const rawRecord = { ...makeRecord() } as Record<string, unknown>;
    delete rawRecord.verifiedPublicFacts;
    delete rawRecord.thresholdEcdsaPublicKeyB64u;

    expect(() => upsertThresholdEcdsaSessionFact(deps, rawRecord)).toThrow(
      /missing verifiedPublicFacts/,
    );
  });

  test('normalizes persisted ECDSA records without storing subjectId', () => {
    const deps = makeThresholdEcdsaSessionStoreDeps({ now: () => 1_800_000_000_000 });
    const rawRecord = { ...makeRecord() } as Record<string, unknown>;
    delete rawRecord.subjectId;

    const stored = upsertThresholdEcdsaSessionFact(deps, rawRecord);

    expect('subjectId' in stored).toBe(false);
  });

  test('rejects persisted ECDSA records with any subjectId', () => {
    const deps = makeThresholdEcdsaSessionStoreDeps({ now: () => 1_800_000_000_000 });
    const rawRecord = {
      ...makeRecord(),
      subjectId: 'alice.testnet',
    } as Record<string, unknown>;

    expect(() => upsertThresholdEcdsaSessionFact(deps, rawRecord)).toThrow(/unexpected subjectId/);
  });

  test('client store allows one shared key identity across EVM-family concrete lanes', () => {
    const deps = makeThresholdEcdsaSessionStoreDeps({ now: () => 1_800_000_000_000 });
    upsertThresholdEcdsaSessionFact(
      deps,
      makeRecord({
        signingRootId: 'project:client-shared-key',
        runtimePolicyScope: makeRuntimePolicyScopeForSigningRoot({
          signingRootId: 'project:client-shared-key',
        }),
        chainTarget: EVM_TARGET,
        thresholdSessionId: 'threshold-session-evm-shared',
        signingGrantId: 'wallet-session-evm-shared',
      }),
    );

    expect(() =>
      upsertThresholdEcdsaSessionFact(
        deps,
        makeRecord({
          signingRootId: 'project:client-shared-key',
          runtimePolicyScope: makeRuntimePolicyScopeForSigningRoot({
            signingRootId: 'project:client-shared-key',
          }),
          chainTarget: TEMPO_TARGET,
          thresholdSessionId: 'threshold-session-tempo-shared',
          signingGrantId: 'wallet-session-tempo-shared',
        }),
      ),
    ).not.toThrow();
  });

});
