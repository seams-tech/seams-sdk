import { expect, test } from '@playwright/test';
import { deriveThresholdEcdsaKeyHandle } from '@shared/utils/thresholdEcdsaKeyHandle';
import { toAccountId } from '../../client/src/core/types/accountIds';
import type { ThresholdEcdsaSecp256k1KeyRef } from '../../client/src/core/signingEngine/interfaces/signing';
import {
  buildEmailOtpEcdsaAuthBinding,
  buildEvmFamilyEcdsaKeyIdentityFromKeyRef,
  buildEvmFamilyEcdsaKeyIdentityFromRecord,
  buildPasskeyEcdsaAuthBinding,
  buildVerifiedEcdsaPublicFacts,
  buildKnownReadyThresholdEcdsaSessionPolicy,
  buildReadyEcdsaSignerSession,
  buildResolvedEvmFamilyEcdsaKey,
  buildThresholdEcdsaSessionTransportAuth,
  deriveEvmFamilyEcdsaKeyHandle,
  deriveEvmFamilyKeyFingerprint,
  deriveEvmFamilyKeyFingerprintFromPublicFacts,
  resolveReadyEvmFamilyEcdsaMaterial,
  toEvmFamilyEcdsaKeyHandle,
  toReadyEcdsaSignerSessionFromReadyMaterial,
  toVerifiedEcdsaPublicFactsFromDurableRecord,
  toVerifiedEcdsaPublicFactsFromKeyRef,
  toVerifiedEcdsaPublicFactsFromReadyMaterial,
  toVerifiedEcdsaPublicFactsFromRecord,
} from '../../client/src/core/signingEngine/session/identity/evmFamilyEcdsaIdentity';
import {
  toWalletSubjectId,
  type ThresholdEcdsaChainTarget,
} from '../../client/src/core/signingEngine/interfaces/ecdsaChainTarget';
import {
  clearStoredThresholdEcdsaSessionRecordByThresholdSessionIdForTarget,
  clearStoredThresholdEcdsaSessionRecordsForWalletKeyHandle,
  clearAllThresholdEcdsaSessionRecords,
  deriveThresholdEcdsaRuntimeLaneKey,
  getThresholdEcdsaKeyRefByKey,
  getThresholdEcdsaSessionRecordByKey,
  getStoredThresholdEcdsaSessionRecordByThresholdSessionIdForTarget,
  listStoredThresholdEcdsaSessionRecordsForWallet,
  listThresholdEcdsaRuntimeLanesForWallet,
  thresholdEcdsaSessionRecordReadModel,
  upsertStoredThresholdEcdsaSessionRecord,
  type ThresholdEcdsaSessionRecord,
  type ThresholdEcdsaSessionStoreDeps,
} from '../../client/src/core/signingEngine/session/persistence/records';
import { selectedEcdsaLane } from '../../client/src/core/signingEngine/session/identity/laneIdentity';

const WALLET_ID = toAccountId('alice.testnet');
const SUBJECT_ID = toWalletSubjectId(WALLET_ID);
const OWNER_ADDRESS = '0x1111111111111111111111111111111111111111';
const OTHER_OWNER_ADDRESS = '0x2222222222222222222222222222222222222222';
const RP_ID = 'localhost';
const VALID_PUBLIC_KEY_B64U = 'AgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA';
const OTHER_VALID_PUBLIC_KEY_B64U = 'AwAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA';

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

function makeRecord(
  overrides: Partial<ThresholdEcdsaSessionRecord> = {},
): ThresholdEcdsaSessionRecord {
  return {
    walletId: WALLET_ID,
    chainTarget: EVM_TARGET,
    relayerUrl: 'https://relay.localhost',
    ecdsaThresholdKeyId: 'ehss-shared-key',
    signingRootId: 'project:dev',
    signingRootVersion: 'default',
    relayerKeyId: 'relayer-key',
    clientVerifyingShareB64u: 'client-verifying-share',
    participantIds: [2, 1],
    thresholdSessionKind: 'jwt',
    thresholdSessionId: 'threshold-session-1',
    walletSigningSessionId: 'wallet-signing-session-1',
    thresholdSessionAuthToken: 'threshold-auth-token',
    expiresAtMs: 1_900_000_000_000,
    remainingUses: 3,
    thresholdEcdsaPublicKeyB64u: VALID_PUBLIC_KEY_B64U,
    ethereumAddress: OWNER_ADDRESS,
    updatedAtMs: 1_800_000_000_000,
    source: 'login',
    ...overrides,
    keyHandle: overrides.keyHandle ?? toEvmFamilyEcdsaKeyHandle('key-handle-shared'),
    authMetadata: overrides.authMetadata ?? { rpId: RP_ID },
  };
}

function makeKeyRef(
  overrides: Partial<ThresholdEcdsaSecp256k1KeyRef> = {},
): ThresholdEcdsaSecp256k1KeyRef {
  return {
    type: 'threshold-ecdsa-secp256k1',
    userId: WALLET_ID,
    chainTarget: EVM_TARGET,
    relayerUrl: 'https://relay.localhost',
    keyHandle: toEvmFamilyEcdsaKeyHandle('key-handle-shared'),
    ecdsaThresholdKeyId: 'ehss-shared-key',
    signingRootId: 'project:dev',
    signingRootVersion: 'default',
    backendBinding: {
      relayerKeyId: 'relayer-key',
      clientVerifyingShareB64u: 'client-verifying-share',
    },
    participantIds: [1, 2],
    thresholdEcdsaPublicKeyB64u: VALID_PUBLIC_KEY_B64U,
    ethereumAddress: OWNER_ADDRESS,
    thresholdSessionKind: 'jwt',
    thresholdSessionAuthToken: 'threshold-auth-token',
    thresholdSessionId: 'threshold-session-1',
    walletSigningSessionId: 'wallet-signing-session-1',
    ...overrides,
  };
}

test.describe('EVM-family ECDSA identity', () => {
  test('derives one shared fingerprint across Tempo and Arc/EVM session lanes', () => {
    const evmKey = buildEvmFamilyEcdsaKeyIdentityFromRecord({
      record: makeRecord({
        chainTarget: EVM_TARGET,
        thresholdSessionId: 'threshold-session-evm',
        walletSigningSessionId: 'wallet-session-evm',
      }),
      rpId: RP_ID,
    });
    const tempoKey = buildEvmFamilyEcdsaKeyIdentityFromRecord({
      record: makeRecord({
        chainTarget: TEMPO_TARGET,
        thresholdSessionId: 'threshold-session-tempo',
        walletSigningSessionId: 'wallet-session-tempo',
      }),
      rpId: RP_ID,
    });

    expect(evmKey.ecdsaThresholdKeyId).toBe(tempoKey.ecdsaThresholdKeyId);
    expect(evmKey.thresholdOwnerAddress).toBe(tempoKey.thresholdOwnerAddress);
    expect(deriveEvmFamilyKeyFingerprint(evmKey)).toBe(deriveEvmFamilyKeyFingerprint(tempoKey));
  });

  test('normalizes participant order before fingerprinting shared key identity', () => {
    const recordKey = buildEvmFamilyEcdsaKeyIdentityFromRecord({
      record: makeRecord({ participantIds: [2, 1] }),
      rpId: RP_ID,
    });
    const keyRefKey = buildEvmFamilyEcdsaKeyIdentityFromKeyRef({
      keyRef: makeKeyRef({ participantIds: [1, 2] }),
      rpId: RP_ID,
    });

    expect(recordKey.participantIds.map(Number)).toEqual([1, 2]);
    expect(deriveEvmFamilyKeyFingerprint(recordKey)).toBe(deriveEvmFamilyKeyFingerprint(keyRefKey));
  });

  test('derives public-facts fingerprint without session or chain identity', async () => {
    const publicFacts = await toVerifiedEcdsaPublicFactsFromRecord({
      record: makeRecord({ thresholdEcdsaPublicKeyB64u: VALID_PUBLIC_KEY_B64U }),
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
      ecdsaThresholdKeyId: 'ehss-shared-key',
      signingRootId: 'project:dev',
      signingRootVersion: 'default',
    });
    const implicitDefault = await deriveEvmFamilyEcdsaKeyHandle({
      ecdsaThresholdKeyId: 'ehss-shared-key',
      signingRootId: 'project:dev',
      signingRootVersion: '',
    });
    const sharedUtilityHandle = await deriveThresholdEcdsaKeyHandle({
      ecdsaThresholdKeyId: 'ehss-shared-key',
      signingRootId: 'project:dev',
      signingRootVersion: 'default',
    });

    expect(explicitDefault).toBe(implicitDefault);
    expect(explicitDefault).toBe(sharedUtilityHandle);
    expect(explicitDefault).toMatch(/^ehss-key-/);
  });

  test('builds verified public facts from runtime records and key refs', async () => {
    const recordFacts = await toVerifiedEcdsaPublicFactsFromRecord({
      record: makeRecord({ thresholdEcdsaPublicKeyB64u: VALID_PUBLIC_KEY_B64U }),
    });
    const keyRefFacts = await toVerifiedEcdsaPublicFactsFromKeyRef({
      keyRef: makeKeyRef({ thresholdEcdsaPublicKeyB64u: VALID_PUBLIC_KEY_B64U }),
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
      record: makeRecord({ thresholdEcdsaPublicKeyB64u: VALID_PUBLIC_KEY_B64U }),
    });
    const passkeyKey = buildResolvedEvmFamilyEcdsaKey({
      walletId: WALLET_ID,
      publicFacts,
      authBinding: buildPasskeyEcdsaAuthBinding({ rpId: RP_ID }),
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
    expect(() => buildPasskeyEcdsaAuthBinding({ rpId: '' })).toThrow(/rpId is required/);
    expect(() =>
      buildEmailOtpEcdsaAuthBinding({ authSubjectId: '', providerId: 'google' }),
    ).toThrow(/authSubjectId is required/);
    expect(() =>
      buildEmailOtpEcdsaAuthBinding({ authSubjectId: 'google:alice', providerId: '' }),
    ).toThrow(/providerId is required/);
  });

  test('builds ready signer session material with transport auth and inline share', async () => {
    const keyRef = makeKeyRef({
      thresholdEcdsaPublicKeyB64u: VALID_PUBLIC_KEY_B64U,
      backendBinding: {
        relayerKeyId: 'relayer-key',
        clientVerifyingShareB64u: 'client-verifying-share',
        clientAdditiveShare32B64u: 'client-share',
      },
    });
    const publicFacts = await toVerifiedEcdsaPublicFactsFromKeyRef({ keyRef });
    const signerSession = buildReadyEcdsaSignerSession({
      keyRef,
      publicFacts,
      sessionPolicy: buildKnownReadyThresholdEcdsaSessionPolicy({
        remainingUses: 1,
        expiresAtMs: 1_900_000_000_000,
      }),
      thresholdSessionKind: 'jwt',
      thresholdSessionAuthToken: 'threshold-auth-token',
    });

    expect(signerSession.kind).toBe('ready_ecdsa_signer_session');
    expect(signerSession.publicFacts).toBe(publicFacts);
    expect(signerSession.session.policy).toEqual({
      kind: 'known_threshold_ecdsa_session_policy',
      remainingUses: 1,
      expiresAtMs: 1_900_000_000_000,
    });
    expect(signerSession.transport.auth.kind).toBe('jwt_threshold_session_auth');
    expect(signerSession.transport.relayerKeyId).toBe('relayer-key');
    expect(signerSession.clientShare.kind).toBe('inline_client_share');
    if (signerSession.clientShare.kind !== 'inline_client_share') {
      throw new Error('expected inline client share');
    }
    expect(signerSession.clientShare.clientAdditiveShare32B64u).toBe('client-share');
    expect('keyRef' in signerSession).toBe(false);
    expect('thresholdSessionAuthToken' in signerSession).toBe(false);
  });

  test('builds ready signer sessions from validated ready material', async () => {
    const record = makeRecord({
      thresholdEcdsaPublicKeyB64u: VALID_PUBLIC_KEY_B64U,
    });
    const keyRef = makeKeyRef({
      thresholdEcdsaPublicKeyB64u: VALID_PUBLIC_KEY_B64U,
      backendBinding: {
        relayerKeyId: 'relayer-key',
        clientVerifyingShareB64u: 'client-verifying-share',
        clientAdditiveShare32B64u: 'client-share',
      },
    });
    const resolution = resolveReadyEvmFamilyEcdsaMaterial({
      record,
      keyRef,
      rpId: RP_ID,
      expected: {
        walletId: WALLET_ID,
        chainTarget: EVM_TARGET,
        authMethod: 'passkey',
        source: 'login',
        thresholdSessionId: record.thresholdSessionId,
        walletSigningSessionId: record.walletSigningSessionId,
      },
    });
    expect(resolution.kind).toBe('ready');
    if (resolution.kind !== 'ready') {
      throw new Error('expected ready material');
    }
    expect(resolution.material.cachedExportArtifact).toBeNull();
    expect(resolution.material.signingKeyContext).toEqual({
      ecdsaThresholdKeyId: 'ehss-shared-key',
      signingRootId: 'project:dev',
      signingRootVersion: 'default',
      participantIds: [1, 2],
    });

    const signerSession = await toReadyEcdsaSignerSessionFromReadyMaterial({
      material: resolution.material,
    });

    expect(signerSession.session.thresholdSessionId).toBe(record.thresholdSessionId);
    expect(signerSession.session.walletSigningSessionId).toBe(record.walletSigningSessionId);
    expect(signerSession.publicFacts.publicKeyB64u).toBe(VALID_PUBLIC_KEY_B64U);
    expect(signerSession.clientShare.kind).toBe('inline_client_share');
  });

  test('ready-material public facts require paired record and keyRef facts', async () => {
    const record = makeRecord({
      thresholdEcdsaPublicKeyB64u: VALID_PUBLIC_KEY_B64U,
    });
    const keyRef = makeKeyRef({
      thresholdEcdsaPublicKeyB64u: undefined,
      backendBinding: {
        relayerKeyId: 'relayer-key',
        clientVerifyingShareB64u: 'client-verifying-share',
        clientAdditiveShare32B64u: 'client-share',
      },
    });
    const resolution = resolveReadyEvmFamilyEcdsaMaterial({
      record,
      keyRef,
      rpId: RP_ID,
      expected: {
        walletId: WALLET_ID,
        chainTarget: EVM_TARGET,
        authMethod: 'passkey',
        source: 'login',
        thresholdSessionId: record.thresholdSessionId,
        walletSigningSessionId: record.walletSigningSessionId,
      },
    });
    expect(resolution.kind).toBe('ready');
    if (resolution.kind !== 'ready') {
      throw new Error('expected ready material');
    }

    await expect(
      toVerifiedEcdsaPublicFactsFromReadyMaterial({ material: resolution.material }),
    ).rejects.toThrow(/thresholdEcdsaPublicKeyB64u is required/);
    await expect(
      toReadyEcdsaSignerSessionFromReadyMaterial({ material: resolution.material }),
    ).rejects.toThrow(/thresholdEcdsaPublicKeyB64u is required/);
  });

  test('builds Email OTP worker share handles with exact lane identity', async () => {
    const keyRef = makeKeyRef({
      thresholdEcdsaPublicKeyB64u: VALID_PUBLIC_KEY_B64U,
      thresholdSessionKind: 'cookie',
      thresholdSessionAuthToken: undefined,
      backendBinding: {
        relayerKeyId: 'relayer-key',
        clientVerifyingShareB64u: 'client-verifying-share',
        clientAdditiveShareHandle: {
          kind: 'email_otp_worker_session',
          sessionId: 'email-otp-worker-share-1',
        },
      },
    });
    const publicFacts = await toVerifiedEcdsaPublicFactsFromKeyRef({ keyRef });
    const signerSession = buildReadyEcdsaSignerSession({
      keyRef,
      publicFacts,
      sessionPolicy: buildKnownReadyThresholdEcdsaSessionPolicy({
        remainingUses: 1,
        expiresAtMs: 1_900_000_000_000,
      }),
      thresholdSessionKind: 'cookie',
    });

    expect(signerSession.transport.auth.kind).toBe('cookie_threshold_session_auth');
    expect(signerSession.clientShare.kind).toBe('email_otp_worker_share');
    if (signerSession.clientShare.kind !== 'email_otp_worker_share') {
      throw new Error('expected Email OTP worker share');
    }
    expect(signerSession.clientShare.handle.sessionId).toBe('email-otp-worker-share-1');
    expect(signerSession.clientShare.handle.laneIdentity).toEqual({
      kind: 'email_otp_worker_share_lane_identity',
      keyHandle: publicFacts.keyHandle,
      chainTarget: EVM_TARGET,
      walletSigningSessionId: 'wallet-signing-session-1',
      thresholdSessionId: 'threshold-session-1',
    });
  });

  test('rejects incomplete ready signer session material', async () => {
    const keyRef = makeKeyRef({
      thresholdEcdsaPublicKeyB64u: VALID_PUBLIC_KEY_B64U,
      backendBinding: {
        relayerKeyId: 'relayer-key',
        clientVerifyingShareB64u: 'client-verifying-share',
      },
    });
    const publicFacts = await toVerifiedEcdsaPublicFactsFromKeyRef({ keyRef });

    expect(() =>
      buildThresholdEcdsaSessionTransportAuth(
        { thresholdSessionKind: 'jwt' } as unknown as Parameters<
          typeof buildThresholdEcdsaSessionTransportAuth
        >[0],
      ),
    ).toThrow(/thresholdSessionAuthToken is required/);
    expect(() =>
      buildReadyEcdsaSignerSession({
        keyRef,
        publicFacts,
        sessionPolicy: buildKnownReadyThresholdEcdsaSessionPolicy({
          remainingUses: 1,
          expiresAtMs: 1_900_000_000_000,
        }),
        thresholdSessionKind: 'jwt',
        thresholdSessionAuthToken: 'threshold-auth-token',
      }),
    ).toThrow(/clientAdditiveShare32B64u is required/);
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
      rpId: RP_ID,
    });
    const baseFingerprint = deriveEvmFamilyKeyFingerprint(baseKey);
    const variants = [
      buildEvmFamilyEcdsaKeyIdentityFromRecord({
        record: makeRecord(),
        rpId: 'wallet.other.test',
      }),
      buildEvmFamilyEcdsaKeyIdentityFromRecord({
        record: makeRecord({ signingRootId: 'project:other' }),
        rpId: RP_ID,
      }),
      buildEvmFamilyEcdsaKeyIdentityFromRecord({
        record: makeRecord({ signingRootVersion: 'v2' }),
        rpId: RP_ID,
      }),
      buildEvmFamilyEcdsaKeyIdentityFromRecord({
        record: makeRecord({ participantIds: [1, 2, 3] }),
        rpId: RP_ID,
      }),
      buildEvmFamilyEcdsaKeyIdentityFromRecord({
        record: makeRecord({ ecdsaThresholdKeyId: 'ehss-other-key' }),
        rpId: RP_ID,
      }),
      buildEvmFamilyEcdsaKeyIdentityFromRecord({
        record: makeRecord({ ethereumAddress: OTHER_OWNER_ADDRESS }),
        rpId: RP_ID,
      }),
    ];

    for (const variant of variants) {
      expect(deriveEvmFamilyKeyFingerprint(variant)).not.toBe(baseFingerprint);
    }
  });

  test('rejects ready material when record and keyRef owner addresses drift', () => {
    const result = resolveReadyEvmFamilyEcdsaMaterial({
      record: makeRecord(),
      keyRef: makeKeyRef({ ethereumAddress: OTHER_OWNER_ADDRESS }),
      rpId: RP_ID,
      expected: {
        walletId: WALLET_ID,
        chainTarget: EVM_TARGET,
        authMethod: 'passkey',
        source: 'login',
        thresholdSessionId: 'threshold-session-1',
        walletSigningSessionId: 'wallet-signing-session-1',
      },
      nowMs: 1_800_000_000_000,
    });

    if (result.kind !== 'identity_mismatch') {
      throw new Error(`expected identity_mismatch, got ${result.kind}`);
    }
    expect(result.reason.kind).toBe('owner_address_mismatch');
  });

  test('rejects ready material when record and keyRef public keys drift', () => {
    const result = resolveReadyEvmFamilyEcdsaMaterial({
      record: makeRecord({ thresholdEcdsaPublicKeyB64u: VALID_PUBLIC_KEY_B64U }),
      keyRef: makeKeyRef({ thresholdEcdsaPublicKeyB64u: OTHER_VALID_PUBLIC_KEY_B64U }),
      rpId: RP_ID,
      expected: {
        walletId: WALLET_ID,
        chainTarget: EVM_TARGET,
        authMethod: 'passkey',
        source: 'login',
        thresholdSessionId: 'threshold-session-1',
        walletSigningSessionId: 'wallet-signing-session-1',
      },
      nowMs: 1_800_000_000_000,
    });

    if (result.kind !== 'identity_mismatch') {
      throw new Error(`expected identity_mismatch, got ${result.kind}`);
    }
    expect(result.reason.kind).toBe('public_key_mismatch');
  });

  test('rejects ready material when record and keyRef wallet ids drift', () => {
    const otherWallet = toAccountId('mallory.testnet');
    const result = resolveReadyEvmFamilyEcdsaMaterial({
      record: makeRecord(),
      keyRef: makeKeyRef({
        userId: otherWallet,
      }),
      rpId: RP_ID,
      expected: {
        walletId: WALLET_ID,
        chainTarget: EVM_TARGET,
        authMethod: 'passkey',
        source: 'login',
        thresholdSessionId: 'threshold-session-1',
        walletSigningSessionId: 'wallet-signing-session-1',
      },
      nowMs: 1_800_000_000_000,
    });

    if (result.kind !== 'identity_mismatch') {
      throw new Error(`expected identity_mismatch, got ${result.kind}`);
    }
    expect(result.reason.kind).toBe('wallet_mismatch');
  });

  test('rejects ready material when paired material belongs to another wallet', () => {
    const otherWallet = toAccountId('mallory.testnet');
    const result = resolveReadyEvmFamilyEcdsaMaterial({
      record: makeRecord({
        walletId: otherWallet,
      }),
      keyRef: makeKeyRef({
        userId: otherWallet,
      }),
      rpId: RP_ID,
      expected: {
        walletId: WALLET_ID,
        chainTarget: EVM_TARGET,
        authMethod: 'passkey',
        source: 'login',
        thresholdSessionId: 'threshold-session-1',
        walletSigningSessionId: 'wallet-signing-session-1',
      },
      nowMs: 1_800_000_000_000,
    });

    if (result.kind !== 'identity_mismatch') {
      throw new Error(`expected identity_mismatch, got ${result.kind}`);
    }
    expect(result.reason.kind).toBe('wallet_mismatch');
    expect(result.reason.expected).toBe(WALLET_ID);
    expect(result.reason.actual).toBe(otherWallet);
  });

  test('record builder rejects persisted owner address when trusted key-ref owner disagrees', () => {
    expect(() =>
      buildEvmFamilyEcdsaKeyIdentityFromRecord({
        record: makeRecord({ ethereumAddress: OTHER_OWNER_ADDRESS }),
        rpId: RP_ID,
        trustedOwnerAddress: OWNER_ADDRESS,
      }),
    ).toThrow(/persisted owner address mismatches trusted EVM-family key material/);
  });

  test('key-ref builder rejects owner address when trusted key material disagrees', () => {
    expect(() =>
      buildEvmFamilyEcdsaKeyIdentityFromKeyRef({
        keyRef: makeKeyRef({ ethereumAddress: OTHER_OWNER_ADDRESS }),
        rpId: RP_ID,
        trustedOwnerAddress: OWNER_ADDRESS,
      }),
    ).toThrow(/key ref owner address mismatches trusted EVM-family key material/);
  });

  test('returns stale before ready material can reach signing', () => {
    const result = resolveReadyEvmFamilyEcdsaMaterial({
      record: makeRecord({ remainingUses: 0 }),
      keyRef: makeKeyRef(),
      rpId: RP_ID,
      expected: {
        walletId: WALLET_ID,
        chainTarget: EVM_TARGET,
        authMethod: 'passkey',
        source: 'login',
        thresholdSessionId: 'threshold-session-1',
        walletSigningSessionId: 'wallet-signing-session-1',
      },
      nowMs: 1_800_000_000_000,
    });

    if (result.kind !== 'stale') {
      throw new Error(`expected stale, got ${result.kind}`);
    }
    expect(result.reason.reason).toBe('exhausted');
  });

  test('resolves ready material only for the exact concrete session lane', () => {
    const result = resolveReadyEvmFamilyEcdsaMaterial({
      record: makeRecord(),
      keyRef: makeKeyRef(),
      rpId: RP_ID,
      expected: {
        walletId: WALLET_ID,
        chainTarget: EVM_TARGET,
        authMethod: 'passkey',
        source: 'login',
        thresholdSessionId: 'threshold-session-1',
        walletSigningSessionId: 'wallet-signing-session-1',
      },
      nowMs: 1_800_000_000_000,
    });

    if (result.kind !== 'ready') {
      throw new Error(`expected ready, got ${result.kind}`);
    }
    expect(result.material.key.thresholdOwnerAddress).toBe(OWNER_ADDRESS);
    expect(result.material.lane.thresholdSessionId).toBe('threshold-session-1');
    expect(result.material.lane.chainTarget).toEqual(EVM_TARGET);
  });

  test('normalizes persisted ECDSA reads into shared key identity plus concrete lane', () => {
    const readModel = thresholdEcdsaSessionRecordReadModel(
      makeRecord({
        participantIds: [2, 1],
        ethereumAddress: '0xAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',
      }),
    );

    expect(readModel.key.rpId).toBe(RP_ID);
    expect(readModel.key.keyScope).toBe('evm-family');
    expect(readModel.key.participantIds.map(Number)).toEqual([1, 2]);
    expect(readModel.key.thresholdOwnerAddress).toBe('0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa');
    expect(readModel.lane.key).toBe(readModel.key);
    expect(readModel.lane.chainTarget).toEqual(EVM_TARGET);
    expect(readModel.lane.thresholdSessionId).toBe('threshold-session-1');
    expect(readModel.lane.walletSigningSessionId).toBe('wallet-signing-session-1');
  });

  test('runtime ECDSA lane listing returns the canonical record read model', () => {
    const deps: ThresholdEcdsaSessionStoreDeps = {
      recordsByLane: new Map(),
      now: () => 1_800_000_000_000,
    };
    upsertStoredThresholdEcdsaSessionRecord(
      deps,
      makeRecord({
        participantIds: [2, 1],
        ethereumAddress: '0xBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB',
      }),
    );

    const [lane] = listThresholdEcdsaRuntimeLanesForWallet(deps, WALLET_ID);

    expect(lane).toBeDefined();
    expect(lane?.key.thresholdOwnerAddress).toBe('0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb');
    expect(lane?.key.participantIds.map(Number)).toEqual([1, 2]);
    expect(lane?.lane.key).toBe(lane?.key);
    expect(lane?.lane.thresholdSessionId).toBe('threshold-session-1');
    expect(lane?.key.rpId).toBe(RP_ID);
  });

  test('runtime ECDSA lane listing backfills canonical verified public facts on legacy persisted records', () => {
    clearAllThresholdEcdsaSessionRecords({ recordsByLane: new Map() });
    const deps: ThresholdEcdsaSessionStoreDeps = {
      recordsByLane: new Map(),
      now: () => 1_800_000_000_000,
    };
    const legacyRecord = makeRecord();
    const laneKey = deriveThresholdEcdsaRuntimeLaneKey(legacyRecord);
    const legacyWithoutFacts = { ...legacyRecord } as Record<string, unknown>;
    delete legacyWithoutFacts.verifiedPublicFacts;
    deps.recordsByLane.set(laneKey, legacyWithoutFacts as ThresholdEcdsaSessionRecord);

    const [lane] = listThresholdEcdsaRuntimeLanesForWallet(deps, WALLET_ID);
    const stored = deps.recordsByLane.get(laneKey);

    expect(lane).toBeDefined();
    expect(stored?.verifiedPublicFacts?.keyHandle).toBe(legacyRecord.keyHandle);
  });

  test('runtime ECDSA lane listing prunes non-rehydratable legacy persisted records', () => {
    clearAllThresholdEcdsaSessionRecords({ recordsByLane: new Map() });
    const deps: ThresholdEcdsaSessionStoreDeps = {
      recordsByLane: new Map(),
      now: () => 1_800_000_000_000,
    };
    const legacyRecord = makeRecord();
    const laneKey = deriveThresholdEcdsaRuntimeLaneKey(legacyRecord);
    const nonRehydratable = { ...legacyRecord } as Record<string, unknown>;
    delete nonRehydratable.verifiedPublicFacts;
    delete nonRehydratable.thresholdEcdsaPublicKeyB64u;
    deps.recordsByLane.set(laneKey, nonRehydratable as ThresholdEcdsaSessionRecord);

    const lanes = listThresholdEcdsaRuntimeLanesForWallet(deps, WALLET_ID);

    expect(lanes).toHaveLength(0);
    expect(deps.recordsByLane.has(laneKey)).toBe(false);
  });

  test('clears only the targeted runtime session lane for a threshold session id + chain target', () => {
    clearAllThresholdEcdsaSessionRecords({ recordsByLane: new Map() });
    const deps: ThresholdEcdsaSessionStoreDeps = {
      recordsByLane: new Map(),
      now: () => 1_800_000_000_000,
    };
    upsertStoredThresholdEcdsaSessionRecord(
      deps,
      makeRecord({
        chainTarget: EVM_TARGET,
        thresholdSessionId: 'threshold-session-clear-target',
        walletSigningSessionId: 'wallet-session-clear-target-evm',
      }),
    );
    upsertStoredThresholdEcdsaSessionRecord(
      deps,
      makeRecord({
        chainTarget: TEMPO_TARGET,
        thresholdSessionId: 'threshold-session-clear-target',
        walletSigningSessionId: 'wallet-session-clear-target-tempo',
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
    clearAllThresholdEcdsaSessionRecords({ recordsByLane: new Map() });
    const deps: ThresholdEcdsaSessionStoreDeps = {
      recordsByLane: new Map(),
      now: () => 1_800_000_000_000,
    };
    const sharedKeyHandle = toEvmFamilyEcdsaKeyHandle('key-handle-clear-shared');
    const emailOtpAuthContext = {
      policy: 'session',
      retention: 'session',
      reason: 'login',
      authMethod: 'email_otp',
    } as const;
    upsertStoredThresholdEcdsaSessionRecord(
      deps,
      makeRecord({
        keyHandle: sharedKeyHandle,
        thresholdSessionId: 'threshold-session-clear-shared-a',
        walletSigningSessionId: 'wallet-session-clear-shared-a',
        source: 'email_otp',
        emailOtpAuthContext,
      }),
    );
    upsertStoredThresholdEcdsaSessionRecord(
      deps,
      makeRecord({
        keyHandle: sharedKeyHandle,
        chainTarget: TEMPO_TARGET,
        thresholdSessionId: 'threshold-session-clear-shared-b',
        walletSigningSessionId: 'wallet-session-clear-shared-b',
        source: 'email_otp',
        emailOtpAuthContext,
      }),
    );
    upsertStoredThresholdEcdsaSessionRecord(
      deps,
      makeRecord({
        keyHandle: toEvmFamilyEcdsaKeyHandle('key-handle-clear-other'),
        thresholdSessionId: 'threshold-session-clear-other',
        walletSigningSessionId: 'wallet-session-clear-other',
        source: 'email_otp',
        emailOtpAuthContext,
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
    const deps: ThresholdEcdsaSessionStoreDeps = {
      recordsByLane: new Map(),
      now: () => 1_800_000_000_000,
    };
    const rawRecord = { ...makeRecord() } as Record<string, unknown>;
    delete rawRecord.verifiedPublicFacts;
    delete rawRecord.thresholdEcdsaPublicKeyB64u;

    expect(() => upsertStoredThresholdEcdsaSessionRecord(deps, rawRecord)).toThrow(
      /missing verifiedPublicFacts/,
    );
  });

  test('normalizes persisted ECDSA records without storing subjectId', () => {
    const deps: ThresholdEcdsaSessionStoreDeps = {
      recordsByLane: new Map(),
      now: () => 1_800_000_000_000,
    };
    const rawRecord = { ...makeRecord() } as Record<string, unknown>;
    delete rawRecord.subjectId;

    const stored = upsertStoredThresholdEcdsaSessionRecord(deps, rawRecord);

    expect('subjectId' in stored).toBe(false);
  });

  test('rejects persisted ECDSA records with subjectId that mismatches walletId', () => {
    const deps: ThresholdEcdsaSessionStoreDeps = {
      recordsByLane: new Map(),
      now: () => 1_800_000_000_000,
    };
    const rawRecord = {
      ...makeRecord(),
      subjectId: toWalletSubjectId('bob.testnet'),
    } as Record<string, unknown>;

    expect(() => upsertStoredThresholdEcdsaSessionRecord(deps, rawRecord)).toThrow(
      /subjectId mismatch/,
    );
  });

  test('client store allows one shared key identity across EVM-family concrete lanes', () => {
    const deps: ThresholdEcdsaSessionStoreDeps = {
      recordsByLane: new Map(),
      now: () => 1_800_000_000_000,
    };
    upsertStoredThresholdEcdsaSessionRecord(
      deps,
      makeRecord({
        signingRootId: 'project:client-shared-key',
        chainTarget: EVM_TARGET,
        thresholdSessionId: 'threshold-session-evm-shared',
        walletSigningSessionId: 'wallet-session-evm-shared',
      }),
    );

    expect(() =>
      upsertStoredThresholdEcdsaSessionRecord(
        deps,
        makeRecord({
          signingRootId: 'project:client-shared-key',
          chainTarget: TEMPO_TARGET,
          thresholdSessionId: 'threshold-session-tempo-shared',
          walletSigningSessionId: 'wallet-session-tempo-shared',
        }),
      ),
    ).not.toThrow();
  });

  test('client store rejects a second key identity for the same EVM-family signing root', () => {
    const deps: ThresholdEcdsaSessionStoreDeps = {
      recordsByLane: new Map(),
      now: () => 1_800_000_000_000,
    };
    const runtimePolicyScope = {
      orgId: 'org-test',
      projectId: 'project-client-conflict',
      envId: 'dev',
      signingRootVersion: 'default',
    } as const;
    upsertStoredThresholdEcdsaSessionRecord(
      deps,
      makeRecord({
        runtimePolicyScope,
        signingRootId: undefined,
        thresholdSessionId: 'threshold-session-first-key',
        walletSigningSessionId: 'wallet-session-first-key',
      }),
    );

    expect(() =>
      upsertStoredThresholdEcdsaSessionRecord(
        deps,
        makeRecord({
          runtimePolicyScope,
          signingRootId: undefined,
          chainTarget: TEMPO_TARGET,
          keyHandle: toEvmFamilyEcdsaKeyHandle('key-handle-conflicting'),
          thresholdSessionId: 'threshold-session-second-key',
          walletSigningSessionId: 'wallet-session-second-key',
        }),
      ),
    ).toThrow(/EVM-family ECDSA key identity/);
  });

  test('exact ECDSA lookup rejects a selected lane with the wrong wallet identity', () => {
    const deps: ThresholdEcdsaSessionStoreDeps = {
      recordsByLane: new Map(),
      now: () => 1_800_000_000_000,
    };
    const record = makeRecord();
    const key = buildEvmFamilyEcdsaKeyIdentityFromRecord({ record, rpId: RP_ID });
    const otherWallet = toAccountId('mallory.testnet');
    const otherWalletRecord = {
      walletId: otherWallet,
    } satisfies Partial<ThresholdEcdsaSessionRecord>;
    const otherWalletKey = buildEvmFamilyEcdsaKeyIdentityFromRecord({
      record: makeRecord(otherWalletRecord),
      rpId: RP_ID,
    });
    upsertStoredThresholdEcdsaSessionRecord(deps, record);
    const matchingLane = selectedEcdsaLane({
      key,
      keyHandle: record.keyHandle,
      walletId: WALLET_ID,
      authMethod: 'passkey',
      walletSigningSessionId: 'wallet-signing-session-1',
      thresholdSessionId: 'threshold-session-1',
      chainTarget: EVM_TARGET,
    });
    const wrongWalletLane = selectedEcdsaLane({
      ...matchingLane,
      key: otherWalletKey,
      walletId: otherWallet,
    });

    expect(getThresholdEcdsaSessionRecordByKey(deps, matchingLane)?.walletId).toBe(WALLET_ID);
    expect(getThresholdEcdsaKeyRefByKey(deps, matchingLane)?.keyRef.userId).toBe(WALLET_ID);
    expect(getThresholdEcdsaSessionRecordByKey(deps, wrongWalletLane)).toBeNull();
    expect(getThresholdEcdsaKeyRefByKey(deps, wrongWalletLane)).toBeNull();
  });
});
