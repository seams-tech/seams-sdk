import { expect, test } from '@playwright/test';
import { base64UrlEncode } from '@shared/utils/base64';
import { deriveEvmFamilySigningKeySlotId } from '@shared/signing-lanes';
import { deriveSigningRootId } from '@shared/threshold/signingRootScope';
import { claimPasskeyEcdsaPrfFirst } from '../../packages/sdk-web/src/core/signingEngine/session/passkey/ecdsaRecovery';
import { restoreEmailOtpEcdsaSigningSessionMaterialFromSealedRecord } from '../../packages/sdk-web/src/core/signingEngine/session/emailOtp/ecdsaRecovery';
import type { SigningSessionSealedStoreRecord } from '../../packages/sdk-web/src/core/signingEngine/session/persistence/sealedSessionStore';
import {
  buildEcdsaRoleLocalPasskeyAuthMethod,
  buildEcdsaRoleLocalPublicFacts,
  buildEcdsaRoleLocalReadyRecord,
} from '../../packages/sdk-web/src/core/signingEngine/session/persistence/ecdsaRoleLocalRecords';
import {
  normalizeSealedRecoveryRecord,
  type EmailOtpEcdsaSealedRecoveryRecord,
} from '../../packages/sdk-web/src/core/signingEngine/session/sealedRecovery/recoveryRecord';
import { buildEmailOtpAuthContextForWalletAuthMethod } from '../../packages/sdk-web/src/core/signingEngine/session/identity/laneIdentity';
import {
  clearAllThresholdEcdsaSessionRecords,
  upsertRestoredThresholdEcdsaSessionRecord,
  type ThresholdEcdsaSessionRecord,
} from '../../packages/sdk-web/src/core/signingEngine/session/persistence/records';

const TEMPO_CHAIN_TARGET = {
  kind: 'tempo' as const,
  chainId: 42431,
  networkSlug: 'tempo-testnet',
};
const EMAIL_OTP_RUNTIME_POLICY_SCOPE = {
  orgId: 'org-test',
  projectId: 'root',
  envId: 'email-otp',
  signingRootVersion: 'v1',
} as const;
const PASSKEY_RUNTIME_POLICY_SCOPE = {
  orgId: 'org-test',
  projectId: 'root',
  envId: 'passkey',
  signingRootVersion: 'v1',
} as const;
const EMAIL_OTP_SIGNING_ROOT_ID = deriveSigningRootId(EMAIL_OTP_RUNTIME_POLICY_SCOPE);
const PASSKEY_SIGNING_ROOT_ID = deriveSigningRootId(PASSKEY_RUNTIME_POLICY_SCOPE);
const EMAIL_OTP_WALLET_KEY_ID = deriveEvmFamilySigningKeySlotId({
  walletId: 'alice.testnet',
  signingRootId: EMAIL_OTP_SIGNING_ROOT_ID,
  signingRootVersion: 'v1',
});
const PASSKEY_WALLET_KEY_ID = deriveEvmFamilySigningKeySlotId({
  walletId: 'alice.testnet',
  signingRootId: PASSKEY_SIGNING_ROOT_ID,
  signingRootVersion: 'v1',
});
const EMAIL_OTP_PROVIDER_SUBJECT_ID = 'google:alice';
const EMAIL_OTP_EMAIL_HASH_HEX = 'email-hash-alice';

function bytesB64u(length: number, fill: number): string {
  return base64UrlEncode(new Uint8Array(length).fill(fill));
}

function compressedPublicKeyB64u(prefix: 2 | 3, fill: number): string {
  const bytes = new Uint8Array(33).fill(fill);
  bytes[0] = prefix;
  return base64UrlEncode(bytes);
}

function makeEmailOtpEcdsaSealedRecord(
  overrides?: Partial<SigningSessionSealedStoreRecord>,
): EmailOtpEcdsaSealedRecoveryRecord {
  const now = Date.now();
  const normalized = normalizeSealedRecoveryRecord({
    v: 1,
    alg: 'shamir3pass-v1',
    storageScope: 'iframe_origin_indexeddb',
    authMethod: 'email_otp',
    secretKind: 'signing_session_secret32',
    storeKey: 'email_otp:ecdsa:tempo:tsess-ecdsa',
    signingGrantId: 'wsess-ecdsa',
    thresholdSessionIds: {
      ecdsa: 'tsess-ecdsa',
      ed25519: 'tsess-ed25519',
    },
    sealedSecretB64u: 'sealed-secret',
    curve: 'ecdsa',
    walletId: 'alice.testnet',
    relayerUrl: 'https://relay.example',
    shamirPrimeB64u: 'prime-b64u',
    keyVersion: 'signing-session-seal-kek-test-r1',
    ecdsaRestore: {
      chainTarget: TEMPO_CHAIN_TARGET,
      evmFamilySigningKeySlotId: EMAIL_OTP_WALLET_KEY_ID,
      runtimePolicyScope: EMAIL_OTP_RUNTIME_POLICY_SCOPE,
      providerSubjectId: EMAIL_OTP_PROVIDER_SUBJECT_ID,
      emailHashHex: EMAIL_OTP_EMAIL_HASH_HEX,
      sessionKind: 'jwt',
      walletSessionJwt: 'jwt-ecdsa',
      keyHandle: 'key-handle-ecdsa',
      ecdsaThresholdKeyId: 'ecdsa-key',
      ethereumAddress: `0x${'33'.repeat(20)}`,
      relayerKeyId: 'relayer-key',
      clientVerifyingShareB64u: 'client-verifying-share',
      thresholdEcdsaPublicKeyB64u: 'threshold-public-key',
      participantIds: [1, 2],
    },
	    ed25519Restore: {
	      nearAccountId: 'alice.testnet',
      nearEd25519SigningKeyId: 'alice.testnet',
      rpId: 'example.com',
      providerSubjectId: EMAIL_OTP_PROVIDER_SUBJECT_ID,
      emailHashHex: EMAIL_OTP_EMAIL_HASH_HEX,
      relayerKeyId: 'relayer-key-ed25519',
      participantIds: [1, 2],
      sessionKind: 'jwt',
      walletSessionJwt: 'jwt-ed25519',
      xClientBaseB64u: 'x-client-base',
      clientVerifyingShareB64u: 'client-verifying-share-ed25519',
    },
    issuedAtMs: now - 1_000,
    expiresAtMs: now + 60_000,
    remainingUses: 3,
    updatedAtMs: now,
    ...overrides,
  });
  if (
    normalized.kind !== 'accepted' ||
    normalized.record.authMethod !== 'email_otp' ||
    normalized.record.curve !== 'ecdsa'
  ) {
    throw new Error('Expected accepted Email OTP ECDSA recovery record fixture');
  }
  return normalized.record;
}

function makeEmailOtpEcdsaCurrentRecord(
  overrides?: Partial<ThresholdEcdsaSessionRecord>,
): ThresholdEcdsaSessionRecord {
  const now = Date.now();
  return {
    source: 'email_otp',
    walletId: 'alice.testnet',
    evmFamilySigningKeySlotId: EMAIL_OTP_WALLET_KEY_ID,
    chainTarget: TEMPO_CHAIN_TARGET,
    relayerUrl: 'https://relay.example',
    keyHandle: 'key-handle-ecdsa',
    ecdsaThresholdKeyId: 'ecdsa-key',
    signingRootId: EMAIL_OTP_SIGNING_ROOT_ID,
    signingRootVersion: 'v1',
    runtimePolicyScope: EMAIL_OTP_RUNTIME_POLICY_SCOPE,
    relayerKeyId: 'relayer-key',
    clientVerifyingShareB64u: 'client-verifying-share',
    ecdsaRoleLocalReadyRecord: {} as never,
    participantIds: [1, 2],
    thresholdSessionKind: 'jwt',
    walletSessionJwt: 'jwt-current-ecdsa',
    signingSessionSealShamirPrimeB64u: 'prime-b64u',
    signingSessionSealKeyVersion: 'signing-session-seal-kek-test-r1',
    thresholdSessionId: 'tsess-ecdsa',
    signingGrantId: 'wsess-ecdsa',
    expiresAtMs: now + 60_000,
    remainingUses: 3,
    ethereumAddress: `0x${'33'.repeat(20)}`,
    updatedAtMs: now,
    emailOtpAuthContext: buildEmailOtpAuthContextForWalletAuthMethod({
      policy: 'session',
      walletId: 'alice.testnet',
      emailHashHex: EMAIL_OTP_EMAIL_HASH_HEX,
      retention: 'session',
      reason: 'login',
      provider: 'google',
      providerUserId: EMAIL_OTP_PROVIDER_SUBJECT_ID,
    }),
    ...overrides,
  } as never;
}

function makePasskeyEcdsaCurrentRecord(
  overrides?: Partial<ThresholdEcdsaSessionRecord>,
): ThresholdEcdsaSessionRecord {
  const now = Date.now();
  const hssClientSharePublicKey33B64u = compressedPublicKeyB64u(2, 11);
  const relayerPublicKey33B64u = compressedPublicKeyB64u(3, 12);
  const groupPublicKey33B64u = compressedPublicKeyB64u(2, 13);
  const ecdsaRoleLocalReadyRecord = buildEcdsaRoleLocalReadyRecord({
    stateBlob: {
      kind: 'ecdsa_role_local_state_blob_v1',
      curve: 'secp256k1',
      encoding: 'base64url',
      producer: 'signer_core',
      stateBlobB64u: bytesB64u(48, 9),
    },
    publicFacts: buildEcdsaRoleLocalPublicFacts({
      walletId: 'alice.testnet',
      evmFamilySigningKeySlotId: PASSKEY_WALLET_KEY_ID,
      chainTarget: TEMPO_CHAIN_TARGET,
      keyHandle: 'key-handle-passkey-ecdsa',
      ecdsaThresholdKeyId: 'ecdsa-passkey-key',
      signingRootId: PASSKEY_SIGNING_ROOT_ID,
      signingRootVersion: 'v1',
      clientParticipantId: 1,
      relayerParticipantId: 2,
      participantIds: [1, 2],
      applicationBindingDigestB64u: bytesB64u(32, 8),
      contextBinding32B64u: bytesB64u(32, 6),
      hssClientSharePublicKey33B64u,
      relayerPublicKey33B64u,
      groupPublicKey33B64u,
      ethereumAddress: `0x${'44'.repeat(20)}`,
    }),
    authMethod: buildEcdsaRoleLocalPasskeyAuthMethod({
      credentialIdB64u: 'passkey-credential-id',
      rpId: 'example.com',
    }),
  });
  return {
    source: 'login',
    walletId: 'alice.testnet',
    evmFamilySigningKeySlotId: PASSKEY_WALLET_KEY_ID,
    chainTarget: TEMPO_CHAIN_TARGET,
    relayerUrl: 'https://relay.example',
    keyHandle: 'key-handle-passkey-ecdsa',
    ecdsaThresholdKeyId: 'ecdsa-passkey-key',
    signingRootId: PASSKEY_SIGNING_ROOT_ID,
    signingRootVersion: 'v1',
    relayerKeyId: 'relayer-key-passkey',
    clientVerifyingShareB64u: hssClientSharePublicKey33B64u,
    ecdsaRoleLocalReadyRecord,
    participantIds: [1, 2],
    thresholdSessionKind: 'jwt',
    walletSessionJwt: 'jwt-current-passkey-ecdsa',
    signingSessionSealShamirPrimeB64u: 'prime-b64u',
    signingSessionSealKeyVersion: 'signing-session-seal-kek-test-r1',
    thresholdSessionId: 'tsess-passkey-ecdsa',
    signingGrantId: 'wsess-passkey-ecdsa',
    expiresAtMs: now + 60_000,
    remainingUses: 3,
    thresholdEcdsaPublicKeyB64u: groupPublicKey33B64u,
    verifiedPublicFacts: {
      kind: 'verified_ecdsa_public_facts',
      keyHandle: 'key-handle-passkey-ecdsa',
      publicKeyB64u: groupPublicKey33B64u,
      participantIds: [1, 2],
      thresholdOwnerAddress: `0x${'44'.repeat(20)}`,
    },
    ethereumAddress: `0x${'44'.repeat(20)}`,
    relayerVerifyingShareB64u: relayerPublicKey33B64u,
    updatedAtMs: now,
    ...overrides,
  } as never;
}

test.describe('sealed recovery method adapters', () => {
  test.beforeEach(() => {
    clearAllThresholdEcdsaSessionRecords({ recordsByLane: new Map() });
  });

  test.afterEach(() => {
    clearAllThresholdEcdsaSessionRecords({ recordsByLane: new Map() });
  });

  test('rejects sealed recovery records without canonical session ids', () => {
    const now = Date.now();
    const normalized = normalizeSealedRecoveryRecord({
      v: 1,
      alg: 'shamir3pass-v1',
      storageScope: 'iframe_origin_indexeddb',
      authMethod: 'email_otp',
      secretKind: 'signing_session_secret32',
      storeKey: 'email_otp:ecdsa:tempo:legacy-threshold-session',
      signingGrantId: 'signing-grant',
      sealedSecretB64u: 'sealed-secret',
      curve: 'ecdsa',
      walletId: 'alice.testnet',
      relayerUrl: 'https://relay.example',
      ecdsaRestore: {
        chainTarget: TEMPO_CHAIN_TARGET,
        evmFamilySigningKeySlotId: EMAIL_OTP_WALLET_KEY_ID,
        runtimePolicyScope: EMAIL_OTP_RUNTIME_POLICY_SCOPE,
        providerSubjectId: EMAIL_OTP_PROVIDER_SUBJECT_ID,
        emailHashHex: EMAIL_OTP_EMAIL_HASH_HEX,
        sessionKind: 'jwt',
        walletSessionJwt: 'jwt-ecdsa',
        keyHandle: 'key-handle-ecdsa',
        ecdsaThresholdKeyId: 'ecdsa-key',
        ethereumAddress: `0x${'33'.repeat(20)}`,
        relayerKeyId: 'relayer-key',
        clientVerifyingShareB64u: 'client-verifying-share',
        thresholdEcdsaPublicKeyB64u: 'threshold-public-key',
        participantIds: [1, 2],
      },
      issuedAtMs: now - 1_000,
      expiresAtMs: now + 60_000,
      remainingUses: 3,
      updatedAtMs: now,
    });

    expect(normalized).toMatchObject({
      kind: 'rejected',
      rejection: {
        kind: 'rejected_sealed_recovery_record',
        reason: 'missing_identity',
      },
    });
  });

  test('rejects ECDSA sealed recovery records with subjectId', () => {
    const now = Date.now();
    const normalized = normalizeSealedRecoveryRecord({
      v: 1,
      alg: 'shamir3pass-v1',
      storageScope: 'iframe_origin_indexeddb',
      authMethod: 'email_otp',
      secretKind: 'signing_session_secret32',
      storeKey: 'email_otp:ecdsa:tempo:tsess-ecdsa',
      signingGrantId: 'wsess-ecdsa',
      thresholdSessionIds: {
        ecdsa: 'tsess-ecdsa',
      },
      sealedSecretB64u: 'sealed-secret',
      curve: 'ecdsa',
      walletId: 'alice.testnet',
      subjectId: 'alice.testnet',
      relayerUrl: 'https://relay.example',
      ecdsaRestore: {
        chainTarget: TEMPO_CHAIN_TARGET,
        evmFamilySigningKeySlotId: EMAIL_OTP_WALLET_KEY_ID,
        runtimePolicyScope: EMAIL_OTP_RUNTIME_POLICY_SCOPE,
        providerSubjectId: EMAIL_OTP_PROVIDER_SUBJECT_ID,
        emailHashHex: EMAIL_OTP_EMAIL_HASH_HEX,
        sessionKind: 'jwt',
        walletSessionJwt: 'jwt-ecdsa',
        keyHandle: 'key-handle-ecdsa',
        ecdsaThresholdKeyId: 'ecdsa-key',
        ethereumAddress: `0x${'33'.repeat(20)}`,
        relayerKeyId: 'relayer-key',
        clientVerifyingShareB64u: 'client-verifying-share',
        thresholdEcdsaPublicKeyB64u: 'threshold-public-key',
        participantIds: [1, 2],
      },
      issuedAtMs: now - 1_000,
      expiresAtMs: now + 60_000,
      remainingUses: 3,
      updatedAtMs: now,
    });

    expect(normalized).toMatchObject({
      kind: 'rejected',
      rejection: {
        kind: 'rejected_sealed_recovery_record',
        reason: 'invalid_identity',
      },
    });
  });

  test('rejects ECDSA sealed recovery records with raw signing-root binding', () => {
    const now = Date.now();
    const normalized = normalizeSealedRecoveryRecord({
      v: 1,
      alg: 'shamir3pass-v1',
      storageScope: 'iframe_origin_indexeddb',
      authMethod: 'email_otp',
      secretKind: 'signing_session_secret32',
      storeKey: 'email_otp:ecdsa:tempo:tsess-ecdsa',
      signingGrantId: 'wsess-ecdsa',
      thresholdSessionIds: {
        ecdsa: 'tsess-ecdsa',
      },
      sealedSecretB64u: 'sealed-secret',
      curve: 'ecdsa',
      walletId: 'alice.testnet',
      signingRootId: EMAIL_OTP_SIGNING_ROOT_ID,
      signingRootVersion: 'v1',
      relayerUrl: 'https://relay.example',
      ecdsaRestore: {
        chainTarget: TEMPO_CHAIN_TARGET,
        evmFamilySigningKeySlotId: EMAIL_OTP_WALLET_KEY_ID,
        runtimePolicyScope: EMAIL_OTP_RUNTIME_POLICY_SCOPE,
        providerSubjectId: EMAIL_OTP_PROVIDER_SUBJECT_ID,
        emailHashHex: EMAIL_OTP_EMAIL_HASH_HEX,
        sessionKind: 'jwt',
        walletSessionJwt: 'jwt-ecdsa',
        keyHandle: 'key-handle-ecdsa',
        ecdsaThresholdKeyId: 'ecdsa-key',
        ethereumAddress: `0x${'33'.repeat(20)}`,
        relayerKeyId: 'relayer-key',
        clientVerifyingShareB64u: 'client-verifying-share',
        thresholdEcdsaPublicKeyB64u: 'threshold-public-key',
        participantIds: [1, 2],
      },
      issuedAtMs: now - 1_000,
      expiresAtMs: now + 60_000,
      remainingUses: 3,
      updatedAtMs: now,
    });

    expect(normalized).toMatchObject({
      kind: 'rejected',
      rejection: {
        kind: 'rejected_sealed_recovery_record',
        reason: 'invalid_identity',
      },
    });
  });

  test('rejects Email OTP sealed recovery records without providerSubjectId', () => {
    const now = Date.now();
    const normalized = normalizeSealedRecoveryRecord({
      v: 1,
      alg: 'shamir3pass-v1',
      storageScope: 'iframe_origin_indexeddb',
      authMethod: 'email_otp',
      secretKind: 'signing_session_secret32',
      storeKey: 'email_otp:ecdsa:tempo:tsess-ecdsa',
      signingGrantId: 'wsess-ecdsa',
      thresholdSessionIds: {
        ecdsa: 'tsess-ecdsa',
      },
      sealedSecretB64u: 'sealed-secret',
      curve: 'ecdsa',
      walletId: 'alice.testnet',
      relayerUrl: 'https://relay.example',
      ecdsaRestore: {
        chainTarget: TEMPO_CHAIN_TARGET,
        evmFamilySigningKeySlotId: EMAIL_OTP_WALLET_KEY_ID,
        runtimePolicyScope: EMAIL_OTP_RUNTIME_POLICY_SCOPE,
        authSubjectId: EMAIL_OTP_PROVIDER_SUBJECT_ID,
        emailHashHex: EMAIL_OTP_EMAIL_HASH_HEX,
        sessionKind: 'jwt',
        walletSessionJwt: 'jwt-ecdsa',
        keyHandle: 'key-handle-ecdsa',
        ecdsaThresholdKeyId: 'ecdsa-key',
        ethereumAddress: `0x${'33'.repeat(20)}`,
        relayerKeyId: 'relayer-key',
        clientVerifyingShareB64u: 'client-verifying-share',
        thresholdEcdsaPublicKeyB64u: 'threshold-public-key',
        participantIds: [1, 2],
      },
      issuedAtMs: now - 1_000,
      expiresAtMs: now + 60_000,
      remainingUses: 3,
      updatedAtMs: now,
    });

    expect(normalized).toMatchObject({
      kind: 'rejected',
      rejection: {
        kind: 'rejected_sealed_recovery_record',
        reason: 'missing_restore_metadata',
      },
    });
  });

  test('rejects passkey Ed25519 sealed recovery records with raw client-base metadata', () => {
    const now = Date.now();
    const normalized = normalizeSealedRecoveryRecord({
      v: 1,
      alg: 'shamir3pass-v1',
      storageScope: 'iframe_origin_indexeddb',
      authMethod: 'passkey',
      secretKind: 'signing_session_secret32',
      storeKey: 'passkey:ed25519:near:tsess-ed25519',
      signingGrantId: 'wsess-passkey-ed25519',
      thresholdSessionIds: {
        ed25519: 'tsess-passkey-ed25519',
      },
      sealedSecretB64u: 'sealed-secret',
      curve: 'ed25519',
      walletId: 'alice.testnet',
      userId: 'alice.testnet',
      relayerUrl: 'https://relay.example',
      shamirPrimeB64u: 'prime-b64u',
      keyVersion: 'signing-session-seal-kek-test-r1',
	      ed25519Restore: {
	        nearAccountId: 'alice.testnet',
	        nearEd25519SigningKeyId: 'alice.testnet',
	        rpId: 'example.com',
        credentialIdB64u: 'passkey-credential-ed25519',
        relayerKeyId: 'relayer-key-ed25519',
        participantIds: [1, 2],
        sessionKind: 'jwt',
        walletSessionJwt: 'jwt-ed25519',
        xClientBaseB64u: 'stale-x-client-base',
        clientVerifyingShareB64u: 'stale-client-verifying-share',
      },
      issuedAtMs: now - 1_000,
      expiresAtMs: now + 60_000,
      remainingUses: 3,
      updatedAtMs: now,
    });

    expect(normalized).toMatchObject({
      kind: 'rejected',
      rejection: {
        kind: 'rejected_sealed_recovery_record',
        reason: 'missing_restore_metadata',
      },
    });
  });

  test('restores before claiming passkey ECDSA PRF material', async () => {
    upsertRestoredThresholdEcdsaSessionRecord(makePasskeyEcdsaCurrentRecord());

    const calls: Array<{ kind: 'restore' | 'claim'; args: Record<string, unknown> }> = [];
    const prfFirstB64u = await claimPasskeyEcdsaPrfFirst({
      touchConfirm: {
        restorePersistedSessionForSigning: async (args) => {
          calls.push({ kind: 'restore', args: args as Record<string, unknown> });
          return { kind: 'completed', attempted: 0, restored: 0, deferred: 0 };
        },
        claimWarmSessionMaterial: async (args) => {
          calls.push({ kind: 'claim', args: args as Record<string, unknown> });
          return {
            ok: true as const,
            prfFirstB64u: 'prf-first-passkey-ecdsa',
            remainingUses: 2,
            expiresAtMs: Date.now() + 60_000,
          };
        },
      },
      walletId: 'alice.testnet',
      signingGrantId: 'wsess-passkey-ecdsa',
      thresholdSessionId: 'tsess-passkey-ecdsa',
      chainTarget: TEMPO_CHAIN_TARGET,
      errorContext: 'passkey ECDSA test',
    });

    expect(prfFirstB64u).toBe('prf-first-passkey-ecdsa');
    expect(calls).toHaveLength(2);
    expect(calls[0]).toMatchObject({
      kind: 'restore',
      args: {
        walletId: 'alice.testnet',
        authMethod: 'passkey',
        curve: 'ecdsa',
        signingGrantId: 'wsess-passkey-ecdsa',
        thresholdSessionId: 'tsess-passkey-ecdsa',
      },
    });
    expect(calls[1]).toMatchObject({
      kind: 'claim',
      args: {
        sessionId: 'tsess-passkey-ecdsa',
        curve: 'ecdsa',
        chainTarget: TEMPO_CHAIN_TARGET,
      },
    });
  });

  test('rejects Email OTP ECDSA sealed restore on signing grant mismatch', async () => {
    const sealedRecord = makeEmailOtpEcdsaSealedRecord();

    await expect(
      restoreEmailOtpEcdsaSigningSessionMaterialFromSealedRecord({
        configs: { signing: { sessionSeal: {} } } as never,
        getSignerWorkerContext: () => ({
          requestWorkerOperation: async () => {
            throw new Error('worker should not be called on identity mismatch');
          },
        }),
        commitEvmFamilyThresholdEcdsaSessions: async () => {
          throw new Error('commit should not be called on identity mismatch');
        },
        hydrateSigningSession: async () => undefined,
        requireRpId: () => 'example.com',
        sealedRecord,
        ecdsaRecord: {
          source: 'email_otp',
          walletId: 'alice.testnet',
          nearAccountId: 'alice.testnet',
          thresholdSessionId: 'tsess-ecdsa',
          signingGrantId: 'wsess-mismatch',
          relayerUrl: 'https://relay.example',
          walletSessionJwt: 'jwt-ecdsa',
          signingSessionSealShamirPrimeB64u: 'prime-b64u',
          chainTarget: TEMPO_CHAIN_TARGET,
          emailOtpAuthContext: buildEmailOtpAuthContextForWalletAuthMethod({
            policy: 'session',
            walletId: 'alice.testnet',
            emailHashHex: EMAIL_OTP_EMAIL_HASH_HEX,
            retention: 'session',
            reason: 'login',
            provider: 'google',
            providerUserId: EMAIL_OTP_PROVIDER_SUBJECT_ID,
          }),
          signingRootId: EMAIL_OTP_SIGNING_ROOT_ID,
          signingRootVersion: 'v1',
          ecdsaThresholdKeyId: 'ecdsa-key',
          relayerKeyId: 'relayer-key',
          participantIds: [1, 2],
          thresholdSessionKind: 'jwt',
          subjectId: 'alice.testnet',
          remainingUses: 3,
          expiresAtMs: Date.now() + 60_000,
          createdAtMs: Date.now(),
          updatedAtMs: Date.now(),
        } as never,
      }),
    ).rejects.toThrow('signing grant id mismatch');
  });

  test('rejects current-record Email OTP ECDSA restore without current Wallet Session JWT', async () => {
    const sealedRecord = makeEmailOtpEcdsaSealedRecord();

    await expect(
      restoreEmailOtpEcdsaSigningSessionMaterialFromSealedRecord({
        configs: { signing: { sessionSeal: {} } } as never,
        getSignerWorkerContext: () => ({
          requestWorkerOperation: async () => {
            throw new Error('worker should not be called when current JWT is missing');
          },
        }),
        commitEvmFamilyThresholdEcdsaSessions: async () => {
          throw new Error('commit should not be called when current JWT is missing');
        },
        hydrateSigningSession: async () => undefined,
        requireRpId: () => 'example.com',
        sealedRecord,
        ecdsaRecord: makeEmailOtpEcdsaCurrentRecord({
          walletSessionJwt: undefined,
        } as never),
      }),
    ).rejects.toThrow('current record is missing Wallet Session JWT');
  });

  for (const mismatchCase of [
    {
      label: 'wallet id',
      overrides: { walletId: 'bob.testnet' },
      message: 'wallet id mismatch',
    },
    {
      label: 'missing signing-root version',
      overrides: { signingRootVersion: undefined },
      message: 'missing signing-root version',
    },
    {
      label: 'signing-root version',
      overrides: { signingRootVersion: 'v2' },
      message: 'signing-root version mismatch',
    },
    {
      label: 'relayer URL',
      overrides: { relayerUrl: 'https://different-relay.example' },
      message: 'relayer URL mismatch',
    },
    {
      label: 'key handle',
      overrides: { keyHandle: 'different-key-handle' },
      message: 'key handle mismatch',
    },
    {
      label: 'relayer key id',
      overrides: { relayerKeyId: 'different-relayer-key' },
      message: 'relayer key id mismatch',
    },
    {
      label: 'participant ids',
      overrides: { participantIds: [2, 1] },
      message: 'participant ids mismatch',
    },
  ] as const) {
    test(`rejects current-record Email OTP ECDSA restore on ${mismatchCase.label} mismatch`, async () => {
      const sealedRecord = makeEmailOtpEcdsaSealedRecord();

      await expect(
        restoreEmailOtpEcdsaSigningSessionMaterialFromSealedRecord({
          configs: { signing: { sessionSeal: {} } } as never,
          getSignerWorkerContext: () => ({
            requestWorkerOperation: async () => {
              throw new Error('worker should not be called on current/sealed mismatch');
            },
          }),
          commitEvmFamilyThresholdEcdsaSessions: async () => {
            throw new Error('commit should not be called on current/sealed mismatch');
          },
          hydrateSigningSession: async () => undefined,
          requireRpId: () => 'example.com',
          sealedRecord,
          ecdsaRecord: makeEmailOtpEcdsaCurrentRecord(mismatchCase.overrides as never),
        }),
      ).rejects.toThrow(mismatchCase.message);
    });
  }

  test('rejects Email OTP ECDSA core restore without normalized seal transport metadata', async () => {
    const sealedRecord = {
      ...makeEmailOtpEcdsaSealedRecord(),
      keyVersion: '',
    } as EmailOtpEcdsaSealedRecoveryRecord;

    await expect(
      restoreEmailOtpEcdsaSigningSessionMaterialFromSealedRecord({
        configs: {
          signing: {
            sessionSeal: {
              signingSessionSealKeyVersion: 'fallback-key-version',
              shamirPrimeB64u: 'fallback-prime',
            },
          },
        } as never,
        getSignerWorkerContext: () => ({
          requestWorkerOperation: async () => {
            throw new Error('worker should not be called when seal metadata is missing');
          },
        }),
        commitEvmFamilyThresholdEcdsaSessions: async () => {
          throw new Error('commit should not be called when seal metadata is missing');
        },
        hydrateSigningSession: async () => undefined,
        requireRpId: () => 'example.com',
        sealedRecord,
      }),
    ).rejects.toThrow('missing normalized seal transport metadata');
  });

  for (const staleCase of [
    { label: 'expired', overrides: { expiresAtMs: Date.now() - 1, remainingUses: 1 } },
    { label: 'exhausted', overrides: { expiresAtMs: Date.now() + 60_000, remainingUses: 0 } },
  ] as const) {
    test(`rejects ${staleCase.label} Email OTP ECDSA sealed records`, async () => {
      const sealedRecord = {
        ...makeEmailOtpEcdsaSealedRecord(),
        ...staleCase.overrides,
      };

      await expect(
        restoreEmailOtpEcdsaSigningSessionMaterialFromSealedRecord({
          configs: { signing: { sessionSeal: {} } } as never,
          getSignerWorkerContext: () => ({
            requestWorkerOperation: async () => {
              throw new Error('worker should not be called for stale sealed records');
            },
          }),
          commitEvmFamilyThresholdEcdsaSessions: async () => {
            throw new Error('commit should not be called for stale sealed records');
          },
          hydrateSigningSession: async () => undefined,
          requireRpId: () => 'example.com',
          sealedRecord,
        }),
      ).rejects.toThrow(`${staleCase.label} sealed record`);
    });
  }

  test('rejects Email OTP Ed25519 sealed recovery records with raw client-base metadata', () => {
    const now = Date.now();
    const normalized = normalizeSealedRecoveryRecord({
      v: 1,
      alg: 'shamir3pass-v1',
      storageScope: 'iframe_origin_indexeddb',
      authMethod: 'email_otp',
      secretKind: 'signing_session_secret32',
      storeKey: 'email_otp:ed25519:near:tsess-ed25519',
      signingGrantId: 'wsess-ecdsa',
      thresholdSessionIds: {
        ecdsa: 'tsess-ecdsa',
        ed25519: 'tsess-ed25519',
      },
      sealedSecretB64u: 'sealed-secret',
      curve: 'ed25519',
      walletId: 'alice.testnet',
      userId: 'alice.testnet',
      relayerUrl: 'https://relay.example',
      shamirPrimeB64u: 'prime-b64u',
      keyVersion: 'signing-session-seal-kek-test-r1',
	      ed25519Restore: {
	        nearAccountId: 'alice.testnet',
        nearEd25519SigningKeyId: 'alice.testnet',
        rpId: 'example.com',
        providerSubjectId: EMAIL_OTP_PROVIDER_SUBJECT_ID,
        emailHashHex: EMAIL_OTP_EMAIL_HASH_HEX,
        relayerKeyId: 'relayer-key-ed25519',
        participantIds: [1, 2],
        sessionKind: 'jwt',
        walletSessionJwt: 'jwt-ed25519',
        xClientBaseB64u: 'x-client-base',
        clientVerifyingShareB64u: 'client-verifying-share-ed25519',
      },
      issuedAtMs: now - 1_000,
      expiresAtMs: now + 60_000,
      remainingUses: 3,
      updatedAtMs: now,
    });

    expect(normalized).toMatchObject({
      kind: 'rejected',
      rejection: {
        kind: 'rejected_sealed_recovery_record',
        reason: 'missing_restore_metadata',
      },
    });
  });
});
