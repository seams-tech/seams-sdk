import { expect, test } from '@playwright/test';

import {
  normalizeSealedRecoveryRecord,
  type RawSigningSessionSealedStoreRecord,
} from '../../packages/wallet/src/core/signingEngine/session/sealedRecovery/recoveryRecord';
import { ecdsaCapabilityActivationLookupFixture } from './helpers/ecdsaCapabilityManifest.fixtures';
import { buildEmailOtpEcdsaSealedRuntimeRecordFixture } from './helpers/sealedSigningSession.fixtures';

function emailOtpEcdsaSealedRecoveryRecord(
  overrides: Partial<RawSigningSessionSealedStoreRecord> = {},
): RawSigningSessionSealedStoreRecord {
  const now = Date.now();
  return {
    ...buildEmailOtpEcdsaSealedRuntimeRecordFixture({
      manifest: ecdsaCapabilityActivationLookupFixture().manifest,
    }),
    issuedAtMs: now - 1_000,
    expiresAtMs: now + 60_000,
    updatedAtMs: now,
    ...overrides,
  };
}

test.describe('sealed recovery record strict normalization', () => {
  test('accepts canonical Email OTP ECDSA sealed recovery records', () => {
    const normalized = normalizeSealedRecoveryRecord(emailOtpEcdsaSealedRecoveryRecord());

    expect(normalized).toMatchObject({
      kind: 'accepted',
      record: {
        authMethod: 'email_otp',
        curve: 'ecdsa',
        walletId: 'ecdsa-manifest-fixture-wallet',
      },
    });
  });

  test('rejects top-level userId as stale sealed recovery identity', () => {
    const normalized = normalizeSealedRecoveryRecord(
      emailOtpEcdsaSealedRecoveryRecord({ userId: 'legacy-user-id' }),
    );

    expect(normalized).toMatchObject({
      kind: 'rejected',
      rejection: {
        kind: 'rejected_sealed_recovery_record',
        reason: 'invalid_identity',
      },
    });
  });

  test('rejects a sealed recovery record whose policy scope exists only in its JWT', () => {
    const record = emailOtpEcdsaSealedRecoveryRecord();
    const restore = record.ecdsaRestore;
    if (!restore || typeof restore !== 'object') {
      throw new Error('sealed recovery fixture requires ECDSA restore metadata');
    }
    const normalized = normalizeSealedRecoveryRecord({
      ...record,
      ecdsaRestore: {
        ...restore,
        runtimePolicyScope: undefined,
      },
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
