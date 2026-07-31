import { expect, test } from '@playwright/test';
import { requireEmailOtpSealedRestoreAuthorization } from '@/core/signingEngine/session/emailOtp/ecdsaRecovery';
import { normalizeSealedRecoveryRecord } from '@/core/signingEngine/session/sealedRecovery/recoveryRecord';
import {
  activeEvmFamilyWalletSessionAuthorizationFixture,
  ecdsaCapabilityHydrationLookupFixture,
} from './helpers/ecdsaCapabilityManifest.fixtures';
import { buildEmailOtpEcdsaSealedRuntimeRecordFixture } from './helpers/sealedSigningSession.fixtures';

const ACTIVE_JWT = 'eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJraW5kIjoicm91dGVyX2FiX2VjZHNhX2Rlcml2YXRpb25fd2FsbGV0X3Nlc3Npb25fdjEifQ.current';

function restoreFixture() {
  const manifest = ecdsaCapabilityHydrationLookupFixture().active.manifest;
  const storedRecord = buildEmailOtpEcdsaSealedRuntimeRecordFixture({ manifest });
  const normalized = normalizeSealedRecoveryRecord(storedRecord);
  if (normalized.kind !== 'accepted' || normalized.record.authMethod !== 'email_otp') {
    throw new Error('fixture must normalize to an Email OTP ECDSA recovery record');
  }
  const authorization = activeEvmFamilyWalletSessionAuthorizationFixture({
    manifest,
    authMethod: 'email_otp',
    walletSessionJwt: ACTIVE_JWT,
  }).projection;
  return { authorization, sealedRecord: normalized.record, storedRecord };
}

test('Email OTP sealed restore uses the current active authorization bearer', () => {
  const { authorization, sealedRecord, storedRecord } = restoreFixture();
  expect(storedRecord.ecdsaRestore.walletSessionJwt).not.toBe(ACTIVE_JWT);

  const resolved = requireEmailOtpSealedRestoreAuthorization({
    sealedRecord,
    authorizationRead: { kind: 'found', projection: authorization },
    nowMs: Date.now(),
  });

  expect(resolved.walletSessionJwt).toBe(ACTIVE_JWT);
});

test('Email OTP sealed restore fails closed without active authorization', () => {
  const { sealedRecord } = restoreFixture();
  expect(() =>
    requireEmailOtpSealedRestoreAuthorization({
      sealedRecord,
      authorizationRead: { kind: 'missing' },
      nowMs: Date.now(),
    }),
  ).toThrow('requires active Wallet Session authorization: missing');
});
