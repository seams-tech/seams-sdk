import { expect, test } from '@playwright/test';
import {
  buildWalletRecoveryCommittedProjectionV1,
  parseWalletRecoveryCommittedProjectionV1,
} from '../../packages/shared-ts/src/wallet-recovery/walletRecoveryCommittedProjection';
import { buildFullOwnerDelegatedWalletAuthorityV1 } from '../../packages/shared-ts/src/authorization/delegatedAuthority';
import { buildWalletAuthMethodRecordV2 } from '../../packages/shared-ts/src/utils/registrationIntent';
import { parseEmailOtpProviderUserId } from '../../packages/shared-ts/src/utils/domainIds';
import { buildLinkedDeviceManagementAuthorityFixture } from './helpers/linkedDeviceManagement.fixtures';

function required<T>(result: { readonly ok: true; readonly value: T } | { readonly ok: false }): T {
  if (!result.ok) throw new Error('invalid projection fixture identity');
  return result.value;
}

function asRecord(value: unknown, label: string): Record<string, unknown> {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) {
    throw new Error(`${label} must be an object`);
  }
  return Object.fromEntries(Object.entries(value));
}

function cloneRecord(value: unknown): Record<string, unknown> {
  return asRecord(JSON.parse(JSON.stringify(value)), 'projection clone');
}

async function passkeyProjectionFixture() {
  const fixture = await buildLinkedDeviceManagementAuthorityFixture({
    label: 'projection-passkey',
    permissions: buildFullOwnerDelegatedWalletAuthorityV1().permissions,
    provenance: 'wallet_recovery',
    identity: {
      walletId: 'alice.testnet',
      authorityId: 'wallet-authority:projection-passkey',
      walletAuthMethodId: 'wallet-auth-method:projection-passkey',
      rpId: 'wallet.example.localhost',
      credentialIdB64u: 'Y3JlZGVudGlhbC1wcm9qZWN0aW9u',
    },
  });
  if (fixture.authority.provenance.kind !== 'wallet_recovery') {
    throw new Error('passkey projection fixture lost recovery provenance');
  }
  const projection = buildWalletRecoveryCommittedProjectionV1({
    kind: 'passkey',
    storeVersion: 'store-projection-passkey',
    walletId: fixture.authority.walletId,
    recoveryOperationId: fixture.authority.provenance.recoveryOperationId,
    targetDeviceId: fixture.authority.principal.deviceId,
    targetAuthorityId: fixture.authority.authorityId,
    targetWalletAuthMethodId: fixture.authMethod.walletAuthMethodId,
    authority: fixture.authority,
    authMethod: fixture.authMethod,
  });
  return {
    projection,
    expected: {
      kind: 'passkey' as const,
      walletId: projection.walletId,
      recoveryOperationId: projection.recoveryOperationId,
      targetDeviceId: projection.targetDeviceId,
      targetAuthorityId: projection.targetAuthorityId,
      targetWalletAuthMethodId: projection.targetWalletAuthMethodId,
      rpId: projection.target.rpId,
      credentialIdB64u: projection.target.credentialIdB64u,
    },
  };
}

async function emailProjectionFixture() {
  const fixture = await buildLinkedDeviceManagementAuthorityFixture({
    label: 'projection-email',
    permissions: buildFullOwnerDelegatedWalletAuthorityV1().permissions,
    provenance: 'wallet_recovery',
    identity: {
      walletId: 'alice.testnet',
      authorityId: 'wallet-authority:projection-email',
      walletAuthMethodId: 'wallet-auth-method:projection-email',
      rpId: 'wallet.example.localhost',
    },
  });
  if (fixture.authority.provenance.kind !== 'wallet_recovery') {
    throw new Error('Email projection fixture lost recovery provenance');
  }
  const authMethod = buildWalletAuthMethodRecordV2({
    version: 'wallet_auth_method_v2',
    walletAuthMethodId: fixture.authMethod.walletAuthMethodId,
    walletId: fixture.authority.walletId,
    walletAuthorityId: fixture.authority.authorityId,
    kind: 'email_otp',
    status: 'active',
    emailHashHex: 'b'.repeat(64),
    registrationAuthorityId: 'challenge:projection-email',
    createdAtMs: fixture.authMethod.createdAtMs,
    updatedAtMs: fixture.authMethod.updatedAtMs,
    activatedAtMs: fixture.authMethod.activatedAtMs,
  });
  if (authMethod.kind !== 'email_otp' || authMethod.status !== 'active') {
    throw new Error('Email projection fixture changed branch');
  }
  const projection = buildWalletRecoveryCommittedProjectionV1({
    kind: 'google_email_otp',
    storeVersion: 'store-projection-email',
    walletId: fixture.authority.walletId,
    recoveryOperationId: fixture.authority.provenance.recoveryOperationId,
    targetDeviceId: fixture.authority.principal.deviceId,
    targetAuthorityId: fixture.authority.authorityId,
    targetWalletAuthMethodId: authMethod.walletAuthMethodId,
    authority: fixture.authority,
    authMethod,
    providerSubject: required(parseEmailOtpProviderUserId('google:projection-email')),
    emailHashHex: authMethod.emailHashHex,
    registrationAuthorityId: authMethod.registrationAuthorityId,
    enrollment: {
      kind: 'email_otp_enrollment_reference_v1',
      enrollmentId: 'enrollment:projection-email',
      enrollmentSealKeyVersion: 'email-otp-seal-v1',
    },
  });
  return {
    projection,
    expected: {
      kind: 'google_email_otp' as const,
      walletId: projection.walletId,
      recoveryOperationId: projection.recoveryOperationId,
      targetDeviceId: projection.targetDeviceId,
      targetAuthorityId: projection.targetAuthorityId,
      targetWalletAuthMethodId: projection.targetWalletAuthMethodId,
      providerSubject: projection.target.providerSubject,
      emailHashHex: projection.target.emailHashHex,
      registrationAuthorityId: projection.target.registrationAuthorityId,
      enrollment: projection.target.enrollment,
    },
  };
}

test('parses the exact Passkey committed projection branch', async () => {
  const fixture = await passkeyProjectionFixture();
  await expect(
    parseWalletRecoveryCommittedProjectionV1(
      JSON.parse(JSON.stringify(fixture.projection)),
      fixture.expected,
    ),
  ).resolves.toEqual(fixture.projection);
});

test('parses the exact Google Email OTP branch without enrollment material', async () => {
  const fixture = await emailProjectionFixture();
  const raw = JSON.parse(JSON.stringify(fixture.projection));
  const target = asRecord(raw.target, 'Email OTP target');
  expect(target.enrollment).toEqual({
    kind: 'email_otp_enrollment_reference_v1',
    enrollmentId: 'enrollment:projection-email',
    enrollmentSealKeyVersion: 'email-otp-seal-v1',
  });
  expect(JSON.stringify(raw)).not.toContain('serverSealedFactorCiphertextB64u');
  await expect(parseWalletRecoveryCommittedProjectionV1(raw, fixture.expected)).resolves.toEqual(
    fixture.projection,
  );
});

test('rejects identity, branch, digest, and secret-bearing projection drift', async () => {
  const passkey = await passkeyProjectionFixture();
  const wrongIdentity = cloneRecord(passkey.projection);
  wrongIdentity.walletId = 'mallory.testnet';
  await expect(
    parseWalletRecoveryCommittedProjectionV1(wrongIdentity, passkey.expected),
  ).rejects.toThrow();

  const extraField = cloneRecord(passkey.projection);
  extraField.operationCredential = 'credential-must-not-cross-read-boundary';
  await expect(
    parseWalletRecoveryCommittedProjectionV1(extraField, passkey.expected),
  ).rejects.toThrow();

  const wrongBranch = cloneRecord(passkey.projection);
  wrongBranch.kind = 'google_email_otp';
  await expect(
    parseWalletRecoveryCommittedProjectionV1(wrongBranch, passkey.expected),
  ).rejects.toThrow();

  const digestDrift = cloneRecord(passkey.projection);
  const authority = asRecord(digestDrift.authority, 'authority');
  authority.authorityDigestB64u = 'ZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXp7fH1-f4CBgoM';
  digestDrift.authority = authority;
  await expect(
    parseWalletRecoveryCommittedProjectionV1(digestDrift, passkey.expected),
  ).rejects.toThrow();

  const email = await emailProjectionFixture();
  const emailDrift = cloneRecord(email.projection);
  const emailTarget = asRecord(emailDrift.target, 'Email OTP target');
  emailTarget.providerSubject = 'google:drifted-subject';
  emailTarget.enrollment = {
    kind: 'email_otp_enrollment_reference_v1',
    enrollmentId: 'enrollment:projection-email',
    enrollmentSealKeyVersion: 'email-otp-seal-v1',
    serverSealedFactorCiphertextB64u: 'sealed-secret',
  };
  emailDrift.target = emailTarget;
  await expect(
    parseWalletRecoveryCommittedProjectionV1(emailDrift, email.expected),
  ).rejects.toThrow();
});
