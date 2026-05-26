import { expect, test } from '@playwright/test';
import {
  parseCurrentEmailOtpAuthStateRow,
  parseCurrentEmailOtpChallengeRow,
  parseCurrentEmailOtpGrantRow,
  parseCurrentEmailOtpRecoveryWrappedEnrollmentEscrowRow,
  parseCurrentEmailOtpUnlockChallengeRow,
  parseCurrentEmailOtpWalletEnrollmentRow,
  parseCurrentGoogleEmailOtpRegistrationAttemptRow,
} from '../../server/src/core/EmailOtpPostgresRecords';

test.describe('email otp postgres records', () => {
  test('requires current challenge rows with explicit operation and matching expiry', () => {
    expect(
      parseCurrentEmailOtpChallengeRow({
        recordJson: {
          version: 'email_otp_challenge_v1',
          challengeId: 'challenge-id',
          userId: 'user-id',
          walletId: 'wallet-id',
          otpChannel: 'email_otp',
          email: 'user@example.com',
          otpCode: '123456',
          sessionHash: 'session-hash',
          appSessionVersion: 'app-session-v1',
          action: 'wallet_email_otp_login',
          operation: 'wallet_unlock',
          createdAtMs: 100,
          expiresAtMs: 200,
          attemptCount: 0,
          maxAttempts: 5,
        },
        expiresAtMs: 200,
      }),
    ).toEqual({
      version: 'email_otp_challenge_v1',
      challengeId: 'challenge-id',
      userId: 'user-id',
      walletId: 'wallet-id',
      otpChannel: 'email_otp',
      email: 'user@example.com',
      otpCode: '123456',
      sessionHash: 'session-hash',
      appSessionVersion: 'app-session-v1',
      action: 'wallet_email_otp_login',
      operation: 'wallet_unlock',
      createdAtMs: 100,
      expiresAtMs: 200,
      attemptCount: 0,
      maxAttempts: 5,
    });

    expect(
      parseCurrentEmailOtpChallengeRow({
        recordJson: {
          version: 'email_otp_challenge_v1',
          challengeId: 'challenge-id',
          userId: 'user-id',
          walletId: 'wallet-id',
          otpChannel: 'email_otp',
          email: 'user@example.com',
          otpCode: '123456',
          sessionHash: 'session-hash',
          appSessionVersion: 'app-session-v1',
          action: 'wallet_email_otp_login',
          createdAtMs: 100,
          expiresAtMs: 200,
          attemptCount: 0,
          maxAttempts: 5,
        },
        expiresAtMs: 200,
      }),
    ).toBeNull();

    expect(
      parseCurrentEmailOtpChallengeRow({
        recordJson: {
          version: 'email_otp_challenge_v1',
          challengeId: 'challenge-id',
          userId: 'user-id',
          walletId: 'wallet-id',
          otpChannel: 'email_otp',
          email: 'user@example.com',
          otpCode: '123456',
          sessionHash: 'session-hash',
          appSessionVersion: 'app-session-v1',
          action: 'wallet_email_otp_login',
          operation: 'wallet_unlock',
          createdAtMs: 100,
          expiresAtMs: 200,
          attemptCount: 0,
          maxAttempts: 5,
        },
        expiresAtMs: 201,
      }),
    ).toBeNull();
  });

  test('requires current grant and unlock challenge rows', () => {
    expect(
      parseCurrentEmailOtpGrantRow({
        recordJson: {
          version: 'email_otp_grant_v1',
          grantToken: 'grant-token',
          userId: 'user-id',
          walletId: 'wallet-id',
          challengeId: 'challenge-id',
          otpChannel: 'email_otp',
          sessionHash: 'session-hash',
          appSessionVersion: 'app-session-v1',
          action: 'wallet_email_otp_unseal',
          issuedAtMs: 100,
          expiresAtMs: 200,
        },
        expiresAtMs: 200,
      }),
    ).toEqual({
      version: 'email_otp_grant_v1',
      grantToken: 'grant-token',
      userId: 'user-id',
      walletId: 'wallet-id',
      challengeId: 'challenge-id',
      otpChannel: 'email_otp',
      sessionHash: 'session-hash',
      appSessionVersion: 'app-session-v1',
      action: 'wallet_email_otp_unseal',
      issuedAtMs: 100,
      expiresAtMs: 200,
    });

    expect(
      parseCurrentEmailOtpGrantRow({
        recordJson: {
          version: 'email_otp_grant_v1',
          grantToken: 'grant-token',
          userId: 'user-id',
          walletId: 'wallet-id',
          challengeId: 'challenge-id',
          otpChannel: 'email_otp',
          sessionHash: 'session-hash',
          appSessionVersion: 'app-session-v1',
          action: 'wallet_email_otp_unseal',
          issuedAtMs: 100,
          expiresAtMs: 200,
        },
        expiresAtMs: 201,
      }),
    ).toBeNull();

    expect(
      parseCurrentEmailOtpUnlockChallengeRow({
        recordJson: {
          version: 'email_otp_unlock_challenge_v1',
          challengeId: 'challenge-id',
          walletId: 'wallet-id',
          userId: 'user-id',
          challengeB64u: 'challenge-b64u',
          createdAtMs: 100,
          expiresAtMs: 200,
        },
        expiresAtMs: 200,
      }),
    ).toEqual({
      version: 'email_otp_unlock_challenge_v1',
      challengeId: 'challenge-id',
      walletId: 'wallet-id',
      userId: 'user-id',
      challengeB64u: 'challenge-b64u',
      createdAtMs: 100,
      expiresAtMs: 200,
    });

    expect(
      parseCurrentEmailOtpUnlockChallengeRow({
        recordJson: {
          version: 'email_otp_unlock_challenge_v1',
          challengeId: 'challenge-id',
          walletId: 'wallet-id',
          userId: 'user-id',
          challengeB64u: 'challenge-b64u',
          createdAtMs: 100,
          expiresAtMs: 200,
        },
        expiresAtMs: 201,
      }),
    ).toBeNull();
  });

  test('requires current registration attempt rows without implicit defaults', () => {
    expect(
      parseCurrentGoogleEmailOtpRegistrationAttemptRow({
        recordJson: {
          version: 'google_email_otp_registration_attempt_v1',
          attemptId: 'attempt-id',
          providerSubject: 'provider-subject',
          email: 'user@example.com',
          walletId: 'wallet-id',
          authProvider: 'google_oidc',
          accountIdSlugVersion: 'hmac_readable_v1',
          walletIdDerivationNonce: 'recordNonceA012345',
          collisionCounter: 0,
          state: 'started',
          createdAtMs: 100,
          updatedAtMs: 120,
          expiresAtMs: 300,
          runtimePolicyScope: {
            orgId: 'org-id',
            projectId: 'project-id',
            envId: 'env-id',
            signingRootVersion: 'default',
          },
        },
        expiresAtMs: 300,
        updatedAtMs: 120,
      }),
    ).toEqual({
      version: 'google_email_otp_registration_attempt_v1',
      attemptId: 'attempt-id',
      providerSubject: 'provider-subject',
      email: 'user@example.com',
      walletId: 'wallet-id',
      authProvider: 'google_oidc',
      accountIdSlugVersion: 'hmac_readable_v1',
      walletIdDerivationNonce: 'recordNonceA012345',
      collisionCounter: 0,
      state: 'started',
      createdAtMs: 100,
      updatedAtMs: 120,
      expiresAtMs: 300,
      runtimePolicyScope: {
        orgId: 'org-id',
        projectId: 'project-id',
        envId: 'env-id',
        signingRootVersion: 'default',
      },
    });

    expect(
      parseCurrentGoogleEmailOtpRegistrationAttemptRow({
        recordJson: {
          version: 'google_email_otp_registration_attempt_v1',
          attemptId: 'attempt-id',
          providerSubject: 'provider-subject',
          email: 'user@example.com',
          walletId: 'wallet-id',
          accountIdSlugVersion: 'hmac_readable_v1',
          walletIdDerivationNonce: 'recordNonceA012345',
          collisionCounter: 0,
          state: 'started',
          createdAtMs: 100,
          updatedAtMs: 120,
          expiresAtMs: 300,
        },
        expiresAtMs: 300,
        updatedAtMs: 120,
      }),
    ).toBeNull();

    expect(
      parseCurrentGoogleEmailOtpRegistrationAttemptRow({
        recordJson: {
          version: 'google_email_otp_registration_attempt_v1',
          attemptId: 'attempt-id',
          providerSubject: 'provider-subject',
          email: 'user@example.com',
          walletId: 'wallet-id',
          authProvider: 'google_oidc',
          accountIdSlugVersion: 'hmac_readable_v1',
          walletIdDerivationNonce: 'recordNonceA012345',
          collisionCounter: 0,
          state: 'started',
          createdAtMs: 100,
          updatedAtMs: 120,
          expiresAtMs: 300,
        },
        expiresAtMs: 301,
        updatedAtMs: 120,
      }),
    ).toBeNull();
  });

  test('requires current enrollment, escrow, and auth-state rows', () => {
    expect(
      parseCurrentEmailOtpWalletEnrollmentRow({
        recordJson: {
          version: 'email_otp_wallet_enrollment_v1',
          walletId: 'wallet-id',
          providerUserId: 'provider-user-id',
          orgId: 'org-id',
          verifiedEmail: 'USER@EXAMPLE.COM',
          enrollmentId: 'enrollment-id',
          enrollmentVersion: 'enrollment-v1',
          enrollmentSealKeyVersion: 'seal-key-v1',
          signingRootId: 'signing-root-id',
          signingRootVersion: 'default',
          recoveryWrappedEnrollmentEscrowCount: 2,
          clientUnlockPublicKeyB64u: 'unlock-public-key',
          unlockKeyVersion: 'unlock-key-v1',
          thresholdEcdsaClientVerifyingShareB64u: 'client-share',
          createdAtMs: 100,
          updatedAtMs: 120,
        },
        updatedAtMs: 120,
      }),
    ).toEqual({
      version: 'email_otp_wallet_enrollment_v1',
      walletId: 'wallet-id',
      providerUserId: 'provider-user-id',
      orgId: 'org-id',
      verifiedEmail: 'user@example.com',
      enrollmentId: 'enrollment-id',
      enrollmentVersion: 'enrollment-v1',
      enrollmentSealKeyVersion: 'seal-key-v1',
      signingRootId: 'signing-root-id',
      signingRootVersion: 'default',
      recoveryWrappedEnrollmentEscrowCount: 2,
      clientUnlockPublicKeyB64u: 'unlock-public-key',
      unlockKeyVersion: 'unlock-key-v1',
      thresholdEcdsaClientVerifyingShareB64u: 'client-share',
      createdAtMs: 100,
      updatedAtMs: 120,
    });

    expect(
      parseCurrentEmailOtpRecoveryWrappedEnrollmentEscrowRow({
        recordJson: {
          version: 'email_otp_recovery_wrapped_enrollment_escrow_v1',
          alg: 'chacha20poly1305-hkdf-sha256-v1',
          secretKind: 'email_otp_device_enrollment_escrow',
          escrowKind: 'recovery_wrapped_enrollment_escrow',
          walletId: 'wallet-id',
          userId: 'user-id',
          authSubjectId: 'auth-subject-id',
          authMethod: 'google_sso_email_otp',
          enrollmentId: 'enrollment-id',
          enrollmentVersion: 'enrollment-v1',
          enrollmentSealKeyVersion: 'seal-key-v1',
          signingRootId: 'signing-root-id',
          signingRootVersion: 'default',
          recoveryKeyId: 'recovery-key-id',
          recoveryKeyStatus: 'active',
          nonceB64u: 'nonce_b64u',
          wrappedDeviceEnrollmentEscrowB64u: 'wrapped_b64u',
          aadHashB64u: 'aad_hash_b64u',
          issuedAtMs: 100,
          updatedAtMs: 120,
        },
        updatedAtMs: 120,
      }),
    ).toEqual({
      version: 'email_otp_recovery_wrapped_enrollment_escrow_v1',
      alg: 'chacha20poly1305-hkdf-sha256-v1',
      secretKind: 'email_otp_device_enrollment_escrow',
      escrowKind: 'recovery_wrapped_enrollment_escrow',
      walletId: 'wallet-id',
      userId: 'user-id',
      authSubjectId: 'auth-subject-id',
      authMethod: 'google_sso_email_otp',
      enrollmentId: 'enrollment-id',
      enrollmentVersion: 'enrollment-v1',
      enrollmentSealKeyVersion: 'seal-key-v1',
      signingRootId: 'signing-root-id',
      signingRootVersion: 'default',
      recoveryKeyId: 'recovery-key-id',
      recoveryKeyStatus: 'active',
      nonceB64u: 'nonce_b64u',
      wrappedDeviceEnrollmentEscrowB64u: 'wrapped_b64u',
      aadHashB64u: 'aad_hash_b64u',
      issuedAtMs: 100,
      updatedAtMs: 120,
    });

    expect(
      parseCurrentEmailOtpAuthStateRow({
        recordJson: {
          version: 'email_otp_auth_state_v1',
          walletId: 'wallet-id',
          providerUserId: 'provider-user-id',
          orgId: 'org-id',
          createdAtMs: 100,
          updatedAtMs: 120,
          otpFailureCount: 0,
        },
        updatedAtMs: 120,
      }),
    ).toEqual({
      version: 'email_otp_auth_state_v1',
      walletId: 'wallet-id',
      providerUserId: 'provider-user-id',
      orgId: 'org-id',
      createdAtMs: 100,
      updatedAtMs: 120,
      otpFailureCount: 0,
    });

    expect(
      parseCurrentEmailOtpWalletEnrollmentRow({
        recordJson: {
          version: 'email_otp_wallet_enrollment_v1',
          walletId: 'wallet-id',
          providerUserId: 'provider-user-id',
          orgId: 'org-id',
          verifiedEmail: 'user@example.com',
          enrollmentId: 'enrollment-id',
          enrollmentVersion: 'enrollment-v1',
          enrollmentSealKeyVersion: 'seal-key-v1',
          signingRootId: 'signing-root-id',
          signingRootVersion: 'default',
          recoveryWrappedEnrollmentEscrowCount: 2,
          clientUnlockPublicKeyB64u: 'unlock-public-key',
          unlockKeyVersion: 'unlock-key-v1',
          thresholdEcdsaClientVerifyingShareB64u: 'client-share',
          createdAtMs: 100,
          updatedAtMs: 120,
        },
        updatedAtMs: 121,
      }),
    ).toBeNull();
  });
});
