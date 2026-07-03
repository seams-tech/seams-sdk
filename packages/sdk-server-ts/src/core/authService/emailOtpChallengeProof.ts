import {
  EMAIL_OTP_CHANNEL,
  WALLET_EMAIL_OTP_ACTIONS,
  WALLET_EMAIL_OTP_EXPORT_OPERATION,
  WALLET_EMAIL_OTP_REGISTRATION_OPERATION,
  WALLET_EMAIL_OTP_TRANSACTION_SIGN_OPERATION,
  WALLET_EMAIL_OTP_UNLOCK_OPERATION,
} from '@shared/utils/emailOtpDomain';
import {
  parseAppSessionVersion,
  parseChallengeSubjectId,
  parseEmailOtpChallengeId,
  parseEmailOtpRegistrationAttemptId,
  parseOrgId,
  parseProviderSubject,
  parseWalletId,
  type AppSessionVersion,
  type ChallengeSubjectId,
  type EmailOtpChallengeId,
  type EmailOtpRegistrationAttemptId,
  type OrgId,
  type ProviderSubject,
  type WalletId,
} from '@shared/utils/domainIds';
import { toOptionalTrimmedString } from '@shared/utils/validation';
import type {
  EmailOtpAuthStateRecord,
  EmailOtpChallengeAction,
  EmailOtpChallengeOperation,
  EmailOtpChallengeRecord,
  EmailOtpRecoveryWrappedEnrollmentEscrowRecord,
  EmailOtpWalletEnrollmentRecord,
} from '../EmailOtpStores';

function assertNever(value: never): never {
  throw new Error(`Unexpected value: ${String(value)}`);
}

export type EmailOtpRegistrationEnrollmentPersistence = {
  previousProviderWalletId?: string;
  enrollment: EmailOtpWalletEnrollmentRecord;
  recoveryWrappedEnrollmentEscrows: readonly EmailOtpRecoveryWrappedEnrollmentEscrowRecord[];
  authState: EmailOtpAuthStateRecord;
};

export type EmailOtpRecoveryChallengeEscrow = Omit<
  EmailOtpRecoveryWrappedEnrollmentEscrowRecord,
  | 'recoveryKeyId'
  | 'recoveryKeyStatus'
  | 'issuedAtMs'
  | 'updatedAtMs'
  | 'consumedAtMs'
  | 'revokedAtMs'
>;

export function redactEmailOtpRecoveryChallengeEscrow(
  record: EmailOtpRecoveryWrappedEnrollmentEscrowRecord,
): EmailOtpRecoveryChallengeEscrow {
  return {
    version: record.version,
    alg: record.alg,
    secretKind: record.secretKind,
    escrowKind: record.escrowKind,
    walletId: record.walletId,
    userId: record.userId,
    authSubjectId: record.authSubjectId,
    authMethod: record.authMethod,
    enrollmentId: record.enrollmentId,
    enrollmentVersion: record.enrollmentVersion,
    enrollmentSealKeyVersion: record.enrollmentSealKeyVersion,
    signingRootId: record.signingRootId,
    signingRootVersion: record.signingRootVersion,
    nonceB64u: record.nonceB64u,
    wrappedDeviceEnrollmentEscrowB64u: record.wrappedDeviceEnrollmentEscrowB64u,
    aadHashB64u: record.aadHashB64u,
  };
}

export type EmailOtpRegistrationChallengePurpose =
  | {
      kind: 'registration';
      action: typeof WALLET_EMAIL_OTP_ACTIONS.registration;
      operation: typeof WALLET_EMAIL_OTP_REGISTRATION_OPERATION;
    }
  | {
      kind: 'registration_reroll';
      action: typeof WALLET_EMAIL_OTP_ACTIONS.login;
      operation: typeof WALLET_EMAIL_OTP_UNLOCK_OPERATION;
    };

export type EmailOtpRegistrationChallengeProof =
  | {
      kind: 'registration_attempt';
      providerSubject: ProviderSubject;
      challengeSubjectId: ChallengeSubjectId;
      proofEmail: string;
      registrationAttemptId: EmailOtpRegistrationAttemptId;
      challengeId: EmailOtpChallengeId;
      finalWalletId: WalletId;
      orgId: OrgId;
      appSessionVersion: AppSessionVersion;
    }
  | {
      kind: 'direct_proof_email';
      providerSubject: ProviderSubject;
      challengeSubjectId: ChallengeSubjectId;
      proofEmail: string;
      registrationAttemptId?: never;
      challengeId: EmailOtpChallengeId;
      finalWalletId: WalletId;
      orgId: OrgId;
      appSessionVersion: AppSessionVersion;
    };

export type VerifiedEmailOtpRegistrationChallengeProofShared = {
  providerSubject: ProviderSubject;
  challengeSubjectId: ChallengeSubjectId;
  challengeEmail: string;
  challengeId: EmailOtpChallengeId;
  originalWalletId: WalletId;
  finalWalletId: WalletId;
  orgId: OrgId;
  appSessionVersion: AppSessionVersion;
  purpose: EmailOtpRegistrationChallengePurpose;
};

export type VerifiedEmailOtpRegistrationChallengeProof =
  | (VerifiedEmailOtpRegistrationChallengeProofShared & {
      kind: 'registration_attempt';
      registrationAttemptId: EmailOtpRegistrationAttemptId;
    })
  | (VerifiedEmailOtpRegistrationChallengeProofShared & {
      kind: 'direct_proof_email';
      registrationAttemptId?: never;
    });

export type EmailOtpChallengeVerificationIntent =
  | {
      kind: 'registration';
      binding: EmailOtpRegistrationChallengeProof;
      allowWalletReroll: boolean;
    }
  | {
      kind: 'wallet_unlock';
    }
  | {
      kind: 'transaction_sign';
    }
  | {
      kind: 'export_key';
    }
  | {
      kind: 'device_recovery';
    };

export type EmailOtpStoredChallengePurpose =
  | {
      kind: 'registration';
      action: typeof WALLET_EMAIL_OTP_ACTIONS.registration;
      operation: typeof WALLET_EMAIL_OTP_REGISTRATION_OPERATION;
    }
  | {
      kind: 'wallet_unlock';
      action: typeof WALLET_EMAIL_OTP_ACTIONS.login;
      operation: typeof WALLET_EMAIL_OTP_UNLOCK_OPERATION;
    }
  | {
      kind: 'transaction_sign';
      action: typeof WALLET_EMAIL_OTP_ACTIONS.login;
      operation: typeof WALLET_EMAIL_OTP_TRANSACTION_SIGN_OPERATION;
    }
  | {
      kind: 'export_key';
      action: typeof WALLET_EMAIL_OTP_ACTIONS.login;
      operation: typeof WALLET_EMAIL_OTP_EXPORT_OPERATION;
    }
  | {
      kind: 'device_recovery';
      action: typeof WALLET_EMAIL_OTP_ACTIONS.deviceRecovery;
      operation: typeof WALLET_EMAIL_OTP_UNLOCK_OPERATION;
    };

export type EmailOtpChallengeBindingMismatchCode =
  | 'challenge_id_mismatch'
  | 'challenge_purpose_mismatch'
  | 'challenge_subject_mismatch'
  | 'challenge_email_mismatch'
  | 'challenge_wallet_mismatch'
  | 'challenge_session_mismatch'
  | 'challenge_org_mismatch'
  | 'challenge_channel_mismatch'
  | 'registration_reroll_disallowed';

export type VerifiedEmailOtpChallengeCodeSuccessBase = {
  challengeId: EmailOtpChallengeId;
  challengeSubjectId: ChallengeSubjectId;
  walletId: WalletId;
  orgId: OrgId;
  email?: string;
  otpChannel: typeof EMAIL_OTP_CHANNEL;
};

export type VerifiedEmailOtpChallengeCodeSuccess =
  | (VerifiedEmailOtpChallengeCodeSuccessBase & {
      intent: 'registration';
      registrationChallengeProof: VerifiedEmailOtpRegistrationChallengeProof;
    })
  | (VerifiedEmailOtpChallengeCodeSuccessBase & {
      intent: 'wallet_unlock' | 'transaction_sign' | 'export_key' | 'device_recovery';
      registrationChallengeProof?: never;
    });

export type VerifiedEmailOtpChallengeCodeResult =
  | ({ ok: true } & VerifiedEmailOtpChallengeCodeSuccess)
  | {
      ok: false;
      code: string;
      message: string;
      attemptsRemaining?: number;
      lockedUntilMs?: number;
    };

export function emailOtpChallengeVerificationIntentFromRequest(input: {
  expectedAction: EmailOtpChallengeAction;
  expectedOperation?: EmailOtpChallengeOperation;
  registrationChallengeProof?: EmailOtpRegistrationChallengeProof;
  allowRegistrationChallengeReroll?: boolean;
}): EmailOtpChallengeVerificationIntent {
  if (input.expectedAction === WALLET_EMAIL_OTP_ACTIONS.registration) {
    if (!input.registrationChallengeProof) {
      throw new Error('Email OTP registration verification requires registration challenge proof');
    }
    return {
      kind: 'registration',
      binding: input.registrationChallengeProof,
      allowWalletReroll: input.allowRegistrationChallengeReroll === true,
    };
  }
  if (input.expectedAction === WALLET_EMAIL_OTP_ACTIONS.deviceRecovery) {
    return { kind: 'device_recovery' };
  }
  const operation = input.expectedOperation || WALLET_EMAIL_OTP_UNLOCK_OPERATION;
  if (operation === WALLET_EMAIL_OTP_TRANSACTION_SIGN_OPERATION) {
    return { kind: 'transaction_sign' };
  }
  if (operation === WALLET_EMAIL_OTP_EXPORT_OPERATION) {
    return { kind: 'export_key' };
  }
  return { kind: 'wallet_unlock' };
}

export function expectedEmailOtpStoredChallengePurpose(
  intent: EmailOtpChallengeVerificationIntent,
): EmailOtpStoredChallengePurpose {
  switch (intent.kind) {
    case 'registration':
      return {
        kind: 'registration',
        action: WALLET_EMAIL_OTP_ACTIONS.registration,
        operation: WALLET_EMAIL_OTP_REGISTRATION_OPERATION,
      };
    case 'wallet_unlock':
      return {
        kind: 'wallet_unlock',
        action: WALLET_EMAIL_OTP_ACTIONS.login,
        operation: WALLET_EMAIL_OTP_UNLOCK_OPERATION,
      };
    case 'transaction_sign':
      return {
        kind: 'transaction_sign',
        action: WALLET_EMAIL_OTP_ACTIONS.login,
        operation: WALLET_EMAIL_OTP_TRANSACTION_SIGN_OPERATION,
      };
    case 'export_key':
      return {
        kind: 'export_key',
        action: WALLET_EMAIL_OTP_ACTIONS.login,
        operation: WALLET_EMAIL_OTP_EXPORT_OPERATION,
      };
    case 'device_recovery':
      return {
        kind: 'device_recovery',
        action: WALLET_EMAIL_OTP_ACTIONS.deviceRecovery,
        operation: WALLET_EMAIL_OTP_UNLOCK_OPERATION,
      };
  }
  return assertNever(intent);
}

export function readEmailOtpStoredChallengePurpose(
  record: Pick<EmailOtpChallengeRecord, 'action' | 'operation'>,
): EmailOtpStoredChallengePurpose | null {
  if (
    record.action === WALLET_EMAIL_OTP_ACTIONS.registration &&
    record.operation === WALLET_EMAIL_OTP_REGISTRATION_OPERATION
  ) {
    return {
      kind: 'registration',
      action: WALLET_EMAIL_OTP_ACTIONS.registration,
      operation: WALLET_EMAIL_OTP_REGISTRATION_OPERATION,
    };
  }
  if (record.action === WALLET_EMAIL_OTP_ACTIONS.login) {
    if (record.operation === WALLET_EMAIL_OTP_TRANSACTION_SIGN_OPERATION) {
      return {
        kind: 'transaction_sign',
        action: WALLET_EMAIL_OTP_ACTIONS.login,
        operation: WALLET_EMAIL_OTP_TRANSACTION_SIGN_OPERATION,
      };
    }
    if (record.operation === WALLET_EMAIL_OTP_EXPORT_OPERATION) {
      return {
        kind: 'export_key',
        action: WALLET_EMAIL_OTP_ACTIONS.login,
        operation: WALLET_EMAIL_OTP_EXPORT_OPERATION,
      };
    }
    if (record.operation === WALLET_EMAIL_OTP_UNLOCK_OPERATION) {
      return {
        kind: 'wallet_unlock',
        action: WALLET_EMAIL_OTP_ACTIONS.login,
        operation: WALLET_EMAIL_OTP_UNLOCK_OPERATION,
      };
    }
  }
  if (
    record.action === WALLET_EMAIL_OTP_ACTIONS.deviceRecovery &&
    record.operation === WALLET_EMAIL_OTP_UNLOCK_OPERATION
  ) {
    return {
      kind: 'device_recovery',
      action: WALLET_EMAIL_OTP_ACTIONS.deviceRecovery,
      operation: WALLET_EMAIL_OTP_UNLOCK_OPERATION,
    };
  }
  return null;
}

export function emailOtpStoredChallengePurposeMatches(input: {
  expected: EmailOtpStoredChallengePurpose;
  actual: EmailOtpStoredChallengePurpose | null;
}): boolean {
  if (!input.actual) return false;
  return (
    input.actual.kind === input.expected.kind &&
    input.actual.action === input.expected.action &&
    input.actual.operation === input.expected.operation
  );
}

export function emailOtpRegistrationChallengePurposeForRecord(input: {
  storedPurpose: EmailOtpStoredChallengePurpose | null;
  allowWalletReroll: boolean;
}): EmailOtpRegistrationChallengePurpose | null {
  if (input.storedPurpose?.kind === 'registration') {
    return {
      kind: 'registration',
      action: WALLET_EMAIL_OTP_ACTIONS.registration,
      operation: WALLET_EMAIL_OTP_REGISTRATION_OPERATION,
    };
  }
  if (input.allowWalletReroll && input.storedPurpose?.kind === 'wallet_unlock') {
    return {
      kind: 'registration_reroll',
      action: WALLET_EMAIL_OTP_ACTIONS.login,
      operation: WALLET_EMAIL_OTP_UNLOCK_OPERATION,
    };
  }
  return null;
}

export function buildVerifiedEmailOtpRegistrationChallengeProof(input: {
  record: EmailOtpChallengeRecord;
  challengeSubjectId: ChallengeSubjectId;
  proof: EmailOtpRegistrationChallengeProof;
  storedPurpose: EmailOtpStoredChallengePurpose | null;
  allowWalletReroll: boolean;
}): VerifiedEmailOtpRegistrationChallengeProof | null {
  if (input.record.challengeSubjectId !== input.challengeSubjectId) return null;
  if (input.proof.challengeSubjectId !== input.challengeSubjectId) return null;
  if (String(input.proof.providerSubject) !== String(input.proof.challengeSubjectId)) return null;
  if (input.record.otpChannel !== EMAIL_OTP_CHANNEL) return null;
  if (String(input.record.orgId || '') !== input.proof.orgId) return null;
  if (input.record.appSessionVersion !== input.proof.appSessionVersion) return null;
  const purpose = emailOtpRegistrationChallengePurposeForRecord({
    storedPurpose: input.storedPurpose,
    allowWalletReroll: input.allowWalletReroll,
  });
  if (!purpose) return null;
  const proofEmail = toOptionalTrimmedString(input.proof.proofEmail)?.toLowerCase();
  const challengeEmail = toOptionalTrimmedString(input.record.email)?.toLowerCase();
  if (!proofEmail || !challengeEmail || proofEmail !== challengeEmail) return null;
  const originalWalletId = parseWalletId(input.record.walletId);
  if (!originalWalletId.ok) return null;

  switch (input.proof.kind) {
    case 'registration_attempt':
      return {
        kind: 'registration_attempt',
        providerSubject: input.proof.providerSubject,
        challengeSubjectId: input.proof.challengeSubjectId,
        challengeEmail,
        challengeId: input.proof.challengeId,
        originalWalletId: originalWalletId.value,
        finalWalletId: input.proof.finalWalletId,
        orgId: input.proof.orgId,
        appSessionVersion: input.proof.appSessionVersion,
        purpose,
        registrationAttemptId: input.proof.registrationAttemptId,
      };
    case 'direct_proof_email':
      return {
        kind: 'direct_proof_email',
        providerSubject: input.proof.providerSubject,
        challengeSubjectId: input.proof.challengeSubjectId,
        challengeEmail,
        challengeId: input.proof.challengeId,
        originalWalletId: originalWalletId.value,
        finalWalletId: input.proof.finalWalletId,
        orgId: input.proof.orgId,
        appSessionVersion: input.proof.appSessionVersion,
        purpose,
      };
  }
  return assertNever(input.proof);
}

export type EmailOtpRegistrationChallengeProofResult =
  | { ok: true; proof: EmailOtpRegistrationChallengeProof }
  | { ok: false; code: string; message: string };

export type EmailOtpRegistrationChallengeProofInput =
  | {
      kind: 'google_registration_attempt';
      providerSubject: ProviderSubject;
      challengeSubjectId: ChallengeSubjectId;
      walletId: WalletId;
      orgId: OrgId;
      appSessionVersion: AppSessionVersion;
      registrationAttemptId: EmailOtpRegistrationAttemptId;
      challengeId: EmailOtpChallengeId;
    }
  | {
      kind: 'direct_proof_email';
      providerSubject: ProviderSubject;
      challengeSubjectId: ChallengeSubjectId;
      finalWalletId: WalletId;
      orgId: OrgId;
      appSessionVersion: AppSessionVersion;
      proofEmail: string;
      challengeId: EmailOtpChallengeId;
    };

export type EmailOtpRegistrationChallengeProofInputResult =
  | { ok: true; input: EmailOtpRegistrationChallengeProofInput }
  | { ok: false; code: string; message: string };

export function parseRawEmailOtpRegistrationChallengeProofInput(request: {
  providerSubject: unknown;
  walletId: unknown;
  orgId: unknown;
  appSessionVersion: unknown;
  challengeId: unknown;
  proofEmail?: unknown;
  googleEmailOtpRegistrationAttemptId?: unknown;
}): EmailOtpRegistrationChallengeProofInputResult {
  const providerSubject = parseProviderSubject(request.providerSubject);
  if (!providerSubject.ok) {
    return {
      ok: false,
      code: 'invalid_body',
      message: 'Email OTP registration requires providerSubject',
    };
  }
  const challengeSubjectId = parseChallengeSubjectId(request.providerSubject);
  if (!challengeSubjectId.ok) {
    return {
      ok: false,
      code: 'invalid_body',
      message: 'Email OTP registration requires challengeSubjectId',
    };
  }
  const challengeId = parseEmailOtpChallengeId(request.challengeId);
  if (!challengeId.ok) {
    return {
      ok: false,
      code: 'invalid_body',
      message: 'Email OTP registration requires challengeId',
    };
  }
  const finalWalletId = parseWalletId(request.walletId);
  if (!finalWalletId.ok) {
    return {
      ok: false,
      code: 'invalid_body',
      message: 'Email OTP registration requires walletId',
    };
  }
  const orgId = parseOrgId(request.orgId);
  if (!orgId.ok) {
    return {
      ok: false,
      code: 'invalid_body',
      message: 'Email OTP registration requires orgId',
    };
  }
  const appSessionVersion = parseAppSessionVersion(request.appSessionVersion);
  if (!appSessionVersion.ok) {
    return {
      ok: false,
      code: 'invalid_body',
      message: 'Email OTP registration requires appSessionVersion',
    };
  }

  const registrationAttemptId = parseEmailOtpRegistrationAttemptId(
    request.googleEmailOtpRegistrationAttemptId,
  );
  if (registrationAttemptId.ok) {
    return {
      ok: true,
      input: {
        kind: 'google_registration_attempt',
        providerSubject: providerSubject.value,
        challengeSubjectId: challengeSubjectId.value,
        walletId: finalWalletId.value,
        orgId: orgId.value,
        appSessionVersion: appSessionVersion.value,
        registrationAttemptId: registrationAttemptId.value,
        challengeId: challengeId.value,
      },
    };
  }
  if (registrationAttemptId.error.code === 'invalid') {
    return {
      ok: false,
      code: 'invalid_body',
      message: 'googleEmailOtpRegistrationAttemptId must be a string',
    };
  }

  const proofEmail = toOptionalTrimmedString(request.proofEmail)?.toLowerCase();
  if (!proofEmail) {
    return {
      ok: false,
      code: 'invalid_body',
      message: 'Email OTP registration requires proofEmail',
    };
  }
  return {
    ok: true,
    input: {
      kind: 'direct_proof_email',
      providerSubject: providerSubject.value,
      challengeSubjectId: challengeSubjectId.value,
      finalWalletId: finalWalletId.value,
      orgId: orgId.value,
      appSessionVersion: appSessionVersion.value,
      proofEmail,
      challengeId: challengeId.value,
    },
  };
}
