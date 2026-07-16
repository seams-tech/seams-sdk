import { base64UrlDecode, base64UrlEncode } from '@shared/utils/encoders';
import {
  EMAIL_OTP_RECOVERY_KEY_COUNT,
  encodeEmailOtpRecoveryWrappedEnrollmentAad,
} from '@shared/utils/emailOtpRecoveryKey';
import { WALLET_EMAIL_OTP_ACTIONS } from '@shared/utils/emailOtpDomain';
import { parseWalletId, type WalletId } from '@shared/utils/domainIds';
import { toOptionalTrimmedString } from '@shared/utils/validation';
import type { RegistrationAuthority } from '@shared/utils/registrationIntent';
import type {
  EmailOtpAuthStateRecord,
  EmailOtpAuthStateStore,
  EmailOtpChannel,
  EmailOtpRecoveryWrappedEnrollmentEscrowBoundary,
  EmailOtpRecoveryWrappedEnrollmentEscrowRecord,
  EmailOtpRecoveryWrappedEnrollmentEscrowStore,
  EmailOtpRegistrationAttemptStore,
  EmailOtpWalletEnrollmentRecord,
  EmailOtpWalletEnrollmentStore,
} from '../EmailOtpStores';
import {
  emailOtpRecoveryWrappedEnrollmentEscrowBoundaryFromRecord,
  parseEmailOtpRecoveryWrappedEnrollmentEscrowBoundary,
} from '../EmailOtpStores';
import type { IdentityStore } from '../IdentityStore';
import type { WalletStore } from '../WalletStore';
import type {
  WalletRegistrationFinalizeRequest
} from '../registrationContracts';
import { validateSecp256k1PublicKey33 } from '../ThresholdService/evmCryptoWasm';
import { sha256BytesPortable } from './portableCrypto';
import {
  parseRawEmailOtpRegistrationChallengeProofInput,
  type EmailOtpRegistrationChallengeProofInput,
  type EmailOtpRegistrationChallengeProofResult,
  type EmailOtpRegistrationEnrollmentPersistence,
  type VerifiedEmailOtpChallengeCodeResult,
} from './emailOtpChallengeProof';
import { completeGoogleEmailOtpRegistrationAttemptWithStore } from './googleEmailOtpRegistration';
import type { VerifyEmailOtpChallengeCodeRequest } from './emailOtpChallengeVerification';

function assertNever(value: never): never {
  throw new Error(`Unexpected value: ${String(value)}`);
}

export type EmailOtpEnrollmentMaterialValidationResult =
  | {
      ok: true;
      recoveryWrappedEnrollmentEscrows: EmailOtpRecoveryWrappedEnrollmentEscrowRecord[];
      enrollmentSealKeyVersion: string;
      clientUnlockPublicKeyB64u: string;
      unlockKeyVersion: string;
      thresholdEcdsaClientVerifyingShareB64u: string;
    }
  | { ok: false; code: string; message: string };

export type VerifyEmailOtpEnrollmentInput = {
  request: VerifyEmailOtpEnrollmentRequest;
  walletStore: WalletStore;
  walletEnrollmentStore: EmailOtpWalletEnrollmentStore;
  authStateStore: EmailOtpAuthStateStore;
  recoveryWrappedEnrollmentEscrowStore: EmailOtpRecoveryWrappedEnrollmentEscrowStore;
  registrationAttemptStore: EmailOtpRegistrationAttemptStore;
  identityStore: IdentityStore;
  verifyChallengeCode: (
    request: VerifyEmailOtpChallengeCodeRequest,
  ) => Promise<VerifiedEmailOtpChallengeCodeResult>;
};

export type VerifyEmailOtpEnrollmentRequest = {
  providerSubject: unknown;
  walletId: unknown;
  orgId: unknown;
  challengeId: unknown;
  otpCode: unknown;
  otpChannel: unknown;
  sessionHash: unknown;
  appSessionVersion: unknown;
  proofEmail?: unknown;
  clientIp?: unknown;
  recoveryWrappedEnrollmentEscrows?: unknown;
  enrollmentSealKeyVersion?: unknown;
  clientUnlockPublicKeyB64u?: unknown;
  unlockKeyVersion?: unknown;
  thresholdEcdsaClientVerifyingShareB64u?: unknown;
  googleEmailOtpRegistrationAttemptId?: unknown;
};

export async function validateEmailOtpEnrollmentMaterial(request: {
  recoveryWrappedEnrollmentEscrows?: unknown;
  enrollmentSealKeyVersion?: unknown;
  clientUnlockPublicKeyB64u?: unknown;
  unlockKeyVersion?: unknown;
  thresholdEcdsaClientVerifyingShareB64u?: unknown;
}): Promise<
  | {
      ok: true;
      recoveryWrappedEnrollmentEscrows: EmailOtpRecoveryWrappedEnrollmentEscrowRecord[];
      enrollmentSealKeyVersion: string;
      clientUnlockPublicKeyB64u: string;
      unlockKeyVersion: string;
      thresholdEcdsaClientVerifyingShareB64u: string;
    }
  | { ok: false; code: string; message: string }
> {
  const enrollmentSealKeyVersion = toOptionalTrimmedString(request.enrollmentSealKeyVersion);
  const rawRecoveryWrappedEnrollmentEscrows = Array.isArray(
    request.recoveryWrappedEnrollmentEscrows,
  )
    ? request.recoveryWrappedEnrollmentEscrows
    : [];
  const parsedRecoveryWrappedEnrollmentEscrows = rawRecoveryWrappedEnrollmentEscrows
    .map((record) => parseEmailOtpRecoveryWrappedEnrollmentEscrowBoundary(record))
    .filter((record): record is EmailOtpRecoveryWrappedEnrollmentEscrowBoundary =>
      Boolean(record),
    );
  const recoveryWrappedEnrollmentEscrows = parsedRecoveryWrappedEnrollmentEscrows.map(
    (parsed) => parsed.record,
  );
  const clientUnlockPublicKeyB64u = toOptionalTrimmedString(request.clientUnlockPublicKeyB64u);
  const unlockKeyVersion = toOptionalTrimmedString(request.unlockKeyVersion);
  const thresholdEcdsaClientVerifyingShareB64u = toOptionalTrimmedString(
    request.thresholdEcdsaClientVerifyingShareB64u,
  );
  if (
    rawRecoveryWrappedEnrollmentEscrows.length !== EMAIL_OTP_RECOVERY_KEY_COUNT ||
    recoveryWrappedEnrollmentEscrows.length !== EMAIL_OTP_RECOVERY_KEY_COUNT
  ) {
    return {
      ok: false,
      code: 'invalid_body',
      message: `Exactly ${EMAIL_OTP_RECOVERY_KEY_COUNT} recovery-wrapped enrollment escrows are required`,
    };
  }
  if (!enrollmentSealKeyVersion) {
    return {
      ok: false,
      code: 'invalid_body',
      message: 'enrollmentSealKeyVersion is required',
    };
  }
  const escrowSetValidation = await validateEmailOtpRecoveryWrappedEnrollmentEscrowSet(
    parsedRecoveryWrappedEnrollmentEscrows,
  );
  if (!escrowSetValidation.ok) return escrowSetValidation;
  if (!clientUnlockPublicKeyB64u) {
    return { ok: false, code: 'invalid_body', message: 'clientUnlockPublicKeyB64u is required' };
  }
  if (!unlockKeyVersion) {
    return { ok: false, code: 'invalid_body', message: 'unlockKeyVersion is required' };
  }
  if (!thresholdEcdsaClientVerifyingShareB64u) {
    return {
      ok: false,
      code: 'invalid_body',
      message: 'thresholdEcdsaClientVerifyingShareB64u is required',
    };
  }

  let unlockPublicKeyBytes: Uint8Array;
  try {
    unlockPublicKeyBytes = base64UrlDecode(clientUnlockPublicKeyB64u);
  } catch {
    return {
      ok: false,
      code: 'invalid_body',
      message: 'clientUnlockPublicKeyB64u must be valid base64url',
    };
  }
  if (unlockPublicKeyBytes.length !== 33) {
    return {
      ok: false,
      code: 'invalid_body',
      message: 'clientUnlockPublicKeyB64u must decode to 33 bytes (compressed secp256k1 pubkey)',
    };
  }
  try {
    await validateSecp256k1PublicKey33(unlockPublicKeyBytes);
  } catch {
    return {
      ok: false,
      code: 'invalid_body',
      message: 'clientUnlockPublicKeyB64u is not a valid secp256k1 public key',
    };
  }

  let clientVerifyingShareBytes: Uint8Array;
  try {
    clientVerifyingShareBytes = base64UrlDecode(thresholdEcdsaClientVerifyingShareB64u);
  } catch {
    return {
      ok: false,
      code: 'invalid_body',
      message: 'thresholdEcdsaClientVerifyingShareB64u must be valid base64url',
    };
  }
  if (clientVerifyingShareBytes.length !== 33) {
    return {
      ok: false,
      code: 'invalid_body',
      message:
        'thresholdEcdsaClientVerifyingShareB64u must decode to 33 bytes (compressed secp256k1 pubkey)',
    };
  }
  try {
    await validateSecp256k1PublicKey33(clientVerifyingShareBytes);
  } catch {
    return {
      ok: false,
      code: 'invalid_body',
      message: 'thresholdEcdsaClientVerifyingShareB64u is not a valid secp256k1 public key',
    };
  }

  return {
    ok: true,
    recoveryWrappedEnrollmentEscrows,
    enrollmentSealKeyVersion,
    clientUnlockPublicKeyB64u,
    unlockKeyVersion,
    thresholdEcdsaClientVerifyingShareB64u,
  };
}

export async function validateEmailOtpRecoveryWrappedEnrollmentEscrowSet(
  records: EmailOtpRecoveryWrappedEnrollmentEscrowBoundary[],
): Promise<{ ok: true } | { ok: false; code: string; message: string }> {
  const recoveryKeyIds = new Set<string>();
  const nonceB64us = new Set<string>();
  const first = records[0];
  if (!first) {
    return {
      ok: false,
      code: 'invalid_body',
      message: `Exactly ${EMAIL_OTP_RECOVERY_KEY_COUNT} recovery-wrapped enrollment escrows are required`,
    };
  }

  for (const boundary of records) {
    if (boundary.lifecycle.status !== 'active') {
      return {
        ok: false,
        code: 'invalid_body',
        message: 'Recovery-wrapped enrollment escrows must be active at enrollment',
      };
    }
    const record = boundary.record;
    if (recoveryKeyIds.has(record.recoveryKeyId)) {
      return {
        ok: false,
        code: 'invalid_body',
        message: 'Recovery-wrapped enrollment escrow recoveryKeyId values must be unique',
      };
    }
    recoveryKeyIds.add(record.recoveryKeyId);

    if (nonceB64us.has(record.nonceB64u)) {
      return {
        ok: false,
        code: 'invalid_body',
        message: 'Recovery-wrapped enrollment escrow nonce values must be unique',
      };
    }
    nonceB64us.add(record.nonceB64u);

    if (
      record.walletId !== first.record.walletId ||
      record.userId !== first.record.userId ||
      record.authSubjectId !== first.record.authSubjectId ||
      record.authMethod !== first.record.authMethod ||
      record.enrollmentId !== first.record.enrollmentId ||
      record.enrollmentVersion !== first.record.enrollmentVersion ||
      record.enrollmentSealKeyVersion !== first.record.enrollmentSealKeyVersion ||
      record.signingRootId !== first.record.signingRootId ||
      record.signingRootVersion !== first.record.signingRootVersion
    ) {
      return {
        ok: false,
        code: 'invalid_body',
        message: 'Recovery-wrapped enrollment escrow metadata must share one enrollment scope',
      };
    }

    const expectedAadHashB64u = base64UrlEncode(
      await sha256BytesPortable(encodeEmailOtpRecoveryWrappedEnrollmentAad(boundary.binding)),
    );
    if (record.aadHashB64u !== expectedAadHashB64u) {
      return {
        ok: false,
        code: 'invalid_body',
        message: 'Recovery-wrapped enrollment escrow aadHashB64u does not match metadata',
      };
    }
  }

  if (
    recoveryKeyIds.size !== EMAIL_OTP_RECOVERY_KEY_COUNT ||
    nonceB64us.size !== EMAIL_OTP_RECOVERY_KEY_COUNT
  ) {
    return {
      ok: false,
      code: 'invalid_body',
      message: `Exactly ${EMAIL_OTP_RECOVERY_KEY_COUNT} distinct recovery-wrapped enrollment escrows are required`,
    };
  }

  return { ok: true };
}

export function emailOtpRecoveryEscrowMatchesEnrollment(
  boundary: EmailOtpRecoveryWrappedEnrollmentEscrowBoundary,
  enrollment: EmailOtpWalletEnrollmentRecord,
): boolean {
  const { auth, enrollment: bindingEnrollment, signingRoot } = boundary.binding;
  return (
    auth.walletId === enrollment.walletId &&
    auth.userId === enrollment.providerUserId &&
    auth.authSubjectId === enrollment.providerUserId &&
    bindingEnrollment.enrollmentId === enrollment.enrollmentId &&
    bindingEnrollment.enrollmentVersion === enrollment.enrollmentVersion &&
    bindingEnrollment.enrollmentSealKeyVersion === enrollment.enrollmentSealKeyVersion &&
    signingRoot.signingRootId === enrollment.signingRootId &&
    signingRoot.signingRootVersion === enrollment.signingRootVersion
  );
}

export async function buildEmailOtpRegistrationEnrollmentPersistence(input: {
  walletEnrollmentStore: EmailOtpWalletEnrollmentStore;
  authStateStore: EmailOtpAuthStateStore;
  walletId: string;
  orgId: string;
  authSubjectId: string;
  verifiedEmail: string;
  material: NonNullable<WalletRegistrationFinalizeRequest['emailOtpEnrollment']>;
  nowMs: number;
}): Promise<
  | { ok: true; persistence: EmailOtpRegistrationEnrollmentPersistence }
  | { ok: false; code: string; message: string }
> {
  const enrollmentMaterial = await validateEmailOtpEnrollmentMaterial(input.material);
  if (!enrollmentMaterial.ok) return enrollmentMaterial;
  const orgId = toOptionalTrimmedString(input.orgId) || '';
  const walletId = toOptionalTrimmedString(input.walletId) || '';
  const authSubjectId = toOptionalTrimmedString(input.authSubjectId) || '';
  const verifiedEmail = toOptionalTrimmedString(input.verifiedEmail)?.toLowerCase() || '';
  if (!orgId || !walletId || !authSubjectId || !verifiedEmail) {
    return {
      ok: false,
      code: 'invalid_body',
      message: 'Email OTP registration enrollment requires wallet, org, and email identity',
    };
  }
  const existing = await input.walletEnrollmentStore.get(walletId);
  const existingState = await input.authStateStore.get(walletId);
  const enrollmentScope = enrollmentMaterial.recoveryWrappedEnrollmentEscrows[0];
  if (!enrollmentScope) {
    return {
      ok: false,
      code: 'invalid_body',
      message: `Exactly ${EMAIL_OTP_RECOVERY_KEY_COUNT} recovery-wrapped enrollment escrows are required`,
    };
  }
  for (const record of enrollmentMaterial.recoveryWrappedEnrollmentEscrows) {
    if (
      record.walletId !== walletId ||
      record.userId !== authSubjectId ||
      record.authSubjectId !== authSubjectId ||
      record.enrollmentSealKeyVersion !== enrollmentMaterial.enrollmentSealKeyVersion ||
      record.recoveryKeyStatus !== 'active'
    ) {
      return {
        ok: false,
        code: 'invalid_body',
        message: 'Recovery-wrapped enrollment escrow metadata does not match registration',
      };
    }
  }
  const enrollment: EmailOtpWalletEnrollmentRecord = {
    version: 'email_otp_wallet_enrollment_v1',
    walletId,
    providerUserId: authSubjectId,
    orgId,
    verifiedEmail,
    enrollmentId: enrollmentScope.enrollmentId,
    enrollmentVersion: enrollmentScope.enrollmentVersion,
    enrollmentSealKeyVersion: enrollmentMaterial.enrollmentSealKeyVersion,
    signingRootId: enrollmentScope.signingRootId,
    signingRootVersion: enrollmentScope.signingRootVersion,
    recoveryWrappedEnrollmentEscrowCount:
      enrollmentMaterial.recoveryWrappedEnrollmentEscrows.length,
    clientUnlockPublicKeyB64u: enrollmentMaterial.clientUnlockPublicKeyB64u,
    unlockKeyVersion: enrollmentMaterial.unlockKeyVersion,
    thresholdEcdsaClientVerifyingShareB64u:
      enrollmentMaterial.thresholdEcdsaClientVerifyingShareB64u,
    createdAtMs: existing?.createdAtMs ?? input.nowMs,
    updatedAtMs: input.nowMs,
  };
  const existingProviderEnrollment =
    await input.walletEnrollmentStore.getByProviderUserId({
      providerUserId: enrollment.providerUserId,
      orgId: enrollment.orgId,
    });
  const recoveryWrappedEnrollmentEscrows =
    enrollmentMaterial.recoveryWrappedEnrollmentEscrows.map((record) => ({
      ...record,
      updatedAtMs: input.nowMs,
    }));
  const authState: EmailOtpAuthStateRecord = {
    version: 'email_otp_auth_state_v1',
    walletId: enrollment.walletId,
    providerUserId: enrollment.providerUserId,
    orgId: enrollment.orgId,
    createdAtMs:
      existingState &&
      existingState.providerUserId === enrollment.providerUserId &&
      existingState.orgId === enrollment.orgId
        ? existingState.createdAtMs
        : input.nowMs,
    updatedAtMs: input.nowMs,
    otpFailureCount: 0,
    lastOtpFailureAtMs: undefined,
    otpLockedUntilMs: undefined,
    ...(existingState?.lastEmailOtpLoginAtMs &&
    existingState.providerUserId === enrollment.providerUserId &&
    existingState.orgId === enrollment.orgId
      ? { lastEmailOtpLoginAtMs: existingState.lastEmailOtpLoginAtMs }
      : {}),
    ...(existingState?.lastStrongAuthAtMs &&
    existingState.providerUserId === enrollment.providerUserId &&
    existingState.orgId === enrollment.orgId
      ? { lastStrongAuthAtMs: existingState.lastStrongAuthAtMs }
      : {}),
  };
  return {
    ok: true,
    persistence: {
      ...(existingProviderEnrollment &&
      existingProviderEnrollment.walletId !== enrollment.walletId
        ? { previousProviderWalletId: existingProviderEnrollment.walletId }
        : {}),
      enrollment,
      recoveryWrappedEnrollmentEscrows,
      authState,
    },
  };
}

export async function emailOtpEnrollmentPersistenceForRegistrationFinalize(input: {
  walletEnrollmentStore: EmailOtpWalletEnrollmentStore;
  authStateStore: EmailOtpAuthStateStore;
  authority: RegistrationAuthority;
  request: WalletRegistrationFinalizeRequest;
  walletId: WalletId;
  orgId: string;
  nowMs: number;
}): Promise<
  | { ok: true; persistence?: EmailOtpRegistrationEnrollmentPersistence }
  | { ok: false; code: string; message: string }
> {
  if (input.authority.kind !== 'email_otp') {
    if (input.request.emailOtpEnrollment) {
      return {
        ok: false,
        code: 'invalid_body',
        message: 'emailOtpEnrollment is only valid for Email OTP registration',
      };
    }
    return { ok: true };
  }
  if (!input.request.emailOtpEnrollment) {
    return {
      ok: false,
      code: 'invalid_body',
      message: 'Email OTP registration finalize requires emailOtpEnrollment',
    };
  }
  const backupAck = input.request.emailOtpBackupAck;
  if (!backupAck) {
    return {
      ok: false,
      code: 'invalid_body',
      message: 'Email OTP registration finalize requires emailOtpBackupAck',
    };
  }
  if (
    input.authority.walletId !== input.walletId ||
    input.authority.finalWalletId !== input.walletId ||
    input.authority.orgId !== input.orgId
  ) {
    return {
      ok: false,
      code: 'authority_binding_mismatch',
      message: 'Email OTP registration authority does not match finalize scope',
    };
  }
  if (
    input.authority.proofKind === 'google_sso_registration' &&
    (backupAck.offerId !== input.authority.googleEmailOtpRegistrationOfferId ||
      backupAck.candidateId !== input.authority.googleEmailOtpRegistrationCandidateId)
  ) {
    return {
      ok: false,
      code: 'backup_ack_binding_mismatch',
      message: 'Email OTP recovery-code backup acknowledgement does not match the offer',
    };
  }
  if (
    input.authority.proofKind !== 'google_sso_registration' &&
    (backupAck.offerId || backupAck.candidateId)
  ) {
    return {
      ok: false,
      code: 'backup_ack_binding_mismatch',
      message: 'Email OTP recovery-code backup acknowledgement has unexpected offer metadata',
    };
  }
  if (backupAck.acknowledgedAtMs < backupAck.recoveryCodesIssuedAtMs) {
    return {
      ok: false,
      code: 'backup_ack_invalid',
      message: 'Email OTP recovery-code backup acknowledgement predates code issuance',
    };
  }
  const authSubjectId = toOptionalTrimmedString(input.authority.providerSubject) || '';
  const verifiedEmail = toOptionalTrimmedString(input.authority.email)?.toLowerCase() || '';
  const enrollment = await buildEmailOtpRegistrationEnrollmentPersistence({
    walletEnrollmentStore: input.walletEnrollmentStore,
    authStateStore: input.authStateStore,
    walletId: input.walletId,
    orgId: input.orgId,
    authSubjectId,
    verifiedEmail,
    material: input.request.emailOtpEnrollment,
    nowMs: input.nowMs,
  });
  if (!enrollment.ok) return enrollment;
  const firstEscrow = enrollment.persistence.recoveryWrappedEnrollmentEscrows[0];
  if (!firstEscrow || firstEscrow.issuedAtMs !== backupAck.recoveryCodesIssuedAtMs) {
    return {
      ok: false,
      code: 'backup_ack_binding_mismatch',
      message:
        'Email OTP recovery-code backup acknowledgement timestamp does not match enrollment',
    };
  }
  return { ok: true, persistence: enrollment.persistence };
}

export async function resolveEmailOtpRegistrationChallengeProof(input: {
  proofInput: EmailOtpRegistrationChallengeProofInput;
  registrationAttemptStore: EmailOtpRegistrationAttemptStore;
  nowMs: number;
}): Promise<EmailOtpRegistrationChallengeProofResult> {
  const proofInput = input.proofInput;
  switch (proofInput.kind) {
    case 'google_registration_attempt': {
      const attempt = await input.registrationAttemptStore.get(
        proofInput.registrationAttemptId,
      );
      if (!attempt) {
        return {
          ok: false,
          code: 'registration_attempt_missing',
          message: 'Google Email OTP registration attempt expired or was not found',
        };
      }
      if (attempt.providerSubject !== proofInput.providerSubject) {
        return {
          ok: false,
          code: 'challenge_subject_mismatch',
          message: 'Email OTP registration attempt does not match the provider subject',
        };
      }
      if (attempt.expiresAtMs <= input.nowMs) {
        return {
          ok: false,
          code: 'registration_attempt_expired',
          message: 'Google Email OTP registration attempt expired',
        };
      }
      if (attempt.walletId !== proofInput.walletId) {
        return {
          ok: false,
          code: 'wallet_identity_mismatch',
          message: 'registrationAttemptId does not match walletId',
        };
      }
      return {
        ok: true,
        proof: {
          kind: 'registration_attempt',
          providerSubject: proofInput.providerSubject,
          challengeSubjectId: proofInput.challengeSubjectId,
          proofEmail: attempt.email.toLowerCase(),
          registrationAttemptId: proofInput.registrationAttemptId,
          challengeId: proofInput.challengeId,
          finalWalletId: proofInput.walletId,
          orgId: proofInput.orgId,
          appSessionVersion: proofInput.appSessionVersion,
        },
      };
    }
    case 'direct_proof_email':
      return {
        ok: true,
        proof: {
          kind: 'direct_proof_email',
          providerSubject: proofInput.providerSubject,
          challengeSubjectId: proofInput.challengeSubjectId,
          proofEmail: proofInput.proofEmail,
          challengeId: proofInput.challengeId,
          finalWalletId: proofInput.finalWalletId,
          orgId: proofInput.orgId,
          appSessionVersion: proofInput.appSessionVersion,
        },
      };
  }
  return assertNever(proofInput);
}

export async function verifyEmailOtpEnrollment(
  input: VerifyEmailOtpEnrollmentInput,
): Promise<
  | {
      ok: true;
      walletId: string;
      otpChannel: EmailOtpChannel;
      enrollment: {
        createdAtMs: number;
        updatedAtMs: number;
        enrollmentSealKeyVersion: string;
        unlockKeyVersion: string;
      };
    }
  | {
      ok: false;
      code: string;
      message: string;
      attemptsRemaining?: number;
      lockedUntilMs?: number;
    }
> {
  const request = input.request;
  const proofInput = parseRawEmailOtpRegistrationChallengeProofInput(request);
  if (!proofInput.ok) return proofInput;
  const proofResult = await resolveEmailOtpRegistrationChallengeProof({
    proofInput: proofInput.input,
    registrationAttemptStore: input.registrationAttemptStore,
    nowMs: Date.now(),
  });
  if (!proofResult.ok) return proofResult;
  const verified = await input.verifyChallengeCode({
    ...request,
    challengeSubjectId: proofResult.proof.challengeSubjectId,
    registrationChallengeProof: proofResult.proof,
    allowRegistrationChallengeReroll: true,
    expectedAction: WALLET_EMAIL_OTP_ACTIONS.registration,
  });
  if (!verified.ok) return verified;
  const verifiedEmail = toOptionalTrimmedString(verified.email)?.toLowerCase();
  if (!verifiedEmail) {
    return {
      ok: false,
      code: 'internal',
      message: 'Email OTP enrollment verification did not include a verified email',
    };
  }
  const enrollmentMaterial = await validateEmailOtpEnrollmentMaterial(request);
  if (!enrollmentMaterial.ok) return enrollmentMaterial;
  const orgId = toOptionalTrimmedString(verified.orgId) || '';
  if (!orgId) {
    return {
      ok: false,
      code: 'invalid_body',
      message: 'Email OTP enrollment requires orgId tenant scope',
    };
  }
  const verifiedWalletId = parseWalletId(verified.walletId);
  if (!verifiedWalletId.ok) {
    return {
      ok: false,
      code: 'invalid_body',
      message: 'Email OTP enrollment verification returned an invalid walletId',
    };
  }
  const canonicalWallet = await input.walletStore.getWallet({
    walletId: verifiedWalletId.value,
  });
  if (!canonicalWallet) {
    return {
      ok: false,
      code: 'wallet_registration_incomplete',
      message:
        'Email OTP enrollment requires an existing canonical wallet. New wallet registration must finalize through /wallets/register/finalize.',
    };
  }
  const existing = await input.walletEnrollmentStore.get(verified.walletId);
  const existingState = await input.authStateStore.get(verified.walletId);
  const nowMs = Date.now();
  const enrollmentScope = enrollmentMaterial.recoveryWrappedEnrollmentEscrows[0];
  if (!enrollmentScope) {
    return {
      ok: false,
      code: 'invalid_body',
      message: `Exactly ${EMAIL_OTP_RECOVERY_KEY_COUNT} recovery-wrapped enrollment escrows are required`,
    };
  }
  for (const record of enrollmentMaterial.recoveryWrappedEnrollmentEscrows) {
    if (
      record.walletId !== verified.walletId ||
      record.userId !== verified.challengeSubjectId ||
      record.authSubjectId !== verified.challengeSubjectId ||
      record.enrollmentSealKeyVersion !== enrollmentMaterial.enrollmentSealKeyVersion ||
      record.recoveryKeyStatus !== 'active'
    ) {
      return {
        ok: false,
        code: 'invalid_body',
        message: 'Recovery-wrapped enrollment escrow metadata does not match enrollment',
      };
    }
  }
  const enrollmentRecord: EmailOtpWalletEnrollmentRecord = {
    version: 'email_otp_wallet_enrollment_v1',
    walletId: verified.walletId,
    providerUserId: verified.challengeSubjectId,
    orgId,
    verifiedEmail,
    enrollmentId: enrollmentScope.enrollmentId,
    enrollmentVersion: enrollmentScope.enrollmentVersion,
    enrollmentSealKeyVersion: enrollmentMaterial.enrollmentSealKeyVersion,
    signingRootId: enrollmentScope.signingRootId,
    signingRootVersion: enrollmentScope.signingRootVersion,
    recoveryWrappedEnrollmentEscrowCount:
      enrollmentMaterial.recoveryWrappedEnrollmentEscrows.length,
    clientUnlockPublicKeyB64u: enrollmentMaterial.clientUnlockPublicKeyB64u,
    unlockKeyVersion: enrollmentMaterial.unlockKeyVersion,
    thresholdEcdsaClientVerifyingShareB64u:
      enrollmentMaterial.thresholdEcdsaClientVerifyingShareB64u,
    createdAtMs: existing?.createdAtMs ?? nowMs,
    updatedAtMs: nowMs,
  };
  const existingProviderEnrollment =
    await input.walletEnrollmentStore.getByProviderUserId({
      providerUserId: enrollmentRecord.providerUserId,
      orgId: enrollmentRecord.orgId,
    });
  if (
    existingProviderEnrollment &&
    existingProviderEnrollment.walletId !== enrollmentRecord.walletId
  ) {
    await input.walletEnrollmentStore.del(existingProviderEnrollment.walletId);
  }
  await input.walletEnrollmentStore.put(enrollmentRecord);
  const recoveryWrappedEnrollmentEscrowStore = input.recoveryWrappedEnrollmentEscrowStore;
  await recoveryWrappedEnrollmentEscrowStore.putMany(
    enrollmentMaterial.recoveryWrappedEnrollmentEscrows.map((record) => ({
      ...record,
      updatedAtMs: nowMs,
    })),
  );
  const activeRecoveryWrappedEnrollmentEscrowCount = (
    await recoveryWrappedEnrollmentEscrowStore.listByWallet(verified.walletId)
  ).filter(
    (record) =>
      record.recoveryKeyStatus === 'active' &&
      emailOtpRecoveryEscrowMatchesEnrollment(
        emailOtpRecoveryWrappedEnrollmentEscrowBoundaryFromRecord(record),
        enrollmentRecord,
      ),
  ).length;
  if (activeRecoveryWrappedEnrollmentEscrowCount !== EMAIL_OTP_RECOVERY_KEY_COUNT) {
    return {
      ok: false,
      code: 'internal',
      message: `Email OTP enrollment persisted ${activeRecoveryWrappedEnrollmentEscrowCount} active recovery-wrapped escrows; expected ${EMAIL_OTP_RECOVERY_KEY_COUNT}`,
    };
  }
  await input.authStateStore.put({
    version: 'email_otp_auth_state_v1',
    walletId: enrollmentRecord.walletId,
    providerUserId: enrollmentRecord.providerUserId,
    orgId: enrollmentRecord.orgId,
    createdAtMs:
      existingState &&
      existingState.providerUserId === enrollmentRecord.providerUserId &&
      existingState.orgId === enrollmentRecord.orgId
        ? existingState.createdAtMs
        : nowMs,
    updatedAtMs: nowMs,
    otpFailureCount: 0,
    lastOtpFailureAtMs: undefined,
    otpLockedUntilMs: undefined,
    ...(existingState?.lastEmailOtpLoginAtMs &&
    existingState.providerUserId === enrollmentRecord.providerUserId &&
    existingState.orgId === enrollmentRecord.orgId
      ? { lastEmailOtpLoginAtMs: existingState.lastEmailOtpLoginAtMs }
      : {}),
    ...(existingState?.lastStrongAuthAtMs &&
    existingState.providerUserId === enrollmentRecord.providerUserId &&
    existingState.orgId === enrollmentRecord.orgId
      ? { lastStrongAuthAtMs: existingState.lastStrongAuthAtMs }
      : {}),
  });
  const completedRegistration = await completeGoogleEmailOtpRegistrationAttemptWithStore({
    registrationAttemptStore: input.registrationAttemptStore,
    identityStore: input.identityStore,
    nowMs: Date.now(),
    registrationAttemptId: request.googleEmailOtpRegistrationAttemptId,
    walletId: verified.walletId,
  });
  if (!completedRegistration.ok) return completedRegistration;
  return {
    ok: true,
    walletId: verified.walletId,
    otpChannel: verified.otpChannel,
    enrollment: {
      createdAtMs: existing?.createdAtMs ?? nowMs,
      updatedAtMs: nowMs,
      enrollmentSealKeyVersion: enrollmentMaterial.enrollmentSealKeyVersion,
      unlockKeyVersion: enrollmentMaterial.unlockKeyVersion,
    },
  };
}
