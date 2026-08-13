import { base64UrlDecode } from '@shared/utils/encoders';
import {
  EMAIL_OTP_INITIAL_ENROLLMENT_VERSION,
  emailOtpDeviceEnrollmentId,
  WALLET_EMAIL_OTP_ACTIONS,
} from '@shared/utils/emailOtpDomain';
import { parseWalletId, type WalletId } from '@shared/utils/domainIds';
import { toOptionalTrimmedString } from '@shared/utils/validation';
import type { RegistrationAuthority } from '@shared/utils/registrationIntent';
import type {
  EmailOtpAuthStateRecord,
  EmailOtpAuthStateStore,
  EmailOtpChannel,
  EmailOtpRegistrationAttemptStore,
  EmailOtpWalletEnrollmentRecord,
  EmailOtpWalletEnrollmentStore,
} from '../EmailOtpStores';
import type { IdentityStore } from '../IdentityStore';
import type { WalletStore } from '../WalletStore';
import type { WalletRegistrationFinalizeRequest } from '../registrationContracts';
import { validateSecp256k1PublicKey33 } from '../ThresholdService/evmCryptoWasm';
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
      enrollmentSealKeyVersion: string;
      serverSealedFactorCiphertextB64u: string;
      clientUnlockPublicKeyB64u: string;
      unlockKeyVersion: string;
    }
  | { ok: false; code: string; message: string };

export type VerifyEmailOtpEnrollmentInput = {
  request: VerifyEmailOtpEnrollmentRequest;
  walletStore: WalletStore;
  walletEnrollmentStore: EmailOtpWalletEnrollmentStore;
  authStateStore: EmailOtpAuthStateStore;
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
  enrollmentSealKeyVersion?: unknown;
  serverSealedFactorCiphertextB64u?: unknown;
  clientUnlockPublicKeyB64u?: unknown;
  unlockKeyVersion?: unknown;
  googleEmailOtpRegistrationAttemptId?: unknown;
};

export async function validateEmailOtpEnrollmentMaterial(request: {
  enrollmentSealKeyVersion?: unknown;
  clientUnlockPublicKeyB64u?: unknown;
  unlockKeyVersion?: unknown;
  serverSealedFactorCiphertextB64u?: unknown;
}): Promise<
  | {
      ok: true;
      enrollmentSealKeyVersion: string;
      clientUnlockPublicKeyB64u: string;
      unlockKeyVersion: string;
      serverSealedFactorCiphertextB64u: string;
    }
  | { ok: false; code: string; message: string }
> {
  const enrollmentSealKeyVersion = toOptionalTrimmedString(request.enrollmentSealKeyVersion);
  const clientUnlockPublicKeyB64u = toOptionalTrimmedString(request.clientUnlockPublicKeyB64u);
  const unlockKeyVersion = toOptionalTrimmedString(request.unlockKeyVersion);
  const serverSealedFactorCiphertextB64u = toOptionalTrimmedString(
    request.serverSealedFactorCiphertextB64u,
  );
  if (!enrollmentSealKeyVersion) {
    return {
      ok: false,
      code: 'invalid_body',
      message: 'enrollmentSealKeyVersion is required',
    };
  }
  if (!clientUnlockPublicKeyB64u) {
    return { ok: false, code: 'invalid_body', message: 'clientUnlockPublicKeyB64u is required' };
  }
  if (!unlockKeyVersion) {
    return { ok: false, code: 'invalid_body', message: 'unlockKeyVersion is required' };
  }
  if (!serverSealedFactorCiphertextB64u) {
    return {
      ok: false,
      code: 'invalid_body',
      message: 'serverSealedFactorCiphertextB64u is required',
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

  return {
    ok: true,
    enrollmentSealKeyVersion,
    clientUnlockPublicKeyB64u,
    unlockKeyVersion,
    serverSealedFactorCiphertextB64u,
  };
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
  const enrollment: EmailOtpWalletEnrollmentRecord = {
    version: 'email_otp_wallet_enrollment_v1',
    walletId,
    providerUserId: authSubjectId,
    orgId,
    verifiedEmail,
    enrollmentId: emailOtpDeviceEnrollmentId(walletId, authSubjectId),
    enrollmentVersion: EMAIL_OTP_INITIAL_ENROLLMENT_VERSION,
    enrollmentSealKeyVersion: enrollmentMaterial.enrollmentSealKeyVersion,
    serverSealedFactorCiphertextB64u: enrollmentMaterial.serverSealedFactorCiphertextB64u,
    clientUnlockPublicKeyB64u: enrollmentMaterial.clientUnlockPublicKeyB64u,
    unlockKeyVersion: enrollmentMaterial.unlockKeyVersion,
    createdAtMs: existing?.createdAtMs ?? input.nowMs,
    updatedAtMs: input.nowMs,
  };
  const existingProviderEnrollment = await input.walletEnrollmentStore.getByProviderUserId({
    providerUserId: enrollment.providerUserId,
    orgId: enrollment.orgId,
  });
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
      ...(existingProviderEnrollment && existingProviderEnrollment.walletId !== enrollment.walletId
        ? { previousProviderWalletId: existingProviderEnrollment.walletId }
        : {}),
      enrollment,
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
      const attempt = await input.registrationAttemptStore.get(proofInput.registrationAttemptId);
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

export async function verifyEmailOtpEnrollment(input: VerifyEmailOtpEnrollmentInput): Promise<
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
        'Email OTP enrollment requires a canonical wallet created by /wallets/register/activate.',
    };
  }
  const existing = await input.walletEnrollmentStore.get(verified.walletId);
  const existingState = await input.authStateStore.get(verified.walletId);
  const nowMs = Date.now();
  const enrollmentRecord: EmailOtpWalletEnrollmentRecord = {
    version: 'email_otp_wallet_enrollment_v1',
    walletId: verified.walletId,
    providerUserId: verified.challengeSubjectId,
    orgId,
    verifiedEmail,
    enrollmentId: emailOtpDeviceEnrollmentId(verified.walletId, verified.challengeSubjectId),
    enrollmentVersion: EMAIL_OTP_INITIAL_ENROLLMENT_VERSION,
    enrollmentSealKeyVersion: enrollmentMaterial.enrollmentSealKeyVersion,
    serverSealedFactorCiphertextB64u: enrollmentMaterial.serverSealedFactorCiphertextB64u,
    clientUnlockPublicKeyB64u: enrollmentMaterial.clientUnlockPublicKeyB64u,
    unlockKeyVersion: enrollmentMaterial.unlockKeyVersion,
    createdAtMs: existing?.createdAtMs ?? nowMs,
    updatedAtMs: nowMs,
  };
  const existingProviderEnrollment = await input.walletEnrollmentStore.getByProviderUserId({
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
