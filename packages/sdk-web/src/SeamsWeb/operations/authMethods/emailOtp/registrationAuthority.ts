import { EMAIL_OTP_CHANNEL } from '@shared/utils/emailOtpDomain';
import type {
  EmailOtpRegistrationAuthMethodInput,
  EmailOtpRegistrationProof,
} from '@shared/utils/registrationIntent';
import { decodeJwtPayloadRecord } from '@shared/utils/sessionTokens';
import { requestEmailOtpEnrollmentChallenge } from '@/SeamsWeb/operations/authMethods/emailOtp/challenge';

type FetchLike = typeof fetch;

export type EmailOtpRegistrationAuthorityMaterial = {
  kind: 'email_otp';
  proof: EmailOtpRegistrationProof;
  registrationAuthorityId: string;
  appSessionVersion: string;
  providerSubject: string;
  email: string;
};

function requireTrimmedField(value: unknown, label: string): string {
  const text = typeof value === 'string' ? value.trim() : '';
  if (!text) {
    throw new Error(`${label} is required for Email OTP registration authority`);
  }
  return text;
}

function appSessionVersionFromJwt(appSessionJwt: string): string {
  const payload = decodeJwtPayloadRecord(appSessionJwt);
  return typeof payload?.appSessionVersion === 'string' ? payload.appSessionVersion.trim() : '';
}

function emailOtpRegistrationProviderSubjectFromJwt(appSessionJwt: string): string {
  const payload = decodeJwtPayloadRecord(appSessionJwt);
  return typeof payload?.providerSubject === 'string' ? payload.providerSubject.trim() : '';
}

export async function collectEmailOtpRegistrationAuthority(args: {
  authMethod: EmailOtpRegistrationAuthMethodInput;
  relayUrl: string;
  walletId: string;
  registrationIntentDigestB64u: string;
  appSessionJwt: string;
  appSessionVersion?: string;
  fetchImpl?: FetchLike;
}): Promise<EmailOtpRegistrationAuthorityMaterial> {
  const email = requireTrimmedField(args.authMethod.email, 'email').toLowerCase();
  const relayUrl = requireTrimmedField(args.relayUrl, 'relayUrl');
  const walletId = requireTrimmedField(args.walletId, 'walletId');
  const registrationIntentDigestB64u = requireTrimmedField(
    args.registrationIntentDigestB64u,
    'registrationIntentDigestB64u',
  );
  const appSessionJwt = requireTrimmedField(args.appSessionJwt, 'appSessionJwt');
  const providerSubject = requireTrimmedField(
    emailOtpRegistrationProviderSubjectFromJwt(appSessionJwt),
    'providerSubject',
  );
  const jwtAppSessionVersion = appSessionVersionFromJwt(appSessionJwt);
  const explicitAppSessionVersion =
    typeof args.appSessionVersion === 'string' ? args.appSessionVersion.trim() : '';
  if (args.authMethod.proofKind === 'google_sso_registration') {
    const registrationAttemptId = requireTrimmedField(
      args.authMethod.googleEmailOtpRegistrationAttemptId,
      'googleEmailOtpRegistrationAttemptId',
    );
    const registrationOfferId = requireTrimmedField(
      args.authMethod.googleEmailOtpRegistrationOfferId,
      'googleEmailOtpRegistrationOfferId',
    );
    const registrationCandidateId = requireTrimmedField(
      args.authMethod.googleEmailOtpRegistrationCandidateId,
      'googleEmailOtpRegistrationCandidateId',
    );
    const appSessionVersion = explicitAppSessionVersion || jwtAppSessionVersion;
    if (!appSessionVersion) {
      throw new Error('appSessionVersion is required for Email OTP registration authority');
    }
    return {
      kind: 'email_otp',
      proof: {
        version: 'email_otp_registration_proof_v1',
        proofKind: 'google_sso_registration',
        providerSubject,
        email,
        googleEmailOtpRegistrationAttemptId: registrationAttemptId,
        googleEmailOtpRegistrationOfferId: registrationOfferId,
        googleEmailOtpRegistrationCandidateId: registrationCandidateId,
        registrationIntentDigestB64u,
        appSessionVersion,
      },
      registrationAuthorityId: registrationAttemptId,
      appSessionVersion,
      providerSubject,
      email,
    };
  }
  const otpCode = requireTrimmedField(args.authMethod.otpCode, 'otpCode');
  const inputChallengeId =
    typeof args.authMethod.challengeId === 'string' ? args.authMethod.challengeId.trim() : '';
  const challenge = inputChallengeId
    ? null
    : await requestEmailOtpEnrollmentChallenge({
        relayUrl,
        walletId: walletId,
        appSessionJwt,
        fetchImpl: args.fetchImpl,
      });
  const challengeId = inputChallengeId || requireTrimmedField(challenge?.challengeId, 'challengeId');
  const appSessionVersion =
    explicitAppSessionVersion ||
    (typeof challenge?.appSessionVersion === 'string' ? challenge.appSessionVersion.trim() : '') ||
    jwtAppSessionVersion;
  if (!appSessionVersion) {
    throw new Error('appSessionVersion is required for Email OTP registration authority');
  }
  return {
    kind: 'email_otp',
    proof: {
      version: 'email_otp_registration_proof_v1',
      proofKind: 'otp_challenge',
      providerSubject,
      email,
      challengeId,
      otpCode,
      otpChannel: EMAIL_OTP_CHANNEL,
      registrationIntentDigestB64u,
      appSessionVersion,
    },
    registrationAuthorityId: challengeId,
    appSessionVersion,
    providerSubject,
    email,
  };
}
