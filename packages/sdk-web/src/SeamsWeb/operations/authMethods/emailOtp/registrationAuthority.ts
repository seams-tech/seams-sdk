import { EMAIL_OTP_CHANNEL } from '@shared/utils/emailOtpDomain';
import type {
  EmailOtpRegistrationAuthMethodInput,
  EmailOtpRegistrationProof,
} from '@shared/utils/registrationIntent';
import { requestEmailOtpEnrollmentChallenge } from '@/SeamsWeb/operations/authMethods/emailOtp/challenge';

type FetchLike = typeof fetch;

export type EmailOtpRegistrationAuthorityMaterial = {
  kind: 'email_otp';
  proof: EmailOtpRegistrationProof;
  registrationAuthorityId: string;
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

export async function collectEmailOtpRegistrationAuthority(args: {
  authMethod: EmailOtpRegistrationAuthMethodInput;
  relayUrl: string;
  walletId: string;
  registrationIntentDigestB64u: string;
  fetchImpl?: FetchLike;
}): Promise<EmailOtpRegistrationAuthorityMaterial> {
  const email = requireTrimmedField(args.authMethod.email, 'email').toLowerCase();
  const providerSubject = requireTrimmedField(args.authMethod.providerSubject, 'providerSubject');
  const relayUrl = requireTrimmedField(args.relayUrl, 'relayUrl');
  const walletId = requireTrimmedField(args.walletId, 'walletId');
  const registrationIntentDigestB64u = requireTrimmedField(
    args.registrationIntentDigestB64u,
    'registrationIntentDigestB64u',
  );
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
      },
      registrationAuthorityId: registrationAttemptId,
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
        walletId,
        fetchImpl: args.fetchImpl,
      });
  const challengeId = inputChallengeId || requireTrimmedField(challenge?.challengeId, 'challengeId');
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
    },
    registrationAuthorityId: challengeId,
    providerSubject,
    email,
  };
}
