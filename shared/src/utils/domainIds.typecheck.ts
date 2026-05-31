import type {
  ChallengeSubjectId,
  AppSessionVersion,
  EmailOtpChallengeId,
  EmailOtpRegistrationAttemptId,
  OrgId,
  ProviderSubject,
  ThresholdEcdsaSessionId,
  ThresholdEd25519SessionId,
  WalletId,
  WalletSigningSessionId,
} from './domainIds';

declare const walletId: WalletId;
declare const providerSubject: ProviderSubject;
declare const challengeSubjectId: ChallengeSubjectId;
declare const orgId: OrgId;
declare const appSessionVersion: AppSessionVersion;
declare const emailOtpChallengeId: EmailOtpChallengeId;
declare const registrationAttemptId: EmailOtpRegistrationAttemptId;
declare const walletSigningSessionId: WalletSigningSessionId;
declare const thresholdEd25519SessionId: ThresholdEd25519SessionId;
declare const thresholdEcdsaSessionId: ThresholdEcdsaSessionId;

function acceptsWalletId(value: WalletId): void {
  void value;
}

function acceptsProviderSubject(value: ProviderSubject): void {
  void value;
}

function acceptsChallengeSubjectId(value: ChallengeSubjectId): void {
  void value;
}

function acceptsEmailOtpChallengeId(value: EmailOtpChallengeId): void {
  void value;
}

function acceptsEmailOtpRegistrationAttemptId(value: EmailOtpRegistrationAttemptId): void {
  void value;
}

function acceptsOrgId(value: OrgId): void {
  void value;
}

function acceptsAppSessionVersion(value: AppSessionVersion): void {
  void value;
}

function acceptsWalletSigningSessionId(value: WalletSigningSessionId): void {
  void value;
}

function acceptsThresholdEd25519SessionId(value: ThresholdEd25519SessionId): void {
  void value;
}

function acceptsThresholdEcdsaSessionId(value: ThresholdEcdsaSessionId): void {
  void value;
}

acceptsWalletId(walletId);
acceptsProviderSubject(providerSubject);
acceptsChallengeSubjectId(challengeSubjectId);
acceptsOrgId(orgId);
acceptsAppSessionVersion(appSessionVersion);
acceptsEmailOtpChallengeId(emailOtpChallengeId);
acceptsEmailOtpRegistrationAttemptId(registrationAttemptId);
acceptsWalletSigningSessionId(walletSigningSessionId);
acceptsThresholdEd25519SessionId(thresholdEd25519SessionId);
acceptsThresholdEcdsaSessionId(thresholdEcdsaSessionId);

// @ts-expect-error Provider subjects are not wallet ids.
acceptsWalletId(providerSubject);

// @ts-expect-error Wallet ids are not provider subjects.
acceptsProviderSubject(walletId);

// @ts-expect-error Challenge subjects are not wallet ids.
acceptsWalletId(challengeSubjectId);

// @ts-expect-error Provider subjects are not challenge subject ids.
acceptsChallengeSubjectId(providerSubject);

// @ts-expect-error OTP challenge ids are not challenge-owner subjects.
acceptsChallengeSubjectId(emailOtpChallengeId);

// @ts-expect-error Organization ids are not wallet ids.
acceptsWalletId(orgId);

// @ts-expect-error App-session versions are not organization ids.
acceptsOrgId(appSessionVersion);

// @ts-expect-error Registration attempt ids are not OTP challenge ids.
acceptsEmailOtpChallengeId(registrationAttemptId);

// @ts-expect-error OTP challenge ids are not registration attempt ids.
acceptsEmailOtpRegistrationAttemptId(emailOtpChallengeId);

// @ts-expect-error Wallet signing-session ids are not threshold Ed25519 session ids.
acceptsThresholdEd25519SessionId(walletSigningSessionId);

// @ts-expect-error Threshold Ed25519 and ECDSA session ids are curve-specific.
acceptsThresholdEcdsaSessionId(thresholdEd25519SessionId);

// @ts-expect-error Threshold ECDSA session ids are not wallet signing-session ids.
acceptsWalletSigningSessionId(thresholdEcdsaSessionId);
