import type {
  ChallengeSubjectId,
  AppSessionVersion,
  AgentPrincipalId,
  DelegatedIdempotencyKey,
  DelegatedIntentDigest,
  EmailOtpChallengeId,
  EmailOtpRegistrationAttemptId,
  GoogleProviderSubject,
  LaneShareEpoch,
  LinkedDeviceId,
  LinkDeviceSessionId,
  MandatePolicyId,
  OrgId,
  ProviderSubject,
  RotationOperationId,
  SigningLaneId,
  ThresholdEcdsaSessionId,
  ThresholdEd25519SessionId,
  VerifiedGoogleEmail,
  WalletId,
  WalletKeyId,
  SigningGrantId,
} from './domainIds';

declare const walletId: WalletId;
declare const providerSubject: ProviderSubject;
declare const googleProviderSubject: GoogleProviderSubject;
declare const verifiedGoogleEmail: VerifiedGoogleEmail;
declare const challengeSubjectId: ChallengeSubjectId;
declare const orgId: OrgId;
declare const appSessionVersion: AppSessionVersion;
declare const emailOtpChallengeId: EmailOtpChallengeId;
declare const registrationAttemptId: EmailOtpRegistrationAttemptId;
declare const signingGrantId: SigningGrantId;
declare const thresholdEd25519SessionId: ThresholdEd25519SessionId;
declare const thresholdEcdsaSessionId: ThresholdEcdsaSessionId;
declare const walletKeyId: WalletKeyId;
declare const signingLaneId: SigningLaneId;
declare const laneShareEpoch: LaneShareEpoch;
declare const agentPrincipalId: AgentPrincipalId;
declare const linkedDeviceId: LinkedDeviceId;
declare const mandatePolicyId: MandatePolicyId;
declare const rotationOperationId: RotationOperationId;
declare const delegatedIntentDigest: DelegatedIntentDigest;
declare const delegatedIdempotencyKey: DelegatedIdempotencyKey;
declare const linkDeviceSessionId: LinkDeviceSessionId;

function acceptsWalletId(value: WalletId): void {
  void value;
}

function acceptsProviderSubject(value: ProviderSubject): void {
  void value;
}

function acceptsGoogleProviderSubject(value: GoogleProviderSubject): void {
  void value;
}

function acceptsVerifiedGoogleEmail(value: VerifiedGoogleEmail): void {
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

function acceptsSigningGrantId(value: SigningGrantId): void {
  void value;
}

function acceptsThresholdEd25519SessionId(value: ThresholdEd25519SessionId): void {
  void value;
}

function acceptsThresholdEcdsaSessionId(value: ThresholdEcdsaSessionId): void {
  void value;
}

function acceptsWalletKeyId(value: WalletKeyId): void {
  void value;
}

function acceptsSigningLaneId(value: SigningLaneId): void {
  void value;
}

function acceptsLaneShareEpoch(value: LaneShareEpoch): void {
  void value;
}

function acceptsAgentPrincipalId(value: AgentPrincipalId): void {
  void value;
}

function acceptsLinkedDeviceId(value: LinkedDeviceId): void {
  void value;
}

function acceptsMandatePolicyId(value: MandatePolicyId): void {
  void value;
}

function acceptsRotationOperationId(value: RotationOperationId): void {
  void value;
}

function acceptsDelegatedIntentDigest(value: DelegatedIntentDigest): void {
  void value;
}

function acceptsDelegatedIdempotencyKey(value: DelegatedIdempotencyKey): void {
  void value;
}

function acceptsLinkDeviceSessionId(value: LinkDeviceSessionId): void {
  void value;
}

acceptsWalletId(walletId);
acceptsProviderSubject(providerSubject);
acceptsProviderSubject(googleProviderSubject);
acceptsGoogleProviderSubject(googleProviderSubject);
acceptsVerifiedGoogleEmail(verifiedGoogleEmail);
acceptsChallengeSubjectId(challengeSubjectId);
acceptsOrgId(orgId);
acceptsAppSessionVersion(appSessionVersion);
acceptsEmailOtpChallengeId(emailOtpChallengeId);
acceptsEmailOtpRegistrationAttemptId(registrationAttemptId);
acceptsSigningGrantId(signingGrantId);
acceptsThresholdEd25519SessionId(thresholdEd25519SessionId);
acceptsThresholdEcdsaSessionId(thresholdEcdsaSessionId);
acceptsWalletKeyId(walletKeyId);
acceptsSigningLaneId(signingLaneId);
acceptsLaneShareEpoch(laneShareEpoch);
acceptsAgentPrincipalId(agentPrincipalId);
acceptsLinkedDeviceId(linkedDeviceId);
acceptsMandatePolicyId(mandatePolicyId);
acceptsRotationOperationId(rotationOperationId);
acceptsDelegatedIntentDigest(delegatedIntentDigest);
acceptsDelegatedIdempotencyKey(delegatedIdempotencyKey);
acceptsLinkDeviceSessionId(linkDeviceSessionId);

// @ts-expect-error Provider subjects are not wallet ids.
acceptsWalletId(providerSubject);

// @ts-expect-error Wallet ids are not provider subjects.
acceptsProviderSubject(walletId);

// @ts-expect-error Generic provider subjects are not Google-specific provider subjects.
acceptsGoogleProviderSubject(providerSubject);

// @ts-expect-error Verified Google emails are not provider subjects.
acceptsProviderSubject(verifiedGoogleEmail);

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
acceptsThresholdEd25519SessionId(signingGrantId);

// @ts-expect-error Threshold Ed25519 and ECDSA session ids are curve-specific.
acceptsThresholdEcdsaSessionId(thresholdEd25519SessionId);

// @ts-expect-error Threshold ECDSA session ids are not wallet signing-session ids.
acceptsSigningGrantId(thresholdEcdsaSessionId);

// @ts-expect-error Wallet keys are not wallet ids.
acceptsWalletId(walletKeyId);

// @ts-expect-error Wallet ids are not wallet keys.
acceptsWalletKeyId(walletId);

// @ts-expect-error Signing lanes are not wallet signing sessions.
acceptsSigningGrantId(signingLaneId);

// @ts-expect-error Wallet signing sessions are not signing lanes.
acceptsSigningLaneId(signingGrantId);

// @ts-expect-error Lane share epochs are not signing lanes.
acceptsSigningLaneId(laneShareEpoch);

// @ts-expect-error Agent principals are not linked devices.
acceptsLinkedDeviceId(agentPrincipalId);

// @ts-expect-error Linked devices are not agent principals.
acceptsAgentPrincipalId(linkedDeviceId);

// @ts-expect-error Mandate policies are not rotation operations.
acceptsRotationOperationId(mandatePolicyId);

// @ts-expect-error Delegated intent digests are not idempotency keys.
acceptsDelegatedIdempotencyKey(delegatedIntentDigest);

// @ts-expect-error Link-device sessions are not signing lanes.
acceptsSigningLaneId(linkDeviceSessionId);
