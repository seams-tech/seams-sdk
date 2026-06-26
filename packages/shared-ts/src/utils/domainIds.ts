export type DomainId<TBrand extends string> = string & {
  readonly __domainIdBrand: TBrand;
};

export type DomainIdParseError = {
  code: 'missing' | 'invalid';
  message: string;
};

export type DomainIdParseResult<T> =
  | { ok: true; value: T }
  | { ok: false; error: DomainIdParseError };

// Durable wallet identity. This is the canonical local/server wallet id and
// must not be used as an OIDC subject, challenge owner, or session id.
export type WalletId = DomainId<'WalletId'>;

// Subject from the upstream identity provider, such as a Google OIDC `sub`.
// This identifies the human/provider account that requested or verified OTP.
export type ProviderSubject = DomainId<'ProviderSubject'>;
export type GoogleProviderSubject = ProviderSubject & {
  readonly __googleProviderSubjectBrand: 'GoogleProviderSubject';
};
export type VerifiedGoogleEmail = DomainId<'VerifiedGoogleEmail'>;

// Subject that owns an Email OTP challenge. For Google registration this should
// match ProviderSubject after parsing, but it remains a separate type so
// challenge records cannot be accidentally compared to wallet ids.
export type ChallengeSubjectId = DomainId<'ChallengeSubjectId'>;

// Email OTP challenge handle. This identifies one issued OTP challenge and
// must not be used as the provider subject that owns the challenge.
export type EmailOtpChallengeId = DomainId<'EmailOtpChallengeId'>;

// Hosted Email OTP registration-attempt handle. This is a server-side attempt
// pointer, distinct from both the OTP challenge id and the wallet id.
export type EmailOtpRegistrationAttemptId = DomainId<'EmailOtpRegistrationAttemptId'>;

// Tenant or organization scope for hosted auth and wallet records. This must
// stay separate from wallet ids and provider subjects.
export type OrgId = DomainId<'OrgId'>;

// App-session version string from the auth/session authority. OTP challenges
// bind to it so old app sessions cannot consume new challenges.
export type AppSessionVersion = DomainId<'AppSessionVersion'>;

// WebAuthn relying-party id. This belongs to passkey/WebAuthn auth scope and
// must not be used as a wallet, NEAR account, or signing-key identity.
export type WebAuthnRpId = DomainId<'WebAuthnRpId'>;

// Client signing grant id. This groups one local approval/session
// budget and can cover multiple threshold-session ids.
export type SigningGrantId = DomainId<'SigningGrantId'>;

// Server threshold Ed25519 session id used for NEAR signing and Ed25519 export.
export type ThresholdEd25519SessionId = DomainId<'ThresholdEd25519SessionId'>;

// Server threshold ECDSA session id used for Tempo/EVM signing and ECDSA export.
export type ThresholdEcdsaSessionId = DomainId<'ThresholdEcdsaSessionId'>;

// Curve-specific server threshold session id. Use this only at APIs that are
// genuinely curve-generic; prefer the curve-specific id in curve-specific code.
export type ThresholdSessionId = ThresholdEd25519SessionId | ThresholdEcdsaSessionId;

// Stable wallet key identity. A wallet can have multiple signing lanes that
// all sign for this same wallet key.
export type WalletKeyId = DomainId<'WalletKeyId'>;

// Lane-scoped signer identity under one wallet key.
export type SigningLaneId = DomainId<'SigningLaneId'>;

// Share epoch for one signing lane. This is distinct from session ids and root
// custody epochs.
export type LaneShareEpoch = DomainId<'LaneShareEpoch'>;

// Delegated agent principal that can hold a lane-scoped MPC share.
export type AgentPrincipalId = DomainId<'AgentPrincipalId'>;

// Linked physical or browser device principal that can hold a lane-scoped MPC
// share.
export type LinkedDeviceId = DomainId<'LinkedDeviceId'>;

// Delegated mandate policy identity.
export type MandatePolicyId = DomainId<'MandatePolicyId'>;

// Rotation or lane-creation operation identity.
export type RotationOperationId = DomainId<'RotationOperationId'>;

// Canonical delegated intent digest.
export type DelegatedIntentDigest = DomainId<'DelegatedIntentDigest'>;

// Idempotency key scoped to a delegated signer request.
export type DelegatedIdempotencyKey = DomainId<'DelegatedIdempotencyKey'>;

// QR/device-link relay session identity.
export type LinkDeviceSessionId = DomainId<'LinkDeviceSessionId'>;

function parseDomainId<T>(raw: unknown, fieldName: string): DomainIdParseResult<T> {
  if (raw == null) {
    return {
      ok: false,
      error: {
        code: 'missing',
        message: `${fieldName} is required`,
      },
    };
  }
  if (typeof raw !== 'string') {
    return {
      ok: false,
      error: {
        code: 'invalid',
        message: `${fieldName} must be a string`,
      },
    };
  }
  const value = raw.trim();
  if (!value) {
    return {
      ok: false,
      error: {
        code: 'missing',
        message: `${fieldName} is required`,
      },
    };
  }
  return { ok: true, value: value as T };
}

export function parseWalletId(raw: unknown): DomainIdParseResult<WalletId> {
  return parseDomainId(raw, 'walletId');
}

export function parseProviderSubject(raw: unknown): DomainIdParseResult<ProviderSubject> {
  return parseDomainId(raw, 'providerSubject');
}

export function parseGoogleProviderSubject(
  raw: unknown,
): DomainIdParseResult<GoogleProviderSubject> {
  const parsed = parseDomainId<GoogleProviderSubject>(raw, 'googleProviderSubject');
  if (!parsed.ok) return parsed;
  if (!parsed.value.startsWith('google:')) {
    return {
      ok: false,
      error: {
        code: 'invalid',
        message: 'googleProviderSubject must start with google:',
      },
    };
  }
  return parsed;
}

export function parseVerifiedGoogleEmail(raw: unknown): DomainIdParseResult<VerifiedGoogleEmail> {
  const parsed = parseDomainId<VerifiedGoogleEmail>(raw, 'verifiedGoogleEmail');
  if (!parsed.ok) return parsed;
  const normalized = parsed.value.toLowerCase();
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(normalized)) {
    return {
      ok: false,
      error: {
        code: 'invalid',
        message: 'verifiedGoogleEmail must be an email address',
      },
    };
  }
  return { ok: true, value: normalized as VerifiedGoogleEmail };
}

export function parseChallengeSubjectId(raw: unknown): DomainIdParseResult<ChallengeSubjectId> {
  return parseDomainId(raw, 'challengeSubjectId');
}

export function parseEmailOtpChallengeId(raw: unknown): DomainIdParseResult<EmailOtpChallengeId> {
  return parseDomainId(raw, 'emailOtpChallengeId');
}

export function parseEmailOtpRegistrationAttemptId(
  raw: unknown,
): DomainIdParseResult<EmailOtpRegistrationAttemptId> {
  return parseDomainId(raw, 'emailOtpRegistrationAttemptId');
}

export function parseOrgId(raw: unknown): DomainIdParseResult<OrgId> {
  return parseDomainId(raw, 'orgId');
}

export function parseAppSessionVersion(raw: unknown): DomainIdParseResult<AppSessionVersion> {
  return parseDomainId(raw, 'appSessionVersion');
}

export function parseWebAuthnRpId(raw: unknown): DomainIdParseResult<WebAuthnRpId> {
  return parseDomainId(raw, 'rpId');
}

export function formatWebAuthnRpIdForWire(value: WebAuthnRpId): string {
  return value;
}

export function parseSigningGrantId(
  raw: unknown,
): DomainIdParseResult<SigningGrantId> {
  return parseDomainId(raw, 'signingGrantId');
}

export function parseThresholdEd25519SessionId(
  raw: unknown,
): DomainIdParseResult<ThresholdEd25519SessionId> {
  return parseDomainId(raw, 'thresholdEd25519SessionId');
}

export function parseThresholdEcdsaSessionId(
  raw: unknown,
): DomainIdParseResult<ThresholdEcdsaSessionId> {
  return parseDomainId(raw, 'thresholdEcdsaSessionId');
}

export function parseThresholdSessionId(raw: unknown): DomainIdParseResult<ThresholdSessionId> {
  return parseDomainId(raw, 'thresholdSessionId');
}

export function parseWalletKeyId(raw: unknown): DomainIdParseResult<WalletKeyId> {
  return parseDomainId(raw, 'walletKeyId');
}

export function parseSigningLaneId(raw: unknown): DomainIdParseResult<SigningLaneId> {
  return parseDomainId(raw, 'signingLaneId');
}

export function parseLaneShareEpoch(raw: unknown): DomainIdParseResult<LaneShareEpoch> {
  return parseDomainId(raw, 'laneShareEpoch');
}

export function parseAgentPrincipalId(raw: unknown): DomainIdParseResult<AgentPrincipalId> {
  return parseDomainId(raw, 'agentPrincipalId');
}

export function parseLinkedDeviceId(raw: unknown): DomainIdParseResult<LinkedDeviceId> {
  return parseDomainId(raw, 'linkedDeviceId');
}

export function parseMandatePolicyId(raw: unknown): DomainIdParseResult<MandatePolicyId> {
  return parseDomainId(raw, 'mandatePolicyId');
}

export function parseRotationOperationId(
  raw: unknown,
): DomainIdParseResult<RotationOperationId> {
  return parseDomainId(raw, 'rotationOperationId');
}

export function parseDelegatedIntentDigest(
  raw: unknown,
): DomainIdParseResult<DelegatedIntentDigest> {
  return parseDomainId(raw, 'delegatedIntentDigest');
}

export function parseDelegatedIdempotencyKey(
  raw: unknown,
): DomainIdParseResult<DelegatedIdempotencyKey> {
  return parseDomainId(raw, 'delegatedIdempotencyKey');
}

export function parseLinkDeviceSessionId(
  raw: unknown,
): DomainIdParseResult<LinkDeviceSessionId> {
  return parseDomainId(raw, 'linkDeviceSessionId');
}
