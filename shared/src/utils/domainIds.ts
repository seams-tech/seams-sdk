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

// Client wallet signing-session id. This groups one local approval/session
// budget and can cover multiple threshold-session ids.
export type WalletSigningSessionId = DomainId<'WalletSigningSessionId'>;

// Server threshold Ed25519 session id used for NEAR signing and Ed25519 export.
export type ThresholdEd25519SessionId = DomainId<'ThresholdEd25519SessionId'>;

// Server threshold ECDSA session id used for Tempo/EVM signing and ECDSA export.
export type ThresholdEcdsaSessionId = DomainId<'ThresholdEcdsaSessionId'>;

// Curve-specific server threshold session id. Use this only at APIs that are
// genuinely curve-generic; prefer the curve-specific id in curve-specific code.
export type ThresholdSessionId = ThresholdEd25519SessionId | ThresholdEcdsaSessionId;

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

export function parseWalletSigningSessionId(
  raw: unknown,
): DomainIdParseResult<WalletSigningSessionId> {
  return parseDomainId(raw, 'walletSigningSessionId');
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
