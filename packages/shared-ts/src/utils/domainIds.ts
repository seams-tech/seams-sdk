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
export type VerifiedEmailAddress = DomainId<'VerifiedEmailAddress'>;
export type EmailOtpProviderUserId = DomainId<'EmailOtpProviderUserId'>;

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

// WebAuthn relying-party id. This belongs to passkey/WebAuthn auth scope and
// must not be used as a wallet, NEAR account, or signing-key identity.
export type WebAuthnRpId = DomainId<'WebAuthnRpId'>;
export type WebAuthnCredentialIdB64u = DomainId<'WebAuthnCredentialIdB64u'>;

// One passkey-sealed custody envelope. This locates ciphertext for a credential
// and must never be used as a wallet, credential, lane, material-activation, or
// authorization identity.
export type PasskeyEnvelopeId = DomainId<'PasskeyEnvelopeId'>;
export type WalletAuthMethodId = DomainId<'WalletAuthMethodId'>;
// One opaque authority that owns wallet permissions and exact signer activations.
export type WalletAuthorityId = DomainId<'WalletAuthorityId'>;
export type WalletAuthorityBindingDigest = DomainId<'WalletAuthorityBindingDigest'>;
// Opaque identities that keep MPC capability, material, runtime, and lifecycle
// bindings independent from authorization and wallet-session identities.
export type CapabilityInstanceRef = DomainId<'CapabilityInstanceRef'>;
export type MpcMaterialOwnerRef = DomainId<'MpcMaterialOwnerRef'>;
export type MpcCapabilityRuntimeRef = DomainId<'MpcCapabilityRuntimeRef'>;
export type MpcMaterialActivationId = DomainId<'MpcMaterialActivationId'>;
export type MpcSigningWorkerRef = DomainId<'MpcSigningWorkerRef'>;
export type MpcKeyBindingRef = DomainId<'MpcKeyBindingRef'>;
export type MpcLifecycleBindingRef = DomainId<'MpcLifecycleBindingRef'>;
export type MpcReauthorizationPolicyRef = DomainId<'MpcReauthorizationPolicyRef'>;
export type MpcRegisteredPublicKeyBindingRef = DomainId<'MpcRegisteredPublicKeyBindingRef'>;

type MpcMaterialActivationRefFields = {
  readonly activationId: MpcMaterialActivationId;
  readonly capability: CapabilityInstanceRef;
  readonly materialOwner: MpcMaterialOwnerRef;
  readonly keyBinding: MpcKeyBindingRef;
  readonly lifecycleBinding: MpcLifecycleBindingRef;
  readonly signingWorker: MpcSigningWorkerRef;
};

class MpcMaterialActivationReference {
  private retainProof(): true {
    return true;
  }
  readonly kind: 'mpc_material_activation_ref';
  readonly activationId: MpcMaterialActivationId;
  readonly capability: CapabilityInstanceRef;
  readonly materialOwner: MpcMaterialOwnerRef;
  readonly keyBinding: MpcKeyBindingRef;
  readonly lifecycleBinding: MpcLifecycleBindingRef;
  readonly signingWorker: MpcSigningWorkerRef;

  constructor(fields: MpcMaterialActivationRefFields) {
    void this.retainProof();
    this.kind = 'mpc_material_activation_ref';
    this.activationId = fields.activationId;
    this.capability = fields.capability;
    this.materialOwner = fields.materialOwner;
    this.keyBinding = fields.keyBinding;
    this.lifecycleBinding = fields.lifecycleBinding;
    this.signingWorker = fields.signingWorker;
  }
}

export type MpcMaterialActivationRef = MpcMaterialActivationReference;

// Server threshold Ed25519 session id used for NEAR signing and Ed25519 export.
export type ThresholdEd25519SessionId = DomainId<'ThresholdEd25519SessionId'>;

// Server threshold ECDSA session id used for Tempo/EVM signing and ECDSA export.
export type ThresholdEcdsaSessionId = DomainId<'ThresholdEcdsaSessionId'>;

// Deterministic selector for one activated ECDSA key state. This is durable
// key identity and must never be used as an authorization-session id.
export type EcdsaActiveStateId = DomainId<'EcdsaActiveStateId'>;

// Curve-specific server threshold session id. Use this only at APIs that are
// genuinely curve-generic; prefer the curve-specific id in curve-specific code.
export type ThresholdSessionId = ThresholdEd25519SessionId | ThresholdEcdsaSessionId;

// Root-share epoch activated by the signing worker. This identifies durable
// ECDSA key material and must never be substituted with a threshold session id.
export type RootShareEpoch = DomainId<'RootShareEpoch'>;

// Stable wallet key identity. A wallet can have multiple signing lanes that
// all sign for this same wallet key.
export type WalletKeyId = DomainId<'WalletKeyId'>;

// Lane-scoped signer identity under one wallet key.
export type SigningLaneId = DomainId<'SigningLaneId'>;

// Share epoch for one signing lane. This is distinct from session ids and root
// custody epochs.
export type LaneShareEpoch = DomainId<'LaneShareEpoch'>;

// Linked physical or browser device principal that can hold a lane-scoped MPC
// share.
export type LinkedDeviceId = DomainId<'LinkedDeviceId'>;

// Immutable identities for one rotatable signing-lane protocol operation and
// its aggregate enrollment.
export type LaneOperationId = DomainId<'LaneOperationId'>;
export type LaneEnrollmentId = DomainId<'LaneEnrollmentId'>;
export type LaneOperationIdempotencyKey = DomainId<'LaneOperationIdempotencyKey'>;
export type LinkedDeviceEnrollmentId = DomainId<'LinkedDeviceEnrollmentId'>;
// One immutable recovery operation that owns the fresh recovered-device authority.
export type WalletRecoveryOperationId = DomainId<'WalletRecoveryOperationId'>;
export type Ed25519YaoSuiteId = DomainId<'Ed25519YaoSuiteId'>;
export type EcdsaRelayerKeyId = DomainId<'EcdsaRelayerKeyId'>;
export type LaneHolderRecipientHandleV1 = DomainId<'LaneHolderRecipientHandleV1'>;

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

export function hasControlCharacter(value: string): boolean {
  for (const character of value) {
    const code = character.charCodeAt(0);
    if (code <= 31 || code === 127) return true;
  }
  return false;
}

export function hasWhitespaceOrControlCharacters(value: string): boolean {
  for (const character of value) {
    if (/\s/.test(character)) return true;
  }
  return hasControlCharacter(value);
}

export function parseWalletId(raw: unknown): DomainIdParseResult<WalletId> {
  const parsed = parseDomainId<WalletId>(raw, 'walletId');
  if (!parsed.ok) return parsed;
  if (hasWhitespaceOrControlCharacters(parsed.value)) {
    return {
      ok: false,
      error: {
        code: 'invalid',
        message: 'walletId must not contain whitespace or control characters',
      },
    };
  }
  return parsed;
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

export function parseVerifiedEmailAddress(raw: unknown): DomainIdParseResult<VerifiedEmailAddress> {
  const parsed = parseDomainId<VerifiedEmailAddress>(raw, 'verifiedEmailAddress');
  if (!parsed.ok) return parsed;
  const normalized = parsed.value.toLowerCase();
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(normalized)) {
    return {
      ok: false,
      error: {
        code: 'invalid',
        message: 'verifiedEmailAddress must be an email address',
      },
    };
  }
  return { ok: true, value: normalized as VerifiedEmailAddress };
}

export function parseEmailOtpProviderUserId(
  raw: unknown,
): DomainIdParseResult<EmailOtpProviderUserId> {
  return parseDomainId(raw, 'emailOtpProviderUserId');
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

export function parseWebAuthnRpId(raw: unknown): DomainIdParseResult<WebAuthnRpId> {
  const parsed = parseDomainId<WebAuthnRpId>(raw, 'rpId');
  if (!parsed.ok) return parsed;
  if (hasWhitespaceOrControlCharacters(parsed.value)) {
    return {
      ok: false,
      error: {
        code: 'invalid',
        message: 'rpId contains whitespace or control characters',
      },
    };
  }
  return parsed;
}

export function parseWebAuthnCredentialIdB64u(
  raw: unknown,
): DomainIdParseResult<WebAuthnCredentialIdB64u> {
  return parseDomainId(raw, 'credentialIdB64u');
}

export function parsePasskeyEnvelopeId(raw: unknown): DomainIdParseResult<PasskeyEnvelopeId> {
  return parseDomainId(raw, 'passkeyEnvelopeId');
}

/**
 * Mints a wallet auth-method id.
 *
 * Server-side only, and there is exactly one of these because an auth method's
 * identity is now authenticated data: it goes into the custody envelope's AAD,
 * so an id minted to a second shape would seal envelopes the parsers reject.
 * A client never chooses one — registration and every addition receive theirs
 * from the intent that allocated it.
 */
export function allocateWalletAuthMethodId(randomSuffix: string): WalletAuthMethodId {
  const parsed = parseWalletAuthMethodId(`wallet-auth-method:${randomSuffix}`);
  if (!parsed.ok) {
    throw new Error(`Generated wallet auth-method ID is invalid: ${parsed.error.message}`);
  }
  return parsed.value;
}

export function parseWalletAuthMethodId(raw: unknown): DomainIdParseResult<WalletAuthMethodId> {
  return parseDomainId(raw, 'walletAuthMethodId');
}

export function parseWalletAuthorityId(raw: unknown): DomainIdParseResult<WalletAuthorityId> {
  return parseDomainId(raw, 'walletAuthorityId');
}

export function parseWalletAuthorityBindingDigest(
  raw: unknown,
): DomainIdParseResult<WalletAuthorityBindingDigest> {
  return parseDomainId(raw, 'walletAuthorityBindingDigest');
}

export function parseCapabilityInstanceRef(
  raw: unknown,
): DomainIdParseResult<CapabilityInstanceRef> {
  return parseDomainId(raw, 'capabilityInstanceRef');
}

export function parseMpcMaterialOwnerRef(raw: unknown): DomainIdParseResult<MpcMaterialOwnerRef> {
  return parseDomainId(raw, 'mpcMaterialOwnerRef');
}

export function parseMpcCapabilityRuntimeRef(
  raw: unknown,
): DomainIdParseResult<MpcCapabilityRuntimeRef> {
  return parseDomainId(raw, 'mpcCapabilityRuntimeRef');
}

export function parseMpcMaterialActivationId(
  raw: unknown,
): DomainIdParseResult<MpcMaterialActivationId> {
  return parseDomainId(raw, 'mpcMaterialActivationId');
}

export function parseMpcSigningWorkerRef(raw: unknown): DomainIdParseResult<MpcSigningWorkerRef> {
  return parseDomainId(raw, 'mpcSigningWorkerRef');
}

export function parseMpcKeyBindingRef(raw: unknown): DomainIdParseResult<MpcKeyBindingRef> {
  return parseDomainId(raw, 'mpcKeyBindingRef');
}

export function parseMpcLifecycleBindingRef(
  raw: unknown,
): DomainIdParseResult<MpcLifecycleBindingRef> {
  return parseDomainId(raw, 'mpcLifecycleBindingRef');
}

export function parseMpcReauthorizationPolicyRef(
  raw: unknown,
): DomainIdParseResult<MpcReauthorizationPolicyRef> {
  return parseDomainId(raw, 'mpcReauthorizationPolicyRef');
}

export function parseMpcRegisteredPublicKeyBindingRef(
  raw: unknown,
): DomainIdParseResult<MpcRegisteredPublicKeyBindingRef> {
  return parseDomainId(raw, 'mpcRegisteredPublicKeyBindingRef');
}

export function buildMpcMaterialActivationRef(
  fields: MpcMaterialActivationRefFields,
): MpcMaterialActivationRef {
  return new MpcMaterialActivationReference(fields);
}

export function mpcMaterialActivationRefsEqual(
  left: MpcMaterialActivationRef,
  right: MpcMaterialActivationRef,
): boolean {
  return (
    left.activationId === right.activationId &&
    left.capability === right.capability &&
    left.materialOwner === right.materialOwner &&
    left.keyBinding === right.keyBinding &&
    left.lifecycleBinding === right.lifecycleBinding &&
    left.signingWorker === right.signingWorker
  );
}

function isMpcMaterialActivationRefField(field: string): boolean {
  switch (field) {
    case 'kind':
    case 'activationId':
    case 'capability':
    case 'materialOwner':
    case 'keyBinding':
    case 'lifecycleBinding':
    case 'signingWorker':
      return true;
    default:
      return false;
  }
}

export function parseMpcMaterialActivationRef(
  raw: unknown,
): DomainIdParseResult<MpcMaterialActivationRef> {
  if (raw == null) {
    return {
      ok: false,
      error: {
        code: 'missing',
        message: 'mpcMaterialActivationRef is required',
      },
    };
  }
  if (typeof raw !== 'object' || Array.isArray(raw)) {
    return {
      ok: false,
      error: {
        code: 'invalid',
        message: 'mpcMaterialActivationRef must be an object',
      },
    };
  }

  const record = raw as Record<string, unknown>;
  const fields = Object.keys(record);
  if (fields.length !== 7) {
    return {
      ok: false,
      error: {
        code: 'invalid',
        message: 'mpcMaterialActivationRef has invalid fields',
      },
    };
  }
  for (const field of fields) {
    if (!isMpcMaterialActivationRefField(field)) {
      return {
        ok: false,
        error: {
          code: 'invalid',
          message: 'mpcMaterialActivationRef has invalid fields',
        },
      };
    }
  }
  if (record.kind !== 'mpc_material_activation_ref') {
    return {
      ok: false,
      error: {
        code: 'invalid',
        message: 'mpcMaterialActivationRef.kind is invalid',
      },
    };
  }

  const activationId = parseMpcMaterialActivationId(record.activationId);
  if (!activationId.ok) return activationId;
  const capability = parseCapabilityInstanceRef(record.capability);
  if (!capability.ok) return capability;
  const materialOwner = parseMpcMaterialOwnerRef(record.materialOwner);
  if (!materialOwner.ok) return materialOwner;
  const keyBinding = parseMpcKeyBindingRef(record.keyBinding);
  if (!keyBinding.ok) return keyBinding;
  const lifecycleBinding = parseMpcLifecycleBindingRef(record.lifecycleBinding);
  if (!lifecycleBinding.ok) return lifecycleBinding;
  const signingWorker = parseMpcSigningWorkerRef(record.signingWorker);
  if (!signingWorker.ok) return signingWorker;

  return {
    ok: true,
    value: buildMpcMaterialActivationRef({
      activationId: activationId.value,
      capability: capability.value,
      materialOwner: materialOwner.value,
      keyBinding: keyBinding.value,
      lifecycleBinding: lifecycleBinding.value,
      signingWorker: signingWorker.value,
    }),
  };
}

export function formatWebAuthnRpIdForWire(value: WebAuthnRpId): string {
  return value;
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

export function parseEcdsaActiveStateId(raw: unknown): DomainIdParseResult<EcdsaActiveStateId> {
  return parseDomainId(raw, 'ecdsaActiveStateId');
}

export function parseThresholdSessionId(raw: unknown): DomainIdParseResult<ThresholdSessionId> {
  return parseDomainId(raw, 'thresholdSessionId');
}

export function parseRootShareEpoch(raw: unknown): DomainIdParseResult<RootShareEpoch> {
  return parseDomainId(raw, 'rootShareEpoch');
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

export function parseLinkedDeviceId(raw: unknown): DomainIdParseResult<LinkedDeviceId> {
  return parseDomainId(raw, 'linkedDeviceId');
}

export function parseLaneOperationId(raw: unknown): DomainIdParseResult<LaneOperationId> {
  return parseDomainId(raw, 'laneOperationId');
}

export function parseLaneEnrollmentId(raw: unknown): DomainIdParseResult<LaneEnrollmentId> {
  return parseDomainId(raw, 'laneEnrollmentId');
}

export function parseLaneOperationIdempotencyKey(
  raw: unknown,
): DomainIdParseResult<LaneOperationIdempotencyKey> {
  return parseDomainId(raw, 'laneOperationIdempotencyKey');
}

export function parseLinkedDeviceEnrollmentId(
  raw: unknown,
): DomainIdParseResult<LinkedDeviceEnrollmentId> {
  return parseDomainId(raw, 'linkedDeviceEnrollmentId');
}

export function parseWalletRecoveryOperationId(
  raw: unknown,
): DomainIdParseResult<WalletRecoveryOperationId> {
  return parseDomainId(raw, 'walletRecoveryOperationId');
}

export function parseEd25519YaoSuiteId(raw: unknown): DomainIdParseResult<Ed25519YaoSuiteId> {
  return parseDomainId(raw, 'ed25519YaoSuiteId');
}

export function parseEcdsaRelayerKeyId(raw: unknown): DomainIdParseResult<EcdsaRelayerKeyId> {
  return parseDomainId(raw, 'ecdsaRelayerKeyId');
}

export function parseLaneHolderRecipientHandleV1(
  raw: unknown,
): DomainIdParseResult<LaneHolderRecipientHandleV1> {
  return parseDomainId(raw, 'laneHolderRecipientHandle');
}

export function parseLinkDeviceSessionId(raw: unknown): DomainIdParseResult<LinkDeviceSessionId> {
  return parseDomainId(raw, 'linkDeviceSessionId');
}
