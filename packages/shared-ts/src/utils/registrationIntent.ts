import { alphabetizeStringify, sha256BytesUtf8 } from './digests';
import type {
  AppSessionVersion,
  ChallengeSubjectId,
  EmailOtpChallengeId,
  OrgId,
  ProviderSubject,
  WalletId,
} from './domainIds';
import { parseWalletId } from './domainIds';
import { base64UrlEncode } from './encoders';
import type { ImplicitNearAccountId, NamedNearAccountId } from './near';

export type { WalletId } from './domainIds';
export type { ImplicitNearAccountId, NamedNearAccountId, NearAccountId } from './near';

export type RegistrationIntentGrant = string & {
  readonly __registrationIntentGrantBrand: unique symbol;
};

export type AddAuthMethodIntentGrant = string & {
  readonly __addAuthMethodIntentGrantBrand: unique symbol;
};

export type AddSignerIntentGrant = string & {
  readonly __addSignerIntentGrantBrand: unique symbol;
};

export type GeneratedImplicitWalletId = WalletId & {
  readonly __generatedImplicitWalletIdBrand: unique symbol;
};

export type NearEd25519SigningKeyId = string & {
  readonly __nearEd25519SigningKeyIdBrand: unique symbol;
};

export type RegisterWalletInput =
  | {
      kind: 'server_generated';
      walletId?: never;
    }
  | {
      kind: 'provided';
      walletId: WalletId;
    };

export type PasskeyRegistrationAuthMethodInput = {
  kind: 'passkey';
  authenticatorOptions?: unknown;
  email?: never;
  otpCode?: never;
  challengeId?: never;
  appSessionJwt?: never;
};

export type EmailOtpRegistrationAuthMethodInput =
  | {
      kind: 'email_otp';
      proofKind: 'otp_challenge';
      email: string;
      otpCode: string;
      appSessionJwt: string;
      challengeId?: string;
      googleEmailOtpRegistrationAttemptId?: never;
      googleEmailOtpRegistrationOfferId?: never;
      googleEmailOtpRegistrationCandidateId?: never;
      authenticatorOptions?: never;
    }
  | {
      kind: 'email_otp';
      proofKind: 'google_sso_registration';
      email: string;
      appSessionJwt: string;
      googleEmailOtpRegistrationAttemptId: string;
      googleEmailOtpRegistrationOfferId: string;
      googleEmailOtpRegistrationCandidateId: string;
      otpCode?: never;
      challengeId?: never;
      authenticatorOptions?: never;
    };

export type RegistrationAuthMethodInput =
  | PasskeyRegistrationAuthMethodInput
  | EmailOtpRegistrationAuthMethodInput;

export type AddAuthMethodInput =
  | {
      kind: 'passkey';
      email?: never;
      otpCode?: never;
      challengeId?: never;
      appSessionJwt?: never;
      authenticatorOptions?: never;
    }
  | {
      kind: 'email_otp';
      email: string;
      otpCode?: never;
      challengeId?: never;
      appSessionJwt?: never;
      authenticatorOptions?: never;
    };

export type WalletAuthMethodTarget =
  | {
      kind: 'passkey';
      credentialIdB64u: string;
      email?: never;
    }
  | {
      kind: 'email_otp';
      email: string;
      credentialIdB64u?: never;
    };

export type RegistrationAuthority =
  | {
      kind: 'passkey';
      walletId: WalletId;
      rpId: string;
      credentialIdB64u: string;
      credentialPublicKeyB64u: string;
      counter: number;
      registrationIntentDigestB64u: string;
      providerSubject?: never;
      challengeSubjectId?: never;
      email?: never;
      emailHashHex?: never;
      registrationAuthorityId?: never;
      challengeId?: never;
      googleEmailOtpRegistrationAttemptId?: never;
      originalWalletId?: never;
      finalWalletId?: never;
      orgId?: never;
      appSessionVersion?: never;
      challengePurpose?: never;
      googleEmailOtpRegistrationOfferId?: never;
      googleEmailOtpRegistrationCandidateId?: never;
    }
  | {
      kind: 'email_otp';
      proofKind: 'otp_challenge';
      walletId: WalletId;
      /** OIDC provider subject from the app-session JWT that requested the OTP. */
      providerSubject: ProviderSubject;
      /** Challenge owner verified against the OTP challenge record. */
      challengeSubjectId: ChallengeSubjectId;
      /** Normalized email address that received and verified the OTP. */
      email: string;
      emailHashHex: string;
      challengeId: EmailOtpChallengeId;
      registrationAuthorityId: EmailOtpChallengeId;
      /** Wallet id attached to the original OTP challenge before any name reroll. */
      originalWalletId: WalletId;
      /** Final wallet id selected for registration. */
      finalWalletId: WalletId;
      /** Tenant scope verified against the OTP challenge record. */
      orgId: OrgId;
      /** App-session version verified against the OTP challenge record. */
      appSessionVersion: AppSessionVersion;
      challengePurpose: 'registration' | 'registration_reroll';
      registrationIntentDigestB64u: string;
      credentialIdB64u?: never;
      credentialPublicKeyB64u?: never;
      counter?: never;
      rpId?: never;
      googleEmailOtpRegistrationAttemptId?: never;
      googleEmailOtpRegistrationOfferId?: never;
      googleEmailOtpRegistrationCandidateId?: never;
    }
  | {
      kind: 'email_otp';
      proofKind: 'google_sso_registration';
      walletId: WalletId;
      providerSubject: ProviderSubject;
      email: string;
      emailHashHex: string;
      googleEmailOtpRegistrationAttemptId: string;
      googleEmailOtpRegistrationOfferId: string;
      googleEmailOtpRegistrationCandidateId: string;
      registrationAuthorityId: string;
      finalWalletId: WalletId;
      orgId: OrgId;
      appSessionVersion: AppSessionVersion;
      registrationIntentDigestB64u: string;
      challengeSubjectId?: never;
      challengeId?: never;
      originalWalletId?: never;
      challengePurpose?: never;
      credentialIdB64u?: never;
      credentialPublicKeyB64u?: never;
      counter?: never;
      rpId?: never;
    };

export type EmailOtpRegistrationProof =
  | {
      version: 'email_otp_registration_proof_v1';
      proofKind: 'otp_challenge';
      /** OIDC provider subject from the app-session JWT that requested the OTP. */
      providerSubject: string;
      /** Normalized email address that received the OTP. */
      email: string;
      challengeId: string;
      otpCode: string;
      otpChannel: 'email_otp';
      /** Registration intent digest that binds the OTP proof to the wallet-registration request. */
      registrationIntentDigestB64u: string;
      appSessionVersion: string;
      googleEmailOtpRegistrationAttemptId?: never;
      googleEmailOtpRegistrationOfferId?: never;
      googleEmailOtpRegistrationCandidateId?: never;
    }
  | {
      version: 'email_otp_registration_proof_v1';
      proofKind: 'google_sso_registration';
      providerSubject: string;
      email: string;
      googleEmailOtpRegistrationAttemptId: string;
      googleEmailOtpRegistrationOfferId: string;
      googleEmailOtpRegistrationCandidateId: string;
      registrationIntentDigestB64u: string;
      appSessionVersion: string;
      challengeId?: never;
      otpCode?: never;
      otpChannel?: never;
    };

export type WalletAuthMethodRecord =
  | {
      version: 'wallet_auth_method_v1';
      kind: 'passkey';
      status: 'active' | 'revoked';
      walletId: WalletId;
      rpId: string;
      credentialIdB64u: string;
      credentialPublicKeyB64u: string;
      counter: number;
      createdAtMs: number;
      updatedAtMs: number;
      emailHashHex?: never;
      challengeId?: never;
    }
  | {
      version: 'wallet_auth_method_v1';
      kind: 'email_otp';
      status: 'active' | 'revoked';
      walletId: WalletId;
      emailHashHex: string;
      registrationAuthorityId: string;
      createdAtMs: number;
      updatedAtMs: number;
      rpId?: never;
      credentialIdB64u?: never;
      credentialPublicKeyB64u?: never;
      counter?: never;
    };

export type RegistrationNearAccountProvisioning =
  | {
      kind: 'implicit_account';
      accountIdSource: 'ed25519_public_key';
      requestedAccountId?: never;
      sponsor?: never;
    }
  | {
      kind: 'sponsored_named_account';
      requestedAccountId: NamedNearAccountId;
      sponsor: 'relayer';
      accountIdSource?: never;
    };

export type ResolvedRegistrationNearAccount =
  | {
      kind: 'implicit_account';
      nearAccountId: ImplicitNearAccountId;
      nearEd25519SigningKeyId: NearEd25519SigningKeyId;
      transactionHash?: never;
    }
  | {
      kind: 'sponsored_named_account';
      nearAccountId: NamedNearAccountId;
      nearEd25519SigningKeyId: NearEd25519SigningKeyId;
      transactionHash: string;
    };

export type ThresholdEd25519RegistrationSpec = {
  accountProvisioning: RegistrationNearAccountProvisioning;
  signerSlot: number;
  participantIds: number[];
  keyPurpose: string;
  keyVersion: string;
  derivationVersion: number;
};

export type ThresholdEcdsaRegistrationSpec = {
  chainTargets: unknown[];
  participantIds: number[];
};

export type NearAccountOwnershipProofMessageV1 = {
  version: 'near_account_ownership_proof_message_v1';
  walletId: WalletId;
  rpId: string;
  nearAccountId: string;
  publicKey: string;
  nonceB64u: string;
  issuedAtMs: number;
  expiresAtMs: number;
};

export type NearAccountOwnershipProofV1 = {
  version: 'near_account_ownership_proof_v1';
  message: NearAccountOwnershipProofMessageV1;
  signatureB64u: string;
};

export type ThresholdEd25519AddSignerSpec =
  | {
      mode: 'create_near_account';
      nearAccountId: string;
      signerSlot: number;
      participantIds: number[];
      keyPurpose: string;
      keyVersion: string;
      derivationVersion: number;
      accountOwnershipProof?: never;
    }
  | {
      mode: 'link_existing_near_account';
      nearAccountId: string;
      signerSlot: number;
      participantIds: number[];
      keyPurpose: string;
      keyVersion: string;
      derivationVersion: number;
      accountOwnershipProof: NearAccountOwnershipProofV1;
    };

export type ThresholdEcdsaAddSignerSpec = {
  chainTargets: unknown[];
  participantIds: number[];
};

export type RegistrationSignerSelection =
  | {
      mode: 'ed25519_only';
      ed25519: ThresholdEd25519RegistrationSpec;
      ecdsa?: never;
    }
  | {
      mode: 'ecdsa_only';
      ecdsa: ThresholdEcdsaRegistrationSpec;
      ed25519?: never;
    }
  | {
      mode: 'ed25519_and_ecdsa';
      ed25519: ThresholdEd25519RegistrationSpec;
      ecdsa: ThresholdEcdsaRegistrationSpec;
    };

export type AddSignerSelection =
  | {
      mode: 'ed25519';
      ed25519: ThresholdEd25519AddSignerSpec;
      ecdsa?: never;
    }
  | {
      mode: 'ecdsa';
      ecdsa: ThresholdEcdsaAddSignerSpec;
      ed25519?: never;
    };

export type RuntimePolicyScopeLike = {
  orgId: string;
  projectId: string;
  envId: string;
  signingRootVersion?: string;
};

export type RegistrationIntentV1 = {
  version: 'registration_intent_v1';
  walletId: WalletId;
  rpId: string;
  authMethod: RegistrationAuthMethodInput;
  signerSelection: RegistrationSignerSelection;
  runtimePolicyScope?: RuntimePolicyScopeLike;
  nonceB64u: string;
};

export type AddSignerIntentV1 = {
  version: 'add_signer_intent_v1';
  walletId: WalletId;
  rpId: string;
  signerSelection: AddSignerSelection;
  runtimePolicyScope?: RuntimePolicyScopeLike;
  nonceB64u: string;
};

export type AddAuthMethodIntentV1 = {
  version: 'add_auth_method_intent_v1';
  walletId: WalletId;
  rpId: string;
  authMethod: AddAuthMethodInput;
  runtimePolicyScope?: RuntimePolicyScopeLike;
  nonceB64u: string;
};

export function walletIdFromString(value: string): WalletId {
  const parsed = parseWalletId(value);
  if (!parsed.ok) {
    throw new Error(parsed.error.message);
  }
  return parsed.value;
}

export type GeneratedImplicitWalletIdParseResult =
  | { ok: true; value: GeneratedImplicitWalletId }
  | {
      ok: false;
      error: {
        code: 'missing' | 'invalid';
        message: string;
      };
    };

const GENERATED_IMPLICIT_WALLET_ID_PATTERN = /^[a-z]+-[a-z]+-[a-z0-9]{6}$/;

export function parseGeneratedImplicitWalletId(
  raw: unknown,
): GeneratedImplicitWalletIdParseResult {
  const parsed = parseWalletId(raw);
  if (!parsed.ok) return parsed;
  const value = String(parsed.value);
  if (!GENERATED_IMPLICIT_WALLET_ID_PATTERN.test(value)) {
    return {
      ok: false,
      error: {
        code: 'invalid',
        message:
          'generated implicit walletId must match the word-word-suffix generated format',
      },
    };
  }
  return { ok: true, value: parsed.value as GeneratedImplicitWalletId };
}

export function requireGeneratedImplicitWalletId(value: unknown): GeneratedImplicitWalletId {
  const parsed = parseGeneratedImplicitWalletId(value);
  if (!parsed.ok) {
    throw new Error(parsed.error.message);
  }
  return parsed.value;
}

export function nearEd25519SigningKeyIdFromString(value: string): NearEd25519SigningKeyId {
  const normalized = String(value || '').trim();
  if (!normalized) {
    throw new Error('nearEd25519SigningKeyId is required');
  }
  return normalized as NearEd25519SigningKeyId;
}

export function nearEd25519SigningKeyIdFromWalletId(walletId: WalletId): NearEd25519SigningKeyId {
  return nearEd25519SigningKeyIdFromString(String(walletId));
}

export type GeneratedImplicitNearEd25519SigningKeyDigestInput = {
  kind: 'generated_implicit_near_ed25519_signing_key_v1';
  walletId: GeneratedImplicitWalletId;
  rpId: string;
  signingRootId: string;
  signingRootVersion: string;
  signerSlot: number;
  participantIds: readonly number[];
  keyPurpose: string;
  keyVersion: string;
  derivationVersion: number;
};

export async function computeGeneratedImplicitNearEd25519SigningKeyId(
  input: GeneratedImplicitNearEd25519SigningKeyDigestInput,
): Promise<NearEd25519SigningKeyId> {
  const canonical = alphabetizeStringify({
    kind: input.kind,
    walletId: String(input.walletId),
    rpId: input.rpId,
    signingRootId: input.signingRootId,
    signingRootVersion: input.signingRootVersion,
    signerSlot: input.signerSlot,
    participantIds: [...input.participantIds],
    keyPurpose: input.keyPurpose,
    keyVersion: input.keyVersion,
    derivationVersion: input.derivationVersion,
  });
  const digest = base64UrlEncode(await sha256BytesUtf8(canonical));
  return nearEd25519SigningKeyIdFromString(`ed25519ks_${digest}`);
}

export async function computeRegistrationNearEd25519SigningKeyId(input: {
  walletId: WalletId;
  rpId: string;
  signingRootId: string;
  signingRootVersion: string;
  ed25519: ThresholdEd25519RegistrationSpec;
}): Promise<NearEd25519SigningKeyId> {
  switch (input.ed25519.accountProvisioning.kind) {
    case 'implicit_account':
      return await computeGeneratedImplicitNearEd25519SigningKeyId({
        kind: 'generated_implicit_near_ed25519_signing_key_v1',
        walletId: requireGeneratedImplicitWalletId(input.walletId),
        rpId: input.rpId,
        signingRootId: input.signingRootId,
        signingRootVersion: input.signingRootVersion,
        signerSlot: input.ed25519.signerSlot,
        participantIds: input.ed25519.participantIds,
        keyPurpose: input.ed25519.keyPurpose,
        keyVersion: input.ed25519.keyVersion,
        derivationVersion: input.ed25519.derivationVersion,
      });
    case 'sponsored_named_account':
      return nearEd25519SigningKeyIdFromWalletId(input.walletId);
    default: {
      const exhaustive: never = input.ed25519.accountProvisioning;
      return exhaustive;
    }
  }
}

export function implicitNearAccountProvisioning(): RegistrationNearAccountProvisioning {
  return {
    kind: 'implicit_account',
    accountIdSource: 'ed25519_public_key',
  };
}

export function sponsoredNamedNearAccountProvisioning(
  requestedAccountId: NamedNearAccountId,
): RegistrationNearAccountProvisioning {
  return {
    kind: 'sponsored_named_account',
    requestedAccountId,
    sponsor: 'relayer',
  };
}

export function registrationProvisioningScopeKey(
  provisioning: RegistrationNearAccountProvisioning,
): string {
  switch (provisioning.kind) {
    case 'implicit_account':
      return 'implicit_account';
    case 'sponsored_named_account':
      return `sponsored_named_account:${String(provisioning.requestedAccountId)}`;
    default: {
      const exhaustive: never = provisioning;
      return exhaustive;
    }
  }
}

export function registrationIntentGrantFromString(value: string): RegistrationIntentGrant {
  return String(value || '').trim() as RegistrationIntentGrant;
}

export function addAuthMethodIntentGrantFromString(value: string): AddAuthMethodIntentGrant {
  return String(value || '').trim() as AddAuthMethodIntentGrant;
}

export function addSignerIntentGrantFromString(value: string): AddSignerIntentGrant {
  return String(value || '').trim() as AddSignerIntentGrant;
}

export function serializeRegistrationIntentV1(intent: RegistrationIntentV1): string {
  return alphabetizeStringify(intent);
}

export function serializeAddSignerIntentV1(intent: AddSignerIntentV1): string {
  return alphabetizeStringify(intent);
}

export function serializeAddAuthMethodIntentV1(intent: AddAuthMethodIntentV1): string {
  return alphabetizeStringify(intent);
}

export function serializeNearAccountOwnershipProofMessageV1(
  message: NearAccountOwnershipProofMessageV1,
): string {
  return alphabetizeStringify(message);
}

export async function computeRegistrationIntentDigestB64u(
  intent: RegistrationIntentV1,
): Promise<string> {
  return base64UrlEncode(await sha256BytesUtf8(serializeRegistrationIntentV1(intent)));
}

export async function computeAddSignerIntentDigestB64u(intent: AddSignerIntentV1): Promise<string> {
  return base64UrlEncode(await sha256BytesUtf8(serializeAddSignerIntentV1(intent)));
}

export async function computeAddAuthMethodIntentDigestB64u(
  intent: AddAuthMethodIntentV1,
): Promise<string> {
  return base64UrlEncode(await sha256BytesUtf8(serializeAddAuthMethodIntentV1(intent)));
}

export async function computeNearAccountOwnershipProofDigestB64u(
  message: NearAccountOwnershipProofMessageV1,
): Promise<string> {
  return base64UrlEncode(
    await sha256BytesUtf8(serializeNearAccountOwnershipProofMessageV1(message)),
  );
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function trimString(value: unknown): string {
  return typeof value === 'string' ? value.trim() : '';
}

export function normalizeRegistrationAuthMethodInput(
  raw: unknown,
): RegistrationAuthMethodInput | null {
  if (!isRecord(raw)) return null;
  const kind = trimString(raw.kind);
  if (kind === 'passkey') {
    if (
      Object.prototype.hasOwnProperty.call(raw, 'email') ||
      Object.prototype.hasOwnProperty.call(raw, 'otpCode') ||
      Object.prototype.hasOwnProperty.call(raw, 'challengeId')
    ) {
      return null;
    }
    return {
      kind: 'passkey',
      ...(raw.authenticatorOptions !== undefined
        ? { authenticatorOptions: raw.authenticatorOptions }
        : {}),
    };
  }
  if (kind === 'email_otp') {
    const proofKind = trimString(raw.proofKind);
    const email = trimString(raw.email);
    const appSessionJwt = trimString(raw.appSessionJwt);
    if (
      !email ||
      !appSessionJwt ||
      Object.prototype.hasOwnProperty.call(raw, 'authenticatorOptions')
    ) {
      return null;
    }
    if (proofKind === 'otp_challenge') {
      const otpCode = trimString(raw.otpCode);
      const challengeId = trimString(raw.challengeId);
      if (
        !otpCode ||
        Object.prototype.hasOwnProperty.call(raw, 'googleEmailOtpRegistrationAttemptId') ||
        Object.prototype.hasOwnProperty.call(raw, 'googleEmailOtpRegistrationOfferId') ||
        Object.prototype.hasOwnProperty.call(raw, 'googleEmailOtpRegistrationCandidateId')
      ) {
        return null;
      }
      return {
        kind: 'email_otp',
        proofKind: 'otp_challenge',
        email,
        otpCode,
        appSessionJwt,
        ...(challengeId ? { challengeId } : {}),
      };
    }
    if (proofKind === 'google_sso_registration') {
      const googleEmailOtpRegistrationAttemptId = trimString(
        raw.googleEmailOtpRegistrationAttemptId,
      );
      const googleEmailOtpRegistrationOfferId = trimString(raw.googleEmailOtpRegistrationOfferId);
      const googleEmailOtpRegistrationCandidateId = trimString(
        raw.googleEmailOtpRegistrationCandidateId,
      );
      if (
        !googleEmailOtpRegistrationAttemptId ||
        !googleEmailOtpRegistrationOfferId ||
        !googleEmailOtpRegistrationCandidateId ||
        Object.prototype.hasOwnProperty.call(raw, 'otpCode') ||
        Object.prototype.hasOwnProperty.call(raw, 'challengeId')
      ) {
        return null;
      }
      return {
        kind: 'email_otp',
        proofKind: 'google_sso_registration',
        email,
        appSessionJwt,
        googleEmailOtpRegistrationAttemptId,
        googleEmailOtpRegistrationOfferId,
        googleEmailOtpRegistrationCandidateId,
      };
    }
    return null;
  }
  return null;
}

export function normalizeAddAuthMethodInput(raw: unknown): AddAuthMethodInput | null {
  if (!isRecord(raw)) return null;
  const kind = trimString(raw.kind);
  if (kind === 'passkey') {
    if (
      Object.prototype.hasOwnProperty.call(raw, 'email') ||
      Object.prototype.hasOwnProperty.call(raw, 'otpCode') ||
      Object.prototype.hasOwnProperty.call(raw, 'challengeId') ||
      Object.prototype.hasOwnProperty.call(raw, 'appSessionJwt') ||
      Object.prototype.hasOwnProperty.call(raw, 'authenticatorOptions')
    ) {
      return null;
    }
    return { kind: 'passkey' };
  }
  if (kind === 'email_otp') {
    const email = trimString(raw.email);
    if (
      !email ||
      Object.prototype.hasOwnProperty.call(raw, 'otpCode') ||
      Object.prototype.hasOwnProperty.call(raw, 'challengeId') ||
      Object.prototype.hasOwnProperty.call(raw, 'appSessionJwt') ||
      Object.prototype.hasOwnProperty.call(raw, 'authenticatorOptions')
    ) {
      return null;
    }
    return {
      kind: 'email_otp',
      email,
    };
  }
  return null;
}

export function normalizeWalletAuthMethodTarget(raw: unknown): WalletAuthMethodTarget | null {
  if (!isRecord(raw)) return null;
  const kind = trimString(raw.kind);
  if (kind === 'passkey') {
    const credentialIdB64u = trimString(raw.credentialIdB64u);
    if (!credentialIdB64u || Object.prototype.hasOwnProperty.call(raw, 'email')) {
      return null;
    }
    return {
      kind: 'passkey',
      credentialIdB64u,
    };
  }
  if (kind === 'email_otp') {
    const email = trimString(raw.email).toLowerCase();
    if (!email || Object.prototype.hasOwnProperty.call(raw, 'credentialIdB64u')) {
      return null;
    }
    return {
      kind: 'email_otp',
      email,
    };
  }
  return null;
}

export function normalizeEmailOtpRegistrationProof(raw: unknown): EmailOtpRegistrationProof | null {
  if (!isRecord(raw)) return null;
  const version = trimString(raw.version);
  const proofKind = trimString(raw.proofKind);
  const providerSubject = trimString(raw.providerSubject);
  const email = trimString(raw.email).toLowerCase();
  const registrationIntentDigestB64u = trimString(raw.registrationIntentDigestB64u);
  const appSessionVersion = trimString(raw.appSessionVersion);
  if (
    version !== 'email_otp_registration_proof_v1' ||
    !providerSubject ||
    !email ||
    !registrationIntentDigestB64u ||
    !appSessionVersion
  ) {
    return null;
  }
  if (proofKind === 'otp_challenge') {
    const challengeId = trimString(raw.challengeId);
    const otpCode = trimString(raw.otpCode);
    const otpChannel = trimString(raw.otpChannel);
    if (
      !challengeId ||
      !otpCode ||
      otpChannel !== 'email_otp' ||
      Object.prototype.hasOwnProperty.call(raw, 'googleEmailOtpRegistrationAttemptId') ||
      Object.prototype.hasOwnProperty.call(raw, 'googleEmailOtpRegistrationOfferId') ||
      Object.prototype.hasOwnProperty.call(raw, 'googleEmailOtpRegistrationCandidateId')
    ) {
      return null;
    }
    return {
      version: 'email_otp_registration_proof_v1',
      proofKind: 'otp_challenge',
      providerSubject,
      email,
      challengeId,
      otpCode,
      otpChannel: 'email_otp',
      registrationIntentDigestB64u,
      appSessionVersion,
    };
  }
  if (proofKind === 'google_sso_registration') {
    const googleEmailOtpRegistrationAttemptId = trimString(raw.googleEmailOtpRegistrationAttemptId);
    const googleEmailOtpRegistrationOfferId = trimString(raw.googleEmailOtpRegistrationOfferId);
    const googleEmailOtpRegistrationCandidateId = trimString(
      raw.googleEmailOtpRegistrationCandidateId,
    );
    if (
      !googleEmailOtpRegistrationAttemptId ||
      !googleEmailOtpRegistrationOfferId ||
      !googleEmailOtpRegistrationCandidateId ||
      Object.prototype.hasOwnProperty.call(raw, 'challengeId') ||
      Object.prototype.hasOwnProperty.call(raw, 'otpCode') ||
      Object.prototype.hasOwnProperty.call(raw, 'otpChannel')
    ) {
      return null;
    }
    return {
      version: 'email_otp_registration_proof_v1',
      proofKind: 'google_sso_registration',
      providerSubject,
      email,
      googleEmailOtpRegistrationAttemptId,
      googleEmailOtpRegistrationOfferId,
      googleEmailOtpRegistrationCandidateId,
      registrationIntentDigestB64u,
      appSessionVersion,
    };
  }
  return null;
}

function normalizeTimestampMs(value: unknown): number | null {
  const numeric = Number(value);
  if (!Number.isSafeInteger(numeric) || numeric <= 0) return null;
  return numeric;
}

export function normalizeNearAccountOwnershipProofV1(
  raw: unknown,
): NearAccountOwnershipProofV1 | null {
  if (!isRecord(raw)) return null;
  const message = isRecord(raw.message) ? raw.message : null;
  if (!message) return null;
  const proofVersion = trimString(raw.version);
  const messageVersion = trimString(message.version);
  const walletId = walletIdFromString(trimString(message.walletId));
  const rpId = trimString(message.rpId);
  const nearAccountId = trimString(message.nearAccountId);
  const publicKey = trimString(message.publicKey);
  const nonceB64u = trimString(message.nonceB64u);
  const issuedAtMs = normalizeTimestampMs(message.issuedAtMs);
  const expiresAtMs = normalizeTimestampMs(message.expiresAtMs);
  const signatureB64u = trimString(raw.signatureB64u);
  if (
    proofVersion !== 'near_account_ownership_proof_v1' ||
    messageVersion !== 'near_account_ownership_proof_message_v1' ||
    !walletId ||
    !rpId ||
    !nearAccountId ||
    !publicKey ||
    !nonceB64u ||
    issuedAtMs === null ||
    expiresAtMs === null ||
    !signatureB64u
  ) {
    return null;
  }
  return {
    version: 'near_account_ownership_proof_v1',
    signatureB64u,
    message: {
      version: 'near_account_ownership_proof_message_v1',
      walletId,
      rpId,
      nearAccountId,
      publicKey,
      nonceB64u,
      issuedAtMs,
      expiresAtMs,
    },
  };
}
