import { alphabetizeStringify, sha256BytesUtf8 } from './digests';
import type {
  AppSessionVersion,
  ChallengeSubjectId,
  EmailOtpChallengeId,
  OrgId,
  ProviderSubject,
  WalletId,
  WebAuthnRpId,
} from './domainIds';
import { parseWalletId, parseWebAuthnRpId } from './domainIds';
import { base64UrlEncode } from './encoders';
import {
  parseNamedNearAccountId,
  type ImplicitNearAccountId,
  type NamedNearAccountId,
} from './near';

export type { WalletId, WebAuthnRpId } from './domainIds';
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

export type ServerAllocatedWalletId = WalletId & {
  readonly __serverAllocatedWalletIdBrand: unique symbol;
};

export type NearEd25519SigningKeyId = string & {
  readonly __nearEd25519SigningKeyIdBrand: unique symbol;
};

export type RegisterWalletInput =
  | {
      kind: 'server_allocated';
      walletId?: never;
    }
  | {
      kind: 'provided';
      walletId: WalletId;
    };

export type PasskeyRegistrationAuthMethodInput = {
  kind: 'passkey';
  rpId: WebAuthnRpId;
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
      rpId?: never;
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
      rpId?: never;
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
      rpId: WebAuthnRpId;
      email?: never;
      otpCode?: never;
      challengeId?: never;
      appSessionJwt?: never;
      authenticatorOptions?: never;
    }
  | {
      kind: 'email_otp';
      email: string;
      rpId?: never;
      otpCode?: never;
      challengeId?: never;
      appSessionJwt?: never;
      authenticatorOptions?: never;
    };

export type WalletAuthMethodTarget =
  | {
      kind: 'passkey';
      rpId: WebAuthnRpId;
      credentialIdB64u: string;
      email?: never;
    }
  | {
      kind: 'email_otp';
      email: string;
      rpId?: never;
      credentialIdB64u?: never;
    };

export type RegistrationAuthority =
  | {
      kind: 'passkey';
      walletId: WalletId;
      rpId: WebAuthnRpId;
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
      rpId: WebAuthnRpId;
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

export type RegistrationSignerBranchKey = string & {
  readonly __registrationSignerBranchKeyBrand: unique symbol;
};

export type RegistrationNearEd25519SignerRequest = {
  kind: 'near_ed25519';
  accountProvisioning: RegistrationNearAccountProvisioning;
  signerSlot: number;
  participantIds: readonly number[];
  derivationVersion: number;
  keyPurpose?: never;
  keyVersion?: never;
  chainTargets?: never;
};

export type RegistrationEvmFamilyEcdsaSignerRequest = {
  kind: 'evm_family_ecdsa';
  participantIds: readonly number[];
  chainTargets: readonly unknown[];
  accountProvisioning?: never;
  signerSlot?: never;
  keyPurpose?: never;
  keyVersion?: never;
  derivationVersion?: never;
};

export type RegistrationSignerRequest =
  | RegistrationNearEd25519SignerRequest
  | RegistrationEvmFamilyEcdsaSignerRequest;

export type RegistrationSignerSetSelection = {
  kind: 'signer_set';
  signers: readonly RegistrationSignerRequest[];
  mode?: never;
  ed25519?: never;
  ecdsa?: never;
};

export type RegistrationNearEd25519SignerPlan = {
  kind: 'near_ed25519';
  branchKey: RegistrationSignerBranchKey;
  accountProvisioning: RegistrationNearAccountProvisioning;
  signerSlot: number;
  participantIds: readonly number[];
  keyPurpose: string;
  keyVersion: string;
  derivationVersion: number;
  chainTargets?: never;
};

export type RegistrationEvmFamilyEcdsaSignerPlan = RegistrationEvmFamilyEcdsaSignerRequest & {
  branchKey: RegistrationSignerBranchKey;
};

export type RegistrationSignerPlanBranch =
  | RegistrationNearEd25519SignerPlan
  | RegistrationEvmFamilyEcdsaSignerPlan;

export type RegistrationSignerPlan = {
  kind: 'signer_set';
  branches: readonly RegistrationSignerPlanBranch[];
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
  authMethod: RegistrationAuthMethodInput;
  signerSelection: RegistrationSignerSetSelection;
  runtimePolicyScope?: RuntimePolicyScopeLike;
  nonceB64u: string;
};

export type AddSignerIntentV1 = {
  version: 'add_signer_intent_v1';
  walletId: WalletId;
  signerSelection: AddSignerSelection;
  runtimePolicyScope?: RuntimePolicyScopeLike;
  nonceB64u: string;
};

export type AddAuthMethodIntentV1 = {
  version: 'add_auth_method_intent_v1';
  walletId: WalletId;
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

export type ServerAllocatedWalletIdParseResult =
  | { ok: true; value: ServerAllocatedWalletId }
  | {
      ok: false;
      error: {
        code: 'missing' | 'invalid';
        message: string;
      };
    };

const SERVER_ALLOCATED_WALLET_ADJECTIVES = [
  'amber',
  'brisk',
  'cedar',
  'cobalt',
  'crimson',
  'frost',
  'golden',
  'harbor',
  'indigo',
  'jade',
  'lunar',
  'maple',
  'opal',
  'polar',
  'silver',
  'verdant',
  'violet',
  'willow',
] as const;

const SERVER_ALLOCATED_WALLET_NOUNS = [
  'atlas',
  'bloom',
  'canyon',
  'ember',
  'fjord',
  'giant',
  'grove',
  'harvest',
  'lantern',
  'meadow',
  'orchid',
  'quartz',
  'raven',
  'solstice',
  'summit',
  'tempo',
  'vermillion',
  'voyage',
  'zenith',
] as const;

const SERVER_ALLOCATED_WALLET_SUFFIX_ALPHABET = '23456789abcdefghjkmnpqrstuvwxyz';
const SERVER_ALLOCATED_WALLET_ID_PATTERN = /^([a-z]+)-([a-z]+)-([a-z0-9]{6})$/;
const SERVER_ALLOCATED_WALLET_ADJECTIVE_SET = new Set<string>(SERVER_ALLOCATED_WALLET_ADJECTIVES);
const SERVER_ALLOCATED_WALLET_NOUN_SET = new Set<string>(SERVER_ALLOCATED_WALLET_NOUNS);

export function createServerAllocatedWalletId(): ServerAllocatedWalletId {
  return requireServerAllocatedWalletId(
    [
      randomServerAllocatedWalletWord(SERVER_ALLOCATED_WALLET_ADJECTIVES),
      randomServerAllocatedWalletWord(SERVER_ALLOCATED_WALLET_NOUNS),
      randomServerAllocatedWalletSuffix(6),
    ].join('-'),
  );
}

export function parseServerAllocatedWalletId(raw: unknown): ServerAllocatedWalletIdParseResult {
  const parsed = parseWalletId(raw);
  if (!parsed.ok) return parsed;
  const value = String(parsed.value);
  const match = SERVER_ALLOCATED_WALLET_ID_PATTERN.exec(value);
  const adjective = match?.[1] || '';
  const noun = match?.[2] || '';
  const suffix = match?.[3] || '';
  if (
    !match ||
    !SERVER_ALLOCATED_WALLET_ADJECTIVE_SET.has(adjective) ||
    !SERVER_ALLOCATED_WALLET_NOUN_SET.has(noun) ||
    !serverAllocatedWalletSuffixIsValid(suffix)
  ) {
    return {
      ok: false,
      error: {
        code: 'invalid',
        message:
          'server-allocated walletId must match the approved readable word-word-suffix allocation format',
      },
    };
  }
  return { ok: true, value: parsed.value as ServerAllocatedWalletId };
}

export function requireServerAllocatedWalletId(value: unknown): ServerAllocatedWalletId {
  const parsed = parseServerAllocatedWalletId(value);
  if (!parsed.ok) {
    throw new Error(parsed.error.message);
  }
  return parsed.value;
}

function serverAllocatedRandomIndex(maxExclusive: number): number {
  if (!Number.isSafeInteger(maxExclusive) || maxExclusive <= 0 || maxExclusive > 256) {
    throw new Error('Invalid server-allocated wallet random bound');
  }
  const limit = 256 - (256 % maxExclusive);
  const byte = new Uint8Array(1);
  for (;;) {
    crypto.getRandomValues(byte);
    if (byte[0] < limit) return byte[0] % maxExclusive;
  }
}

function randomServerAllocatedWalletWord(words: readonly string[]): string {
  return words[serverAllocatedRandomIndex(words.length)]!;
}

function randomServerAllocatedWalletSuffix(length: number): string {
  let suffix = '';
  for (let index = 0; index < length; index += 1) {
    suffix +=
      SERVER_ALLOCATED_WALLET_SUFFIX_ALPHABET[
        serverAllocatedRandomIndex(SERVER_ALLOCATED_WALLET_SUFFIX_ALPHABET.length)
      ];
  }
  return suffix;
}

function serverAllocatedWalletSuffixIsValid(suffix: string): boolean {
  if (suffix.length !== 6) return false;
  for (const character of suffix) {
    if (!SERVER_ALLOCATED_WALLET_SUFFIX_ALPHABET.includes(character)) return false;
  }
  return true;
}

export function nearEd25519SigningKeyIdFromString(value: string): NearEd25519SigningKeyId {
  const normalized = String(value || '').trim();
  if (!normalized) {
    throw new Error('nearEd25519SigningKeyId is required');
  }
  return normalized as NearEd25519SigningKeyId;
}

export function parseNearEd25519SigningKeyId(value: unknown): NearEd25519SigningKeyId {
  if (typeof value !== 'string') {
    throw new Error('nearEd25519SigningKeyId must be a string');
  }
  return nearEd25519SigningKeyIdFromString(value);
}

export function formatNearEd25519SigningKeyIdForWire(value: NearEd25519SigningKeyId): string {
  return value;
}

export function nearEd25519SigningKeyIdFromWalletId(walletId: WalletId): NearEd25519SigningKeyId {
  return nearEd25519SigningKeyIdFromString(String(walletId));
}

export type GeneratedImplicitNearEd25519SigningKeyDigestInput = {
  kind: 'generated_implicit_near_ed25519_signing_key_v1';
  walletId: ServerAllocatedWalletId;
  authorityScope: RegistrationEd25519AuthorityScope;
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
    authorityScope: input.authorityScope,
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

export type RegistrationEd25519AuthorityScope =
  | {
      kind: 'passkey';
      rpId: WebAuthnRpId;
      proofKind?: never;
      email?: never;
      challengeId?: never;
      googleEmailOtpRegistrationAttemptId?: never;
      googleEmailOtpRegistrationOfferId?: never;
      googleEmailOtpRegistrationCandidateId?: never;
    }
  | {
      kind: 'email_otp';
      proofKind: 'otp_challenge';
      email: string;
      challengeId?: string;
      rpId?: never;
      googleEmailOtpRegistrationAttemptId?: never;
      googleEmailOtpRegistrationOfferId?: never;
      googleEmailOtpRegistrationCandidateId?: never;
    }
  | {
      kind: 'email_otp';
      proofKind: 'google_sso_registration';
      email: string;
      googleEmailOtpRegistrationAttemptId: string;
      googleEmailOtpRegistrationOfferId: string;
      googleEmailOtpRegistrationCandidateId: string;
      rpId?: never;
      challengeId?: never;
    };

export function registrationEd25519AuthorityScope(
  authMethod: RegistrationAuthMethodInput,
): RegistrationEd25519AuthorityScope {
  switch (authMethod.kind) {
    case 'passkey':
      return {
        kind: 'passkey',
        rpId: authMethod.rpId,
      };
    case 'email_otp':
      switch (authMethod.proofKind) {
        case 'otp_challenge':
          return {
            kind: 'email_otp',
            proofKind: 'otp_challenge',
            email: authMethod.email,
            ...(authMethod.challengeId ? { challengeId: authMethod.challengeId } : {}),
          };
        case 'google_sso_registration':
          return {
            kind: 'email_otp',
            proofKind: 'google_sso_registration',
            email: authMethod.email,
            googleEmailOtpRegistrationAttemptId: authMethod.googleEmailOtpRegistrationAttemptId,
            googleEmailOtpRegistrationOfferId: authMethod.googleEmailOtpRegistrationOfferId,
            googleEmailOtpRegistrationCandidateId: authMethod.googleEmailOtpRegistrationCandidateId,
          };
        default: {
          const exhaustive: never = authMethod;
          return exhaustive;
        }
      }
    default: {
      const exhaustive: never = authMethod;
      return exhaustive;
    }
  }
}

export async function computeRegistrationNearEd25519SigningKeyId(input: {
  walletId: WalletId;
  authorityScope: RegistrationEd25519AuthorityScope;
  signingRootId: string;
  signingRootVersion: string;
  ed25519: ThresholdEd25519RegistrationSpec;
}): Promise<NearEd25519SigningKeyId> {
  switch (input.ed25519.accountProvisioning.kind) {
    case 'implicit_account':
      return await computeGeneratedImplicitNearEd25519SigningKeyId({
        kind: 'generated_implicit_near_ed25519_signing_key_v1',
        walletId: requireServerAllocatedWalletId(input.walletId),
        authorityScope: input.authorityScope,
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

function normalizePositiveInteger(raw: unknown, fallback: number): number {
  const value = typeof raw === 'number' ? raw : Number(raw);
  return Number.isFinite(value) && value >= 1 ? Math.floor(value) : fallback;
}

function collectPositiveParticipantIds(raw: unknown): number[] {
  if (!Array.isArray(raw)) return [];
  const participantIds: number[] = [];
  for (const id of raw) {
    const numericId = Number(id);
    if (Number.isInteger(numericId) && numericId > 0) participantIds.push(numericId);
  }
  return participantIds;
}

function normalizeUnknownArray(raw: unknown): unknown[] {
  return Array.isArray(raw) ? raw : [];
}

function normalizeRegistrationNearAccountProvisioning(
  raw: unknown,
): RegistrationNearAccountProvisioning | null {
  if (!isRecord(raw)) return null;
  const kind = trimString(raw.kind);
  switch (kind) {
    case 'implicit_account':
      if (
        Object.prototype.hasOwnProperty.call(raw, 'requestedAccountId') ||
        Object.prototype.hasOwnProperty.call(raw, 'sponsor')
      ) {
        return null;
      }
      return {
        kind: 'implicit_account',
        accountIdSource: 'ed25519_public_key',
      };
    case 'sponsored_named_account': {
      if (Object.prototype.hasOwnProperty.call(raw, 'accountIdSource')) return null;
      const parsed = parseNamedNearAccountId(raw.requestedAccountId);
      if (!parsed.ok) return null;
      return {
        kind: 'sponsored_named_account',
        requestedAccountId: parsed.value,
        sponsor: 'relayer',
      };
    }
    default:
      return null;
  }
}

function normalizeRegistrationEcdsaSpec(
  value: Record<string, unknown> | null,
): ThresholdEcdsaRegistrationSpec | null {
  if (!value) return null;
  const participantIds = collectPositiveParticipantIds(value.participantIds);
  const chainTargets = normalizeUnknownArray(value.chainTargets);
  if (participantIds.length === 0 || chainTargets.length === 0) return null;
  return { participantIds, chainTargets };
}

export type NormalizeSignerSelectionResult<TSelection> =
  | { ok: true; value: TSelection }
  | { ok: false; code: string; message: string };

export type NormalizeAddSignerSelectionOptions = {
  readonly normalizeEcdsaChainTarget: (target: unknown) => unknown | null;
};

export type RegistrationSignerSetSelectionFromPlanOptions = {
  readonly normalizeEcdsaChainTarget?: (target: unknown) => unknown | null;
};

const REGISTRATION_NEAR_ED25519_KEY_PURPOSE = 'near_tx';
const REGISTRATION_NEAR_ED25519_KEY_VERSION = 'threshold-ed25519-hss-v1';

export function registrationSignerBranchKeyFromString(value: string): RegistrationSignerBranchKey {
  const normalized = trimString(value);
  if (!normalized) {
    throw new Error('registration signer branch key is required');
  }
  return normalized as RegistrationSignerBranchKey;
}

export function registrationNearEd25519BranchKey(signerSlot: number): RegistrationSignerBranchKey {
  return registrationSignerBranchKeyFromString(`near_ed25519:slot:${signerSlot}`);
}

function registrationEvmFamilyEcdsaTargetKey(target: unknown): string {
  return alphabetizeStringify(target);
}

export function registrationEvmFamilyEcdsaBranchKey(
  chainTargets: readonly unknown[],
): RegistrationSignerBranchKey {
  return registrationSignerBranchKeyFromString(
    `evm_family_ecdsa:${chainTargets.map(registrationEvmFamilyEcdsaTargetKey).join('|')}`,
  );
}

function registrationSignerPlanFromRequests(
  signers: readonly RegistrationSignerRequest[],
): NormalizeSignerSelectionResult<RegistrationSignerPlan> {
  return registrationSignerPlanFromBranches(signers.map(registrationSignerPlanBranchFromRequest));
}

function registrationSignerPlanFromBranches(
  branches: readonly RegistrationSignerPlanBranch[],
): NormalizeSignerSelectionResult<RegistrationSignerPlan> {
  if (branches.length === 0) {
    return {
      ok: false,
      code: 'invalid_body',
      message: 'signer set must include at least one signer',
    };
  }
  const nearSlots = new Set<number>();
  const ecdsaTargetKeys = new Set<string>();
  const branchKeys = new Set<string>();
  for (const branch of branches) {
    const duplicate = findRegistrationSignerPlanDuplicate({
      branch,
      nearSlots,
      ecdsaTargetKeys,
      branchKeys,
    });
    if (duplicate) return duplicate;
  }
  return {
    ok: true,
    value: {
      kind: 'signer_set',
      branches,
    },
  };
}

function registrationSignerPlanBranchFromRequest(
  signer: RegistrationSignerRequest,
): RegistrationSignerPlanBranch {
  switch (signer.kind) {
    case 'near_ed25519':
      return {
        kind: 'near_ed25519',
        branchKey: registrationNearEd25519BranchKey(signer.signerSlot),
        accountProvisioning: signer.accountProvisioning,
        signerSlot: signer.signerSlot,
        participantIds: signer.participantIds,
        keyPurpose: REGISTRATION_NEAR_ED25519_KEY_PURPOSE,
        keyVersion: REGISTRATION_NEAR_ED25519_KEY_VERSION,
        derivationVersion: signer.derivationVersion,
      };
    case 'evm_family_ecdsa':
      return {
        kind: 'evm_family_ecdsa',
        branchKey: registrationEvmFamilyEcdsaBranchKey(signer.chainTargets),
        participantIds: signer.participantIds,
        chainTargets: signer.chainTargets,
      };
    default:
      return assertNeverRegistrationSignerRequest(signer);
  }
}

function findRegistrationSignerPlanDuplicate(input: {
  readonly branch: RegistrationSignerPlanBranch;
  readonly nearSlots: Set<number>;
  readonly ecdsaTargetKeys: Set<string>;
  readonly branchKeys: Set<string>;
}): NormalizeSignerSelectionResult<RegistrationSignerPlan> | null {
  switch (input.branch.kind) {
    case 'near_ed25519':
      if (input.nearSlots.has(input.branch.signerSlot)) {
        return {
          ok: false,
          code: 'invalid_body',
          message: 'duplicate near_ed25519 signer slot is invalid',
        };
      }
      input.nearSlots.add(input.branch.signerSlot);
      break;
    case 'evm_family_ecdsa':
      {
        const duplicateTarget = findDuplicateRegistrationEcdsaTarget(
          input.branch,
          input.ecdsaTargetKeys,
        );
        if (duplicateTarget) return duplicateTarget;
      }
      break;
    default:
      return assertNeverRegistrationSignerPlanBranch(input.branch);
  }
  return findDuplicateRegistrationSignerBranch(input.branch, input.branchKeys);
}

function findDuplicateRegistrationSignerBranch(
  branch: RegistrationSignerPlanBranch,
  branchKeys: Set<string>,
): NormalizeSignerSelectionResult<RegistrationSignerPlan> | null {
  const branchKey = String(branch.branchKey);
  if (branchKeys.has(branchKey)) {
    return { ok: false, code: 'invalid_body', message: 'duplicate signer branch is invalid' };
  }
  branchKeys.add(branchKey);
  return null;
}

function findDuplicateRegistrationEcdsaTarget(
  branch: RegistrationEvmFamilyEcdsaSignerPlan,
  ecdsaTargetKeys: Set<string>,
): NormalizeSignerSelectionResult<RegistrationSignerPlan> | null {
  for (const target of branch.chainTargets) {
    const targetKey = registrationEvmFamilyEcdsaTargetKey(target);
    if (ecdsaTargetKeys.has(targetKey)) {
      return {
        ok: false,
        code: 'invalid_body',
        message: 'duplicate evm_family_ecdsa chain target is invalid',
      };
    }
    ecdsaTargetKeys.add(targetKey);
  }
  return null;
}

function normalizeRegistrationSignerRequest(
  raw: unknown,
): NormalizeSignerSelectionResult<RegistrationSignerRequest> {
  if (!isRecord(raw)) {
    return { ok: false, code: 'invalid_body', message: 'signer set entry must be an object' };
  }
  const kind = trimString(raw.kind);
  switch (kind) {
    case 'near_ed25519':
      return normalizeRegistrationNearEd25519SignerRequest(raw);
    case 'evm_family_ecdsa':
      return normalizeRegistrationEvmFamilyEcdsaSignerRequest(raw);
    default:
      return { ok: false, code: 'invalid_body', message: 'unsupported registration signer kind' };
  }
}

function normalizeRegistrationNearEd25519SignerRequest(
  raw: Record<string, unknown>,
): NormalizeSignerSelectionResult<RegistrationSignerRequest> {
  if (
    Object.prototype.hasOwnProperty.call(raw, 'keyPurpose') ||
    Object.prototype.hasOwnProperty.call(raw, 'keyVersion')
  ) {
    return {
      ok: false,
      code: 'invalid_body',
      message: 'near_ed25519 signer spec cannot include protocol key fields',
    };
  }
  if (
    Object.prototype.hasOwnProperty.call(raw, 'nearAccountId') ||
    Object.prototype.hasOwnProperty.call(raw, 'createNearAccount')
  ) {
    return { ok: false, code: 'invalid_body', message: 'near_ed25519 signer spec is invalid' };
  }
  const accountProvisioning = normalizeRegistrationNearAccountProvisioning(raw.accountProvisioning);
  const signerSlot = normalizePositiveInteger(raw.signerSlot, 0);
  const derivationVersion = Number(raw.derivationVersion);
  const participantIds = collectPositiveParticipantIds(raw.participantIds);
  if (
    !accountProvisioning ||
    signerSlot < 1 ||
    participantIds.length === 0 ||
    derivationVersion !== 1
  ) {
    return { ok: false, code: 'invalid_body', message: 'near_ed25519 signer spec is invalid' };
  }
  return {
    ok: true,
    value: {
      kind: 'near_ed25519',
      accountProvisioning,
      signerSlot,
      participantIds,
      derivationVersion,
    },
  };
}

function normalizeRegistrationEvmFamilyEcdsaSignerRequest(
  raw: Record<string, unknown>,
): NormalizeSignerSelectionResult<RegistrationSignerRequest> {
  const ecdsa = normalizeRegistrationEcdsaSpec(raw);
  if (!ecdsa) {
    return { ok: false, code: 'invalid_body', message: 'evm_family_ecdsa signer spec is invalid' };
  }
  return {
    ok: true,
    value: {
      kind: 'evm_family_ecdsa',
      participantIds: ecdsa.participantIds,
      chainTargets: ecdsa.chainTargets,
    },
  };
}

function normalizeRegistrationSignerSetPlan(
  raw: Record<string, unknown>,
): NormalizeSignerSelectionResult<RegistrationSignerPlan> {
  if (!Array.isArray(raw.signers)) {
    return { ok: false, code: 'invalid_body', message: 'signerSelection.signers must be an array' };
  }
  const signers: RegistrationSignerRequest[] = [];
  for (const rawSigner of raw.signers) {
    const signer = normalizeRegistrationSignerRequest(rawSigner);
    if (!signer.ok) return signer;
    signers.push(signer.value);
  }
  return registrationSignerPlanFromRequests(signers);
}

export function normalizeRegistrationSignerPlan(
  raw: unknown,
): NormalizeSignerSelectionResult<RegistrationSignerPlan> {
  if (!isRecord(raw)) {
    return { ok: false, code: 'invalid_body', message: 'signerSelection must be an object' };
  }
  if (trimString(raw.kind) === 'signer_set') {
    return normalizeRegistrationSignerSetPlan(raw);
  }
  return { ok: false, code: 'invalid_body', message: 'signerSelection.kind must be signer_set' };
}

export function registrationSignerPlanFromSelection(
  selection: RegistrationSignerSetSelection,
): NormalizeSignerSelectionResult<RegistrationSignerPlan> {
  return registrationSignerPlanFromRequests(selection.signers);
}

export function findRegistrationSignerPlanNearEd25519Branch(
  plan: RegistrationSignerPlan,
): RegistrationNearEd25519SignerPlan | null {
  for (const branch of plan.branches) {
    if (branch.kind === 'near_ed25519') return branch;
  }
  return null;
}

export function findRegistrationSignerPlanEvmFamilyEcdsaBranch(
  plan: RegistrationSignerPlan,
): RegistrationEvmFamilyEcdsaSignerPlan | null {
  for (const branch of plan.branches) {
    if (branch.kind === 'evm_family_ecdsa') return branch;
  }
  return null;
}

export function registrationSignerSetSelectionFromPlan(
  plan: RegistrationSignerPlan,
  options: RegistrationSignerSetSelectionFromPlanOptions = {},
): NormalizeSignerSelectionResult<RegistrationSignerSetSelection> {
  const signers: RegistrationSignerRequest[] = [];
  for (const branch of plan.branches) {
    const signer = registrationSignerRequestFromPlanBranchForSelection(branch, options);
    if (!signer.ok) return signer;
    signers.push(signer.value);
  }
  return {
    ok: true,
    value: {
      kind: 'signer_set',
      signers,
    },
  };
}

function registrationSignerRequestFromPlanBranchForSelection(
  branch: RegistrationSignerPlanBranch,
  options: RegistrationSignerSetSelectionFromPlanOptions,
): NormalizeSignerSelectionResult<RegistrationSignerRequest> {
  switch (branch.kind) {
    case 'near_ed25519':
      return {
        ok: true,
        value: registrationNearEd25519RequestFromPlanBranch(branch),
      };
    case 'evm_family_ecdsa':
      return registrationEvmFamilyEcdsaRequestFromPlanBranch(branch, options);
    default:
      return assertNeverRegistrationSignerPlanBranch(branch);
  }
}

function registrationNearEd25519RequestFromPlanBranch(
  branch: RegistrationNearEd25519SignerPlan,
): RegistrationNearEd25519SignerRequest {
  return {
    kind: 'near_ed25519',
    accountProvisioning: branch.accountProvisioning,
    signerSlot: branch.signerSlot,
    participantIds: [...branch.participantIds],
    derivationVersion: branch.derivationVersion,
  };
}

function registrationEvmFamilyEcdsaRequestFromPlanBranch(
  branch: RegistrationEvmFamilyEcdsaSignerPlan,
  options: RegistrationSignerSetSelectionFromPlanOptions,
): NormalizeSignerSelectionResult<RegistrationEvmFamilyEcdsaSignerRequest> {
  const chainTargets = registrationEcdsaChainTargetsFromPlanBranch(branch, options);
  if (!chainTargets) {
    return {
      ok: false,
      code: 'invalid_body',
      message: 'registration ECDSA chainTargets are invalid',
    };
  }
  return {
    ok: true,
    value: {
      kind: 'evm_family_ecdsa',
      participantIds: [...branch.participantIds],
      chainTargets,
    },
  };
}

function registrationEcdsaChainTargetsFromPlanBranch(
  branch: RegistrationEvmFamilyEcdsaSignerPlan,
  options: RegistrationSignerSetSelectionFromPlanOptions,
): unknown[] | null {
  if (!options.normalizeEcdsaChainTarget) return [...branch.chainTargets];
  const chainTargets: unknown[] = [];
  for (const target of branch.chainTargets) {
    const normalized = options.normalizeEcdsaChainTarget(target);
    if (!normalized) return null;
    chainTargets.push(normalized);
  }
  return chainTargets;
}

function assertNeverRegistrationSignerRequest(value: never): never {
  throw new Error(`Unsupported registration signer request: ${String(value)}`);
}

function assertNeverRegistrationSignerPlanBranch(value: never): never {
  throw new Error(`Unsupported registration signer plan branch: ${String(value)}`);
}

export function normalizeAddSignerSelection(
  raw: unknown,
  options: NormalizeAddSignerSelectionOptions,
): NormalizeSignerSelectionResult<AddSignerSelection> {
  if (!isRecord(raw)) {
    return { ok: false, code: 'invalid_body', message: 'signerSelection must be an object' };
  }
  const mode = trimString(raw.mode);
  if (mode === 'ecdsa') return normalizeAddSignerEcdsaSelection(raw.ecdsa, options);
  if (mode === 'ed25519') return normalizeAddSignerEd25519Selection(raw.ed25519);
  return { ok: false, code: 'invalid_body', message: 'unsupported add-signer mode' };
}

function normalizeAddSignerEcdsaSelection(
  raw: unknown,
  options: NormalizeAddSignerSelectionOptions,
): NormalizeSignerSelectionResult<AddSignerSelection> {
  const ecdsaRaw = isRecord(raw) ? raw : null;
  const participantIds = collectPositiveParticipantIds(ecdsaRaw?.participantIds);
  const chainTargets = normalizeAddSignerEcdsaChainTargets(ecdsaRaw?.chainTargets, options);
  if (participantIds.length === 0 || chainTargets.length === 0) {
    return { ok: false, code: 'invalid_body', message: 'ecdsa add-signer spec is invalid' };
  }
  return {
    ok: true,
    value: {
      mode: 'ecdsa',
      ecdsa: {
        chainTargets,
        participantIds,
      },
    },
  };
}

function normalizeAddSignerEcdsaChainTargets(
  raw: unknown,
  options: NormalizeAddSignerSelectionOptions,
): unknown[] {
  if (!Array.isArray(raw)) return [];
  const chainTargets: unknown[] = [];
  for (const target of raw) {
    const normalized = options.normalizeEcdsaChainTarget(target);
    if (!normalized) return [];
    chainTargets.push(normalized);
  }
  return chainTargets;
}

function normalizeAddSignerEd25519Selection(
  raw: unknown,
): NormalizeSignerSelectionResult<AddSignerSelection> {
  const ed25519Raw = isRecord(raw) ? raw : null;
  const ed25519Mode = trimString(ed25519Raw?.mode);
  const nearAccountId = trimString(ed25519Raw?.nearAccountId);
  const signerSlot = normalizePositiveInteger(ed25519Raw?.signerSlot, 1);
  const keyPurpose = trimString(ed25519Raw?.keyPurpose);
  const keyVersion = trimString(ed25519Raw?.keyVersion);
  const derivationVersion = normalizePositiveInteger(ed25519Raw?.derivationVersion, 0);
  const participantIds = collectPositiveParticipantIds(ed25519Raw?.participantIds);
  if (
    !nearAccountId ||
    !keyPurpose ||
    !keyVersion ||
    !derivationVersion ||
    participantIds.length === 0
  ) {
    return { ok: false, code: 'invalid_body', message: 'ed25519 add-signer spec is invalid' };
  }
  if (ed25519Mode === 'create_near_account') {
    return {
      ok: true,
      value: {
        mode: 'ed25519',
        ed25519: {
          mode: ed25519Mode,
          nearAccountId,
          signerSlot,
          participantIds,
          keyPurpose,
          keyVersion,
          derivationVersion,
        },
      },
    };
  }
  if (ed25519Mode === 'link_existing_near_account') {
    return normalizeAddSignerLinkedEd25519Selection({
      raw: ed25519Raw,
      nearAccountId,
      signerSlot,
      participantIds,
      keyPurpose,
      keyVersion,
      derivationVersion,
    });
  }
  return { ok: false, code: 'invalid_body', message: 'unsupported add-signer mode' };
}

function normalizeAddSignerLinkedEd25519Selection(input: {
  readonly raw: Record<string, unknown> | null;
  readonly nearAccountId: string;
  readonly signerSlot: number;
  readonly participantIds: readonly number[];
  readonly keyPurpose: string;
  readonly keyVersion: string;
  readonly derivationVersion: number;
}): NormalizeSignerSelectionResult<AddSignerSelection> {
  const accountOwnershipProof = normalizeNearAccountOwnershipProofV1(
    input.raw?.accountOwnershipProof,
  );
  if (!accountOwnershipProof) {
    return {
      ok: false,
      code: 'invalid_body',
      message: 'ed25519 add-signer account ownership proof is required',
    };
  }
  return {
    ok: true,
    value: {
      mode: 'ed25519',
      ed25519: {
        mode: 'link_existing_near_account',
        nearAccountId: input.nearAccountId,
        signerSlot: input.signerSlot,
        participantIds: [...input.participantIds],
        keyPurpose: input.keyPurpose,
        keyVersion: input.keyVersion,
        derivationVersion: input.derivationVersion,
        accountOwnershipProof,
      },
    },
  };
}

export function normalizeRegistrationAuthMethodInput(
  raw: unknown,
): RegistrationAuthMethodInput | null {
  if (!isRecord(raw)) return null;
  const kind = trimString(raw.kind);
  if (kind === 'passkey') {
    const rpId = parseWebAuthnRpId(raw.rpId);
    if (
      !rpId.ok ||
      Object.prototype.hasOwnProperty.call(raw, 'email') ||
      Object.prototype.hasOwnProperty.call(raw, 'otpCode') ||
      Object.prototype.hasOwnProperty.call(raw, 'challengeId')
    ) {
      return null;
    }
    return {
      kind: 'passkey',
      rpId: rpId.value,
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
      Object.prototype.hasOwnProperty.call(raw, 'rpId') ||
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
    const rpId = parseWebAuthnRpId(raw.rpId);
    if (
      !rpId.ok ||
      Object.prototype.hasOwnProperty.call(raw, 'email') ||
      Object.prototype.hasOwnProperty.call(raw, 'otpCode') ||
      Object.prototype.hasOwnProperty.call(raw, 'challengeId') ||
      Object.prototype.hasOwnProperty.call(raw, 'appSessionJwt') ||
      Object.prototype.hasOwnProperty.call(raw, 'authenticatorOptions')
    ) {
      return null;
    }
    return { kind: 'passkey', rpId: rpId.value };
  }
  if (kind === 'email_otp') {
    const email = trimString(raw.email);
    if (
      !email ||
      Object.prototype.hasOwnProperty.call(raw, 'rpId') ||
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
    const rpId = parseWebAuthnRpId(raw.rpId);
    const credentialIdB64u = trimString(raw.credentialIdB64u);
    if (!rpId.ok || !credentialIdB64u || Object.prototype.hasOwnProperty.call(raw, 'email')) {
      return null;
    }
    return {
      kind: 'passkey',
      rpId: rpId.value,
      credentialIdB64u,
    };
  }
  if (kind === 'email_otp') {
    const email = trimString(raw.email).toLowerCase();
    if (
      !email ||
      Object.prototype.hasOwnProperty.call(raw, 'rpId') ||
      Object.prototype.hasOwnProperty.call(raw, 'credentialIdB64u')
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
  const walletId = parseWalletId(trimString(message.walletId));
  const nearAccountId = trimString(message.nearAccountId);
  const publicKey = trimString(message.publicKey);
  const nonceB64u = trimString(message.nonceB64u);
  const issuedAtMs = normalizeTimestampMs(message.issuedAtMs);
  const expiresAtMs = normalizeTimestampMs(message.expiresAtMs);
  const signatureB64u = trimString(raw.signatureB64u);
  if (
    proofVersion !== 'near_account_ownership_proof_v1' ||
    messageVersion !== 'near_account_ownership_proof_message_v1' ||
    Object.prototype.hasOwnProperty.call(message, 'rpId') ||
    !walletId.ok ||
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
      walletId: walletId.value,
      nearAccountId,
      publicKey,
      nonceB64u,
      issuedAtMs,
      expiresAtMs,
    },
  };
}
