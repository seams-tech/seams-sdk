import { base64UrlDecode } from '@shared/utils/encoders';
import { parseDigestB64u, type DigestB64u } from '@shared/utils/canonicalPrimitives';
import {
  parseProviderSubject,
  parseWebAuthnCredentialIdB64u,
  parseWebAuthnRpId,
  parseLinkedDeviceEnrollmentId,
  parseLinkedDeviceId,
  parseWalletKeyId,
  type ProviderSubject,
  type WebAuthnCredentialIdB64u,
  type LinkedDeviceEnrollmentId,
  type LinkedDeviceId,
  type WalletKeyId,
} from '@shared/utils/domainIds';
import {
  isEmailOtpWalletAuthAuthority,
  isPasskeyWalletAuthAuthority,
  parseWalletAuthAuthorityRef,
  parseWalletAuthAuthority,
  type WalletAuthAuthority,
  type WalletAuthAuthorityRef,
} from '@shared/utils/walletAuthAuthority';
import { ensureEd25519Prefix, toOptionalString, toTrimmedString } from '@shared/utils/validation';
import {
  ECDSA_DERIVATION_ROLE_LOCAL_FIRST_BOOTSTRAP_ROOT_PROOF_VERSION,
  type EcdsaClientRootPublicKey33B64u,
  type DerivationClientSharePublicKey33B64u,
  type EcdsaDerivationRelayerPublicKey33B64u,
  type EcdsaDerivationRoleLocalFirstBootstrapRootProof,
} from '@shared/threshold/ecdsaDerivationRoleLocalBootstrap';
import {
  THRESHOLD_ED25519_2P_PARTICIPANT_IDS,
  normalizeThresholdEd25519ParticipantIds,
} from '@shared/threshold/participants';
import {
  MAX_WALLET_SESSION_REMAINING_USES,
  MAX_WALLET_SESSION_TTL_MS,
} from '@shared/threshold/sessionPolicy';
import type { RuntimePolicyScope } from '@shared/threshold/signingRootScope';
import { normalizeRuntimePolicyScope } from '@shared/threshold/signingRootScope';
import {
  ROUTER_AB_ECDSA_DERIVATION_WALLET_SESSION_JWT_KIND,
  ROUTER_AB_ED25519_WALLET_SESSION_JWT_KIND,
} from '@shared/utils/sessionTokens';
import {
  parseEvmFamilySigningKeySlotIdOrNull,
  type EvmFamilySigningKeySlotId,
} from '@shared/signing-lanes';
import {
  parseRouterAbEcdsaDerivationNormalSigningStateV1,
  parseRouterAbEcdsaDerivationNormalSigningScopeV1,
  type RouterAbEcdsaDerivationNormalSigningStateV1,
  type RouterAbEcdsaDerivationNormalSigningScopeV1,
} from '@shared/utils/routerAbEcdsaDerivation';
import {
  parseRouterAbEd25519NormalSigningState,
  type RouterAbEd25519NormalSigningState,
} from '@shared/utils/signingSessionSeal';
import type {
  EcdsaDerivationClientBootstrapRequest,
  EcdsaDerivationPasskeyBootstrapAuthorization,
  EcdsaDerivationPublicIdentity,
  ThresholdEd25519AuthorityScope,
  WebAuthnAuthenticationCredential,
} from '../types';
import { registrationPreparationIdFromString } from '../registrationContracts';
import {
  parseMpcWalletSigningQuotaId,
  parseTenantId,
  parseLinkedDeviceWalletSessionAuthorizationId,
  parseWalletSessionAuthorizationId,
  parseWalletSessionId,
  type MpcWalletSigningQuotaId,
  type TenantId,
  type LinkedDeviceWalletSessionAuthorizationId,
  type WalletSessionAuthorizationId,
  type WalletSessionId,
} from '@shared/authorization/capabilityKinds';
import { parseEcdsaKeyHandle, type EcdsaKeyHandle } from '../keyMaterialBrands';
import {
  parseDelegatedWalletAuthorityV1,
  type DelegatedWalletAuthorityV1,
} from '@shared/authorization/delegatedAuthority';

export type ThresholdValidationOk = { ok: true };
export type ThresholdValidationErr = { ok: false; code: string; message: string };
export type ThresholdValidationResult = ThresholdValidationOk | ThresholdValidationErr;

export function isObject(v: unknown): v is Record<string, unknown> {
  return !!v && typeof v === 'object' && !Array.isArray(v);
}

export function isValidNumber(v: unknown): v is number {
  return typeof v === 'number' && Number.isFinite(v);
}

function isNonNegativeInteger(v: unknown): v is number {
  return typeof v === 'number' && Number.isSafeInteger(v) && v >= 0;
}

function isPositiveIntegerAtMost(value: unknown, maximum: number): value is number {
  return typeof value === 'number' && Number.isSafeInteger(value) && value > 0 && value <= maximum;
}

function decodeFixedB64u(value: string, expectedLength: number): Uint8Array | null {
  try {
    const decoded = base64UrlDecode(value);
    if (decoded.length !== expectedLength) return null;
    return decoded;
  } catch {
    return null;
  }
}

function parseB64uFixed(value: unknown, expectedLength: number): string | null {
  const text = toOptionalString(value);
  if (!text) return null;
  return decodeFixedB64u(text, expectedLength) ? text : null;
}

function parseSec1CompressedPublicKey33B64u(value: unknown): string | null {
  const text = toOptionalString(value);
  if (!text) return null;
  const decoded = decodeFixedB64u(text, 33);
  if (!decoded) return null;
  const prefix = decoded[0];
  if (prefix !== 0x02 && prefix !== 0x03) return null;
  return text;
}

function parseEcdsaDerivationClientRootProof(
  value: unknown,
): EcdsaDerivationRoleLocalFirstBootstrapRootProof | null {
  if (!isObject(value)) return null;
  if (
    toOptionalString(value.version) !==
    ECDSA_DERIVATION_ROLE_LOCAL_FIRST_BOOTSTRAP_ROOT_PROOF_VERSION
  ) {
    return null;
  }
  const clientRootPublicKey33B64u = parseSec1CompressedPublicKey33B64u(
    value.clientRootPublicKey33B64u,
  );
  const digest32B64u = parseB64uFixed(value.digest32B64u, 32);
  const signature65B64u = parseB64uFixed(value.signature65B64u, 65);
  if (!clientRootPublicKey33B64u || !digest32B64u || !signature65B64u) return null;
  return {
    version: ECDSA_DERIVATION_ROLE_LOCAL_FIRST_BOOTSTRAP_ROOT_PROOF_VERSION,
    clientRootPublicKey33B64u: clientRootPublicKey33B64u as EcdsaClientRootPublicKey33B64u,
    digest32B64u,
    signature65B64u,
  };
}

function parseWebAuthnAuthenticationCredential(
  value: unknown,
): WebAuthnAuthenticationCredential | null {
  if (!isObject(value)) return null;
  const id = toOptionalString(value.id);
  const rawId = toOptionalString(value.rawId);
  const type = toOptionalString(value.type);
  const authenticatorAttachment =
    value.authenticatorAttachment === undefined || value.authenticatorAttachment === null
      ? null
      : toOptionalString(value.authenticatorAttachment);
  if (!id || !rawId || !type) return null;
  if (value.authenticatorAttachment !== undefined && value.authenticatorAttachment !== null) {
    if (!authenticatorAttachment) return null;
  }
  if (!isObject(value.response)) return null;
  const clientDataJSON = toOptionalString(value.response.clientDataJSON);
  const authenticatorData = toOptionalString(value.response.authenticatorData);
  const signature = toOptionalString(value.response.signature);
  const userHandle =
    value.response.userHandle === undefined || value.response.userHandle === null
      ? null
      : toOptionalString(value.response.userHandle);
  if (!clientDataJSON || !authenticatorData || !signature) return null;
  if (
    value.response.userHandle !== undefined &&
    value.response.userHandle !== null &&
    !userHandle
  ) {
    return null;
  }
  return {
    id,
    rawId,
    type,
    authenticatorAttachment,
    response: {
      clientDataJSON,
      authenticatorData,
      signature,
      userHandle,
    },
    clientExtensionResults: value.clientExtensionResults ?? null,
  };
}

function parseEcdsaDerivationPasskeyBootstrapAuthorization(
  value: unknown,
): EcdsaDerivationPasskeyBootstrapAuthorization | null {
  if (!isObject(value)) return null;
  if (toOptionalString(value.kind) !== 'passkey_bootstrap') return null;
  const rpId = toOptionalString(value.rpId);
  const webauthnAuthentication = parseWebAuthnAuthenticationCredential(
    value.webauthn_authentication,
  );
  let runtimePolicyScope: RuntimePolicyScope | undefined;
  if (value.runtimePolicyScope !== undefined) {
    try {
      runtimePolicyScope = normalizeRuntimePolicyScope(value.runtimePolicyScope);
    } catch {
      return null;
    }
  }
  const projectEnvironmentId = toOptionalString(value.projectEnvironmentId);
  if (!rpId || !webauthnAuthentication) return null;
  return {
    kind: 'passkey_bootstrap',
    rpId,
    webauthn_authentication: webauthnAuthentication,
    ...(runtimePolicyScope ? { runtimePolicyScope } : {}),
    ...(projectEnvironmentId ? { projectEnvironmentId } : {}),
  };
}

function hasForbiddenFields(raw: Record<string, unknown>, fields: readonly string[]): boolean {
  return fields.some((field) => raw[field] !== undefined);
}

export type ParsedThresholdEcdsaSigningRootMetadata = {
  signingRootId: string;
  signingRootVersion?: string;
  walletKeyVersion: string;
  derivationVersion: number;
};

function hasThresholdEcdsaSigningRootMetadata(raw: Record<string, unknown>): boolean {
  return (
    raw.signingRootId !== undefined ||
    raw.signingRootVersion !== undefined ||
    raw.walletKeyVersion !== undefined ||
    raw.derivationVersion !== undefined
  );
}

function parseThresholdEcdsaSigningRootMetadataFields(
  raw: Record<string, unknown>,
): ParsedThresholdEcdsaSigningRootMetadata | null {
  const signingRootId = toOptionalString(raw.signingRootId);
  const signingRootVersion = toOptionalString(raw.signingRootVersion);
  const walletKeyVersion = toOptionalString(raw.walletKeyVersion);
  const derivationVersionRaw = raw.derivationVersion;
  if (!signingRootId || !walletKeyVersion) return null;
  if (!isValidNumber(derivationVersionRaw)) return null;
  const derivationVersion = Math.floor(derivationVersionRaw);
  if (derivationVersion < 1 || derivationVersion !== derivationVersionRaw) return null;
  return {
    signingRootId,
    ...(signingRootVersion ? { signingRootVersion } : {}),
    walletKeyVersion,
    derivationVersion,
  };
}

function parseOptionalThresholdEcdsaSigningRootMetadataFields(
  raw: Record<string, unknown>,
): { ok: true; value?: ParsedThresholdEcdsaSigningRootMetadata } | { ok: false } {
  if (!hasThresholdEcdsaSigningRootMetadata(raw)) return { ok: true };
  const value = parseThresholdEcdsaSigningRootMetadataFields(raw);
  return value ? { ok: true, value } : { ok: false };
}

export function toPrefixWithColon(prefix: unknown, defaultPrefix: string): string {
  const p = toOptionalString(prefix);
  if (!p) return defaultPrefix;
  return p.endsWith(':') ? p : `${p}:`;
}

export function toThresholdEd25519KeyPrefix(prefix: unknown): string {
  return toPrefixWithColon(prefix, 'w3a:threshold-ed25519:key:');
}

export function toThresholdEd25519SessionPrefix(prefix: unknown): string {
  return toPrefixWithColon(prefix, 'w3a:threshold-ed25519:sess:');
}

export function toThresholdEd25519WalletSessionPrefix(prefix: unknown): string {
  return toPrefixWithColon(prefix, 'w3a:threshold-ed25519:wallet-session:');
}

export function toThresholdEd25519PrefixFromBase(
  basePrefix: unknown,
  kind: 'key' | 'sess' | 'wallet-session',
): string {
  const base = toOptionalString(basePrefix);
  if (!base) return '';
  const trimmed = base.trim();
  if (!trimmed) return '';
  const prefix = trimmed.endsWith(':') ? trimmed : `${trimmed}:`;
  return `${prefix}${kind}:`;
}

export function canonicalThresholdEd25519RelayerKeyId(relayerKeyId: unknown): string {
  return ensureEd25519Prefix(toOptionalString(relayerKeyId));
}

export function toThresholdEcdsaKeyPrefix(prefix: unknown): string {
  return toPrefixWithColon(prefix, 'w3a:threshold-ecdsa:key:');
}

export function toThresholdEcdsaSessionPrefix(prefix: unknown): string {
  return toPrefixWithColon(prefix, 'w3a:threshold-ecdsa:sess:');
}

export function toThresholdEcdsaWalletSessionPrefix(prefix: unknown): string {
  return toPrefixWithColon(prefix, 'w3a:threshold-ecdsa:wallet-session:');
}

export function toThresholdEcdsaPresignPrefix(prefix: unknown): string {
  return toPrefixWithColon(prefix, 'w3a:threshold-ecdsa:presign:');
}

export function toThresholdEcdsaPrefixFromBase(
  basePrefix: unknown,
  kind: 'key' | 'sess' | 'wallet-session' | 'presign',
): string {
  const base = toOptionalString(basePrefix);
  if (!base) return '';
  const trimmed = base.trim();
  if (!trimmed) return '';
  const prefix = trimmed.endsWith(':') ? trimmed : `${trimmed}:`;
  return `${prefix}threshold-ecdsa:${kind}:`;
}

export type ParsedThresholdEd25519RouterMaterial = {
  signingShareB64u: string;
  verifyingShareB64u: string;
};

export type ParsedThresholdEd25519ProvisioningKeyRecord = {
  kind: 'provisioning';
  walletId: string;
  nearAccountId: string;
  nearEd25519SigningKeyId: string;
  authorityScope: ThresholdEd25519AuthorityScope;
  publicKey: string;
  keyVersion: string;
  routerMaterial?: never;
  recoveryExportCapable?: never;
};

export type ParsedThresholdEd25519ReadyKeyRecord = {
  kind: 'ready';
  walletId: string;
  nearAccountId: string;
  nearEd25519SigningKeyId: string;
  authorityScope: ThresholdEd25519AuthorityScope;
  publicKey: string;
  routerMaterial: ParsedThresholdEd25519RouterMaterial;
  keyVersion: string;
  recoveryExportCapable: true;
};

export type ParsedThresholdEd25519KeyRecord =
  | ParsedThresholdEd25519ProvisioningKeyRecord
  | ParsedThresholdEd25519ReadyKeyRecord;

function parseThresholdEd25519RouterMaterial(
  raw: Record<string, unknown>,
): ParsedThresholdEd25519RouterMaterial | null {
  if (!isObject(raw.routerMaterial)) return null;
  const signingShareB64u = toOptionalString(raw.routerMaterial.signingShareB64u);
  const verifyingShareB64u = toOptionalString(raw.routerMaterial.verifyingShareB64u);
  if (!signingShareB64u || !verifyingShareB64u) return null;
  return { signingShareB64u, verifyingShareB64u };
}

export function parseThresholdEd25519ReadyKeyRecord(
  raw: unknown,
): ParsedThresholdEd25519ReadyKeyRecord | null {
  if (!isObject(raw)) return null;
  const kind = toOptionalString(raw.kind);
  const walletId = toOptionalString(raw.walletId);
  const nearAccountId = toOptionalString(raw.nearAccountId);
  const nearEd25519SigningKeyId = toOptionalString(raw.nearEd25519SigningKeyId);
  const authorityScope = parseThresholdEd25519AuthorityScope(raw.authorityScope);
  const publicKey = toOptionalString(raw.publicKey);
  const routerMaterial = parseThresholdEd25519RouterMaterial(raw);
  const keyVersion = toOptionalString(raw.keyVersion);
  const recoveryExportCapable = raw.recoveryExportCapable === true ? (true as const) : false;
  if (
    Object.prototype.hasOwnProperty.call(raw, 'rpId') ||
    kind !== 'ready' ||
    !walletId ||
    !nearAccountId ||
    !nearEd25519SigningKeyId ||
    !authorityScope ||
    !publicKey ||
    !routerMaterial ||
    !keyVersion ||
    recoveryExportCapable !== true
  )
    return null;
  return {
    kind: 'ready',
    walletId,
    nearAccountId,
    nearEd25519SigningKeyId,
    authorityScope,
    publicKey,
    routerMaterial,
    keyVersion,
    recoveryExportCapable: true,
  };
}

export function parseThresholdEd25519KeyRecord(
  raw: unknown,
): ParsedThresholdEd25519ReadyKeyRecord | null {
  return parseThresholdEd25519ReadyKeyRecord(raw);
}

const ECDSA_DERIVATION_V1_CONTEXT_FORBIDDEN_FIELDS = [
  'subjectId',
  'walletSessionUserId',
  'walletKeyId',
  'subject_id',
  'wallet_session_user_id',
  'wallet_id',
  'wallet_key_id',
  'ecdsa_threshold_key_id',
  'signing_root_id',
  'signing_root_version',
  'keyPurpose',
  'key_purpose',
  'keyVersion',
  'key_version',
] as const;

function hasExactFields(raw: Record<string, unknown>, fields: readonly string[]): boolean {
  const allowed = new Set(fields);
  const actual = Object.keys(raw);
  return actual.length === fields.length && actual.every((field) => allowed.has(field));
}

const ECDSA_DERIVATION_BOOTSTRAP_FORBIDDEN_FIELDS = [
  ...ECDSA_DERIVATION_V1_CONTEXT_FORBIDDEN_FIELDS,
  'rpId',
  'rp_id',
  'chainTarget',
  'yClient32Le',
  'yClient32LeB64u',
  'clientRootShare32B64u',
  'clientShare32B64u',
  'xClient32',
  'xClient32B64u',
  'yRelayer32Le',
  'yRelayer32LeB64u',
  'xRelayer32',
  'xRelayer32B64u',
  'relayerShare32B64u',
  'serverExportShare32B64u',
  'canonicalPrivateKeyHex',
  'privateKeyHex',
] as const;

export function parseEcdsaDerivationPublicIdentity(
  raw: unknown,
): EcdsaDerivationPublicIdentity | null {
  if (!isObject(raw)) return null;
  const derivationClientSharePublicKey33B64u = parseSec1CompressedPublicKey33B64u(
    raw.derivationClientSharePublicKey33B64u,
  );
  const relayerPublicKey33B64u = parseSec1CompressedPublicKey33B64u(raw.relayerPublicKey33B64u);
  const groupPublicKey33B64u = parseSec1CompressedPublicKey33B64u(raw.groupPublicKey33B64u);
  const ethereumAddress = toOptionalString(raw.ethereumAddress);
  if (
    !derivationClientSharePublicKey33B64u ||
    !relayerPublicKey33B64u ||
    !groupPublicKey33B64u ||
    !ethereumAddress
  ) {
    return null;
  }
  return {
    derivationClientSharePublicKey33B64u:
      derivationClientSharePublicKey33B64u as DerivationClientSharePublicKey33B64u,
    relayerPublicKey33B64u: relayerPublicKey33B64u as EcdsaDerivationRelayerPublicKey33B64u,
    groupPublicKey33B64u,
    ethereumAddress,
  };
}

export function parseEcdsaDerivationClientBootstrapRequest(
  raw: unknown,
): EcdsaDerivationClientBootstrapRequest | null {
  if (!isObject(raw)) return null;
  if (hasForbiddenFields(raw, ECDSA_DERIVATION_BOOTSTRAP_FORBIDDEN_FIELDS)) return null;
  if (toOptionalString(raw.formatVersion) !== 'ecdsa-derivation-role-local') return null;
  if (toOptionalString(raw.keyScope) !== 'evm-family') return null;
  const walletId = toOptionalString(raw.walletId);
  const evmFamilySigningKeySlotId = parseEvmFamilySigningKeySlotIdOrNull(
    raw.evmFamilySigningKeySlotId,
  );
  const ecdsaThresholdKeyId = toOptionalString(raw.ecdsaThresholdKeyId);
  const signingRootId = toOptionalString(raw.signingRootId);
  const signingRootVersion = toOptionalString(raw.signingRootVersion);
  const relayerKeyId = toOptionalString(raw.relayerKeyId);
  const registrationPreparationIdRaw = toOptionalString(raw.registrationPreparationId);
  const derivationClientSharePublicKey33B64u = parseSec1CompressedPublicKey33B64u(
    raw.derivationClientSharePublicKey33B64u,
  );
  const contextBinding32B64u = parseB64uFixed(raw.contextBinding32B64u, 32);
  const requestId = toOptionalString(raw.requestId);
  const sessionId = toOptionalString(raw.sessionId);
  const clientShareRetryCounter = raw.clientShareRetryCounter;
  const ttlMs = raw.ttlMs;
  const remainingUses = raw.remainingUses;
  const participantIds = normalizeThresholdEd25519ParticipantIds(raw.participantIds);
  const runtimePolicyScopeRaw = (raw as { runtimePolicyScope?: unknown }).runtimePolicyScope;
  const runtimePolicyScope =
    runtimePolicyScopeRaw === undefined ? null : parseRuntimePolicyScope(runtimePolicyScopeRaw);
  const clientRootProof =
    raw.clientRootProof === undefined
      ? null
      : parseEcdsaDerivationClientRootProof(raw.clientRootProof);
  const passkeyBootstrapAuthorization =
    raw.passkeyBootstrapAuthorization === undefined
      ? null
      : parseEcdsaDerivationPasskeyBootstrapAuthorization(raw.passkeyBootstrapAuthorization);
  if (
    !walletId ||
    !evmFamilySigningKeySlotId ||
    !ecdsaThresholdKeyId ||
    !signingRootId ||
    !signingRootVersion ||
    !relayerKeyId ||
    !derivationClientSharePublicKey33B64u ||
    !contextBinding32B64u ||
    !requestId ||
    !sessionId ||
    !isNonNegativeInteger(clientShareRetryCounter) ||
    !isPositiveIntegerAtMost(ttlMs, MAX_WALLET_SESSION_TTL_MS) ||
    !isPositiveIntegerAtMost(remainingUses, MAX_WALLET_SESSION_REMAINING_USES) ||
    !participantIds ||
    (runtimePolicyScopeRaw !== undefined && !runtimePolicyScope) ||
    (raw.clientRootProof !== undefined && !clientRootProof) ||
    (raw.passkeyBootstrapAuthorization !== undefined && !passkeyBootstrapAuthorization) ||
    [raw.clientRootProof, raw.passkeyBootstrapAuthorization].filter((value) => value !== undefined)
      .length > 1
  ) {
    return null;
  }
  const base = {
    formatVersion: 'ecdsa-derivation-role-local' as const,
    walletId,
    evmFamilySigningKeySlotId,
    ecdsaThresholdKeyId,
    signingRootId,
    signingRootVersion,
    keyScope: 'evm-family' as const,
    relayerKeyId,
    ...(registrationPreparationIdRaw
      ? {
          registrationPreparationId: registrationPreparationIdFromString(
            registrationPreparationIdRaw,
          ),
        }
      : {}),
    derivationClientSharePublicKey33B64u:
      derivationClientSharePublicKey33B64u as DerivationClientSharePublicKey33B64u,
    clientShareRetryCounter,
    contextBinding32B64u,
    requestId,
    sessionId,
    ttlMs,
    remainingUses,
    participantIds,
    ...(runtimePolicyScope ? { runtimePolicyScope } : {}),
  };
  if (clientRootProof) return { ...base, clientRootProof };
  if (passkeyBootstrapAuthorization) {
    return { ...base, passkeyBootstrapAuthorization };
  }
  return base;
}

export type ParsedThresholdEd25519Commitments = { hiding: string; binding: string };

export function parseThresholdEd25519Commitments(
  raw: unknown,
): ParsedThresholdEd25519Commitments | null {
  if (!isObject(raw)) return null;
  const hiding = toOptionalString(raw.hiding);
  const binding = toOptionalString(raw.binding);
  if (!hiding || !binding) return null;
  return { hiding, binding };
}

export type ParsedThresholdEd25519CommitmentsById = Record<
  string,
  ParsedThresholdEd25519Commitments
>;

export function parseThresholdEd25519CommitmentsById(
  raw: unknown,
): ParsedThresholdEd25519CommitmentsById | null {
  if (!isObject(raw)) return null;
  const out: ParsedThresholdEd25519CommitmentsById = {};
  for (const [k, v] of Object.entries(raw)) {
    const key = toTrimmedString(k);
    if (!key) return null;
    const commitments = parseThresholdEd25519Commitments(v);
    if (!commitments) return null;
    out[key] = commitments;
  }
  return Object.keys(out).length ? out : null;
}

export function parseThresholdEd25519AuthorityScope(
  raw: unknown,
): ThresholdEd25519AuthorityScope | null {
  if (!isObject(raw)) return null;
  const kind = toOptionalString(raw.kind);
  switch (kind) {
    case 'passkey_rp': {
      const rpId = parseWebAuthnRpId(raw.rpId);
      if (
        !rpId.ok ||
        toOptionalString(raw.proofKind) ||
        toOptionalString(raw.email) ||
        toOptionalString(raw.provider) ||
        toOptionalString(raw.providerUserId) ||
        toOptionalString(raw.challengeId) ||
        toOptionalString(raw.googleEmailOtpRegistrationAttemptId) ||
        toOptionalString(raw.googleEmailOtpRegistrationOfferId) ||
        toOptionalString(raw.googleEmailOtpRegistrationCandidateId)
      ) {
        return null;
      }
      return { kind, rpId: rpId.value };
    }
    case 'email_otp': {
      if (
        toOptionalString(raw.rpId) ||
        toOptionalString(raw.email) ||
        toOptionalString(raw.proofKind) ||
        toOptionalString(raw.challengeId) ||
        toOptionalString(raw.googleEmailOtpRegistrationAttemptId) ||
        toOptionalString(raw.googleEmailOtpRegistrationOfferId) ||
        toOptionalString(raw.googleEmailOtpRegistrationCandidateId)
      ) {
        return null;
      }
      const provider = toOptionalString(raw.provider);
      const providerUserId = toOptionalString(raw.providerUserId);
      if ((provider !== 'google' && provider !== 'email') || !providerUserId) return null;
      return { kind, provider, providerUserId };
    }
    default:
      return null;
  }
}

export function thresholdEd25519AuthorityScopeFromWalletAuthAuthority(
  authority: WalletAuthAuthority,
): ThresholdEd25519AuthorityScope {
  if (isPasskeyWalletAuthAuthority(authority)) {
    return { kind: 'passkey_rp', rpId: authority.verifier.rpId };
  }
  if (isEmailOtpWalletAuthAuthority(authority)) {
    return {
      kind: 'email_otp',
      provider: authority.factor.provider,
      providerUserId: authority.factor.providerUserId,
    };
  }
  authority satisfies never;
  throw new Error('[threshold-ed25519] unsupported wallet auth authority');
}

export function thresholdEd25519AuthorityScopesMatch(
  left: ThresholdEd25519AuthorityScope,
  right: ThresholdEd25519AuthorityScope,
): boolean {
  if (left.kind !== right.kind) return false;
  switch (left.kind) {
    case 'passkey_rp':
      return right.kind === 'passkey_rp' && left.rpId === right.rpId;
    case 'email_otp':
      return (
        right.kind === 'email_otp' &&
        left.provider === right.provider &&
        left.providerUserId === right.providerUserId
      );
  }
  return false;
}

export type ParsedThresholdEd25519MpcSessionRecord = {
  expiresAtMs: number;
  ecdsaThresholdKeyId?: string;
  keyHandle?: string;
  relayerKeyId: string;
  purpose: string;
  intentDigestB64u: string;
  signingDigestB64u: string;
  userId: string;
  authorityScope: ThresholdEd25519AuthorityScope;
  clientVerifyingShareB64u?: string;
  participantIds: number[];
} & Partial<ParsedThresholdEcdsaSigningRootMetadata>;

export type ParsedThresholdEcdsaMpcSessionRecord = {
  expiresAtMs: number;
  ecdsaThresholdKeyId?: string;
  keyHandle?: string;
  relayerKeyId: string;
  purpose: string;
  intentDigestB64u: string;
  signingDigestB64u: string;
  walletId: string;
  clientVerifyingShareB64u?: string;
  participantIds: number[];
} & Partial<ParsedThresholdEcdsaSigningRootMetadata>;

export function parseThresholdEd25519MpcSessionRecord(
  raw: unknown,
): ParsedThresholdEd25519MpcSessionRecord | null {
  if (!isObject(raw)) return null;
  const expiresAtMs = raw.expiresAtMs;
  const ecdsaThresholdKeyId = toOptionalString(raw.ecdsaThresholdKeyId);
  const keyHandle = toOptionalString(raw.keyHandle);
  const relayerKeyId = toOptionalString(raw.relayerKeyId);
  const purpose = toOptionalString(raw.purpose);
  const intentDigestB64u = toOptionalString(raw.intentDigestB64u);
  const signingDigestB64u = toOptionalString(raw.signingDigestB64u);
  const userId = toOptionalString(raw.userId);
  const authorityScope = parseThresholdEd25519AuthorityScope(raw.authorityScope);
  const clientVerifyingShareB64u = toOptionalString(raw.clientVerifyingShareB64u);
  const participantIds = normalizeThresholdEd25519ParticipantIds(raw.participantIds) || [
    ...THRESHOLD_ED25519_2P_PARTICIPANT_IDS,
  ];
  const signingRootMetadata = parseOptionalThresholdEcdsaSigningRootMetadataFields(raw);
  if (Object.prototype.hasOwnProperty.call(raw, 'rpId')) return null;
  if (!signingRootMetadata.ok) return null;
  if (!isValidNumber(expiresAtMs)) return null;
  if (
    !relayerKeyId ||
    !purpose ||
    !intentDigestB64u ||
    !signingDigestB64u ||
    !userId ||
    !authorityScope
  ) {
    return null;
  }
  return {
    expiresAtMs,
    ...(ecdsaThresholdKeyId ? { ecdsaThresholdKeyId } : {}),
    ...(keyHandle ? { keyHandle } : {}),
    relayerKeyId,
    purpose,
    intentDigestB64u,
    signingDigestB64u,
    userId,
    authorityScope,
    ...(clientVerifyingShareB64u ? { clientVerifyingShareB64u } : {}),
    participantIds,
    ...(signingRootMetadata.value ? signingRootMetadata.value : {}),
  };
}

export function parseThresholdEcdsaMpcSessionRecord(
  raw: unknown,
): ParsedThresholdEcdsaMpcSessionRecord | null {
  if (!isObject(raw)) return null;
  const expiresAtMs = raw.expiresAtMs;
  const ecdsaThresholdKeyId = toOptionalString(raw.ecdsaThresholdKeyId);
  const keyHandle = toOptionalString(raw.keyHandle);
  const relayerKeyId = toOptionalString(raw.relayerKeyId);
  const purpose = toOptionalString(raw.purpose);
  const intentDigestB64u = toOptionalString(raw.intentDigestB64u);
  const signingDigestB64u = toOptionalString(raw.signingDigestB64u);
  const walletId = toOptionalString(raw.walletId);
  const clientVerifyingShareB64u = toOptionalString(raw.clientVerifyingShareB64u);
  const participantIds = normalizeThresholdEd25519ParticipantIds(raw.participantIds) || [
    ...THRESHOLD_ED25519_2P_PARTICIPANT_IDS,
  ];
  const signingRootMetadata = parseOptionalThresholdEcdsaSigningRootMetadataFields(raw);
  if (!signingRootMetadata.ok) return null;
  if (!isValidNumber(expiresAtMs)) return null;
  if (!relayerKeyId || !purpose || !intentDigestB64u || !signingDigestB64u || !walletId) {
    return null;
  }
  return {
    expiresAtMs,
    ...(ecdsaThresholdKeyId ? { ecdsaThresholdKeyId } : {}),
    ...(keyHandle ? { keyHandle } : {}),
    relayerKeyId,
    purpose,
    intentDigestB64u,
    signingDigestB64u,
    walletId,
    ...(clientVerifyingShareB64u ? { clientVerifyingShareB64u } : {}),
    participantIds,
    ...(signingRootMetadata.value ? signingRootMetadata.value : {}),
  };
}

export type ParsedThresholdEd25519SigningShareMaterial =
  | {
      kind: 'key_store';
    }
  | {
      kind: 'embedded_cosigner_share';
      relayerSigningShareB64u: string;
    };

export type ParsedThresholdEd25519SigningSessionRecord = {
  expiresAtMs: number;
  mpcSessionId: string;
  relayerKeyId: string;
  signingDigestB64u: string;
  userId: string;
  authorityScope: ThresholdEd25519AuthorityScope;
  commitmentsById: ParsedThresholdEd25519CommitmentsById;
  signingShare: ParsedThresholdEd25519SigningShareMaterial;
  relayerNoncesB64u: string;
  participantIds: number[];
};

export function parseThresholdEd25519SigningSessionRecord(
  raw: unknown,
): ParsedThresholdEd25519SigningSessionRecord | null {
  if (!isObject(raw)) return null;
  const expiresAtMs = raw.expiresAtMs;
  const mpcSessionId = toOptionalString(raw.mpcSessionId);
  const relayerKeyId = toOptionalString(raw.relayerKeyId);
  const signingDigestB64u = toOptionalString(raw.signingDigestB64u);
  const userId = toOptionalString(raw.userId);
  const authorityScope = parseThresholdEd25519AuthorityScope(raw.authorityScope);
  const commitmentsById = parseThresholdEd25519CommitmentsById(raw.commitmentsById);
  const signingShare = parseThresholdEd25519SigningShareMaterial(raw);
  const relayerNoncesB64u = toOptionalString(raw.relayerNoncesB64u);
  const participantIds = normalizeThresholdEd25519ParticipantIds(raw.participantIds) || [
    ...THRESHOLD_ED25519_2P_PARTICIPANT_IDS,
  ];
  if (!isValidNumber(expiresAtMs)) return null;
  if (Object.prototype.hasOwnProperty.call(raw, 'rpId')) return null;
  if (
    !mpcSessionId ||
    !relayerKeyId ||
    !signingDigestB64u ||
    !userId ||
    !authorityScope ||
    !commitmentsById ||
    !signingShare ||
    !relayerNoncesB64u
  ) {
    return null;
  }
  return {
    expiresAtMs,
    mpcSessionId,
    relayerKeyId,
    signingDigestB64u,
    userId,
    authorityScope,
    commitmentsById,
    signingShare,
    relayerNoncesB64u,
    participantIds,
  };
}

function parseThresholdEd25519SigningShareMaterial(
  raw: Record<string, unknown>,
): ParsedThresholdEd25519SigningShareMaterial | null {
  if (isObject(raw.signingShare)) {
    const kind = toOptionalString(raw.signingShare.kind);
    if (kind === 'key_store') {
      return toOptionalString(raw.signingShare.relayerSigningShareB64u) ? null : { kind };
    }
    if (kind === 'embedded_cosigner_share') {
      const relayerSigningShareB64u = toOptionalString(raw.signingShare.relayerSigningShareB64u);
      return relayerSigningShareB64u ? { kind, relayerSigningShareB64u } : null;
    }
    return null;
  }
  const legacyShare = toOptionalString(raw.relayerSigningShareB64u);
  return legacyShare
    ? { kind: 'embedded_cosigner_share', relayerSigningShareB64u: legacyShare }
    : { kind: 'key_store' };
}

export type ParsedThresholdEd25519StringById = Record<string, string>;

export function parseThresholdEd25519StringById(
  raw: unknown,
): ParsedThresholdEd25519StringById | null {
  if (!isObject(raw)) return null;
  const out: ParsedThresholdEd25519StringById = {};
  for (const [k, v] of Object.entries(raw)) {
    const key = toTrimmedString(k);
    const value = toOptionalString(v);
    if (!key || !value) return null;
    out[key] = value;
  }
  return Object.keys(out).length ? out : null;
}

export type ParsedThresholdEd25519CoordinatorSigningSessionRecord = {
  mode: 'cosigner';
  expiresAtMs: number;
  mpcSessionId: string;
  relayerKeyId: string;
  signingDigestB64u: string;
  userId: string;
  authorityScope: ThresholdEd25519AuthorityScope;
  commitmentsById: ParsedThresholdEd25519CommitmentsById;
  participantIds: number[];
  groupPublicKey: string;
  cosignerIds: number[];
  cosignerRelayerUrlsById: ParsedThresholdEd25519StringById;
  cosignerCoordinatorGrantsById: ParsedThresholdEd25519StringById;
  relayerVerifyingSharesById: ParsedThresholdEd25519StringById;
};

export function parseThresholdEd25519CoordinatorSigningSessionRecord(
  raw: unknown,
): ParsedThresholdEd25519CoordinatorSigningSessionRecord | null {
  if (!isObject(raw)) return null;
  const expiresAtMs = raw.expiresAtMs;
  const mpcSessionId = toOptionalString(raw.mpcSessionId);
  const relayerKeyId = toOptionalString(raw.relayerKeyId);
  const signingDigestB64u = toOptionalString(raw.signingDigestB64u);
  const userId = toOptionalString(raw.userId);
  const authorityScope = parseThresholdEd25519AuthorityScope(raw.authorityScope);
  const commitmentsById = parseThresholdEd25519CommitmentsById(raw.commitmentsById);
  const participantIds = normalizeThresholdEd25519ParticipantIds(raw.participantIds) || [
    ...THRESHOLD_ED25519_2P_PARTICIPANT_IDS,
  ];
  const relayerVerifyingSharesById = parseThresholdEd25519StringById(
    raw.relayerVerifyingSharesById,
  );

  if (!isValidNumber(expiresAtMs)) return null;
  if (Object.prototype.hasOwnProperty.call(raw, 'rpId')) return null;
  if (
    !mpcSessionId ||
    !relayerKeyId ||
    !signingDigestB64u ||
    !userId ||
    !authorityScope ||
    !commitmentsById ||
    !relayerVerifyingSharesById
  ) {
    return null;
  }

  const mode = toOptionalString(raw.mode);
  if (mode !== 'cosigner') return null;

  const groupPublicKey = toOptionalString(raw.groupPublicKey);
  const cosignerIds = normalizeThresholdEd25519ParticipantIds(raw.cosignerIds);
  const cosignerRelayerUrlsById = parseThresholdEd25519StringById(raw.cosignerRelayerUrlsById);
  const cosignerCoordinatorGrantsById = parseThresholdEd25519StringById(
    raw.cosignerCoordinatorGrantsById,
  );
  if (!groupPublicKey || !cosignerIds || !cosignerRelayerUrlsById || !cosignerCoordinatorGrantsById)
    return null;
  return {
    mode: 'cosigner',
    expiresAtMs,
    mpcSessionId,
    relayerKeyId,
    signingDigestB64u,
    userId,
    authorityScope,
    commitmentsById,
    participantIds,
    groupPublicKey,
    cosignerIds,
    cosignerRelayerUrlsById,
    cosignerCoordinatorGrantsById,
    relayerVerifyingSharesById,
  };
}

export type ParsedEd25519WalletSessionRecord = {
  expiresAtMs: number;
  relayerKeyId: string;
  userId: string;
  walletId: string;
  nearAccountId: string;
  nearEd25519SigningKeyId: string;
  authorityScope: ThresholdEd25519AuthorityScope;
  participantIds: number[];
} & Partial<ParsedThresholdEcdsaSigningRootMetadata>;

export function parseEd25519WalletSessionRecord(
  raw: unknown,
): ParsedEd25519WalletSessionRecord | null {
  if (!isObject(raw)) return null;
  const expiresAtMs = raw.expiresAtMs;
  const relayerKeyId = toOptionalString(raw.relayerKeyId);
  const userId = toOptionalString(raw.userId);
  const walletId = toOptionalString(raw.walletId);
  const nearAccountId = toOptionalString(raw.nearAccountId);
  const nearEd25519SigningKeyId = toOptionalString(raw.nearEd25519SigningKeyId);
  const authorityScope = parseThresholdEd25519AuthorityScope(raw.authorityScope);
  const participantIds = normalizeThresholdEd25519ParticipantIds(raw.participantIds) || [
    ...THRESHOLD_ED25519_2P_PARTICIPANT_IDS,
  ];
  const signingRootMetadata = parseOptionalThresholdEcdsaSigningRootMetadataFields(raw);
  if (Object.prototype.hasOwnProperty.call(raw, 'rpId')) return null;
  if (!signingRootMetadata.ok) return null;
  if (!isValidNumber(expiresAtMs)) return null;
  if (
    !relayerKeyId ||
    !userId ||
    !walletId ||
    !nearAccountId ||
    !nearEd25519SigningKeyId ||
    !authorityScope
  ) {
    return null;
  }
  return {
    expiresAtMs,
    relayerKeyId,
    userId,
    walletId,
    nearAccountId,
    nearEd25519SigningKeyId,
    authorityScope,
    participantIds,
    ...(signingRootMetadata.value ? signingRootMetadata.value : {}),
  };
}

type ParsedEcdsaWalletSessionRecordCore = {
  expiresAtMs: number;
  relayerKeyId: string;
  walletId: string;
  keyHandle: EcdsaKeyHandle;
  participantIds: number[];
};

export type ParsedEcdsaWalletSessionRecord = ParsedEcdsaWalletSessionRecordCore &
  (
    | {
        signingRootId?: never;
        signingRootVersion?: never;
        walletKeyVersion?: never;
        derivationVersion?: never;
      }
    | ParsedThresholdEcdsaSigningRootMetadata
  );

export function parseEcdsaWalletSessionRecord(raw: unknown): ParsedEcdsaWalletSessionRecord | null {
  if (!isObject(raw)) return null;
  if ('evmFamilySigningKeySlotId' in raw) return null;
  const expiresAtMs = raw.expiresAtMs;
  const relayerKeyId = toOptionalString(raw.relayerKeyId);
  const walletId = toOptionalString(raw.walletId);
  let keyHandle: EcdsaKeyHandle;
  try {
    keyHandle = parseEcdsaKeyHandle(raw.keyHandle);
  } catch {
    return null;
  }
  const participantIds = normalizeThresholdEd25519ParticipantIds(raw.participantIds) || [
    ...THRESHOLD_ED25519_2P_PARTICIPANT_IDS,
  ];
  const signingRootMetadata = parseOptionalThresholdEcdsaSigningRootMetadataFields(raw);
  if (!signingRootMetadata.ok) return null;
  if (!isValidNumber(expiresAtMs)) return null;
  if (!relayerKeyId || !walletId) return null;
  const core: ParsedEcdsaWalletSessionRecordCore = {
    expiresAtMs,
    relayerKeyId,
    walletId,
    keyHandle,
    participantIds,
  };
  if (!signingRootMetadata.value) return core;
  return { ...core, ...signingRootMetadata.value };
}

export type ParsedRouterAbEcdsaDerivationPoolFillSessionStage =
  | 'triples'
  | 'triples_done'
  | 'presign'
  | 'done';

export type ParsedRouterAbEcdsaDerivationPoolFillSessionDestination = {
  kind: 'router_ab_ecdsa_derivation_signing_worker_pool';
  routerAbEcdsaDerivation: {
    scope: RouterAbEcdsaDerivationNormalSigningScopeV1;
    expiresAtMs: number;
  };
};

export type ParsedRouterAbEcdsaDerivationPoolFillSessionRecord = {
  expiresAtMs: number;
  walletId: string;
  keyHandle: EcdsaKeyHandle;
  relayerKeyId: string;
  presignPoolKey: string;
  poolFill: ParsedRouterAbEcdsaDerivationPoolFillSessionDestination;
  ownerInstanceId?: string;
  participantIds: number[];
  clientParticipantId: number;
  relayerParticipantId: number;
  stage: ParsedRouterAbEcdsaDerivationPoolFillSessionStage;
  version: number;
  createdAtMs: number;
  updatedAtMs: number;
} & ParsedThresholdEcdsaSigningRootMetadata;

function parseRouterAbEcdsaDerivationPoolFillSessionDestination(
  value: unknown,
  sessionExpiresAtMs: number,
): ParsedRouterAbEcdsaDerivationPoolFillSessionDestination | null {
  if (!isObject(value)) return null;
  const kind = toOptionalString(value.kind);
  if (kind !== 'router_ab_ecdsa_derivation_signing_worker_pool') return null;
  if (!isObject(value.routerAbEcdsaDerivation)) return null;
  const expiresAtMs = value.routerAbEcdsaDerivation.expiresAtMs;
  if (!isValidNumber(expiresAtMs)) return null;
  const expiresAtMsInt = Math.floor(expiresAtMs);
  if (expiresAtMsInt !== expiresAtMs || expiresAtMsInt <= 0) return null;
  if (expiresAtMsInt > sessionExpiresAtMs) return null;
  let scope: RouterAbEcdsaDerivationNormalSigningScopeV1;
  try {
    scope = parseRouterAbEcdsaDerivationNormalSigningScopeV1(value.routerAbEcdsaDerivation.scope);
  } catch {
    return null;
  }
  return {
    kind,
    routerAbEcdsaDerivation: {
      scope,
      expiresAtMs: expiresAtMsInt,
    },
  };
}

export function parseRouterAbEcdsaDerivationPoolFillSessionRecord(
  raw: unknown,
): ParsedRouterAbEcdsaDerivationPoolFillSessionRecord | null {
  if (!isObject(raw)) return null;
  if ('evmFamilySigningKeySlotId' in raw) return null;
  const expiresAtMs = raw.expiresAtMs;
  const walletId = toOptionalString(raw.walletId);
  let keyHandle: EcdsaKeyHandle;
  try {
    keyHandle = parseEcdsaKeyHandle(raw.keyHandle);
  } catch {
    return null;
  }
  const relayerKeyId = toOptionalString(raw.relayerKeyId);
  const presignPoolKey = toOptionalString(raw.presignPoolKey);
  const ownerInstanceId = toOptionalString(raw.ownerInstanceId);
  const participantIds = normalizeThresholdEd25519ParticipantIds(raw.participantIds) || [
    ...THRESHOLD_ED25519_2P_PARTICIPANT_IDS,
  ];
  const clientParticipantId = raw.clientParticipantId;
  const relayerParticipantId = raw.relayerParticipantId;
  const stageRaw = toOptionalString(raw.stage);
  const version = raw.version;
  const createdAtMs = raw.createdAtMs;
  const updatedAtMs = raw.updatedAtMs;
  const signingRootMetadata = parseThresholdEcdsaSigningRootMetadataFields(raw);

  const stage: ParsedRouterAbEcdsaDerivationPoolFillSessionStage | null =
    stageRaw === 'triples'
      ? 'triples'
      : stageRaw === 'triples_done'
        ? 'triples_done'
        : stageRaw === 'presign'
          ? 'presign'
          : stageRaw === 'done'
            ? 'done'
            : null;

  if (!isValidNumber(expiresAtMs) || !isValidNumber(createdAtMs) || !isValidNumber(updatedAtMs)) {
    return null;
  }
  const poolFill = parseRouterAbEcdsaDerivationPoolFillSessionDestination(
    raw.poolFill,
    expiresAtMs,
  );
  if (
    !walletId ||
    !relayerKeyId ||
    !presignPoolKey ||
    !poolFill ||
    !stage ||
    !signingRootMetadata ||
    !isValidNumber(clientParticipantId) ||
    !isValidNumber(relayerParticipantId) ||
    !isValidNumber(version)
  ) {
    return null;
  }

  const clientParticipantIdInt = Math.floor(clientParticipantId);
  const relayerParticipantIdInt = Math.floor(relayerParticipantId);
  const versionInt = Math.floor(version);
  if (clientParticipantIdInt < 1 || relayerParticipantIdInt < 1 || versionInt < 1) {
    return null;
  }

  return {
    expiresAtMs,
    walletId,
    keyHandle,
    relayerKeyId,
    presignPoolKey,
    poolFill,
    ...(ownerInstanceId ? { ownerInstanceId } : {}),
    participantIds,
    clientParticipantId: clientParticipantIdInt,
    relayerParticipantId: relayerParticipantIdInt,
    stage,
    version: versionInt,
    createdAtMs,
    updatedAtMs,
    ...signingRootMetadata,
  };
}

export type LinkedDeviceWalletSessionPermissionClaimsV1 = DelegatedWalletAuthorityV1;

type LinkedDeviceWalletSessionClaimBase = {
  sub: string;
  walletId: string;
  kind: string;
  authorizationKind: 'linked_device_wallet_session';
  authorizationId: LinkedDeviceWalletSessionAuthorizationId;
  tenantId: TenantId;
  deviceId: LinkedDeviceId;
  enrollmentId: LinkedDeviceEnrollmentId;
  walletKeyId: WalletKeyId;
  keyManifestDigestB64u: DigestB64u;
  revocationEpoch: number;
  permission: LinkedDeviceWalletSessionPermissionClaimsV1;
  issuedAtMs: number;
  expiresAtMs: number;
  walletSessionId: WalletSessionId;
  quotaId: MpcWalletSigningQuotaId;
  iat: number;
  exp: number;
  nbf?: number;
};

export type RouterAbEd25519LinkedDeviceWalletSessionClaims = LinkedDeviceWalletSessionClaimBase & {
  readonly kind: typeof ROUTER_AB_ED25519_WALLET_SESSION_JWT_KIND;
  readonly authorizationKind: 'linked_device_wallet_session';
  readonly nearAccountId?: never;
  readonly nearEd25519SigningKeyId?: never;
  readonly sid?: never;
  readonly authority?: never;
  readonly authorityScope?: never;
  readonly thresholdSessionId?: never;
  readonly relayerKeyId?: never;
  readonly participantIds?: never;
  readonly thresholdExpiresAtMs?: never;
  readonly runtimePolicyScope?: never;
  readonly routerAbNormalSigning?: never;
};

function parseRuntimePolicyScope(raw: unknown): RuntimePolicyScope | null {
  try {
    return normalizeRuntimePolicyScope(raw as Record<string, unknown>);
  } catch {
    return null;
  }
}

function parseLinkedDeviceWalletSessionPermissionClaims(
  raw: unknown,
): LinkedDeviceWalletSessionPermissionClaimsV1 | null {
  const parsed = parseDelegatedWalletAuthorityV1(raw);
  return parsed.ok ? parsed.value : null;
}

export function parseRouterAbEd25519LinkedDeviceWalletSessionClaims(
  raw: unknown,
): RouterAbEd25519LinkedDeviceWalletSessionClaims | null {
  if (!isObject(raw)) return null;
  if (toOptionalString(raw.kind) !== ROUTER_AB_ED25519_WALLET_SESSION_JWT_KIND) return null;
  if (toOptionalString(raw.authorizationKind) !== 'linked_device_wallet_session') return null;
  if (
    hasForbiddenFields(raw, [
      'nearAccountId',
      'nearEd25519SigningKeyId',
      'sid',
      'authority',
      'authorityScope',
      'thresholdSessionId',
      'relayerKeyId',
      'participantIds',
      'thresholdExpiresAtMs',
      'runtimePolicyScope',
      'routerAbNormalSigning',
      'authorizationSessionId',
      'walletAuthAuthorityRef',
      'authSource',
      'keyScope',
      'keyHandle',
      'evmFamilySigningKeySlotId',
      'ecdsaThresholdKeyId',
      'signingRootId',
      'signingRootVersion',
      'walletKeyVersion',
      'derivationVersion',
      'stableKeyContext',
      'publicIdentity',
      'activationEpoch',
      'materialActivation',
      'routerMaterial',
      'signingWorkerId',
      'routerAbEcdsaDerivationNormalSigning',
      'routerAbEcdsaDerivationIssuerBinding',
    ])
  ) {
    return null;
  }
  const deviceIdResult = parseLinkedDeviceId(raw.deviceId);
  const enrollmentIdResult = parseLinkedDeviceEnrollmentId(raw.enrollmentId);
  const walletKeyIdResult = parseWalletKeyId(raw.walletKeyId);
  const tenantIdResult = parseTenantId(raw.tenantId);
  const authorizationIdResult = parseLinkedDeviceWalletSessionAuthorizationId(raw.authorizationId);
  const walletSessionIdResult = parseWalletSessionId(raw.walletSessionId);
  const quotaIdResult = parseMpcWalletSigningQuotaId(raw.quotaId);
  const keyManifestDigest = (() => {
    try {
      return parseDigestB64u(raw.keyManifestDigestB64u);
    } catch {
      return null;
    }
  })();
  const walletId = toOptionalString(raw.walletId);
  const sub = toOptionalString(raw.sub);
  const issuedAtMs = raw.issuedAtMs;
  const expiresAtMs = raw.expiresAtMs;
  const revocationEpoch = raw.revocationEpoch;
  const permission = parseLinkedDeviceWalletSessionPermissionClaims(raw.permission);
  const iat = raw.iat;
  const exp = raw.exp;
  if (
    !deviceIdResult.ok ||
    !enrollmentIdResult.ok ||
    !walletKeyIdResult.ok ||
    !tenantIdResult.ok ||
    !authorizationIdResult.ok ||
    !walletSessionIdResult.ok ||
    !quotaIdResult.ok ||
    !keyManifestDigest ||
    !walletId ||
    !sub ||
    sub !== `linked-device:${String(deviceIdResult.value)}` ||
    !isNonNegativeInteger(issuedAtMs) ||
    !isNonNegativeInteger(expiresAtMs) ||
    !isNonNegativeInteger(revocationEpoch) ||
    !permission ||
    !isNonNegativeInteger(iat) ||
    !isNonNegativeInteger(exp) ||
    issuedAtMs >= expiresAtMs ||
    exp <= 0 ||
    issuedAtMs < iat * 1000 ||
    issuedAtMs >= (iat + 1) * 1000 ||
    expiresAtMs < exp * 1000 ||
    expiresAtMs >= (exp + 1) * 1000
  ) {
    return null;
  }
  const out: RouterAbEd25519LinkedDeviceWalletSessionClaims = {
    sub,
    walletId,
    kind: ROUTER_AB_ED25519_WALLET_SESSION_JWT_KIND,
    authorizationKind: 'linked_device_wallet_session',
    authorizationId: authorizationIdResult.value,
    walletSessionId: walletSessionIdResult.value,
    quotaId: quotaIdResult.value,
    tenantId: tenantIdResult.value,
    deviceId: deviceIdResult.value,
    enrollmentId: enrollmentIdResult.value,
    walletKeyId: walletKeyIdResult.value,
    keyManifestDigestB64u: keyManifestDigest,
    revocationEpoch,
    permission,
    issuedAtMs,
    expiresAtMs,
    iat,
    exp,
  };
  const nbf = raw.nbf;
  if (nbf !== undefined) {
    const value = Number(nbf);
    if (!isNonNegativeInteger(value)) return null;
    out.nbf = value;
  }
  return out;
}

export type RouterAbEcdsaDerivationLinkedDeviceWalletSessionClaims =
  LinkedDeviceWalletSessionClaimBase & {
    readonly kind: typeof ROUTER_AB_ECDSA_DERIVATION_WALLET_SESSION_JWT_KIND;
    readonly authorizationKind: 'linked_device_wallet_session';
    readonly sid?: never;
    readonly authorizationSessionId?: never;
    readonly walletAuthAuthorityRef?: never;
    readonly authSource?: never;
    readonly nearAccountId?: never;
    readonly nearEd25519SigningKeyId?: never;
    readonly authority?: never;
    readonly authorityScope?: never;
    readonly thresholdSessionId?: never;
    readonly relayerKeyId?: never;
    readonly participantIds?: never;
    readonly thresholdExpiresAtMs?: never;
    readonly runtimePolicyScope?: never;
    readonly routerAbEcdsaDerivationNormalSigning?: never;
    readonly keyScope?: never;
    readonly keyHandle?: never;
  };

export function parseRouterAbEcdsaDerivationLinkedDeviceWalletSessionClaims(
  raw: unknown,
): RouterAbEcdsaDerivationLinkedDeviceWalletSessionClaims | null {
  if (!isObject(raw)) return null;
  if (toOptionalString(raw.kind) !== ROUTER_AB_ECDSA_DERIVATION_WALLET_SESSION_JWT_KIND) {
    return null;
  }
  if (toOptionalString(raw.authorizationKind) !== 'linked_device_wallet_session') return null;
  if (
    hasForbiddenFields(raw, [
      'sid',
      'authorizationSessionId',
      'walletAuthAuthorityRef',
      'authSource',
      'runtimePolicyScope',
      'nearAccountId',
      'nearEd25519SigningKeyId',
      'authority',
      'authorityScope',
      'thresholdSessionId',
      'relayerKeyId',
      'participantIds',
      'thresholdExpiresAtMs',
      'routerAbEcdsaDerivationNormalSigning',
      'routerAbEcdsaDerivationIssuerBinding',
      'routerAbNormalSigning',
      'keyScope',
      'keyHandle',
      'evmFamilySigningKeySlotId',
      'ecdsaThresholdKeyId',
      'signingRootId',
      'signingRootVersion',
      'walletKeyVersion',
      'derivationVersion',
      'stableKeyContext',
      'publicIdentity',
      'activationEpoch',
      'materialActivation',
      'routerMaterial',
      'signingWorkerId',
    ])
  ) {
    return null;
  }
  const deviceIdResult = parseLinkedDeviceId(raw.deviceId);
  const enrollmentIdResult = parseLinkedDeviceEnrollmentId(raw.enrollmentId);
  const walletKeyIdResult = parseWalletKeyId(raw.walletKeyId);
  const tenantIdResult = parseTenantId(raw.tenantId);
  const authorizationIdResult = parseLinkedDeviceWalletSessionAuthorizationId(raw.authorizationId);
  const walletSessionIdResult = parseWalletSessionId(raw.walletSessionId);
  const quotaIdResult = parseMpcWalletSigningQuotaId(raw.quotaId);
  const keyManifestDigest = (() => {
    try {
      return parseDigestB64u(raw.keyManifestDigestB64u);
    } catch {
      return null;
    }
  })();
  const walletId = toOptionalString(raw.walletId);
  const sub = toOptionalString(raw.sub);
  const issuedAtMs = raw.issuedAtMs;
  const expiresAtMs = raw.expiresAtMs;
  const revocationEpoch = raw.revocationEpoch;
  const permission = parseLinkedDeviceWalletSessionPermissionClaims(raw.permission);
  const iat = raw.iat;
  const exp = raw.exp;
  if (
    !deviceIdResult.ok ||
    !enrollmentIdResult.ok ||
    !walletKeyIdResult.ok ||
    !tenantIdResult.ok ||
    !authorizationIdResult.ok ||
    !walletSessionIdResult.ok ||
    !quotaIdResult.ok ||
    !keyManifestDigest ||
    !walletId ||
    !sub ||
    sub !== `linked-device:${String(deviceIdResult.value)}` ||
    !isNonNegativeInteger(issuedAtMs) ||
    !isNonNegativeInteger(expiresAtMs) ||
    !isNonNegativeInteger(revocationEpoch) ||
    !permission ||
    issuedAtMs >= expiresAtMs ||
    !isNonNegativeInteger(iat) ||
    !isNonNegativeInteger(exp) ||
    exp <= 0 ||
    issuedAtMs < iat * 1000 ||
    issuedAtMs >= (iat + 1) * 1000 ||
    expiresAtMs < exp * 1000 ||
    expiresAtMs >= (exp + 1) * 1000
  ) {
    return null;
  }
  const out: RouterAbEcdsaDerivationLinkedDeviceWalletSessionClaims = {
    sub,
    walletId,
    kind: ROUTER_AB_ECDSA_DERIVATION_WALLET_SESSION_JWT_KIND,
    authorizationKind: 'linked_device_wallet_session',
    authorizationId: authorizationIdResult.value,
    walletSessionId: walletSessionIdResult.value,
    quotaId: quotaIdResult.value,
    tenantId: tenantIdResult.value,
    deviceId: deviceIdResult.value,
    enrollmentId: enrollmentIdResult.value,
    walletKeyId: walletKeyIdResult.value,
    keyManifestDigestB64u: keyManifestDigest,
    revocationEpoch,
    permission,
    issuedAtMs,
    expiresAtMs,
    iat,
    exp,
  };
  const nbf = raw.nbf;
  if (nbf !== undefined) {
    const value = Number(nbf);
    if (!isNonNegativeInteger(value)) return null;
    out.nbf = value;
  }
  return out;
}

export function normalizeByteArray32(input: unknown): Uint8Array | null {
  if (input instanceof Uint8Array) {
    return input.length === 32 ? input : null;
  }
  if (!Array.isArray(input) || input.length !== 32) return null;
  const out = new Uint8Array(32);
  for (let i = 0; i < 32; i++) {
    const v = Number(input[i]);
    if (!Number.isFinite(v) || v < 0 || v > 255) return null;
    out[i] = v;
  }
  return out;
}

export function toNearPublicKeyStr(v: unknown): string {
  return ensureEd25519Prefix(toOptionalString(v));
}

export function extractAuthorizeSigningPublicKey(purpose: string, signingPayload: unknown): string {
  if (!isObject(signingPayload)) return '';
  if (purpose === 'near_tx') {
    const ctx = isObject(signingPayload.transactionContext)
      ? signingPayload.transactionContext
      : null;
    return toNearPublicKeyStr(ctx?.nearPublicKeyStr);
  }
  if (purpose === 'nep461_delegate') {
    const delegate = isObject(signingPayload.delegate) ? signingPayload.delegate : null;
    return toNearPublicKeyStr(delegate?.publicKey);
  }
  return '';
}
