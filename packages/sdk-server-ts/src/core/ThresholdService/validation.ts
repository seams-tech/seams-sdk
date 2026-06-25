import type { AccessKeyList } from '../rpcClients/near/NearClient';
import { base64UrlDecode } from '@shared/utils/encoders';
import { ensureEd25519Prefix, toOptionalString, toTrimmedString } from '@shared/utils/validation';
import {
  ECDSA_HSS_ROLE_LOCAL_FIRST_BOOTSTRAP_ROOT_PROOF_VERSION,
  type EcdsaClientRootPublicKey33B64u,
  type EcdsaHssClientSharePublicKey33B64u,
  type EcdsaRelayerHssPublicKey33B64u,
  type EcdsaHssRoleLocalFirstBootstrapRootProof,
} from '@shared/threshold/ecdsaHssRoleLocalBootstrap';
import {
  THRESHOLD_ED25519_2P_PARTICIPANT_IDS,
  normalizeThresholdEd25519ParticipantIds,
} from '@shared/threshold/participants';
import type { RuntimePolicyScope } from '@shared/threshold/signingRootScope';
import { normalizeRuntimePolicyScope } from '@shared/threshold/signingRootScope';
import {
  ROUTER_AB_ECDSA_HSS_WALLET_SESSION_JWT_KIND,
  ROUTER_AB_ED25519_WALLET_SESSION_JWT_KIND,
  THRESHOLD_ECDSA_SESSION_AUTH_TOKEN_KIND,
  THRESHOLD_ED25519_SESSION_AUTH_TOKEN_KIND,
} from '@shared/utils/sessionTokens';
import {
  parseRouterAbEcdsaHssNormalSigningStateV1,
  parseRouterAbEcdsaHssNormalSigningScopeV1,
  type RouterAbEcdsaHssNormalSigningStateV1,
  type RouterAbEcdsaHssNormalSigningScopeV1,
} from '@shared/utils/routerAbEcdsaHss';
import {
  parseRouterAbEd25519NormalSigningState,
  type RouterAbEd25519NormalSigningState,
} from '@shared/utils/signingSessionSeal';
import type {
  EcdsaHssClientBootstrapRequest,
  EcdsaHssPasskeyBootstrapAuthorization,
  EcdsaHssExportShareRequest,
  EcdsaHssPublicIdentity,
  EcdsaHssRoleLocalKeyRecord,
  WebAuthnAuthenticationCredential,
  WalletRegistrationEcdsaClientBootstrap,
} from '../types';
import { registrationPreparationIdFromString } from '../types';

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

function parseEcdsaHssClientRootProof(
  value: unknown,
): EcdsaHssRoleLocalFirstBootstrapRootProof | null {
  if (!isObject(value)) return null;
  if (toOptionalString(value.version) !== ECDSA_HSS_ROLE_LOCAL_FIRST_BOOTSTRAP_ROOT_PROOF_VERSION) {
    return null;
  }
  const clientRootPublicKey33B64u = parseSec1CompressedPublicKey33B64u(
    value.clientRootPublicKey33B64u,
  );
  const digest32B64u = parseB64uFixed(value.digest32B64u, 32);
  const signature65B64u = parseB64uFixed(value.signature65B64u, 65);
  if (!clientRootPublicKey33B64u || !digest32B64u || !signature65B64u) return null;
  return {
    version: ECDSA_HSS_ROLE_LOCAL_FIRST_BOOTSTRAP_ROOT_PROOF_VERSION,
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
  if (value.response.userHandle !== undefined && value.response.userHandle !== null && !userHandle) {
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

function parseEcdsaHssPasskeyBootstrapAuthorization(
  value: unknown,
): EcdsaHssPasskeyBootstrapAuthorization | null {
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
  const runtimeEnvironmentId = toOptionalString(value.runtimeEnvironmentId);
  if (!rpId || !webauthnAuthentication) return null;
  return {
    kind: 'passkey_bootstrap',
    rpId,
    webauthn_authentication: webauthnAuthentication,
    ...(runtimePolicyScope ? { runtimePolicyScope } : {}),
    ...(runtimeEnvironmentId ? { runtimeEnvironmentId } : {}),
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

export type ParsedThresholdEd25519KeyRecord = {
  walletId: string;
  nearAccountId: string;
  nearEd25519SigningKeyId: string;
  rpId: string;
  publicKey: string;
  relayerSigningShareB64u: string;
  relayerVerifyingShareB64u: string;
  keyVersion: string;
  recoveryExportCapable: true;
};

export function parseThresholdEd25519KeyRecord(
  raw: unknown,
): ParsedThresholdEd25519KeyRecord | null {
  if (!isObject(raw)) return null;
  const walletId = toOptionalString(raw.walletId);
  const nearAccountId = toOptionalString(raw.nearAccountId);
  const nearEd25519SigningKeyId = toOptionalString(raw.nearEd25519SigningKeyId);
  const rpId = toOptionalString(raw.rpId);
  const publicKey = toOptionalString(raw.publicKey);
  const relayerSigningShareB64u = toOptionalString(raw.relayerSigningShareB64u);
  const relayerVerifyingShareB64u = toOptionalString(raw.relayerVerifyingShareB64u);
  const keyVersion = toOptionalString(raw.keyVersion);
  const recoveryExportCapable = raw.recoveryExportCapable === true ? (true as const) : false;
  if (
    !walletId ||
    !nearAccountId ||
    !nearEd25519SigningKeyId ||
    !rpId ||
    !publicKey ||
    !relayerSigningShareB64u ||
    !relayerVerifyingShareB64u ||
    !keyVersion ||
    recoveryExportCapable !== true
  )
    return null;
  return {
    walletId,
    nearAccountId,
    nearEd25519SigningKeyId,
    rpId,
    publicKey,
    relayerSigningShareB64u,
    relayerVerifyingShareB64u,
    keyVersion,
    recoveryExportCapable: true,
  };
}

const ECDSA_HSS_V1_CONTEXT_FORBIDDEN_FIELDS = [
  'subjectId',
  'walletSessionUserId',
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

const ECDSA_HSS_BOOTSTRAP_FORBIDDEN_FIELDS = [
  ...ECDSA_HSS_V1_CONTEXT_FORBIDDEN_FIELDS,
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

const ECDSA_HSS_EXPORT_REQUEST_FORBIDDEN_FIELDS = [
  ...ECDSA_HSS_V1_CONTEXT_FORBIDDEN_FIELDS,
  'rpId',
  'rp_id',
  'chainTarget',
  'yClient32Le',
  'yClient32LeB64u',
  'yRelayer32Le',
  'yRelayer32LeB64u',
  'clientShare32B64u',
  'relayerShare32B64u',
  'serverExportShare32B64u',
  'canonicalPrivateKeyHex',
  'privateKeyHex',
] as const;

function parseEcdsaHssPublicIdentity(raw: unknown): EcdsaHssPublicIdentity | null {
  if (!isObject(raw)) return null;
  const hssClientSharePublicKey33B64u = parseSec1CompressedPublicKey33B64u(
    raw.hssClientSharePublicKey33B64u,
  );
  const relayerPublicKey33B64u = parseSec1CompressedPublicKey33B64u(raw.relayerPublicKey33B64u);
  const groupPublicKey33B64u = parseSec1CompressedPublicKey33B64u(raw.groupPublicKey33B64u);
  const ethereumAddress = toOptionalString(raw.ethereumAddress);
  if (
    !hssClientSharePublicKey33B64u ||
    !relayerPublicKey33B64u ||
    !groupPublicKey33B64u ||
    !ethereumAddress
  ) {
    return null;
  }
  return {
    hssClientSharePublicKey33B64u:
      hssClientSharePublicKey33B64u as EcdsaHssClientSharePublicKey33B64u,
    relayerPublicKey33B64u: relayerPublicKey33B64u as EcdsaRelayerHssPublicKey33B64u,
    groupPublicKey33B64u,
    ethereumAddress,
  };
}

export function parseEcdsaHssClientBootstrapRequest(
  raw: unknown,
): EcdsaHssClientBootstrapRequest | null {
  if (!isObject(raw)) return null;
  if (hasForbiddenFields(raw, ECDSA_HSS_BOOTSTRAP_FORBIDDEN_FIELDS)) return null;
  if (toOptionalString(raw.formatVersion) !== 'ecdsa-hss-role-local') return null;
  if (toOptionalString(raw.keyScope) !== 'evm-family') return null;
  const walletId = toOptionalString(raw.walletId);
  const walletKeyId = toOptionalString(raw.walletKeyId);
  const ecdsaThresholdKeyId = toOptionalString(raw.ecdsaThresholdKeyId);
  const signingRootId = toOptionalString(raw.signingRootId);
  const signingRootVersion = toOptionalString(raw.signingRootVersion);
  const relayerKeyId = toOptionalString(raw.relayerKeyId);
  const registrationPreparationIdRaw = toOptionalString(raw.registrationPreparationId);
  const hssClientSharePublicKey33B64u = parseSec1CompressedPublicKey33B64u(
    raw.hssClientSharePublicKey33B64u,
  );
  const contextBinding32B64u = parseB64uFixed(raw.contextBinding32B64u, 32);
  const requestId = toOptionalString(raw.requestId);
  const sessionId = toOptionalString(raw.sessionId);
  const signingGrantId = toOptionalString(raw.signingGrantId);
  const clientShareRetryCounter = raw.clientShareRetryCounter;
  const ttlMs = raw.ttlMs;
  const remainingUses = raw.remainingUses;
  const sessionKindRaw = toOptionalString(raw.sessionKind);
  const sessionKind: 'jwt' | null | undefined =
    sessionKindRaw === 'jwt' ? 'jwt' : sessionKindRaw ? null : undefined;
  const participantIds = normalizeThresholdEd25519ParticipantIds(raw.participantIds);
  const runtimePolicyScopeRaw = (raw as { runtimePolicyScope?: unknown }).runtimePolicyScope;
  const runtimePolicyScope =
    runtimePolicyScopeRaw === undefined ? null : parseRuntimePolicyScope(runtimePolicyScopeRaw);
  const clientRootProof =
    raw.clientRootProof === undefined ? null : parseEcdsaHssClientRootProof(raw.clientRootProof);
  const passkeyBootstrapAuthorization =
    raw.passkeyBootstrapAuthorization === undefined
      ? null
      : parseEcdsaHssPasskeyBootstrapAuthorization(raw.passkeyBootstrapAuthorization);
  if (
    !walletId ||
    !walletKeyId ||
    !ecdsaThresholdKeyId ||
    !signingRootId ||
    !signingRootVersion ||
    !relayerKeyId ||
    !hssClientSharePublicKey33B64u ||
    !contextBinding32B64u ||
    !requestId ||
    sessionKind === null ||
    !sessionId ||
    !signingGrantId ||
    !isNonNegativeInteger(clientShareRetryCounter) ||
    !isNonNegativeInteger(ttlMs) ||
    !isNonNegativeInteger(remainingUses) ||
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
    formatVersion: 'ecdsa-hss-role-local' as const,
    walletId,
    walletKeyId,
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
    hssClientSharePublicKey33B64u:
      hssClientSharePublicKey33B64u as EcdsaHssClientSharePublicKey33B64u,
    clientShareRetryCounter,
    contextBinding32B64u,
    requestId,
    sessionId,
    signingGrantId,
    ttlMs,
    remainingUses,
    participantIds,
    sessionKind,
    ...(runtimePolicyScope ? { runtimePolicyScope } : {}),
  };
  if (clientRootProof) return { ...base, clientRootProof };
  if (passkeyBootstrapAuthorization) {
    return { ...base, passkeyBootstrapAuthorization };
  }
  return base;
}

export function parseWalletRegistrationEcdsaClientBootstrap(
  raw: unknown,
): WalletRegistrationEcdsaClientBootstrap | null {
  if (!isObject(raw)) return null;
  if (toOptionalString(raw.sessionId)) return null;
  if (raw.clientRootProof !== undefined || raw.passkeyBootstrapAuthorization !== undefined) {
    return null;
  }
  const thresholdSessionId = toOptionalString(raw.thresholdSessionId);
  if (!thresholdSessionId) return null;
  const parsed = parseEcdsaHssClientBootstrapRequest({
    formatVersion: raw.formatVersion,
    walletId: raw.walletId,
    walletKeyId: raw.walletKeyId,
    ecdsaThresholdKeyId: raw.ecdsaThresholdKeyId,
    signingRootId: raw.signingRootId,
    signingRootVersion: raw.signingRootVersion,
    keyScope: raw.keyScope,
    relayerKeyId: raw.relayerKeyId,
    registrationPreparationId: raw.registrationPreparationId,
    hssClientSharePublicKey33B64u: raw.hssClientSharePublicKey33B64u,
    clientShareRetryCounter: raw.clientShareRetryCounter,
    contextBinding32B64u: raw.contextBinding32B64u,
    requestId: raw.requestId,
    sessionId: thresholdSessionId,
    signingGrantId: raw.signingGrantId,
    ttlMs: raw.ttlMs,
    remainingUses: raw.remainingUses,
    participantIds: raw.participantIds,
    runtimePolicyScope: raw.runtimePolicyScope,
  });
  if (
    !parsed ||
    parsed.clientRootProof ||
    parsed.passkeyBootstrapAuthorization ||
    parsed.sessionKind
  ) {
    return null;
  }
  return {
    formatVersion: parsed.formatVersion,
    walletId: parsed.walletId,
    walletKeyId: parsed.walletKeyId,
    ecdsaThresholdKeyId: parsed.ecdsaThresholdKeyId,
    signingRootId: parsed.signingRootId,
    signingRootVersion: parsed.signingRootVersion,
    keyScope: parsed.keyScope,
    relayerKeyId: parsed.relayerKeyId,
    ...(parsed.registrationPreparationId
      ? { registrationPreparationId: parsed.registrationPreparationId }
      : {}),
    hssClientSharePublicKey33B64u: parsed.hssClientSharePublicKey33B64u,
    clientShareRetryCounter: parsed.clientShareRetryCounter,
    contextBinding32B64u: parsed.contextBinding32B64u,
    requestId: parsed.requestId,
    thresholdSessionId: parsed.sessionId,
    signingGrantId: parsed.signingGrantId,
    ttlMs: parsed.ttlMs,
    remainingUses: parsed.remainingUses,
    participantIds: parsed.participantIds,
    ...(parsed.runtimePolicyScope ? { runtimePolicyScope: parsed.runtimePolicyScope } : {}),
  };
}

export function parseEcdsaHssExportShareRequest(raw: unknown): EcdsaHssExportShareRequest | null {
  if (!isObject(raw)) return null;
  if (hasForbiddenFields(raw, ECDSA_HSS_EXPORT_REQUEST_FORBIDDEN_FIELDS)) return null;
  if (toOptionalString(raw.formatVersion) !== 'ecdsa-hss-role-local-export') return null;
  const walletId = toOptionalString(raw.walletId);
  const walletKeyId = toOptionalString(raw.walletKeyId);
  const ecdsaThresholdKeyId = toOptionalString(raw.ecdsaThresholdKeyId);
  const relayerKeyId = toOptionalString(raw.relayerKeyId);
  const contextBinding32B64u = parseB64uFixed(raw.contextBinding32B64u, 32);
  const publicIdentity = parseEcdsaHssPublicIdentity(raw.publicIdentity);
  const exportRequestNonce32B64u = parseB64uFixed(raw.exportRequestNonce32B64u, 32);
  const confirmationDigest32B64u = parseB64uFixed(raw.confirmationDigest32B64u, 32);
  const authorizationDigest32B64u = parseB64uFixed(raw.authorizationDigest32B64u, 32);
  const issuedAtUnixMs = raw.issuedAtUnixMs;
  const expiresAtUnixMs = raw.expiresAtUnixMs;
  const clientDeviceId = toOptionalString(raw.clientDeviceId);
  const clientSessionId = toOptionalString(raw.clientSessionId);
  if (
    !walletId ||
    !walletKeyId ||
    !ecdsaThresholdKeyId ||
    !relayerKeyId ||
    !contextBinding32B64u ||
    !publicIdentity ||
    !exportRequestNonce32B64u ||
    !confirmationDigest32B64u ||
    !authorizationDigest32B64u ||
    !isNonNegativeInteger(issuedAtUnixMs) ||
    !isNonNegativeInteger(expiresAtUnixMs) ||
    expiresAtUnixMs <= issuedAtUnixMs ||
    !clientDeviceId ||
    !clientSessionId
  ) {
    return null;
  }
  return {
    formatVersion: 'ecdsa-hss-role-local-export',
    walletId,
    walletKeyId,
    ecdsaThresholdKeyId,
    relayerKeyId,
    contextBinding32B64u,
    publicIdentity,
    exportRequestNonce32B64u,
    confirmationDigest32B64u,
    authorizationDigest32B64u,
    issuedAtUnixMs,
    expiresAtUnixMs,
    clientDeviceId,
    clientSessionId,
  };
}

export function parseEcdsaHssRoleLocalKeyRecord(raw: unknown): EcdsaHssRoleLocalKeyRecord | null {
  if (!isObject(raw)) return null;
  if (hasForbiddenFields(raw, ECDSA_HSS_V1_CONTEXT_FORBIDDEN_FIELDS)) return null;
  if (toOptionalString(raw.version) !== 'threshold_ecdsa_hss_role_local_v2') return null;
  if (toOptionalString(raw.keyScope) !== 'evm-family') return null;
  const ecdsaThresholdKeyId = toOptionalString(raw.ecdsaThresholdKeyId);
  const keyHandle = toOptionalString(raw.keyHandle);
  const walletId = toOptionalString(raw.walletId);
  const walletKeyId = toOptionalString(raw.walletKeyId);
  const signingRootId = toOptionalString(raw.signingRootId);
  const signingRootVersion = toOptionalString(raw.signingRootVersion);
  const relayerKeyId = toOptionalString(raw.relayerKeyId);
  const contextBinding32B64u = parseB64uFixed(raw.contextBinding32B64u, 32);
  const relayerShare32B64u = parseB64uFixed(raw.relayerShare32B64u, 32);
  const relayerPublicKey33B64u = parseSec1CompressedPublicKey33B64u(raw.relayerPublicKey33B64u);
  const clientPublicKey33B64u = parseSec1CompressedPublicKey33B64u(raw.clientPublicKey33B64u);
  const groupPublicKey33B64u = parseSec1CompressedPublicKey33B64u(raw.groupPublicKey33B64u);
  const ethereumAddress = toOptionalString(raw.ethereumAddress);
  const relayerCaitSithInput = isObject(raw.relayerCaitSithInput) ? raw.relayerCaitSithInput : null;
  const relayerMappedPrivateShare32B64u = parseB64uFixed(
    relayerCaitSithInput?.mappedPrivateShare32B64u,
    32,
  );
  const relayerVerifyingShare33B64u = parseSec1CompressedPublicKey33B64u(
    relayerCaitSithInput?.verifyingShare33B64u,
  );
  const publicTranscriptDigest32B64u = parseB64uFixed(raw.publicTranscriptDigest32B64u, 32);
  const createdAtMs = raw.createdAtMs;
  const updatedAtMs = raw.updatedAtMs;
  if (
    !ecdsaThresholdKeyId ||
    !keyHandle ||
    !walletId ||
    !walletKeyId ||
    !signingRootId ||
    !signingRootVersion ||
    !relayerKeyId ||
    !contextBinding32B64u ||
    !relayerShare32B64u ||
    !relayerPublicKey33B64u ||
    !clientPublicKey33B64u ||
    !groupPublicKey33B64u ||
    !ethereumAddress ||
    !relayerCaitSithInput ||
    relayerCaitSithInput.participantId !== 2 ||
    !relayerMappedPrivateShare32B64u ||
    !relayerVerifyingShare33B64u ||
    !publicTranscriptDigest32B64u ||
    !isValidNumber(createdAtMs) ||
    !isValidNumber(updatedAtMs)
  ) {
    return null;
  }
  return {
    version: 'threshold_ecdsa_hss_role_local_v2',
    ecdsaThresholdKeyId,
    keyHandle,
    walletId,
    walletKeyId,
    signingRootId,
    signingRootVersion,
    keyScope: 'evm-family',
    relayerKeyId,
    contextBinding32B64u,
    relayerShare32B64u,
    relayerPublicKey33B64u,
    clientPublicKey33B64u,
    groupPublicKey33B64u,
    ethereumAddress,
    relayerCaitSithInput: {
      participantId: 2,
      mappedPrivateShare32B64u: relayerMappedPrivateShare32B64u,
      verifyingShare33B64u: relayerVerifyingShare33B64u,
    },
    publicTranscriptDigest32B64u,
    createdAtMs,
    updatedAtMs,
  };
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

export type ParsedThresholdEd25519MpcSessionRecord = {
  expiresAtMs: number;
  ecdsaThresholdKeyId?: string;
  keyHandle?: string;
  relayerKeyId: string;
  purpose: string;
  intentDigestB64u: string;
  signingDigestB64u: string;
  userId: string;
  rpId: string;
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
  walletKeyId: string;
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
  const rpId = toOptionalString(raw.rpId);
  const clientVerifyingShareB64u = toOptionalString(raw.clientVerifyingShareB64u);
  const participantIds = normalizeThresholdEd25519ParticipantIds(raw.participantIds) || [
    ...THRESHOLD_ED25519_2P_PARTICIPANT_IDS,
  ];
  const signingRootMetadata = parseOptionalThresholdEcdsaSigningRootMetadataFields(raw);
  if (!signingRootMetadata.ok) return null;
  if (!isValidNumber(expiresAtMs)) return null;
  if (!relayerKeyId || !purpose || !intentDigestB64u || !signingDigestB64u || !userId || !rpId)
    return null;
  return {
    expiresAtMs,
    ...(ecdsaThresholdKeyId ? { ecdsaThresholdKeyId } : {}),
    ...(keyHandle ? { keyHandle } : {}),
    relayerKeyId,
    purpose,
    intentDigestB64u,
    signingDigestB64u,
    userId,
    rpId,
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
  const walletId = toOptionalString(raw.walletId) || toOptionalString(raw.walletSessionUserId);
  const walletKeyId = toOptionalString(raw.walletKeyId);
  const clientVerifyingShareB64u = toOptionalString(raw.clientVerifyingShareB64u);
  const participantIds = normalizeThresholdEd25519ParticipantIds(raw.participantIds) || [
    ...THRESHOLD_ED25519_2P_PARTICIPANT_IDS,
  ];
  const signingRootMetadata = parseOptionalThresholdEcdsaSigningRootMetadataFields(raw);
  if (!signingRootMetadata.ok) return null;
  if (!isValidNumber(expiresAtMs)) return null;
  if (
    !relayerKeyId ||
    !purpose ||
    !intentDigestB64u ||
    !signingDigestB64u ||
    !walletId ||
    !walletKeyId
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
    walletId,
    walletKeyId,
    ...(clientVerifyingShareB64u ? { clientVerifyingShareB64u } : {}),
    participantIds,
    ...(signingRootMetadata.value ? signingRootMetadata.value : {}),
  };
}

export type ParsedThresholdEd25519SigningSessionRecord = {
  expiresAtMs: number;
  mpcSessionId: string;
  relayerKeyId: string;
  signingDigestB64u: string;
  userId: string;
  rpId: string;
  commitmentsById: ParsedThresholdEd25519CommitmentsById;
  relayerSigningShareB64u?: string;
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
  const rpId = toOptionalString(raw.rpId);
  const commitmentsById = parseThresholdEd25519CommitmentsById(raw.commitmentsById);
  const relayerSigningShareB64u = toOptionalString(raw.relayerSigningShareB64u);
  const relayerNoncesB64u = toOptionalString(raw.relayerNoncesB64u);
  const participantIds = normalizeThresholdEd25519ParticipantIds(raw.participantIds) || [
    ...THRESHOLD_ED25519_2P_PARTICIPANT_IDS,
  ];
  if (!isValidNumber(expiresAtMs)) return null;
  if (
    !mpcSessionId ||
    !relayerKeyId ||
    !signingDigestB64u ||
    !userId ||
    !rpId ||
    !commitmentsById ||
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
    rpId,
    commitmentsById,
    ...(relayerSigningShareB64u ? { relayerSigningShareB64u } : {}),
    relayerNoncesB64u,
    participantIds,
  };
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
  rpId: string;
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
  const rpId = toOptionalString(raw.rpId);
  const commitmentsById = parseThresholdEd25519CommitmentsById(raw.commitmentsById);
  const participantIds = normalizeThresholdEd25519ParticipantIds(raw.participantIds) || [
    ...THRESHOLD_ED25519_2P_PARTICIPANT_IDS,
  ];
  const relayerVerifyingSharesById = parseThresholdEd25519StringById(
    raw.relayerVerifyingSharesById,
  );

  if (!isValidNumber(expiresAtMs)) return null;
  if (
    !mpcSessionId ||
    !relayerKeyId ||
    !signingDigestB64u ||
    !userId ||
    !rpId ||
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
    rpId,
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
  rpId: string;
  participantIds: number[];
  walletBudgetBinding?: {
    curve: 'ed25519' | 'ecdsa';
    thresholdSessionId: string;
  };
} & Partial<ParsedThresholdEcdsaSigningRootMetadata>;

function parseWalletBudgetBinding(
  raw: unknown,
): ParsedEd25519WalletSessionRecord['walletBudgetBinding'] {
  if (!isObject(raw)) return undefined;
  const curve = toOptionalString(raw.curve);
  const thresholdSessionId = toOptionalString(raw.thresholdSessionId);
  if ((curve !== 'ed25519' && curve !== 'ecdsa') || !thresholdSessionId) return undefined;
  return { curve, thresholdSessionId };
}

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
  const rpId = toOptionalString(raw.rpId);
  const participantIds = normalizeThresholdEd25519ParticipantIds(raw.participantIds) || [
    ...THRESHOLD_ED25519_2P_PARTICIPANT_IDS,
  ];
  const signingRootMetadata = parseOptionalThresholdEcdsaSigningRootMetadataFields(raw);
  const walletBudgetBinding = parseWalletBudgetBinding(raw.walletBudgetBinding);
  if (!signingRootMetadata.ok) return null;
  if (!isValidNumber(expiresAtMs)) return null;
  if (!relayerKeyId || !userId || !walletId || !nearAccountId || !nearEd25519SigningKeyId || !rpId)
    return null;
  return {
    expiresAtMs,
    relayerKeyId,
    userId,
    walletId,
    nearAccountId,
    nearEd25519SigningKeyId,
    rpId,
    participantIds,
    ...(walletBudgetBinding ? { walletBudgetBinding } : {}),
    ...(signingRootMetadata.value ? signingRootMetadata.value : {}),
  };
}

export type ParsedEcdsaWalletSessionRecord = {
  expiresAtMs: number;
  relayerKeyId: string;
  walletId: string;
  walletKeyId: string;
  participantIds: number[];
} & Partial<ParsedThresholdEcdsaSigningRootMetadata>;

export function parseEcdsaWalletSessionRecord(
  raw: unknown,
): ParsedEcdsaWalletSessionRecord | null {
  if (!isObject(raw)) return null;
  const expiresAtMs = raw.expiresAtMs;
  const relayerKeyId = toOptionalString(raw.relayerKeyId);
  const walletId = toOptionalString(raw.walletId) || toOptionalString(raw.walletSessionUserId);
  const walletKeyId = toOptionalString(raw.walletKeyId);
  const participantIds = normalizeThresholdEd25519ParticipantIds(raw.participantIds) || [
    ...THRESHOLD_ED25519_2P_PARTICIPANT_IDS,
  ];
  const signingRootMetadata = parseOptionalThresholdEcdsaSigningRootMetadataFields(raw);
  if (!signingRootMetadata.ok) return null;
  if (!isValidNumber(expiresAtMs)) return null;
  if (!relayerKeyId || !walletId || !walletKeyId) return null;
  return {
    expiresAtMs,
    relayerKeyId,
    walletId,
    walletKeyId,
    participantIds,
    ...(signingRootMetadata.value ? signingRootMetadata.value : {}),
  };
}

export type ParsedWalletSigningBudgetSessionRecord = {
  kind: 'wallet_signing_budget_session';
  expiresAtMs: number;
  relayerKeyId: string;
  walletId: string;
  budgetScope:
    | { kind: 'passkey_rp'; rpId: string }
    | { kind: 'wallet_key'; walletKeyId: string };
  binding: {
    curve: 'ed25519' | 'ecdsa';
    thresholdSessionId: string;
  };
  participantIds: number[];
};

function parseWalletSigningBudgetScope(
  raw: unknown,
): ParsedWalletSigningBudgetSessionRecord['budgetScope'] | null {
  if (!isObject(raw)) return null;
  const kind = toOptionalString(raw.kind);
  if (kind === 'passkey_rp') {
    const rpId = toOptionalString(raw.rpId);
    return rpId ? { kind, rpId } : null;
  }
  if (kind === 'wallet_key') {
    const walletKeyId = toOptionalString(raw.walletKeyId);
    return walletKeyId ? { kind, walletKeyId } : null;
  }
  return null;
}

export function parseWalletSigningBudgetSessionRecord(
  raw: unknown,
): ParsedWalletSigningBudgetSessionRecord | null {
  if (!isObject(raw)) return null;
  const kind = toOptionalString(raw.kind);
  const expiresAtMs = raw.expiresAtMs;
  const relayerKeyId = toOptionalString(raw.relayerKeyId);
  const walletId = toOptionalString(raw.walletId);
  const budgetScope = parseWalletSigningBudgetScope(raw.budgetScope);
  const binding = parseWalletBudgetBinding(raw.binding);
  const participantIds = normalizeThresholdEd25519ParticipantIds(raw.participantIds) || [
    ...THRESHOLD_ED25519_2P_PARTICIPANT_IDS,
  ];
  if (kind !== 'wallet_signing_budget_session') return null;
  if (!isValidNumber(expiresAtMs)) return null;
  if (!relayerKeyId || !walletId || !budgetScope || !binding) return null;
  return {
    kind,
    expiresAtMs,
    relayerKeyId,
    walletId,
    budgetScope,
    binding,
    participantIds,
  };
}

export type ParsedRouterAbEcdsaHssServerPresignatureShareRecord = {
  relayerKeyId: string;
  presignatureId: string;
  bigRB64u: string;
  kShareB64u: string;
  sigmaShareB64u: string;
  createdAtMs: number;
};

export type ParsedRouterAbEcdsaHssPoolFillSessionStage =
  | 'triples'
  | 'triples_done'
  | 'presign'
  | 'done';

export type ParsedRouterAbEcdsaHssPoolFillSessionDestination =
  | {
      kind: 'local_threshold_ecdsa_presignature_pool';
      routerAbEcdsaHss?: never;
    }
  | {
      kind: 'router_ab_ecdsa_hss_signing_worker_pool';
      routerAbEcdsaHss: {
        scope: RouterAbEcdsaHssNormalSigningScopeV1;
        expiresAtMs: number;
      };
    };

export type ParsedRouterAbEcdsaHssPoolFillSessionRecord = {
  expiresAtMs: number;
  walletId: string;
  walletKeyId: string;
  relayerKeyId: string;
  presignPoolKey: string;
  poolFill: ParsedRouterAbEcdsaHssPoolFillSessionDestination;
  ownerInstanceId?: string;
  participantIds: number[];
  clientParticipantId: number;
  relayerParticipantId: number;
  stage: ParsedRouterAbEcdsaHssPoolFillSessionStage;
  version: number;
  createdAtMs: number;
  updatedAtMs: number;
} & ParsedThresholdEcdsaSigningRootMetadata;

function parseRouterAbEcdsaHssPoolFillSessionDestination(
  value: unknown,
  sessionExpiresAtMs: number,
): ParsedRouterAbEcdsaHssPoolFillSessionDestination | null {
  if (!isObject(value)) return null;
  const kind = toOptionalString(value.kind);
  if (kind === 'local_threshold_ecdsa_presignature_pool') {
    return { kind };
  }
  if (kind !== 'router_ab_ecdsa_hss_signing_worker_pool') return null;
  if (!isObject(value.routerAbEcdsaHss)) return null;
  const expiresAtMs = value.routerAbEcdsaHss.expiresAtMs;
  if (!isValidNumber(expiresAtMs)) return null;
  const expiresAtMsInt = Math.floor(expiresAtMs);
  if (expiresAtMsInt !== expiresAtMs || expiresAtMsInt <= 0) return null;
  if (expiresAtMsInt > sessionExpiresAtMs) return null;
  let scope: RouterAbEcdsaHssNormalSigningScopeV1;
  try {
    scope = parseRouterAbEcdsaHssNormalSigningScopeV1(value.routerAbEcdsaHss.scope);
  } catch {
    return null;
  }
  return {
    kind,
    routerAbEcdsaHss: {
      scope,
      expiresAtMs: expiresAtMsInt,
    },
  };
}

export function parseRouterAbEcdsaHssPoolFillSessionRecord(
  raw: unknown,
): ParsedRouterAbEcdsaHssPoolFillSessionRecord | null {
  if (!isObject(raw)) return null;
  const expiresAtMs = raw.expiresAtMs;
  const walletId =
    toOptionalString(raw.walletId) ||
    toOptionalString(raw.walletSessionUserId) ||
    toOptionalString(raw.userId);
  const walletKeyId = toOptionalString(raw.walletKeyId);
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

  const stage: ParsedRouterAbEcdsaHssPoolFillSessionStage | null =
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
  const poolFill = parseRouterAbEcdsaHssPoolFillSessionDestination(raw.poolFill, expiresAtMs);
  if (
    !walletId ||
    !walletKeyId ||
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
    walletKeyId,
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

export function parseRouterAbEcdsaHssServerPresignatureShareRecord(
  raw: unknown,
): ParsedRouterAbEcdsaHssServerPresignatureShareRecord | null {
  if (!isObject(raw)) return null;
  const relayerKeyId = toOptionalString(raw.relayerKeyId);
  const presignatureId = toOptionalString(raw.presignatureId);
  const bigRB64u = toOptionalString(raw.bigRB64u);
  const kShareB64u = toOptionalString(raw.kShareB64u);
  const sigmaShareB64u = toOptionalString(raw.sigmaShareB64u);
  const createdAtMs = raw.createdAtMs;
  if (!relayerKeyId || !presignatureId || !bigRB64u || !kShareB64u || !sigmaShareB64u) return null;
  if (!isValidNumber(createdAtMs)) return null;
  return { relayerKeyId, presignatureId, bigRB64u, kShareB64u, sigmaShareB64u, createdAtMs };
}

type Ed25519WalletSessionClaimKind =
  | typeof THRESHOLD_ED25519_SESSION_AUTH_TOKEN_KIND
  | typeof ROUTER_AB_ED25519_WALLET_SESSION_JWT_KIND;

export type Ed25519WalletSessionClaimsForKind<Kind extends Ed25519WalletSessionClaimKind> = {
  sub: string;
  walletId: string;
  nearAccountId: string;
  nearEd25519SigningKeyId: string;
  kind: Kind;
  thresholdSessionId: string;
  signingGrantId: string;
  relayerKeyId: string;
  rpId: string;
  runtimePolicyScope?: RuntimePolicyScope;
  thresholdExpiresAtMs: number;
  participantIds: number[];
  iat?: number;
  exp?: number;
  nbf?: number;
};

export type LegacyThresholdEd25519SessionClaims = Ed25519WalletSessionClaimsForKind<
  typeof THRESHOLD_ED25519_SESSION_AUTH_TOKEN_KIND
>;

export type RouterAbEd25519WalletSessionClaims = Ed25519WalletSessionClaimsForKind<
  typeof ROUTER_AB_ED25519_WALLET_SESSION_JWT_KIND
> & {
  runtimePolicyScope: RuntimePolicyScope;
  routerAbNormalSigning: RouterAbEd25519NormalSigningState;
};

export type ThresholdEd25519SessionClaims =
  | LegacyThresholdEd25519SessionClaims
  | RouterAbEd25519WalletSessionClaims;

function parseRuntimePolicyScope(raw: unknown): RuntimePolicyScope | null {
  try {
    return normalizeRuntimePolicyScope(raw as Record<string, unknown>);
  } catch {
    return null;
  }
}

function parseEd25519WalletSessionClaimsForKind<Kind extends Ed25519WalletSessionClaimKind>(
  raw: unknown,
  expectedKind: Kind,
): Ed25519WalletSessionClaimsForKind<Kind> | null {
  if (!isObject(raw)) return null;
  const kind = toOptionalString(raw.kind);
  if (kind !== expectedKind) return null;
  const sub = toOptionalString(raw.sub);
  const walletId = toOptionalString((raw as { walletId?: unknown }).walletId);
  const nearAccountId = toOptionalString((raw as { nearAccountId?: unknown }).nearAccountId);
  const nearEd25519SigningKeyId = toOptionalString(
    (raw as { nearEd25519SigningKeyId?: unknown }).nearEd25519SigningKeyId,
  );
  const thresholdSessionId = toOptionalString(
    (raw as { thresholdSessionId?: unknown }).thresholdSessionId,
  );
  const signingGrantId = toOptionalString((raw as { signingGrantId?: unknown }).signingGrantId);
  const relayerKeyId = toOptionalString(raw.relayerKeyId);
  const rpId = toOptionalString(raw.rpId);
  if (
    !sub ||
    !walletId ||
    walletId !== sub ||
    !nearAccountId ||
    !nearEd25519SigningKeyId ||
    !thresholdSessionId ||
    !signingGrantId ||
    !relayerKeyId ||
    !rpId
  )
    return null;
  const thresholdExpiresAtMs = (raw as { thresholdExpiresAtMs?: unknown }).thresholdExpiresAtMs;
  if (!isValidNumber(thresholdExpiresAtMs)) return null;
  const participantIds = normalizeThresholdEd25519ParticipantIds(
    (raw as { participantIds?: unknown }).participantIds,
  );
  if (!participantIds || participantIds.length < 2) return null;
  const out: Ed25519WalletSessionClaimsForKind<Kind> = {
    sub,
    walletId,
    nearAccountId,
    nearEd25519SigningKeyId,
    kind: expectedKind,
    thresholdSessionId,
    signingGrantId,
    relayerKeyId,
    rpId,
    thresholdExpiresAtMs,
    participantIds,
  };
  const runtimePolicyScopeRaw = (raw as { runtimePolicyScope?: unknown }).runtimePolicyScope;
  if (runtimePolicyScopeRaw !== undefined) {
    const runtimePolicyScope = parseRuntimePolicyScope(runtimePolicyScopeRaw);
    if (!runtimePolicyScope) {
      console.warn(
        '[threshold-ecdsa-e2e] app session runtimePolicyScope parse failed',
        runtimePolicyScopeRaw,
      );
      return null;
    }
    out.runtimePolicyScope = runtimePolicyScope;
  }

  const iat = (raw as { iat?: unknown }).iat;
  if (iat !== undefined) {
    const v = Number(iat);
    if (!Number.isFinite(v)) return null;
    out.iat = v;
  }

  const exp = (raw as { exp?: unknown }).exp;
  if (exp !== undefined) {
    const v = Number(exp);
    if (!Number.isFinite(v)) return null;
    out.exp = v;
  }

  const nbf = (raw as { nbf?: unknown }).nbf;
  if (nbf !== undefined) {
    const v = Number(nbf);
    if (!Number.isFinite(v)) return null;
    out.nbf = v;
  }

  return out;
}

export function parseThresholdEd25519SessionClaims(
  raw: unknown,
): LegacyThresholdEd25519SessionClaims | null {
  // Legacy parser compatibility boundary: retained only for historical parser
  // tests and non-signing migration reads. Active Router A/B route/service code
  // must use parseRouterAbEd25519WalletSessionClaims; delete this parser when
  // legacy threshold-session JWT fixture coverage is removed.
  return parseEd25519WalletSessionClaimsForKind(raw, THRESHOLD_ED25519_SESSION_AUTH_TOKEN_KIND);
}

export function parseRouterAbEd25519WalletSessionClaims(
  raw: unknown,
): RouterAbEd25519WalletSessionClaims | null {
  const claims = parseEd25519WalletSessionClaimsForKind(
    raw,
    ROUTER_AB_ED25519_WALLET_SESSION_JWT_KIND,
  );
  if (!claims?.runtimePolicyScope) return null;
  let routerAbNormalSigning: RouterAbEd25519NormalSigningState | null = null;
  try {
    routerAbNormalSigning = parseRouterAbEd25519NormalSigningState(
      isObject(raw) ? raw.routerAbNormalSigning : undefined,
    );
  } catch {
    return null;
  }
  if (!routerAbNormalSigning) return null;
  return {
    ...claims,
    runtimePolicyScope: claims.runtimePolicyScope,
    routerAbNormalSigning,
  };
}

export type ParsedRouterAbEd25519PresignRecord = {
  kind: 'router_ab_ed25519_presign_record_v2';
  expiresAtMs: number;
  thresholdSessionId: string;
  signingGrantId: string;
  relayerKeyId: string;
  nearAccountId: string;
  nearNetworkId: string;
  signerPublicKey: string;
  rpcPolicyId: string;
  rpId: string;
  runtimePolicyScope: RuntimePolicyScope;
  protocolVersion: 'ed25519_frost_2p_presign_v1';
  participantIds: number[];
  groupPublicKey: string;
  clientVerifyingShareB64u: string;
  clientCommitments: ParsedThresholdEd25519Commitments;
  relayerCommitments: ParsedThresholdEd25519Commitments;
  relayerVerifyingShareB64u: string;
  relayerNoncesB64u: string;
};

export function parseRouterAbEd25519PresignRecord(
  raw: unknown,
): ParsedRouterAbEd25519PresignRecord | null {
  if (!isObject(raw)) return null;
  const kind = toOptionalString(raw.kind);
  const expiresAtMs = raw.expiresAtMs;
  const thresholdSessionId = toOptionalString(raw.thresholdSessionId);
  const signingGrantId = toOptionalString(raw.signingGrantId);
  const relayerKeyId = toOptionalString(raw.relayerKeyId);
  const nearAccountId = toOptionalString(raw.nearAccountId);
  const nearNetworkId = toOptionalString(raw.nearNetworkId);
  const signerPublicKey = toOptionalString(raw.signerPublicKey);
  const rpcPolicyId = toOptionalString(raw.rpcPolicyId);
  const rpId = toOptionalString(raw.rpId);
  const runtimePolicyScope = parseRuntimePolicyScope(raw.runtimePolicyScope);
  const protocolVersion = toOptionalString(raw.protocolVersion);
  const participantIds = normalizeThresholdEd25519ParticipantIds(raw.participantIds);
  const groupPublicKey = toOptionalString(raw.groupPublicKey);
  const clientVerifyingShareB64u = toOptionalString(raw.clientVerifyingShareB64u);
  const clientCommitments = parseThresholdEd25519Commitments(raw.clientCommitments);
  const relayerCommitments = parseThresholdEd25519Commitments(raw.relayerCommitments);
  const relayerVerifyingShareB64u = toOptionalString(raw.relayerVerifyingShareB64u);
  const relayerNoncesB64u = toOptionalString(raw.relayerNoncesB64u);

  if (
    kind !== 'router_ab_ed25519_presign_record_v2' ||
    !isValidNumber(expiresAtMs) ||
    !thresholdSessionId ||
    !signingGrantId ||
    !relayerKeyId ||
    !nearAccountId ||
    !nearNetworkId ||
    !signerPublicKey ||
    !rpcPolicyId ||
    !rpId ||
    !runtimePolicyScope ||
    protocolVersion !== 'ed25519_frost_2p_presign_v1' ||
    !participantIds ||
    participantIds.length < 2 ||
    !groupPublicKey ||
    !clientVerifyingShareB64u ||
    !clientCommitments ||
    !relayerCommitments ||
    !relayerVerifyingShareB64u ||
    !relayerNoncesB64u
  ) {
    return null;
  }

  return {
    kind,
    expiresAtMs,
    thresholdSessionId,
    signingGrantId,
    relayerKeyId,
    nearAccountId,
    nearNetworkId,
    signerPublicKey,
    rpcPolicyId,
    rpId,
    runtimePolicyScope,
    protocolVersion,
    participantIds,
    groupPublicKey,
    clientVerifyingShareB64u,
    clientCommitments,
    relayerCommitments,
    relayerVerifyingShareB64u,
    relayerNoncesB64u,
  };
}

export type AppSessionClaims = {
  sub: string;
  kind: 'app_session_v1';
  appSessionVersion: string;
  walletId?: string;
  googleEmailOtpRegistrationAttemptId?: string;
  googleEmailOtpResolutionMode?: 'existing_wallet' | 'register_started';
  runtimePolicyScope?: RuntimePolicyScope;
  iat?: number;
  exp?: number;
  nbf?: number;
};

export function parseAppSessionClaims(raw: unknown): AppSessionClaims | null {
  if (!isObject(raw)) return null;
  const kind = toOptionalString(raw.kind);
  if (kind !== 'app_session_v1') return null;
  const sub = toOptionalString(raw.sub);
  const appSessionVersion = toOptionalString(raw.appSessionVersion);
  if (!sub || !appSessionVersion) return null;
  const out: AppSessionClaims = {
    sub,
    kind,
    appSessionVersion,
  };
  const walletId = toOptionalString((raw as { walletId?: unknown }).walletId);
  if (walletId) out.walletId = walletId;
  const googleEmailOtpRegistrationAttemptId = toOptionalString(
    (raw as { googleEmailOtpRegistrationAttemptId?: unknown }).googleEmailOtpRegistrationAttemptId,
  );
  if (googleEmailOtpRegistrationAttemptId) {
    out.googleEmailOtpRegistrationAttemptId = googleEmailOtpRegistrationAttemptId;
  }
  const googleEmailOtpResolutionModeRaw = (raw as { googleEmailOtpResolutionMode?: unknown })
    .googleEmailOtpResolutionMode;
  const googleEmailOtpResolutionMode =
    googleEmailOtpResolutionModeRaw === undefined
      ? ''
      : toOptionalString(googleEmailOtpResolutionModeRaw);
  if (googleEmailOtpResolutionMode) {
    if (
      googleEmailOtpResolutionMode !== 'existing_wallet' &&
      googleEmailOtpResolutionMode !== 'register_started'
    ) {
      return null;
    }
    out.googleEmailOtpResolutionMode = googleEmailOtpResolutionMode;
  } else if (googleEmailOtpResolutionModeRaw !== undefined) {
    return null;
  }
  const runtimePolicyScopeRaw = (raw as { runtimePolicyScope?: unknown }).runtimePolicyScope;
  if (runtimePolicyScopeRaw !== undefined) {
    const runtimePolicyScope = parseRuntimePolicyScope(runtimePolicyScopeRaw);
    if (!runtimePolicyScope) return null;
    out.runtimePolicyScope = runtimePolicyScope;
  }

  const iat = (raw as { iat?: unknown }).iat;
  if (iat !== undefined) {
    const v = Number(iat);
    if (!Number.isFinite(v)) return null;
    out.iat = v;
  }

  const exp = (raw as { exp?: unknown }).exp;
  if (exp !== undefined) {
    const v = Number(exp);
    if (!Number.isFinite(v)) return null;
    out.exp = v;
  }

  const nbf = (raw as { nbf?: unknown }).nbf;
  if (nbf !== undefined) {
    const v = Number(nbf);
    if (!Number.isFinite(v)) return null;
    out.nbf = v;
  }

  return out;
}

export function resolveAppSessionProviderUserIdForWalletScope(
  claims: AppSessionClaims | null | undefined,
  requestedWalletId: unknown,
): string | undefined {
  if (!claims) return undefined;
  const subject = toOptionalString(claims.sub);
  const walletId = toOptionalString(requestedWalletId);
  if (!subject || !walletId || subject === walletId) return undefined;
  return subject;
}

export function resolveAppSessionWalletIdForWalletScope(
  claims: AppSessionClaims | null | undefined,
  requestedWalletIdRaw: unknown,
): string | undefined {
  if (!claims) return undefined;
  const explicitWalletId = toOptionalString(claims.walletId);
  if (explicitWalletId) return explicitWalletId;
  const subject = toOptionalString(claims.sub);
  const requestedWalletId = toOptionalString(requestedWalletIdRaw);
  if (subject && requestedWalletId && subject === requestedWalletId) return subject;
  return undefined;
}

type EcdsaWalletSessionClaimKind =
  | typeof THRESHOLD_ECDSA_SESSION_AUTH_TOKEN_KIND
  | typeof ROUTER_AB_ECDSA_HSS_WALLET_SESSION_JWT_KIND;

export type EcdsaWalletSessionClaimsForKind<Kind extends EcdsaWalletSessionClaimKind> = {
  sub: string;
  walletId: string;
  kind: Kind;
  thresholdSessionId: string;
  signingGrantId: string;
  keyScope: 'evm-family';
  keyHandle: string;
  relayerKeyId: string;
  walletKeyId: string;
  runtimePolicyScope?: RuntimePolicyScope;
  thresholdExpiresAtMs: number;
  participantIds: number[];
  iat?: number;
  exp?: number;
  nbf?: number;
};

export type LegacyThresholdEcdsaSessionClaims = EcdsaWalletSessionClaimsForKind<
  typeof THRESHOLD_ECDSA_SESSION_AUTH_TOKEN_KIND
>;

export type RouterAbEcdsaHssWalletSessionClaims = EcdsaWalletSessionClaimsForKind<
  typeof ROUTER_AB_ECDSA_HSS_WALLET_SESSION_JWT_KIND
> & {
  routerAbEcdsaHssNormalSigning: RouterAbEcdsaHssNormalSigningStateV1;
};

export type ThresholdEcdsaSessionClaims =
  | LegacyThresholdEcdsaSessionClaims
  | RouterAbEcdsaHssWalletSessionClaims;

function parseEcdsaWalletSessionClaimsForKind<Kind extends EcdsaWalletSessionClaimKind>(
  raw: unknown,
  expectedKind: Kind,
): EcdsaWalletSessionClaimsForKind<Kind> | null {
  if (!isObject(raw)) return null;
  const kind = toOptionalString(raw.kind);
  if (kind !== expectedKind) return null;
  const sub = toOptionalString(raw.sub);
  const walletId = toOptionalString((raw as { walletId?: unknown }).walletId);
  const thresholdSessionId = toOptionalString(
    (raw as { thresholdSessionId?: unknown }).thresholdSessionId,
  );
  const signingGrantId = toOptionalString((raw as { signingGrantId?: unknown }).signingGrantId);
  const keyScope = toOptionalString((raw as { keyScope?: unknown }).keyScope);
  const keyHandle = toOptionalString((raw as { keyHandle?: unknown }).keyHandle);
  const relayerKeyId = toOptionalString(raw.relayerKeyId);
  const walletKeyId = toOptionalString((raw as { walletKeyId?: unknown }).walletKeyId);
  if (
    !sub ||
    !walletId ||
    walletId !== sub ||
    !thresholdSessionId ||
    !signingGrantId ||
    keyScope !== 'evm-family' ||
    !keyHandle ||
    !relayerKeyId ||
    !walletKeyId
  )
    return null;
  const thresholdExpiresAtMs = (raw as { thresholdExpiresAtMs?: unknown }).thresholdExpiresAtMs;
  if (!isValidNumber(thresholdExpiresAtMs)) return null;
  const participantIds = normalizeThresholdEd25519ParticipantIds(
    (raw as { participantIds?: unknown }).participantIds,
  );
  if (!participantIds || participantIds.length < 2) return null;
  const out: EcdsaWalletSessionClaimsForKind<Kind> = {
    sub,
    walletId,
    kind: expectedKind,
    thresholdSessionId,
    signingGrantId,
    keyScope,
    keyHandle,
    relayerKeyId,
    walletKeyId,
    thresholdExpiresAtMs,
    participantIds,
  };
  const runtimePolicyScopeRaw = (raw as { runtimePolicyScope?: unknown }).runtimePolicyScope;
  if (runtimePolicyScopeRaw !== undefined) {
    const runtimePolicyScope = parseRuntimePolicyScope(runtimePolicyScopeRaw);
    if (!runtimePolicyScope) return null;
    out.runtimePolicyScope = runtimePolicyScope;
  }

  const iat = (raw as { iat?: unknown }).iat;
  if (iat !== undefined) {
    const v = Number(iat);
    if (!Number.isFinite(v)) return null;
    out.iat = v;
  }

  const exp = (raw as { exp?: unknown }).exp;
  if (exp !== undefined) {
    const v = Number(exp);
    if (!Number.isFinite(v)) return null;
    out.exp = v;
  }

  const nbf = (raw as { nbf?: unknown }).nbf;
  if (nbf !== undefined) {
    const v = Number(nbf);
    if (!Number.isFinite(v)) return null;
    out.nbf = v;
  }

  return out;
}

export function parseThresholdEcdsaSessionClaims(
  raw: unknown,
): LegacyThresholdEcdsaSessionClaims | null {
  // Legacy parser compatibility boundary: retained only for historical parser
  // tests and non-signing migration reads. Active Router A/B route/service code
  // must use parseRouterAbEcdsaHssWalletSessionClaims; delete this parser when
  // legacy threshold-session JWT fixture coverage is removed.
  return parseEcdsaWalletSessionClaimsForKind(raw, THRESHOLD_ECDSA_SESSION_AUTH_TOKEN_KIND);
}

export function parseRouterAbEcdsaHssWalletSessionClaims(
  raw: unknown,
): RouterAbEcdsaHssWalletSessionClaims | null {
  const claims = parseEcdsaWalletSessionClaimsForKind(
    raw,
    ROUTER_AB_ECDSA_HSS_WALLET_SESSION_JWT_KIND,
  );
  if (!claims || !isObject(raw)) return null;
  const hasNormalSigning = raw.routerAbEcdsaHssNormalSigning !== undefined;
  const hasIssuerBinding = raw.routerAbEcdsaHssIssuerBinding !== undefined;
  if (!hasNormalSigning || hasIssuerBinding) return null;

  let normalSigning: RouterAbEcdsaHssNormalSigningStateV1 | null = null;
  try {
    normalSigning = parseRouterAbEcdsaHssNormalSigningStateV1(raw.routerAbEcdsaHssNormalSigning);
  } catch {
    return null;
  }
  if (!normalSigning) return null;
  return {
    ...claims,
    routerAbEcdsaHssNormalSigning: normalSigning,
  };
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

export async function ensureRelayerKeyIsActiveAccessKey(input: {
  nearAccountId: unknown;
  relayerPublicKey: unknown;
  expectedSigningPublicKey?: unknown;
  viewAccessKeyList: (accountId: string) => Promise<AccessKeyList>;
  maxAttempts?: unknown;
  initialDelayMs?: unknown;
}): Promise<ThresholdValidationResult> {
  const nearAccountId = toOptionalString(input.nearAccountId);
  const relayerPublicKey = toNearPublicKeyStr(input.relayerPublicKey);
  const expectedSigningPublicKey = toNearPublicKeyStr(input.expectedSigningPublicKey);
  const maxAttemptsRaw = Number(input.maxAttempts);
  const maxAttempts =
    Number.isFinite(maxAttemptsRaw) && maxAttemptsRaw >= 1
      ? Math.min(10, Math.floor(maxAttemptsRaw))
      : 1;
  const initialDelayMsRaw = Number(input.initialDelayMs);
  const initialDelayMs =
    Number.isFinite(initialDelayMsRaw) && initialDelayMsRaw >= 0
      ? Math.min(1_000, Math.floor(initialDelayMsRaw))
      : 50;
  if (!nearAccountId)
    return { ok: false, code: 'invalid_body', message: 'nearAccountId is required' };
  if (!relayerPublicKey)
    return { ok: false, code: 'internal', message: 'Missing relayer public key for relayerKeyId' };

  if (expectedSigningPublicKey && expectedSigningPublicKey !== relayerPublicKey) {
    return {
      ok: false,
      code: 'unauthorized',
      message: 'relayerKeyId does not match signingPayload public key',
    };
  }

  let lastLookupError: unknown = null;
  let delayMs = initialDelayMs;
  try {
    for (let attempt = 1; attempt <= maxAttempts; attempt += 1) {
      try {
        const list = await input.viewAccessKeyList(nearAccountId);
        const keys = list.keys || [];
        const found = keys.some((k) => toNearPublicKeyStr(k.public_key) === relayerPublicKey);
        if (found) return { ok: true };
      } catch (e: unknown) {
        lastLookupError = e;
      }

      if (attempt < maxAttempts && delayMs > 0) {
        await new Promise<void>((resolve) => setTimeout(resolve, delayMs));
        delayMs = Math.min(1_000, delayMs * 2);
      }
    }

    if (lastLookupError) {
      const msg = String(
        lastLookupError && typeof lastLookupError === 'object' && 'message' in lastLookupError
          ? (lastLookupError as { message?: unknown }).message
          : lastLookupError || 'Failed to query NEAR access keys',
      );
      return { ok: false, code: 'internal', message: `Failed to verify access key scope: ${msg}` };
    }
    return {
      ok: false,
      code: 'unauthorized',
      message: 'relayerKeyId public key is not an active access key for nearAccountId',
    };
  } catch (e: unknown) {
    const msg = String(
      e && typeof e === 'object' && 'message' in e
        ? (e as { message?: unknown }).message
        : e || 'Failed to query NEAR access keys',
    );
    return { ok: false, code: 'internal', message: `Failed to verify access key scope: ${msg}` };
  }
}
