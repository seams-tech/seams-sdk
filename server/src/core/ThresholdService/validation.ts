import type { AccessKeyList } from '@/core/rpcClients/near/NearClient';
import { alphabetizeStringify, sha256BytesUtf8 } from '@shared/utils/digests';
import { base64UrlDecode } from '@shared/utils/encoders';
import { ensureEd25519Prefix, toOptionalString, toTrimmedString } from '@shared/utils/validation';
import {
  ECDSA_HSS_ROLE_LOCAL_FIRST_BOOTSTRAP_ROOT_PROOF_VERSION,
  type EcdsaHssRoleLocalFirstBootstrapRootProof,
} from '@shared/threshold/ecdsaHssRoleLocalBootstrap';
import {
  THRESHOLD_ED25519_2P_PARTICIPANT_IDS,
  normalizeThresholdEd25519ParticipantIds,
} from '@shared/threshold/participants';
import type { RuntimePolicyScope } from '@shared/threshold/signingRootScope';
import { normalizeRuntimePolicyScope } from '@shared/threshold/signingRootScope';
import { REGISTRATION_CONTINUATION_JWT_KIND } from '@shared/utils/sessionTokens';
import {
  thresholdEcdsaChainTargetKey,
  thresholdEcdsaChainTargetFromValue,
  type ThresholdEcdsaChainTarget,
} from '../thresholdEcdsaChainTarget';
import type {
  EcdsaHssClientBootstrapRequest,
  EcdsaHssPasskeyFirstBootstrapAuthorization,
  EcdsaHssExportShareRequest,
  EcdsaHssPublicIdentity,
  EcdsaHssRoleLocalKeyRecord,
} from '../types';

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
  if (
    toOptionalString(value.version) !== ECDSA_HSS_ROLE_LOCAL_FIRST_BOOTSTRAP_ROOT_PROOF_VERSION
  ) {
    return null;
  }
  const digest32B64u = parseB64uFixed(value.digest32B64u, 32);
  const signature65B64u = parseB64uFixed(value.signature65B64u, 65);
  if (!digest32B64u || !signature65B64u) return null;
  return {
    version: ECDSA_HSS_ROLE_LOCAL_FIRST_BOOTSTRAP_ROOT_PROOF_VERSION,
    digest32B64u,
    signature65B64u,
  };
}

function parseEcdsaHssPasskeyFirstBootstrapAuthorization(
  value: unknown,
): EcdsaHssPasskeyFirstBootstrapAuthorization | null {
  if (!isObject(value)) return null;
  if (toOptionalString(value.kind) !== 'passkey_first_bootstrap') return null;
  if (!isObject(value.webauthn_authentication)) return null;
  let runtimePolicyScope: RuntimePolicyScope | undefined;
  if (value.runtimePolicyScope !== undefined) {
    try {
      runtimePolicyScope = normalizeRuntimePolicyScope(value.runtimePolicyScope);
    } catch {
      return null;
    }
  }
  const runtimeEnvironmentId = toOptionalString(value.runtimeEnvironmentId);
  return {
    kind: 'passkey_first_bootstrap',
    webauthn_authentication: value.webauthn_authentication as any,
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

export function toThresholdEd25519AuthPrefix(prefix: unknown): string {
  return toPrefixWithColon(prefix, 'w3a:threshold-ed25519:auth:');
}

export function toThresholdEd25519PrefixFromBase(
  basePrefix: unknown,
  kind: 'key' | 'sess' | 'auth',
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

export function toThresholdEcdsaAuthPrefix(prefix: unknown): string {
  return toPrefixWithColon(prefix, 'w3a:threshold-ecdsa:auth:');
}

export function toThresholdEcdsaSigningPrefix(prefix: unknown): string {
  return toPrefixWithColon(prefix, 'w3a:threshold-ecdsa:signing:');
}

export function toThresholdEcdsaPresignPrefix(prefix: unknown): string {
  return toPrefixWithColon(prefix, 'w3a:threshold-ecdsa:presign:');
}

export function toThresholdEcdsaPrefixFromBase(
  basePrefix: unknown,
  kind: 'key' | 'sess' | 'auth' | 'signing' | 'presign',
): string {
  const base = toOptionalString(basePrefix);
  if (!base) return '';
  const trimmed = base.trim();
  if (!trimmed) return '';
  const prefix = trimmed.endsWith(':') ? trimmed : `${trimmed}:`;
  return `${prefix}threshold-ecdsa:${kind}:`;
}

export type ParsedThresholdEd25519KeyRecord = {
  nearAccountId: string;
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
  const nearAccountId = toOptionalString(raw.nearAccountId);
  const rpId = toOptionalString(raw.rpId);
  const publicKey = toOptionalString(raw.publicKey);
  const relayerSigningShareB64u = toOptionalString(raw.relayerSigningShareB64u);
  const relayerVerifyingShareB64u = toOptionalString(raw.relayerVerifyingShareB64u);
  const keyVersion = toOptionalString(raw.keyVersion);
  const recoveryExportCapable = raw.recoveryExportCapable === true ? (true as const) : false;
  if (
    !nearAccountId ||
    !rpId ||
    !publicKey ||
    !relayerSigningShareB64u ||
    !relayerVerifyingShareB64u ||
    !keyVersion ||
    recoveryExportCapable !== true
  )
    return null;
  return {
    nearAccountId,
    rpId,
    publicKey,
    relayerSigningShareB64u,
    relayerVerifyingShareB64u,
    keyVersion,
    recoveryExportCapable: true,
  };
}

const ECDSA_HSS_BOOTSTRAP_FORBIDDEN_FIELDS = [
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
  const clientPublicKey33B64u = parseSec1CompressedPublicKey33B64u(raw.clientPublicKey33B64u);
  const relayerPublicKey33B64u = parseSec1CompressedPublicKey33B64u(raw.relayerPublicKey33B64u);
  const groupPublicKey33B64u = parseSec1CompressedPublicKey33B64u(raw.groupPublicKey33B64u);
  const ethereumAddress = toOptionalString(raw.ethereumAddress);
  if (!clientPublicKey33B64u || !relayerPublicKey33B64u || !groupPublicKey33B64u || !ethereumAddress) {
    return null;
  }
  return {
    clientPublicKey33B64u,
    relayerPublicKey33B64u,
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
  const walletSessionUserId = toOptionalString(raw.walletSessionUserId);
  const rpId = toOptionalString(raw.rpId);
  const subjectId = toOptionalString(raw.subjectId);
  const ecdsaThresholdKeyId = toOptionalString(raw.ecdsaThresholdKeyId);
  const signingRootId = toOptionalString(raw.signingRootId);
  const signingRootVersion = toOptionalString(raw.signingRootVersion);
  const relayerKeyId = toOptionalString(raw.relayerKeyId);
  const clientPublicKey33B64u = parseSec1CompressedPublicKey33B64u(raw.clientPublicKey33B64u);
  const contextBinding32B64u = parseB64uFixed(raw.contextBinding32B64u, 32);
  const requestId = toOptionalString(raw.requestId);
  const sessionId = toOptionalString(raw.sessionId);
  const walletSigningSessionId = toOptionalString(raw.walletSigningSessionId);
  const clientShareRetryCounter = raw.clientShareRetryCounter;
  const ttlMs = raw.ttlMs;
  const remainingUses = raw.remainingUses;
  const participantIds = normalizeThresholdEd25519ParticipantIds(raw.participantIds);
  const clientRootProof =
    raw.clientRootProof === undefined ? null : parseEcdsaHssClientRootProof(raw.clientRootProof);
  const passkeyFirstBootstrapAuthorization =
    raw.passkeyFirstBootstrapAuthorization === undefined
      ? null
      : parseEcdsaHssPasskeyFirstBootstrapAuthorization(
          raw.passkeyFirstBootstrapAuthorization,
        );
  if (
    !walletSessionUserId ||
    !rpId ||
    !subjectId ||
    !ecdsaThresholdKeyId ||
    !signingRootId ||
    !signingRootVersion ||
    !relayerKeyId ||
    !clientPublicKey33B64u ||
    !contextBinding32B64u ||
    !requestId ||
    !sessionId ||
    !walletSigningSessionId ||
    !isNonNegativeInteger(clientShareRetryCounter) ||
    !isNonNegativeInteger(ttlMs) ||
    !isNonNegativeInteger(remainingUses) ||
    !participantIds ||
    (raw.clientRootProof !== undefined && !clientRootProof) ||
    (raw.passkeyFirstBootstrapAuthorization !== undefined &&
      !passkeyFirstBootstrapAuthorization) ||
    (raw.clientRootProof !== undefined && raw.passkeyFirstBootstrapAuthorization !== undefined)
  ) {
    return null;
  }
  const base = {
    formatVersion: 'ecdsa-hss-role-local' as const,
    walletSessionUserId,
    rpId,
    subjectId,
    ecdsaThresholdKeyId,
    signingRootId,
    signingRootVersion,
    keyScope: 'evm-family' as const,
    relayerKeyId,
    clientPublicKey33B64u,
    clientShareRetryCounter,
    contextBinding32B64u,
    requestId,
    sessionId,
    walletSigningSessionId,
    ttlMs,
    remainingUses,
    participantIds,
  };
  if (clientRootProof) return { ...base, clientRootProof };
  if (passkeyFirstBootstrapAuthorization) {
    return { ...base, passkeyFirstBootstrapAuthorization };
  }
  return base;
}

export function parseEcdsaHssExportShareRequest(
  raw: unknown,
): EcdsaHssExportShareRequest | null {
  if (!isObject(raw)) return null;
  if (hasForbiddenFields(raw, ECDSA_HSS_EXPORT_REQUEST_FORBIDDEN_FIELDS)) return null;
  if (toOptionalString(raw.formatVersion) !== 'ecdsa-hss-role-local-export') return null;
  const walletSessionUserId = toOptionalString(raw.walletSessionUserId);
  const rpId = toOptionalString(raw.rpId);
  const subjectId = toOptionalString(raw.subjectId);
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
    !walletSessionUserId ||
    !rpId ||
    !subjectId ||
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
    walletSessionUserId,
    rpId,
    subjectId,
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

export function parseEcdsaHssRoleLocalKeyRecord(
  raw: unknown,
): EcdsaHssRoleLocalKeyRecord | null {
  if (!isObject(raw)) return null;
  if (toOptionalString(raw.version) !== 'threshold_ecdsa_hss_role_local') return null;
  if (toOptionalString(raw.keyScope) !== 'evm-family') return null;
  const ecdsaThresholdKeyId = toOptionalString(raw.ecdsaThresholdKeyId);
  const keyHandle = toOptionalString(raw.keyHandle);
  const walletSessionUserId = toOptionalString(raw.walletSessionUserId);
  const rpId = toOptionalString(raw.rpId);
  const subjectId = toOptionalString(raw.subjectId);
  const signingRootId = toOptionalString(raw.signingRootId);
  const signingRootVersion = toOptionalString(raw.signingRootVersion);
  const relayerKeyId = toOptionalString(raw.relayerKeyId);
  const contextBinding32B64u = parseB64uFixed(raw.contextBinding32B64u, 32);
  const relayerShare32B64u = parseB64uFixed(raw.relayerShare32B64u, 32);
  const relayerPublicKey33B64u = parseSec1CompressedPublicKey33B64u(raw.relayerPublicKey33B64u);
  const clientPublicKey33B64u = parseSec1CompressedPublicKey33B64u(raw.clientPublicKey33B64u);
  const groupPublicKey33B64u = parseSec1CompressedPublicKey33B64u(raw.groupPublicKey33B64u);
  const ethereumAddress = toOptionalString(raw.ethereumAddress);
  const relayerCaitSithInput = isObject(raw.relayerCaitSithInput)
    ? raw.relayerCaitSithInput
    : null;
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
    !walletSessionUserId ||
    !rpId ||
    !subjectId ||
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
    version: 'threshold_ecdsa_hss_role_local',
    ecdsaThresholdKeyId,
    keyHandle,
    walletSessionUserId,
    rpId,
    subjectId,
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

export type ParsedEd25519AuthSessionRecord = {
  expiresAtMs: number;
  relayerKeyId: string;
  userId: string;
  rpId: string;
  participantIds: number[];
} & Partial<ParsedThresholdEcdsaSigningRootMetadata>;

export function parseEd25519AuthSessionRecord(raw: unknown): ParsedEd25519AuthSessionRecord | null {
  if (!isObject(raw)) return null;
  const expiresAtMs = raw.expiresAtMs;
  const relayerKeyId = toOptionalString(raw.relayerKeyId);
  const userId = toOptionalString(raw.userId);
  const rpId = toOptionalString(raw.rpId);
  const participantIds = normalizeThresholdEd25519ParticipantIds(raw.participantIds) || [
    ...THRESHOLD_ED25519_2P_PARTICIPANT_IDS,
  ];
  const signingRootMetadata = parseOptionalThresholdEcdsaSigningRootMetadataFields(raw);
  if (!signingRootMetadata.ok) return null;
  if (!isValidNumber(expiresAtMs)) return null;
  if (!relayerKeyId || !userId || !rpId) return null;
  return {
    expiresAtMs,
    relayerKeyId,
    userId,
    rpId,
    participantIds,
    ...(signingRootMetadata.value ? signingRootMetadata.value : {}),
  };
}

export type ParsedThresholdEcdsaSigningSessionRecord = {
  expiresAtMs: number;
  mpcSessionId: string;
  relayerKeyId: string;
  presignPoolKey: string;
  ecdsaThresholdKeyId: string;
  thresholdEcdsaPublicKeyB64u: string;
  signingDigestB64u: string;
  walletSessionUserId: string;
  rpId: string;
  clientVerifyingShareB64u: string;
  participantIds: number[];
  presignatureId: string;
  entropyB64u: string;
  bigRB64u?: string;
} & ParsedThresholdEcdsaSigningRootMetadata;

export function parseThresholdEcdsaSigningSessionRecord(
  raw: unknown,
): ParsedThresholdEcdsaSigningSessionRecord | null {
  if (!isObject(raw)) return null;
  const expiresAtMs = raw.expiresAtMs;
  const mpcSessionId = toOptionalString(raw.mpcSessionId);
  const relayerKeyId = toOptionalString(raw.relayerKeyId);
  const presignPoolKey = toOptionalString(raw.presignPoolKey);
  const ecdsaThresholdKeyId = toOptionalString(raw.ecdsaThresholdKeyId);
  const thresholdEcdsaPublicKeyB64u = toOptionalString(raw.thresholdEcdsaPublicKeyB64u);
  const signingDigestB64u = toOptionalString(raw.signingDigestB64u);
  const walletSessionUserId =
    toOptionalString(raw.walletSessionUserId) || toOptionalString(raw.userId);
  const rpId = toOptionalString(raw.rpId);
  const clientVerifyingShareB64u = toOptionalString(raw.clientVerifyingShareB64u);
  const participantIds = normalizeThresholdEd25519ParticipantIds(raw.participantIds) || [
    ...THRESHOLD_ED25519_2P_PARTICIPANT_IDS,
  ];
  const presignatureId = toOptionalString(raw.presignatureId);
  const entropyB64u = toOptionalString(raw.entropyB64u);
  const bigRB64u = toOptionalString(raw.bigRB64u);
  const signingRootMetadata = parseThresholdEcdsaSigningRootMetadataFields(raw);
  if (!isValidNumber(expiresAtMs)) return null;
  if (
    !mpcSessionId ||
    !relayerKeyId ||
    !presignPoolKey ||
    !ecdsaThresholdKeyId ||
    !thresholdEcdsaPublicKeyB64u ||
    !signingDigestB64u ||
    !walletSessionUserId ||
    !rpId ||
    !clientVerifyingShareB64u ||
    !presignatureId ||
    !entropyB64u ||
    !signingRootMetadata
  ) {
    return null;
  }
  return {
    expiresAtMs,
    mpcSessionId,
    relayerKeyId,
    presignPoolKey,
    ecdsaThresholdKeyId,
    thresholdEcdsaPublicKeyB64u,
    signingDigestB64u,
    walletSessionUserId,
    rpId,
    clientVerifyingShareB64u,
    participantIds,
    presignatureId,
    entropyB64u,
    ...signingRootMetadata,
    ...(bigRB64u ? { bigRB64u } : {}),
  };
}

export type ParsedThresholdEcdsaPresignatureRelayerShareRecord = {
  relayerKeyId: string;
  presignatureId: string;
  bigRB64u: string;
  kShareB64u: string;
  sigmaShareB64u: string;
  createdAtMs: number;
};

export type ParsedThresholdEcdsaPresignSessionStage =
  | 'triples'
  | 'triples_done'
  | 'presign'
  | 'done';

export type ParsedThresholdEcdsaPresignSessionRecord = {
  expiresAtMs: number;
  walletSessionUserId: string;
  rpId: string;
  relayerKeyId: string;
  presignPoolKey: string;
  ownerInstanceId?: string;
  participantIds: number[];
  clientParticipantId: number;
  relayerParticipantId: number;
  stage: ParsedThresholdEcdsaPresignSessionStage;
  version: number;
  createdAtMs: number;
  updatedAtMs: number;
} & ParsedThresholdEcdsaSigningRootMetadata;

export function parseThresholdEcdsaPresignSessionRecord(
  raw: unknown,
): ParsedThresholdEcdsaPresignSessionRecord | null {
  if (!isObject(raw)) return null;
  const expiresAtMs = raw.expiresAtMs;
  const walletSessionUserId =
    toOptionalString(raw.walletSessionUserId) || toOptionalString(raw.userId);
  const rpId = toOptionalString(raw.rpId);
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

  const stage: ParsedThresholdEcdsaPresignSessionStage | null =
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
  if (
    !walletSessionUserId ||
    !rpId ||
    !relayerKeyId ||
    !presignPoolKey ||
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
    walletSessionUserId,
    rpId,
    relayerKeyId,
    presignPoolKey,
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

export function parseThresholdEcdsaPresignatureRelayerShareRecord(
  raw: unknown,
): ParsedThresholdEcdsaPresignatureRelayerShareRecord | null {
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

export type ThresholdEd25519SessionClaims = {
  /**
   * Standard JWT subject. For threshold-session tokens this must match walletId.
   * Route/business logic should use walletId so it never collides with app-session provider subjects.
   */
  sub: string;
  walletId: string;
  kind: 'threshold_ed25519_session_v1';
  sessionId: string;
  walletSigningSessionId: string;
  relayerKeyId: string;
  rpId: string;
  runtimePolicyScope?: RuntimePolicyScope;
  /**
   * Server-enforced threshold session expiry (ms since epoch).
   * Relayer authorization validates expiry without a KV record fetch.
   */
  thresholdExpiresAtMs: number;
  /**
   * Signer-set binding (sorted unique participant ids).
   * Relayer authorization validates signer set without a KV record fetch.
   */
  participantIds: number[];
  // Standard JWT time claims (seconds since epoch).
  iat?: number;
  exp?: number;
  nbf?: number;
};

function parseRuntimePolicyScope(raw: unknown): RuntimePolicyScope | null {
  try {
    return normalizeRuntimePolicyScope(raw as Record<string, unknown>);
  } catch {
    return null;
  }
}

export function parseThresholdEd25519SessionClaims(
  raw: unknown,
): ThresholdEd25519SessionClaims | null {
  if (!isObject(raw)) return null;
  const kind = toOptionalString(raw.kind);
  if (kind !== 'threshold_ed25519_session_v1') return null;
  const sub = toOptionalString(raw.sub);
  const walletId = toOptionalString((raw as { walletId?: unknown }).walletId);
  const sessionId = toOptionalString(raw.sessionId);
  const walletSigningSessionId = toOptionalString(
    (raw as { walletSigningSessionId?: unknown }).walletSigningSessionId,
  );
  const relayerKeyId = toOptionalString(raw.relayerKeyId);
  const rpId = toOptionalString(raw.rpId);
  if (
    !sub ||
    !walletId ||
    walletId !== sub ||
    !sessionId ||
    !walletSigningSessionId ||
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
  const out: ThresholdEd25519SessionClaims = {
    sub,
    walletId,
    kind,
    sessionId,
    walletSigningSessionId,
    relayerKeyId,
    rpId,
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

export type AppSessionClaims = {
  sub: string;
  kind: 'app_session_v1';
  appSessionVersion: string;
  walletId?: string;
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
  walletSessionUserId: unknown,
): string | undefined {
  if (!claims) return undefined;
  const subject = toOptionalString(claims.sub);
  const walletId = toOptionalString(walletSessionUserId);
  if (!subject || !walletId || subject === walletId) return undefined;
  return subject;
}

export function resolveAppSessionWalletIdForWalletScope(
  claims: AppSessionClaims | null | undefined,
  walletSessionUserId: unknown,
): string | undefined {
  if (!claims) return undefined;
  const explicitWalletId = toOptionalString(claims.walletId);
  if (explicitWalletId) return explicitWalletId;
  const subject = toOptionalString(claims.sub);
  const requestedWalletId = toOptionalString(walletSessionUserId);
  if (subject && requestedWalletId && subject === requestedWalletId) return subject;
  return undefined;
}

export type ThresholdEcdsaSessionClaims = {
  /**
   * Standard JWT subject. For threshold-session tokens this must match walletId.
   * Route/business logic should use walletId so it never collides with app-session provider subjects.
   */
  sub: string;
  walletId: string;
  kind: 'threshold_ecdsa_session_v1';
  sessionId: string;
  walletSigningSessionId: string;
  subjectId: string;
  chainTarget: ThresholdEcdsaChainTarget;
  keyHandle: string;
  relayerKeyId: string;
  rpId: string;
  runtimePolicyScope?: RuntimePolicyScope;
  /**
   * Server-enforced threshold session expiry (ms since epoch).
   * Authorization validates expiry without a KV record fetch.
   */
  thresholdExpiresAtMs: number;
  /**
   * Signer-set binding (sorted unique participant ids).
   * Authorization validates signer set without a KV record fetch.
   */
  participantIds: number[];
  // Standard JWT time claims (seconds since epoch).
  iat?: number;
  exp?: number;
  nbf?: number;
};

export function parseThresholdEcdsaSessionClaims(raw: unknown): ThresholdEcdsaSessionClaims | null {
  if (!isObject(raw)) return null;
  const kind = toOptionalString(raw.kind);
  if (kind !== 'threshold_ecdsa_session_v1') return null;
  const sub = toOptionalString(raw.sub);
  const walletId = toOptionalString((raw as { walletId?: unknown }).walletId);
  const sessionId = toOptionalString(raw.sessionId);
  const walletSigningSessionId = toOptionalString(
    (raw as { walletSigningSessionId?: unknown }).walletSigningSessionId,
  );
  const subjectId = toOptionalString((raw as { subjectId?: unknown }).subjectId);
  const chainTarget = thresholdEcdsaChainTargetFromValue(
    (raw as { chainTarget?: unknown }).chainTarget,
  );
  const keyHandle = toOptionalString((raw as { keyHandle?: unknown }).keyHandle);
  const relayerKeyId = toOptionalString(raw.relayerKeyId);
  const rpId = toOptionalString(raw.rpId);
  if (
    !sub ||
    !walletId ||
    walletId !== sub ||
    !sessionId ||
    !walletSigningSessionId ||
    !subjectId ||
    !chainTarget ||
    !keyHandle ||
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
  const out: ThresholdEcdsaSessionClaims = {
    sub,
    walletId,
    kind,
    sessionId,
    walletSigningSessionId,
    subjectId,
    chainTarget,
    keyHandle,
    relayerKeyId,
    rpId,
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

export type RegistrationContinuationClaims = {
  sub: string;
  walletId: string;
  kind: typeof REGISTRATION_CONTINUATION_JWT_KIND;
  rpId: string;
  subjectId: string;
  thresholdEcdsaChainTargets: ThresholdEcdsaChainTarget[];
  registrationExpiresAtMs: number;
  runtimePolicyScope?: RuntimePolicyScope;
  iat?: number;
  exp?: number;
  nbf?: number;
};

export function parseRegistrationContinuationClaims(
  raw: unknown,
): RegistrationContinuationClaims | null {
  if (!isObject(raw)) return null;
  const kind = toOptionalString(raw.kind);
  if (kind !== REGISTRATION_CONTINUATION_JWT_KIND) return null;
  const sub = toOptionalString(raw.sub);
  const walletId = toOptionalString((raw as { walletId?: unknown }).walletId);
  const rpId = toOptionalString(raw.rpId);
  const subjectId = toOptionalString((raw as { subjectId?: unknown }).subjectId);
  if (!sub || !walletId || walletId !== sub || !rpId || !subjectId) return null;
  const registrationExpiresAtMs = Number(
    (raw as { registrationExpiresAtMs?: unknown }).registrationExpiresAtMs,
  );
  if (!Number.isFinite(registrationExpiresAtMs) || registrationExpiresAtMs <= 0) return null;
  const rawTargets = (raw as { thresholdEcdsaChainTargets?: unknown }).thresholdEcdsaChainTargets;
  if (!Array.isArray(rawTargets) || rawTargets.length < 1) return null;
  const thresholdEcdsaChainTargets: ThresholdEcdsaChainTarget[] = [];
  const seen = new Set<string>();
  for (const rawTarget of rawTargets) {
    const target = thresholdEcdsaChainTargetFromValue(rawTarget);
    if (!target) return null;
    const key = thresholdEcdsaChainTargetKey(target);
    if (seen.has(key)) return null;
    seen.add(key);
    thresholdEcdsaChainTargets.push(target);
  }
  const out: RegistrationContinuationClaims = {
    sub,
    walletId,
    kind,
    rpId,
    subjectId,
    thresholdEcdsaChainTargets,
    registrationExpiresAtMs,
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

export function bytesEqual32(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== 32 || b.length !== 32) return false;
  for (let i = 0; i < 32; i++) {
    if (a[i] !== b[i]) return false;
  }
  return true;
}

export function toNearPublicKeyStr(v: unknown): string {
  return ensureEd25519Prefix(toOptionalString(v));
}

export function normalizeActionForIntentDigest(a: unknown): Record<string, unknown> {
  if (!isObject(a)) return { action_type: '' };
  const actionType = toOptionalString(a.action_type);
  switch (actionType) {
    case 'FunctionCall':
      return {
        action_type: actionType,
        args: toOptionalString(a.args),
        deposit: toOptionalString(a.deposit),
        gas: toOptionalString(a.gas),
        method_name: toOptionalString(a.method_name),
      };
    case 'Transfer':
      return { action_type: actionType, deposit: toOptionalString(a.deposit) };
    case 'Stake':
      return {
        action_type: actionType,
        stake: toOptionalString(a.stake),
        public_key: toOptionalString(a.public_key),
      };
    case 'AddKey':
      return {
        action_type: actionType,
        public_key: toOptionalString(a.public_key),
        access_key: toOptionalString(a.access_key),
      };
    case 'DeleteKey':
      return { action_type: actionType, public_key: toOptionalString(a.public_key) };
    case 'DeleteAccount':
      return { action_type: actionType, beneficiary_id: toOptionalString(a.beneficiary_id) };
    case 'DeployContract':
      return { action_type: actionType, code: Array.isArray(a.code) ? a.code : [] };
    case 'DeployGlobalContract':
      return {
        action_type: actionType,
        code: Array.isArray(a.code) ? a.code : [],
        deploy_mode: toOptionalString(a.deploy_mode),
      };
    case 'UseGlobalContract':
      return {
        action_type: actionType,
        account_id: toOptionalString(a.account_id) || undefined,
        code_hash: toOptionalString(a.code_hash) || undefined,
      };
    case 'CreateAccount':
    case 'SignedDelegate':
    default:
      return { action_type: actionType };
  }
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

type NearTxAuthorizeSigningPayload = {
  kind?: string;
  txSigningRequests: Array<{
    nearAccountId: string;
    receiverId: string;
    actions: unknown[];
  }>;
  transactionContext: {
    nearPublicKeyStr: string;
    nextNonce: string;
    txBlockHash: string;
    txBlockHeight?: string;
  };
};

type Nep461DelegateAuthorizeSigningPayload = {
  kind?: string;
  delegate: {
    senderId: string;
    receiverId: string;
    actions: unknown[];
    nonce: string;
    maxBlockHeight: string;
    publicKey: string;
  };
};

type Nep413AuthorizeSigningPayload = {
  kind?: string;
  nearAccountId: string;
  message: string;
  recipient: string;
  nonce: string;
  state?: string;
};

export async function verifyThresholdEd25519AuthorizeSigningPayload(input: {
  purpose: string;
  signingPayload: unknown;
  signingDigest32: Uint8Array;
  intentDigest32: Uint8Array;
  userId: string;
  ensureSignerWasm: () => Promise<void>;
  computeNearTxSigningDigests: (payload: unknown) => unknown;
  computeDelegateSigningDigest: (payload: unknown) => unknown;
  computeNep413SigningDigest: (payload: unknown) => unknown;
}): Promise<ThresholdValidationResult> {
  const purpose = input.purpose;
  const signingPayload = input.signingPayload;
  if (!isObject(signingPayload)) {
    return {
      ok: false,
      code: 'invalid_body',
      message: 'signingPayload (object) is required for threshold authorization',
    };
  }

  const kind = toOptionalString(signingPayload.kind);
  const expectedKind = purpose;
  if (kind && kind !== expectedKind) {
    return {
      ok: false,
      code: 'invalid_body',
      message: `signingPayload.kind must match purpose (${expectedKind})`,
    };
  }

  // 1) Recompute intent_digest_32 from signingPayload and compare to the authorized digest.
  let intentDigest32Computed: Uint8Array;
  try {
    if (purpose === 'near_tx') {
      const payload = signingPayload as Partial<NearTxAuthorizeSigningPayload>;
      const txs = payload.txSigningRequests;
      if (!Array.isArray(txs) || !txs.length)
        throw new Error('signingPayload.txSigningRequests is required');
      const nearAccountId = toOptionalString(txs[0]?.nearAccountId);
      if (!nearAccountId) throw new Error('txSigningRequests[0].nearAccountId is required');
      for (const tx of txs) {
        if (toOptionalString(tx?.nearAccountId) !== nearAccountId) {
          throw new Error('All txSigningRequests[].nearAccountId must match');
        }
      }
      if (nearAccountId !== input.userId)
        throw new Error('txSigningRequests[].nearAccountId must match session user');
      const txInputs = txs.map((tx) => ({
        receiverId: toOptionalString(tx?.receiverId),
        actions: Array.isArray(tx?.actions)
          ? tx.actions.map((a) => normalizeActionForIntentDigest(a))
          : [],
      }));
      const json = alphabetizeStringify(txInputs);
      intentDigest32Computed = await sha256BytesUtf8(json);
    } else if (purpose === 'nep461_delegate') {
      const payload = signingPayload as Partial<Nep461DelegateAuthorizeSigningPayload>;
      const d = payload.delegate;
      if (!isObject(d)) throw new Error('signingPayload.delegate is required');
      const senderId = toOptionalString(d.senderId);
      if (!senderId) throw new Error('delegate.senderId is required');
      if (senderId !== input.userId) throw new Error('delegate.senderId must match session user');
      const txInputs = [
        {
          receiverId: toOptionalString(d.receiverId),
          actions: Array.isArray(d.actions)
            ? d.actions.map((a) => normalizeActionForIntentDigest(a))
            : [],
        },
      ];
      const json = alphabetizeStringify(txInputs);
      intentDigest32Computed = await sha256BytesUtf8(json);
    } else if (purpose === 'nep413') {
      const payload = signingPayload as Partial<Nep413AuthorizeSigningPayload>;
      const nearAccountId = toOptionalString(payload.nearAccountId);
      if (!nearAccountId) throw new Error('signingPayload.nearAccountId is required');
      if (nearAccountId !== input.userId)
        throw new Error('signingPayload.nearAccountId must match session user');
      const recipient = toOptionalString(payload.recipient);
      const message = toOptionalString(payload.message);
      const json = alphabetizeStringify({ kind: 'nep413', nearAccountId, recipient, message });
      intentDigest32Computed = await sha256BytesUtf8(json);
    } else {
      throw new Error(`Unsupported purpose: ${purpose}`);
    }
  } catch (e: unknown) {
    const msg = String(
      e && typeof e === 'object' && 'message' in e
        ? (e as { message?: unknown }).message
        : e || 'Failed to recompute intent digest',
    );
    return { ok: false, code: 'invalid_body', message: msg };
  }

  if (intentDigest32Computed.length !== 32) {
    return {
      ok: false,
      code: 'internal',
      message: `Computed intent digest is not 32 bytes (got ${intentDigest32Computed.length})`,
    };
  }
  if (!bytesEqual32(intentDigest32Computed, input.intentDigest32)) {
    return {
      ok: false,
      code: 'intent_digest_mismatch',
      message: 'signingPayload does not match authorized intentDigest32',
    };
  }

  // 2) Recompute signing_digest_32 from signingPayload and compare to requested signing digest.
  let signingDigest32Computed: Uint8Array[];
  try {
    await input.ensureSignerWasm();
    signingDigest32Computed = (() => {
      if (purpose === 'near_tx') {
        const digestsUnknown: unknown = input.computeNearTxSigningDigests(signingPayload);
        if (!Array.isArray(digestsUnknown)) throw new Error('near_tx digest recomputation failed');
        return digestsUnknown.map((d, i) => {
          const bytes = normalizeByteArray32(d);
          if (!bytes) throw new Error(`near_tx digest[${i}] is not 32 bytes`);
          return bytes;
        });
      }
      if (purpose === 'nep461_delegate') {
        const digestUnknown: unknown = input.computeDelegateSigningDigest(signingPayload);
        const bytes = normalizeByteArray32(digestUnknown);
        if (!bytes) throw new Error('nep461_delegate digest is not 32 bytes');
        return [bytes];
      }
      if (purpose === 'nep413') {
        const digestUnknown: unknown = input.computeNep413SigningDigest(signingPayload);
        const bytes = normalizeByteArray32(digestUnknown);
        if (!bytes) throw new Error('nep413 digest is not 32 bytes');
        return [bytes];
      }
      throw new Error(`Unsupported purpose: ${purpose}`);
    })();
  } catch (e: unknown) {
    const msg = String(
      e && typeof e === 'object' && 'message' in e
        ? (e as { message?: unknown }).message
        : e || 'Failed to recompute signing digest',
    );
    return { ok: false, code: 'invalid_body', message: msg };
  }

  const match = signingDigest32Computed.some((d) => bytesEqual32(d, input.signingDigest32));
  if (!match) {
    return {
      ok: false,
      code: 'signing_digest_mismatch',
      message: 'signingPayload does not match signing_digest_32',
    };
  }

  return { ok: true };
}

export type ThresholdAuthorizeSigningDigestOnlyOk = { ok: true; intentDigest32: Uint8Array };
export type ThresholdAuthorizeSigningDigestOnlyResult =
  | ThresholdAuthorizeSigningDigestOnlyOk
  | ThresholdValidationErr;

export async function verifyThresholdEd25519AuthorizeSigningPayloadSigningDigestOnly(input: {
  purpose: string;
  signingPayload: unknown;
  signingDigest32: Uint8Array;
  userId: string;
  ensureSignerWasm: () => Promise<void>;
  computeNearTxSigningDigests: (payload: unknown) => unknown;
  computeDelegateSigningDigest: (payload: unknown) => unknown;
  computeNep413SigningDigest: (payload: unknown) => unknown;
}): Promise<ThresholdAuthorizeSigningDigestOnlyResult> {
  const purpose = input.purpose;
  const signingPayload = input.signingPayload;
  if (!isObject(signingPayload)) {
    return {
      ok: false,
      code: 'invalid_body',
      message: 'signingPayload (object) is required for threshold authorization',
    };
  }

  const kind = toOptionalString(signingPayload.kind);
  const expectedKind = purpose;
  if (kind && kind !== expectedKind) {
    return {
      ok: false,
      code: 'invalid_body',
      message: `signingPayload.kind must match purpose (${expectedKind})`,
    };
  }

  // 1) Recompute intent_digest_32 from signingPayload (not contract-bound in session mode).
  let intentDigest32Computed: Uint8Array;
  try {
    if (purpose === 'near_tx') {
      const payload = signingPayload as Partial<NearTxAuthorizeSigningPayload>;
      const txs = payload.txSigningRequests;
      if (!Array.isArray(txs) || !txs.length)
        throw new Error('signingPayload.txSigningRequests is required');
      const nearAccountId = toOptionalString(txs[0]?.nearAccountId);
      if (!nearAccountId) throw new Error('txSigningRequests[0].nearAccountId is required');
      for (const tx of txs) {
        if (toOptionalString(tx?.nearAccountId) !== nearAccountId) {
          throw new Error('All txSigningRequests[].nearAccountId must match');
        }
      }
      if (nearAccountId !== input.userId)
        throw new Error('txSigningRequests[].nearAccountId must match session user');
      const txInputs = txs.map((tx) => ({
        receiverId: toOptionalString(tx?.receiverId),
        actions: Array.isArray(tx?.actions)
          ? tx.actions.map((a) => normalizeActionForIntentDigest(a))
          : [],
      }));
      const json = alphabetizeStringify(txInputs);
      intentDigest32Computed = await sha256BytesUtf8(json);
    } else if (purpose === 'nep461_delegate') {
      const payload = signingPayload as Partial<Nep461DelegateAuthorizeSigningPayload>;
      const d = payload.delegate;
      if (!isObject(d)) throw new Error('signingPayload.delegate is required');
      const senderId = toOptionalString(d.senderId);
      if (!senderId) throw new Error('delegate.senderId is required');
      if (senderId !== input.userId) throw new Error('delegate.senderId must match session user');
      const txInputs = [
        {
          receiverId: toOptionalString(d.receiverId),
          actions: Array.isArray(d.actions)
            ? d.actions.map((a) => normalizeActionForIntentDigest(a))
            : [],
        },
      ];
      const json = alphabetizeStringify(txInputs);
      intentDigest32Computed = await sha256BytesUtf8(json);
    } else if (purpose === 'nep413') {
      const payload = signingPayload as Partial<Nep413AuthorizeSigningPayload>;
      const nearAccountId = toOptionalString(payload.nearAccountId);
      if (!nearAccountId) throw new Error('signingPayload.nearAccountId is required');
      if (nearAccountId !== input.userId)
        throw new Error('signingPayload.nearAccountId must match session user');
      const recipient = toOptionalString(payload.recipient);
      const message = toOptionalString(payload.message);
      const json = alphabetizeStringify({ kind: 'nep413', nearAccountId, recipient, message });
      intentDigest32Computed = await sha256BytesUtf8(json);
    } else {
      throw new Error(`Unsupported purpose: ${purpose}`);
    }
  } catch (e: unknown) {
    const msg = String(
      e && typeof e === 'object' && 'message' in e
        ? (e as { message?: unknown }).message
        : e || 'Failed to recompute intent digest',
    );
    return { ok: false, code: 'invalid_body', message: msg };
  }

  if (intentDigest32Computed.length !== 32) {
    return {
      ok: false,
      code: 'internal',
      message: `Computed intent digest is not 32 bytes (got ${intentDigest32Computed.length})`,
    };
  }

  // 2) Recompute signing_digest_32 from signingPayload and compare to requested signing digest.
  let signingDigest32Computed: Uint8Array[];
  try {
    await input.ensureSignerWasm();
    signingDigest32Computed = (() => {
      if (purpose === 'near_tx') {
        const digestsUnknown: unknown = input.computeNearTxSigningDigests(signingPayload);
        if (!Array.isArray(digestsUnknown)) throw new Error('near_tx digest recomputation failed');
        return digestsUnknown.map((d, i) => {
          const bytes = normalizeByteArray32(d);
          if (!bytes) throw new Error(`near_tx digest[${i}] is not 32 bytes`);
          return bytes;
        });
      }
      if (purpose === 'nep461_delegate') {
        const digestUnknown: unknown = input.computeDelegateSigningDigest(signingPayload);
        const bytes = normalizeByteArray32(digestUnknown);
        if (!bytes) throw new Error('nep461_delegate digest is not 32 bytes');
        return [bytes];
      }
      if (purpose === 'nep413') {
        const digestUnknown: unknown = input.computeNep413SigningDigest(signingPayload);
        const bytes = normalizeByteArray32(digestUnknown);
        if (!bytes) throw new Error('nep413 digest is not 32 bytes');
        return [bytes];
      }
      throw new Error(`Unsupported purpose: ${purpose}`);
    })();
  } catch (e: unknown) {
    const msg = String(
      e && typeof e === 'object' && 'message' in e
        ? (e as { message?: unknown }).message
        : e || 'Failed to recompute signing digest',
    );
    return { ok: false, code: 'invalid_body', message: msg };
  }

  const match = signingDigest32Computed.some((d) => bytesEqual32(d, input.signingDigest32));
  if (!match) {
    return {
      ok: false,
      code: 'signing_digest_mismatch',
      message: 'signingPayload does not match signing_digest_32',
    };
  }

  return { ok: true, intentDigest32: intentDigest32Computed };
}
