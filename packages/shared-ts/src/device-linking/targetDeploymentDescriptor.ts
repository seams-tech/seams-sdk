import {
  parseLaneOperationId,
  parseLaneShareEpoch,
  parseLinkedDeviceEnrollmentId,
  parseLinkedDeviceId,
  parseLinkDeviceSessionId,
  parseSigningLaneId,
  parseWalletKeyId,
  type LaneOperationId,
  type LaneShareEpoch,
  type LinkedDeviceId,
  type LinkedDeviceEnrollmentId,
  type LinkDeviceSessionId,
  type SigningLaneId,
  type WalletKeyId,
} from '../signing-lanes/ids';
import {
  parseMpcMaterialActivationId,
  parseWalletId,
  parseWebAuthnCredentialIdB64u,
  type MpcMaterialActivationId,
  type WalletId,
  type WebAuthnCredentialIdB64u,
} from '../utils/domainIds';
import { parseDigestB64u, type DigestB64u } from '../utils/canonicalPrimitives';
import { parseEd25519YaoSuiteId, type Ed25519YaoSuiteId } from '../signing-lanes/ids';
import { parseEcdsaTargetCapabilityBindingV1 } from '../signing-lanes/rotationParsers';
import type {
  EcdsaTargetCapabilityBindingV1,
  LaneTargetSigningWorkerV1,
} from '../signing-lanes/rotation';
import type { LaneHolderParticipantId } from '../signing-lanes/participants';
import {
  parseLaneHolderParticipantId,
  parseSigningWorkerParticipantRecordV1,
} from '../signing-lanes/participants';
import { alphabetizeStringify, sha256BytesUtf8 } from '../utils/digests';
import { base64UrlDecode, base64UrlEncode } from '../utils/base64';
import { hasWhitespaceOrControlCharacters } from '../utils/domainIds';

/** Canonical domain for the control-plane deployment descriptor payload. */
export const LINKED_DEVICE_TARGET_DEPLOYMENT_DESCRIPTOR_DOMAIN_V1 =
  'seams/linked-device/target-deployment-descriptor/v1' as const;

export type LinkedDeviceTargetDeploymentDescriptorId = string & {
  readonly __linkedDeviceTargetDeploymentDescriptorIdBrand: 'LinkedDeviceTargetDeploymentDescriptorId';
};

export type LinkedDeviceTargetDeploymentDescriptorSigningKeyId = string & {
  readonly __linkedDeviceTargetDeploymentDescriptorSigningKeyIdBrand: 'LinkedDeviceTargetDeploymentDescriptorSigningKeyId';
};

export type LinkedDeviceTargetDeploymentDescriptorSignatureB64u = string & {
  readonly __linkedDeviceTargetDeploymentDescriptorSignatureB64uBrand: 'LinkedDeviceTargetDeploymentDescriptorSignatureB64u';
};

type LinkedDeviceTargetDeploymentDescriptorRequestBaseV1 = {
  readonly kind: 'linked_device_target_deployment_descriptor_request_v1';
  readonly linkSessionId: LinkDeviceSessionId;
  readonly walletId: WalletId;
  readonly walletKeyId: WalletKeyId;
  readonly enrollmentId: LinkedDeviceEnrollmentId;
  readonly deviceId: LinkedDeviceId;
  readonly operationId: LaneOperationId;
  readonly childIndex: number;
  readonly targetLaneId: SigningLaneId;
  readonly targetLaneShareEpoch: LaneShareEpoch;
  readonly targetMaterialActivationId: MpcMaterialActivationId;
  readonly targetHolderParticipantId: LaneHolderParticipantId;
  readonly targetPreparationDigestB64u: DigestB64u;
  readonly registrationDigestB64u: DigestB64u;
  readonly credentialIdB64u: WebAuthnCredentialIdB64u;
};

export type LinkedDeviceTargetDeploymentDescriptorRequestV1 =
  | (LinkedDeviceTargetDeploymentDescriptorRequestBaseV1 & {
      readonly keyFamily: 'ed25519';
    })
  | (LinkedDeviceTargetDeploymentDescriptorRequestBaseV1 & {
      readonly keyFamily: 'ecdsa_secp256k1';
    });

type LinkedDeviceTargetDeploymentDescriptorCommonV1<
  TRequest extends LinkedDeviceTargetDeploymentDescriptorRequestV1,
> = {
  readonly kind: 'linked_device_target_deployment_descriptor_v1';
  readonly descriptorId: LinkedDeviceTargetDeploymentDescriptorId;
  readonly signingKeyId: LinkedDeviceTargetDeploymentDescriptorSigningKeyId;
  readonly request: TRequest;
  readonly targetHolderParticipantId: LaneHolderParticipantId;
  readonly targetSigningWorker: LaneTargetSigningWorkerV1;
  readonly issuedAtMs: number;
  readonly expiresAtMs: number;
};

export type LinkedDeviceTargetDeploymentDescriptorUnsignedV1 =
  | (LinkedDeviceTargetDeploymentDescriptorCommonV1<
      Extract<LinkedDeviceTargetDeploymentDescriptorRequestV1, { readonly keyFamily: 'ed25519' }>
    > & {
      readonly keyFamily: 'ed25519';
      readonly yaoSuiteId: Ed25519YaoSuiteId;
      readonly circuitDigestB64u: DigestB64u;
      readonly targetCapability?: never;
    })
  | (LinkedDeviceTargetDeploymentDescriptorCommonV1<
      Extract<
        LinkedDeviceTargetDeploymentDescriptorRequestV1,
        { readonly keyFamily: 'ecdsa_secp256k1' }
      >
    > & {
      readonly keyFamily: 'ecdsa_secp256k1';
      readonly targetCapability: EcdsaTargetCapabilityBindingV1;
      readonly yaoSuiteId?: never;
      readonly circuitDigestB64u?: never;
    });

export type LinkedDeviceTargetDeploymentDescriptorV1 =
  | (Extract<
      LinkedDeviceTargetDeploymentDescriptorUnsignedV1,
      { readonly keyFamily: 'ed25519' }
    > & {
      readonly descriptorDigestB64u: DigestB64u;
      readonly signatureB64u: LinkedDeviceTargetDeploymentDescriptorSignatureB64u;
    })
  | (Extract<
      LinkedDeviceTargetDeploymentDescriptorUnsignedV1,
      { readonly keyFamily: 'ecdsa_secp256k1' }
    > & {
      readonly descriptorDigestB64u: DigestB64u;
      readonly signatureB64u: LinkedDeviceTargetDeploymentDescriptorSignatureB64u;
    });

export type LinkedDeviceTargetDeploymentDescriptorDigestInputV1 =
  LinkedDeviceTargetDeploymentDescriptorUnsignedV1;

export type LinkedDeviceTargetDeploymentDescriptorSignerV1 = {
  readonly signingKeyId: LinkedDeviceTargetDeploymentDescriptorSigningKeyId;
  signTargetDeploymentDescriptorV1(input: {
    readonly encodedPayload: Uint8Array;
    readonly descriptorDigestB64u: DigestB64u;
    readonly request: LinkedDeviceTargetDeploymentDescriptorRequestV1;
  }): Promise<string>;
};

export type LinkedDeviceTargetDeploymentDescriptorVerifierV1 = {
  verifyTargetDeploymentDescriptorV1(input: {
    readonly descriptor: LinkedDeviceTargetDeploymentDescriptorV1;
    readonly encodedPayload: Uint8Array;
    readonly descriptorDigestB64u: DigestB64u;
  }): Promise<boolean>;
};

type UnknownRecord = Record<string, unknown>;

const REQUEST_FIELDS = [
  'kind',
  'linkSessionId',
  'walletId',
  'walletKeyId',
  'enrollmentId',
  'deviceId',
  'operationId',
  'childIndex',
  'keyFamily',
  'targetLaneId',
  'targetLaneShareEpoch',
  'targetMaterialActivationId',
  'targetHolderParticipantId',
  'targetPreparationDigestB64u',
  'registrationDigestB64u',
  'credentialIdB64u',
] as const;

const COMMON_FIELDS = [
  'kind',
  'descriptorId',
  'signingKeyId',
  'request',
  'keyFamily',
  'targetHolderParticipantId',
  'targetSigningWorker',
  'issuedAtMs',
  'expiresAtMs',
] as const;

const UNSIGNED_FIELDS = [
  ...COMMON_FIELDS,
  'yaoSuiteId',
  'circuitDigestB64u',
  'targetCapability',
] as const;
const SIGNED_FIELDS = [...UNSIGNED_FIELDS, 'descriptorDigestB64u', 'signatureB64u'] as const;

function requireRecord(raw: unknown, label: string): UnknownRecord {
  if (raw === null || typeof raw !== 'object' || Array.isArray(raw)) {
    throw new Error(`${label} must be an object`);
  }
  return raw as UnknownRecord;
}

function rejectUnknownFields(
  record: UnknownRecord,
  fields: readonly string[],
  label: string,
): void {
  const allowed = new Set(fields);
  for (const field of Object.keys(record)) {
    if (!allowed.has(field)) throw new Error(`${label}.${field} is not supported`);
  }
  for (const field of fields) {
    if (!(field in record)) throw new Error(`${label}.${field} is required`);
  }
}

function requireFields(record: UnknownRecord, fields: readonly string[], label: string): void {
  for (const field of fields) {
    if (!(field in record)) throw new Error(`${label}.${field} is required`);
  }
}

function rejectUnknownOnly(record: UnknownRecord, fields: readonly string[], label: string): void {
  const allowed = new Set(fields);
  for (const field of Object.keys(record)) {
    if (!allowed.has(field)) throw new Error(`${label}.${field} is not supported`);
  }
}

function parseNonEmptyString<T extends string>(raw: unknown, label: string): T {
  if (
    typeof raw !== 'string' ||
    raw.trim() !== raw ||
    raw.length === 0 ||
    hasWhitespaceOrControlCharacters(raw)
  ) {
    throw new Error(`${label} must be a non-empty canonical string`);
  }
  return raw as T;
}

function parseChildIndex(raw: unknown, label: string): number {
  if (!Number.isSafeInteger(raw) || Number(raw) < 0 || Number(raw) > 0xffffffff) {
    throw new Error(`${label} must be a non-negative u32`);
  }
  return Number(raw);
}

function parseTimestamp(raw: unknown, label: string): number {
  if (!Number.isSafeInteger(raw) || Number(raw) <= 0) {
    throw new Error(`${label} must be a positive safe integer`);
  }
  return Number(raw);
}

function parseFixedBase64Url<T extends string>(raw: unknown, bytes: number, label: string): T {
  if (typeof raw !== 'string' || !/^[A-Za-z0-9_-]+$/.test(raw)) {
    throw new Error(`${label} must be canonical base64url`);
  }
  let decoded: Uint8Array;
  try {
    decoded = base64UrlDecode(raw);
  } catch {
    throw new Error(`${label} must be canonical base64url`);
  }
  if (decoded.length !== bytes || base64UrlEncode(decoded) !== raw) {
    throw new Error(`${label} must be canonical base64url for ${bytes} bytes`);
  }
  return raw as T;
}

function parseDescriptorDigest(raw: unknown, label: string): DigestB64u {
  try {
    return parseDigestB64u(raw);
  } catch (error) {
    throw new Error(`${label} ${error instanceof Error ? error.message : 'is invalid'}`);
  }
}

function parseCredentialId(raw: unknown, label: string): WebAuthnCredentialIdB64u {
  const credentialId = parseResult(parseWebAuthnCredentialIdB64u(raw), label);
  if (!/^[A-Za-z0-9_-]+$/.test(credentialId)) {
    throw new Error(`${label} must be canonical base64url`);
  }
  let decoded: Uint8Array;
  try {
    decoded = base64UrlDecode(credentialId);
  } catch {
    throw new Error(`${label} must be canonical base64url`);
  }
  if (decoded.length === 0 || base64UrlEncode(decoded) !== credentialId) {
    throw new Error(`${label} must be canonical base64url`);
  }
  return credentialId;
}

function parseResult<T>(
  result:
    | { readonly ok: true; readonly value: T }
    | { readonly ok: false; readonly error: { readonly message: string } },
  label: string,
): T {
  if (!result.ok) throw new Error(`${label} ${result.error.message}`);
  return result.value;
}

function parseTargetSigningWorker(raw: unknown, label: string): LaneTargetSigningWorkerV1 {
  const record = requireRecord(raw, label);
  if ('kind' in record) throw new Error(`${label}.kind is not supported`);
  const parsed = parseSigningWorkerParticipantRecordV1(
    { kind: 'signing_worker_participant_v1', ...record },
    label,
  );
  return {
    participantId: parsed.participantId,
    participantBindingDigestB64u: parsed.participantBindingDigestB64u,
    recipientKeyId: parsed.recipientKeyId,
    hpkePublicKeyB64u: parsed.hpkePublicKeyB64u,
    hpkePublicKeyDigestB64u: parsed.hpkePublicKeyDigestB64u,
  };
}

function normalizeRequest(
  raw: unknown,
  label: string,
): LinkedDeviceTargetDeploymentDescriptorRequestV1 {
  const record = requireRecord(raw, label);
  rejectUnknownFields(record, REQUEST_FIELDS, label);
  if (record.kind !== 'linked_device_target_deployment_descriptor_request_v1') {
    throw new Error(`${label}.kind is invalid`);
  }
  const base = {
    kind: 'linked_device_target_deployment_descriptor_request_v1' as const,
    linkSessionId: parseResult(
      parseLinkDeviceSessionId(record.linkSessionId),
      `${label}.linkSessionId`,
    ),
    walletId: parseResult(parseWalletId(record.walletId), `${label}.walletId`),
    walletKeyId: parseResult(parseWalletKeyId(record.walletKeyId), `${label}.walletKeyId`),
    enrollmentId: parseResult(
      parseLinkedDeviceEnrollmentId(record.enrollmentId),
      `${label}.enrollmentId`,
    ),
    deviceId: parseResult(parseLinkedDeviceId(record.deviceId), `${label}.deviceId`),
    operationId: parseResult(parseLaneOperationId(record.operationId), `${label}.operationId`),
    childIndex: parseChildIndex(record.childIndex, `${label}.childIndex`),
    targetLaneId: parseResult(parseSigningLaneId(record.targetLaneId), `${label}.targetLaneId`),
    targetLaneShareEpoch: parseResult(
      parseLaneShareEpoch(record.targetLaneShareEpoch),
      `${label}.targetLaneShareEpoch`,
    ),
    targetMaterialActivationId: parseResult(
      parseMpcMaterialActivationId(record.targetMaterialActivationId),
      `${label}.targetMaterialActivationId`,
    ),
    targetHolderParticipantId: parseResult(
      parseLaneHolderParticipantId(record.targetHolderParticipantId),
      `${label}.targetHolderParticipantId`,
    ),
    targetPreparationDigestB64u: parseDescriptorDigest(
      record.targetPreparationDigestB64u,
      `${label}.targetPreparationDigestB64u`,
    ),
    registrationDigestB64u: parseDescriptorDigest(
      record.registrationDigestB64u,
      `${label}.registrationDigestB64u`,
    ),
    credentialIdB64u: parseCredentialId(record.credentialIdB64u, `${label}.credentialIdB64u`),
  };
  if (record.keyFamily === 'ed25519' || record.keyFamily === 'ecdsa_secp256k1') {
    return { ...base, keyFamily: record.keyFamily };
  }
  throw new Error(`${label}.keyFamily is invalid`);
}

function normalizeUnsigned(
  raw: unknown,
  label: string,
): LinkedDeviceTargetDeploymentDescriptorUnsignedV1 {
  const record = requireRecord(raw, label);
  rejectUnknownOnly(record, SIGNED_FIELDS, label);
  requireFields(record, COMMON_FIELDS, label);
  if (record.kind !== 'linked_device_target_deployment_descriptor_v1') {
    throw new Error(`${label}.kind is invalid`);
  }
  const request = normalizeRequest(record.request, `${label}.request`);
  const keyFamily = record.keyFamily;
  if (keyFamily !== request.keyFamily)
    throw new Error(`${label}.keyFamily must match request.keyFamily`);
  const common = {
    kind: 'linked_device_target_deployment_descriptor_v1' as const,
    descriptorId: parseNonEmptyString<LinkedDeviceTargetDeploymentDescriptorId>(
      record.descriptorId,
      `${label}.descriptorId`,
    ),
    signingKeyId: parseNonEmptyString<LinkedDeviceTargetDeploymentDescriptorSigningKeyId>(
      record.signingKeyId,
      `${label}.signingKeyId`,
    ),
    request,
    targetHolderParticipantId: parseResult(
      parseLaneHolderParticipantId(record.targetHolderParticipantId),
      `${label}.targetHolderParticipantId`,
    ),
    targetSigningWorker: parseTargetSigningWorker(
      record.targetSigningWorker,
      `${label}.targetSigningWorker`,
    ),
    issuedAtMs: parseTimestamp(record.issuedAtMs, `${label}.issuedAtMs`),
    expiresAtMs: parseTimestamp(record.expiresAtMs, `${label}.expiresAtMs`),
  };
  if (common.targetHolderParticipantId !== request.targetHolderParticipantId) {
    throw new Error(
      `${label}.targetHolderParticipantId must match request.targetHolderParticipantId`,
    );
  }
  if (common.expiresAtMs <= common.issuedAtMs)
    throw new Error(`${label}.expiresAtMs must be after issuedAtMs`);
  if (keyFamily === 'ed25519' && request.keyFamily === 'ed25519') {
    if (record.targetCapability !== undefined)
      throw new Error(`${label}.targetCapability is not supported for Ed25519`);
    if (record.yaoSuiteId === undefined || record.circuitDigestB64u === undefined) {
      throw new Error(`${label}.yaoSuiteId and circuitDigestB64u are required for Ed25519`);
    }
    return {
      ...common,
      keyFamily: 'ed25519',
      request,
      yaoSuiteId: parseResult(parseEd25519YaoSuiteId(record.yaoSuiteId), `${label}.yaoSuiteId`),
      circuitDigestB64u: parseDescriptorDigest(
        record.circuitDigestB64u,
        `${label}.circuitDigestB64u`,
      ),
    };
  }
  if (keyFamily !== 'ecdsa_secp256k1' || request.keyFamily !== 'ecdsa_secp256k1') {
    throw new Error(`${label}.keyFamily is invalid`);
  }
  if (record.yaoSuiteId !== undefined || record.circuitDigestB64u !== undefined) {
    throw new Error(`${label}.yaoSuiteId and circuitDigestB64u are not supported for ECDSA`);
  }
  return {
    ...common,
    keyFamily: 'ecdsa_secp256k1',
    request,
    targetCapability: parseEcdsaTargetCapabilityBindingV1(
      record.targetCapability,
      `${label}.targetCapability`,
    ),
  };
}

function unsignedPayload(value: LinkedDeviceTargetDeploymentDescriptorUnsignedV1): string {
  return `${LINKED_DEVICE_TARGET_DEPLOYMENT_DESCRIPTOR_DOMAIN_V1}\u0000${alphabetizeStringify(value)}`;
}

export function parseLinkedDeviceTargetDeploymentDescriptorRequestV1(
  raw: unknown,
  label = 'targetDeploymentDescriptorRequest',
): LinkedDeviceTargetDeploymentDescriptorRequestV1 {
  return normalizeRequest(raw, label);
}

export function parseLinkedDeviceTargetDeploymentDescriptorUnsignedV1(
  raw: unknown,
  label = 'targetDeploymentDescriptor',
): LinkedDeviceTargetDeploymentDescriptorUnsignedV1 {
  const record = requireRecord(raw, label);
  rejectUnknownOnly(record, UNSIGNED_FIELDS, label);
  return normalizeUnsigned(raw, label);
}

export function parseLinkedDeviceTargetDeploymentDescriptorV1(
  raw: unknown,
  label = 'targetDeploymentDescriptor',
): LinkedDeviceTargetDeploymentDescriptorV1 {
  const record = requireRecord(raw, label);
  rejectUnknownOnly(record, SIGNED_FIELDS, label);
  requireFields(record, [...COMMON_FIELDS, 'descriptorDigestB64u', 'signatureB64u'], label);
  const unsigned = normalizeUnsigned(record, label);
  return {
    ...unsigned,
    descriptorDigestB64u: parseDescriptorDigest(
      record.descriptorDigestB64u,
      `${label}.descriptorDigestB64u`,
    ),
    signatureB64u: parseFixedBase64Url<LinkedDeviceTargetDeploymentDescriptorSignatureB64u>(
      record.signatureB64u,
      64,
      `${label}.signatureB64u`,
    ),
  };
}

export function encodeLinkedDeviceTargetDeploymentDescriptorV1(
  value: LinkedDeviceTargetDeploymentDescriptorUnsignedV1,
): Uint8Array {
  const normalized = normalizeUnsigned(value, 'targetDeploymentDescriptor');
  return new TextEncoder().encode(unsignedPayload(normalized));
}

export async function computeLinkedDeviceTargetDeploymentDescriptorDigestV1(
  value: LinkedDeviceTargetDeploymentDescriptorUnsignedV1,
): Promise<DigestB64u> {
  return parseDigestB64u(
    base64UrlEncode(
      await sha256BytesUtf8(
        unsignedPayload(normalizeUnsigned(value, 'targetDeploymentDescriptor')),
      ),
    ),
  );
}

export function buildLinkedDeviceTargetDeploymentDescriptorRequestV1(
  input: LinkedDeviceTargetDeploymentDescriptorRequestV1,
): LinkedDeviceTargetDeploymentDescriptorRequestV1 {
  return normalizeRequest(input, 'targetDeploymentDescriptorRequest');
}

export async function buildLinkedDeviceTargetDeploymentDescriptorV1(
  input: LinkedDeviceTargetDeploymentDescriptorUnsignedV1 & {
    readonly signatureB64u: string;
  },
): Promise<LinkedDeviceTargetDeploymentDescriptorV1> {
  const unsigned = normalizeUnsigned(input, 'targetDeploymentDescriptor');
  const descriptorDigestB64u =
    await computeLinkedDeviceTargetDeploymentDescriptorDigestV1(unsigned);
  return {
    ...unsigned,
    descriptorDigestB64u,
    signatureB64u: parseFixedBase64Url<LinkedDeviceTargetDeploymentDescriptorSignatureB64u>(
      input.signatureB64u,
      64,
      'targetDeploymentDescriptor.signatureB64u',
    ),
  };
}
