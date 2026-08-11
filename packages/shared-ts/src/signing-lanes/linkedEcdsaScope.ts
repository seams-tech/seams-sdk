import type {
  DomainIdParseResult,
  MpcMaterialActivationRef,
  MpcMaterialActivationId,
  WalletId,
} from '../utils/domainIds';
import {
  parseLaneEnrollmentId,
  parseLaneOperationId,
  parseLaneShareEpoch,
  parseSigningLaneId,
  parseWalletKeyId,
  type LaneEnrollmentId,
  type LaneOperationId,
  type LaneShareEpoch,
  type SigningLaneId,
  type WalletKeyId,
} from './ids';
import {
  parseMpcMaterialActivationId,
  parseMpcMaterialActivationRef,
  parseWalletId,
} from '../utils/domainIds';
import { parseDigestB64u, type DigestB64u } from '../utils/canonicalPrimitives';
import {
  parseSecp256k1CompressedPublicKeyB64u,
  type Secp256k1CompressedPublicKeyB64u,
} from '../passkey-custody/primitives';
import {
  parseLaneHolderParticipantId,
  parseLaneParticipantBindingDigestB64u,
  parseSigningWorkerParticipantId,
  parseSigningWorkerRecipientKeyDigestB64u,
  parseSigningWorkerRecipientKeyId,
  type LaneHolderParticipantId,
  type LaneParticipantBindingDigestB64u,
  type SigningWorkerParticipantId,
  type SigningWorkerRecipientKeyDigestB64u,
  type SigningWorkerRecipientKeyId,
} from './participants';
import type { EcdsaTargetCapabilityBindingV1 } from './rotation';
import { parseEcdsaTargetCapabilityBindingV1 } from './rotationParsers';

const LINKED_ECDSA_SCOPE_FIELDS = [
  'kind',
  'keyFamily',
  'laneKind',
  'walletId',
  'walletKeyId',
  'enrollmentId',
  'operationId',
  'laneId',
  'laneShareEpoch',
  'revocationEpoch',
  'targetMaterialActivationId',
  'materialActivation',
  'targetCapability',
  'thresholdPublicKey33B64u',
  'evmAddress',
  'publicIdentityDigestB64u',
  'targetHolderPublicCommitmentB64u',
  'targetServerPublicCommitmentB64u',
  'holderParticipantId',
  'signingWorkerParticipantId',
  'holderParticipantBindingDigestB64u',
  'signingWorkerParticipantBindingDigestB64u',
  'holderRecipientKeyDigestB64u',
  'serverRecipientKeyDigestB64u',
  'signingWorkerRecipientKeyId',
  'transcriptHashB64u',
  'protocolCommitReceiptDigestB64u',
] as const;

type LinkedEcdsaScopeOwnerFieldsForbiddenV1 = {
  readonly signingRootId?: never;
  readonly signingRootVersion?: never;
  readonly context?: never;
  readonly publicIdentity?: never;
  readonly signingWorker?: never;
  readonly activationEpoch?: never;
  readonly keyHandle?: never;
  readonly relayerKeyId?: never;
  readonly participantIds?: never;
  readonly runtimePolicyScope?: never;
  readonly authorization?: never;
};

/**
 * Trusted public identity for a linked ECDSA lane.
 *
 * The scope intentionally models the activated lane rather than the owner
 * derivation root. Root metadata and owner public-identity bags are forbidden
 * at the type level and rejected by the exact parser at runtime.
 */
export type LinkedDeviceEcdsaNormalSigningScopeV1 = LinkedEcdsaScopeOwnerFieldsForbiddenV1 & {
  readonly kind: 'linked_device_ecdsa_normal_signing_scope_v1';
  readonly keyFamily: 'ecdsa_secp256k1';
  readonly laneKind: 'linked_device';
  readonly walletId: WalletId;
  readonly walletKeyId: WalletKeyId;
  readonly enrollmentId: LaneEnrollmentId;
  readonly operationId: LaneOperationId;
  readonly laneId: SigningLaneId;
  readonly laneShareEpoch: LaneShareEpoch;
  readonly revocationEpoch: number;
  readonly targetMaterialActivationId: MpcMaterialActivationId;
  readonly materialActivation: MpcMaterialActivationRef;
  readonly targetCapability: EcdsaTargetCapabilityBindingV1;
  readonly thresholdPublicKey33B64u: Secp256k1CompressedPublicKeyB64u;
  readonly evmAddress: string;
  readonly publicIdentityDigestB64u: DigestB64u;
  readonly targetHolderPublicCommitmentB64u: Secp256k1CompressedPublicKeyB64u;
  readonly targetServerPublicCommitmentB64u: Secp256k1CompressedPublicKeyB64u;
  readonly holderParticipantId: LaneHolderParticipantId;
  readonly signingWorkerParticipantId: SigningWorkerParticipantId;
  readonly holderParticipantBindingDigestB64u: LaneParticipantBindingDigestB64u;
  readonly signingWorkerParticipantBindingDigestB64u: LaneParticipantBindingDigestB64u;
  readonly holderRecipientKeyDigestB64u: SigningWorkerRecipientKeyDigestB64u;
  readonly serverRecipientKeyDigestB64u: SigningWorkerRecipientKeyDigestB64u;
  readonly signingWorkerRecipientKeyId: SigningWorkerRecipientKeyId;
  readonly transcriptHashB64u: DigestB64u;
  readonly protocolCommitReceiptDigestB64u: DigestB64u;
};

export type LinkedDeviceEcdsaNormalSigningScopeInputV1 = Omit<
  LinkedDeviceEcdsaNormalSigningScopeV1,
  'kind' | 'keyFamily' | 'laneKind'
>;

export function buildLinkedDeviceEcdsaNormalSigningScopeV1(
  input: LinkedDeviceEcdsaNormalSigningScopeInputV1,
): LinkedDeviceEcdsaNormalSigningScopeV1 {
  const scope = {
    kind: 'linked_device_ecdsa_normal_signing_scope_v1' as const,
    keyFamily: 'ecdsa_secp256k1' as const,
    laneKind: 'linked_device' as const,
    walletId: input.walletId,
    walletKeyId: input.walletKeyId,
    enrollmentId: input.enrollmentId,
    operationId: input.operationId,
    laneId: input.laneId,
    laneShareEpoch: input.laneShareEpoch,
    revocationEpoch: input.revocationEpoch,
    targetMaterialActivationId: input.targetMaterialActivationId,
    materialActivation: input.materialActivation,
    targetCapability: input.targetCapability,
    thresholdPublicKey33B64u: input.thresholdPublicKey33B64u,
    evmAddress: input.evmAddress,
    publicIdentityDigestB64u: input.publicIdentityDigestB64u,
    targetHolderPublicCommitmentB64u: input.targetHolderPublicCommitmentB64u,
    targetServerPublicCommitmentB64u: input.targetServerPublicCommitmentB64u,
    holderParticipantId: input.holderParticipantId,
    signingWorkerParticipantId: input.signingWorkerParticipantId,
    holderParticipantBindingDigestB64u: input.holderParticipantBindingDigestB64u,
    signingWorkerParticipantBindingDigestB64u: input.signingWorkerParticipantBindingDigestB64u,
    holderRecipientKeyDigestB64u: input.holderRecipientKeyDigestB64u,
    serverRecipientKeyDigestB64u: input.serverRecipientKeyDigestB64u,
    signingWorkerRecipientKeyId: input.signingWorkerRecipientKeyId,
    transcriptHashB64u: input.transcriptHashB64u,
    protocolCommitReceiptDigestB64u: input.protocolCommitReceiptDigestB64u,
  } satisfies LinkedDeviceEcdsaNormalSigningScopeV1;
  validateLinkedDeviceEcdsaNormalSigningScopeV1(scope);
  return scope;
}

export function validateLinkedDeviceEcdsaNormalSigningScopeV1(
  scope: LinkedDeviceEcdsaNormalSigningScopeV1,
): void {
  if (scope.kind !== 'linked_device_ecdsa_normal_signing_scope_v1') {
    throw new Error('linked ECDSA scope kind is invalid');
  }
  if (scope.keyFamily !== 'ecdsa_secp256k1' || scope.laneKind !== 'linked_device') {
    throw new Error('linked ECDSA scope discriminator is invalid');
  }
  if (scope.materialActivation.activationId !== scope.targetMaterialActivationId) {
    throw new Error('linked ECDSA scope activation id does not match material activation');
  }
  if (!Number.isSafeInteger(scope.revocationEpoch) || scope.revocationEpoch < 0) {
    throw new Error('linked ECDSA scope revocation epoch is invalid');
  }
  if (!/^0x[0-9a-fA-F]{40}$/.test(scope.evmAddress)) {
    throw new Error('linked ECDSA scope EVM address is invalid');
  }
  requireVisibleText(scope.holderParticipantId, 'holderParticipantId');
  requireVisibleText(scope.signingWorkerParticipantId, 'signingWorkerParticipantId');
}

export function parseLinkedDeviceEcdsaNormalSigningScopeV1(
  value: unknown,
  label = 'LinkedDeviceEcdsaNormalSigningScopeV1',
): LinkedDeviceEcdsaNormalSigningScopeV1 {
  const record = exactRecord(value, LINKED_ECDSA_SCOPE_FIELDS, label);
  if (record.kind !== 'linked_device_ecdsa_normal_signing_scope_v1') {
    throw new Error(`${label}.kind is invalid`);
  }
  if (record.keyFamily !== 'ecdsa_secp256k1' || record.laneKind !== 'linked_device') {
    throw new Error(`${label} discriminator is invalid`);
  }
  return buildLinkedDeviceEcdsaNormalSigningScopeV1({
    walletId: parseDomain(parseWalletId(record.walletId), `${label}.walletId`),
    walletKeyId: parseDomain(parseWalletKeyId(record.walletKeyId), `${label}.walletKeyId`),
    enrollmentId: parseDomain(parseLaneEnrollmentId(record.enrollmentId), `${label}.enrollmentId`),
    operationId: parseDomain(parseLaneOperationId(record.operationId), `${label}.operationId`),
    laneId: parseDomain(parseSigningLaneId(record.laneId), `${label}.laneId`),
    laneShareEpoch: parseDomain(
      parseLaneShareEpoch(record.laneShareEpoch),
      `${label}.laneShareEpoch`,
    ),
    revocationEpoch: parseEpoch(record.revocationEpoch, `${label}.revocationEpoch`),
    targetMaterialActivationId: parseDomain(
      parseMpcMaterialActivationId(record.targetMaterialActivationId),
      `${label}.targetMaterialActivationId`,
    ),
    materialActivation: parseDomain(
      parseMpcMaterialActivationRef(record.materialActivation),
      `${label}.materialActivation`,
    ),
    targetCapability: parseEcdsaTargetCapabilityBindingV1(
      record.targetCapability,
      `${label}.targetCapability`,
    ),
    thresholdPublicKey33B64u: parseSecp256k1CompressedPublicKeyB64u(
      record.thresholdPublicKey33B64u,
    ),
    evmAddress: parseEvmAddress(record.evmAddress, `${label}.evmAddress`),
    publicIdentityDigestB64u: parseDigestB64u(record.publicIdentityDigestB64u),
    targetHolderPublicCommitmentB64u: parseSecp256k1CompressedPublicKeyB64u(
      record.targetHolderPublicCommitmentB64u,
    ),
    targetServerPublicCommitmentB64u: parseSecp256k1CompressedPublicKeyB64u(
      record.targetServerPublicCommitmentB64u,
    ),
    holderParticipantId: parseDomain(
      parseLaneHolderParticipantId(record.holderParticipantId),
      `${label}.holderParticipantId`,
    ),
    signingWorkerParticipantId: parseDomain(
      parseSigningWorkerParticipantId(record.signingWorkerParticipantId),
      `${label}.signingWorkerParticipantId`,
    ),
    holderParticipantBindingDigestB64u: parseDomain(
      parseLaneParticipantBindingDigestB64u(record.holderParticipantBindingDigestB64u),
      `${label}.holderParticipantBindingDigestB64u`,
    ),
    signingWorkerParticipantBindingDigestB64u: parseDomain(
      parseLaneParticipantBindingDigestB64u(record.signingWorkerParticipantBindingDigestB64u),
      `${label}.signingWorkerParticipantBindingDigestB64u`,
    ),
    holderRecipientKeyDigestB64u: parseDomain(
      parseSigningWorkerRecipientKeyDigestB64u(record.holderRecipientKeyDigestB64u),
      `${label}.holderRecipientKeyDigestB64u`,
    ),
    serverRecipientKeyDigestB64u: parseDomain(
      parseSigningWorkerRecipientKeyDigestB64u(record.serverRecipientKeyDigestB64u),
      `${label}.serverRecipientKeyDigestB64u`,
    ),
    signingWorkerRecipientKeyId: parseDomain(
      parseSigningWorkerRecipientKeyId(record.signingWorkerRecipientKeyId),
      `${label}.signingWorkerRecipientKeyId`,
    ),
    transcriptHashB64u: parseDigestB64u(record.transcriptHashB64u),
    protocolCommitReceiptDigestB64u: parseDigestB64u(record.protocolCommitReceiptDigestB64u),
  });
}

function exactRecord(
  value: unknown,
  fields: readonly string[],
  label: string,
): Record<string, unknown> {
  if (!isRecord(value)) {
    throw new Error(`${label} must be an object`);
  }
  const actual = Object.keys(value);
  if (actual.length !== fields.length || actual.some((field) => !fields.includes(field))) {
    throw new Error(`${label} fields are invalid`);
  }
  return value;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

function parseDomain<T>(result: DomainIdParseResult<T>, label: string): T {
  if (!result.ok) throw new Error(`${label}: ${result.error.message}`);
  return result.value;
}

function parseEpoch(value: unknown, label: string): number {
  if (!Number.isSafeInteger(value) || Number(value) < 0) {
    throw new Error(`${label} must be a non-negative safe integer`);
  }
  return Number(value);
}

function parseEvmAddress(value: unknown, label: string): string {
  if (typeof value !== 'string' || !/^0x[0-9a-fA-F]{40}$/.test(value)) {
    throw new Error(`${label} must be a 20-byte hexadecimal EVM address`);
  }
  return value;
}

function requireVisibleText(value: string, label: string): void {
  if (!value || [...value].some((character) => /\s|[\u0000-\u001f\u007f]/u.test(character))) {
    throw new Error(`${label} must contain visible non-whitespace text`);
  }
}
