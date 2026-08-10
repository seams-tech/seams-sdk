import {
  parseAuthorizedOperationId,
  type AuthorizedOperationId,
} from '../authorization/capabilityKinds';
import {
  parseEcdsaCapabilityManifestId,
  parseEcdsaCapabilityManifestRevision,
  parseEcdsaLifecycleId,
  parseEcdsaServerGeneration,
  type EcdsaCapabilityManifestId,
  type EcdsaCapabilityManifestRevision,
  type EcdsaServerGeneration,
} from '../utils/ecdsaCapabilityActivation';
import {
  hasWhitespaceOrControlCharacters,
  parseCapabilityInstanceRef,
  parseLaneShareEpoch,
  parseLinkedDeviceId,
  parseMpcKeyBindingRef,
  parseMpcLifecycleBindingRef,
  parseMpcMaterialActivationId,
  parseMpcMaterialActivationRef,
  parseMpcMaterialOwnerRef,
  parseMpcSigningWorkerRef,
  parseSigningLaneId,
  parseThresholdEcdsaSessionId,
  parseWalletId,
  parseWalletKeyId,
  type DomainIdParseResult,
  type MpcMaterialActivationRef,
  type MpcMaterialActivationId,
  type WalletId,
  type WalletKeyId,
} from '../utils/domainIds';
import {
  parseCorrelationId,
  parseDigestB64u,
  parseIsoTimestamp,
  type IsoTimestamp,
} from '../utils/canonicalPrimitives';
import {
  parseEd25519PublicKeyB64u,
  parseKeyCreationSignerSlot,
  parseSecp256k1CompressedPublicKeyB64u,
  rejectUnknownFields,
  requireRecord,
} from '../passkey-custody/primitives';
import { parseNearEd25519SigningKeyId } from '../utils/registrationIntent';
import { parseSdkEcdsaDerivationThresholdKeyId } from '../threshold/ecdsaDerivationRoleLocalBootstrap';
import {
  parseEvmFamilySigningKeySlotId,
  type EvmFamilySigningKeySlotId,
} from './evmFamilySigningKeySlotId';
import {
  parseHpkePublicKeyB64u,
  parseLaneCustodyBindingDigestB64u,
  parseLaneHolderCustodyBindingId,
  parseLaneHolderParticipantRecordV1,
  parseLaneHolderParticipantId,
  parseLaneParticipantBindingDigestB64u,
  parseSigningWorkerParticipantRecordV1,
  parseSigningWorkerParticipantId,
  parseSigningWorkerRecipientKeyDigestB64u,
  parseSigningWorkerRecipientKeyId,
  type HpkePublicKeyB64u,
  type LaneHolderCustodyBindingId,
  type LaneHolderParticipantId,
  type LaneParticipantBindingDigestB64u,
  type SigningWorkerParticipantId,
  type SigningWorkerRecipientKeyId,
} from './participants';
import {
  parseLaneShareEpoch as parseLaneShareEpochFromIds,
  parseLaneEnrollmentId as parseLaneEnrollmentIdFromIds,
  parseLaneOperationId as parseLaneOperationIdFromIds,
  parseLaneOperationIdempotencyKey as parseLaneOperationIdempotencyKeyFromIds,
  parseLinkedDeviceEnrollmentId as parseLinkedDeviceEnrollmentIdFromIds,
  parseEd25519YaoSuiteId,
  parseEcdsaRelayerKeyId,
  parseSigningLaneId as parseSigningLaneIdFromIds,
  parseWalletKeyId as parseWalletKeyIdFromIds,
  type EcdsaRelayerKeyId,
  type Ed25519YaoSuiteId,
  type LaneEnrollmentId,
  type LaneOperationId,
  type LaneOperationIdempotencyKey,
  type LinkedDeviceEnrollmentId,
  type SigningLaneId,
  type ThresholdEcdsaChainTarget,
  type LaneShareEpoch,
} from './ids';
import type { SigningLaneKind } from './records';
import type { NearEd25519SigningKeyId } from '../utils/registrationIntent';
import type { KeyCreationSignerSlot } from '../passkey-custody/primitives';
import type {
  ActiveLaneProtocolSourceV1,
  AggregateLaneActivationChildReceiptV1,
  AggregateLaneActivationReceiptV1,
  AggregateLaneRevocationChildReceiptV1,
  AggregateLaneRevocationReceiptV1,
  CommitLaneEnrollmentActivationV1,
  CommitLaneEnrollmentRevocationV1,
  CompleteSigningLaneRevocationV1,
  EcdsaAdditiveLaneCreationJobV1,
  EcdsaAdditiveLaneHolderRoundV1,
  EcdsaAdditiveLaneJobV1,
  EcdsaAdditiveLaneRefreshJobV1,
  EcdsaAdditiveLaneServerRoundV1,
  EcdsaAdditiveLaneTranscriptPreambleV1,
  EcdsaAdditiveLaneTranscriptV1,
  EcdsaServerRetirementReceiptV1,
  Ed25519ServerRetirementReceiptV1,
  EcdsaSourceCapabilityBindingV1,
  EcdsaTargetCapabilityBindingV1,
  EcdsaTargetThresholdSessionBindingV1,
  Ed25519YaoLaneCreationJobV1,
  Ed25519YaoLaneJobV1,
  Ed25519YaoLaneRefreshJobV1,
  LaneCreationTargetV1,
  LaneEnrollmentLifecycleV1,
  LaneEnrollmentManifestChildV1,
  LaneEnrollmentManifestV1,
  LaneHolderDeliveryReceiptV1,
  LaneHolderPackageWireV1,
  LaneOperationAuthorizationBindingV1,
  LaneProductEpochActiveV1,
  LaneProductEpochPendingVisibilityV1,
  LaneProductEpochRevocationPendingV1,
  LaneProductEpochRecordCommonV1,
  LaneProductEpochRecordV1,
  LaneProductEpochRetiredV1,
  LaneProductEpochRevokedV1,
  LaneProtocolCommitReceiptV1,
  LaneProtocolLifecycle,
  LaneProtocolRecordV1,
  LaneRefreshTargetV1,
  LaneRefreshPredecessorRetirementV1,
  LaneServerActivationReceiptV1,
  LaneServerRetirementReceiptV1,
  SigningWorkerLaneMaterialIdentityV1,
  RevokeLaneEnrollmentV1,
  RevokeSigningLaneV1,
  RotatableSigningLaneJobV1,
  OwnerLaneRefreshAuthorizationBindingV1,
  LinkedDeviceLaneAuthorizationBindingV1,
} from './rotation';
import type { DigestB64u } from '../utils/canonicalPrimitives';

type UnknownRecord = Record<string, unknown>;

function opaqueJson(raw: unknown, label: string): string {
  if (typeof raw !== 'string' || raw.length === 0) {
    throw new Error(`${label} must be a non-empty JSON string`);
  }
  try {
    const parsed: unknown = JSON.parse(raw);
    if (typeof parsed !== 'object' || parsed === null || Array.isArray(parsed)) {
      throw new Error('top-level value must be an object');
    }
  } catch (error) {
    throw new Error(
      `${label} must contain valid object JSON: ${error instanceof Error ? error.message : 'invalid JSON'}`,
    );
  }
  return raw;
}

const NON_EMPTY_FIELDS = {
  authorization: [
    'kind',
    'authorizedOperationId',
    'linkedDeviceEnrollmentId',
    'linkedDevicePermissionDigestB64u',
  ] as const,
  refreshAuthorization: ['kind', 'authorizedOperationId', 'ownerLaneRefreshDigestB64u'] as const,
  source: [
    'laneId',
    'laneKind',
    'laneShareEpoch',
    'revocationEpoch',
    'holderParticipantId',
    'signingWorkerParticipantId',
    'signingWorkerRecipientKeyId',
    'participantBindingDigestB64u',
    'materialActivation',
  ] as const,
  holder: [
    'participantId',
    'participantBindingDigestB64u',
    'custodyBindingId',
    'custodyBindingDigestB64u',
    'hpkePublicKeyB64u',
    'hpkePublicKeyDigestB64u',
  ] as const,
  worker: [
    'participantId',
    'participantBindingDigestB64u',
    'recipientKeyId',
    'hpkePublicKeyB64u',
    'hpkePublicKeyDigestB64u',
  ] as const,
};

function requiredField(record: UnknownRecord, field: string, label: string): unknown {
  if (!Object.prototype.hasOwnProperty.call(record, field) || record[field] === undefined) {
    throw new Error(`${label}.${field} is required`);
  }
  return record[field];
}

function exactRecord(raw: unknown, fields: readonly string[], label: string): UnknownRecord {
  const record = requireRecord(raw, label);
  rejectUnknownFields(record, fields, label);
  for (const field of fields) requiredField(record, field, label);
  return record;
}

function requiredString(raw: unknown, label: string): string {
  if (typeof raw !== 'string') throw new Error(`${label} must be a string`);
  const value = raw.trim();
  if (!value) throw new Error(`${label} is required`);
  if (hasWhitespaceOrControlCharacters(value)) {
    throw new Error(`${label} must not contain whitespace or control characters`);
  }
  return value;
}

function requiredInteger(raw: unknown, label: string, allowZero = true): number {
  if (!Number.isSafeInteger(raw) || Number(raw) < (allowZero ? 0 : 1)) {
    throw new Error(`${label} must be a ${allowZero ? 'non-negative' : 'positive'} safe integer`);
  }
  return Number(raw);
}

function resultValue<T>(result: DomainIdParseResult<T>, label: string): T {
  if (result.ok) return result.value;
  throw new Error(`${label} ${result.error.message}`);
}

function digest(raw: unknown, label: string): DigestB64u {
  try {
    return parseDigestB64u(raw);
  } catch (error) {
    throw new Error(`${label} ${error instanceof Error ? error.message : 'is invalid'}`);
  }
}

function parseIso(raw: unknown, label: string): IsoTimestamp {
  try {
    return parseIsoTimestamp(raw);
  } catch (error) {
    throw new Error(`${label} ${error instanceof Error ? error.message : 'is invalid'}`);
  }
}

function parseMpcActivation(raw: unknown, label: string): MpcMaterialActivationRef {
  return resultValue(parseMpcMaterialActivationRef(raw), label);
}

function nonEmptyTuple<T>(values: readonly T[], label: string): [T, ...T[]] {
  if (values.length === 0) throw new Error(`${label} must be non-empty`);
  const [first, ...rest] = values;
  return [first, ...rest];
}

function parseLaneOperationId(raw: unknown, label: string): LaneOperationId {
  return resultValue(parseLaneOperationIdFromIds(raw), label);
}

function parseEnrollmentId(raw: unknown, label: string): LaneEnrollmentId {
  return resultValue(parseLaneEnrollmentIdFromIds(raw), label);
}

function parseOperationIdempotencyKey(raw: unknown, label: string): LaneOperationIdempotencyKey {
  return resultValue(parseLaneOperationIdempotencyKeyFromIds(raw), label);
}

function parseLinkedDeviceEnrollmentIdValue(raw: unknown, label: string): LinkedDeviceEnrollmentId {
  return resultValue(parseLinkedDeviceEnrollmentIdFromIds(raw), label);
}

function parseLaneId(raw: unknown, label: string): SigningLaneId {
  return resultValue(parseSigningLaneIdFromIds(raw), label);
}

function parseShareEpoch(raw: unknown, label: string): LaneShareEpoch {
  return resultValue(parseLaneShareEpochFromIds(raw), label);
}

function parseKeyId(raw: unknown, label: string): WalletKeyId {
  return resultValue(parseWalletKeyIdFromIds(raw), label);
}

function parseLaneKind(raw: unknown, label: string): SigningLaneKind {
  switch (raw) {
    case 'owner_passkey':
    case 'owner_email_otp':
    case 'linked_device':
    case 'delegated_execution':
    case 'recovery':
    case 'break_glass':
      return raw;
    default:
      throw new Error(`${label} must be a known signing lane kind`);
  }
}

function parseKeyFamily(raw: unknown, label: string): 'ed25519' | 'ecdsa_secp256k1' {
  if (raw === 'ed25519' || raw === 'ecdsa_secp256k1') return raw;
  throw new Error(`${label} must be ed25519 or ecdsa_secp256k1`);
}

function parseAuthorization(
  raw: unknown,
  label = 'authorization',
): LaneOperationAuthorizationBindingV1 {
  const record = requireRecord(raw, label);
  switch (record.kind) {
    case 'linked_device_enrollment': {
      const value = exactRecord(record, NON_EMPTY_FIELDS.authorization, label);
      return {
        kind: 'linked_device_enrollment',
        authorizedOperationId: resultValue(
          parseAuthorizedOperationId(value.authorizedOperationId),
          `${label}.authorizedOperationId`,
        ),
        linkedDeviceEnrollmentId: parseLinkedDeviceEnrollmentIdValue(
          value.linkedDeviceEnrollmentId,
          `${label}.linkedDeviceEnrollmentId`,
        ),
        linkedDevicePermissionDigestB64u: digest(
          value.linkedDevicePermissionDigestB64u,
          `${label}.linkedDevicePermissionDigestB64u`,
        ),
      };
    }
    case 'owner_lane_refresh': {
      const value = exactRecord(record, NON_EMPTY_FIELDS.refreshAuthorization, label);
      return {
        kind: 'owner_lane_refresh',
        authorizedOperationId: resultValue(
          parseAuthorizedOperationId(value.authorizedOperationId),
          `${label}.authorizedOperationId`,
        ),
        ownerLaneRefreshDigestB64u: digest(
          value.ownerLaneRefreshDigestB64u,
          `${label}.ownerLaneRefreshDigestB64u`,
        ),
      };
    }
    default:
      throw new Error(`${label}.kind is invalid`);
  }
}

function parseSource(raw: unknown, label = 'source'): ActiveLaneProtocolSourceV1 {
  const record = exactRecord(raw, NON_EMPTY_FIELDS.source, label);
  return {
    laneId: parseLaneId(record.laneId, `${label}.laneId`),
    laneKind: parseLaneKind(record.laneKind, `${label}.laneKind`),
    laneShareEpoch: parseShareEpoch(record.laneShareEpoch, `${label}.laneShareEpoch`),
    revocationEpoch: requiredInteger(record.revocationEpoch, `${label}.revocationEpoch`),
    holderParticipantId: resultValue(
      parseLaneHolderParticipantId(record.holderParticipantId),
      `${label}.holderParticipantId`,
    ),
    signingWorkerParticipantId: resultValue(
      parseSigningWorkerParticipantId(record.signingWorkerParticipantId),
      `${label}.signingWorkerParticipantId`,
    ),
    signingWorkerRecipientKeyId: resultValue(
      parseSigningWorkerRecipientKeyId(record.signingWorkerRecipientKeyId),
      `${label}.signingWorkerRecipientKeyId`,
    ),
    participantBindingDigestB64u: resultValue(
      parseLaneParticipantBindingDigestB64u(record.participantBindingDigestB64u),
      `${label}.participantBindingDigestB64u`,
    ),
    materialActivation: parseMpcActivation(
      record.materialActivation,
      `${label}.materialActivation`,
    ),
  };
}

function parseTargetHolder(raw: unknown, label = 'targetHolder') {
  const record = exactRecord(raw, NON_EMPTY_FIELDS.holder, label);
  return {
    participantId: resultValue(
      parseLaneHolderParticipantId(record.participantId),
      `${label}.participantId`,
    ),
    participantBindingDigestB64u: resultValue(
      parseLaneParticipantBindingDigestB64u(record.participantBindingDigestB64u),
      `${label}.participantBindingDigestB64u`,
    ),
    custodyBindingId: resultValue(
      parseLaneHolderCustodyBindingId(record.custodyBindingId),
      `${label}.custodyBindingId`,
    ),
    custodyBindingDigestB64u: resultValue(
      parseLaneCustodyBindingDigestB64u(record.custodyBindingDigestB64u),
      `${label}.custodyBindingDigestB64u`,
    ),
    hpkePublicKeyB64u: resultValue(
      parseHpkePublicKeyB64u(record.hpkePublicKeyB64u),
      `${label}.hpkePublicKeyB64u`,
    ),
    hpkePublicKeyDigestB64u: resultValue(
      parseSigningWorkerRecipientKeyDigestB64u(record.hpkePublicKeyDigestB64u),
      `${label}.hpkePublicKeyDigestB64u`,
    ),
  };
}

function parseTargetSigningWorker(raw: unknown, label = 'targetSigningWorker') {
  const record = exactRecord(raw, NON_EMPTY_FIELDS.worker, label);
  return {
    participantId: resultValue(
      parseSigningWorkerParticipantId(record.participantId),
      `${label}.participantId`,
    ),
    participantBindingDigestB64u: resultValue(
      parseLaneParticipantBindingDigestB64u(record.participantBindingDigestB64u),
      `${label}.participantBindingDigestB64u`,
    ),
    recipientKeyId: resultValue(
      parseSigningWorkerRecipientKeyId(record.recipientKeyId),
      `${label}.recipientKeyId`,
    ),
    hpkePublicKeyB64u: resultValue(
      parseHpkePublicKeyB64u(record.hpkePublicKeyB64u),
      `${label}.hpkePublicKeyB64u`,
    ),
    hpkePublicKeyDigestB64u: resultValue(
      parseSigningWorkerRecipientKeyDigestB64u(record.hpkePublicKeyDigestB64u),
      `${label}.hpkePublicKeyDigestB64u`,
    ),
  };
}

export function buildLaneCreationTargetV1(args: {
  readonly laneId: SigningLaneId;
  readonly laneShareEpoch: LaneShareEpoch;
}): LaneCreationTargetV1 {
  return {
    operation: 'create_lane',
    laneId: args.laneId,
    laneKind: 'linked_device',
    laneShareEpoch: args.laneShareEpoch,
    expectedTargetState: 'absent',
  };
}

export function buildLaneRefreshTargetV1(args: {
  readonly laneId: SigningLaneId;
  readonly laneKind: Exclude<SigningLaneKind, 'delegated_execution'>;
  readonly laneShareEpoch: LaneShareEpoch;
  readonly priorMaterialActivation: MpcMaterialActivationRef;
}): LaneRefreshTargetV1 {
  return {
    operation: 'refresh_lane',
    laneId: args.laneId,
    laneKind: args.laneKind,
    laneShareEpoch: args.laneShareEpoch,
    expectedTargetState: 'active_previous_epoch',
    priorMaterialActivation: args.priorMaterialActivation,
  };
}

function parseTarget(
  raw: unknown,
  source: ActiveLaneProtocolSourceV1,
  label = 'target',
): LaneCreationTargetV1 | LaneRefreshTargetV1 {
  const record = requireRecord(raw, label);
  if (record.operation === 'create_lane') {
    const value = exactRecord(
      record,
      ['operation', 'laneId', 'laneKind', 'laneShareEpoch', 'expectedTargetState'],
      label,
    );
    if (value.laneKind !== 'linked_device' || value.expectedTargetState !== 'absent') {
      throw new Error(`${label} create branch has invalid target state`);
    }
    const target = buildLaneCreationTargetV1({
      laneId: parseLaneId(value.laneId, `${label}.laneId`),
      laneShareEpoch: parseShareEpoch(value.laneShareEpoch, `${label}.laneShareEpoch`),
    });
    if (source.laneKind === 'linked_device' || source.laneKind === 'delegated_execution') {
      throw new Error(`${label} creation requires an owner-controlled source lane`);
    }
    if (String(target.laneId) === String(source.laneId)) {
      throw new Error(`${label}.laneId must differ from source.laneId for creation`);
    }
    return target;
  }
  if (record.operation === 'refresh_lane') {
    const value = exactRecord(
      record,
      [
        'operation',
        'laneId',
        'laneKind',
        'laneShareEpoch',
        'expectedTargetState',
        'priorMaterialActivation',
      ],
      label,
    );
    if (value.expectedTargetState !== 'active_previous_epoch') {
      throw new Error(`${label} refresh branch has invalid target state`);
    }
    const laneId = parseLaneId(value.laneId, `${label}.laneId`);
    if (String(laneId) !== String(source.laneId)) {
      throw new Error(`${label}.laneId must match source.laneId for refresh`);
    }
    const laneShareEpoch = parseShareEpoch(value.laneShareEpoch, `${label}.laneShareEpoch`);
    if (String(laneShareEpoch) === String(source.laneShareEpoch)) {
      throw new Error(`${label}.laneShareEpoch must advance source.laneShareEpoch`);
    }
    const laneKind = parseLaneKind(value.laneKind, `${label}.laneKind`);
    if (laneKind !== source.laneKind) {
      throw new Error(`${label}.laneKind must match source.laneKind for refresh`);
    }
    if (laneKind !== 'delegated_execution') {
      return buildLaneRefreshTargetV1({
        laneId,
        laneKind,
        laneShareEpoch,
        priorMaterialActivation: parseMpcActivation(
          value.priorMaterialActivation,
          `${label}.priorMaterialActivation`,
        ),
      });
    }
  }
  throw new Error(`${label}.operation is invalid`);
}

function parseOperation(
  raw: unknown,
  source: ActiveLaneProtocolSourceV1,
  label = 'operation',
):
  | { target: LaneCreationTargetV1; authorization: LinkedDeviceLaneAuthorizationBindingV1 }
  | { target: LaneRefreshTargetV1; authorization: OwnerLaneRefreshAuthorizationBindingV1 } {
  const record = exactRecord(raw, ['target', 'authorization'], label);
  const target = parseTarget(record.target, source, `${label}.target`);
  const authorization = parseAuthorization(record.authorization, `${label}.authorization`);
  if (target.operation === 'create_lane') {
    if (authorization.kind !== 'linked_device_enrollment') {
      throw new Error(`${label}.authorization must be linked-device enrollment for creation`);
    }
    return { target, authorization };
  }
  if (authorization.kind !== 'owner_lane_refresh') {
    throw new Error(`${label}.authorization must be owner refresh for refresh`);
  }
  return { target, authorization };
}

type ParsedCreationOperation = Extract<
  ReturnType<typeof parseOperation>,
  { target: { operation: 'create_lane' } }
>;
type ParsedRefreshOperation = Extract<
  ReturnType<typeof parseOperation>,
  { target: { operation: 'refresh_lane' } }
>;

function isParsedCreationOperation(
  value: ReturnType<typeof parseOperation>,
): value is ParsedCreationOperation {
  return value.target.operation === 'create_lane';
}

function parseCommonJob(record: UnknownRecord, label: string) {
  const value = exactRecord(
    {
      operationId: record.operationId,
      enrollmentId: record.enrollmentId,
      idempotencyKey: record.idempotencyKey,
      walletId: record.walletId,
      walletKeyId: record.walletKeyId,
      source: record.source,
      targetHolder: record.targetHolder,
      targetSigningWorker: record.targetSigningWorker,
      targetMaterialActivationId: record.targetMaterialActivationId,
      protocolVersion: record.protocolVersion,
      expiresAtMs: record.expiresAtMs,
    },
    [
      'operationId',
      'enrollmentId',
      'idempotencyKey',
      'walletId',
      'walletKeyId',
      'source',
      'targetHolder',
      'targetSigningWorker',
      'targetMaterialActivationId',
      'protocolVersion',
      'expiresAtMs',
    ],
    label,
  );
  const source = parseSource(value.source, `${label}.source`);
  const targetHolder = parseTargetHolder(value.targetHolder, `${label}.targetHolder`);
  const targetSigningWorker = parseTargetSigningWorker(
    value.targetSigningWorker,
    `${label}.targetSigningWorker`,
  );
  const targetMaterialActivationId = resultValue(
    parseMpcMaterialActivationId(value.targetMaterialActivationId),
    `${label}.targetMaterialActivationId`,
  );
  if (String(targetMaterialActivationId) === String(source.materialActivation.activationId)) {
    throw new Error(`${label}.targetMaterialActivationId must be fresh`);
  }
  if (value.protocolVersion !== 'rotatable_signing_lane_protocol_v1') {
    throw new Error(`${label}.protocolVersion is invalid`);
  }
  return {
    operationId: parseLaneOperationId(value.operationId, `${label}.operationId`),
    enrollmentId: parseEnrollmentId(value.enrollmentId, `${label}.enrollmentId`),
    idempotencyKey: parseOperationIdempotencyKey(value.idempotencyKey, `${label}.idempotencyKey`),
    walletId: resultValue(parseWalletId(value.walletId), `${label}.walletId`),
    walletKeyId: parseKeyId(value.walletKeyId, `${label}.walletKeyId`),
    source,
    targetHolder,
    targetSigningWorker,
    targetMaterialActivationId,
    protocolVersion: 'rotatable_signing_lane_protocol_v1' as const,
    expiresAtMs: requiredInteger(value.expiresAtMs, `${label}.expiresAtMs`),
  };
}

function parseEcdsaSourceCapability(raw: unknown, label: string): EcdsaSourceCapabilityBindingV1 {
  const record = exactRecord(
    raw,
    ['manifestId', 'manifestRevision', 'serverGeneration', 'ecdsaThresholdKeyId', 'relayerKeyId'],
    label,
  );
  return {
    manifestId: parseEcdsaCapabilityManifestId(record.manifestId),
    manifestRevision: parseEcdsaCapabilityManifestRevision(record.manifestRevision),
    serverGeneration: parseEcdsaServerGeneration(record.serverGeneration),
    ecdsaThresholdKeyId: parseSdkEcdsaDerivationThresholdKeyId(record.ecdsaThresholdKeyId),
    relayerKeyId: resultValue(parseEcdsaRelayerKeyId(record.relayerKeyId), `${label}.relayerKeyId`),
  };
}

function parseChainTarget(raw: unknown, label: string): ThresholdEcdsaChainTarget {
  const record = requireRecord(raw, label);
  if (record.kind === 'evm') {
    const value = exactRecord(record, ['kind', 'namespace', 'chainId', 'networkSlug'], label);
    if (value.namespace !== 'eip155') throw new Error(`${label}.namespace is invalid`);
    return {
      kind: 'evm',
      namespace: 'eip155',
      chainId: requiredInteger(value.chainId, `${label}.chainId`),
      networkSlug: requiredString(value.networkSlug, `${label}.networkSlug`),
    };
  }
  if (record.kind === 'tempo') {
    const value = exactRecord(record, ['kind', 'chainId', 'networkSlug'], label);
    return {
      kind: 'tempo',
      chainId: requiredInteger(value.chainId, `${label}.chainId`),
      networkSlug: requiredString(value.networkSlug, `${label}.networkSlug`),
    };
  }
  throw new Error(`${label}.kind is invalid`);
}

function parseEcdsaTargetCapability(raw: unknown, label: string): EcdsaTargetCapabilityBindingV1 {
  const record = exactRecord(
    raw,
    ['manifestId', 'manifestRevision', 'ecdsaThresholdKeyId', 'orderedThresholdSessions'],
    label,
  );
  const sessionsRaw = requiredArray(
    record.orderedThresholdSessions,
    `${label}.orderedThresholdSessions`,
  );
  if (sessionsRaw.length === 0)
    throw new Error(`${label}.orderedThresholdSessions must be non-empty`);
  const orderedThresholdSessions = sessionsRaw.map((item, index) => {
    const session = exactRecord(
      item,
      ['chainTarget', 'thresholdSessionId', 'participantBindingDigestB64u'],
      `${label}.orderedThresholdSessions[${index}]`,
    );
    return {
      chainTarget: parseChainTarget(
        session.chainTarget,
        `${label}.orderedThresholdSessions[${index}].chainTarget`,
      ),
      thresholdSessionId: resultValue(
        parseThresholdEcdsaSessionId(session.thresholdSessionId),
        `${label}.orderedThresholdSessions[${index}].thresholdSessionId`,
      ),
      participantBindingDigestB64u: digest(
        session.participantBindingDigestB64u,
        `${label}.orderedThresholdSessions[${index}].participantBindingDigestB64u`,
      ),
    } satisfies EcdsaTargetThresholdSessionBindingV1;
  });
  return {
    manifestId: parseEcdsaCapabilityManifestId(record.manifestId),
    manifestRevision: parseEcdsaCapabilityManifestRevision(record.manifestRevision),
    ecdsaThresholdKeyId: parseSdkEcdsaDerivationThresholdKeyId(record.ecdsaThresholdKeyId),
    orderedThresholdSessions: nonEmptyTuple(
      orderedThresholdSessions,
      `${label}.orderedThresholdSessions`,
    ),
  };
}

type ParsedEcdsaCurve = {
  readonly kind: 'ecdsa_additive_lane_job_v1';
  readonly keyFamily: 'ecdsa_secp256k1';
  readonly evmFamilySigningKeySlotId: EcdsaAdditiveLaneCreationJobV1['evmFamilySigningKeySlotId'];
  readonly thresholdPublicKey33B64u: string;
  readonly evmAddress: string;
  readonly sourceCapability: EcdsaSourceCapabilityBindingV1;
  readonly targetCapability: EcdsaTargetCapabilityBindingV1;
  readonly sourceHolderVerifyingShare33B64u: string;
  readonly sourceServerVerifyingShare33B64u: string;
  readonly reshareChannelBindingDigestB64u: string;
  readonly transcriptEncoding: 'ecdsa_additive_lane_transcript_v1';
};

type ParsedJobCommon = ReturnType<typeof parseCommonJob>;

type ParsedEdCurve = {
  readonly kind: 'ed25519_yao_lane_job_v1';
  readonly keyFamily: 'ed25519';
  readonly registeredPublicKeyB64u: string;
  readonly nearEd25519SigningKeyId: NearEd25519SigningKeyId;
  readonly keyCreationSignerSlot: KeyCreationSignerSlot;
  readonly stableContextBindingB64u: string;
  readonly yaoSuiteId: Ed25519YaoSuiteId;
  readonly circuitDigestB64u: string;
};

function buildEdCreationJob(
  common: ParsedJobCommon,
  operation: ParsedCreationOperation,
  curve: ParsedEdCurve,
): Ed25519YaoLaneCreationJobV1 {
  return {
    operationId: common.operationId,
    enrollmentId: common.enrollmentId,
    idempotencyKey: common.idempotencyKey,
    walletId: common.walletId,
    walletKeyId: common.walletKeyId,
    source: common.source,
    targetHolder: common.targetHolder,
    targetSigningWorker: common.targetSigningWorker,
    targetMaterialActivationId: common.targetMaterialActivationId,
    protocolVersion: common.protocolVersion,
    expiresAtMs: common.expiresAtMs,
    target: operation.target,
    authorization: operation.authorization,
    yaoRequestKind: 'lane_provisioning',
    kind: curve.kind,
    keyFamily: curve.keyFamily,
    registeredPublicKeyB64u: curve.registeredPublicKeyB64u,
    nearEd25519SigningKeyId: curve.nearEd25519SigningKeyId,
    keyCreationSignerSlot: curve.keyCreationSignerSlot,
    stableContextBindingB64u: curve.stableContextBindingB64u,
    yaoSuiteId: curve.yaoSuiteId,
    circuitDigestB64u: curve.circuitDigestB64u,
  };
}

function buildEdRefreshJob(
  common: ParsedJobCommon,
  operation: ParsedRefreshOperation,
  curve: ParsedEdCurve,
): Ed25519YaoLaneRefreshJobV1 {
  return {
    operationId: common.operationId,
    enrollmentId: common.enrollmentId,
    idempotencyKey: common.idempotencyKey,
    walletId: common.walletId,
    walletKeyId: common.walletKeyId,
    source: common.source,
    targetHolder: common.targetHolder,
    targetSigningWorker: common.targetSigningWorker,
    targetMaterialActivationId: common.targetMaterialActivationId,
    protocolVersion: common.protocolVersion,
    expiresAtMs: common.expiresAtMs,
    target: operation.target,
    authorization: operation.authorization,
    yaoRequestKind: 'lane_refresh',
    kind: curve.kind,
    keyFamily: curve.keyFamily,
    registeredPublicKeyB64u: curve.registeredPublicKeyB64u,
    nearEd25519SigningKeyId: curve.nearEd25519SigningKeyId,
    keyCreationSignerSlot: curve.keyCreationSignerSlot,
    stableContextBindingB64u: curve.stableContextBindingB64u,
    yaoSuiteId: curve.yaoSuiteId,
    circuitDigestB64u: curve.circuitDigestB64u,
  };
}

function buildEcdsaCreationJob(
  common: ParsedJobCommon,
  operation: ParsedCreationOperation,
  curve: ParsedEcdsaCurve,
): EcdsaAdditiveLaneCreationJobV1 {
  return {
    operationId: common.operationId,
    enrollmentId: common.enrollmentId,
    idempotencyKey: common.idempotencyKey,
    walletId: common.walletId,
    walletKeyId: common.walletKeyId,
    source: common.source,
    targetHolder: common.targetHolder,
    targetSigningWorker: common.targetSigningWorker,
    targetMaterialActivationId: common.targetMaterialActivationId,
    protocolVersion: common.protocolVersion,
    expiresAtMs: common.expiresAtMs,
    target: operation.target,
    authorization: operation.authorization,
    kind: curve.kind,
    keyFamily: curve.keyFamily,
    evmFamilySigningKeySlotId: curve.evmFamilySigningKeySlotId,
    thresholdPublicKey33B64u: curve.thresholdPublicKey33B64u,
    evmAddress: curve.evmAddress,
    sourceCapability: curve.sourceCapability,
    targetCapability: curve.targetCapability,
    sourceHolderVerifyingShare33B64u: curve.sourceHolderVerifyingShare33B64u,
    sourceServerVerifyingShare33B64u: curve.sourceServerVerifyingShare33B64u,
    reshareChannelBindingDigestB64u: curve.reshareChannelBindingDigestB64u,
    transcriptEncoding: curve.transcriptEncoding,
  };
}

function buildEcdsaRefreshJob(
  common: ParsedJobCommon,
  operation: ParsedRefreshOperation,
  curve: ParsedEcdsaCurve,
): EcdsaAdditiveLaneRefreshJobV1 {
  return {
    operationId: common.operationId,
    enrollmentId: common.enrollmentId,
    idempotencyKey: common.idempotencyKey,
    walletId: common.walletId,
    walletKeyId: common.walletKeyId,
    source: common.source,
    targetHolder: common.targetHolder,
    targetSigningWorker: common.targetSigningWorker,
    targetMaterialActivationId: common.targetMaterialActivationId,
    protocolVersion: common.protocolVersion,
    expiresAtMs: common.expiresAtMs,
    target: operation.target,
    authorization: operation.authorization,
    kind: curve.kind,
    keyFamily: curve.keyFamily,
    evmFamilySigningKeySlotId: curve.evmFamilySigningKeySlotId,
    thresholdPublicKey33B64u: curve.thresholdPublicKey33B64u,
    evmAddress: curve.evmAddress,
    sourceCapability: curve.sourceCapability,
    targetCapability: curve.targetCapability,
    sourceHolderVerifyingShare33B64u: curve.sourceHolderVerifyingShare33B64u,
    sourceServerVerifyingShare33B64u: curve.sourceServerVerifyingShare33B64u,
    reshareChannelBindingDigestB64u: curve.reshareChannelBindingDigestB64u,
    transcriptEncoding: curve.transcriptEncoding,
  };
}

function parseEcdsaJob(record: UnknownRecord, label: string): EcdsaAdditiveLaneJobV1 {
  const value = exactRecord(
    record,
    [
      'kind',
      'keyFamily',
      'operationId',
      'enrollmentId',
      'idempotencyKey',
      'walletId',
      'walletKeyId',
      'source',
      'targetHolder',
      'targetSigningWorker',
      'targetMaterialActivationId',
      'protocolVersion',
      'expiresAtMs',
      'target',
      'authorization',
      'evmFamilySigningKeySlotId',
      'thresholdPublicKey33B64u',
      'evmAddress',
      'sourceCapability',
      'targetCapability',
      'sourceHolderVerifyingShare33B64u',
      'sourceServerVerifyingShare33B64u',
      'reshareChannelBindingDigestB64u',
      'transcriptEncoding',
    ],
    label,
  );
  if (value.kind !== 'ecdsa_additive_lane_job_v1' || value.keyFamily !== 'ecdsa_secp256k1') {
    throw new Error(`${label} kind/keyFamily is invalid`);
  }
  if (value.transcriptEncoding !== 'ecdsa_additive_lane_transcript_v1') {
    throw new Error(`${label}.transcriptEncoding is invalid`);
  }
  const common = parseCommonJob(value, label);
  const operationFromValue = parseOperation(
    { target: value.target, authorization: value.authorization },
    common.source,
    `${label}.operation`,
  );
  const curve = {
    kind: 'ecdsa_additive_lane_job_v1' as const,
    keyFamily: 'ecdsa_secp256k1' as const,
    evmFamilySigningKeySlotId: (() => {
      const parsed = parseEvmFamilySigningKeySlotId(value.evmFamilySigningKeySlotId);
      if (parsed.ok) return parsed.value;
      throw new Error(`${label}.evmFamilySigningKeySlotId is invalid`);
    })(),
    thresholdPublicKey33B64u: parseSecp256k1CompressedPublicKeyB64u(value.thresholdPublicKey33B64u),
    evmAddress: requiredString(value.evmAddress, `${label}.evmAddress`),
    sourceCapability: parseEcdsaSourceCapability(
      value.sourceCapability,
      `${label}.sourceCapability`,
    ),
    targetCapability: parseEcdsaTargetCapability(
      value.targetCapability,
      `${label}.targetCapability`,
    ),
    sourceHolderVerifyingShare33B64u: parseSecp256k1CompressedPublicKeyB64u(
      value.sourceHolderVerifyingShare33B64u,
      `${label}.sourceHolderVerifyingShare33B64u`,
    ),
    sourceServerVerifyingShare33B64u: parseSecp256k1CompressedPublicKeyB64u(
      value.sourceServerVerifyingShare33B64u,
      `${label}.sourceServerVerifyingShare33B64u`,
    ),
    reshareChannelBindingDigestB64u: digest(
      value.reshareChannelBindingDigestB64u,
      `${label}.reshareChannelBindingDigestB64u`,
    ),
    transcriptEncoding: 'ecdsa_additive_lane_transcript_v1' as const,
  };
  if (isParsedCreationOperation(operationFromValue)) {
    return buildEcdsaCreationJob(common, operationFromValue, curve);
  }
  return buildEcdsaRefreshJob(common, operationFromValue, curve);
}

function parseEdJob(record: UnknownRecord, label: string): Ed25519YaoLaneJobV1 {
  const value = exactRecord(
    record,
    [
      'kind',
      'keyFamily',
      'operationId',
      'enrollmentId',
      'idempotencyKey',
      'walletId',
      'walletKeyId',
      'source',
      'targetHolder',
      'targetSigningWorker',
      'targetMaterialActivationId',
      'protocolVersion',
      'expiresAtMs',
      'target',
      'authorization',
      'yaoRequestKind',
      'registeredPublicKeyB64u',
      'nearEd25519SigningKeyId',
      'keyCreationSignerSlot',
      'stableContextBindingB64u',
      'yaoSuiteId',
      'circuitDigestB64u',
    ],
    label,
  );
  if (value.kind !== 'ed25519_yao_lane_job_v1' || value.keyFamily !== 'ed25519') {
    throw new Error(`${label} kind/keyFamily is invalid`);
  }
  const common = parseCommonJob(value, label);
  const operation = parseOperation(
    { target: value.target, authorization: value.authorization },
    common.source,
    `${label}.operation`,
  );
  const yaoRequestKind = requiredString(value.yaoRequestKind, `${label}.yaoRequestKind`);
  const curve = {
    kind: 'ed25519_yao_lane_job_v1' as const,
    keyFamily: 'ed25519' as const,
    registeredPublicKeyB64u: parseEd25519PublicKeyB64u(value.registeredPublicKeyB64u),
    nearEd25519SigningKeyId: parseNearEd25519SigningKeyId(value.nearEd25519SigningKeyId),
    keyCreationSignerSlot: parseKeyCreationSignerSlot(value.keyCreationSignerSlot),
    stableContextBindingB64u: digest(
      value.stableContextBindingB64u,
      `${label}.stableContextBindingB64u`,
    ),
    yaoSuiteId: resultValue(parseEd25519YaoSuiteId(value.yaoSuiteId), `${label}.yaoSuiteId`),
    circuitDigestB64u: digest(value.circuitDigestB64u, `${label}.circuitDigestB64u`),
  };
  if (isParsedCreationOperation(operation)) {
    if (yaoRequestKind !== 'lane_provisioning')
      throw new Error(`${label}.yaoRequestKind must be lane_provisioning for creation`);
    return buildEdCreationJob(common, operation, curve);
  }
  if (yaoRequestKind !== 'lane_refresh')
    throw new Error(`${label}.yaoRequestKind must be lane_refresh for refresh`);
  return buildEdRefreshJob(common, operation, curve);
}

export function parseRotatableSigningLaneJobV1(
  raw: unknown,
  label = 'laneProtocolJob',
): RotatableSigningLaneJobV1 {
  const record = requireRecord(raw, label);
  if (record.kind === 'ed25519_yao_lane_job_v1') return parseEdJob(record, label);
  if (record.kind === 'ecdsa_additive_lane_job_v1') return parseEcdsaJob(record, label);
  throw new Error(`${label}.kind is invalid`);
}

export function parseLaneHolderPackageWireV1(
  raw: unknown,
  label = 'laneHolderPackage',
): LaneHolderPackageWireV1 {
  const record = requireRecord(raw, label);
  switch (record.kind) {
    case 'ed25519_yao_lane_holder_package_set_v1': {
      const value = exactRecord(
        record,
        ['kind', 'deriverAEncryptedPackageJson', 'deriverBEncryptedPackageJson'],
        label,
      );
      return {
        kind: 'ed25519_yao_lane_holder_package_set_v1',
        deriverAEncryptedPackageJson: opaqueJson(
          value.deriverAEncryptedPackageJson,
          `${label}.deriverAEncryptedPackageJson`,
        ),
        deriverBEncryptedPackageJson: opaqueJson(
          value.deriverBEncryptedPackageJson,
          `${label}.deriverBEncryptedPackageJson`,
        ),
      };
    }
    case 'ecdsa_additive_lane_holder_package_v1': {
      const value = exactRecord(record, ['kind', 'ecdsaEncryptedMaterialEnvelopeJson'], label);
      return {
        kind: 'ecdsa_additive_lane_holder_package_v1',
        ecdsaEncryptedMaterialEnvelopeJson: opaqueJson(
          value.ecdsaEncryptedMaterialEnvelopeJson,
          `${label}.ecdsaEncryptedMaterialEnvelopeJson`,
        ),
      };
    }
    default:
      throw new Error(`${label}.kind is invalid`);
  }
}

export const parseLaneProtocolJobV1 = parseRotatableSigningLaneJobV1;

function parseReceiptCommon(raw: unknown, fields: readonly string[], label: string): UnknownRecord {
  return exactRecord(raw, fields, label);
}

export function parseLaneProtocolCommitReceiptV1(
  raw: unknown,
  label = 'protocolCommitReceipt',
): LaneProtocolCommitReceiptV1 {
  const record = parseReceiptCommon(
    raw,
    [
      'kind',
      'operationId',
      'enrollmentId',
      'walletId',
      'walletKeyId',
      'sourceLaneId',
      'sourceLaneShareEpoch',
      'sourceRevocationEpoch',
      'sourceMaterialActivation',
      'targetLaneId',
      'targetLaneShareEpoch',
      'targetMaterialActivationId',
      'keyFamily',
      'publicIdentityDigestB64u',
      'targetHolderPublicCommitmentB64u',
      'targetServerPublicCommitmentB64u',
      'targetHolderCiphertextDigestSetB64u',
      'targetServerCiphertextDigestSetB64u',
      'holderRecipientKeyDigestB64u',
      'serverRecipientKeyDigestB64u',
      'transcriptHashB64u',
      'committedAtMs',
    ],
    label,
  );
  if (record.kind !== 'lane_protocol_commit_receipt_v1')
    throw new Error(`${label}.kind is invalid`);
  return {
    kind: 'lane_protocol_commit_receipt_v1',
    operationId: parseLaneOperationId(record.operationId, `${label}.operationId`),
    enrollmentId: parseEnrollmentId(record.enrollmentId, `${label}.enrollmentId`),
    walletId: resultValue(parseWalletId(record.walletId), `${label}.walletId`),
    walletKeyId: parseKeyId(record.walletKeyId, `${label}.walletKeyId`),
    sourceLaneId: parseLaneId(record.sourceLaneId, `${label}.sourceLaneId`),
    sourceLaneShareEpoch: parseShareEpoch(
      record.sourceLaneShareEpoch,
      `${label}.sourceLaneShareEpoch`,
    ),
    sourceRevocationEpoch: requiredInteger(
      record.sourceRevocationEpoch,
      `${label}.sourceRevocationEpoch`,
    ),
    sourceMaterialActivation: parseMpcActivation(
      record.sourceMaterialActivation,
      `${label}.sourceMaterialActivation`,
    ),
    targetLaneId: parseLaneId(record.targetLaneId, `${label}.targetLaneId`),
    targetLaneShareEpoch: parseShareEpoch(
      record.targetLaneShareEpoch,
      `${label}.targetLaneShareEpoch`,
    ),
    targetMaterialActivationId: resultValue(
      parseMpcMaterialActivationId(record.targetMaterialActivationId),
      `${label}.targetMaterialActivationId`,
    ),
    keyFamily: parseKeyFamily(record.keyFamily, `${label}.keyFamily`),
    publicIdentityDigestB64u: digest(
      record.publicIdentityDigestB64u,
      `${label}.publicIdentityDigestB64u`,
    ),
    targetHolderPublicCommitmentB64u: requiredString(
      record.targetHolderPublicCommitmentB64u,
      `${label}.targetHolderPublicCommitmentB64u`,
    ),
    targetServerPublicCommitmentB64u: requiredString(
      record.targetServerPublicCommitmentB64u,
      `${label}.targetServerPublicCommitmentB64u`,
    ),
    targetHolderCiphertextDigestSetB64u: digest(
      record.targetHolderCiphertextDigestSetB64u,
      `${label}.targetHolderCiphertextDigestSetB64u`,
    ),
    targetServerCiphertextDigestSetB64u: digest(
      record.targetServerCiphertextDigestSetB64u,
      `${label}.targetServerCiphertextDigestSetB64u`,
    ),
    holderRecipientKeyDigestB64u: digest(
      record.holderRecipientKeyDigestB64u,
      `${label}.holderRecipientKeyDigestB64u`,
    ),
    serverRecipientKeyDigestB64u: digest(
      record.serverRecipientKeyDigestB64u,
      `${label}.serverRecipientKeyDigestB64u`,
    ),
    transcriptHashB64u: digest(record.transcriptHashB64u, `${label}.transcriptHashB64u`),
    committedAtMs: requiredInteger(record.committedAtMs, `${label}.committedAtMs`),
  };
}

export function parseLaneHolderDeliveryReceiptV1(
  raw: unknown,
  label = 'holderDeliveryReceipt',
): LaneHolderDeliveryReceiptV1 {
  const record = parseReceiptCommon(
    raw,
    [
      'kind',
      'operationId',
      'enrollmentId',
      'targetLaneId',
      'targetLaneShareEpoch',
      'targetMaterialActivationId',
      'holderParticipantBindingDigestB64u',
      'holderRecipientKeyDigestB64u',
      'holderCiphertextDigestSetB64u',
      'sealedHolderRecordDigestB64u',
      'transcriptHashB64u',
      'acknowledgedAtMs',
    ],
    label,
  );
  if (record.kind !== 'lane_holder_delivery_receipt_v1')
    throw new Error(`${label}.kind is invalid`);
  return {
    kind: 'lane_holder_delivery_receipt_v1',
    operationId: parseLaneOperationId(record.operationId, `${label}.operationId`),
    enrollmentId: parseEnrollmentId(record.enrollmentId, `${label}.enrollmentId`),
    targetLaneId: parseLaneId(record.targetLaneId, `${label}.targetLaneId`),
    targetLaneShareEpoch: parseShareEpoch(
      record.targetLaneShareEpoch,
      `${label}.targetLaneShareEpoch`,
    ),
    targetMaterialActivationId: resultValue(
      parseMpcMaterialActivationId(record.targetMaterialActivationId),
      `${label}.targetMaterialActivationId`,
    ),
    holderParticipantBindingDigestB64u: digest(
      record.holderParticipantBindingDigestB64u,
      `${label}.holderParticipantBindingDigestB64u`,
    ),
    holderRecipientKeyDigestB64u: digest(
      record.holderRecipientKeyDigestB64u,
      `${label}.holderRecipientKeyDigestB64u`,
    ),
    holderCiphertextDigestSetB64u: digest(
      record.holderCiphertextDigestSetB64u,
      `${label}.holderCiphertextDigestSetB64u`,
    ),
    sealedHolderRecordDigestB64u: digest(
      record.sealedHolderRecordDigestB64u,
      `${label}.sealedHolderRecordDigestB64u`,
    ),
    transcriptHashB64u: digest(record.transcriptHashB64u, `${label}.transcriptHashB64u`),
    acknowledgedAtMs: requiredInteger(record.acknowledgedAtMs, `${label}.acknowledgedAtMs`),
  };
}

export function parseLaneServerActivationReceiptV1(
  raw: unknown,
  label = 'serverActivationReceipt',
): LaneServerActivationReceiptV1 {
  const record = parseReceiptCommon(
    raw,
    [
      'kind',
      'operationId',
      'enrollmentId',
      'targetLaneId',
      'targetLaneShareEpoch',
      'targetMaterialActivation',
      'signingWorkerParticipantBindingDigestB64u',
      'serverCiphertextDigestSetB64u',
      'transcriptHashB64u',
      'activatedAtMs',
    ],
    label,
  );
  if (record.kind !== 'lane_server_activation_receipt_v1')
    throw new Error(`${label}.kind is invalid`);
  return {
    kind: 'lane_server_activation_receipt_v1',
    operationId: parseLaneOperationId(record.operationId, `${label}.operationId`),
    enrollmentId: parseEnrollmentId(record.enrollmentId, `${label}.enrollmentId`),
    targetLaneId: parseLaneId(record.targetLaneId, `${label}.targetLaneId`),
    targetLaneShareEpoch: parseShareEpoch(
      record.targetLaneShareEpoch,
      `${label}.targetLaneShareEpoch`,
    ),
    targetMaterialActivation: parseMpcActivation(
      record.targetMaterialActivation,
      `${label}.targetMaterialActivation`,
    ),
    signingWorkerParticipantBindingDigestB64u: digest(
      record.signingWorkerParticipantBindingDigestB64u,
      `${label}.signingWorkerParticipantBindingDigestB64u`,
    ),
    serverCiphertextDigestSetB64u: digest(
      record.serverCiphertextDigestSetB64u,
      `${label}.serverCiphertextDigestSetB64u`,
    ),
    transcriptHashB64u: digest(record.transcriptHashB64u, `${label}.transcriptHashB64u`),
    activatedAtMs: requiredInteger(record.activatedAtMs, `${label}.activatedAtMs`),
  };
}

function requiredArray(raw: unknown, label: string): unknown[] {
  if (!Array.isArray(raw)) throw new Error(`${label} must be an array`);
  return raw;
}

function parseManifestChild(raw: unknown, label: string): LaneEnrollmentManifestChildV1 {
  const record = exactRecord(
    raw,
    [
      'operationId',
      'walletKeyId',
      'keyFamily',
      'sourceLaneId',
      'sourceLaneShareEpoch',
      'sourceRevocationEpoch',
      'sourceMaterialActivation',
      'targetLaneId',
      'targetLaneShareEpoch',
      'targetMaterialActivationId',
      'holderParticipantBindingDigestB64u',
      'signingWorkerParticipantBindingDigestB64u',
    ],
    label,
  );
  return {
    operationId: parseLaneOperationId(record.operationId, `${label}.operationId`),
    walletKeyId: parseKeyId(record.walletKeyId, `${label}.walletKeyId`),
    keyFamily: parseKeyFamily(record.keyFamily, `${label}.keyFamily`),
    sourceLaneId: parseLaneId(record.sourceLaneId, `${label}.sourceLaneId`),
    sourceLaneShareEpoch: parseShareEpoch(
      record.sourceLaneShareEpoch,
      `${label}.sourceLaneShareEpoch`,
    ),
    sourceRevocationEpoch: requiredInteger(
      record.sourceRevocationEpoch,
      `${label}.sourceRevocationEpoch`,
    ),
    sourceMaterialActivation: parseMpcActivation(
      record.sourceMaterialActivation,
      `${label}.sourceMaterialActivation`,
    ),
    targetLaneId: parseLaneId(record.targetLaneId, `${label}.targetLaneId`),
    targetLaneShareEpoch: parseShareEpoch(
      record.targetLaneShareEpoch,
      `${label}.targetLaneShareEpoch`,
    ),
    targetMaterialActivationId: resultValue(
      parseMpcMaterialActivationId(record.targetMaterialActivationId),
      `${label}.targetMaterialActivationId`,
    ),
    holderParticipantBindingDigestB64u: digest(
      record.holderParticipantBindingDigestB64u,
      `${label}.holderParticipantBindingDigestB64u`,
    ),
    signingWorkerParticipantBindingDigestB64u: digest(
      record.signingWorkerParticipantBindingDigestB64u,
      `${label}.signingWorkerParticipantBindingDigestB64u`,
    ),
  };
}

function assertUniqueChildren(
  children: readonly LaneEnrollmentManifestChildV1[],
  label: string,
): void {
  const fields: Array<keyof LaneEnrollmentManifestChildV1> = [
    'operationId',
    'walletKeyId',
    'targetLaneId',
    'targetMaterialActivationId',
  ];
  for (const field of fields) {
    const values = children.map((child) => String(child[field]));
    if (new Set(values).size !== values.length)
      throw new Error(`${label} contains duplicate ${field}`);
  }
}

function assertUniqueAggregateActivationChildren(
  children: readonly AggregateLaneActivationChildReceiptV1[],
  label: string,
): void {
  const values = [
    children.map((child) => String(child.operationId)),
    children.map((child) => String(child.walletKeyId)),
    children.map((child) => String(child.targetLaneId)),
    children.map((child) => String(child.targetMaterialActivation.activationId)),
  ];
  for (const entries of values) {
    if (new Set(entries).size !== entries.length)
      throw new Error(`${label} contains duplicate child identity`);
  }
}

export function parseLaneEnrollmentManifestV1(
  raw: unknown,
  label = 'laneEnrollmentManifest',
): LaneEnrollmentManifestV1 {
  const record = exactRecord(
    raw,
    [
      'kind',
      'enrollmentId',
      'walletId',
      'authorization',
      'orderedChildren',
      'createdAtMs',
      'expiresAtMs',
    ],
    label,
  );
  if (record.kind !== 'lane_enrollment_manifest_v1') throw new Error(`${label}.kind is invalid`);
  const childrenRaw = requiredArray(record.orderedChildren, `${label}.orderedChildren`);
  if (childrenRaw.length === 0) throw new Error(`${label}.orderedChildren must be non-empty`);
  const orderedChildren = nonEmptyTuple(
    childrenRaw.map((child, index) =>
      parseManifestChild(child, `${label}.orderedChildren[${index}]`),
    ),
    `${label}.orderedChildren`,
  );
  assertUniqueChildren(orderedChildren, `${label}.orderedChildren`);
  const createdAtMs = requiredInteger(record.createdAtMs, `${label}.createdAtMs`);
  const expiresAtMs = requiredInteger(record.expiresAtMs, `${label}.expiresAtMs`);
  if (expiresAtMs <= createdAtMs) throw new Error(`${label}.expiresAtMs must be after createdAtMs`);
  return {
    kind: 'lane_enrollment_manifest_v1',
    enrollmentId: parseEnrollmentId(record.enrollmentId, `${label}.enrollmentId`),
    walletId: resultValue(parseWalletId(record.walletId), `${label}.walletId`),
    authorization: parseAuthorization(record.authorization, `${label}.authorization`),
    orderedChildren,
    createdAtMs,
    expiresAtMs,
  };
}

function parseAggregateActivationChild(
  raw: unknown,
  label: string,
): AggregateLaneActivationChildReceiptV1 {
  const record = exactRecord(
    raw,
    [
      'operationId',
      'walletKeyId',
      'targetLaneId',
      'targetLaneShareEpoch',
      'targetMaterialActivation',
      'protocolCommitReceiptDigestB64u',
      'holderDeliveryReceiptDigestB64u',
      'serverActivationReceiptDigestB64u',
    ],
    label,
  );
  return {
    operationId: parseLaneOperationId(record.operationId, `${label}.operationId`),
    walletKeyId: parseKeyId(record.walletKeyId, `${label}.walletKeyId`),
    targetLaneId: parseLaneId(record.targetLaneId, `${label}.targetLaneId`),
    targetLaneShareEpoch: parseShareEpoch(
      record.targetLaneShareEpoch,
      `${label}.targetLaneShareEpoch`,
    ),
    targetMaterialActivation: parseMpcActivation(
      record.targetMaterialActivation,
      `${label}.targetMaterialActivation`,
    ),
    protocolCommitReceiptDigestB64u: digest(
      record.protocolCommitReceiptDigestB64u,
      `${label}.protocolCommitReceiptDigestB64u`,
    ),
    holderDeliveryReceiptDigestB64u: digest(
      record.holderDeliveryReceiptDigestB64u,
      `${label}.holderDeliveryReceiptDigestB64u`,
    ),
    serverActivationReceiptDigestB64u: digest(
      record.serverActivationReceiptDigestB64u,
      `${label}.serverActivationReceiptDigestB64u`,
    ),
  };
}

export function buildAggregateLaneActivationChildReceiptV1(
  input: AggregateLaneActivationChildReceiptV1,
): AggregateLaneActivationChildReceiptV1 {
  return parseAggregateActivationChild(input, 'aggregateLaneActivationChildReceipt');
}

export function parseAggregateLaneActivationReceiptV1(
  raw: unknown,
  label = 'aggregateActivationReceipt',
): AggregateLaneActivationReceiptV1 {
  const record = exactRecord(
    raw,
    [
      'kind',
      'enrollmentId',
      'walletId',
      'manifestDigestB64u',
      'orderedChildReceipts',
      'activatedAtMs',
    ],
    label,
  );
  if (record.kind !== 'aggregate_lane_activation_receipt_v1')
    throw new Error(`${label}.kind is invalid`);
  const childrenRaw = requiredArray(record.orderedChildReceipts, `${label}.orderedChildReceipts`);
  if (childrenRaw.length === 0) throw new Error(`${label}.orderedChildReceipts must be non-empty`);
  const orderedChildReceipts = nonEmptyTuple(
    childrenRaw.map((child, index) =>
      parseAggregateActivationChild(child, `${label}.orderedChildReceipts[${index}]`),
    ),
    `${label}.orderedChildReceipts`,
  );
  assertUniqueAggregateActivationChildren(orderedChildReceipts, `${label}.orderedChildReceipts`);
  return {
    kind: 'aggregate_lane_activation_receipt_v1',
    enrollmentId: parseEnrollmentId(record.enrollmentId, `${label}.enrollmentId`),
    walletId: resultValue(parseWalletId(record.walletId), `${label}.walletId`),
    manifestDigestB64u: digest(record.manifestDigestB64u, `${label}.manifestDigestB64u`),
    orderedChildReceipts,
    activatedAtMs: requiredInteger(record.activatedAtMs, `${label}.activatedAtMs`),
  };
}

export function parseCommitLaneEnrollmentActivationV1(
  raw: unknown,
  label = 'commitLaneEnrollmentActivation',
): CommitLaneEnrollmentActivationV1 {
  const record = exactRecord(
    raw,
    [
      'kind',
      'enrollmentId',
      'walletId',
      'manifestDigestB64u',
      'orderedChildReceipts',
      'orderedPredecessorRetirements',
      'activatedAtMs',
    ],
    label,
  );
  if (record.kind !== 'commit_lane_enrollment_activation_v1')
    throw new Error(`${label}.kind is invalid`);
  const receipt = parseAggregateLaneActivationReceiptV1(
    {
      kind: 'aggregate_lane_activation_receipt_v1',
      enrollmentId: record.enrollmentId,
      walletId: record.walletId,
      manifestDigestB64u: record.manifestDigestB64u,
      orderedChildReceipts: record.orderedChildReceipts,
      activatedAtMs: record.activatedAtMs,
    },
    `${label}.receipt`,
  );
  const predecessorRetirementsRaw = requiredArray(
    record.orderedPredecessorRetirements,
    `${label}.orderedPredecessorRetirements`,
  );
  const orderedPredecessorRetirements = predecessorRetirementsRaw.map((value, index) =>
    parseLaneRefreshPredecessorRetirementV1(
      value,
      `${label}.orderedPredecessorRetirements[${index}]`,
    ),
  );
  const refreshOperationIds = orderedPredecessorRetirements.map((value) =>
    String(value.refreshOperationId),
  );
  if (new Set(refreshOperationIds).size !== refreshOperationIds.length)
    throw new Error(`${label}.orderedPredecessorRetirements contains duplicate refresh operation`);
  return {
    kind: 'commit_lane_enrollment_activation_v1',
    enrollmentId: receipt.enrollmentId,
    walletId: receipt.walletId,
    manifestDigestB64u: receipt.manifestDigestB64u,
    orderedChildReceipts: receipt.orderedChildReceipts,
    orderedPredecessorRetirements,
    activatedAtMs: receipt.activatedAtMs,
  };
}

export function parseLaneRefreshPredecessorRetirementV1(
  raw: unknown,
  label = 'laneRefreshPredecessorRetirement',
): LaneRefreshPredecessorRetirementV1 {
  const record = exactRecord(
    raw,
    [
      'refreshOperationId',
      'sourceLaneId',
      'sourceLaneShareEpoch',
      'sourceMaterialActivation',
      'retirementEffectBindingDigestB64u',
      'retirementReceipt',
    ],
    label,
  );
  return {
    refreshOperationId: parseLaneOperationId(
      record.refreshOperationId,
      `${label}.refreshOperationId`,
    ),
    sourceLaneId: parseLaneId(record.sourceLaneId, `${label}.sourceLaneId`),
    sourceLaneShareEpoch: parseShareEpoch(
      record.sourceLaneShareEpoch,
      `${label}.sourceLaneShareEpoch`,
    ),
    sourceMaterialActivation: parseMpcActivation(
      record.sourceMaterialActivation,
      `${label}.sourceMaterialActivation`,
    ),
    retirementEffectBindingDigestB64u: digest(
      record.retirementEffectBindingDigestB64u,
      `${label}.retirementEffectBindingDigestB64u`,
    ),
    retirementReceipt: parseLaneServerRetirementReceiptV1(
      record.retirementReceipt,
      `${label}.retirementReceipt`,
    ),
  };
}

function parseAggregateRevocationChild(
  raw: unknown,
  label: string,
): AggregateLaneRevocationChildReceiptV1 {
  const record = exactRecord(
    raw,
    [
      'operationId',
      'walletKeyId',
      'targetLaneId',
      'targetLaneShareEpoch',
      'targetMaterialActivation',
      'revocationEpoch',
      'retirementReceiptDigestB64u',
    ],
    label,
  );
  return {
    operationId: parseLaneOperationId(record.operationId, `${label}.operationId`),
    walletKeyId: parseKeyId(record.walletKeyId, `${label}.walletKeyId`),
    targetLaneId: parseLaneId(record.targetLaneId, `${label}.targetLaneId`),
    targetLaneShareEpoch: parseShareEpoch(
      record.targetLaneShareEpoch,
      `${label}.targetLaneShareEpoch`,
    ),
    targetMaterialActivation: parseMpcActivation(
      record.targetMaterialActivation,
      `${label}.targetMaterialActivation`,
    ),
    revocationEpoch: requiredInteger(record.revocationEpoch, `${label}.revocationEpoch`),
    retirementReceiptDigestB64u: digest(
      record.retirementReceiptDigestB64u,
      `${label}.retirementReceiptDigestB64u`,
    ),
  };
}

export function parseAggregateLaneRevocationReceiptV1(
  raw: unknown,
  label = 'aggregateRevocationReceipt',
): AggregateLaneRevocationReceiptV1 {
  const record = exactRecord(
    raw,
    [
      'kind',
      'enrollmentId',
      'walletId',
      'manifestDigestB64u',
      'orderedChildReceipts',
      'revokedAtMs',
    ],
    label,
  );
  if (record.kind !== 'aggregate_lane_revocation_receipt_v1')
    throw new Error(`${label}.kind is invalid`);
  const childrenRaw = requiredArray(record.orderedChildReceipts, `${label}.orderedChildReceipts`);
  if (childrenRaw.length === 0) throw new Error(`${label}.orderedChildReceipts must be non-empty`);
  const orderedChildReceipts = nonEmptyTuple(
    childrenRaw.map((child, index) =>
      parseAggregateRevocationChild(child, `${label}.orderedChildReceipts[${index}]`),
    ),
    `${label}.orderedChildReceipts`,
  );
  return {
    kind: 'aggregate_lane_revocation_receipt_v1',
    enrollmentId: parseEnrollmentId(record.enrollmentId, `${label}.enrollmentId`),
    walletId: resultValue(parseWalletId(record.walletId), `${label}.walletId`),
    manifestDigestB64u: digest(record.manifestDigestB64u, `${label}.manifestDigestB64u`),
    orderedChildReceipts,
    revokedAtMs: requiredInteger(record.revokedAtMs, `${label}.revokedAtMs`),
  };
}

export function parseRevokeLaneEnrollmentV1(
  raw: unknown,
  label = 'revokeLaneEnrollment',
): RevokeLaneEnrollmentV1 {
  const record = exactRecord(
    raw,
    ['kind', 'enrollmentId', 'walletId', 'manifestDigestB64u', 'reason', 'requestedAtMs'],
    label,
  );
  if (record.kind !== 'revoke_lane_enrollment_v1') throw new Error(`${label}.kind is invalid`);
  const reason = record.reason;
  if (
    reason !== 'cancelled_after_commit' &&
    reason !== 'expired_after_commit' &&
    reason !== 'revoked_during_activation' &&
    reason !== 'user_revoked' &&
    reason !== 'device_compromise' &&
    reason !== 'agent_compromise'
  ) {
    throw new Error(`${label}.reason is invalid`);
  }
  return {
    kind: 'revoke_lane_enrollment_v1',
    enrollmentId: parseEnrollmentId(record.enrollmentId, `${label}.enrollmentId`),
    walletId: resultValue(parseWalletId(record.walletId), `${label}.walletId`),
    manifestDigestB64u: digest(record.manifestDigestB64u, `${label}.manifestDigestB64u`),
    reason,
    requestedAtMs: requiredInteger(record.requestedAtMs, `${label}.requestedAtMs`),
  };
}

export function parseRevokeSigningLaneV1(
  raw: unknown,
  label = 'revokeSigningLane',
): RevokeSigningLaneV1 {
  const record = exactRecord(
    raw,
    [
      'kind',
      'walletId',
      'walletKeyId',
      'laneId',
      'laneShareEpoch',
      'expectedRevocationEpoch',
      'reason',
      'retirementCorrelationId',
      'retirementRequestDigestB64u',
      'retirementEffectBindingDigestB64u',
      'requestedAtMs',
    ],
    label,
  );
  if (record.kind !== 'revoke_signing_lane_v1') throw new Error(`${label}.kind is invalid`);
  const reason = record.reason;
  if (
    reason !== 'user_revoked' &&
    reason !== 'policy_revoked' &&
    reason !== 'device_compromise' &&
    reason !== 'agent_compromise' &&
    reason !== 'rotation'
  ) {
    throw new Error(`${label}.reason is invalid`);
  }
  return {
    kind: 'revoke_signing_lane_v1',
    walletId: resultValue(parseWalletId(record.walletId), `${label}.walletId`),
    walletKeyId: parseKeyId(record.walletKeyId, `${label}.walletKeyId`),
    laneId: parseLaneId(record.laneId, `${label}.laneId`),
    laneShareEpoch: parseShareEpoch(record.laneShareEpoch, `${label}.laneShareEpoch`),
    expectedRevocationEpoch: requiredInteger(
      record.expectedRevocationEpoch,
      `${label}.expectedRevocationEpoch`,
    ),
    reason,
    retirementCorrelationId: parseCorrelationId(record.retirementCorrelationId),
    retirementRequestDigestB64u: digest(
      record.retirementRequestDigestB64u,
      `${label}.retirementRequestDigestB64u`,
    ),
    retirementEffectBindingDigestB64u: digest(
      record.retirementEffectBindingDigestB64u,
      `${label}.retirementEffectBindingDigestB64u`,
    ),
    requestedAtMs: requiredInteger(record.requestedAtMs, `${label}.requestedAtMs`),
  };
}

export function parseCompleteSigningLaneRevocationV1(
  raw: unknown,
  label = 'completeSigningLaneRevocation',
): CompleteSigningLaneRevocationV1 {
  const record = exactRecord(
    raw,
    ['kind', 'command', 'expectedVersion', 'commandDigestB64u', 'retirementReceipt', 'revokedAtMs'],
    label,
  );
  if (record.kind !== 'complete_signing_lane_revocation_v1')
    throw new Error(`${label}.kind is invalid`);
  return {
    kind: 'complete_signing_lane_revocation_v1',
    command: parseRevokeSigningLaneV1(record.command, `${label}.command`),
    expectedVersion: requiredInteger(record.expectedVersion, `${label}.expectedVersion`),
    commandDigestB64u: digest(record.commandDigestB64u, `${label}.commandDigestB64u`),
    retirementReceipt: parseLaneServerRetirementReceiptV1(
      record.retirementReceipt,
      `${label}.retirementReceipt`,
    ),
    revokedAtMs: requiredInteger(record.revokedAtMs, `${label}.revokedAtMs`),
  };
}

export function parseCommitLaneEnrollmentRevocationV1(
  raw: unknown,
  label = 'commitLaneEnrollmentRevocation',
): CommitLaneEnrollmentRevocationV1 {
  const record = exactRecord(
    raw,
    ['kind', 'enrollmentId', 'walletId', 'manifestDigestB64u', 'receipt', 'revokedAtMs'],
    label,
  );
  if (record.kind !== 'commit_lane_enrollment_revocation_v1')
    throw new Error(`${label}.kind is invalid`);
  const receipt = parseAggregateLaneRevocationReceiptV1(record.receipt, `${label}.receipt`);
  const enrollmentId = parseEnrollmentId(record.enrollmentId, `${label}.enrollmentId`);
  const walletId = resultValue(parseWalletId(record.walletId), `${label}.walletId`);
  if (
    String(receipt.enrollmentId) !== String(enrollmentId) ||
    String(receipt.walletId) !== String(walletId)
  ) {
    throw new Error(`${label}.receipt identity does not match command`);
  }
  return {
    kind: 'commit_lane_enrollment_revocation_v1',
    enrollmentId,
    walletId,
    manifestDigestB64u: digest(record.manifestDigestB64u, `${label}.manifestDigestB64u`),
    receipt,
    revokedAtMs: requiredInteger(record.revokedAtMs, `${label}.revokedAtMs`),
  };
}

function parseProductEpochCommon(
  record: UnknownRecord,
  label: string,
): LaneProductEpochRecordCommonV1 {
  return {
    kind: 'lane_product_epoch_record_v1' as const,
    walletId: resultValue(parseWalletId(record.walletId), `${label}.walletId`),
    walletKeyId: parseKeyId(record.walletKeyId, `${label}.walletKeyId`),
    laneId: parseLaneId(record.laneId, `${label}.laneId`),
    laneKind: parseLaneKind(record.laneKind, `${label}.laneKind`),
    laneShareEpoch: parseShareEpoch(record.laneShareEpoch, `${label}.laneShareEpoch`),
    keyFamily: parseKeyFamily(record.keyFamily, `${label}.keyFamily`),
    enrollmentId: parseEnrollmentId(record.enrollmentId, `${label}.enrollmentId`),
    operationId: parseLaneOperationId(record.operationId, `${label}.operationId`),
    targetMaterialActivationId: resultValue(
      parseMpcMaterialActivationId(record.targetMaterialActivationId),
      `${label}.targetMaterialActivationId`,
    ),
    materialActivation: parseMpcActivation(
      record.materialActivation,
      `${label}.materialActivation`,
    ),
    publicIdentityDigestB64u: digest(
      record.publicIdentityDigestB64u,
      `${label}.publicIdentityDigestB64u`,
    ),
    holderParticipant: parseLaneHolderParticipantRecordV1(
      record.holderParticipant,
      `${label}.holderParticipant`,
    ),
    signingWorkerParticipant: parseSigningWorkerParticipantRecordV1(
      record.signingWorkerParticipant,
      `${label}.signingWorkerParticipant`,
    ),
    participantSetBindingDigestB64u: resultValue(
      parseLaneParticipantBindingDigestB64u(record.participantSetBindingDigestB64u),
      `${label}.participantSetBindingDigestB64u`,
    ),
    revocationEpoch: requiredInteger(record.revocationEpoch, `${label}.revocationEpoch`),
    createdAtMs: requiredInteger(record.createdAtMs, `${label}.createdAtMs`),
  };
}

function parseProductRevocationReason(
  raw: unknown,
  label: string,
): LaneProductEpochRevokedV1['revocationReason'] {
  if (
    raw !== 'user_revoked' &&
    raw !== 'policy_revoked' &&
    raw !== 'device_compromise' &&
    raw !== 'agent_compromise' &&
    raw !== 'rotation'
  )
    throw new Error(`${label}.revocationReason is invalid`);
  return raw;
}

export function parseLaneProductEpochRecordV1(
  raw: unknown,
  label = 'laneProductEpochRecord',
): LaneProductEpochRecordV1 {
  const record = requireRecord(raw, label);
  switch (record.state) {
    case 'pending_visibility': {
      const value = exactRecord(
        record,
        [
          'kind',
          'walletId',
          'walletKeyId',
          'laneId',
          'laneKind',
          'laneShareEpoch',
          'keyFamily',
          'enrollmentId',
          'operationId',
          'targetMaterialActivationId',
          'materialActivation',
          'publicIdentityDigestB64u',
          'holderParticipant',
          'signingWorkerParticipant',
          'participantSetBindingDigestB64u',
          'revocationEpoch',
          'createdAtMs',
          'state',
          'aggregateManifestDigestB64u',
          'protocolCommitReceiptDigestB64u',
          'holderDeliveryReceiptDigestB64u',
          'serverActivationReceiptDigestB64u',
          'pendingSinceMs',
        ],
        label,
      );
      if (value.kind !== 'lane_product_epoch_record_v1')
        throw new Error(`${label}.kind is invalid`);
      return {
        ...parseProductEpochCommon(value, label),
        state: 'pending_visibility',
        aggregateManifestDigestB64u: digest(
          value.aggregateManifestDigestB64u,
          `${label}.aggregateManifestDigestB64u`,
        ),
        protocolCommitReceiptDigestB64u: digest(
          value.protocolCommitReceiptDigestB64u,
          `${label}.protocolCommitReceiptDigestB64u`,
        ),
        holderDeliveryReceiptDigestB64u: digest(
          value.holderDeliveryReceiptDigestB64u,
          `${label}.holderDeliveryReceiptDigestB64u`,
        ),
        serverActivationReceiptDigestB64u: digest(
          value.serverActivationReceiptDigestB64u,
          `${label}.serverActivationReceiptDigestB64u`,
        ),
        pendingSinceMs: requiredInteger(value.pendingSinceMs, `${label}.pendingSinceMs`),
      };
    }
    case 'active': {
      const value = exactRecord(
        record,
        [
          'kind',
          'walletId',
          'walletKeyId',
          'laneId',
          'laneKind',
          'laneShareEpoch',
          'keyFamily',
          'enrollmentId',
          'operationId',
          'targetMaterialActivationId',
          'materialActivation',
          'publicIdentityDigestB64u',
          'holderParticipant',
          'signingWorkerParticipant',
          'participantSetBindingDigestB64u',
          'revocationEpoch',
          'createdAtMs',
          'state',
          'aggregateManifestDigestB64u',
          'aggregateActivationReceiptDigestB64u',
          'activatedAtMs',
        ],
        label,
      );
      if (value.kind !== 'lane_product_epoch_record_v1')
        throw new Error(`${label}.kind is invalid`);
      return {
        ...parseProductEpochCommon(value, label),
        state: 'active',
        aggregateManifestDigestB64u: digest(
          value.aggregateManifestDigestB64u,
          `${label}.aggregateManifestDigestB64u`,
        ),
        aggregateActivationReceiptDigestB64u: digest(
          value.aggregateActivationReceiptDigestB64u,
          `${label}.aggregateActivationReceiptDigestB64u`,
        ),
        activatedAtMs: requiredInteger(value.activatedAtMs, `${label}.activatedAtMs`),
      };
    }
    case 'retired': {
      const value = exactRecord(
        record,
        [
          'kind',
          'walletId',
          'walletKeyId',
          'laneId',
          'laneKind',
          'laneShareEpoch',
          'keyFamily',
          'enrollmentId',
          'operationId',
          'targetMaterialActivationId',
          'materialActivation',
          'publicIdentityDigestB64u',
          'holderParticipant',
          'signingWorkerParticipant',
          'participantSetBindingDigestB64u',
          'revocationEpoch',
          'createdAtMs',
          'state',
          'retirementReason',
          'retirementReceiptDigestB64u',
          'retiredAtMs',
        ],
        label,
      );
      if (value.kind !== 'lane_product_epoch_record_v1')
        throw new Error(`${label}.kind is invalid`);
      if (
        value.retirementReason !== 'rotation' &&
        value.retirementReason !== 'device_compromise' &&
        value.retirementReason !== 'agent_compromise'
      )
        throw new Error(`${label}.retirementReason is invalid`);
      return {
        ...parseProductEpochCommon(value, label),
        state: 'retired',
        retirementReason: value.retirementReason,
        retirementReceiptDigestB64u: digest(
          value.retirementReceiptDigestB64u,
          `${label}.retirementReceiptDigestB64u`,
        ),
        retiredAtMs: requiredInteger(value.retiredAtMs, `${label}.retiredAtMs`),
      };
    }
    case 'revocation_pending': {
      const value = exactRecord(
        record,
        [
          'kind',
          'walletId',
          'walletKeyId',
          'laneId',
          'laneKind',
          'laneShareEpoch',
          'keyFamily',
          'enrollmentId',
          'operationId',
          'targetMaterialActivationId',
          'materialActivation',
          'publicIdentityDigestB64u',
          'holderParticipant',
          'signingWorkerParticipant',
          'participantSetBindingDigestB64u',
          'revocationEpoch',
          'createdAtMs',
          'state',
          'revocationReason',
          'retirementEffectBindingDigestB64u',
          'revocationRequestedAtMs',
        ],
        label,
      );
      if (value.kind !== 'lane_product_epoch_record_v1')
        throw new Error(`${label}.kind is invalid`);
      const reason = parseProductRevocationReason(value.revocationReason, label);
      return {
        ...parseProductEpochCommon(value, label),
        state: 'revocation_pending',
        revocationEpoch: requiredInteger(value.revocationEpoch, `${label}.revocationEpoch`),
        revocationReason: reason,
        retirementEffectBindingDigestB64u: digest(
          value.retirementEffectBindingDigestB64u,
          `${label}.retirementEffectBindingDigestB64u`,
        ),
        revocationRequestedAtMs: requiredInteger(
          value.revocationRequestedAtMs,
          `${label}.revocationRequestedAtMs`,
        ),
      };
    }
    case 'revoked': {
      const value = exactRecord(
        record,
        [
          'kind',
          'walletId',
          'walletKeyId',
          'laneId',
          'laneKind',
          'laneShareEpoch',
          'keyFamily',
          'enrollmentId',
          'operationId',
          'targetMaterialActivationId',
          'materialActivation',
          'publicIdentityDigestB64u',
          'holderParticipant',
          'signingWorkerParticipant',
          'participantSetBindingDigestB64u',
          'revocationEpoch',
          'createdAtMs',
          'state',
          'revocationReason',
          'retirementEffectBindingDigestB64u',
          'revocationReceiptDigestB64u',
          'revokedAtMs',
        ],
        label,
      );
      if (value.kind !== 'lane_product_epoch_record_v1')
        throw new Error(`${label}.kind is invalid`);
      const reason = parseProductRevocationReason(value.revocationReason, label);
      return {
        ...parseProductEpochCommon(value, label),
        state: 'revoked',
        revocationEpoch: requiredInteger(value.revocationEpoch, `${label}.revocationEpoch`),
        revocationReason: reason,
        retirementEffectBindingDigestB64u: digest(
          value.retirementEffectBindingDigestB64u,
          `${label}.retirementEffectBindingDigestB64u`,
        ),
        revocationReceiptDigestB64u: digest(
          value.revocationReceiptDigestB64u,
          `${label}.revocationReceiptDigestB64u`,
        ),
        revokedAtMs: requiredInteger(value.revokedAtMs, `${label}.revokedAtMs`),
      };
    }
    default:
      throw new Error(`${label}.state is invalid`);
  }
}

export function parseLaneProtocolLifecycleV1(
  raw: unknown,
  label = 'laneProtocolLifecycle',
): LaneProtocolLifecycle {
  const record = requireRecord(raw, label);
  switch (record.state) {
    case 'preparing': {
      const value = exactRecord(record, ['state', 'startedAtMs'], label);
      return {
        state: 'preparing',
        startedAtMs: requiredInteger(value.startedAtMs, `${label}.startedAtMs`),
      };
    }
    case 'awaiting_protocol_commitment': {
      const value = exactRecord(record, ['state', 'startedAtMs'], label);
      return {
        state: 'awaiting_protocol_commitment',
        startedAtMs: requiredInteger(value.startedAtMs, `${label}.startedAtMs`),
      };
    }
    case 'committed_awaiting_holder_delivery': {
      const value = exactRecord(
        record,
        [
          'state',
          'startedAtMs',
          'committedAtMs',
          'transcriptHashB64u',
          'protocolCommitReceiptDigestB64u',
        ],
        label,
      );
      return {
        state: 'committed_awaiting_holder_delivery',
        startedAtMs: requiredInteger(value.startedAtMs, `${label}.startedAtMs`),
        committedAtMs: requiredInteger(value.committedAtMs, `${label}.committedAtMs`),
        transcriptHashB64u: digest(value.transcriptHashB64u, `${label}.transcriptHashB64u`),
        protocolCommitReceiptDigestB64u: digest(
          value.protocolCommitReceiptDigestB64u,
          `${label}.protocolCommitReceiptDigestB64u`,
        ),
      };
    }
    case 'awaiting_server_activation': {
      const value = exactRecord(
        record,
        [
          'state',
          'startedAtMs',
          'committedAtMs',
          'transcriptHashB64u',
          'protocolCommitReceiptDigestB64u',
          'holderDeliveryReceiptDigestB64u',
          'holderReceiptAtMs',
        ],
        label,
      );
      return {
        state: 'awaiting_server_activation',
        startedAtMs: requiredInteger(value.startedAtMs, `${label}.startedAtMs`),
        committedAtMs: requiredInteger(value.committedAtMs, `${label}.committedAtMs`),
        transcriptHashB64u: digest(value.transcriptHashB64u, `${label}.transcriptHashB64u`),
        protocolCommitReceiptDigestB64u: digest(
          value.protocolCommitReceiptDigestB64u,
          `${label}.protocolCommitReceiptDigestB64u`,
        ),
        holderDeliveryReceiptDigestB64u: digest(
          value.holderDeliveryReceiptDigestB64u,
          `${label}.holderDeliveryReceiptDigestB64u`,
        ),
        holderReceiptAtMs: requiredInteger(value.holderReceiptAtMs, `${label}.holderReceiptAtMs`),
      };
    }
    case 'ready_for_parent_visibility': {
      const value = exactRecord(
        record,
        [
          'state',
          'startedAtMs',
          'committedAtMs',
          'transcriptHashB64u',
          'protocolCommitReceiptDigestB64u',
          'holderDeliveryReceiptDigestB64u',
          'holderReceiptAtMs',
          'serverActivationReceiptDigestB64u',
          'serverActivatedAtMs',
        ],
        label,
      );
      return {
        state: 'ready_for_parent_visibility',
        startedAtMs: requiredInteger(value.startedAtMs, `${label}.startedAtMs`),
        committedAtMs: requiredInteger(value.committedAtMs, `${label}.committedAtMs`),
        transcriptHashB64u: digest(value.transcriptHashB64u, `${label}.transcriptHashB64u`),
        protocolCommitReceiptDigestB64u: digest(
          value.protocolCommitReceiptDigestB64u,
          `${label}.protocolCommitReceiptDigestB64u`,
        ),
        holderDeliveryReceiptDigestB64u: digest(
          value.holderDeliveryReceiptDigestB64u,
          `${label}.holderDeliveryReceiptDigestB64u`,
        ),
        holderReceiptAtMs: requiredInteger(value.holderReceiptAtMs, `${label}.holderReceiptAtMs`),
        serverActivationReceiptDigestB64u: digest(
          value.serverActivationReceiptDigestB64u,
          `${label}.serverActivationReceiptDigestB64u`,
        ),
        serverActivatedAtMs: requiredInteger(
          value.serverActivatedAtMs,
          `${label}.serverActivatedAtMs`,
        ),
      };
    }
    case 'active': {
      const value = exactRecord(
        record,
        [
          'state',
          'transcriptHashB64u',
          'protocolCommitReceiptDigestB64u',
          'holderDeliveryReceiptDigestB64u',
          'serverActivationReceiptDigestB64u',
          'aggregateActivationReceiptDigestB64u',
          'activatedAtMs',
        ],
        label,
      );
      return {
        state: 'active',
        transcriptHashB64u: digest(value.transcriptHashB64u, `${label}.transcriptHashB64u`),
        protocolCommitReceiptDigestB64u: digest(
          value.protocolCommitReceiptDigestB64u,
          `${label}.protocolCommitReceiptDigestB64u`,
        ),
        holderDeliveryReceiptDigestB64u: digest(
          value.holderDeliveryReceiptDigestB64u,
          `${label}.holderDeliveryReceiptDigestB64u`,
        ),
        serverActivationReceiptDigestB64u: digest(
          value.serverActivationReceiptDigestB64u,
          `${label}.serverActivationReceiptDigestB64u`,
        ),
        aggregateActivationReceiptDigestB64u: digest(
          value.aggregateActivationReceiptDigestB64u,
          `${label}.aggregateActivationReceiptDigestB64u`,
        ),
        activatedAtMs: requiredInteger(value.activatedAtMs, `${label}.activatedAtMs`),
      };
    }
    case 'aborted_precommit': {
      const value = exactRecord(
        record,
        ['state', 'startedAtMs', 'abortedAtMs', 'abortReason'],
        label,
      );
      if (
        value.abortReason !== 'cancelled' &&
        value.abortReason !== 'expired' &&
        value.abortReason !== 'revoked_before_commit'
      )
        throw new Error(`${label}.abortReason is invalid`);
      return {
        state: 'aborted_precommit',
        startedAtMs: requiredInteger(value.startedAtMs, `${label}.startedAtMs`),
        abortedAtMs: requiredInteger(value.abortedAtMs, `${label}.abortedAtMs`),
        abortReason: value.abortReason,
      };
    }
    case 'committed_completion_required': {
      const value = exactRecord(
        record,
        [
          'state',
          'startedAtMs',
          'committedAtMs',
          'transcriptHashB64u',
          'protocolCommitReceiptDigestB64u',
          'recoveryReason',
        ],
        label,
      );
      if (
        value.recoveryReason !== 'exact_redelivery_required' &&
        value.recoveryReason !== 'recovery_required'
      )
        throw new Error(`${label}.recoveryReason is invalid`);
      return {
        state: 'committed_completion_required',
        startedAtMs: requiredInteger(value.startedAtMs, `${label}.startedAtMs`),
        committedAtMs: requiredInteger(value.committedAtMs, `${label}.committedAtMs`),
        transcriptHashB64u: digest(value.transcriptHashB64u, `${label}.transcriptHashB64u`),
        protocolCommitReceiptDigestB64u: digest(
          value.protocolCommitReceiptDigestB64u,
          `${label}.protocolCommitReceiptDigestB64u`,
        ),
        recoveryReason: value.recoveryReason,
      };
    }
    default:
      throw new Error(`${label}.state is invalid`);
  }
}

export function parseLaneEnrollmentLifecycleV1(
  raw: unknown,
  label = 'laneEnrollmentLifecycle',
): LaneEnrollmentLifecycleV1 {
  const record = requireRecord(raw, label);
  switch (record.state) {
    case 'preparing': {
      const value = exactRecord(record, ['state', 'manifestDigestB64u', 'startedAtMs'], label);
      return {
        state: 'preparing',
        manifestDigestB64u: digest(value.manifestDigestB64u, `${label}.manifestDigestB64u`),
        startedAtMs: requiredInteger(value.startedAtMs, `${label}.startedAtMs`),
      };
    }
    case 'committed_completion_required': {
      const value = exactRecord(
        record,
        ['state', 'manifestDigestB64u', 'committedChildOperationIds', 'markedAtMs'],
        label,
      );
      const ids = requiredArray(
        value.committedChildOperationIds,
        `${label}.committedChildOperationIds`,
      );
      if (ids.length === 0)
        throw new Error(`${label}.committedChildOperationIds must be non-empty`);
      return {
        state: 'committed_completion_required',
        manifestDigestB64u: digest(value.manifestDigestB64u, `${label}.manifestDigestB64u`),
        committedChildOperationIds: nonEmptyTuple(
          ids.map((id, index) =>
            parseLaneOperationId(id, `${label}.committedChildOperationIds[${index}]`),
          ),
          `${label}.committedChildOperationIds`,
        ),
        markedAtMs: requiredInteger(value.markedAtMs, `${label}.markedAtMs`),
      };
    }
    case 'ready_for_visibility': {
      const value = exactRecord(
        record,
        ['state', 'manifestDigestB64u', 'aggregateReceiptDigestB64u', 'readyAtMs'],
        label,
      );
      return {
        state: 'ready_for_visibility',
        manifestDigestB64u: digest(value.manifestDigestB64u, `${label}.manifestDigestB64u`),
        aggregateReceiptDigestB64u: digest(
          value.aggregateReceiptDigestB64u,
          `${label}.aggregateReceiptDigestB64u`,
        ),
        readyAtMs: requiredInteger(value.readyAtMs, `${label}.readyAtMs`),
      };
    }
    case 'active': {
      const value = exactRecord(
        record,
        ['state', 'manifestDigestB64u', 'aggregateReceiptDigestB64u', 'activatedAtMs'],
        label,
      );
      return {
        state: 'active',
        manifestDigestB64u: digest(value.manifestDigestB64u, `${label}.manifestDigestB64u`),
        aggregateReceiptDigestB64u: digest(
          value.aggregateReceiptDigestB64u,
          `${label}.aggregateReceiptDigestB64u`,
        ),
        activatedAtMs: requiredInteger(value.activatedAtMs, `${label}.activatedAtMs`),
      };
    }
    case 'cancelled_precommit': {
      const value = exactRecord(record, ['state', 'cancelledAtMs'], label);
      return {
        state: 'cancelled_precommit',
        cancelledAtMs: requiredInteger(value.cancelledAtMs, `${label}.cancelledAtMs`),
      };
    }
    case 'revoking_committed_targets': {
      const value = exactRecord(
        record,
        ['state', 'manifestDigestB64u', 'reason', 'markedAtMs'],
        label,
      );
      if (
        value.reason !== 'cancelled_after_commit' &&
        value.reason !== 'expired_after_commit' &&
        value.reason !== 'revoked_during_activation'
      )
        throw new Error(`${label}.reason is invalid`);
      return {
        state: 'revoking_committed_targets',
        manifestDigestB64u: digest(value.manifestDigestB64u, `${label}.manifestDigestB64u`),
        reason: value.reason,
        markedAtMs: requiredInteger(value.markedAtMs, `${label}.markedAtMs`),
      };
    }
    case 'revoked': {
      const value = exactRecord(
        record,
        ['state', 'manifestDigestB64u', 'aggregateRevocationReceiptDigestB64u', 'revokedAtMs'],
        label,
      );
      return {
        state: 'revoked',
        manifestDigestB64u: digest(value.manifestDigestB64u, `${label}.manifestDigestB64u`),
        aggregateRevocationReceiptDigestB64u: digest(
          value.aggregateRevocationReceiptDigestB64u,
          `${label}.aggregateRevocationReceiptDigestB64u`,
        ),
        revokedAtMs: requiredInteger(value.revokedAtMs, `${label}.revokedAtMs`),
      };
    }
    default:
      throw new Error(`${label}.state is invalid`);
  }
}

export function buildLaneProtocolRecordV1(args: {
  readonly job: RotatableSigningLaneJobV1;
  readonly lifecycle: LaneProtocolLifecycle;
}): LaneProtocolRecordV1 {
  return { job: args.job, lifecycle: args.lifecycle };
}

export function parseLaneProtocolRecordV1(
  raw: unknown,
  label = 'laneProtocolRecord',
): LaneProtocolRecordV1 {
  const record = exactRecord(raw, ['job', 'lifecycle'], label);
  return {
    job: parseRotatableSigningLaneJobV1(record.job, `${label}.job`),
    lifecycle: parseLaneProtocolLifecycleV1(record.lifecycle, `${label}.lifecycle`),
  };
}

export function buildRotatableSigningLaneJobV1(
  raw: unknown,
  label = 'laneProtocolJob',
): RotatableSigningLaneJobV1 {
  return parseRotatableSigningLaneJobV1(raw, label);
}

export function buildLaneProtocolCommitReceiptV1(
  args: Omit<LaneProtocolCommitReceiptV1, 'kind'>,
): LaneProtocolCommitReceiptV1 {
  return parseLaneProtocolCommitReceiptV1({ kind: 'lane_protocol_commit_receipt_v1', ...args });
}

export function buildLaneHolderDeliveryReceiptV1(
  args: Omit<LaneHolderDeliveryReceiptV1, 'kind'>,
): LaneHolderDeliveryReceiptV1 {
  return parseLaneHolderDeliveryReceiptV1({ kind: 'lane_holder_delivery_receipt_v1', ...args });
}

export function buildLaneServerActivationReceiptV1(
  args: Omit<LaneServerActivationReceiptV1, 'kind'>,
): LaneServerActivationReceiptV1 {
  return parseLaneServerActivationReceiptV1({ kind: 'lane_server_activation_receipt_v1', ...args });
}

export function buildLaneEnrollmentManifestV1(
  args: Omit<LaneEnrollmentManifestV1, 'kind'>,
): LaneEnrollmentManifestV1 {
  return parseLaneEnrollmentManifestV1({ kind: 'lane_enrollment_manifest_v1', ...args });
}

export function buildAggregateLaneActivationReceiptV1(
  args: Omit<AggregateLaneActivationReceiptV1, 'kind'>,
): AggregateLaneActivationReceiptV1 {
  return parseAggregateLaneActivationReceiptV1({
    kind: 'aggregate_lane_activation_receipt_v1',
    ...args,
  });
}

export function buildCommitLaneEnrollmentActivationV1(
  args: Omit<CommitLaneEnrollmentActivationV1, 'kind'>,
): CommitLaneEnrollmentActivationV1 {
  return parseCommitLaneEnrollmentActivationV1({
    kind: 'commit_lane_enrollment_activation_v1',
    ...args,
  });
}

export function buildAggregateLaneRevocationReceiptV1(
  args: Omit<AggregateLaneRevocationReceiptV1, 'kind'>,
): AggregateLaneRevocationReceiptV1 {
  return parseAggregateLaneRevocationReceiptV1({
    kind: 'aggregate_lane_revocation_receipt_v1',
    ...args,
  });
}

export function buildRevokeLaneEnrollmentV1(
  args: Omit<RevokeLaneEnrollmentV1, 'kind'>,
): RevokeLaneEnrollmentV1 {
  return parseRevokeLaneEnrollmentV1({ kind: 'revoke_lane_enrollment_v1', ...args });
}

export function buildRevokeSigningLaneV1(
  args: Omit<RevokeSigningLaneV1, 'kind'>,
): RevokeSigningLaneV1 {
  return parseRevokeSigningLaneV1({ kind: 'revoke_signing_lane_v1', ...args });
}

export function buildCompleteSigningLaneRevocationV1(
  args: Omit<CompleteSigningLaneRevocationV1, 'kind'>,
): CompleteSigningLaneRevocationV1 {
  return parseCompleteSigningLaneRevocationV1({
    kind: 'complete_signing_lane_revocation_v1',
    ...args,
  });
}

export function buildCommitLaneEnrollmentRevocationV1(
  args: Omit<CommitLaneEnrollmentRevocationV1, 'kind'>,
): CommitLaneEnrollmentRevocationV1 {
  return parseCommitLaneEnrollmentRevocationV1({
    kind: 'commit_lane_enrollment_revocation_v1',
    ...args,
  });
}

export function buildLaneProductEpochPendingVisibilityV1(
  args: Omit<LaneProductEpochPendingVisibilityV1, 'kind' | 'state'>,
): LaneProductEpochPendingVisibilityV1 {
  const value = parseLaneProductEpochRecordV1({
    kind: 'lane_product_epoch_record_v1',
    state: 'pending_visibility',
    ...args,
  });
  if (value.state !== 'pending_visibility') throw new Error('product epoch state changed');
  return value;
}

export function buildLaneProductEpochActiveV1(
  args: Omit<LaneProductEpochActiveV1, 'kind' | 'state'>,
): LaneProductEpochActiveV1 {
  const value = parseLaneProductEpochRecordV1({
    kind: 'lane_product_epoch_record_v1',
    state: 'active',
    ...args,
  });
  if (value.state !== 'active') throw new Error('product epoch state changed');
  return value;
}

export function buildLaneProductEpochRetiredV1(
  args: Omit<LaneProductEpochRetiredV1, 'kind' | 'state'>,
): LaneProductEpochRetiredV1 {
  const value = parseLaneProductEpochRecordV1({
    kind: 'lane_product_epoch_record_v1',
    state: 'retired',
    ...args,
  });
  if (value.state !== 'retired') throw new Error('product epoch state changed');
  return value;
}

export function buildLaneProductEpochRevocationPendingV1(
  args: Omit<LaneProductEpochRevocationPendingV1, 'kind' | 'state'>,
): LaneProductEpochRevocationPendingV1 {
  const value = parseLaneProductEpochRecordV1({
    kind: 'lane_product_epoch_record_v1',
    state: 'revocation_pending',
    ...args,
  });
  if (value.state !== 'revocation_pending') throw new Error('product epoch state changed');
  return value;
}

export function buildLaneProductEpochRevokedV1(
  args: Omit<LaneProductEpochRevokedV1, 'kind' | 'state'>,
): LaneProductEpochRevokedV1 {
  const value = parseLaneProductEpochRecordV1({
    kind: 'lane_product_epoch_record_v1',
    state: 'revoked',
    ...args,
  });
  if (value.state !== 'revoked') throw new Error('product epoch state changed');
  return value;
}

export function parseEcdsaAdditiveLaneTranscriptPreambleV1(
  raw: unknown,
  label = 'ecdsaPreamble',
): EcdsaAdditiveLaneTranscriptPreambleV1 {
  const record = exactRecord(raw, ['kind', 'job'], label);
  if (record.kind !== 'ecdsa_additive_lane_transcript_preamble_v1')
    throw new Error(`${label}.kind is invalid`);
  return {
    kind: 'ecdsa_additive_lane_transcript_preamble_v1',
    job: parseEcdsaJob(requireRecord(record.job, `${label}.job`), `${label}.job`),
  };
}

export function parseEcdsaAdditiveLaneHolderRoundV1(
  raw: unknown,
  label = 'ecdsaHolderRound',
): EcdsaAdditiveLaneHolderRoundV1 {
  const record = exactRecord(
    raw,
    [
      'kind',
      'preambleHashB64u',
      'targetHolderPublicCommitment33B64u',
      'encryptedDeltaCiphertextDigestB64u',
      'sealedTargetHolderMaterialDigestB64u',
      'holderAttestationB64u',
      'holderCommittedAtMs',
    ],
    label,
  );
  if (record.kind !== 'ecdsa_additive_lane_holder_round_v1')
    throw new Error(`${label}.kind is invalid`);
  return {
    kind: 'ecdsa_additive_lane_holder_round_v1',
    preambleHashB64u: digest(record.preambleHashB64u, `${label}.preambleHashB64u`),
    targetHolderPublicCommitment33B64u: parseSecp256k1CompressedPublicKeyB64u(
      record.targetHolderPublicCommitment33B64u,
    ),
    encryptedDeltaCiphertextDigestB64u: digest(
      record.encryptedDeltaCiphertextDigestB64u,
      `${label}.encryptedDeltaCiphertextDigestB64u`,
    ),
    sealedTargetHolderMaterialDigestB64u: digest(
      record.sealedTargetHolderMaterialDigestB64u,
      `${label}.sealedTargetHolderMaterialDigestB64u`,
    ),
    holderAttestationB64u: requiredString(
      record.holderAttestationB64u,
      `${label}.holderAttestationB64u`,
    ),
    holderCommittedAtMs: requiredInteger(
      record.holderCommittedAtMs,
      `${label}.holderCommittedAtMs`,
    ),
  };
}

export function parseEcdsaAdditiveLaneServerRoundV1(
  raw: unknown,
  label = 'ecdsaServerRound',
): EcdsaAdditiveLaneServerRoundV1 {
  const record = exactRecord(
    raw,
    [
      'kind',
      'preambleHashB64u',
      'holderRoundHashB64u',
      'targetServerPublicCommitment33B64u',
      'sealedTargetServerMaterialDigestB64u',
      'targetThresholdSessionSetDigestB64u',
      'publicIdentityRelationDigestB64u',
      'serverAttestationB64u',
      'serverCommittedAtMs',
    ],
    label,
  );
  if (record.kind !== 'ecdsa_additive_lane_server_round_v1')
    throw new Error(`${label}.kind is invalid`);
  return {
    kind: 'ecdsa_additive_lane_server_round_v1',
    preambleHashB64u: digest(record.preambleHashB64u, `${label}.preambleHashB64u`),
    holderRoundHashB64u: digest(record.holderRoundHashB64u, `${label}.holderRoundHashB64u`),
    targetServerPublicCommitment33B64u: parseSecp256k1CompressedPublicKeyB64u(
      record.targetServerPublicCommitment33B64u,
    ),
    sealedTargetServerMaterialDigestB64u: digest(
      record.sealedTargetServerMaterialDigestB64u,
      `${label}.sealedTargetServerMaterialDigestB64u`,
    ),
    targetThresholdSessionSetDigestB64u: digest(
      record.targetThresholdSessionSetDigestB64u,
      `${label}.targetThresholdSessionSetDigestB64u`,
    ),
    publicIdentityRelationDigestB64u: digest(
      record.publicIdentityRelationDigestB64u,
      `${label}.publicIdentityRelationDigestB64u`,
    ),
    serverAttestationB64u: requiredString(
      record.serverAttestationB64u,
      `${label}.serverAttestationB64u`,
    ),
    serverCommittedAtMs: requiredInteger(
      record.serverCommittedAtMs,
      `${label}.serverCommittedAtMs`,
    ),
  };
}

export function parseEcdsaAdditiveLaneTranscriptV1(
  raw: unknown,
  label = 'ecdsaTranscript',
): EcdsaAdditiveLaneTranscriptV1 {
  const record = exactRecord(
    raw,
    ['kind', 'preambleHashB64u', 'holderRoundHashB64u', 'serverRoundHashB64u'],
    label,
  );
  if (record.kind !== 'ecdsa_additive_lane_transcript_v1')
    throw new Error(`${label}.kind is invalid`);
  return {
    kind: 'ecdsa_additive_lane_transcript_v1',
    preambleHashB64u: digest(record.preambleHashB64u, `${label}.preambleHashB64u`),
    holderRoundHashB64u: digest(record.holderRoundHashB64u, `${label}.holderRoundHashB64u`),
    serverRoundHashB64u: digest(record.serverRoundHashB64u, `${label}.serverRoundHashB64u`),
  };
}

export function parseEcdsaServerRetirementReceiptV1(
  raw: unknown,
  label = 'ecdsaRetirementReceipt',
): EcdsaServerRetirementReceiptV1 {
  const record = exactRecord(
    raw,
    [
      'kind',
      'manifest',
      'materialActivation',
      'walletKeyId',
      'laneId',
      'laneShareEpoch',
      'revocationEpoch',
      'retirementReason',
      'retirementCorrelationId',
      'retirementRequestDigestB64u',
      'serverGeneration',
      'lifecycleId',
      'receiptDigestB64u',
      'retiredAt',
    ],
    label,
  );
  if (record.kind !== 'ecdsa_server_retirement_receipt_v1')
    throw new Error(`${label}.kind is invalid`);
  const manifest = exactRecord(
    record.manifest,
    ['manifestId', 'manifestRevision'],
    `${label}.manifest`,
  );
  const retirementReason = record.retirementReason;
  if (
    retirementReason !== 'lane_revoked' &&
    retirementReason !== 'device_compromise' &&
    retirementReason !== 'agent_compromise' &&
    retirementReason !== 'rotation'
  )
    throw new Error(`${label}.retirementReason is invalid`);
  return {
    kind: 'ecdsa_server_retirement_receipt_v1',
    manifest: {
      manifestId: parseEcdsaCapabilityManifestId(manifest.manifestId),
      manifestRevision: parseEcdsaCapabilityManifestRevision(manifest.manifestRevision),
    },
    materialActivation: parseMpcActivation(
      record.materialActivation,
      `${label}.materialActivation`,
    ),
    walletKeyId: parseKeyId(record.walletKeyId, `${label}.walletKeyId`),
    laneId: parseLaneId(record.laneId, `${label}.laneId`),
    laneShareEpoch: parseShareEpoch(record.laneShareEpoch, `${label}.laneShareEpoch`),
    revocationEpoch: requiredInteger(record.revocationEpoch, `${label}.revocationEpoch`),
    retirementReason,
    retirementCorrelationId: parseCorrelationId(record.retirementCorrelationId),
    retirementRequestDigestB64u: digest(
      record.retirementRequestDigestB64u,
      `${label}.retirementRequestDigestB64u`,
    ),
    serverGeneration: parseEcdsaServerGeneration(record.serverGeneration),
    lifecycleId: parseEcdsaLifecycleId(record.lifecycleId),
    receiptDigestB64u: digest(record.receiptDigestB64u, `${label}.receiptDigestB64u`),
    retiredAt: parseIso(record.retiredAt, `${label}.retiredAt`),
  };
}

export function parseSigningWorkerLaneMaterialIdentityV1<
  TKeyFamily extends 'ed25519' | 'ecdsa_secp256k1',
>(
  raw: unknown,
  expectedKeyFamily: TKeyFamily,
  label = 'signingWorkerLaneMaterialIdentity',
): SigningWorkerLaneMaterialIdentityV1<TKeyFamily> {
  const record = exactRecord(
    raw,
    [
      'operationId',
      'enrollmentId',
      'walletId',
      'walletKeyId',
      'targetLaneId',
      'targetLaneShareEpoch',
      'targetMaterialActivationId',
      'keyFamily',
      'holderParticipantBindingDigestB64u',
      'signingWorkerParticipantBindingDigestB64u',
      'holderRecipientKeyDigestB64u',
      'serverRecipientKeyDigestB64u',
      'transcriptHashB64u',
      'protocolCommitReceiptDigestB64u',
    ],
    label,
  );
  if (record.keyFamily !== expectedKeyFamily) throw new Error(`${label}.keyFamily is invalid`);
  return {
    operationId: resultValue(
      parseLaneOperationIdFromIds(record.operationId),
      `${label}.operationId`,
    ),
    enrollmentId: resultValue(
      parseLaneEnrollmentIdFromIds(record.enrollmentId),
      `${label}.enrollmentId`,
    ),
    walletId: resultValue(parseWalletId(record.walletId), `${label}.walletId`),
    walletKeyId: resultValue(parseWalletKeyIdFromIds(record.walletKeyId), `${label}.walletKeyId`),
    targetLaneId: resultValue(
      parseSigningLaneIdFromIds(record.targetLaneId),
      `${label}.targetLaneId`,
    ),
    targetLaneShareEpoch: resultValue(
      parseLaneShareEpochFromIds(record.targetLaneShareEpoch),
      `${label}.targetLaneShareEpoch`,
    ),
    targetMaterialActivationId: resultValue(
      parseMpcMaterialActivationId(record.targetMaterialActivationId),
      `${label}.targetMaterialActivationId`,
    ),
    keyFamily: expectedKeyFamily,
    holderParticipantBindingDigestB64u: digest(
      record.holderParticipantBindingDigestB64u,
      `${label}.holderParticipantBindingDigestB64u`,
    ),
    signingWorkerParticipantBindingDigestB64u: digest(
      record.signingWorkerParticipantBindingDigestB64u,
      `${label}.signingWorkerParticipantBindingDigestB64u`,
    ),
    holderRecipientKeyDigestB64u: digest(
      record.holderRecipientKeyDigestB64u,
      `${label}.holderRecipientKeyDigestB64u`,
    ),
    serverRecipientKeyDigestB64u: digest(
      record.serverRecipientKeyDigestB64u,
      `${label}.serverRecipientKeyDigestB64u`,
    ),
    transcriptHashB64u: digest(record.transcriptHashB64u, `${label}.transcriptHashB64u`),
    protocolCommitReceiptDigestB64u: digest(
      record.protocolCommitReceiptDigestB64u,
      `${label}.protocolCommitReceiptDigestB64u`,
    ),
  };
}

export function parseEd25519ServerRetirementReceiptV1(
  raw: unknown,
  label = 'ed25519RetirementReceipt',
): Ed25519ServerRetirementReceiptV1 {
  const record = exactRecord(
    raw,
    [
      'kind',
      'identity',
      'revocationEpoch',
      'retirementReason',
      'retirementCorrelationId',
      'retirementRequestDigestB64u',
      'receiptDigestB64u',
      'retiredAtMs',
    ],
    label,
  );
  if (record.kind !== 'ed25519_server_retirement_receipt_v1')
    throw new Error(`${label}.kind is invalid`);
  const retirementReason = record.retirementReason;
  if (
    retirementReason !== 'lane_revoked' &&
    retirementReason !== 'device_compromise' &&
    retirementReason !== 'agent_compromise' &&
    retirementReason !== 'rotation'
  )
    throw new Error(`${label}.retirementReason is invalid`);
  return {
    kind: 'ed25519_server_retirement_receipt_v1',
    identity: parseSigningWorkerLaneMaterialIdentityV1(
      record.identity,
      'ed25519',
      `${label}.identity`,
    ),
    revocationEpoch: requiredInteger(record.revocationEpoch, `${label}.revocationEpoch`),
    retirementReason,
    retirementCorrelationId: parseCorrelationId(record.retirementCorrelationId),
    retirementRequestDigestB64u: digest(
      record.retirementRequestDigestB64u,
      `${label}.retirementRequestDigestB64u`,
    ),
    receiptDigestB64u: digest(record.receiptDigestB64u, `${label}.receiptDigestB64u`),
    retiredAtMs: requiredInteger(record.retiredAtMs, `${label}.retiredAtMs`),
  };
}

export function parseLaneServerRetirementReceiptV1(
  raw: unknown,
  label = 'laneServerRetirementReceipt',
): LaneServerRetirementReceiptV1 {
  const record = requireRecord(raw, label);
  switch (record.kind) {
    case 'ecdsa_server_retirement_receipt_v1':
      return parseEcdsaServerRetirementReceiptV1(record, label);
    case 'ed25519_server_retirement_receipt_v1':
      return parseEd25519ServerRetirementReceiptV1(record, label);
    default:
      throw new Error(`${label}.kind is invalid`);
  }
}
