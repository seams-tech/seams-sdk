import type {
  LinkedDeviceOwnerSourceChildResolutionV1,
  LinkedDeviceTargetEnrichedChildResolutionV1,
} from './d1LinkedDeviceTargetPlanner';
import type { EcdsaSourceCapabilityBindingV1 } from '@shared/signing-lanes/rotation';
import { parseEcdsaTargetCapabilityBindingV1 } from '@shared/signing-lanes/rotationParsers';
import {
  parseLaneShareEpoch,
  parseMpcMaterialActivationRef,
  parseSigningLaneId,
  parseWalletKeyId,
} from '@shared/utils/domainIds';
import { parseAuthorizedOperationId } from '@shared/authorization/capabilityKinds';
import {
  parseLaneHolderParticipantId,
  parseLaneParticipantBindingDigestB64u,
  parseSigningWorkerParticipantId,
  parseSigningWorkerRecipientKeyId,
  parseHpkePublicKeyB64u,
  parseSigningWorkerRecipientKeyDigestB64u,
} from '@shared/signing-lanes/participants';
import { parseDigestB64u, type DigestB64u } from '@shared/utils/canonicalPrimitives';
import {
  parseEd25519PublicKeyB64u,
  parseKeyCreationSignerSlot,
  parseSecp256k1CompressedPublicKeyB64u,
} from '@shared/passkey-custody/primitives';
import { parseNearEd25519SigningKeyId } from '@shared/utils/registrationIntent';
import {
  parseEd25519YaoSuiteId,
  parseEcdsaRelayerKeyId,
  parseLaneOperationIdempotencyKey,
} from '@shared/signing-lanes/ids';
import { parseEvmFamilySigningKeySlotId } from '@shared/signing-lanes/evmFamilySigningKeySlotId';
import {
  parseEcdsaCapabilityManifestId,
  parseEcdsaCapabilityManifestRevision,
  parseEcdsaServerGeneration,
} from '@shared/utils/ecdsaCapabilityActivation';
import { parseSdkEcdsaDerivationThresholdKeyId } from '@shared/threshold/ecdsaDerivationRoleLocalBootstrap';
import { parseOwnerLaneParticipantContinuityV1 } from '@shared/signing-lanes/ownerContinuity';

export function parseLinkedDeviceOwnerSourceChildResolutionV1(
  raw: unknown,
  label = 'sourceChild',
): LinkedDeviceOwnerSourceChildResolutionV1 {
  const record = requireRecord(raw, label);
  const sourceRecord = stripPersistedTargetFacts(record);
  const keyFamily = sourceRecord.keyFamily;
  if (keyFamily !== 'ed25519' && keyFamily !== 'ecdsa_secp256k1')
    throw new Error(`${label}.keyFamily is invalid`);
  const common = {
    walletKeyId: parseRequired(parseWalletKeyId(sourceRecord.walletKeyId), `${label}.walletKeyId`),
    source: parseSource(sourceRecord.source, `${label}.source`),
    authorization: parseAuthorization(sourceRecord.authorization, `${label}.authorization`),
  };
  if (keyFamily === 'ed25519') {
    const value = exactRecord(
      sourceRecord,
      [
        'walletKeyId',
        'source',
        'authorization',
        'keyFamily',
        'registeredPublicKeyB64u',
        'nearEd25519SigningKeyId',
        'keyCreationSignerSlot',
        'stableContextBindingB64u',
      ],
      label,
    );
    return {
      ...common,
      keyFamily,
      registeredPublicKeyB64u: parseEd25519PublicKeyB64u(value.registeredPublicKeyB64u),
      nearEd25519SigningKeyId: parseNearEd25519SigningKeyId(value.nearEd25519SigningKeyId),
      keyCreationSignerSlot: parseKeyCreationSignerSlot(value.keyCreationSignerSlot),
      stableContextBindingB64u: parseDigest(
        value.stableContextBindingB64u,
        `${label}.stableContextBindingB64u`,
      ),
    };
  }
  const value = exactRecord(
    sourceRecord,
    [
      'walletKeyId',
      'source',
      'authorization',
      'keyFamily',
      'evmFamilySigningKeySlotId',
      'thresholdPublicKey33B64u',
      'evmAddress',
      'sourceCapability',
      'sourceHolderVerifyingShare33B64u',
      'sourceServerVerifyingShare33B64u',
    ],
    label,
  );
  return {
    ...common,
    keyFamily,
    evmFamilySigningKeySlotId: parseRequired(
      parseEvmFamilySigningKeySlotId(value.evmFamilySigningKeySlotId),
      `${label}.evmFamilySigningKeySlotId`,
    ),
    thresholdPublicKey33B64u: parseSecp256k1CompressedPublicKeyB64u(value.thresholdPublicKey33B64u),
    evmAddress: parseRequiredString(value.evmAddress, `${label}.evmAddress`),
    sourceCapability: parseSourceCapability(value.sourceCapability, `${label}.sourceCapability`),
    sourceHolderVerifyingShare33B64u: parseSecp256k1CompressedPublicKeyB64u(
      value.sourceHolderVerifyingShare33B64u,
    ),
    sourceServerVerifyingShare33B64u: parseSecp256k1CompressedPublicKeyB64u(
      value.sourceServerVerifyingShare33B64u,
    ),
  };
}

function stripPersistedTargetFacts(record: Record<string, unknown>): Record<string, unknown> {
  const {
    targetHolderParticipantId: _targetHolderParticipantId,
    targetSigningWorker: _targetSigningWorker,
    targetCapability: _targetCapability,
    ...sourceRecord
  } = record;
  return sourceRecord;
}

export function parseLinkedDeviceTargetEnrichedChildResolutionV1(
  raw: unknown,
  label = 'targetChild',
): LinkedDeviceTargetEnrichedChildResolutionV1 {
  const record = requireRecord(raw, label);
  const source = parseLinkedDeviceOwnerSourceChildResolutionV1(
    sourceRecordForTargetEnrichment(record),
    `${label}.source`,
  );
  const targetHolderParticipantId = parseRequired(
    parseLaneHolderParticipantId(record.targetHolderParticipantId),
    `${label}.targetHolderParticipantId`,
  );
  const targetSigningWorker = parseTargetSigningWorker(
    record.targetSigningWorker,
    `${label}.targetSigningWorker`,
  );
  if (source.keyFamily === 'ed25519') {
    exactRecord(
      record,
      [
        'walletKeyId',
        'source',
        'authorization',
        'keyFamily',
        'registeredPublicKeyB64u',
        'nearEd25519SigningKeyId',
        'keyCreationSignerSlot',
        'stableContextBindingB64u',
        'yaoSuiteId',
        'circuitDigestB64u',
        'targetHolderParticipantId',
        'targetSigningWorker',
      ],
      label,
    );
    return {
      ...source,
      keyFamily: 'ed25519',
      targetHolderParticipantId,
      targetSigningWorker,
      yaoSuiteId: parseRequired(parseEd25519YaoSuiteId(record.yaoSuiteId), `${label}.yaoSuiteId`),
      circuitDigestB64u: parseDigest(record.circuitDigestB64u, `${label}.circuitDigestB64u`),
    };
  }
  const value = exactRecord(
    record,
    [
      'walletKeyId',
      'source',
      'authorization',
      'keyFamily',
      'evmFamilySigningKeySlotId',
      'thresholdPublicKey33B64u',
      'evmAddress',
      'sourceCapability',
      'sourceHolderVerifyingShare33B64u',
      'sourceServerVerifyingShare33B64u',
      'reshareChannelBindingDigestB64u',
      'targetHolderParticipantId',
      'targetSigningWorker',
      'targetCapability',
    ],
    label,
  );
  return {
    ...source,
    keyFamily: 'ecdsa_secp256k1',
    targetHolderParticipantId,
    targetSigningWorker,
    targetCapability: parseEcdsaTargetCapabilityBindingV1(
      value.targetCapability,
      `${label}.targetCapability`,
    ),
    reshareChannelBindingDigestB64u: parseDigest(
      value.reshareChannelBindingDigestB64u,
      `${label}.reshareChannelBindingDigestB64u`,
    ),
  };
}

function sourceRecordForTargetEnrichment(record: Record<string, unknown>): Record<string, unknown> {
  const keyFamily = record.keyFamily;
  if (keyFamily === 'ed25519') {
    return {
      walletKeyId: record.walletKeyId,
      source: record.source,
      authorization: record.authorization,
      keyFamily,
      registeredPublicKeyB64u: record.registeredPublicKeyB64u,
      nearEd25519SigningKeyId: record.nearEd25519SigningKeyId,
      keyCreationSignerSlot: record.keyCreationSignerSlot,
      stableContextBindingB64u: record.stableContextBindingB64u,
    };
  }
  return {
    walletKeyId: record.walletKeyId,
    source: record.source,
    authorization: record.authorization,
    keyFamily,
    evmFamilySigningKeySlotId: record.evmFamilySigningKeySlotId,
    thresholdPublicKey33B64u: record.thresholdPublicKey33B64u,
    evmAddress: record.evmAddress,
    sourceCapability: record.sourceCapability,
    sourceHolderVerifyingShare33B64u: record.sourceHolderVerifyingShare33B64u,
    sourceServerVerifyingShare33B64u: record.sourceServerVerifyingShare33B64u,
  };
}

function parseTargetSigningWorker(
  raw: unknown,
  label: string,
): LinkedDeviceTargetEnrichedChildResolutionV1['targetSigningWorker'] {
  const record = exactRecord(
    raw,
    [
      'participantId',
      'participantBindingDigestB64u',
      'recipientKeyId',
      'hpkePublicKeyB64u',
      'hpkePublicKeyDigestB64u',
    ],
    label,
  );
  return {
    participantId: parseRequired(
      parseSigningWorkerParticipantId(record.participantId),
      `${label}.participantId`,
    ),
    participantBindingDigestB64u: parseRequired(
      parseLaneParticipantBindingDigestB64u(record.participantBindingDigestB64u),
      `${label}.participantBindingDigestB64u`,
    ),
    recipientKeyId: parseRequired(
      parseSigningWorkerRecipientKeyId(record.recipientKeyId),
      `${label}.recipientKeyId`,
    ),
    hpkePublicKeyB64u: parseRequired(
      parseHpkePublicKeyB64u(record.hpkePublicKeyB64u),
      `${label}.hpkePublicKeyB64u`,
    ),
    hpkePublicKeyDigestB64u: parseRequired(
      parseSigningWorkerRecipientKeyDigestB64u(record.hpkePublicKeyDigestB64u),
      `${label}.hpkePublicKeyDigestB64u`,
    ),
  };
}

function parseSource(
  raw: unknown,
  label: string,
): LinkedDeviceOwnerSourceChildResolutionV1['source'] {
  const baseRecord = requireRecord(raw, label);
  const sourceKind = baseRecord.sourceKind;
  if (sourceKind !== 'owner_registration' && sourceKind !== 'provisioned_lane') {
    throw new Error(`${label}.sourceKind is invalid`);
  }
  const record = exactRecord(
    baseRecord,
    sourceKind === 'owner_registration'
      ? ([
          'laneId',
          'laneKind',
          'laneShareEpoch',
          'revocationEpoch',
          'sourceKind',
          'participantBindingDigestB64u',
          'materialActivation',
          'ownerParticipantContinuity',
        ] as const)
      : ([
          'laneId',
          'laneKind',
          'laneShareEpoch',
          'revocationEpoch',
          'sourceKind',
          'participantBindingDigestB64u',
          'materialActivation',
          'holderParticipantId',
          'signingWorkerParticipantId',
          'signingWorkerRecipientKeyId',
        ] as const),
    label,
  );
  const laneKind = record.laneKind;
  if (
    laneKind !== 'owner_passkey' &&
    laneKind !== 'owner_email_otp' &&
    laneKind !== 'linked_device' &&
    laneKind !== 'delegated_execution' &&
    laneKind !== 'recovery' &&
    laneKind !== 'break_glass'
  )
    throw new Error(`${label}.laneKind is invalid`);
  const materialActivation = parseMpcMaterialActivationRef(record.materialActivation);
  const common = {
    laneId: parseRequired(parseSigningLaneId(record.laneId), `${label}.laneId`),
    laneShareEpoch: parseRequired(
      parseLaneShareEpoch(record.laneShareEpoch),
      `${label}.laneShareEpoch`,
    ),
    revocationEpoch: requiredNonNegativeInteger(record.revocationEpoch, `${label}.revocationEpoch`),
    participantBindingDigestB64u: parseRequired(
      parseLaneParticipantBindingDigestB64u(record.participantBindingDigestB64u),
      `${label}.participantBindingDigestB64u`,
    ),
    materialActivation: parseRequired(materialActivation, `${label}.materialActivation`),
  };
  if (sourceKind === 'owner_registration') {
    if (laneKind !== 'owner_passkey' && laneKind !== 'owner_email_otp') {
      throw new Error(`${label}.laneKind must be owner for owner_registration`);
    }
    return {
      ...common,
      sourceKind: 'owner_registration',
      laneKind,
      ownerParticipantContinuity: parseOwnerLaneParticipantContinuityV1(
        record.ownerParticipantContinuity,
        `${label}.ownerParticipantContinuity`,
      ),
    };
  }
  if (laneKind === 'owner_passkey' || laneKind === 'owner_email_otp') {
    throw new Error(`${label}.laneKind must be provisioned for provisioned_lane`);
  }
  return {
    ...common,
    sourceKind: 'provisioned_lane',
    laneKind,
    holderParticipantId: parseRequired(
      parseLaneHolderParticipantId(record.holderParticipantId),
      `${label}.holderParticipantId`,
    ),
    signingWorkerParticipantId: parseRequired(
      parseSigningWorkerParticipantId(record.signingWorkerParticipantId),
      `${label}.signingWorkerParticipantId`,
    ),
    signingWorkerRecipientKeyId: parseRequired(
      parseSigningWorkerRecipientKeyId(record.signingWorkerRecipientKeyId),
      `${label}.signingWorkerRecipientKeyId`,
    ),
  };
}

function parseAuthorization(
  raw: unknown,
  label: string,
): LinkedDeviceOwnerSourceChildResolutionV1['authorization'] {
  const record = exactRecord(
    raw,
    ['authorizedOperationId', 'idempotencyKey', 'linkedDevicePermissionDigestB64u'],
    label,
  );
  return {
    authorizedOperationId: parseRequired(
      parseAuthorizedOperationId(record.authorizedOperationId),
      `${label}.authorizedOperationId`,
    ),
    idempotencyKey: parseRequired(
      parseLaneOperationIdempotencyKey(record.idempotencyKey),
      `${label}.idempotencyKey`,
    ),
    linkedDevicePermissionDigestB64u: parseDigest(
      record.linkedDevicePermissionDigestB64u,
      `${label}.linkedDevicePermissionDigestB64u`,
    ),
  };
}

function parseSourceCapability(raw: unknown, label: string): EcdsaSourceCapabilityBindingV1 {
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
    relayerKeyId: parseRequired(
      parseEcdsaRelayerKeyId(record.relayerKeyId),
      `${label}.relayerKeyId`,
    ),
  };
}

function parseDigest(raw: unknown, label: string): DigestB64u {
  try {
    return parseDigestB64u(raw);
  } catch {
    throw new Error(`${label} is invalid`);
  }
}
function parseRequired<T>(
  result:
    | { readonly ok: true; readonly value: T }
    | { readonly ok: false; readonly error: { readonly message: string } },
  label: string,
): T {
  if (result.ok) return result.value;
  throw new Error(`${label}: ${result.error.message}`);
}
function parseRequiredString(raw: unknown, label: string): string {
  if (typeof raw !== 'string' || !raw.trim() || raw.trim() !== raw)
    throw new Error(`${label} is invalid`);
  return raw;
}
function requiredNonNegativeInteger(raw: unknown, label: string): number {
  const value = typeof raw === 'number' ? raw : Number(raw);
  if (!Number.isSafeInteger(value) || value < 0) throw new Error(`${label} is invalid`);
  return value;
}
function requireRecord(raw: unknown, label: string): Record<string, unknown> {
  if (!raw || typeof raw !== 'object' || Array.isArray(raw))
    throw new Error(`${label} must be an object`);
  return raw as Record<string, unknown>;
}
function exactRecord(
  raw: unknown,
  fields: readonly string[],
  label: string,
): Record<string, unknown> {
  const record = requireRecord(raw, label);
  const allowed = new Set(fields);
  for (const key of Object.keys(record))
    if (!allowed.has(key)) throw new Error(`${label}.${key} is unsupported`);
  for (const field of fields)
    if (!(field in record)) throw new Error(`${label}.${field} is required`);
  return record;
}
