import { base64UrlDecode, base64UrlEncode } from '@shared/utils/base64';
import {
  thresholdEcdsaChainTargetKey,
  thresholdEcdsaChainTargetsEqual,
  thresholdEcdsaChainTargetFromRequest,
  toWalletId,
} from '../signingEngine/interfaces/ecdsaChainTarget';
import { toRpId } from '../signingEngine/session/identity/evmFamilyEcdsaIdentity';
import {
  toEcdsaHssSigningRootId,
  toEcdsaHssSigningRootVersion,
  toEcdsaHssThresholdKeyId,
} from '../signingEngine/session/identity/emailOtpHssIdentity';
import {
  parseRawThresholdEcdsaSessionRecord,
  thresholdEcdsaRecordRpId,
  type ThresholdEcdsaSessionRecord,
} from '../signingEngine/session/persistence/records';
import type {
  EcdsaRoleLocalPublicFacts,
  EcdsaRoleLocalRecordParseResult,
  EcdsaRoleLocalReadyRecord,
  EcdsaRoleLocalReadyStateBlob,
  LoadEcdsaRoleLocalReadyRecordInput,
} from './types';
import type {
  EcdsaHssClientSharePublicKey33B64u,
  EcdsaRelayerHssPublicKey33B64u,
} from '@shared/threshold/ecdsaHssRoleLocalBootstrap';

type RoleLocalLegacyState = NonNullable<
  ThresholdEcdsaSessionRecord['ecdsaHssRoleLocalClientState']
>;

export type EcdsaRoleLocalExportMaterial = {
  readyRecord: EcdsaRoleLocalReadyRecord;
  contextBinding32B64u: string;
  clientShareRetryCounter: number;
};

export type EcdsaRoleLocalWorkerExportMaterial = EcdsaRoleLocalExportMaterial & {
  roleLocalState: RoleLocalLegacyState;
};

function isRecord(value: unknown): value is Record<string, unknown> {
  return Boolean(value && typeof value === 'object' && !Array.isArray(value));
}

function requiredString(value: unknown, field: string): string {
  const normalized = String(value ?? '').trim();
  if (!normalized) {
    throw new Error(`[platform][ecdsa-role-local] ${field} is required`);
  }
  return normalized;
}

function parseBase64UrlBytes(value: unknown, field: string, byteLength: number): string {
  const normalized = requiredString(value, field);
  const decoded = base64UrlDecode(normalized);
  if (decoded.length !== byteLength) {
    throw new Error(`[platform][ecdsa-role-local] ${field} must decode to ${byteLength} bytes`);
  }
  return normalized;
}

function parseHssClientSharePublicKey(
  value: unknown,
): EcdsaHssClientSharePublicKey33B64u {
  return parseBase64UrlBytes(
    value,
    'hssClientSharePublicKey33B64u',
    33,
  ) as EcdsaHssClientSharePublicKey33B64u;
}

function parseRelayerHssPublicKey(value: unknown): EcdsaRelayerHssPublicKey33B64u {
  return parseBase64UrlBytes(
    value,
    'relayerPublicKey33B64u',
    33,
  ) as EcdsaRelayerHssPublicKey33B64u;
}

function parseGroupPublicKey(value: unknown): string {
  return parseBase64UrlBytes(value, 'groupPublicKey33B64u', 33);
}

function parseEthereumAddress(value: unknown): `0x${string}` {
  const normalized = requiredString(value, 'ethereumAddress').toLowerCase();
  if (!/^0x[0-9a-f]{40}$/.test(normalized)) {
    throw new Error('[platform][ecdsa-role-local] ethereumAddress must be an EVM address');
  }
  return normalized as `0x${string}`;
}

function parseParticipantIds(value: unknown): readonly [1, 2] {
  if (!Array.isArray(value) || value.length !== 2 || value[0] !== 1 || value[1] !== 2) {
    throw new Error('[platform][ecdsa-role-local] participantIds must be [1, 2]');
  }
  return [1, 2] as const;
}

function parseReadyStateBlob(input: unknown): EcdsaRoleLocalReadyStateBlob {
  if (!isRecord(input)) {
    throw new Error('[platform][ecdsa-role-local] stateBlob must be an object');
  }
  const kind = requiredString(input.kind, 'stateBlob.kind');
  const curve = requiredString(input.curve, 'stateBlob.curve');
  const encoding = requiredString(input.encoding, 'stateBlob.encoding');
  const producer = requiredString(input.producer, 'stateBlob.producer');
  const stateBlobB64u = requiredString(input.stateBlobB64u, 'stateBlob.stateBlobB64u');
  if (
    kind !== 'ecdsa_role_local_state_blob_v1' ||
    curve !== 'secp256k1' ||
    encoding !== 'base64url' ||
    producer !== 'signer_core'
  ) {
    throw new Error('[platform][ecdsa-role-local] stateBlob envelope is invalid');
  }
  try {
    base64UrlDecode(stateBlobB64u);
  } catch (error) {
    throw new Error('[platform][ecdsa-role-local] stateBlob payload is not base64url', {
      cause: error,
    });
  }
  return {
    kind: 'ecdsa_role_local_state_blob_v1',
    curve: 'secp256k1',
    encoding: 'base64url',
    producer: 'signer_core',
    stateBlobB64u,
  };
}

function parsePublicFacts(input: unknown): EcdsaRoleLocalPublicFacts {
  if (!isRecord(input)) {
    throw new Error('[platform][ecdsa-role-local] publicFacts must be an object');
  }
  return {
    walletId: toWalletId(input.walletId),
    rpId: toRpId(input.rpId),
    chainTarget: thresholdEcdsaChainTargetFromRequest(
      isRecord(input.chainTarget) ? input.chainTarget : {},
    ),
    keyHandle: requiredString(input.keyHandle, 'keyHandle'),
    ecdsaThresholdKeyId: toEcdsaHssThresholdKeyId(input.ecdsaThresholdKeyId),
    signingRootId: toEcdsaHssSigningRootId(input.signingRootId),
    signingRootVersion: toEcdsaHssSigningRootVersion(input.signingRootVersion),
    clientParticipantId: 1,
    relayerParticipantId: 2,
    participantIds: parseParticipantIds(input.participantIds),
    hssClientSharePublicKey33B64u: parseHssClientSharePublicKey(
      input.hssClientSharePublicKey33B64u,
    ),
    relayerPublicKey33B64u: parseRelayerHssPublicKey(input.relayerPublicKey33B64u),
    groupPublicKey33B64u: parseGroupPublicKey(input.groupPublicKey33B64u),
    ethereumAddress: parseEthereumAddress(input.ethereumAddress),
  };
}

function roleLocalReadyStateBlobFromLegacy(args: {
  state: RoleLocalLegacyState;
  publicFacts: EcdsaRoleLocalPublicFacts;
}): EcdsaRoleLocalReadyStateBlob {
  const payload = {
    kind: 'legacy_threshold_ecdsa_role_local_ready_state_v1',
    contextBinding32B64u: parseBase64UrlBytes(
      args.state.contextBinding32B64u,
      'contextBinding32B64u',
      32,
    ),
    clientShareRetryCounter: Math.max(0, Math.floor(Number(args.state.clientShareRetryCounter))),
    clientPublicKey33B64u: parseHssClientSharePublicKey(args.state.clientPublicKey33B64u),
    relayerPublicKey33B64u: parseRelayerHssPublicKey(args.state.relayerPublicKey33B64u),
    groupPublicKey33B64u: parseGroupPublicKey(args.state.groupPublicKey33B64u),
    ethereumAddress: parseEthereumAddress(args.state.ethereumAddress),
    publicFacts: serializeEcdsaRoleLocalPublicFacts(args.publicFacts),
  };
  return {
    kind: 'ecdsa_role_local_state_blob_v1',
    curve: 'secp256k1',
    encoding: 'base64url',
    producer: 'signer_core',
    stateBlobB64u: base64UrlEncode(new TextEncoder().encode(JSON.stringify(payload))),
  };
}

export function parseEcdsaRoleLocalReadyRecord(input: unknown): EcdsaRoleLocalReadyRecord {
  if (!isRecord(input)) {
    throw new Error('[platform][ecdsa-role-local] ready record must be an object');
  }
  const kind = requiredString(input.kind, 'readyRecord.kind');
  if (kind !== 'ecdsa_role_local_ready_record_v1') {
    throw new Error('[platform][ecdsa-role-local] ready record kind is invalid');
  }
  return {
    kind: 'ecdsa_role_local_ready_record_v1',
    stateBlob: parseReadyStateBlob(input.stateBlob),
    publicFacts: parsePublicFacts(input.publicFacts),
  };
}

function thresholdEcdsaSessionRecordAsRoleLocalReadyRecord(
  record: ThresholdEcdsaSessionRecord,
): EcdsaRoleLocalReadyRecord {
  const state = record.ecdsaHssRoleLocalClientState;
  if (!state) {
    throw new Error('[platform][ecdsa-role-local] session record is missing role-local state');
  }
  const publicFacts: EcdsaRoleLocalPublicFacts = {
    walletId: toWalletId(record.walletId),
    rpId: toRpId(thresholdEcdsaRecordRpId(record)),
    chainTarget: record.chainTarget,
    keyHandle: requiredString(record.keyHandle, 'keyHandle'),
    ecdsaThresholdKeyId: toEcdsaHssThresholdKeyId(record.ecdsaThresholdKeyId),
    signingRootId: toEcdsaHssSigningRootId(record.signingRootId),
    signingRootVersion: toEcdsaHssSigningRootVersion(record.signingRootVersion),
    clientParticipantId: 1,
    relayerParticipantId: 2,
    participantIds: parseParticipantIds(record.participantIds),
    hssClientSharePublicKey33B64u: parseHssClientSharePublicKey(state.clientPublicKey33B64u),
    relayerPublicKey33B64u: parseRelayerHssPublicKey(state.relayerPublicKey33B64u),
    groupPublicKey33B64u: parseGroupPublicKey(state.groupPublicKey33B64u),
    ethereumAddress: parseEthereumAddress(state.ethereumAddress),
  };
  return {
    kind: 'ecdsa_role_local_ready_record_v1',
    stateBlob: roleLocalReadyStateBlobFromLegacy({ state, publicFacts }),
    publicFacts,
  };
}

export function parseThresholdEcdsaSessionRecordAsRoleLocalReadyRecord(
  input: unknown,
): EcdsaRoleLocalReadyRecord {
  return thresholdEcdsaSessionRecordAsRoleLocalReadyRecord(
    parseRawThresholdEcdsaSessionRecord(input),
  );
}

export function parseThresholdEcdsaSessionRecordAsRoleLocalExportMaterial(
  input: unknown,
): EcdsaRoleLocalExportMaterial {
  return thresholdEcdsaSessionRecordAsRoleLocalExportMaterial(
    parseRawThresholdEcdsaSessionRecord(input),
  );
}

function thresholdEcdsaSessionRecordAsRoleLocalExportMaterial(
  record: ThresholdEcdsaSessionRecord,
): EcdsaRoleLocalExportMaterial {
  const state = record.ecdsaHssRoleLocalClientState;
  if (!state) {
    throw new Error('[platform][ecdsa-role-local] session record is missing role-local state');
  }
  return {
    readyRecord: thresholdEcdsaSessionRecordAsRoleLocalReadyRecord(record),
    contextBinding32B64u: parseBase64UrlBytes(
      state.contextBinding32B64u,
      'contextBinding32B64u',
      32,
    ),
    clientShareRetryCounter: Math.max(0, Math.floor(Number(state.clientShareRetryCounter))),
  };
}

export function parseThresholdEcdsaSessionRecordAsRoleLocalWorkerExportMaterial(
  input: unknown,
): EcdsaRoleLocalWorkerExportMaterial {
  const record = parseRawThresholdEcdsaSessionRecord(input);
  const state = record.ecdsaHssRoleLocalClientState;
  if (!state) {
    throw new Error('[platform][ecdsa-role-local] session record is missing role-local state');
  }
  return {
    ...thresholdEcdsaSessionRecordAsRoleLocalExportMaterial(record),
    roleLocalState: state,
  };
}

export function parseRawEcdsaRoleLocalRecord(input: unknown): EcdsaRoleLocalRecordParseResult {
  try {
    return {
      ok: true,
      source: 'ready_record',
      record: parseEcdsaRoleLocalReadyRecord(input),
    };
  } catch (readyRecordError) {
    try {
      return {
        ok: true,
        source: 'legacy_threshold_ecdsa_session_record',
        record: parseThresholdEcdsaSessionRecordAsRoleLocalReadyRecord(input),
      };
    } catch (legacyRecordError) {
      let message = '[platform][ecdsa-role-local] malformed role-local record';
      if (legacyRecordError instanceof Error) {
        message = legacyRecordError.message;
      } else if (readyRecordError instanceof Error) {
        message = readyRecordError.message;
      }
      return {
        ok: false,
        code: 'malformed_record',
        message,
      };
    }
  }
}

export function serializeEcdsaRoleLocalPublicFacts(
  facts: EcdsaRoleLocalPublicFacts,
): Record<string, unknown> {
  return {
    walletId: facts.walletId,
    rpId: facts.rpId,
    chainTarget: facts.chainTarget,
    keyHandle: facts.keyHandle,
    ecdsaThresholdKeyId: facts.ecdsaThresholdKeyId,
    signingRootId: facts.signingRootId,
    signingRootVersion: facts.signingRootVersion,
    clientParticipantId: 1,
    relayerParticipantId: 2,
    participantIds: [1, 2],
    hssClientSharePublicKey33B64u: facts.hssClientSharePublicKey33B64u,
    relayerPublicKey33B64u: facts.relayerPublicKey33B64u,
    groupPublicKey33B64u: facts.groupPublicKey33B64u,
    ethereumAddress: facts.ethereumAddress,
  };
}

export function serializeEcdsaRoleLocalReadyRecord(
  record: EcdsaRoleLocalReadyRecord,
): Record<string, unknown> {
  const parsed = parseEcdsaRoleLocalReadyRecord(record);
  return {
    kind: 'ecdsa_role_local_ready_record_v1',
    stateBlob: {
      kind: parsed.stateBlob.kind,
      curve: parsed.stateBlob.curve,
      encoding: parsed.stateBlob.encoding,
      producer: parsed.stateBlob.producer,
      stateBlobB64u: parsed.stateBlob.stateBlobB64u,
    },
    publicFacts: serializeEcdsaRoleLocalPublicFacts(parsed.publicFacts),
  };
}

function keyPart(value: unknown): string {
  return encodeURIComponent(requiredString(value, 'storage key part'));
}

export function ecdsaRoleLocalReadyRecordStorageKey(
  input: LoadEcdsaRoleLocalReadyRecordInput | EcdsaRoleLocalPublicFacts,
): string {
  return [
    'ecdsa_role_local_ready_v1',
    keyPart(input.walletId),
    keyPart(input.rpId),
    keyPart(thresholdEcdsaChainTargetKey(input.chainTarget)),
    keyPart(input.keyHandle),
    keyPart(input.ecdsaThresholdKeyId),
    keyPart(input.signingRootId),
    keyPart(input.signingRootVersion),
    keyPart(input.participantIds.join(',')),
  ].join(':');
}

export function ecdsaRoleLocalReadyRecordMatchesInput(args: {
  record: EcdsaRoleLocalReadyRecord;
  input: LoadEcdsaRoleLocalReadyRecordInput;
}): boolean {
  const facts = args.record.publicFacts;
  const input = args.input;
  return (
    String(facts.walletId) === String(input.walletId) &&
    String(facts.rpId) === String(input.rpId) &&
    thresholdEcdsaChainTargetsEqual(facts.chainTarget, input.chainTarget) &&
    String(facts.keyHandle) === String(input.keyHandle) &&
    String(facts.ecdsaThresholdKeyId) === String(input.ecdsaThresholdKeyId) &&
    String(facts.signingRootId) === String(input.signingRootId) &&
    String(facts.signingRootVersion) === String(input.signingRootVersion) &&
    facts.participantIds[0] === input.participantIds[0] &&
    facts.participantIds[1] === input.participantIds[1]
  );
}
