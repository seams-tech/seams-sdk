import { base64UrlDecode } from '@shared/utils/base64';
import {
  thresholdEcdsaChainTargetKey,
  thresholdEcdsaChainTargetsEqual,
  thresholdEcdsaChainTargetFromRequest,
  toWalletId,
} from '../../interfaces/ecdsaChainTarget';
import { toRpId } from '../identity/evmFamilyEcdsaIdentity';
import {
  toEcdsaHssSigningRootId,
  toEcdsaHssSigningRootVersion,
  toEcdsaHssThresholdKeyId,
  toEmailOtpAuthSubjectId,
} from '../identity/emailOtpHssIdentity';
import {
  parseRawThresholdEcdsaSessionRecord,
  type ThresholdEcdsaSessionRecord,
} from './records';
import type {
  CleanupMalformedEcdsaRoleLocalRecordInput,
  CredentialIdB64u,
  EcdsaGroupPublicKey33B64u,
  EcdsaRoleLocalAuthMethod,
  EcdsaRoleLocalPublicFacts,
  EcdsaRoleLocalRecordParseResult,
  EcdsaRoleLocalReadyRecord,
  EcdsaRoleLocalReadyStateBlob,
  EcdsaRoleLocalSessionRecordState,
  LoadEcdsaRoleLocalReadyRecordInput,
} from '@/core/platform/types';
import type {
  EcdsaHssClientSharePublicKey33B64u,
  EcdsaRelayerHssPublicKey33B64u,
} from '@shared/threshold/ecdsaHssRoleLocalBootstrap';
import { requireEvmFamilySigningKeySlotId } from '@shared/signing-lanes';

export type EcdsaRoleLocalExportMaterial = {
  readyRecord: EcdsaRoleLocalReadyRecord;
  contextBinding32B64u: string;
};

function isRecord(value: unknown): value is Record<string, unknown> {
  return Boolean(value && typeof value === 'object' && !Array.isArray(value));
}

function assertNever(value: never): never {
  throw new Error(`Unhandled ECDSA role-local branch: ${String(value)}`);
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

function parseCompressedSecp256k1PublicKey(value: unknown, field: string): string {
  const normalized = requiredString(value, field);
  const decoded = base64UrlDecode(normalized);
  if (decoded.length !== 33) {
    throw new Error(`[platform][ecdsa-role-local] ${field} must decode to 33 bytes`);
  }
  if (decoded[0] !== 2 && decoded[0] !== 3) {
    throw new Error(`[platform][ecdsa-role-local] ${field} must be a compressed SEC1 key`);
  }
  return normalized;
}

function parseHssClientSharePublicKey(value: unknown): EcdsaHssClientSharePublicKey33B64u {
  return parseCompressedSecp256k1PublicKey(
    value,
    'hssClientSharePublicKey33B64u',
  ) as EcdsaHssClientSharePublicKey33B64u;
}

function parseRelayerHssPublicKey(value: unknown): EcdsaRelayerHssPublicKey33B64u {
  return parseCompressedSecp256k1PublicKey(
    value,
    'relayerPublicKey33B64u',
  ) as EcdsaRelayerHssPublicKey33B64u;
}

function parseGroupPublicKey(value: unknown): EcdsaGroupPublicKey33B64u {
  return parseCompressedSecp256k1PublicKey(
    value,
    'groupPublicKey33B64u',
  ) as EcdsaGroupPublicKey33B64u;
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

function parseCredentialIdB64u(value: unknown, field = 'credentialIdB64u'): CredentialIdB64u {
  return requiredString(value, field) as CredentialIdB64u;
}

function toWalletKeyId(value: unknown) {
  return requireEvmFamilySigningKeySlotId(value);
}

function parseAuthMethod(input: unknown): EcdsaRoleLocalAuthMethod {
  if (!isRecord(input)) {
    throw new Error('[platform][ecdsa-role-local] authMethod must be an object');
  }
  const kind = requiredString(input.kind, 'authMethod.kind');
  switch (kind) {
    case 'passkey':
      return {
        kind: 'passkey',
        credentialIdB64u: parseCredentialIdB64u(input.credentialIdB64u),
        rpId: toRpId(input.rpId),
      };
    case 'email_otp':
      return {
        kind: 'email_otp',
        authSubjectId: toEmailOtpAuthSubjectId(input.authSubjectId),
      };
    default:
      throw new Error('[platform][ecdsa-role-local] authMethod kind is invalid');
  }
}

export function buildEcdsaRoleLocalPasskeyAuthMethod(input: {
  credentialIdB64u: unknown;
  rpId: unknown;
}): Extract<EcdsaRoleLocalAuthMethod, { kind: 'passkey' }> {
  return {
    kind: 'passkey',
    credentialIdB64u: parseCredentialIdB64u(input.credentialIdB64u),
    rpId: toRpId(input.rpId),
  };
}

export function buildEcdsaRoleLocalEmailOtpAuthMethod(input: {
  authSubjectId: unknown;
}): Extract<EcdsaRoleLocalAuthMethod, { kind: 'email_otp' }> {
  return {
    kind: 'email_otp',
    authSubjectId: toEmailOtpAuthSubjectId(input.authSubjectId),
  };
}

function authMethodsEqual(
  left: EcdsaRoleLocalAuthMethod,
  right: EcdsaRoleLocalAuthMethod,
): boolean {
  if (left.kind !== right.kind) return false;
  switch (left.kind) {
    case 'passkey':
      if (right.kind !== 'passkey') return false;
      return (
        String(left.rpId) === String(right.rpId) &&
        String(left.credentialIdB64u) === String(right.credentialIdB64u)
      );
    case 'email_otp':
      if (right.kind !== 'email_otp') return false;
      return String(left.authSubjectId) === String(right.authSubjectId);
    default:
      return assertNever(left);
  }
}

function readyRecordFromParts(args: {
  stateBlob: EcdsaRoleLocalReadyStateBlob;
  publicFacts: EcdsaRoleLocalPublicFacts;
  authMethod: EcdsaRoleLocalAuthMethod;
}): EcdsaRoleLocalReadyRecord {
  switch (args.authMethod.kind) {
    case 'passkey':
      return {
        kind: 'ecdsa_role_local_ready_passkey_v1',
        stateBlob: args.stateBlob,
        publicFacts: args.publicFacts,
        authMethod: args.authMethod,
      };
    case 'email_otp':
      return {
        kind: 'ecdsa_role_local_ready_email_otp_v1',
        stateBlob: args.stateBlob,
        publicFacts: args.publicFacts,
        authMethod: args.authMethod,
      };
    default:
      return assertNever(args.authMethod);
  }
}

function parsePublicFacts(input: unknown): EcdsaRoleLocalPublicFacts {
  if (!isRecord(input)) {
    throw new Error('[platform][ecdsa-role-local] publicFacts must be an object');
  }
  if (
    input.rpId !== undefined ||
    input.credentialIdB64u !== undefined ||
    input.authSubjectId !== undefined
  ) {
    throw new Error('[platform][ecdsa-role-local] auth fields are not publicFacts');
  }
  if (Number(input.clientParticipantId) !== 1) {
    throw new Error('[platform][ecdsa-role-local] clientParticipantId must be 1');
  }
  if (Number(input.relayerParticipantId) !== 2) {
    throw new Error('[platform][ecdsa-role-local] relayerParticipantId must be 2');
  }
  const hssClientSharePublicKey33B64u = parseHssClientSharePublicKey(
    input.hssClientSharePublicKey33B64u,
  );
  const relayerPublicKey33B64u = parseRelayerHssPublicKey(input.relayerPublicKey33B64u);
  if (String(hssClientSharePublicKey33B64u) === String(relayerPublicKey33B64u)) {
    throw new Error(
      '[platform][ecdsa-role-local] relayerPublicKey33B64u must differ from hssClientSharePublicKey33B64u',
    );
  }
  return {
    walletId: toWalletId(input.walletId),
    evmFamilySigningKeySlotId: toWalletKeyId(input.evmFamilySigningKeySlotId),
    chainTarget: thresholdEcdsaChainTargetFromRequest(
      isRecord(input.chainTarget) ? input.chainTarget : {},
    ),
    keyHandle: requiredString(input.keyHandle, 'keyHandle'),
    ecdsaThresholdKeyId: toEcdsaHssThresholdKeyId(input.ecdsaThresholdKeyId),
    signingRootId: toEcdsaHssSigningRootId(input.signingRootId),
    signingRootVersion: toEcdsaHssSigningRootVersion(input.signingRootVersion),
    applicationBindingDigestB64u: parseBase64UrlBytes(
      input.applicationBindingDigestB64u,
      'applicationBindingDigestB64u',
      32,
    ),
    clientParticipantId: 1,
    relayerParticipantId: 2,
    participantIds: parseParticipantIds(input.participantIds),
    contextBinding32B64u: parseBase64UrlBytes(
      input.contextBinding32B64u,
      'contextBinding32B64u',
      32,
    ),
    hssClientSharePublicKey33B64u,
    relayerPublicKey33B64u,
    groupPublicKey33B64u: parseGroupPublicKey(input.groupPublicKey33B64u),
    ethereumAddress: parseEthereumAddress(input.ethereumAddress),
  };
}

export function buildEcdsaRoleLocalPublicFacts(input: unknown): EcdsaRoleLocalPublicFacts {
  return parsePublicFacts(input);
}

export function parseEcdsaRoleLocalReadyRecord(
  input: unknown,
): EcdsaRoleLocalReadyRecord {
  if (!isRecord(input)) {
    throw new Error('[platform][ecdsa-role-local] ready record must be an object');
  }
  const kind = requiredString(input.kind, 'readyRecord.kind');
  if (
    kind !== 'ecdsa_role_local_ready_passkey_v1' &&
    kind !== 'ecdsa_role_local_ready_email_otp_v1'
  ) {
    throw new Error('[platform][ecdsa-role-local] ready record kind is invalid');
  }
  const publicFacts = parsePublicFacts(input.publicFacts);
  const stateBlob = parseReadyStateBlob(input.stateBlob);
  const authMethod = parseAuthMethod(input.authMethod);
  const parsed = readyRecordFromParts({
    stateBlob,
    publicFacts,
    authMethod,
  });
  if (
    (kind === 'ecdsa_role_local_ready_passkey_v1' && parsed.kind !== kind) ||
    (kind === 'ecdsa_role_local_ready_email_otp_v1' && parsed.kind !== kind)
  ) {
    throw new Error('[platform][ecdsa-role-local] ready record authMethod branch mismatch');
  }
  return parsed;
}

function serializeAuthMethod(authMethod: EcdsaRoleLocalAuthMethod): Record<string, unknown> {
  switch (authMethod.kind) {
    case 'passkey':
      return {
        kind: 'passkey',
        credentialIdB64u: authMethod.credentialIdB64u,
        rpId: authMethod.rpId,
      };
    case 'email_otp':
      return {
        kind: 'email_otp',
        authSubjectId: authMethod.authSubjectId,
      };
    default:
      return assertNever(authMethod);
  }
}

export function buildEcdsaRoleLocalReadyRecord(input: {
  stateBlob: EcdsaRoleLocalReadyStateBlob;
  publicFacts: EcdsaRoleLocalPublicFacts;
  authMethod: EcdsaRoleLocalAuthMethod;
}): EcdsaRoleLocalReadyRecord {
  return readyRecordFromParts({
    stateBlob: parseReadyStateBlob(input.stateBlob),
    publicFacts: parsePublicFacts(input.publicFacts),
    authMethod: input.authMethod,
  });
}

function thresholdEcdsaSessionRecordAsRoleLocalReadyRecord(
  record: ThresholdEcdsaSessionRecord,
): EcdsaRoleLocalReadyRecord {
  if (!record.ecdsaRoleLocalReadyRecord) {
    throw new Error('[platform][ecdsa-role-local] session record is missing role-local state');
  }
  return parseEcdsaRoleLocalReadyRecord(record.ecdsaRoleLocalReadyRecord);
}

export function parseThresholdEcdsaSessionRecordAsRoleLocalReadyRecord(
  input: unknown,
): EcdsaRoleLocalReadyRecord {
  return thresholdEcdsaSessionRecordAsRoleLocalReadyRecord(
    parseRawThresholdEcdsaSessionRecord(input),
  );
}

export function thresholdEcdsaRecordHasRoleLocalSigningMaterial(input: unknown): boolean {
  const state = classifyThresholdEcdsaSessionRecordRoleLocalState({
    record: input,
    nowMs: Date.now(),
  });
  switch (state.kind) {
    case 'ready_passkey_role_local_material_v1':
    case 'ready_email_otp_role_local_material_v1':
      return true;
    case 'reauth_required_role_local_material_v1':
    case 'cleanup_only_raw_role_local_record_v1':
      return false;
    default:
      return assertNever(state);
  }
}

export function classifyThresholdEcdsaSessionRecordRoleLocalState(args: {
  record: unknown;
  nowMs: number;
}): EcdsaRoleLocalSessionRecordState {
  let record: ThresholdEcdsaSessionRecord;
  let readyRecord: EcdsaRoleLocalReadyRecord;
  try {
    record = parseRawThresholdEcdsaSessionRecord(args.record);
    readyRecord = thresholdEcdsaSessionRecordAsRoleLocalReadyRecord(record);
  } catch (error) {
    return {
      kind: 'cleanup_only_raw_role_local_record_v1',
      reason: 'malformed_record',
      message:
        error instanceof Error
          ? error.message
          : '[platform][ecdsa-role-local] malformed role-local record',
    };
  }

  const authMethod = readyRecord.authMethod;
  const remainingUses = Math.floor(Number(record.remainingUses) || 0);
  if (remainingUses <= 0) {
    return {
      kind: 'reauth_required_role_local_material_v1',
      authMethod,
      readyRecord,
      reason: 'exhausted',
    };
  }
  const expiresAtMs = Math.floor(Number(record.expiresAtMs) || 0);
  if (expiresAtMs <= Math.floor(Number(args.nowMs) || 0)) {
    return {
      kind: 'reauth_required_role_local_material_v1',
      authMethod,
      readyRecord,
      reason: 'expired',
    };
  }

  const handle = record.clientAdditiveShareHandle;
  const workerSessionId =
    handle?.kind === 'email_otp_worker_session' ? String(handle.sessionId || '').trim() : '';
  if (readyRecord.kind === 'ecdsa_role_local_ready_email_otp_v1' && workerSessionId) {
    return {
      kind: 'ready_email_otp_role_local_material_v1',
      authMethod: readyRecord.authMethod,
      readyRecord,
      inlineSigningMaterial: {
        kind: 'email_otp_worker_share',
        workerSessionId,
      },
    };
  }
  if (readyRecord.kind === 'ecdsa_role_local_ready_email_otp_v1') {
    return {
      kind: 'ready_email_otp_role_local_material_v1',
      authMethod: readyRecord.authMethod,
      readyRecord,
      inlineSigningMaterial: {
        kind: 'role_local_ready_state_blob',
        stateBlob: readyRecord.stateBlob,
      },
    };
  }
  if (readyRecord.kind === 'ecdsa_role_local_ready_passkey_v1' && workerSessionId) {
    return {
      kind: 'reauth_required_role_local_material_v1',
      authMethod,
      readyRecord,
      reason: 'unsupported_material_owner',
    };
  }
  if (readyRecord.kind === 'ecdsa_role_local_ready_passkey_v1') {
    return {
      kind: 'ready_passkey_role_local_material_v1',
      authMethod: readyRecord.authMethod,
      readyRecord,
      inlineSigningMaterial: {
        kind: 'role_local_ready_state_blob',
        stateBlob: readyRecord.stateBlob,
      },
    };
  }
  return {
    kind: 'reauth_required_role_local_material_v1',
    authMethod,
    readyRecord,
    reason: 'unsupported_material_owner',
  };
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
  const readyRecord = thresholdEcdsaSessionRecordAsRoleLocalReadyRecord(record);
  return {
    readyRecord,
    contextBinding32B64u: readyRecord.publicFacts.contextBinding32B64u,
  };
}

function cleanupInputFromLookup(args: {
  lookup: LoadEcdsaRoleLocalReadyRecordInput;
  reason: string;
}): CleanupMalformedEcdsaRoleLocalRecordInput {
  return {
    ...args.lookup,
    reason: args.reason,
  };
}

export function parseRawEcdsaRoleLocalRecord(input: {
  raw: unknown;
  lookup: LoadEcdsaRoleLocalReadyRecordInput;
}): EcdsaRoleLocalRecordParseResult {
  try {
    const record = parseEcdsaRoleLocalReadyRecord(input.raw);
    if (!ecdsaRoleLocalReadyRecordMatchesInput({ record, input: input.lookup })) {
      const message =
        '[platform][ecdsa-role-local] ready record identity does not match lookup input';
      return {
        ok: false,
        code: 'malformed_record',
        message,
        cleanup: cleanupInputFromLookup({ lookup: input.lookup, reason: message }),
      };
    }
    return {
      ok: true,
      source: 'ready_record',
      state: {
        kind: 'ready',
        record,
      },
    };
  } catch (error) {
    const message =
      error instanceof Error
        ? error.message
        : '[platform][ecdsa-role-local] malformed role-local record';
    return {
      ok: false,
      code: 'malformed_record',
      message,
      cleanup: cleanupInputFromLookup({ lookup: input.lookup, reason: message }),
    };
  }
}

function serializeEcdsaRoleLocalPublicFacts(
  facts: EcdsaRoleLocalPublicFacts,
): Record<string, unknown> {
  return {
    walletId: facts.walletId,
    evmFamilySigningKeySlotId: facts.evmFamilySigningKeySlotId,
    chainTarget: facts.chainTarget,
    keyHandle: facts.keyHandle,
    ecdsaThresholdKeyId: facts.ecdsaThresholdKeyId,
    signingRootId: facts.signingRootId,
    signingRootVersion: facts.signingRootVersion,
    applicationBindingDigestB64u: facts.applicationBindingDigestB64u,
    clientParticipantId: 1,
    relayerParticipantId: 2,
    participantIds: [1, 2],
    contextBinding32B64u: facts.contextBinding32B64u,
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
    kind: parsed.kind,
    stateBlob: {
      kind: parsed.stateBlob.kind,
      curve: parsed.stateBlob.curve,
      encoding: parsed.stateBlob.encoding,
      producer: parsed.stateBlob.producer,
      stateBlobB64u: parsed.stateBlob.stateBlobB64u,
    },
    publicFacts: serializeEcdsaRoleLocalPublicFacts(parsed.publicFacts),
    authMethod: serializeAuthMethod(parsed.authMethod),
  };
}

function keyPart(value: unknown): string {
  return encodeURIComponent(requiredString(value, 'storage key part'));
}

export function ecdsaRoleLocalReadyRecordStorageKey(
  input: LoadEcdsaRoleLocalReadyRecordInput,
): string {
  return [
    'ecdsa_role_local_ready_v1',
    keyPart(input.walletId),
    keyPart(input.evmFamilySigningKeySlotId),
    keyPart(thresholdEcdsaChainTargetKey(input.chainTarget)),
    keyPart(input.keyHandle),
    keyPart(input.ecdsaThresholdKeyId),
    keyPart(input.signingRootId),
    keyPart(input.signingRootVersion),
    keyPart(input.participantIds.join(',')),
    keyPart(ecdsaRoleLocalAuthMethodStorageKeyPart(input.authMethod)),
  ].join(':');
}

function ecdsaRoleLocalAuthMethodStorageKeyPart(authMethod: EcdsaRoleLocalAuthMethod): string {
  switch (authMethod.kind) {
    case 'passkey':
      return ['passkey', authMethod.rpId, authMethod.credentialIdB64u].join(':');
    case 'email_otp':
      return ['email_otp', authMethod.authSubjectId].join(':');
    default:
      return assertNever(authMethod);
  }
}

export function ecdsaRoleLocalReadyRecordMatchesInput(args: {
  record: EcdsaRoleLocalReadyRecord;
  input: LoadEcdsaRoleLocalReadyRecordInput;
}): boolean {
  const facts = args.record.publicFacts;
  const input = args.input;
  return (
    String(facts.walletId) === String(input.walletId) &&
    String(facts.evmFamilySigningKeySlotId) === String(input.evmFamilySigningKeySlotId) &&
    thresholdEcdsaChainTargetsEqual(facts.chainTarget, input.chainTarget) &&
    String(facts.keyHandle) === String(input.keyHandle) &&
    String(facts.ecdsaThresholdKeyId) === String(input.ecdsaThresholdKeyId) &&
    String(facts.signingRootId) === String(input.signingRootId) &&
    String(facts.signingRootVersion) === String(input.signingRootVersion) &&
    facts.participantIds[0] === input.participantIds[0] &&
    facts.participantIds[1] === input.participantIds[1] &&
    authMethodsEqual(args.record.authMethod, input.authMethod)
  );
}
