import { buildNearAccountRefs } from '@/core/accountData/near/accountRefs';
import { buildEnvelopeAAD, KEY_PAYLOAD_ENC_VERSION } from '@/core/indexedDB/keyMaterialEnvelope';
import type { KeyMaterialRecord } from '@/core/indexedDB/keyMaterial.types';
import {
  resolveAccountKeyMaterialTarget,
  type AccountKeyMaterialDeps,
  type ResolvedAccountKeyMaterialTarget,
} from '@/core/indexedDB/accountKeyMaterial';
import { base58Encode } from '@shared/utils/base58';
import { base64UrlDecode } from '@shared/utils/base64';
import { isPlainObject } from '@shared/utils/validation';

export const EMAIL_OTP_ED25519_YAO_LOCAL_MATERIAL_KEY_KIND =
  'email_otp_router_ab_ed25519_yao_active_client_v1' as const;
export const EMAIL_OTP_ED25519_YAO_LOCAL_MATERIAL_SCHEMA_VERSION = 1 as const;
export const EMAIL_OTP_ED25519_YAO_LOCAL_MATERIAL_ALGORITHM =
  'chacha20poly1305-hkdf-sha256-email-otp-enrollment-secret-v1' as const;

const EMAIL_OTP_ED25519_YAO_LOCAL_MATERIAL_NONCE_BYTES = 12;

type EmailOtpEd25519YaoLocalMaterialStorePort = AccountKeyMaterialDeps['clientDB'] &
  AccountKeyMaterialDeps['keyMaterialStore'] & {
    deleteKeyMaterial(
      profileId: string,
      signerSlot: number,
      chainIdKey: string,
      keyKind: typeof EMAIL_OTP_ED25519_YAO_LOCAL_MATERIAL_KEY_KIND,
    ): Promise<void>;
  };

export type EmailOtpEd25519YaoStableCustodyBindingV1 = {
  kind: typeof EMAIL_OTP_ED25519_YAO_LOCAL_MATERIAL_KEY_KIND;
  walletId: string;
  nearAccountId: string;
  provider: 'google' | 'email';
  providerSubjectId: string;
  enrollmentId: string;
  enrollmentVersion: string;
  enrollmentSealKeyVersion: string;
  signerSlot: number;
  nearEd25519SigningKeyId: string;
  signingRootId: string;
  signingRootVersion: string;
  lifecycleId: string;
  rootShareEpoch: string;
  signerSetId: string;
  participantIds: readonly [number, number];
  signingWorkerId: string;
  registeredPublicKeyB64u: string;
  signingWorkerVerifyingShareB64u: string;
  stateEpoch: string;
  activationTranscriptB64u: string;
  activeCapabilityBindingB64u: string;
  applicationBinding: {
    walletId: string;
    nearEd25519SigningKeyId: string;
    signingRootId: string;
    keyCreationSignerSlot: number;
  };
};

export type EmailOtpEd25519YaoOpaqueLocalEnvelopeV1 = {
  algorithm: typeof EMAIL_OTP_ED25519_YAO_LOCAL_MATERIAL_ALGORITHM;
  nonceB64u: string;
  ciphertextB64u: string;
};

export type EmailOtpEd25519YaoLocalMaterialV1 = {
  kind: 'email_otp_ed25519_yao_local_material_v1';
  binding: EmailOtpEd25519YaoStableCustodyBindingV1;
  envelope: EmailOtpEd25519YaoOpaqueLocalEnvelopeV1;
};

export type EmailOtpEd25519YaoLocalMaterialInvalidCode =
  | 'ciphertext_invalid'
  | 'custody_binding_mismatch'
  | 'registered_public_key_mismatch'
  | 'unsupported_envelope_version';

export type EmailOtpEd25519YaoLocalMaterialResolutionV1 =
  | {
      kind: 'exact_material_ready';
      material: EmailOtpEd25519YaoLocalMaterialV1;
      code?: never;
    }
  | {
      kind: 'material_absent';
      material?: never;
      code?: never;
    }
  | {
      kind: 'material_invalid';
      code: EmailOtpEd25519YaoLocalMaterialInvalidCode;
      material?: never;
    };

export type PersistEmailOtpEd25519YaoLocalMaterialInputV1 = {
  store: EmailOtpEd25519YaoLocalMaterialStorePort;
  binding: EmailOtpEd25519YaoStableCustodyBindingV1;
  envelope: EmailOtpEd25519YaoOpaqueLocalEnvelopeV1;
};

export type ReadEmailOtpEd25519YaoLocalMaterialInputV1 = {
  store: EmailOtpEd25519YaoLocalMaterialStorePort;
  expectedBinding: EmailOtpEd25519YaoStableCustodyBindingV1;
};

export type ReadEmailOtpEd25519YaoLocalMaterialByLocatorInputV1 = {
  store: EmailOtpEd25519YaoLocalMaterialStorePort;
  walletId: string;
  nearAccountId: string;
  signerSlot: number;
  providerSubjectId: string;
  expectedOperationalPublicKey: string;
};

export type DeleteEmailOtpEd25519YaoLocalMaterialInputV1 = {
  store: EmailOtpEd25519YaoLocalMaterialStorePort;
  binding: EmailOtpEd25519YaoStableCustodyBindingV1;
};

type ParsedStoredEnvelope = {
  algorithm: typeof EMAIL_OTP_ED25519_YAO_LOCAL_MATERIAL_ALGORITHM;
  nonceB64u: string;
  ciphertextB64u: string;
};

function invalidMaterial(
  code: EmailOtpEd25519YaoLocalMaterialInvalidCode,
): EmailOtpEd25519YaoLocalMaterialResolutionV1 {
  return { kind: 'material_invalid', code };
}

function readRequiredString(value: unknown): string | null {
  if (typeof value !== 'string') return null;
  const normalized = value.trim();
  return normalized || null;
}

function readPositiveSafeInteger(value: unknown): number | null {
  return Number.isSafeInteger(value) && typeof value === 'number' && value >= 1 ? value : null;
}

function readProvider(value: unknown): 'google' | 'email' | null {
  if (value === 'google' || value === 'email') return value;
  return null;
}

function readParticipantIds(value: unknown): readonly [number, number] | null {
  if (!Array.isArray(value) || value.length !== 2) return null;
  const first = readPositiveSafeInteger(value[0]);
  const second = readPositiveSafeInteger(value[1]);
  if (first === null || second === null || first > 65_535 || second > 65_535 || first === second) {
    return null;
  }
  return [first, second];
}

function decodeBase64Url(value: unknown): Uint8Array | null {
  const normalized = readRequiredString(value);
  if (!normalized) return null;
  try {
    return base64UrlDecode(normalized);
  } catch {
    return null;
  }
}

function readBytes32B64u(value: unknown): string | null {
  const normalized = readRequiredString(value);
  const decoded = decodeBase64Url(value);
  return normalized && decoded?.byteLength === 32 ? normalized : null;
}

function hasExactlyKeys(value: Record<string, unknown>, keys: readonly string[]): boolean {
  const actualKeys = Object.keys(value);
  if (actualKeys.length !== keys.length) return false;
  for (const key of keys) {
    if (!Object.prototype.hasOwnProperty.call(value, key)) return false;
  }
  return true;
}

function parseApplicationBinding(
  value: unknown,
): EmailOtpEd25519YaoStableCustodyBindingV1['applicationBinding'] | null {
  if (!isPlainObject(value)) return null;
  if (
    !hasExactlyKeys(value, [
      'walletId',
      'nearEd25519SigningKeyId',
      'signingRootId',
      'keyCreationSignerSlot',
    ])
  ) {
    return null;
  }
  const walletId = readRequiredString(value.walletId);
  const nearEd25519SigningKeyId = readRequiredString(value.nearEd25519SigningKeyId);
  const signingRootId = readRequiredString(value.signingRootId);
  const keyCreationSignerSlot = readPositiveSafeInteger(value.keyCreationSignerSlot);
  if (!walletId || !nearEd25519SigningKeyId || !signingRootId || keyCreationSignerSlot === null) {
    return null;
  }
  return {
    walletId,
    nearEd25519SigningKeyId,
    signingRootId,
    keyCreationSignerSlot,
  };
}

function parseStableCustodyBinding(
  value: unknown,
): EmailOtpEd25519YaoStableCustodyBindingV1 | null {
  if (!isPlainObject(value)) return null;
  if (
    !hasExactlyKeys(value, [
      'kind',
      'walletId',
      'nearAccountId',
      'provider',
      'providerSubjectId',
      'enrollmentId',
      'enrollmentVersion',
      'enrollmentSealKeyVersion',
      'signerSlot',
      'nearEd25519SigningKeyId',
      'signingRootId',
      'signingRootVersion',
      'lifecycleId',
      'rootShareEpoch',
      'signerSetId',
      'participantIds',
      'signingWorkerId',
      'registeredPublicKeyB64u',
      'signingWorkerVerifyingShareB64u',
      'stateEpoch',
      'activationTranscriptB64u',
      'activeCapabilityBindingB64u',
      'applicationBinding',
    ])
  ) {
    return null;
  }
  if (value.kind !== EMAIL_OTP_ED25519_YAO_LOCAL_MATERIAL_KEY_KIND) return null;

  const walletId = readRequiredString(value.walletId);
  const nearAccountId = readRequiredString(value.nearAccountId);
  const provider = readProvider(value.provider);
  const providerSubjectId = readRequiredString(value.providerSubjectId);
  const enrollmentId = readRequiredString(value.enrollmentId);
  const enrollmentVersion = readRequiredString(value.enrollmentVersion);
  const enrollmentSealKeyVersion = readRequiredString(value.enrollmentSealKeyVersion);
  const signerSlot = readPositiveSafeInteger(value.signerSlot);
  const nearEd25519SigningKeyId = readRequiredString(value.nearEd25519SigningKeyId);
  const signingRootId = readRequiredString(value.signingRootId);
  const signingRootVersion = readRequiredString(value.signingRootVersion);
  const lifecycleId = readRequiredString(value.lifecycleId);
  const rootShareEpoch = readRequiredString(value.rootShareEpoch);
  const signerSetId = readRequiredString(value.signerSetId);
  const participantIds = readParticipantIds(value.participantIds);
  const signingWorkerId = readRequiredString(value.signingWorkerId);
  const registeredPublicKeyB64u = readBytes32B64u(value.registeredPublicKeyB64u);
  const signingWorkerVerifyingShareB64u = readBytes32B64u(value.signingWorkerVerifyingShareB64u);
  const stateEpoch = readRequiredString(value.stateEpoch);
  const activationTranscriptB64u = readRequiredString(value.activationTranscriptB64u);
  const activeCapabilityBindingB64u = readBytes32B64u(value.activeCapabilityBindingB64u);
  const applicationBinding = parseApplicationBinding(value.applicationBinding);

  if (
    !walletId ||
    !nearAccountId ||
    !provider ||
    !providerSubjectId ||
    !enrollmentId ||
    !enrollmentVersion ||
    !enrollmentSealKeyVersion ||
    signerSlot === null ||
    !nearEd25519SigningKeyId ||
    !signingRootId ||
    !signingRootVersion ||
    !lifecycleId ||
    !rootShareEpoch ||
    !signerSetId ||
    !participantIds ||
    !signingWorkerId ||
    !registeredPublicKeyB64u ||
    !signingWorkerVerifyingShareB64u ||
    !stateEpoch ||
    !/^(0|[1-9][0-9]*)$/.test(stateEpoch) ||
    !activationTranscriptB64u ||
    !decodeBase64Url(activationTranscriptB64u)?.byteLength ||
    !activeCapabilityBindingB64u ||
    !applicationBinding
  ) {
    return null;
  }
  if (
    applicationBinding.walletId !== walletId ||
    applicationBinding.nearEd25519SigningKeyId !== nearEd25519SigningKeyId ||
    applicationBinding.signingRootId !== signingRootId ||
    applicationBinding.keyCreationSignerSlot !== signerSlot
  ) {
    return null;
  }

  return {
    kind: EMAIL_OTP_ED25519_YAO_LOCAL_MATERIAL_KEY_KIND,
    walletId,
    nearAccountId,
    provider,
    providerSubjectId,
    enrollmentId,
    enrollmentVersion,
    enrollmentSealKeyVersion,
    signerSlot,
    nearEd25519SigningKeyId,
    signingRootId,
    signingRootVersion,
    lifecycleId,
    rootShareEpoch,
    signerSetId,
    participantIds,
    signingWorkerId,
    registeredPublicKeyB64u,
    signingWorkerVerifyingShareB64u,
    stateEpoch,
    activationTranscriptB64u,
    activeCapabilityBindingB64u,
    applicationBinding,
  };
}

function stableBindingEquals(
  left: EmailOtpEd25519YaoStableCustodyBindingV1,
  right: EmailOtpEd25519YaoStableCustodyBindingV1,
): boolean {
  return (
    left.kind === right.kind &&
    left.walletId === right.walletId &&
    left.nearAccountId === right.nearAccountId &&
    left.provider === right.provider &&
    left.providerSubjectId === right.providerSubjectId &&
    left.enrollmentId === right.enrollmentId &&
    left.enrollmentVersion === right.enrollmentVersion &&
    left.enrollmentSealKeyVersion === right.enrollmentSealKeyVersion &&
    left.signerSlot === right.signerSlot &&
    left.nearEd25519SigningKeyId === right.nearEd25519SigningKeyId &&
    left.signingRootId === right.signingRootId &&
    left.signingRootVersion === right.signingRootVersion &&
    left.lifecycleId === right.lifecycleId &&
    left.rootShareEpoch === right.rootShareEpoch &&
    left.signerSetId === right.signerSetId &&
    left.participantIds[0] === right.participantIds[0] &&
    left.participantIds[1] === right.participantIds[1] &&
    left.signingWorkerId === right.signingWorkerId &&
    left.registeredPublicKeyB64u === right.registeredPublicKeyB64u &&
    left.signingWorkerVerifyingShareB64u === right.signingWorkerVerifyingShareB64u &&
    left.stateEpoch === right.stateEpoch &&
    left.activationTranscriptB64u === right.activationTranscriptB64u &&
    left.activeCapabilityBindingB64u === right.activeCapabilityBindingB64u &&
    left.applicationBinding.walletId === right.applicationBinding.walletId &&
    left.applicationBinding.nearEd25519SigningKeyId ===
      right.applicationBinding.nearEd25519SigningKeyId &&
    left.applicationBinding.signingRootId === right.applicationBinding.signingRootId &&
    left.applicationBinding.keyCreationSignerSlot === right.applicationBinding.keyCreationSignerSlot
  );
}

export function encodeEmailOtpEd25519YaoStableCustodyBindingV1(
  input: EmailOtpEd25519YaoStableCustodyBindingV1,
): Uint8Array {
  const binding = canonicalizeInputBinding(input);
  return new TextEncoder().encode(
    JSON.stringify([
      binding.kind,
      binding.walletId,
      binding.nearAccountId,
      binding.provider,
      binding.providerSubjectId,
      binding.enrollmentId,
      binding.enrollmentVersion,
      binding.enrollmentSealKeyVersion,
      binding.signerSlot,
      binding.nearEd25519SigningKeyId,
      binding.signingRootId,
      binding.signingRootVersion,
      binding.lifecycleId,
      binding.rootShareEpoch,
      binding.signerSetId,
      binding.participantIds[0],
      binding.participantIds[1],
      binding.signingWorkerId,
      binding.registeredPublicKeyB64u,
      binding.signingWorkerVerifyingShareB64u,
      binding.stateEpoch,
      binding.activationTranscriptB64u,
      binding.activeCapabilityBindingB64u,
      binding.applicationBinding.walletId,
      binding.applicationBinding.nearEd25519SigningKeyId,
      binding.applicationBinding.signingRootId,
      binding.applicationBinding.keyCreationSignerSlot,
    ]),
  );
}

function parseStoredEnvelope(record: KeyMaterialRecord): ParsedStoredEnvelope | null {
  const envelope = record.payloadEnvelope;
  if (!envelope) return null;
  const nonce = decodeBase64Url(envelope.nonce);
  const ciphertext = decodeBase64Url(envelope.ciphertext);
  if (
    nonce?.byteLength !== EMAIL_OTP_ED25519_YAO_LOCAL_MATERIAL_NONCE_BYTES ||
    !ciphertext?.byteLength
  ) {
    return null;
  }
  return {
    algorithm: EMAIL_OTP_ED25519_YAO_LOCAL_MATERIAL_ALGORITHM,
    nonceB64u: envelope.nonce,
    ciphertextB64u: envelope.ciphertext,
  };
}

function recordStorageIdentityMatches(
  record: KeyMaterialRecord,
  target: ResolvedAccountKeyMaterialTarget,
  expectedBinding: EmailOtpEd25519YaoStableCustodyBindingV1,
): boolean {
  const expectedAad = buildEnvelopeAAD({
    profileId: target.profileId,
    signerSlot: expectedBinding.signerSlot,
    chainIdKey: target.chainIdKey,
    accountAddress: target.accountAddress,
    keyKind: EMAIL_OTP_ED25519_YAO_LOCAL_MATERIAL_KEY_KIND,
    schemaVersion: EMAIL_OTP_ED25519_YAO_LOCAL_MATERIAL_SCHEMA_VERSION,
    signerId: expectedBinding.nearEd25519SigningKeyId,
  });
  const actualAad = record.payloadEnvelope?.aad;
  return (
    record.profileId === target.profileId &&
    record.signerSlot === expectedBinding.signerSlot &&
    record.chainIdKey === target.chainIdKey &&
    record.accountAddress === target.accountAddress &&
    record.keyKind === EMAIL_OTP_ED25519_YAO_LOCAL_MATERIAL_KEY_KIND &&
    record.algorithm === 'ed25519' &&
    record.signerId === expectedBinding.nearEd25519SigningKeyId &&
    actualAad?.profileId === expectedAad.profileId &&
    actualAad.signerSlot === expectedAad.signerSlot &&
    actualAad.chainIdKey === expectedAad.chainIdKey &&
    actualAad.accountAddress === expectedAad.accountAddress &&
    actualAad.keyKind === expectedAad.keyKind &&
    actualAad.schemaVersion === expectedAad.schemaVersion &&
    actualAad.signerId === expectedAad.signerId
  );
}

function canonicalizeInputBinding(
  binding: EmailOtpEd25519YaoStableCustodyBindingV1,
): EmailOtpEd25519YaoStableCustodyBindingV1 {
  const parsed = parseStableCustodyBinding(binding);
  if (!parsed) throw new Error('Email OTP Ed25519 local custody binding is invalid');
  return parsed;
}

function canonicalizeOpaqueEnvelope(
  envelope: EmailOtpEd25519YaoOpaqueLocalEnvelopeV1,
): EmailOtpEd25519YaoOpaqueLocalEnvelopeV1 {
  if (envelope.algorithm !== EMAIL_OTP_ED25519_YAO_LOCAL_MATERIAL_ALGORITHM) {
    throw new Error('Email OTP Ed25519 local custody envelope algorithm is invalid');
  }
  const nonce = decodeBase64Url(envelope.nonceB64u);
  const ciphertext = decodeBase64Url(envelope.ciphertextB64u);
  if (
    nonce?.byteLength !== EMAIL_OTP_ED25519_YAO_LOCAL_MATERIAL_NONCE_BYTES ||
    !ciphertext?.byteLength
  ) {
    throw new Error('Email OTP Ed25519 local custody envelope ciphertext is invalid');
  }
  return {
    algorithm: EMAIL_OTP_ED25519_YAO_LOCAL_MATERIAL_ALGORITHM,
    nonceB64u: envelope.nonceB64u,
    ciphertextB64u: envelope.ciphertextB64u,
  };
}

async function requireStorageTarget(
  store: EmailOtpEd25519YaoLocalMaterialStorePort,
  binding: EmailOtpEd25519YaoStableCustodyBindingV1,
): Promise<ResolvedAccountKeyMaterialTarget> {
  const target = await resolveAccountKeyMaterialTarget(store, {
    accountRefs: buildNearAccountRefs(binding.nearAccountId),
  });
  if (!target) {
    throw new Error('Email OTP Ed25519 local custody requires a persisted wallet profile');
  }
  return target;
}

export function parseEmailOtpEd25519YaoLocalMaterialRecordV1(args: {
  record: KeyMaterialRecord | null;
  target: ResolvedAccountKeyMaterialTarget;
  expectedBinding: EmailOtpEd25519YaoStableCustodyBindingV1;
}): EmailOtpEd25519YaoLocalMaterialResolutionV1 {
  if (!args.record) return { kind: 'material_absent' };
  const expectedBinding = parseStableCustodyBinding(args.expectedBinding);
  if (!expectedBinding) return invalidMaterial('custody_binding_mismatch');
  if (
    args.record.schemaVersion !== EMAIL_OTP_ED25519_YAO_LOCAL_MATERIAL_SCHEMA_VERSION ||
    args.record.payloadEnvelope?.encVersion !== KEY_PAYLOAD_ENC_VERSION ||
    args.record.payloadEnvelope.alg !== EMAIL_OTP_ED25519_YAO_LOCAL_MATERIAL_ALGORITHM
  ) {
    return invalidMaterial('unsupported_envelope_version');
  }
  if (!recordStorageIdentityMatches(args.record, args.target, expectedBinding)) {
    return invalidMaterial('custody_binding_mismatch');
  }
  if (!isPlainObject(args.record.payload)) {
    return invalidMaterial('custody_binding_mismatch');
  }
  if (!hasExactlyKeys(args.record.payload, ['binding'])) {
    return invalidMaterial('custody_binding_mismatch');
  }
  const storedBinding = parseStableCustodyBinding(args.record.payload.binding);
  if (!storedBinding || !stableBindingEquals(storedBinding, expectedBinding)) {
    return invalidMaterial('custody_binding_mismatch');
  }
  const expectedPublicKey = `ed25519:${base58Encode(
    base64UrlDecode(storedBinding.registeredPublicKeyB64u),
  )}`;
  if (args.record.publicKey !== expectedPublicKey) {
    return invalidMaterial('registered_public_key_mismatch');
  }
  const envelope = parseStoredEnvelope(args.record);
  if (!envelope) return invalidMaterial('ciphertext_invalid');
  return {
    kind: 'exact_material_ready',
    material: {
      kind: 'email_otp_ed25519_yao_local_material_v1',
      binding: storedBinding,
      envelope,
    },
  };
}

export async function persistEmailOtpEd25519YaoLocalMaterialV1(
  input: PersistEmailOtpEd25519YaoLocalMaterialInputV1,
): Promise<void> {
  const binding = canonicalizeInputBinding(input.binding);
  const envelope = canonicalizeOpaqueEnvelope(input.envelope);
  const target = await requireStorageTarget(input.store, binding);
  const record: KeyMaterialRecord = {
    profileId: target.profileId,
    signerSlot: binding.signerSlot,
    chainIdKey: target.chainIdKey,
    accountAddress: target.accountAddress,
    keyKind: EMAIL_OTP_ED25519_YAO_LOCAL_MATERIAL_KEY_KIND,
    algorithm: 'ed25519',
    publicKey: `ed25519:${base58Encode(base64UrlDecode(binding.registeredPublicKeyB64u))}`,
    signerId: binding.nearEd25519SigningKeyId,
    payload: { binding },
    payloadEnvelope: {
      encVersion: KEY_PAYLOAD_ENC_VERSION,
      alg: envelope.algorithm,
      nonce: envelope.nonceB64u,
      ciphertext: envelope.ciphertextB64u,
      aad: buildEnvelopeAAD({
        profileId: target.profileId,
        signerSlot: binding.signerSlot,
        chainIdKey: target.chainIdKey,
        accountAddress: target.accountAddress,
        keyKind: EMAIL_OTP_ED25519_YAO_LOCAL_MATERIAL_KEY_KIND,
        schemaVersion: EMAIL_OTP_ED25519_YAO_LOCAL_MATERIAL_SCHEMA_VERSION,
        signerId: binding.nearEd25519SigningKeyId,
      }),
    },
    timestamp: Date.now(),
    schemaVersion: EMAIL_OTP_ED25519_YAO_LOCAL_MATERIAL_SCHEMA_VERSION,
  };
  await input.store.storeKeyMaterial(record);
}

export async function readEmailOtpEd25519YaoLocalMaterialV1(
  input: ReadEmailOtpEd25519YaoLocalMaterialInputV1,
): Promise<EmailOtpEd25519YaoLocalMaterialResolutionV1> {
  const expectedBinding = canonicalizeInputBinding(input.expectedBinding);
  const target = await resolveAccountKeyMaterialTarget(input.store, {
    accountRefs: buildNearAccountRefs(expectedBinding.nearAccountId),
  });
  if (!target) return { kind: 'material_absent' };
  const record = await input.store.getKeyMaterial(
    target.profileId,
    expectedBinding.signerSlot,
    target.chainIdKey,
    EMAIL_OTP_ED25519_YAO_LOCAL_MATERIAL_KEY_KIND,
  );
  return parseEmailOtpEd25519YaoLocalMaterialRecordV1({
    record,
    target,
    expectedBinding,
  });
}

export async function readEmailOtpEd25519YaoLocalMaterialByLocatorV1(
  input: ReadEmailOtpEd25519YaoLocalMaterialByLocatorInputV1,
): Promise<EmailOtpEd25519YaoLocalMaterialResolutionV1> {
  const walletId = readRequiredString(input.walletId);
  const nearAccountId = readRequiredString(input.nearAccountId);
  const providerSubjectId = readRequiredString(input.providerSubjectId);
  const expectedOperationalPublicKey = readRequiredString(input.expectedOperationalPublicKey);
  const signerSlot = readPositiveSafeInteger(input.signerSlot);
  if (!walletId || !nearAccountId || !providerSubjectId || !expectedOperationalPublicKey || !signerSlot) {
    throw new Error('Email OTP Ed25519 local custody locator is invalid');
  }
  const target = await resolveAccountKeyMaterialTarget(input.store, {
    accountRefs: buildNearAccountRefs(nearAccountId),
  });
  if (!target) return { kind: 'material_absent' };
  const record = await input.store.getKeyMaterial(
    target.profileId,
    signerSlot,
    target.chainIdKey,
    EMAIL_OTP_ED25519_YAO_LOCAL_MATERIAL_KEY_KIND,
  );
  if (!record) return { kind: 'material_absent' };
  if (!isPlainObject(record.payload)) return invalidMaterial('custody_binding_mismatch');
  const storedBinding = parseStableCustodyBinding(record.payload.binding);
  if (!storedBinding) return invalidMaterial('custody_binding_mismatch');
  if (
    storedBinding.walletId !== walletId ||
    storedBinding.nearAccountId !== nearAccountId ||
    storedBinding.providerSubjectId !== providerSubjectId ||
    storedBinding.signerSlot !== signerSlot ||
    record.publicKey !== expectedOperationalPublicKey
  ) {
    return invalidMaterial('custody_binding_mismatch');
  }
  return parseEmailOtpEd25519YaoLocalMaterialRecordV1({
    record,
    target,
    expectedBinding: storedBinding,
  });
}

export async function deleteEmailOtpEd25519YaoLocalMaterialV1(
  input: DeleteEmailOtpEd25519YaoLocalMaterialInputV1,
): Promise<void> {
  const binding = canonicalizeInputBinding(input.binding);
  const target = await resolveAccountKeyMaterialTarget(input.store, {
    accountRefs: buildNearAccountRefs(binding.nearAccountId),
  });
  if (!target) return;
  await input.store.deleteKeyMaterial(
    target.profileId,
    binding.signerSlot,
    target.chainIdKey,
    EMAIL_OTP_ED25519_YAO_LOCAL_MATERIAL_KEY_KIND,
  );
}
