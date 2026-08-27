import {
  parseWalletAuthMethodId,
  parseWalletAuthorityId,
  parseWalletAuthorityBindingDigest,
  parseWalletId,
  parseWalletRecoveryOperationId,
  parsePasskeyEnvelopeId,
  parseWebAuthnCredentialIdB64u,
  type PasskeyEnvelopeId,
  parseWebAuthnRpId,
  type WalletAuthorityId,
  type WalletAuthMethodId,
  type WalletAuthorityBindingDigest,
  type WalletId,
  type WalletRecoveryOperationId,
  type WebAuthnCredentialIdB64u,
  type WebAuthnRpId,
} from '@shared/utils/domainIds';
import { parseDeviceId, type DeviceId } from '@shared/authorization/capabilityKinds';
import type { WalletAuthorityProvenanceV1 } from '@shared/authorization/walletAuthority';
import {
  parseEnvelopeRevision,
  type EnvelopeRevision,
  type PasskeyCustodyEnvelopeRecord,
} from '@shared/passkey-custody';
import {
  parseWalletAuthMethodRecordV2,
  type WalletAuthMethodRecordV2,
} from '@shared/utils/registrationIntent';
import {
  parseRecoveryCodeReservationId,
  type RecoveryCodeReservationId,
} from '@shared/wallet-recovery/recoveryCodeReservation';
import { toOptionalTrimmedString } from '@shared/utils/validation';
import {
  parseWebAuthnAuthenticatorDeviceInfoJson,
  type WebAuthnAuthenticatorDeviceInfo,
} from '@shared/utils/webauthnDeviceInfo';
import {
  nonNegativeSafeInteger,
  optionalNonNegativeInteger,
  positiveInteger,
  toRecordValue,
} from '../auth/d1RouterApiAuthBoundary';
import { normalizeRuntimePolicyScope } from '@shared/threshold/signingRootScope';
import type { ThresholdRuntimePolicyScope } from '../../../../core/types';
import type { WebAuthnCredentialBindingRecord as CoreWebAuthnCredentialBindingRecord } from '../../../../core/WebAuthnCredentialBindingStore';

export type D1AuthenticatorRow = {
  readonly credential_id_b64u?: unknown;
  readonly credential_public_key_b64u?: unknown;
  readonly counter?: unknown;
  readonly created_at_ms?: unknown;
  readonly updated_at_ms?: unknown;
  readonly device_info_json?: unknown;
};

export type D1RecordJsonRow = {
  readonly record_json?: unknown;
};

export type WebAuthnCredentialBindingRecord = CoreWebAuthnCredentialBindingRecord;

export type WebAuthnSyncWalletBinding = {
  readonly walletId: string;
  readonly nearAccountId: string;
  readonly nearEd25519SigningKeyId: string;
  readonly rpId: string;
  readonly credentialIdB64u: string;
  readonly signerSlot: number;
};

export type NearPublicKeyAuthBinding = {
  readonly kind: 'passkey';
  readonly rpId: WebAuthnRpId;
  readonly credentialIdB64u: string;
};

export type NearPublicKeyRecord = {
  readonly publicKey: string;
  readonly kind: 'threshold' | 'local' | 'backup' | 'ephemeral';
  readonly signerSlot?: number;
  readonly authBinding?: NearPublicKeyAuthBinding;
  readonly credentialIdB64u?: never;
  readonly rpId?: never;
  readonly createdAtMs?: number;
  readonly updatedAtMs?: number;
};

export type WebAuthnAuthenticatorRecord = {
  readonly credentialIdB64u: string;
  readonly credentialPublicKeyB64u: string;
  readonly counter: number;
  readonly createdAtMs: number;
  readonly updatedAtMs: number;
  readonly deviceInfo: WebAuthnAuthenticatorDeviceInfo;
};

export function parseWebAuthnAuthenticatorRowDeviceInfo(
  raw: unknown,
): WebAuthnAuthenticatorDeviceInfo {
  return parseWebAuthnAuthenticatorDeviceInfoJson(raw);
}

export type WebAuthnLoginChallengeRecord = {
  readonly version: 'webauthn_login_challenge_v1';
  readonly challengeId: string;
  readonly userId: string;
  readonly rpId: string;
  readonly challengeB64u: string;
  readonly createdAtMs: number;
  readonly expiresAtMs: number;
};

export type WebAuthnSyncChallengeRecord = {
  readonly version: 'webauthn_sync_challenge_v1';
  readonly challengeId: string;
  readonly rpId: string;
  readonly expectedUserId?: string;
  readonly challengeB64u: string;
  readonly createdAtMs: number;
  readonly expiresAtMs: number;
};

/**
 * The exact continuity snapshot selected by prepare. The snapshot is stored
 * inside the one-shot challenge so finalization cannot silently switch to a
 * different active method or envelope after the code is reserved.
 */
export type WebAuthnRecoveryContinuityAnchorRecord = {
  readonly kind: 'wallet_recovery_continuity_anchor_v1';
  readonly walletAuthMethodId: WalletAuthMethodId;
  readonly walletAuthorityId: WalletAuthorityId;
  readonly authorityDigestB64u: WalletAuthorityBindingDigest;
  readonly provenanceKind: WalletAuthorityProvenanceV1['kind'];
  readonly method: Extract<WalletAuthMethodRecordV2, { readonly status: 'active' }>;
  readonly envelope: WebAuthnRecoveryContinuityEnvelopeAnchorRecord;
};

export type WebAuthnRecoveryContinuityEnvelopeAnchorRecord =
  | {
      readonly kind: 'passkey';
      readonly envelopeId: PasskeyEnvelopeId;
      readonly walletId: WalletId;
      readonly rpId: WebAuthnRpId;
      readonly credentialIdB64u: WebAuthnCredentialIdB64u;
      readonly envelopeRevision: EnvelopeRevision;
      readonly updatedAtMs: number;
      readonly bindingKind: 'wallet_custody_seed_v1';
    }
  | {
      readonly kind: 'email_otp';
      readonly envelopeId: PasskeyEnvelopeId;
      readonly walletId: WalletId;
      readonly enrollmentId: string;
      readonly enrollmentSealKeyVersion: string;
      readonly envelopeRevision: EnvelopeRevision;
      readonly updatedAtMs: number;
      readonly bindingKind: 'wallet_custody_seed_v1';
    };

/** A one-shot passkey registration ceremony bound to a wallet recovery hold. */
export type WebAuthnRecoveryRegistrationChallengeRecord = {
  readonly version: 'webauthn_recovery_registration_challenge_v2';
  readonly challengeId: string;
  readonly walletId: WalletId;
  readonly reservationId: RecoveryCodeReservationId;
  readonly recoveryOperationId: WalletRecoveryOperationId;
  readonly targetDeviceId: DeviceId;
  readonly targetAuthorityId: WalletAuthorityId;
  readonly targetWalletAuthMethodId: WalletAuthMethodId;
  readonly origin: string;
  readonly rpId: WebAuthnRpId;
  readonly replacementId: string;
  readonly challengeB64u: string;
  readonly continuityAnchor: WebAuthnRecoveryContinuityAnchorRecord;
  readonly createdAtMs: number;
  readonly expiresAtMs: number;
};

export function parseWebAuthnLoginChallengeRecord(
  input: unknown,
): WebAuthnLoginChallengeRecord | null {
  const record = parseJsonRecord(input);
  if (!record) return null;
  const version = toOptionalTrimmedString(record.version);
  const challengeId = toOptionalTrimmedString(record.challengeId);
  const userId = toOptionalTrimmedString(record.userId);
  const rpId = toOptionalTrimmedString(record.rpId);
  const challengeB64u = toOptionalTrimmedString(record.challengeB64u);
  const createdAtMs = positiveInteger(record.createdAtMs);
  const expiresAtMs = positiveInteger(record.expiresAtMs);
  if (version !== 'webauthn_login_challenge_v1') return null;
  if (!challengeId || !userId || !rpId || !challengeB64u) return null;
  if (createdAtMs === null || expiresAtMs === null) return null;
  return {
    version: 'webauthn_login_challenge_v1',
    challengeId,
    userId,
    rpId,
    challengeB64u,
    createdAtMs,
    expiresAtMs,
  };
}

export function parseWebAuthnSyncChallengeRecord(
  input: unknown,
): WebAuthnSyncChallengeRecord | null {
  const record = parseJsonRecord(input);
  if (!record) return null;
  const version = toOptionalTrimmedString(record.version);
  const challengeId = toOptionalTrimmedString(record.challengeId);
  const rpId = toOptionalTrimmedString(record.rpId);
  const expectedUserId = toOptionalTrimmedString(record.expectedUserId);
  const challengeB64u = toOptionalTrimmedString(record.challengeB64u);
  const createdAtMs = positiveInteger(record.createdAtMs);
  const expiresAtMs = positiveInteger(record.expiresAtMs);
  if (version !== 'webauthn_sync_challenge_v1') return null;
  if (!challengeId || !rpId || !challengeB64u) return null;
  if (createdAtMs === null || expiresAtMs === null) return null;
  return {
    version: 'webauthn_sync_challenge_v1',
    challengeId,
    rpId,
    ...(expectedUserId ? { expectedUserId } : {}),
    challengeB64u,
    createdAtMs,
    expiresAtMs,
  };
}

export function parseWebAuthnRecoveryRegistrationChallengeRecord(
  input: unknown,
): WebAuthnRecoveryRegistrationChallengeRecord | null {
  const record = parseJsonRecord(input);
  if (!record) return null;
  const fields = Object.keys(record);
  const expectedFields = [
    'version',
    'challengeId',
    'walletId',
    'reservationId',
    'recoveryOperationId',
    'targetDeviceId',
    'targetAuthorityId',
    'targetWalletAuthMethodId',
    'origin',
    'rpId',
    'replacementId',
    'challengeB64u',
    'continuityAnchor',
    'createdAtMs',
    'expiresAtMs',
  ] as const;
  if (
    fields.length !== expectedFields.length ||
    expectedFields.some((field) => !fields.includes(field))
  ) {
    return null;
  }
  const version = toOptionalTrimmedString(record.version);
  const challengeId = toOptionalTrimmedString(record.challengeId);
  const walletId = parseWalletId(record.walletId);
  let reservationId: RecoveryCodeReservationId | null = null;
  try {
    reservationId = parseRecoveryCodeReservationId(record.reservationId);
  } catch {
    reservationId = null;
  }
  const recoveryOperationId = parseWalletRecoveryOperationId(record.recoveryOperationId);
  const targetDeviceId = parseDeviceId(record.targetDeviceId);
  const targetAuthorityId = parseWalletAuthorityId(record.targetAuthorityId);
  const targetWalletAuthMethodId = parseWalletAuthMethodId(record.targetWalletAuthMethodId);
  const origin = toOptionalTrimmedString(record.origin);
  const rpId = parseWebAuthnRpId(record.rpId);
  const replacementId = toOptionalTrimmedString(record.replacementId);
  const challengeB64u = toOptionalTrimmedString(record.challengeB64u);
  const continuityAnchor = parseWebAuthnRecoveryContinuityAnchor(record.continuityAnchor);
  const createdAtMs = positiveInteger(record.createdAtMs);
  const expiresAtMs = positiveInteger(record.expiresAtMs);
  if (version !== 'webauthn_recovery_registration_challenge_v2') return null;
  if (
    !challengeId ||
    !walletId.ok ||
    !reservationId ||
    !recoveryOperationId.ok ||
    !targetDeviceId.ok ||
    !targetAuthorityId.ok ||
    !targetWalletAuthMethodId.ok ||
    !origin ||
    !rpId.ok ||
    !replacementId ||
    !challengeB64u ||
    !continuityAnchor ||
    continuityAnchor.method.walletId !== walletId.value ||
    continuityAnchor.envelope.walletId !== walletId.value
  ) {
    return null;
  }
  if (
    createdAtMs === null ||
    expiresAtMs === null ||
    expiresAtMs <= createdAtMs
  )
    return null;
  return {
    version: 'webauthn_recovery_registration_challenge_v2',
    challengeId,
    walletId: walletId.value,
    reservationId,
    recoveryOperationId: recoveryOperationId.value,
    targetDeviceId: targetDeviceId.value,
    targetAuthorityId: targetAuthorityId.value,
    targetWalletAuthMethodId: targetWalletAuthMethodId.value,
    origin,
    rpId: rpId.value,
    replacementId,
    challengeB64u,
    continuityAnchor,
    createdAtMs,
    expiresAtMs,
  };
}

function parseWebAuthnRecoveryContinuityAnchor(
  input: unknown,
): WebAuthnRecoveryContinuityAnchorRecord | null {
  const record = parseJsonRecord(input);
  if (!record) return null;
  const expectedFields = [
    'kind',
    'walletAuthMethodId',
    'walletAuthorityId',
    'authorityDigestB64u',
    'provenanceKind',
    'method',
    'envelope',
  ] as const;
  const fields = Object.keys(record);
  if (
    fields.length !== expectedFields.length ||
    expectedFields.some((field) => !fields.includes(field))
  ) {
    return null;
  }
  if (record.kind !== 'wallet_recovery_continuity_anchor_v1') return null;
  const walletAuthMethodId = parseWalletAuthMethodId(record.walletAuthMethodId);
  const walletAuthorityId = parseWalletAuthorityId(record.walletAuthorityId);
  const authorityDigestB64u = parseWalletAuthorityBindingDigest(record.authorityDigestB64u);
  const provenanceKind = parseWalletAuthorityProvenanceKind(record.provenanceKind);
  const method = parseWalletAuthMethodRecordV2(record.method);
  const envelope = parseWebAuthnRecoveryContinuityEnvelopeAnchor(record.envelope);
  if (
    !walletAuthMethodId.ok ||
    !walletAuthorityId.ok ||
    !authorityDigestB64u.ok ||
    !provenanceKind ||
    !method ||
    method.status !== 'active' ||
    !envelope ||
    method.walletAuthMethodId !== walletAuthMethodId.value ||
    method.walletAuthorityId !== walletAuthorityId.value
  ) {
    return null;
  }
  if (method.kind === 'passkey') {
    if (
      envelope.kind !== 'passkey' ||
      envelope.rpId !== method.rpId ||
      envelope.credentialIdB64u !== method.credentialIdB64u
    ) {
      return null;
    }
  } else if (envelope.kind !== 'email_otp') {
    return null;
  }
  return {
    kind: 'wallet_recovery_continuity_anchor_v1',
    walletAuthMethodId: walletAuthMethodId.value,
    walletAuthorityId: walletAuthorityId.value,
    authorityDigestB64u: authorityDigestB64u.value,
    provenanceKind,
    method,
    envelope,
  };
}

export function buildWebAuthnRecoveryContinuityAnchorRecord(input: {
  readonly walletAuthMethodId: WalletAuthMethodId;
  readonly walletAuthorityId: WalletAuthorityId;
  readonly authorityDigestB64u: WalletAuthorityBindingDigest;
  readonly provenanceKind: WalletAuthorityProvenanceV1['kind'];
  readonly method: Extract<WalletAuthMethodRecordV2, { readonly status: 'active' }>;
  readonly envelope: PasskeyCustodyEnvelopeRecord;
}): WebAuthnRecoveryContinuityAnchorRecord {
  if (
    input.method.walletAuthMethodId !== input.walletAuthMethodId ||
    input.method.walletAuthorityId !== input.walletAuthorityId ||
    input.envelope.walletId !== input.method.walletId ||
    input.envelope.lifecycle.state !== 'active' ||
    input.envelope.binding.kind !== 'wallet_custody_seed_v1' ||
    input.envelope.ownership.kind !== 'method_bound' ||
    input.envelope.ownership.walletAuthMethodId !== input.walletAuthMethodId
  ) {
    throw new Error('continuity anchor method and envelope identities do not match');
  }
  const envelope = buildWebAuthnRecoveryContinuityEnvelopeAnchor(input.envelope);
  if (input.method.kind === 'passkey') {
    if (
      envelope.kind !== 'passkey' ||
      envelope.rpId !== input.method.rpId ||
      envelope.credentialIdB64u !== input.method.credentialIdB64u
    ) {
      throw new Error('passkey continuity anchor factor does not match its method');
    }
  } else if (envelope.kind !== 'email_otp') {
    throw new Error('email continuity anchor factor does not match its method');
  }
  return {
    kind: 'wallet_recovery_continuity_anchor_v1',
    walletAuthMethodId: input.walletAuthMethodId,
    walletAuthorityId: input.walletAuthorityId,
    authorityDigestB64u: input.authorityDigestB64u,
    provenanceKind: input.provenanceKind,
    method: input.method,
    envelope,
  };
}

function buildWebAuthnRecoveryContinuityEnvelopeAnchor(
  envelope: PasskeyCustodyEnvelopeRecord,
): WebAuthnRecoveryContinuityEnvelopeAnchorRecord {
  if (envelope.lifecycle.state !== 'active') {
    throw new Error('continuity anchor envelope must be active');
  }
  switch (envelope.factor.kind) {
    case 'passkey':
      return {
        kind: 'passkey',
        envelopeId: envelope.envelopeId,
        walletId: envelope.walletId,
        rpId: envelope.factor.rpId,
        credentialIdB64u: envelope.factor.credentialIdB64u,
        envelopeRevision: envelope.envelopeRevision,
        updatedAtMs: envelope.updatedAtMs,
        bindingKind: 'wallet_custody_seed_v1',
      };
    case 'email_otp':
      return {
        kind: 'email_otp',
        envelopeId: envelope.envelopeId,
        walletId: envelope.walletId,
        enrollmentId: envelope.factor.enrollmentId,
        enrollmentSealKeyVersion: envelope.factor.enrollmentSealKeyVersion,
        envelopeRevision: envelope.envelopeRevision,
        updatedAtMs: envelope.updatedAtMs,
        bindingKind: 'wallet_custody_seed_v1',
      };
  }
}

function parseWebAuthnRecoveryContinuityEnvelopeAnchor(
  input: unknown,
): WebAuthnRecoveryContinuityEnvelopeAnchorRecord | null {
  const record = parseJsonRecord(input);
  if (!record) return null;
  const kind = toOptionalTrimmedString(record.kind);
  const envelopeId = parsePasskeyEnvelopeId(record.envelopeId);
  const walletId = parseWalletId(record.walletId);
  const envelopeRevision = parseRecoveryEnvelopeRevision(record.envelopeRevision);
  const updatedAtMs = positiveInteger(record.updatedAtMs);
  if (
    !kind ||
    !envelopeId.ok ||
    !walletId.ok ||
    !envelopeRevision ||
    updatedAtMs === null ||
    record.bindingKind !== 'wallet_custody_seed_v1'
  ) {
    return null;
  }
  if (kind === 'passkey') {
    if (!hasExactFields(record, [
      'kind',
      'envelopeId',
      'walletId',
      'rpId',
      'credentialIdB64u',
      'envelopeRevision',
      'updatedAtMs',
      'bindingKind',
    ])) {
      return null;
    }
    const rpId = parseWebAuthnRpId(record.rpId);
    const credentialIdB64u = parseWebAuthnCredentialIdB64u(record.credentialIdB64u);
    if (!rpId.ok || !credentialIdB64u.ok) return null;
    return {
      kind: 'passkey',
      envelopeId: envelopeId.value,
      walletId: walletId.value,
      rpId: rpId.value,
      credentialIdB64u: credentialIdB64u.value,
      envelopeRevision,
      updatedAtMs,
      bindingKind: 'wallet_custody_seed_v1',
    };
  }
  if (kind === 'email_otp') {
    if (!hasExactFields(record, [
      'kind',
      'envelopeId',
      'walletId',
      'enrollmentId',
      'enrollmentSealKeyVersion',
      'envelopeRevision',
      'updatedAtMs',
      'bindingKind',
    ])) {
      return null;
    }
    const enrollmentId = toOptionalTrimmedString(record.enrollmentId);
    const enrollmentSealKeyVersion = toOptionalTrimmedString(record.enrollmentSealKeyVersion);
    if (!enrollmentId || !enrollmentSealKeyVersion) return null;
    return {
      kind: 'email_otp',
      envelopeId: envelopeId.value,
      walletId: walletId.value,
      enrollmentId,
      enrollmentSealKeyVersion,
      envelopeRevision,
      updatedAtMs,
      bindingKind: 'wallet_custody_seed_v1',
    };
  }
  return null;
}

function parseRecoveryEnvelopeRevision(input: unknown): EnvelopeRevision | null {
  try {
    return parseEnvelopeRevision(input);
  } catch {
    return null;
  }
}

function hasExactFields(record: Record<string, unknown>, expectedFields: readonly string[]): boolean {
  const fields = Object.keys(record);
  return (
    fields.length === expectedFields.length &&
    expectedFields.every((field) => fields.includes(field))
  );
}

function parseWalletAuthorityProvenanceKind(
  input: unknown,
): WalletAuthorityProvenanceV1['kind'] | null {
  switch (input) {
    case 'wallet_registration':
    case 'device_link':
    case 'wallet_recovery':
      return input;
    default:
      return null;
  }
}

export function parseWebAuthnAuthenticator(
  row: D1AuthenticatorRow | null,
): WebAuthnAuthenticatorRecord | null {
  const credentialIdB64u = toOptionalTrimmedString(row?.credential_id_b64u);
  const credentialPublicKeyB64u = toOptionalTrimmedString(row?.credential_public_key_b64u);
  const counter = nonNegativeSafeInteger(row?.counter);
  const createdAtMs = positiveInteger(row?.created_at_ms);
  const updatedAtMs = positiveInteger(row?.updated_at_ms);
  if (!credentialIdB64u || !credentialPublicKeyB64u) return null;
  if (counter === null || createdAtMs === null || updatedAtMs === null) return null;
  return {
    credentialIdB64u,
    credentialPublicKeyB64u,
    counter,
    createdAtMs,
    updatedAtMs,
    deviceInfo: parseWebAuthnAuthenticatorRowDeviceInfo(row?.device_info_json),
  };
}

export function parseWebAuthnBinding(row: D1RecordJsonRow): WebAuthnCredentialBindingRecord | null {
  const record = parseJsonRecord(row.record_json);
  if (!record) return null;
  const version = toOptionalTrimmedString(record.version);
  const rpId = toOptionalTrimmedString(record.rpId);
  const credentialIdB64u = toOptionalTrimmedString(record.credentialIdB64u);
  const userId = toOptionalTrimmedString(record.userId);
  // signerSlot is absent until the wallet's Ed25519 Yao ceremony settles, the
  // same way nearAccountId/publicKey below already are.
  const signerSlot = positiveInteger(record.signerSlot);
  if (version !== 'webauthn_credential_binding_v1' || !rpId || !credentialIdB64u || !userId)
    return null;
  const nearAccountId = toOptionalTrimmedString(record.nearAccountId);
  const nearEd25519SigningKeyId = toOptionalTrimmedString(record.nearEd25519SigningKeyId);
  const publicKey = toOptionalTrimmedString(record.publicKey);
  const relayerKeyId = toOptionalTrimmedString(record.relayerKeyId);
  const keyVersion = toOptionalTrimmedString(record.keyVersion);
  const clientParticipantId = optionalNonNegativeInteger(record.clientParticipantId);
  const relayerParticipantId = optionalNonNegativeInteger(record.relayerParticipantId);
  const participantIds = optionalNumberArray(record.participantIds);
  const runtimePolicyScope =
    record.runtimePolicyScope && typeof record.runtimePolicyScope === 'object'
      ? (() => {
          try {
            return normalizeRuntimePolicyScope(
              record.runtimePolicyScope,
            ) satisfies ThresholdRuntimePolicyScope;
          } catch {
            return undefined;
          }
        })()
      : undefined;
  const createdAtMs = positiveInteger(record.createdAtMs);
  const updatedAtMs = positiveInteger(record.updatedAtMs);
  if (createdAtMs === null || updatedAtMs === null) return null;
  const base = {
    version: 'webauthn_credential_binding_v1' as const,
    rpId,
    credentialIdB64u,
    userId,
    ...(relayerKeyId ? { relayerKeyId } : {}),
    ...(keyVersion ? { keyVersion } : {}),
    ...(typeof record.recoveryExportCapable === 'boolean'
      ? { recoveryExportCapable: record.recoveryExportCapable }
      : {}),
    ...(clientParticipantId !== undefined ? { clientParticipantId } : {}),
    ...(relayerParticipantId !== undefined ? { relayerParticipantId } : {}),
    ...(participantIds ? { participantIds } : {}),
    ...(runtimePolicyScope ? { runtimePolicyScope } : {}),
    createdAtMs,
    updatedAtMs,
  };
  const hasAnyEd25519Fact =
    Boolean(nearAccountId || nearEd25519SigningKeyId || publicKey) || signerSlot !== null;
  if (!hasAnyEd25519Fact) return base;
  if (!nearAccountId || !nearEd25519SigningKeyId || !publicKey || signerSlot === null) return null;
  return {
    ...base,
    nearAccountId,
    nearEd25519SigningKeyId,
    publicKey,
    signerSlot,
  };
}

export function webAuthnSyncWalletBindingFromCredentialBinding(
  binding: WebAuthnCredentialBindingRecord,
): WebAuthnSyncWalletBinding | null {
  const { nearAccountId, nearEd25519SigningKeyId, signerSlot } = binding;
  if (!nearAccountId || !nearEd25519SigningKeyId || signerSlot === undefined) return null;
  return {
    walletId: binding.userId,
    nearAccountId,
    nearEd25519SigningKeyId,
    rpId: binding.rpId,
    credentialIdB64u: binding.credentialIdB64u,
    signerSlot,
  };
}

export function parseNearPublicKey(row: D1RecordJsonRow): NearPublicKeyRecord | null {
  const record = parseJsonRecord(row.record_json);
  if (!record) return null;
  const publicKey = toOptionalTrimmedString(record.publicKey);
  const kindRaw = toOptionalTrimmedString(record.kind);
  const kind = parseNearPublicKeyKind(kindRaw);
  const authBinding = parseNearPublicKeyAuthBinding(record);
  if (authBinding === null) return null;
  if (!publicKey || !kind) return null;
  return {
    publicKey,
    kind,
    signerSlot: optionalNonNegativeInteger(record.signerSlot),
    ...(authBinding ? { authBinding } : {}),
    createdAtMs: optionalNonNegativeInteger(record.createdAtMs),
    updatedAtMs: optionalNonNegativeInteger(record.updatedAtMs),
  };
}

function parseJsonRecord(input: unknown): Record<string, unknown> | null {
  if (typeof input === 'string') {
    try {
      return toRecordValue(JSON.parse(input));
    } catch {
      return null;
    }
  }
  return toRecordValue(input);
}

function optionalNumberArray(input: unknown): number[] | undefined {
  if (!Array.isArray(input)) return undefined;
  const values: number[] = [];
  for (const item of input) {
    const value = nonNegativeSafeInteger(item);
    if (value === null) return undefined;
    values.push(value);
  }
  return values;
}

function parseNearPublicKeyKind(input: string | undefined): NearPublicKeyRecord['kind'] | null {
  switch (input) {
    case 'threshold':
    case 'local':
    case 'backup':
    case 'ephemeral':
      return input;
    default:
      return null;
  }
}

function parseNearPublicKeyAuthBinding(
  record: Record<string, unknown>,
): NearPublicKeyAuthBinding | undefined | null {
  if (
    Object.prototype.hasOwnProperty.call(record, 'rpId') ||
    Object.prototype.hasOwnProperty.call(record, 'credentialIdB64u')
  ) {
    return null;
  }
  if (record.authBinding === undefined) return undefined;
  const authBinding = toRecordValue(record.authBinding);
  if (!authBinding) return null;
  const kind = toOptionalTrimmedString(authBinding.kind);
  const rpId = parseWebAuthnRpId(authBinding.rpId);
  const credentialIdB64u = toOptionalTrimmedString(authBinding.credentialIdB64u);
  if (kind !== 'passkey' || !rpId.ok || !credentialIdB64u) return null;
  return { kind: 'passkey', rpId: rpId.value, credentialIdB64u };
}
