import { parseDeviceId, type DeviceId } from '@shared/authorization/capabilityKinds';
import { alphabetizeStringify } from '@shared/utils/digests';
import {
  parseWalletAuthMethodId,
  parseWalletAuthorityId,
  parseWalletId,
  parseWalletRecoveryOperationId,
  parseEmailOtpProviderUserId,
  parseWebAuthnCredentialIdB64u,
  parseWebAuthnRpId,
  type EmailOtpProviderUserId,
  type WalletAuthMethodId,
  type WalletAuthorityId,
  type WalletId,
  type WalletRecoveryOperationId,
  type WebAuthnCredentialIdB64u,
  type WebAuthnRpId,
} from '@shared/utils/domainIds';
import {
  parseRecoveryCodeReservationId,
  type RecoveryCodeReservationId,
} from '@shared/wallet-recovery/recoveryCodeReservation';
import {
  parseWalletRecoveryCommittedProjectionV1,
  type WalletRecoveryCommittedProjectionExpectationV1,
  type WalletRecoveryCommittedProjectionV1,
  type WalletRecoveryEmailOtpEnrollmentReferenceV1,
} from '@shared/wallet-recovery/walletRecoveryCommittedProjection';

const RECORD_KIND = 'pending_wallet_recovery_commit_v1' as const;
const RECORD_VERSION = 1 as const;
const APP_STATE_PREFIX = `${RECORD_KIND}:`;
const AES_GCM_IV_BYTES = 12;

/**
 * Local recovery material is carried as one encrypted envelope. The key is a
 * non-extractable WebCrypto key and the plaintext never enters IndexedDB.
 * Public projection identities remain outside the envelope for strict replay
 * matching.
 */
export type PendingWalletRecoveryEncryptedMaterialV1 = {
  readonly kind: 'wallet_recovery_encrypted_material_v1';
  readonly key: CryptoKey;
  readonly iv: Uint8Array;
  readonly ciphertext: Uint8Array;
};

export type PendingWalletRecoveryTargetIdentityV1 =
  | {
      readonly kind: 'passkey';
      readonly rpId: WebAuthnRpId;
      readonly credentialIdB64u: WebAuthnCredentialIdB64u;
    }
  | {
      readonly kind: 'google_email_otp';
      readonly providerSubject: EmailOtpProviderUserId;
      readonly emailHashHex: string;
      readonly registrationAuthorityId: string;
      readonly enrollment: WalletRecoveryEmailOtpEnrollmentReferenceV1;
    };

type PendingWalletRecoveryCommitCommonV1 = {
  readonly kind: typeof RECORD_KIND;
  readonly version: typeof RECORD_VERSION;
  readonly recoveryOperationId: WalletRecoveryOperationId;
  readonly walletId: WalletId;
  readonly reservationId: RecoveryCodeReservationId;
  readonly targetDeviceId: DeviceId;
  readonly targetAuthorityId: WalletAuthorityId;
  readonly targetWalletAuthMethodId: WalletAuthMethodId;
  readonly localMaterial: PendingWalletRecoveryEncryptedMaterialV1;
  readonly createdAtMs: number;
  readonly updatedAtMs: number;
};

type PendingWalletRecoveryCommitIdentityV1 = PendingWalletRecoveryCommitCommonV1 & {
  readonly target: PendingWalletRecoveryTargetIdentityV1;
};

export type PendingWalletRecoveryCommitV1 =
  | (PendingWalletRecoveryCommitIdentityV1 & {
      readonly stage: 'awaiting_server_promotion';
      readonly projection?: never;
    })
  | (PendingWalletRecoveryCommitCommonV1 & {
      readonly stage: 'server_promoted';
      readonly target: Extract<PendingWalletRecoveryTargetIdentityV1, { readonly kind: 'passkey' }>;
      readonly projection: Extract<
        WalletRecoveryCommittedProjectionV1,
        { readonly kind: 'passkey' }
      >;
    })
  | (PendingWalletRecoveryCommitCommonV1 & {
      readonly stage: 'server_promoted';
      readonly target: Extract<
        PendingWalletRecoveryTargetIdentityV1,
        { readonly kind: 'google_email_otp' }
      >;
      readonly projection: Extract<
        WalletRecoveryCommittedProjectionV1,
        { readonly kind: 'google_email_otp' }
      >;
    });

export type PendingWalletRecoveryCommitStorageRow = {
  readonly recovery_operation_id: WalletRecoveryOperationId;
  readonly stage: PendingWalletRecoveryCommitV1['stage'];
  readonly wallet_id: WalletId;
  readonly target_authority_id: WalletAuthorityId;
  readonly target_wallet_auth_method_id: WalletAuthMethodId;
  readonly updated_at_ms: number;
  readonly record: PendingWalletRecoveryCommitV1;
};

export type PendingWalletRecoveryPromotionAdvanceInputV1 = {
  readonly awaiting: Extract<
    PendingWalletRecoveryCommitV1,
    { readonly stage: 'awaiting_server_promotion' }
  >;
  readonly promoted: Extract<
    PendingWalletRecoveryCommitV1,
    { readonly stage: 'server_promoted' }
  >;
};

export function pendingWalletRecoveryCommitIdentityMatches(
  left: PendingWalletRecoveryCommitV1,
  right: PendingWalletRecoveryCommitV1,
): boolean {
  return (
    left.recoveryOperationId === right.recoveryOperationId &&
    left.walletId === right.walletId &&
    left.reservationId === right.reservationId &&
    left.targetDeviceId === right.targetDeviceId &&
    left.targetAuthorityId === right.targetAuthorityId &&
    left.targetWalletAuthMethodId === right.targetWalletAuthMethodId &&
    left.target.kind === right.target.kind &&
    (left.target.kind === 'passkey'
      ? right.target.kind === 'passkey' &&
        left.target.rpId === right.target.rpId &&
        left.target.credentialIdB64u === right.target.credentialIdB64u
      : right.target.kind === 'google_email_otp' &&
        left.target.providerSubject === right.target.providerSubject &&
        left.target.emailHashHex === right.target.emailHashHex &&
        left.target.registrationAuthorityId === right.target.registrationAuthorityId &&
        left.target.enrollment.enrollmentId === right.target.enrollment.enrollmentId &&
        left.target.enrollment.enrollmentSealKeyVersion ===
          right.target.enrollment.enrollmentSealKeyVersion) &&
    left.createdAtMs === right.createdAtMs
  );
}

export function pendingWalletRecoveryCommitAppStateKey(
  recoveryOperationId: WalletRecoveryOperationId,
): string {
  return `${APP_STATE_PREFIX}${String(recoveryOperationId)}`;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function hasExactKeys(record: Record<string, unknown>, keys: readonly string[]): boolean {
  const expected = new Set(keys);
  const actual = Object.keys(record);
  return actual.length === keys.length && actual.every((key) => expected.has(key));
}

function nonEmptyString(value: unknown): string | null {
  if (typeof value !== 'string' || value.length === 0 || value.trim() !== value) return null;
  return value;
}

function positiveSafeInteger(value: unknown): number | null {
  return typeof value === 'number' && Number.isSafeInteger(value) && value > 0 ? value : null;
}

function isNonExtractableAesGcmKey(value: unknown): value is CryptoKey {
  return (
    typeof CryptoKey !== 'undefined' &&
    value instanceof CryptoKey &&
    value.type === 'secret' &&
    value.extractable === false &&
    value.algorithm.name === 'AES-GCM' &&
    value.usages.includes('encrypt') &&
    value.usages.includes('decrypt')
  );
}

function parseEncryptedMaterial(raw: unknown): PendingWalletRecoveryEncryptedMaterialV1 | null {
  if (
    !isRecord(raw) ||
    !hasExactKeys(raw, ['kind', 'key', 'iv', 'ciphertext']) ||
    raw.kind !== 'wallet_recovery_encrypted_material_v1' ||
    !isNonExtractableAesGcmKey(raw.key) ||
    !(raw.iv instanceof Uint8Array) ||
    raw.iv.byteLength !== AES_GCM_IV_BYTES ||
    !(raw.ciphertext instanceof Uint8Array) ||
    raw.ciphertext.byteLength === 0
  ) {
    return null;
  }
  return {
    kind: 'wallet_recovery_encrypted_material_v1',
    key: raw.key,
    iv: raw.iv,
    ciphertext: raw.ciphertext,
  };
}

function parseEnrollmentReference(
  raw: unknown,
): WalletRecoveryEmailOtpEnrollmentReferenceV1 | null {
  if (
    !isRecord(raw) ||
    !hasExactKeys(raw, ['kind', 'enrollmentId', 'enrollmentSealKeyVersion']) ||
    raw.kind !== 'email_otp_enrollment_reference_v1'
  ) {
    return null;
  }
  const enrollmentId = nonEmptyString(raw.enrollmentId);
  const enrollmentSealKeyVersion = nonEmptyString(raw.enrollmentSealKeyVersion);
  if (!enrollmentId || !enrollmentSealKeyVersion) return null;
  return {
    kind: 'email_otp_enrollment_reference_v1',
    enrollmentId,
    enrollmentSealKeyVersion,
  };
}

function parseTarget(raw: unknown): PendingWalletRecoveryTargetIdentityV1 | null {
  if (!isRecord(raw) || typeof raw.kind !== 'string') return null;
  if (raw.kind === 'passkey') {
    if (!hasExactKeys(raw, ['kind', 'rpId', 'credentialIdB64u'])) return null;
    const rpId = parseWebAuthnRpId(raw.rpId);
    const credentialIdB64u = parseWebAuthnCredentialIdB64u(raw.credentialIdB64u);
    return rpId.ok && credentialIdB64u.ok
      ? { kind: 'passkey', rpId: rpId.value, credentialIdB64u: credentialIdB64u.value }
      : null;
  }
  if (raw.kind !== 'google_email_otp') return null;
  if (
    !hasExactKeys(raw, [
      'kind',
      'providerSubject',
      'emailHashHex',
      'registrationAuthorityId',
      'enrollment',
    ]) ||
    typeof raw.emailHashHex !== 'string' ||
    !/^[0-9a-f]{64}$/.test(raw.emailHashHex)
  ) {
    return null;
  }
  const providerSubject = parseEmailOtpProviderUserId(raw.providerSubject);
  const registrationAuthorityId = nonEmptyString(raw.registrationAuthorityId);
  const enrollment = parseEnrollmentReference(raw.enrollment);
  return providerSubject.ok && registrationAuthorityId && enrollment
    ? {
        kind: 'google_email_otp',
        providerSubject: providerSubject.value,
        emailHashHex: raw.emailHashHex,
        registrationAuthorityId,
        enrollment,
      }
    : null;
}

function projectionExpectation(
  record: PendingWalletRecoveryCommitIdentityV1,
): WalletRecoveryCommittedProjectionExpectationV1 {
  if (record.target.kind === 'passkey') {
    return {
      kind: 'passkey',
      walletId: record.walletId,
      recoveryOperationId: record.recoveryOperationId,
      targetDeviceId: record.targetDeviceId,
      targetAuthorityId: record.targetAuthorityId,
      targetWalletAuthMethodId: record.targetWalletAuthMethodId,
      rpId: record.target.rpId,
      credentialIdB64u: record.target.credentialIdB64u,
    };
  }
  return {
    kind: 'google_email_otp',
    walletId: record.walletId,
    recoveryOperationId: record.recoveryOperationId,
    targetDeviceId: record.targetDeviceId,
    targetAuthorityId: record.targetAuthorityId,
    targetWalletAuthMethodId: record.targetWalletAuthMethodId,
    providerSubject: record.target.providerSubject,
    emailHashHex: record.target.emailHashHex,
    registrationAuthorityId: record.target.registrationAuthorityId,
    enrollment: record.target.enrollment,
  };
}

export async function parsePendingWalletRecoveryCommitV1(
  raw: unknown,
): Promise<PendingWalletRecoveryCommitV1 | null> {
  if (!isRecord(raw)) return null;
  const baseKeys = [
    'kind',
    'version',
    'stage',
    'recoveryOperationId',
    'walletId',
    'reservationId',
    'targetDeviceId',
    'targetAuthorityId',
    'targetWalletAuthMethodId',
    'target',
    'localMaterial',
    'createdAtMs',
    'updatedAtMs',
  ] as const;
  if (
    (raw.stage === 'server_promoted' && !hasExactKeys(raw, [...baseKeys, 'projection'])) ||
    (raw.stage === 'awaiting_server_promotion' && !hasExactKeys(raw, baseKeys)) ||
    (raw.stage !== 'server_promoted' && raw.stage !== 'awaiting_server_promotion') ||
    raw.kind !== RECORD_KIND ||
    raw.version !== RECORD_VERSION
  ) {
    return null;
  }
  const recoveryOperationId = parseWalletRecoveryOperationId(raw.recoveryOperationId);
  const walletId = parseWalletId(raw.walletId);
  const reservationId = (() => {
    try {
      return parseRecoveryCodeReservationId(raw.reservationId);
    } catch {
      return null;
    }
  })();
  const targetDeviceId = parseDeviceId(raw.targetDeviceId);
  const targetAuthorityId = parseWalletAuthorityId(raw.targetAuthorityId);
  const targetWalletAuthMethodId = parseWalletAuthMethodId(raw.targetWalletAuthMethodId);
  const target = parseTarget(raw.target);
  const localMaterial = parseEncryptedMaterial(raw.localMaterial);
  const createdAtMs = positiveSafeInteger(raw.createdAtMs);
  const updatedAtMs = positiveSafeInteger(raw.updatedAtMs);
  if (
    !recoveryOperationId.ok ||
    !walletId.ok ||
    !reservationId ||
    !targetDeviceId.ok ||
    !targetAuthorityId.ok ||
    !targetWalletAuthMethodId.ok ||
    !target ||
    !localMaterial ||
    createdAtMs === null ||
    updatedAtMs === null ||
    updatedAtMs < createdAtMs
  ) {
    return null;
  }
  const common: PendingWalletRecoveryCommitCommonV1 = {
    kind: RECORD_KIND,
    version: RECORD_VERSION,
    recoveryOperationId: recoveryOperationId.value,
    walletId: walletId.value,
    reservationId,
    targetDeviceId: targetDeviceId.value,
    targetAuthorityId: targetAuthorityId.value,
    targetWalletAuthMethodId: targetWalletAuthMethodId.value,
    localMaterial,
    createdAtMs,
    updatedAtMs,
  };
  if (raw.stage === 'awaiting_server_promotion') {
    return { ...common, stage: raw.stage, target };
  }
  const identity: PendingWalletRecoveryCommitIdentityV1 = { ...common, target };
  let projection: WalletRecoveryCommittedProjectionV1;
  try {
    projection = await parseWalletRecoveryCommittedProjectionV1(
      raw.projection,
      projectionExpectation(identity),
    );
  } catch {
    return null;
  }
  if (projection.kind !== target.kind) return null;
  if (projection.kind === 'passkey' && target.kind === 'passkey') {
    return { ...common, stage: raw.stage, target, projection };
  }
  if (projection.kind === 'google_email_otp' && target.kind === 'google_email_otp') {
    return { ...common, stage: raw.stage, target, projection };
  }
  return null;
}

export async function buildPendingWalletRecoveryCommitV1(
  input: PendingWalletRecoveryCommitV1,
): Promise<PendingWalletRecoveryCommitV1> {
  const parsed = await parsePendingWalletRecoveryCommitV1(input);
  if (!parsed) throw new Error('pending wallet recovery commit is invalid');
  return parsed;
}

export type PendingWalletRecoveryCommitAppStateRow = {
  readonly key: string;
  readonly value: PendingWalletRecoveryCommitStorageRow;
};

export async function toPendingWalletRecoveryCommitAppStateRow(
  record: PendingWalletRecoveryCommitV1,
): Promise<PendingWalletRecoveryCommitAppStateRow> {
  const parsed = await buildPendingWalletRecoveryCommitV1(record);
  const value: PendingWalletRecoveryCommitStorageRow = {
    recovery_operation_id: parsed.recoveryOperationId,
    stage: parsed.stage,
    wallet_id: parsed.walletId,
    target_authority_id: parsed.targetAuthorityId,
    target_wallet_auth_method_id: parsed.targetWalletAuthMethodId,
    updated_at_ms: parsed.updatedAtMs,
    record: parsed,
  };
  return {
    key: pendingWalletRecoveryCommitAppStateKey(parsed.recoveryOperationId),
    value,
  };
}

export async function parsePendingWalletRecoveryCommitAppStateRow(
  raw: unknown,
): Promise<PendingWalletRecoveryCommitStorageRow | null> {
  if (!isRecord(raw) || !hasExactKeys(raw, ['key', 'value'])) return null;
  if (typeof raw.key !== 'string' || !raw.key.startsWith(APP_STATE_PREFIX)) return null;
  if (!isRecord(raw.value)) return null;
  if (
    !hasExactKeys(raw.value, [
      'recovery_operation_id',
      'stage',
      'wallet_id',
      'target_authority_id',
      'target_wallet_auth_method_id',
      'updated_at_ms',
      'record',
    ])
  ) {
    return null;
  }
  const record = await parsePendingWalletRecoveryCommitV1(raw.value.record);
  if (!record) return null;
  if (
    raw.key !== pendingWalletRecoveryCommitAppStateKey(record.recoveryOperationId) ||
    raw.value.recovery_operation_id !== record.recoveryOperationId ||
    raw.value.stage !== record.stage ||
    raw.value.wallet_id !== record.walletId ||
    raw.value.target_authority_id !== record.targetAuthorityId ||
    raw.value.target_wallet_auth_method_id !== record.targetWalletAuthMethodId ||
    raw.value.updated_at_ms !== record.updatedAtMs
  ) {
    return null;
  }
  return {
    recovery_operation_id: record.recoveryOperationId,
    stage: record.stage,
    wallet_id: record.walletId,
    target_authority_id: record.targetAuthorityId,
    target_wallet_auth_method_id: record.targetWalletAuthMethodId,
    updated_at_ms: record.updatedAtMs,
    record,
  };
}

/**
 * Compare an app-state row while it is still inside an IndexedDB transaction.
 * Projection validation happens before opening the transaction because its
 * digest check is asynchronous; this synchronous comparison closes the CAS
 * over the row's public fields and encrypted bytes.
 */
export function pendingWalletRecoveryCommitAppStateRowsMatch(
  raw: unknown,
  expected: PendingWalletRecoveryCommitAppStateRow,
): boolean {
  if (!isRecord(raw) || !hasExactKeys(raw, ['key', 'value']) || raw.key !== expected.key) {
    return false;
  }
  if (
    !isRecord(raw.value) ||
    !hasExactKeys(raw.value, [
      'recovery_operation_id',
      'stage',
      'wallet_id',
      'target_authority_id',
      'target_wallet_auth_method_id',
      'updated_at_ms',
      'record',
    ])
  ) {
    return false;
  }
  const actual = raw.value as Record<string, unknown>;
  const expectedValue = expected.value;
  if (
    actual.recovery_operation_id !== expectedValue.recovery_operation_id ||
    actual.stage !== expectedValue.stage ||
    actual.wallet_id !== expectedValue.wallet_id ||
    actual.target_authority_id !== expectedValue.target_authority_id ||
    actual.target_wallet_auth_method_id !== expectedValue.target_wallet_auth_method_id ||
    actual.updated_at_ms !== expectedValue.updated_at_ms ||
    !isRecord(actual.record)
  ) {
    return false;
  }
  const actualRecord = actual.record;
  const expectedRecord = expectedValue.record;
  const actualMaterial = parseEncryptedMaterial(actualRecord.localMaterial);
  const expectedMaterial = expectedRecord.localMaterial;
  if (
    !actualMaterial ||
    !hasExactKeys(actualRecord, Object.keys(expectedRecord)) ||
    actualMaterial.iv.byteLength !== expectedMaterial.iv.byteLength ||
    actualMaterial.ciphertext.byteLength !== expectedMaterial.ciphertext.byteLength
  ) {
    return false;
  }
  const actualMaterialBytes = {
    iv: Array.from(actualMaterial.iv),
    ciphertext: Array.from(actualMaterial.ciphertext),
  };
  const expectedMaterialBytes = {
    iv: Array.from(expectedMaterial.iv),
    ciphertext: Array.from(expectedMaterial.ciphertext),
  };
  if (alphabetizeStringify(actualMaterialBytes) !== alphabetizeStringify(expectedMaterialBytes)) {
    return false;
  }
  const actualWithoutKey = {
    ...actualRecord,
    localMaterial: {
      ...actualMaterial,
      key: undefined,
      iv: undefined,
      ciphertext: undefined,
    },
  };
  const expectedWithoutKey = {
    ...expectedRecord,
    localMaterial: {
      ...expectedMaterial,
      key: undefined,
      iv: undefined,
      ciphertext: undefined,
    },
  };
  return alphabetizeStringify(actualWithoutKey) === alphabetizeStringify(expectedWithoutKey);
}

export function pendingWalletRecoveryProjectionExpectation(
  record: Extract<PendingWalletRecoveryCommitV1, { readonly stage: 'server_promoted' }>,
): WalletRecoveryCommittedProjectionExpectationV1 {
  return projectionExpectation(record);
}
