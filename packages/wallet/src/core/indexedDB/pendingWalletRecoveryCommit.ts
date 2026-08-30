import { parseDeviceId, type DeviceId } from '@shared/authorization/capabilityKinds';
import { alphabetizeStringify } from '@shared/utils/digests';
import { base64UrlDecode, base64UrlEncode } from '@shared/utils/encoders';
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
const LOCAL_MATERIAL_CODEC_KIND = 'pending_wallet_recovery_plaintext_codec_v1' as const;
const FORBIDDEN_PLAINTEXT_KEY =
  /^(?:recoveryCode(?:Bytes|B64u|Plaintext)?|otpCode|idToken|custodySeed(?:B64u)?|walletCustodySeed(?:B64u)?|seed(?:B64u)?|recoverySecret(?:B64u)?|factorSecret(?:32|B64u)?|clientSecret32|ownedFactorSecret(?:B64u)?|prf(?:Output|First|_output|_first|FirstB64u|_first_b64u)?|passkeyPrfFirstB64u|nearPrivateKey|privateKey|canonicalSeed(?:B64u)?|signingShare32(?:B64u)?|xClientBase(?:B64u)?|clientOutputMask(?:B64u)?)$/i;
const MAX_LOCAL_MATERIAL_CODEC_DEPTH = 32;

type PendingWalletRecoveryEncodedValueV1 =
  | null
  | boolean
  | string
  | number
  | { readonly kind: 'bigint'; readonly decimal: string }
  | { readonly kind: 'uint8_array'; readonly bytesB64u: string }
  | { readonly kind: 'array'; readonly items: readonly PendingWalletRecoveryEncodedValueV1[] }
  | {
      readonly kind: 'record';
      readonly entries: readonly {
        readonly key: string;
        readonly value: PendingWalletRecoveryEncodedValueV1;
      }[];
    };

type PendingWalletRecoveryPlaintextEnvelopeV1 = {
  readonly kind: typeof LOCAL_MATERIAL_CODEC_KIND;
  readonly value: PendingWalletRecoveryEncodedValueV1;
};

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

export function pendingWalletRecoveryCommitAppStateKey(
  recoveryOperationId: WalletRecoveryOperationId,
): string {
  return `${APP_STATE_PREFIX}${String(recoveryOperationId)}`;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function encodePendingWalletRecoveryValue(
  value: unknown,
  path: string,
  depth = 0,
): PendingWalletRecoveryEncodedValueV1 {
  if (depth > MAX_LOCAL_MATERIAL_CODEC_DEPTH) {
    throw new Error(`pending wallet recovery plaintext ${path} is too deeply nested`);
  }
  if (value === null || typeof value === 'boolean' || typeof value === 'string') return value;
  if (typeof value === 'number') {
    if (!Number.isFinite(value) || !Number.isSafeInteger(value) || Object.is(value, -0)) {
      throw new Error(`pending wallet recovery plaintext ${path} has an invalid number`);
    }
    return value;
  }
  if (typeof value === 'bigint') return { kind: 'bigint', decimal: value.toString(10) };
  if (value instanceof Uint8Array) {
    return { kind: 'uint8_array', bytesB64u: base64UrlEncode(value) };
  }
  if (Array.isArray(value)) {
    const items: PendingWalletRecoveryEncodedValueV1[] = [];
    for (let index = 0; index < value.length; index += 1) {
      items.push(encodePendingWalletRecoveryValue(value[index], `${path}[${index}]`, depth + 1));
    }
    return {
      kind: 'array',
      items,
    };
  }
  if (!isRecord(value) || Object.getPrototypeOf(value) !== Object.prototype) {
    throw new Error(`pending wallet recovery plaintext ${path} is not a plain record`);
  }
  const entries: {
    readonly key: string;
    readonly value: PendingWalletRecoveryEncodedValueV1;
  }[] = [];
  for (const key of Object.keys(value).sort()) {
    if (
      FORBIDDEN_PLAINTEXT_KEY.test(key) ||
      key === '__proto__' ||
      key === 'constructor' ||
      key === 'prototype'
    ) {
      throw new Error(`pending wallet recovery plaintext contains forbidden field ${key}`);
    }
    const child = value[key];
    if (child === undefined) {
      throw new Error(`pending wallet recovery plaintext ${path}.${key} is undefined`);
    }
    entries.push({
      key,
      value: encodePendingWalletRecoveryValue(child, `${path}.${key}`, depth + 1),
    });
  }
  return { kind: 'record', entries };
}

function decodePendingWalletRecoveryValue(
  raw: unknown,
  path: string,
  depth = 0,
): unknown {
  if (depth > MAX_LOCAL_MATERIAL_CODEC_DEPTH) {
    throw new Error(`pending wallet recovery plaintext ${path} is too deeply nested`);
  }
  if (
    raw === null ||
    typeof raw === 'boolean' ||
    typeof raw === 'string' ||
    (typeof raw === 'number' && Number.isSafeInteger(raw) && !Object.is(raw, -0))
  ) {
    return raw;
  }
  if (!isRecord(raw) || typeof raw.kind !== 'string') {
    throw new Error(`pending wallet recovery plaintext ${path} is invalid`);
  }
  switch (raw.kind) {
    case 'bigint': {
      if (
        !hasExactKeys(raw, ['kind', 'decimal']) ||
        typeof raw.decimal !== 'string' ||
        !/^(?:0|[1-9][0-9]*|-[1-9][0-9]*)$/.test(raw.decimal)
      ) {
        throw new Error(`pending wallet recovery plaintext ${path} bigint is invalid`);
      }
      return BigInt(raw.decimal);
    }
    case 'uint8_array': {
      if (!hasExactKeys(raw, ['kind', 'bytesB64u']) || typeof raw.bytesB64u !== 'string') {
        throw new Error(`pending wallet recovery plaintext ${path} bytes are invalid`);
      }
      const bytes = base64UrlDecode(raw.bytesB64u);
      if (base64UrlEncode(bytes) !== raw.bytesB64u) {
        throw new Error(`pending wallet recovery plaintext ${path} bytes are not canonical`);
      }
      return Uint8Array.from(bytes);
    }
    case 'array': {
      if (!hasExactKeys(raw, ['kind', 'items']) || !Array.isArray(raw.items)) {
        throw new Error(`pending wallet recovery plaintext ${path} array is invalid`);
      }
      const items: unknown[] = [];
      for (let index = 0; index < raw.items.length; index += 1) {
        items.push(
          decodePendingWalletRecoveryValue(raw.items[index], `${path}[${index}]`, depth + 1),
        );
      }
      return items;
    }
    case 'record': {
      if (!hasExactKeys(raw, ['kind', 'entries']) || !Array.isArray(raw.entries)) {
        throw new Error(`pending wallet recovery plaintext ${path} record is invalid`);
      }
      const result: Record<string, unknown> = {};
      let previousKey = '';
      for (const [index, entryRaw] of raw.entries.entries()) {
        if (!isRecord(entryRaw) || !hasExactKeys(entryRaw, ['key', 'value'])) {
          throw new Error(`pending wallet recovery plaintext ${path} entry is invalid`);
        }
        const key = nonEmptyString(entryRaw.key);
        if (!key || FORBIDDEN_PLAINTEXT_KEY.test(key) || (index > 0 && key <= previousKey)) {
          throw new Error(`pending wallet recovery plaintext ${path} key is invalid`);
        }
        if (key === '__proto__' || key === 'constructor' || key === 'prototype') {
          throw new Error(`pending wallet recovery plaintext ${path} key is invalid`);
        }
        Object.defineProperty(result, key, {
          configurable: true,
          enumerable: true,
          value: decodePendingWalletRecoveryValue(entryRaw.value, `${path}.${key}`, depth + 1),
          writable: true,
        });
        previousKey = key;
      }
      return result;
    }
    default:
      throw new Error(`pending wallet recovery plaintext ${path} tag is invalid`);
  }
}

export async function encryptPendingWalletRecoveryPlaintextV1(
  plaintext: unknown,
): Promise<PendingWalletRecoveryEncryptedMaterialV1> {
  const envelope: PendingWalletRecoveryPlaintextEnvelopeV1 = {
    kind: LOCAL_MATERIAL_CODEC_KIND,
    value: encodePendingWalletRecoveryValue(plaintext, 'value'),
  };
  const key = await crypto.subtle.generateKey({ name: 'AES-GCM', length: 256 }, false, [
    'encrypt',
    'decrypt',
  ]);
  const iv = crypto.getRandomValues(new Uint8Array(AES_GCM_IV_BYTES));
  const encoded = new TextEncoder().encode(JSON.stringify(envelope));
  try {
    const ciphertext = new Uint8Array(
      await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, encoded),
    );
    return { kind: 'wallet_recovery_encrypted_material_v1', key, iv, ciphertext };
  } finally {
    encoded.fill(0);
  }
}

export async function decryptPendingWalletRecoveryPlaintextV1(
  material: PendingWalletRecoveryEncryptedMaterialV1,
): Promise<unknown> {
  const parsedMaterial = parseEncryptedMaterial(material);
  if (!parsedMaterial) throw new Error('pending wallet recovery encrypted material is invalid');
  const bytes = new Uint8Array(
    await crypto.subtle.decrypt(
      { name: 'AES-GCM', iv: parsedMaterial.iv },
      parsedMaterial.key,
      parsedMaterial.ciphertext,
    ),
  );
  try {
    const raw: unknown = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes));
    if (
      !isRecord(raw) ||
      !hasExactKeys(raw, ['kind', 'value']) ||
      raw.kind !== LOCAL_MATERIAL_CODEC_KIND
    ) {
      throw new Error('pending wallet recovery plaintext envelope is invalid');
    }
    return decodePendingWalletRecoveryValue(raw.value, 'value');
  } finally {
    bytes.fill(0);
  }
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
  if (
    typeof CryptoKey === 'undefined' ||
    !(value instanceof CryptoKey) ||
    value.type !== 'secret' ||
    value.extractable !== false ||
    value.algorithm.name !== 'AES-GCM' ||
    value.usages.length !== 2 ||
    !value.usages.includes('encrypt') ||
    !value.usages.includes('decrypt')
  ) {
    return false;
  }
  return 'length' in value.algorithm && value.algorithm.length === 256;
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
