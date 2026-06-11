type Brand<TValue, TBrand extends string> = TValue & { readonly __brand: TBrand };

export type UserId = Brand<string, 'UserId'>;
export type VoiceIdEnrollmentId = Brand<string, 'VoiceIdEnrollmentId'>;
export type VoiceIdVerificationId = Brand<string, 'VoiceIdVerificationId'>;
export type VoiceIdPromptSetId = Brand<string, 'VoiceIdPromptSetId'>;
export type VoiceIdModelVersion = Brand<string, 'VoiceIdModelVersion'>;
export type VoiceIdTemplateVersion = Brand<string, 'VoiceIdTemplateVersion'>;
export type VoiceIdThresholdVersion = Brand<string, 'VoiceIdThresholdVersion'>;
export type IsoDateTime = Brand<string, 'IsoDateTime'>;
export type EncryptedBytes = Brand<string, 'EncryptedBytes'>;

function parseNonEmptyBrandedString<TBrand extends string>(
  value: unknown,
  fieldName: string,
): Brand<string, TBrand> {
  if (typeof value !== 'string' || value.trim().length === 0) {
    throw new Error(`${fieldName} must be a non-empty string`);
  }

  return value as Brand<string, TBrand>;
}

export function parseUserId(value: unknown): UserId {
  return parseNonEmptyBrandedString(value, 'userId');
}

export function parseEnrollmentId(value: unknown): VoiceIdEnrollmentId {
  return parseNonEmptyBrandedString(value, 'enrollmentId');
}

export function parseVerificationId(value: unknown): VoiceIdVerificationId {
  return parseNonEmptyBrandedString(value, 'verificationId');
}

export function parsePromptSetId(value: unknown): VoiceIdPromptSetId {
  return parseNonEmptyBrandedString(value, 'promptSetId');
}

export function parseModelVersion(value: unknown): VoiceIdModelVersion {
  return parseNonEmptyBrandedString(value, 'modelVersion');
}

export function parseTemplateVersion(value: unknown): VoiceIdTemplateVersion {
  return parseNonEmptyBrandedString(value, 'templateVersion');
}

export function parseThresholdVersion(value: unknown): VoiceIdThresholdVersion {
  return parseNonEmptyBrandedString(value, 'thresholdVersion');
}

export function parseEncryptedBytes(value: unknown): EncryptedBytes {
  return parseNonEmptyBrandedString(value, 'encryptedTemplate');
}

export function parseIsoDateTime(value: unknown): IsoDateTime {
  const parsed = parseNonEmptyBrandedString<'IsoDateTime'>(value, 'isoDateTime');
  if (Number.isNaN(Date.parse(parsed))) {
    throw new Error('isoDateTime must be an ISO date-time string');
  }

  return parsed;
}

export function createId<TId extends string>(prefix: string, random = cryptoRandomString): TId {
  return `${prefix}_${random()}` as TId;
}

function cryptoRandomString(): string {
  const cryptoApi = globalThis.crypto;
  if (cryptoApi) {
    const bytes = new Uint8Array(16);
    cryptoApi.getRandomValues(bytes);
    return Array.from(bytes, (byte) => byte.toString(16).padStart(2, '0')).join('');
  }

  return `${Date.now().toString(36)}_${Math.random().toString(36).slice(2)}`;
}

export function nowIsoDateTime(now = new Date()): IsoDateTime {
  return parseIsoDateTime(now.toISOString());
}
