import {
  assertNever,
  parseEncryptedBytes,
  type EncryptedBytes,
} from '../../../shared/src/index.ts';
import type { VoiceIdEnrollmentRecord } from '../../../shared/src/records.ts';
import type {
  VoiceIdTemplateEncryptionAadLabel,
  VoiceIdTemplateEncryptionAlgorithm,
  VoiceIdTemplateEncryptionKeyConfig,
  VoiceIdTemplateEncryptionKeyId,
  VoiceIdTemplateEncryptionRotationVersion,
} from './VoiceIdTemplateEncryptionConfig.ts';
import type { VoiceIdEnrollmentStore } from './VoiceIdStores.ts';

export type VoiceIdTemplateEncryptionSecret = {
  kind: 'aes_gcm_256_raw_key';
  bytes: Uint8Array;
};

export type VoiceIdTemplateEncryptionSecretEnv = Readonly<Record<string, unknown>>;

export type VoiceIdTemplateCipher = {
  wrapTemplate(input: VoiceIdTemplateCipherInput): Promise<EncryptedBytes>;
  unwrapTemplate(input: VoiceIdTemplateCipherInput): Promise<EncryptedBytes>;
};

export type VoiceIdTemplateCipherInput = {
  record: Extract<VoiceIdEnrollmentRecord, { state: 'enrolled' | 'disabled' }>;
  encryptedTemplate: EncryptedBytes;
};

export type VoiceIdAesGcmTemplateCipherConfig = {
  keyConfig: VoiceIdTemplateEncryptionKeyConfig;
  secret: VoiceIdTemplateEncryptionSecret;
  randomBytes?: (byteLength: number) => Uint8Array;
  crypto?: Crypto;
};

type VoiceIdTemplateEnvelopeSchemaVersion = 'voiceid-template-wrap-v1';

type VoiceIdTemplateEnvelope = {
  schemaVersion: VoiceIdTemplateEnvelopeSchemaVersion;
  algorithm: VoiceIdTemplateEncryptionAlgorithm;
  keyId: VoiceIdTemplateEncryptionKeyId;
  rotationVersion: VoiceIdTemplateEncryptionRotationVersion;
  aadLabel: VoiceIdTemplateEncryptionAadLabel;
  nonceBase64Url: string;
  ciphertextBase64Url: string;
};

type VoiceIdTemplateAad = {
  schemaVersion: VoiceIdTemplateEnvelopeSchemaVersion;
  aadLabel: VoiceIdTemplateEncryptionAadLabel;
  keyId: VoiceIdTemplateEncryptionKeyId;
  rotationVersion: VoiceIdTemplateEncryptionRotationVersion;
  userId: string;
  enrollmentId: string;
  modelVersion: string;
  templateVersion: string;
  thresholdVersion: string;
};

const envelopeSchemaVersion: VoiceIdTemplateEnvelopeSchemaVersion = 'voiceid-template-wrap-v1';
const envelopePrefix = `${envelopeSchemaVersion}.`;
const aesGcmNonceByteLength = 12;
const aesGcm256KeyByteLength = 32;

function ownedBytes(bytes: Uint8Array): Uint8Array<ArrayBuffer> {
  return new Uint8Array(bytes);
}

export function parseVoiceIdTemplateEncryptionSecret(
  value: unknown,
): VoiceIdTemplateEncryptionSecret {
  if (typeof value !== 'string' || value.trim().length === 0) {
    throw new Error('template encryption secret must be a non-empty base64 string');
  }
  const bytes = decodeBase64Url(value.trim());
  if (bytes.byteLength !== aesGcm256KeyByteLength) {
    throw new Error('template encryption secret must decode to 32 bytes for AES-GCM-256');
  }

  return { kind: 'aes_gcm_256_raw_key', bytes };
}

export function resolveVoiceIdTemplateEncryptionSecretFromEnv(
  keyConfig: VoiceIdTemplateEncryptionKeyConfig,
  env: VoiceIdTemplateEncryptionSecretEnv,
): VoiceIdTemplateEncryptionSecret {
  switch (keyConfig.kind) {
    case 'cloudflare_workers_secret':
      return parseVoiceIdTemplateEncryptionSecret(requireSecretEnv(env, keyConfig.secretBindingName));
    case 'robot_local_secret':
      return parseVoiceIdTemplateEncryptionSecret(requireSecretEnv(env, keyConfig.secretEnvName));
  }

  return assertNever(keyConfig);
}

export class VoiceIdAesGcmTemplateCipher implements VoiceIdTemplateCipher {
  private readonly cryptoApi: Crypto;
  private readonly randomBytes: (byteLength: number) => Uint8Array;

  constructor(private readonly config: VoiceIdAesGcmTemplateCipherConfig) {
    this.cryptoApi = config.crypto ?? requireCrypto();
    this.randomBytes = config.randomBytes ?? ((byteLength) => {
      const bytes = new Uint8Array(byteLength);
      this.cryptoApi.getRandomValues(bytes);
      return bytes;
    });
  }

  async wrapTemplate(input: VoiceIdTemplateCipherInput): Promise<EncryptedBytes> {
    const key = await this.importAesGcmKey();
    const nonce = this.randomBytes(aesGcmNonceByteLength);
    if (nonce.byteLength !== aesGcmNonceByteLength) {
      throw new Error(`template nonce must be ${aesGcmNonceByteLength} bytes`);
    }
    const aad = encodeJson(buildAad(this.config.keyConfig, input.record));
    const ciphertext = new Uint8Array(
      await this.cryptoApi.subtle.encrypt(
        { name: 'AES-GCM', iv: ownedBytes(nonce), additionalData: ownedBytes(aad) },
        key,
        ownedBytes(encodeUtf8(input.encryptedTemplate)),
      ),
    );
    const envelope: VoiceIdTemplateEnvelope = {
      schemaVersion: envelopeSchemaVersion,
      algorithm: this.config.keyConfig.algorithm,
      keyId: this.config.keyConfig.keyId,
      rotationVersion: this.config.keyConfig.rotationVersion,
      aadLabel: this.config.keyConfig.aadLabel,
      nonceBase64Url: encodeBase64Url(nonce),
      ciphertextBase64Url: encodeBase64Url(ciphertext),
    };

    return parseEncryptedBytes(`${envelopePrefix}${encodeBase64Url(encodeJson(envelope))}`);
  }

  async unwrapTemplate(input: VoiceIdTemplateCipherInput): Promise<EncryptedBytes> {
    const envelope = parseTemplateEnvelope(input.encryptedTemplate);
    assertEnvelopeMatchesKeyConfig(envelope, this.config.keyConfig);
    const key = await this.importAesGcmKey();
    const aad = encodeJson(buildAad(this.config.keyConfig, input.record));
    const plaintext = new Uint8Array(
      await this.cryptoApi.subtle.decrypt(
        {
          name: 'AES-GCM',
          iv: ownedBytes(decodeBase64Url(envelope.nonceBase64Url)),
          additionalData: ownedBytes(aad),
        },
        key,
        ownedBytes(decodeBase64Url(envelope.ciphertextBase64Url)),
      ),
    );

    return parseEncryptedBytes(decodeUtf8(plaintext));
  }

  private async importAesGcmKey(): Promise<CryptoKey> {
    return await this.cryptoApi.subtle.importKey(
      'raw',
      ownedBytes(this.config.secret.bytes),
      { name: 'AES-GCM' },
      false,
      ['encrypt', 'decrypt'],
    );
  }
}

export class VoiceIdTemplateWrappingEnrollmentStore implements VoiceIdEnrollmentStore {
  constructor(
    private readonly inner: VoiceIdEnrollmentStore,
    private readonly cipher: VoiceIdTemplateCipher,
  ) {}

  async getByUserId(
    userId: Parameters<VoiceIdEnrollmentStore['getByUserId']>[0],
  ): Promise<VoiceIdEnrollmentRecord | null> {
    const record = await this.inner.getByUserId(userId);
    return record === null ? null : await this.unwrapEnrollmentRecord(record);
  }

  async getByEnrollmentId(
    enrollmentId: Parameters<VoiceIdEnrollmentStore['getByEnrollmentId']>[0],
  ): Promise<VoiceIdEnrollmentRecord | null> {
    const record = await this.inner.getByEnrollmentId(enrollmentId);
    return record === null ? null : await this.unwrapEnrollmentRecord(record);
  }

  async create(
    record: Extract<VoiceIdEnrollmentRecord, { state: 'pending_continuous_recording' }>,
  ): Promise<boolean> {
    return await this.inner.create(record);
  }

  async claimPending(
    record: Extract<VoiceIdEnrollmentRecord, { state: 'analyzing_continuous_recording' }>,
  ): Promise<boolean> {
    return await this.inner.claimPending(record);
  }

  async failPending(
    record: Extract<VoiceIdEnrollmentRecord, { state: 'failed' }>,
  ): Promise<boolean> {
    return await this.inner.failPending(record);
  }

  async completeAnalysis(
    record: Extract<VoiceIdEnrollmentRecord, { state: 'failed' | 'enrolled' }>,
  ): Promise<boolean> {
    const wrapped = await this.wrapAnalysisCompletion(record);
    return await this.inner.completeAnalysis(wrapped);
  }

  async disable(
    record: Extract<VoiceIdEnrollmentRecord, { state: 'disabled' }>,
  ): Promise<boolean> {
    const wrapped = await this.wrapDisabledRecord(record);
    return await this.inner.disable(wrapped);
  }

  private async wrapAnalysisCompletion(
    record: Extract<VoiceIdEnrollmentRecord, { state: 'failed' | 'enrolled' }>,
  ): Promise<Extract<VoiceIdEnrollmentRecord, { state: 'failed' | 'enrolled' }>> {
    switch (record.state) {
      case 'failed':
        return record;
      case 'enrolled': {
        const encryptedTemplate = await this.cipher.wrapTemplate({ record, encryptedTemplate: record.encryptedTemplate });
        return {
          state: 'enrolled',
          userId: record.userId,
          enrollmentId: record.enrollmentId,
          promptSetId: record.promptSetId,
          modelVersion: record.modelVersion,
          templateVersion: record.templateVersion,
          thresholdVersion: record.thresholdVersion,
          encryptedTemplate,
          createdAt: record.createdAt,
          enrolledAt: record.enrolledAt,
        };
      }
      default:
        return assertNever(record);
    }
  }

  private async wrapDisabledRecord(
    record: Extract<VoiceIdEnrollmentRecord, { state: 'disabled' }>,
  ): Promise<Extract<VoiceIdEnrollmentRecord, { state: 'disabled' }>> {
    const encryptedTemplate = await this.cipher.wrapTemplate({
      record,
      encryptedTemplate: record.encryptedTemplate,
    });
    return {
      state: 'disabled',
      userId: record.userId,
      enrollmentId: record.enrollmentId,
      promptSetId: record.promptSetId,
      modelVersion: record.modelVersion,
      templateVersion: record.templateVersion,
      thresholdVersion: record.thresholdVersion,
      encryptedTemplate,
      createdAt: record.createdAt,
      enrolledAt: record.enrolledAt,
      disabledAt: record.disabledAt,
    };
  }

  private async unwrapEnrollmentRecord(record: VoiceIdEnrollmentRecord): Promise<VoiceIdEnrollmentRecord> {
    switch (record.state) {
      case 'pending_continuous_recording':
      case 'analyzing_continuous_recording':
      case 'failed':
        return record;
      case 'enrolled': {
        const encryptedTemplate = await this.cipher.unwrapTemplate({ record, encryptedTemplate: record.encryptedTemplate });
        return {
          state: 'enrolled',
          userId: record.userId,
          enrollmentId: record.enrollmentId,
          promptSetId: record.promptSetId,
          modelVersion: record.modelVersion,
          templateVersion: record.templateVersion,
          thresholdVersion: record.thresholdVersion,
          encryptedTemplate,
          createdAt: record.createdAt,
          enrolledAt: record.enrolledAt,
        };
      }
      case 'disabled': {
        const encryptedTemplate = await this.cipher.unwrapTemplate({ record, encryptedTemplate: record.encryptedTemplate });
        return {
          state: 'disabled',
          userId: record.userId,
          enrollmentId: record.enrollmentId,
          promptSetId: record.promptSetId,
          modelVersion: record.modelVersion,
          templateVersion: record.templateVersion,
          thresholdVersion: record.thresholdVersion,
          encryptedTemplate,
          createdAt: record.createdAt,
          enrolledAt: record.enrolledAt,
          disabledAt: record.disabledAt,
        };
      }
      default:
        return assertNever(record);
    }
  }
}

function requireSecretEnv(env: VoiceIdTemplateEncryptionSecretEnv, name: string): unknown {
  const value = env[name];
  if (value === undefined) {
    throw new Error(`${name} must be set`);
  }

  return value;
}

function assertEnvelopeMatchesKeyConfig(
  envelope: VoiceIdTemplateEnvelope,
  keyConfig: VoiceIdTemplateEncryptionKeyConfig,
): void {
  if (envelope.algorithm !== keyConfig.algorithm) {
    throw new Error('template envelope algorithm does not match configured key');
  }
  if (envelope.keyId !== keyConfig.keyId) {
    throw new Error('template envelope key id does not match configured key');
  }
  if (envelope.rotationVersion !== keyConfig.rotationVersion) {
    throw new Error('template envelope rotation version does not match configured key');
  }
  if (envelope.aadLabel !== keyConfig.aadLabel) {
    throw new Error('template envelope AAD label does not match configured key');
  }
}

function buildAad(
  keyConfig: VoiceIdTemplateEncryptionKeyConfig,
  record: Extract<VoiceIdEnrollmentRecord, { state: 'enrolled' | 'disabled' }>,
): VoiceIdTemplateAad {
  return {
    schemaVersion: envelopeSchemaVersion,
    aadLabel: keyConfig.aadLabel,
    keyId: keyConfig.keyId,
    rotationVersion: keyConfig.rotationVersion,
    userId: record.userId,
    enrollmentId: record.enrollmentId,
    modelVersion: record.modelVersion,
    templateVersion: record.templateVersion,
    thresholdVersion: record.thresholdVersion,
  };
}

function parseTemplateEnvelope(value: EncryptedBytes): VoiceIdTemplateEnvelope {
  if (!value.startsWith(envelopePrefix)) {
    throw new Error(`template envelope must start with ${envelopePrefix}`);
  }
  const raw = decodeJson(decodeBase64Url(value.slice(envelopePrefix.length)), 'template envelope');
  if (raw.schemaVersion !== envelopeSchemaVersion) {
    throw new Error(`template envelope schemaVersion must be ${envelopeSchemaVersion}`);
  }
  if (raw.algorithm !== 'AES-GCM-256') {
    throw new Error('template envelope algorithm must be AES-GCM-256');
  }

  return {
    schemaVersion: raw.schemaVersion,
    algorithm: raw.algorithm,
    keyId: parseEnvelopeString(raw.keyId, 'keyId') as VoiceIdTemplateEncryptionKeyId,
    rotationVersion: parseEnvelopeString(raw.rotationVersion, 'rotationVersion') as VoiceIdTemplateEncryptionRotationVersion,
    aadLabel: parseEnvelopeString(raw.aadLabel, 'aadLabel') as VoiceIdTemplateEncryptionAadLabel,
    nonceBase64Url: parseEnvelopeString(raw.nonceBase64Url, 'nonceBase64Url'),
    ciphertextBase64Url: parseEnvelopeString(raw.ciphertextBase64Url, 'ciphertextBase64Url'),
  };
}

function parseEnvelopeString(value: unknown, fieldName: string): string {
  if (typeof value !== 'string' || value.trim().length === 0) {
    throw new Error(`template envelope ${fieldName} must be a non-empty string`);
  }

  return value;
}

function requireCrypto(): Crypto {
  const cryptoApi = globalThis.crypto;
  if (cryptoApi === undefined) {
    throw new Error('Web Crypto is required for VoiceID template encryption');
  }

  return cryptoApi;
}

function encodeJson(value: unknown): Uint8Array {
  return encodeUtf8(JSON.stringify(value));
}

function decodeJson(bytes: Uint8Array, fieldName: string): Record<string, unknown> {
  const value = JSON.parse(decodeUtf8(bytes)) as unknown;
  if (typeof value !== 'object' || value === null || Array.isArray(value)) {
    throw new Error(`${fieldName} must decode to an object`);
  }

  return value as Record<string, unknown>;
}

function encodeUtf8(value: string): Uint8Array {
  return new TextEncoder().encode(value);
}

function decodeUtf8(bytes: Uint8Array): string {
  return new TextDecoder().decode(bytes);
}

function encodeBase64Url(bytes: Uint8Array): string {
  const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';
  let output = '';
  let index = 0;
  for (; index + 2 < bytes.length; index += 3) {
    const value = (bytes[index] << 16) | (bytes[index + 1] << 8) | bytes[index + 2];
    output += alphabet[(value >> 18) & 63];
    output += alphabet[(value >> 12) & 63];
    output += alphabet[(value >> 6) & 63];
    output += alphabet[value & 63];
  }

  const remaining = bytes.length - index;
  if (remaining === 1) {
    const value = bytes[index] << 16;
    output += alphabet[(value >> 18) & 63];
    output += alphabet[(value >> 12) & 63];
    output += '==';
  } else if (remaining === 2) {
    const value = (bytes[index] << 16) | (bytes[index + 1] << 8);
    output += alphabet[(value >> 18) & 63];
    output += alphabet[(value >> 12) & 63];
    output += alphabet[(value >> 6) & 63];
    output += '=';
  }

  return output.replaceAll('+', '-').replaceAll('/', '_').replaceAll('=', '');
}

function decodeBase64Url(value: string): Uint8Array {
  const normalized = value.replaceAll('-', '+').replaceAll('_', '/');
  const padded = normalized.padEnd(normalized.length + ((4 - (normalized.length % 4)) % 4), '=');
  if (!/^[A-Za-z0-9+/]*={0,2}$/.test(padded)) {
    throw new Error('base64url value contains invalid characters');
  }
  const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';
  const cleanLength = padded.endsWith('==') ? padded.length - 2 : padded.endsWith('=') ? padded.length - 1 : padded.length;
  const outputLength = Math.floor((cleanLength * 3) / 4);
  const output = new Uint8Array(outputLength);
  let outputIndex = 0;
  for (let index = 0; index < padded.length; index += 4) {
    const first = alphabet.indexOf(padded[index]);
    const second = alphabet.indexOf(padded[index + 1]);
    const third = padded[index + 2] === '=' ? 0 : alphabet.indexOf(padded[index + 2]);
    const fourth = padded[index + 3] === '=' ? 0 : alphabet.indexOf(padded[index + 3]);
    if (first < 0 || second < 0 || third < 0 || fourth < 0) {
      throw new Error('base64url value contains invalid characters');
    }
    const chunk = (first << 18) | (second << 12) | (third << 6) | fourth;
    if (outputIndex < output.length) {
      output[outputIndex] = (chunk >> 16) & 255;
      outputIndex += 1;
    }
    if (outputIndex < output.length) {
      output[outputIndex] = (chunk >> 8) & 255;
      outputIndex += 1;
    }
    if (outputIndex < output.length) {
      output[outputIndex] = chunk & 255;
      outputIndex += 1;
    }
  }

  return output;
}
