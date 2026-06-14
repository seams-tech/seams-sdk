import assert from 'node:assert/strict';
import test from 'node:test';
import {
  InMemoryVoiceIdEnrollmentStore,
  parseVoiceIdTemplateEncryptionKeyConfigFromEnv,
  parseVoiceIdTemplateEncryptionSecret,
  resolveVoiceIdTemplateEncryptionSecretFromEnv,
  VoiceIdAesGcmTemplateCipher,
  VoiceIdTemplateWrappingEnrollmentStore,
} from '../../server/src/index.ts';
import {
  parseEncryptedBytes,
  parseEnrollmentId,
  parseIsoDateTime,
  parseModelVersion,
  parsePromptSetId,
  parseTemplateVersion,
  parseThresholdVersion,
  parseUserId,
  type EncryptedBytes,
} from '../../shared/src/index.ts';
import type { VoiceIdEnrollmentRecord } from '../../shared/src/records.ts';

const base64Key = 'AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=';

test('parses template encryption secrets from configured env locations', () => {
  const cloudflareConfig = parseVoiceIdTemplateEncryptionKeyConfigFromEnv({
    VOICEID_TEMPLATE_KEY_SOURCE: 'cloudflare-workers-secret',
    VOICEID_TEMPLATE_KEY_ALGORITHM: 'AES-GCM-256',
    VOICEID_TEMPLATE_KEY_ID: 'voiceid-template-key-2026-06',
    VOICEID_TEMPLATE_KEY_SECRET_BINDING: 'VOICEID_TEMPLATE_ENCRYPTION_KEY',
    VOICEID_TEMPLATE_KEY_ROTATION_VERSION: 'rotation-1',
    VOICEID_TEMPLATE_KEY_AAD_LABEL: 'voiceid-template-v1',
  });
  const cloudflareSecret = resolveVoiceIdTemplateEncryptionSecretFromEnv(cloudflareConfig, {
    VOICEID_TEMPLATE_ENCRYPTION_KEY: base64Key,
  });

  assert.equal(cloudflareSecret.kind, 'aes_gcm_256_raw_key');
  assert.equal(cloudflareSecret.bytes.byteLength, 32);

  const robotConfig = parseVoiceIdTemplateEncryptionKeyConfigFromEnv({
    VOICEID_TEMPLATE_KEY_SOURCE: 'robot-local-secret',
    VOICEID_TEMPLATE_KEY_ALGORITHM: 'AES-GCM-256',
    VOICEID_TEMPLATE_KEY_ID: 'reachy-template-key-2026-06',
    VOICEID_TEMPLATE_KEY_SECRET_ENV: 'VOICEID_REACHY_TEMPLATE_KEY',
    VOICEID_TEMPLATE_KEY_ROTATION_VERSION: 'rotation-1',
    VOICEID_TEMPLATE_KEY_AAD_LABEL: 'voiceid-reachy-template-v1',
  });
  const robotSecret = resolveVoiceIdTemplateEncryptionSecretFromEnv(robotConfig, {
    VOICEID_REACHY_TEMPLATE_KEY: base64Key.replaceAll('+', '-').replaceAll('/', '_').replaceAll('=', ''),
  });

  assert.equal(robotSecret.bytes.byteLength, 32);
  assert.throws(
    () => parseVoiceIdTemplateEncryptionSecret('c2hvcnQ='),
    /template encryption secret must decode to 32 bytes/,
  );
});

test('AES-GCM template cipher wraps verifier templates and binds enrollment metadata', async () => {
  const cipher = newTestCipher();
  const record = enrolledRecord();
  const verifierTemplate = parseEncryptedBytes('verifier-template-payload');

  const wrapped = await cipher.wrapTemplate({ record, encryptedTemplate: verifierTemplate });

  assert.match(wrapped, /^voiceid-template-wrap-v1\./);
  assert.notEqual(wrapped, verifierTemplate);
  assert.equal(await cipher.unwrapTemplate({ record, encryptedTemplate: wrapped }), verifierTemplate);

  await assert.rejects(
    async () => await cipher.unwrapTemplate({
      record: enrolledRecord({ enrollmentId: parseEnrollmentId('enroll_other') }),
      encryptedTemplate: wrapped,
    }),
  );
});

test('template wrapping enrollment store persists wrapped templates and returns verifier templates', async () => {
  const inner = new InMemoryVoiceIdEnrollmentStore();
  const store = new VoiceIdTemplateWrappingEnrollmentStore(inner, newTestCipher());
  const record = enrolledRecord({ encryptedTemplate: parseEncryptedBytes('verifier-template-payload') });

  await store.save(record);

  const persisted = await inner.getByEnrollmentId(record.enrollmentId);
  assert.equal(persisted?.state, 'enrolled');
  assert.match(persisted.encryptedTemplate, /^voiceid-template-wrap-v1\./);
  assert.notEqual(persisted.encryptedTemplate, record.encryptedTemplate);

  assert.deepEqual(await store.getByEnrollmentId(record.enrollmentId), record);
  assert.deepEqual(await store.getByUserId(record.userId), record);
});

function newTestCipher(): VoiceIdAesGcmTemplateCipher {
  const keyConfig = parseVoiceIdTemplateEncryptionKeyConfigFromEnv({
    VOICEID_TEMPLATE_KEY_SOURCE: 'cloudflare-workers-secret',
    VOICEID_TEMPLATE_KEY_ALGORITHM: 'AES-GCM-256',
    VOICEID_TEMPLATE_KEY_ID: 'voiceid-template-key-2026-06',
    VOICEID_TEMPLATE_KEY_SECRET_BINDING: 'VOICEID_TEMPLATE_ENCRYPTION_KEY',
    VOICEID_TEMPLATE_KEY_ROTATION_VERSION: 'rotation-1',
    VOICEID_TEMPLATE_KEY_AAD_LABEL: 'voiceid-template-v1',
  });
  return new VoiceIdAesGcmTemplateCipher({
    keyConfig,
    secret: parseVoiceIdTemplateEncryptionSecret(base64Key),
    randomBytes: () => new Uint8Array([0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11]),
  });
}

function enrolledRecord(
  overrides: Partial<{
    enrollmentId: VoiceIdEnrollmentRecord['enrollmentId'];
    encryptedTemplate: EncryptedBytes;
  }> = {},
): Extract<VoiceIdEnrollmentRecord, { state: 'enrolled' }> {
  return {
    state: 'enrolled',
    userId: parseUserId('owner'),
    enrollmentId: overrides.enrollmentId ?? parseEnrollmentId('enroll_1'),
    promptSetId: parsePromptSetId('prompt-v1'),
    modelVersion: parseModelVersion('model-v1'),
    templateVersion: parseTemplateVersion('template-v1'),
    thresholdVersion: parseThresholdVersion('threshold-v1'),
    encryptedTemplate: overrides.encryptedTemplate ?? parseEncryptedBytes('template-payload'),
    createdAt: parseIsoDateTime('2026-06-13T00:00:00.000Z'),
    enrolledAt: parseIsoDateTime('2026-06-13T00:01:00.000Z'),
  };
}
