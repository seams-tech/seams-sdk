import assert from 'node:assert/strict';
import test from 'node:test';
import { parseVoiceIdTemplateEncryptionKeyConfigFromEnv } from '../../server/src/store/VoiceIdTemplateEncryptionConfig.ts';

test('parses Cloudflare Workers template encryption key config', () => {
  const config = parseVoiceIdTemplateEncryptionKeyConfigFromEnv({
    VOICEID_TEMPLATE_KEY_SOURCE: 'cloudflare-workers-secret',
    VOICEID_TEMPLATE_KEY_ALGORITHM: 'AES-GCM-256',
    VOICEID_TEMPLATE_KEY_ID: 'voiceid-template-key-2026-06',
    VOICEID_TEMPLATE_KEY_SECRET_BINDING: 'VOICEID_TEMPLATE_ENCRYPTION_KEY',
    VOICEID_TEMPLATE_KEY_ROTATION_VERSION: 'rotation-2026-06',
    VOICEID_TEMPLATE_KEY_AAD_LABEL: 'voiceid-template-v1',
  });

  assert.equal(config.kind, 'cloudflare_workers_secret');
  assert.equal(config.configVersion, 'voiceid-template-encryption-config-v1');
  assert.equal(config.algorithm, 'AES-GCM-256');
  assert.equal(config.keyId, 'voiceid-template-key-2026-06');
  assert.equal(config.secretBindingName, 'VOICEID_TEMPLATE_ENCRYPTION_KEY');
  assert.equal(config.rotationVersion, 'rotation-2026-06');
  assert.equal(config.aadLabel, 'voiceid-template-v1');
  assert.equal(Object.hasOwn(config, 'secret'), false);
  assert.equal(Object.hasOwn(config, 'secretValue'), false);
  assert.equal(Object.hasOwn(config, 'keyMaterial'), false);
});

test('parses robot-local template encryption key config', () => {
  const config = parseVoiceIdTemplateEncryptionKeyConfigFromEnv({
    VOICEID_TEMPLATE_KEY_SOURCE: 'robot-local-secret',
    VOICEID_TEMPLATE_KEY_ALGORITHM: 'AES-GCM-256',
    VOICEID_TEMPLATE_KEY_ID: 'reachy-template-key-2026-06',
    VOICEID_TEMPLATE_KEY_SECRET_ENV: 'VOICEID_ROBOT_TEMPLATE_ENCRYPTION_KEY',
    VOICEID_TEMPLATE_KEY_ROTATION_VERSION: 'robot-rotation-2026-06',
    VOICEID_TEMPLATE_KEY_AAD_LABEL: 'voiceid-reachy-template-v1',
  });

  assert.equal(config.kind, 'robot_local_secret');
  assert.equal(config.algorithm, 'AES-GCM-256');
  assert.equal(config.keyId, 'reachy-template-key-2026-06');
  assert.equal(config.secretEnvName, 'VOICEID_ROBOT_TEMPLATE_ENCRYPTION_KEY');
});

test('rejects incomplete or invalid template encryption key config', () => {
  assert.throws(
    () => parseVoiceIdTemplateEncryptionKeyConfigFromEnv({}),
    /VOICEID_TEMPLATE_KEY_SOURCE must be set/,
  );

  assert.throws(
    () => parseVoiceIdTemplateEncryptionKeyConfigFromEnv({
      VOICEID_TEMPLATE_KEY_SOURCE: 'cloudflare-workers-secret',
      VOICEID_TEMPLATE_KEY_ALGORITHM: 'AES-GCM-128',
      VOICEID_TEMPLATE_KEY_ID: 'voiceid-template-key-2026-06',
      VOICEID_TEMPLATE_KEY_SECRET_BINDING: 'VOICEID_TEMPLATE_ENCRYPTION_KEY',
      VOICEID_TEMPLATE_KEY_ROTATION_VERSION: 'rotation-2026-06',
      VOICEID_TEMPLATE_KEY_AAD_LABEL: 'voiceid-template-v1',
    }),
    /VOICEID_TEMPLATE_KEY_ALGORITHM must be AES-GCM-256/,
  );

  assert.throws(
    () => parseVoiceIdTemplateEncryptionKeyConfigFromEnv({
      VOICEID_TEMPLATE_KEY_SOURCE: 'cloudflare-workers-secret',
      VOICEID_TEMPLATE_KEY_ALGORITHM: 'AES-GCM-256',
      VOICEID_TEMPLATE_KEY_ID: 'voiceid-template-key-2026-06',
      VOICEID_TEMPLATE_KEY_ROTATION_VERSION: 'rotation-2026-06',
      VOICEID_TEMPLATE_KEY_AAD_LABEL: 'voiceid-template-v1',
    }),
    /VOICEID_TEMPLATE_KEY_SECRET_BINDING must be set/,
  );

  assert.throws(
    () => parseVoiceIdTemplateEncryptionKeyConfigFromEnv({
      VOICEID_TEMPLATE_KEY_SOURCE: 'local-dev-secret',
      VOICEID_TEMPLATE_KEY_ALGORITHM: 'AES-GCM-256',
      VOICEID_TEMPLATE_KEY_ID: 'voiceid-template-key-2026-06',
      VOICEID_TEMPLATE_KEY_ROTATION_VERSION: 'rotation-2026-06',
      VOICEID_TEMPLATE_KEY_AAD_LABEL: 'voiceid-template-v1',
    }),
    /VOICEID_TEMPLATE_KEY_SOURCE must be 'cloudflare-workers-secret' or 'robot-local-secret'/,
  );
});
