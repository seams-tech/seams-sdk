import assert from 'node:assert/strict';
import test from 'node:test';
import { parseVoiceIdDiagnosticRetentionConfigFromEnv } from '../../server/src/store/VoiceIdDiagnosticRetentionConfig.ts';

test('diagnostic retention defaults to disabled without raw capture', () => {
  const config = parseVoiceIdDiagnosticRetentionConfigFromEnv({});

  assert.equal(config.kind, 'disabled');
  assert.equal(config.configVersion, 'voiceid-diagnostic-retention-config-v1');
  assert.equal(config.rawAudio, false);
  assert.equal(config.rawVideo, false);
});

test('parses Cloudflare R2 diagnostic retention config', () => {
  const config = parseVoiceIdDiagnosticRetentionConfigFromEnv({
    VOICEID_DIAGNOSTIC_RETENTION: 'cloudflare-r2',
    VOICEID_DIAGNOSTIC_POLICY_VERSION: 'diagnostics-v1',
    VOICEID_DIAGNOSTIC_R2_BUCKET_BINDING: 'VOICEID_DIAGNOSTICS_BUCKET',
    VOICEID_DIAGNOSTIC_RETENTION_TTL_SECONDS: '3600',
    VOICEID_DIAGNOSTIC_CAPTURE_AUDIO: 'true',
    VOICEID_DIAGNOSTIC_CAPTURE_VIDEO: 'false',
    VOICEID_DIAGNOSTIC_MAX_ARTIFACT_BYTES: '1048576',
  });

  assert.equal(config.kind, 'cloudflare_r2');
  assert.equal(config.policyVersion, 'diagnostics-v1');
  assert.equal(config.bucketBindingName, 'VOICEID_DIAGNOSTICS_BUCKET');
  assert.deepEqual(config.retentionWindow, { ttlSeconds: 3600, deleteAfterSeconds: 3600 });
  assert.deepEqual(config.capture, { rawAudio: true, rawVideo: false });
  assert.equal(config.maxArtifactBytes, 1048576);
});

test('parses robot-local diagnostic retention config', () => {
  const config = parseVoiceIdDiagnosticRetentionConfigFromEnv({
    VOICEID_DIAGNOSTIC_RETENTION: 'robot-local-files',
    VOICEID_DIAGNOSTIC_POLICY_VERSION: 'robot-diagnostics-v1',
    VOICEID_DIAGNOSTIC_LOCAL_DIRECTORY: '/var/lib/voiceid/diagnostics',
    VOICEID_DIAGNOSTIC_RETENTION_TTL_SECONDS: '600',
    VOICEID_DIAGNOSTIC_CAPTURE_AUDIO: 'false',
    VOICEID_DIAGNOSTIC_CAPTURE_VIDEO: 'true',
    VOICEID_DIAGNOSTIC_MAX_ARTIFACT_BYTES: '524288',
  });

  assert.equal(config.kind, 'robot_local_files');
  assert.equal(config.policyVersion, 'robot-diagnostics-v1');
  assert.equal(config.directory, '/var/lib/voiceid/diagnostics');
  assert.deepEqual(config.capture, { rawAudio: false, rawVideo: true });
});

test('rejects diagnostic retention without explicit capture and retention window', () => {
  assert.throws(
    () => parseVoiceIdDiagnosticRetentionConfigFromEnv({
      VOICEID_DIAGNOSTIC_RETENTION: 'cloudflare-r2',
      VOICEID_DIAGNOSTIC_POLICY_VERSION: 'diagnostics-v1',
      VOICEID_DIAGNOSTIC_R2_BUCKET_BINDING: 'VOICEID_DIAGNOSTICS_BUCKET',
      VOICEID_DIAGNOSTIC_RETENTION_TTL_SECONDS: '3600',
      VOICEID_DIAGNOSTIC_CAPTURE_AUDIO: 'false',
      VOICEID_DIAGNOSTIC_CAPTURE_VIDEO: 'false',
      VOICEID_DIAGNOSTIC_MAX_ARTIFACT_BYTES: '1048576',
    }),
    /requires audio, video, or both capture types/,
  );

  assert.throws(
    () => parseVoiceIdDiagnosticRetentionConfigFromEnv({
      VOICEID_DIAGNOSTIC_RETENTION: 'cloudflare-r2',
      VOICEID_DIAGNOSTIC_POLICY_VERSION: 'diagnostics-v1',
      VOICEID_DIAGNOSTIC_R2_BUCKET_BINDING: 'VOICEID_DIAGNOSTICS_BUCKET',
      VOICEID_DIAGNOSTIC_CAPTURE_AUDIO: 'true',
      VOICEID_DIAGNOSTIC_CAPTURE_VIDEO: 'false',
      VOICEID_DIAGNOSTIC_MAX_ARTIFACT_BYTES: '1048576',
    }),
    /VOICEID_DIAGNOSTIC_RETENTION_TTL_SECONDS must be set/,
  );
});

test('rejects diagnostic retention outside configured bounds', () => {
  const baseEnv = {
    VOICEID_DIAGNOSTIC_RETENTION: 'cloudflare-r2',
    VOICEID_DIAGNOSTIC_POLICY_VERSION: 'diagnostics-v1',
    VOICEID_DIAGNOSTIC_R2_BUCKET_BINDING: 'VOICEID_DIAGNOSTICS_BUCKET',
    VOICEID_DIAGNOSTIC_CAPTURE_AUDIO: 'true',
    VOICEID_DIAGNOSTIC_CAPTURE_VIDEO: 'false',
    VOICEID_DIAGNOSTIC_MAX_ARTIFACT_BYTES: '1048576',
  };

  assert.throws(
    () => parseVoiceIdDiagnosticRetentionConfigFromEnv({
      ...baseEnv,
      VOICEID_DIAGNOSTIC_RETENTION_TTL_SECONDS: '30',
    }),
    /VOICEID_DIAGNOSTIC_RETENTION_TTL_SECONDS must be between 60 and 604800/,
  );

  assert.throws(
    () => parseVoiceIdDiagnosticRetentionConfigFromEnv({
      ...baseEnv,
      VOICEID_DIAGNOSTIC_RETENTION_TTL_SECONDS: '3600',
      VOICEID_DIAGNOSTIC_MAX_ARTIFACT_BYTES: '26214401',
    }),
    /VOICEID_DIAGNOSTIC_MAX_ARTIFACT_BYTES must be between 1 and 26214400/,
  );
});
