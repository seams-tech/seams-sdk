import assert from 'node:assert/strict';
import test from 'node:test';
import {
  buildVoiceIdFixtureManifest,
  buildVoiceIdFixtureManifestEntry,
  parseIsoDateTime,
  parseVoiceIdFixtureId,
  parseVoiceIdFixtureManifest,
  validateVoiceIdFixtureAudioFiles,
} from '../../shared/src/index.ts';

function fixtureEntry(input: {
  fixtureId: string;
  audioFileName: string;
}) {
  return buildVoiceIdFixtureManifestEntry({
    fixtureId: parseVoiceIdFixtureId(input.fixtureId),
    audioFileName: input.audioFileName,
    speakerLabel: 'owner',
    phraseLabel: 'Walking on clouds',
    expectedRelation: 'owner_enrollment',
    captureDevice: 'browser microphone',
    durationMs: 1800,
    environmentNotes: 'quiet room',
    capturedAt: parseIsoDateTime('2026-06-09T00:00:00.000Z'),
    byteLength: 1234,
    mimeType: 'audio/webm',
  });
}

test('fixture manifest parser accepts complete fixture metadata', () => {
  const manifest = buildVoiceIdFixtureManifest({
    createdAt: parseIsoDateTime('2026-06-09T00:01:00.000Z'),
    entries: [fixtureEntry({ fixtureId: 'fixture_owner_1', audioFileName: 'owner-1.webm' })],
  });

  const parsed = parseVoiceIdFixtureManifest(JSON.parse(JSON.stringify(manifest)));

  assert.equal(parsed.kind, 'ok');
  assert.equal(parsed.manifest.entries[0].fixtureId, 'fixture_owner_1');
  assert.equal(parsed.manifest.entries[0].audioFileName, 'owner-1.webm');
});

test('fixture manifest parser rejects malformed relation and duplicate ids', () => {
  const malformedRelation = parseVoiceIdFixtureManifest({
    schemaVersion: 'voice_id_fixture_manifest_v1',
    createdAt: '2026-06-09T00:01:00.000Z',
    entries: [
      {
        ...fixtureEntry({ fixtureId: 'fixture_owner_1', audioFileName: 'owner-1.webm' }),
        expectedRelation: 'same-ish',
      },
    ],
  });

  assert.equal(malformedRelation.kind, 'error');
  assert.equal(malformedRelation.reason, 'malformed_manifest');

  const duplicateIds = parseVoiceIdFixtureManifest({
    schemaVersion: 'voice_id_fixture_manifest_v1',
    createdAt: '2026-06-09T00:01:00.000Z',
    entries: [
      fixtureEntry({ fixtureId: 'fixture_owner_1', audioFileName: 'owner-1.webm' }),
      fixtureEntry({ fixtureId: 'fixture_owner_1', audioFileName: 'owner-2.webm' }),
    ],
  });

  assert.equal(duplicateIds.kind, 'error');
  assert.equal(duplicateIds.reason, 'duplicate_fixture_id');
});

test('fixture audio validation rejects manifests that reference missing files', () => {
  const manifest = buildVoiceIdFixtureManifest({
    createdAt: parseIsoDateTime('2026-06-09T00:01:00.000Z'),
    entries: [
      fixtureEntry({ fixtureId: 'fixture_owner_1', audioFileName: 'owner-1.webm' }),
      fixtureEntry({ fixtureId: 'fixture_owner_2', audioFileName: 'owner-2.webm' }),
    ],
  });

  assert.deepEqual(
    validateVoiceIdFixtureAudioFiles({
      manifest,
      audioFileNames: ['owner-1.webm', 'owner-2.webm'],
    }),
    { kind: 'valid' },
  );

  const missing = validateVoiceIdFixtureAudioFiles({
    manifest,
    audioFileNames: ['owner-1.webm'],
  });

  assert.equal(missing.kind, 'invalid');
  if (missing.kind === 'invalid') {
    assert.equal(missing.reason, 'missing_audio_file');
    assert.equal(missing.audioFileName, 'owner-2.webm');
  }
});
