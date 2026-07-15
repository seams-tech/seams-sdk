import {
  buildVoiceIdFixtureManifest,
  buildVoiceIdFixtureManifestEntry,
  createRandomId,
  nowIsoDateTime,
  type VoiceIdAudioMetadata,
  type VoiceIdFixtureExpectedRelation,
  type VoiceIdFixtureManifest,
  type VoiceIdFixtureManifestEntry,
  parseVoiceIdFixtureId,
} from '../../../shared/src/index.ts';

export type CapturedVoiceIdFixture = {
  readonly entry: VoiceIdFixtureManifestEntry;
  readonly blob: Blob;
};

export function createCapturedVoiceIdFixture(input: {
  readonly blob: Blob;
  readonly metadata: VoiceIdAudioMetadata;
  readonly speakerLabel: string;
  readonly phraseLabel: string;
  readonly expectedRelation: VoiceIdFixtureExpectedRelation;
  readonly captureDevice: string;
  readonly environmentNotes: string;
}): CapturedVoiceIdFixture {
  const fixtureId = parseVoiceIdFixtureId(createRandomId('fixture'));
  const audioFileName = `voiceid-${fixtureId}.${audioFileExtension(input.blob.type)}`;
  return {
    blob: input.blob,
    entry: buildVoiceIdFixtureManifestEntry({
      fixtureId,
      audioFileName,
      speakerLabel: input.speakerLabel,
      phraseLabel: input.phraseLabel,
      expectedRelation: input.expectedRelation,
      captureDevice: input.captureDevice,
      durationMs: input.metadata.durationMs,
      environmentNotes: input.environmentNotes,
      capturedAt: input.metadata.capturedAt,
      byteLength: input.blob.size,
      mimeType: input.blob.type || input.metadata.mimeType,
    }),
  };
}

export function buildManifestFromCapturedVoiceIdFixtures(input: {
  readonly fixtures: readonly CapturedVoiceIdFixture[];
  readonly createdAt?: ReturnType<typeof nowIsoDateTime>;
}): VoiceIdFixtureManifest {
  return buildVoiceIdFixtureManifest({
    createdAt: input.createdAt ?? nowIsoDateTime(),
    entries: input.fixtures.map((fixture) => fixture.entry),
  });
}

export function downloadVoiceIdFixtureAudio(fixture: CapturedVoiceIdFixture): void {
  downloadBlob(fixture.entry.audioFileName, fixture.blob);
}

export function downloadVoiceIdFixtureManifest(manifest: VoiceIdFixtureManifest): void {
  downloadBlob(
    'voiceid-fixture-manifest.json',
    new Blob([JSON.stringify(manifest, null, 2)], { type: 'application/json' }),
  );
}

function audioFileExtension(mimeType: string): string {
  const normalized = mimeType.trim().toLowerCase();
  if (normalized.includes('webm')) return 'webm';
  if (normalized.includes('wav')) return 'wav';
  if (normalized.includes('mpeg') || normalized.includes('mp3')) return 'mp3';
  if (normalized.includes('mp4') || normalized.includes('aac')) return 'm4a';
  if (normalized.includes('ogg') || normalized.includes('opus')) return 'ogg';
  return 'webm';
}

function downloadBlob(fileName: string, blob: Blob): void {
  const url = URL.createObjectURL(blob);
  const link = document.createElement('a');
  link.href = url;
  link.download = fileName;
  link.style.display = 'none';
  document.body.append(link);
  link.click();
  link.remove();
  window.setTimeout(() => URL.revokeObjectURL(url), 1000);
}
