import { parseIsoDateTime, type IsoDateTime } from './ids.ts';

export const VOICE_ID_FIXTURE_MANIFEST_SCHEMA_VERSION = 'voice_id_fixture_manifest_v1';

export type VoiceIdFixtureId = string & { readonly __brand: 'VoiceIdFixtureId' };

export type VoiceIdFixtureExpectedRelation =
  | 'owner_enrollment'
  | 'owner_verification'
  | 'different_speaker'
  | 'wrong_phrase'
  | 'noisy'
  | 'too_short';

export const VOICE_ID_FIXTURE_EXPECTED_RELATIONS: readonly VoiceIdFixtureExpectedRelation[] = [
  'owner_enrollment',
  'owner_verification',
  'different_speaker',
  'wrong_phrase',
  'noisy',
  'too_short',
];

export type VoiceIdFixtureManifestEntry = {
  readonly fixtureId: VoiceIdFixtureId;
  readonly audioFileName: string;
  readonly speakerLabel: string;
  readonly phraseLabel: string;
  readonly expectedRelation: VoiceIdFixtureExpectedRelation;
  readonly captureDevice: string;
  readonly durationMs: number;
  readonly environmentNotes: string;
  readonly capturedAt: IsoDateTime;
  readonly byteLength: number;
  readonly mimeType: string;
};

export type VoiceIdFixtureManifest = {
  readonly schemaVersion: typeof VOICE_ID_FIXTURE_MANIFEST_SCHEMA_VERSION;
  readonly createdAt: IsoDateTime;
  readonly entries: readonly VoiceIdFixtureManifestEntry[];
};

export type VoiceIdFixtureManifestParseResult =
  | { readonly kind: 'ok'; readonly manifest: VoiceIdFixtureManifest }
  | {
      readonly kind: 'error';
      readonly reason:
        | 'malformed_manifest'
        | 'duplicate_fixture_id'
        | 'duplicate_audio_file_name';
      readonly message: string;
    };

type VoiceIdFixtureManifestParseError = Extract<
  VoiceIdFixtureManifestParseResult,
  { readonly kind: 'error' }
>;

export type VoiceIdFixtureAudioFileValidationResult =
  | { readonly kind: 'valid' }
  | {
      readonly kind: 'invalid';
      readonly reason: 'missing_audio_file';
      readonly message: string;
      readonly audioFileName: string;
    };

export function parseVoiceIdFixtureId(value: unknown): VoiceIdFixtureId {
  const normalized = parseNonEmptyString(value, 'fixtureId');
  if (!/^[a-zA-Z0-9_-]+$/.test(normalized)) {
    throw new Error('fixtureId may only contain letters, numbers, underscore, or hyphen');
  }
  return normalized as VoiceIdFixtureId;
}

export function buildVoiceIdFixtureManifestEntry(
  input: VoiceIdFixtureManifestEntry,
): VoiceIdFixtureManifestEntry {
  return parseVoiceIdFixtureManifestEntry(input);
}

export function buildVoiceIdFixtureManifest(input: {
  readonly createdAt: IsoDateTime;
  readonly entries: readonly VoiceIdFixtureManifestEntry[];
}): VoiceIdFixtureManifest {
  const manifest: VoiceIdFixtureManifest = {
    schemaVersion: VOICE_ID_FIXTURE_MANIFEST_SCHEMA_VERSION,
    createdAt: input.createdAt,
    entries: input.entries.map(buildVoiceIdFixtureManifestEntry),
  };
  const duplicateError = findDuplicateManifestEntryError(manifest.entries);
  if (duplicateError) throw new Error(duplicateError.message);
  return manifest;
}

export function parseVoiceIdFixtureManifest(
  value: unknown,
): VoiceIdFixtureManifestParseResult {
  try {
    const input = parseObject(value, 'fixture manifest');
    const schemaVersion = parseNonEmptyString(input.schemaVersion, 'schemaVersion');
    if (schemaVersion !== VOICE_ID_FIXTURE_MANIFEST_SCHEMA_VERSION) {
      return {
        kind: 'error',
        reason: 'malformed_manifest',
        message: `schemaVersion must be ${VOICE_ID_FIXTURE_MANIFEST_SCHEMA_VERSION}`,
      };
    }
    const entries = parseArray(input.entries, 'entries').map(parseVoiceIdFixtureManifestEntry);
    const duplicateError = findDuplicateManifestEntryError(entries);
    if (duplicateError) return duplicateError;
    return {
      kind: 'ok',
      manifest: {
        schemaVersion: VOICE_ID_FIXTURE_MANIFEST_SCHEMA_VERSION,
        createdAt: parseIsoDateTime(input.createdAt),
        entries,
      },
    };
  } catch (error) {
    return {
      kind: 'error',
      reason: 'malformed_manifest',
      message: error instanceof Error ? error.message : 'fixture manifest is malformed',
    };
  }
}

export function requireVoiceIdFixtureManifest(value: unknown): VoiceIdFixtureManifest {
  const parsed = parseVoiceIdFixtureManifest(value);
  if (parsed.kind === 'error') throw new Error(parsed.message);
  return parsed.manifest;
}

export function validateVoiceIdFixtureAudioFiles(input: {
  readonly manifest: VoiceIdFixtureManifest;
  readonly audioFileNames: readonly string[];
}): VoiceIdFixtureAudioFileValidationResult {
  const audioFileNames = new Set(input.audioFileNames);
  for (const entry of input.manifest.entries) {
    if (!audioFileNames.has(entry.audioFileName)) {
      return {
        kind: 'invalid',
        reason: 'missing_audio_file',
        message: `fixture manifest references missing audio file ${entry.audioFileName}`,
        audioFileName: entry.audioFileName,
      };
    }
  }
  return { kind: 'valid' };
}

function parseVoiceIdFixtureManifestEntry(value: unknown): VoiceIdFixtureManifestEntry {
  const input = parseObject(value, 'fixture manifest entry');
  return {
    fixtureId: parseVoiceIdFixtureId(input.fixtureId),
    audioFileName: parseAudioFileName(input.audioFileName),
    speakerLabel: parseNonEmptyString(input.speakerLabel, 'speakerLabel'),
    phraseLabel: parseNonEmptyString(input.phraseLabel, 'phraseLabel'),
    expectedRelation: parseExpectedRelation(input.expectedRelation),
    captureDevice: parseNonEmptyString(input.captureDevice, 'captureDevice'),
    durationMs: parsePositiveNumber(input.durationMs, 'durationMs'),
    environmentNotes: parseNonEmptyString(input.environmentNotes, 'environmentNotes'),
    capturedAt: parseIsoDateTime(input.capturedAt),
    byteLength: parsePositiveInteger(input.byteLength, 'byteLength'),
    mimeType: parseNonEmptyString(input.mimeType, 'mimeType'),
  };
}

function findDuplicateManifestEntryError(
  entries: readonly VoiceIdFixtureManifestEntry[],
): VoiceIdFixtureManifestParseError | null {
  const fixtureIds = new Set<string>();
  const audioFileNames = new Set<string>();
  for (const entry of entries) {
    if (fixtureIds.has(entry.fixtureId)) {
      return {
        kind: 'error',
        reason: 'duplicate_fixture_id',
        message: `fixtureId ${entry.fixtureId} is duplicated`,
      };
    }
    fixtureIds.add(entry.fixtureId);
    if (audioFileNames.has(entry.audioFileName)) {
      return {
        kind: 'error',
        reason: 'duplicate_audio_file_name',
        message: `audioFileName ${entry.audioFileName} is duplicated`,
      };
    }
    audioFileNames.add(entry.audioFileName);
  }
  return null;
}

function parseObject(value: unknown, fieldName: string): Record<string, unknown> {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) {
    throw new Error(`${fieldName} must be an object`);
  }
  return value as Record<string, unknown>;
}

function parseArray(value: unknown, fieldName: string): readonly unknown[] {
  if (!Array.isArray(value)) throw new Error(`${fieldName} must be an array`);
  return value;
}

function parseNonEmptyString(value: unknown, fieldName: string): string {
  if (typeof value !== 'string' || value.trim().length === 0) {
    throw new Error(`${fieldName} must be a non-empty string`);
  }
  return value.trim();
}

function parseAudioFileName(value: unknown): string {
  const fileName = parseNonEmptyString(value, 'audioFileName');
  if (fileName.includes('/') || fileName.includes('\\') || fileName === '.' || fileName === '..') {
    throw new Error('audioFileName must be a file name, not a path');
  }
  return fileName;
}

function parseExpectedRelation(value: unknown): VoiceIdFixtureExpectedRelation {
  const normalized = parseNonEmptyString(value, 'expectedRelation');
  if (
    !VOICE_ID_FIXTURE_EXPECTED_RELATIONS.includes(
      normalized as VoiceIdFixtureExpectedRelation,
    )
  ) {
    throw new Error('expectedRelation is invalid');
  }
  return normalized as VoiceIdFixtureExpectedRelation;
}

function parsePositiveNumber(value: unknown, fieldName: string): number {
  if (typeof value !== 'number' || !Number.isFinite(value) || value <= 0) {
    throw new Error(`${fieldName} must be a positive number`);
  }
  return value;
}

function parsePositiveInteger(value: unknown, fieldName: string): number {
  const parsed = parsePositiveNumber(value, fieldName);
  if (!Number.isInteger(parsed)) throw new Error(`${fieldName} must be an integer`);
  return parsed;
}
