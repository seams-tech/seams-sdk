import {
  type VoiceIdAudioChannelCount,
  type VoiceIdAudioMetadata,
  type VoiceIdAudioSampleRate,
  type VoiceIdFixtureBehavior,
} from './audio.ts';
import { parseIsoDateTime } from './ids.ts';

type JsonObject = Record<string, unknown>;

export function parseJsonObject(value: unknown, name: string): JsonObject {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) {
    throw new Error(`${name} must be an object`);
  }

  return value as JsonObject;
}

export function parseVoiceIdAudioMetadata(value: unknown): VoiceIdAudioMetadata {
  const input = parseJsonObject(value, 'audio metadata');
  const mimeType = parseString(input.mimeType, 'mimeType');
  const durationMs = parsePositiveNumber(input.durationMs, 'durationMs');
  const byteLength = parsePositiveInteger(input.byteLength, 'byteLength');
  const recorder = parseString(input.recorder, 'recorder');
  const capturedAt = parseIsoDateTime(input.capturedAt);

  return {
    mimeType,
    durationMs,
    byteLength,
    recorder,
    capturedAt,
    sampleRate: parseSampleRate(input.sampleRate),
    channelCount: parseChannelCount(input.channelCount),
    fixtureBehavior: parseFixtureBehavior(input.fixtureBehavior),
  };
}

function parseSampleRate(value: unknown): VoiceIdAudioSampleRate {
  const input = parseJsonObject(value, 'sampleRate');
  if (input.kind === 'unknown') {
    return { kind: 'unknown' };
  }
  if (input.kind === 'known') {
    return { kind: 'known', hertz: parsePositiveInteger(input.hertz, 'sampleRate.hertz') };
  }

  throw new Error('sampleRate.kind must be known or unknown');
}

function parseChannelCount(value: unknown): VoiceIdAudioChannelCount {
  const input = parseJsonObject(value, 'channelCount');
  if (input.kind === 'unknown') {
    return { kind: 'unknown' };
  }
  if (input.kind === 'known') {
    return { kind: 'known', count: parsePositiveInteger(input.count, 'channelCount.count') };
  }

  throw new Error('channelCount.kind must be known or unknown');
}

function parseFixtureBehavior(value: unknown): VoiceIdFixtureBehavior {
  const input = parseJsonObject(value, 'fixtureBehavior');
  if (input.kind === 'none') {
    return { kind: 'none' };
  }
  if (input.kind === 'speaker_label') {
    return { kind: 'speaker_label', speakerLabel: parseString(input.speakerLabel, 'speakerLabel') };
  }
  if (input.kind === 'low_score') {
    return { kind: 'low_score', speakerLabel: parseString(input.speakerLabel, 'speakerLabel') };
  }
  if (input.kind === 'noisy') {
    return { kind: 'noisy', speakerLabel: parseString(input.speakerLabel, 'speakerLabel') };
  }

  throw new Error('fixtureBehavior.kind is invalid');
}

function parseString(value: unknown, fieldName: string): string {
  if (typeof value !== 'string' || value.trim().length === 0) {
    throw new Error(`${fieldName} must be a non-empty string`);
  }

  return value;
}

function parsePositiveNumber(value: unknown, fieldName: string): number {
  if (typeof value !== 'number' || !Number.isFinite(value) || value <= 0) {
    throw new Error(`${fieldName} must be a positive number`);
  }

  return value;
}

function parsePositiveInteger(value: unknown, fieldName: string): number {
  const parsed = parsePositiveNumber(value, fieldName);
  if (!Number.isInteger(parsed)) {
    throw new Error(`${fieldName} must be an integer`);
  }

  return parsed;
}
