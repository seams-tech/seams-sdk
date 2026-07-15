import { nowIsoDateTime, type VoiceIdAudioMetadata } from '../../../shared/src/index.ts';

export function buildBrowserAudioMetadata(input: {
  blob: Blob;
  durationMs: number;
  recorder: string;
}): VoiceIdAudioMetadata {
  return {
    mimeType: input.blob.type || 'audio/webm',
    durationMs: input.durationMs,
    sampleRate: { kind: 'unknown' },
    channelCount: { kind: 'unknown' },
    byteLength: input.blob.size,
    capturedAt: nowIsoDateTime(),
    recorder: input.recorder,
  };
}

export function buildVoiceIdAudioFormData(input: {
  blob: Blob;
  metadata: VoiceIdAudioMetadata;
  fields: Record<string, unknown>;
}): FormData {
  const form = new FormData();
  form.set('audio', input.blob);
  form.set('metadata', JSON.stringify(input.metadata));
  form.set('fields', JSON.stringify(input.fields));
  return form;
}
