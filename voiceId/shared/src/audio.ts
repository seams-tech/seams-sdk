import type { IsoDateTime } from './ids.ts';

export type VoiceIdAudioKnownSampleRate = {
  kind: 'known';
  hertz: number;
};

export type VoiceIdAudioUnknownSampleRate = {
  kind: 'unknown';
};

export type VoiceIdAudioSampleRate =
  | VoiceIdAudioKnownSampleRate
  | VoiceIdAudioUnknownSampleRate;

export type VoiceIdAudioKnownChannelCount = {
  kind: 'known';
  count: number;
};

export type VoiceIdAudioUnknownChannelCount = {
  kind: 'unknown';
};

export type VoiceIdAudioChannelCount =
  | VoiceIdAudioKnownChannelCount
  | VoiceIdAudioUnknownChannelCount;

export type VoiceIdAudioMetadata = {
  mimeType: string;
  durationMs: number;
  sampleRate: VoiceIdAudioSampleRate;
  channelCount: VoiceIdAudioChannelCount;
  byteLength: number;
  capturedAt: IsoDateTime;
  recorder: string;
};

export type VoiceIdAudioInput = {
  bytes: Uint8Array;
  metadata: VoiceIdAudioMetadata;
};

export type VoiceIdAudioQualityResult =
  | {
      kind: 'accepted';
      durationMs: number;
      signalScore: number;
    }
  | {
      kind: 'rejected';
      reason: 'too_short' | 'empty_audio';
      durationMs: number;
    }
  | {
      kind: 'uncertain';
      reason:
        | 'noisy_audio'
        | 'too_short'
        | 'model_low_confidence'
        | 'verifier_unavailable'
        | 'undecodable_audio'
        | 'clipped_audio'
        | 'low_speech'
        | 'low_snr'
        | 'metadata_mismatch';
      durationMs: number;
    };

export function buildAudioInput(bytes: Uint8Array, metadata: VoiceIdAudioMetadata): VoiceIdAudioInput {
  if (bytes.byteLength !== metadata.byteLength) {
    throw new Error('audio byte length does not match metadata');
  }

  return { bytes, metadata };
}
