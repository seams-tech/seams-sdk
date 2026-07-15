import type { VoiceIdAudioInput, VoiceIdAudioQualityResult } from '../../../shared/src/audio.ts';
import {
  parseEncryptedBytes,
  parseModelVersion,
  parseTemplateVersion,
  parseThresholdVersion,
} from '../../../shared/src/ids.ts';
import type { VoiceIdSpeakerMatchResult } from '../../../shared/src/results.ts';
import type {
  VoiceIdEnrollmentSpeechWindow,
  VoiceIdSpeakerVerification,
  VoiceIdEnrollmentTemplateBuildResult,
  VoiceIdVerifier,
} from './VoiceIdVerifier.ts';

const modelVersion = parseModelVersion('fake-voiceid-model-v1');
const templateVersion = parseTemplateVersion('fake-template-v1');
const thresholdVersion = parseThresholdVersion('fake-threshold-v1');
const noisyAudioMarker = 0xf1;
const lowScoreAudioMarker = 0xf2;
const differentSpeakerAudioMarker = 0xf3;
const decoderFailureAudioMarker = 0xf5;
const duplicateWindowsAudioMarker = 0xf6;
const interruptedCaptureAudioMarker = 0xf7;

export class FakeVoiceIdVerifier implements VoiceIdVerifier {
  async buildEnrollmentTemplate(input: {
    audio: VoiceIdAudioInput;
    expectedPromptCount: number;
  }): Promise<VoiceIdEnrollmentTemplateBuildResult> {
    const rejection = fakeEnrollmentRejection(input.audio);
    if (rejection !== null) return rejection;
    const quality = evaluateAudioQuality(input.audio);
    if (quality.kind !== 'accepted') {
      return {
        kind: 'rejected',
        reason: quality.reason === 'empty_audio' ? 'decoder_failure' : 'insufficient_speech',
      };
    }
    const windows = fakeSpeechWindows(input.audio.metadata.durationMs, input.expectedPromptCount);

    return {
      kind: 'built',
      encryptedTemplate: parseEncryptedBytes('fake-template:owner'),
      modelVersion,
      templateVersion,
      thresholdVersion,
      quality,
      analysis: {
        analysisVersion: 'fake-continuous-analysis-v1',
        sourceCodec: 'fake-audio',
        sourceSampleRateHz: 16_000,
        sourceChannelCount: 1,
        decodedDurationMs: input.audio.metadata.durationMs,
        usableSpeechMs: windows.reduce(sumSpeechWindowDuration, 0),
        windows,
      },
    };
  }

  async verifySpeaker(input: Parameters<VoiceIdVerifier['verifySpeaker']>[0]): Promise<VoiceIdSpeakerVerification> {
    const quality = evaluateAudioQuality(input.audio);
    const speaker = matchSpeaker({
      audio: input.audio,
      threshold: input.threshold,
    });

    return {
      quality,
      speaker,
    };
  }
}

function fakeEnrollmentRejection(
  audio: VoiceIdAudioInput,
): Extract<VoiceIdEnrollmentTemplateBuildResult, { kind: 'rejected' }> | null {
  switch (audio.bytes[0]) {
    case decoderFailureAudioMarker:
      return { kind: 'rejected', reason: 'decoder_failure' };
    case interruptedCaptureAudioMarker:
      return { kind: 'rejected', reason: 'interrupted_capture' };
    case duplicateWindowsAudioMarker:
      return { kind: 'rejected', reason: 'duplicate_windows' };
    case differentSpeakerAudioMarker:
      return { kind: 'rejected', reason: 'multi_speaker' };
    case noisyAudioMarker:
      return { kind: 'rejected', reason: 'low_snr' };
    default:
      return null;
  }
}

function fakeSpeechWindows(
  durationMs: number,
  expectedPromptCount: number,
): readonly VoiceIdEnrollmentSpeechWindow[] {
  const windowDurationMs = Math.floor(durationMs / expectedPromptCount);
  const windows: VoiceIdEnrollmentSpeechWindow[] = [];
  for (let index = 0; index < expectedPromptCount; index += 1) {
    const startMs = index * windowDurationMs;
    const endMs = index === expectedPromptCount - 1 ? durationMs : startMs + windowDurationMs;
    windows.push({
      index,
      startMs,
      endMs,
      speechMs: Math.max(0, endMs - startMs - 250),
      signalScore: 0.94 - index * 0.01,
      templateWeight: 1 / expectedPromptCount,
    });
  }
  return windows;
}

function sumSpeechWindowDuration(total: number, window: VoiceIdEnrollmentSpeechWindow): number {
  return total + window.speechMs;
}

function evaluateAudioQuality(audio: VoiceIdAudioInput): VoiceIdAudioQualityResult {
  if (audio.bytes.byteLength === 0) {
    return {
      kind: 'rejected',
      reason: 'empty_audio',
      durationMs: audio.metadata.durationMs,
    };
  }

  if (audio.metadata.durationMs < 900) {
    return {
      kind: 'uncertain',
      reason: 'too_short',
      durationMs: audio.metadata.durationMs,
    };
  }

  if (audio.bytes[0] === noisyAudioMarker) {
    return {
      kind: 'uncertain',
      reason: 'noisy_audio',
      durationMs: audio.metadata.durationMs,
    };
  }

  return {
    kind: 'accepted',
    durationMs: audio.metadata.durationMs,
    signalScore: 0.94,
  };
}

function matchSpeaker(input: {
  audio: VoiceIdAudioInput;
  threshold: number;
}): VoiceIdSpeakerMatchResult {
  const score = getSpeakerScore(input.audio);
  if (score >= input.threshold) {
    return {
      kind: 'accepted',
      score,
      threshold: input.threshold,
      modelVersion,
      thresholdVersion,
    };
  }

  if (score >= input.threshold - 0.08) {
    return {
      kind: 'uncertain',
      reason: 'model_low_confidence',
      score,
      threshold: input.threshold,
      modelVersion,
      thresholdVersion,
    };
  }

  return {
    kind: 'rejected',
    reason: 'speaker_mismatch',
    score,
    threshold: input.threshold,
    modelVersion,
    thresholdVersion,
  };
}

function getSpeakerScore(audio: VoiceIdAudioInput): number {
  if (audio.bytes[0] === lowScoreAudioMarker) {
    return 0.72;
  }
  if (audio.bytes[0] === differentSpeakerAudioMarker) {
    return 0.31;
  }

  return 0.9;
}
