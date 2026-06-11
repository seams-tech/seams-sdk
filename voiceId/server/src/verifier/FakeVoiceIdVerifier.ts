import type { VoiceIdAudioInput, VoiceIdAudioQualityResult } from '../../../shared/src/audio.ts';
import {
  parseEncryptedBytes,
  parseModelVersion,
  parseTemplateVersion,
  parseThresholdVersion,
} from '../../../shared/src/ids.ts';
import type { VoiceIdSpeakerMatchResult } from '../../../shared/src/results.ts';
import type {
  VoiceIdEnrollmentEmbedding,
  VoiceIdSpeakerVerification,
  VoiceIdTemplateBuildResult,
  VoiceIdVerifier,
} from './VoiceIdVerifier.ts';

const modelVersion = parseModelVersion('fake-voiceid-model-v1');
const templateVersion = parseTemplateVersion('fake-template-v1');
const thresholdVersion = parseThresholdVersion('fake-threshold-v1');

export class FakeVoiceIdVerifier implements VoiceIdVerifier {
  async extractEnrollmentEmbedding(input: {
    audio: VoiceIdAudioInput;
  }): Promise<VoiceIdEnrollmentEmbedding> {
    const quality = evaluateAudioQuality(input.audio);
    const speakerLabel = getSpeakerLabel(input.audio);

    return {
      vector: deterministicVector(speakerLabel),
      speakerLabel,
      quality,
    };
  }

  async buildTemplate(input: {
    embeddings: readonly VoiceIdEnrollmentEmbedding[];
  }): Promise<VoiceIdTemplateBuildResult> {
    const accepted = input.embeddings.filter((embedding) => embedding.quality.kind === 'accepted');
    if (accepted.length === 0) {
      return { kind: 'rejected', reason: 'insufficient_quality' };
    }

    const [first] = accepted;
    const allSameSpeaker = accepted.every((embedding) => embedding.speakerLabel === first.speakerLabel);
    if (!allSameSpeaker) {
      return { kind: 'rejected', reason: 'inconsistent_speaker' };
    }

    return {
      kind: 'built',
      encryptedTemplate: parseEncryptedBytes(`fake-template:${first.speakerLabel}`),
      modelVersion,
      templateVersion,
      thresholdVersion,
      speakerLabel: first.speakerLabel,
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

  if (audio.metadata.fixtureBehavior.kind === 'noisy') {
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
  if (audio.metadata.fixtureBehavior.kind === 'low_score') {
    return 0.72;
  }
  if (audio.metadata.fixtureBehavior.kind === 'speaker_label') {
    return audio.metadata.fixtureBehavior.speakerLabel === 'owner' ? 0.94 : 0.31;
  }

  return 0.9;
}

function getSpeakerLabel(audio: VoiceIdAudioInput): string {
  if (audio.metadata.fixtureBehavior.kind === 'speaker_label') {
    return audio.metadata.fixtureBehavior.speakerLabel;
  }
  if (audio.metadata.fixtureBehavior.kind === 'low_score') {
    return audio.metadata.fixtureBehavior.speakerLabel;
  }
  if (audio.metadata.fixtureBehavior.kind === 'noisy') {
    return audio.metadata.fixtureBehavior.speakerLabel;
  }

  return 'owner';
}

function deterministicVector(seed: string): readonly number[] {
  const base = Array.from(seed).reduce((sum, char) => sum + char.charCodeAt(0), 0);
  return [base % 7, base % 11, base % 13, base % 17].map((value) => value / 17);
}
