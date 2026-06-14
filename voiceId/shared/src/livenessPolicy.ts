import { assertNever } from './assertNever.ts';
import type { IsoDateTime } from './ids.ts';
import type { VoiceIdLivenessResult } from './policy.ts';

export type VoiceIdAudioCaptureSource =
  | {
      kind: 'trusted_microphone';
      deviceId: string;
    }
  | {
      kind: 'unknown_microphone';
      reason: 'browser_device_label_unavailable' | 'robot_source_unattested';
    }
  | {
      kind: 'loopback_or_speaker';
      reason: 'loopback_device' | 'speaker_playback_detected';
    };

export type VoiceIdAudioReplayRisk =
  | {
      kind: 'low';
    }
  | {
      kind: 'high';
      reason: 'reused_capture_hash' | 'synthetic_artifacts' | 'channel_replay_artifacts';
    }
  | {
      kind: 'uncertain';
      reason: 'missing_source_attestation' | 'channel_artifacts_unclear';
    };

export type VoiceIdAudioLivenessSignals = {
  kind: 'audio_liveness_signals_v1';
  promptOpenedAt: IsoDateTime;
  speechStartedAt: IsoDateTime;
  speechEndedAt: IsoDateTime;
  captureSource: VoiceIdAudioCaptureSource;
  replayRisk: VoiceIdAudioReplayRisk;
};

export type VoiceIdLocalDeviceContext = {
  kind: 'local_device_context_v1';
  deviceId: string;
  sidecarId: string;
  captureStartedAt: IsoDateTime;
  evaluatedAt: IsoDateTime;
  localPolicyVersion: string;
};

export type VoiceIdAudioLivenessPolicy = {
  kind: 'audio_liveness_policy_v1';
  minSpeechDurationMs: number;
  maxSpeechDurationMs: number;
  maxPromptToSpeechStartMs: number;
  requireTrustedMicrophone: boolean;
};

export function defaultVoiceIdAudioLivenessPolicy(): VoiceIdAudioLivenessPolicy {
  return {
    kind: 'audio_liveness_policy_v1',
    minSpeechDurationMs: 500,
    maxSpeechDurationMs: 10_000,
    maxPromptToSpeechStartMs: 30_000,
    requireTrustedMicrophone: true,
  };
}

export function evaluateVoiceIdAudioLiveness(input: {
  audio: VoiceIdAudioLivenessSignals;
  context: VoiceIdLocalDeviceContext;
  policy: VoiceIdAudioLivenessPolicy;
}): VoiceIdLivenessResult {
  const promptOpenedAtMs = isoMs(input.audio.promptOpenedAt);
  const speechStartedAtMs = isoMs(input.audio.speechStartedAt);
  const speechEndedAtMs = isoMs(input.audio.speechEndedAt);
  const durationMs = speechEndedAtMs - speechStartedAtMs;

  if (speechStartedAtMs < promptOpenedAtMs) {
    return { kind: 'rejected', reason: 'replay_detected' };
  }
  if (speechStartedAtMs - promptOpenedAtMs > input.policy.maxPromptToSpeechStartMs) {
    return { kind: 'uncertain', reason: 'liveness_unavailable' };
  }
  if (durationMs < input.policy.minSpeechDurationMs || durationMs > input.policy.maxSpeechDurationMs) {
    return { kind: 'uncertain', reason: 'liveness_unavailable' };
  }

  switch (input.audio.captureSource.kind) {
    case 'trusted_microphone':
      break;
    case 'unknown_microphone':
      if (input.policy.requireTrustedMicrophone) {
        return { kind: 'uncertain', reason: 'liveness_unavailable' };
      }
      break;
    case 'loopback_or_speaker':
      return { kind: 'rejected', reason: 'replay_detected' };
    default:
      return assertNever(input.audio.captureSource);
  }

  switch (input.audio.replayRisk.kind) {
    case 'low':
      return {
        kind: 'accepted',
        method: 'audio',
        checkedAt: input.context.evaluatedAt,
      };
    case 'high':
      return { kind: 'rejected', reason: 'replay_detected' };
    case 'uncertain':
      return { kind: 'uncertain', reason: 'liveness_unavailable' };
    default:
      return assertNever(input.audio.replayRisk);
  }
}

function isoMs(value: IsoDateTime): number {
  return Date.parse(value);
}
