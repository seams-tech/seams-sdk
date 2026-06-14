import assert from 'node:assert/strict';
import test from 'node:test';
import {
  defaultVoiceIdAudioLivenessPolicy,
  evaluateVoiceIdAudioLiveness,
  parseIsoDateTime,
  type VoiceIdAudioLivenessSignals,
  type VoiceIdLocalDeviceContext,
} from '../../shared/src/index.ts';

test('audio liveness accepts fresh speech from a trusted microphone', () => {
  const result = evaluateVoiceIdAudioLiveness({
    audio: acceptedAudio(),
    context: localDeviceContext(),
    policy: defaultVoiceIdAudioLivenessPolicy(),
  });

  assert.deepEqual(result, {
    kind: 'accepted',
    method: 'audio',
    checkedAt: parseIsoDateTime('2026-06-13T00:00:02.200Z'),
  });
});

test('audio liveness rejects replay-risk audio', () => {
  const result = evaluateVoiceIdAudioLiveness({
    audio: {
      ...acceptedAudio(),
      replayRisk: { kind: 'high', reason: 'reused_capture_hash' },
    },
    context: localDeviceContext(),
    policy: defaultVoiceIdAudioLivenessPolicy(),
  });

  assert.deepEqual(result, { kind: 'rejected', reason: 'replay_detected' });
});

test('audio liveness rejects loopback or speaker playback sources', () => {
  const result = evaluateVoiceIdAudioLiveness({
    audio: {
      ...acceptedAudio(),
      captureSource: {
        kind: 'loopback_or_speaker',
        reason: 'speaker_playback_detected',
      },
    },
    context: localDeviceContext(),
    policy: defaultVoiceIdAudioLivenessPolicy(),
  });

  assert.deepEqual(result, { kind: 'rejected', reason: 'replay_detected' });
});

test('audio liveness returns uncertain for unknown microphone under embedded policy', () => {
  const result = evaluateVoiceIdAudioLiveness({
    audio: {
      ...acceptedAudio(),
      captureSource: {
        kind: 'unknown_microphone',
        reason: 'robot_source_unattested',
      },
    },
    context: localDeviceContext(),
    policy: defaultVoiceIdAudioLivenessPolicy(),
  });

  assert.deepEqual(result, { kind: 'uncertain', reason: 'liveness_unavailable' });
});

test('audio liveness returns uncertain for implausible speech timing', () => {
  const result = evaluateVoiceIdAudioLiveness({
    audio: {
      ...acceptedAudio(),
      speechStartedAt: parseIsoDateTime('2026-06-13T00:00:00.600Z'),
      speechEndedAt: parseIsoDateTime('2026-06-13T00:00:00.700Z'),
    },
    context: localDeviceContext(),
    policy: defaultVoiceIdAudioLivenessPolicy(),
  });

  assert.deepEqual(result, { kind: 'uncertain', reason: 'liveness_unavailable' });
});

function acceptedAudio(): VoiceIdAudioLivenessSignals {
  return {
    kind: 'audio_liveness_signals_v1',
    promptOpenedAt: parseIsoDateTime('2026-06-13T00:00:00.000Z'),
    speechStartedAt: parseIsoDateTime('2026-06-13T00:00:00.600Z'),
    speechEndedAt: parseIsoDateTime('2026-06-13T00:00:01.900Z'),
    captureSource: {
      kind: 'trusted_microphone',
      deviceId: 'reachy-mic-1',
    },
    replayRisk: { kind: 'low' },
  };
}

function localDeviceContext(): VoiceIdLocalDeviceContext {
  return {
    kind: 'local_device_context_v1',
    deviceId: 'reachy-mini-devkit',
    sidecarId: 'voiceid-sidecar-1',
    captureStartedAt: parseIsoDateTime('2026-06-13T00:00:00.000Z'),
    evaluatedAt: parseIsoDateTime('2026-06-13T00:00:02.200Z'),
    localPolicyVersion: 'voiceid-liveness-policy-v1',
  };
}
