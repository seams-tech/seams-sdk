import assert from 'node:assert/strict';
import test from 'node:test';
import {
  createVoiceIdApiOnlyCapability,
  createVoiceIdBrowserCaptureCapability,
  VoiceIdClient,
  type VoiceIdRecorderLike,
} from '../../client/src/index.ts';
import {
  parseIsoDateTime,
  type VoiceIdAudioLivenessSignals,
  type VoiceIdLocalDeviceContext,
} from '../../shared/src/index.ts';

test('VoiceIdClient binds fetch before invoking it', async () => {
  const client = new VoiceIdClient({
    baseUrl: 'http://localhost',
    fetch(input, init) {
      assert.equal(this, globalThis);
      assert.equal(String(input), 'http://localhost/voice-id/enrollment/start');
      assert.equal(init?.method, 'POST');

      return Promise.resolve(
        new Response(JSON.stringify({ kind: 'ok', value: { ok: true } }), {
          headers: { 'Content-Type': 'application/json' },
        }),
      );
    },
  });

  const response = await client.startEnrollment({
    userId: 'owner',
    phrase: 'Walking on clouds',
  });

  assert.deepEqual(response, { kind: 'ok', value: { ok: true } });
});

test('VoiceIdClient posts owner-presence authorization requests', async () => {
  let postedBody: unknown = null;
  const client = new VoiceIdClient({
    baseUrl: 'http://localhost',
    fetch(input, init) {
      assert.equal(String(input), 'http://localhost/voice-id/owner-presence/authorize');
      assert.equal(init?.method, 'POST');
      postedBody = JSON.parse(String(init?.body)) as unknown;

      return Promise.resolve(
        new Response(JSON.stringify({ kind: 'ok', value: { decision: { kind: 'accepted' } } }), {
          headers: { 'Content-Type': 'application/json' },
        }),
      );
    },
  });

  const response = await client.authorizeOwnerPresence({
    verificationId: 'verify_1',
    intentDigest: 'A'.repeat(43),
    useCase: 'wallet_mpc_signing',
    policyVersion: 'voiceid-wallet-policy-v1',
    audio: acceptedAudioLivenessSignals(),
    context: localDeviceContext(),
  });

  assert.deepEqual(response, { kind: 'ok', value: { decision: { kind: 'accepted' } } });
  assert.deepEqual(
    postedBody,
    {
      verificationId: 'verify_1',
      intentDigest: 'A'.repeat(43),
      useCase: 'wallet_mpc_signing',
      policyVersion: 'voiceid-wallet-policy-v1',
      audio: acceptedAudioLivenessSignals(),
      context: localDeviceContext(),
    },
  );
});

test('VoiceID API-only capability exposes route client without recorder', () => {
  const capability = createVoiceIdApiOnlyCapability({
    clientConfig: {
      baseUrl: 'http://localhost',
      fetch: async () => new Response('{}'),
    },
  });

  assert.equal(capability.kind, 'voice_id_client_capability_v1');
  assert.equal(capability.mode, 'api_only');
  assert.ok(capability.client instanceof VoiceIdClient);
  assert.equal('createRecorder' in capability, false);
});

test('VoiceID browser capability loads recorder lazily', async () => {
  let loaderCalls = 0;
  const capability = createVoiceIdBrowserCaptureCapability({
    clientConfig: {
      baseUrl: 'http://localhost',
      fetch: async () => new Response('{}'),
    },
    recorderLoader: async () => {
      loaderCalls += 1;
      return FakeRecorder;
    },
  });

  assert.equal(capability.mode, 'browser_capture');
  assert.equal(loaderCalls, 0);

  const recorder = await capability.createRecorder();
  assert.equal(loaderCalls, 1);
  assert.equal(recorder.state.kind, 'idle');
});

class FakeRecorder implements VoiceIdRecorderLike {
  state: VoiceIdRecorderLike['state'] = { kind: 'idle' };

  async recordClip(): Promise<VoiceIdRecorderLike['state']> {
    return this.state;
  }

  buildMetadata(): never {
    throw new Error('not implemented in capability unit test');
  }
}

function acceptedAudioLivenessSignals(): VoiceIdAudioLivenessSignals {
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
