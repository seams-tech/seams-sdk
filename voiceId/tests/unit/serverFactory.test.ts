import assert from 'node:assert/strict';
import test from 'node:test';
import {
  createDefaultVoiceIdService,
  createVoiceIdVerifierFromEnv,
  PythonVoiceIdVerifier,
  voiceIdEcapaLocalDevSpeakerScoreThreshold,
  voiceIdFakeSpeakerScoreThreshold,
  voiceIdSpeakerScoreThresholdFromEnv,
  verifierTransportModeFromEnv,
} from '../../server/src/index.ts';
import { FakeVoiceIdVerifier } from '../../server/src/verifier/FakeVoiceIdVerifier.ts';

test('verifier transport mode defaults to fake', () => {
  withEnv({ VOICEID_VERIFIER_TRANSPORT: null }, () => {
    assert.equal(verifierTransportModeFromEnv(), 'fake');
  });
});

test('verifier transport mode accepts supported deployment modes', () => {
  withEnv({ VOICEID_VERIFIER_TRANSPORT: 'python-subprocess' }, () => {
    assert.equal(verifierTransportModeFromEnv(), 'python-subprocess');
  });
  withEnv({ VOICEID_VERIFIER_TRANSPORT: 'python-http' }, () => {
    assert.equal(verifierTransportModeFromEnv(), 'python-http');
  });
});

test('verifier transport mode rejects invalid values', () => {
  withEnv({ VOICEID_VERIFIER_TRANSPORT: 'python' }, () => {
    assert.throws(
      () => verifierTransportModeFromEnv(),
      /VOICEID_VERIFIER_TRANSPORT/,
    );
  });
});

test('factory builds fake and Python verifier modes', () => {
  assert.ok(createVoiceIdVerifierFromEnv('fake') instanceof FakeVoiceIdVerifier);
  assert.ok(createVoiceIdVerifierFromEnv('python-subprocess') instanceof PythonVoiceIdVerifier);
  assert.ok(createVoiceIdVerifierFromEnv('python-http') instanceof PythonVoiceIdVerifier);
});

test('default service accepts explicit verifier mode override', () => {
  const service = createDefaultVoiceIdService({ verifierMode: 'fake' });
  assert.equal(typeof service.startEnrollment, 'function');
});

test('service threshold config defaults by verifier backend and accepts env override', () => {
  assert.equal(
    voiceIdSpeakerScoreThresholdFromEnv({
      env: {},
      verifierMode: 'fake',
    }),
    voiceIdFakeSpeakerScoreThreshold,
  );
  assert.equal(
    voiceIdSpeakerScoreThresholdFromEnv({
      env: { VOICEID_VERIFIER_BACKEND: 'ecapa' },
      verifierMode: 'python-http',
    }),
    voiceIdEcapaLocalDevSpeakerScoreThreshold,
  );
  assert.equal(
    voiceIdSpeakerScoreThresholdFromEnv({
      env: { VOICEID_SPEAKER_SCORE_THRESHOLD: '0.7', VOICEID_VERIFIER_BACKEND: 'ecapa' },
      verifierMode: 'python-http',
    }),
    0.7,
  );
  assert.throws(
    () =>
      voiceIdSpeakerScoreThresholdFromEnv({
        env: { VOICEID_SPEAKER_SCORE_THRESHOLD: '1.5' },
        verifierMode: 'python-http',
      }),
    /VOICEID_SPEAKER_SCORE_THRESHOLD/,
  );
});

function withEnv(updates: Readonly<Record<string, string | null>>, run: () => void): void {
  const previous = new Map<string, string | undefined>();
  for (const name of Object.keys(updates)) {
    previous.set(name, process.env[name]);
    const value = updates[name];
    if (value === null) {
      delete process.env[name];
    } else {
      process.env[name] = value;
    }
  }

  try {
    run();
  } finally {
    for (const [name, value] of previous) {
      if (value === undefined) {
        delete process.env[name];
      } else {
        process.env[name] = value;
      }
    }
  }
}
