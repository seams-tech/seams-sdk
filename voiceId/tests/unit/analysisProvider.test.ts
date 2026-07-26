import assert from 'node:assert/strict';
import test from 'node:test';
import { PythonMoonshineAnalysisProvider } from '../../server/src/analysis/PythonMoonshineAnalysisProvider.ts';
import type { PythonVoiceIdVerifierTransport } from '../../server/src/verifier/PythonVoiceIdVerifier.ts';
import {
  buildAudioInput,
  nowIsoDateTime,
  parseEncryptedBytes,
  parseModelVersion,
  parseTemplateVersion,
  parseThresholdVersion,
  parseUserId,
  parseEnrollmentId,
  parsePromptPhrase,
  parsePromptSetId,
} from '../../shared/src/index.ts';

test('Python Moonshine analysis provider parses one combined verification response', async () => {
  let request: Record<string, unknown> | null = null;
  const transport: PythonVoiceIdVerifierTransport = {
    async buildEnrollmentTemplate() {
      throw new Error('unused');
    },
    async verifySpeaker() {
      throw new Error('unused');
    },
    async analyzeVerification(value) {
      request = value;
      return {
        kind: 'verification_analysis',
        requestId: value.requestId,
        quality: { kind: 'accepted', durationMs: 1500, signalScore: 0.94 },
        speaker: {
          kind: 'accepted',
          score: 0.91,
          threshold: 0.82,
          modelVersion: 'model-v1',
          thresholdVersion: 'threshold-v1',
        },
        speech: {
          kind: 'speech_analysis',
          requestId: 'speech_1',
          transcript: 'please approve this request f e d c b a',
          phrase: {
            kind: 'accepted',
            expectedNormalized: 'approve this request a b c d e f',
            spokenNormalized: 'please approve this request f e d c b a',
            confidence: 0.91,
            reason: null,
          },
          intent: {
            kind: 'accepted',
            intent: 'approve',
            canonicalPhrase: 'approve this request',
            confidence: 0.91,
            reason: null,
          },
          sampleRateHz: 16000,
        },
        pad: {
          kind: 'accepted',
          score: 0.91,
          rejectThreshold: 0.35,
          acceptThreshold: 0.65,
          modelVersion: 'aasist-test',
          calibrationVersion: 'pad-calibration-test',
          latencyMs: 18.5,
        },
      };
    },
  };
  const provider = new PythonMoonshineAnalysisProvider(transport, 'approve');
  const result = await provider.analyzeVerification({
    audio: buildAudioInput(new Uint8Array([1, 2, 3]), {
      mimeType: 'audio/webm',
      durationMs: 1500,
      sampleRate: { kind: 'unknown' },
      channelCount: { kind: 'unknown' },
      byteLength: 3,
      capturedAt: nowIsoDateTime(),
      recorder: 'test',
    }),
    expectedPhrase: parsePromptPhrase('approve this request a b c d e f'),
    enrollment: {
      state: 'enrolled',
      userId: parseUserId('owner'),
      enrollmentId: parseEnrollmentId('enrollment_1'),
      promptSetId: parsePromptSetId('prompt_set_1'),
      modelVersion: parseModelVersion('model-v1'),
      templateVersion: parseTemplateVersion('template-v1'),
      thresholdVersion: parseThresholdVersion('threshold-v1'),
      encryptedTemplate: parseEncryptedBytes('template'),
      createdAt: nowIsoDateTime(),
      enrolledAt: nowIsoDateTime(),
    },
    threshold: 0.82,
  });

  assert.equal(result.phrase.kind, 'accepted');
  assert.equal(result.intent.kind, 'accepted');
  assert.equal(result.intent.kind === 'accepted' ? result.intent.matchedIntent : '', 'approve');
  assert.equal(result.speaker.kind, 'accepted');
  assert.equal(result.pad.kind, 'accepted');
  assert.ok(request !== null);
  assert.equal(request['expectedPhrase'], 'approve this request a b c d e f');
  assert.deepEqual(request['challengeTokens'], ['a', 'b', 'c', 'd', 'e', 'f']);
});
