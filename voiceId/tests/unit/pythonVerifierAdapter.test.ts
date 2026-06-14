import assert from 'node:assert/strict';
import { mkdtemp, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';
import {
  buildAudioInput,
  nowIsoDateTime,
  parseEncryptedBytes,
  parseModelVersion,
  parseTemplateVersion,
  parseThresholdVersion,
} from '../../shared/src/index.ts';
import {
  PYTHON_VOICE_ID_VERIFIER_SCHEMA_VERSION,
  PythonVoiceIdVerifier,
  parsePythonSpeakerVerificationResponse,
  type PythonBuildTemplateRequest,
  type PythonExtractEnrollmentEmbeddingRequest,
  type PythonVerifySpeakerRequest,
} from '../../server/src/verifier/PythonVoiceIdVerifier.ts';
import {
  PythonHttpVoiceIdVerifierError,
  PythonHttpVoiceIdVerifierTransport,
} from '../../server/src/verifier/PythonHttpVoiceIdVerifierTransport.ts';
import {
  PythonSubprocessVoiceIdVerifierError,
  PythonSubprocessVoiceIdVerifierTransport,
} from '../../server/src/verifier/PythonSubprocessVoiceIdVerifierTransport.ts';

test('PythonVoiceIdVerifier builds enrollment embedding requests and parses responses', async () => {
  const capturedRequests: PythonExtractEnrollmentEmbeddingRequest[] = [];
  const verifier = new PythonVoiceIdVerifier({
    createRequestId: () => 'request_1',
    transport: {
      async extractEnrollmentEmbedding(request) {
        capturedRequests.push(request);
        return enrollmentEmbeddingResponse({ requestId: request.requestId });
      },
      async buildTemplate() {
        throw new Error('unused');
      },
      async verifySpeaker() {
        throw new Error('unused');
      },
    },
  });

  const embedding = await verifier.extractEnrollmentEmbedding({ audio: makeAudio() });

  assert.deepEqual(embedding.vector, [0.1, 0.2, 0.3, 0.4]);
  assert.equal(embedding.speakerLabel, 'owner');
  assert.equal(embedding.quality.kind, 'accepted');
  const capturedRequest = capturedRequests[0];
  assert.equal(capturedRequest.schemaVersion, PYTHON_VOICE_ID_VERIFIER_SCHEMA_VERSION);
  assert.equal(capturedRequest.requestId, 'request_1');
  assert.equal(capturedRequest.audio.audioBase64, Buffer.from([1, 2, 3, 4]).toString('base64'));
  assert.equal(capturedRequest.audio.metadata.byteLength, 4);
  assert.deepEqual(capturedRequest.audio.metadata.sampleRate, { kind: 'known', hertz: 48000 });
});

test('PythonVoiceIdVerifier builds templates through the Python transport', async () => {
  const capturedRequests: PythonBuildTemplateRequest[] = [];
  const verifier = new PythonVoiceIdVerifier({
    createRequestId: () => 'template_request_1',
    transport: {
      async extractEnrollmentEmbedding() {
        throw new Error('unused');
      },
      async buildTemplate(request) {
        capturedRequests.push(request);
        return builtTemplateResponse({ requestId: request.requestId });
      },
      async verifySpeaker() {
        throw new Error('unused');
      },
    },
  });

  const template = await verifier.buildTemplate({
    embeddings: [
      {
        vector: [0.1, 0.2, 0.3, 0.4],
        speakerLabel: 'owner',
        quality: { kind: 'accepted', durationMs: 1800, signalScore: 0.9 },
      },
    ],
  });

  assert.equal(template.kind, 'built');
  const capturedRequest = capturedRequests[0];
  assert.equal(capturedRequest.schemaVersion, PYTHON_VOICE_ID_VERIFIER_SCHEMA_VERSION);
  assert.equal(capturedRequest.embeddings[0].speakerLabel, 'owner');
  assert.deepEqual(capturedRequest.embeddings[0].quality, {
    kind: 'accepted',
    durationMs: 1800,
    signalScore: 0.9,
  });
});

test('PythonVoiceIdVerifier verifies speakers through the Python transport', async () => {
  const capturedRequests: PythonVerifySpeakerRequest[] = [];
  const verifier = new PythonVoiceIdVerifier({
    createRequestId: () => 'verify_request_1',
    transport: {
      async extractEnrollmentEmbedding() {
        throw new Error('unused');
      },
      async buildTemplate() {
        throw new Error('unused');
      },
      async verifySpeaker(request) {
        capturedRequests.push(request);
        return speakerVerificationResponse({ requestId: request.requestId, speakerKind: 'accepted' });
      },
    },
  });

  const result = await verifier.verifySpeaker({
    audio: makeAudio(),
    template: {
      encryptedTemplate: parseEncryptedBytes('template_payload'),
      templateVersion: parseTemplateVersion('template-v1'),
      modelVersion: parseModelVersion('model-v1'),
      thresholdVersion: parseThresholdVersion('threshold-v1'),
    },
    threshold: 0.82,
  });

  assert.equal(result.quality.kind, 'accepted');
  assert.equal(result.speaker.kind, 'accepted');
  const capturedRequest = capturedRequests[0];
  assert.equal(capturedRequest.threshold, 0.82);
  assert.equal(capturedRequest.template.encryptedTemplate, 'template_payload');
});

test('Python verifier response parser handles rejected and uncertain speaker branches', () => {
  const rejected = parsePythonSpeakerVerificationResponse(
    speakerVerificationResponse({ requestId: 'request_1', speakerKind: 'rejected', score: -0.1 }),
  );
  const uncertain = parsePythonSpeakerVerificationResponse(
    speakerVerificationResponse({ requestId: 'request_2', speakerKind: 'uncertain' }),
  );

  assert.equal(rejected.speaker.kind, 'rejected');
  assert.equal(rejected.speaker.kind === 'rejected' ? rejected.speaker.reason : '', 'speaker_mismatch');
  assert.equal(rejected.speaker.kind === 'rejected' ? rejected.speaker.score : 0, -0.1);
  assert.equal(uncertain.speaker.kind, 'uncertain');
  assert.equal(uncertain.speaker.kind === 'uncertain' ? uncertain.speaker.reason : '', 'model_low_confidence');
});

test('Python verifier response parser rejects malformed speaker responses', () => {
  assert.throws(
    () =>
      parsePythonSpeakerVerificationResponse({
        ...speakerVerificationResponse({ requestId: 'request_1', speakerKind: 'accepted' }),
        speaker: {
          kind: 'accepted',
          score: 1.5,
          threshold: 0.82,
          modelVersion: 'model-v1',
          thresholdVersion: 'threshold-v1',
        },
      }),
    /speaker.score must be between -1 and 1/,
  );
});

test('Python subprocess transport calls the verifier app', async () => {
  const verifier = new PythonVoiceIdVerifier({
    createRequestId: () => 'subprocess_request_1',
    transport: new PythonSubprocessVoiceIdVerifierTransport({
      env: { VOICEID_VERIFIER_BACKEND: 'placeholder' },
    }),
  });

  const embedding = await verifier.extractEnrollmentEmbedding({ audio: makeAudio() });

  assert.equal(embedding.quality.kind, 'accepted');
  assert.equal(embedding.speakerLabel, 'unknown_speaker');
  assert.deepEqual(embedding.vector, [
    3 / 7,
    10 / 11,
    10 / 13,
    10 / 17,
  ]);
});

test('Python subprocess transport reports timeouts', async () => {
  const tempDir = await mkdtemp(join(tmpdir(), 'voiceid-verifier-'));
  const scriptPath = join(tempDir, 'sleeping_verifier.py');
  await writeFile(scriptPath, 'import time\\ntime.sleep(2)\\n', 'utf8');
  const verifier = new PythonVoiceIdVerifier({
    transport: new PythonSubprocessVoiceIdVerifierTransport({
      appScriptPath: scriptPath,
      verifierPackagePath: tempDir,
      timeoutMs: 25,
    }),
  });

  await assert.rejects(
    () => verifier.extractEnrollmentEmbedding({ audio: makeAudio() }),
    (error) =>
      error instanceof PythonSubprocessVoiceIdVerifierError &&
      /timed out/.test(error.message),
  );
});

test('Python HTTP transport posts verifier requests to sidecar endpoints', async () => {
  const capturedRequests: Array<{ url: string; body: unknown }> = [];
  const verifier = new PythonVoiceIdVerifier({
    createRequestId: () => 'http_request_1',
    transport: new PythonHttpVoiceIdVerifierTransport({
      baseUrl: 'http://127.0.0.1:9191/voice-id/verifier',
      fetchJson: async (input, init) => {
        capturedRequests.push({
          url: String(input),
          body: JSON.parse(String(init?.body)),
        });
        return new Response(JSON.stringify(enrollmentEmbeddingResponse({ requestId: 'http_request_1' })));
      },
    }),
  });

  const embedding = await verifier.extractEnrollmentEmbedding({ audio: makeAudio() });

  assert.equal(embedding.quality.kind, 'accepted');
  assert.equal(capturedRequests[0].url, 'http://127.0.0.1:9191/voice-id/verifier/extract-enrollment-embedding');
  assert.equal(
    (capturedRequests[0].body as PythonExtractEnrollmentEmbeddingRequest).schemaVersion,
    PYTHON_VOICE_ID_VERIFIER_SCHEMA_VERSION,
  );
});

test('Python HTTP transport reports sidecar HTTP failures', async () => {
  const verifier = new PythonVoiceIdVerifier({
    transport: new PythonHttpVoiceIdVerifierTransport({
      baseUrl: 'http://127.0.0.1:9191',
      fetchJson: async () => new Response('sidecar unavailable', { status: 503 }),
    }),
  });

  await assert.rejects(
    () => verifier.extractEnrollmentEmbedding({ audio: makeAudio() }),
    (error) =>
      error instanceof PythonHttpVoiceIdVerifierError &&
      /HTTP 503/.test(error.message),
  );
});

test('Python HTTP transport reports sidecar timeouts', async () => {
  const verifier = new PythonVoiceIdVerifier({
    transport: new PythonHttpVoiceIdVerifierTransport({
      baseUrl: 'http://127.0.0.1:9191',
      timeoutMs: 25,
      fetchJson: async (_input, init) =>
        await new Promise<Response>((_resolve, reject) => {
          init?.signal?.addEventListener('abort', () => {
            const error = new Error('aborted');
            error.name = 'AbortError';
            reject(error);
          });
        }),
    }),
  });

  await assert.rejects(
    () => verifier.extractEnrollmentEmbedding({ audio: makeAudio() }),
    (error) =>
      error instanceof PythonHttpVoiceIdVerifierError &&
      /timed out/.test(error.message),
  );
});

function makeAudio() {
  const bytes = new Uint8Array([1, 2, 3, 4]);
  return buildAudioInput(bytes, {
    mimeType: 'audio/webm',
    durationMs: 1800,
    sampleRate: { kind: 'known', hertz: 48000 },
    channelCount: { kind: 'known', count: 1 },
    byteLength: bytes.byteLength,
    capturedAt: nowIsoDateTime(new Date('2026-06-09T00:00:00.000Z')),
    recorder: 'MediaRecorder',
    fixtureBehavior: { kind: 'speaker_label', speakerLabel: 'owner' },
  });
}

function enrollmentEmbeddingResponse(input: { requestId: string }) {
  return {
    kind: 'embedding',
    requestId: input.requestId,
    modelVersion: 'python-placeholder-model-v1',
    thresholdVersion: 'python-placeholder-threshold-v1',
    speakerLabel: 'owner',
    embedding: [0.1, 0.2, 0.3, 0.4],
    quality: { kind: 'accepted', durationMs: 1800, signalScore: 0.9 },
  };
}

function builtTemplateResponse(input: { requestId: string }) {
  return {
    kind: 'built',
    requestId: input.requestId,
    encryptedTemplate: 'template_payload',
    templateVersion: 'python-placeholder-template-v1',
    modelVersion: 'python-placeholder-model-v1',
    thresholdVersion: 'python-placeholder-threshold-v1',
    speakerLabel: 'owner',
  };
}

function speakerVerificationResponse(input: {
  requestId: string;
  speakerKind: 'accepted' | 'rejected' | 'uncertain';
  score?: number;
}) {
  return {
    kind: 'speaker_verification',
    requestId: input.requestId,
    quality: { kind: 'accepted', durationMs: 1800, signalScore: 0.9 },
    speaker: speakerResponse(input.speakerKind, input.score),
  };
}

function speakerResponse(kind: 'accepted' | 'rejected' | 'uncertain', score?: number) {
  switch (kind) {
    case 'accepted':
      return {
        kind: 'accepted',
        score: score ?? 0.94,
        threshold: 0.82,
        modelVersion: 'python-placeholder-model-v1',
        thresholdVersion: 'python-placeholder-threshold-v1',
      };
    case 'rejected':
      return {
        kind: 'rejected',
        reason: 'speaker_mismatch',
        score: score ?? 0.3,
        threshold: 0.82,
        modelVersion: 'python-placeholder-model-v1',
        thresholdVersion: 'python-placeholder-threshold-v1',
      };
    case 'uncertain':
      return {
        kind: 'uncertain',
        reason: 'model_low_confidence',
        score: score ?? 0.78,
        threshold: 0.82,
        modelVersion: 'python-placeholder-model-v1',
        thresholdVersion: 'python-placeholder-threshold-v1',
      };
  }
}
