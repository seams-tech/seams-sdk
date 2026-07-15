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
  type VoiceIdAudioInput,
} from '../../shared/src/index.ts';
import {
  PYTHON_VOICE_ID_VERIFIER_SCHEMA_VERSION,
  PythonVoiceIdVerifier,
  parsePythonEnrollmentTemplateResponse,
  parsePythonSpeakerVerificationResponse,
  type PythonBuildEnrollmentTemplateRequest,
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

test('PythonVoiceIdVerifier submits one continuous recording for atomic enrollment', async () => {
  const capturedRequests: PythonBuildEnrollmentTemplateRequest[] = [];
  const verifier = new PythonVoiceIdVerifier({
    createRequestId: () => 'enrollment_request_1',
    transport: {
      async buildEnrollmentTemplate(request) {
        capturedRequests.push(request);
        return builtEnrollmentTemplateResponse(request.requestId);
      },
      async verifySpeaker() {
        throw new Error('unused');
      },
    },
  });

  const result = await verifier.buildEnrollmentTemplate({
    audio: makeEnrollmentAudio(),
    expectedPromptCount: 4,
  });

  assert.equal(result.kind, 'built');
  assert.equal(result.kind === 'built' ? result.analysis.windows.length : 0, 4);
  assert.equal(capturedRequests.length, 1);
  const capturedRequest = capturedRequests[0];
  assert.equal(capturedRequest.schemaVersion, PYTHON_VOICE_ID_VERIFIER_SCHEMA_VERSION);
  assert.equal(capturedRequest.requestId, 'enrollment_request_1');
  assert.equal(capturedRequest.expectedPromptCount, 4);
  assert.equal(capturedRequest.audio.metadata.byteLength, capturedRequest.audio.audioBase64.length / 4 * 3 - 1);
  assert.deepEqual(capturedRequest.audio.metadata.sampleRate, { kind: 'known', hertz: 16000 });
});

test('Python enrollment parser preserves precise terminal failures', () => {
  const result = parsePythonEnrollmentTemplateResponse({
    kind: 'rejected',
    requestId: 'enrollment_request_1',
    reason: 'duplicate_windows',
  });

  assert.deepEqual(result, { kind: 'rejected', reason: 'duplicate_windows' });
});

test('PythonVoiceIdVerifier verifies speakers through the current transport', async () => {
  const capturedRequests: PythonVerifySpeakerRequest[] = [];
  const verifier = new PythonVoiceIdVerifier({
    createRequestId: () => 'verify_request_1',
    transport: {
      async buildEnrollmentTemplate() {
        throw new Error('unused');
      },
      async verifySpeaker(request) {
        capturedRequests.push(request);
        return speakerVerificationResponse(request.requestId, 'accepted');
      },
    },
  });

  const result = await verifier.verifySpeaker({
    audio: makeVerificationAudio(),
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
  assert.equal(capturedRequests[0].threshold, 0.82);
  assert.equal(capturedRequests[0].template.encryptedTemplate, 'template_payload');
});

test('Python speaker parser handles rejected and uncertain branches', () => {
  const rejected = parsePythonSpeakerVerificationResponse(
    speakerVerificationResponse('request_1', 'rejected', -0.1),
  );
  const uncertain = parsePythonSpeakerVerificationResponse(
    speakerVerificationResponse('request_2', 'uncertain'),
  );

  assert.equal(rejected.speaker.kind, 'rejected');
  assert.equal(rejected.speaker.kind === 'rejected' ? rejected.speaker.reason : '', 'speaker_mismatch');
  assert.equal(rejected.speaker.kind === 'rejected' ? rejected.speaker.score : 0, -0.1);
  assert.equal(uncertain.speaker.kind, 'uncertain');
  assert.equal(uncertain.speaker.kind === 'uncertain' ? uncertain.speaker.reason : '', 'model_low_confidence');
});

test('Python speaker parser rejects malformed scores', () => {
  const response = speakerVerificationResponse('request_1', 'accepted');
  response.speaker.score = 1.5;

  assert.throws(
    () => parsePythonSpeakerVerificationResponse(response),
    /speaker.score must be between -1 and 1/,
  );
});

test('Python subprocess transport builds a template without exporting embeddings', async () => {
  const verifier = new PythonVoiceIdVerifier({
    createRequestId: () => 'subprocess_request_1',
    transport: new PythonSubprocessVoiceIdVerifierTransport({
      env: { VOICEID_VERIFIER_BACKEND: 'placeholder' },
    }),
  });

  const result = await verifier.buildEnrollmentTemplate({
    audio: makeEnrollmentAudio(),
    expectedPromptCount: 4,
  });

  assert.equal(result.kind, 'built');
  assert.equal(result.kind === 'built' ? result.analysis.windows.length : 0, 4);
});

test('Python subprocess transport reports timeouts', async () => {
  const tempDir = await mkdtemp(join(tmpdir(), 'voiceid-verifier-'));
  const scriptPath = join(tempDir, 'sleeping_verifier.py');
  await writeFile(scriptPath, 'import time\ntime.sleep(2)\n', 'utf8');
  const verifier = new PythonVoiceIdVerifier({
    transport: new PythonSubprocessVoiceIdVerifierTransport({
      appScriptPath: scriptPath,
      verifierPackagePath: tempDir,
      timeoutMs: 25,
    }),
  });

  await assert.rejects(
    () =>
      verifier.buildEnrollmentTemplate({
        audio: makeTransportOnlyAudio(),
        expectedPromptCount: 4,
      }),
    (error) =>
      error instanceof PythonSubprocessVoiceIdVerifierError && /timed out/.test(error.message),
  );
});

test('Python HTTP transport posts to the atomic enrollment endpoint', async () => {
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
        return new Response(JSON.stringify(builtEnrollmentTemplateResponse('http_request_1')));
      },
    }),
  });

  const result = await verifier.buildEnrollmentTemplate({
    audio: makeEnrollmentAudio(),
    expectedPromptCount: 4,
  });

  assert.equal(result.kind, 'built');
  assert.equal(
    capturedRequests[0].url,
    'http://127.0.0.1:9191/voice-id/verifier/build-enrollment-template',
  );
  const bodyJson = JSON.stringify(capturedRequests[0].body);
  assert.match(bodyJson, /"schemaVersion":"voice_id_verifier_v2"/);
  assert.match(bodyJson, /"requestId":"http_request_1"/);
  assert.match(bodyJson, /"expectedPromptCount":4/);
});

test('Python HTTP transport reports sidecar HTTP failures', async () => {
  const verifier = new PythonVoiceIdVerifier({
    transport: new PythonHttpVoiceIdVerifierTransport({
      baseUrl: 'http://127.0.0.1:9191',
      fetchJson: async () => new Response('sidecar unavailable', { status: 503 }),
    }),
  });

  await assert.rejects(
    () => verifier.buildEnrollmentTemplate({ audio: makeEnrollmentAudio(), expectedPromptCount: 4 }),
    (error) => error instanceof PythonHttpVoiceIdVerifierError && /HTTP 503/.test(error.message),
  );
});

test('Python HTTP transport reports sidecar timeouts', async () => {
  const verifier = new PythonVoiceIdVerifier({
    transport: new PythonHttpVoiceIdVerifierTransport({
      baseUrl: 'http://127.0.0.1:9191',
      timeoutMs: 25,
      fetchJson: waitForAbort,
    }),
  });

  await assert.rejects(
    () => verifier.buildEnrollmentTemplate({ audio: makeEnrollmentAudio(), expectedPromptCount: 4 }),
    (error) => error instanceof PythonHttpVoiceIdVerifierError && /timed out/.test(error.message),
  );
});

function waitForAbort(_input: RequestInfo | URL, init?: RequestInit): Promise<Response> {
  return new Promise<Response>((_resolve, reject) => {
    init?.signal?.addEventListener('abort', () => {
      const error = new Error('aborted');
      error.name = 'AbortError';
      reject(error);
    });
  });
}

function makeEnrollmentAudio(): VoiceIdAudioInput {
  const bytes = makeWav([
    { frequencyHz: 210, durationMs: 2500 },
    { frequencyHz: null, durationMs: 500 },
    { frequencyHz: 270, durationMs: 2500 },
    { frequencyHz: null, durationMs: 500 },
    { frequencyHz: 330, durationMs: 2500 },
    { frequencyHz: null, durationMs: 500 },
    { frequencyHz: 410, durationMs: 2500 },
    { frequencyHz: null, durationMs: 500 },
  ]);
  return makeAudio(bytes, 12000);
}

function makeVerificationAudio(): VoiceIdAudioInput {
  return makeAudio(makeWav([{ frequencyHz: 240, durationMs: 1800 }]), 1800);
}

function makeTransportOnlyAudio(): VoiceIdAudioInput {
  return makeAudio(new Uint8Array([1, 2, 3, 4]), 6000);
}

function makeAudio(bytes: Uint8Array, durationMs: number): VoiceIdAudioInput {
  return buildAudioInput(bytes, {
    mimeType: 'audio/wav',
    durationMs,
    sampleRate: { kind: 'known', hertz: 16000 },
    channelCount: { kind: 'known', count: 1 },
    byteLength: bytes.byteLength,
    capturedAt: nowIsoDateTime(new Date('2026-06-09T00:00:00.000Z')),
    recorder: 'MediaRecorder',
  });
}

type WavSegment = {
  readonly frequencyHz: number | null;
  readonly durationMs: number;
};

function makeWav(segments: readonly WavSegment[]): Uint8Array {
  const sampleRateHz = 16000;
  const sampleCount = segments.reduce(
    (total, segment) => total + Math.round(sampleRateHz * segment.durationMs / 1000),
    0,
  );
  const buffer = Buffer.alloc(44 + sampleCount * 2);
  writeWavHeader(buffer, sampleCount, sampleRateHz);
  let sampleOffset = 0;
  for (const segment of segments) {
    const segmentSampleCount = Math.round(sampleRateHz * segment.durationMs / 1000);
    for (let index = 0; index < segmentSampleCount; index += 1) {
      const sample = segment.frequencyHz === null
        ? 0
        : Math.round(0.2 * 32767 * Math.sin(2 * Math.PI * segment.frequencyHz * index / sampleRateHz));
      buffer.writeInt16LE(sample, 44 + sampleOffset * 2);
      sampleOffset += 1;
    }
  }
  return buffer;
}

function writeWavHeader(buffer: Buffer, sampleCount: number, sampleRateHz: number): void {
  buffer.write('RIFF', 0, 'ascii');
  buffer.writeUInt32LE(36 + sampleCount * 2, 4);
  buffer.write('WAVE', 8, 'ascii');
  buffer.write('fmt ', 12, 'ascii');
  buffer.writeUInt32LE(16, 16);
  buffer.writeUInt16LE(1, 20);
  buffer.writeUInt16LE(1, 22);
  buffer.writeUInt32LE(sampleRateHz, 24);
  buffer.writeUInt32LE(sampleRateHz * 2, 28);
  buffer.writeUInt16LE(2, 32);
  buffer.writeUInt16LE(16, 34);
  buffer.write('data', 36, 'ascii');
  buffer.writeUInt32LE(sampleCount * 2, 40);
}

function builtEnrollmentTemplateResponse(requestId: string) {
  return {
    kind: 'built',
    requestId,
    encryptedTemplate: 'template_payload',
    templateVersion: 'python-placeholder-template-v1',
    modelVersion: 'python-placeholder-model-v1',
    thresholdVersion: 'python-placeholder-threshold-v1',
    quality: { kind: 'accepted', durationMs: 12000, signalScore: 0.9 },
    analysis: {
      analysisVersion: 'continuous-enrollment-v1',
      sourceCodec: 'pcm_s16le',
      sourceSampleRateHz: 16000,
      sourceChannelCount: 1,
      decodedDurationMs: 12000,
      usableSpeechMs: 10000,
      windows: [0, 1, 2, 3].map(enrollmentWindowResponse),
    },
  };
}

function enrollmentWindowResponse(index: number) {
  return {
    index,
    startMs: index * 3000,
    endMs: index * 3000 + 2500,
    speechMs: 2500,
    signalScore: 0.8,
    templateWeight: 0.25,
  };
}

type SpeakerKind = 'accepted' | 'rejected' | 'uncertain';

function speakerVerificationResponse(requestId: string, speakerKind: SpeakerKind, score?: number) {
  return {
    kind: 'speaker_verification',
    requestId,
    quality: { kind: 'accepted', durationMs: 1800, signalScore: 0.9 },
    speaker: speakerResponse(speakerKind, score),
  };
}

function speakerResponse(kind: SpeakerKind, score?: number) {
  const common = {
    score: score ?? (kind === 'accepted' ? 0.94 : kind === 'rejected' ? 0.3 : 0.78),
    threshold: 0.82,
    modelVersion: 'python-placeholder-model-v1',
    thresholdVersion: 'python-placeholder-threshold-v1',
  };
  switch (kind) {
    case 'accepted':
      return { kind: 'accepted', ...common };
    case 'rejected':
      return { kind: 'rejected', reason: 'speaker_mismatch', ...common };
    case 'uncertain':
      return { kind: 'uncertain', reason: 'model_low_confidence', ...common };
  }
}
