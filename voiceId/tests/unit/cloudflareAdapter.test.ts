import assert from 'node:assert/strict';
import test from 'node:test';
import {
  createVoiceIdCloudflareFetchHandler,
  parseVoiceIdCloudflareEnv,
} from '../../server/src/cloudflare.ts';
import type {
  VoiceIdCloudflareD1Database,
  VoiceIdCloudflareD1PreparedStatement,
  VoiceIdCloudflareSqlValue,
} from '../../server/src/store/CloudflareVoiceIdD1Stores.ts';
import type {
  VoiceIdCloudflareEnrollmentRow,
  VoiceIdCloudflareVerificationRow,
} from '../../server/src/store/CloudflareVoiceIdStorageRows.ts';
import { encodeBase64Bytes } from '../../server/src/verifier/PythonVoiceIdVerifier.ts';
import { nowIsoDateTime } from '../../shared/src/index.ts';

test('Cloudflare env parser requires HTTP verifier URL', () => {
  assert.deepEqual(
    parseVoiceIdCloudflareEnv({
      VOICEID_PYTHON_VERIFIER_URL: 'https://verifier.example/voice-id/verifier/',
      VOICEID_VERIFIER_TIMEOUT_MS: '2500',
    }),
    {
      verifier: {
        kind: 'python_http',
        baseUrl: 'https://verifier.example/voice-id/verifier/',
        timeoutMs: 2500,
      },
      speakerScoreThreshold: 0.6352,
      storage: { kind: 'memory' },
      transcript: { kind: 'fake' },
    },
  );

  assert.throws(
    () =>
      parseVoiceIdCloudflareEnv({
        VOICEID_PYTHON_VERIFIER_URL: 'ftp://verifier.example/voice-id/verifier/',
      }),
    /http or https/,
  );
});

test('Cloudflare env parser accepts D1 storage with template wrapping config', () => {
  assert.deepEqual(
    parseVoiceIdCloudflareEnv({
      VOICEID_PYTHON_VERIFIER_URL: 'https://verifier.example/voice-id/verifier/',
      VOICEID_STORAGE_KIND: 'cloudflare-d1',
      VOICEID_D1_DATABASE: new FakeVoiceIdD1Database(),
      VOICEID_TEMPLATE_KEY_SOURCE: 'cloudflare-workers-secret',
      VOICEID_TEMPLATE_KEY_ALGORITHM: 'AES-GCM-256',
      VOICEID_TEMPLATE_KEY_ID: 'voiceid-template-key-2026-06',
      VOICEID_TEMPLATE_KEY_SECRET_BINDING: 'VOICEID_TEMPLATE_ENCRYPTION_KEY',
      VOICEID_TEMPLATE_KEY_ROTATION_VERSION: 'rotation-1',
      VOICEID_TEMPLATE_KEY_AAD_LABEL: 'voiceid-template-v1',
      VOICEID_TEMPLATE_ENCRYPTION_KEY: templateEncryptionKey,
    }),
    {
      verifier: {
        kind: 'python_http',
        baseUrl: 'https://verifier.example/voice-id/verifier/',
        timeoutMs: 10_000,
      },
      speakerScoreThreshold: 0.6352,
      storage: {
        kind: 'cloudflare_d1',
        databaseBindingName: 'VOICEID_D1_DATABASE',
        templateKeyConfig: {
          kind: 'cloudflare_workers_secret',
          configVersion: 'voiceid-template-encryption-config-v1',
          algorithm: 'AES-GCM-256',
          keyId: 'voiceid-template-key-2026-06',
          secretBindingName: 'VOICEID_TEMPLATE_ENCRYPTION_KEY',
          rotationVersion: 'rotation-1',
          aadLabel: 'voiceid-template-v1',
        },
      },
      transcript: { kind: 'fake' },
    },
  );

  assert.throws(
    () =>
      parseVoiceIdCloudflareEnv({
        VOICEID_PYTHON_VERIFIER_URL: 'https://verifier.example/voice-id/verifier/',
        VOICEID_STORAGE_KIND: 'cloudflare-d1',
      }),
    /VOICEID_D1_DATABASE binding must be a D1 database/,
  );
});

test('Cloudflare env parser accepts Workers AI ASR transcript provider', () => {
  assert.deepEqual(
    parseVoiceIdCloudflareEnv({
      VOICEID_PYTHON_VERIFIER_URL: 'https://verifier.example/voice-id/verifier/',
      VOICEID_TRANSCRIPT_PROVIDER: 'cloudflare-workers-ai',
      AI: new FakeCloudflareAiBinding({ text: 'Walking on clouds' }),
    }),
    {
      verifier: {
        kind: 'python_http',
        baseUrl: 'https://verifier.example/voice-id/verifier/',
        timeoutMs: 10_000,
      },
      speakerScoreThreshold: 0.6352,
      storage: { kind: 'memory' },
      transcript: {
        kind: 'cloudflare_workers_ai',
        aiBindingName: 'AI',
        model: '@cf/openai/whisper',
      },
    },
  );

  assert.throws(
    () =>
      parseVoiceIdCloudflareEnv({
        VOICEID_PYTHON_VERIFIER_URL: 'https://verifier.example/voice-id/verifier/',
        VOICEID_TRANSCRIPT_PROVIDER: 'cloudflare-workers-ai',
      }),
    /AI binding/,
  );
});

test('Cloudflare env parser accepts speaker score threshold override', () => {
  assert.equal(
    parseVoiceIdCloudflareEnv({
      VOICEID_PYTHON_VERIFIER_URL: 'https://verifier.example/voice-id/verifier/',
      VOICEID_SPEAKER_SCORE_THRESHOLD: '0.7',
    }).speakerScoreThreshold,
    0.7,
  );
  assert.throws(
    () =>
      parseVoiceIdCloudflareEnv({
        VOICEID_PYTHON_VERIFIER_URL: 'https://verifier.example/voice-id/verifier/',
        VOICEID_SPEAKER_SCORE_THRESHOLD: 'not-a-threshold',
      }),
    /VOICEID_SPEAKER_SCORE_THRESHOLD/,
  );
});

test('portable base64 encoder does not require Node Buffer', () => {
  assert.equal(encodeBase64Bytes(new Uint8Array([])), '');
  assert.equal(encodeBase64Bytes(new Uint8Array([1])), 'AQ==');
  assert.equal(encodeBase64Bytes(new Uint8Array([1, 2])), 'AQI=');
  assert.equal(encodeBase64Bytes(new Uint8Array([1, 2, 3, 4])), 'AQIDBA==');
});

test('Cloudflare fetch handler completes a python-http verifier flow', async () => {
  const ai = new FakeCloudflareAiBinding({ text: 'Walking on clouds' });
  const handler = createVoiceIdCloudflareFetchHandler(
    {
      VOICEID_PYTHON_VERIFIER_URL: 'https://verifier.example/voice-id/verifier/',
      VOICEID_TRANSCRIPT_PROVIDER: 'cloudflare-workers-ai',
      AI: ai,
    },
    {
      verifierFetch: async (input, init) => {
        const request = JSON.parse(String(init?.body)) as { requestId: string };
        const url = String(input);
        if (url.endsWith('/extract-enrollment-embedding')) {
          return jsonResponse(enrollmentEmbeddingResponse(request.requestId));
        }
        if (url.endsWith('/build-template')) {
          return jsonResponse(builtTemplateResponse(request.requestId));
        }
        if (url.endsWith('/verify-speaker')) {
          assert.equal((request as { threshold?: number }).threshold, 0.6352);
          return jsonResponse(speakerVerificationResponse(request.requestId));
        }
        return new Response('not found', { status: 404 });
      },
      now: () => new Date('2026-06-13T00:00:00.000Z'),
    },
  );

  const enrollment = await readOkResponse<{ record: { enrollmentId: string } }>(
    await postJson(handler, '/voice-id/enrollment/start', {
      userId: 'owner',
      phrase: 'Walking on clouds',
    }),
  );

  for (let attemptNumber = 1; attemptNumber <= 3; attemptNumber += 1) {
    const sample = await readOkResponse<{ quality: { kind: string } }>(
      await postSample(handler, '/voice-id/enrollment/sample', {
        userId: 'owner',
        enrollmentId: enrollment.record.enrollmentId,
        expectedPhrase: 'Walking on clouds',
        spokenPhrase: 'Walking on clouds',
        attemptNumber,
      }),
    );
    assert.equal(sample.quality.kind, 'accepted');
  }

  const finalized = await readOkResponse<{ state: string }>(
    await postJson(handler, '/voice-id/enrollment/finalize', {
      userId: 'owner',
      enrollmentId: enrollment.record.enrollmentId,
    }),
  );
  assert.equal(finalized.state, 'enrolled');

  const verification = await readOkResponse<{ record: { verificationId: string } }>(
    await postJson(handler, '/voice-id/verification/start', {
      userId: 'owner',
      enrollmentId: enrollment.record.enrollmentId,
      phrase: 'Walking on clouds',
      ...testIntentBindingBody(),
    }),
  );

  const result = await readOkResponse<{ kind: string }>(
    await postSample(handler, '/voice-id/verification/sample', {
      userId: 'owner',
      enrollmentId: enrollment.record.enrollmentId,
      verificationId: verification.record.verificationId,
      expectedPhrase: 'Walking on clouds',
      spokenPhrase: 'Walking on clouds',
      attemptNumber: 1,
    }),
  );
  assert.equal(result.kind, 'accepted');
  assert.equal(ai.calls.length, 1);
  assert.deepEqual(ai.calls[0], {
    model: '@cf/openai/whisper',
    audio: [1, 2, 3, 4],
  });
});

test('Cloudflare fetch handler persists enrolled templates through D1 AES-GCM wrapping', async () => {
  const database = new FakeVoiceIdD1Database();
  let verifySpeakerTemplate: string | null = null;
  const handler = createVoiceIdCloudflareFetchHandler(
    {
      VOICEID_PYTHON_VERIFIER_URL: 'https://verifier.example/voice-id/verifier/',
      VOICEID_STORAGE_KIND: 'cloudflare-d1',
      VOICEID_D1_DATABASE: database,
      VOICEID_TEMPLATE_KEY_SOURCE: 'cloudflare-workers-secret',
      VOICEID_TEMPLATE_KEY_ALGORITHM: 'AES-GCM-256',
      VOICEID_TEMPLATE_KEY_ID: 'voiceid-template-key-2026-06',
      VOICEID_TEMPLATE_KEY_SECRET_BINDING: 'VOICEID_TEMPLATE_ENCRYPTION_KEY',
      VOICEID_TEMPLATE_KEY_ROTATION_VERSION: 'rotation-1',
      VOICEID_TEMPLATE_KEY_AAD_LABEL: 'voiceid-template-v1',
      VOICEID_TEMPLATE_ENCRYPTION_KEY: templateEncryptionKey,
    },
    {
      verifierFetch: async (input, init) => {
        const request = JSON.parse(String(init?.body)) as {
          requestId: string;
          template?: { encryptedTemplate: string };
        };
        const url = String(input);
        if (url.endsWith('/extract-enrollment-embedding')) {
          return jsonResponse(enrollmentEmbeddingResponse(request.requestId));
        }
        if (url.endsWith('/build-template')) {
          return jsonResponse(builtTemplateResponse(request.requestId));
        }
        if (url.endsWith('/verify-speaker')) {
          verifySpeakerTemplate = request.template?.encryptedTemplate ?? null;
          return jsonResponse(speakerVerificationResponse(request.requestId));
        }
        return new Response('not found', { status: 404 });
      },
      now: () => new Date('2026-06-13T00:00:00.000Z'),
    },
  );

  const enrollment = await readOkResponse<{ record: { enrollmentId: string } }>(
    await postJson(handler, '/voice-id/enrollment/start', {
      userId: 'owner',
      phrase: 'Walking on clouds',
    }),
  );

  for (let attemptNumber = 1; attemptNumber <= 3; attemptNumber += 1) {
    await readOkResponse<{ quality: { kind: string } }>(
      await postSample(handler, '/voice-id/enrollment/sample', {
        userId: 'owner',
        enrollmentId: enrollment.record.enrollmentId,
        expectedPhrase: 'Walking on clouds',
        spokenPhrase: 'Walking on clouds',
        attemptNumber,
      }),
    );
  }

  await readOkResponse<{ state: string }>(
    await postJson(handler, '/voice-id/enrollment/finalize', {
      userId: 'owner',
      enrollmentId: enrollment.record.enrollmentId,
    }),
  );

  const persisted = database.enrollments.get(enrollment.record.enrollmentId);
  assert.equal(persisted?.state, 'enrolled');
  assert.match(persisted.encryptedTemplate ?? '', /^voiceid-template-wrap-v1\./);
  assert.notEqual(persisted.encryptedTemplate, 'template_payload');

  const verification = await readOkResponse<{ record: { verificationId: string } }>(
    await postJson(handler, '/voice-id/verification/start', {
      userId: 'owner',
      enrollmentId: enrollment.record.enrollmentId,
      phrase: 'Walking on clouds',
      ...testIntentBindingBody(),
    }),
  );

  await readOkResponse<{ kind: string }>(
    await postSample(handler, '/voice-id/verification/sample', {
      userId: 'owner',
      enrollmentId: enrollment.record.enrollmentId,
      verificationId: verification.record.verificationId,
      expectedPhrase: 'Walking on clouds',
      spokenPhrase: 'Walking on clouds',
      attemptNumber: 1,
    }),
  );

  assert.equal(verifySpeakerTemplate, 'template_payload');
});

const templateEncryptionKey = 'AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=';

async function postJson(
  handler: ReturnType<typeof createVoiceIdCloudflareFetchHandler>,
  path: string,
  body: Record<string, unknown>,
): Promise<Response> {
  return await handler(
    new Request(`https://worker.example${path}`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
    }),
  );
}

async function postSample(
  handler: ReturnType<typeof createVoiceIdCloudflareFetchHandler>,
  path: string,
  fields: Record<string, unknown>,
): Promise<Response> {
  const bytes = new Uint8Array([1, 2, 3, 4]);
  const form = new FormData();
  form.set('audio', new Blob([bytes], { type: 'audio/webm' }));
  form.set('metadata', JSON.stringify(buildTestMetadata(bytes.byteLength)));
  form.set('fields', JSON.stringify(fields));
  return await handler(
    new Request(`https://worker.example${path}`, {
      method: 'POST',
      body: form,
    }),
  );
}

async function readOkResponse<TValue>(response: Response): Promise<TValue> {
  assert.equal(response.status, 200);
  const body = (await response.json()) as { kind: string; value: TValue };
  assert.equal(body.kind, 'ok');
  return body.value;
}

function buildTestMetadata(byteLength: number) {
  return {
    mimeType: 'audio/webm',
    durationMs: 1800,
    sampleRate: { kind: 'unknown' },
    channelCount: { kind: 'unknown' },
    byteLength,
    capturedAt: nowIsoDateTime(new Date('2026-06-13T00:00:00.000Z')),
    recorder: 'cloudflare-test',
    fixtureBehavior: { kind: 'speaker_label', speakerLabel: 'owner' },
  };
}

function jsonResponse(value: unknown): Response {
  return new Response(JSON.stringify(value), {
    headers: { 'Content-Type': 'application/json' },
  });
}

function enrollmentEmbeddingResponse(requestId: string) {
  return {
    kind: 'embedding',
    requestId,
    modelVersion: 'python-placeholder-model-v1',
    thresholdVersion: 'python-placeholder-threshold-v1',
    speakerLabel: 'owner',
    embedding: [0.1, 0.2, 0.3, 0.4],
    quality: { kind: 'accepted', durationMs: 1800, signalScore: 0.9 },
  };
}

function builtTemplateResponse(requestId: string) {
  return {
    kind: 'built',
    requestId,
    encryptedTemplate: 'template_payload',
    templateVersion: 'python-placeholder-template-v1',
    modelVersion: 'python-placeholder-model-v1',
    thresholdVersion: 'python-placeholder-threshold-v1',
    speakerLabel: 'owner',
  };
}

function speakerVerificationResponse(requestId: string) {
  return {
    kind: 'speaker_verification',
    requestId,
    quality: { kind: 'accepted', durationMs: 1800, signalScore: 0.9 },
    speaker: {
      kind: 'accepted',
      score: 0.94,
      threshold: 0.6352,
      modelVersion: 'python-placeholder-model-v1',
      thresholdVersion: 'python-placeholder-threshold-v1',
    },
  };
}

class FakeCloudflareAiBinding {
  readonly calls: Array<{ model: '@cf/openai/whisper'; audio: number[] }> = [];

  constructor(private readonly response: unknown) {}

  async run(model: '@cf/openai/whisper', input: { audio: number[] }): Promise<unknown> {
    this.calls.push({ model, audio: input.audio });
    return this.response;
  }
}

class FakeVoiceIdD1Database implements VoiceIdCloudflareD1Database {
  readonly enrollments = new Map<string, VoiceIdCloudflareEnrollmentRow>();
  readonly verifications = new Map<string, VoiceIdCloudflareVerificationRow>();

  prepare(query: string): VoiceIdCloudflareD1PreparedStatement {
    return new FakeVoiceIdD1PreparedStatement(this, query);
  }
}

class FakeVoiceIdD1PreparedStatement implements VoiceIdCloudflareD1PreparedStatement {
  private values: VoiceIdCloudflareSqlValue[] = [];

  constructor(
    private readonly database: FakeVoiceIdD1Database,
    private readonly query: string,
  ) {}

  bind(...values: VoiceIdCloudflareSqlValue[]): VoiceIdCloudflareD1PreparedStatement {
    this.values = values;
    return this;
  }

  async first<TRecord = Record<string, unknown>>(): Promise<TRecord | null> {
    if (this.query.includes('FROM voice_id_enrollments') && this.query.includes('WHERE enrollmentId = ?')) {
      return d1Row<TRecord>(this.database.enrollments.get(String(this.values[0])) ?? null);
    }
    if (this.query.includes('FROM voice_id_enrollments') && this.query.includes('WHERE userId = ?')) {
      const userId = String(this.values[0]);
      const rows = Array.from(this.database.enrollments.values())
        .filter((row) => row.userId === userId)
        .sort((left, right) => right.createdAt.localeCompare(left.createdAt));
      return d1Row<TRecord>(rows[0] ?? null);
    }
    if (this.query.includes('FROM voice_id_verifications') && this.query.includes('WHERE verificationId = ?')) {
      return d1Row<TRecord>(this.database.verifications.get(String(this.values[0])) ?? null);
    }

    throw new Error(`unsupported first query: ${this.query}`);
  }

  async run(): Promise<unknown> {
    if (this.query.includes('INSERT OR REPLACE INTO voice_id_enrollments')) {
      const row = enrollmentRowFromValues(this.values);
      this.database.enrollments.set(row.enrollmentId, row);
      return { success: true };
    }
    if (this.query.includes('INSERT OR REPLACE INTO voice_id_verifications')) {
      const row = verificationRowFromValues(this.values);
      this.database.verifications.set(row.verificationId, row);
      return { success: true };
    }

    throw new Error(`unsupported run query: ${this.query}`);
  }
}

function d1Row<TRecord>(row: VoiceIdCloudflareEnrollmentRow | VoiceIdCloudflareVerificationRow | null): TRecord | null {
  return row === null ? null : row as unknown as TRecord;
}

function enrollmentRowFromValues(values: readonly VoiceIdCloudflareSqlValue[]): VoiceIdCloudflareEnrollmentRow {
  return {
    schemaVersion: 1,
    recordKind: 'voice_id_enrollment',
    userId: requireString(values[2], 'userId'),
    enrollmentId: requireString(values[3], 'enrollmentId'),
    state: requireEnrollmentState(values[4]),
    promptSetId: requireString(values[5], 'promptSetId'),
    modelVersion: requireString(values[6], 'modelVersion'),
    createdAt: requireString(values[7], 'createdAt'),
    expiresAt: nullableString(values[8]),
    requiredSampleCount: nullableNumber(values[9]),
    acceptedSampleCount: nullableNumber(values[10]),
    attemptCount: nullableNumber(values[11]),
    templateVersion: nullableString(values[12]),
    thresholdVersion: nullableString(values[13]),
    encryptedTemplate: nullableString(values[14]),
    enrolledAt: nullableString(values[15]),
    disabledAt: nullableString(values[16]),
  };
}

function verificationRowFromValues(values: readonly VoiceIdCloudflareSqlValue[]): VoiceIdCloudflareVerificationRow {
  return {
    schemaVersion: 1,
    recordKind: 'voice_id_verification',
    userId: requireString(values[2], 'userId'),
    enrollmentId: requireString(values[3], 'enrollmentId'),
    verificationId: requireString(values[4], 'verificationId'),
    state: requireVerificationState(values[5]),
    expectedPhrase: requireString(values[6], 'expectedPhrase'),
    intentDigest: requireString(values[7], 'intentDigest'),
    intentExpiresAt: requireString(values[8], 'intentExpiresAt'),
    intentNonce: requireString(values[9], 'intentNonce'),
    createdAt: requireString(values[10], 'createdAt'),
    expiresAt: requireString(values[11], 'expiresAt'),
    attemptCount: nullableNumber(values[12]),
    completedAt: nullableString(values[13]),
    resultJson: nullableString(values[14]),
    ownerPresenceEvidenceKind: requireOwnerPresenceEvidenceKind(values[15]),
    ownerPresenceConsumedAt: nullableString(values[16]),
  };
}

function testIntentBindingBody(): Record<string, unknown> {
  return {
    intentDigest: 'A'.repeat(43),
    intentExpiresAt: '2099-01-01T00:00:00.000Z',
    intentNonce: 'nonce_123456',
  };
}

function requireString(value: VoiceIdCloudflareSqlValue | undefined, fieldName: string): string {
  if (typeof value !== 'string') {
    throw new Error(`${fieldName} must be a string`);
  }

  return value;
}

function nullableString(value: VoiceIdCloudflareSqlValue | undefined): string | null {
  return value === null ? null : requireString(value, 'nullable string');
}

function nullableNumber(value: VoiceIdCloudflareSqlValue | undefined): number | null {
  if (value === null) {
    return null;
  }
  if (typeof value !== 'number') {
    throw new Error('nullable number must be a number or null');
  }

  return value;
}

function requireEnrollmentState(value: VoiceIdCloudflareSqlValue | undefined): VoiceIdCloudflareEnrollmentRow['state'] {
  if (value === 'pending' || value === 'enrolled' || value === 'disabled') {
    return value;
  }

  throw new Error('enrollment state is invalid');
}

function requireVerificationState(value: VoiceIdCloudflareSqlValue | undefined): VoiceIdCloudflareVerificationRow['state'] {
  if (
    value === 'issued'
    || value === 'accepted'
    || value === 'rejected'
    || value === 'uncertain'
    || value === 'expired'
  ) {
    return value;
  }

  throw new Error('verification state is invalid');
}

function requireOwnerPresenceEvidenceKind(
  value: VoiceIdCloudflareSqlValue | undefined,
): VoiceIdCloudflareVerificationRow['ownerPresenceEvidenceKind'] {
  if (value === null || value === 'available' || value === 'consumed') {
    return value;
  }

  throw new Error('owner-presence evidence state is invalid');
}
