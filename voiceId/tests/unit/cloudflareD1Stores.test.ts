import assert from 'node:assert/strict';
import test from 'node:test';
import {
  nowIsoDateTime,
  parseEnrollmentId,
  parseModelVersion,
  parsePromptPhrase,
  parsePromptSetId,
  parseUserId,
  parseVerificationId,
  parseVoiceIdChallengeNonce,
  type VoiceIdEnrollmentRecord,
  type VoiceIdVerificationRecord,
} from '../../shared/src/index.ts';
import {
  CloudflareD1VoiceIdEnrollmentStore,
  CloudflareD1VoiceIdVerificationStore,
  voiceIdCloudflareD1SchemaStatements,
  type VoiceIdCloudflareD1Database,
  type VoiceIdCloudflareD1PreparedStatement,
  type VoiceIdCloudflareEnrollmentRow,
  type VoiceIdCloudflareSqlValue,
  type VoiceIdCloudflareVerificationRow,
} from '../../server/src/index.ts';

test('D1 schema contains the analysis-claim v4 persistence tables', () => {
  const schema = voiceIdCloudflareD1SchemaStatements().join('\n');
  assert.match(schema, /voice_id_enrollments_v4/);
  assert.match(schema, /voice_id_verifications_v4/);
});

test('D1 enrollment store persists continuous enrollment state', async () => {
  const database = new FakeD1Database();
  const store = new CloudflareD1VoiceIdEnrollmentStore(database);
  const record = pendingEnrollment();
  assert.equal(await store.create(record), true);
  assert.equal(await store.create(record), false);
  assert.deepEqual(await store.getByEnrollmentId(record.enrollmentId), record);
  assert.deepEqual(await store.getByUserId(record.userId), record);

  const analysis = analyzingEnrollment(record);
  assert.equal(await store.claimPending(analysis), true);
  assert.equal(await store.claimPending(analysis), false);

  const failed: Extract<VoiceIdEnrollmentRecord, { state: 'failed' }> = {
    state: 'failed',
    userId: record.userId,
    enrollmentId: record.enrollmentId,
    promptSetId: record.promptSetId,
    modelVersion: record.modelVersion,
    createdAt: record.createdAt,
    failedAt: record.createdAt,
    failureReason: 'capture_too_short',
  };
  assert.equal(await store.completeAnalysis(failed), true);
  assert.equal(await store.completeAnalysis(failed), false);
  assert.deepEqual(await store.getByEnrollmentId(record.enrollmentId), failed);
});

test('D1 verification store commits one terminal transition', async () => {
  const database = new FakeD1Database();
  const store = new CloudflareD1VoiceIdVerificationStore(database);
  const record = issuedVerification();
  assert.equal(await store.create(record), true);
  assert.equal(await store.create(record), false);
  assert.deepEqual(await store.getByVerificationId(record.verificationId), record);

  const analysis = analyzingVerification(record);
  assert.equal(await store.claimIssued(analysis), true);
  assert.equal(await store.claimIssued(analysis), false);

  const failed: Extract<VoiceIdVerificationRecord, { state: 'analysis_failed' }> = {
    state: 'analysis_failed',
    userId: record.userId,
    enrollmentId: record.enrollmentId,
    verificationId: record.verificationId,
    expectedPhrase: record.expectedPhrase,
    challengeNonce: record.challengeNonce,
    createdAt: record.createdAt,
    expiresAt: record.expiresAt,
    analysisStartedAt: analysis.analysisStartedAt,
    analysisExpiresAt: analysis.analysisExpiresAt,
    completedAt: analysis.analysisExpiresAt,
    failureReason: 'analysis_timeout',
  };
  assert.equal(await store.completeAnalysis(failed), true);
  assert.equal(await store.completeAnalysis(failed), false);
  assert.deepEqual(await store.getByVerificationId(record.verificationId), failed);
});

class FakeD1Database implements VoiceIdCloudflareD1Database {
  readonly enrollmentRows = new Map<string, VoiceIdCloudflareEnrollmentRow>();
  readonly verificationRows = new Map<string, VoiceIdCloudflareVerificationRow>();

  prepare(query: string): VoiceIdCloudflareD1PreparedStatement {
    return new FakeD1Statement(this, query);
  }
}

class FakeD1Statement implements VoiceIdCloudflareD1PreparedStatement {
  private values: VoiceIdCloudflareSqlValue[] = [];

  constructor(
    private readonly database: FakeD1Database,
    private readonly query: string,
  ) {}

  bind(...values: VoiceIdCloudflareSqlValue[]): VoiceIdCloudflareD1PreparedStatement {
    this.values = values;
    return this;
  }

  async first<TRecord = Record<string, unknown>>(): Promise<TRecord | null> {
    const key = String(this.values[0]);
    if (this.query.includes('voice_id_verifications_v4')) {
      const row = this.database.verificationRows.get(key);
      return row === undefined ? null : row as TRecord;
    }
    const row = this.query.includes('WHERE userId')
      ? [...this.database.enrollmentRows.values()].find((candidate) => candidate.userId === key)
      : this.database.enrollmentRows.get(key);
    return row === undefined ? null : row as TRecord;
  }

  async run(): Promise<unknown> {
    if (this.query.includes('INSERT OR IGNORE INTO voice_id_verifications_v4')) {
      const row: VoiceIdCloudflareVerificationRow = {
        schemaVersion: Number(this.values[0]),
        recordKind: requireVerificationKind(this.values[1]),
        userId: String(this.values[2]),
        enrollmentId: String(this.values[3]),
        verificationId: String(this.values[4]),
        lifecycleState: requireVerificationState(this.values[5]),
        createdAt: String(this.values[6]),
        recordJson: String(this.values[7]),
      };
      if (this.database.verificationRows.has(row.verificationId)) return mutationResult(0);
      this.database.verificationRows.set(row.verificationId, row);
      return mutationResult(1);
    }
    if (this.query.includes('UPDATE voice_id_verifications_v4')) {
      const verificationId = String(this.values[2]);
      const current = this.database.verificationRows.get(verificationId);
      if (
        current === undefined
        || current.userId !== String(this.values[3])
        || current.enrollmentId !== String(this.values[4])
        || current.lifecycleState !== String(this.values[5])
      ) return mutationResult(0);
      this.database.verificationRows.set(verificationId, {
        schemaVersion: current.schemaVersion,
        recordKind: current.recordKind,
        userId: current.userId,
        enrollmentId: current.enrollmentId,
        verificationId: current.verificationId,
        lifecycleState: requireVerificationState(this.values[0]),
        createdAt: current.createdAt,
        recordJson: String(this.values[1]),
      });
      return mutationResult(1);
    }
    if (this.query.includes('INSERT OR IGNORE')) {
      const row: VoiceIdCloudflareEnrollmentRow = {
        schemaVersion: Number(this.values[0]),
        recordKind: requireEnrollmentKind(this.values[1]),
        userId: String(this.values[2]),
        enrollmentId: String(this.values[3]),
        lifecycleState: requireEnrollmentState(this.values[4]),
        createdAt: String(this.values[5]),
        recordJson: String(this.values[6]),
      };
      if (this.database.enrollmentRows.has(row.enrollmentId)) return mutationResult(0);
      this.database.enrollmentRows.set(row.enrollmentId, row);
      return mutationResult(1);
    }
    if (this.query.includes('UPDATE voice_id_enrollments_v4')) {
      const enrollmentId = String(this.values[2]);
      const current = this.database.enrollmentRows.get(enrollmentId);
      if (
        current === undefined
        || current.userId !== String(this.values[3])
        || current.lifecycleState !== String(this.values[4])
      ) return mutationResult(0);
      this.database.enrollmentRows.set(enrollmentId, {
        schemaVersion: current.schemaVersion,
        recordKind: current.recordKind,
        userId: current.userId,
        enrollmentId: current.enrollmentId,
        lifecycleState: requireEnrollmentState(this.values[0]),
        createdAt: current.createdAt,
        recordJson: String(this.values[1]),
      });
      return mutationResult(1);
    }
    throw new Error(`unexpected D1 mutation: ${this.query}`);
  }
}

function pendingEnrollment(): Extract<VoiceIdEnrollmentRecord, { state: 'pending_continuous_recording' }> {
  const now = nowIsoDateTime(new Date('2026-07-13T00:00:00.000Z'));
  return {
    state: 'pending_continuous_recording',
    userId: parseUserId('owner'),
    enrollmentId: parseEnrollmentId('enrollment_1'),
    promptSetId: parsePromptSetId('prompt_set_1'),
    promptSequence: [
      parsePromptPhrase('Copper river carries morning light'),
      parsePromptPhrase('Seven quiet lanterns cross the harbor'),
      parsePromptPhrase('Bright cedar branches move in winter'),
      parsePromptPhrase('A silver compass points toward home'),
    ],
    modelVersion: parseModelVersion('model_1'),
    createdAt: now,
    expiresAt: now,
    minimumCaptureMs: 12_000,
    targetCaptureMs: 18_000,
    maximumCaptureMs: 30_000,
  };
}

function issuedVerification(): Extract<VoiceIdVerificationRecord, { state: 'issued' }> {
  const now = nowIsoDateTime(new Date('2026-07-13T00:00:00.000Z'));
  return {
    state: 'issued',
    userId: parseUserId('owner'),
    enrollmentId: parseEnrollmentId('enrollment_1'),
    verificationId: parseVerificationId('verification_1'),
    expectedPhrase: parsePromptPhrase('River lantern a b c d e f'),
    challengeNonce: parseVoiceIdChallengeNonce('challenge_nonce_abcdef'),
    createdAt: now,
    expiresAt: now,
  };
}

function analyzingEnrollment(
  record: Extract<VoiceIdEnrollmentRecord, { state: 'pending_continuous_recording' }>,
): Extract<VoiceIdEnrollmentRecord, { state: 'analyzing_continuous_recording' }> {
  return {
    state: 'analyzing_continuous_recording',
    userId: record.userId,
    enrollmentId: record.enrollmentId,
    promptSetId: record.promptSetId,
    promptSequence: record.promptSequence,
    modelVersion: record.modelVersion,
    createdAt: record.createdAt,
    expiresAt: record.expiresAt,
    minimumCaptureMs: record.minimumCaptureMs,
    targetCaptureMs: record.targetCaptureMs,
    maximumCaptureMs: record.maximumCaptureMs,
    analysisStartedAt: record.createdAt,
    analysisExpiresAt: record.expiresAt,
  };
}

function analyzingVerification(
  record: Extract<VoiceIdVerificationRecord, { state: 'issued' }>,
): Extract<VoiceIdVerificationRecord, { state: 'analyzing' }> {
  return {
    state: 'analyzing',
    userId: record.userId,
    enrollmentId: record.enrollmentId,
    verificationId: record.verificationId,
    expectedPhrase: record.expectedPhrase,
    challengeNonce: record.challengeNonce,
    createdAt: record.createdAt,
    expiresAt: record.expiresAt,
    analysisStartedAt: record.createdAt,
    analysisExpiresAt: record.expiresAt,
  };
}

function requireEnrollmentKind(value: VoiceIdCloudflareSqlValue): 'enrollment' {
  assert.equal(value, 'enrollment');
  return 'enrollment';
}

function requireVerificationKind(value: VoiceIdCloudflareSqlValue): 'verification' {
  assert.equal(value, 'verification');
  return 'verification';
}

function requireEnrollmentState(
  value: VoiceIdCloudflareSqlValue,
): VoiceIdEnrollmentRecord['state'] {
  if (
    value !== 'pending_continuous_recording'
    && value !== 'analyzing_continuous_recording'
    && value !== 'failed'
    && value !== 'enrolled'
    && value !== 'disabled'
  ) throw new Error('invalid enrollment state');
  return value;
}

function requireVerificationState(
  value: VoiceIdCloudflareSqlValue,
): VoiceIdVerificationRecord['state'] {
  if (
    value !== 'issued'
    && value !== 'analyzing'
    && value !== 'evidence_observed'
    && value !== 'rejected'
    && value !== 'uncertain'
    && value !== 'expired'
    && value !== 'analysis_failed'
  ) throw new Error('invalid verification state');
  return value;
}

function mutationResult(changes: number): unknown {
  return { success: true, meta: { changes } };
}
