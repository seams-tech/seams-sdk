import assert from 'node:assert/strict';
import test from 'node:test';
import {
  CloudflareD1VoiceIdEnrollmentStore,
  CloudflareD1VoiceIdVerificationStore,
  voiceIdCloudflareD1SchemaStatements,
  type VoiceIdCloudflareD1Database,
  type VoiceIdCloudflareD1PreparedStatement,
  type VoiceIdCloudflareSqlValue,
} from '../../server/src/store/CloudflareVoiceIdD1Stores.ts';
import {
  parseEncryptedBytes,
  parseEnrollmentId,
  parseIsoDateTime,
  parseModelVersion,
  parsePromptPhrase,
  parsePromptSetId,
  parseTemplateVersion,
  parseThresholdVersion,
  parseUserId,
  parseVerificationId,
  parseVoiceIdIntentDigest,
  parseVoiceIdIntentNonce,
  type VoiceIdEnrollmentRecord,
  type VoiceIdVerificationRecord,
  type VoiceIdVerificationResult,
} from '../../shared/src/index.ts';
import type {
  VoiceIdCloudflareEnrollmentRow,
  VoiceIdCloudflareVerificationRow,
} from '../../server/src/store/CloudflareVoiceIdStorageRows.ts';

test('Cloudflare D1 schema statements create enrollment and verification tables', () => {
  const statements = voiceIdCloudflareD1SchemaStatements();

  assert.equal(statements.some((statement) => statement.includes('CREATE TABLE IF NOT EXISTS voice_id_enrollments')), true);
  assert.equal(statements.some((statement) => statement.includes('CREATE TABLE IF NOT EXISTS voice_id_verifications')), true);
  assert.equal(statements.some((statement) => statement.includes('voice_id_enrollments_user_created_idx')), true);
  assert.equal(statements.some((statement) => statement.includes('voice_id_verifications_enrollment_created_idx')), true);
});

test('Cloudflare D1 enrollment store saves and reads typed enrollment records', async () => {
  const database = new FakeVoiceIdD1Database();
  const store = new CloudflareD1VoiceIdEnrollmentStore(database);
  const pending = makePendingEnrollment();
  const enrolled = makeEnrolledEnrollment();

  await store.save(pending);
  assert.deepEqual(await store.getByEnrollmentId(pending.enrollmentId), pending);
  assert.deepEqual(await store.getByUserId(pending.userId), pending);

  await store.save(enrolled);
  assert.deepEqual(await store.getByEnrollmentId(enrolled.enrollmentId), enrolled);
  assert.deepEqual(await store.getByUserId(enrolled.userId), enrolled);
  assert.equal(database.enrollments.get(enrolled.enrollmentId)?.encryptedTemplate, 'ciphertext');
});

test('Cloudflare D1 verification store saves and reads typed verification records', async () => {
  const database = new FakeVoiceIdD1Database();
  const store = new CloudflareD1VoiceIdVerificationStore(database);
  const issued = makeIssuedVerification();
  const accepted = makeAcceptedVerification();

  await store.save(issued);
  assert.deepEqual(await store.getByVerificationId(issued.verificationId), issued);

  await store.save(accepted);
  assert.deepEqual(await store.getByVerificationId(accepted.verificationId), accepted);
  assert.equal(database.verifications.get(accepted.verificationId)?.attemptCount, null);
  assert.equal(typeof database.verifications.get(accepted.verificationId)?.resultJson, 'string');
});

test('Cloudflare D1 stores reject malformed persisted rows at read boundary', async () => {
  const database = new FakeVoiceIdD1Database();
  const store = new CloudflareD1VoiceIdVerificationStore(database);
  const issued = makeIssuedVerification();

  await store.save(issued);
  database.verifications.set(issued.verificationId, {
    ...database.verifications.get(issued.verificationId)!,
    rawAudioBytes: 'base64-audio',
  } as VoiceIdCloudflareVerificationRow);

  await assert.rejects(
    async () => await store.getByVerificationId(issued.verificationId),
    /must not contain raw capture column rawAudioBytes/,
  );
});

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

function makePendingEnrollment(): Extract<VoiceIdEnrollmentRecord, { state: 'pending' }> {
  return {
    state: 'pending',
    userId: parseUserId('owner'),
    enrollmentId: parseEnrollmentId('enroll_1'),
    promptSetId: parsePromptSetId('prompt-v1'),
    modelVersion: parseModelVersion('model-v1'),
    createdAt: parseIsoDateTime('2026-06-13T00:00:00.000Z'),
    expiresAt: parseIsoDateTime('2026-06-13T00:10:00.000Z'),
    requiredSampleCount: 3,
    acceptedSampleCount: 1,
    attemptCount: 2,
  };
}

function makeEnrolledEnrollment(): Extract<VoiceIdEnrollmentRecord, { state: 'enrolled' }> {
  return {
    state: 'enrolled',
    userId: parseUserId('owner'),
    enrollmentId: parseEnrollmentId('enroll_1'),
    promptSetId: parsePromptSetId('prompt-v1'),
    modelVersion: parseModelVersion('model-v1'),
    templateVersion: parseTemplateVersion('template-v1'),
    thresholdVersion: parseThresholdVersion('threshold-v1'),
    encryptedTemplate: parseEncryptedBytes('ciphertext'),
    createdAt: parseIsoDateTime('2026-06-13T00:00:00.000Z'),
    enrolledAt: parseIsoDateTime('2026-06-13T00:05:00.000Z'),
  };
}

function makeIssuedVerification(): Extract<VoiceIdVerificationRecord, { state: 'issued' }> {
  return {
    state: 'issued',
    userId: parseUserId('owner'),
    enrollmentId: parseEnrollmentId('enroll_1'),
    verificationId: parseVerificationId('verify_1'),
    expectedPhrase: parsePromptPhrase('Walking on clouds'),
    intentDigest: parseVoiceIdIntentDigest('A'.repeat(43)),
    intentExpiresAt: parseIsoDateTime('2026-06-13T00:07:00.000Z'),
    intentNonce: parseVoiceIdIntentNonce('nonce_123456'),
    createdAt: parseIsoDateTime('2026-06-13T00:06:00.000Z'),
    expiresAt: parseIsoDateTime('2026-06-13T00:07:00.000Z'),
    attemptCount: 0,
  };
}

function makeAcceptedVerification(): Extract<VoiceIdVerificationRecord, { state: 'accepted' }> {
  const result: VoiceIdVerificationResult = {
    kind: 'accepted',
    enrollmentId: parseEnrollmentId('enroll_1'),
    verificationId: parseVerificationId('verify_1'),
    templateVersion: parseTemplateVersion('template-v1'),
    modelVersion: parseModelVersion('model-v1'),
    thresholdVersion: parseThresholdVersion('threshold-v1'),
    checks: {
      phrase: {
        kind: 'accepted',
        expectedNormalized: 'walking on clouds',
        spokenNormalized: 'walking on clouds',
        confidence: 0.98,
      },
      speaker: {
        kind: 'accepted',
        score: 0.93,
        threshold: 0.82,
        modelVersion: parseModelVersion('model-v1'),
        thresholdVersion: parseThresholdVersion('threshold-v1'),
      },
      quality: {
        kind: 'accepted',
        durationMs: 1800,
        signalScore: 0.94,
      },
    },
  };

  return {
    state: 'accepted',
    userId: parseUserId('owner'),
    enrollmentId: parseEnrollmentId('enroll_1'),
    verificationId: parseVerificationId('verify_1'),
    expectedPhrase: parsePromptPhrase('Walking on clouds'),
    intentDigest: parseVoiceIdIntentDigest('A'.repeat(43)),
    intentExpiresAt: parseIsoDateTime('2026-06-13T00:07:00.000Z'),
    intentNonce: parseVoiceIdIntentNonce('nonce_123456'),
    createdAt: parseIsoDateTime('2026-06-13T00:06:00.000Z'),
    expiresAt: parseIsoDateTime('2026-06-13T00:07:00.000Z'),
    completedAt: parseIsoDateTime('2026-06-13T00:06:20.000Z'),
    result,
    ownerPresenceEvidence: { kind: 'available' },
  };
}
