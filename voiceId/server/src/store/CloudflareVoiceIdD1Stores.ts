import type {
  VoiceIdEnrollmentRecord,
  VoiceIdVerificationRecord,
} from '../../../shared/src/records.ts';
import type {
  UserId,
  VoiceIdEnrollmentId,
  VoiceIdVerificationId,
} from '../../../shared/src/ids.ts';
import {
  parseCloudflareEnrollmentRow,
  parseCloudflareVerificationRow,
  serializeEnrollmentRecordForCloudflare,
  serializeVerificationRecordForCloudflare,
  type VoiceIdCloudflareEnrollmentRow,
  type VoiceIdCloudflareVerificationRow,
} from './CloudflareVoiceIdStorageRows.ts';
import type { VoiceIdEnrollmentStore, VoiceIdVerificationStore } from './VoiceIdStores.ts';

export type VoiceIdCloudflareSqlValue = string | number | null;

export type VoiceIdCloudflareD1PreparedStatement = {
  bind(...values: VoiceIdCloudflareSqlValue[]): VoiceIdCloudflareD1PreparedStatement;
  first<TRecord = Record<string, unknown>>(): Promise<TRecord | null>;
  run(): Promise<unknown>;
};

export type VoiceIdCloudflareD1Database = {
  prepare(query: string): VoiceIdCloudflareD1PreparedStatement;
};

const enrollmentTable = 'voice_id_enrollments';
const verificationTable = 'voice_id_verifications';

const enrollmentColumns = [
  'schemaVersion',
  'recordKind',
  'userId',
  'enrollmentId',
  'state',
  'promptSetId',
  'modelVersion',
  'createdAt',
  'expiresAt',
  'requiredSampleCount',
  'acceptedSampleCount',
  'attemptCount',
  'templateVersion',
  'thresholdVersion',
  'encryptedTemplate',
  'enrolledAt',
  'disabledAt',
] as const;

const verificationColumns = [
  'schemaVersion',
  'recordKind',
  'userId',
  'enrollmentId',
  'verificationId',
  'state',
  'expectedPhrase',
  'intentDigest',
  'intentExpiresAt',
  'intentNonce',
  'createdAt',
  'expiresAt',
  'attemptCount',
  'completedAt',
  'resultJson',
  'ownerPresenceEvidenceKind',
  'ownerPresenceConsumedAt',
] as const;

export function voiceIdCloudflareD1SchemaStatements(): readonly string[] {
  return [
    `CREATE TABLE IF NOT EXISTS ${enrollmentTable} (
      schemaVersion INTEGER NOT NULL,
      recordKind TEXT NOT NULL,
      userId TEXT NOT NULL,
      enrollmentId TEXT PRIMARY KEY,
      state TEXT NOT NULL,
      promptSetId TEXT NOT NULL,
      modelVersion TEXT NOT NULL,
      createdAt TEXT NOT NULL,
      expiresAt TEXT,
      requiredSampleCount INTEGER,
      acceptedSampleCount INTEGER,
      attemptCount INTEGER,
      templateVersion TEXT,
      thresholdVersion TEXT,
      encryptedTemplate TEXT,
      enrolledAt TEXT,
      disabledAt TEXT
    )`,
    `CREATE INDEX IF NOT EXISTS voice_id_enrollments_user_created_idx
      ON ${enrollmentTable} (userId, createdAt DESC)`,
    `CREATE TABLE IF NOT EXISTS ${verificationTable} (
      schemaVersion INTEGER NOT NULL,
      recordKind TEXT NOT NULL,
      userId TEXT NOT NULL,
      enrollmentId TEXT NOT NULL,
      verificationId TEXT PRIMARY KEY,
      state TEXT NOT NULL,
      expectedPhrase TEXT NOT NULL,
      intentDigest TEXT NOT NULL,
      intentExpiresAt TEXT NOT NULL,
      intentNonce TEXT NOT NULL,
      createdAt TEXT NOT NULL,
      expiresAt TEXT NOT NULL,
      attemptCount INTEGER,
      completedAt TEXT,
      resultJson TEXT,
      ownerPresenceEvidenceKind TEXT,
      ownerPresenceConsumedAt TEXT
    )`,
    `CREATE INDEX IF NOT EXISTS voice_id_verifications_enrollment_created_idx
      ON ${verificationTable} (enrollmentId, createdAt DESC)`,
  ];
}

export class CloudflareD1VoiceIdEnrollmentStore implements VoiceIdEnrollmentStore {
  constructor(private readonly database: VoiceIdCloudflareD1Database) {}

  async getByUserId(userId: UserId): Promise<VoiceIdEnrollmentRecord | null> {
    const row = await this.database
      .prepare(
        `SELECT ${enrollmentColumns.join(', ')}
          FROM ${enrollmentTable}
          WHERE userId = ?
          ORDER BY createdAt DESC
          LIMIT 1`,
      )
      .bind(userId)
      .first<VoiceIdCloudflareEnrollmentRow>();

    return row === null ? null : parseCloudflareEnrollmentRow(row);
  }

  async getByEnrollmentId(enrollmentId: VoiceIdEnrollmentId): Promise<VoiceIdEnrollmentRecord | null> {
    const row = await this.database
      .prepare(
        `SELECT ${enrollmentColumns.join(', ')}
          FROM ${enrollmentTable}
          WHERE enrollmentId = ?
          LIMIT 1`,
      )
      .bind(enrollmentId)
      .first<VoiceIdCloudflareEnrollmentRow>();

    return row === null ? null : parseCloudflareEnrollmentRow(row);
  }

  async save(record: VoiceIdEnrollmentRecord): Promise<void> {
    const row = serializeEnrollmentRecordForCloudflare(record);
    await this.database
      .prepare(
        `INSERT OR REPLACE INTO ${enrollmentTable} (${enrollmentColumns.join(', ')})
          VALUES (${placeholders(enrollmentColumns.length)})`,
      )
      .bind(...enrollmentRowValues(row))
      .run();
  }
}

export class CloudflareD1VoiceIdVerificationStore implements VoiceIdVerificationStore {
  constructor(private readonly database: VoiceIdCloudflareD1Database) {}

  async getByVerificationId(verificationId: VoiceIdVerificationId): Promise<VoiceIdVerificationRecord | null> {
    const row = await this.database
      .prepare(
        `SELECT ${verificationColumns.join(', ')}
          FROM ${verificationTable}
          WHERE verificationId = ?
          LIMIT 1`,
      )
      .bind(verificationId)
      .first<VoiceIdCloudflareVerificationRow>();

    return row === null ? null : parseCloudflareVerificationRow(row);
  }

  async save(record: VoiceIdVerificationRecord): Promise<void> {
    const row = serializeVerificationRecordForCloudflare(record);
    await this.database
      .prepare(
        `INSERT OR REPLACE INTO ${verificationTable} (${verificationColumns.join(', ')})
          VALUES (${placeholders(verificationColumns.length)})`,
      )
      .bind(...verificationRowValues(row))
      .run();
  }
}

function placeholders(count: number): string {
  return Array.from({ length: count }, () => '?').join(', ');
}

function enrollmentRowValues(row: VoiceIdCloudflareEnrollmentRow): VoiceIdCloudflareSqlValue[] {
  return [
    row.schemaVersion,
    row.recordKind,
    row.userId,
    row.enrollmentId,
    row.state,
    row.promptSetId,
    row.modelVersion,
    row.createdAt,
    row.expiresAt,
    row.requiredSampleCount,
    row.acceptedSampleCount,
    row.attemptCount,
    row.templateVersion,
    row.thresholdVersion,
    row.encryptedTemplate,
    row.enrolledAt,
    row.disabledAt,
  ];
}

function verificationRowValues(row: VoiceIdCloudflareVerificationRow): VoiceIdCloudflareSqlValue[] {
  return [
    row.schemaVersion,
    row.recordKind,
    row.userId,
    row.enrollmentId,
    row.verificationId,
    row.state,
    row.expectedPhrase,
    row.intentDigest,
    row.intentExpiresAt,
    row.intentNonce,
    row.createdAt,
    row.expiresAt,
    row.attemptCount,
    row.completedAt,
    row.resultJson,
    row.ownerPresenceEvidenceKind,
    row.ownerPresenceConsumedAt,
  ];
}
