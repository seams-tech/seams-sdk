import type {
  VoiceIdEnrollmentRecord,
  VoiceIdVerificationRecord,
} from '../../../shared/src/records.ts';
import type {
  UserId,
  VoiceIdEnrollmentId,
  VoiceIdVerificationId,
} from '../../../shared/src/ids.ts';
import { parseJsonObject } from '../../../shared/src/parsers.ts';
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

const enrollmentTable = 'voice_id_enrollments_v4';
const verificationTable = 'voice_id_verifications_v4';
const enrollmentColumns = ['schemaVersion', 'recordKind', 'userId', 'enrollmentId', 'lifecycleState', 'createdAt', 'recordJson'] as const;
const verificationColumns = ['schemaVersion', 'recordKind', 'userId', 'enrollmentId', 'verificationId', 'lifecycleState', 'createdAt', 'recordJson'] as const;

export function voiceIdCloudflareD1SchemaStatements(): readonly string[] {
  return [
    `CREATE TABLE IF NOT EXISTS ${enrollmentTable} (
      schemaVersion INTEGER NOT NULL,
      recordKind TEXT NOT NULL,
      userId TEXT NOT NULL,
      enrollmentId TEXT PRIMARY KEY,
      lifecycleState TEXT NOT NULL,
      createdAt TEXT NOT NULL,
      recordJson TEXT NOT NULL
    )`,
    `CREATE INDEX IF NOT EXISTS voice_id_enrollments_v4_user_created_idx
      ON ${enrollmentTable} (userId, createdAt DESC)`,
    `CREATE TABLE IF NOT EXISTS ${verificationTable} (
      schemaVersion INTEGER NOT NULL,
      recordKind TEXT NOT NULL,
      userId TEXT NOT NULL,
      enrollmentId TEXT NOT NULL,
      verificationId TEXT PRIMARY KEY,
      lifecycleState TEXT NOT NULL,
      createdAt TEXT NOT NULL,
      recordJson TEXT NOT NULL
    )`,
    `CREATE INDEX IF NOT EXISTS voice_id_verifications_v4_enrollment_created_idx
      ON ${verificationTable} (enrollmentId, createdAt DESC)`,
  ];
}

export class CloudflareD1VoiceIdEnrollmentStore implements VoiceIdEnrollmentStore {
  constructor(private readonly database: VoiceIdCloudflareD1Database) {}

  async getByUserId(userId: UserId): Promise<VoiceIdEnrollmentRecord | null> {
    const row = await this.database.prepare(
      `SELECT ${enrollmentColumns.join(', ')} FROM ${enrollmentTable}
       WHERE userId = ? ORDER BY createdAt DESC LIMIT 1`,
    ).bind(userId).first<VoiceIdCloudflareEnrollmentRow>();
    return row === null ? null : parseCloudflareEnrollmentRow(row);
  }

  async getByEnrollmentId(enrollmentId: VoiceIdEnrollmentId): Promise<VoiceIdEnrollmentRecord | null> {
    const row = await this.database.prepare(
      `SELECT ${enrollmentColumns.join(', ')} FROM ${enrollmentTable}
       WHERE enrollmentId = ? LIMIT 1`,
    ).bind(enrollmentId).first<VoiceIdCloudflareEnrollmentRow>();
    return row === null ? null : parseCloudflareEnrollmentRow(row);
  }

  async create(
    record: Extract<VoiceIdEnrollmentRecord, { state: 'pending_continuous_recording' }>,
  ): Promise<boolean> {
    const row = serializeEnrollmentRecordForCloudflare(record);
    const result = await this.database.prepare(
      `INSERT OR IGNORE INTO ${enrollmentTable} (${enrollmentColumns.join(', ')})
       VALUES (${placeholders(enrollmentColumns.length)})`,
    ).bind(
      row.schemaVersion,
      row.recordKind,
      row.userId,
      row.enrollmentId,
      row.lifecycleState,
      row.createdAt,
      row.recordJson,
    ).run();
    return parseMutationChanged(result);
  }

  async claimPending(
    record: Extract<VoiceIdEnrollmentRecord, { state: 'analyzing_continuous_recording' }>,
  ): Promise<boolean> {
    return await this.transition(record, 'pending_continuous_recording');
  }

  async failPending(
    record: Extract<VoiceIdEnrollmentRecord, { state: 'failed' }>,
  ): Promise<boolean> {
    return await this.transition(record, 'pending_continuous_recording');
  }

  async completeAnalysis(
    record: Extract<VoiceIdEnrollmentRecord, { state: 'failed' | 'enrolled' }>,
  ): Promise<boolean> {
    return await this.transition(record, 'analyzing_continuous_recording');
  }

  async disable(
    record: Extract<VoiceIdEnrollmentRecord, { state: 'disabled' }>,
  ): Promise<boolean> {
    return await this.transition(record, 'enrolled');
  }

  private async transition(
    record: Exclude<VoiceIdEnrollmentRecord, { state: 'pending_continuous_recording' }>,
    expectedState: 'pending_continuous_recording' | 'analyzing_continuous_recording' | 'enrolled',
  ): Promise<boolean> {
    const row = serializeEnrollmentRecordForCloudflare(record);
    const result = await this.database.prepare(
      `UPDATE ${enrollmentTable}
       SET lifecycleState = ?, recordJson = ?
       WHERE enrollmentId = ? AND userId = ? AND lifecycleState = ?`,
    ).bind(
      row.lifecycleState,
      row.recordJson,
      row.enrollmentId,
      row.userId,
      expectedState,
    ).run();
    return parseMutationChanged(result);
  }
}

export class CloudflareD1VoiceIdVerificationStore implements VoiceIdVerificationStore {
  constructor(private readonly database: VoiceIdCloudflareD1Database) {}

  async getByVerificationId(verificationId: VoiceIdVerificationId): Promise<VoiceIdVerificationRecord | null> {
    const row = await this.database.prepare(
      `SELECT ${verificationColumns.join(', ')} FROM ${verificationTable}
       WHERE verificationId = ? LIMIT 1`,
    ).bind(verificationId).first<VoiceIdCloudflareVerificationRow>();
    return row === null ? null : parseCloudflareVerificationRow(row);
  }

  async create(
    record: Extract<VoiceIdVerificationRecord, { state: 'issued' }>,
  ): Promise<boolean> {
    const row = serializeVerificationRecordForCloudflare(record);
    const result = await this.database.prepare(
      `INSERT OR IGNORE INTO ${verificationTable} (${verificationColumns.join(', ')})
       VALUES (${placeholders(verificationColumns.length)})`,
    ).bind(
      row.schemaVersion,
      row.recordKind,
      row.userId,
      row.enrollmentId,
      row.verificationId,
      row.lifecycleState,
      row.createdAt,
      row.recordJson,
    ).run();
    return parseMutationChanged(result);
  }

  async claimIssued(
    record: Extract<VoiceIdVerificationRecord, { state: 'analyzing' }>,
  ): Promise<boolean> {
    return await this.transition(record, 'issued');
  }

  async expireIssued(
    record: Extract<VoiceIdVerificationRecord, { state: 'expired' }>,
  ): Promise<boolean> {
    return await this.transition(record, 'issued');
  }

  async completeAnalysis(
    record: Extract<VoiceIdVerificationRecord, { state: 'evidence_observed' | 'rejected' | 'uncertain' | 'analysis_failed' }>,
  ): Promise<boolean> {
    return await this.transition(record, 'analyzing');
  }

  private async transition(
    record: Exclude<VoiceIdVerificationRecord, { state: 'issued' }>,
    expectedState: 'issued' | 'analyzing',
  ): Promise<boolean> {
    const row = serializeVerificationRecordForCloudflare(record);
    const result = await this.database.prepare(
      `UPDATE ${verificationTable}
       SET lifecycleState = ?, recordJson = ?
       WHERE verificationId = ? AND userId = ? AND enrollmentId = ? AND lifecycleState = ?`,
    ).bind(
      row.lifecycleState,
      row.recordJson,
      row.verificationId,
      row.userId,
      row.enrollmentId,
      expectedState,
    ).run();
    return parseMutationChanged(result);
  }
}

function placeholders(count: number): string {
  return Array.from({ length: count }, questionMark).join(', ');
}

function questionMark(): string {
  return '?';
}

function parseMutationChanged(value: unknown): boolean {
  const result = parseJsonObject(value, 'D1 mutation result');
  const meta = parseJsonObject(result.meta, 'D1 mutation metadata');
  if (
    typeof meta.changes !== 'number'
    || !Number.isSafeInteger(meta.changes)
    || meta.changes < 0
    || meta.changes > 1
  ) {
    throw new Error('D1 mutation changes must be zero or one');
  }
  return meta.changes === 1;
}
