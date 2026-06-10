import { buildEmailOtpRecoveryCodeSet, type EmailOtpRecoveryCodeSet } from '@shared/utils/emailOtpRecoveryKey';
import { normalizeInteger, normalizeOptionalNonEmptyString } from '@shared/utils/normalize';
import {
  SEAMS_WALLET_DB_NAME,
  SEAMS_WALLET_DB_VERSION,
  SEAMS_WALLET_INDEXES,
  SEAMS_WALLET_STORES,
} from '../schemaNames';
import { seamsWalletDB } from '../singletons';
import type { SeamsWalletDBManager } from './manager';

export const EMAIL_OTP_RECOVERY_CODE_BACKUP_RECORD_VERSION = 1 as const;
export const EMAIL_OTP_RECOVERY_CODE_BACKUP_DB_NAME = SEAMS_WALLET_DB_NAME;
export const EMAIL_OTP_RECOVERY_CODE_BACKUP_DB_VERSION = SEAMS_WALLET_DB_VERSION;
export const EMAIL_OTP_RECOVERY_CODE_BACKUP_STORE_NAME =
  SEAMS_WALLET_STORES.emailOtpRecoveryCodeBackups;
export const EMAIL_OTP_RECOVERY_CODE_BACKUP_SECRET_KIND =
  'email_otp_recovery_codes_backup' as const;
const EMAIL_OTP_RECOVERY_CODE_BACKUP_PAYLOAD_FIELD = 'backup_record';

export type EmailOtpRecoveryCodeBackupStorageScope =
  | 'host_origin_indexeddb'
  | 'iframe_origin_indexeddb';

export type StoredEmailOtpRecoveryCodeBackupRecord = {
  v: typeof EMAIL_OTP_RECOVERY_CODE_BACKUP_RECORD_VERSION;
  secretKind: typeof EMAIL_OTP_RECOVERY_CODE_BACKUP_SECRET_KIND;
  storageScope: EmailOtpRecoveryCodeBackupStorageScope;
  status: 'stored';
  walletId: string;
  enrollmentId: string;
  enrollmentSealKeyVersion: string;
  recoveryCodesIssuedAtMs: number;
  recoveryKeys: EmailOtpRecoveryCodeSet;
  createdAtMs: number;
  lastDisplayedAtMs: number | null;
  lastDownloadedAtMs: number | null;
};

export type WriteEmailOtpRecoveryCodeBackupInput = Omit<
  StoredEmailOtpRecoveryCodeBackupRecord,
  | 'v'
  | 'secretKind'
  | 'status'
  | 'createdAtMs'
  | 'lastDisplayedAtMs'
  | 'lastDownloadedAtMs'
> & {
  createdAtMs?: number;
  lastDisplayedAtMs?: number | null;
  lastDownloadedAtMs?: number | null;
};

function isRecord(value: unknown): value is Record<string, unknown> {
  return !!value && typeof value === 'object' && !Array.isArray(value);
}

function normalizeStorageScope(value: unknown): EmailOtpRecoveryCodeBackupStorageScope | null {
  const scope = String(value || '').trim();
  if (scope === 'host_origin_indexeddb' || scope === 'iframe_origin_indexeddb') return scope;
  return null;
}

function normalizePositiveTimestamp(value: unknown): number | null {
  const parsed = normalizeInteger(value);
  return parsed !== null && parsed > 0 ? parsed : null;
}

function normalizeRecoveryCodeSet(value: unknown): EmailOtpRecoveryCodeSet | null {
  if (!Array.isArray(value)) return null;
  try {
    return buildEmailOtpRecoveryCodeSet(value.map(String));
  } catch {
    return null;
  }
}

function normalizeNullableTimestamp(value: unknown): number | null {
  if (value === null || value === undefined) return null;
  return normalizePositiveTimestamp(value);
}

export function normalizeEmailOtpRecoveryCodeBackupRecord(
  value: unknown,
): StoredEmailOtpRecoveryCodeBackupRecord | null {
  const row = isRecord(value) ? value : null;
  if (
    row &&
    EMAIL_OTP_RECOVERY_CODE_BACKUP_PAYLOAD_FIELD in row &&
    row[EMAIL_OTP_RECOVERY_CODE_BACKUP_PAYLOAD_FIELD]
  ) {
    value = row[EMAIL_OTP_RECOVERY_CODE_BACKUP_PAYLOAD_FIELD];
  }
  const obj = isRecord(value) ? value : null;
  if (!obj) return null;
  if (Number(obj.v) !== EMAIL_OTP_RECOVERY_CODE_BACKUP_RECORD_VERSION) return null;
  const secretKind = String(obj.secretKind || '').trim();
  if (secretKind !== EMAIL_OTP_RECOVERY_CODE_BACKUP_SECRET_KIND) return null;
  const status = String(obj.status || '').trim();
  if (status !== 'stored') return null;

  const storageScope = normalizeStorageScope(obj.storageScope);
  const walletId = normalizeOptionalNonEmptyString(obj.walletId);
  const enrollmentId = normalizeOptionalNonEmptyString(obj.enrollmentId);
  const enrollmentSealKeyVersion = normalizeOptionalNonEmptyString(obj.enrollmentSealKeyVersion);
  const recoveryCodesIssuedAtMs = normalizePositiveTimestamp(obj.recoveryCodesIssuedAtMs);
  const createdAtMs = normalizePositiveTimestamp(obj.createdAtMs);
  const lastDisplayedAtMs = normalizeNullableTimestamp(obj.lastDisplayedAtMs);
  const lastDownloadedAtMs = normalizeNullableTimestamp(obj.lastDownloadedAtMs);
  const recoveryKeys = normalizeRecoveryCodeSet(obj.recoveryKeys);

  if (
    !storageScope ||
    !walletId ||
    !enrollmentId ||
    !enrollmentSealKeyVersion ||
    recoveryCodesIssuedAtMs === null ||
    createdAtMs === null ||
    !recoveryKeys
  ) {
    return null;
  }

  return {
    v: EMAIL_OTP_RECOVERY_CODE_BACKUP_RECORD_VERSION,
    secretKind: EMAIL_OTP_RECOVERY_CODE_BACKUP_SECRET_KIND,
    storageScope,
    status: 'stored',
    walletId,
    enrollmentId,
    enrollmentSealKeyVersion,
    recoveryCodesIssuedAtMs,
    recoveryKeys,
    createdAtMs,
    lastDisplayedAtMs,
    lastDownloadedAtMs,
  };
}

function emailOtpRecoveryCodeBackupStorageRow(
  record: StoredEmailOtpRecoveryCodeBackupRecord,
): Record<string, unknown> {
  return {
    wallet_id: record.walletId,
    enrollment_id: record.enrollmentId,
    enrollment_seal_key_version: record.enrollmentSealKeyVersion,
    status: record.status,
    recovery_codes_issued_at_ms: record.recoveryCodesIssuedAtMs,
    [EMAIL_OTP_RECOVERY_CODE_BACKUP_PAYLOAD_FIELD]: record,
  };
}

function emailOtpRecoveryCodeBackupStorageKey(value: unknown): [string, string] | null {
  const row = isRecord(value) ? value : null;
  const walletId = normalizeOptionalNonEmptyString(row?.wallet_id);
  const enrollmentId = normalizeOptionalNonEmptyString(row?.enrollment_id);
  if (walletId && enrollmentId) return [walletId, enrollmentId];
  const record = normalizeEmailOtpRecoveryCodeBackupRecord(value);
  if (!record) return null;
  return [record.walletId, record.enrollmentId];
}

export class EmailOtpRecoveryCodeBackupRepository {
  constructor(private readonly manager: SeamsWalletDBManager = seamsWalletDB) {}

  async write(
    args: WriteEmailOtpRecoveryCodeBackupInput,
  ): Promise<StoredEmailOtpRecoveryCodeBackupRecord> {
    const nowMs = args.createdAtMs ?? Date.now();
    const record = normalizeEmailOtpRecoveryCodeBackupRecord({
      v: EMAIL_OTP_RECOVERY_CODE_BACKUP_RECORD_VERSION,
      secretKind: EMAIL_OTP_RECOVERY_CODE_BACKUP_SECRET_KIND,
      storageScope: args.storageScope,
      status: 'stored',
      walletId: args.walletId,
      enrollmentId: args.enrollmentId,
      enrollmentSealKeyVersion: args.enrollmentSealKeyVersion,
      recoveryCodesIssuedAtMs: args.recoveryCodesIssuedAtMs,
      recoveryKeys: args.recoveryKeys,
      createdAtMs: nowMs,
      lastDisplayedAtMs: args.lastDisplayedAtMs ?? null,
      lastDownloadedAtMs: args.lastDownloadedAtMs ?? null,
    });
    if (!record) {
      throw new Error('Invalid Email OTP recovery-code backup record');
    }

    await this.manager.runTransaction(
      [EMAIL_OTP_RECOVERY_CODE_BACKUP_STORE_NAME],
      'readwrite',
      async (ctx) => {
        await ctx
          .store(EMAIL_OTP_RECOVERY_CODE_BACKUP_STORE_NAME)
          .put(emailOtpRecoveryCodeBackupStorageRow(record));
      },
    );
    return record;
  }

  async readMatching(args: {
    walletId: string;
    enrollmentId: string;
    enrollmentSealKeyVersion: string;
  }): Promise<StoredEmailOtpRecoveryCodeBackupRecord | null> {
    const walletId = normalizeOptionalNonEmptyString(args.walletId);
    const enrollmentId = normalizeOptionalNonEmptyString(args.enrollmentId);
    const enrollmentSealKeyVersion = normalizeOptionalNonEmptyString(args.enrollmentSealKeyVersion);
    if (!walletId || !enrollmentId || !enrollmentSealKeyVersion) return null;
    const db = await this.manager.getDB();
    const value = await db.get(EMAIL_OTP_RECOVERY_CODE_BACKUP_STORE_NAME, [
      walletId,
      enrollmentId,
    ]);
    const record = normalizeEmailOtpRecoveryCodeBackupRecord(value);
    if (!record || record.enrollmentSealKeyVersion !== enrollmentSealKeyVersion) {
      return null;
    }
    return record;
  }

  async markDisplayed(args: {
    walletId: string;
    enrollmentId: string;
    enrollmentSealKeyVersion: string;
    displayedAtMs?: number;
  }): Promise<StoredEmailOtpRecoveryCodeBackupRecord | null> {
    const record = await this.readMatching(args);
    if (!record) return null;
    const updated = {
      ...record,
      lastDisplayedAtMs: args.displayedAtMs ?? Date.now(),
    };
    await this.manager.runTransaction(
      [EMAIL_OTP_RECOVERY_CODE_BACKUP_STORE_NAME],
      'readwrite',
      async (ctx) => {
        await ctx
          .store(EMAIL_OTP_RECOVERY_CODE_BACKUP_STORE_NAME)
          .put(emailOtpRecoveryCodeBackupStorageRow(updated));
      },
    );
    return updated;
  }

  async markDownloaded(args: {
    walletId: string;
    enrollmentId: string;
    enrollmentSealKeyVersion: string;
    downloadedAtMs?: number;
  }): Promise<StoredEmailOtpRecoveryCodeBackupRecord | null> {
    const record = await this.readMatching(args);
    if (!record) return null;
    const updated = {
      ...record,
      lastDownloadedAtMs: args.downloadedAtMs ?? Date.now(),
    };
    await this.manager.runTransaction(
      [EMAIL_OTP_RECOVERY_CODE_BACKUP_STORE_NAME],
      'readwrite',
      async (ctx) => {
        await ctx
          .store(EMAIL_OTP_RECOVERY_CODE_BACKUP_STORE_NAME)
          .put(emailOtpRecoveryCodeBackupStorageRow(updated));
      },
    );
    return updated;
  }

  async delete(args: { walletId: string; enrollmentId: string }): Promise<void> {
    const walletId = normalizeOptionalNonEmptyString(args.walletId);
    const enrollmentId = normalizeOptionalNonEmptyString(args.enrollmentId);
    if (!walletId || !enrollmentId) return;
    await this.manager.runTransaction(
      [EMAIL_OTP_RECOVERY_CODE_BACKUP_STORE_NAME],
      'readwrite',
      async (ctx) => {
        await ctx.store(EMAIL_OTP_RECOVERY_CODE_BACKUP_STORE_NAME).delete([
          walletId,
          enrollmentId,
        ]);
      },
    );
  }

  async deleteForWallet(args: { walletId: string }): Promise<void> {
    const walletId = normalizeOptionalNonEmptyString(args.walletId);
    if (!walletId) return;
    await this.manager.runTransaction(
      [EMAIL_OTP_RECOVERY_CODE_BACKUP_STORE_NAME],
      'readwrite',
      async (ctx) => {
        const store = ctx.store(EMAIL_OTP_RECOVERY_CODE_BACKUP_STORE_NAME);
        const rows = await store.index(SEAMS_WALLET_INDEXES.walletId).getAll(walletId);
        for (const row of rows) {
          const key = emailOtpRecoveryCodeBackupStorageKey(row);
          if (key) await store.delete(key);
        }
      },
    );
  }

  async clearAll(): Promise<void> {
    await this.manager.runTransaction(
      [EMAIL_OTP_RECOVERY_CODE_BACKUP_STORE_NAME],
      'readwrite',
      async (ctx) => {
        await ctx.store(EMAIL_OTP_RECOVERY_CODE_BACKUP_STORE_NAME).clear();
      },
    );
  }
}

export const emailOtpRecoveryCodeBackupRepository = new EmailOtpRecoveryCodeBackupRepository();
