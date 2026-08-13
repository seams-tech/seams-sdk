import { parseDeviceId, parseSeamsSessionId } from '@shared/authorization/capabilityKinds';
import { alphabetizeStringify } from '@shared/utils/digests';
import { secureRandomBase64Url } from '@shared/utils/secureRandomId';
import { toOptionalTrimmedString } from '@shared/utils/validation';
import type { D1PreparedStatementLike, D1ResultLike } from '../../../../storage/tenantRoute';

type ScopedD1Prepare = (sql: string, values: readonly unknown[]) => D1PreparedStatementLike;

export const GOOGLE_EMAIL_OTP_SESSION_EXCHANGE_JOURNAL_KIND_V1 =
  'google_email_otp_session_exchange_journal_v1' as const;

export const GOOGLE_EMAIL_OTP_SESSION_EXCHANGE_PHASES = [
  'claimed',
  'session_prepared',
  'completed',
] as const;

export type GoogleEmailOtpSessionExchangePhase =
  (typeof GOOGLE_EMAIL_OTP_SESSION_EXCHANGE_PHASES)[number];
export type GoogleEmailOtpSessionExchangeAccountMode = 'login';

export type GoogleEmailOtpSessionExchangePrepared = {
  readonly seamsSessionId: string;
  readonly deviceId: string;
  readonly createdAtMs: number;
};

export type GoogleEmailOtpSessionExchangeReplayResponse = {
  readonly status: number;
  readonly bodyText: string;
  readonly setCookie?: string;
};

type GoogleEmailOtpSessionExchangeJournalBase = {
  readonly kind: typeof GOOGLE_EMAIL_OTP_SESSION_EXCHANGE_JOURNAL_KIND_V1;
  readonly idempotencyKey: string;
  readonly requestFingerprint: string;
  readonly accountMode: GoogleEmailOtpSessionExchangeAccountMode;
  readonly version: number;
  readonly phaseData: Readonly<Record<string, unknown>>;
  readonly prepared: GoogleEmailOtpSessionExchangePrepared;
  readonly createdAtMs: number;
  readonly updatedAtMs: number;
  readonly expiresAtMs: number;
};

export type GoogleEmailOtpSessionExchangeJournal =
  | (GoogleEmailOtpSessionExchangeJournalBase & {
      readonly lifecycle: 'in_progress';
      readonly phase: Exclude<GoogleEmailOtpSessionExchangePhase, 'completed'>;
      readonly response?: never;
    })
  | (GoogleEmailOtpSessionExchangeJournalBase & {
      readonly lifecycle: 'completed';
      readonly phase: 'completed';
      readonly response: GoogleEmailOtpSessionExchangeReplayResponse;
    });

export type GoogleEmailOtpSessionExchangeCompletedJournal = Extract<
  GoogleEmailOtpSessionExchangeJournal,
  { readonly lifecycle: 'completed' }
>;

export type ClaimGoogleEmailOtpSessionExchangeInput = {
  readonly idempotencyKey: string;
  readonly requestFingerprint: string;
  readonly accountMode: GoogleEmailOtpSessionExchangeAccountMode;
  readonly nowMs: number;
};

export type GoogleEmailOtpSessionExchangeClaimResult =
  | { readonly kind: 'claimed'; readonly journal: GoogleEmailOtpSessionExchangeJournal }
  | { readonly kind: 'resume'; readonly journal: GoogleEmailOtpSessionExchangeJournal }
  | { readonly kind: 'replayed'; readonly journal: GoogleEmailOtpSessionExchangeCompletedJournal }
  | {
      readonly kind: 'conflict';
      readonly code: 'idempotency_conflict';
      readonly journal: GoogleEmailOtpSessionExchangeJournal;
      readonly message: string;
    }
  | { readonly kind: 'uncertain'; readonly message: string };

export type GoogleEmailOtpSessionExchangeMutationResult =
  | { readonly kind: 'stored'; readonly journal: GoogleEmailOtpSessionExchangeJournal }
  | { readonly kind: 'replayed'; readonly journal: GoogleEmailOtpSessionExchangeJournal }
  | {
      readonly kind: 'conflict';
      readonly code: 'version_conflict' | 'response_conflict' | 'request_conflict';
      readonly journal?: GoogleEmailOtpSessionExchangeJournal;
      readonly message: string;
    }
  | {
      readonly kind: 'in_progress';
      readonly journal: GoogleEmailOtpSessionExchangeJournal;
      readonly retryAfterMs: number;
    }
  | { readonly kind: 'uncertain'; readonly message: string };

export type GoogleEmailOtpSessionExchangeCheckpointInput = {
  readonly key: string;
  readonly expectedVersion: number;
  readonly phase: Exclude<GoogleEmailOtpSessionExchangePhase, 'claimed' | 'completed'>;
  readonly data: Readonly<Record<string, unknown>>;
};

export type GoogleEmailOtpSessionExchangeCompleteInput = {
  readonly key: string;
  readonly expectedVersion: number;
  readonly response: GoogleEmailOtpSessionExchangeReplayResponse;
  readonly expiresAtMs: number;
};

type JournalRow = {
  readonly idempotency_key?: unknown;
  readonly request_fingerprint?: unknown;
  readonly account_mode?: unknown;
  readonly lifecycle_kind?: unknown;
  readonly phase?: unknown;
  readonly version?: unknown;
  readonly phase_data_json?: unknown;
  readonly prepared_seams_session_id?: unknown;
  readonly prepared_device_id?: unknown;
  readonly prepared_created_at_ms?: unknown;
  readonly response_status?: unknown;
  readonly response_body_text?: unknown;
  readonly response_set_cookie?: unknown;
  readonly created_at_ms?: unknown;
  readonly updated_at_ms?: unknown;
  readonly expires_at_ms?: unknown;
};

const JOURNAL_TABLE = 'google_email_otp_session_exchange_journals';
const IN_PROGRESS_RETRY_AFTER_MS = 5_000;
const DEFAULT_EXPIRES_AFTER_MS = 15 * 60 * 1_000;

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function containsAsciiControlCharacter(value: string): boolean {
  for (let index = 0; index < value.length; index += 1) {
    const code = value.charCodeAt(index);
    if (code <= 0x1f || code === 0x7f) return true;
  }
  return false;
}

function requiredString(value: unknown, field: string, maxLength = 512): string {
  const normalized = toOptionalTrimmedString(value);
  if (!normalized || normalized.length > maxLength || containsAsciiControlCharacter(normalized)) {
    throw new Error(`Stored ${field} is invalid`);
  }
  return normalized;
}

function requiredPositiveInteger(value: unknown, field: string): number {
  const numeric = typeof value === 'number' ? value : Number(value);
  if (!Number.isSafeInteger(numeric) || numeric <= 0) {
    throw new Error(`Stored ${field} is invalid`);
  }
  return numeric;
}

function requiredVersion(value: unknown): number {
  const numeric = requiredPositiveInteger(value, 'session exchange version');
  return numeric;
}

function parsePhase(value: unknown): GoogleEmailOtpSessionExchangePhase {
  switch (value) {
    case 'claimed':
    case 'session_prepared':
    case 'completed':
      return value;
    default:
      throw new Error('Stored session exchange phase is invalid');
  }
}

function phaseRank(phase: GoogleEmailOtpSessionExchangePhase): number {
  switch (phase) {
    case 'claimed':
      return 0;
    case 'session_prepared':
      return 1;
    case 'completed':
      return 2;
  }
}

function parseAccountMode(value: unknown): GoogleEmailOtpSessionExchangeAccountMode {
  if (value !== 'login') {
    throw new Error('Stored session exchange account mode is invalid');
  }
  return value;
}

function parsePhaseData(value: unknown): Readonly<Record<string, unknown>> {
  if (typeof value !== 'string') throw new Error('Stored session exchange phase data is invalid');
  let parsed: unknown;
  try {
    parsed = JSON.parse(value);
  } catch {
    throw new Error('Stored session exchange phase data is malformed');
  }
  if (!isRecord(parsed)) throw new Error('Stored session exchange phase data is invalid');
  return parsed;
}

function parseResponse(row: JournalRow): GoogleEmailOtpSessionExchangeReplayResponse | undefined {
  if (
    row.response_status == null &&
    row.response_body_text == null &&
    row.response_set_cookie == null
  ) {
    return undefined;
  }
  const status = Number(row.response_status);
  if (!Number.isInteger(status) || status < 100 || status > 599) {
    throw new Error('Stored session exchange response status is invalid');
  }
  if (typeof row.response_body_text !== 'string') {
    throw new Error('Stored session exchange response body is invalid');
  }
  if (row.response_set_cookie != null && typeof row.response_set_cookie !== 'string') {
    throw new Error('Stored session exchange Set-Cookie is invalid');
  }
  return {
    status,
    bodyText: row.response_body_text,
    ...(typeof row.response_set_cookie === 'string' ? { setCookie: row.response_set_cookie } : {}),
  };
}

function parseJournalRow(row: JournalRow | null): GoogleEmailOtpSessionExchangeJournal | null {
  if (!row) return null;
  const lifecycle = row.lifecycle_kind;
  if (lifecycle !== 'in_progress' && lifecycle !== 'completed') {
    throw new Error('Stored session exchange lifecycle is invalid');
  }
  const phase = parsePhase(row.phase);
  const response = parseResponse(row);
  if (lifecycle === 'in_progress' && (phase === 'completed' || response)) {
    throw new Error('In-progress session exchange contains terminal state');
  }
  if (lifecycle === 'completed' && (phase !== 'completed' || !response)) {
    throw new Error('Completed session exchange is missing its terminal response');
  }
  const seamsSessionId = requiredString(row.prepared_seams_session_id, 'prepared session ID');
  const deviceId = requiredString(row.prepared_device_id, 'prepared device ID');
  if (!parseSeamsSessionId(seamsSessionId).ok || !parseDeviceId(deviceId).ok) {
    throw new Error('Stored session exchange prepared identity is invalid');
  }
  const createdAtMs = requiredPositiveInteger(row.created_at_ms, 'session exchange creation time');
  const updatedAtMs = requiredPositiveInteger(row.updated_at_ms, 'session exchange update time');
  const expiresAtMs = requiredPositiveInteger(row.expires_at_ms, 'session exchange expiry');
  if (updatedAtMs < createdAtMs || expiresAtMs <= createdAtMs) {
    throw new Error('Stored session exchange timestamps are invalid');
  }
  const preparedCreatedAtMs = requiredPositiveInteger(
    row.prepared_created_at_ms,
    'prepared session creation time',
  );
  if (preparedCreatedAtMs !== createdAtMs) {
    throw new Error('Stored session exchange prepared timestamp is inconsistent');
  }
  const common: GoogleEmailOtpSessionExchangeJournalBase = {
    kind: GOOGLE_EMAIL_OTP_SESSION_EXCHANGE_JOURNAL_KIND_V1,
    idempotencyKey: requiredString(row.idempotency_key, 'session exchange idempotency key'),
    requestFingerprint: requiredString(
      row.request_fingerprint,
      'session exchange request fingerprint',
    ),
    accountMode: parseAccountMode(row.account_mode),
    version: requiredVersion(row.version),
    phaseData: parsePhaseData(row.phase_data_json),
    prepared: {
      seamsSessionId,
      deviceId,
      createdAtMs: preparedCreatedAtMs,
    },
    createdAtMs,
    updatedAtMs,
    expiresAtMs,
  };
  if (lifecycle === 'completed') {
    if (!response) throw new Error('Completed session exchange response is missing');
    return { ...common, lifecycle: 'completed', phase: 'completed', response };
  }
  if (phase === 'completed') throw new Error('In-progress session exchange phase is terminal');
  return { ...common, lifecycle: 'in_progress', phase };
}

function changedRows(result: D1ResultLike<unknown>): number {
  if (!result.success) throw new Error('D1 session exchange write failed');
  const changes = result.meta?.changes;
  return typeof changes === 'number' && Number.isSafeInteger(changes) ? changes : 0;
}

function normalizeKey(value: unknown, field: string, maxLength = 512): string {
  const normalized = toOptionalTrimmedString(value);
  if (!normalized || normalized.length > maxLength || containsAsciiControlCharacter(normalized)) {
    throw new Error(`${field} is required`);
  }
  return normalized;
}

function normalizeNow(value: unknown, field: string): number {
  const numeric = Number(value);
  if (!Number.isSafeInteger(numeric) || numeric <= 0) throw new Error(`${field} is invalid`);
  return numeric;
}

function normalizeDuration(value: unknown, field: string): number {
  const numeric = Number(value);
  if (!Number.isSafeInteger(numeric) || numeric <= 0) throw new Error(`${field} is invalid`);
  return numeric;
}

function normalizeAccountMode(value: unknown): GoogleEmailOtpSessionExchangeAccountMode {
  if (value !== 'login') throw new Error('accountMode is invalid');
  return value;
}

function normalizePhaseData(value: Readonly<Record<string, unknown>>): string {
  if (!isRecord(value)) throw new Error('phase data must be an object');
  const serialized = JSON.stringify(value);
  if (serialized.length > 65_536) throw new Error('phase data is too large');
  return serialized;
}

function normalizeResponse(
  value: GoogleEmailOtpSessionExchangeReplayResponse,
): GoogleEmailOtpSessionExchangeReplayResponse {
  const status = Number(value.status);
  if (!Number.isInteger(status) || status < 100 || status > 599)
    throw new Error('response.status is invalid');
  if (typeof value.bodyText !== 'string') throw new Error('response.bodyText is invalid');
  if (value.bodyText.length > 65_536) throw new Error('response.bodyText is too large');
  if (
    value.setCookie !== undefined &&
    (typeof value.setCookie !== 'string' || value.setCookie.length > 8_192)
  ) {
    throw new Error('response.setCookie is invalid');
  }
  return {
    status,
    bodyText: value.bodyText,
    ...(value.setCookie !== undefined ? { setCookie: value.setCookie } : {}),
  };
}

function sameResponse(
  left: GoogleEmailOtpSessionExchangeReplayResponse | undefined,
  right: GoogleEmailOtpSessionExchangeReplayResponse,
): boolean {
  return Boolean(
    left &&
    left.status === right.status &&
    left.bodyText === right.bodyText &&
    left.setCookie === right.setCookie,
  );
}

function phaseDataContains(
  current: Readonly<Record<string, unknown>>,
  expected: Readonly<Record<string, unknown>>,
): boolean {
  const expectedKeys = Object.keys(expected);
  for (const key of expectedKeys) {
    if (alphabetizeStringify(current[key]) !== alphabetizeStringify(expected[key])) return false;
  }
  return true;
}

function initialPrepared(nowMs: number): GoogleEmailOtpSessionExchangePrepared {
  return {
    seamsSessionId: `ses_${secureRandomBase64Url(24, 'session exchange')}`,
    deviceId: `dev_${secureRandomBase64Url(18, 'session exchange device')}`,
    createdAtMs: nowMs,
  };
}

function journalInsertValues(input: {
  readonly idempotencyKey: string;
  readonly requestFingerprint: string;
  readonly accountMode: GoogleEmailOtpSessionExchangeAccountMode;
  readonly prepared: GoogleEmailOtpSessionExchangePrepared;
  readonly nowMs: number;
  readonly expiresAtMs: number;
}): readonly unknown[] {
  return [
    input.idempotencyKey,
    input.requestFingerprint,
    input.accountMode,
    'in_progress',
    'claimed',
    1,
    '{}',
    input.prepared.seamsSessionId,
    input.prepared.deviceId,
    input.prepared.createdAtMs,
    input.nowMs,
    input.nowMs,
    input.expiresAtMs,
  ];
}

function isCompletedJournal(
  journal: GoogleEmailOtpSessionExchangeJournal,
): journal is GoogleEmailOtpSessionExchangeCompletedJournal {
  return journal.lifecycle === 'completed';
}

export class CloudflareD1GoogleEmailOtpSessionExchangeStore {
  private readonly prepare: ScopedD1Prepare;
  private readonly expiresAfterMs: number;

  constructor(input: { readonly prepare: ScopedD1Prepare; readonly expiresAfterMs?: number }) {
    this.prepare = input.prepare;
    this.expiresAfterMs = normalizeDuration(
      input.expiresAfterMs ?? DEFAULT_EXPIRES_AFTER_MS,
      'session exchange expiry duration',
    );
  }

  async read(idempotencyKey: string): Promise<GoogleEmailOtpSessionExchangeJournal | null> {
    const key = normalizeKey(idempotencyKey, 'idempotencyKey');
    const row = await this.prepare(
      `SELECT idempotency_key, request_fingerprint, account_mode, lifecycle_kind,
              phase, version, phase_data_json, prepared_seams_session_id,
              prepared_device_id, prepared_created_at_ms, response_status,
              response_body_text, response_set_cookie, created_at_ms,
              updated_at_ms, expires_at_ms
         FROM ${JOURNAL_TABLE}
        WHERE namespace = ? AND org_id = ? AND project_id = ? AND env_id = ?
          AND idempotency_key = ?
        LIMIT 1`,
      [key],
    ).first<JournalRow>();
    return parseJournalRow(row);
  }

  async claim(
    input: ClaimGoogleEmailOtpSessionExchangeInput,
  ): Promise<GoogleEmailOtpSessionExchangeClaimResult> {
    let key: string;
    let fingerprint: string;
    let accountMode: GoogleEmailOtpSessionExchangeAccountMode;
    let nowMs: number;
    try {
      key = normalizeKey(input.idempotencyKey, 'idempotencyKey');
      fingerprint = normalizeKey(input.requestFingerprint, 'requestFingerprint');
      accountMode = normalizeAccountMode(input.accountMode);
      nowMs = normalizeNow(input.nowMs, 'nowMs');
    } catch (error: unknown) {
      return { kind: 'uncertain', message: error instanceof Error ? error.message : String(error) };
    }
    const prepared = initialPrepared(nowMs);
    const expiresAtMs = nowMs + this.expiresAfterMs;
    try {
      const inserted = await this.prepare(
        `INSERT OR IGNORE INTO ${JOURNAL_TABLE} (
          namespace, org_id, project_id, env_id, idempotency_key,
          request_fingerprint, account_mode, lifecycle_kind, phase, version,
          phase_data_json, prepared_seams_session_id, prepared_device_id,
          prepared_created_at_ms, created_at_ms, updated_at_ms, expires_at_ms
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
        journalInsertValues({
          idempotencyKey: key,
          requestFingerprint: fingerprint,
          accountMode,
          prepared,
          nowMs,
          expiresAtMs,
        }),
      ).run();
      const journal = await this.read(key);
      if (!journal) {
        return {
          kind: 'uncertain',
          message:
            changedRows(inserted) === 1
              ? 'Session exchange claim committed without a readable journal'
              : 'Session exchange claim was not readable after a concurrent write',
        };
      }
      if (changedRows(inserted) === 1) return { kind: 'claimed', journal };
      if (journal.requestFingerprint !== fingerprint || journal.accountMode !== accountMode) {
        return {
          kind: 'conflict',
          code: 'idempotency_conflict',
          journal,
          message: 'Session exchange idempotency key was reused for a different request',
        };
      }
      if (journal.expiresAtMs <= nowMs) {
        return {
          kind: 'conflict',
          code: 'idempotency_conflict',
          journal,
          message: 'Session exchange idempotency key has expired',
        };
      }
      if (isCompletedJournal(journal)) return { kind: 'replayed', journal };
      return { kind: 'resume', journal };
    } catch (error: unknown) {
      try {
        const journal = await this.read(key);
        if (journal) {
          if (journal.requestFingerprint !== fingerprint || journal.accountMode !== accountMode) {
            return {
              kind: 'conflict',
              code: 'idempotency_conflict',
              journal,
              message: 'Session exchange idempotency key was reused for a different request',
            };
          }
          if (journal.expiresAtMs <= nowMs) {
            return {
              kind: 'conflict',
              code: 'idempotency_conflict',
              journal,
              message: 'Session exchange idempotency key has expired',
            };
          }
          if (isCompletedJournal(journal)) return { kind: 'replayed', journal };
          return { kind: 'resume', journal };
        }
      } catch {
        // The original write/read error is the useful uncertainty signal.
      }
      return { kind: 'uncertain', message: error instanceof Error ? error.message : String(error) };
    }
  }

  async claimGoogleEmailOtp(
    input: ClaimGoogleEmailOtpSessionExchangeInput,
  ): Promise<GoogleEmailOtpSessionExchangeClaimResult> {
    return await this.claim(input);
  }

  async checkpoint(
    input: GoogleEmailOtpSessionExchangeCheckpointInput,
  ): Promise<GoogleEmailOtpSessionExchangeMutationResult> {
    let key: string;
    let expectedVersion: number;
    let phaseData: string;
    try {
      key = normalizeKey(input.key, 'idempotencyKey');
      expectedVersion = requiredVersion(input.expectedVersion);
      phaseData = normalizePhaseData(input.data);
    } catch (error: unknown) {
      return { kind: 'uncertain', message: error instanceof Error ? error.message : String(error) };
    }
    try {
      const current = await this.read(key);
      if (!current)
        return { kind: 'uncertain', message: 'Session exchange checkpoint target is missing' };
      if (current.lifecycle === 'completed') return { kind: 'replayed', journal: current };
      if (current.version !== expectedVersion) {
        return {
          kind: 'conflict',
          code: 'version_conflict',
          journal: current,
          message: 'Session exchange checkpoint version is stale',
        };
      }
      if (phaseRank(input.phase) <= phaseRank(current.phase)) {
        return {
          kind: 'conflict',
          code: 'version_conflict',
          journal: current,
          message: 'Session exchange checkpoint phase cannot move backwards',
        };
      }
      const update = await this.prepare(
        `UPDATE ${JOURNAL_TABLE}
            SET phase = ?5, version = version + 1,
                phase_data_json = json_patch(phase_data_json, ?6), updated_at_ms = ?7
          WHERE namespace = ?1 AND org_id = ?2 AND project_id = ?3 AND env_id = ?4
            AND idempotency_key = ?8 AND version = ?9 AND lifecycle_kind = 'in_progress'`,
        [input.phase, phaseData, Date.now(), key, expectedVersion],
      ).run();
      if (changedRows(update) === 1) {
        const journal = await this.read(key);
        if (!journal)
          return {
            kind: 'uncertain',
            message: 'Session exchange checkpoint disappeared after commit',
          };
        return { kind: 'stored', journal };
      }
      const journal = await this.read(key);
      if (!journal)
        return { kind: 'uncertain', message: 'Session exchange checkpoint target is missing' };
      if (journal.lifecycle === 'completed') return { kind: 'replayed', journal };
      if (journal.version !== expectedVersion) {
        return {
          kind: 'conflict',
          code: 'version_conflict',
          journal,
          message: 'Session exchange checkpoint version is stale',
        };
      }
      return { kind: 'in_progress', journal, retryAfterMs: IN_PROGRESS_RETRY_AFTER_MS };
    } catch (error: unknown) {
      try {
        const current = await this.read(key);
        if (current) {
          if (current.lifecycle === 'completed') {
            return { kind: 'replayed', journal: current };
          }
          if (
            current.version > expectedVersion &&
            current.phase === input.phase &&
            phaseDataContains(current.phaseData, input.data)
          ) {
            return { kind: 'stored', journal: current };
          }
          if (current.version !== expectedVersion) {
            return {
              kind: 'conflict',
              code: 'version_conflict',
              journal: current,
              message: 'Session exchange checkpoint version is stale after an uncertain write',
            };
          }
        }
      } catch {
        // The original write/read error remains the uncertainty signal.
      }
      return { kind: 'uncertain', message: error instanceof Error ? error.message : String(error) };
    }
  }

  async complete(
    input: GoogleEmailOtpSessionExchangeCompleteInput,
  ): Promise<GoogleEmailOtpSessionExchangeMutationResult> {
    let key: string;
    let expectedVersion: number;
    const completedAtMs = Date.now();
    let expiresAtMs: number;
    let response: GoogleEmailOtpSessionExchangeReplayResponse;
    try {
      key = normalizeKey(input.key, 'idempotencyKey');
      expectedVersion = requiredVersion(input.expectedVersion);
      expiresAtMs = normalizeNow(input.expiresAtMs, 'expiresAtMs');
      response = normalizeResponse(input.response);
      if (expiresAtMs <= completedAtMs) throw new Error('expiresAtMs must be after completedAtMs');
    } catch (error: unknown) {
      return { kind: 'uncertain', message: error instanceof Error ? error.message : String(error) };
    }
    try {
      const update = await this.prepare(
        `UPDATE ${JOURNAL_TABLE}
            SET lifecycle_kind = 'completed', phase = 'completed', version = version + 1,
                response_status = ?5, response_body_text = ?6, response_set_cookie = ?7,
                updated_at_ms = ?8, expires_at_ms = ?9
          WHERE namespace = ?1 AND org_id = ?2 AND project_id = ?3 AND env_id = ?4
            AND idempotency_key = ?10 AND version = ?11 AND lifecycle_kind = 'in_progress'`,
        [
          response.status,
          response.bodyText,
          response.setCookie ?? null,
          completedAtMs,
          expiresAtMs,
          key,
          expectedVersion,
        ],
      ).run();
      if (changedRows(update) === 1) {
        const journal = await this.read(key);
        if (!journal)
          return {
            kind: 'uncertain',
            message: 'Completed session exchange disappeared after commit',
          };
        return { kind: 'stored', journal };
      }
      const journal = await this.read(key);
      if (!journal)
        return { kind: 'uncertain', message: 'Session exchange completion target is missing' };
      if (isCompletedJournal(journal)) {
        if (sameResponse(journal.response, response)) return { kind: 'replayed', journal };
        return {
          kind: 'conflict',
          code: 'response_conflict',
          journal,
          message: 'Session exchange already completed with a different response',
        };
      }
      if (journal.version !== expectedVersion) {
        return {
          kind: 'conflict',
          code: 'version_conflict',
          journal,
          message: 'Session exchange completion version is stale',
        };
      }
      return { kind: 'in_progress', journal, retryAfterMs: IN_PROGRESS_RETRY_AFTER_MS };
    } catch (error: unknown) {
      try {
        const current = await this.read(key);
        if (current) {
          if (isCompletedJournal(current)) {
            if (sameResponse(current.response, response))
              return { kind: 'replayed', journal: current };
            return {
              kind: 'conflict',
              code: 'response_conflict',
              journal: current,
              message: 'Session exchange already completed with a different response',
            };
          }
          if (current.version !== expectedVersion) {
            return {
              kind: 'conflict',
              code: 'version_conflict',
              journal: current,
              message: 'Session exchange completion version is stale after an uncertain write',
            };
          }
        }
      } catch {
        // The original write/read error remains the uncertainty signal.
      }
      return { kind: 'uncertain', message: error instanceof Error ? error.message : String(error) };
    }
  }
}
