import { spawnSync } from 'node:child_process';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { expect, test } from '@playwright/test';
import { createD1ConsoleAccountService } from '../../packages/sdk-server-ts/src/console/account/d1';
import { createD1ConsoleApiKeyService } from '../../packages/sdk-server-ts/src/console/apiKeys/d1';
import { createD1ConsoleApprovalService } from '../../packages/sdk-server-ts/src/console/approvals/d1';
import { createD1ConsoleAuditService } from '../../packages/sdk-server-ts/src/console/audit/d1';
import {
  createD1ConsoleBillingService,
  runD1ConsoleBillingMonthlyFinalization,
} from '../../packages/sdk-server-ts/src/console/billing/d1';
import { createD1ConsoleBillingPrepaidReservationService } from '../../packages/sdk-server-ts/src/console/billingPrepaidReservations/d1';
import { createD1ConsoleBootstrapTokenService } from '../../packages/sdk-server-ts/src/console/bootstrapTokens/d1';
import { createD1ConsoleKeyExportService } from '../../packages/sdk-server-ts/src/console/keyExports/d1';
import {
  createD1ConsoleObservabilityIngestionService,
  createD1ConsoleObservabilityService,
} from '../../packages/sdk-server-ts/src/console/observability/d1';
import { createD1ConsoleOrgProjectEnvService } from '../../packages/sdk-server-ts/src/console/orgProjectEnv/d1';
import { createD1ConsolePolicyService } from '../../packages/sdk-server-ts/src/console/policies/d1';
import {
  createD1ConsoleRuntimeSnapshotService,
  runD1ConsoleRuntimeSnapshotOutboxDispatch,
  type D1ConsoleRuntimeSnapshotOutboxDispatchResult,
} from '../../packages/sdk-server-ts/src/console/runtimeSnapshots/d1';
import type { ConsoleRuntimeSnapshotOutboxEvent } from '../../packages/sdk-server-ts/src/console/runtimeSnapshots/types';
import { createD1ConsoleSponsoredCallService } from '../../packages/sdk-server-ts/src/console/sponsoredCalls/d1';
import { createD1ConsoleSponsorshipSpendCapService } from '../../packages/sdk-server-ts/src/console/sponsorshipSpendCaps/d1';
import { createD1ConsoleTeamRbacService } from '../../packages/sdk-server-ts/src/console/teamRbac/d1';
import { createD1ConsoleWalletService } from '../../packages/sdk-server-ts/src/console/wallets/d1';
import {
  createAesGcmConsoleWebhookSecretCipher,
  createD1ConsoleWebhookService,
  runD1ConsoleWebhookRetryDispatch,
  type ConsoleWebhookSecretCipher,
  type D1ConsoleWebhookRetryDispatchResult,
} from '../../packages/sdk-server-ts/src/console/webhooks/d1';
import type {
  WebhookDispatchAdapter,
  WebhookDispatchRequest,
  WebhookDispatchResult,
} from '../../packages/sdk-server-ts/src/console/webhooks/service';
import {
  D1EmailRecoveryPreparationStore,
  type EmailRecoveryPreparationRecord,
} from '../../packages/sdk-server-ts/src/core/EmailRecoveryPreparationStore';
import {
  D1EmailOtpAuthStateStore,
  D1EmailOtpChallengeStore,
  D1EmailOtpGrantStore,
  D1EmailOtpRecoveryWrappedEnrollmentEscrowStore,
  D1EmailOtpRegistrationAttemptStore,
  D1EmailOtpUnlockChallengeStore,
  D1EmailOtpWalletEnrollmentStore,
  type EmailOtpChallengeContextInput,
  type EmailOtpChallengeRecord,
  type EmailOtpGrantRecord,
  type EmailOtpRecoveryWrappedEnrollmentEscrowRecord,
  type EmailOtpWalletEnrollmentRecord,
  type GoogleEmailOtpRegistrationAttemptRecord,
} from '../../packages/sdk-server-ts/src/core/EmailOtpStores';
import { D1WebAuthnAuthenticatorStore } from '../../packages/sdk-server-ts/src/core/WebAuthnAuthenticatorStore';
import { D1WebAuthnCredentialBindingStore } from '../../packages/sdk-server-ts/src/core/WebAuthnCredentialBindingStore';
import { D1WebAuthnLoginChallengeStore } from '../../packages/sdk-server-ts/src/core/WebAuthnLoginChallengeStore';
import { D1WebAuthnSyncChallengeStore } from '../../packages/sdk-server-ts/src/core/WebAuthnSyncChallengeStore';
import { D1IdentityStore } from '../../packages/sdk-server-ts/src/core/IdentityStore';
import {
  D1NearPublicKeyStore,
  type NearPublicKeyRecord,
} from '../../packages/sdk-server-ts/src/core/NearPublicKeyStore';
import {
  D1RecoveryExecutionStore,
  type RecoveryExecutionRecord,
} from '../../packages/sdk-server-ts/src/core/RecoveryExecutionStore';
import { D1RecoverySessionStore } from '../../packages/sdk-server-ts/src/core/RecoverySessionStore';
import { D1WalletAuthMethodStore } from '../../packages/sdk-server-ts/src/core/WalletAuthMethodStore';
import { D1WalletStore } from '../../packages/sdk-server-ts/src/core/WalletStore';
import { D1SigningRootSecretStore } from '../../packages/sdk-server-ts/src/core/ThresholdService/stores/SigningRootSecretStore.d1';
import type {
  D1DatabaseLike,
  D1PreparedStatementLike,
  D1ResultLike,
} from '../../packages/sdk-server-ts/src/storage/tenantRoute';
import { walletIdFromString } from '../../packages/shared-ts/src/utils/registrationIntent';
import {
  EMAIL_OTP_CHANNEL,
  WALLET_EMAIL_OTP_ACTIONS,
  WALLET_EMAIL_OTP_UNLOCK_OPERATION,
} from '../../packages/shared-ts/src/utils/emailOtpDomain';
import {
  EMAIL_OTP_RECOVERY_WRAP_ALG,
  EMAIL_OTP_RECOVERY_WRAPPED_ENROLLMENT_ESCROW_KIND,
  EMAIL_OTP_RECOVERY_WRAPPED_ENROLLMENT_SECRET_KIND,
} from '../../packages/shared-ts/src/utils/emailOtpRecoveryKey';
import {
  recordSponsoredExecution,
  type RecordSponsoredExecutionInput,
} from '../../packages/sdk-server-ts/src/router/sponsorshipExecution';
import type {
  SponsorshipSpendPricingEstimateInput,
  SponsorshipSpendPricingFinalizeInput,
  SponsorshipSpendPricingQuote,
  SponsorshipSpendPricingService,
} from '../../packages/sdk-server-ts/src/sponsorship/spendCaps';

type SqliteJsonRow = Record<string, unknown>;
type ErrorWithCode = { readonly code?: unknown };
type SponsoredRecordBuildInput = Parameters<RecordSponsoredExecutionInput['buildRecord']>[0];
type SponsoredRecordBuildOutput = ReturnType<RecordSponsoredExecutionInput['buildRecord']>;

class SqliteCliD1Database implements D1DatabaseLike {
  constructor(readonly databasePath: string) {}

  prepare(query: string): D1PreparedStatementLike {
    return new SqliteCliD1PreparedStatement(this.databasePath, query, []);
  }

  async batch<T = unknown>(
    statements: readonly D1PreparedStatementLike[],
  ): Promise<readonly T[]> {
    const sqlStatements = statements.map(sqlFromD1PreparedStatement);
    runSqlite(this.databasePath, `BEGIN IMMEDIATE; ${sqlStatements.join(' ')} COMMIT;`);
    return sqlStatements.map(buildSuccessfulD1BatchResult) as readonly T[];
  }

  async exec(query: string): Promise<unknown> {
    runSqlite(this.databasePath, query);
    return null;
  }
}

class SqliteCliD1PreparedStatement implements D1PreparedStatementLike {
  constructor(
    private readonly databasePath: string,
    private readonly query: string,
    private readonly values: readonly unknown[],
  ) {}

  bind(...values: readonly unknown[]): D1PreparedStatementLike {
    return new SqliteCliD1PreparedStatement(this.databasePath, this.query, values);
  }

  async first<T = unknown>(columnName?: string): Promise<T | null> {
    const result = await this.all<SqliteJsonRow>();
    const row = result.results?.[0] || null;
    if (!row) return null;
    if (!columnName) return row as T;
    const value = row[columnName];
    return value === undefined ? null : (value as T);
  }

  async all<T = unknown>(): Promise<D1ResultLike<T>> {
    const results = runSqliteJson(this.databasePath, this.toSql());
    return {
      success: true,
      results: results as readonly T[],
      meta: {
        rows_read: results.length,
        rows_written: 0,
      },
    };
  }

  async run<T = unknown>(): Promise<D1ResultLike<T>> {
    const sql = `${this.toSql()} SELECT changes() AS changes, last_insert_rowid() AS last_row_id;`;
    const results = runSqliteJson(this.databasePath, sql);
    const metaRow = results.at(-1) || {};
    return {
      success: true,
      results: [] as readonly T[],
      meta: {
        changes: toInteger(metaRow.changes),
        last_row_id: toInteger(metaRow.last_row_id),
        rows_written: toInteger(metaRow.changes),
      },
    };
  }

  toSql(): string {
    return interpolateSql(this.query, this.values);
  }
}

class RuntimeSnapshotOutboxRaceHarness {
  readonly dispatchedEventIds: string[] = [];
  competitorResult: D1ConsoleRuntimeSnapshotOutboxDispatchResult | null = null;

  constructor(
    private readonly database: D1DatabaseLike,
    private readonly namespace: string,
    private readonly orgId: string,
    private readonly nowMs: number,
  ) {}

  now(): Date {
    return new Date(this.nowMs);
  }

  async dispatch(event: ConsoleRuntimeSnapshotOutboxEvent): Promise<void> {
    this.dispatchedEventIds.push(event.eventId);
    this.competitorResult = await runD1ConsoleRuntimeSnapshotOutboxDispatch({
      database: this.database,
      namespace: this.namespace,
      orgIds: [this.orgId],
      limit: 1,
      ensureSchema: false,
      now: this.now.bind(this),
      workerId: 'snapshot-race-worker-b',
      claimTtlMs: 60_000,
      dispatch: this.competitorDispatch.bind(this),
    });
  }

  async competitorDispatch(event: ConsoleRuntimeSnapshotOutboxEvent): Promise<void> {
    this.dispatchedEventIds.push(`competitor:${event.eventId}`);
  }
}

class TestMutableClock {
  private currentMs: number;

  constructor(initialIso: string) {
    this.currentMs = Date.parse(initialIso);
    this.now = this.now.bind(this);
  }

  set(iso: string): void {
    this.currentMs = Date.parse(iso);
  }

  now(): Date {
    return new Date(this.currentMs);
  }
}

class D1WebhookDispatchHarness implements WebhookDispatchAdapter {
  readonly requests: WebhookDispatchRequest[] = [];
  private readonly queuedResults: WebhookDispatchResult[] = [];

  pushResult(result: WebhookDispatchResult): void {
    this.queuedResults.push(result);
  }

  async dispatch(input: WebhookDispatchRequest): Promise<WebhookDispatchResult> {
    this.requests.push(input);
    return (
      this.queuedResults.shift() || {
        ok: true,
        statusCode: 200,
        responseBody: 'ok',
      }
    );
  }
}

class D1WebhookRetryRaceHarness implements WebhookDispatchAdapter {
  readonly requests: WebhookDispatchRequest[] = [];
  competitorResult: D1ConsoleWebhookRetryDispatchResult | null = null;

  constructor(
    private readonly input: {
      readonly database: D1DatabaseLike;
      readonly namespace: string;
      readonly orgId: string;
      readonly secretCipher: ConsoleWebhookSecretCipher;
      readonly now: () => Date;
    },
  ) {}

  async dispatch(request: WebhookDispatchRequest): Promise<WebhookDispatchResult> {
    this.requests.push(request);
    this.competitorResult = await runD1ConsoleWebhookRetryDispatch({
      database: this.input.database,
      namespace: this.input.namespace,
      orgIds: [this.input.orgId],
      secretCipher: this.input.secretCipher,
      ensureSchema: false,
      now: this.input.now,
      dispatcher: this.competitorDispatch.bind(this),
      initialBackoffMs: 0,
      maxBackoffMs: 0,
      workerId: 'webhook-retry-worker-b',
    });
    return {
      ok: true,
      statusCode: 200,
      responseBody: 'retried',
    };
  }

  async competitorDispatch(request: WebhookDispatchRequest): Promise<WebhookDispatchResult> {
    this.requests.push({
      ...request,
      eventId: `competitor:${request.eventId}`,
    });
    return {
      ok: true,
      statusCode: 200,
      responseBody: 'competitor-retried',
    };
  }
}

class StaticSponsoredSpendPricingService implements SponsorshipSpendPricingService {
  constructor(
    private readonly estimatedSpendMinor: number,
    private readonly settledSpendMinor: number,
  ) {}

  async estimateSponsoredExecutionSpend(
    _input: SponsorshipSpendPricingEstimateInput,
  ): Promise<SponsorshipSpendPricingQuote> {
    return {
      spendMinor: this.estimatedSpendMinor,
      pricingVersion: 'static:estimate',
    };
  }

  async finalizeSponsoredExecutionSpend(
    _input: SponsorshipSpendPricingFinalizeInput,
  ): Promise<SponsorshipSpendPricingQuote> {
    return {
      spendMinor: this.settledSpendMinor,
      pricingVersion: 'static:settled',
    };
  }
}

class AtomicD1SponsoredRecordBuilder {
  constructor(private readonly idempotencyKey: string) {}

  build(input: SponsoredRecordBuildInput): SponsoredRecordBuildOutput {
    return {
      environmentId: 'env-production',
      apiKeyId: 'api-key-d1-atomic',
      apiKeyKind: 'publishable_key',
      route: 'sponsored_evm_call_v1',
      policyId: 'policy-sponsored-gas',
      chainFamily: 'evm',
      intentKind: 'evm_call',
      accountRef: '0x1111111111111111111111111111111111111111',
      targetRef: '0x2222222222222222222222222222222222222222',
      sponsorRef: '0x3333333333333333333333333333333333333333',
      detailsJson: JSON.stringify({
        kind: 'd1-atomic-sponsored-settlement',
        billing: input.prepaidSettlement,
      }),
      estimatedSpendMinor: input.prepaidSettlement?.estimatedSpendMinor ?? null,
      settledSpendMinor: input.prepaidSettlement?.settledSpendMinor ?? null,
      pricingVersion: input.prepaidSettlement?.pricingVersion ?? null,
      pricingSource: input.prepaidSettlement ? 'sponsorship_pricing_service' : null,
      billingLedgerEntryId: input.billingLedgerEntryId,
      prepaidReservationId: input.prepaidSettlement?.reservationId || null,
      charged: Boolean(
        input.prepaidSettlement &&
          !input.prepaidSettlement.released &&
          input.prepaidSettlement.settledSpendMinor > 0,
      ),
      chargedReason: input.prepaidSettlement
        ? input.prepaidSettlement.released
          ? 'released_zero_spend'
          : input.prepaidSettlement.settledSpendMinor > 0
            ? 'sponsored_execution_debit'
            : 'settled_zero_spend'
        : null,
      settledAt: input.prepaidSettlement?.settledAt || null,
      idempotencyKey: this.idempotencyKey,
    };
  }
}

function fixedD1AtomicBillingNow(): Date {
  return new Date('2026-06-27T00:00:00.000Z');
}

function createD1AtomicAssessment(): RecordSponsoredExecutionInput['assessment'] {
  return {
    succeeded: true,
    txOrExecutionRef: '0xatomicsettled',
    receiptStatus: 'success',
    feeUnit: 'wei',
    feeAmount: '1000000000000000',
    executorKind: 'evm_eoa',
    responseCode: 'ok',
    responseMessage: 'settled',
    recordErrorCode: null,
    recordErrorMessage: null,
  };
}

function sqlFromD1PreparedStatement(statement: D1PreparedStatementLike): string {
  if (!(statement instanceof SqliteCliD1PreparedStatement)) {
    throw new Error('SQLite D1 test batch only accepts SQLite-backed statements');
  }
  return statement.toSql();
}

function buildSuccessfulD1BatchResult(): D1ResultLike {
  return {
    success: true,
    results: [],
    meta: {
      changes: 0,
      rows_written: 0,
    },
  };
}

function createTemporaryD1Database(): { readonly database: D1DatabaseLike; readonly tempDir: string } {
  const tempDir = mkdtempSync(path.join(tmpdir(), 'seams-d1-adapter-test-'));
  return {
    database: new SqliteCliD1Database(path.join(tempDir, 'test.sqlite')),
    tempDir,
  };
}

function cleanupTemporaryD1Database(tempDir: string): void {
  rmSync(tempDir, { recursive: true, force: true });
}

function runSqlite(databasePath: string, sql: string): void {
  const result = spawnSync('sqlite3', [databasePath, sql], {
    encoding: 'utf8',
    maxBuffer: 16 * 1024 * 1024,
  });
  if (result.status === 0) return;
  throw new Error(formatSqliteError(result.stderr, sql));
}

function runSqliteJson(databasePath: string, sql: string): readonly SqliteJsonRow[] {
  const result = spawnSync('sqlite3', ['-json', databasePath, sql], {
    encoding: 'utf8',
    maxBuffer: 16 * 1024 * 1024,
  });
  if (result.status !== 0) {
    throw new Error(formatSqliteError(result.stderr, sql));
  }
  const stdout = result.stdout.trim();
  if (!stdout) return [];
  const parsed: unknown = JSON.parse(stdout);
  if (!Array.isArray(parsed)) {
    throw new Error(`sqlite3 JSON output was not an array: ${stdout}`);
  }
  return parsed.filter(isSqliteJsonRow);
}

function formatSqliteError(stderr: string, sql: string): string {
  return `sqlite3 failed: ${stderr.trim() || 'unknown error'}\nSQL: ${sql}`;
}

function isSqliteJsonRow(input: unknown): input is SqliteJsonRow {
  return Boolean(input && typeof input === 'object' && !Array.isArray(input));
}

function interpolateSql(query: string, values: readonly unknown[]): string {
  const segments = splitSqlByPlaceholders(query);
  if (segments.length - 1 !== values.length) {
    throw new Error(
      `SQL placeholder count ${segments.length - 1} did not match bound value count ${values.length}`,
    );
  }
  let sql = segments[0] || '';
  for (let i = 0; i < values.length; i += 1) {
    sql += `${sqlLiteral(values[i])}${segments[i + 1] || ''}`;
  }
  return ensureSqlStatementTerminator(sql);
}

function splitSqlByPlaceholders(query: string): readonly string[] {
  const segments: string[] = [];
  let current = '';
  let inSingleQuote = false;
  for (let i = 0; i < query.length; i += 1) {
    const char = query[i] || '';
    const next = query[i + 1] || '';
    if (char === "'" && inSingleQuote && next === "'") {
      current += "''";
      i += 1;
      continue;
    }
    if (char === "'") {
      inSingleQuote = !inSingleQuote;
      current += char;
      continue;
    }
    if (char === '?' && !inSingleQuote) {
      segments.push(current);
      current = '';
      continue;
    }
    current += char;
  }
  segments.push(current);
  return segments;
}

function ensureSqlStatementTerminator(sql: string): string {
  const trimmed = sql.trim();
  return trimmed.endsWith(';') ? trimmed : `${trimmed};`;
}

function sqlLiteral(value: unknown): string {
  if (value === null || value === undefined) return 'NULL';
  if (typeof value === 'boolean') return value ? '1' : '0';
  if (typeof value === 'number' && Number.isFinite(value)) return String(value);
  if (typeof value === 'bigint') return value.toString();
  if (value instanceof Uint8Array) return `X'${Buffer.from(value).toString('hex')}'`;
  if (value instanceof Date) return quoteSqlString(value.toISOString());
  return quoteSqlString(String(value));
}

function quoteSqlString(value: string): string {
  return `'${value.replace(/'/g, "''")}'`;
}

function toInteger(value: unknown): number {
  const parsed = typeof value === 'number' ? value : Number(value);
  return Number.isFinite(parsed) ? Math.trunc(parsed) : 0;
}

function errorCode(error: unknown): string {
  const maybeCode = isErrorWithCode(error) ? error.code : null;
  return String(maybeCode || '');
}

function createD1WebhookTestSecretCipher() {
  return createAesGcmConsoleWebhookSecretCipher({
    keyId: 'webhook-test-key-r1',
    keyBytes: new Uint8Array(32).fill(7),
  });
}

function recoveryExecutionAction(record: RecoveryExecutionRecord): string {
  return record.action;
}

function nearPublicKeyValue(record: NearPublicKeyRecord): string {
  return record.publicKey;
}

function webhookDispatchEventId(request: WebhookDispatchRequest): string {
  return request.eventId;
}

function buildD1EmailRecoveryPreparationRecord(input: {
  readonly requestId: string;
  readonly createdAtMs: number;
  readonly expiresAtMs: number;
}): EmailRecoveryPreparationRecord {
  return {
    version: 'email_recovery_preparation_v1',
    requestId: input.requestId,
    accountId: 'wallet-d1-email-recovery',
    walletBinding: {
      walletId: 'wallet-d1-email-recovery',
      nearAccountId: 'wallet-d1-email-recovery.testnet',
      nearEd25519SigningKeyId: 'near-ed25519-email-recovery',
      rpId: 'app.seams.test',
      signerSlot: 1,
    },
    rpId: 'app.seams.test',
    signerSlot: 1,
    credentialIdB64u: 'credential-d1-email-recovery',
    credentialPublicKeyB64u: 'credential-public-key-d1-email-recovery',
    counter: 0,
    createdAtMs: input.createdAtMs,
    expiresAtMs: input.expiresAtMs,
    thresholdEd25519: {
      relayerKeyId: 'relayer-key-email-recovery',
      publicKey: 'ed25519:email-recovery-public-key',
      keyVersion: 'email-recovery-key-v1',
      recoveryExportCapable: true,
      clientParticipantId: 1,
      relayerParticipantId: 2,
      participantIds: [1, 2],
    },
    ecdsa: {
      kind: 'evm_family_ecdsa_keygen',
      chainTargets: [
        {
          kind: 'evm',
          namespace: 'eip155',
          chainId: 1,
        },
      ],
      prepare: {
        formatVersion: 'ecdsa-hss-role-local',
        walletId: 'wallet-d1-email-recovery',
        walletKeyId: 'wallet-key-d1-email-recovery',
        ecdsaThresholdKeyId: 'ecdsa-threshold-d1-email-recovery',
        signingRootId: 'signing-root-d1-email-recovery',
        signingRootVersion: 'version-d1-email-recovery',
        keyScope: 'evm-family',
        relayerKeyId: 'relayer-ecdsa-d1-email-recovery',
        requestId: 'ecdsa-request-d1-email-recovery',
        thresholdSessionId: 'threshold-session-d1-email-recovery',
        signingGrantId: 'signing-grant-d1-email-recovery',
        ttlMs: 300_000,
        remainingUses: 10,
        participantIds: [1, 2],
      },
    },
  };
}

function buildD1EmailOtpChallengeContext(input: {
  readonly nowMs: number;
}): EmailOtpChallengeContextInput {
  return {
    challengeSubjectId: 'google-subject-d1-email-otp',
    walletId: 'wallet-d1-email-otp',
    orgId: 'org-d1-signer',
    otpChannel: EMAIL_OTP_CHANNEL,
    sessionHash: 'session-hash-d1-email-otp',
    appSessionVersion: 'app-session-v1',
    action: WALLET_EMAIL_OTP_ACTIONS.login,
    operation: WALLET_EMAIL_OTP_UNLOCK_OPERATION,
    nowMs: input.nowMs,
  };
}

function buildD1EmailOtpChallengeRecord(input: {
  readonly challengeId: string;
  readonly otpCode: string;
  readonly createdAtMs: number;
  readonly expiresAtMs: number;
}): EmailOtpChallengeRecord {
  return {
    version: 'email_otp_challenge_v1',
    challengeId: input.challengeId,
    challengeSubjectId: 'google-subject-d1-email-otp',
    walletId: 'wallet-d1-email-otp',
    orgId: 'org-d1-signer',
    otpChannel: EMAIL_OTP_CHANNEL,
    email: 'email-otp-d1@example.com',
    otpCode: input.otpCode,
    sessionHash: 'session-hash-d1-email-otp',
    appSessionVersion: 'app-session-v1',
    action: WALLET_EMAIL_OTP_ACTIONS.login,
    operation: WALLET_EMAIL_OTP_UNLOCK_OPERATION,
    createdAtMs: input.createdAtMs,
    expiresAtMs: input.expiresAtMs,
    attemptCount: 0,
    maxAttempts: 5,
  };
}

function buildD1EmailOtpGrantRecord(input: {
  readonly grantToken: string;
  readonly issuedAtMs: number;
  readonly expiresAtMs: number;
}): EmailOtpGrantRecord {
  return {
    version: 'email_otp_grant_v1',
    grantToken: input.grantToken,
    userId: 'google-subject-d1-email-otp',
    walletId: 'wallet-d1-email-otp',
    orgId: 'org-d1-signer',
    challengeId: 'email-otp-challenge-latest',
    otpChannel: EMAIL_OTP_CHANNEL,
    sessionHash: 'session-hash-d1-email-otp',
    appSessionVersion: 'app-session-v1',
    action: WALLET_EMAIL_OTP_ACTIONS.unseal,
    issuedAtMs: input.issuedAtMs,
    expiresAtMs: input.expiresAtMs,
  };
}

function buildD1EmailOtpWalletEnrollmentRecord(input: {
  readonly updatedAtMs: number;
}): EmailOtpWalletEnrollmentRecord {
  return {
    version: 'email_otp_wallet_enrollment_v1',
    walletId: 'wallet-d1-email-otp',
    providerUserId: 'google-subject-d1-email-otp',
    orgId: 'org-d1-signer',
    verifiedEmail: 'email-otp-d1@example.com',
    enrollmentId: 'email-otp-enrollment-d1',
    enrollmentVersion: 'enrollment-v1',
    enrollmentSealKeyVersion: 'seal-key-v1',
    signingRootId: 'signing-root-email-otp-d1',
    signingRootVersion: 'signing-root-version-v1',
    recoveryWrappedEnrollmentEscrowCount: 2,
    clientUnlockPublicKeyB64u: 'clientUnlockPublicKeyB64u',
    unlockKeyVersion: 'unlock-key-v1',
    thresholdEcdsaClientVerifyingShareB64u: 'thresholdEcdsaClientVerifyingShareB64u',
    createdAtMs: Date.parse('2026-06-27T10:00:00.000Z'),
    updatedAtMs: input.updatedAtMs,
  };
}

function buildD1EmailOtpEscrowRecord(input: {
  readonly recoveryKeyId: string;
  readonly recoveryKeyStatus: 'active' | 'consumed';
  readonly updatedAtMs: number;
}): EmailOtpRecoveryWrappedEnrollmentEscrowRecord {
  const base = {
    version: 'email_otp_recovery_wrapped_enrollment_escrow_v1' as const,
    alg: EMAIL_OTP_RECOVERY_WRAP_ALG,
    secretKind: EMAIL_OTP_RECOVERY_WRAPPED_ENROLLMENT_SECRET_KIND,
    escrowKind: EMAIL_OTP_RECOVERY_WRAPPED_ENROLLMENT_ESCROW_KIND,
    walletId: 'wallet-d1-email-otp',
    userId: 'google-subject-d1-email-otp',
    authSubjectId: 'google-subject-d1-email-otp',
    authMethod: 'google_sso_email_otp' as const,
    enrollmentId: 'email-otp-enrollment-d1',
    enrollmentVersion: 'enrollment-v1',
    enrollmentSealKeyVersion: 'seal-key-v1',
    signingRootId: 'signing-root-email-otp-d1',
    signingRootVersion: 'signing-root-version-v1',
    recoveryKeyId: input.recoveryKeyId,
    nonceB64u: 'AAAAAAAAAAAA',
    wrappedDeviceEnrollmentEscrowB64u: 'BBBBBBBBBBBB',
    aadHashB64u: 'CCCCCCCCCCCC',
    issuedAtMs: Date.parse('2026-06-27T10:00:00.000Z'),
    updatedAtMs: input.updatedAtMs,
  };
  if (input.recoveryKeyStatus === 'active') {
    return { ...base, recoveryKeyStatus: 'active' };
  }
  return {
    ...base,
    recoveryKeyStatus: 'consumed',
    consumedAtMs: input.updatedAtMs,
  };
}

function buildD1EmailOtpRegistrationAttemptRecord(input: {
  readonly attemptId: string;
  readonly appSessionVersion: string;
  readonly walletId: string;
  readonly runtimeProjectId: string;
  readonly updatedAtMs: number;
  readonly expiresAtMs: number;
}): GoogleEmailOtpRegistrationAttemptRecord {
  return {
    version: 'google_email_otp_registration_attempt_v1',
    attemptId: input.attemptId,
    providerSubject: 'google-subject-d1-email-otp',
    email: 'email-otp-d1@example.com',
    walletId: input.walletId,
    offerId: 'email-otp-offer-d1',
    offerCandidates: [
      {
        candidateId: 'candidate-primary',
        walletId: input.walletId,
        collisionCounter: 0,
      },
      {
        candidateId: 'candidate-secondary',
        walletId: 'wallet-d1-email-otp-offer-candidate',
        collisionCounter: 1,
      },
    ],
    selectedCandidateId: 'candidate-primary',
    appSessionVersion: input.appSessionVersion,
    authProvider: 'google_oidc',
    accountIdSlugVersion: 'hmac_readable_v1',
    walletIdDerivationNonce: 'wallet-id-nonce-d1',
    collisionCounter: 0,
    state: 'started',
    createdAtMs: Date.parse('2026-06-27T10:00:00.000Z'),
    updatedAtMs: input.updatedAtMs,
    expiresAtMs: input.expiresAtMs,
    runtimePolicyScope: {
      orgId: 'org-d1-signer',
      projectId: input.runtimeProjectId,
      envId: 'env-production',
      signingRootVersion: 'signing-root-version-v1',
    },
  };
}

function isErrorWithCode(input: unknown): input is ErrorWithCode {
  return Boolean(input && typeof input === 'object' && 'code' in input);
}

test.describe('D1 adapter contracts', () => {
  test('org project environment adapter scopes tenants and default environments', async () => {
    const temp = createTemporaryD1Database();
    try {
      const service = await createD1ConsoleOrgProjectEnvService({
        database: temp.database,
        namespace: 'd1-contracts',
        ensureSchema: true,
        now: () => new Date('2026-06-27T00:00:00.000Z'),
      });
      const primaryCtx = {
        orgId: 'org-d1-projects-primary',
        actorUserId: 'user-d1-projects-primary',
        roles: ['admin'],
      };
      const secondaryCtx = {
        orgId: 'org-d1-projects-secondary',
        actorUserId: 'user-d1-projects-secondary',
        roles: ['admin'],
      };

      let missingOrgError: unknown = null;
      try {
        await service.getOrganization(primaryCtx);
      } catch (error: unknown) {
        missingOrgError = error;
      }
      expect(errorCode(missingOrgError)).toBe('organization_not_found');

      const primaryOrg = await service.upsertOrganization(primaryCtx, {
        name: 'D1 Primary Org',
      });
      expect(primaryOrg.slug).toBe('d1-primary-org');
      await expect(service.findDefaultOrganization()).resolves.toMatchObject({
        id: primaryCtx.orgId,
      });

      const project = await service.createProject(primaryCtx, {
        id: 'project-d1-org',
        name: 'D1 Control Plane',
        liveEnvironmentsEnabled: false,
      });
      expect(project.environmentCount).toBe(3);

      const environments = await service.listEnvironments(primaryCtx, {
        projectId: project.id,
      });
      expect(environments.map((environment) => environment.key)).toEqual([
        'prod',
        'staging',
        'dev',
      ]);
      expect(environments.map((environment) => environment.status)).toEqual([
        'DISABLED',
        'DISABLED',
        'ACTIVE',
      ]);

      const prodEnvironment = await service.updateEnvironment(
        primaryCtx,
        'project-d1-org:prod',
        {
          signingRootVersion: 'signing-root-d1-v2',
          name: 'Production Root',
        },
      );
      expect(prodEnvironment?.signingRootVersion).toBe('signing-root-d1-v2');

      await service.upsertOrganization(secondaryCtx, {
        name: 'D1 Secondary Org',
      });
      await expect(service.findDefaultOrganization()).resolves.toBeNull();
      await expect(service.listProjects(secondaryCtx)).resolves.toHaveLength(0);
      await expect(
        service.updateEnvironment(secondaryCtx, 'project-d1-org:prod', {
          name: 'Cross Tenant Mutation',
        }),
      ).resolves.toBeNull();

      await expect(
        service.findOrganizationForScope({ projectId: project.id }),
      ).resolves.toMatchObject({
        id: primaryCtx.orgId,
      });
      await expect(
        service.findOrganizationForScope({
          projectId: project.id,
          environmentId: 'project-d1-org:prod',
        }),
      ).resolves.toMatchObject({
        id: primaryCtx.orgId,
      });
      await expect(service.searchOrganizations({ query: 'primary', limit: 5 })).resolves.toEqual([
        expect.objectContaining({ id: primaryCtx.orgId }),
      ]);

      let duplicateEnvironmentKeyError: unknown = null;
      try {
        await service.createEnvironment(primaryCtx, {
          projectId: project.id,
          key: 'dev',
          name: 'Duplicate Development',
        });
      } catch (error: unknown) {
        duplicateEnvironmentKeyError = error;
      }
      expect(errorCode(duplicateEnvironmentKeyError)).toBe('environment_key_conflict');

      const archivedProject = await service.archiveProject(primaryCtx, project.id);
      expect(archivedProject?.status).toBe('ARCHIVED');
      const archivedEnvironments = await service.listEnvironments(primaryCtx, {
        projectId: project.id,
        status: 'ARCHIVED',
      });
      expect(archivedEnvironments).toHaveLength(3);

      let archivedProjectError: unknown = null;
      try {
        await service.updateProject(primaryCtx, project.id, {
          name: 'Archived Project Update',
        });
      } catch (error: unknown) {
        archivedProjectError = error;
      }
      expect(errorCode(archivedProjectError)).toBe('project_archived');

      const deleted = await service.deleteOrganization(primaryCtx);
      expect(deleted.deleted).toBe(true);
      await expect(service.findOrganizationForScope({ projectId: project.id })).resolves.toBeNull();
    } finally {
      cleanupTemporaryD1Database(temp.tempDir);
    }
  });

  test('account adapter stores profiles and resolves created organizations from D1', async () => {
    const temp = createTemporaryD1Database();
    try {
      const namespace = 'd1-contracts';
      const orgProjectEnv = await createD1ConsoleOrgProjectEnvService({
        database: temp.database,
        namespace,
        ensureSchema: true,
        now: () => new Date('2026-06-27T00:00:00.000Z'),
      });
      const teamRbac = await createD1ConsoleTeamRbacService({
        database: temp.database,
        namespace,
        ensureSchema: true,
        now: () => new Date('2026-06-27T00:00:00.000Z'),
      });
      const service = await createD1ConsoleAccountService({
        database: temp.database,
        namespace,
        ensureSchema: true,
        orgProjectEnv,
        teamRbac,
        now: () => new Date('2026-06-27T00:00:00.000Z'),
      });
      const ctx = {
        userId: 'user-d1-account',
        orgId: 'org-d1-account-home',
        roles: [],
        email: 'USER-D1-ACCOUNT@example.com',
        name: 'D1 Account User',
      };

      const initialProfile = await service.getProfile(ctx);
      expect(initialProfile.displayName).toBe('D1 Account User');
      expect(initialProfile.primaryEmail).toBe('user-d1-account@example.com');
      expect(initialProfile.backupEmails).toHaveLength(0);

      const updatedProfile = await service.updateProfile(ctx, {
        displayName: 'D1 Account Owner',
        primaryEmail: 'owner-d1-account@example.com',
        addBackupEmail: 'backup-d1-account@example.com',
      });
      expect(updatedProfile.displayName).toBe('D1 Account Owner');
      expect(updatedProfile.primaryEmail).toBe('owner-d1-account@example.com');
      expect(updatedProfile.backupEmails).toEqual([
        expect.objectContaining({
          email: 'backup-d1-account@example.com',
          status: 'PENDING',
        }),
      ]);

      const duplicateBackupProfile = await service.updateProfile(ctx, {
        addBackupEmail: 'backup-d1-account@example.com',
      });
      expect(duplicateBackupProfile.backupEmails).toHaveLength(1);

      const removedBackupProfile = await service.updateProfile(ctx, {
        removeBackupEmail: 'backup-d1-account@example.com',
      });
      expect(removedBackupProfile.backupEmails).toHaveLength(0);

      let readOnlyEmailError: unknown = null;
      try {
        await service.updateProfile(
          { ...ctx, provider: 'oidc' },
          { primaryEmail: 'oidc-owned@example.com' },
        );
      } catch (error: unknown) {
        readOnlyEmailError = error;
      }
      expect(errorCode(readOnlyEmailError)).toBe('primary_email_read_only');

      const organization = await service.createOrganization(ctx, {
        id: 'org-d1-account-created',
        name: 'D1 Account Created Org',
      });
      expect(organization.actorIsOwner).toBe(true);
      expect(organization.actorRoles).toContain('owner');

      await orgProjectEnv.createProject(
        {
          orgId: organization.id,
          actorUserId: ctx.userId,
          roles: ['owner'],
        },
        {
          id: 'project-d1-account',
          name: 'D1 Account Project',
          liveEnvironmentsEnabled: true,
        },
      );

      const organizations = await service.listOrganizations(ctx);
      expect(organizations).toHaveLength(1);
      expect(organizations[0]).toMatchObject({
        id: organization.id,
        selectedProjectId: 'project-d1-account',
        selectedEnvironmentId: 'project-d1-account:prod',
      });

      const switched = await service.switchOrganizationContext(ctx, organization.id);
      expect(switched.actorRoles).toContain('owner');
      expect(switched.projectId).toBe('project-d1-account');
      expect(switched.environmentId).toBe('project-d1-account:prod');

      const renamed = await service.updateOrganization(ctx, organization.id, {
        name: 'D1 Account Renamed Org',
      });
      expect(renamed.name).toBe('D1 Account Renamed Org');

      let duplicateOrganizationError: unknown = null;
      try {
        await service.createOrganization(ctx, {
          id: organization.id,
          name: 'Duplicate Org',
        });
      } catch (error: unknown) {
        duplicateOrganizationError = error;
      }
      expect(errorCode(duplicateOrganizationError)).toBe('organization_already_exists');
    } finally {
      cleanupTemporaryD1Database(temp.tempDir);
    }
  });

  test('wallet index adapter scopes tenants and paginates filtered D1 rows', async () => {
    const temp = createTemporaryD1Database();
    try {
      let nowMsValue = Date.parse('2026-06-27T00:30:00.000Z');
      const service = await createD1ConsoleWalletService({
        database: temp.database,
        namespace: 'd1-contracts',
        ensureSchema: true,
        now: () => new Date(nowMsValue),
      });
      const primaryCtx = {
        orgId: 'org-d1-wallets-primary',
        actorUserId: 'user-d1-wallets-primary',
        roles: ['admin'],
      };
      const secondaryCtx = {
        orgId: 'org-d1-wallets-secondary',
        actorUserId: 'user-d1-wallets-secondary',
        roles: ['admin'],
      };
      const upsertWallet = service.upsertWallet;
      if (!upsertWallet) throw new Error('D1 wallet adapter must expose wallet upsert');

      const alpha = await upsertWallet(primaryCtx, {
        id: 'wallet-d1-shared',
        projectId: 'project-d1-wallets',
        environmentId: 'env-d1-wallets-prod',
        userId: 'user-alpha',
        externalRefId: 'external-alpha',
        address: '0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
        chain: 'Ethereum',
        walletType: 'EOA',
        status: 'ACTIVE',
        policyId: 'policy-alpha',
        balanceMinor: 500,
        lastActivityAt: '2026-06-27T00:31:00.000Z',
        createdAt: '2026-06-27T00:30:00.000Z',
        updatedAt: '2026-06-27T00:31:00.000Z',
      });
      expect(alpha).toMatchObject({
        id: 'wallet-d1-shared',
        orgId: primaryCtx.orgId,
        chain: 'Ethereum',
        walletType: 'EOA',
        status: 'ACTIVE',
        balanceMinor: 500,
        lastActivityAt: '2026-06-27T00:31:00.000Z',
      });

      await upsertWallet(primaryCtx, {
        id: 'wallet-d1-beta',
        projectId: 'project-d1-wallets',
        environmentId: 'env-d1-wallets-prod',
        userId: 'user-beta',
        externalRefId: 'external-beta',
        address: '0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb',
        chain: 'Base',
        walletType: 'SMART',
        status: 'FROZEN',
        policyId: 'policy-beta',
        balanceMinor: 2_500,
        lastActivityAt: '2026-06-27T00:35:00.000Z',
        createdAt: '2026-06-27T00:32:00.000Z',
        updatedAt: '2026-06-27T00:35:00.000Z',
      });
      await upsertWallet(primaryCtx, {
        id: 'wallet-d1-gamma',
        projectId: 'project-d1-wallets',
        environmentId: 'env-d1-wallets-dev',
        userId: 'user-gamma',
        externalRefId: 'external-gamma',
        address: '0xcccccccccccccccccccccccccccccccccccccccc',
        chain: 'NEAR',
        walletType: 'EOA',
        status: 'ARCHIVED',
        balanceMinor: 1_000,
        lastActivityAt: null,
        createdAt: '2026-06-27T00:34:00.000Z',
        updatedAt: '2026-06-27T00:36:00.000Z',
      });
      const secondaryWallet = await upsertWallet(secondaryCtx, {
        id: 'wallet-d1-shared',
        projectId: 'project-d1-wallets-other',
        environmentId: 'env-d1-wallets-other-prod',
        userId: 'user-secondary',
        externalRefId: 'external-secondary',
        address: '0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
        chain: 'Ethereum',
        walletType: 'EOA',
        status: 'ACTIVE',
        balanceMinor: 9_999,
      });
      expect(secondaryWallet.orgId).toBe(secondaryCtx.orgId);

      await expect(service.getWallet(primaryCtx, 'wallet-d1-shared')).resolves.toMatchObject({
        orgId: primaryCtx.orgId,
        userId: 'user-alpha',
      });
      await expect(service.getWallet(secondaryCtx, 'wallet-d1-shared')).resolves.toMatchObject({
        orgId: secondaryCtx.orgId,
        userId: 'user-secondary',
      });
      await expect(service.listWallets(secondaryCtx)).resolves.toMatchObject({
        items: [expect.objectContaining({ id: 'wallet-d1-shared' })],
      });

      await expect(
        service.listWallets(primaryCtx, {
          environmentId: 'env-d1-wallets-prod',
          chain: 'Base',
          walletType: 'SMART',
          status: 'FROZEN',
          policyId: 'policy-beta',
          userId: 'user-beta',
          externalRefId: 'external-beta',
        }),
      ).resolves.toEqual({
        items: [expect.objectContaining({ id: 'wallet-d1-beta' })],
      });
      await expect(
        service.searchWallets(primaryCtx, {
          q: 'BBBB',
          limit: 10,
        }),
      ).resolves.toEqual({
        items: [expect.objectContaining({ id: 'wallet-d1-beta' })],
      });
      await expect(
        service.searchWallets(primaryCtx, {
          q: 'external-gamma',
          limit: 10,
        }),
      ).resolves.toEqual({
        items: [expect.objectContaining({ id: 'wallet-d1-gamma' })],
      });

      const firstBalancePage = await service.listWallets(primaryCtx, {
        sortBy: 'balance',
        sortOrder: 'desc',
        limit: 2,
      });
      expect(firstBalancePage.items.map((wallet) => wallet.id)).toEqual([
        'wallet-d1-beta',
        'wallet-d1-gamma',
      ]);
      expect(firstBalancePage.nextCursor).toBeTruthy();
      const secondBalancePage = await service.listWallets(primaryCtx, {
        sortBy: 'balance',
        sortOrder: 'desc',
        limit: 2,
        cursor: firstBalancePage.nextCursor,
      });
      expect(secondBalancePage.items.map((wallet) => wallet.id)).toEqual(['wallet-d1-shared']);

      await expect(
        service.listWallets(primaryCtx, {
          sortBy: 'createdAt',
          sortOrder: 'desc',
          cursor: firstBalancePage.nextCursor,
        }),
      ).rejects.toMatchObject({ code: 'invalid_query' });

      nowMsValue = Date.parse('2026-06-27T00:40:00.000Z');
      const updatedAlpha = await upsertWallet(primaryCtx, {
        id: 'wallet-d1-shared',
        projectId: 'project-d1-wallets',
        environmentId: 'env-d1-wallets-prod',
        userId: 'user-alpha',
        externalRefId: 'external-alpha',
        address: '0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
        chain: 'Ethereum',
        walletType: 'EOA',
        status: 'ARCHIVED',
        balanceMinor: 750,
        lastActivityAt: '2026-06-27T00:39:00.000Z',
      });
      expect(updatedAlpha).toMatchObject({
        id: 'wallet-d1-shared',
        status: 'ARCHIVED',
        balanceMinor: 750,
        createdAt: '2026-06-27T00:30:00.000Z',
        updatedAt: '2026-06-27T00:40:00.000Z',
      });

      await expect(
        upsertWallet(primaryCtx, {
          id: 'wallet-d1-conflict',
          projectId: 'project-d1-wallets',
          environmentId: 'env-d1-wallets-prod',
          userId: 'user-conflict',
          externalRefId: 'external-conflict',
          address: '0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb',
          chain: 'Base',
        }),
      ).rejects.toMatchObject({ code: 'wallet_address_conflict' });
    } finally {
      cleanupTemporaryD1Database(temp.tempDir);
    }
  });

  test('API key adapter scopes tenants and authenticates hashed D1 credentials', async () => {
    const temp = createTemporaryD1Database();
    try {
      let nowMsValue = Date.parse('2026-06-27T01:00:00.000Z');
      const service = await createD1ConsoleApiKeyService({
        database: temp.database,
        namespace: 'd1-contracts',
        ensureSchema: true,
        now: () => new Date(nowMsValue),
      });
      const primaryCtx = {
        orgId: 'org-d1-api-keys-primary',
        actorUserId: 'user-d1-api-keys-primary',
        roles: ['admin'],
      };
      const secondaryCtx = {
        orgId: 'org-d1-api-keys-secondary',
        actorUserId: 'user-d1-api-keys-secondary',
        roles: ['admin'],
      };

      const createdSecretKey = await service.createApiKey(primaryCtx, {
        kind: 'secret_key',
        name: 'D1 Server Key',
        environmentId: 'env-d1-api-prod',
        scopes: ['wallets.read', 'accounts.create'],
        ipAllowlist: ['203.0.113.0/24'],
      });
      expect(createdSecretKey.secret).toMatch(/^sk_/);
      await expect(service.listApiKeys(primaryCtx)).resolves.toHaveLength(1);
      await expect(service.listApiKeys(secondaryCtx)).resolves.toHaveLength(0);
      await expect(
        service.updateApiKey(secondaryCtx, createdSecretKey.apiKey.id, {
          name: 'Cross Tenant Rename',
        }),
      ).resolves.toBeNull();

      const authenticateApiKey = service.authenticateApiKey;
      if (!authenticateApiKey) throw new Error('D1 API key adapter must expose secret auth');
      const authOk = await authenticateApiKey({
        secret: createdSecretKey.secret,
        endpoint: '/v1/wallets',
        requiredScopes: ['wallets.read'],
        sourceIp: '203.0.113.42',
        environmentId: 'env-d1-api-prod',
      });
      expect(authOk.ok).toBe(true);
      if (!authOk.ok) throw new Error(authOk.message);
      expect(authOk.apiKey.endpointUsageCounts['/v1/wallets']).toBe(1);
      expect(authOk.apiKey.lastUsedAt).toBe('2026-06-27T01:00:00.000Z');

      nowMsValue = Date.parse('2026-06-27T01:01:00.000Z');
      const scopeDenied = await authenticateApiKey({
        secret: createdSecretKey.secret,
        endpoint: '/v1/wallets/signers',
        requiredScopes: ['wallets.signers.create'],
        sourceIp: '203.0.113.42',
        environmentId: 'env-d1-api-prod',
      });
      expect(scopeDenied).toMatchObject({
        ok: false,
        status: 403,
        code: 'secret_key_forbidden_scope',
      });
      const afterScopeDenied = await service.listApiKeys(primaryCtx);
      expect(afterScopeDenied[0]?.anomalyFlags).toContain('auth.scope_denied');

      const updatedSecretKey = await service.updateApiKey(primaryCtx, createdSecretKey.apiKey.id, {
        name: 'D1 Server Key Renamed',
        scopes: ['wallets.read'],
        ipAllowlist: ['203.0.113.42'],
      });
      expect(updatedSecretKey).toMatchObject({
        id: createdSecretKey.apiKey.id,
        name: 'D1 Server Key Renamed',
        scopes: ['wallets.read'],
        ipAllowlist: ['203.0.113.42'],
      });

      const rotatedSecretKey = await service.rotateApiKey(primaryCtx, createdSecretKey.apiKey.id);
      expect(rotatedSecretKey?.apiKey.secretVersion).toBe(2);
      expect(rotatedSecretKey?.secret).toMatch(/^sk_/);
      expect(rotatedSecretKey?.secret).not.toBe(createdSecretKey.secret);
      const staleSecretAuth = await authenticateApiKey({
        secret: createdSecretKey.secret,
        endpoint: '/v1/wallets',
        requiredScopes: ['wallets.read'],
        sourceIp: '203.0.113.42',
        environmentId: 'env-d1-api-prod',
      });
      expect(staleSecretAuth).toMatchObject({
        ok: false,
        status: 401,
        code: 'secret_key_invalid',
      });

      const createdPublishableKey = await service.createApiKey(primaryCtx, {
        kind: 'publishable_key',
        name: 'D1 Browser Key',
        environmentId: 'env-d1-api-prod',
        allowedOrigins: ['https://app.example.com'],
        rateLimitBucket: 'browser-default',
        quotaBucket: 'prepaid-default',
        riskPolicy: { mode: 'standard' },
        paymentPolicy: { billing: 'prepaid' },
      });
      expect(createdPublishableKey.secret).toMatch(/^pk_/);

      const authenticatePublishableKey = service.authenticatePublishableKey;
      if (!authenticatePublishableKey) {
        throw new Error('D1 API key adapter must expose publishable auth');
      }
      nowMsValue = Date.parse('2026-06-27T01:02:00.000Z');
      const publishableAuthOk = await authenticatePublishableKey({
        secret: createdPublishableKey.secret,
        origin: 'https://app.example.com',
        environmentId: 'env-d1-api-prod',
      });
      expect(publishableAuthOk.ok).toBe(true);
      if (!publishableAuthOk.ok) throw new Error(publishableAuthOk.message);
      expect(publishableAuthOk.apiKey.lastUsedAt).toBe('2026-06-27T01:02:00.000Z');

      const blockedOrigin = await authenticatePublishableKey({
        secret: createdPublishableKey.secret,
        origin: 'https://evil.example.com',
        environmentId: 'env-d1-api-prod',
      });
      expect(blockedOrigin).toMatchObject({
        ok: false,
        status: 403,
        code: 'publishable_key_origin_blocked',
      });

      const revoked = await service.revokeApiKey(primaryCtx, createdPublishableKey.apiKey.id, {
        reason: 'credential_rotation',
      });
      expect(revoked.apiKey).toMatchObject({
        id: createdPublishableKey.apiKey.id,
        status: 'REVOKED',
        revokedReason: 'credential_rotation',
      });
      await expect(
        service.rotateApiKey(primaryCtx, createdPublishableKey.apiKey.id),
      ).rejects.toMatchObject({ code: 'api_key_revoked' });

      const deleted = await service.deleteApiKey(primaryCtx, createdPublishableKey.apiKey.id);
      expect(deleted).toMatchObject({
        deleted: true,
        apiKey: expect.objectContaining({ id: createdPublishableKey.apiKey.id }),
      });
      const remaining = await service.listApiKeys(primaryCtx);
      expect(remaining.map((apiKey) => apiKey.id)).toEqual([createdSecretKey.apiKey.id]);
    } finally {
      cleanupTemporaryD1Database(temp.tempDir);
    }
  });

  test('bootstrap token adapter redeems through atomic D1 conditional updates', async () => {
    const temp = createTemporaryD1Database();
    try {
      let nowMsValue = Date.parse('2026-06-27T02:00:00.000Z');
      const service = await createD1ConsoleBootstrapTokenService({
        database: temp.database,
        namespace: 'd1-contracts',
        ensureSchema: true,
        now: () => new Date(nowMsValue),
      });
      const primaryCtx = {
        orgId: 'org-d1-bootstrap-primary',
        actorUserId: 'user-d1-bootstrap-primary',
        roles: ['admin'],
      };
      const secondaryCtx = {
        orgId: 'org-d1-bootstrap-secondary',
        actorUserId: 'user-d1-bootstrap-secondary',
        roles: ['admin'],
      };

      const created = await service.createToken(primaryCtx, {
        publishableKeyId: 'pk-d1-bootstrap',
        projectId: 'project-d1-bootstrap',
        environmentId: 'env-d1-bootstrap-prod',
        newAccountId: 'account-d1-bootstrap',
        rpId: 'app.example.com',
        origin: 'https://app.example.com',
        method: 'post',
        path: '/wallets/register/intent',
        allowedPaths: ['/wallets/register/intent', '/wallets/register/complete'],
        requestHashSha256: 'request-hash-d1-bootstrap',
        maxUses: 2,
        ttlMs: 60_000,
        riskDecision: 'allow',
        paymentReference: 'billing-reservation-d1-bootstrap',
      });
      expect(created.token).toMatch(/^tbt_v1_/);
      expect(created.record).toMatchObject({
        orgId: primaryCtx.orgId,
        publishableKeyId: 'pk-d1-bootstrap',
        method: 'POST',
        maxUses: 2,
        usedCount: 0,
        status: 'issued',
      });
      expect(created.record.allowedPaths).toEqual([
        '/wallets/register/intent',
        '/wallets/register/complete',
      ]);

      await expect(
        service.countIssued(primaryCtx, { publishableKeyId: 'pk-d1-bootstrap' }),
      ).resolves.toBe(1);
      await expect(
        service.countIssued(secondaryCtx, { publishableKeyId: 'pk-d1-bootstrap' }),
      ).resolves.toBe(0);
      await expect(
        service.countIssued(primaryCtx, {
          publishableKeyId: 'pk-d1-bootstrap',
          issuedSince: '2026-06-27T02:00:01.000Z',
        }),
      ).resolves.toBe(0);

      const peeked = await service.peekTokenRecord(created.token);
      expect(peeked).toMatchObject({
        id: created.record.id,
        usedCount: 0,
        status: 'issued',
      });
      await expect(service.peekTokenRecord(`${created.token}tampered`)).resolves.toBeNull();

      const originMismatch = await service.redeemToken({
        token: created.token,
        origin: 'https://evil.example.com',
        method: 'POST',
        path: '/wallets/register/intent',
        requestHashSha256: 'request-hash-d1-bootstrap',
      });
      expect(originMismatch).toMatchObject({
        ok: false,
        status: 403,
        code: 'bootstrap_token_origin_mismatch',
      });
      await expect(service.peekTokenRecord(created.token)).resolves.toMatchObject({
        usedCount: 0,
        status: 'issued',
      });

      const requestMismatch = await service.redeemToken({
        token: created.token,
        origin: 'https://app.example.com',
        method: 'POST',
        path: '/wallets/register/intent',
        requestHashSha256: 'wrong-request-hash',
      });
      expect(requestMismatch).toMatchObject({
        ok: false,
        status: 409,
        code: 'bootstrap_token_request_mismatch',
      });
      await expect(service.peekTokenRecord(created.token)).resolves.toMatchObject({
        usedCount: 0,
        status: 'issued',
      });

      const firstRedeem = await service.redeemToken({
        token: created.token,
        origin: 'https://app.example.com',
        method: 'POST',
        path: '/wallets/register/complete',
        requestHashSha256: 'request-hash-d1-bootstrap',
      });
      expect(firstRedeem).toMatchObject({
        ok: true,
        record: expect.objectContaining({
          usedCount: 1,
          status: 'issued',
          redeemedAt: '2026-06-27T02:00:00.000Z',
        }),
      });

      nowMsValue = Date.parse('2026-06-27T02:00:01.000Z');
      const secondRedeem = await service.redeemToken({
        token: created.token,
        origin: 'https://app.example.com',
        method: 'POST',
        path: '/wallets/register/intent',
        requestHashSha256: 'request-hash-d1-bootstrap',
      });
      expect(secondRedeem).toMatchObject({
        ok: true,
        record: expect.objectContaining({
          usedCount: 2,
          status: 'redeemed',
          redeemedAt: '2026-06-27T02:00:01.000Z',
        }),
      });

      const thirdRedeem = await service.redeemToken({
        token: created.token,
        origin: 'https://app.example.com',
        method: 'POST',
        path: '/wallets/register/intent',
        requestHashSha256: 'request-hash-d1-bootstrap',
      });
      expect(thirdRedeem).toMatchObject({
        ok: false,
        status: 409,
        code: 'bootstrap_token_already_used',
      });

      nowMsValue = Date.parse('2026-06-27T02:05:00.000Z');
      const expiring = await service.createToken(primaryCtx, {
        publishableKeyId: 'pk-d1-bootstrap-expiring',
        projectId: 'project-d1-bootstrap',
        environmentId: 'env-d1-bootstrap-prod',
        newAccountId: 'account-d1-bootstrap-expiring',
        rpId: 'app.example.com',
        origin: 'https://app.example.com',
        method: 'POST',
        path: '/wallets/register/intent',
        ttlMs: 1_000,
      });
      nowMsValue = Date.parse('2026-06-27T02:05:02.000Z');
      const expired = await service.redeemToken({
        token: expiring.token,
        origin: 'https://app.example.com',
        method: 'POST',
        path: '/wallets/register/intent',
      });
      expect(expired).toMatchObject({
        ok: false,
        status: 401,
        code: 'bootstrap_token_expired',
      });
      await expect(service.peekTokenRecord(expiring.token)).resolves.toMatchObject({
        usedCount: 0,
        status: 'expired',
      });
    } finally {
      cleanupTemporaryD1Database(temp.tempDir);
    }
  });

  test('approval adapter records MFA-gated decisions through D1 conditional updates', async () => {
    const temp = createTemporaryD1Database();
    try {
      let nowMsValue = Date.parse('2026-06-27T02:30:00.000Z');
      const service = await createD1ConsoleApprovalService({
        database: temp.database,
        namespace: 'd1-contracts',
        ensureSchema: true,
        now: () => new Date(nowMsValue),
      });
      const requesterCtx = {
        orgId: 'org-d1-approvals-primary',
        actorUserId: 'user-d1-approvals-requester',
        roles: ['admin'],
      };
      const approverCtx = {
        orgId: requesterCtx.orgId,
        actorUserId: 'user-d1-approvals-approver',
        roles: ['security_admin'],
      };
      const finalApproverCtx = {
        orgId: requesterCtx.orgId,
        actorUserId: 'user-d1-approvals-final-approver',
        roles: ['security_admin'],
      };
      const secondaryCtx = {
        orgId: 'org-d1-approvals-secondary',
        actorUserId: 'user-d1-approvals-secondary',
        roles: ['security_admin'],
      };

      const keyExport = await service.createApprovalRequest(requesterCtx, {
        id: 'approval-d1-key-export',
        operationType: 'KEY_EXPORT',
        reason: 'Export production root share envelope',
        projectId: 'project-d1-approvals',
        environmentId: 'env-d1-approvals-prod',
        resourceType: 'signing_root',
        resourceId: 'signing-root-d1-approvals',
        metadata: { exportFormat: 'encrypted_bundle', custodyTicket: 'ticket-42' },
      });
      expect(keyExport).toMatchObject({
        id: 'approval-d1-key-export',
        orgId: requesterCtx.orgId,
        operationType: 'KEY_EXPORT',
        status: 'PENDING',
        requestedByUserId: requesterCtx.actorUserId,
        requiredApprovals: 2,
        requireMfa: true,
        projectId: 'project-d1-approvals',
        environmentId: 'env-d1-approvals-prod',
        metadata: { exportFormat: 'encrypted_bundle', custodyTicket: 'ticket-42' },
        decisions: [],
        createdAt: '2026-06-27T02:30:00.000Z',
        resolvedAt: null,
      });

      await expect(
        service.getApprovalRequest(secondaryCtx, keyExport.id),
      ).resolves.toBeNull();
      await expect(
        service.approveApprovalRequest(secondaryCtx, keyExport.id, {
          reason: 'Cross-tenant approval',
          mfaVerified: true,
        }),
      ).resolves.toBeNull();
      await expect(service.listApprovalRequests(secondaryCtx)).resolves.toHaveLength(0);

      let duplicateCreateError: unknown = null;
      try {
        await service.createApprovalRequest(requesterCtx, {
          id: keyExport.id,
          operationType: 'KEY_EXPORT',
          reason: 'Duplicate key export request',
        });
      } catch (error: unknown) {
        duplicateCreateError = error;
      }
      expect(errorCode(duplicateCreateError)).toBe('approval_request_exists');

      let missingMfaError: unknown = null;
      try {
        await service.approveApprovalRequest(approverCtx, keyExport.id, {
          reason: 'Approve without MFA',
          mfaVerified: false,
        });
      } catch (error: unknown) {
        missingMfaError = error;
      }
      expect(errorCode(missingMfaError)).toBe('mfa_required');

      nowMsValue = Date.parse('2026-06-27T02:31:00.000Z');
      const firstApproval = await service.approveApprovalRequest(approverCtx, keyExport.id, {
        reason: 'MFA verified for custody export',
        mfaVerified: true,
      });
      expect(firstApproval).toMatchObject({
        status: 'PENDING',
        resolvedAt: null,
        decisions: [
          {
            decision: 'APPROVE',
            actorUserId: approverCtx.actorUserId,
            mfaVerified: true,
            decidedAt: '2026-06-27T02:31:00.000Z',
          },
        ],
      });

      let duplicateDecisionError: unknown = null;
      try {
        await service.approveApprovalRequest(approverCtx, keyExport.id, {
          reason: 'Duplicate approval',
          mfaVerified: true,
        });
      } catch (error: unknown) {
        duplicateDecisionError = error;
      }
      expect(errorCode(duplicateDecisionError)).toBe('already_decided');

      await expect(
        service.listApprovalRequests(requesterCtx, {
          status: 'PENDING',
          operationType: 'KEY_EXPORT',
          projectId: 'project-d1-approvals',
          environmentId: 'env-d1-approvals-prod',
        }),
      ).resolves.toEqual([expect.objectContaining({ id: keyExport.id })]);

      nowMsValue = Date.parse('2026-06-27T02:32:00.000Z');
      const finalApproval = await service.approveApprovalRequest(
        finalApproverCtx,
        keyExport.id,
        {
          reason: 'Second custody approval',
          mfaVerified: true,
        },
      );
      expect(finalApproval).toMatchObject({
        status: 'APPROVED',
        resolvedAt: '2026-06-27T02:32:00.000Z',
      });
      expect(finalApproval?.decisions).toHaveLength(2);

      let approvedRejectError: unknown = null;
      try {
        await service.rejectApprovalRequest(finalApproverCtx, keyExport.id, {
          reason: 'Too late to reject',
        });
      } catch (error: unknown) {
        approvedRejectError = error;
      }
      expect(errorCode(approvedRejectError)).toBe('invalid_state');

      await expect(
        service.listApprovalRequests(requesterCtx, { status: 'APPROVED' }),
      ).resolves.toEqual([expect.objectContaining({ id: keyExport.id })]);

      nowMsValue = Date.parse('2026-06-27T02:33:00.000Z');
      const policyPublish = await service.createApprovalRequest(requesterCtx, {
        id: 'approval-d1-policy-publish',
        operationType: 'POLICY_PUBLISH',
        reason: 'Publish production policy',
        projectId: 'project-d1-approvals',
        environmentId: 'env-d1-approvals-prod',
      });
      expect(policyPublish).toMatchObject({
        requiredApprovals: 1,
        requireMfa: false,
        status: 'PENDING',
      });

      nowMsValue = Date.parse('2026-06-27T02:34:00.000Z');
      const rejected = await service.rejectApprovalRequest(approverCtx, policyPublish.id, {
        reason: 'Policy needs another review',
      });
      expect(rejected).toMatchObject({
        status: 'REJECTED',
        resolvedAt: '2026-06-27T02:34:00.000Z',
        decisions: [
          {
            decision: 'REJECT',
            actorUserId: approverCtx.actorUserId,
            mfaVerified: false,
          },
        ],
      });

      let rejectedApproveError: unknown = null;
      try {
        await service.approveApprovalRequest(finalApproverCtx, policyPublish.id, {
          reason: 'Too late to approve',
          mfaVerified: true,
        });
      } catch (error: unknown) {
        rejectedApproveError = error;
      }
      expect(errorCode(rejectedApproveError)).toBe('invalid_state');

      await expect(
        service.listApprovalRequests(requesterCtx, { status: 'REJECTED' }),
      ).resolves.toEqual([expect.objectContaining({ id: policyPublish.id })]);
      await expect(service.listApprovalRequests(requesterCtx)).resolves.toEqual([
        expect.objectContaining({ id: policyPublish.id }),
        expect.objectContaining({ id: keyExport.id }),
      ]);
    } finally {
      cleanupTemporaryD1Database(temp.tempDir);
    }
  });

  test('key export adapter records MFA approvals through D1 conditional updates', async () => {
    const temp = createTemporaryD1Database();
    try {
      const clock = new TestMutableClock('2026-06-27T02:40:00.000Z');
      const service = await createD1ConsoleKeyExportService({
        database: temp.database,
        namespace: 'd1-contracts',
        ensureSchema: true,
        now: clock.now,
      });
      const requesterCtx = {
        orgId: 'org-d1-key-exports-primary',
        actorUserId: 'user-d1-key-exports-requester',
        roles: ['admin'],
      };
      const approverCtx = {
        orgId: requesterCtx.orgId,
        actorUserId: 'user-d1-key-exports-approver',
        roles: ['security_admin'],
      };
      const finalApproverCtx = {
        orgId: requesterCtx.orgId,
        actorUserId: 'user-d1-key-exports-final-approver',
        roles: ['security_admin'],
      };
      const secondaryCtx = {
        orgId: 'org-d1-key-exports-secondary',
        actorUserId: 'user-d1-key-exports-secondary',
        roles: ['security_admin'],
      };

      const created = await service.createKeyExport(requesterCtx, {
        id: 'key-export-d1-root',
        environmentId: 'env-d1-key-exports-prod',
        walletId: 'wallet-d1-key-export',
        mode: 'APPROVAL_REQUIRED',
        reason: 'Export encrypted root share for custody recovery',
        requiredApprovals: 2,
        constraints: {
          roles: ['owner', 'owner', 'security_admin'],
          chains: ['Base'],
          walletTypes: ['EOA'],
          environmentIds: ['env-d1-key-exports-prod'],
        },
      });
      expect(created).toMatchObject({
        id: 'key-export-d1-root',
        orgId: requesterCtx.orgId,
        environmentId: 'env-d1-key-exports-prod',
        walletId: 'wallet-d1-key-export',
        status: 'PENDING_APPROVAL',
        requestedByUserId: requesterCtx.actorUserId,
        requiredApprovals: 2,
        approvals: [],
        constraints: {
          roles: ['owner', 'security_admin'],
          chains: ['Base'],
          walletTypes: ['EOA'],
          environmentIds: ['env-d1-key-exports-prod'],
        },
        createdAt: '2026-06-27T02:40:00.000Z',
      });

      await expect(service.listKeyExports(secondaryCtx)).resolves.toHaveLength(0);
      await expect(
        service.approveKeyExport(secondaryCtx, created.id, {
          reason: 'Cross tenant approval',
          mfaVerified: true,
        }),
      ).resolves.toBeNull();

      let duplicateCreateError: unknown = null;
      try {
        await service.createKeyExport(requesterCtx, {
          id: created.id,
          environmentId: 'env-d1-key-exports-prod',
          reason: 'Duplicate export',
        });
      } catch (error: unknown) {
        duplicateCreateError = error;
      }
      expect(errorCode(duplicateCreateError)).toBe('key_export_exists');

      let missingMfaError: unknown = null;
      try {
        await service.approveKeyExport(approverCtx, created.id, {
          reason: 'Approve without MFA',
          mfaVerified: false,
        });
      } catch (error: unknown) {
        missingMfaError = error;
      }
      expect(errorCode(missingMfaError)).toBe('mfa_required');

      clock.set('2026-06-27T02:41:00.000Z');
      const firstApproval = await service.approveKeyExport(approverCtx, created.id, {
        reason: 'MFA verified',
        mfaVerified: true,
      });
      expect(firstApproval).toMatchObject({
        status: 'PENDING_APPROVAL',
        approvals: [
          {
            approverUserId: approverCtx.actorUserId,
            approvedAt: '2026-06-27T02:41:00.000Z',
            reason: 'MFA verified',
            mfaVerified: true,
          },
        ],
      });

      await expect(
        service.approveKeyExport(approverCtx, created.id, {
          reason: 'Duplicate approval',
          mfaVerified: true,
        }),
      ).rejects.toMatchObject({ code: 'already_approved' });

      await expect(
        service.listKeyExports(requesterCtx, {
          environmentId: 'env-d1-key-exports-prod',
          status: 'PENDING_APPROVAL',
        }),
      ).resolves.toEqual([expect.objectContaining({ id: created.id })]);

      clock.set('2026-06-27T02:42:00.000Z');
      const finalApproval = await service.approveKeyExport(finalApproverCtx, created.id, {
        reason: 'Second approval',
        mfaVerified: true,
      });
      expect(finalApproval).toMatchObject({
        status: 'APPROVED',
        updatedAt: '2026-06-27T02:42:00.000Z',
      });
      expect(finalApproval?.approvals).toHaveLength(2);

      await expect(
        service.approveKeyExport(finalApproverCtx, created.id, {
          reason: 'Too late',
          mfaVerified: true,
        }),
      ).rejects.toMatchObject({ code: 'invalid_state' });

      await expect(
        service.listKeyExports(requesterCtx, { status: 'APPROVED' }),
      ).resolves.toEqual([expect.objectContaining({ id: created.id })]);

      clock.set('2026-06-27T02:43:00.000Z');
      const second = await service.createKeyExport(requesterCtx, {
        id: 'key-export-d1-dev',
        environmentId: 'env-d1-key-exports-dev',
        mode: 'ALLOWED_WITH_CONSTRAINTS',
        reason: 'Development export',
        requiredApprovals: 1,
      });
      expect(second).toMatchObject({
        status: 'PENDING_APPROVAL',
        mode: 'ALLOWED_WITH_CONSTRAINTS',
        requiredApprovals: 1,
      });
      await expect(
        service.listKeyExports(requesterCtx, {
          environmentId: 'env-d1-key-exports-dev',
        }),
      ).resolves.toEqual([expect.objectContaining({ id: second.id })]);
    } finally {
      cleanupTemporaryD1Database(temp.tempDir);
    }
  });

  test('webhook adapter stores sealed secrets and records D1 delivery lifecycle', async () => {
    const temp = createTemporaryD1Database();
    try {
      const clock = new TestMutableClock('2026-06-27T02:50:00.000Z');
      const dispatcher = new D1WebhookDispatchHarness();
      const service = await createD1ConsoleWebhookService({
        database: temp.database,
        namespace: 'd1-contracts',
        ensureSchema: true,
        now: clock.now,
        dispatcher,
        secretCipher: createD1WebhookTestSecretCipher(),
        endpointDegradedThreshold: 1,
      });
      const primaryCtx = {
        orgId: 'org-d1-webhooks-primary',
        actorUserId: 'user-d1-webhooks-primary',
        roles: ['admin'],
      };
      const secondaryCtx = {
        orgId: 'org-d1-webhooks-secondary',
        actorUserId: 'user-d1-webhooks-secondary',
        roles: ['admin'],
      };

      const endpoint = await service.createEndpoint(primaryCtx, {
        url: 'https://example.com/d1-webhooks',
        eventCategories: ['billing', 'session', 'billing'],
      });
      expect(endpoint).toMatchObject({
        orgId: primaryCtx.orgId,
        url: 'https://example.com/d1-webhooks',
        eventCategories: ['billing', 'session'],
        status: 'ACTIVE',
        secretVersion: 1,
        createdAt: '2026-06-27T02:50:00.000Z',
      });
      expect(endpoint.secretPreview.startsWith('whsec_')).toBe(true);
      await expect(service.listEndpoints(secondaryCtx)).resolves.toHaveLength(0);

      const secretRow = await temp.database
        .prepare(
          `SELECT signing_secret_ciphertext_b64u, signing_secret_key_id
             FROM console_webhook_endpoints
            WHERE namespace = ?
              AND org_id = ?
              AND id = ?`,
        )
        .bind('d1-contracts', primaryCtx.orgId, endpoint.id)
        .first<SqliteJsonRow>();
      expect(String(secretRow?.signing_secret_ciphertext_b64u || '').startsWith('whsec_')).toBe(
        false,
      );
      expect(secretRow?.signing_secret_key_id).toBe('webhook-test-key-r1');

      dispatcher.pushResult({
        ok: true,
        statusCode: 202,
        responseBody: 'accepted',
      });
      clock.set('2026-06-27T02:51:00.000Z');
      const delivered = await service.emitEvent(primaryCtx, {
        eventId: 'evt-d1-webhooks-billing',
        eventType: 'billing.credit_purchase.settled',
        payload: { invoiceId: 'inv-d1-webhooks' },
      });
      expect(delivered).toEqual({
        eventId: 'evt-d1-webhooks-billing',
        attempted: 1,
        delivered: 1,
        failed: 0,
      });
      expect(dispatcher.requests).toHaveLength(1);
      expect(dispatcher.requests[0].headers['X-Console-Webhook-Signature']).toContain('v1=');
      expect(JSON.parse(dispatcher.requests[0].body)).toMatchObject({
        id: 'evt-d1-webhooks-billing',
        type: 'billing.credit_purchase.settled',
        data: { invoiceId: 'inv-d1-webhooks' },
      });

      const deliveryPage = await service.listDeliveries(primaryCtx, endpoint.id);
      expect(deliveryPage.items).toHaveLength(1);
      expect(deliveryPage.items[0]).toMatchObject({
        eventId: 'evt-d1-webhooks-billing',
        status: 'SUCCEEDED',
        attemptCount: 1,
        replayCount: 0,
        responseStatus: 202,
      });
      const attemptPage = await service.listAttempts(primaryCtx, endpoint.id, {
        deliveryId: deliveryPage.items[0].id,
      });
      expect(attemptPage.items).toEqual([
        expect.objectContaining({
          status: 'SUCCEEDED',
          responseStatus: 202,
          isReplay: false,
        }),
      ]);

      dispatcher.pushResult({
        ok: false,
        statusCode: 500,
        responseBody: 'failed',
        errorMessage: 'HTTP 500',
      });
      clock.set('2026-06-27T02:52:00.000Z');
      const failed = await service.emitEvent(primaryCtx, {
        eventId: 'evt-d1-webhooks-session',
        eventType: 'session.warm.expired',
        payload: { sessionId: 'sess-d1-webhooks' },
      });
      expect(failed).toEqual({
        eventId: 'evt-d1-webhooks-session',
        attempted: 1,
        delivered: 0,
        failed: 1,
      });

      const deadLetterPage = await service.listDeadLetters(primaryCtx, endpoint.id, {
        includeResolved: false,
      });
      expect(deadLetterPage.items).toHaveLength(1);
      expect(deadLetterPage.items[0]).toMatchObject({
        eventId: 'evt-d1-webhooks-session',
        failedAttempts: 1,
        lastResponseStatus: 500,
        resolvedAt: null,
      });

      dispatcher.pushResult({
        ok: true,
        statusCode: 200,
        responseBody: 'replayed',
      });
      clock.set('2026-06-27T02:53:00.000Z');
      const replay = await service.replayDelivery(primaryCtx, endpoint.id, {
        deliveryId: deadLetterPage.items[0].deliveryId,
      });
      expect(replay).toMatchObject({
        replayed: true,
        delivery: {
          status: 'SUCCEEDED',
          attemptCount: 2,
          replayCount: 1,
          responseStatus: 200,
        },
      });

      await expect(
        service.listDeadLetters(primaryCtx, endpoint.id, { includeResolved: false }),
      ).resolves.toEqual({ items: [] });
      await expect(
        service.listDeadLetters(primaryCtx, endpoint.id, { includeResolved: true }),
      ).resolves.toEqual({
        items: [expect.objectContaining({ resolvedAt: '2026-06-27T02:53:00.000Z' })],
      });

      const disabled = await service.updateEndpoint(primaryCtx, endpoint.id, {
        status: 'DISABLED',
        eventCategories: ['billing'],
      });
      expect(disabled).toMatchObject({
        status: 'DISABLED',
        eventCategories: ['billing'],
      });
      const skipped = await service.emitEvent(primaryCtx, {
        eventId: 'evt-d1-webhooks-disabled',
        eventType: 'billing.credit_purchase.settled',
        payload: {},
      });
      expect(skipped).toEqual({
        eventId: 'evt-d1-webhooks-disabled',
        attempted: 0,
        delivered: 0,
        failed: 0,
      });

      const removed = await service.deleteEndpoint(primaryCtx, endpoint.id);
      expect(removed).toMatchObject({
        removed: true,
        endpoint: { id: endpoint.id },
      });
      await expect(service.listEndpoints(primaryCtx)).resolves.toEqual([]);
    } finally {
      cleanupTemporaryD1Database(temp.tempDir);
    }
  });

  test('webhook D1 retry dispatch claims failed deliveries before sending', async () => {
    const temp = createTemporaryD1Database();
    try {
      const clock = new TestMutableClock('2026-06-27T03:00:00.000Z');
      const namespace = 'd1-contracts';
      const orgId = 'org-d1-webhook-retry';
      const secretCipher = createD1WebhookTestSecretCipher();
      const initialDispatcher = new D1WebhookDispatchHarness();
      const service = await createD1ConsoleWebhookService({
        database: temp.database,
        namespace,
        ensureSchema: true,
        now: clock.now,
        dispatcher: initialDispatcher,
        secretCipher,
      });
      const ctx = {
        orgId,
        actorUserId: 'user-d1-webhook-retry',
        roles: ['admin'],
      };

      const endpoint = await service.createEndpoint(ctx, {
        url: 'https://example.com/d1-webhook-retry',
        eventCategories: ['billing'],
      });
      initialDispatcher.pushResult({
        ok: false,
        statusCode: 503,
        responseBody: 'unavailable',
        errorMessage: 'HTTP 503',
      });
      clock.set('2026-06-27T03:01:00.000Z');
      await expect(
        service.emitEvent(ctx, {
          eventId: 'evt-d1-webhook-retry',
          eventType: 'billing.credit_purchase.settled',
          payload: { invoiceId: 'inv-d1-webhook-retry' },
        }),
      ).resolves.toMatchObject({
        attempted: 1,
        delivered: 0,
        failed: 1,
      });

      const failedDeliveryPage = await service.listDeliveries(ctx, endpoint.id);
      expect(failedDeliveryPage.items).toEqual([
        expect.objectContaining({
          status: 'FAILED',
          attemptCount: 1,
        }),
      ]);

      clock.set('2026-06-27T03:02:00.000Z');
      const retryHarness = new D1WebhookRetryRaceHarness({
        database: temp.database,
        namespace,
        orgId,
        secretCipher,
        now: clock.now,
      });
      const retryResult = await runD1ConsoleWebhookRetryDispatch({
        database: temp.database,
        namespace,
        orgIds: [orgId],
        secretCipher,
        ensureSchema: false,
        now: clock.now,
        dispatcher: retryHarness,
        initialBackoffMs: 0,
        maxBackoffMs: 0,
        workerId: 'webhook-retry-worker-a',
      });

      expect(retryResult).toMatchObject({
        attemptedCount: 1,
        deliveredCount: 1,
        failedCount: 0,
      });
      expect(retryHarness.competitorResult).toMatchObject({
        attemptedCount: 0,
        skippedCount: 0,
      });
      expect(retryHarness.requests.map(webhookDispatchEventId)).toEqual([
        'evt-d1-webhook-retry',
      ]);
      await expect(service.listDeliveries(ctx, endpoint.id)).resolves.toMatchObject({
        items: [
          expect.objectContaining({
            status: 'SUCCEEDED',
            attemptCount: 2,
            replayCount: 0,
            responseStatus: 200,
          }),
        ],
      });
      await expect(
        service.listDeadLetters(ctx, endpoint.id, { includeResolved: false }),
      ).resolves.toEqual({ items: [] });
    } finally {
      cleanupTemporaryD1Database(temp.tempDir);
    }
  });

  test('observability adapter stores compact D1 incident events and request rollups', async () => {
    const temp = createTemporaryD1Database();
    try {
      const clock = new TestMutableClock('2026-06-27T03:05:00.000Z');
      const ingestion = await createD1ConsoleObservabilityIngestionService({
        database: temp.database,
        namespace: 'd1-contracts',
        ensureSchema: true,
        now: clock.now,
        redactionPolicy: {
          denylistKeys: ['token'],
          replacement: '[masked]',
          redactionVersion: 3,
        },
      });
      const service = await createD1ConsoleObservabilityService({
        database: temp.database,
        namespace: 'd1-contracts',
        ensureSchema: false,
        now: clock.now,
      });
      const primaryCtx = {
        orgId: 'org-d1-observability-primary',
        actorUserId: 'user-d1-observability-primary',
        roles: ['ops'],
      };
      const secondaryCtx = {
        orgId: 'org-d1-observability-secondary',
        actorUserId: 'user-d1-observability-secondary',
        roles: ['ops'],
      };

      const appendResult = await ingestion.appendEvent(primaryCtx, {
        eventId: 'evt-d1-observability-dead-letter',
        schemaVersion: 1,
        source: 'WEBHOOK',
        ingestedAtMs: Date.parse('2026-06-27T03:01:00.000Z'),
        timestamp: '2026-06-27T03:01:00.000Z',
        orgId: primaryCtx.orgId,
        service: 'webhooks',
        component: 'delivery_dispatch',
        level: 'ERROR',
        eventType: 'webhook.delivery.dead_letter',
        message: 'Webhook delivery moved to DLQ',
        requestId: 'req-d1-observability',
        traceId: 'trace-d1-observability',
        metadata: {
          deliveryId: 'delivery-d1-observability',
          token: 'should-not-persist',
        },
        redactionVersion: 1,
        redactionApplied: false,
      });
      expect(appendResult).toEqual({ accepted: 1, deduplicated: 0 });
      await expect(
        ingestion.appendEvent(primaryCtx, {
          eventId: 'evt-d1-observability-dead-letter',
          schemaVersion: 1,
          source: 'WEBHOOK',
          ingestedAtMs: Date.parse('2026-06-27T03:01:00.000Z'),
          timestamp: '2026-06-27T03:01:00.000Z',
          orgId: primaryCtx.orgId,
          service: 'webhooks',
          component: 'delivery_dispatch',
          level: 'ERROR',
          eventType: 'webhook.delivery.dead_letter',
          message: 'Duplicate dead letter',
          metadata: {},
          redactionVersion: 1,
          redactionApplied: false,
        }),
      ).resolves.toEqual({ accepted: 0, deduplicated: 1 });

      await ingestion.observeRequestMetric(primaryCtx, {
        orgId: primaryCtx.orgId,
        projectId: 'project-d1-observability',
        environmentId: 'env-d1-observability',
        route: '/console/webhooks/wh_1/replay',
        method: 'POST',
        statusCode: 500,
        latencyMs: 420,
        timestamp: '2026-06-27T03:02:00.000Z',
      });
      await ingestion.observeRequestMetric(primaryCtx, {
        orgId: primaryCtx.orgId,
        projectId: 'project-d1-observability',
        environmentId: 'env-d1-observability',
        route: '/console/webhooks',
        method: 'GET',
        statusCode: 200,
        latencyMs: 100,
        timestamp: '2026-06-27T03:03:00.000Z',
      });

      const summary = await service.getSummary(primaryCtx, {
        from: '2026-06-27T03:00:00.000Z',
        to: '2026-06-27T03:10:00.000Z',
      });
      expect(summary).toMatchObject({
        status: { state: 'ok' },
        errorRate: 1,
        p95LatencyMs: 500,
        failingServices: 1,
        deadLetterCount: 1,
      });

      await expect(
        service.getSummary(secondaryCtx, {
          from: '2026-06-27T03:00:00.000Z',
          to: '2026-06-27T03:10:00.000Z',
        }),
      ).resolves.toMatchObject({
        errorRate: 0,
        failingServices: 0,
        deadLetterCount: 0,
      });

      const events = await service.listEvents(primaryCtx, {
        from: '2026-06-27T03:00:00.000Z',
        to: '2026-06-27T03:10:00.000Z',
        query: 'DLQ',
        limit: 10,
      });
      expect(events).toMatchObject({
        status: { state: 'ok' },
        totalPages: 1,
      });
      expect(events.events).toEqual([
        expect.objectContaining({
          id: 'evt-d1-observability-dead-letter',
          orgId: primaryCtx.orgId,
          service: 'webhooks',
          level: 'ERROR',
          eventType: 'webhook.delivery.dead_letter',
          metadata: {
            deliveryId: 'delivery-d1-observability',
            token: '[masked]',
          },
        }),
      ]);

      const services = await service.listServices(primaryCtx, {
        from: '2026-06-27T03:00:00.000Z',
        to: '2026-06-27T03:10:00.000Z',
      });
      expect(services.services).toEqual([
        expect.objectContaining({
          service: 'webhooks',
          status: 'DEGRADED',
          recentFailureCount: 2,
        }),
      ]);

      const timeseries = await service.getTimeseries(primaryCtx, {
        from: '2026-06-27T03:00:00.000Z',
        to: '2026-06-27T03:10:00.000Z',
        service: 'webhooks',
        bucketMinutes: 5,
      });
      expect(
        timeseries.buckets.filter((bucket) => bucket.requestCount > 0),
      ).toEqual([
        expect.objectContaining({
          errorCount: 1,
          requestCount: 1,
          p95LatencyMs: 500,
        }),
      ]);
    } finally {
      cleanupTemporaryD1Database(temp.tempDir);
    }
  });

  test('audit adapter stores append-only events and evidence with tenant filters', async () => {
    const temp = createTemporaryD1Database();
    try {
      let nowMsValue = Date.parse('2026-06-27T03:00:00.000Z');
      const service = await createD1ConsoleAuditService({
        database: temp.database,
        namespace: 'd1-contracts',
        ensureSchema: true,
        now: () => new Date(nowMsValue),
      });
      const primaryCtx = {
        orgId: 'org-d1-audit-primary',
        actorUserId: 'user-d1-audit-primary',
        roles: ['security_admin'],
      };
      const secondaryCtx = {
        orgId: 'org-d1-audit-secondary',
        actorUserId: 'user-d1-audit-secondary',
        roles: ['security_admin'],
      };

      const policyEvent = await service.appendEvent(primaryCtx, {
        id: 'aud-d1-policy-publish',
        projectId: 'project-d1-audit',
        environmentId: 'env-d1-audit-prod',
        category: 'POLICY',
        action: 'policy.publish',
        outcome: 'SUCCESS',
        summary: 'Published policy to production',
        metadata: { policyId: 'policy-d1-audit', version: 7 },
      });
      expect(policyEvent).toMatchObject({
        orgId: primaryCtx.orgId,
        actorUserId: primaryCtx.actorUserId,
        actorType: 'USER',
        metadata: { policyId: 'policy-d1-audit', version: 7 },
        createdAt: '2026-06-27T03:00:00.000Z',
      });

      nowMsValue = Date.parse('2026-06-27T03:05:00.000Z');
      const billingEvent = await service.appendEvent(primaryCtx, {
        id: 'aud-d1-billing-failure',
        projectId: 'project-d1-audit',
        environmentId: 'env-d1-audit-dev',
        actorUserId: 'system-billing',
        actorType: 'SYSTEM',
        category: 'BILLING',
        action: 'billing.webhook.failed',
        outcome: 'FAILURE',
        summary: 'Stripe webhook failed reconciliation',
        metadata: { providerRef: 'evt-d1-audit', retryable: true },
      });
      expect(billingEvent.actorType).toBe('SYSTEM');

      await expect(service.listEvents(secondaryCtx)).resolves.toHaveLength(0);
      await expect(service.listEvents(primaryCtx, { limit: 1 })).resolves.toEqual([
        expect.objectContaining({ id: billingEvent.id }),
      ]);
      await expect(service.listEvents(primaryCtx, { category: 'POLICY' })).resolves.toEqual([
        expect.objectContaining({ id: policyEvent.id }),
      ]);
      await expect(
        service.listEvents(primaryCtx, {
          projectId: 'project-d1-audit',
          environmentId: 'env-d1-audit-dev',
          outcome: 'FAILURE',
        }),
      ).resolves.toEqual([expect.objectContaining({ id: billingEvent.id })]);
      await expect(service.listEvents(primaryCtx, { q: 'stripe webhook' })).resolves.toEqual([
        expect.objectContaining({ id: billingEvent.id }),
      ]);
      await expect(
        service.listEvents(primaryCtx, {
          from: '2026-06-27T03:01:00.000Z',
          to: '2026-06-27T03:06:00.000Z',
        }),
      ).resolves.toEqual([expect.objectContaining({ id: billingEvent.id })]);

      let duplicateEventError: unknown = null;
      try {
        await service.appendEvent(primaryCtx, {
          id: policyEvent.id,
          category: 'POLICY',
          action: 'policy.publish',
          outcome: 'SUCCESS',
          summary: 'Duplicate policy event',
        });
      } catch (error: unknown) {
        duplicateEventError = error;
      }
      expect(errorCode(duplicateEventError)).toBe('event_already_exists');

      nowMsValue = Date.parse('2026-06-27T03:10:00.000Z');
      const evidence = await service.appendEvidence(primaryCtx, {
        id: 'evd-d1-policy-bundle',
        projectId: 'project-d1-audit',
        environmentId: 'env-d1-audit-prod',
        domain: 'POLICY',
        title: 'Policy publish evidence',
        summary: 'Policy publish evidence bundle',
        eventIds: [policyEvent.id, policyEvent.id, billingEvent.id],
        references: [
          { kind: 'APPROVAL', referenceId: 'approval-d1-audit', label: 'Approval request' },
          { kind: 'APPROVAL', referenceId: 'approval-d1-audit', label: 'Approval request' },
          { kind: 'LOG', referenceId: 'policy-d1-audit:v7', label: 'Policy version log' },
        ],
      });
      expect(evidence.eventIds).toEqual([policyEvent.id, billingEvent.id]);
      expect(evidence.references).toEqual([
        { kind: 'APPROVAL', referenceId: 'approval-d1-audit', label: 'Approval request' },
        { kind: 'LOG', referenceId: 'policy-d1-audit:v7', label: 'Policy version log' },
      ]);
      await expect(service.listEvidence(primaryCtx, { domain: 'POLICY' })).resolves.toEqual([
        expect.objectContaining({ id: evidence.id }),
      ]);
      await expect(
        service.listEvidence(primaryCtx, { environmentId: 'env-d1-audit-dev' }),
      ).resolves.toHaveLength(0);
      await expect(service.listEvidence(secondaryCtx)).resolves.toHaveLength(0);

      let duplicateEvidenceError: unknown = null;
      try {
        await service.appendEvidence(primaryCtx, {
          id: evidence.id,
          domain: 'POLICY',
          title: 'Duplicate evidence',
          summary: 'Duplicate evidence bundle',
        });
      } catch (error: unknown) {
        duplicateEvidenceError = error;
      }
      expect(errorCode(duplicateEvidenceError)).toBe('evidence_already_exists');
    } finally {
      cleanupTemporaryD1Database(temp.tempDir);
    }
  });

  test('team RBAC adapter preserves owner and member lifecycle invariants', async () => {
    const temp = createTemporaryD1Database();
    try {
      const service = await createD1ConsoleTeamRbacService({
        database: temp.database,
        namespace: 'd1-contracts',
        ensureSchema: true,
        now: () => new Date('2026-06-27T00:00:00.000Z'),
      });
      const ownerCtx = {
        orgId: 'org-d1-team-rbac',
        actorUserId: 'user-d1-owner',
        roles: [],
        actorEmail: 'owner-d1-team@example.com',
        actorDisplayName: 'D1 Owner',
      };
      const ownerClaimCtx = {
        ...ownerCtx,
        roles: ['owner'],
      };

      const owner = await service.bootstrapOwner(ownerCtx);
      expect(owner.roles.map((entry) => entry.role)).toContain('owner');

      let forbiddenOwnerInviteError: unknown = null;
      try {
        await service.inviteMember(ownerCtx, {
          userId: 'user-d1-forbidden-owner',
          email: 'forbidden-owner@example.com',
          roles: [{ role: 'owner', scope: 'ORG' }],
        });
      } catch (error: unknown) {
        forbiddenOwnerInviteError = error;
      }
      expect(errorCode(forbiddenOwnerInviteError)).toBe('forbidden');

      const admin = await service.inviteMember(ownerClaimCtx, {
        userId: 'user-d1-admin',
        email: 'admin-d1-team@example.com',
        displayName: 'D1 Admin',
        roles: [{ role: 'admin', scope: 'ORG' }],
      });
      expect(admin.status).toBe('ACTIVE');
      expect(admin.roles.map((entry) => entry.role)).toEqual(['admin']);

      let duplicateMemberError: unknown = null;
      try {
        await service.inviteMember(ownerClaimCtx, {
          userId: 'user-d1-admin-copy',
          email: 'admin-d1-team@example.com',
          roles: [{ role: 'billing_read', scope: 'ORG' }],
        });
      } catch (error: unknown) {
        duplicateMemberError = error;
      }
      expect(errorCode(duplicateMemberError)).toBe('member_already_exists');

      let lastOwnerRoleError: unknown = null;
      try {
        await service.updateMemberRoles(ownerClaimCtx, owner.id, {
          roles: [{ role: 'admin', scope: 'ORG' }],
        });
      } catch (error: unknown) {
        lastOwnerRoleError = error;
      }
      expect(errorCode(lastOwnerRoleError)).toBe('last_owner_required');

      const transfer = await service.transferOwner(ownerClaimCtx, admin.id);
      expect(transfer.previousOwner.roles.map((entry) => entry.role)).toEqual(['admin']);
      expect(transfer.nextOwner.roles.map((entry) => entry.role)).toEqual(['admin', 'owner']);

      let lastOwnerRemoveError: unknown = null;
      try {
        await service.removeMember(
          {
            ...ownerClaimCtx,
            actorUserId: admin.userId,
            actorEmail: admin.email,
          },
          admin.id,
        );
      } catch (error: unknown) {
        lastOwnerRemoveError = error;
      }
      expect(errorCode(lastOwnerRemoveError)).toBe('last_owner_required');

      const removedPreviousOwner = await service.removeMember(
        {
          ...ownerClaimCtx,
          actorUserId: admin.userId,
          actorEmail: admin.email,
        },
        owner.id,
      );
      expect(removedPreviousOwner.removed).toBe(true);
      expect(removedPreviousOwner.member?.status).toBe('REMOVED');

      const restored = await service.inviteMember(
        {
          ...ownerClaimCtx,
          actorUserId: admin.userId,
          actorEmail: admin.email,
        },
        {
          userId: owner.userId,
          email: owner.email,
          roles: [{ role: 'billing_read', scope: 'ORG' }],
        },
      );
      expect(restored.id).toBe(owner.id);
      expect(restored.status).toBe('ACTIVE');
      expect(restored.roles.map((entry) => entry.role)).toEqual(['billing_read']);

      const activeMembers = service.listOrganizationMembers
        ? await service.listOrganizationMembers('org-d1-team-rbac', { status: 'ACTIVE' })
        : [];
      expect(activeMembers).toHaveLength(2);
      const otherOrgMembers = service.listOrganizationMembers
        ? await service.listOrganizationMembers('org-d1-team-rbac-other')
        : [];
      expect(otherOrgMembers).toEqual([]);
    } finally {
      cleanupTemporaryD1Database(temp.tempDir);
    }
  });

  test('policy adapter bootstraps defaults and resolves published scope precedence', async () => {
    const temp = createTemporaryD1Database();
    try {
      const service = await createD1ConsolePolicyService({
        database: temp.database,
        namespace: 'd1-contracts',
        ensureSchema: true,
        now: () => new Date('2026-06-27T00:00:00.000Z'),
      });
      const ctx = {
        orgId: 'org-d1-policies',
        actorUserId: 'user-d1-policies',
        roles: ['admin'],
      };

      const initialPolicies = await service.listPolicies(ctx);
      expect(initialPolicies).toHaveLength(1);
      const defaultPolicy = initialPolicies[0];
      expect(defaultPolicy).toMatchObject({
        orgId: ctx.orgId,
        isSystemDefault: true,
        kind: 'TRANSACTION',
        status: 'PUBLISHED',
        version: 1,
      });

      const defaultVersions = await service.listPolicyVersions(ctx, defaultPolicy.id);
      expect(defaultVersions).toEqual([
        expect.objectContaining({
          policyId: defaultPolicy.id,
          version: 1,
          actorUserId: 'system-bootstrap',
        }),
      ]);

      let defaultDeleteError: unknown = null;
      try {
        await service.deletePolicy(ctx, defaultPolicy.id);
      } catch (error: unknown) {
        defaultDeleteError = error;
      }
      expect(errorCode(defaultDeleteError)).toBe('default_policy_protected');

      const created = await service.createPolicy(ctx, {
        kind: 'TRANSACTION',
        name: 'D1 Project Policy',
        rules: {
          allowedChains: ['eip155:84532'],
          blockedActions: ['delete_wallet'],
        },
        assignment: {
          scopeType: 'PROJECT',
          scopeId: 'project-d1-policy',
        },
      });
      expect(created.status).toBe('DRAFT');
      expect(created.version).toBe(0);

      const firstPublish = await service.publishPolicy(ctx, created.id);
      expect(firstPublish?.policy).toMatchObject({
        id: created.id,
        status: 'PUBLISHED',
        version: 1,
      });

      const updated = await service.updatePolicy(ctx, created.id, {
        rules: {
          allowedChains: ['eip155:1'],
          blockedActions: ['delete_wallet'],
        },
      });
      expect(updated?.status).toBe('DRAFT');
      const secondPublish = await service.publishPolicy(ctx, created.id);
      expect(secondPublish?.policy.version).toBe(2);

      const versions = await service.listPolicyVersions(ctx, created.id);
      expect(versions?.map((version) => version.version)).toEqual([2, 1]);
      expect(versions?.map((version) => version.actorUserId)).toEqual([
        ctx.actorUserId,
        ctx.actorUserId,
      ]);

      const allowedSimulation = await service.simulatePolicy(ctx, created.id, {
        action: 'sign_transaction',
        chain: 'eip155:1',
        amountMinor: 1,
      });
      expect(allowedSimulation?.decision).toBe('ALLOW');

      const deniedSimulation = await service.simulatePolicy(ctx, created.id, {
        action: 'sign_transaction',
        chain: 'eip155:84532',
        amountMinor: 1,
      });
      expect(deniedSimulation?.decision).toBe('DENY');
      expect(deniedSimulation?.denyReasons.map((reason) => reason.code)).toContain(
        'CHAIN_NOT_ALLOWED',
      );

      const envAssignment = await service.upsertAssignment(ctx, {
        scopeType: 'ENVIRONMENT',
        scopeId: 'env-d1-policy',
        policyId: created.id,
      });
      const resolved = await service.resolvePoliciesForWallets(ctx, [
        {
          walletId: 'wallet-d1-env',
          projectId: 'project-d1-policy',
          environmentId: 'env-d1-policy',
        },
        {
          walletId: 'wallet-d1-project',
          projectId: 'project-d1-policy',
        },
        {
          walletId: 'wallet-d1-default',
        },
      ]);
      expect(resolved).toEqual({
        'wallet-d1-env': created.id,
        'wallet-d1-project': created.id,
        'wallet-d1-default': defaultPolicy.id,
      });

      const removedAssignment = await service.deleteAssignment(ctx, envAssignment.id);
      expect(removedAssignment.removed).toBe(true);
      const resolvedAfterDelete = await service.resolvePoliciesForWallets(ctx, [
        {
          walletId: 'wallet-d1-env',
          projectId: 'project-d1-policy',
          environmentId: 'env-d1-policy',
        },
      ]);
      expect(resolvedAfterDelete['wallet-d1-env']).toBe(created.id);

      const gasPolicy = await service.createPolicy(ctx, {
        kind: 'GAS_SPONSORSHIP',
        name: 'D1 Gas Policy',
        rules: {
          kind: 'evm_call',
          scopeType: 'ENVIRONMENT',
          projectId: 'project-d1-policy',
          environmentId: 'env-d1-policy',
          allowedCalls: [
            {
              chainId: 84532,
              to: '0x1111111111111111111111111111111111111111',
              functionSignature: 'mint(address)',
              maxGasLimit: '100000',
              maxValueWei: '0',
            },
          ],
        },
      });

      let gasAssignmentError: unknown = null;
      try {
        await service.upsertAssignment(ctx, {
          scopeType: 'WALLET',
          scopeId: 'wallet-d1-gas',
          policyId: gasPolicy.id,
        });
      } catch (error: unknown) {
        gasAssignmentError = error;
      }
      expect(errorCode(gasAssignmentError)).toBe('policy_assignment_unsupported');

      const otherCtx = {
        orgId: 'org-d1-policies-other',
        actorUserId: 'user-d1-policies-other',
        roles: ['admin'],
      };
      await expect(service.getPolicy(otherCtx, created.id)).resolves.toBeNull();
      const otherPolicies = await service.listPolicies(otherCtx);
      expect(otherPolicies).toHaveLength(1);
      expect(otherPolicies[0].id).not.toBe(defaultPolicy.id);
    } finally {
      cleanupTemporaryD1Database(temp.tempDir);
    }
  });

  test('billing reservations are trigger-atomic and idempotent', async () => {
    const temp = createTemporaryD1Database();
    try {
      const service = await createD1ConsoleBillingPrepaidReservationService({
        database: temp.database,
        namespace: 'd1-contracts',
        ensureSchema: true,
        now: () => new Date('2026-06-27T00:00:00.000Z'),
        defaultReservationTtlMs: 60_000,
      });
      const ctx = {
        orgId: 'org-d1-billing',
        actorUserId: 'user-d1-billing',
        roles: ['admin'],
      };

      const first = await service.reserve(ctx, {
        sourceEventId: 'reservation-source-1',
        environmentId: 'env-production',
        policyId: 'policy-sponsored-gas',
        postedBalanceMinor: 500,
        estimatedSpendMinor: 300,
      });
      expect(first.summary.reservedMinor).toBe(300);
      expect(first.summary.activeReservationCount).toBe(1);

      const duplicate = await service.reserve(ctx, {
        sourceEventId: 'reservation-source-1',
        environmentId: 'env-production',
        policyId: 'policy-sponsored-gas',
        postedBalanceMinor: 500,
        estimatedSpendMinor: 450,
      });
      expect(duplicate.reservation.id).toBe(first.reservation.id);
      expect(duplicate.summary.reservedMinor).toBe(300);
      expect(duplicate.summary.activeReservationCount).toBe(1);

      let insufficientError: unknown = null;
      try {
        await service.reserve(ctx, {
          sourceEventId: 'reservation-source-2',
          environmentId: 'env-production',
          policyId: 'policy-sponsored-gas',
          postedBalanceMinor: 500,
          estimatedSpendMinor: 250,
        });
      } catch (error: unknown) {
        insufficientError = error;
      }
      expect(errorCode(insufficientError)).toBe('prepaid_balance_insufficient');
      expect(await service.getReservationBySourceEventId(ctx, 'reservation-source-2')).toBeNull();

      const summaryAfterFailure = await service.getSummary(ctx);
      expect(summaryAfterFailure.reservedMinor).toBe(300);
      expect(summaryAfterFailure.activeReservationCount).toBe(1);

      const settled = await service.settle(ctx, {
        sourceEventId: 'reservation-source-1',
        settledSpendMinor: 175,
        txOrExecutionRef: '0xsettled',
        pricingVersion: 'static:v1',
      });
      expect(settled?.reservation.status).toBe('SETTLED');
      expect(settled?.reservation.settledMinor).toBe(175);
      expect(settled?.reservation.releasedMinor).toBe(125);
      expect(settled?.summary.reservedMinor).toBe(0);
      expect(settled?.summary.activeReservationCount).toBe(0);
    } finally {
      cleanupTemporaryD1Database(temp.tempDir);
    }
  });

  test('sponsorship spend caps reserve and settle through trigger-backed D1 windows', async () => {
    const temp = createTemporaryD1Database();
    try {
      let nowMsValue = Date.parse('2026-06-27T04:00:00.000Z');
      const service = await createD1ConsoleSponsorshipSpendCapService({
        database: temp.database,
        namespace: 'd1-contracts',
        ensureSchema: true,
        now: () => new Date(nowMsValue),
      });
      const primaryCtx = {
        orgId: 'org-d1-spend-caps-primary',
        actorUserId: 'user-d1-spend-caps-primary',
        roles: ['admin'],
      };
      const secondaryCtx = {
        orgId: 'org-d1-spend-caps-secondary',
        actorUserId: 'user-d1-spend-caps-secondary',
        roles: ['admin'],
      };

      const first = await service.reserve(primaryCtx, {
        sourceEventId: 'spend-cap-reservation-1',
        environmentId: 'env-d1-spend-caps-prod',
        policyId: 'policy-d1-sponsored-gas',
        chainId: 8453,
        mode: 'CHAIN_TOTAL',
        period: 'MONTHLY',
        capMinor: 1_000,
        estimatedSpendMinor: 400,
      });
      expect(first.reservation).toMatchObject({
        orgId: primaryCtx.orgId,
        status: 'RESERVED',
        accountRef: null,
        requestedMinor: 400,
        windowStartAt: '2026-06-01T00:00:00.000Z',
        windowEndAt: '2026-07-01T00:00:00.000Z',
      });
      expect(first.usage).toMatchObject({
        reservedMinor: 400,
        settledMinor: 0,
        availableMinor: 600,
      });

      const duplicate = await service.reserve(primaryCtx, {
        sourceEventId: 'spend-cap-reservation-1',
        environmentId: 'env-d1-spend-caps-prod',
        policyId: 'policy-d1-sponsored-gas',
        chainId: 8453,
        mode: 'CHAIN_TOTAL',
        period: 'MONTHLY',
        capMinor: 1_000,
        estimatedSpendMinor: 900,
      });
      expect(duplicate.reservation.id).toBe(first.reservation.id);
      expect(duplicate.usage).toMatchObject({
        reservedMinor: 400,
        settledMinor: 0,
        availableMinor: 600,
      });

      await expect(
        service.getReservationBySourceEventId(secondaryCtx, 'spend-cap-reservation-1'),
      ).resolves.toBeNull();
      await expect(
        service.getWindowUsage(secondaryCtx, {
          environmentId: 'env-d1-spend-caps-prod',
          policyId: 'policy-d1-sponsored-gas',
          chainId: 8453,
          mode: 'CHAIN_TOTAL',
          period: 'MONTHLY',
          at: new Date('2026-06-27T04:00:00.000Z'),
        }),
      ).resolves.toBeNull();

      let exceededError: unknown = null;
      try {
        await service.reserve(primaryCtx, {
          sourceEventId: 'spend-cap-reservation-2',
          environmentId: 'env-d1-spend-caps-prod',
          policyId: 'policy-d1-sponsored-gas',
          chainId: 8453,
          mode: 'CHAIN_TOTAL',
          period: 'MONTHLY',
          capMinor: 1_000,
          estimatedSpendMinor: 700,
        });
      } catch (error: unknown) {
        exceededError = error;
      }
      expect(errorCode(exceededError)).toBe('spend_cap_exceeded');
      await expect(
        service.getReservationBySourceEventId(primaryCtx, 'spend-cap-reservation-2'),
      ).resolves.toBeNull();

      nowMsValue = Date.parse('2026-06-27T04:05:00.000Z');
      const settled = await service.settle(primaryCtx, {
        sourceEventId: 'spend-cap-reservation-1',
        settledSpendMinor: 250,
      });
      expect(settled?.reservation).toMatchObject({
        status: 'SETTLED',
        settledMinor: 250,
        releasedMinor: 150,
        updatedAt: '2026-06-27T04:05:00.000Z',
      });
      expect(settled?.usage).toMatchObject({
        reservedMinor: 0,
        settledMinor: 250,
        availableMinor: 750,
      });

      await expect(
        service.settle(primaryCtx, {
          sourceEventId: 'spend-cap-reservation-1',
          settledSpendMinor: 250,
        }),
      ).resolves.toMatchObject({
        reservation: expect.objectContaining({ status: 'SETTLED' }),
        usage: expect.objectContaining({ settledMinor: 250 }),
      });
      await expect(
        service.settle(primaryCtx, {
          sourceEventId: 'spend-cap-reservation-1',
          settledSpendMinor: 300,
        }),
      ).rejects.toMatchObject({ code: 'invalid_state' });

      await expect(
        service.release(primaryCtx, { sourceEventId: 'spend-cap-reservation-1' }),
      ).resolves.toMatchObject({
        reservation: expect.objectContaining({ status: 'SETTLED' }),
        usage: expect.objectContaining({ settledMinor: 250 }),
      });

      nowMsValue = Date.parse('2026-06-27T04:10:00.000Z');
      const walletBucket = await service.reserve(primaryCtx, {
        sourceEventId: 'spend-cap-wallet-1',
        environmentId: 'env-d1-spend-caps-prod',
        policyId: 'policy-d1-sponsored-gas',
        accountRef: 'wallet-d1-alpha',
        chainId: 8453,
        mode: 'WALLET_CHAIN_TOTAL',
        period: 'MONTHLY',
        capMinor: 500,
        estimatedSpendMinor: 200,
      });
      expect(walletBucket.reservation.accountRef).toBe('wallet-d1-alpha');
      expect(walletBucket.usage).toMatchObject({
        reservedMinor: 200,
        settledMinor: 0,
        availableMinor: 300,
      });

      nowMsValue = Date.parse('2026-06-27T04:11:00.000Z');
      const released = await service.release(primaryCtx, {
        sourceEventId: 'spend-cap-wallet-1',
      });
      expect(released?.reservation).toMatchObject({
        status: 'RELEASED',
        releasedMinor: 200,
        updatedAt: '2026-06-27T04:11:00.000Z',
      });
      expect(released?.usage).toMatchObject({
        reservedMinor: 0,
        settledMinor: 0,
        availableMinor: 500,
      });

      await expect(
        service.settle(primaryCtx, {
          sourceEventId: 'spend-cap-wallet-1',
          settledSpendMinor: 100,
        }),
      ).rejects.toMatchObject({ code: 'invalid_state' });

      await expect(
        service.reserve(primaryCtx, {
          sourceEventId: 'spend-cap-wallet-missing-account',
          environmentId: 'env-d1-spend-caps-prod',
          policyId: 'policy-d1-sponsored-gas',
          chainId: 8453,
          mode: 'WALLET_CHAIN_TOTAL',
          period: 'MONTHLY',
          capMinor: 500,
          estimatedSpendMinor: 100,
        }),
      ).rejects.toMatchObject({ code: 'invalid_request' });
    } finally {
      cleanupTemporaryD1Database(temp.tempDir);
    }
  });

  test('billing credit purchases settle through D1 Stripe webhook idempotency', async () => {
    const temp = createTemporaryD1Database();
    try {
      const billing = await createD1ConsoleBillingService({
        database: temp.database,
        namespace: 'd1-contracts',
        ensureSchema: true,
        now: fixedD1AtomicBillingNow,
      });
      const ctx = {
        orgId: 'org-d1-billing-purchase',
        actorUserId: 'user-d1-billing-purchase',
        roles: ['admin'],
      };

      const checkout = await billing.createStripeCheckoutSession(ctx, {
        creditPackId: 'usd_10',
        successUrl: 'https://example.test/success',
        cancelUrl: 'https://example.test/cancel',
      });
      expect(checkout.amountMinor).toBe(1000);
      expect(checkout.id).toMatch(/^cs_/);

      const settled = await billing.reconcileStripeCheckoutSession(ctx, {
        checkoutSessionId: checkout.id,
      });
      expect(settled.settled).toBe(true);
      expect(settled.settledNow).toBe(true);
      expect(settled.purchase).toMatchObject({
        status: 'SETTLED',
        amountMinor: 1000,
        providerCheckoutSessionRef: checkout.id,
      });
      expect(settled.invoice).toMatchObject({
        documentType: 'PURCHASE_RECEIPT',
        status: 'PAID',
        amountDueMinor: 1000,
        amountPaidMinor: 1000,
      });

      const lineItems = await billing.listInvoiceLineItems(ctx, settled.invoice?.id || '');
      expect(lineItems).toEqual([
        expect.objectContaining({
          itemType: 'CREDIT_TOP_UP',
          quantity: 1,
          unitAmountMinor: 1000,
          amountMinor: 1000,
        }),
      ]);
      await expect(billing.getOverview(ctx)).resolves.toMatchObject({
        creditBalanceMinor: 1000,
        recentCreditPurchasedMinor: 1000,
      });

      const duplicateReconcile = await billing.reconcileStripeCheckoutSession(ctx, {
        checkoutSessionId: checkout.id,
      });
      expect(duplicateReconcile.settled).toBe(true);
      expect(duplicateReconcile.settledNow).toBe(false);

      const duplicateWebhook = await billing.processStripeWebhookEvent({
        eventId: `stripe_checkout_reconcile:${checkout.id}`,
        eventType: 'checkout.session.completed',
        orgId: ctx.orgId,
        checkoutSessionId: checkout.id,
        providerCustomerRef: checkout.customerRef,
      });
      expect(duplicateWebhook.accepted).toBe(false);
      expect(duplicateWebhook.purchase?.id).toBe(settled.purchase?.id);

      const freshWebhook = await billing.processStripeWebhookEvent({
        eventId: 'evt_d1_purchase_second_delivery',
        eventType: 'checkout.session.completed',
        orgId: ctx.orgId,
        checkoutSessionId: checkout.id,
        providerCustomerRef: checkout.customerRef,
      });
      expect(freshWebhook.accepted).toBe(true);
      expect(freshWebhook.purchase?.id).toBe(settled.purchase?.id);

      const creditActivity = await billing.listAccountActivity(ctx, {
        eventType: 'CREDIT_PURCHASE',
        limit: 10,
      });
      expect(creditActivity.entries).toHaveLength(1);
      await expect(billing.getOverview(ctx)).resolves.toMatchObject({
        creditBalanceMinor: 1000,
      });

      const invoices = await billing.listInvoicesPage(ctx, {
        documentType: 'PURCHASE_RECEIPT',
        limit: 10,
      });
      expect(invoices.totalCount).toBe(1);
      expect(invoices.summary.receiptCount).toBe(1);
    } finally {
      cleanupTemporaryD1Database(temp.tempDir);
    }
  });

  test('billing monthly finalization persists D1 usage statements idempotently', async () => {
    const temp = createTemporaryD1Database();
    try {
      const namespace = 'd1-contracts';
      const orgId = 'org-d1-billing-monthly';
      const billing = await createD1ConsoleBillingService({
        database: temp.database,
        namespace,
        ensureSchema: true,
        now: fixedD1AtomicBillingNow,
      });
      const ctx = {
        orgId,
        actorUserId: 'user-d1-billing-monthly',
        roles: ['admin'],
      };

      await temp.database
        .prepare(
          `INSERT INTO console_billing_monthly_active_wallets
            (namespace, org_id, month_utc, wallet_id, source_event_id, created_at_ms)
           VALUES
            (?, ?, ?, ?, ?, ?)`,
        )
        .bind(
          namespace,
          orgId,
          '2026-05',
          'wallet-d1-monthly-1',
          'usage-event-d1-monthly-1',
          Date.parse('2026-05-10T00:00:00.000Z'),
        )
        .run();

      const first = await runD1ConsoleBillingMonthlyFinalization({
        database: temp.database,
        namespace,
        orgIds: [orgId],
        periodMonthUtc: '2026-05',
        ensureSchema: false,
        now: fixedD1AtomicBillingNow,
      });
      expect(first).toMatchObject({
        periodMonthUtc: '2026-05',
        orgCount: 1,
        generatedCount: 1,
        skippedCount: 0,
        failures: [],
      });

      const invoices = await billing.listInvoicesPage(ctx, {
        documentType: 'USAGE_STATEMENT',
        periodMonthUtc: '2026-05',
        limit: 10,
      });
      expect(invoices.totalCount).toBe(1);
      expect(invoices.invoices[0]).toMatchObject({
        documentType: 'USAGE_STATEMENT',
        status: 'PAID',
        amountDueMinor: 300,
        amountPaidMinor: 300,
      });

      const lineItems = await billing.listInvoiceLineItems(ctx, invoices.invoices[0]?.id || '');
      expect(lineItems).toEqual([
        expect.objectContaining({
          itemType: 'MAW_USAGE_DEBIT',
          quantity: 1,
          unitAmountMinor: 300,
          amountMinor: 300,
        }),
      ]);

      const activity = await billing.listAccountActivity(ctx, {
        eventType: 'USAGE_DEBIT',
        periodMonthUtc: '2026-05',
        limit: 10,
      });
      expect(activity.entries).toHaveLength(1);
      expect(activity.entries[0]).toMatchObject({
        amountMinor: -300,
        reasonCode: 'usage_statement_reconciliation',
      });

      const second = await runD1ConsoleBillingMonthlyFinalization({
        database: temp.database,
        namespace,
        orgIds: [orgId],
        periodMonthUtc: '2026-05',
        ensureSchema: false,
        now: fixedD1AtomicBillingNow,
      });
      expect(second).toMatchObject({
        generatedCount: 0,
        skippedCount: 1,
        failures: [],
      });
      const repeatedActivity = await billing.listAccountActivity(ctx, {
        eventType: 'USAGE_DEBIT',
        periodMonthUtc: '2026-05',
        limit: 10,
      });
      expect(repeatedActivity.entries).toHaveLength(1);
    } finally {
      cleanupTemporaryD1Database(temp.tempDir);
    }
  });

  test('sponsored gas settlement writes reservation, billing, and call record in one D1 batch', async () => {
    const temp = createTemporaryD1Database();
    try {
      const namespace = 'd1-contracts';
      const billing = await createD1ConsoleBillingService({
        database: temp.database,
        namespace,
        ensureSchema: true,
        now: fixedD1AtomicBillingNow,
      });
      const prepaidReservations = await createD1ConsoleBillingPrepaidReservationService({
        database: temp.database,
        namespace,
        ensureSchema: true,
        now: fixedD1AtomicBillingNow,
        defaultReservationTtlMs: 60_000,
      });
      const sponsoredCalls = await createD1ConsoleSponsoredCallService({
        database: temp.database,
        namespace,
        ensureSchema: true,
        now: fixedD1AtomicBillingNow,
      });
      const ctx = {
        orgId: 'org-d1-atomic-sponsored',
        actorUserId: 'user-d1-atomic-sponsored',
        roles: ['platform_admin'],
      };
      const reservationSourceEventId = 'prepaid-reservation-d1-atomic';

      await billing.grantManualSupportCredit(ctx, {
        amountMinor: 1000,
        reasonCode: 'test_credit',
        note: 'Seed prepaid balance for D1 sponsored settlement',
        idempotencyKey: 'manual-credit-d1-atomic',
      });
      const overviewBeforeReservation = await billing.getOverview(ctx);
      expect(overviewBeforeReservation.creditBalanceMinor).toBe(1000);

      const reserved = await prepaidReservations.reserve(ctx, {
        sourceEventId: reservationSourceEventId,
        environmentId: 'env-production',
        policyId: 'policy-sponsored-gas',
        postedBalanceMinor: overviewBeforeReservation.creditBalanceMinor,
        estimatedSpendMinor: 700,
      });
      const pricing = new StaticSponsoredSpendPricingService(700, 425);
      const builder = new AtomicD1SponsoredRecordBuilder('sponsored-call-d1-atomic');
      const assessment = createD1AtomicAssessment();
      const record = await recordSponsoredExecution({
        billing,
        billingSourceEventIdPrefix: 'sponsored_evm_call_debit',
        context: ctx,
        ledger: sponsoredCalls,
        buildRecord: builder.build.bind(builder),
        assessment,
        walletId: 'wallet-d1-atomic',
        prepaidSettlementInput: {
          reservation: {
            sourceEventId: reservationSourceEventId,
            estimatedSpendMinor: 700,
            estimatedPricingVersion: 'static:estimate',
          },
          prepaidReservations,
          pricing,
          ctx,
          chainFamily: 'evm',
          intentKind: 'evm_call',
          executorKind: 'evm_eoa',
          environmentId: 'env-production',
          policyId: 'policy-sponsored-gas',
          accountRef: '0x1111111111111111111111111111111111111111',
          targetRef: '0x2222222222222222222222222222222222222222',
          chainId: 84532,
          txOrExecutionRef: assessment.txOrExecutionRef,
          receiptStatus: assessment.receiptStatus,
          feeUnit: assessment.feeUnit,
          feeAmount: assessment.feeAmount,
          requestDetails: {
            kind: 'd1-atomic-sponsored-settlement',
          },
        },
      });

      expect(record.charged).toBe(true);
      expect(record.settledSpendMinor).toBe(425);
      expect(record.billingLedgerEntryId).toMatch(/^ble_scr_/);
      expect(record.prepaidReservationId).toBe(reserved.reservation.id);

      const settledReservation = await prepaidReservations.getReservationBySourceEventId(
        ctx,
        reservationSourceEventId,
      );
      expect(settledReservation?.status).toBe('SETTLED');
      expect(settledReservation?.settledMinor).toBe(425);
      expect(settledReservation?.releasedMinor).toBe(275);

      const summary = await prepaidReservations.getSummary(ctx);
      expect(summary.reservedMinor).toBe(0);
      expect(summary.activeReservationCount).toBe(0);

      const debits = await billing.getSponsoredExecutionDebitsByIds(ctx, [
        record.billingLedgerEntryId || '',
      ]);
      expect(debits).toHaveLength(1);
      expect(debits[0]).toMatchObject({
        amountMinor: -425,
        sourceEventId: `sponsored_evm_call_debit:${reservationSourceEventId}`,
      });
      const overviewAfterSettlement = await billing.getOverview(ctx);
      expect(overviewAfterSettlement.creditBalanceMinor).toBe(575);

      const duplicate = await recordSponsoredExecution({
        billing,
        billingSourceEventIdPrefix: 'sponsored_evm_call_debit',
        context: ctx,
        ledger: sponsoredCalls,
        buildRecord: builder.build.bind(builder),
        assessment,
        walletId: 'wallet-d1-atomic',
        prepaidSettlementInput: {
          reservation: {
            sourceEventId: reservationSourceEventId,
            estimatedSpendMinor: 700,
            estimatedPricingVersion: 'static:estimate',
          },
          prepaidReservations,
          pricing,
          ctx,
          chainFamily: 'evm',
          intentKind: 'evm_call',
          executorKind: 'evm_eoa',
          environmentId: 'env-production',
          policyId: 'policy-sponsored-gas',
          accountRef: '0x1111111111111111111111111111111111111111',
          targetRef: '0x2222222222222222222222222222222222222222',
          chainId: 84532,
          txOrExecutionRef: assessment.txOrExecutionRef,
          receiptStatus: assessment.receiptStatus,
          feeUnit: assessment.feeUnit,
          feeAmount: assessment.feeAmount,
          requestDetails: {
            kind: 'd1-atomic-sponsored-settlement',
          },
        },
      });
      expect(duplicate.id).toBe(record.id);

      const sponsoredDebitActivity = await billing.listAccountActivity(ctx, {
        eventType: 'SPONSORED_EXECUTION_DEBIT',
        limit: 10,
      });
      expect(sponsoredDebitActivity.entries).toHaveLength(1);
      await expect(billing.getOverview(ctx)).resolves.toMatchObject({
        creditBalanceMinor: 575,
      });

      const conflictingBuilder = new AtomicD1SponsoredRecordBuilder(
        'sponsored-call-d1-atomic-conflict',
      );
      let duplicateReservationError: unknown = null;
      try {
        await recordSponsoredExecution({
          billing,
          billingSourceEventIdPrefix: 'sponsored_evm_call_debit',
          context: ctx,
          ledger: sponsoredCalls,
          buildRecord: conflictingBuilder.build.bind(conflictingBuilder),
          assessment,
          walletId: 'wallet-d1-atomic',
          prepaidSettlementInput: {
            reservation: {
              sourceEventId: reservationSourceEventId,
              estimatedSpendMinor: 700,
              estimatedPricingVersion: 'static:estimate',
            },
            prepaidReservations,
            pricing,
            ctx,
            chainFamily: 'evm',
            intentKind: 'evm_call',
            executorKind: 'evm_eoa',
            environmentId: 'env-production',
            policyId: 'policy-sponsored-gas',
            accountRef: '0x1111111111111111111111111111111111111111',
            targetRef: '0x2222222222222222222222222222222222222222',
            chainId: 84532,
            txOrExecutionRef: assessment.txOrExecutionRef,
            receiptStatus: assessment.receiptStatus,
            feeUnit: assessment.feeUnit,
            feeAmount: assessment.feeAmount,
            requestDetails: {
              kind: 'd1-atomic-sponsored-settlement',
            },
          },
        });
      } catch (error: unknown) {
        duplicateReservationError = error;
      }
      expect(String(duplicateReservationError)).toContain('UNIQUE constraint failed');
      await expect(billing.getOverview(ctx)).resolves.toMatchObject({
        creditBalanceMinor: 575,
      });
      const recordsPage = await sponsoredCalls.listRecords(ctx, { limit: 10, lookbackDays: 1 });
      expect(recordsPage.items).toHaveLength(1);
    } finally {
      cleanupTemporaryD1Database(temp.tempDir);
    }
  });

  test('sponsored call idempotency returns the original record', async () => {
    const temp = createTemporaryD1Database();
    try {
      const service = await createD1ConsoleSponsoredCallService({
        database: temp.database,
        namespace: 'd1-contracts',
        ensureSchema: true,
        now: () => new Date('2026-06-27T00:00:00.000Z'),
      });
      const ctx = {
        orgId: 'org-d1-sponsored',
        actorUserId: 'user-d1-sponsored',
        roles: ['admin'],
      };
      const request = {
        environmentId: 'env-production',
        apiKeyId: 'api-key-1',
        apiKeyKind: 'secret_key' as const,
        route: 'sponsored_evm_call_v1',
        policyId: 'policy-sponsored-gas',
        chainFamily: 'evm' as const,
        intentKind: 'evm_call' as const,
        executorKind: 'evm_eoa' as const,
        accountRef: '0x1111111111111111111111111111111111111111',
        targetRef: '0x2222222222222222222222222222222222222222',
        sponsorRef: '0x3333333333333333333333333333333333333333',
        receiptStatus: 'success' as const,
        feeUnit: 'wei' as const,
        feeAmount: '1000000000000000',
        detailsJson: '{"kind":"contract-test"}',
        estimatedSpendMinor: 100,
        settledSpendMinor: 75,
        pricingVersion: 'static:v1',
        pricingSource: 'contract-test',
        billingLedgerEntryId: 'ledger-entry-1',
        prepaidReservationId: 'reservation-1',
        charged: true,
        chargedReason: 'sponsored_gas',
        settledAt: '2026-06-27T00:00:01.000Z',
        idempotencyKey: 'sponsored-idempotency-1',
      };

      const first = await service.createRecord(ctx, request);
      const duplicate = await service.createRecord(ctx, {
        ...request,
        id: 'different-record-id',
        feeAmount: '9999999999999999',
      });
      const page = await service.listRecords(ctx, { limit: 10, lookbackDays: 1 });

      expect(duplicate.id).toBe(first.id);
      expect(duplicate.feeAmount).toBe(first.feeAmount);
      expect(page.items).toHaveLength(1);
    } finally {
      cleanupTemporaryD1Database(temp.tempDir);
    }
  });

  test('signer wallet metadata and auth methods are scoped by tenant environment', async () => {
    const temp = createTemporaryD1Database();
    try {
      const walletId = walletIdFromString('wallet-d1-metadata');
      const scope = {
        database: temp.database,
        namespace: 'd1-contracts',
        orgId: 'org-d1-signer',
        projectId: 'project-d1-signer',
        envId: 'env-production',
      };
      const otherEnvScope = {
        ...scope,
        envId: 'env-development',
      };
      const walletStore = new D1WalletStore(scope);
      const otherWalletStore = new D1WalletStore({
        ...otherEnvScope,
        ensureSchema: false,
      });
      const authMethodStore = new D1WalletAuthMethodStore(scope);
      const otherAuthMethodStore = new D1WalletAuthMethodStore({
        ...otherEnvScope,
        ensureSchema: false,
      });

      await walletStore.putSubject({
        version: 'wallet_v1',
        walletId,
        rpId: 'app.seams.test',
        createdAtMs: 1000,
        updatedAtMs: 2000,
      });
      await walletStore.putSigner({
        version: 'wallet_signer_ed25519_v1',
        walletId,
        rpId: 'app.seams.test',
        signerId: 'ed25519:wallet-d1-metadata:1',
        nearAccountId: 'wallet-d1-metadata.testnet',
        nearEd25519SigningKeyId: 'near-ed25519-key-1',
        signerSlot: 1,
        publicKey: 'ed25519:public-key-1',
        relayerKeyId: 'relayer-key-1',
        keyVersion: 'signer-key-v1',
        recoveryExportCapable: true,
        createdAtMs: 1000,
        updatedAtMs: 2000,
      });
      await authMethodStore.put({
        version: 'wallet_auth_method_v1',
        kind: 'passkey',
        status: 'active',
        walletId,
        rpId: 'app.seams.test',
        credentialIdB64u: 'credential-d1-wallet',
        credentialPublicKeyB64u: 'public-key-d1-wallet',
        counter: 3,
        createdAtMs: 3000,
        updatedAtMs: 3000,
      });
      await authMethodStore.put({
        version: 'wallet_auth_method_v1',
        kind: 'email_otp',
        status: 'active',
        walletId,
        emailHashHex: '0123456789abcdef',
        registrationAuthorityId: 'registration-authority-d1',
        createdAtMs: 4000,
        updatedAtMs: 4000,
      });

      await expect(walletStore.getWallet({ walletId })).resolves.toMatchObject({
        version: 'wallet_v1',
        walletId,
        rpId: 'app.seams.test',
      });
      await expect(otherWalletStore.getWallet({ walletId })).resolves.toBeNull();
      await expect(
        authMethodStore.getPasskey({
          rpId: 'app.seams.test',
          credentialIdB64u: 'credential-d1-wallet',
        }),
      ).resolves.toMatchObject({
        kind: 'passkey',
        walletId,
        credentialIdB64u: 'credential-d1-wallet',
      });
      await expect(
        authMethodStore.getEmailOtp({
          walletId,
          emailHashHex: '0123456789abcdef',
        }),
      ).resolves.toMatchObject({
        kind: 'email_otp',
        walletId,
        emailHashHex: '0123456789abcdef',
      });
      await expect(
        otherAuthMethodStore.getPasskey({
          rpId: 'app.seams.test',
          credentialIdB64u: 'credential-d1-wallet',
        }),
      ).resolves.toBeNull();

      const authMethods = await authMethodStore.listForWallet({
        walletId,
        rpId: 'app.seams.test',
      });
      expect(authMethods.map((record) => record.kind)).toEqual(['passkey', 'email_otp']);

      const signerRow = await temp.database
        .prepare(
          `SELECT COUNT(*) AS signer_count
             FROM signer_wallet_signers
            WHERE namespace = ?
              AND org_id = ?
              AND project_id = ?
              AND env_id = ?
              AND wallet_id = ?`,
        )
        .bind(scope.namespace, scope.orgId, scope.projectId, scope.envId, walletId)
        .first<SqliteJsonRow>();
      expect(Number(signerRow?.signer_count)).toBe(1);
    } finally {
      cleanupTemporaryD1Database(temp.tempDir);
    }
  });

  test('signer WebAuthn stores persist scoped credentials and atomic challenges', async () => {
    const temp = createTemporaryD1Database();
    try {
      const clock = new TestMutableClock('2026-06-27T04:00:00.000Z');
      const scope = {
        database: temp.database,
        namespace: 'd1-contracts',
        orgId: 'org-d1-signer',
        projectId: 'project-d1-signer',
        envId: 'env-production',
      };
      const otherEnvScope = {
        ...scope,
        envId: 'env-development',
      };
      const authenticatorStore = new D1WebAuthnAuthenticatorStore(scope);
      const otherAuthenticatorStore = new D1WebAuthnAuthenticatorStore({
        ...otherEnvScope,
        ensureSchema: false,
      });
      const bindingStore = new D1WebAuthnCredentialBindingStore(scope);
      const otherBindingStore = new D1WebAuthnCredentialBindingStore({
        ...otherEnvScope,
        ensureSchema: false,
      });
      const loginChallengeStore = new D1WebAuthnLoginChallengeStore({
        ...scope,
        now: clock.now,
      });
      const syncChallengeStore = new D1WebAuthnSyncChallengeStore({
        ...scope,
        ensureSchema: false,
        now: clock.now,
      });

      await authenticatorStore.put('user-d1-webauthn', {
        version: 'webauthn_authenticator_v1',
        credentialIdB64u: 'credential-d1-webauthn',
        credentialPublicKeyB64u: 'public-key-d1-webauthn',
        counter: 1,
        createdAtMs: 1000,
        updatedAtMs: 1000,
      });
      await authenticatorStore.put('user-d1-webauthn', {
        version: 'webauthn_authenticator_v1',
        credentialIdB64u: 'credential-d1-webauthn',
        credentialPublicKeyB64u: 'public-key-d1-webauthn',
        counter: 3,
        createdAtMs: 900,
        updatedAtMs: 2000,
      });
      await bindingStore.put({
        version: 'webauthn_credential_binding_v1',
        rpId: 'app.seams.test',
        credentialIdB64u: 'credential-d1-webauthn',
        userId: 'user-d1-webauthn',
        nearAccountId: 'wallet-d1-webauthn.testnet',
        nearEd25519SigningKeyId: 'near-ed25519-key-webauthn',
        signerSlot: 7,
        publicKey: 'ed25519:public-key-webauthn',
        relayerKeyId: 'relayer-key-webauthn',
        keyVersion: 'webauthn-key-v1',
        recoveryExportCapable: true,
        createdAtMs: 1000,
        updatedAtMs: 2000,
      });

      await expect(
        authenticatorStore.get('user-d1-webauthn', 'credential-d1-webauthn'),
      ).resolves.toMatchObject({
        credentialIdB64u: 'credential-d1-webauthn',
        counter: 3,
        createdAtMs: 900,
        updatedAtMs: 2000,
      });
      await expect(
        otherAuthenticatorStore.get('user-d1-webauthn', 'credential-d1-webauthn'),
      ).resolves.toBeNull();
      await expect(authenticatorStore.list('user-d1-webauthn')).resolves.toEqual([
        expect.objectContaining({
          credentialIdB64u: 'credential-d1-webauthn',
        }),
      ]);

      await expect(
        bindingStore.get('app.seams.test', 'credential-d1-webauthn'),
      ).resolves.toMatchObject({
        userId: 'user-d1-webauthn',
        signerSlot: 7,
      });
      await expect(
        otherBindingStore.get('app.seams.test', 'credential-d1-webauthn'),
      ).resolves.toBeNull();
      await expect(
        bindingStore.getMaxSignerSlot({
          userId: 'user-d1-webauthn',
          rpId: 'app.seams.test',
        }),
      ).resolves.toBe(7);
      await expect(
        bindingStore.listByUserId({
          userId: 'user-d1-webauthn',
          rpId: 'app.seams.test',
        }),
      ).resolves.toEqual([
        expect.objectContaining({
          credentialIdB64u: 'credential-d1-webauthn',
          signerSlot: 7,
        }),
      ]);

      await loginChallengeStore.put({
        version: 'webauthn_login_challenge_v1',
        challengeId: 'login-challenge-d1',
        userId: 'user-d1-webauthn',
        rpId: 'app.seams.test',
        challengeB64u: 'login-challenge-b64u',
        createdAtMs: Date.parse('2026-06-27T04:00:00.000Z'),
        expiresAtMs: Date.parse('2026-06-27T04:05:00.000Z'),
      });
      await expect(loginChallengeStore.consume('login-challenge-d1')).resolves.toMatchObject({
        challengeId: 'login-challenge-d1',
        userId: 'user-d1-webauthn',
      });
      await expect(loginChallengeStore.consume('login-challenge-d1')).resolves.toBeNull();

      await syncChallengeStore.put({
        version: 'webauthn_sync_challenge_v1',
        challengeId: 'sync-challenge-d1',
        rpId: 'app.seams.test',
        expectedUserId: 'user-d1-webauthn',
        challengeB64u: 'sync-challenge-b64u',
        createdAtMs: Date.parse('2026-06-27T04:00:00.000Z'),
        expiresAtMs: Date.parse('2026-06-27T04:05:00.000Z'),
      });
      await expect(syncChallengeStore.consume('sync-challenge-d1')).resolves.toMatchObject({
        challengeId: 'sync-challenge-d1',
        expectedUserId: 'user-d1-webauthn',
      });
      await expect(syncChallengeStore.consume('sync-challenge-d1')).resolves.toBeNull();
    } finally {
      cleanupTemporaryD1Database(temp.tempDir);
    }
  });

  test('signer identity links and app session versions are scoped in D1', async () => {
    const temp = createTemporaryD1Database();
    try {
      const clock = new TestMutableClock('2026-06-27T05:00:00.000Z');
      const scope = {
        database: temp.database,
        namespace: 'd1-contracts',
        orgId: 'org-d1-signer',
        projectId: 'project-d1-signer',
        envId: 'env-production',
        now: clock.now,
      };
      const identity = new D1IdentityStore(scope);
      const otherEnvIdentity = new D1IdentityStore({
        ...scope,
        envId: 'env-development',
        ensureSchema: false,
      });

      await expect(
        identity.linkSubjectToUserId({
          userId: 'user-d1-identity-alice',
          subject: 'google:alice',
        }),
      ).resolves.toEqual({ ok: true });
      await expect(
        identity.linkSubjectToUserId({
          userId: 'user-d1-identity-alice',
          subject: 'passkey:alice',
        }),
      ).resolves.toEqual({ ok: true });
      await expect(identity.getUserIdBySubject('google:alice')).resolves.toBe(
        'user-d1-identity-alice',
      );
      await expect(identity.listSubjectsByUserId('user-d1-identity-alice')).resolves.toEqual([
        'google:alice',
        'passkey:alice',
      ]);
      await expect(otherEnvIdentity.getUserIdBySubject('google:alice')).resolves.toBeNull();

      await expect(
        identity.linkSubjectToUserId({
          userId: 'user-d1-identity-bob',
          subject: 'github:bob',
        }),
      ).resolves.toEqual({ ok: true });
      await expect(
        identity.linkSubjectToUserId({
          userId: 'user-d1-identity-charlie',
          subject: 'github:bob',
        }),
      ).resolves.toMatchObject({
        ok: false,
        code: 'already_linked',
      });
      await expect(
        identity.linkSubjectToUserId({
          userId: 'user-d1-identity-charlie',
          subject: 'github:bob',
          allowMoveIfSoleIdentity: true,
        }),
      ).resolves.toEqual({
        ok: true,
        movedFromUserId: 'user-d1-identity-bob',
      });
      await expect(identity.getUserIdBySubject('github:bob')).resolves.toBe(
        'user-d1-identity-charlie',
      );

      await expect(
        identity.unlinkSubjectFromUserId({
          userId: 'user-d1-identity-charlie',
          subject: 'github:bob',
        }),
      ).resolves.toMatchObject({
        ok: false,
        code: 'cannot_unlink_last_identity',
      });
      await expect(
        identity.unlinkSubjectFromUserId({
          userId: 'user-d1-identity-alice',
          subject: 'passkey:alice',
        }),
      ).resolves.toEqual({ ok: true });
      await expect(identity.listSubjectsByUserId('user-d1-identity-alice')).resolves.toEqual([
        'google:alice',
      ]);
      await expect(
        identity.deleteSubjectLinkForDevCleanup({
          userId: 'user-d1-identity-alice',
          subject: 'google:alice',
        }),
      ).resolves.toEqual({ ok: true });
      await expect(identity.getUserIdBySubject('google:alice')).resolves.toBeNull();

      const ensuredVersion = await identity.ensureAppSessionVersionByUserId(
        'user-d1-identity-alice',
      );
      expect(ensuredVersion).toEqual(expect.any(String));
      expect(ensuredVersion.length).toBeGreaterThan(20);
      await expect(
        identity.ensureAppSessionVersionByUserId('user-d1-identity-alice'),
      ).resolves.toBe(ensuredVersion);
      await expect(
        otherEnvIdentity.getAppSessionVersionByUserId('user-d1-identity-alice'),
      ).resolves.toBeNull();
      const rotatedVersion = await identity.rotateAppSessionVersionByUserId(
        'user-d1-identity-alice',
      );
      expect(rotatedVersion).toEqual(expect.any(String));
      expect(rotatedVersion).not.toBe(ensuredVersion);
      await expect(
        identity.getAppSessionVersionByUserId('user-d1-identity-alice'),
      ).resolves.toBe(rotatedVersion);
    } finally {
      cleanupTemporaryD1Database(temp.tempDir);
    }
  });

  test('signer recovery sessions and executions are scoped in D1', async () => {
    const temp = createTemporaryD1Database();
    try {
      const clock = new TestMutableClock('2026-06-27T06:00:00.000Z');
      const scope = {
        database: temp.database,
        namespace: 'd1-contracts',
        orgId: 'org-d1-signer',
        projectId: 'project-d1-signer',
        envId: 'env-production',
      };
      const otherEnvScope = {
        ...scope,
        envId: 'env-development',
        ensureSchema: false,
      };
      const sessionStore = new D1RecoverySessionStore({
        ...scope,
        now: clock.now,
      });
      const otherEnvSessionStore = new D1RecoverySessionStore({
        ...otherEnvScope,
        now: clock.now,
      });
      const executionStore = new D1RecoveryExecutionStore(scope);
      const otherEnvExecutionStore = new D1RecoveryExecutionStore(otherEnvScope);
      const recoverySession = {
        version: 'recovery_session_v1',
        sessionId: 'recovery-session-d1',
        userId: 'user-d1-recovery',
        nearAccountId: 'wallet-d1-recovery.testnet',
        signerSlot: 1,
        status: 'prepared',
        createdAtMs: Date.parse('2026-06-27T06:00:00.000Z'),
        updatedAtMs: Date.parse('2026-06-27T06:01:00.000Z'),
        expiresAtMs: Date.parse('2026-06-27T07:00:00.000Z'),
        newNearPublicKey: 'ed25519:new-public-key',
        newEvmOwnerAddress: '0x1111111111111111111111111111111111111111',
        recoveryDeadlineEpochSeconds: 1782530400,
        recoveryEmailPayloadHash: 'hash-recovery-email',
        metadata: { source: 'd1-test' },
      } as const;
      const pendingExecution = {
        version: 'recovery_execution_v1',
        sessionId: 'recovery-session-d1',
        userId: 'user-d1-recovery',
        nearAccountId: 'wallet-d1-recovery.testnet',
        chainIdKey: 'near:testnet',
        accountAddress: 'wallet-d1-recovery.testnet',
        action: 'submit_recovery',
        status: 'pending',
        createdAtMs: Date.parse('2026-06-27T06:02:00.000Z'),
        updatedAtMs: Date.parse('2026-06-27T06:03:00.000Z'),
        metadata: { source: 'd1-test' },
      } as const;
      const confirmedExecution = {
        version: 'recovery_execution_v1',
        sessionId: 'recovery-session-d1',
        userId: 'user-d1-recovery',
        nearAccountId: 'wallet-d1-recovery.testnet',
        chainIdKey: 'near:testnet',
        accountAddress: 'wallet-d1-recovery.testnet',
        action: 'confirm_recovery',
        status: 'confirmed',
        createdAtMs: Date.parse('2026-06-27T06:04:00.000Z'),
        updatedAtMs: Date.parse('2026-06-27T06:05:00.000Z'),
        transactionHash: 'near-tx-confirmed',
      } as const;

      await sessionStore.put(recoverySession);
      await expect(sessionStore.get('recovery-session-d1')).resolves.toMatchObject({
        sessionId: 'recovery-session-d1',
        nearAccountId: 'wallet-d1-recovery.testnet',
        status: 'prepared',
      });
      await expect(otherEnvSessionStore.get('recovery-session-d1')).resolves.toBeNull();
      await expect(
        sessionStore.listByNearAccountId('wallet-d1-recovery.testnet'),
      ).resolves.toEqual([
        expect.objectContaining({
          sessionId: 'recovery-session-d1',
        }),
      ]);

      clock.set('2026-06-27T07:01:00.000Z');
      await expect(sessionStore.get('recovery-session-d1')).resolves.toBeNull();

      await executionStore.put(pendingExecution);
      await executionStore.put(confirmedExecution);
      await expect(
        executionStore.get({
          sessionId: 'recovery-session-d1',
          chainIdKey: 'NEAR:TESTNET',
          accountAddress: 'wallet-d1-recovery.testnet',
          action: 'submit_recovery',
        }),
      ).resolves.toMatchObject({
        status: 'pending',
        action: 'submit_recovery',
      });
      await expect(
        otherEnvExecutionStore.get({
          sessionId: 'recovery-session-d1',
          chainIdKey: 'near:testnet',
          accountAddress: 'wallet-d1-recovery.testnet',
          action: 'submit_recovery',
        }),
      ).resolves.toBeNull();

      const sessionExecutions = await executionStore.listBySessionId('recovery-session-d1');
      expect(sessionExecutions).toHaveLength(2);
      expect(sessionExecutions.map(recoveryExecutionAction).sort()).toEqual([
        'confirm_recovery',
        'submit_recovery',
      ]);
      await expect(
        executionStore.listByStatus({
          status: 'pending',
          action: 'submit_recovery',
          updatedBeforeMs: Date.parse('2026-06-27T06:04:00.000Z'),
          limit: 1,
        }),
      ).resolves.toEqual([
        expect.objectContaining({
          sessionId: 'recovery-session-d1',
          action: 'submit_recovery',
        }),
      ]);
    } finally {
      cleanupTemporaryD1Database(temp.tempDir);
    }
  });

  test('signer email recovery preparations are scoped and expire in D1', async () => {
    const temp = createTemporaryD1Database();
    try {
      const clock = new TestMutableClock('2026-06-27T09:00:00.000Z');
      const scope = {
        database: temp.database,
        namespace: 'd1-contracts',
        orgId: 'org-d1-signer',
        projectId: 'project-d1-signer',
        envId: 'env-production',
        now: clock.now,
      };
      const preparationStore = new D1EmailRecoveryPreparationStore(scope);
      const otherEnvPreparationStore = new D1EmailRecoveryPreparationStore({
        ...scope,
        envId: 'env-development',
        ensureSchema: false,
      });
      const activePreparation = buildD1EmailRecoveryPreparationRecord({
        requestId: 'email-recovery-preparation-d1',
        createdAtMs: Date.parse('2026-06-27T09:00:00.000Z'),
        expiresAtMs: Date.parse('2026-06-27T09:30:00.000Z'),
      });
      const deletePreparation = buildD1EmailRecoveryPreparationRecord({
        requestId: 'email-recovery-preparation-delete-d1',
        createdAtMs: Date.parse('2026-06-27T09:01:00.000Z'),
        expiresAtMs: Date.parse('2026-06-27T09:30:00.000Z'),
      });

      await preparationStore.put(activePreparation);
      await expect(
        preparationStore.get('email-recovery-preparation-d1'),
      ).resolves.toMatchObject({
        requestId: 'email-recovery-preparation-d1',
        accountId: 'wallet-d1-email-recovery',
        rpId: 'app.seams.test',
      });
      await expect(
        otherEnvPreparationStore.get('email-recovery-preparation-d1'),
      ).resolves.toBeNull();

      clock.set('2026-06-27T09:31:00.000Z');
      await expect(preparationStore.get('email-recovery-preparation-d1')).resolves.toBeNull();

      clock.set('2026-06-27T09:02:00.000Z');
      await preparationStore.put(deletePreparation);
      await expect(
        preparationStore.get('email-recovery-preparation-delete-d1'),
      ).resolves.toMatchObject({
        requestId: 'email-recovery-preparation-delete-d1',
      });
      await preparationStore.del('email-recovery-preparation-delete-d1');
      await expect(
        preparationStore.get('email-recovery-preparation-delete-d1'),
      ).resolves.toBeNull();
    } finally {
      cleanupTemporaryD1Database(temp.tempDir);
    }
  });

  test('signer Email OTP stores are scoped and consume one-time records in D1', async () => {
    const temp = createTemporaryD1Database();
    try {
      const nowMs = Date.parse('2026-06-27T10:05:00.000Z');
      const scope = {
        database: temp.database,
        namespace: 'd1-contracts',
        orgId: 'org-d1-signer',
        projectId: 'project-d1-signer',
        envId: 'env-production',
      };
      const otherEnvScope = {
        database: temp.database,
        namespace: 'd1-contracts',
        orgId: 'org-d1-signer',
        projectId: 'project-d1-signer',
        envId: 'env-development',
        ensureSchema: false,
      };
      const challengeStore = new D1EmailOtpChallengeStore(scope);
      const otherEnvChallengeStore = new D1EmailOtpChallengeStore(otherEnvScope);
      const grantStore = new D1EmailOtpGrantStore(scope);
      const otherEnvGrantStore = new D1EmailOtpGrantStore(otherEnvScope);
      const enrollmentStore = new D1EmailOtpWalletEnrollmentStore(scope);
      const otherEnvEnrollmentStore = new D1EmailOtpWalletEnrollmentStore(otherEnvScope);
      const escrowStore = new D1EmailOtpRecoveryWrappedEnrollmentEscrowStore(scope);
      const otherEnvEscrowStore = new D1EmailOtpRecoveryWrappedEnrollmentEscrowStore(otherEnvScope);
      const authStateStore = new D1EmailOtpAuthStateStore(scope);
      const otherEnvAuthStateStore = new D1EmailOtpAuthStateStore(otherEnvScope);
      const unlockChallengeStore = new D1EmailOtpUnlockChallengeStore(scope);
      const otherEnvUnlockChallengeStore = new D1EmailOtpUnlockChallengeStore(otherEnvScope);
      const registrationAttemptStore = new D1EmailOtpRegistrationAttemptStore(scope);
      const otherEnvRegistrationAttemptStore = new D1EmailOtpRegistrationAttemptStore(
        otherEnvScope,
      );

      const oldestChallenge = buildD1EmailOtpChallengeRecord({
        challengeId: 'email-otp-challenge-oldest',
        otpCode: '111111',
        createdAtMs: Date.parse('2026-06-27T10:00:00.000Z'),
        expiresAtMs: Date.parse('2026-06-27T10:30:00.000Z'),
      });
      const latestChallenge = buildD1EmailOtpChallengeRecord({
        challengeId: 'email-otp-challenge-latest',
        otpCode: '222222',
        createdAtMs: Date.parse('2026-06-27T10:01:00.000Z'),
        expiresAtMs: Date.parse('2026-06-27T10:40:00.000Z'),
      });
      const expiredChallenge = buildD1EmailOtpChallengeRecord({
        challengeId: 'email-otp-challenge-expired',
        otpCode: '333333',
        createdAtMs: Date.parse('2026-06-27T09:00:00.000Z'),
        expiresAtMs: Date.parse('2026-06-27T09:30:00.000Z'),
      });
      const challengeContext = buildD1EmailOtpChallengeContext({ nowMs });

      await challengeStore.put(oldestChallenge);
      await challengeStore.put(latestChallenge);
      await challengeStore.put(expiredChallenge);
      await expect(challengeStore.get('email-otp-challenge-latest')).resolves.toMatchObject({
        challengeId: 'email-otp-challenge-latest',
      });
      await expect(otherEnvChallengeStore.get('email-otp-challenge-latest')).resolves.toBeNull();
      await expect(challengeStore.countActiveByContext(challengeContext)).resolves.toBe(2);
      await expect(
        challengeStore.findLatestActiveByContext(challengeContext),
      ).resolves.toMatchObject({ challengeId: 'email-otp-challenge-latest' });
      await expect(
        challengeStore.findActiveByContext({
          ...challengeContext,
          otpCode: '222222',
        }),
      ).resolves.toMatchObject({ challengeId: 'email-otp-challenge-latest' });
      await expect(
        challengeStore.deleteOldestActiveByContext(challengeContext),
      ).resolves.toMatchObject({ challengeId: 'email-otp-challenge-oldest' });
      await expect(challengeStore.countActiveByContext(challengeContext)).resolves.toBe(1);
      const expiredChallenges = await challengeStore.deleteExpired(nowMs);
      expect(expiredChallenges.map((challenge) => challenge.challengeId)).toEqual([
        'email-otp-challenge-expired',
      ]);

      const grant = buildD1EmailOtpGrantRecord({
        grantToken: 'email-otp-grant-d1',
        issuedAtMs: nowMs,
        expiresAtMs: Date.parse('2026-06-27T10:30:00.000Z'),
      });
      await grantStore.put(grant);
      await expect(grantStore.get('email-otp-grant-d1')).resolves.toMatchObject({
        grantToken: 'email-otp-grant-d1',
      });
      await expect(otherEnvGrantStore.get('email-otp-grant-d1')).resolves.toBeNull();
      await expect(grantStore.consume('email-otp-grant-d1')).resolves.toMatchObject({
        grantToken: 'email-otp-grant-d1',
      });
      await expect(grantStore.consume('email-otp-grant-d1')).resolves.toBeNull();

      const enrollment = buildD1EmailOtpWalletEnrollmentRecord({
        updatedAtMs: Date.parse('2026-06-27T10:01:00.000Z'),
      });
      await enrollmentStore.put(enrollment);
      await expect(enrollmentStore.get('wallet-d1-email-otp')).resolves.toMatchObject({
        walletId: 'wallet-d1-email-otp',
        providerUserId: 'google-subject-d1-email-otp',
      });
      await expect(
        enrollmentStore.getByProviderUserId({
          providerUserId: 'google-subject-d1-email-otp',
          orgId: 'org-d1-signer',
        }),
      ).resolves.toMatchObject({ walletId: 'wallet-d1-email-otp' });
      await expect(otherEnvEnrollmentStore.get('wallet-d1-email-otp')).resolves.toBeNull();

      const activeEscrow = buildD1EmailOtpEscrowRecord({
        recoveryKeyId: 'recovery-key-active',
        recoveryKeyStatus: 'active',
        updatedAtMs: Date.parse('2026-06-27T10:02:00.000Z'),
      });
      const consumedEscrow = buildD1EmailOtpEscrowRecord({
        recoveryKeyId: 'recovery-key-consumed',
        recoveryKeyStatus: 'consumed',
        updatedAtMs: Date.parse('2026-06-27T10:03:00.000Z'),
      });
      await escrowStore.putMany([activeEscrow, consumedEscrow]);
      await expect(
        escrowStore.get({
          walletId: 'wallet-d1-email-otp',
          recoveryKeyId: 'recovery-key-active',
        }),
      ).resolves.toMatchObject({ recoveryKeyStatus: 'active' });
      await expect(escrowStore.listActiveByWallet('wallet-d1-email-otp')).resolves.toHaveLength(1);
      await expect(escrowStore.listByWallet('wallet-d1-email-otp')).resolves.toHaveLength(2);
      await expect(otherEnvEscrowStore.listByWallet('wallet-d1-email-otp')).resolves.toHaveLength(
        0,
      );
      await escrowStore.del({
        walletId: 'wallet-d1-email-otp',
        recoveryKeyId: 'recovery-key-active',
      });
      await expect(
        escrowStore.get({
          walletId: 'wallet-d1-email-otp',
          recoveryKeyId: 'recovery-key-active',
        }),
      ).resolves.toBeNull();

      await authStateStore.put({
        version: 'email_otp_auth_state_v1',
        walletId: 'wallet-d1-email-otp',
        providerUserId: 'google-subject-d1-email-otp',
        orgId: 'org-d1-signer',
        createdAtMs: nowMs,
        updatedAtMs: nowMs,
        otpFailureCount: 1,
        lastEmailOtpLoginAtMs: nowMs,
      });
      await expect(authStateStore.get('wallet-d1-email-otp')).resolves.toMatchObject({
        otpFailureCount: 1,
      });
      await expect(otherEnvAuthStateStore.get('wallet-d1-email-otp')).resolves.toBeNull();

      await unlockChallengeStore.put({
        version: 'email_otp_unlock_challenge_v1',
        challengeId: 'email-otp-unlock-challenge-d1',
        walletId: 'wallet-d1-email-otp',
        userId: 'google-subject-d1-email-otp',
        orgId: 'org-d1-signer',
        challengeB64u: 'unlockChallengeB64u',
        createdAtMs: nowMs,
        expiresAtMs: Date.parse('2026-06-27T10:30:00.000Z'),
      });
      await expect(
        otherEnvUnlockChallengeStore.consume('email-otp-unlock-challenge-d1'),
      ).resolves.toBeNull();
      await expect(
        unlockChallengeStore.consume('email-otp-unlock-challenge-d1'),
      ).resolves.toMatchObject({ challengeId: 'email-otp-unlock-challenge-d1' });
      await expect(unlockChallengeStore.consume('email-otp-unlock-challenge-d1')).resolves.toBeNull();

      const activeAttempt = buildD1EmailOtpRegistrationAttemptRecord({
        attemptId: 'email-otp-registration-active',
        appSessionVersion: 'app-session-v1',
        walletId: 'wallet-d1-email-otp-registration',
        runtimeProjectId: 'project-d1-signer',
        updatedAtMs: Date.parse('2026-06-27T10:01:00.000Z'),
        expiresAtMs: Date.parse('2026-06-27T10:30:00.000Z'),
      });
      const wrongRuntimeAttempt = buildD1EmailOtpRegistrationAttemptRecord({
        attemptId: 'email-otp-registration-wrong-runtime',
        appSessionVersion: 'app-session-v1',
        walletId: 'wallet-d1-email-otp-registration-wrong-runtime',
        runtimeProjectId: 'project-other-runtime',
        updatedAtMs: Date.parse('2026-06-27T10:04:00.000Z'),
        expiresAtMs: Date.parse('2026-06-27T10:30:00.000Z'),
      });
      const replacedAttempt = buildD1EmailOtpRegistrationAttemptRecord({
        attemptId: 'email-otp-registration-replaced',
        appSessionVersion: 'app-session-old',
        walletId: 'wallet-d1-email-otp-registration-replaced',
        runtimeProjectId: 'project-d1-signer',
        updatedAtMs: Date.parse('2026-06-27T10:02:00.000Z'),
        expiresAtMs: Date.parse('2026-06-27T10:30:00.000Z'),
      });
      const expiredAttempt = buildD1EmailOtpRegistrationAttemptRecord({
        attemptId: 'email-otp-registration-expired',
        appSessionVersion: 'app-session-expired',
        walletId: 'wallet-d1-email-otp-registration-expired',
        runtimeProjectId: 'project-d1-signer',
        updatedAtMs: Date.parse('2026-06-27T10:02:00.000Z'),
        expiresAtMs: Date.parse('2026-06-27T10:04:00.000Z'),
      });
      await registrationAttemptStore.put(activeAttempt);
      await registrationAttemptStore.put(wrongRuntimeAttempt);
      await registrationAttemptStore.put(replacedAttempt);
      await registrationAttemptStore.put(expiredAttempt);
      await expect(
        otherEnvRegistrationAttemptStore.get('email-otp-registration-active'),
      ).resolves.toBeNull();
      await expect(
        registrationAttemptStore.findStartedBySubjectEmail({
          providerSubject: 'google-subject-d1-email-otp',
          email: 'email-otp-d1@example.com',
          orgId: 'org-d1-signer',
          appSessionVersion: 'app-session-v1',
          runtimePolicyScope: {
            orgId: 'org-d1-signer',
            projectId: 'project-d1-signer',
            envId: 'env-production',
            signingRootVersion: 'signing-root-version-v1',
          },
          nowMs,
        }),
      ).resolves.toMatchObject({ attemptId: 'email-otp-registration-active' });
      await expect(
        registrationAttemptStore.hasLiveStartedWalletAttempt({
          walletId: 'wallet-d1-email-otp-offer-candidate',
          nowMs,
        }),
      ).resolves.toBe(true);
      await expect(
        registrationAttemptStore.abandonStartedBySubjectEmailExceptAppSession({
          providerSubject: 'google-subject-d1-email-otp',
          email: 'email-otp-d1@example.com',
          orgId: 'org-d1-signer',
          appSessionVersion: 'app-session-v1',
          runtimePolicyScope: {
            orgId: 'org-d1-signer',
            projectId: 'project-d1-signer',
            envId: 'env-production',
            signingRootVersion: 'signing-root-version-v1',
          },
          nowMs,
          failureCode: 'app_session_version_replaced',
        }),
      ).resolves.toBe(1);
      await expect(
        registrationAttemptStore.get('email-otp-registration-replaced'),
      ).resolves.toMatchObject({ state: 'abandoned' });
      await expect(registrationAttemptStore.deleteExpired(nowMs)).resolves.toBe(1);
    } finally {
      cleanupTemporaryD1Database(temp.tempDir);
    }
  });

  test('signer NEAR public key metadata is scoped in D1', async () => {
    const temp = createTemporaryD1Database();
    try {
      const scope = {
        database: temp.database,
        namespace: 'd1-contracts',
        orgId: 'org-d1-signer',
        projectId: 'project-d1-signer',
        envId: 'env-production',
      };
      const keyStore = new D1NearPublicKeyStore(scope);
      const otherEnvKeyStore = new D1NearPublicKeyStore({
        ...scope,
        envId: 'env-development',
        ensureSchema: false,
      });
      const thresholdKey = {
        version: 'near_public_key_v1',
        userId: 'user-d1-near-key',
        publicKey: 'ed25519:threshold-public-key',
        kind: 'threshold',
        signerSlot: 2,
        credentialIdB64u: 'credential-d1-near-key',
        rpId: 'app.seams.test',
        createdAtMs: Date.parse('2026-06-27T08:00:00.000Z'),
        updatedAtMs: Date.parse('2026-06-27T08:00:00.000Z'),
        addedTxHash: 'near-tx-add-threshold',
      } as const;
      const backupKey = {
        version: 'near_public_key_v1',
        userId: 'user-d1-near-key',
        publicKey: 'ed25519:backup-public-key',
        kind: 'backup',
        signerSlot: 1,
        createdAtMs: Date.parse('2026-06-27T08:01:00.000Z'),
        updatedAtMs: Date.parse('2026-06-27T08:01:00.000Z'),
      } as const;
      const removedThresholdKey = {
        ...thresholdKey,
        updatedAtMs: Date.parse('2026-06-27T08:02:00.000Z'),
        removedAtMs: Date.parse('2026-06-27T08:02:00.000Z'),
      } as const;

      await keyStore.put(thresholdKey);
      await keyStore.put(backupKey);
      await keyStore.put(removedThresholdKey);

      const keys = await keyStore.listByUserId('user-d1-near-key');
      expect(keys.map(nearPublicKeyValue)).toEqual([
        'ed25519:backup-public-key',
        'ed25519:threshold-public-key',
      ]);
      expect(keys[1]).toMatchObject({
        kind: 'threshold',
        signerSlot: 2,
        removedAtMs: Date.parse('2026-06-27T08:02:00.000Z'),
      });
      await expect(otherEnvKeyStore.listByUserId('user-d1-near-key')).resolves.toHaveLength(0);
      await expect(keyStore.listByUserId('')).resolves.toHaveLength(0);
    } finally {
      cleanupTemporaryD1Database(temp.tempDir);
    }
  });

  test('signer sealed shares are scoped by tenant, project, and environment', async () => {
    const temp = createTemporaryD1Database();
    try {
      const sharedOptions = {
        database: temp.database,
        namespace: 'd1-contracts',
        orgId: 'org-d1-signer',
        projectId: 'project-d1-signer',
        envelopeVersion: 'd1-secret-share-v1',
        lastAuditEventId: 'audit-event-1',
        now: () => new Date('2026-06-27T00:00:00.000Z'),
      };
      const productionStore = new D1SigningRootSecretStore({
        ...sharedOptions,
        envId: 'env-production',
      });
      const developmentStore = new D1SigningRootSecretStore({
        ...sharedOptions,
        envId: 'env-development',
      });

      await productionStore.putSealedSigningRootSecretShare({
        signingRootId: 'signing-root-1',
        signingRootVersion: 'version-1',
        shareId: 1,
        sealedShare: new Uint8Array([1, 2, 3, 4]),
        storageId: 'r2://shares/signing-root-1/share-1',
        kekId: 'kek-production-1',
      });

      const productionShares = await productionStore.listSealedSigningRootSecretShares({
        signingRootId: 'signing-root-1',
        signingRootVersion: 'version-1',
      });
      const developmentShares = await developmentStore.listSealedSigningRootSecretShares({
        signingRootId: 'signing-root-1',
        signingRootVersion: 'version-1',
      });

      expect(productionShares).toHaveLength(1);
      expect(productionShares[0]?.kekId).toBe('kek-production-1');
      expect(Array.from(productionShares[0]?.sealedShare || [])).toEqual([1, 2, 3, 4]);
      expect(developmentShares).toHaveLength(0);

      let missingKekError: unknown = null;
      try {
        await productionStore.putSealedSigningRootSecretShare({
          signingRootId: 'signing-root-1',
          signingRootVersion: 'version-1',
          shareId: 2,
          sealedShare: new Uint8Array([5, 6, 7, 8]),
        });
      } catch (error: unknown) {
        missingKekError = error;
      }
      expect(String(missingKekError)).toContain(
        'kekId is required for D1 signing-root secret shares',
      );
    } finally {
      cleanupTemporaryD1Database(temp.tempDir);
    }
  });

  test('runtime snapshot outbox claim lease prevents duplicate dispatch', async () => {
    const temp = createTemporaryD1Database();
    try {
      const namespace = 'd1-contracts';
      const orgId = 'org-d1-runtime-snapshot';
      const nowMs = Date.parse('2026-06-27T00:00:00.000Z');
      const harness = new RuntimeSnapshotOutboxRaceHarness(
        temp.database,
        namespace,
        orgId,
        nowMs,
      );
      const service = await createD1ConsoleRuntimeSnapshotService({
        database: temp.database,
        namespace,
        ensureSchema: true,
        now: harness.now.bind(harness),
        retentionTtlMs: 1000 * 60 * 60,
      });
      const ctx = {
        orgId,
        actorUserId: 'user-d1-runtime-snapshot',
        roles: ['admin'],
      };

      await service.publishSnapshot(ctx, {
        snapshotId: 'snapshot-race-1',
        projectId: 'project-runtime',
        environmentId: 'env-production',
        payload: {
          policy: { id: 'policy-runtime' },
          gasSponsorship: { enabled: true },
          metadata: { source: 'd1-contract-test' },
        },
      });

      const primaryResult = await runD1ConsoleRuntimeSnapshotOutboxDispatch({
        database: temp.database,
        namespace,
        orgIds: [orgId],
        limit: 1,
        ensureSchema: false,
        now: harness.now.bind(harness),
        workerId: 'snapshot-race-worker-a',
        claimTtlMs: 60_000,
        dispatch: harness.dispatch.bind(harness),
      });
      const afterDispatchResult = await runD1ConsoleRuntimeSnapshotOutboxDispatch({
        database: temp.database,
        namespace,
        orgIds: [orgId],
        limit: 1,
        ensureSchema: false,
        now: harness.now.bind(harness),
        workerId: 'snapshot-race-worker-c',
        claimTtlMs: 60_000,
        dispatch: harness.competitorDispatch.bind(harness),
      });

      expect(primaryResult.dispatchedCount).toBe(1);
      expect(primaryResult.failureCount).toBe(0);
      expect(harness.competitorResult?.dispatchedCount).toBe(0);
      expect(harness.competitorResult?.failureCount).toBe(0);
      expect(afterDispatchResult.dispatchedCount).toBe(0);
      expect(harness.dispatchedEventIds).toHaveLength(1);
    } finally {
      cleanupTemporaryD1Database(temp.tempDir);
    }
  });
});
