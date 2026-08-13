import { expect, test } from '@playwright/test';
import {
  buildAccountWelcomeEmailV1,
  buildBillingRefundResultEmailV1,
  buildLowBalanceWarningEmailV1,
  buildMembershipAccessChangedEmailV1,
  buildOrganizationInvitationEmailV1,
  buildOwnerMembershipChangedEmailV1,
  buildPrepaidTopUpReceiptEmailV1,
  createAesGcmConsoleInvitationSecretCipher,
  createCaptureConsoleEmailProvider,
  createConsoleEmailOutboxInsertStatement,
  createConsoleInvitationEmailCancellationStatement,
  createResendConsoleEmailProvider,
  getD1ConsoleEmailOutbox,
  listD1ConsoleEmailDeliveries,
  listD1ConsoleEmailFinalFailures,
  parseConsoleEmailTemplate,
  renderConsoleEmailV1,
  retryD1ConsoleEmailFinalFailure,
  runD1ConsoleEmailDispatcher,
  type BillingRefundResultEmailV1,
  type ConsoleEmailOutboxInsert,
  type ConsoleEmailProvider,
  type ConsoleEmailProviderSendRequest,
  type ConsoleEmailProviderSendResult,
  type ConsoleEmailTemplateV1,
  type ConsoleInvitationSecretCipher,
} from '@seams-internal/console-server/email';
import { createD1ConsoleOnboardingWelcomeEmail } from '../../packages/console-server-ts/src/onboarding/welcomeEmail';
import type { D1DatabaseLike } from '../../packages/sdk-server-ts/src/storage/tenantRoute';
import {
  applyD1MigrationFiles,
  cleanupTemporaryD1Database,
  createTemporaryD1Database,
  listD1MigrationFiles,
} from '../helpers/sqliteD1';

const NAMESPACE = 'console-email-test';
const ORG_ID = 'org-console-email';
const BASE_NOW = new Date('2026-07-22T10:00:00.000Z');
const INVITATION_SECRET = 'invite_token_value_that_must_not_be_stored';

// @ts-expect-error A succeeded refund requires the post-refund balance.
const rejectedSucceededRefundTypeFixture: BillingRefundResultEmailV1 = {
  family: 'BILLING_REFUND_RESULT',
  version: 1,
  outcome: 'SUCCEEDED',
  organizationName: 'Type Fixture Org',
  refundId: 'refund-type-fixture',
  amountMinor: 100,
  currency: 'USD',
  consoleBaseUrl: 'https://console.example.test',
};
void rejectedSucceededRefundTypeFixture;

interface ConsoleEmailTestDatabase {
  readonly database: D1DatabaseLike;
  readonly tempDir: string;
}

class SequencedConsoleEmailProvider implements ConsoleEmailProvider {
  readonly provider = 'capture' as const;
  readonly requests: ConsoleEmailProviderSendRequest[] = [];
  private readonly results: ConsoleEmailProviderSendResult[];
  private index = 0;

  constructor(results: readonly ConsoleEmailProviderSendResult[]) {
    this.results = [...results];
  }

  async send(request: ConsoleEmailProviderSendRequest): Promise<ConsoleEmailProviderSendResult> {
    this.requests.push(request);
    const result = this.results[Math.min(this.index, this.results.length - 1)];
    this.index += 1;
    if (!result) throw new Error('Sequenced email provider has no configured result');
    return result;
  }
}

class SlowConsoleEmailProvider implements ConsoleEmailProvider {
  readonly provider = 'capture' as const;
  sendCount = 0;

  async send(request: ConsoleEmailProviderSendRequest): Promise<ConsoleEmailProviderSendResult> {
    this.sendCount += 1;
    await delay();
    return {
      kind: 'SENT',
      providerMessageId: `slow_${request.outboxId}`,
      statusCode: null,
    };
  }
}

class MutableConsoleEmailClock {
  private currentMs: number;

  constructor(initial: Date) {
    this.currentMs = initial.getTime();
  }

  now(): Date {
    return new Date(this.currentMs);
  }

  advance(milliseconds: number): void {
    this.currentMs += milliseconds;
  }
}

let resendFetchUrl = '';
let resendFetchInit: RequestInit | undefined;

async function recordingResendFetch(
  input: RequestInfo | URL,
  init?: RequestInit,
): Promise<Response> {
  resendFetchUrl = String(input);
  resendFetchInit = init;
  return new Response(JSON.stringify({ id: 'resend-message-1' }), {
    status: 200,
    headers: { 'Content-Type': 'application/json' },
  });
}

function delayResolve(resolve: () => void): void {
  setTimeout(resolve, 25);
}

async function delay(): Promise<void> {
  await new Promise<void>(delayResolve);
}

function createTestCipher(): ConsoleInvitationSecretCipher {
  return createAesGcmConsoleInvitationSecretCipher({
    keyId: 'console-email-test-key-v1',
    keyBytes: new Uint8Array(32).fill(23),
  });
}

async function createConsoleEmailTestDatabase(): Promise<ConsoleEmailTestDatabase> {
  const temporary = createTemporaryD1Database();
  await applyD1MigrationFiles(temporary.database, listD1MigrationFiles('d1-console'));
  await temporary.database
    .prepare(
      `INSERT INTO organizations
         (namespace, id, name, slug, created_by_user_id, status, created_at_ms, updated_at_ms)
       VALUES (?, ?, ?, ?, ?, 'ACTIVE', ?, ?)`,
    )
    .bind(NAMESPACE, ORG_ID, 'Email Test Org', 'email-test-org', 'email-test-user', 1, 1)
    .run();
  return temporary;
}

function buildTopUpOutbox(input: {
  readonly outboxId: string;
  readonly dedupeKey: string;
  readonly createdAt: Date;
}): ConsoleEmailOutboxInsert {
  return {
    outboxId: input.outboxId,
    dedupeKey: input.dedupeKey,
    orgId: ORG_ID,
    recipient: {
      email: 'billing@example.com',
      displayName: 'Billing Contact',
    },
    template: buildPrepaidTopUpReceiptEmailV1({
      organizationName: 'Email Test Org',
      purchaseId: `purchase-${input.outboxId}`,
      amountMinor: 2_500,
      balanceAfterMinor: 7_500,
      purchasedAt: input.createdAt.toISOString(),
      consoleBaseUrl: 'https://console.example.test',
    }),
    createdAt: input.createdAt,
    availableAt: input.createdAt,
  };
}

function buildInvitationOutbox(input: {
  readonly outboxId: string;
  readonly dedupeKey: string;
  readonly invitationId: string;
  readonly createdAt: Date;
  readonly expiresAt: Date;
}): ConsoleEmailOutboxInsert {
  return {
    outboxId: input.outboxId,
    dedupeKey: input.dedupeKey,
    orgId: ORG_ID,
    recipient: {
      email: 'invitee@example.com',
      displayName: 'Invitee',
    },
    template: buildOrganizationInvitationEmailV1({
      invitationId: input.invitationId,
      organizationName: 'Email Test Org',
      inviterDisplayName: 'Owner',
      invitedRole: 'OWNER',
      consoleBaseUrl: 'https://console.example.test',
      expiresAt: input.expiresAt.toISOString(),
    }),
    invitationSecret: INVITATION_SECRET,
    createdAt: input.createdAt,
    availableAt: input.createdAt,
  };
}

async function insertOutbox(
  database: D1DatabaseLike,
  cipher: ConsoleInvitationSecretCipher,
  email: ConsoleEmailOutboxInsert,
): Promise<void> {
  const statement = await createConsoleEmailOutboxInsertStatement({
    database,
    namespace: NAMESPACE,
    email,
    invitationSecretCipher: cipher,
  });
  await statement.run();
}

async function countRows(
  database: D1DatabaseLike,
  table: string,
  whereSql: string,
  values: readonly unknown[],
): Promise<number> {
  const row = await database
    .prepare(`SELECT COUNT(*) AS row_count FROM ${table} WHERE ${whereSql}`)
    .bind(...values)
    .first<{ row_count?: unknown }>();
  return Number(row?.row_count || 0);
}

async function readRawOutbox(
  database: D1DatabaseLike,
  outboxId: string,
): Promise<Record<string, unknown>> {
  const row = await database
    .prepare(
      `SELECT *
         FROM console_email_outbox
        WHERE namespace = ? AND org_id = ? AND id = ?`,
    )
    .bind(NAMESPACE, ORG_ID, outboxId)
    .first<Record<string, unknown>>();
  if (!row) throw new Error(`Missing outbox ${outboxId}`);
  return row;
}

function sentProviderResult(messageId: string): ConsoleEmailProviderSendResult {
  return {
    kind: 'SENT',
    providerMessageId: messageId,
    statusCode: null,
  };
}

function retryableProviderResult(code: string): ConsoleEmailProviderSendResult {
  return {
    kind: 'RETRYABLE_FAILURE',
    errorCode: code,
    statusCode: 503,
  };
}

test.describe('console transactional email', () => {
  test('defines and renders the seven closed versioned template families', () => {
    const templates: ConsoleEmailTemplateV1[] = [
      buildAccountWelcomeEmailV1({
        recipientDisplayName: 'Ada',
        organizationName: 'Acme',
        projectName: 'Checkout',
        consoleBaseUrl: 'https://console.example.test',
        docsBaseUrl: 'https://docs.example.test',
      }),
      buildOrganizationInvitationEmailV1({
        invitationId: 'inv-template',
        organizationName: 'Acme & Partners',
        inviterDisplayName: 'Alice <Owner>',
        invitedRole: 'ADMIN',
        consoleBaseUrl: 'https://console.example.test',
        expiresAt: '2026-07-29T10:00:00.000Z',
      }),
      buildOwnerMembershipChangedEmailV1({
        change: 'ADDED',
        organizationName: 'Acme',
        ownerDisplayName: 'Bob',
        changedByDisplayName: 'Alice',
      }),
      buildMembershipAccessChangedEmailV1({
        change: 'SUSPENDED',
        organizationName: 'Acme',
        memberDisplayName: 'Carol',
        changedByDisplayName: 'Alice',
      }),
      buildPrepaidTopUpReceiptEmailV1({
        organizationName: 'Acme',
        purchaseId: 'purchase-1',
        amountMinor: 5_000,
        balanceAfterMinor: 8_000,
        purchasedAt: '2026-07-22T10:00:00.000Z',
        consoleBaseUrl: 'https://console.example.test',
      }),
      buildBillingRefundResultEmailV1({
        outcome: 'FAILED',
        organizationName: 'Acme',
        refundId: 'refund-1',
        amountMinor: 1_000,
        failureCode: 'provider_declined',
        consoleBaseUrl: 'https://console.example.test',
      }),
      buildLowBalanceWarningEmailV1({
        organizationName: 'Acme',
        balanceMinor: 500,
        thresholdMinor: 2_000,
        consoleBaseUrl: 'https://console.example.test',
      }),
    ];

    const families = new Set<string>();
    for (const template of templates) {
      const parsed = parseConsoleEmailTemplate(JSON.parse(JSON.stringify(template)));
      families.add(parsed.family);
      expect(parsed.version).toBe(1);
      if (parsed.family !== 'ORGANIZATION_INVITATION') {
        const rendered = renderConsoleEmailV1(parsed);
        expect(rendered.subject.length).toBeGreaterThan(0);
        expect(rendered.text.length).toBeGreaterThan(0);
        expect(rendered.html).toContain('<!doctype html>');
      }
    }
    expect(families.size).toBe(7);
    expect(() =>
      parseConsoleEmailTemplate({
        family: 'BILLING_REFUND_RESULT',
        version: 1,
        outcome: 'SUCCEEDED',
        organizationName: 'Acme',
        refundId: 'refund-invalid',
        amountMinor: 100,
        currency: 'USD',
        consoleBaseUrl: 'https://console.example.test',
      }),
    ).toThrow('balanceAfterMinor');
  });

  test('queues one welcome email when onboarding completion is retried', async () => {
    const testDb = await createConsoleEmailTestDatabase();
    const welcomeEmail = createD1ConsoleOnboardingWelcomeEmail({
      database: testDb.database,
      namespace: NAMESPACE,
      consoleBaseUrl: 'https://console.example.test',
      docsBaseUrl: 'https://docs.example.test',
      now: fixedNow,
    });
    const email = {
      orgId: ORG_ID,
      userId: 'user-welcome',
      recipientEmail: 'ada@example.test',
      recipientDisplayName: 'Ada',
      organizationName: 'Acme',
      projectName: 'Checkout',
    };
    try {
      await welcomeEmail.enqueue(email);
      await welcomeEmail.enqueue(email);
      expect(
        await countRows(
          testDb.database,
          'console_email_outbox',
          'namespace = ? AND org_id = ? AND template_family = ?',
          [NAMESPACE, ORG_ID, 'ACCOUNT_WELCOME'],
        ),
      ).toBe(1);
      const provider = createCaptureConsoleEmailProvider();
      const result = await runD1ConsoleEmailDispatcher({
        database: testDb.database,
        namespace: NAMESPACE,
        provider,
        now: fixedNow,
      });
      expect(result.sentCount).toBe(1);
      expect(provider.listCaptured()[0]).toMatchObject({
        subject: 'Welcome to Seams',
        recipient: { email: 'ada@example.test', displayName: 'Ada' },
      });
      expect(provider.listCaptured()[0]?.text).toContain('What are you building?');
    } finally {
      cleanupTemporaryD1Database(testDb.tempDir);
    }
  });

  test('batches a domain mutation and outbox insert atomically with a statement guard', async () => {
    const testDb = await createConsoleEmailTestDatabase();
    const cipher = createTestCipher();
    try {
      await testDb.database.exec(
        'CREATE TABLE domain_events (id TEXT PRIMARY KEY, created_at_ms INTEGER NOT NULL);',
      );
      const email = buildTopUpOutbox({
        outboxId: 'email-atomic',
        dedupeKey: 'top-up:purchase-atomic',
        createdAt: BASE_NOW,
      });
      const outboxStatement = await createConsoleEmailOutboxInsertStatement({
        database: testDb.database,
        namespace: NAMESPACE,
        email,
        invitationSecretCipher: cipher,
        insertGuard: 'PREVIOUS_STATEMENT_CHANGED_ONE',
      });
      await testDb.database.batch([
        testDb.database
          .prepare('INSERT INTO domain_events (id, created_at_ms) VALUES (?, ?)')
          .bind('domain-event-atomic', BASE_NOW.getTime()),
        outboxStatement,
      ]);
      expect(
        await countRows(testDb.database, 'console_email_outbox', 'namespace = ? AND org_id = ?', [
          NAMESPACE,
          ORG_ID,
        ]),
      ).toBe(1);

      const skippedEmail = buildTopUpOutbox({
        outboxId: 'email-guard-skipped',
        dedupeKey: 'top-up:guard-skipped',
        createdAt: BASE_NOW,
      });
      const skippedStatement = await createConsoleEmailOutboxInsertStatement({
        database: testDb.database,
        namespace: NAMESPACE,
        email: skippedEmail,
        invitationSecretCipher: cipher,
        insertGuard: 'PREVIOUS_STATEMENT_CHANGED_ONE',
      });
      await testDb.database.batch([
        testDb.database
          .prepare('INSERT OR IGNORE INTO domain_events (id, created_at_ms) VALUES (?, ?)')
          .bind('domain-event-atomic', BASE_NOW.getTime()),
        skippedStatement,
      ]);
      expect(
        await countRows(testDb.database, 'console_email_outbox', 'namespace = ? AND org_id = ?', [
          NAMESPACE,
          ORG_ID,
        ]),
      ).toBe(1);
    } finally {
      cleanupTemporaryD1Database(testDb.tempDir);
    }
  });

  test('encrypts invitation material and erases it after provider acceptance', async () => {
    const testDb = await createConsoleEmailTestDatabase();
    const cipher = createTestCipher();
    const provider = createCaptureConsoleEmailProvider();
    try {
      await insertOutbox(
        testDb.database,
        cipher,
        buildInvitationOutbox({
          outboxId: 'email-invitation',
          dedupeKey: 'invitation:inv-1:v1',
          invitationId: 'inv-1',
          createdAt: BASE_NOW,
          expiresAt: new Date(BASE_NOW.getTime() + 7 * 24 * 60 * 60_000),
        }),
      );
      const pending = await readRawOutbox(testDb.database, 'email-invitation');
      expect(String(pending.template_payload_json)).not.toContain(INVITATION_SECRET);
      expect(String(pending.invitation_secret_ciphertext_b64u)).not.toContain(INVITATION_SECRET);

      const result = await runD1ConsoleEmailDispatcher({
        database: testDb.database,
        namespace: NAMESPACE,
        provider,
        invitationSecretCipher: cipher,
        now: fixedNow,
      });
      expect(result.sentCount).toBe(1);
      expect(provider.listCaptured()).toHaveLength(1);
      expect(provider.listCaptured()[0]?.text).toContain(encodeURIComponent(INVITATION_SECRET));

      const sent = await readRawOutbox(testDb.database, 'email-invitation');
      expect(sent.status).toBe('SENT');
      expect(sent.invitation_secret_ciphertext_b64u).toBeNull();
      expect(sent.invitation_secret_key_id).toBeNull();
      expect(sent.invitation_secret_envelope_version).toBeNull();

      const deliveries = await listD1ConsoleEmailDeliveries({
        database: testDb.database,
        namespace: NAMESPACE,
        orgId: ORG_ID,
        outboxId: 'email-invitation',
      });
      expect(JSON.stringify(deliveries)).not.toContain(INVITATION_SECRET);
      const rawDeliveries = await testDb.database
        .prepare('SELECT * FROM console_email_deliveries WHERE namespace = ? AND org_id = ?')
        .bind(NAMESPACE, ORG_ID)
        .all<Record<string, unknown>>();
      expect(JSON.stringify(rawDeliveries.results || [])).not.toContain(INVITATION_SECRET);
    } finally {
      cleanupTemporaryD1Database(testDb.tempDir);
    }
  });

  test('uses a claim lease so concurrent workers send one message once', async () => {
    const testDb = await createConsoleEmailTestDatabase();
    const cipher = createTestCipher();
    const provider = new SlowConsoleEmailProvider();
    try {
      await insertOutbox(
        testDb.database,
        cipher,
        buildTopUpOutbox({
          outboxId: 'email-concurrent',
          dedupeKey: 'top-up:concurrent',
          createdAt: BASE_NOW,
        }),
      );
      const first = runD1ConsoleEmailDispatcher({
        database: testDb.database,
        namespace: NAMESPACE,
        provider,
        invitationSecretCipher: cipher,
        now: fixedNow,
        workerId: 'worker-one',
      });
      await delay();
      const second = runD1ConsoleEmailDispatcher({
        database: testDb.database,
        namespace: NAMESPACE,
        provider,
        invitationSecretCipher: cipher,
        now: fixedNow,
        workerId: 'worker-two',
      });
      const results = await Promise.all([first, second]);
      expect(provider.sendCount).toBe(1);
      expect(results[0].sentCount + results[1].sentCount).toBe(1);
      expect(results[0].claimedCount + results[1].claimedCount).toBe(1);
      expect(
        await countRows(
          testDb.database,
          'console_email_deliveries',
          'namespace = ? AND org_id = ? AND outbox_id = ?',
          [NAMESPACE, ORG_ID, 'email-concurrent'],
        ),
      ).toBe(1);
    } finally {
      cleanupTemporaryD1Database(testDb.tempDir);
    }
  });

  test('retries transient failures, records final failure, and supports manual retry', async () => {
    const testDb = await createConsoleEmailTestDatabase();
    const cipher = createTestCipher();
    const provider = new SequencedConsoleEmailProvider([
      retryableProviderResult('resend_http_503'),
      retryableProviderResult('resend_http_503'),
      sentProviderResult('provider-after-retry'),
    ]);
    const clock = new MutableConsoleEmailClock(BASE_NOW);
    const now = clock.now.bind(clock);
    try {
      await insertOutbox(
        testDb.database,
        cipher,
        buildTopUpOutbox({
          outboxId: 'email-retries',
          dedupeKey: 'top-up:retries',
          createdAt: BASE_NOW,
        }),
      );
      const first = await runD1ConsoleEmailDispatcher({
        database: testDb.database,
        namespace: NAMESPACE,
        provider,
        invitationSecretCipher: cipher,
        now,
        maxAttemptsPerCycle: 2,
        initialBackoffMs: 1_000,
      });
      expect(first.retryScheduledCount).toBe(1);
      clock.advance(1_000);

      const second = await runD1ConsoleEmailDispatcher({
        database: testDb.database,
        namespace: NAMESPACE,
        provider,
        invitationSecretCipher: cipher,
        now,
        maxAttemptsPerCycle: 2,
        initialBackoffMs: 1_000,
      });
      expect(second.finalFailureCount).toBe(1);
      expect(
        (
          await getD1ConsoleEmailOutbox({
            database: testDb.database,
            namespace: NAMESPACE,
            orgId: ORG_ID,
            outboxId: 'email-retries',
          })
        )?.status,
      ).toBe('FINAL_FAILED');
      const finalFailures = await listD1ConsoleEmailFinalFailures({
        database: testDb.database,
        namespace: NAMESPACE,
        orgId: ORG_ID,
      });
      expect(finalFailures).toHaveLength(1);
      expect(finalFailures[0]?.lastErrorCode).toBe('resend_http_503');

      clock.advance(1_000);
      expect(
        await retryD1ConsoleEmailFinalFailure({
          database: testDb.database,
          namespace: NAMESPACE,
          orgId: ORG_ID,
          outboxId: 'email-retries',
          now,
        }),
      ).toBe(true);
      const third = await runD1ConsoleEmailDispatcher({
        database: testDb.database,
        namespace: NAMESPACE,
        provider,
        invitationSecretCipher: cipher,
        now,
        maxAttemptsPerCycle: 2,
        initialBackoffMs: 1_000,
      });
      expect(third.sentCount).toBe(1);
      const deliveries = await listD1ConsoleEmailDeliveries({
        database: testDb.database,
        namespace: NAMESPACE,
        orgId: ORG_ID,
        outboxId: 'email-retries',
      });
      expect(deliveries).toHaveLength(3);
      expect(deliveries[0]?.outcome).toBe('SENT');
      expect(deliveries[1]?.outcome).toBe('FINAL_FAILED');
      expect(deliveries[2]?.outcome).toBe('RETRYABLE_FAILED');
    } finally {
      cleanupTemporaryD1Database(testDb.tempDir);
    }
  });

  test('cancels and erases invitation secrets on domain terminal state or expiry', async () => {
    const testDb = await createConsoleEmailTestDatabase();
    const cipher = createTestCipher();
    const provider = createCaptureConsoleEmailProvider();
    try {
      await insertOutbox(
        testDb.database,
        cipher,
        buildInvitationOutbox({
          outboxId: 'email-canceled-invitation',
          dedupeKey: 'invitation:canceled',
          invitationId: 'inv-canceled',
          createdAt: BASE_NOW,
          expiresAt: new Date(BASE_NOW.getTime() + 60_000),
        }),
      );
      await testDb.database.batch([
        createConsoleInvitationEmailCancellationStatement({
          database: testDb.database,
          namespace: NAMESPACE,
          orgId: ORG_ID,
          invitationId: 'inv-canceled',
          canceledAt: new Date(BASE_NOW.getTime() + 1_000),
        }),
      ]);
      const canceled = await readRawOutbox(testDb.database, 'email-canceled-invitation');
      expect(canceled.status).toBe('CANCELED');
      expect(canceled.invitation_secret_ciphertext_b64u).toBeNull();

      await insertOutbox(
        testDb.database,
        cipher,
        buildInvitationOutbox({
          outboxId: 'email-expired-invitation',
          dedupeKey: 'invitation:expired',
          invitationId: 'inv-expired',
          createdAt: BASE_NOW,
          expiresAt: new Date(BASE_NOW.getTime() + 500),
        }),
      );
      const expiryResult = await runD1ConsoleEmailDispatcher({
        database: testDb.database,
        namespace: NAMESPACE,
        provider,
        invitationSecretCipher: cipher,
        now: nowAfterInvitationExpiry,
      });
      expect(expiryResult.canceledCount).toBe(1);
      expect(provider.listCaptured()).toHaveLength(0);
      const expired = await readRawOutbox(testDb.database, 'email-expired-invitation');
      expect(expired.status).toBe('CANCELED');
      expect(expired.invitation_secret_ciphertext_b64u).toBeNull();
    } finally {
      cleanupTemporaryD1Database(testDb.tempDir);
    }
  });

  test('sends Resend requests through fetch with the outbox idempotency key', async () => {
    resendFetchUrl = '';
    resendFetchInit = undefined;
    const provider = createResendConsoleEmailProvider({
      apiKey: 're_test_console_email',
      from: 'Seams <console@example.test>',
      apiUrl: 'https://resend.example.test/emails',
      fetchImpl: recordingResendFetch,
    });
    const result = await provider.send({
      outboxId: 'email-resend-idempotency',
      recipient: {
        email: 'recipient@example.test',
        displayName: 'Recipient',
      },
      subject: 'Test email',
      text: 'Text body',
      html: '<p>HTML body</p>',
    });
    expect(result).toEqual({
      kind: 'SENT',
      providerMessageId: 'resend-message-1',
      statusCode: 200,
    });
    expect(resendFetchUrl).toBe('https://resend.example.test/emails');
    const headers = new Headers(resendFetchInit?.headers);
    expect(headers.get('Idempotency-Key')).toBe('email-resend-idempotency');
    expect(headers.get('Authorization')).toBe('Bearer re_test_console_email');
    const body = JSON.parse(String(resendFetchInit?.body || '{}'));
    expect(body.to).toEqual(['recipient@example.test']);
    expect(body.subject).toBe('Test email');
  });
});

function fixedNow(): Date {
  return new Date(BASE_NOW);
}

function nowAfterInvitationExpiry(): Date {
  return new Date(BASE_NOW.getTime() + 1_000);
}
