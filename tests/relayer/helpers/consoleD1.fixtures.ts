import { expect } from '@playwright/test';
import type { ConsoleAccountContext } from '../../../packages/console-server-ts/src/account/service';
import {
  CONSOLE_BILLING_PREPAID_RESERVATION_D1_RUNTIME,
  getConsoleBillingPrepaidReservationD1Runtime,
  type ConsoleBillingPrepaidReservationD1Runtime,
} from '../../../packages/console-server-ts/src/billingPrepaidReservations/d1';
import type { ConsoleBillingPrepaidReservationService } from '../../../packages/console-server-ts/src/billingPrepaidReservations/service';
import type { ConsoleBillingPrepaidReservation } from '../../../packages/console-server-ts/src/billingPrepaidReservations/types';
import {
  runD1ConsoleRuntimeSnapshotOutboxDispatch,
  type D1ConsoleRuntimeSnapshotOutboxDispatchResult,
} from '../../../packages/console-server-ts/src/runtimeSnapshots/d1';
import type { ConsoleRuntimeSnapshotOutboxEvent } from '../../../packages/console-server-ts/src/runtimeSnapshots/types';
import {
  createAesGcmConsoleWebhookSecretCipher,
  runD1ConsoleWebhookRetryDispatch,
  type ConsoleWebhookSecretCipher,
  type D1ConsoleWebhookRetryDispatchResult,
} from '../../../packages/console-server-ts/src/webhooks/d1';
import type {
  WebhookDispatchAdapter,
  WebhookDispatchRequest,
  WebhookDispatchResult,
} from '../../../packages/console-server-ts/src/webhooks/service';
import {
  type EmailOtpChallengeContextInput,
  type EmailOtpChallengeRecord,
  type EmailOtpGrantRecord,
  type EmailOtpWalletEnrollmentRecord,
  type GoogleEmailOtpRegistrationAttemptRecord,
} from '../../../packages/sdk-server-ts/src/core/EmailOtpStores';
import type { NearPublicKeyRecord } from '../../../packages/sdk-server-ts/src/core/NearPublicKeyStore';
import type { D1DatabaseLike } from '../../../packages/sdk-server-ts/src/storage/tenantRoute';
import {
  EMAIL_OTP_CHANNEL,
  WALLET_EMAIL_OTP_ACTIONS,
  WALLET_EMAIL_OTP_UNLOCK_OPERATION,
} from '../../../packages/shared-ts/src/utils/emailOtpDomain';
import type { RecordSponsoredExecutionInput } from '../../../packages/console-server-ts/src/router/sponsorshipExecution';
import type {
  SponsorshipSpendPricingEstimateInput,
  SponsorshipSpendPricingFinalizeInput,
  SponsorshipSpendPricingQuote,
  SponsorshipSpendPricingService,
} from '../../../packages/console-server-ts/src/sponsorship/spendCaps';
import {
  applyD1MigrationFiles,
  type D1MigrationDirectoryName,
  listD1MigrationFiles,
} from '../../helpers/sqliteD1';

export type SqliteJsonRow = Record<string, unknown>;
export type ErrorWithCode = { readonly code?: unknown };
export type D1MigrationTarget = {
  readonly directoryName: D1MigrationDirectoryName;
};

export async function applyConsoleD1Migrations(database: D1DatabaseLike): Promise<void> {
  await applyD1MigrationFiles(database, listD1MigrationFiles('d1-console'));
}

export type SponsoredRecordBuildInput = Parameters<RecordSponsoredExecutionInput['buildRecord']>[0];
export type SponsoredRecordBuildOutput = ReturnType<RecordSponsoredExecutionInput['buildRecord']>;
export type RawD1SponsoredCallInsertInput = {
  readonly id: string;
  readonly detailsJson: string;
  readonly idempotencyKey: string;
  readonly estimatedSpendMinor: number | null;
  readonly settledSpendMinor: number | null;
  readonly createdAtMs: number;
  readonly updatedAtMs: number;
};
export type RawD1PrepaidReservationInsertInput = {
  readonly id: string;
  readonly environmentId: string;
  readonly sourceEventId: string;
  readonly requestedMinor: number;
  readonly postedBalanceMinor: number;
  readonly settledMinor: number;
  readonly releasedMinor: number;
  readonly status: string;
  readonly txOrExecutionRef: string | null;
  readonly pricingVersion: string | null;
  readonly expiresAtMs: number;
  readonly createdAtMs: number;
  readonly updatedAtMs: number;
};
export type RawD1BillingLedgerEntryInsertInput = {
  readonly namespace: string;
  readonly orgId: string;
  readonly id: string;
  readonly entryType: string;
  readonly amountMinor: number;
  readonly description: string;
  readonly monthUtc: string | null;
  readonly relatedInvoiceId: string | null;
  readonly relatedPurchaseId: string | null;
  readonly sourceEventId: string | null;
  readonly actorType: string;
  readonly actorUserId: string | null;
  readonly reasonCode: string | null;
  readonly note: string | null;
  readonly idempotencyKey: string | null;
  readonly createdAtMs: number;
};
export type RawD1BillingLedgerPostingInsertInput = {
  readonly namespace: string;
  readonly orgId: string;
  readonly id: string;
  readonly ledgerEntryId: string;
  readonly accountCode: string;
  readonly direction: string;
  readonly amountMinor: number;
  readonly createdAtMs: number;
};
export type RawD1BillingMonthlyActiveWalletInsertInput = {
  readonly namespace: string;
  readonly orgId: string;
  readonly monthUtc: string;
  readonly walletId: string;
  readonly sourceEventId: string | null;
  readonly createdAtMs: number;
};
export type RawD1RuntimeSnapshotInsertInput = {
  readonly namespace: string;
  readonly orgId: string;
  readonly projectId: string;
  readonly environmentId: string;
  readonly snapshotId: string;
  readonly version: number;
  readonly effectiveAtMs: number;
  readonly checksum: string;
  readonly payloadJson: string;
  readonly createdAtMs: number;
  readonly createdBy: string;
};
export type RawD1RuntimeSnapshotOutboxInsertInput = {
  readonly namespace: string;
  readonly orgId: string;
  readonly projectId: string;
  readonly environmentId: string;
  readonly eventId: string;
  readonly eventType: string;
  readonly snapshotId: string;
  readonly snapshotVersion: number;
  readonly payloadJson: string;
  readonly status: string;
  readonly attemptCount: number;
  readonly availableAtMs: number;
  readonly claimedBy: string | null;
  readonly claimExpiresAtMs: number | null;
  readonly lastError: string | null;
  readonly createdAtMs: number;
  readonly updatedAtMs: number;
  readonly dispatchedAtMs: number | null;
};
export type RawD1WebhookEndpointInsertInput = {
  readonly namespace: string;
  readonly orgId: string;
  readonly id: string;
  readonly url: string;
  readonly status: 'ACTIVE' | 'DISABLED' | string;
  readonly signingSecretCiphertextB64u: string;
  readonly signingSecretKeyId: string;
  readonly signingSecretEnvelopeVersion: string;
  readonly secretVersion: number;
  readonly secretPreview: string;
  readonly createdAtMs: number;
  readonly updatedAtMs: number;
};
export type RawD1WebhookEndpointCategoryInsertInput = {
  readonly namespace: string;
  readonly orgId: string;
  readonly endpointId: string;
  readonly category: string;
};
export type RawD1WalletAuthMethodInsertInput = {
  readonly walletId: string;
  readonly rpId: string;
  readonly kind: 'passkey' | 'email_otp';
  readonly walletAuthMethodId: string;
  readonly authIdentifierKey: string;
  readonly credentialIdB64u: string | null;
  readonly credentialPublicKeyB64u: string | null;
  readonly emailHashHex: string | null;
  readonly registrationAuthorityId: string | null;
  readonly recordJson: string;
  readonly createdAtMs: number;
  readonly updatedAtMs: number;
};
export type RawD1WalletSignerInsertInput = {
  readonly walletId: string;
  readonly signerFamily: 'ed25519' | 'ecdsa';
  readonly signerId: string;
  readonly chainTargetKey: string | null;
  readonly recordJson: string;
  readonly createdAtMs: number;
  readonly updatedAtMs: number;
};
export type RawD1WalletInsertInput = {
  readonly walletId: string;
  readonly recordJson: string;
  readonly createdAtMs: number;
  readonly updatedAtMs: number;
};
export type RawD1IdentityLinkInsertInput = {
  readonly namespace: string;
  readonly orgId: string;
  readonly projectId: string;
  readonly envId: string;
  readonly subject: string;
  readonly userId: string;
  readonly recordJson: string;
  readonly createdAtMs: number;
  readonly updatedAtMs: number;
};
export type RawD1AppSessionVersionInsertInput = {
  readonly namespace: string;
  readonly orgId: string;
  readonly projectId: string;
  readonly envId: string;
  readonly userId: string;
  readonly sessionVersion: string;
  readonly recordJson: string;
  readonly createdAtMs: number;
  readonly updatedAtMs: number;
};
export type RawD1EmailOtpChallengeInsertInput = {
  readonly namespace: string;
  readonly orgId: string;
  readonly projectId: string;
  readonly envId: string;
  readonly challengeId: string;
  readonly challengeSubjectId: string;
  readonly walletId: string;
  readonly recordOrgId: string;
  readonly otpChannel: string;
  readonly sessionHash: string;
  readonly appSessionVersion: string;
  readonly action: string;
  readonly operation: string;
  readonly otpCode: string;
  readonly recordJson: string;
  readonly createdAtMs: number;
  readonly expiresAtMs: number;
};
export type RawD1EmailOtpGrantInsertInput = {
  readonly namespace: string;
  readonly orgId: string;
  readonly projectId: string;
  readonly envId: string;
  readonly grantToken: string;
  readonly userId: string;
  readonly walletId: string;
  readonly recordOrgId: string;
  readonly challengeId: string;
  readonly action: string;
  readonly recordJson: string;
  readonly issuedAtMs: number;
  readonly expiresAtMs: number;
};
export type RawD1EmailOtpEnrollmentInsertInput = {
  readonly namespace: string;
  readonly orgId: string;
  readonly projectId: string;
  readonly envId: string;
  readonly walletId: string;
  readonly providerUserId: string;
  readonly recordOrgId: string;
  readonly verifiedEmail: string;
  readonly recordJson: string;
  readonly createdAtMs: number;
  readonly updatedAtMs: number;
};
export type RawD1EmailOtpAuthStateInsertInput = {
  readonly namespace: string;
  readonly orgId: string;
  readonly projectId: string;
  readonly envId: string;
  readonly walletId: string;
  readonly providerUserId: string;
  readonly recordOrgId: string;
  readonly recordJson: string;
  readonly createdAtMs: number;
  readonly updatedAtMs: number;
};
export type RawD1EmailOtpUnlockChallengeInsertInput = {
  readonly namespace: string;
  readonly orgId: string;
  readonly projectId: string;
  readonly envId: string;
  readonly challengeId: string;
  readonly walletId: string;
  readonly userId: string;
  readonly recordOrgId: string;
  readonly recordJson: string;
  readonly createdAtMs: number;
  readonly expiresAtMs: number;
};
export type RawD1EmailOtpRegistrationAttemptInsertInput = {
  readonly namespace: string;
  readonly orgId: string;
  readonly projectId: string;
  readonly envId: string;
  readonly attemptId: string;
  readonly providerSubject: string;
  readonly email: string;
  readonly walletId: string;
  readonly state: string;
  readonly appSessionVersion: string;
  readonly runtimeOrgId: string;
  readonly runtimePolicyKey: string;
  readonly offerWalletIdsJson: string;
  readonly recordJson: string;
  readonly createdAtMs: number;
  readonly updatedAtMs: number;
  readonly expiresAtMs: number;
};
export type RawD1EmailOtpRateLimitInsertInput = {
  readonly namespace: string;
  readonly orgId: string;
  readonly projectId: string;
  readonly envId: string;
  readonly rateKey: string;
  readonly consumedCount: number;
  readonly resetAtMs: number;
  readonly updatedAtMs: number;
};

export function unwrapFixture<T>(result: { ok: true; value: T } | { ok: false }): T {
  if (!result.ok) throw new Error('invalid fixture value');
  return result.value;
}

export function makeD1AccountOwnerContext(): ConsoleAccountContext {
  return {
    kind: 'authorized',
    userId: 'user-d1-account',
    orgId: 'org-d1-account-home',
    membershipId: 'membership-d1-account-owner',
    role: 'OWNER',
    authorizationVersion: 1,
    adminPermissions: [],
    projectAccess: { kind: 'all' },
    email: 'USER-D1-ACCOUNT@example.com',
    name: 'D1 Account User',
    provider: null,
    projectId: null,
    environmentId: null,
    platformSupport: false,
  };
}

export class RuntimeSnapshotOutboxRaceHarness {
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

export class TestMutableClock {
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

export class D1WebhookDispatchHarness implements WebhookDispatchAdapter {
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

export class D1WebhookRetryRaceHarness implements WebhookDispatchAdapter {
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
      dispatcher: { dispatch: this.competitorDispatch.bind(this) },
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

export class StaticSponsoredSpendPricingService implements SponsorshipSpendPricingService {
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

export class AtomicD1SponsoredRecordBuilder {
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

export class StaleReadPrepaidReservationService implements ConsoleBillingPrepaidReservationService {
  readonly [CONSOLE_BILLING_PREPAID_RESERVATION_D1_RUNTIME]: ConsoleBillingPrepaidReservationD1Runtime;

  constructor(
    private readonly delegate: ConsoleBillingPrepaidReservationService,
    private readonly staleReservation: ConsoleBillingPrepaidReservation,
  ) {
    const runtime = getConsoleBillingPrepaidReservationD1Runtime(delegate);
    if (!runtime) {
      throw new Error('Stale prepaid reservation wrapper requires a D1-backed delegate');
    }
    this[CONSOLE_BILLING_PREPAID_RESERVATION_D1_RUNTIME] = runtime;
  }

  async getReservationBySourceEventId(
    ctx: Parameters<ConsoleBillingPrepaidReservationService['getReservationBySourceEventId']>[0],
    sourceEventId: string,
  ): ReturnType<ConsoleBillingPrepaidReservationService['getReservationBySourceEventId']> {
    if (sourceEventId === this.staleReservation.sourceEventId) {
      return { ...this.staleReservation };
    }
    return await this.delegate.getReservationBySourceEventId(ctx, sourceEventId);
  }

  async getSummary(
    ctx: Parameters<ConsoleBillingPrepaidReservationService['getSummary']>[0],
  ): ReturnType<ConsoleBillingPrepaidReservationService['getSummary']> {
    return await this.delegate.getSummary(ctx);
  }

  async reserve(
    ctx: Parameters<ConsoleBillingPrepaidReservationService['reserve']>[0],
    request: Parameters<ConsoleBillingPrepaidReservationService['reserve']>[1],
  ): ReturnType<ConsoleBillingPrepaidReservationService['reserve']> {
    return await this.delegate.reserve(ctx, request);
  }

  async settle(
    ctx: Parameters<ConsoleBillingPrepaidReservationService['settle']>[0],
    request: Parameters<ConsoleBillingPrepaidReservationService['settle']>[1],
  ): ReturnType<ConsoleBillingPrepaidReservationService['settle']> {
    return await this.delegate.settle(ctx, request);
  }

  async release(
    ctx: Parameters<ConsoleBillingPrepaidReservationService['release']>[0],
    request: Parameters<ConsoleBillingPrepaidReservationService['release']>[1],
  ): ReturnType<ConsoleBillingPrepaidReservationService['release']> {
    return await this.delegate.release(ctx, request);
  }

  async expireStaleReservations(
    request?: Parameters<ConsoleBillingPrepaidReservationService['expireStaleReservations']>[0],
  ): ReturnType<ConsoleBillingPrepaidReservationService['expireStaleReservations']> {
    return await this.delegate.expireStaleReservations(request);
  }
}

export function fixedD1AtomicBillingNow(): Date {
  return new Date('2026-06-27T00:00:00.000Z');
}

export function buildRawD1SponsoredCallInsertInput(input: {
  readonly id: string;
  readonly detailsJson?: string;
  readonly idempotencyKey?: string;
  readonly estimatedSpendMinor?: number | null;
  readonly settledSpendMinor?: number | null;
  readonly createdAtMs?: number;
  readonly updatedAtMs?: number;
}): RawD1SponsoredCallInsertInput {
  return {
    id: input.id,
    detailsJson: input.detailsJson ?? '{}',
    idempotencyKey: input.idempotencyKey ?? `raw-${input.id}`,
    estimatedSpendMinor: input.estimatedSpendMinor ?? null,
    settledSpendMinor: input.settledSpendMinor ?? null,
    createdAtMs: input.createdAtMs ?? Date.parse('2026-06-27T00:00:00.000Z'),
    updatedAtMs: input.updatedAtMs ?? Date.parse('2026-06-27T00:00:01.000Z'),
  };
}

export function buildRawD1PrepaidReservationInsertInput(input: {
  readonly id: string;
  readonly environmentId?: string;
  readonly sourceEventId?: string;
  readonly requestedMinor?: number;
  readonly postedBalanceMinor?: number;
  readonly settledMinor?: number;
  readonly releasedMinor?: number;
  readonly status?: string;
  readonly txOrExecutionRef?: string | null;
  readonly pricingVersion?: string | null;
  readonly expiresAtMs?: number;
  readonly createdAtMs?: number;
  readonly updatedAtMs?: number;
}): RawD1PrepaidReservationInsertInput {
  const createdAtMs = input.createdAtMs ?? Date.parse('2026-06-27T00:00:00.000Z');
  const requestedMinor = input.requestedMinor ?? 100;
  const settledMinor = input.settledMinor ?? 75;
  return {
    id: input.id,
    environmentId: input.environmentId ?? 'env-production',
    sourceEventId: input.sourceEventId ?? `raw-${input.id}`,
    requestedMinor,
    postedBalanceMinor: input.postedBalanceMinor ?? 1000,
    settledMinor,
    releasedMinor: input.releasedMinor ?? Math.max(requestedMinor - settledMinor, 0),
    status: input.status ?? 'SETTLED',
    txOrExecutionRef:
      input.txOrExecutionRef === undefined ? '0xrawsettled' : input.txOrExecutionRef,
    pricingVersion: input.pricingVersion === undefined ? 'static:raw' : input.pricingVersion,
    expiresAtMs: input.expiresAtMs ?? createdAtMs + 60_000,
    createdAtMs,
    updatedAtMs: input.updatedAtMs ?? createdAtMs + 1000,
  };
}

export function buildRawD1BillingLedgerEntryInsertInput(
  input: Partial<RawD1BillingLedgerEntryInsertInput>,
): RawD1BillingLedgerEntryInsertInput {
  return {
    namespace: input.namespace ?? 'd1-contracts',
    orgId: input.orgId ?? 'org-d1-billing-ledger-schema',
    id: input.id ?? 'ble_raw_schema',
    entryType: input.entryType ?? 'MANUAL_ADJUSTMENT',
    amountMinor: input.amountMinor ?? 100,
    description: input.description ?? 'Raw manual adjustment',
    monthUtc: input.monthUtc === undefined ? '2026-06' : input.monthUtc,
    relatedInvoiceId: input.relatedInvoiceId === undefined ? null : input.relatedInvoiceId,
    relatedPurchaseId: input.relatedPurchaseId === undefined ? null : input.relatedPurchaseId,
    sourceEventId: input.sourceEventId === undefined ? 'raw-ledger-source' : input.sourceEventId,
    actorType: input.actorType ?? 'SYSTEM',
    actorUserId: input.actorUserId === undefined ? null : input.actorUserId,
    reasonCode: input.reasonCode === undefined ? 'raw_adjustment' : input.reasonCode,
    note: input.note === undefined ? 'Raw ledger adjustment' : input.note,
    idempotencyKey:
      input.idempotencyKey === undefined ? 'raw-ledger-idempotency' : input.idempotencyKey,
    createdAtMs: input.createdAtMs ?? Date.parse('2026-06-27T00:00:00.000Z'),
  };
}

export function buildRawD1BillingLedgerPostingInsertInput(
  input: Partial<RawD1BillingLedgerPostingInsertInput>,
): RawD1BillingLedgerPostingInsertInput {
  return {
    namespace: input.namespace ?? 'd1-contracts',
    orgId: input.orgId ?? 'org-d1-billing-ledger-schema',
    id: input.id ?? 'ble_raw_schema:manual_posting',
    ledgerEntryId: input.ledgerEntryId ?? 'ble_raw_schema',
    accountCode: input.accountCode ?? 'org_prepaid_liability',
    direction: input.direction ?? 'DEBIT',
    amountMinor: input.amountMinor ?? 100,
    createdAtMs: input.createdAtMs ?? Date.parse('2026-06-27T00:00:00.000Z'),
  };
}

export function buildRawD1BillingMonthlyActiveWalletInsertInput(
  input: Partial<RawD1BillingMonthlyActiveWalletInsertInput>,
): RawD1BillingMonthlyActiveWalletInsertInput {
  return {
    namespace: input.namespace ?? 'd1-contracts',
    orgId: input.orgId ?? 'org-d1-billing-ledger-schema',
    monthUtc: input.monthUtc ?? '2026-06',
    walletId: input.walletId ?? 'wallet-raw-billing-ledger',
    sourceEventId:
      input.sourceEventId === undefined ? 'raw-monthly-wallet-source' : input.sourceEventId,
    createdAtMs: input.createdAtMs ?? Date.parse('2026-06-27T00:00:00.000Z'),
  };
}

export function buildRawD1RuntimeSnapshotInsertInput(
  input: Partial<RawD1RuntimeSnapshotInsertInput>,
): RawD1RuntimeSnapshotInsertInput {
  const createdAtMs = input.createdAtMs ?? Date.parse('2026-06-27T00:00:00.000Z');
  const snapshotId = input.snapshotId ?? 'runtime_snapshot_raw_schema';
  return {
    namespace: input.namespace ?? 'd1-contracts',
    orgId: input.orgId ?? 'org-d1-runtime-schema',
    projectId: input.projectId ?? 'project-d1-runtime-schema',
    environmentId: input.environmentId ?? 'env-production',
    snapshotId,
    version: input.version ?? 1,
    effectiveAtMs: input.effectiveAtMs ?? createdAtMs,
    checksum: input.checksum ?? 'fnv1a32:1234abcd',
    payloadJson:
      input.payloadJson ??
      JSON.stringify({
        policy: {},
        gasSponsorship: {},
      }),
    createdAtMs,
    createdBy: input.createdBy ?? 'user-runtime-schema',
  };
}

export function buildRawD1RuntimeSnapshotOutboxInsertInput(
  input: Partial<RawD1RuntimeSnapshotOutboxInsertInput>,
): RawD1RuntimeSnapshotOutboxInsertInput {
  const createdAtMs = input.createdAtMs ?? Date.parse('2026-06-27T00:00:00.000Z');
  const updatedAtMs = input.updatedAtMs ?? createdAtMs + 1000;
  const eventId = input.eventId ?? 'runtime_snapshot_event_raw_schema';
  const snapshotId = input.snapshotId ?? 'runtime_snapshot_raw_schema';
  return {
    namespace: input.namespace ?? 'd1-contracts',
    orgId: input.orgId ?? 'org-d1-runtime-schema',
    projectId: input.projectId ?? 'project-d1-runtime-schema',
    environmentId: input.environmentId ?? 'env-production',
    eventId,
    eventType: input.eventType ?? 'RUNTIME_SNAPSHOT_PUBLISHED_V1',
    snapshotId,
    snapshotVersion: input.snapshotVersion ?? 1,
    payloadJson:
      input.payloadJson ??
      JSON.stringify({
        eventType: 'runtime_snapshot.published.v1',
        snapshot: {
          snapshotId,
        },
      }),
    status: input.status ?? 'PENDING',
    attemptCount: input.attemptCount ?? 0,
    availableAtMs: input.availableAtMs ?? createdAtMs,
    claimedBy: input.claimedBy === undefined ? null : input.claimedBy,
    claimExpiresAtMs: input.claimExpiresAtMs === undefined ? null : input.claimExpiresAtMs,
    lastError: input.lastError === undefined ? null : input.lastError,
    createdAtMs,
    updatedAtMs,
    dispatchedAtMs: input.dispatchedAtMs === undefined ? null : input.dispatchedAtMs,
  };
}

export function buildRawD1WebhookEndpointInsertInput(
  input: Partial<RawD1WebhookEndpointInsertInput>,
): RawD1WebhookEndpointInsertInput {
  const createdAtMs = input.createdAtMs ?? Date.parse('2026-06-27T00:00:00.000Z');
  return {
    namespace: input.namespace ?? 'd1-contracts',
    orgId: input.orgId ?? 'org-d1-webhook-schema',
    id: input.id ?? 'wh_raw_webhook_schema',
    url: input.url ?? 'https://webhook.example.test/receive',
    status: input.status ?? 'ACTIVE',
    signingSecretCiphertextB64u: input.signingSecretCiphertextB64u ?? 'c2VhbGVkX3NlY3JldA',
    signingSecretKeyId: input.signingSecretKeyId ?? 'webhook-kek-raw',
    signingSecretEnvelopeVersion:
      input.signingSecretEnvelopeVersion ?? 'console-webhook-secret:aes-gcm:v1',
    secretVersion: input.secretVersion ?? 1,
    secretPreview: input.secretPreview ?? 'whsec_raw...',
    createdAtMs,
    updatedAtMs: input.updatedAtMs ?? createdAtMs + 1000,
  };
}

export function buildRawD1WebhookEndpointCategoryInsertInput(
  input: Partial<RawD1WebhookEndpointCategoryInsertInput>,
): RawD1WebhookEndpointCategoryInsertInput {
  return {
    namespace: input.namespace ?? 'd1-contracts',
    orgId: input.orgId ?? 'org-d1-webhook-schema',
    endpointId: input.endpointId ?? 'wh_raw_webhook_schema',
    category: input.category ?? 'wallet',
  };
}

export function buildRawD1PasskeyAuthMethodInsertInput(input: {
  readonly rpId?: string;
  readonly walletId?: string;
  readonly credentialIdB64u?: string | null;
  readonly credentialPublicKeyB64u?: string | null;
  readonly emailHashHex?: string | null;
  readonly registrationAuthorityId?: string | null;
  readonly walletAuthMethodId?: string;
  readonly authIdentifierKey?: string;
}): RawD1WalletAuthMethodInsertInput {
  const rpId = input.rpId ?? 'app.example.test';
  const walletId = input.walletId ?? 'wallet-raw-passkey';
  const credentialIdB64u =
    input.credentialIdB64u === undefined ? 'credential-raw-passkey' : input.credentialIdB64u;
  return {
    walletId,
    rpId,
    kind: 'passkey',
    walletAuthMethodId: input.walletAuthMethodId ?? `passkey:${rpId}:${credentialIdB64u || ''}`,
    authIdentifierKey: input.authIdentifierKey ?? credentialIdB64u ?? '',
    credentialIdB64u,
    credentialPublicKeyB64u:
      input.credentialPublicKeyB64u === undefined
        ? 'credential-public-key-raw-passkey'
        : input.credentialPublicKeyB64u,
    emailHashHex: input.emailHashHex ?? null,
    registrationAuthorityId: input.registrationAuthorityId ?? null,
    recordJson: '{}',
    createdAtMs: Date.parse('2026-06-27T00:00:00.000Z'),
    updatedAtMs: Date.parse('2026-06-27T00:00:01.000Z'),
  };
}

export function buildRawD1EmailOtpAuthMethodInsertInput(input: {
  readonly rpId?: string;
  readonly walletId?: string;
  readonly credentialIdB64u?: string | null;
  readonly credentialPublicKeyB64u?: string | null;
  readonly emailHashHex?: string | null;
  readonly registrationAuthorityId?: string | null;
  readonly walletAuthMethodId?: string;
  readonly authIdentifierKey?: string;
}): RawD1WalletAuthMethodInsertInput {
  const walletId = input.walletId ?? 'wallet-raw-email-otp';
  const emailHashHex = input.emailHashHex === undefined ? 'a'.repeat(64) : input.emailHashHex;
  return {
    walletId,
    rpId: input.rpId ?? '',
    kind: 'email_otp',
    walletAuthMethodId: input.walletAuthMethodId ?? `email_otp:${walletId}:${emailHashHex || ''}`,
    authIdentifierKey: input.authIdentifierKey ?? emailHashHex ?? '',
    credentialIdB64u: input.credentialIdB64u ?? null,
    credentialPublicKeyB64u: input.credentialPublicKeyB64u ?? null,
    emailHashHex,
    registrationAuthorityId:
      input.registrationAuthorityId === undefined
        ? 'registration-authority-raw-email'
        : input.registrationAuthorityId,
    recordJson: '{}',
    createdAtMs: Date.parse('2026-06-27T00:00:00.000Z'),
    updatedAtMs: Date.parse('2026-06-27T00:00:01.000Z'),
  };
}

export function buildRawD1Ed25519WalletSignerInsertInput(input: {
  readonly walletId?: string;
  readonly signerId?: string;
  readonly chainTargetKey?: string | null;
  readonly recordJson?: string;
}): RawD1WalletSignerInsertInput {
  const walletId = input.walletId ?? 'wallet-raw-ed25519-signer';
  const signerId = input.signerId ?? 'ed25519:wallet-raw-ed25519.testnet:1';
  return {
    walletId,
    signerFamily: 'ed25519',
    signerId,
    chainTargetKey: input.chainTargetKey ?? null,
    recordJson:
      input.recordJson ??
      JSON.stringify({
        version: 'wallet_signer_ed25519_v1',
        walletId,
        signerId,
      }),
    createdAtMs: Date.parse('2026-06-27T00:00:00.000Z'),
    updatedAtMs: Date.parse('2026-06-27T00:00:01.000Z'),
  };
}

export function buildRawD1WalletInsertInput(input: {
  readonly walletId?: string;
  readonly recordJson?: string;
  readonly createdAtMs?: number;
  readonly updatedAtMs?: number;
}): RawD1WalletInsertInput {
  const walletId = input.walletId ?? 'wallet-raw-identity';
  return {
    walletId,
    recordJson:
      input.recordJson ??
      JSON.stringify({
        version: 'wallet_v1',
        walletId,
      }),
    createdAtMs: input.createdAtMs ?? Date.parse('2026-06-27T00:00:00.000Z'),
    updatedAtMs: input.updatedAtMs ?? Date.parse('2026-06-27T00:00:01.000Z'),
  };
}

export function buildRawD1EcdsaWalletSignerInsertInput(input: {
  readonly walletId?: string;
  readonly signerId?: string;
  readonly chainTargetKey?: string | null;
  readonly recordJson?: string;
}): RawD1WalletSignerInsertInput {
  const walletId = input.walletId ?? 'wallet-raw-ecdsa-signer';
  const chainTargetKey =
    input.chainTargetKey === undefined ? 'evm:eip155:8453' : input.chainTargetKey;
  const signerId = input.signerId ?? `ecdsa:${chainTargetKey || ''}`;
  return {
    walletId,
    signerFamily: 'ecdsa',
    signerId,
    chainTargetKey,
    recordJson:
      input.recordJson ??
      JSON.stringify({
        version: 'wallet_signer_ecdsa_v1',
        walletId,
        signerId,
        chainTargetKey,
      }),
    createdAtMs: Date.parse('2026-06-27T00:00:00.000Z'),
    updatedAtMs: Date.parse('2026-06-27T00:00:01.000Z'),
  };
}

export function buildRawD1IdentityLinkInsertInput(
  input: Partial<RawD1IdentityLinkInsertInput>,
): RawD1IdentityLinkInsertInput {
  const createdAtMs = input.createdAtMs ?? Date.parse('2026-06-27T00:00:00.000Z');
  const updatedAtMs = input.updatedAtMs ?? createdAtMs + 1000;
  const subject = input.subject ?? 'google:raw-identity-subject';
  const userId = input.userId ?? 'wallet-raw-identity-session';
  return {
    namespace: input.namespace ?? 'd1-contracts',
    orgId: input.orgId ?? 'org-d1-identity-schema',
    projectId: input.projectId ?? 'project-d1-identity-schema',
    envId: input.envId ?? 'env-production',
    subject,
    userId,
    recordJson:
      input.recordJson ??
      JSON.stringify({
        version: 'identity_subject_v1',
        subject,
        userId,
        createdAtMs,
        updatedAtMs,
      }),
    createdAtMs,
    updatedAtMs,
  };
}

export function buildRawD1AppSessionVersionInsertInput(
  input: Partial<RawD1AppSessionVersionInsertInput>,
): RawD1AppSessionVersionInsertInput {
  const createdAtMs = input.createdAtMs ?? Date.parse('2026-06-27T00:00:00.000Z');
  const updatedAtMs = input.updatedAtMs ?? createdAtMs + 1000;
  const userId = input.userId ?? 'wallet-raw-app-session';
  const sessionVersion = input.sessionVersion ?? 'app-session-version-raw';
  return {
    namespace: input.namespace ?? 'd1-contracts',
    orgId: input.orgId ?? 'org-d1-identity-schema',
    projectId: input.projectId ?? 'project-d1-identity-schema',
    envId: input.envId ?? 'env-production',
    userId,
    sessionVersion,
    recordJson:
      input.recordJson ??
      JSON.stringify({
        version: 'app_session_version_v1',
        userId,
        appSessionVersion: sessionVersion,
        createdAtMs,
        updatedAtMs,
      }),
    createdAtMs,
    updatedAtMs,
  };
}

export function buildRawD1EmailOtpChallengeInsertInput(
  input: Partial<RawD1EmailOtpChallengeInsertInput>,
): RawD1EmailOtpChallengeInsertInput {
  const createdAtMs = input.createdAtMs ?? Date.parse('2026-06-27T00:00:00.000Z');
  const expiresAtMs = input.expiresAtMs ?? createdAtMs + 600_000;
  const challengeId = input.challengeId ?? 'email-otp-challenge-raw-schema';
  const challengeSubjectId = input.challengeSubjectId ?? 'google-subject-raw-email-otp';
  const walletId = input.walletId ?? 'wallet-raw-email-otp';
  const recordOrgId = input.recordOrgId ?? 'org-d1-email-otp-schema';
  const otpChannel = input.otpChannel ?? 'email_otp';
  const sessionHash = input.sessionHash ?? 'session-hash-raw-email-otp';
  const appSessionVersion = input.appSessionVersion ?? 'app-session-raw-email-otp';
  const action = input.action ?? 'wallet_email_otp_login';
  const operation = input.operation ?? 'wallet_unlock';
  const otpCode = input.otpCode ?? '123456';
  return {
    namespace: input.namespace ?? 'd1-contracts',
    orgId: input.orgId ?? 'org-d1-email-otp-schema',
    projectId: input.projectId ?? 'project-d1-email-otp-schema',
    envId: input.envId ?? 'env-production',
    challengeId,
    challengeSubjectId,
    walletId,
    recordOrgId,
    otpChannel,
    sessionHash,
    appSessionVersion,
    action,
    operation,
    otpCode,
    recordJson:
      input.recordJson ??
      JSON.stringify({
        version: 'email_otp_challenge_v1',
        challengeId,
        challengeSubjectId,
        walletId,
        orgId: recordOrgId,
        otpChannel,
        email: 'raw@example.test',
        otpCode,
        sessionHash,
        appSessionVersion,
        action,
        operation,
        createdAtMs,
        expiresAtMs,
        attemptCount: 0,
        maxAttempts: 3,
      }),
    createdAtMs,
    expiresAtMs,
  };
}

export function buildRawD1EmailOtpGrantInsertInput(
  input: Partial<RawD1EmailOtpGrantInsertInput>,
): RawD1EmailOtpGrantInsertInput {
  const issuedAtMs = input.issuedAtMs ?? Date.parse('2026-06-27T00:00:00.000Z');
  const expiresAtMs = input.expiresAtMs ?? issuedAtMs + 600_000;
  const grantToken = input.grantToken ?? 'email-otp-grant-raw-schema';
  const userId = input.userId ?? 'google-subject-raw-email-otp';
  const walletId = input.walletId ?? 'wallet-raw-email-otp';
  const recordOrgId = input.recordOrgId ?? 'org-d1-email-otp-schema';
  const challengeId = input.challengeId ?? 'email-otp-challenge-raw-schema';
  const action = input.action ?? 'wallet_email_otp_unseal';
  return {
    namespace: input.namespace ?? 'd1-contracts',
    orgId: input.orgId ?? 'org-d1-email-otp-schema',
    projectId: input.projectId ?? 'project-d1-email-otp-schema',
    envId: input.envId ?? 'env-production',
    grantToken,
    userId,
    walletId,
    recordOrgId,
    challengeId,
    action,
    recordJson:
      input.recordJson ??
      JSON.stringify({
        version: 'email_otp_grant_v1',
        grantToken,
        userId,
        walletId,
        orgId: recordOrgId,
        challengeId,
        otpChannel: 'email_otp',
        sessionHash: 'session-hash-raw-email-otp',
        appSessionVersion: 'app-session-raw-email-otp',
        action,
        issuedAtMs,
        expiresAtMs,
      }),
    issuedAtMs,
    expiresAtMs,
  };
}

export function buildRawD1EmailOtpEnrollmentInsertInput(
  input: Partial<RawD1EmailOtpEnrollmentInsertInput>,
): RawD1EmailOtpEnrollmentInsertInput {
  const createdAtMs = input.createdAtMs ?? Date.parse('2026-06-27T00:00:00.000Z');
  const updatedAtMs = input.updatedAtMs ?? createdAtMs + 1000;
  const walletId = input.walletId ?? 'wallet-raw-email-otp';
  const providerUserId = input.providerUserId ?? 'google-subject-raw-email-otp';
  const recordOrgId = input.recordOrgId ?? 'org-d1-email-otp-schema';
  const verifiedEmail = input.verifiedEmail ?? 'raw@example.test';
  return {
    namespace: input.namespace ?? 'd1-contracts',
    orgId: input.orgId ?? 'org-d1-email-otp-schema',
    projectId: input.projectId ?? 'project-d1-email-otp-schema',
    envId: input.envId ?? 'env-production',
    walletId,
    providerUserId,
    recordOrgId,
    verifiedEmail,
    recordJson:
      input.recordJson ??
      JSON.stringify({
        version: 'email_otp_wallet_enrollment_v1',
        walletId,
        providerUserId,
        orgId: recordOrgId,
        verifiedEmail,
        enrollmentId: 'enrollment-raw-email-otp',
        enrollmentVersion: '1',
        enrollmentSealKeyVersion: 'seal-v1',
        signingRootId: 'signing-root-raw-email-otp',
        signingRootVersion: '1',
        recoveryWrappedEnrollmentEscrowCount: 10,
        clientUnlockPublicKeyB64u: 'A'.repeat(43),
        unlockKeyVersion: 'unlock-v1',
        thresholdEcdsaClientVerifyingShareB64u: 'B'.repeat(43),
        createdAtMs,
        updatedAtMs,
      }),
    createdAtMs,
    updatedAtMs,
  };
}

export function buildRawD1EmailOtpAuthStateInsertInput(
  input: Partial<RawD1EmailOtpAuthStateInsertInput>,
): RawD1EmailOtpAuthStateInsertInput {
  const createdAtMs = input.createdAtMs ?? Date.parse('2026-06-27T00:00:00.000Z');
  const updatedAtMs = input.updatedAtMs ?? createdAtMs + 1000;
  const walletId = input.walletId ?? 'wallet-raw-email-otp';
  const providerUserId = input.providerUserId ?? 'google-subject-raw-email-otp';
  const recordOrgId = input.recordOrgId ?? 'org-d1-email-otp-schema';
  return {
    namespace: input.namespace ?? 'd1-contracts',
    orgId: input.orgId ?? 'org-d1-email-otp-schema',
    projectId: input.projectId ?? 'project-d1-email-otp-schema',
    envId: input.envId ?? 'env-production',
    walletId,
    providerUserId,
    recordOrgId,
    recordJson:
      input.recordJson ??
      JSON.stringify({
        version: 'email_otp_auth_state_v1',
        walletId,
        providerUserId,
        orgId: recordOrgId,
        createdAtMs,
        updatedAtMs,
        otpFailureCount: 0,
      }),
    createdAtMs,
    updatedAtMs,
  };
}

export function buildRawD1EmailOtpUnlockChallengeInsertInput(
  input: Partial<RawD1EmailOtpUnlockChallengeInsertInput>,
): RawD1EmailOtpUnlockChallengeInsertInput {
  const createdAtMs = input.createdAtMs ?? Date.parse('2026-06-27T00:00:00.000Z');
  const expiresAtMs = input.expiresAtMs ?? createdAtMs + 600_000;
  const challengeId = input.challengeId ?? 'email-otp-unlock-challenge-raw-schema';
  const walletId = input.walletId ?? 'wallet-raw-email-otp';
  const userId = input.userId ?? 'google-subject-raw-email-otp';
  const recordOrgId = input.recordOrgId ?? 'org-d1-email-otp-schema';
  return {
    namespace: input.namespace ?? 'd1-contracts',
    orgId: input.orgId ?? 'org-d1-email-otp-schema',
    projectId: input.projectId ?? 'project-d1-email-otp-schema',
    envId: input.envId ?? 'env-production',
    challengeId,
    walletId,
    userId,
    recordOrgId,
    recordJson:
      input.recordJson ??
      JSON.stringify({
        version: 'email_otp_unlock_challenge_v1',
        challengeId,
        walletId,
        userId,
        orgId: recordOrgId,
        challengeB64u: 'unlock-challenge-raw-email-otp',
        createdAtMs,
        expiresAtMs,
      }),
    createdAtMs,
    expiresAtMs,
  };
}

export function buildRawD1EmailOtpRegistrationAttemptInsertInput(
  input: Partial<RawD1EmailOtpRegistrationAttemptInsertInput>,
): RawD1EmailOtpRegistrationAttemptInsertInput {
  const createdAtMs = input.createdAtMs ?? Date.parse('2026-06-27T00:00:00.000Z');
  const updatedAtMs = input.updatedAtMs ?? createdAtMs + 1000;
  const expiresAtMs = input.expiresAtMs ?? createdAtMs + 600_000;
  const attemptId = input.attemptId ?? 'email-otp-registration-attempt-raw-schema';
  const providerSubject = input.providerSubject ?? 'google-subject-raw-email-otp';
  const email = input.email ?? 'raw@example.test';
  const walletId = input.walletId ?? 'wallet-raw-email-otp';
  const state = input.state ?? 'started';
  const appSessionVersion = input.appSessionVersion ?? 'app-session-raw-email-otp';
  const runtimeOrgId = input.runtimeOrgId ?? 'org-d1-email-otp-schema';
  const runtimePolicyKey =
    input.runtimePolicyKey ??
    'org-d1-email-otp-schema\nproject-d1-email-otp-schema\nenv-production\n1';
  const offerWalletIdsJson = input.offerWalletIdsJson ?? JSON.stringify([walletId]);
  return {
    namespace: input.namespace ?? 'd1-contracts',
    orgId: input.orgId ?? 'org-d1-email-otp-schema',
    projectId: input.projectId ?? 'project-d1-email-otp-schema',
    envId: input.envId ?? 'env-production',
    attemptId,
    providerSubject,
    email,
    walletId,
    state,
    appSessionVersion,
    runtimeOrgId,
    runtimePolicyKey,
    offerWalletIdsJson,
    recordJson:
      input.recordJson ??
      JSON.stringify({
        version: 'google_email_otp_registration_attempt_v1',
        attemptId,
        providerSubject,
        email,
        walletId,
        offerId: 'offer-raw-email-otp',
        offerCandidates: [
          { candidateId: 'candidate-raw-email-otp', walletId, collisionCounter: 0 },
        ],
        selectedCandidateId: 'candidate-raw-email-otp',
        appSessionVersion,
        authProvider: 'google',
        accountIdSlugVersion: 'hmac_readable_v1',
        walletIdDerivationNonce: 'nonce-raw-email-otp',
        collisionCounter: 0,
        state,
        createdAtMs,
        updatedAtMs,
        expiresAtMs,
        runtimePolicyScope: {
          orgId: runtimeOrgId,
          projectId: 'project-d1-email-otp-schema',
          envId: 'env-production',
          signingRootVersion: '1',
        },
      }),
    createdAtMs,
    updatedAtMs,
    expiresAtMs,
  };
}

export function buildRawD1EmailOtpRateLimitInsertInput(
  input: Partial<RawD1EmailOtpRateLimitInsertInput>,
): RawD1EmailOtpRateLimitInsertInput {
  const updatedAtMs = input.updatedAtMs ?? Date.parse('2026-06-27T00:00:00.000Z');
  return {
    namespace: input.namespace ?? 'd1-contracts',
    orgId: input.orgId ?? 'org-d1-email-otp-schema',
    projectId: input.projectId ?? 'project-d1-email-otp-schema',
    envId: input.envId ?? 'env-production',
    rateKey: input.rateKey ?? 'scope=challenge:action=raw:limit=3:windowMs=60000:ip:127.0.0.1',
    consumedCount: input.consumedCount ?? 1,
    resetAtMs: input.resetAtMs ?? updatedAtMs + 60_000,
    updatedAtMs,
  };
}

export async function insertRawD1SponsoredCallRecord(
  database: D1DatabaseLike,
  input: RawD1SponsoredCallInsertInput,
): Promise<void> {
  await database
    .prepare(
      `INSERT INTO sponsored_call_records (
        namespace,
        org_id,
        id,
        environment_id,
        api_key_id,
        api_key_kind,
        route,
        receipt_status,
        details_json,
        estimated_spend_minor,
        settled_spend_minor,
        idempotency_key,
        created_at_ms,
        updated_at_ms
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
    )
    .bind(
      'd1-contracts',
      'org-d1-sponsored-schema',
      input.id,
      'env-production',
      'api-key-raw-sponsored',
      'secret_key',
      'sponsored_evm_call_v1',
      'success',
      input.detailsJson,
      input.estimatedSpendMinor,
      input.settledSpendMinor,
      input.idempotencyKey,
      input.createdAtMs,
      input.updatedAtMs,
    )
    .run();
}

export async function insertRawD1PrepaidReservationRecord(
  database: D1DatabaseLike,
  input: RawD1PrepaidReservationInsertInput,
): Promise<void> {
  await database
    .prepare(
      `INSERT INTO billing_prepaid_reservations (
        namespace,
        org_id,
        id,
        environment_id,
        source_event_id,
        requested_minor,
        posted_balance_minor,
        settled_minor,
        released_minor,
        status,
        tx_or_execution_ref,
        pricing_version,
        expires_at_ms,
        created_at_ms,
        updated_at_ms
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
    )
    .bind(
      'd1-contracts',
      'org-d1-prepaid-schema',
      input.id,
      input.environmentId,
      input.sourceEventId,
      input.requestedMinor,
      input.postedBalanceMinor,
      input.settledMinor,
      input.releasedMinor,
      input.status,
      input.txOrExecutionRef,
      input.pricingVersion,
      input.expiresAtMs,
      input.createdAtMs,
      input.updatedAtMs,
    )
    .run();
}

export async function insertRawD1BillingLedgerEntryRecord(
  database: D1DatabaseLike,
  input: RawD1BillingLedgerEntryInsertInput,
): Promise<void> {
  await database
    .prepare(
      `INSERT INTO billing_ledger_entries (
        namespace,
        org_id,
        id,
        entry_type,
        amount_minor,
        description,
        month_utc,
        related_invoice_id,
        related_purchase_id,
        source_event_id,
        actor_type,
        actor_user_id,
        reason_code,
        note,
        idempotency_key,
        created_at_ms
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
    )
    .bind(
      input.namespace,
      input.orgId,
      input.id,
      input.entryType,
      input.amountMinor,
      input.description,
      input.monthUtc,
      input.relatedInvoiceId,
      input.relatedPurchaseId,
      input.sourceEventId,
      input.actorType,
      input.actorUserId,
      input.reasonCode,
      input.note,
      input.idempotencyKey,
      input.createdAtMs,
    )
    .run();
}

export async function insertRawD1BillingLedgerPostingRecord(
  database: D1DatabaseLike,
  input: RawD1BillingLedgerPostingInsertInput,
): Promise<void> {
  await database
    .prepare(
      `INSERT INTO billing_ledger_postings (
        namespace,
        org_id,
        id,
        ledger_entry_id,
        account_code,
        direction,
        amount_minor,
        created_at_ms
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
    )
    .bind(
      input.namespace,
      input.orgId,
      input.id,
      input.ledgerEntryId,
      input.accountCode,
      input.direction,
      input.amountMinor,
      input.createdAtMs,
    )
    .run();
}

export async function insertRawD1BillingMonthlyActiveWalletRecord(
  database: D1DatabaseLike,
  input: RawD1BillingMonthlyActiveWalletInsertInput,
): Promise<void> {
  await database
    .prepare(
      `INSERT INTO billing_monthly_active_wallets (
        namespace,
        org_id,
        month_utc,
        wallet_id,
        source_event_id,
        created_at_ms
      ) VALUES (?, ?, ?, ?, ?, ?)`,
    )
    .bind(
      input.namespace,
      input.orgId,
      input.monthUtc,
      input.walletId,
      input.sourceEventId,
      input.createdAtMs,
    )
    .run();
}

export async function insertRawD1RuntimeSnapshotRecord(
  database: D1DatabaseLike,
  input: RawD1RuntimeSnapshotInsertInput,
): Promise<void> {
  await database
    .prepare(
      `INSERT INTO runtime_snapshots (
        namespace,
        org_id,
        project_id,
        environment_id,
        snapshot_id,
        version,
        effective_at_ms,
        checksum,
        payload_json,
        created_at_ms,
        created_by
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
    )
    .bind(
      input.namespace,
      input.orgId,
      input.projectId,
      input.environmentId,
      input.snapshotId,
      input.version,
      input.effectiveAtMs,
      input.checksum,
      input.payloadJson,
      input.createdAtMs,
      input.createdBy,
    )
    .run();
}

export async function insertRawD1RuntimeSnapshotOutboxRecord(
  database: D1DatabaseLike,
  input: RawD1RuntimeSnapshotOutboxInsertInput,
): Promise<void> {
  await database
    .prepare(
      `INSERT INTO runtime_snapshot_outbox (
        namespace,
        org_id,
        project_id,
        environment_id,
        event_id,
        event_type,
        snapshot_id,
        snapshot_version,
        payload_json,
        status,
        attempt_count,
        available_at_ms,
        claimed_by,
        claim_expires_at_ms,
        last_error,
        created_at_ms,
        updated_at_ms,
        dispatched_at_ms
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
    )
    .bind(
      input.namespace,
      input.orgId,
      input.projectId,
      input.environmentId,
      input.eventId,
      input.eventType,
      input.snapshotId,
      input.snapshotVersion,
      input.payloadJson,
      input.status,
      input.attemptCount,
      input.availableAtMs,
      input.claimedBy,
      input.claimExpiresAtMs,
      input.lastError,
      input.createdAtMs,
      input.updatedAtMs,
      input.dispatchedAtMs,
    )
    .run();
}

export async function insertRawD1WebhookEndpointRecord(
  database: D1DatabaseLike,
  input: RawD1WebhookEndpointInsertInput,
): Promise<void> {
  await database
    .prepare(
      `INSERT INTO webhook_endpoints (
        namespace,
        org_id,
        id,
        url,
        status,
        signing_secret_ciphertext_b64u,
        signing_secret_key_id,
        signing_secret_envelope_version,
        secret_version,
        secret_preview,
        created_at_ms,
        updated_at_ms
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
    )
    .bind(
      input.namespace,
      input.orgId,
      input.id,
      input.url,
      input.status,
      input.signingSecretCiphertextB64u,
      input.signingSecretKeyId,
      input.signingSecretEnvelopeVersion,
      input.secretVersion,
      input.secretPreview,
      input.createdAtMs,
      input.updatedAtMs,
    )
    .run();
}

export async function insertRawD1WebhookEndpointCategoryRecord(
  database: D1DatabaseLike,
  input: RawD1WebhookEndpointCategoryInsertInput,
): Promise<void> {
  await database
    .prepare(
      `INSERT INTO webhook_endpoint_categories (
        namespace,
        org_id,
        endpoint_id,
        category
      ) VALUES (?, ?, ?, ?)`,
    )
    .bind(input.namespace, input.orgId, input.endpointId, input.category)
    .run();
}

export async function insertRawD1WalletRecord(
  database: D1DatabaseLike,
  input: RawD1WalletInsertInput,
): Promise<void> {
  await database
    .prepare(
      `INSERT INTO wallets (
        namespace,
        org_id,
        project_id,
        env_id,
        wallet_id,
        record_json,
        created_at_ms,
        updated_at_ms
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
    )
    .bind(
      'd1-contracts',
      'org-d1-signer-schema',
      'project-d1-signer-schema',
      'env-production',
      input.walletId,
      input.recordJson,
      input.createdAtMs,
      input.updatedAtMs,
    )
    .run();
}

export async function insertRawD1WalletSignerRecord(
  database: D1DatabaseLike,
  input: RawD1WalletSignerInsertInput,
): Promise<void> {
  await database
    .prepare(
      `INSERT INTO wallet_signers (
        namespace,
        org_id,
        project_id,
        env_id,
        wallet_id,
        signer_family,
        signer_id,
        chain_target_key,
        record_json,
        created_at_ms,
        updated_at_ms
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
    )
    .bind(
      'd1-contracts',
      'org-d1-signer-schema',
      'project-d1-signer-schema',
      'env-production',
      input.walletId,
      input.signerFamily,
      input.signerId,
      input.chainTargetKey,
      input.recordJson,
      input.createdAtMs,
      input.updatedAtMs,
    )
    .run();
}

export async function insertRawD1WalletAuthMethodRecord(
  database: D1DatabaseLike,
  input: RawD1WalletAuthMethodInsertInput,
): Promise<void> {
  await database
    .prepare(
      `INSERT INTO wallet_auth_methods (
        namespace,
        org_id,
        project_id,
        env_id,
        wallet_id,
        rp_id,
        kind,
        status,
        wallet_auth_method_id,
        auth_identifier_key,
        credential_id_b64u,
        credential_public_key_b64u,
        email_hash_hex,
        registration_authority_id,
        record_json,
        created_at_ms,
        updated_at_ms
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
    )
    .bind(
      'd1-contracts',
      'org-d1-signer-schema',
      'project-d1-signer-schema',
      'env-production',
      input.walletId,
      input.rpId,
      input.kind,
      'active',
      input.walletAuthMethodId,
      input.authIdentifierKey,
      input.credentialIdB64u,
      input.credentialPublicKeyB64u,
      input.emailHashHex,
      input.registrationAuthorityId,
      input.recordJson,
      input.createdAtMs,
      input.updatedAtMs,
    )
    .run();
}

export async function insertRawD1IdentityLinkRecord(
  database: D1DatabaseLike,
  input: RawD1IdentityLinkInsertInput,
): Promise<void> {
  await database
    .prepare(
      `INSERT INTO identity_links (
        namespace,
        org_id,
        project_id,
        env_id,
        subject,
        user_id,
        record_json,
        created_at_ms,
        updated_at_ms
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
    )
    .bind(
      input.namespace,
      input.orgId,
      input.projectId,
      input.envId,
      input.subject,
      input.userId,
      input.recordJson,
      input.createdAtMs,
      input.updatedAtMs,
    )
    .run();
}

export async function insertRawD1AppSessionVersionRecord(
  database: D1DatabaseLike,
  input: RawD1AppSessionVersionInsertInput,
): Promise<void> {
  await database
    .prepare(
      `INSERT INTO app_session_versions (
        namespace,
        org_id,
        project_id,
        env_id,
        user_id,
        session_version,
        record_json,
        created_at_ms,
        updated_at_ms
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
    )
    .bind(
      input.namespace,
      input.orgId,
      input.projectId,
      input.envId,
      input.userId,
      input.sessionVersion,
      input.recordJson,
      input.createdAtMs,
      input.updatedAtMs,
    )
    .run();
}

export async function insertRawD1EmailOtpChallengeRecord(
  database: D1DatabaseLike,
  input: RawD1EmailOtpChallengeInsertInput,
): Promise<void> {
  await database
    .prepare(
      `INSERT INTO email_otp_challenges (
        namespace,
        org_id,
        project_id,
        env_id,
        challenge_id,
        challenge_subject_id,
        wallet_id,
        record_org_id,
        otp_channel,
        session_hash,
        app_session_version,
        action,
        operation,
        otp_code,
        record_json,
        created_at_ms,
        expires_at_ms
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
    )
    .bind(
      input.namespace,
      input.orgId,
      input.projectId,
      input.envId,
      input.challengeId,
      input.challengeSubjectId,
      input.walletId,
      input.recordOrgId,
      input.otpChannel,
      input.sessionHash,
      input.appSessionVersion,
      input.action,
      input.operation,
      input.otpCode,
      input.recordJson,
      input.createdAtMs,
      input.expiresAtMs,
    )
    .run();
}

export async function insertRawD1EmailOtpGrantRecord(
  database: D1DatabaseLike,
  input: RawD1EmailOtpGrantInsertInput,
): Promise<void> {
  await database
    .prepare(
      `INSERT INTO email_otp_grants (
        namespace,
        org_id,
        project_id,
        env_id,
        grant_token,
        user_id,
        wallet_id,
        record_org_id,
        challenge_id,
        action,
        record_json,
        issued_at_ms,
        expires_at_ms
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
    )
    .bind(
      input.namespace,
      input.orgId,
      input.projectId,
      input.envId,
      input.grantToken,
      input.userId,
      input.walletId,
      input.recordOrgId,
      input.challengeId,
      input.action,
      input.recordJson,
      input.issuedAtMs,
      input.expiresAtMs,
    )
    .run();
}

export async function insertRawD1EmailOtpEnrollmentRecord(
  database: D1DatabaseLike,
  input: RawD1EmailOtpEnrollmentInsertInput,
): Promise<void> {
  await database
    .prepare(
      `INSERT INTO email_otp_wallet_enrollments (
        namespace,
        org_id,
        project_id,
        env_id,
        wallet_id,
        provider_user_id,
        record_org_id,
        verified_email,
        record_json,
        created_at_ms,
        updated_at_ms
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
    )
    .bind(
      input.namespace,
      input.orgId,
      input.projectId,
      input.envId,
      input.walletId,
      input.providerUserId,
      input.recordOrgId,
      input.verifiedEmail,
      input.recordJson,
      input.createdAtMs,
      input.updatedAtMs,
    )
    .run();
}

export async function insertRawD1EmailOtpAuthStateRecord(
  database: D1DatabaseLike,
  input: RawD1EmailOtpAuthStateInsertInput,
): Promise<void> {
  await database
    .prepare(
      `INSERT INTO email_otp_auth_states (
        namespace,
        org_id,
        project_id,
        env_id,
        wallet_id,
        provider_user_id,
        record_org_id,
        record_json,
        created_at_ms,
        updated_at_ms
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
    )
    .bind(
      input.namespace,
      input.orgId,
      input.projectId,
      input.envId,
      input.walletId,
      input.providerUserId,
      input.recordOrgId,
      input.recordJson,
      input.createdAtMs,
      input.updatedAtMs,
    )
    .run();
}

export async function insertRawD1EmailOtpUnlockChallengeRecord(
  database: D1DatabaseLike,
  input: RawD1EmailOtpUnlockChallengeInsertInput,
): Promise<void> {
  await database
    .prepare(
      `INSERT INTO email_otp_unlock_challenges (
        namespace,
        org_id,
        project_id,
        env_id,
        challenge_id,
        wallet_id,
        user_id,
        record_org_id,
        record_json,
        created_at_ms,
        expires_at_ms
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
    )
    .bind(
      input.namespace,
      input.orgId,
      input.projectId,
      input.envId,
      input.challengeId,
      input.walletId,
      input.userId,
      input.recordOrgId,
      input.recordJson,
      input.createdAtMs,
      input.expiresAtMs,
    )
    .run();
}

export async function insertRawD1EmailOtpRegistrationAttemptRecord(
  database: D1DatabaseLike,
  input: RawD1EmailOtpRegistrationAttemptInsertInput,
): Promise<void> {
  await database
    .prepare(
      `INSERT INTO email_otp_registration_attempts (
        namespace,
        org_id,
        project_id,
        env_id,
        attempt_id,
        provider_subject,
        email,
        wallet_id,
        state,
        app_session_version,
        runtime_org_id,
        runtime_policy_key,
        offer_wallet_ids_json,
        record_json,
        created_at_ms,
        updated_at_ms,
        expires_at_ms
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
    )
    .bind(
      input.namespace,
      input.orgId,
      input.projectId,
      input.envId,
      input.attemptId,
      input.providerSubject,
      input.email,
      input.walletId,
      input.state,
      input.appSessionVersion,
      input.runtimeOrgId,
      input.runtimePolicyKey,
      input.offerWalletIdsJson,
      input.recordJson,
      input.createdAtMs,
      input.updatedAtMs,
      input.expiresAtMs,
    )
    .run();
}

export async function insertRawD1EmailOtpRateLimitRecord(
  database: D1DatabaseLike,
  input: RawD1EmailOtpRateLimitInsertInput,
): Promise<void> {
  await database
    .prepare(
      `INSERT INTO email_otp_rate_limits (
        namespace,
        org_id,
        project_id,
        env_id,
        rate_key,
        consumed_count,
        reset_at_ms,
        updated_at_ms
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
    )
    .bind(
      input.namespace,
      input.orgId,
      input.projectId,
      input.envId,
      input.rateKey,
      input.consumedCount,
      input.resetAtMs,
      input.updatedAtMs,
    )
    .run();
}

export async function expectRawD1EmailOtpChallengeInsertRejected(
  database: D1DatabaseLike,
  input: RawD1EmailOtpChallengeInsertInput,
): Promise<void> {
  await expect(insertRawD1EmailOtpChallengeRecord(database, input)).rejects.toThrow(
    /CHECK constraint failed/,
  );
}

export async function expectRawD1EmailOtpGrantInsertRejected(
  database: D1DatabaseLike,
  input: RawD1EmailOtpGrantInsertInput,
): Promise<void> {
  await expect(insertRawD1EmailOtpGrantRecord(database, input)).rejects.toThrow(
    /CHECK constraint failed/,
  );
}

export async function expectRawD1EmailOtpEnrollmentInsertRejected(
  database: D1DatabaseLike,
  input: RawD1EmailOtpEnrollmentInsertInput,
): Promise<void> {
  await expect(insertRawD1EmailOtpEnrollmentRecord(database, input)).rejects.toThrow(
    /CHECK constraint failed/,
  );
}

export async function expectRawD1EmailOtpAuthStateInsertRejected(
  database: D1DatabaseLike,
  input: RawD1EmailOtpAuthStateInsertInput,
): Promise<void> {
  await expect(insertRawD1EmailOtpAuthStateRecord(database, input)).rejects.toThrow(
    /CHECK constraint failed/,
  );
}

export async function expectRawD1EmailOtpUnlockChallengeInsertRejected(
  database: D1DatabaseLike,
  input: RawD1EmailOtpUnlockChallengeInsertInput,
): Promise<void> {
  await expect(insertRawD1EmailOtpUnlockChallengeRecord(database, input)).rejects.toThrow(
    /CHECK constraint failed/,
  );
}

export async function expectRawD1EmailOtpRegistrationAttemptInsertRejected(
  database: D1DatabaseLike,
  input: RawD1EmailOtpRegistrationAttemptInsertInput,
): Promise<void> {
  await expect(insertRawD1EmailOtpRegistrationAttemptRecord(database, input)).rejects.toThrow(
    /CHECK constraint failed/,
  );
}

export async function expectRawD1EmailOtpRateLimitInsertRejected(
  database: D1DatabaseLike,
  input: RawD1EmailOtpRateLimitInsertInput,
): Promise<void> {
  await expect(insertRawD1EmailOtpRateLimitRecord(database, input)).rejects.toThrow(
    /CHECK constraint failed/,
  );
}

export async function expectRawD1SponsoredCallInsertRejected(
  database: D1DatabaseLike,
  input: RawD1SponsoredCallInsertInput,
): Promise<void> {
  await expect(insertRawD1SponsoredCallRecord(database, input)).rejects.toThrow(
    /CHECK constraint failed/,
  );
}

export async function expectRawD1PrepaidReservationInsertRejected(
  database: D1DatabaseLike,
  input: RawD1PrepaidReservationInsertInput,
): Promise<void> {
  await expect(insertRawD1PrepaidReservationRecord(database, input)).rejects.toThrow(
    /CHECK constraint failed/,
  );
}

export async function expectRawD1BillingLedgerEntryInsertRejected(
  database: D1DatabaseLike,
  input: RawD1BillingLedgerEntryInsertInput,
): Promise<void> {
  await expect(insertRawD1BillingLedgerEntryRecord(database, input)).rejects.toThrow(
    /CHECK constraint failed/,
  );
}

export async function expectRawD1BillingLedgerPostingInsertRejected(
  database: D1DatabaseLike,
  input: RawD1BillingLedgerPostingInsertInput,
): Promise<void> {
  await expect(insertRawD1BillingLedgerPostingRecord(database, input)).rejects.toThrow(
    /CHECK constraint failed/,
  );
}

export async function expectRawD1BillingMonthlyActiveWalletInsertRejected(
  database: D1DatabaseLike,
  input: RawD1BillingMonthlyActiveWalletInsertInput,
): Promise<void> {
  await expect(insertRawD1BillingMonthlyActiveWalletRecord(database, input)).rejects.toThrow(
    /CHECK constraint failed/,
  );
}

export async function expectRawD1RuntimeSnapshotInsertRejected(
  database: D1DatabaseLike,
  input: RawD1RuntimeSnapshotInsertInput,
): Promise<void> {
  await expect(insertRawD1RuntimeSnapshotRecord(database, input)).rejects.toThrow(
    /CHECK constraint failed/,
  );
}

export async function expectRawD1RuntimeSnapshotOutboxInsertRejected(
  database: D1DatabaseLike,
  input: RawD1RuntimeSnapshotOutboxInsertInput,
): Promise<void> {
  await expect(insertRawD1RuntimeSnapshotOutboxRecord(database, input)).rejects.toThrow(
    /CHECK constraint failed/,
  );
}

export async function expectRawD1WebhookEndpointInsertRejected(
  database: D1DatabaseLike,
  input: RawD1WebhookEndpointInsertInput,
): Promise<void> {
  await expect(insertRawD1WebhookEndpointRecord(database, input)).rejects.toThrow(
    /CHECK constraint failed/,
  );
}

export async function expectRawD1WebhookEndpointCategoryInsertRejected(
  database: D1DatabaseLike,
  input: RawD1WebhookEndpointCategoryInsertInput,
): Promise<void> {
  await expect(insertRawD1WebhookEndpointCategoryRecord(database, input)).rejects.toThrow(
    /CHECK constraint failed/,
  );
}

export async function expectRawD1WalletInsertRejected(
  database: D1DatabaseLike,
  input: RawD1WalletInsertInput,
): Promise<void> {
  await expect(insertRawD1WalletRecord(database, input)).rejects.toThrow(/CHECK constraint failed/);
}

export async function expectRawD1WalletSignerInsertRejected(
  database: D1DatabaseLike,
  input: RawD1WalletSignerInsertInput,
): Promise<void> {
  await expect(insertRawD1WalletSignerRecord(database, input)).rejects.toThrow(
    /CHECK constraint failed/,
  );
}

export async function expectRawD1WalletAuthMethodInsertRejected(
  database: D1DatabaseLike,
  input: RawD1WalletAuthMethodInsertInput,
): Promise<void> {
  await expect(insertRawD1WalletAuthMethodRecord(database, input)).rejects.toThrow(
    /CHECK constraint failed/,
  );
}

export async function expectRawD1IdentityLinkInsertRejected(
  database: D1DatabaseLike,
  input: RawD1IdentityLinkInsertInput,
): Promise<void> {
  await expect(insertRawD1IdentityLinkRecord(database, input)).rejects.toThrow(
    /CHECK constraint failed/,
  );
}

export async function expectRawD1AppSessionVersionInsertRejected(
  database: D1DatabaseLike,
  input: RawD1AppSessionVersionInsertInput,
): Promise<void> {
  await expect(insertRawD1AppSessionVersionRecord(database, input)).rejects.toThrow(
    /CHECK constraint failed/,
  );
}

export function createD1AtomicAssessment(): RecordSponsoredExecutionInput['assessment'] {
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

export function errorCode(error: unknown): string {
  const maybeCode = isErrorWithCode(error) ? error.code : null;
  return String(maybeCode || '');
}

export function createD1WebhookTestSecretCipher() {
  return createAesGcmConsoleWebhookSecretCipher({
    keyId: 'webhook-test-key-r1',
    keyBytes: new Uint8Array(32).fill(7),
  });
}

export function nearPublicKeyValue(record: NearPublicKeyRecord): string {
  return record.publicKey;
}

export function webhookDispatchEventId(request: WebhookDispatchRequest): string {
  return request.eventId;
}

export function buildD1EmailOtpChallengeContext(input: {
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

export function buildD1EmailOtpChallengeRecord(input: {
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

export function buildD1EmailOtpGrantRecord(input: {
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

export function buildD1EmailOtpWalletEnrollmentRecord(input: {
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
    clientUnlockPublicKeyB64u: 'clientUnlockPublicKeyB64u',
    unlockKeyVersion: 'unlock-key-v1',
    serverSealedFactorCiphertextB64u: 'serverSealedFactorCiphertextB64u',
    createdAtMs: Date.parse('2026-06-27T10:00:00.000Z'),
    updatedAtMs: input.updatedAtMs,
  };
}

export function buildD1EmailOtpRegistrationAttemptRecord(input: {
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
    authProvider: 'google',
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

export function isErrorWithCode(input: unknown): input is ErrorWithCode {
  return Boolean(input && typeof input === 'object' && 'code' in input);
}

export const D1_MIGRATION_TARGETS: readonly D1MigrationTarget[] = Object.freeze([
  {
    directoryName: 'd1-console',
  },
  {
    directoryName: 'd1-signer',
  },
]);
