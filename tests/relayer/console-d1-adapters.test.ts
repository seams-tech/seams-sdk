import { expect, test } from '@playwright/test';
import { createD1ConsoleAccountService } from '../../packages/console-server-ts/src/account/d1';
import { createD1ConsoleApiKeyService } from '../../packages/console-server-ts/src/apiKeys/d1';
import { createD1ConsoleApprovalService } from '../../packages/console-server-ts/src/approvals/d1';
import { createD1ConsoleAuditService } from '../../packages/console-server-ts/src/audit/d1';
import {
  createD1ConsoleBillingService,
  runD1ConsoleBillingMonthlyFinalization,
} from '../../packages/console-server-ts/src/billing/d1';
import {
  CONSOLE_BILLING_PREPAID_RESERVATION_D1_RUNTIME,
  createD1ConsoleBillingPrepaidReservationService,
  getConsoleBillingPrepaidReservationD1Runtime,
  type ConsoleBillingPrepaidReservationD1Runtime,
} from '../../packages/console-server-ts/src/billingPrepaidReservations/d1';
import type { ConsoleBillingPrepaidReservationService } from '../../packages/console-server-ts/src/billingPrepaidReservations/service';
import type { ConsoleBillingPrepaidReservation } from '../../packages/console-server-ts/src/billingPrepaidReservations/types';
import { createD1ConsoleBootstrapTokenService } from '../../packages/console-server-ts/src/bootstrapTokens/d1';
import { createD1ConsoleKeyExportService } from '../../packages/console-server-ts/src/keyExports/d1';
import {
  createD1ConsoleObservabilityIngestionService,
  createD1ConsoleObservabilityService,
} from '../../packages/console-server-ts/src/observability/d1';
import { createD1ConsoleOrgProjectEnvService } from '../../packages/console-server-ts/src/orgProjectEnv/d1';
import { createD1ConsolePolicyService } from '../../packages/console-server-ts/src/policies/d1';
import {
  createD1ConsoleRuntimeSnapshotService,
  runD1ConsoleRuntimeSnapshotOutboxDispatch,
  type D1ConsoleRuntimeSnapshotOutboxDispatchResult,
} from '../../packages/console-server-ts/src/runtimeSnapshots/d1';
import type { ConsoleRuntimeSnapshotOutboxEvent } from '../../packages/console-server-ts/src/runtimeSnapshots/types';
import { createD1ConsoleSponsoredCallService } from '../../packages/console-server-ts/src/sponsoredCalls/d1';
import { createD1ConsoleSponsorshipSpendCapService } from '../../packages/console-server-ts/src/sponsorshipSpendCaps/d1';
import { createD1ConsoleTeamRbacService } from '../../packages/console-server-ts/src/teamRbac/d1';
import { createD1ConsoleWalletService } from '../../packages/console-server-ts/src/wallets/d1';
import {
  createAesGcmConsoleWebhookSecretCipher,
  createD1ConsoleWebhookService,
  runD1ConsoleWebhookRetryDispatch,
  type ConsoleWebhookSecretCipher,
  type D1ConsoleWebhookRetryDispatchResult,
} from '../../packages/console-server-ts/src/webhooks/d1';
import type {
  WebhookDispatchAdapter,
  WebhookDispatchRequest,
  WebhookDispatchResult,
} from '../../packages/console-server-ts/src/webhooks/service';
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
import type { D1DatabaseLike } from '../../packages/sdk-server-ts/src/storage/tenantRoute';
import { walletIdFromString } from '../../packages/shared-ts/src/utils/registrationIntent';
import { parseWebAuthnRpId } from '../../packages/shared-ts/src/utils/domainIds';
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
} from '../../packages/console-server-ts/src/router/sponsorshipExecution';
import type {
  SponsorshipSpendPricingEstimateInput,
  SponsorshipSpendPricingFinalizeInput,
  SponsorshipSpendPricingQuote,
  SponsorshipSpendPricingService,
} from '../../packages/console-server-ts/src/sponsorship/spendCaps';
import {
  applyD1MigrationFiles,
  cleanupTemporaryD1Database,
  createTemporaryD1Database,
  d1MigrationFileBasenames,
  type D1MigrationDirectoryName,
  listD1MigrationFiles,
  readTableColumnNames,
  readUserTableCount,
} from '../helpers/sqliteD1';
import { buildEd25519YaoCapabilityFixture } from '../helpers/ed25519YaoCapabilityFixtures';

type SqliteJsonRow = Record<string, unknown>;
type ErrorWithCode = { readonly code?: unknown };
type D1MigrationTarget = {
  readonly directoryName: D1MigrationDirectoryName;
  readonly expectedMigrationCount: number;
  readonly expectedTableCount: number;
};

async function applyConsoleD1Migrations(database: D1DatabaseLike): Promise<void> {
  await applyD1MigrationFiles(database, listD1MigrationFiles('d1-console'));
}

type SponsoredRecordBuildInput = Parameters<RecordSponsoredExecutionInput['buildRecord']>[0];
type SponsoredRecordBuildOutput = ReturnType<RecordSponsoredExecutionInput['buildRecord']>;
type RawD1SponsoredCallInsertInput = {
  readonly id: string;
  readonly detailsJson: string;
  readonly idempotencyKey: string;
  readonly estimatedSpendMinor: number | null;
  readonly settledSpendMinor: number | null;
  readonly createdAtMs: number;
  readonly updatedAtMs: number;
};
type RawD1PrepaidReservationInsertInput = {
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
type RawD1BillingLedgerEntryInsertInput = {
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
type RawD1BillingLedgerPostingInsertInput = {
  readonly namespace: string;
  readonly orgId: string;
  readonly id: string;
  readonly ledgerEntryId: string;
  readonly accountCode: string;
  readonly direction: string;
  readonly amountMinor: number;
  readonly createdAtMs: number;
};
type RawD1BillingMonthlyActiveWalletInsertInput = {
  readonly namespace: string;
  readonly orgId: string;
  readonly monthUtc: string;
  readonly walletId: string;
  readonly sourceEventId: string | null;
  readonly createdAtMs: number;
};
type RawD1RuntimeSnapshotInsertInput = {
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
type RawD1RuntimeSnapshotOutboxInsertInput = {
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
type RawD1WebhookEndpointInsertInput = {
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
type RawD1WebhookEndpointCategoryInsertInput = {
  readonly namespace: string;
  readonly orgId: string;
  readonly endpointId: string;
  readonly category: string;
};
type RawD1WalletAuthMethodInsertInput = {
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
type RawD1WalletSignerInsertInput = {
  readonly walletId: string;
  readonly signerFamily: 'ed25519' | 'ecdsa';
  readonly signerId: string;
  readonly chainTargetKey: string | null;
  readonly recordJson: string;
  readonly createdAtMs: number;
  readonly updatedAtMs: number;
};
type RawD1WalletInsertInput = {
  readonly walletId: string;
  readonly recordJson: string;
  readonly createdAtMs: number;
  readonly updatedAtMs: number;
};
type RawD1SigningRootSecretShareInsertInput = {
  readonly namespace: string;
  readonly orgId: string;
  readonly projectId: string;
  readonly envId: string;
  readonly signingRootId: string;
  readonly signingRootVersion: string;
  readonly shareId: number;
  readonly sealedShareB64u: string;
  readonly storageId: string | null;
  readonly kekId: string;
  readonly envelopeVersion: string;
  readonly aadDigestB64u: string;
  readonly ciphertextDigestB64u: string;
  readonly rotationState: string;
  readonly rotatedFromKekId: string | null;
  readonly rotatedAtMs: number | null;
  readonly retiredAtMs: number | null;
  readonly lastAuditEventId: string;
  readonly createdAtMs: number;
  readonly updatedAtMs: number;
};
type RawD1IdentityLinkInsertInput = {
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
type RawD1AppSessionVersionInsertInput = {
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
type RawD1RecoverySessionInsertInput = {
  readonly namespace: string;
  readonly orgId: string;
  readonly projectId: string;
  readonly envId: string;
  readonly sessionId: string;
  readonly nearAccountId: string;
  readonly recordJson: string;
  readonly expiresAtMs: number;
  readonly createdAtMs: number;
  readonly updatedAtMs: number;
};
type RawD1RecoveryExecutionInsertInput = {
  readonly namespace: string;
  readonly orgId: string;
  readonly projectId: string;
  readonly envId: string;
  readonly sessionId: string;
  readonly chainIdKey: string;
  readonly accountAddress: string;
  readonly action: string;
  readonly status: string;
  readonly recordJson: string;
  readonly createdAtMs: number;
  readonly updatedAtMs: number;
};
type RawD1EmailRecoveryPreparationInsertInput = {
  readonly namespace: string;
  readonly orgId: string;
  readonly projectId: string;
  readonly envId: string;
  readonly requestId: string;
  readonly accountId: string;
  readonly walletId: string;
  readonly rpId: string;
  readonly recordJson: string;
  readonly createdAtMs: number;
  readonly expiresAtMs: number;
};
type RawD1EmailOtpChallengeInsertInput = {
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
type RawD1EmailOtpGrantInsertInput = {
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
type RawD1EmailOtpEnrollmentInsertInput = {
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
type RawD1EmailOtpRecoveryEscrowInsertInput = {
  readonly namespace: string;
  readonly orgId: string;
  readonly projectId: string;
  readonly envId: string;
  readonly walletId: string;
  readonly recoveryKeyId: string;
  readonly recoveryKeyStatus: string;
  readonly recordJson: string;
  readonly issuedAtMs: number;
  readonly updatedAtMs: number;
};
type RawD1EmailOtpAuthStateInsertInput = {
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
type RawD1EmailOtpUnlockChallengeInsertInput = {
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
type RawD1EmailOtpRegistrationAttemptInsertInput = {
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
type RawD1EmailOtpRateLimitInsertInput = {
  readonly namespace: string;
  readonly orgId: string;
  readonly projectId: string;
  readonly envId: string;
  readonly rateKey: string;
  readonly consumedCount: number;
  readonly resetAtMs: number;
  readonly updatedAtMs: number;
};

function unwrapFixture<T>(result: { ok: true; value: T } | { ok: false }): T {
  if (!result.ok) throw new Error('invalid fixture value');
  return result.value;
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

class StaleReadPrepaidReservationService implements ConsoleBillingPrepaidReservationService {
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

function fixedD1AtomicBillingNow(): Date {
  return new Date('2026-06-27T00:00:00.000Z');
}

function buildRawD1SponsoredCallInsertInput(input: {
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

function buildRawD1PrepaidReservationInsertInput(input: {
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

function buildRawD1BillingLedgerEntryInsertInput(
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

function buildRawD1BillingLedgerPostingInsertInput(
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

function buildRawD1BillingMonthlyActiveWalletInsertInput(
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

function buildRawD1RuntimeSnapshotInsertInput(
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

function buildRawD1RuntimeSnapshotOutboxInsertInput(
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

function buildRawD1WebhookEndpointInsertInput(
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

function buildRawD1WebhookEndpointCategoryInsertInput(
  input: Partial<RawD1WebhookEndpointCategoryInsertInput>,
): RawD1WebhookEndpointCategoryInsertInput {
  return {
    namespace: input.namespace ?? 'd1-contracts',
    orgId: input.orgId ?? 'org-d1-webhook-schema',
    endpointId: input.endpointId ?? 'wh_raw_webhook_schema',
    category: input.category ?? 'wallet',
  };
}

function buildRawD1PasskeyAuthMethodInsertInput(input: {
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

function buildRawD1EmailOtpAuthMethodInsertInput(input: {
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

function buildRawD1Ed25519WalletSignerInsertInput(input: {
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

function buildRawD1WalletInsertInput(input: {
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

function buildRawD1EcdsaWalletSignerInsertInput(input: {
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

function buildRawD1SigningRootSecretShareInsertInput(
  input: Partial<RawD1SigningRootSecretShareInsertInput>,
): RawD1SigningRootSecretShareInsertInput {
  const createdAtMs = input.createdAtMs ?? Date.parse('2026-06-27T00:00:00.000Z');
  return {
    namespace: input.namespace ?? 'd1-contracts',
    orgId: input.orgId ?? 'org-d1-signer-schema',
    projectId: input.projectId ?? 'project-d1-signer-schema',
    envId: input.envId ?? 'env-production',
    signingRootId: input.signingRootId ?? 'signing-root-raw-secret',
    signingRootVersion: input.signingRootVersion ?? '',
    shareId: input.shareId ?? 1,
    sealedShareB64u: input.sealedShareB64u ?? 'AQIDBA',
    storageId: input.storageId === undefined ? null : input.storageId,
    kekId: input.kekId ?? 'kek-raw-secret-share',
    envelopeVersion: input.envelopeVersion ?? 'd1-secret-share-v1',
    aadDigestB64u: input.aadDigestB64u ?? 'A'.repeat(43),
    ciphertextDigestB64u: input.ciphertextDigestB64u ?? 'B'.repeat(43),
    rotationState: input.rotationState ?? 'active',
    rotatedFromKekId: input.rotatedFromKekId === undefined ? null : input.rotatedFromKekId,
    rotatedAtMs: input.rotatedAtMs === undefined ? null : input.rotatedAtMs,
    retiredAtMs: input.retiredAtMs === undefined ? null : input.retiredAtMs,
    lastAuditEventId: input.lastAuditEventId ?? 'audit-raw-secret-share',
    createdAtMs,
    updatedAtMs: input.updatedAtMs ?? createdAtMs + 1000,
  };
}

function buildRawD1IdentityLinkInsertInput(
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

function buildRawD1AppSessionVersionInsertInput(
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

function buildRawD1RecoverySessionInsertInput(
  input: Partial<RawD1RecoverySessionInsertInput>,
): RawD1RecoverySessionInsertInput {
  const createdAtMs = input.createdAtMs ?? Date.parse('2026-06-27T00:00:00.000Z');
  const updatedAtMs = input.updatedAtMs ?? createdAtMs + 1000;
  const expiresAtMs = input.expiresAtMs ?? createdAtMs + 600_000;
  const sessionId = input.sessionId ?? 'recovery-session-raw-schema';
  const nearAccountId = input.nearAccountId ?? 'wallet-raw-recovery.testnet';
  return {
    namespace: input.namespace ?? 'd1-contracts',
    orgId: input.orgId ?? 'org-d1-recovery-schema',
    projectId: input.projectId ?? 'project-d1-recovery-schema',
    envId: input.envId ?? 'env-production',
    sessionId,
    nearAccountId,
    recordJson:
      input.recordJson ??
      JSON.stringify({
        version: 'recovery_session_v1',
        sessionId,
        userId: 'wallet-raw-recovery',
        nearAccountId,
        signerSlot: 1,
        status: 'prepared',
        createdAtMs,
        updatedAtMs,
        expiresAtMs,
        newNearPublicKey: 'ed25519:raw-recovery-public-key',
        newEvmOwnerAddress: `0x${'11'.repeat(20)}`,
        recoveryDeadlineEpochSeconds: Math.floor(expiresAtMs / 1000),
        recoveryEmailPayloadHash: 'raw-recovery-email-payload-hash',
      }),
    expiresAtMs,
    createdAtMs,
    updatedAtMs,
  };
}

function buildRawD1RecoveryExecutionInsertInput(
  input: Partial<RawD1RecoveryExecutionInsertInput>,
): RawD1RecoveryExecutionInsertInput {
  const createdAtMs = input.createdAtMs ?? Date.parse('2026-06-27T00:00:00.000Z');
  const updatedAtMs = input.updatedAtMs ?? createdAtMs + 1000;
  const sessionId = input.sessionId ?? 'recovery-session-raw-schema';
  const chainIdKey = input.chainIdKey ?? 'evm:eip155:8453';
  const accountAddress = input.accountAddress ?? `0x${'22'.repeat(20)}`;
  const action = input.action ?? 'recover_owner';
  const status = input.status ?? 'pending';
  return {
    namespace: input.namespace ?? 'd1-contracts',
    orgId: input.orgId ?? 'org-d1-recovery-schema',
    projectId: input.projectId ?? 'project-d1-recovery-schema',
    envId: input.envId ?? 'env-production',
    sessionId,
    chainIdKey,
    accountAddress,
    action,
    status,
    recordJson:
      input.recordJson ??
      JSON.stringify({
        version: 'recovery_execution_v1',
        sessionId,
        userId: 'wallet-raw-recovery',
        nearAccountId: 'wallet-raw-recovery.testnet',
        chainIdKey,
        accountAddress,
        action,
        status,
        createdAtMs,
        updatedAtMs,
      }),
    createdAtMs,
    updatedAtMs,
  };
}

function buildRawD1EmailRecoveryPreparationInsertInput(
  input: Partial<RawD1EmailRecoveryPreparationInsertInput>,
): RawD1EmailRecoveryPreparationInsertInput {
  const createdAtMs = input.createdAtMs ?? Date.parse('2026-06-27T00:00:00.000Z');
  const expiresAtMs = input.expiresAtMs ?? createdAtMs + 600_000;
  const requestId = input.requestId ?? 'email-recovery-preparation-raw-schema';
  const accountId = input.accountId ?? 'wallet-raw-email-recovery.testnet';
  const walletId = input.walletId ?? 'wallet-raw-email-recovery';
  const rpId = input.rpId ?? 'app.example.test';
  return {
    namespace: input.namespace ?? 'd1-contracts',
    orgId: input.orgId ?? 'org-d1-recovery-schema',
    projectId: input.projectId ?? 'project-d1-recovery-schema',
    envId: input.envId ?? 'env-production',
    requestId,
    accountId,
    walletId,
    rpId,
    recordJson:
      input.recordJson ??
      JSON.stringify({
        version: 'email_recovery_preparation_v1',
        requestId,
        accountId,
        walletBinding: {
          walletId,
          nearAccountId: accountId,
          nearEd25519SigningKeyId: 'ed25519:raw-email-recovery',
          rpId,
          signerSlot: 1,
        },
        rpId,
        signerSlot: 1,
        credentialIdB64u: 'raw-email-recovery-credential',
        credentialPublicKeyB64u: 'raw-email-recovery-credential-public-key',
        counter: 0,
        createdAtMs,
        expiresAtMs,
        thresholdEd25519: {
          relayerKeyId: 'relayer-raw-email-recovery',
          publicKey: 'ed25519:raw-email-recovery',
          keyVersion: '1',
          recoveryExportCapable: true,
        },
        ecdsa: {
          kind: 'evm_family_ecdsa_keygen',
          chainTargets: ['evm:eip155:8453'],
          prepare: {
            formatVersion: 'ecdsa-hss-role-local',
            walletId,
            walletKeyId: 'wallet-key-raw-email-recovery',
            ecdsaThresholdKeyId: 'ecdsa-key-raw-email-recovery',
            signingRootId: 'signing-root-raw-email-recovery',
            signingRootVersion: '1',
            keyScope: 'evm-family',
            relayerKeyId: 'relayer-raw-email-recovery',
            requestId,
            thresholdSessionId: 'threshold-session-raw-email-recovery',
            signingGrantId: 'signing-grant-raw-email-recovery',
            ttlMs: 600_000,
            remainingUses: 1,
            participantIds: [1, 2, 3],
          },
        },
      }),
    createdAtMs,
    expiresAtMs,
  };
}

function buildRawD1EmailOtpChallengeInsertInput(
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

function buildRawD1EmailOtpGrantInsertInput(
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

function buildRawD1EmailOtpEnrollmentInsertInput(
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

function buildRawD1EmailOtpRecoveryEscrowInsertInput(
  input: Partial<RawD1EmailOtpRecoveryEscrowInsertInput>,
): RawD1EmailOtpRecoveryEscrowInsertInput {
  const issuedAtMs = input.issuedAtMs ?? Date.parse('2026-06-27T00:00:00.000Z');
  const updatedAtMs = input.updatedAtMs ?? issuedAtMs + 1000;
  const walletId = input.walletId ?? 'wallet-raw-email-otp';
  const recoveryKeyId = input.recoveryKeyId ?? 'recovery-key-raw-email-otp';
  const recoveryKeyStatus = input.recoveryKeyStatus ?? 'active';
  return {
    namespace: input.namespace ?? 'd1-contracts',
    orgId: input.orgId ?? 'org-d1-email-otp-schema',
    projectId: input.projectId ?? 'project-d1-email-otp-schema',
    envId: input.envId ?? 'env-production',
    walletId,
    recoveryKeyId,
    recoveryKeyStatus,
    recordJson:
      input.recordJson ??
      JSON.stringify({
        version: 'email_otp_recovery_wrapped_enrollment_escrow_v1',
        alg: 'chacha20poly1305-hkdf-sha256-v1',
        secretKind: 'email_otp_device_enrollment_escrow',
        escrowKind: 'recovery_wrapped_enrollment_escrow',
        walletId,
        userId: 'google-subject-raw-email-otp',
        authSubjectId: 'google-subject-raw-email-otp',
        authMethod: 'google_sso_email_otp',
        enrollmentId: 'enrollment-raw-email-otp',
        enrollmentVersion: '1',
        enrollmentSealKeyVersion: 'seal-v1',
        signingRootId: 'signing-root-raw-email-otp',
        signingRootVersion: '1',
        recoveryKeyId,
        recoveryKeyStatus,
        nonceB64u: 'nonce-raw-email-otp',
        wrappedDeviceEnrollmentEscrowB64u: 'wrapped-raw-email-otp',
        aadHashB64u: 'hash-raw-email-otp',
        issuedAtMs,
        updatedAtMs,
      }),
    issuedAtMs,
    updatedAtMs,
  };
}

function buildRawD1EmailOtpAuthStateInsertInput(
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

function buildRawD1EmailOtpUnlockChallengeInsertInput(
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

function buildRawD1EmailOtpRegistrationAttemptInsertInput(
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

function buildRawD1EmailOtpRateLimitInsertInput(
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

async function insertRawD1SponsoredCallRecord(
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

async function insertRawD1PrepaidReservationRecord(
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

async function insertRawD1BillingLedgerEntryRecord(
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

async function insertRawD1BillingLedgerPostingRecord(
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

async function insertRawD1BillingMonthlyActiveWalletRecord(
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

async function insertRawD1RuntimeSnapshotRecord(
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

async function insertRawD1RuntimeSnapshotOutboxRecord(
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

async function insertRawD1WebhookEndpointRecord(
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

async function insertRawD1WebhookEndpointCategoryRecord(
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

async function insertRawD1WalletRecord(
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

async function insertRawD1WalletSignerRecord(
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

async function insertRawD1WalletAuthMethodRecord(
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

async function insertRawD1SigningRootSecretShareRecord(
  database: D1DatabaseLike,
  input: RawD1SigningRootSecretShareInsertInput,
): Promise<void> {
  await database
    .prepare(
      `INSERT INTO signing_root_secret_shares (
        namespace,
        org_id,
        project_id,
        env_id,
        signing_root_id,
        signing_root_version,
        share_id,
        sealed_share_b64u,
        storage_id,
        kek_id,
        envelope_version,
        aad_digest_b64u,
        ciphertext_digest_b64u,
        rotation_state,
        rotated_from_kek_id,
        rotated_at_ms,
        retired_at_ms,
        last_audit_event_id,
        created_at_ms,
        updated_at_ms
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
    )
    .bind(
      input.namespace,
      input.orgId,
      input.projectId,
      input.envId,
      input.signingRootId,
      input.signingRootVersion,
      input.shareId,
      input.sealedShareB64u,
      input.storageId,
      input.kekId,
      input.envelopeVersion,
      input.aadDigestB64u,
      input.ciphertextDigestB64u,
      input.rotationState,
      input.rotatedFromKekId,
      input.rotatedAtMs,
      input.retiredAtMs,
      input.lastAuditEventId,
      input.createdAtMs,
      input.updatedAtMs,
    )
    .run();
}

async function insertRawD1IdentityLinkRecord(
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

async function insertRawD1AppSessionVersionRecord(
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

async function insertRawD1RecoverySessionRecord(
  database: D1DatabaseLike,
  input: RawD1RecoverySessionInsertInput,
): Promise<void> {
  await database
    .prepare(
      `INSERT INTO recovery_sessions (
        namespace,
        org_id,
        project_id,
        env_id,
        session_id,
        near_account_id,
        record_json,
        expires_at_ms,
        created_at_ms,
        updated_at_ms
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
    )
    .bind(
      input.namespace,
      input.orgId,
      input.projectId,
      input.envId,
      input.sessionId,
      input.nearAccountId,
      input.recordJson,
      input.expiresAtMs,
      input.createdAtMs,
      input.updatedAtMs,
    )
    .run();
}

async function insertRawD1RecoveryExecutionRecord(
  database: D1DatabaseLike,
  input: RawD1RecoveryExecutionInsertInput,
): Promise<void> {
  await database
    .prepare(
      `INSERT INTO recovery_executions (
        namespace,
        org_id,
        project_id,
        env_id,
        session_id,
        chain_id_key,
        account_address,
        action,
        status,
        record_json,
        created_at_ms,
        updated_at_ms
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
    )
    .bind(
      input.namespace,
      input.orgId,
      input.projectId,
      input.envId,
      input.sessionId,
      input.chainIdKey,
      input.accountAddress,
      input.action,
      input.status,
      input.recordJson,
      input.createdAtMs,
      input.updatedAtMs,
    )
    .run();
}

async function insertRawD1EmailRecoveryPreparationRecord(
  database: D1DatabaseLike,
  input: RawD1EmailRecoveryPreparationInsertInput,
): Promise<void> {
  await database
    .prepare(
      `INSERT INTO email_recovery_preparations (
        namespace,
        org_id,
        project_id,
        env_id,
        request_id,
        account_id,
        wallet_id,
        rp_id,
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
      input.requestId,
      input.accountId,
      input.walletId,
      input.rpId,
      input.recordJson,
      input.createdAtMs,
      input.expiresAtMs,
    )
    .run();
}

async function insertRawD1EmailOtpChallengeRecord(
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

async function insertRawD1EmailOtpGrantRecord(
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

async function insertRawD1EmailOtpEnrollmentRecord(
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

async function insertRawD1EmailOtpRecoveryEscrowRecord(
  database: D1DatabaseLike,
  input: RawD1EmailOtpRecoveryEscrowInsertInput,
): Promise<void> {
  await database
    .prepare(
      `INSERT INTO email_otp_recovery_wrapped_enrollment_escrows (
        namespace,
        org_id,
        project_id,
        env_id,
        wallet_id,
        recovery_key_id,
        recovery_key_status,
        record_json,
        issued_at_ms,
        updated_at_ms
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
    )
    .bind(
      input.namespace,
      input.orgId,
      input.projectId,
      input.envId,
      input.walletId,
      input.recoveryKeyId,
      input.recoveryKeyStatus,
      input.recordJson,
      input.issuedAtMs,
      input.updatedAtMs,
    )
    .run();
}

async function insertRawD1EmailOtpAuthStateRecord(
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

async function insertRawD1EmailOtpUnlockChallengeRecord(
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

async function insertRawD1EmailOtpRegistrationAttemptRecord(
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

async function insertRawD1EmailOtpRateLimitRecord(
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

async function expectRawD1EmailOtpChallengeInsertRejected(
  database: D1DatabaseLike,
  input: RawD1EmailOtpChallengeInsertInput,
): Promise<void> {
  await expect(insertRawD1EmailOtpChallengeRecord(database, input)).rejects.toThrow(
    /CHECK constraint failed/,
  );
}

async function expectRawD1EmailOtpGrantInsertRejected(
  database: D1DatabaseLike,
  input: RawD1EmailOtpGrantInsertInput,
): Promise<void> {
  await expect(insertRawD1EmailOtpGrantRecord(database, input)).rejects.toThrow(
    /CHECK constraint failed/,
  );
}

async function expectRawD1EmailOtpEnrollmentInsertRejected(
  database: D1DatabaseLike,
  input: RawD1EmailOtpEnrollmentInsertInput,
): Promise<void> {
  await expect(insertRawD1EmailOtpEnrollmentRecord(database, input)).rejects.toThrow(
    /CHECK constraint failed/,
  );
}

async function expectRawD1EmailOtpRecoveryEscrowInsertRejected(
  database: D1DatabaseLike,
  input: RawD1EmailOtpRecoveryEscrowInsertInput,
): Promise<void> {
  await expect(insertRawD1EmailOtpRecoveryEscrowRecord(database, input)).rejects.toThrow(
    /CHECK constraint failed/,
  );
}

async function expectRawD1EmailOtpAuthStateInsertRejected(
  database: D1DatabaseLike,
  input: RawD1EmailOtpAuthStateInsertInput,
): Promise<void> {
  await expect(insertRawD1EmailOtpAuthStateRecord(database, input)).rejects.toThrow(
    /CHECK constraint failed/,
  );
}

async function expectRawD1EmailOtpUnlockChallengeInsertRejected(
  database: D1DatabaseLike,
  input: RawD1EmailOtpUnlockChallengeInsertInput,
): Promise<void> {
  await expect(insertRawD1EmailOtpUnlockChallengeRecord(database, input)).rejects.toThrow(
    /CHECK constraint failed/,
  );
}

async function expectRawD1EmailOtpRegistrationAttemptInsertRejected(
  database: D1DatabaseLike,
  input: RawD1EmailOtpRegistrationAttemptInsertInput,
): Promise<void> {
  await expect(insertRawD1EmailOtpRegistrationAttemptRecord(database, input)).rejects.toThrow(
    /CHECK constraint failed/,
  );
}

async function expectRawD1EmailOtpRateLimitInsertRejected(
  database: D1DatabaseLike,
  input: RawD1EmailOtpRateLimitInsertInput,
): Promise<void> {
  await expect(insertRawD1EmailOtpRateLimitRecord(database, input)).rejects.toThrow(
    /CHECK constraint failed/,
  );
}

async function expectRawD1SponsoredCallInsertRejected(
  database: D1DatabaseLike,
  input: RawD1SponsoredCallInsertInput,
): Promise<void> {
  await expect(insertRawD1SponsoredCallRecord(database, input)).rejects.toThrow(
    /CHECK constraint failed/,
  );
}

async function expectRawD1PrepaidReservationInsertRejected(
  database: D1DatabaseLike,
  input: RawD1PrepaidReservationInsertInput,
): Promise<void> {
  await expect(insertRawD1PrepaidReservationRecord(database, input)).rejects.toThrow(
    /CHECK constraint failed/,
  );
}

async function expectRawD1BillingLedgerEntryInsertRejected(
  database: D1DatabaseLike,
  input: RawD1BillingLedgerEntryInsertInput,
): Promise<void> {
  await expect(insertRawD1BillingLedgerEntryRecord(database, input)).rejects.toThrow(
    /CHECK constraint failed/,
  );
}

async function expectRawD1BillingLedgerPostingInsertRejected(
  database: D1DatabaseLike,
  input: RawD1BillingLedgerPostingInsertInput,
): Promise<void> {
  await expect(insertRawD1BillingLedgerPostingRecord(database, input)).rejects.toThrow(
    /CHECK constraint failed/,
  );
}

async function expectRawD1BillingMonthlyActiveWalletInsertRejected(
  database: D1DatabaseLike,
  input: RawD1BillingMonthlyActiveWalletInsertInput,
): Promise<void> {
  await expect(insertRawD1BillingMonthlyActiveWalletRecord(database, input)).rejects.toThrow(
    /CHECK constraint failed/,
  );
}

async function expectRawD1RuntimeSnapshotInsertRejected(
  database: D1DatabaseLike,
  input: RawD1RuntimeSnapshotInsertInput,
): Promise<void> {
  await expect(insertRawD1RuntimeSnapshotRecord(database, input)).rejects.toThrow(
    /CHECK constraint failed/,
  );
}

async function expectRawD1RuntimeSnapshotOutboxInsertRejected(
  database: D1DatabaseLike,
  input: RawD1RuntimeSnapshotOutboxInsertInput,
): Promise<void> {
  await expect(insertRawD1RuntimeSnapshotOutboxRecord(database, input)).rejects.toThrow(
    /CHECK constraint failed/,
  );
}

async function expectRawD1WebhookEndpointInsertRejected(
  database: D1DatabaseLike,
  input: RawD1WebhookEndpointInsertInput,
): Promise<void> {
  await expect(insertRawD1WebhookEndpointRecord(database, input)).rejects.toThrow(
    /CHECK constraint failed/,
  );
}

async function expectRawD1WebhookEndpointCategoryInsertRejected(
  database: D1DatabaseLike,
  input: RawD1WebhookEndpointCategoryInsertInput,
): Promise<void> {
  await expect(insertRawD1WebhookEndpointCategoryRecord(database, input)).rejects.toThrow(
    /CHECK constraint failed/,
  );
}

async function expectRawD1WalletInsertRejected(
  database: D1DatabaseLike,
  input: RawD1WalletInsertInput,
): Promise<void> {
  await expect(insertRawD1WalletRecord(database, input)).rejects.toThrow(/CHECK constraint failed/);
}

async function expectRawD1WalletSignerInsertRejected(
  database: D1DatabaseLike,
  input: RawD1WalletSignerInsertInput,
): Promise<void> {
  await expect(insertRawD1WalletSignerRecord(database, input)).rejects.toThrow(
    /CHECK constraint failed/,
  );
}

async function expectRawD1WalletAuthMethodInsertRejected(
  database: D1DatabaseLike,
  input: RawD1WalletAuthMethodInsertInput,
): Promise<void> {
  await expect(insertRawD1WalletAuthMethodRecord(database, input)).rejects.toThrow(
    /CHECK constraint failed/,
  );
}

async function expectRawD1SigningRootSecretShareInsertRejected(
  database: D1DatabaseLike,
  input: RawD1SigningRootSecretShareInsertInput,
): Promise<void> {
  await expect(insertRawD1SigningRootSecretShareRecord(database, input)).rejects.toThrow(
    /CHECK constraint failed/,
  );
}

async function expectRawD1IdentityLinkInsertRejected(
  database: D1DatabaseLike,
  input: RawD1IdentityLinkInsertInput,
): Promise<void> {
  await expect(insertRawD1IdentityLinkRecord(database, input)).rejects.toThrow(
    /CHECK constraint failed/,
  );
}

async function expectRawD1AppSessionVersionInsertRejected(
  database: D1DatabaseLike,
  input: RawD1AppSessionVersionInsertInput,
): Promise<void> {
  await expect(insertRawD1AppSessionVersionRecord(database, input)).rejects.toThrow(
    /CHECK constraint failed/,
  );
}

async function expectRawD1RecoverySessionInsertRejected(
  database: D1DatabaseLike,
  input: RawD1RecoverySessionInsertInput,
): Promise<void> {
  await expect(insertRawD1RecoverySessionRecord(database, input)).rejects.toThrow(
    /CHECK constraint failed/,
  );
}

async function expectRawD1RecoveryExecutionInsertRejected(
  database: D1DatabaseLike,
  input: RawD1RecoveryExecutionInsertInput,
): Promise<void> {
  await expect(insertRawD1RecoveryExecutionRecord(database, input)).rejects.toThrow(
    /CHECK constraint failed/,
  );
}

async function expectRawD1EmailRecoveryPreparationInsertRejected(
  database: D1DatabaseLike,
  input: RawD1EmailRecoveryPreparationInsertInput,
): Promise<void> {
  await expect(insertRawD1EmailRecoveryPreparationRecord(database, input)).rejects.toThrow(
    /CHECK constraint failed/,
  );
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

function isErrorWithCode(input: unknown): input is ErrorWithCode {
  return Boolean(input && typeof input === 'object' && 'code' in input);
}

const D1_MIGRATION_TARGETS: readonly D1MigrationTarget[] = Object.freeze([
  {
    directoryName: 'd1-console',
    expectedMigrationCount: 18,
    expectedTableCount: 40,
  },
  {
    directoryName: 'd1-signer',
    expectedMigrationCount: 10,
    expectedTableCount: 21,
  },
]);

test.describe('D1 migration smoke', () => {
  for (const target of D1_MIGRATION_TARGETS) {
    test(`${target.directoryName} migrations apply in order`, async () => {
      const temp = createTemporaryD1Database();
      try {
        const migrationFiles = listD1MigrationFiles(target.directoryName);
        expect(d1MigrationFileBasenames(migrationFiles)).toHaveLength(
          target.expectedMigrationCount,
        );

        await applyD1MigrationFiles(temp.database, migrationFiles);

        await expect(readUserTableCount(temp.database)).resolves.toBe(target.expectedTableCount);
        if (target.directoryName === 'd1-signer') {
          const walletColumns = await readTableColumnNames(temp.database, 'wallets');
          const authMethodColumns = await readTableColumnNames(
            temp.database,
            'wallet_auth_methods',
          );
          expect(walletColumns).toContain('wallet_id');
          expect(walletColumns).not.toContain('rp_id');
          expect(authMethodColumns).toContain('rp_id');
        }
      } finally {
        cleanupTemporaryD1Database(temp.tempDir);
      }
    });
  }

  test('d1-signer wallet migration rejects raw identity mismatches', async () => {
    const temp = createTemporaryD1Database();
    try {
      await applyD1MigrationFiles(temp.database, listD1MigrationFiles('d1-signer'));

      await expectRawD1WalletInsertRejected(
        temp.database,
        buildRawD1WalletInsertInput({
          recordJson: JSON.stringify({
            version: 'wrong_wallet_version',
            walletId: 'wallet-raw-identity',
          }),
        }),
      );
      await expectRawD1WalletInsertRejected(
        temp.database,
        buildRawD1WalletInsertInput({
          recordJson: JSON.stringify({
            version: 'wallet_v1',
            walletId: 'different-wallet-id',
          }),
        }),
      );
      await expectRawD1WalletInsertRejected(
        temp.database,
        buildRawD1WalletInsertInput({
          recordJson: JSON.stringify({
            version: 'wallet_v1',
          }),
        }),
      );

      await insertRawD1WalletRecord(temp.database, buildRawD1WalletInsertInput({}));
      const row = await temp.database
        .prepare('SELECT COUNT(*) AS record_count FROM wallets')
        .first<{ record_count?: unknown }>();
      expect(Number(row?.record_count || 0)).toBe(1);
    } finally {
      cleanupTemporaryD1Database(temp.tempDir);
    }
  });

  test('d1-signer wallet signer migration rejects invalid branch rows', async () => {
    const temp = createTemporaryD1Database();
    try {
      await applyD1MigrationFiles(temp.database, listD1MigrationFiles('d1-signer'));

      await expectRawD1WalletSignerInsertRejected(
        temp.database,
        buildRawD1Ed25519WalletSignerInsertInput({
          chainTargetKey: 'evm:eip155:8453',
        }),
      );
      await expectRawD1WalletSignerInsertRejected(
        temp.database,
        buildRawD1Ed25519WalletSignerInsertInput({
          signerId: 'wrong-ed25519-signer-id',
        }),
      );
      await expectRawD1WalletSignerInsertRejected(
        temp.database,
        buildRawD1Ed25519WalletSignerInsertInput({
          recordJson: JSON.stringify({
            version: 'wallet_signer_ed25519_v1',
            walletId: 'different-wallet-id',
            signerId: 'ed25519:wallet-raw-ed25519.testnet:1',
          }),
        }),
      );
      await expectRawD1WalletSignerInsertRejected(
        temp.database,
        buildRawD1EcdsaWalletSignerInsertInput({
          chainTargetKey: null,
        }),
      );
      await expectRawD1WalletSignerInsertRejected(
        temp.database,
        buildRawD1EcdsaWalletSignerInsertInput({
          signerId: 'ecdsa:wrong-chain-target',
        }),
      );
      await expectRawD1WalletSignerInsertRejected(
        temp.database,
        buildRawD1EcdsaWalletSignerInsertInput({
          recordJson: JSON.stringify({
            version: 'wallet_signer_ecdsa_v1',
            walletId: 'wallet-raw-ecdsa-signer',
            signerId: 'ecdsa:evm:eip155:8453',
            chainTargetKey: 'evm:eip155:11155111',
          }),
        }),
      );

      await insertRawD1WalletSignerRecord(
        temp.database,
        buildRawD1Ed25519WalletSignerInsertInput({}),
      );
      await insertRawD1WalletSignerRecord(
        temp.database,
        buildRawD1EcdsaWalletSignerInsertInput({}),
      );
      const row = await temp.database
        .prepare('SELECT COUNT(*) AS record_count FROM wallet_signers')
        .first<{ record_count?: unknown }>();
      expect(Number(row?.record_count || 0)).toBe(2);
    } finally {
      cleanupTemporaryD1Database(temp.tempDir);
    }
  });

  test('d1-signer wallet auth-method migration rejects invalid branch rows', async () => {
    const temp = createTemporaryD1Database();
    try {
      await applyD1MigrationFiles(temp.database, listD1MigrationFiles('d1-signer'));

      await expectRawD1WalletAuthMethodInsertRejected(
        temp.database,
        buildRawD1PasskeyAuthMethodInsertInput({
          credentialIdB64u: null,
        }),
      );
      await expectRawD1WalletAuthMethodInsertRejected(
        temp.database,
        buildRawD1PasskeyAuthMethodInsertInput({
          walletAuthMethodId: 'passkey:wrong-id',
        }),
      );
      await expectRawD1WalletAuthMethodInsertRejected(
        temp.database,
        buildRawD1PasskeyAuthMethodInsertInput({
          emailHashHex: 'b'.repeat(64),
        }),
      );
      await expectRawD1WalletAuthMethodInsertRejected(
        temp.database,
        buildRawD1EmailOtpAuthMethodInsertInput({
          rpId: 'app.example.test',
        }),
      );
      await expectRawD1WalletAuthMethodInsertRejected(
        temp.database,
        buildRawD1EmailOtpAuthMethodInsertInput({
          registrationAuthorityId: null,
        }),
      );
      await expectRawD1WalletAuthMethodInsertRejected(
        temp.database,
        buildRawD1EmailOtpAuthMethodInsertInput({
          authIdentifierKey: 'wrong-email-auth-identifier',
        }),
      );

      await insertRawD1WalletAuthMethodRecord(
        temp.database,
        buildRawD1PasskeyAuthMethodInsertInput({}),
      );
      await insertRawD1WalletAuthMethodRecord(
        temp.database,
        buildRawD1EmailOtpAuthMethodInsertInput({}),
      );
      const row = await temp.database
        .prepare('SELECT COUNT(*) AS record_count FROM wallet_auth_methods')
        .first<{ record_count?: unknown }>();
      expect(Number(row?.record_count || 0)).toBe(2);
    } finally {
      cleanupTemporaryD1Database(temp.tempDir);
    }
  });

  test('d1-signer sealed-share migration rejects corrupt raw custody rows', async () => {
    const temp = createTemporaryD1Database();
    try {
      await applyD1MigrationFiles(temp.database, listD1MigrationFiles('d1-signer'));

      await expectRawD1SigningRootSecretShareInsertRejected(
        temp.database,
        buildRawD1SigningRootSecretShareInsertInput({
          namespace: '',
        }),
      );
      await expectRawD1SigningRootSecretShareInsertRejected(
        temp.database,
        buildRawD1SigningRootSecretShareInsertInput({
          signingRootId: '',
        }),
      );
      await expectRawD1SigningRootSecretShareInsertRejected(
        temp.database,
        buildRawD1SigningRootSecretShareInsertInput({
          sealedShareB64u: 'AQIDBA=',
        }),
      );
      await expectRawD1SigningRootSecretShareInsertRejected(
        temp.database,
        buildRawD1SigningRootSecretShareInsertInput({
          aadDigestB64u: 'short',
        }),
      );
      await expectRawD1SigningRootSecretShareInsertRejected(
        temp.database,
        buildRawD1SigningRootSecretShareInsertInput({
          storageId: '',
        }),
      );
      await expectRawD1SigningRootSecretShareInsertRejected(
        temp.database,
        buildRawD1SigningRootSecretShareInsertInput({
          createdAtMs: 0,
        }),
      );
      await expectRawD1SigningRootSecretShareInsertRejected(
        temp.database,
        buildRawD1SigningRootSecretShareInsertInput({
          updatedAtMs: Date.parse('2026-06-26T23:59:59.000Z'),
        }),
      );
      await expectRawD1SigningRootSecretShareInsertRejected(
        temp.database,
        buildRawD1SigningRootSecretShareInsertInput({
          rotatedAtMs: Date.parse('2026-06-26T23:59:59.000Z'),
        }),
      );

      await insertRawD1SigningRootSecretShareRecord(
        temp.database,
        buildRawD1SigningRootSecretShareInsertInput({}),
      );
      const row = await temp.database
        .prepare('SELECT COUNT(*) AS record_count FROM signing_root_secret_shares')
        .first<{ record_count?: unknown }>();
      expect(Number(row?.record_count || 0)).toBe(1);
    } finally {
      cleanupTemporaryD1Database(temp.tempDir);
    }
  });

  test('d1-signer identity and recovery migrations reject corrupt raw rows', async () => {
    const temp = createTemporaryD1Database();
    try {
      await applyD1MigrationFiles(temp.database, listD1MigrationFiles('d1-signer'));

      await expectRawD1IdentityLinkInsertRejected(
        temp.database,
        buildRawD1IdentityLinkInsertInput({
          namespace: '',
        }),
      );
      await expectRawD1IdentityLinkInsertRejected(
        temp.database,
        buildRawD1IdentityLinkInsertInput({
          subject: '',
        }),
      );
      await expectRawD1IdentityLinkInsertRejected(
        temp.database,
        buildRawD1IdentityLinkInsertInput({
          recordJson: JSON.stringify({
            version: 'wrong_identity_version',
            subject: 'google:raw-identity-subject',
            userId: 'wallet-raw-identity-session',
            createdAtMs: Date.parse('2026-06-27T00:00:00.000Z'),
            updatedAtMs: Date.parse('2026-06-27T00:00:01.000Z'),
          }),
        }),
      );
      await expectRawD1IdentityLinkInsertRejected(
        temp.database,
        buildRawD1IdentityLinkInsertInput({
          recordJson: JSON.stringify({
            version: 'identity_subject_v1',
            subject: 'google:different-subject',
            userId: 'wallet-raw-identity-session',
            createdAtMs: Date.parse('2026-06-27T00:00:00.000Z'),
            updatedAtMs: Date.parse('2026-06-27T00:00:01.000Z'),
          }),
        }),
      );
      await expectRawD1IdentityLinkInsertRejected(
        temp.database,
        buildRawD1IdentityLinkInsertInput({
          createdAtMs: Date.parse('2026-06-27T00:00:01.000Z'),
          updatedAtMs: Date.parse('2026-06-27T00:00:00.000Z'),
        }),
      );
      await insertRawD1IdentityLinkRecord(temp.database, buildRawD1IdentityLinkInsertInput({}));

      await expectRawD1AppSessionVersionInsertRejected(
        temp.database,
        buildRawD1AppSessionVersionInsertInput({
          userId: '',
        }),
      );
      await expectRawD1AppSessionVersionInsertRejected(
        temp.database,
        buildRawD1AppSessionVersionInsertInput({
          sessionVersion: '',
        }),
      );
      await expectRawD1AppSessionVersionInsertRejected(
        temp.database,
        buildRawD1AppSessionVersionInsertInput({
          recordJson: JSON.stringify({
            version: 'wrong_app_session_version',
            userId: 'wallet-raw-app-session',
            appSessionVersion: 'app-session-version-raw',
            createdAtMs: Date.parse('2026-06-27T00:00:00.000Z'),
            updatedAtMs: Date.parse('2026-06-27T00:00:01.000Z'),
          }),
        }),
      );
      await expectRawD1AppSessionVersionInsertRejected(
        temp.database,
        buildRawD1AppSessionVersionInsertInput({
          recordJson: JSON.stringify({
            version: 'app_session_version_v1',
            userId: 'wallet-raw-app-session',
            appSessionVersion: 'different-session-version',
            createdAtMs: Date.parse('2026-06-27T00:00:00.000Z'),
            updatedAtMs: Date.parse('2026-06-27T00:00:01.000Z'),
          }),
        }),
      );
      await insertRawD1AppSessionVersionRecord(
        temp.database,
        buildRawD1AppSessionVersionInsertInput({}),
      );

      await expectRawD1RecoverySessionInsertRejected(
        temp.database,
        buildRawD1RecoverySessionInsertInput({
          sessionId: '',
        }),
      );
      await expectRawD1RecoverySessionInsertRejected(
        temp.database,
        buildRawD1RecoverySessionInsertInput({
          nearAccountId: 'wallet-raw-recovery.testnet',
          recordJson: JSON.stringify({
            version: 'recovery_session_v1',
            sessionId: 'recovery-session-raw-schema',
            nearAccountId: 'different-recovery.testnet',
            status: 'prepared',
            createdAtMs: Date.parse('2026-06-27T00:00:00.000Z'),
            updatedAtMs: Date.parse('2026-06-27T00:00:01.000Z'),
            expiresAtMs: Date.parse('2026-06-27T00:10:00.000Z'),
          }),
        }),
      );
      await expectRawD1RecoverySessionInsertRejected(
        temp.database,
        buildRawD1RecoverySessionInsertInput({
          recordJson: JSON.stringify({
            version: 'recovery_session_v1',
            sessionId: 'recovery-session-raw-schema',
            nearAccountId: 'wallet-raw-recovery.testnet',
            status: 'unsupported',
            createdAtMs: Date.parse('2026-06-27T00:00:00.000Z'),
            updatedAtMs: Date.parse('2026-06-27T00:00:01.000Z'),
            expiresAtMs: Date.parse('2026-06-27T00:10:00.000Z'),
          }),
        }),
      );
      await expectRawD1RecoverySessionInsertRejected(
        temp.database,
        buildRawD1RecoverySessionInsertInput({
          expiresAtMs: Date.parse('2026-06-27T00:00:00.000Z'),
        }),
      );
      await insertRawD1RecoverySessionRecord(
        temp.database,
        buildRawD1RecoverySessionInsertInput({}),
      );

      await expectRawD1RecoveryExecutionInsertRejected(
        temp.database,
        buildRawD1RecoveryExecutionInsertInput({
          chainIdKey: '',
        }),
      );
      await expectRawD1RecoveryExecutionInsertRejected(
        temp.database,
        buildRawD1RecoveryExecutionInsertInput({
          status: 'unsupported',
        }),
      );
      await expectRawD1RecoveryExecutionInsertRejected(
        temp.database,
        buildRawD1RecoveryExecutionInsertInput({
          recordJson: JSON.stringify({
            version: 'recovery_execution_v1',
            sessionId: 'different-recovery-session',
            chainIdKey: 'evm:eip155:8453',
            accountAddress: `0x${'22'.repeat(20)}`,
            action: 'recover_owner',
            status: 'pending',
            createdAtMs: Date.parse('2026-06-27T00:00:00.000Z'),
            updatedAtMs: Date.parse('2026-06-27T00:00:01.000Z'),
          }),
        }),
      );
      await insertRawD1RecoveryExecutionRecord(
        temp.database,
        buildRawD1RecoveryExecutionInsertInput({}),
      );

      await expectRawD1EmailRecoveryPreparationInsertRejected(
        temp.database,
        buildRawD1EmailRecoveryPreparationInsertInput({
          requestId: '',
        }),
      );
      await expectRawD1EmailRecoveryPreparationInsertRejected(
        temp.database,
        buildRawD1EmailRecoveryPreparationInsertInput({
          walletId: '',
        }),
      );
      await expectRawD1EmailRecoveryPreparationInsertRejected(
        temp.database,
        buildRawD1EmailRecoveryPreparationInsertInput({
          recordJson: JSON.stringify({
            version: 'email_recovery_preparation_v1',
            requestId: 'email-recovery-preparation-raw-schema',
            accountId: 'wallet-raw-email-recovery.testnet',
            walletBinding: {
              walletId: 'different-wallet-id',
            },
            rpId: 'app.example.test',
            createdAtMs: Date.parse('2026-06-27T00:00:00.000Z'),
            expiresAtMs: Date.parse('2026-06-27T00:10:00.000Z'),
          }),
        }),
      );
      await expectRawD1EmailRecoveryPreparationInsertRejected(
        temp.database,
        buildRawD1EmailRecoveryPreparationInsertInput({
          expiresAtMs: Date.parse('2026-06-27T00:00:00.000Z'),
        }),
      );
      await insertRawD1EmailRecoveryPreparationRecord(
        temp.database,
        buildRawD1EmailRecoveryPreparationInsertInput({}),
      );

      const identityRow = await temp.database
        .prepare('SELECT COUNT(*) AS record_count FROM identity_links')
        .first<{ record_count?: unknown }>();
      const sessionVersionRow = await temp.database
        .prepare('SELECT COUNT(*) AS record_count FROM app_session_versions')
        .first<{ record_count?: unknown }>();
      const recoverySessionRow = await temp.database
        .prepare('SELECT COUNT(*) AS record_count FROM recovery_sessions')
        .first<{ record_count?: unknown }>();
      const recoveryExecutionRow = await temp.database
        .prepare('SELECT COUNT(*) AS record_count FROM recovery_executions')
        .first<{ record_count?: unknown }>();
      const emailRecoveryRow = await temp.database
        .prepare('SELECT COUNT(*) AS record_count FROM email_recovery_preparations')
        .first<{ record_count?: unknown }>();
      expect(Number(identityRow?.record_count || 0)).toBe(1);
      expect(Number(sessionVersionRow?.record_count || 0)).toBe(1);
      expect(Number(recoverySessionRow?.record_count || 0)).toBe(1);
      expect(Number(recoveryExecutionRow?.record_count || 0)).toBe(1);
      expect(Number(emailRecoveryRow?.record_count || 0)).toBe(1);
    } finally {
      cleanupTemporaryD1Database(temp.tempDir);
    }
  });

  test('d1-signer Email OTP migrations reject corrupt raw rows', async () => {
    const temp = createTemporaryD1Database();
    try {
      await applyD1MigrationFiles(temp.database, listD1MigrationFiles('d1-signer'));

      await expectRawD1EmailOtpChallengeInsertRejected(
        temp.database,
        buildRawD1EmailOtpChallengeInsertInput({
          namespace: '',
        }),
      );
      await expectRawD1EmailOtpChallengeInsertRejected(
        temp.database,
        buildRawD1EmailOtpChallengeInsertInput({
          action: 'unsupported',
        }),
      );
      await expectRawD1EmailOtpChallengeInsertRejected(
        temp.database,
        buildRawD1EmailOtpChallengeInsertInput({
          recordJson: JSON.stringify({
            version: 'email_otp_challenge_v1',
            challengeId: 'different-challenge-id',
            challengeSubjectId: 'google-subject-raw-email-otp',
            walletId: 'wallet-raw-email-otp',
            orgId: 'org-d1-email-otp-schema',
            otpChannel: 'email_otp',
            otpCode: '123456',
            sessionHash: 'session-hash-raw-email-otp',
            appSessionVersion: 'app-session-raw-email-otp',
            action: 'wallet_email_otp_login',
            operation: 'wallet_unlock',
            createdAtMs: Date.parse('2026-06-27T00:00:00.000Z'),
            expiresAtMs: Date.parse('2026-06-27T00:10:00.000Z'),
          }),
        }),
      );
      await insertRawD1EmailOtpChallengeRecord(
        temp.database,
        buildRawD1EmailOtpChallengeInsertInput({}),
      );

      await expectRawD1EmailOtpGrantInsertRejected(
        temp.database,
        buildRawD1EmailOtpGrantInsertInput({
          action: 'wallet_email_otp_registration',
        }),
      );
      await expectRawD1EmailOtpGrantInsertRejected(
        temp.database,
        buildRawD1EmailOtpGrantInsertInput({
          recordJson: JSON.stringify({
            version: 'email_otp_grant_v1',
            grantToken: 'different-email-otp-grant',
            userId: 'google-subject-raw-email-otp',
            walletId: 'wallet-raw-email-otp',
            orgId: 'org-d1-email-otp-schema',
            challengeId: 'email-otp-challenge-raw-schema',
            otpChannel: 'email_otp',
            action: 'wallet_email_otp_unseal',
            issuedAtMs: Date.parse('2026-06-27T00:00:00.000Z'),
            expiresAtMs: Date.parse('2026-06-27T00:10:00.000Z'),
          }),
        }),
      );
      await insertRawD1EmailOtpGrantRecord(temp.database, buildRawD1EmailOtpGrantInsertInput({}));

      await expectRawD1EmailOtpEnrollmentInsertRejected(
        temp.database,
        buildRawD1EmailOtpEnrollmentInsertInput({
          verifiedEmail: '',
        }),
      );
      await expectRawD1EmailOtpEnrollmentInsertRejected(
        temp.database,
        buildRawD1EmailOtpEnrollmentInsertInput({
          recordJson: JSON.stringify({
            version: 'email_otp_wallet_enrollment_v1',
            walletId: 'different-wallet-id',
            providerUserId: 'google-subject-raw-email-otp',
            orgId: 'org-d1-email-otp-schema',
            verifiedEmail: 'raw@example.test',
            createdAtMs: Date.parse('2026-06-27T00:00:00.000Z'),
            updatedAtMs: Date.parse('2026-06-27T00:00:01.000Z'),
          }),
        }),
      );
      await insertRawD1EmailOtpEnrollmentRecord(
        temp.database,
        buildRawD1EmailOtpEnrollmentInsertInput({}),
      );

      await expectRawD1EmailOtpRecoveryEscrowInsertRejected(
        temp.database,
        buildRawD1EmailOtpRecoveryEscrowInsertInput({
          recoveryKeyStatus: 'consumed',
        }),
      );
      await expectRawD1EmailOtpRecoveryEscrowInsertRejected(
        temp.database,
        buildRawD1EmailOtpRecoveryEscrowInsertInput({
          recordJson: JSON.stringify({
            version: 'email_otp_recovery_wrapped_enrollment_escrow_v1',
            alg: 'chacha20poly1305-hkdf-sha256-v1',
            secretKind: 'email_otp_device_enrollment_escrow',
            escrowKind: 'recovery_wrapped_enrollment_escrow',
            walletId: 'wallet-raw-email-otp',
            userId: 'google-subject-raw-email-otp',
            authSubjectId: 'google-subject-raw-email-otp',
            authMethod: 'google_sso_email_otp',
            recoveryKeyId: 'recovery-key-raw-email-otp',
            recoveryKeyStatus: 'active',
            consumedAtMs: Date.parse('2026-06-27T00:00:01.000Z'),
            issuedAtMs: Date.parse('2026-06-27T00:00:00.000Z'),
            updatedAtMs: Date.parse('2026-06-27T00:00:01.000Z'),
          }),
        }),
      );
      await insertRawD1EmailOtpRecoveryEscrowRecord(
        temp.database,
        buildRawD1EmailOtpRecoveryEscrowInsertInput({}),
      );

      await expectRawD1EmailOtpAuthStateInsertRejected(
        temp.database,
        buildRawD1EmailOtpAuthStateInsertInput({
          providerUserId: '',
        }),
      );
      await expectRawD1EmailOtpAuthStateInsertRejected(
        temp.database,
        buildRawD1EmailOtpAuthStateInsertInput({
          updatedAtMs: Date.parse('2026-06-26T23:59:59.000Z'),
        }),
      );
      await insertRawD1EmailOtpAuthStateRecord(
        temp.database,
        buildRawD1EmailOtpAuthStateInsertInput({}),
      );

      await expectRawD1EmailOtpUnlockChallengeInsertRejected(
        temp.database,
        buildRawD1EmailOtpUnlockChallengeInsertInput({
          challengeId: '',
        }),
      );
      await expectRawD1EmailOtpUnlockChallengeInsertRejected(
        temp.database,
        buildRawD1EmailOtpUnlockChallengeInsertInput({
          recordJson: JSON.stringify({
            version: 'email_otp_unlock_challenge_v1',
            challengeId: 'email-otp-unlock-challenge-raw-schema',
            walletId: 'wallet-raw-email-otp',
            userId: 'different-user-id',
            orgId: 'org-d1-email-otp-schema',
            createdAtMs: Date.parse('2026-06-27T00:00:00.000Z'),
            expiresAtMs: Date.parse('2026-06-27T00:10:00.000Z'),
          }),
        }),
      );
      await insertRawD1EmailOtpUnlockChallengeRecord(
        temp.database,
        buildRawD1EmailOtpUnlockChallengeInsertInput({}),
      );

      await expectRawD1EmailOtpRegistrationAttemptInsertRejected(
        temp.database,
        buildRawD1EmailOtpRegistrationAttemptInsertInput({
          state: 'unsupported',
        }),
      );
      await expectRawD1EmailOtpRegistrationAttemptInsertRejected(
        temp.database,
        buildRawD1EmailOtpRegistrationAttemptInsertInput({
          offerWalletIdsJson: JSON.stringify({ walletId: 'wallet-raw-email-otp' }),
        }),
      );
      await expectRawD1EmailOtpRegistrationAttemptInsertRejected(
        temp.database,
        buildRawD1EmailOtpRegistrationAttemptInsertInput({
          recordJson: JSON.stringify({
            version: 'google_email_otp_registration_attempt_v1',
            attemptId: 'email-otp-registration-attempt-raw-schema',
            providerSubject: 'google-subject-raw-email-otp',
            email: 'raw@example.test',
            walletId: 'different-wallet-id',
            state: 'started',
            appSessionVersion: 'app-session-raw-email-otp',
            runtimePolicyScope: {
              orgId: 'org-d1-email-otp-schema',
            },
            createdAtMs: Date.parse('2026-06-27T00:00:00.000Z'),
            updatedAtMs: Date.parse('2026-06-27T00:00:01.000Z'),
            expiresAtMs: Date.parse('2026-06-27T00:10:00.000Z'),
          }),
        }),
      );
      await insertRawD1EmailOtpRegistrationAttemptRecord(
        temp.database,
        buildRawD1EmailOtpRegistrationAttemptInsertInput({}),
      );

      await expectRawD1EmailOtpRateLimitInsertRejected(
        temp.database,
        buildRawD1EmailOtpRateLimitInsertInput({
          rateKey: '',
        }),
      );
      await expectRawD1EmailOtpRateLimitInsertRejected(
        temp.database,
        buildRawD1EmailOtpRateLimitInsertInput({
          resetAtMs: Date.parse('2026-06-27T00:00:00.000Z'),
        }),
      );
      await insertRawD1EmailOtpRateLimitRecord(
        temp.database,
        buildRawD1EmailOtpRateLimitInsertInput({}),
      );

      const challengeRow = await temp.database
        .prepare('SELECT COUNT(*) AS record_count FROM email_otp_challenges')
        .first<{ record_count?: unknown }>();
      const grantRow = await temp.database
        .prepare('SELECT COUNT(*) AS record_count FROM email_otp_grants')
        .first<{ record_count?: unknown }>();
      const enrollmentRow = await temp.database
        .prepare('SELECT COUNT(*) AS record_count FROM email_otp_wallet_enrollments')
        .first<{ record_count?: unknown }>();
      const escrowRow = await temp.database
        .prepare(
          'SELECT COUNT(*) AS record_count FROM email_otp_recovery_wrapped_enrollment_escrows',
        )
        .first<{ record_count?: unknown }>();
      const authStateRow = await temp.database
        .prepare('SELECT COUNT(*) AS record_count FROM email_otp_auth_states')
        .first<{ record_count?: unknown }>();
      const unlockChallengeRow = await temp.database
        .prepare('SELECT COUNT(*) AS record_count FROM email_otp_unlock_challenges')
        .first<{ record_count?: unknown }>();
      const registrationAttemptRow = await temp.database
        .prepare('SELECT COUNT(*) AS record_count FROM email_otp_registration_attempts')
        .first<{ record_count?: unknown }>();
      const rateLimitRow = await temp.database
        .prepare('SELECT COUNT(*) AS record_count FROM email_otp_rate_limits')
        .first<{ record_count?: unknown }>();
      expect(Number(challengeRow?.record_count || 0)).toBe(1);
      expect(Number(grantRow?.record_count || 0)).toBe(1);
      expect(Number(enrollmentRow?.record_count || 0)).toBe(1);
      expect(Number(escrowRow?.record_count || 0)).toBe(1);
      expect(Number(authStateRow?.record_count || 0)).toBe(1);
      expect(Number(unlockChallengeRow?.record_count || 0)).toBe(1);
      expect(Number(registrationAttemptRow?.record_count || 0)).toBe(1);
      expect(Number(rateLimitRow?.record_count || 0)).toBe(1);
    } finally {
      cleanupTemporaryD1Database(temp.tempDir);
    }
  });

  test('d1-console webhook migration rejects corrupt raw endpoint rows', async () => {
    const temp = createTemporaryD1Database();
    try {
      await applyD1MigrationFiles(temp.database, listD1MigrationFiles('d1-console'));

      await expectRawD1WebhookEndpointInsertRejected(
        temp.database,
        buildRawD1WebhookEndpointInsertInput({
          namespace: '',
        }),
      );
      await expectRawD1WebhookEndpointInsertRejected(
        temp.database,
        buildRawD1WebhookEndpointInsertInput({
          id: '',
        }),
      );
      await expectRawD1WebhookEndpointInsertRejected(
        temp.database,
        buildRawD1WebhookEndpointInsertInput({
          url: 'ftp://webhook.example.test/receive',
        }),
      );
      await expectRawD1WebhookEndpointInsertRejected(
        temp.database,
        buildRawD1WebhookEndpointInsertInput({
          signingSecretCiphertextB64u: 'sealed-secret=',
        }),
      );
      await expectRawD1WebhookEndpointInsertRejected(
        temp.database,
        buildRawD1WebhookEndpointInsertInput({
          secretPreview: '',
        }),
      );
      await expectRawD1WebhookEndpointInsertRejected(
        temp.database,
        buildRawD1WebhookEndpointInsertInput({
          createdAtMs: 0,
        }),
      );
      await expectRawD1WebhookEndpointInsertRejected(
        temp.database,
        buildRawD1WebhookEndpointInsertInput({
          updatedAtMs: Date.parse('2026-06-26T23:59:59.000Z'),
        }),
      );

      await insertRawD1WebhookEndpointRecord(
        temp.database,
        buildRawD1WebhookEndpointInsertInput({}),
      );
      await expectRawD1WebhookEndpointCategoryInsertRejected(
        temp.database,
        buildRawD1WebhookEndpointCategoryInsertInput({
          category: 'unsupported',
        }),
      );
      await insertRawD1WebhookEndpointCategoryRecord(
        temp.database,
        buildRawD1WebhookEndpointCategoryInsertInput({}),
      );
      const row = await temp.database
        .prepare('SELECT COUNT(*) AS record_count FROM webhook_endpoints')
        .first<{ record_count?: unknown }>();
      expect(Number(row?.record_count || 0)).toBe(1);
    } finally {
      cleanupTemporaryD1Database(temp.tempDir);
    }
  });

  test('d1-console webhook constraint migration preserves existing endpoint categories', async () => {
    const temp = createTemporaryD1Database();
    try {
      const migrationFiles = listD1MigrationFiles('d1-console');
      const migrationNames = d1MigrationFileBasenames(migrationFiles);
      const constraintMigrationIndex = migrationNames.indexOf(
        '0018_console_constraint_hardening.sql',
      );
      expect(constraintMigrationIndex).toBeGreaterThan(0);

      await applyD1MigrationFiles(temp.database, migrationFiles.slice(0, constraintMigrationIndex));
      await insertRawD1WebhookEndpointRecord(
        temp.database,
        buildRawD1WebhookEndpointInsertInput({}),
      );
      await insertRawD1WebhookEndpointCategoryRecord(
        temp.database,
        buildRawD1WebhookEndpointCategoryInsertInput({}),
      );

      await applyD1MigrationFiles(
        temp.database,
        migrationFiles.slice(constraintMigrationIndex, constraintMigrationIndex + 1),
      );

      const row = await temp.database
        .prepare(
          `SELECT COUNT(*) AS category_count
             FROM webhook_endpoint_categories
            WHERE namespace = ?
              AND org_id = ?
              AND endpoint_id = ?
              AND category = ?`,
        )
        .bind('d1-contracts', 'org-d1-webhook-schema', 'wh_raw_webhook_schema', 'wallet')
        .first<{ category_count?: unknown }>();
      expect(Number(row?.category_count || 0)).toBe(1);
      await expectRawD1WebhookEndpointCategoryInsertRejected(
        temp.database,
        buildRawD1WebhookEndpointCategoryInsertInput({
          category: 'unsupported',
        }),
      );
    } finally {
      cleanupTemporaryD1Database(temp.tempDir);
    }
  });

  test('d1-console sponsored-call migration rejects corrupt raw records', async () => {
    const temp = createTemporaryD1Database();
    try {
      await applyD1MigrationFiles(temp.database, listD1MigrationFiles('d1-console'));

      await expectRawD1SponsoredCallInsertRejected(
        temp.database,
        buildRawD1SponsoredCallInsertInput({
          id: 'raw-sponsored-empty-idempotency',
          idempotencyKey: '',
        }),
      );
      await expectRawD1SponsoredCallInsertRejected(
        temp.database,
        buildRawD1SponsoredCallInsertInput({
          id: 'raw-sponsored-invalid-details',
          detailsJson: '{invalid-json',
        }),
      );
      await expectRawD1SponsoredCallInsertRejected(
        temp.database,
        buildRawD1SponsoredCallInsertInput({
          id: 'raw-sponsored-negative-estimate',
          estimatedSpendMinor: -1,
        }),
      );
      await expectRawD1SponsoredCallInsertRejected(
        temp.database,
        buildRawD1SponsoredCallInsertInput({
          id: 'raw-sponsored-zero-created',
          createdAtMs: 0,
        }),
      );
      await expectRawD1SponsoredCallInsertRejected(
        temp.database,
        buildRawD1SponsoredCallInsertInput({
          id: 'raw-sponsored-regressed-updated',
          createdAtMs: Date.parse('2026-06-27T00:00:01.000Z'),
          updatedAtMs: Date.parse('2026-06-27T00:00:00.000Z'),
        }),
      );

      await insertRawD1SponsoredCallRecord(
        temp.database,
        buildRawD1SponsoredCallInsertInput({
          id: 'raw-sponsored-valid',
          estimatedSpendMinor: 100,
          settledSpendMinor: 75,
        }),
      );
      const row = await temp.database
        .prepare('SELECT COUNT(*) AS record_count FROM sponsored_call_records')
        .first<{ record_count?: unknown }>();
      expect(Number(row?.record_count || 0)).toBe(1);
    } finally {
      cleanupTemporaryD1Database(temp.tempDir);
    }
  });

  test('d1-console prepaid-reservation migration rejects corrupt raw records', async () => {
    const temp = createTemporaryD1Database();
    try {
      await applyD1MigrationFiles(temp.database, listD1MigrationFiles('d1-console'));

      await expectRawD1PrepaidReservationInsertRejected(
        temp.database,
        buildRawD1PrepaidReservationInsertInput({
          id: 'raw-prepaid-empty-source',
          sourceEventId: '',
        }),
      );
      await expectRawD1PrepaidReservationInsertRejected(
        temp.database,
        buildRawD1PrepaidReservationInsertInput({
          id: 'raw-prepaid-zero-request',
          requestedMinor: 0,
          settledMinor: 0,
          releasedMinor: 0,
        }),
      );
      await expectRawD1PrepaidReservationInsertRejected(
        temp.database,
        buildRawD1PrepaidReservationInsertInput({
          id: 'raw-prepaid-bad-release-math',
          requestedMinor: 100,
          settledMinor: 40,
          releasedMinor: 10,
        }),
      );
      await expectRawD1PrepaidReservationInsertRejected(
        temp.database,
        buildRawD1PrepaidReservationInsertInput({
          id: 'raw-prepaid-reserved-settlement-data',
          status: 'RESERVED',
          settledMinor: 0,
          releasedMinor: 0,
          txOrExecutionRef: '0xshould-not-exist',
          pricingVersion: null,
        }),
      );
      await expectRawD1PrepaidReservationInsertRejected(
        temp.database,
        buildRawD1PrepaidReservationInsertInput({
          id: 'raw-prepaid-regressed-updated',
          createdAtMs: Date.parse('2026-06-27T00:00:01.000Z'),
          updatedAtMs: Date.parse('2026-06-27T00:00:00.000Z'),
        }),
      );

      await insertRawD1PrepaidReservationRecord(
        temp.database,
        buildRawD1PrepaidReservationInsertInput({
          id: 'raw-prepaid-valid',
        }),
      );
      const row = await temp.database
        .prepare('SELECT COUNT(*) AS record_count FROM billing_prepaid_reservations')
        .first<{ record_count?: unknown }>();
      expect(Number(row?.record_count || 0)).toBe(1);
    } finally {
      cleanupTemporaryD1Database(temp.tempDir);
    }
  });

  test('d1-console billing ledger migration rejects corrupt raw records', async () => {
    const temp = createTemporaryD1Database();
    try {
      await applyD1MigrationFiles(temp.database, listD1MigrationFiles('d1-console'));

      await expectRawD1BillingLedgerEntryInsertRejected(
        temp.database,
        buildRawD1BillingLedgerEntryInsertInput({
          namespace: '',
        }),
      );
      await expectRawD1BillingLedgerEntryInsertRejected(
        temp.database,
        buildRawD1BillingLedgerEntryInsertInput({
          id: '',
        }),
      );
      await expectRawD1BillingLedgerEntryInsertRejected(
        temp.database,
        buildRawD1BillingLedgerEntryInsertInput({
          description: '',
        }),
      );
      await expectRawD1BillingLedgerEntryInsertRejected(
        temp.database,
        buildRawD1BillingLedgerEntryInsertInput({
          monthUtc: '2026-13',
        }),
      );
      await expectRawD1BillingLedgerEntryInsertRejected(
        temp.database,
        buildRawD1BillingLedgerEntryInsertInput({
          sourceEventId: '',
        }),
      );
      await expectRawD1BillingLedgerEntryInsertRejected(
        temp.database,
        buildRawD1BillingLedgerEntryInsertInput({
          idempotencyKey: '',
        }),
      );
      await expectRawD1BillingLedgerEntryInsertRejected(
        temp.database,
        buildRawD1BillingLedgerEntryInsertInput({
          entryType: 'CREDIT_PURCHASE',
          amountMinor: -100,
        }),
      );
      await expectRawD1BillingLedgerEntryInsertRejected(
        temp.database,
        buildRawD1BillingLedgerEntryInsertInput({
          entryType: 'SPONSORED_EXECUTION_DEBIT',
          amountMinor: 100,
        }),
      );
      await expectRawD1BillingLedgerEntryInsertRejected(
        temp.database,
        buildRawD1BillingLedgerEntryInsertInput({
          entryType: 'MANUAL_ADJUSTMENT',
          amountMinor: 0,
        }),
      );

      await insertRawD1BillingLedgerEntryRecord(
        temp.database,
        buildRawD1BillingLedgerEntryInsertInput({}),
      );

      await expectRawD1BillingLedgerPostingInsertRejected(
        temp.database,
        buildRawD1BillingLedgerPostingInsertInput({
          id: '',
        }),
      );
      await expectRawD1BillingLedgerPostingInsertRejected(
        temp.database,
        buildRawD1BillingLedgerPostingInsertInput({
          accountCode: '',
        }),
      );
      await expectRawD1BillingLedgerPostingInsertRejected(
        temp.database,
        buildRawD1BillingLedgerPostingInsertInput({
          amountMinor: 0,
        }),
      );
      await expectRawD1BillingLedgerPostingInsertRejected(
        temp.database,
        buildRawD1BillingLedgerPostingInsertInput({
          createdAtMs: 0,
        }),
      );
      await insertRawD1BillingLedgerPostingRecord(
        temp.database,
        buildRawD1BillingLedgerPostingInsertInput({}),
      );

      await expectRawD1BillingMonthlyActiveWalletInsertRejected(
        temp.database,
        buildRawD1BillingMonthlyActiveWalletInsertInput({
          monthUtc: '2026-00',
        }),
      );
      await expectRawD1BillingMonthlyActiveWalletInsertRejected(
        temp.database,
        buildRawD1BillingMonthlyActiveWalletInsertInput({
          walletId: '',
        }),
      );
      await expectRawD1BillingMonthlyActiveWalletInsertRejected(
        temp.database,
        buildRawD1BillingMonthlyActiveWalletInsertInput({
          sourceEventId: '',
        }),
      );
      await expectRawD1BillingMonthlyActiveWalletInsertRejected(
        temp.database,
        buildRawD1BillingMonthlyActiveWalletInsertInput({
          createdAtMs: 0,
        }),
      );
      await insertRawD1BillingMonthlyActiveWalletRecord(
        temp.database,
        buildRawD1BillingMonthlyActiveWalletInsertInput({}),
      );

      const ledgerRow = await temp.database
        .prepare('SELECT COUNT(*) AS record_count FROM billing_ledger_entries')
        .first<{ record_count?: unknown }>();
      const postingRow = await temp.database
        .prepare('SELECT COUNT(*) AS record_count FROM billing_ledger_postings')
        .first<{ record_count?: unknown }>();
      const walletRow = await temp.database
        .prepare('SELECT COUNT(*) AS record_count FROM billing_monthly_active_wallets')
        .first<{ record_count?: unknown }>();
      expect(Number(ledgerRow?.record_count || 0)).toBe(1);
      expect(Number(postingRow?.record_count || 0)).toBe(1);
      expect(Number(walletRow?.record_count || 0)).toBe(1);
    } finally {
      cleanupTemporaryD1Database(temp.tempDir);
    }
  });

  test('d1-console runtime snapshot migration rejects corrupt raw outbox rows', async () => {
    const temp = createTemporaryD1Database();
    try {
      await applyD1MigrationFiles(temp.database, listD1MigrationFiles('d1-console'));

      await expectRawD1RuntimeSnapshotInsertRejected(
        temp.database,
        buildRawD1RuntimeSnapshotInsertInput({
          namespace: '',
        }),
      );
      await expectRawD1RuntimeSnapshotInsertRejected(
        temp.database,
        buildRawD1RuntimeSnapshotInsertInput({
          environmentId: '',
        }),
      );
      await expectRawD1RuntimeSnapshotInsertRejected(
        temp.database,
        buildRawD1RuntimeSnapshotInsertInput({
          payloadJson: '{invalid-json',
        }),
      );
      await expectRawD1RuntimeSnapshotInsertRejected(
        temp.database,
        buildRawD1RuntimeSnapshotInsertInput({
          effectiveAtMs: 0,
        }),
      );
      await expectRawD1RuntimeSnapshotInsertRejected(
        temp.database,
        buildRawD1RuntimeSnapshotInsertInput({
          createdBy: '',
        }),
      );

      await insertRawD1RuntimeSnapshotRecord(
        temp.database,
        buildRawD1RuntimeSnapshotInsertInput({}),
      );

      await expectRawD1RuntimeSnapshotOutboxInsertRejected(
        temp.database,
        buildRawD1RuntimeSnapshotOutboxInsertInput({
          eventId: '',
        }),
      );
      await expectRawD1RuntimeSnapshotOutboxInsertRejected(
        temp.database,
        buildRawD1RuntimeSnapshotOutboxInsertInput({
          payloadJson: '{invalid-json',
        }),
      );
      await expectRawD1RuntimeSnapshotOutboxInsertRejected(
        temp.database,
        buildRawD1RuntimeSnapshotOutboxInsertInput({
          claimedBy: 'worker-a',
        }),
      );
      await expectRawD1RuntimeSnapshotOutboxInsertRejected(
        temp.database,
        buildRawD1RuntimeSnapshotOutboxInsertInput({
          claimedBy: 'worker-a',
          claimExpiresAtMs: Date.parse('2026-06-27T00:00:00.500Z'),
        }),
      );
      await expectRawD1RuntimeSnapshotOutboxInsertRejected(
        temp.database,
        buildRawD1RuntimeSnapshotOutboxInsertInput({
          status: 'DISPATCHED',
          attemptCount: 1,
          dispatchedAtMs: null,
        }),
      );
      await expectRawD1RuntimeSnapshotOutboxInsertRejected(
        temp.database,
        buildRawD1RuntimeSnapshotOutboxInsertInput({
          status: 'DEAD_LETTER',
          attemptCount: 1,
          lastError: null,
        }),
      );

      await insertRawD1RuntimeSnapshotOutboxRecord(
        temp.database,
        buildRawD1RuntimeSnapshotOutboxInsertInput({
          eventId: 'runtime_snapshot_event_raw_pending',
          snapshotId: 'runtime_snapshot_raw_pending',
        }),
      );
      await insertRawD1RuntimeSnapshotOutboxRecord(
        temp.database,
        buildRawD1RuntimeSnapshotOutboxInsertInput({
          eventId: 'runtime_snapshot_event_raw_dispatched',
          snapshotId: 'runtime_snapshot_raw_dispatched',
          status: 'DISPATCHED',
          attemptCount: 1,
          dispatchedAtMs: Date.parse('2026-06-27T00:00:02.000Z'),
        }),
      );
      await insertRawD1RuntimeSnapshotOutboxRecord(
        temp.database,
        buildRawD1RuntimeSnapshotOutboxInsertInput({
          eventId: 'runtime_snapshot_event_raw_dead_letter',
          snapshotId: 'runtime_snapshot_raw_dead_letter',
          status: 'DEAD_LETTER',
          attemptCount: 1,
          lastError: 'delivery failed',
        }),
      );
      const snapshotRow = await temp.database
        .prepare('SELECT COUNT(*) AS record_count FROM runtime_snapshots')
        .first<{ record_count?: unknown }>();
      const outboxRow = await temp.database
        .prepare('SELECT COUNT(*) AS record_count FROM runtime_snapshot_outbox')
        .first<{ record_count?: unknown }>();
      expect(Number(snapshotRow?.record_count || 0)).toBe(1);
      expect(Number(outboxRow?.record_count || 0)).toBe(3);
    } finally {
      cleanupTemporaryD1Database(temp.tempDir);
    }
  });
});

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

      const prodEnvironment = await service.updateEnvironment(primaryCtx, 'project-d1-org:prod', {
        signingRootVersion: 'signing-root-d1-v2',
        name: 'Production Root',
      });
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

      await expect(service.getApprovalRequest(secondaryCtx, keyExport.id)).resolves.toBeNull();
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
      const finalApproval = await service.approveApprovalRequest(finalApproverCtx, keyExport.id, {
        reason: 'Second custody approval',
        mfaVerified: true,
      });
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

      await expect(service.listKeyExports(requesterCtx, { status: 'APPROVED' })).resolves.toEqual([
        expect.objectContaining({ id: created.id }),
      ]);

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
             FROM webhook_endpoints
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
      expect(retryHarness.requests.map(webhookDispatchEventId)).toEqual(['evt-d1-webhook-retry']);
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
      expect(timeseries.buckets.filter((bucket) => bucket.requestCount > 0)).toEqual([
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
      await applyConsoleD1Migrations(temp.database);
      const service = await createD1ConsoleBillingPrepaidReservationService({
        database: temp.database,
        namespace: 'd1-contracts',
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
      await applyConsoleD1Migrations(temp.database);
      const billing = await createD1ConsoleBillingService({
        database: temp.database,
        namespace: 'd1-contracts',
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
      await applyConsoleD1Migrations(temp.database);
      const namespace = 'd1-contracts';
      const orgId = 'org-d1-billing-monthly';
      const billing = await createD1ConsoleBillingService({
        database: temp.database,
        namespace,
        now: fixedD1AtomicBillingNow,
      });
      const ctx = {
        orgId,
        actorUserId: 'user-d1-billing-monthly',
        roles: ['admin'],
      };

      await temp.database
        .prepare(
          `INSERT INTO billing_monthly_active_wallets
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
      await applyConsoleD1Migrations(temp.database);
      const namespace = 'd1-contracts';
      const billing = await createD1ConsoleBillingService({
        database: temp.database,
        namespace,
        now: fixedD1AtomicBillingNow,
      });
      const prepaidReservations = await createD1ConsoleBillingPrepaidReservationService({
        database: temp.database,
        namespace,
        now: fixedD1AtomicBillingNow,
        defaultReservationTtlMs: 60_000,
      });
      const sponsoredCalls = await createD1ConsoleSponsoredCallService({
        database: temp.database,
        namespace,
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
      expect(errorCode(duplicateReservationError)).toBe('invalid_state');
      await expect(billing.getOverview(ctx)).resolves.toMatchObject({
        creditBalanceMinor: 575,
      });
      const recordsPage = await sponsoredCalls.listRecords(ctx, { limit: 10, lookbackDays: 1 });
      expect(recordsPage.items).toHaveLength(1);
    } finally {
      cleanupTemporaryD1Database(temp.tempDir);
    }
  });

  test('sponsored gas settlement rejects stale D1 reservation transitions without side effects', async () => {
    const temp = createTemporaryD1Database();
    try {
      await applyConsoleD1Migrations(temp.database);
      const namespace = 'd1-contracts';
      const billing = await createD1ConsoleBillingService({
        database: temp.database,
        namespace,
        now: fixedD1AtomicBillingNow,
      });
      const prepaidReservations = await createD1ConsoleBillingPrepaidReservationService({
        database: temp.database,
        namespace,
        now: fixedD1AtomicBillingNow,
        defaultReservationTtlMs: 60_000,
      });
      const sponsoredCalls = await createD1ConsoleSponsoredCallService({
        database: temp.database,
        namespace,
        now: fixedD1AtomicBillingNow,
      });
      const ctx = {
        orgId: 'org-d1-atomic-sponsored-stale',
        actorUserId: 'user-d1-atomic-sponsored-stale',
        roles: ['platform_admin'],
      };
      const reservationSourceEventId = 'prepaid-reservation-d1-atomic-stale';

      await billing.grantManualSupportCredit(ctx, {
        amountMinor: 1000,
        reasonCode: 'test_credit',
        note: 'Seed prepaid balance for stale D1 sponsored settlement',
        idempotencyKey: 'manual-credit-d1-atomic-stale',
      });
      const overviewBeforeReservation = await billing.getOverview(ctx);
      const reserved = await prepaidReservations.reserve(ctx, {
        sourceEventId: reservationSourceEventId,
        environmentId: 'env-production',
        policyId: 'policy-sponsored-gas',
        postedBalanceMinor: overviewBeforeReservation.creditBalanceMinor,
        estimatedSpendMinor: 700,
      });
      await prepaidReservations.release(ctx, {
        sourceEventId: reservationSourceEventId,
      });

      const stalePrepaidReservations = new StaleReadPrepaidReservationService(
        prepaidReservations,
        reserved.reservation,
      );
      const pricing = new StaticSponsoredSpendPricingService(700, 425);
      const builder = new AtomicD1SponsoredRecordBuilder('sponsored-call-d1-atomic-stale');
      const assessment = createD1AtomicAssessment();
      let staleTransitionError: unknown = null;
      try {
        await recordSponsoredExecution({
          billing,
          billingSourceEventIdPrefix: 'sponsored_evm_call_debit',
          context: ctx,
          ledger: sponsoredCalls,
          buildRecord: builder.build.bind(builder),
          assessment,
          walletId: 'wallet-d1-atomic-stale',
          prepaidSettlementInput: {
            reservation: {
              sourceEventId: reservationSourceEventId,
              estimatedSpendMinor: 700,
              estimatedPricingVersion: 'static:estimate',
            },
            prepaidReservations: stalePrepaidReservations,
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
              kind: 'd1-atomic-sponsored-settlement-stale',
            },
          },
        });
      } catch (error: unknown) {
        staleTransitionError = error;
      }

      expect(errorCode(staleTransitionError)).toBe('invalid_state');
      await expect(billing.getOverview(ctx)).resolves.toMatchObject({
        creditBalanceMinor: 1000,
      });
      const sponsoredDebitActivity = await billing.listAccountActivity(ctx, {
        eventType: 'SPONSORED_EXECUTION_DEBIT',
        limit: 10,
      });
      expect(sponsoredDebitActivity.entries).toHaveLength(0);
      const recordsPage = await sponsoredCalls.listRecords(ctx, { limit: 10, lookbackDays: 1 });
      expect(recordsPage.items).toHaveLength(0);
      const releasedReservation = await prepaidReservations.getReservationBySourceEventId(
        ctx,
        reservationSourceEventId,
      );
      expect(releasedReservation?.status).toBe('RELEASED');
    } finally {
      cleanupTemporaryD1Database(temp.tempDir);
    }
  });

  test('sponsored call idempotency returns the original record', async () => {
    const temp = createTemporaryD1Database();
    try {
      await applyConsoleD1Migrations(temp.database);
      const service = await createD1ConsoleSponsoredCallService({
        database: temp.database,
        namespace: 'd1-contracts',
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
        createdAtMs: 1000,
        updatedAtMs: 2000,
      });
      const runtimePolicyScope = {
        orgId: 'org-d1-signer',
        projectId: 'project-d1-signer',
        envId: 'env-production',
        signingRootVersion: 'signing-root-version-v1',
      } as const;
      const activeYao = buildEd25519YaoCapabilityFixture({
        walletId,
        nearAccountId: 'wallet-d1-metadata.testnet',
        nearEd25519SigningKeyId: 'near-ed25519-key-1',
        thresholdSessionId: 'threshold-session-d1-wallet',
        signerSlot: 1,
        signingWorkerId: 'signing-worker-d1-wallet',
        participantIds: [1, 2],
        runtimePolicyScope,
        seed: 71,
      });
      await walletStore.putSigner({
        version: 'wallet_signer_ed25519_v1',
        walletId,
        signerId: 'ed25519:wallet-d1-metadata:1',
        nearAccountId: 'wallet-d1-metadata.testnet',
        nearEd25519SigningKeyId: 'near-ed25519-key-1',
        thresholdSessionId: 'threshold-session-d1-wallet',
        signerSlot: 1,
        publicKey: activeYao.publicKey,
        signingWorkerId: 'signing-worker-d1-wallet',
        keyVersion: 'signer-key-v1',
        recoveryExportCapable: true,
        participantIds: [1, 2],
        signingRootId: 'project-d1-signer:env-production',
        signingRootVersion: 'signing-root-version-v1',
        runtimePolicyScope,
        activeYaoCapability: activeYao.capability,
        createdAtMs: 1000,
        updatedAtMs: 2000,
      });
      await authMethodStore.put({
        version: 'wallet_auth_method_v1',
        kind: 'passkey',
        status: 'active',
        walletId,
        rpId: unwrapFixture(parseWebAuthnRpId('app.seams.test')),
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
             FROM wallet_signers
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

      const ensuredVersion =
        await identity.ensureAppSessionVersionByUserId('user-d1-identity-alice');
      expect(ensuredVersion).toEqual(expect.any(String));
      expect(ensuredVersion.length).toBeGreaterThan(20);
      await expect(
        identity.ensureAppSessionVersionByUserId('user-d1-identity-alice'),
      ).resolves.toBe(ensuredVersion);
      await expect(
        otherEnvIdentity.getAppSessionVersionByUserId('user-d1-identity-alice'),
      ).resolves.toBeNull();
      const rotatedVersion =
        await identity.rotateAppSessionVersionByUserId('user-d1-identity-alice');
      expect(rotatedVersion).toEqual(expect.any(String));
      expect(rotatedVersion).not.toBe(ensuredVersion);
      await expect(identity.getAppSessionVersionByUserId('user-d1-identity-alice')).resolves.toBe(
        rotatedVersion,
      );
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
      await expect(sessionStore.listByNearAccountId('wallet-d1-recovery.testnet')).resolves.toEqual(
        [
          expect.objectContaining({
            sessionId: 'recovery-session-d1',
          }),
        ],
      );

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
      await expect(preparationStore.get('email-recovery-preparation-d1')).resolves.toMatchObject({
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
      await expect(
        unlockChallengeStore.consume('email-otp-unlock-challenge-d1'),
      ).resolves.toBeNull();

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
        authBinding: {
          kind: 'passkey',
          credentialIdB64u: 'credential-d1-near-key',
          rpId: unwrapFixture(parseWebAuthnRpId('app.seams.test')),
        },
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
      const harness = new RuntimeSnapshotOutboxRaceHarness(temp.database, namespace, orgId, nowMs);
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
