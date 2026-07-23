import type { ConsoleBillingService } from '../billing';
import type { ConsoleBillingPrepaidReservationService } from '../billingPrepaidReservations';
import type { ConsoleObservabilityIngestionService } from '../observability';
import type { ConsoleRuntimeSnapshotService } from '../runtimeSnapshots';
import type {
  ConsoleSponsoredCallReceiptStatus,
  ConsoleSponsoredCallRecord,
  ConsoleSponsoredCallService,
} from '../sponsoredCalls';
import type { ConsoleSponsorshipSpendCapService } from '../sponsorshipSpendCaps';
import type { ConsoleWebhookService } from '../webhooks';
import { getNearSpendCapChainId } from '@seams-internal/console-shared/gasSponsorshipSpendCapTargets';
import {
  buildSponsoredSpendCapSourceEventId,
  isSponsorshipSpendCapEnforcementError,
  releaseSponsoredSpendCap,
  reserveSponsoredSpendCap,
  settleSponsoredSpendCap,
  type SponsorshipSpendCapSettlement,
  type SponsorshipSpendPricingService,
} from '../sponsorship/spendCaps';
import {
  matchResolvedSponsoredNearDelegatePolicy,
  parseResolvedSponsoredNearDelegatePolicies,
  summarizeSignedDelegateForSponsorship,
} from '../sponsorship/near';
import {
  isSponsorshipPrepaidBalanceEnforcementError,
  reserveSponsoredPrepaidBalance,
  settleSponsoredPrepaidBalance,
} from '../sponsorship/prepaidBalance';
import { executeSponsorshipAdapter } from '../sponsorship/executionAdapter';
import {
  createSponsoredNearDelegateExecutionAdapter,
  type SponsoredNearDelegateAuthService,
} from '../sponsorship/nearExecutionAdapter';
import { applyRouteMetering } from '@seams/sdk-server/internal/router/applyRouteMetering';
import {
  enforceRoutePolicy,
  type RoutePolicyResolutionResult,
} from '@seams/sdk-server/internal/router/enforceRoutePolicy';
import type { NormalizedRouterLogger } from '@seams/sdk-server/internal/router/logger';
import { resolvePublishableKeyApiCredentialAuth } from '@seams/sdk-server/internal/router/routerApiCredentialAuth';
import { extractRouterApiEnvironmentId } from '@seams/sdk-server/internal/router/routerApiKeyAuth';
import type { HeaderRecord, RouteResponse } from '@seams/sdk-server/internal/router/routeExecutionContext';
import type { RouteDefinition } from '@seams/sdk-server/internal/router/routeDefinitions';
import type { RouteErrorBody } from '@seams/sdk-server/internal/router/routeResponses';
import { routeJson } from '@seams/sdk-server/internal/router/routeResponses';
import type { RouterApiPublishableKeyAuthAdapter } from '@seams/sdk-server/internal/router/apiCredentialPorts';
import {
  runSponsorshipExecution,
  type SponsorshipExecutionAssessment,
} from './sponsorshipExecution';
import {
  buildSponsorshipRoutePolicyFailureResponse,
  resolveSponsorshipReplayOrMatch,
  resolveSponsorshipRuntimeForPublishableKeyRoute,
} from './sponsorshipRuntime';
import {
  logSponsorshipSpendCapRejected,
  logSponsorshipSpendCapReserved,
  logSponsorshipSpendCapSettled,
} from './sponsorshipSpendCapObservability';
import {
  emitSponsorshipBalanceTransitionEvents,
  emitSponsorshipBlockedObservabilityEvent,
  readSponsorshipBillingBalanceSnapshot,
} from './sponsorshipBillingEvents';
import { isPlainObject } from '@seams-internal/shared-ts/utils/validation';

interface SignedDelegateRequestBody {
  hash: string;
  signedDelegate: unknown;
}

interface SignedDelegateExecutionAssessment extends SponsorshipExecutionAssessment {
  gasBurnt: string | null;
}

export type SignedDelegateRouterApiAuthService = SponsoredNearDelegateAuthService &
  {
    getRelayerAccount(): Promise<{ accountId: string; publicKey: string }>;
  };

type MatchedSponsoredNearDelegate =
  NonNullable<ReturnType<typeof matchResolvedSponsoredNearDelegatePolicy>>;

interface RouterApiSignedDelegateServices {
  signedDelegateAuth: SignedDelegateRouterApiAuthService;
  billing?: ConsoleBillingService | null;
  observabilityIngestion?: ConsoleObservabilityIngestionService | null;
  prepaidReservations?: ConsoleBillingPrepaidReservationService | null;
  pricing?: SponsorshipSpendPricingService | null;
  publishableKeyAuth?: RouterApiPublishableKeyAuthAdapter | null;
  runtimeSnapshots?: ConsoleRuntimeSnapshotService | null;
  spendCaps?: ConsoleSponsorshipSpendCapService | null;
  sponsoredCalls?: ConsoleSponsoredCallService | null;
  webhooks?: ConsoleWebhookService | null;
  webhookActorUserId?: string;
  webhookRoles?: string[];
}

export interface RouterApiSignedDelegateInput {
  body: unknown;
  headers: HeaderRecord;
  logger: NormalizedRouterLogger;
  origin?: string;
  route: RouteDefinition;
  services: RouterApiSignedDelegateServices;
}

function parseSignedDelegateBody(body: unknown): SignedDelegateRequestBody {
  if (!isPlainObject(body)) {
    throw new Error('invalid_body: Expected { hash, signedDelegate }');
  }
  const hash = String(body.hash || '').trim();
  if (!hash || !body.signedDelegate) {
    throw new Error('invalid_body: Expected { hash, signedDelegate }');
  }
  return {
    hash,
    signedDelegate: body.signedDelegate,
  };
}

function extractSignedDelegateSenderId(signedDelegate: unknown): string {
  return isPlainObject(signedDelegate) && isPlainObject(signedDelegate.delegateAction)
    ? String((signedDelegate.delegateAction as Record<string, unknown>).senderId || '').trim() ||
        'unknown-sender'
    : 'unknown-sender';
}

function normalizeNearAccountRef(value: unknown): string {
  return `near:${String(value || '').trim() || 'unknown'}`;
}

function resolveNearSpendCapChainId(networkClass: 'ANY' | 'TESTNET' | 'MAINNET'): number | null {
  if (networkClass === 'MAINNET') {
    return getNearSpendCapChainId('MAINNET');
  }
  if (networkClass === 'TESTNET') {
    return getNearSpendCapChainId('TESTNET');
  }
  return null;
}

function buildSignedDelegateIdempotencyKey(apiKeyId: string, hash: string): string {
  return `signed_delegate:${apiKeyId}:${hash}`;
}

function parseSignedDelegateReplayDetails(value: string): {
  execution: {
    txHash: string | null;
    gasBurnt: string | null;
    tokensBurnt: string | null;
    receiptStatus: string | null;
  };
} | null {
  try {
    const parsed = JSON.parse(value) as Record<string, unknown>;
    const execution =
      parsed.execution && typeof parsed.execution === 'object' && !Array.isArray(parsed.execution)
        ? (parsed.execution as Record<string, unknown>)
        : null;
    return {
      execution: {
        txHash: String(execution?.txHash || '').trim() || null,
        gasBurnt: String(execution?.gasBurnt || '').trim() || null,
        tokensBurnt: String(execution?.tokensBurnt || '').trim() || null,
        receiptStatus: String(execution?.receiptStatus || '').trim() || null,
      },
    };
  } catch {
    return null;
  }
}

function buildSignedDelegateReplayResponse(
  existing: ConsoleSponsoredCallRecord,
): RouteResponse<Record<string, unknown>> {
  const details = parseSignedDelegateReplayDetails(existing.detailsJson);
  const policyId = String(existing.policyId || '').trim() || null;
  if (existing.receiptStatus === 'success') {
    return routeJson(200, {
      ok: true,
      replayed: true,
      recordId: existing.id,
      policyId,
      relayerTxHash: existing.txOrExecutionRef,
      status: 'submitted',
      outcome: null,
      spendYoctoNear: String(existing.feeAmount || '').trim() || '0',
      gasBurnt: details?.execution.gasBurnt || null,
    });
  }
  return routeJson(existing.receiptStatus === 'rpc_rejected' ? 400 : 502, {
    ok: false,
    replayed: true,
    code: String(existing.errorCode || '').trim() || 'delegate_execution_failed',
    message: String(existing.errorMessage || '').trim() || 'Signed delegate execution failed',
    relayerTxHash: existing.txOrExecutionRef,
    outcome: null,
    recordId: existing.id,
    policyId,
    receiptStatus: existing.receiptStatus,
    spendYoctoNear: String(existing.feeAmount || '').trim() || '0',
    gasBurnt: details?.execution.gasBurnt || null,
  });
}

function readNearFailureDetail(status: unknown): {
  code: string | null;
  message: string | null;
} | null {
  if (isPlainObject(status) && isPlainObject(status.Failure)) {
    const failure = status.Failure as Record<string, unknown>;
    return {
      code: String(failure.error_type || '').trim() || 'near_delegate_reverted',
      message: String(failure.error_message || '').trim() || 'Signed delegate execution failed',
    };
  }
  if (String(status || '').trim() === 'Failure') {
    return {
      code: 'near_delegate_reverted',
      message: 'Signed delegate execution failed',
    };
  }
  return null;
}

function resolveNearOutcomeFailure(outcome: unknown): {
  code: string | null;
  message: string | null;
} | null {
  if (!isPlainObject(outcome)) return null;
  const directChecks = [readNearFailureDetail(outcome.status)];
  for (const failure of directChecks) {
    if (failure) return failure;
  }

  const transactionOutcome = isPlainObject(outcome.transaction_outcome)
    ? (outcome.transaction_outcome as Record<string, unknown>)
    : null;
  const rootOutcome = transactionOutcome && isPlainObject(transactionOutcome.outcome)
    ? (transactionOutcome.outcome as Record<string, unknown>)
    : null;
  const rootFailure = readNearFailureDetail(rootOutcome?.status);
  if (rootFailure) return rootFailure;

  if (Array.isArray((outcome as Record<string, unknown>).receipts_outcome)) {
    for (const entry of (outcome as Record<string, unknown>).receipts_outcome as unknown[]) {
      if (!isPlainObject(entry) || !isPlainObject(entry.outcome)) continue;
      const failure = readNearFailureDetail((entry.outcome as Record<string, unknown>).status);
      if (failure) return failure;
    }
  }

  return readNearFailureDetail(outcome.final_execution_status);
}

function resolveSignedDelegateAssessment(result: {
  ok: boolean;
  code?: string;
  error?: string;
  outcome?: unknown;
  transactionHash?: string;
}): SignedDelegateExecutionAssessment {
  const metrics = summarizeNearExecutionOutcome(result.outcome);
  const outcomeHash =
    isPlainObject(result.outcome) && isPlainObject(result.outcome.transaction)
      ? String((result.outcome.transaction as Record<string, unknown>).hash || '').trim()
      : '';
  const transactionHash = String(result.transactionHash || '').trim() || outcomeHash || null;
  const outcomeFailure = resolveNearOutcomeFailure(result.outcome);

  if (result.ok && !outcomeFailure) {
    return {
      succeeded: true,
      txOrExecutionRef: transactionHash,
      receiptStatus: 'success',
      feeUnit: 'yocto_near',
      feeAmount: metrics.feeAmountYoctoNear,
      executorKind: 'near_delegate',
      responseCode: 'ok',
      responseMessage: 'Signed delegate submitted',
      recordErrorCode: null,
      recordErrorMessage: null,
      gasBurnt: metrics.gasBurnt,
    };
  }

  if (outcomeFailure) {
    return {
      succeeded: false,
      txOrExecutionRef: transactionHash,
      receiptStatus: 'reverted',
      feeUnit: 'yocto_near',
      feeAmount: metrics.feeAmountYoctoNear,
      executorKind: 'near_delegate',
      responseCode: 'delegate_execution_failed',
      responseMessage: outcomeFailure.message || 'Signed delegate execution failed',
      recordErrorCode: outcomeFailure.code,
      recordErrorMessage: outcomeFailure.message,
      gasBurnt: metrics.gasBurnt,
    };
  }

  const responseCode = String(result.code || '').trim() || 'delegate_execution_failed';
  const responseMessage =
    String(result.error || '').trim() || 'Failed to execute delegate action';
  const receiptStatus: ConsoleSponsoredCallReceiptStatus = transactionHash
    ? 'broadcast_failed'
    : 'rpc_rejected';
  return {
    succeeded: false,
    txOrExecutionRef: transactionHash,
    receiptStatus,
    feeUnit: 'yocto_near',
    feeAmount: metrics.feeAmountYoctoNear,
    executorKind: 'near_delegate',
    responseCode,
    responseMessage,
    recordErrorCode: responseCode,
    recordErrorMessage: responseMessage,
    gasBurnt: metrics.gasBurnt,
  };
}

function resolveThrownSignedDelegateAssessment(error: unknown): SignedDelegateExecutionAssessment {
  const row =
    error && typeof error === 'object' && !Array.isArray(error)
      ? (error as Record<string, unknown>)
      : {};
  return resolveSignedDelegateAssessment({
    ok: false,
    code: String(row.code || '').trim() || undefined,
    error:
      String(row.error || row.message || '').trim() || 'Failed to execute delegate action',
    outcome: row.outcome,
    transactionHash: String(row.transactionHash || row.txHash || '').trim() || undefined,
  });
}

function summarizeNearExecutionOutcome(
  outcome: unknown,
): {
  feeAmountYoctoNear: string;
  gasBurnt: string | null;
} {
  const rows: Array<Record<string, unknown>> = [];
  if (isPlainObject(outcome)) {
    const transactionOutcome = isPlainObject(outcome.transaction_outcome)
      ? (outcome.transaction_outcome as Record<string, unknown>)
      : null;
    const rootOutcome = transactionOutcome && isPlainObject(transactionOutcome.outcome)
      ? (transactionOutcome.outcome as Record<string, unknown>)
      : null;
    if (rootOutcome) rows.push(rootOutcome);
    if (Array.isArray((outcome as Record<string, unknown>).receipts_outcome)) {
      for (const entry of (outcome as Record<string, unknown>).receipts_outcome as unknown[]) {
        if (!isPlainObject(entry) || !isPlainObject(entry.outcome)) continue;
        rows.push(entry.outcome as Record<string, unknown>);
      }
    }
  }

  let totalTokensBurnt = 0n;
  let totalGasBurnt = 0n;
  for (const row of rows) {
    const tokensBurntRaw = String(row.tokens_burnt || '').trim();
    if (tokensBurntRaw) {
      try {
        totalTokensBurnt += BigInt(tokensBurntRaw);
      } catch {}
    }
    const gasBurntRaw = row.gas_burnt;
    if (typeof gasBurntRaw === 'number' && Number.isFinite(gasBurntRaw)) {
      totalGasBurnt += BigInt(Math.max(0, Math.trunc(gasBurntRaw)));
      continue;
    }
    const gasBurntString = String(gasBurntRaw || '').trim();
    if (!gasBurntString) continue;
    try {
      totalGasBurnt += BigInt(gasBurntString);
    } catch {}
  }

  return {
    feeAmountYoctoNear: totalTokensBurnt.toString(10),
    gasBurnt: totalGasBurnt > 0n ? totalGasBurnt.toString(10) : null,
  };
}

function buildPrepaidFailureResponse(error: unknown): RouteResponse<Record<string, unknown>> | null {
  if (!isSponsorshipPrepaidBalanceEnforcementError(error)) return null;
  return routeJson(error.status, {
    ok: false,
    code: error.code,
    message: error.message,
    ...(error.details ? { details: error.details } : {}),
  });
}

function buildSignedDelegateDetailsJson(input: {
  assessment: SignedDelegateExecutionAssessment;
  hash: string;
  result: { transactionHash?: string; outcome?: unknown };
  signedDelegate: unknown;
  billing?: SponsorshipSpendCapSettlement & {
    sourceEventId: string;
    estimatedSpendMinor: number;
    released?: boolean;
  };
  policySpendCap?: SponsorshipSpendCapSettlement & {
    sourceEventId: string;
    estimatedSpendMinor: number;
  };
}): string {
  const delegateAction =
    isPlainObject(input.signedDelegate) && isPlainObject(input.signedDelegate.delegateAction)
      ? (input.signedDelegate.delegateAction as Record<string, unknown>)
      : null;
  const summary = summarizeNearExecutionOutcome(input.result.outcome);
  return JSON.stringify({
    hash: input.hash,
    delegate: {
      senderId: String(delegateAction?.senderId || '').trim() || null,
      receiverId: String(delegateAction?.receiverId || '').trim() || null,
      maxBlockHeight: String(delegateAction?.maxBlockHeight || '').trim() || null,
    },
    execution: {
      txHash:
        input.assessment.txOrExecutionRef ||
        String(input.result.transactionHash || '').trim() ||
        null,
      gasBurnt: summary.gasBurnt,
      tokensBurnt: input.assessment.feeAmount,
      receiptStatus: input.assessment.receiptStatus,
      errorCode: input.assessment.recordErrorCode,
      errorMessage: input.assessment.recordErrorMessage,
    },
    ...(input.billing
      ? {
          billing: {
            sourceEventId: input.billing.sourceEventId,
            estimatedSpendMinor: String(input.billing.estimatedSpendMinor),
            settledSpendMinor: String(input.billing.settledSpendMinor),
            pricingVersion: input.billing.pricingVersion,
            usedEstimatedFallback: input.billing.usedEstimatedFallback,
            released: input.billing.released ?? false,
          },
        }
      : {}),
    ...(input.policySpendCap
      ? {
          policySpendCap: {
            sourceEventId: input.policySpendCap.sourceEventId,
            estimatedSpendMinor: String(input.policySpendCap.estimatedSpendMinor),
            settledSpendMinor: String(input.policySpendCap.settledSpendMinor),
            pricingVersion: input.policySpendCap.pricingVersion,
            usedEstimatedFallback: input.policySpendCap.usedEstimatedFallback,
          },
        }
      : {}),
  });
}

async function meterSignedDelegate(input: {
  assessment: SignedDelegateExecutionAssessment;
  hash: string;
  idempotencyKey: string;
  policyRef: {
    policyId: string;
    policyName: string | null;
    templateId: string | null;
  };
  result: {
    outcome?: unknown;
    transactionHash?: string;
  };
  route: RouteDefinition;
  routeContext: Awaited<ReturnType<typeof enforceRoutePolicy>> extends infer TResult
    ? TResult extends { ok: true; context: infer TContext }
      ? TContext
      : never
    : never;
  services: RouterApiSignedDelegateServices;
  signedDelegate: unknown;
  prepaidSettlement?: {
    reservationId: string | null;
    settledAt: string;
    sourceEventId: string;
    estimatedSpendMinor: number;
    settledSpendMinor: number;
    pricingVersion: string;
    usedEstimatedFallback: boolean;
    released: boolean;
  };
  spendCapSettlement?: SponsorshipSpendCapSettlement & {
    sourceEventId: string;
    estimatedSpendMinor: number;
  };
}): Promise<void> {
  await applyRouteMetering({
    context: input.routeContext,
    route: input.route,
    response: routeJson(input.assessment.succeeded ? 200 : 502, { ok: input.assessment.succeeded }, {
      usage: {
        ...(input.assessment.gasBurnt ? { gasUsed: input.assessment.gasBurnt } : {}),
        ...(input.assessment.txOrExecutionRef
          ? { transactionHash: input.assessment.txOrExecutionRef }
          : {}),
      },
    }),
    handlers: {
      gas: async ({ context, ledger, response, route }) => {
        if (ledger !== 'near_delegate') return;
        if (context.principal.kind !== 'api_credentials') return;
        if (context.principal.credentialType !== 'publishable_key') return;
        const delegateAction =
          isPlainObject(input.signedDelegate) && isPlainObject(input.signedDelegate.delegateAction)
            ? (input.signedDelegate.delegateAction as Record<string, unknown>)
            : null;
        const senderId = String(delegateAction?.senderId || '').trim() || 'unknown-sender';
        const receiverId = String(delegateAction?.receiverId || '').trim() || 'unknown-receiver';
        const relayer = await input.services.signedDelegateAuth.getRelayerAccount();
        const sponsorshipCtx = {
          orgId: context.principal.principal.orgId,
          actorUserId: 'signed-delegate-executor',
          roles: ['system'],
        };
        const sponsoredCalls = input.services.sponsoredCalls;
        if (!sponsoredCalls) return;
        const beforeBalanceState = await readSponsorshipBillingBalanceSnapshot(
          input.services.billing,
          sponsorshipCtx,
        );
        let billingLedgerEntryId: string | null = null;
        if (
          input.prepaidSettlement &&
          !input.prepaidSettlement.released &&
          input.prepaidSettlement.settledSpendMinor > 0
        ) {
          const billing = input.services.billing;
          if (!billing) return;
          const debit = await billing.recordSponsoredExecutionDebit(sponsorshipCtx, {
            amountMinor: input.prepaidSettlement.settledSpendMinor,
            sourceEventId: `signed_delegate_debit:${input.prepaidSettlement.sourceEventId}`,
            walletId: senderId,
            occurredAt: input.prepaidSettlement.settledAt,
            ...(input.assessment.txOrExecutionRef
              ? { txOrExecutionRef: input.assessment.txOrExecutionRef }
              : {}),
            ...(input.prepaidSettlement.pricingVersion
              ? { pricingVersion: input.prepaidSettlement.pricingVersion }
              : {}),
          });
          billingLedgerEntryId = debit.ledgerEntryId;
          await emitSponsorshipBalanceTransitionEvents({
            services: {
              logger: input.routeContext.logger,
              webhooks: input.services.webhooks || null,
              observabilityIngestion: input.services.observabilityIngestion || null,
              webhookActorUserId: input.services.webhookActorUserId,
              webhookRoles: input.services.webhookRoles,
            },
            ctx: sponsorshipCtx,
            before: beforeBalanceState,
            billing,
            trigger: {
              kind: 'sponsored_execution_debit',
              environmentId: context.principal.principal.environmentId,
              routeId: route.id,
              ledgerEntryId: debit.ledgerEntryId,
              sourceEventId: `signed_delegate_debit:${input.prepaidSettlement.sourceEventId}`,
            },
          });
        }
        await sponsoredCalls.createRecord(sponsorshipCtx, {
          environmentId: context.principal.principal.environmentId,
          apiKeyId: context.principal.principal.apiKeyId,
          apiKeyKind: 'publishable_key',
          route: route.id,
          policyId: input.policyRef.policyId,
          policyNameAtEvent: input.policyRef.policyName,
          templateId: input.policyRef.templateId,
          chainFamily: 'near',
          intentKind: 'near_delegate',
          executorKind: 'near_delegate',
          accountRef: normalizeNearAccountRef(senderId),
          targetRef: normalizeNearAccountRef(receiverId),
          sponsorRef: normalizeNearAccountRef(relayer.accountId),
          txOrExecutionRef: input.assessment.txOrExecutionRef,
          receiptStatus: input.assessment.receiptStatus,
          feeUnit: input.assessment.feeUnit,
          feeAmount: input.assessment.feeAmount,
          detailsJson: buildSignedDelegateDetailsJson({
            assessment: input.assessment,
            hash: input.hash,
            result: input.result,
            signedDelegate: input.signedDelegate,
            ...(input.prepaidSettlement ? { billing: input.prepaidSettlement } : {}),
            ...(input.spendCapSettlement ? { policySpendCap: input.spendCapSettlement } : {}),
          }),
          estimatedSpendMinor: input.prepaidSettlement?.estimatedSpendMinor ?? null,
          settledSpendMinor: input.prepaidSettlement?.settledSpendMinor ?? null,
          pricingVersion: input.prepaidSettlement?.pricingVersion ?? null,
          pricingSource: input.prepaidSettlement ? 'sponsorship_pricing_service' : null,
          billingLedgerEntryId,
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
          errorCode: input.assessment.recordErrorCode,
          errorMessage: input.assessment.recordErrorMessage,
          idempotencyKey: input.idempotencyKey,
        });
      },
    },
  });
}

export async function handleRouterApiSignedDelegate(
  input: RouterApiSignedDelegateInput,
): Promise<RouteResponse<Record<string, unknown> | RouteErrorBody>> {
  const publishableKeyAuth = input.services.publishableKeyAuth || null;
  const resolved = await enforceRoutePolicy({
    headers: input.headers,
    logger: input.logger,
    request: { body: input.body, headers: input.headers },
    route: input.route,
    services: {
      // Key must match the route's requiredServices entry ('signedDelegateAuth');
      // enforceRoutePolicy looks up services by that exact name.
      signedDelegateAuth: input.services.signedDelegateAuth,
      ...(input.services.billing ? { billing: input.services.billing } : {}),
      ...(publishableKeyAuth
        ? { publishableKeyAuth }
        : {}),
      ...(input.services.runtimeSnapshots ? { runtimeSnapshots: input.services.runtimeSnapshots } : {}),
      ...(input.services.sponsoredCalls
        ? { sponsoredCalls: input.services.sponsoredCalls }
        : {}),
    },
    resolvers: publishableKeyAuth
        ? {
          apiCredentials: async () =>
            await resolvePublishableKeyApiCredentialAuth({
              environmentId: extractRouterApiEnvironmentId(input.headers) || undefined,
              headers: input.headers,
              missingEnvironmentMessage:
                'Environment header is required for signed delegate execution',
              missingOriginMessage:
                'Origin header is required and must be a valid exact origin',
              missingPublishableKeyMessage: 'Missing publishable key',
              origin: input.origin,
              publishableKeyAuth,
              route: input.route,
              routeAuthNotConfiguredMessage: 'Signed delegate requires API credential auth policy',
            }),
        }
      : undefined,
  });

  if (!resolved.ok) {
    return buildSponsorshipRoutePolicyFailureResponse({
      status: resolved.status,
      code: resolved.body.code,
      message: resolved.body.message,
      ok: false,
    });
  }

  try {
    const parsedBody = parseSignedDelegateBody(input.body);
    const sponsorshipRuntime = await resolveSponsorshipRuntimeForPublishableKeyRoute({
      resolved,
      runtimeSnapshots: input.services.runtimeSnapshots,
      environmentId: extractRouterApiEnvironmentId(input.headers) || '',
      actorUserId: 'signed-delegate-executor',
      runtimeSnapshotsUnavailableMessage: 'Runtime snapshots are not configured on this server',
      runtimeSnapshotNotFoundMessage: 'No runtime snapshot is available for this environment',
      unexpectedPrincipalMessage: 'Signed delegate route resolved an unexpected principal kind',
    });
    if (!sponsorshipRuntime.ok) {
      return sponsorshipRuntime.response;
    }
    const idempotencyKey = buildSignedDelegateIdempotencyKey(
      sponsorshipRuntime.principal.principal.apiKeyId,
      parsedBody.hash,
    );
    const sponsorshipDispatch = await resolveSponsorshipReplayOrMatch<
      MatchedSponsoredNearDelegate,
      Record<string, unknown>
    >({
      sponsoredCalls: input.services.sponsoredCalls,
      sponsorshipCtx: sponsorshipRuntime.sponsorshipCtx,
      idempotencyKey,
      buildReplayResponse: (existing) => buildSignedDelegateReplayResponse(existing),
      resolveMatch: () => {
        const resolvedPolicies = parseResolvedSponsoredNearDelegatePolicies(
          sponsorshipRuntime.latestSnapshot.payload,
        );
        const matched = matchResolvedSponsoredNearDelegatePolicy({
          policies: resolvedPolicies,
          signedDelegate: parsedBody.signedDelegate,
        });
        if (!matched) {
          let debugSummary: unknown = null;
          try {
            const summary = summarizeSignedDelegateForSponsorship(parsedBody.signedDelegate);
            debugSummary = {
              receiverId: summary.receiverId,
              methods: summary.methods,
              totalDepositYocto: summary.totalDepositYocto.toString(),
              hasTransfer: summary.hasTransfer,
              unsupportedActionKinds: summary.unsupportedActionKinds,
            };
          } catch (error: unknown) {
            debugSummary = { error: error instanceof Error ? error.message : String(error) };
          }
          input.logger.warn('[router-api][signed-delegate] no sponsorship policy matched', {
            environmentId: extractRouterApiEnvironmentId(input.headers) || '',
            resolvedPolicyCount: resolvedPolicies.length,
            allowedReceivers: resolvedPolicies.flatMap((policy) =>
              policy.allowedDelegateActions.map((allowed) => allowed.receiverId),
            ),
            requestSummary: debugSummary,
          });
          return {
            ok: false,
            response: routeJson(403, {
              ok: false,
              code: 'sponsorship_policy_not_matched',
              message: 'Requested delegate action is not sponsorable under the active policy',
            }),
          };
        }
        return {
          ok: true,
          matched,
        };
      },
    });
    if (sponsorshipDispatch.kind === 'response') {
      return sponsorshipDispatch.response;
    }
    const matched = sponsorshipDispatch.matched;
    const delegateSummary = matched.summary;
    const senderId = extractSignedDelegateSenderId(parsedBody.signedDelegate);
    const accountRef = normalizeNearAccountRef(senderId);
    const targetRef = normalizeNearAccountRef(delegateSummary.receiverId);
    const nearSpendCapChainId = resolveNearSpendCapChainId(matched.policy.networkClass);
    if (nearSpendCapChainId === null) {
      return routeJson(500, {
        ok: false,
        code: 'sponsorship_pricing_misconfigured',
        message:
          'NEAR sponsorship requires the matched policy to resolve to a concrete network',
      });
    }
    const spendCapSourceEventId = buildSponsoredSpendCapSourceEventId({
      chainFamily: 'near',
      intentKind: 'near_delegate',
      idempotencyKey,
    });
    const prepaidBalanceSourceEventId = buildSponsoredSpendCapSourceEventId({
      chainFamily: 'near',
      intentKind: 'near_delegate',
      idempotencyKey,
    });
    const spendCapRequestDetails = {
      hash: parsedBody.hash,
      receiverId: delegateSummary.receiverId,
      methods: [...delegateSummary.methods],
      totalDepositYocto: delegateSummary.totalDepositYocto.toString(10),
      hasTransfer: delegateSummary.hasTransfer,
    } satisfies Record<string, unknown>;
    let spendCapReservation = null;
    let prepaidReservation = null;
    const beforeBalanceState = await readSponsorshipBillingBalanceSnapshot(
      input.services.billing,
      sponsorshipRuntime.sponsorshipCtx,
    );
    try {
      spendCapReservation = await reserveSponsoredSpendCap({
        spendCap: matched.policy.spendCap,
        spendCaps: input.services.spendCaps,
        pricing: input.services.pricing,
        ctx: sponsorshipRuntime.sponsorshipCtx,
        chainFamily: 'near',
        intentKind: 'near_delegate',
        executorKind: 'near_delegate',
        environmentId: sponsorshipRuntime.principal.principal.environmentId,
        policyId: matched.policy.policyId,
        accountRef,
        targetRef,
        chainId: nearSpendCapChainId,
        sourceEventId: spendCapSourceEventId,
        requestDetails: spendCapRequestDetails,
      });
      if (spendCapReservation) {
        logSponsorshipSpendCapReserved({
          logger: input.logger,
          routeTag: 'router-api][signed-delegate',
          environmentId: sponsorshipRuntime.principal.principal.environmentId,
          policyId: matched.policy.policyId,
          idempotencyKey,
          chainFamily: 'near',
          intentKind: 'near_delegate',
          executorKind: 'near_delegate',
          chainId: nearSpendCapChainId,
          accountRef,
          targetRef,
          reservation: spendCapReservation,
        });
      }
    } catch (error: unknown) {
      if (isSponsorshipSpendCapEnforcementError(error)) {
        logSponsorshipSpendCapRejected({
          logger: input.logger,
          routeTag: 'router-api][signed-delegate',
          environmentId: sponsorshipRuntime.principal.principal.environmentId,
          policyId: matched.policy.policyId,
          idempotencyKey,
          chainFamily: 'near',
          intentKind: 'near_delegate',
          executorKind: 'near_delegate',
          chainId: nearSpendCapChainId,
          accountRef,
          targetRef,
          errorCode: error.code,
          errorMessage: error.message,
          errorDetails: error.details,
        });
        return routeJson(error.status, {
          ok: false,
          code: error.code,
          message: error.message,
          ...(error.details ? { details: error.details } : {}),
        });
      }
      return routeJson(500, {
        ok: false,
        code: 'internal',
        message:
          error instanceof Error ? error.message : 'Failed to reserve sponsored spend cap',
      });
    }
    try {
      prepaidReservation = await reserveSponsoredPrepaidBalance({
        billing: input.services.billing,
        prepaidReservations: input.services.prepaidReservations,
        pricing: input.services.pricing,
        ctx: sponsorshipRuntime.sponsorshipCtx,
        chainFamily: 'near',
        intentKind: 'near_delegate',
        executorKind: 'near_delegate',
        environmentId: sponsorshipRuntime.principal.principal.environmentId,
        policyId: matched.policy.policyId,
        accountRef,
        targetRef,
        chainId: nearSpendCapChainId,
        sourceEventId: prepaidBalanceSourceEventId,
        requestDetails: spendCapRequestDetails,
      });
    } catch (error: unknown) {
      if (spendCapReservation) {
        try {
          await releaseSponsoredSpendCap({
            reservation: spendCapReservation,
            spendCaps: input.services.spendCaps,
            ctx: sponsorshipRuntime.sponsorshipCtx,
          });
        } catch (releaseError: unknown) {
          input.logger.warn('[router-api][signed-delegate] spend-cap release after prepaid failure failed', {
            route: input.route.id,
            policyId: matched.policy.policyId,
            idempotencyKey,
            error: releaseError instanceof Error ? releaseError.message : String(releaseError),
          });
        }
      }
      if (isSponsorshipPrepaidBalanceEnforcementError(error)) {
        await emitSponsorshipBlockedObservabilityEvent({
          services: {
            logger: input.logger,
            observabilityIngestion: input.services.observabilityIngestion || null,
            webhooks: input.services.webhooks || null,
            webhookActorUserId: input.services.webhookActorUserId,
            webhookRoles: input.services.webhookRoles,
          },
          ctx: sponsorshipRuntime.sponsorshipCtx,
          balance: beforeBalanceState,
          environmentId: sponsorshipRuntime.principal.principal.environmentId,
          policyId: matched.policy.policyId,
          routeId: input.route.id,
          chainFamily: 'near',
          intentKind: 'near_delegate',
          executorKind: 'near_delegate',
          chainId: nearSpendCapChainId,
          accountRef,
          targetRef,
          idempotencyKey,
          sourceEventId: prepaidBalanceSourceEventId,
          error,
        });
      }
      const failure = buildPrepaidFailureResponse(error);
      if (failure) return failure;
      return routeJson(500, {
        ok: false,
        code: 'internal',
        message:
          error instanceof Error ? error.message : 'Failed to reserve sponsored prepaid balance',
      });
    }
    return await runSponsorshipExecution({
      execute: async () =>
        await executeSponsorshipAdapter(
          createSponsoredNearDelegateExecutionAdapter({
            authService: input.services.signedDelegateAuth,
            hash: parsedBody.hash,
            signedDelegate: parsedBody.signedDelegate,
            allowedDelegateAction: matched.allowedDelegateAction,
          }),
        ),
      assessResult: resolveSignedDelegateAssessment,
      assessThrownError: resolveThrownSignedDelegateAssessment,
      onResult: async ({
        result,
        assessment,
      }): Promise<RouteResponse<Record<string, unknown>>> => {
        let spendCapSettlement: (SponsorshipSpendCapSettlement & {
          sourceEventId: string;
          estimatedSpendMinor: number;
        }) | null = null;
        let prepaidSettlement:
          | {
              reservationId: string | null;
              settledAt: string;
              sourceEventId: string;
              estimatedSpendMinor: number;
              settledSpendMinor: number;
              pricingVersion: string;
              usedEstimatedFallback: boolean;
              released: boolean;
            }
          | null = null;
        try {
          const settled = await settleSponsoredSpendCap({
            reservation: spendCapReservation,
            spendCaps: input.services.spendCaps,
            pricing: input.services.pricing,
            ctx: sponsorshipRuntime.sponsorshipCtx,
            chainFamily: 'near',
            intentKind: 'near_delegate',
            executorKind: 'near_delegate',
            environmentId: sponsorshipRuntime.principal.principal.environmentId,
            policyId: matched.policy.policyId,
            accountRef,
            targetRef,
            chainId: nearSpendCapChainId,
            txOrExecutionRef: assessment.txOrExecutionRef,
            receiptStatus: assessment.receiptStatus,
            feeUnit: assessment.feeUnit,
            feeAmount: assessment.feeAmount,
            requestDetails: spendCapRequestDetails,
          });
          if (settled && spendCapReservation) {
            spendCapSettlement = {
              ...settled,
              sourceEventId: spendCapReservation.sourceEventId,
              estimatedSpendMinor: spendCapReservation.estimatedSpendMinor,
            };
            logSponsorshipSpendCapSettled({
              logger: input.logger,
              routeTag: 'router-api][signed-delegate',
              environmentId: sponsorshipRuntime.principal.principal.environmentId,
              policyId: matched.policy.policyId,
              idempotencyKey,
              chainFamily: 'near',
              intentKind: 'near_delegate',
              executorKind: 'near_delegate',
              chainId: nearSpendCapChainId,
              accountRef,
              targetRef,
              reservation: spendCapReservation,
              settlement: settled,
              txOrExecutionRef: assessment.txOrExecutionRef,
              receiptStatus: assessment.receiptStatus,
            });
          }
        } catch (error: unknown) {
          input.logger.warn('[router-api][signed-delegate] spend-cap settlement failed', {
            route: input.route.id,
            policyId: matched.policy.policyId,
            txHash: assessment.txOrExecutionRef,
            error: error instanceof Error ? error.message : String(error),
          });
        }
        try {
          const settled = await settleSponsoredPrepaidBalance({
            reservation: prepaidReservation,
            prepaidReservations: input.services.prepaidReservations,
            pricing: input.services.pricing,
            ctx: sponsorshipRuntime.sponsorshipCtx,
            chainFamily: 'near',
            intentKind: 'near_delegate',
            executorKind: 'near_delegate',
            environmentId: sponsorshipRuntime.principal.principal.environmentId,
            policyId: matched.policy.policyId,
            accountRef,
            targetRef,
            chainId: nearSpendCapChainId,
            txOrExecutionRef: assessment.txOrExecutionRef,
            receiptStatus: assessment.receiptStatus,
            feeUnit: assessment.feeUnit,
            feeAmount: assessment.feeAmount,
            requestDetails: spendCapRequestDetails,
          });
          if (settled && prepaidReservation) {
            prepaidSettlement = {
              ...settled,
              sourceEventId: prepaidReservation.sourceEventId,
              estimatedSpendMinor: prepaidReservation.estimatedSpendMinor,
            };
          }
        } catch (error: unknown) {
          input.logger.warn('[router-api][signed-delegate] prepaid settlement failed', {
            route: input.route.id,
            policyId: matched.policy.policyId,
            txHash: assessment.txOrExecutionRef,
            error: error instanceof Error ? error.message : String(error),
          });
        }
        try {
          await meterSignedDelegate({
            assessment,
            hash: parsedBody.hash,
            idempotencyKey,
            policyRef: {
              policyId: matched.policy.policyId,
              policyName: matched.policy.policyName,
              templateId: matched.policy.templateId,
            },
            result,
            route: input.route,
            routeContext: sponsorshipRuntime.context,
            services: input.services,
            signedDelegate: parsedBody.signedDelegate,
            ...(prepaidSettlement ? { prepaidSettlement } : {}),
            ...(spendCapSettlement ? { spendCapSettlement } : {}),
          });
        } catch (error: unknown) {
          input.logger.warn('[router-api][signed-delegate] metering failed', {
            route: input.route.id,
            txHash: assessment.txOrExecutionRef,
            error: error instanceof Error ? error.message : String(error),
          });
        }

        if (!assessment.succeeded) {
          return routeJson(
            assessment.receiptStatus === 'rpc_rejected' ? 400 : 502,
            {
              ok: false,
              code: assessment.responseCode,
              message: assessment.responseMessage,
              relayerTxHash: assessment.txOrExecutionRef,
              outcome: result.outcome ?? null,
            },
          );
        }

        return routeJson(200, {
          ok: true,
          relayerTxHash: assessment.txOrExecutionRef,
          status: 'submitted',
          outcome: result.outcome ?? null,
        });
      },
      onThrownError: async ({
        error,
        assessment,
      }): Promise<RouteResponse<Record<string, unknown>>> => {
        let prepaidSettlement:
          | {
              reservationId: string | null;
              settledAt: string;
              sourceEventId: string;
              estimatedSpendMinor: number;
              settledSpendMinor: number;
              pricingVersion: string;
              usedEstimatedFallback: boolean;
              released: boolean;
            }
          | null = null;
        try {
          const settled = await settleSponsoredSpendCap({
            reservation: spendCapReservation,
            spendCaps: input.services.spendCaps,
            pricing: input.services.pricing,
            ctx: sponsorshipRuntime.sponsorshipCtx,
            chainFamily: 'near',
            intentKind: 'near_delegate',
            executorKind: 'near_delegate',
            environmentId: sponsorshipRuntime.principal.principal.environmentId,
            policyId: matched.policy.policyId,
            accountRef,
            targetRef,
            chainId: nearSpendCapChainId,
            txOrExecutionRef: assessment.txOrExecutionRef,
            receiptStatus: assessment.receiptStatus,
            feeUnit: assessment.feeUnit,
            feeAmount: assessment.feeAmount,
            requestDetails: spendCapRequestDetails,
          });
          if (settled && spendCapReservation) {
            logSponsorshipSpendCapSettled({
              logger: input.logger,
              routeTag: 'router-api][signed-delegate',
              environmentId: sponsorshipRuntime.principal.principal.environmentId,
              policyId: matched.policy.policyId,
              idempotencyKey,
              chainFamily: 'near',
              intentKind: 'near_delegate',
              executorKind: 'near_delegate',
              chainId: nearSpendCapChainId,
              accountRef,
              targetRef,
              reservation: spendCapReservation,
              settlement: settled,
              txOrExecutionRef: assessment.txOrExecutionRef,
              receiptStatus: assessment.receiptStatus,
            });
          }
        } catch (settleError: unknown) {
          input.logger.warn('[router-api][signed-delegate] spend-cap settlement failed', {
            route: input.route.id,
            policyId: matched.policy.policyId,
            txHash: assessment.txOrExecutionRef,
            error: settleError instanceof Error ? settleError.message : String(settleError),
          });
        }
        try {
          const settled = await settleSponsoredPrepaidBalance({
            reservation: prepaidReservation,
            prepaidReservations: input.services.prepaidReservations,
            pricing: input.services.pricing,
            ctx: sponsorshipRuntime.sponsorshipCtx,
            chainFamily: 'near',
            intentKind: 'near_delegate',
            executorKind: 'near_delegate',
            environmentId: sponsorshipRuntime.principal.principal.environmentId,
            policyId: matched.policy.policyId,
            accountRef,
            targetRef,
            chainId: nearSpendCapChainId,
            txOrExecutionRef: assessment.txOrExecutionRef,
            receiptStatus: assessment.receiptStatus,
            feeUnit: assessment.feeUnit,
            feeAmount: assessment.feeAmount,
            requestDetails: spendCapRequestDetails,
          });
          if (settled && prepaidReservation) {
            prepaidSettlement = {
              ...settled,
              sourceEventId: prepaidReservation.sourceEventId,
              estimatedSpendMinor: prepaidReservation.estimatedSpendMinor,
            };
          }
        } catch (settleError: unknown) {
          input.logger.warn('[router-api][signed-delegate] prepaid settlement failed', {
            route: input.route.id,
            policyId: matched.policy.policyId,
            txHash: assessment.txOrExecutionRef,
            error: settleError instanceof Error ? settleError.message : String(settleError),
          });
        }
        try {
          await meterSignedDelegate({
            assessment,
            hash: parsedBody.hash,
            idempotencyKey,
            policyRef: {
              policyId: matched.policy.policyId,
              policyName: matched.policy.policyName,
              templateId: matched.policy.templateId,
            },
            result: {
              outcome:
                error && typeof error === 'object' && 'outcome' in error
                  ? (error as { outcome?: unknown }).outcome
                  : undefined,
              transactionHash:
                typeof assessment.txOrExecutionRef === 'string' ? assessment.txOrExecutionRef : undefined,
            },
            route: input.route,
            routeContext: sponsorshipRuntime.context,
            services: input.services,
            signedDelegate: parsedBody.signedDelegate,
            ...(prepaidSettlement ? { prepaidSettlement } : {}),
          });
        } catch (meterError: unknown) {
          input.logger.warn('[router-api][signed-delegate] metering failed', {
            route: input.route.id,
            txHash: assessment.txOrExecutionRef,
            error: meterError instanceof Error ? meterError.message : String(meterError),
          });
        }
        return routeJson(500, {
          ok: false,
          code: assessment.responseCode,
          message: assessment.responseMessage,
          relayerTxHash: assessment.txOrExecutionRef,
          outcome:
            error && typeof error === 'object' && 'outcome' in error
              ? (error as { outcome?: unknown }).outcome ?? null
              : null,
        });
      },
    });
  } catch (error: unknown) {
    const message = error instanceof Error ? error.message : String(error);
    if (message.startsWith('invalid_body:')) {
      return routeJson(400, {
        ok: false,
        code: 'invalid_body',
        message: message.slice('invalid_body:'.length).trim() || 'Expected { hash, signedDelegate }',
      });
    }
    return routeJson(500, {
      ok: false,
      code: 'internal',
      message: error instanceof Error ? error.message : 'Internal error while executing delegate action',
    });
  }
}
