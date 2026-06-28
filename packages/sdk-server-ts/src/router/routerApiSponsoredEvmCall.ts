import { buildCorsOrigins, normalizeCorsOrigin } from '../core/SessionService';
import type { ConsoleBillingService } from '../console/billing';
import type { ConsoleBillingPrepaidReservationService } from '../console/billingPrepaidReservations';
import type { ConsoleObservabilityIngestionService } from '../console/observability';
import type { ConsoleRuntimeSnapshotService } from '../console/runtimeSnapshots';
import type {
  ConsoleSponsoredCallReceiptStatus,
  ConsoleSponsoredCallRecord,
  ConsoleSponsoredCallService,
} from '../console/sponsoredCalls';
import type { ConsoleSponsorshipSpendCapService } from '../console/sponsorshipSpendCaps';
import {
  matchResolvedSponsoredEvmCallPolicy,
  normalizeEvmAddress,
  parseOptionalPositiveInteger,
  parseResolvedSponsoredEvmCallPolicies,
  parseSponsoredEvmCallRequest,
  type SponsoredEvmCallRequest,
  type SponsoredEvmPolicyMatch,
  type SponsoredEvmPolicyMismatch,
} from '../sponsorship/evm';
import { DEFAULT_SPONSORED_EVM_CALL_ROUTE_ID } from '../sponsorship/evmRoutes';
import type {
  SponsoredEvmCallExecutorConfig,
  SponsoredEvmExecutionAdapterResolver,
} from '../sponsorship/evmExecutorTypes';
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
  isSponsorshipPrepaidBalanceEnforcementError,
  reserveSponsoredPrepaidBalance,
} from '../sponsorship/prepaidBalance';
import { executeSponsorshipAdapter } from '../sponsorship/executionAdapter';
import { enforceRoutePolicy } from './enforceRoutePolicy';
import type { NormalizedRouterLogger } from './logger';
import { resolvePublishableKeyApiCredentialAuth } from './routerApiCredentialAuth';
import { extractRouterApiEnvironmentId } from './routerApiKeyAuth';
import {
  recordSponsoredExecution,
  runSponsorshipExecution,
  type SponsorshipExecutionAssessment,
} from './sponsorshipExecution';
import {
  emitSponsorshipBlockedObservabilityEvent,
  readSponsorshipBillingBalanceSnapshot,
} from './sponsorshipBillingEvents';
import type { RouterApiPublishableKeyAuthAdapter } from './routerApi';
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
import type { HeaderRecord, RouteResponse } from './routeExecutionContext';
import type { RouteDefinition } from './routeDefinitions';
import type { RouteErrorBody } from './routeResponses';
import { routeJson } from './routeResponses';
import type { ConsoleWebhookService } from '../console/webhooks';
import { isPlainObject } from '@shared/utils/validation';

type SponsoredEvmExecution = {
  txHash: `0x${string}`;
  gasUsed: string;
  effectiveGasPrice: string;
  feeAmount: string;
};

type SponsoredEvmExecutionAssessment = SponsorshipExecutionAssessment & {
  txHash: `0x${string}` | null;
  gasUsed: string | null;
  effectiveGasPrice: string | null;
};

type SponsoredEvmCallDetails = {
  walletId: string;
  walletAddress: `0x${string}`;
  chainId: number;
  call: {
    to: `0x${string}`;
    data: `0x${string}`;
    gasLimit: string;
    valueWei: string;
    selector: `0x${string}`;
  };
  execution: {
    txHash: string | null;
    gasUsed: string | null;
    effectiveGasPrice: string | null;
    feeAmount: string;
  };
  billing?: {
    sourceEventId: string | null;
    estimatedSpendMinor: string | null;
    settledSpendMinor: string | null;
    pricingVersion: string | null;
    usedEstimatedFallback: boolean | null;
    released: boolean | null;
  };
  policySpendCap?: {
    sourceEventId: string | null;
    estimatedSpendMinor: string | null;
    settledSpendMinor: string | null;
    pricingVersion: string | null;
    usedEstimatedFallback: boolean | null;
  };
};

type MatchedSponsoredEvmExecution = {
  matchedPolicy: SponsoredEvmPolicyMatch;
  adapter: NonNullable<ReturnType<SponsoredEvmExecutionAdapterResolver>>;
};

export interface RouterApiSponsoredEvmCallService {
  billing: ConsoleBillingService;
  config: SponsoredEvmCallExecutorConfig;
  corsOrigins: readonly string[];
  resolveExecutionAdapter?: SponsoredEvmExecutionAdapterResolver | null;
  observabilityIngestion?: ConsoleObservabilityIngestionService | null;
  prepaidReservations: ConsoleBillingPrepaidReservationService | null;
  pricing: SponsorshipSpendPricingService | null;
  publishableKeyAuth: RouterApiPublishableKeyAuthAdapter;
  runtimeSnapshots: ConsoleRuntimeSnapshotService | null;
  spendCaps: ConsoleSponsorshipSpendCapService | null;
  sponsoredCalls: ConsoleSponsoredCallService;
  webhooks?: ConsoleWebhookService | null;
  webhookActorUserId?: string;
  webhookRoles?: string[];
}

export interface RouterApiSponsoredEvmCallInput {
  body: unknown;
  headers: HeaderRecord;
  logger: NormalizedRouterLogger;
  origin?: string;
  route: RouteDefinition;
  services: {
    routerApiSponsoredEvmCall?: RouterApiSponsoredEvmCallService | null;
  };
}

function normalizeOrigin(value: unknown): string {
  try {
    const parsed = new URL(String(value || '').trim());
    parsed.hash = '';
    parsed.search = '';
    parsed.pathname = '/';
    return parsed.toString().replace(/\/$/, '');
  } catch {
    return '';
  }
}

function isAllowedOrigin(origin: string, allowedOrigins: readonly string[]): boolean {
  const normalizedOrigin = normalizeCorsOrigin(origin);
  if (!normalizedOrigin) return false;
  const normalizedAllowedOrigins = buildCorsOrigins(...allowedOrigins);
  if (normalizedAllowedOrigins === '*') return true;
  if (!Array.isArray(normalizedAllowedOrigins)) return false;
  return normalizedAllowedOrigins.includes(normalizedOrigin);
}

function normalizeTxHashOrNull(value: unknown): `0x${string}` | null {
  const normalized = String(value || '').trim();
  if (!/^0x[0-9a-fA-F]{64}$/.test(normalized)) return null;
  return normalized as `0x${string}`;
}

// Sponsored spend-cap accounting still binds to the hosted-NEAR account ref.
function buildHostedNearAccountRef(walletId: string): string {
  return `near:${walletId}`;
}

function buildTargetRef(chainId: number, to: `0x${string}`): string {
  return `evm:${chainId}:${to.toLowerCase()}`;
}

function buildSponsorRef(chainId: number, sponsorAddress: `0x${string}`): string {
  return `evm:${chainId}:${sponsorAddress.toLowerCase()}`;
}

function buildDetailsJson(input: {
  request: SponsoredEvmCallRequest;
  selector: `0x${string}`;
  execution: {
    txHash: string | null;
    gasUsed: string | null;
    effectiveGasPrice: string | null;
    feeAmount: string;
  };
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
  const details: SponsoredEvmCallDetails = {
    walletId: input.request.walletId,
    walletAddress: input.request.walletAddress,
    chainId: input.request.chainId,
    call: {
      to: input.request.call.to,
      data: input.request.call.data,
      gasLimit: input.request.call.gasLimit.toString(10),
      valueWei: input.request.call.value.toString(10),
      selector: input.selector,
    },
    execution: {
      txHash: input.execution.txHash,
      gasUsed: input.execution.gasUsed,
      effectiveGasPrice: input.execution.effectiveGasPrice,
      feeAmount: input.execution.feeAmount,
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
  };
  return JSON.stringify(details);
}

function parseDetailsJson(value: string): SponsoredEvmCallDetails | null {
  try {
    const parsed = JSON.parse(value) as Record<string, unknown>;
    const walletId = String(parsed.walletId || '').trim();
    const walletAddress = normalizeEvmAddress(parsed.walletAddress);
    const chainId = parseOptionalPositiveInteger(parsed.chainId);
    const call =
      parsed.call && typeof parsed.call === 'object' && !Array.isArray(parsed.call)
        ? (parsed.call as Record<string, unknown>)
        : null;
    const execution =
      parsed.execution && typeof parsed.execution === 'object' && !Array.isArray(parsed.execution)
        ? (parsed.execution as Record<string, unknown>)
        : null;
    const to = normalizeEvmAddress(call?.to);
    const data = /^0x(?:[0-9a-fA-F]{2})*$/.test(String(call?.data || '').trim())
      ? (String(call?.data || '').trim() as `0x${string}`)
      : null;
    const selector = /^0x[0-9a-fA-F]{8}$/.test(String(call?.selector || '').trim())
      ? (String(call?.selector || '').trim().toLowerCase() as `0x${string}`)
      : null;
    if (!walletId || !walletAddress || !chainId || !to || !data || !selector) return null;
    return {
      walletId,
      walletAddress,
      chainId,
      call: {
        to,
        data,
        gasLimit: String(call?.gasLimit || '').trim() || '0',
        valueWei: String(call?.valueWei || '').trim() || '0',
        selector,
      },
      execution: {
        txHash: String(execution?.txHash || '').trim() || null,
        gasUsed: String(execution?.gasUsed || '').trim() || null,
        effectiveGasPrice: String(execution?.effectiveGasPrice || '').trim() || null,
        feeAmount: String(execution?.feeAmount || '').trim() || '0',
      },
    };
  } catch {
    return null;
  }
}

function parseSponsoredEvmRequestBody(
  body: unknown,
  headers: HeaderRecord,
): SponsoredEvmCallRequest {
  const environmentId = extractRouterApiEnvironmentId(headers);
  const normalizedBody =
    isPlainObject(body)
      ? ({
          ...body,
          environmentId: environmentId || body.environmentId,
        } as Record<string, unknown>)
      : body;
  return parseSponsoredEvmCallRequest(normalizedBody);
}

function buildSuccessfulSponsoredEvmAssessment(
  execution: SponsoredEvmExecution,
): SponsoredEvmExecutionAssessment {
  return {
    succeeded: true,
    txOrExecutionRef: execution.txHash,
    txHash: execution.txHash,
    receiptStatus: 'success',
    feeUnit: 'wei',
    feeAmount: execution.feeAmount,
    executorKind: 'evm_eoa',
    responseCode: 'ok',
    responseMessage: 'Sponsored EVM call submitted',
    recordErrorCode: null,
    recordErrorMessage: null,
    gasUsed: execution.gasUsed,
    effectiveGasPrice: execution.effectiveGasPrice,
  };
}

function buildFailedSponsoredEvmAssessment(error: unknown): SponsoredEvmExecutionAssessment {
  const responseMessage =
    error instanceof Error ? error.message : String(error || 'Sponsored EVM call failed');
  const responseCode =
    error && typeof error === 'object' && 'code' in error
      ? String((error as { code?: unknown }).code || '').trim() || 'sponsored_evm_call_failed'
      : 'sponsored_evm_call_failed';
  const txHash =
    error && typeof error === 'object' && 'txHash' in error
      ? normalizeTxHashOrNull((error as { txHash?: unknown }).txHash)
      : null;
  const gasUsed =
    error && typeof error === 'object' && 'gasUsed' in error
      ? String((error as { gasUsed?: unknown }).gasUsed || '').trim() || null
      : null;
  const effectiveGasPrice =
    error && typeof error === 'object' && 'effectiveGasPrice' in error
      ? String((error as { effectiveGasPrice?: unknown }).effectiveGasPrice || '').trim() || null
      : null;
  const feeAmount =
    error && typeof error === 'object' && 'feeAmount' in error
      ? String((error as { feeAmount?: unknown }).feeAmount || '').trim() || '0'
      : '0';
  const receiptStatus: ConsoleSponsoredCallReceiptStatus =
    responseCode === 'tx_reverted' ? 'reverted' : txHash ? 'broadcast_failed' : 'rpc_rejected';
  return {
    succeeded: false,
    txOrExecutionRef: txHash,
    txHash,
    receiptStatus,
    feeUnit: 'wei',
    feeAmount,
    executorKind: 'evm_eoa',
    responseCode,
    responseMessage,
    recordErrorCode: responseCode,
    recordErrorMessage: responseMessage,
    gasUsed,
    effectiveGasPrice,
  };
}

function buildReplayResponse(existing: ConsoleSponsoredCallRecord): RouteResponse<Record<string, unknown>> {
  const details = parseDetailsJson(existing.detailsJson);
  const feeAmount = String(existing.feeAmount || '').trim() || '0';
  const policyId = String(existing.policyId || '').trim() || null;
  if (existing.receiptStatus === 'success') {
    return routeJson(200, {
      ok: true,
      replayed: true,
      recordId: existing.id,
      policyId,
      txHash: existing.txOrExecutionRef,
      spendWei: feeAmount,
      gasUsed: details?.execution.gasUsed || null,
      effectiveGasPrice: details?.execution.effectiveGasPrice || null,
    });
  }
  return routeJson(502, {
    ok: false,
    replayed: true,
    code: String(existing.errorCode || '').trim() || 'sponsored_evm_call_failed',
    message: String(existing.errorMessage || '').trim() || 'Sponsored EVM call failed',
    txHash: existing.txOrExecutionRef,
    recordId: existing.id,
    policyId,
    spendWei: feeAmount,
    gasUsed: details?.execution.gasUsed || null,
    effectiveGasPrice: details?.execution.effectiveGasPrice || null,
    receiptStatus: existing.receiptStatus,
  });
}

function buildSpendCapFailureResponse(error: unknown): RouteResponse<Record<string, unknown>> | null {
  if (!isSponsorshipSpendCapEnforcementError(error)) return null;
  return routeJson(error.status, {
    ok: false,
    code: error.code,
    message: error.message,
    ...(error.details ? { details: error.details } : {}),
  });
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

function buildSponsorshipPolicyMismatchResponse(
  mismatch: SponsoredEvmPolicyMismatch,
): RouteResponse<Record<string, unknown>> {
  if (mismatch.code === 'selector_mismatch') {
    return routeJson(403, {
      ok: false,
      code: 'sponsorship_policy_selector_mismatch',
      message: 'Requested call selector is not sponsorable under the active policy',
      ...(mismatch.details ? { details: mismatch.details } : {}),
    });
  }
  if (mismatch.code === 'gas_limit_exceeded') {
    return routeJson(403, {
      ok: false,
      code: 'sponsorship_policy_gas_limit_exceeded',
      message: 'Requested call gas limit exceeds the active sponsorship policy',
      ...(mismatch.details ? { details: mismatch.details } : {}),
    });
  }
  if (mismatch.code === 'value_exceeded') {
    return routeJson(403, {
      ok: false,
      code: 'sponsorship_policy_value_exceeded',
      message: 'Requested call value exceeds the active sponsorship policy',
      ...(mismatch.details ? { details: mismatch.details } : {}),
    });
  }
  return routeJson(403, {
    ok: false,
    code: 'sponsorship_policy_not_matched',
    message: 'Requested call is not sponsorable under the active policy',
  });
}

export async function handleRouterApiSponsoredEvmCall(
  input: RouterApiSponsoredEvmCallInput,
): Promise<RouteResponse<Record<string, unknown> | RouteErrorBody>> {
  const routerApiSponsoredEvmCall = input.services.routerApiSponsoredEvmCall || null;

  if (!routerApiSponsoredEvmCall) {
    const resolved = await enforceRoutePolicy({
      headers: input.headers,
      logger: input.logger,
      request: { body: input.body, headers: input.headers },
      route: input.route,
      services: {},
    });
    if (!resolved.ok) return routeJson(resolved.status, resolved.body);
    return routeJson(500, {
      ok: false,
      code: 'internal',
      message: 'Sponsored EVM route unexpectedly resolved without required services',
    });
  }

  const origin = normalizeOrigin(input.origin);
  if (!origin || !isAllowedOrigin(origin, routerApiSponsoredEvmCall.corsOrigins)) {
    return routeJson(403, {
      ok: false,
      code: 'origin_not_allowed',
      message: 'Origin is not allowed',
    });
  }
  const sponsoredEvmConfig = routerApiSponsoredEvmCall.config;
  const publishableKeyAuth = routerApiSponsoredEvmCall.publishableKeyAuth;

  let parsedBody: SponsoredEvmCallRequest;
  try {
    parsedBody = parseSponsoredEvmRequestBody(input.body, input.headers);
  } catch (error: unknown) {
    return routeJson(400, {
      ok: false,
      code: 'invalid_body',
      message: error instanceof Error ? error.message : 'Invalid request body',
    });
  }

  const resolved = await enforceRoutePolicy({
    headers: input.headers,
    logger: input.logger,
    request: { body: parsedBody, headers: input.headers },
    route: input.route,
    services: {
      routerApiSponsoredEvmCall,
    },
    resolvers: {
      apiCredentials: async () =>
        await resolvePublishableKeyApiCredentialAuth({
          environmentId: parsedBody.environmentId,
          headers: input.headers,
          missingEnvironmentMessage:
            'Environment header or body field is required for sponsored EVM execution',
          missingOriginMessage: 'Origin header is required and must be a valid exact origin',
          missingPublishableKeyMessage: 'Missing publishable key',
          origin,
          publishableKeyAuth,
          route: input.route,
          routeAuthNotConfiguredMessage: 'Sponsored EVM call requires API credential auth policy',
        }),
    },
  });

  if (!resolved.ok) {
    return buildSponsorshipRoutePolicyFailureResponse({
      status: resolved.status,
      code: resolved.body.code,
      message: resolved.body.message,
      ok: false,
    });
  }

  const sponsorshipRuntime = await resolveSponsorshipRuntimeForPublishableKeyRoute({
    resolved,
    runtimeSnapshots: routerApiSponsoredEvmCall.runtimeSnapshots,
    environmentId: parsedBody.environmentId,
    actorUserId: 'sponsored-call-executor',
    runtimeSnapshotsUnavailableMessage: 'Runtime snapshots are not configured on this server',
    runtimeSnapshotNotFoundMessage: 'No runtime snapshot is available for this environment',
    unexpectedPrincipalMessage: 'Sponsored EVM execution requires an API credential principal',
  });
  if (!sponsorshipRuntime.ok) {
    return sponsorshipRuntime.response;
  }

  const idempotencyKey = parsedBody.idempotencyKey;
  const sponsorshipDispatch = await resolveSponsorshipReplayOrMatch<
    MatchedSponsoredEvmExecution,
    Record<string, unknown>
  >({
    sponsoredCalls: routerApiSponsoredEvmCall.sponsoredCalls,
    sponsorshipCtx: sponsorshipRuntime.sponsorshipCtx,
    idempotencyKey,
    buildReplayResponse: (existing) => buildReplayResponse(existing),
    resolveMatch: () => {
      const policies = parseResolvedSponsoredEvmCallPolicies(
        sponsorshipRuntime.latestSnapshot.payload,
      );
      const matchedPolicy = matchResolvedSponsoredEvmCallPolicy({
        policies,
        chainId: parsedBody.chainId,
        call: parsedBody.call,
      });
      if (!matchedPolicy.ok) {
        return {
          ok: false,
          response: buildSponsorshipPolicyMismatchResponse(matchedPolicy),
        };
      }
      const resolveExecutionAdapter = routerApiSponsoredEvmCall.resolveExecutionAdapter || null;
      if (!resolveExecutionAdapter) {
        return {
          ok: false,
          response: routeJson(503, {
            ok: false,
            code: 'sponsored_evm_executor_not_wired',
            message: 'Sponsored EVM execution is not wired on this route',
          }),
        };
      }
      const adapter = resolveExecutionAdapter({
        config: sponsoredEvmConfig,
        chainId: parsedBody.chainId,
        call: parsedBody.call,
      });
      if (!adapter) {
        return {
          ok: false,
          response: routeJson(503, {
            ok: false,
            code: 'sponsor_chain_misconfigured',
            message: `Sponsor executor is not configured for chain ${parsedBody.chainId}`,
          }),
        };
      }
      return {
        ok: true,
        matched: {
          matchedPolicy,
          adapter,
        },
      };
    },
  });
  if (sponsorshipDispatch.kind === 'response') {
    return sponsorshipDispatch.response;
  }
  const { matchedPolicy: matched, adapter } = sponsorshipDispatch.matched;
  const accountRef = buildHostedNearAccountRef(parsedBody.walletId);
  const targetRef = buildTargetRef(parsedBody.chainId, parsedBody.call.to);
  const sponsorRef = buildSponsorRef(parsedBody.chainId, adapter.meta.sponsorAddress);
  const spendCapSourceEventId = buildSponsoredSpendCapSourceEventId({
    chainFamily: 'evm',
    intentKind: 'evm_call',
    idempotencyKey,
  });
  const prepaidBalanceSourceEventId = buildSponsoredSpendCapSourceEventId({
    chainFamily: 'evm',
    intentKind: 'evm_call',
    idempotencyKey,
  });
  const spendCapRequestDetails = {
    walletId: parsedBody.walletId,
    walletAddress: parsedBody.walletAddress,
    call: {
      to: parsedBody.call.to,
      data: parsedBody.call.data,
      gasLimit: parsedBody.call.gasLimit.toString(10),
      valueWei: parsedBody.call.value.toString(10),
      selector: matched.selector,
    },
  } satisfies Record<string, unknown>;
  let spendCapReservation = null;
  let prepaidReservation = null;
  const beforeBalanceState = await readSponsorshipBillingBalanceSnapshot(
    routerApiSponsoredEvmCall.billing,
    sponsorshipRuntime.sponsorshipCtx,
  );
  try {
    spendCapReservation = await reserveSponsoredSpendCap({
      spendCap: matched.policy.spendCap,
      spendCaps: routerApiSponsoredEvmCall.spendCaps,
      pricing: routerApiSponsoredEvmCall.pricing,
      ctx: sponsorshipRuntime.sponsorshipCtx,
      chainFamily: 'evm',
      intentKind: 'evm_call',
      executorKind: adapter.executorKind,
      environmentId: parsedBody.environmentId,
      policyId: matched.policy.policyId,
      accountRef,
      targetRef,
      chainId: parsedBody.chainId,
      sourceEventId: spendCapSourceEventId,
      requestDetails: spendCapRequestDetails,
    });
    if (spendCapReservation) {
      logSponsorshipSpendCapReserved({
        logger: input.logger,
        routeTag: 'sponsored-evm-call',
        environmentId: parsedBody.environmentId,
        policyId: matched.policy.policyId,
        idempotencyKey,
        chainFamily: 'evm',
        intentKind: 'evm_call',
        executorKind: adapter.executorKind,
        chainId: parsedBody.chainId,
        accountRef,
        targetRef,
        reservation: spendCapReservation,
      });
    }
  } catch (error: unknown) {
    if (isSponsorshipSpendCapEnforcementError(error)) {
      logSponsorshipSpendCapRejected({
        logger: input.logger,
        routeTag: 'sponsored-evm-call',
        environmentId: parsedBody.environmentId,
        policyId: matched.policy.policyId,
        idempotencyKey,
        chainFamily: 'evm',
        intentKind: 'evm_call',
        executorKind: adapter.executorKind,
        chainId: parsedBody.chainId,
        accountRef,
        targetRef,
        errorCode: error.code,
        errorMessage: error.message,
        errorDetails: error.details,
      });
    }
    const failure = buildSpendCapFailureResponse(error);
    if (failure) return failure;
    return routeJson(500, {
      ok: false,
      code: 'internal',
      message: error instanceof Error ? error.message : 'Failed to reserve sponsored spend cap',
    });
  }

  try {
    prepaidReservation = await reserveSponsoredPrepaidBalance({
      billing: routerApiSponsoredEvmCall.billing,
      prepaidReservations: routerApiSponsoredEvmCall.prepaidReservations,
      pricing: routerApiSponsoredEvmCall.pricing,
      ctx: sponsorshipRuntime.sponsorshipCtx,
      chainFamily: 'evm',
      intentKind: 'evm_call',
      executorKind: adapter.executorKind,
      environmentId: parsedBody.environmentId,
      policyId: matched.policy.policyId,
      accountRef,
      targetRef,
      chainId: parsedBody.chainId,
      sourceEventId: prepaidBalanceSourceEventId,
      requestDetails: spendCapRequestDetails,
    });
  } catch (error: unknown) {
    if (spendCapReservation) {
      try {
        await releaseSponsoredSpendCap({
          reservation: spendCapReservation,
          spendCaps: routerApiSponsoredEvmCall.spendCaps,
          ctx: sponsorshipRuntime.sponsorshipCtx,
        });
      } catch (releaseError: unknown) {
        input.logger.warn('[sponsored-evm-call] spend-cap release after prepaid failure failed', {
          environmentId: parsedBody.environmentId,
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
          observabilityIngestion: routerApiSponsoredEvmCall.observabilityIngestion || null,
          webhooks: routerApiSponsoredEvmCall.webhooks || null,
          webhookActorUserId: routerApiSponsoredEvmCall.webhookActorUserId,
          webhookRoles: routerApiSponsoredEvmCall.webhookRoles,
        },
        ctx: sponsorshipRuntime.sponsorshipCtx,
        balance: beforeBalanceState,
        environmentId: parsedBody.environmentId,
        policyId: matched.policy.policyId,
        routeId: input.route.id,
        chainFamily: 'evm',
        intentKind: 'evm_call',
        executorKind: adapter.executorKind,
        chainId: parsedBody.chainId,
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
      await executeSponsorshipAdapter(adapter),
    assessResult: buildSuccessfulSponsoredEvmAssessment,
    onResult: async ({ assessment }): Promise<RouteResponse<Record<string, unknown>>> => {
      let spendCapSettlement: (SponsorshipSpendCapSettlement & {
        sourceEventId: string;
        estimatedSpendMinor: number;
      }) | null = null;
      try {
        const settled = await settleSponsoredSpendCap({
          reservation: spendCapReservation,
          spendCaps: routerApiSponsoredEvmCall.spendCaps,
          pricing: routerApiSponsoredEvmCall.pricing,
          ctx: sponsorshipRuntime.sponsorshipCtx,
          chainFamily: 'evm',
          intentKind: 'evm_call',
          executorKind: adapter.executorKind,
          environmentId: parsedBody.environmentId,
          policyId: matched.policy.policyId,
          accountRef,
          targetRef,
          chainId: parsedBody.chainId,
          txOrExecutionRef: assessment.txHash,
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
            routeTag: 'sponsored-evm-call',
            environmentId: parsedBody.environmentId,
            policyId: matched.policy.policyId,
            idempotencyKey,
            chainFamily: 'evm',
            intentKind: 'evm_call',
            executorKind: adapter.executorKind,
            chainId: parsedBody.chainId,
            accountRef,
            targetRef,
            reservation: spendCapReservation,
            settlement: settled,
            txOrExecutionRef: assessment.txHash,
            receiptStatus: assessment.receiptStatus,
          });
        }
      } catch (error: unknown) {
        input.logger.warn('[sponsored-evm-call] spend-cap settlement failed', {
          environmentId: parsedBody.environmentId,
          policyId: matched.policy.policyId,
          idempotencyKey,
          txHash: assessment.txHash,
          error: error instanceof Error ? error.message : String(error),
        });
      }
      const record = await recordSponsoredExecution({
        billing: routerApiSponsoredEvmCall.billing,
        billingSourceEventIdPrefix: 'sponsored_evm_call_debit',
        context: sponsorshipRuntime.sponsorshipCtx,
        ledger: routerApiSponsoredEvmCall.sponsoredCalls,
        buildRecord: ({ prepaidSettlement, billingLedgerEntryId }) => ({
          environmentId: parsedBody.environmentId,
          apiKeyId: sponsorshipRuntime.principal.principal.apiKeyId,
          apiKeyKind: 'publishable_key',
          route: DEFAULT_SPONSORED_EVM_CALL_ROUTE_ID,
          policyId: matched.policy.policyId,
          policyNameAtEvent: matched.policy.policyName,
          templateId: matched.policy.templateId,
          chainFamily: 'evm',
          intentKind: 'evm_call',
          accountRef,
          targetRef,
          sponsorRef,
          detailsJson: buildDetailsJson({
            request: parsedBody,
            selector: matched.selector,
            execution: {
              txHash: assessment.txHash,
              gasUsed: assessment.gasUsed,
              effectiveGasPrice: assessment.effectiveGasPrice,
              feeAmount: assessment.feeAmount,
            },
            ...(prepaidSettlement ? { billing: prepaidSettlement } : {}),
            ...(spendCapSettlement ? { policySpendCap: spendCapSettlement } : {}),
          }),
          estimatedSpendMinor: prepaidSettlement?.estimatedSpendMinor ?? null,
          settledSpendMinor: prepaidSettlement?.settledSpendMinor ?? null,
          pricingVersion: prepaidSettlement?.pricingVersion ?? null,
          pricingSource: prepaidSettlement ? 'sponsorship_pricing_service' : null,
          billingLedgerEntryId,
          prepaidReservationId: prepaidSettlement?.reservationId || null,
          charged: Boolean(
            prepaidSettlement &&
              !prepaidSettlement.released &&
              prepaidSettlement.settledSpendMinor > 0,
          ),
          chargedReason: prepaidSettlement
            ? prepaidSettlement.released
              ? 'released_zero_spend'
              : prepaidSettlement.settledSpendMinor > 0
                ? 'sponsored_execution_debit'
                : 'settled_zero_spend'
            : null,
          settledAt: prepaidSettlement?.settledAt || null,
          idempotencyKey,
        }),
        assessment,
        walletId: parsedBody.walletId,
        balanceEvents: {
          logger: input.logger,
          webhooks: routerApiSponsoredEvmCall.webhooks || null,
          observabilityIngestion: routerApiSponsoredEvmCall.observabilityIngestion || null,
          webhookActorUserId: routerApiSponsoredEvmCall.webhookActorUserId,
          webhookRoles: routerApiSponsoredEvmCall.webhookRoles,
        },
        prepaidSettlementInput: {
          reservation: prepaidReservation,
          prepaidReservations: routerApiSponsoredEvmCall.prepaidReservations,
          pricing: routerApiSponsoredEvmCall.pricing,
          ctx: sponsorshipRuntime.sponsorshipCtx,
          chainFamily: 'evm',
          intentKind: 'evm_call',
          executorKind: adapter.executorKind,
          environmentId: parsedBody.environmentId,
          policyId: matched.policy.policyId,
          accountRef,
          targetRef,
          chainId: parsedBody.chainId,
          txOrExecutionRef: assessment.txHash,
          receiptStatus: assessment.receiptStatus,
          feeUnit: assessment.feeUnit,
          feeAmount: assessment.feeAmount,
          requestDetails: spendCapRequestDetails,
        },
      });
      return routeJson(200, {
        ok: true,
        replayed: false,
        recordId: record.id,
        policyId: matched.policy.policyId,
        txHash: assessment.txHash,
        spendWei: assessment.feeAmount,
        gasUsed: assessment.gasUsed,
        effectiveGasPrice: assessment.effectiveGasPrice,
      });
    },
    assessThrownError: buildFailedSponsoredEvmAssessment,
    onThrownError: async ({ assessment }): Promise<RouteResponse<Record<string, unknown>>> => {
      let spendCapSettlement: (SponsorshipSpendCapSettlement & {
        sourceEventId: string;
        estimatedSpendMinor: number;
      }) | null = null;
      try {
        const settled = await settleSponsoredSpendCap({
          reservation: spendCapReservation,
          spendCaps: routerApiSponsoredEvmCall.spendCaps,
          pricing: routerApiSponsoredEvmCall.pricing,
          ctx: sponsorshipRuntime.sponsorshipCtx,
          chainFamily: 'evm',
          intentKind: 'evm_call',
          executorKind: adapter.executorKind,
          environmentId: parsedBody.environmentId,
          policyId: matched.policy.policyId,
          accountRef,
          targetRef,
          chainId: parsedBody.chainId,
          txOrExecutionRef: assessment.txHash,
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
            routeTag: 'sponsored-evm-call',
            environmentId: parsedBody.environmentId,
            policyId: matched.policy.policyId,
            idempotencyKey,
            chainFamily: 'evm',
            intentKind: 'evm_call',
            executorKind: adapter.executorKind,
            chainId: parsedBody.chainId,
            accountRef,
            targetRef,
            reservation: spendCapReservation,
            settlement: settled,
            txOrExecutionRef: assessment.txHash,
            receiptStatus: assessment.receiptStatus,
          });
        }
      } catch (error: unknown) {
        input.logger.warn('[sponsored-evm-call] spend-cap settlement failed', {
          environmentId: parsedBody.environmentId,
          policyId: matched.policy.policyId,
          idempotencyKey,
          txHash: assessment.txHash,
          error: error instanceof Error ? error.message : String(error),
        });
      }
      const record = await recordSponsoredExecution({
        billing: routerApiSponsoredEvmCall.billing,
        billingSourceEventIdPrefix: 'sponsored_evm_call_debit',
        context: sponsorshipRuntime.sponsorshipCtx,
        ledger: routerApiSponsoredEvmCall.sponsoredCalls,
        buildRecord: ({ prepaidSettlement, billingLedgerEntryId }) => ({
          environmentId: parsedBody.environmentId,
          apiKeyId: sponsorshipRuntime.principal.principal.apiKeyId,
          apiKeyKind: 'publishable_key',
          route: DEFAULT_SPONSORED_EVM_CALL_ROUTE_ID,
          policyId: matched.policy.policyId,
          policyNameAtEvent: matched.policy.policyName,
          templateId: matched.policy.templateId,
          chainFamily: 'evm',
          intentKind: 'evm_call',
          accountRef,
          targetRef,
          sponsorRef,
          detailsJson: buildDetailsJson({
            request: parsedBody,
            selector: matched.selector,
            execution: {
              txHash: assessment.txHash,
              gasUsed: assessment.gasUsed,
              effectiveGasPrice: assessment.effectiveGasPrice,
              feeAmount: assessment.feeAmount,
            },
            ...(prepaidSettlement ? { billing: prepaidSettlement } : {}),
            ...(spendCapSettlement ? { policySpendCap: spendCapSettlement } : {}),
          }),
          estimatedSpendMinor: prepaidSettlement?.estimatedSpendMinor ?? null,
          settledSpendMinor: prepaidSettlement?.settledSpendMinor ?? null,
          pricingVersion: prepaidSettlement?.pricingVersion ?? null,
          pricingSource: prepaidSettlement ? 'sponsorship_pricing_service' : null,
          billingLedgerEntryId,
          prepaidReservationId: prepaidSettlement?.reservationId || null,
          charged: Boolean(
            prepaidSettlement &&
              !prepaidSettlement.released &&
              prepaidSettlement.settledSpendMinor > 0,
          ),
          chargedReason: prepaidSettlement
            ? prepaidSettlement.released
              ? 'released_zero_spend'
              : prepaidSettlement.settledSpendMinor > 0
                ? 'sponsored_execution_debit'
                : 'settled_zero_spend'
            : null,
          settledAt: prepaidSettlement?.settledAt || null,
          idempotencyKey,
        }),
        assessment,
        walletId: parsedBody.walletId,
        balanceEvents: {
          logger: input.logger,
          webhooks: routerApiSponsoredEvmCall.webhooks || null,
          observabilityIngestion: routerApiSponsoredEvmCall.observabilityIngestion || null,
          webhookActorUserId: routerApiSponsoredEvmCall.webhookActorUserId,
          webhookRoles: routerApiSponsoredEvmCall.webhookRoles,
        },
        prepaidSettlementInput: {
          reservation: prepaidReservation,
          prepaidReservations: routerApiSponsoredEvmCall.prepaidReservations,
          pricing: routerApiSponsoredEvmCall.pricing,
          ctx: sponsorshipRuntime.sponsorshipCtx,
          chainFamily: 'evm',
          intentKind: 'evm_call',
          executorKind: adapter.executorKind,
          environmentId: parsedBody.environmentId,
          policyId: matched.policy.policyId,
          accountRef,
          targetRef,
          chainId: parsedBody.chainId,
          txOrExecutionRef: assessment.txHash,
          receiptStatus: assessment.receiptStatus,
          feeUnit: assessment.feeUnit,
          feeAmount: assessment.feeAmount,
          requestDetails: spendCapRequestDetails,
        },
      });
      input.logger.error('[sponsored-evm-call] request failed', {
        environmentId: parsedBody.environmentId,
        apiKeyId: sponsorshipRuntime.principal.principal.apiKeyId,
        walletId: parsedBody.walletId,
        walletAddress: parsedBody.walletAddress,
        txHash: assessment.txHash,
        message: assessment.responseMessage,
      });
      return routeJson(502, {
        ok: false,
        code: assessment.responseCode,
        message: assessment.responseMessage,
        txHash: assessment.txHash,
        recordId: record.id,
        policyId: matched.policy.policyId,
      });
    },
  });
}
