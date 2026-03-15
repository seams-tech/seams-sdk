import { buildCorsOrigins, normalizeCorsOrigin } from '../core/SessionService';
import type { ConsoleBillingService } from '../console/billing';
import type { ConsoleRuntimeSnapshotService } from '../console/runtimeSnapshots';
import type {
  ConsoleSponsoredCallReceiptStatus,
  ConsoleSponsoredCallRecord,
  ConsoleSponsoredCallService,
} from '../console/sponsoredCalls';
import {
  TEMPO_DRIP_TO_SELECTOR,
  TEMPO_TESTNET_ONBOARDING_TEMPLATE_ID,
} from '../console/gasSponsorship/onboarding';
import {
  matchResolvedSponsoredEvmCallPolicy,
  normalizeEvmAddress,
  parseOptionalPositiveInteger,
  parseResolvedSponsoredEvmCallPolicies,
  parseSponsoredEvmCallRequest,
  type SponsoredEvmCallRequest,
} from '../sponsorship/evm';
import {
  DEFAULT_SPONSORED_EVM_CALL_ROUTE_ID,
  executeSponsoredEvmCall,
  type SponsoredEvmCallExecutorConfig,
} from '../sponsorship/evmRelay';
import { enforceRoutePolicy } from './enforceRoutePolicy';
import type { NormalizedRouterLogger } from './logger';
import { resolvePublishableKeyMachineAuth } from './relayMachineAuth';
import { recordMeteredGasExecution } from './recordMeteredGasExecution';
import { extractRelayEnvironmentId } from './relayApiKeyAuth';
import type { RelayPublishableKeyAuthAdapter } from './relay';
import type { HeaderRecord, RouteResponse } from './routeExecutionContext';
import type { RouteDefinition } from './routeDefinitions';
import type { RouteErrorBody } from './routeResponses';
import { routeJson } from './routeResponses';

function isObject(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

type SponsoredEvmExecution = {
  txHash: `0x${string}`;
  gasUsed: string;
  effectiveGasPrice: string;
  feeAmount: string;
};

type SponsoredEvmCallDetails = {
  nearAccountId: string;
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
};

export interface RelaySponsoredEvmCallService {
  billing: ConsoleBillingService;
  config: SponsoredEvmCallExecutorConfig | null;
  corsOrigins: readonly string[];
  publishableKeyAuth: RelayPublishableKeyAuthAdapter | null;
  runtimeSnapshots: ConsoleRuntimeSnapshotService | null;
  sponsoredCalls: ConsoleSponsoredCallService;
}

export interface RelaySponsoredEvmCallInput {
  body: unknown;
  headers: HeaderRecord;
  logger: NormalizedRouterLogger;
  origin?: string;
  route: RouteDefinition;
  services: {
    relaySponsoredEvmCall?: RelaySponsoredEvmCallService | null;
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

function parsePolicyFailureMessage(message: string): { code: string; detail: string } {
  const normalized = String(message || '').trim();
  const separatorIndex = normalized.indexOf(':');
  if (separatorIndex <= 0) {
    return {
      code: 'unauthorized',
      detail: normalized || 'Unauthorized',
    };
  }
  return {
    code: normalized.slice(0, separatorIndex).trim() || 'unauthorized',
    detail: normalized.slice(separatorIndex + 1).trim() || 'Unauthorized',
  };
}

function normalizeTxHashOrNull(value: unknown): `0x${string}` | null {
  const normalized = String(value || '').trim();
  if (!/^0x[0-9a-fA-F]{64}$/.test(normalized)) return null;
  return normalized as `0x${string}`;
}

function buildAccountRef(nearAccountId: string): string {
  return `near:${nearAccountId}`;
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
}): string {
  const details: SponsoredEvmCallDetails = {
    nearAccountId: input.request.nearAccountId,
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
  };
  return JSON.stringify(details);
}

function parseDetailsJson(value: string): SponsoredEvmCallDetails | null {
  try {
    const parsed = JSON.parse(value) as Record<string, unknown>;
    const nearAccountId = String(parsed.nearAccountId || '').trim();
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
    if (!nearAccountId || !walletAddress || !chainId || !to || !data || !selector) return null;
    return {
      nearAccountId,
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

function extractFirstAddressArgument(data: `0x${string}`): `0x${string}` | null {
  const hex = String(data || '').trim();
  if (!/^0x[0-9a-fA-F]{8}[0-9a-fA-F]{64,}$/.test(hex)) return null;
  const firstArgStart = 2 + 8;
  return normalizeEvmAddress(`0x${hex.slice(firstArgStart + 24, firstArgStart + 64)}`);
}

function parseSponsoredEvmRequestBody(
  body: unknown,
  headers: HeaderRecord,
): SponsoredEvmCallRequest {
  const environmentId = extractRelayEnvironmentId(headers);
  const normalizedBody =
    isObject(body)
      ? ({
          ...body,
          environmentId: environmentId || body.environmentId,
        } as Record<string, unknown>)
      : body;
  return parseSponsoredEvmCallRequest(normalizedBody);
}

function resolveReceiptStatus(input: {
  errorCode: string;
  txHash: `0x${string}` | null;
}): ConsoleSponsoredCallReceiptStatus {
  if (input.errorCode === 'tx_reverted') return 'reverted';
  if (input.txHash) return 'broadcast_failed';
  return 'rpc_rejected';
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

export async function handleRelaySponsoredEvmCall(
  input: RelaySponsoredEvmCallInput,
): Promise<RouteResponse<Record<string, unknown> | RouteErrorBody>> {
  const relaySponsoredEvmCall = input.services.relaySponsoredEvmCall || null;

  if (!relaySponsoredEvmCall) {
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
  if (!origin || !isAllowedOrigin(origin, relaySponsoredEvmCall.corsOrigins)) {
    return routeJson(403, {
      ok: false,
      code: 'origin_not_allowed',
      message: 'Origin is not allowed',
    });
  }
  if (!relaySponsoredEvmCall.config?.enabled) {
    return routeJson(503, {
      ok: false,
      code: 'sponsored_evm_call_disabled',
      message: 'Sponsored EVM execution is not configured on this server',
    });
  }
  if (!relaySponsoredEvmCall.runtimeSnapshots) {
    return routeJson(503, {
      ok: false,
      code: 'runtime_snapshots_unavailable',
      message: 'Runtime snapshots are not configured on this server',
    });
  }
  if (!relaySponsoredEvmCall.publishableKeyAuth) {
    return routeJson(503, {
      ok: false,
      code: 'publishable_key_auth_unavailable',
      message: 'Publishable key authentication is not configured on this server',
    });
  }
  const publishableKeyAuth = relaySponsoredEvmCall.publishableKeyAuth;

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
      relaySponsoredEvmCall,
    },
    resolvers: {
      machine: async () =>
        await resolvePublishableKeyMachineAuth({
          environmentId: parsedBody.environmentId,
          headers: input.headers,
          missingEnvironmentMessage:
            'Environment header or body field is required for sponsored EVM execution',
          missingOriginMessage: 'Origin header is required and must be a valid exact origin',
          missingPublishableKeyMessage: 'Missing publishable key',
          origin,
          publishableKeyAuth,
          route: input.route,
          routeAuthNotConfiguredMessage: 'Sponsored EVM call requires machine auth policy',
        }),
    },
  });

  if (!resolved.ok) {
    if (
      resolved.body.code === 'route_auth_not_configured' ||
      resolved.body.code === 'service_not_configured'
    ) {
      return routeJson(resolved.status, resolved.body);
    }
    const parsed = parsePolicyFailureMessage(resolved.body.message);
    return routeJson(resolved.status, {
      ok: false,
      code: parsed.code,
      message: parsed.detail,
    });
  }

  if (resolved.context.principal.kind !== 'machine') {
    return routeJson(500, {
      ok: false,
      code: 'internal',
      message: 'Sponsored EVM execution requires a machine principal',
    });
  }

  const sponsorshipCtx = {
    orgId: resolved.context.principal.principal.orgId,
    actorUserId: 'sponsored-call-executor',
    roles: ['system'],
  };

  const latestSnapshot = await relaySponsoredEvmCall.runtimeSnapshots.getLatestSnapshot(
    sponsorshipCtx,
    {
      environmentId: parsedBody.environmentId,
    },
  );
  if (!latestSnapshot) {
    return routeJson(503, {
      ok: false,
      code: 'runtime_snapshot_not_found',
      message: 'No runtime snapshot is available for this environment',
    });
  }

  const policies = parseResolvedSponsoredEvmCallPolicies(latestSnapshot.payload);
  const matched = matchResolvedSponsoredEvmCallPolicy({
    policies,
    chainId: parsedBody.chainId,
    call: parsedBody.call,
  });
  if (!matched) {
    return routeJson(403, {
      ok: false,
      code: 'sponsorship_policy_not_matched',
      message: 'Requested call is not sponsorable under the active policy',
    });
  }
  if (
    matched.policy.templateId === TEMPO_TESTNET_ONBOARDING_TEMPLATE_ID &&
    matched.selector.toLowerCase() === TEMPO_DRIP_TO_SELECTOR
  ) {
    const recipient = extractFirstAddressArgument(parsedBody.call.data);
    if (!recipient || recipient.toLowerCase() !== parsedBody.walletAddress.toLowerCase()) {
      return routeJson(403, {
        ok: false,
        code: 'sponsorship_recipient_mismatch',
        message: 'Onboarding sponsorship recipient must match walletAddress',
      });
    }
  }
  if (parsedBody.chainId !== relaySponsoredEvmCall.config.chainId) {
    return routeJson(503, {
      ok: false,
      code: 'sponsor_chain_misconfigured',
      message: `Sponsor executor is configured for chain ${relaySponsoredEvmCall.config.chainId}, not ${parsedBody.chainId}`,
    });
  }

  const idempotencyKey = parsedBody.idempotencyKey;
  const existing = await relaySponsoredEvmCall.sponsoredCalls.getRecordByIdempotencyKey(
    sponsorshipCtx,
    idempotencyKey,
  );
  if (existing) {
    return buildReplayResponse(existing);
  }

  try {
    const execution = await executeSponsoredEvmCall({
      config: relaySponsoredEvmCall.config,
      chainId: parsedBody.chainId,
      call: parsedBody.call,
    });
    const record = await recordMeteredGasExecution({
      billing: relaySponsoredEvmCall.billing,
      billingSourceEventIdPrefix: 'sponsored_evm_call_usage',
      context: sponsorshipCtx,
      ledger: relaySponsoredEvmCall.sponsoredCalls,
      record: {
        environmentId: parsedBody.environmentId,
        apiKeyId: resolved.context.principal.principal.apiKeyId,
        apiKeyKind: 'publishable_key',
        route: DEFAULT_SPONSORED_EVM_CALL_ROUTE_ID,
        policyId: matched.policy.policyId,
        policyNameAtEvent: matched.policy.policyName,
        chainFamily: 'evm',
        intentKind: 'evm_call',
        accountRef: buildAccountRef(parsedBody.nearAccountId),
        targetRef: buildTargetRef(parsedBody.chainId, parsedBody.call.to),
        sponsorRef: buildSponsorRef(parsedBody.chainId, relaySponsoredEvmCall.config.sponsorAddress),
        txOrExecutionRef: execution.txHash,
        receiptStatus: 'success',
        feeUnit: 'wei',
        feeAmount: execution.feeAmount,
        detailsJson: buildDetailsJson({
          request: parsedBody,
          selector: matched.selector,
          execution: {
            txHash: execution.txHash,
            gasUsed: execution.gasUsed,
            effectiveGasPrice: execution.effectiveGasPrice,
            feeAmount: execution.feeAmount,
          },
        }),
        idempotencyKey,
      },
      succeeded: true,
      walletId: parsedBody.nearAccountId,
    });
    return routeJson(200, {
      ok: true,
      replayed: false,
      recordId: record.id,
      policyId: matched.policy.policyId,
      txHash: execution.txHash,
      spendWei: execution.feeAmount,
      gasUsed: execution.gasUsed,
      effectiveGasPrice: execution.effectiveGasPrice,
    });
  } catch (error: unknown) {
    const message =
      error instanceof Error ? error.message : String(error || 'Sponsored EVM call failed');
    const errorCode =
      error && typeof error === 'object' && 'code' in error
        ? String((error as { code?: unknown }).code || '')
        : '';
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
    const record = await recordMeteredGasExecution({
      billing: relaySponsoredEvmCall.billing,
      billingSourceEventIdPrefix: 'sponsored_evm_call_usage',
      context: sponsorshipCtx,
      ledger: relaySponsoredEvmCall.sponsoredCalls,
      record: {
        environmentId: parsedBody.environmentId,
        apiKeyId: resolved.context.principal.principal.apiKeyId,
        apiKeyKind: 'publishable_key',
        route: DEFAULT_SPONSORED_EVM_CALL_ROUTE_ID,
        policyId: matched.policy.policyId,
        policyNameAtEvent: matched.policy.policyName,
        chainFamily: 'evm',
        intentKind: 'evm_call',
        accountRef: buildAccountRef(parsedBody.nearAccountId),
        targetRef: buildTargetRef(parsedBody.chainId, parsedBody.call.to),
        sponsorRef: buildSponsorRef(parsedBody.chainId, relaySponsoredEvmCall.config.sponsorAddress),
        txOrExecutionRef: txHash,
        receiptStatus: resolveReceiptStatus({ errorCode, txHash }),
        feeUnit: 'wei',
        feeAmount,
        detailsJson: buildDetailsJson({
          request: parsedBody,
          selector: matched.selector,
          execution: {
            txHash,
            gasUsed,
            effectiveGasPrice,
            feeAmount,
          },
        }),
        errorCode: errorCode || null,
        errorMessage: message,
        idempotencyKey,
      },
      succeeded: false,
      walletId: parsedBody.nearAccountId,
    });
    input.logger.error('[sponsored-evm-call] request failed', {
      environmentId: parsedBody.environmentId,
      apiKeyId: resolved.context.principal.principal.apiKeyId,
      nearAccountId: parsedBody.nearAccountId,
      walletAddress: parsedBody.walletAddress,
      txHash,
      message,
    });
    return routeJson(502, {
      ok: false,
      code: errorCode || 'sponsored_evm_call_failed',
      message,
      txHash,
      recordId: record.id,
      policyId: matched.policy.policyId,
    });
  }
}
