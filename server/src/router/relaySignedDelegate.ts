import type { AuthService } from '../core/AuthService';
import type { DelegateActionPolicy } from '../delegateAction';
import type { ConsoleBillingService } from '../console/billing';
import type {
  ConsoleSponsoredCallReceiptStatus,
  ConsoleSponsoredCallService,
} from '../console/sponsoredCalls';
import { applyRouteMetering } from './applyRouteMetering';
import { enforceRoutePolicy, type RoutePolicyResolutionResult } from './enforceRoutePolicy';
import type { NormalizedRouterLogger } from './logger';
import { resolvePublishableKeyApiCredentialAuth } from './relayApiCredentialAuth';
import { extractRelayEnvironmentId } from './relayApiKeyAuth';
import type { HeaderRecord, RouteResponse } from './routeExecutionContext';
import type { RouteDefinition } from './routeDefinitions';
import type { RouteErrorBody } from './routeResponses';
import { routeJson } from './routeResponses';
import { recordMeteredGasExecution } from './recordMeteredGasExecution';
import type { RelayPublishableKeyAuthAdapter } from './relay';

function isObject(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

interface SignedDelegateRequestBody {
  hash: string;
  signedDelegate: unknown;
}

interface SignedDelegateExecutionAssessment {
  feeAmountYoctoNear: string;
  gasBurnt: string | null;
  receiptStatus: ConsoleSponsoredCallReceiptStatus;
  responseCode: string;
  responseMessage: string;
  recordErrorCode: string | null;
  recordErrorMessage: string | null;
  succeeded: boolean;
  transactionHash: string | null;
}

interface RelaySignedDelegateServices {
  authService: AuthService;
  billing?: ConsoleBillingService | null;
  publishableKeyAuth?: RelayPublishableKeyAuthAdapter | null;
  sponsoredCalls?: ConsoleSponsoredCallService | null;
}

export interface RelaySignedDelegateInput {
  body: unknown;
  headers: HeaderRecord;
  logger: NormalizedRouterLogger;
  origin?: string;
  policy?: DelegateActionPolicy;
  route: RouteDefinition;
  services: RelaySignedDelegateServices;
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

function parseSignedDelegateBody(body: unknown): SignedDelegateRequestBody {
  if (!isObject(body)) {
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

function normalizeNearAccountRef(value: unknown): string {
  return `near:${String(value || '').trim() || 'unknown'}`;
}

function readNearFailureDetail(status: unknown): {
  code: string | null;
  message: string | null;
} | null {
  if (isObject(status) && isObject(status.Failure)) {
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
  if (!isObject(outcome)) return null;
  const directChecks = [readNearFailureDetail(outcome.status)];
  for (const failure of directChecks) {
    if (failure) return failure;
  }

  const transactionOutcome = isObject(outcome.transaction_outcome)
    ? (outcome.transaction_outcome as Record<string, unknown>)
    : null;
  const rootOutcome = transactionOutcome && isObject(transactionOutcome.outcome)
    ? (transactionOutcome.outcome as Record<string, unknown>)
    : null;
  const rootFailure = readNearFailureDetail(rootOutcome?.status);
  if (rootFailure) return rootFailure;

  if (Array.isArray((outcome as Record<string, unknown>).receipts_outcome)) {
    for (const entry of (outcome as Record<string, unknown>).receipts_outcome as unknown[]) {
      if (!isObject(entry) || !isObject(entry.outcome)) continue;
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
    isObject(result.outcome) && isObject(result.outcome.transaction)
      ? String((result.outcome.transaction as Record<string, unknown>).hash || '').trim()
      : '';
  const transactionHash = String(result.transactionHash || '').trim() || outcomeHash || null;
  const outcomeFailure = resolveNearOutcomeFailure(result.outcome);

  if (result.ok && !outcomeFailure) {
    return {
      feeAmountYoctoNear: metrics.feeAmountYoctoNear,
      gasBurnt: metrics.gasBurnt,
      receiptStatus: 'success',
      responseCode: 'ok',
      responseMessage: 'Signed delegate submitted',
      recordErrorCode: null,
      recordErrorMessage: null,
      succeeded: true,
      transactionHash,
    };
  }

  if (outcomeFailure) {
    return {
      feeAmountYoctoNear: metrics.feeAmountYoctoNear,
      gasBurnt: metrics.gasBurnt,
      receiptStatus: 'reverted',
      responseCode: 'delegate_execution_failed',
      responseMessage: outcomeFailure.message || 'Signed delegate execution failed',
      recordErrorCode: outcomeFailure.code,
      recordErrorMessage: outcomeFailure.message,
      succeeded: false,
      transactionHash,
    };
  }

  const responseCode = String(result.code || '').trim() || 'delegate_execution_failed';
  const responseMessage =
    String(result.error || '').trim() || 'Failed to execute delegate action';
  const receiptStatus: ConsoleSponsoredCallReceiptStatus = transactionHash
    ? 'broadcast_failed'
    : 'rpc_rejected';
  return {
    feeAmountYoctoNear: metrics.feeAmountYoctoNear,
    gasBurnt: metrics.gasBurnt,
    receiptStatus,
    responseCode,
    responseMessage,
    recordErrorCode: responseCode,
    recordErrorMessage: responseMessage,
    succeeded: false,
    transactionHash,
  };
}

function resolveSignedDelegatePolicyId(policy: DelegateActionPolicy | undefined): string {
  return policy ? 'signed_delegate_policy' : 'signed_delegate_unrestricted';
}

function resolveSignedDelegatePolicyName(
  policy: DelegateActionPolicy | undefined,
): string | null {
  return policy ? 'Signed delegate relay policy' : null;
}

function summarizeNearExecutionOutcome(
  outcome: unknown,
): {
  feeAmountYoctoNear: string;
  gasBurnt: string | null;
} {
  const rows: Array<Record<string, unknown>> = [];
  if (isObject(outcome)) {
    const transactionOutcome = isObject(outcome.transaction_outcome)
      ? (outcome.transaction_outcome as Record<string, unknown>)
      : null;
    const rootOutcome = transactionOutcome && isObject(transactionOutcome.outcome)
      ? (transactionOutcome.outcome as Record<string, unknown>)
      : null;
    if (rootOutcome) rows.push(rootOutcome);
    if (Array.isArray((outcome as Record<string, unknown>).receipts_outcome)) {
      for (const entry of (outcome as Record<string, unknown>).receipts_outcome as unknown[]) {
        if (!isObject(entry) || !isObject(entry.outcome)) continue;
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

function buildSignedDelegateDetailsJson(input: {
  assessment: SignedDelegateExecutionAssessment;
  hash: string;
  result: { transactionHash?: string; outcome?: unknown };
  signedDelegate: unknown;
}): string {
  const delegateAction =
    isObject(input.signedDelegate) && isObject(input.signedDelegate.delegateAction)
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
        input.assessment.transactionHash ||
        String(input.result.transactionHash || '').trim() ||
        null,
      gasBurnt: summary.gasBurnt,
      tokensBurnt: summary.feeAmountYoctoNear,
      receiptStatus: input.assessment.receiptStatus,
      errorCode: input.assessment.recordErrorCode,
      errorMessage: input.assessment.recordErrorMessage,
    },
  });
}

async function meterSignedDelegate(input: {
  assessment: SignedDelegateExecutionAssessment;
  hash: string;
  policy?: DelegateActionPolicy;
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
  services: RelaySignedDelegateServices;
  signedDelegate: unknown;
}): Promise<void> {
  await applyRouteMetering({
    context: input.routeContext,
    route: input.route,
    response: routeJson(input.assessment.succeeded ? 200 : 502, { ok: input.assessment.succeeded }, {
      usage: {
        ...(input.assessment.gasBurnt ? { gasUsed: input.assessment.gasBurnt } : {}),
        ...(input.assessment.transactionHash
          ? { transactionHash: input.assessment.transactionHash }
          : {}),
      },
    }),
    handlers: {
      gas: async ({ context, ledger, response, route }) => {
        if (ledger !== 'near_delegate') return;
        if (context.principal.kind !== 'api_credentials') return;
        if (context.principal.credentialType !== 'publishable_key') return;
        const delegateAction =
          isObject(input.signedDelegate) && isObject(input.signedDelegate.delegateAction)
            ? (input.signedDelegate.delegateAction as Record<string, unknown>)
            : null;
        const senderId = String(delegateAction?.senderId || '').trim() || 'unknown-sender';
        const receiverId = String(delegateAction?.receiverId || '').trim() || 'unknown-receiver';
        const relayer = await input.services.authService.getRelayerAccount();
        const sponsorshipCtx = {
          orgId: context.principal.principal.orgId,
          actorUserId: 'signed-delegate-executor',
          roles: ['system'],
        };
        await recordMeteredGasExecution({
          billing: input.services.billing!,
          billingSourceEventIdPrefix: 'signed_delegate_usage',
          context: sponsorshipCtx,
          ledger: input.services.sponsoredCalls!,
          record: {
            environmentId: context.principal.principal.environmentId,
            apiKeyId: context.principal.principal.apiKeyId,
            apiKeyKind: 'publishable_key',
            route: route.id,
            policyId: resolveSignedDelegatePolicyId(input.policy),
            policyNameAtEvent: resolveSignedDelegatePolicyName(input.policy),
            chainFamily: 'near',
            intentKind: 'near_delegate',
            accountRef: normalizeNearAccountRef(senderId),
            targetRef: normalizeNearAccountRef(receiverId),
            sponsorRef: normalizeNearAccountRef(relayer.accountId),
            txOrExecutionRef: String(response.usage?.transactionHash || '').trim() || null,
            receiptStatus: input.assessment.receiptStatus,
            feeUnit: 'yocto_near',
            feeAmount: input.assessment.feeAmountYoctoNear,
            detailsJson: buildSignedDelegateDetailsJson({
              assessment: input.assessment,
              hash: input.hash,
              result: input.result,
              signedDelegate: input.signedDelegate,
            }),
            errorCode: input.assessment.recordErrorCode,
            errorMessage: input.assessment.recordErrorMessage,
            idempotencyKey: `signed_delegate:${context.principal.principal.apiKeyId}:${input.hash}`,
          },
          succeeded: input.assessment.succeeded,
          walletId: senderId,
        });
      },
    },
  });
}

export async function handleRelaySignedDelegate(
  input: RelaySignedDelegateInput,
): Promise<RouteResponse<Record<string, unknown> | RouteErrorBody>> {
  const publishableKeyAuth = input.services.publishableKeyAuth || null;
  const resolved = await enforceRoutePolicy({
    headers: input.headers,
    logger: input.logger,
    request: { body: input.body, headers: input.headers },
    route: input.route,
    services: {
      authService: input.services.authService,
      ...(input.services.billing ? { billing: input.services.billing } : {}),
      ...(publishableKeyAuth
        ? { publishableKeyAuth }
        : {}),
      ...(input.services.sponsoredCalls
        ? { sponsoredCalls: input.services.sponsoredCalls }
        : {}),
    },
    resolvers: publishableKeyAuth
        ? {
          apiCredentials: async () =>
            await resolvePublishableKeyApiCredentialAuth({
              environmentId: extractRelayEnvironmentId(input.headers) || undefined,
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

  try {
    const parsedBody = parseSignedDelegateBody(input.body);
    const result = await input.services.authService.executeSignedDelegate({
      hash: parsedBody.hash,
      signedDelegate: parsedBody.signedDelegate as any,
      policy: input.policy,
    });

    const assessment = resolveSignedDelegateAssessment(result);

    try {
      await meterSignedDelegate({
        assessment,
        hash: parsedBody.hash,
        policy: input.policy,
        result,
        route: input.route,
        routeContext: resolved.context,
        services: input.services,
        signedDelegate: parsedBody.signedDelegate,
      });
    } catch (error: unknown) {
      input.logger.warn('[relay][signed-delegate] metering failed', {
        route: input.route.id,
        txHash: result.transactionHash || null,
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
          relayerTxHash: assessment.transactionHash,
          outcome: result.outcome ?? null,
        },
      );
    }

    return routeJson(200, {
      ok: true,
      relayerTxHash: assessment.transactionHash,
      status: 'submitted',
      outcome: result.outcome ?? null,
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
