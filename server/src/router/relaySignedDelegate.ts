import type { AuthService } from '../core/AuthService';
import type { DelegateActionPolicy } from '../delegateAction';
import type { ConsoleBillingService } from '../console/billing';
import type { ConsoleSponsoredCallService } from '../console/sponsoredCalls';
import { applyRouteMetering } from './applyRouteMetering';
import { enforceRoutePolicy, type RoutePolicyResolutionResult } from './enforceRoutePolicy';
import type { NormalizedRouterLogger } from './logger';
import type { HeaderRecord, RouteResponse } from './routeExecutionContext';
import type { RouteDefinition } from './routeDefinitions';
import type { RouteErrorBody } from './routeResponses';
import { routeJson } from './routeResponses';
import {
  extractBearerCredential,
  extractRelayEnvironmentId,
} from './relayApiKeyAuth';
import type { RelayPublishableKeyAuthAdapter } from './relay';

function isObject(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

interface SignedDelegateRequestBody {
  hash: string;
  signedDelegate: unknown;
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
      txHash: String(input.result.transactionHash || '').trim() || null,
      gasBurnt: summary.gasBurnt,
      tokensBurnt: summary.feeAmountYoctoNear,
    },
  });
}

async function meterSignedDelegate(input: {
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
  const metrics = summarizeNearExecutionOutcome(input.result.outcome);
  await applyRouteMetering({
    context: input.routeContext,
    route: input.route,
    response: routeJson(200, { ok: true }, {
      usage: {
        ...(metrics.gasBurnt ? { gasUsed: metrics.gasBurnt } : {}),
        ...(input.result.transactionHash
          ? { transactionHash: input.result.transactionHash }
          : {}),
      },
    }),
    handlers: {
      gas: async ({ context, ledger, response, route }) => {
        if (ledger !== 'near_delegate') return;
        if (context.principal.kind !== 'machine') return;
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
        const record = await input.services.sponsoredCalls!.createRecord(sponsorshipCtx, {
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
          receiptStatus: 'success',
          feeUnit: 'yocto_near',
          feeAmount: metrics.feeAmountYoctoNear,
          detailsJson: buildSignedDelegateDetailsJson({
            hash: input.hash,
            result: input.result,
            signedDelegate: input.signedDelegate,
          }),
          sourceEventId: `signed_delegate:${context.principal.principal.apiKeyId}:${input.hash}`,
        });
        await input.services.billing!.recordUsageEvent(sponsorshipCtx, {
          walletId: senderId,
          action: 'contract_call',
          succeeded: true,
          occurredAt: new Date().toISOString(),
          sourceEventId: `signed_delegate_usage:${record.id}`,
        });
      },
    },
  });
}

async function resolveSignedDelegateMachineAuth(input: {
  headers: HeaderRecord;
  origin?: string;
  route: RouteDefinition;
  publishableKeyAuth: RelayPublishableKeyAuthAdapter;
}): Promise<RoutePolicyResolutionResult> {
  if (input.route.auth.plane !== 'machine') {
    return {
      ok: false,
      status: 500,
      code: 'route_auth_not_configured',
      message: 'Signed delegate requires machine auth policy',
    };
  }

  const publishableKey = extractBearerCredential(input.headers);
  if (!publishableKey) {
    return {
      ok: false,
      status: 401,
      code: 'unauthorized',
      message: 'publishable_key_missing: Missing publishable key',
    };
  }

  const origin = String(input.origin || '').trim();
  if (!origin) {
    return {
      ok: false,
      status: 403,
      code: 'forbidden',
      message:
        'publishable_key_origin_blocked: Origin header is required and must be a valid exact origin',
    };
  }

  const environmentId = extractRelayEnvironmentId(input.headers);
  if (!environmentId) {
    return {
      ok: false,
      status: 403,
      code: 'forbidden',
      message:
        'publishable_key_environment_mismatch: Environment header is required for signed delegate execution',
    };
  }

  const authResult = await input.publishableKeyAuth.authenticate({
    secret: publishableKey,
    origin,
    environmentId,
  });
  if (!authResult.ok) {
    return {
      ok: false,
      status: authResult.status,
      code: authResult.status === 403 ? 'forbidden' : 'unauthorized',
      message: `${authResult.code}: ${authResult.message}`,
    };
  }

  return {
    ok: true,
    principal: {
      kind: 'machine',
      credentialType: 'publishable_key',
      principal: authResult.principal,
    },
  };
}

export async function handleRelaySignedDelegate(
  input: RelaySignedDelegateInput,
): Promise<RouteResponse<Record<string, unknown> | RouteErrorBody>> {
  const resolved = await enforceRoutePolicy({
    headers: input.headers,
    logger: input.logger,
    request: { body: input.body, headers: input.headers },
    route: input.route,
    services: {
      authService: input.services.authService,
      ...(input.services.publishableKeyAuth
        ? { publishableKeyAuth: input.services.publishableKeyAuth }
        : {}),
    },
    resolvers: input.services.publishableKeyAuth
      ? {
          machine: async () =>
            await resolveSignedDelegateMachineAuth({
              headers: input.headers,
              origin: input.origin,
              route: input.route,
              publishableKeyAuth: input.services.publishableKeyAuth,
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

    if (!result || !result.ok) {
      return routeJson(400, {
        ok: false,
        code: result?.code || 'delegate_execution_failed',
        message: result?.error || 'Failed to execute delegate action',
      });
    }

    try {
      await meterSignedDelegate({
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

    return routeJson(200, {
      ok: true,
      relayerTxHash: result.transactionHash || null,
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
