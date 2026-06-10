import type {
  ConsoleRuntimeSnapshot,
  ConsoleRuntimeSnapshotContext,
  ConsoleRuntimeSnapshotService,
} from '../console/runtimeSnapshots';
import type {
  ConsoleSponsoredCallContext,
  ConsoleSponsoredCallRecord,
  ConsoleSponsoredCallService,
} from '../console/sponsoredCalls';
import type {
  EnforceRoutePolicyResult,
  RoutePolicyResolutionFailure,
} from './enforceRoutePolicy';
import type { RoutePrincipal } from './routeAuthPolicy';
import type { RouteExecutionContext, RouteResponse, RouteServices } from './routeExecutionContext';
import { routeJson } from './routeResponses';

type PublishableKeyRoutePrincipal = Extract<RoutePrincipal, { kind: 'api_credentials' }> & {
  credentialType: 'publishable_key';
};

type SponsorshipRouteFailureResponse = RouteResponse<Record<string, unknown>>;

export type SponsorshipRuntimeResolution<TServices extends RouteServices = RouteServices> =
  | {
      ok: true;
      context: RouteExecutionContext<TServices>;
      principal: PublishableKeyRoutePrincipal;
      sponsorshipCtx: ConsoleRuntimeSnapshotContext;
      latestSnapshot: ConsoleRuntimeSnapshot;
    }
  | {
      ok: false;
      response: SponsorshipRouteFailureResponse;
    };

export type SponsorshipMatchResolution<TMatched, TBody extends Record<string, unknown>> =
  | {
      ok: true;
      matched: TMatched;
    }
  | {
      ok: false;
      response: RouteResponse<TBody>;
    };

export type SponsorshipReplayOrMatchResolution<
  TMatched,
  TBody extends Record<string, unknown>,
> =
  | {
      kind: 'matched';
      matched: TMatched;
    }
  | {
      kind: 'response';
      response: RouteResponse<TBody>;
    };

function isPublishableKeyRoutePrincipal(
  principal: RoutePrincipal,
): principal is PublishableKeyRoutePrincipal {
  return principal.kind === 'api_credentials' && principal.credentialType === 'publishable_key';
}

export function parseRoutePolicyFailureMessage(message: string): { code: string; detail: string } {
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

export function buildSponsorshipRoutePolicyFailureResponse(
  resolved: RoutePolicyResolutionFailure,
): SponsorshipRouteFailureResponse {
  if (
    resolved.code === 'route_auth_not_configured' ||
    resolved.code === 'service_not_configured'
  ) {
    return routeJson(resolved.status, {
      ok: false,
      code: resolved.code,
      message: resolved.message,
    });
  }
  const parsed = parseRoutePolicyFailureMessage(resolved.message);
  return routeJson(resolved.status, {
    ok: false,
    code: parsed.code,
    message: parsed.detail,
  });
}

export async function resolveSponsorshipRuntimeForPublishableKeyRoute<
  TServices extends RouteServices = RouteServices,
>(input: {
  resolved: Extract<EnforceRoutePolicyResult<TServices>, { ok: true }>;
  runtimeSnapshots: ConsoleRuntimeSnapshotService | null | undefined;
  environmentId: string;
  actorUserId: string;
  roles?: string[];
  runtimeSnapshotsUnavailableMessage: string;
  runtimeSnapshotNotFoundMessage: string;
  unexpectedPrincipalMessage: string;
}): Promise<SponsorshipRuntimeResolution<TServices>> {
  if (!input.runtimeSnapshots) {
    return {
      ok: false,
      response: routeJson(503, {
        ok: false,
        code: 'runtime_snapshots_unavailable',
        message: input.runtimeSnapshotsUnavailableMessage,
      }),
    };
  }

  const principal = input.resolved.context.principal;
  if (!isPublishableKeyRoutePrincipal(principal)) {
    return {
      ok: false,
      response: routeJson(500, {
        ok: false,
        code: 'internal',
        message: input.unexpectedPrincipalMessage,
      }),
    };
  }

  const sponsorshipCtx: ConsoleRuntimeSnapshotContext = {
    orgId: principal.principal.orgId,
    actorUserId: input.actorUserId,
    roles: [...(input.roles || ['system'])],
  };
  const latestSnapshot = await input.runtimeSnapshots.getLatestSnapshot(sponsorshipCtx, {
    environmentId: input.environmentId,
  });
  if (!latestSnapshot) {
    return {
      ok: false,
      response: routeJson(503, {
        ok: false,
        code: 'runtime_snapshot_not_found',
        message: input.runtimeSnapshotNotFoundMessage,
      }),
    };
  }

  return {
    ok: true,
    context: input.resolved.context,
    principal,
    sponsorshipCtx,
    latestSnapshot,
  };
}

export async function resolveSponsorshipReplayOrMatch<
  TMatched,
  TBody extends Record<string, unknown>,
>(input: {
  sponsoredCalls: ConsoleSponsoredCallService | null | undefined;
  sponsorshipCtx: ConsoleSponsoredCallContext;
  idempotencyKey: string;
  buildReplayResponse: (existing: ConsoleSponsoredCallRecord) => RouteResponse<TBody>;
  resolveMatch: () =>
    | SponsorshipMatchResolution<TMatched, TBody>
    | Promise<SponsorshipMatchResolution<TMatched, TBody>>;
}): Promise<SponsorshipReplayOrMatchResolution<TMatched, TBody>> {
  const existing = input.sponsoredCalls
    ? await input.sponsoredCalls.getRecordByIdempotencyKey(
        input.sponsorshipCtx,
        input.idempotencyKey,
      )
    : null;
  if (existing) {
    return {
      kind: 'response',
      response: input.buildReplayResponse(existing),
    };
  }

  const resolved = await input.resolveMatch();
  if (!resolved.ok) {
    return {
      kind: 'response',
      response: resolved.response,
    };
  }

  return {
    kind: 'matched',
    matched: resolved.matched,
  };
}
