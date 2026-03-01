import type { NormalizedRouterLogger } from './logger';
import type { RelayWebhookOptions } from './relay';

const DEFAULT_ORG_ID_CLAIM_KEYS = ['orgId', 'org_id', 'tenantId', 'tenant_id'] as const;

function toOptionalTrimmedString(input: unknown): string | null {
  if (typeof input !== 'string') return null;
  const value = input.trim();
  return value ? value : null;
}

function resolveOrgIdFromClaims(
  claims: Record<string, unknown> | null | undefined,
  keys: string[],
): string | null {
  if (!claims || typeof claims !== 'object') return null;
  for (const key of keys) {
    const value = toOptionalTrimmedString((claims as Record<string, unknown>)[key]);
    if (value) return value;
  }
  return null;
}

export async function emitRelayWebhookEvent(input: {
  logger: NormalizedRouterLogger;
  webhooks: RelayWebhookOptions | null | undefined;
  eventType: string;
  payload: Record<string, unknown>;
  claims?: Record<string, unknown> | null;
  eventId?: string;
  userId?: string;
}): Promise<void> {
  const eventType = toOptionalTrimmedString(input.eventType);
  if (!eventType) return;
  const webhooks = input.webhooks;
  if (!webhooks?.service) return;

  const claimKeys = (
    Array.isArray(webhooks.orgIdClaimKeys) && webhooks.orgIdClaimKeys.length
      ? webhooks.orgIdClaimKeys
      : [...DEFAULT_ORG_ID_CLAIM_KEYS]
  )
    .map((entry) => toOptionalTrimmedString(entry))
    .filter((entry): entry is string => Boolean(entry));

  const orgId =
    toOptionalTrimmedString(webhooks.orgId) ||
    resolveOrgIdFromClaims(input.claims || null, claimKeys) ||
    null;
  if (!orgId) {
    input.logger.debug('[relay][webhooks] skipped event without org scope', {
      eventType,
      eventId: input.eventId || null,
    });
    return;
  }

  const actorUserId = toOptionalTrimmedString(webhooks.actorUserId) || 'system-relay-webhook';
  const roles = Array.isArray(webhooks.roles) && webhooks.roles.length ? webhooks.roles : ['ops'];

  try {
    await webhooks.service.emitEvent(
      {
        orgId,
        actorUserId,
        roles: roles.map((entry) => String(entry || '').trim().toLowerCase()).filter(Boolean),
      },
      {
        ...(input.eventId ? { eventId: input.eventId } : {}),
        eventType,
        payload: {
          ...input.payload,
          ...(input.userId ? { userId: input.userId } : {}),
          orgId,
        },
      },
    );
  } catch (error: unknown) {
    input.logger.warn('[relay][webhooks] failed to emit lifecycle event', {
      eventType,
      orgId,
      eventId: input.eventId || null,
      message: error instanceof Error ? error.message : String(error),
    });
  }
}
