import type { NormalizedLogger } from '@seams/sdk-server/internal/core/logger';
import {
  buildWebhookDeadLetterObservabilityEvent,
  buildWebhookEndpointDegradedObservabilityEvent,
  buildWebhookRetryExhaustedObservabilityEvent,
} from '../observability/adapters';
import type { ConsoleObservabilityIngestionService } from '../observability/ingestionService';
import type { ConsoleWebhooksContext } from './types';

export const DEFAULT_CONSOLE_WEBHOOK_ENDPOINT_DEGRADED_THRESHOLD = 3;

export interface ConsoleWebhookObservabilityOptions {
  observabilityIngestion?: ConsoleObservabilityIngestionService | null;
  observabilityLogger?: Pick<NormalizedLogger, 'warn'> | null;
  endpointDegradedThreshold?: number;
}

export interface ConsoleWebhookDeadLetterSignal {
  kind: 'DEAD_LETTER';
  orgId: string;
  endpointId: string;
  deliveryId: string;
  webhookEventId: string;
  webhookEventType: string;
  failedAttempts: number;
  lastResponseStatus?: number | null;
  lastErrorMessage?: string | null;
  movedToDlqAt: string;
}

export interface ConsoleWebhookRetryExhaustedSignal {
  kind: 'RETRY_EXHAUSTED';
  orgId: string;
  endpointId: string;
  deliveryId: string;
  webhookEventId: string;
  webhookEventType: string;
  failedAttempts: number;
  maxAttempts: number;
  lastResponseStatus?: number | null;
  lastErrorMessage?: string | null;
  exhaustedAt: string;
}

export interface ConsoleWebhookEndpointDegradedSignal {
  kind: 'ENDPOINT_DEGRADED';
  orgId: string;
  endpointId: string;
  unresolvedDeadLetterCount: number;
  degradationThreshold: number;
  latestDeliveryId?: string;
  latestWebhookEventId?: string;
  latestWebhookEventType?: string;
  lastResponseStatus?: number | null;
  lastErrorMessage?: string | null;
  degradedAt: string;
}

export type ConsoleWebhookObservabilitySignal =
  | ConsoleWebhookDeadLetterSignal
  | ConsoleWebhookRetryExhaustedSignal
  | ConsoleWebhookEndpointDegradedSignal;

function normalizeString(raw: unknown): string {
  return String(raw || '').trim();
}

function normalizeRoles(raw: unknown): string[] {
  if (!Array.isArray(raw)) return ['ops'];
  const roles = raw.map((role) => normalizeString(role)).filter(Boolean);
  return roles.length > 0 ? roles : ['ops'];
}

export function normalizeConsoleWebhookEndpointDegradedThreshold(raw: unknown): number {
  const value = Math.floor(Number(raw));
  if (!Number.isFinite(value) || value <= 0) {
    return DEFAULT_CONSOLE_WEBHOOK_ENDPOINT_DEGRADED_THRESHOLD;
  }
  return value;
}

export async function appendConsoleWebhookObservabilitySignals(
  options: ConsoleWebhookObservabilityOptions,
  ctx: ConsoleWebhooksContext,
  signals: readonly ConsoleWebhookObservabilitySignal[],
): Promise<void> {
  const observabilityIngestion = options.observabilityIngestion;
  if (!observabilityIngestion || signals.length === 0) return;

  const ingestCtx = {
    orgId: normalizeString(ctx.orgId),
    actorUserId: normalizeString(ctx.actorUserId) || 'system-webhook-delivery',
    roles: normalizeRoles(ctx.roles),
  };
  if (!ingestCtx.orgId) return;

  for (const signal of signals) {
    try {
      const event =
        signal.kind === 'DEAD_LETTER'
          ? buildWebhookDeadLetterObservabilityEvent({
              orgId: signal.orgId,
              endpointId: signal.endpointId,
              deliveryId: signal.deliveryId,
              webhookEventId: signal.webhookEventId,
              webhookEventType: signal.webhookEventType,
              failedAttempts: signal.failedAttempts,
              ...(signal.lastResponseStatus != null
                ? { lastResponseStatus: signal.lastResponseStatus }
                : {}),
              ...(normalizeString(signal.lastErrorMessage)
                ? { lastErrorMessage: normalizeString(signal.lastErrorMessage) }
                : {}),
              movedToDlqAt: signal.movedToDlqAt,
            })
          : signal.kind === 'RETRY_EXHAUSTED'
            ? buildWebhookRetryExhaustedObservabilityEvent({
                orgId: signal.orgId,
                endpointId: signal.endpointId,
                deliveryId: signal.deliveryId,
                webhookEventId: signal.webhookEventId,
                webhookEventType: signal.webhookEventType,
                failedAttempts: signal.failedAttempts,
                maxAttempts: signal.maxAttempts,
                ...(signal.lastResponseStatus != null
                  ? { lastResponseStatus: signal.lastResponseStatus }
                  : {}),
                ...(normalizeString(signal.lastErrorMessage)
                  ? { lastErrorMessage: normalizeString(signal.lastErrorMessage) }
                  : {}),
                exhaustedAt: signal.exhaustedAt,
              })
            : buildWebhookEndpointDegradedObservabilityEvent({
                orgId: signal.orgId,
                endpointId: signal.endpointId,
                unresolvedDeadLetterCount: signal.unresolvedDeadLetterCount,
                degradationThreshold: signal.degradationThreshold,
                ...(normalizeString(signal.latestDeliveryId)
                  ? { latestDeliveryId: normalizeString(signal.latestDeliveryId) }
                  : {}),
                ...(normalizeString(signal.latestWebhookEventId)
                  ? { latestWebhookEventId: normalizeString(signal.latestWebhookEventId) }
                  : {}),
                ...(normalizeString(signal.latestWebhookEventType)
                  ? { latestWebhookEventType: normalizeString(signal.latestWebhookEventType) }
                  : {}),
                ...(signal.lastResponseStatus != null
                  ? { lastResponseStatus: signal.lastResponseStatus }
                  : {}),
                ...(normalizeString(signal.lastErrorMessage)
                  ? { lastErrorMessage: normalizeString(signal.lastErrorMessage) }
                  : {}),
                degradedAt: signal.degradedAt,
              });
      await observabilityIngestion.appendEvent(ingestCtx, event);
    } catch (error: unknown) {
      options.observabilityLogger?.warn?.(
        '[console-webhooks] failed to append observability event',
        {
          orgId: ingestCtx.orgId,
          signalKind: signal.kind,
          message: error instanceof Error ? error.message : String(error),
        },
      );
    }
  }
}
