import type { NormalizedLogger } from '../../../../core/logger';
import type { PrfSessionSealAuditEvent, PrfSessionSealAuditSink } from '../types';

export interface CreatePrfSessionSealAuditLoggerOptions {
  logger: NormalizedLogger;
  label?: string;
  failureLevel?: 'info' | 'warn' | 'error';
}

function logAtLevel(
  logger: NormalizedLogger,
  level: 'info' | 'warn' | 'error',
  message: string,
  payload: Record<string, unknown>,
): void {
  if (level === 'error') {
    logger.error(message, payload);
    return;
  }
  if (level === 'warn') {
    logger.warn(message, payload);
    return;
  }
  logger.info(message, payload);
}

function buildPayload(event: PrfSessionSealAuditEvent): Record<string, unknown> {
  return {
    operation: event.operation,
    thresholdSessionId: event.thresholdSessionId,
    userId: event.userId,
    ok: event.ok,
    durationMs: event.durationMs,
    ...(event.code ? { code: event.code } : {}),
  };
}

export function createPrfSessionSealAuditLogger(
  options: CreatePrfSessionSealAuditLoggerOptions,
): PrfSessionSealAuditSink {
  const label =
    String(options.label || '[threshold-ecdsa-prf-seal] audit').trim() ||
    '[threshold-ecdsa-prf-seal] audit';
  const failureLevel = options.failureLevel || 'warn';
  return (event) => {
    const payload = buildPayload(event);
    if (event.ok) {
      options.logger.info(label, payload);
      return;
    }
    logAtLevel(options.logger, failureLevel, label, payload);
  };
}
