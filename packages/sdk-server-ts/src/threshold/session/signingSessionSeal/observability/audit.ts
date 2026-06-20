import type { NormalizedLogger } from '../../../../core/logger';
import type { SigningSessionSealAuditEvent, SigningSessionSealAuditSink } from '../signingSessionSeal.types';

export interface CreateSigningSessionSealAuditLoggerOptions {
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

function buildPayload(event: SigningSessionSealAuditEvent): Record<string, unknown> {
  return {
    operation: event.operation,
    thresholdSessionId: event.thresholdSessionId,
    userId: event.userId,
    ok: event.ok,
    durationMs: event.durationMs,
    ...(event.code ? { code: event.code } : {}),
  };
}

export function createSigningSessionSealAuditLogger(
  options: CreateSigningSessionSealAuditLoggerOptions,
): SigningSessionSealAuditSink {
  const label =
    String(options.label || '[threshold-signing-session-seal] audit').trim() ||
    '[threshold-signing-session-seal] audit';
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
