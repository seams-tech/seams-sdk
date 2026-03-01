import type { NormalizedLogger } from '../../../core/logger';
import { createPrfSessionSealAuditLogger } from './observability/audit';
import { composePrfSessionSealGuards, createPrfSessionSealRateLimitGuard } from './guards';
import { createPrfSessionSealService } from './service';
import type {
  CreatePrfSessionSealServiceOptions,
  PrfSessionSealAuditSink,
  PrfSessionSealAuthorizeInput,
  PrfSessionSealAuthorizeResult,
  PrfSessionSealCipherAdapter,
  PrfSessionSealConsumePolicy,
  PrfSessionSealGuard,
  PrfSessionSealRoutesOptions,
  PrfSessionSealServiceIdempotencyOptions,
  PrfSessionSealThresholdSessionPolicy,
  PrfSessionSealStartupCapabilities,
} from './types';
import type { CreatePrfSessionSealAuditLoggerOptions } from './observability/audit';
import type { CreatePrfSessionSealRateLimitGuardOptions } from './guards';

export interface CreatePrfSessionSealRoutesOptionsInput {
  enabled?: boolean;
  basePath?: string;
  sessionPolicy: PrfSessionSealThresholdSessionPolicy;
  cipher: PrfSessionSealCipherAdapter;
  consumePolicy?: PrfSessionSealConsumePolicy;
  idempotency?: PrfSessionSealServiceIdempotencyOptions;
  guard?: PrfSessionSealGuard | null;
  guards?: Array<PrfSessionSealGuard | null | undefined>;
  rateLimit?: Omit<CreatePrfSessionSealRateLimitGuardOptions, 'nowMs'>;
  audit?: PrfSessionSealAuditSink | null;
  logger?: NormalizedLogger | null;
  auditLogger?: Omit<CreatePrfSessionSealAuditLoggerOptions, 'logger'> | null;
  capabilities?: PrfSessionSealStartupCapabilities;
  authorize?: (
    input: PrfSessionSealAuthorizeInput,
  ) => Promise<PrfSessionSealAuthorizeResult> | PrfSessionSealAuthorizeResult;
  nowMs?: () => number;
}

function buildAuditSink(
  input: CreatePrfSessionSealRoutesOptionsInput,
): PrfSessionSealAuditSink | undefined {
  if (input.audit) return input.audit;
  if (!input.logger) return undefined;
  if (input.auditLogger === null) return undefined;
  const options: CreatePrfSessionSealAuditLoggerOptions = {
    logger: input.logger,
  };
  if (input.auditLogger?.label) {
    options.label = input.auditLogger.label;
  }
  if (input.auditLogger?.failureLevel) {
    options.failureLevel = input.auditLogger.failureLevel;
  }
  return createPrfSessionSealAuditLogger(options);
}

function buildGuard(
  input: CreatePrfSessionSealRoutesOptionsInput,
): PrfSessionSealGuard | undefined {
  const guardList: Array<PrfSessionSealGuard | null | undefined> = [];

  if (input.guard) guardList.push(input.guard);
  if (Array.isArray(input.guards)) guardList.push(...input.guards);

  if (input.rateLimit) {
    const rateLimitOptions: CreatePrfSessionSealRateLimitGuardOptions = { ...input.rateLimit };
    if (input.nowMs) {
      rateLimitOptions.nowMs = input.nowMs;
    }
    guardList.push(
      createPrfSessionSealRateLimitGuard(rateLimitOptions),
    );
  }

  const nonNullGuards = guardList.filter(Boolean) as PrfSessionSealGuard[];
  if (nonNullGuards.length === 0) return undefined;
  return composePrfSessionSealGuards(...nonNullGuards);
}

export function createPrfSessionSealRoutesOptions(
  input: CreatePrfSessionSealRoutesOptionsInput,
): PrfSessionSealRoutesOptions {
  const guard = buildGuard(input);
  const audit = buildAuditSink(input);
  const serviceOptions: CreatePrfSessionSealServiceOptions = {
    sessionPolicy: input.sessionPolicy,
    cipher: input.cipher,
  };
  if (input.consumePolicy) {
    serviceOptions.consumePolicy = input.consumePolicy;
  }
  if (input.idempotency) {
    serviceOptions.idempotency = input.idempotency;
  }
  if (guard) {
    serviceOptions.guard = guard;
  }
  if (audit) {
    serviceOptions.audit = audit;
  }
  if (input.logger) {
    serviceOptions.logger = input.logger;
  }
  if (input.nowMs) {
    serviceOptions.nowMs = input.nowMs;
  }

  const options: PrfSessionSealRoutesOptions = {
    service: createPrfSessionSealService(serviceOptions),
  };
  if (input.enabled !== undefined) {
    options.enabled = input.enabled;
  }
  if (input.basePath) {
    options.basePath = input.basePath;
  }
  if (input.authorize) {
    options.authorize = input.authorize;
  }
  if (input.capabilities) {
    options.capabilities = input.capabilities;
  }
  return options;
}
